"""
tests/integration/test_phase4_hardening.py
Phase 4 Gate validation: cryptographic audit verification, orphan cleanup, and injection defense.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from vulnflow.contracts.remediation_plan import RemediationAction, RemediationPlan, RiskTier
from vulnflow.contracts.state import VulnFlowState
from vulnflow.llm.base import (
    LLMAuthenticationError,
    LLMClient,
    LLMMessage,
    LLMRateLimitError,
    LLMResponse,
    LLMTimeoutError,
    LLMUsage,
)
from vulnflow.llm.factory import GuardedRecorderClient
from vulnflow.mcp_servers.git_server import git_server
from vulnflow.observability.audit_log import AuditLogger
from vulnflow.observability.tracing import TraceManager, trace_manager, trace_span
from vulnflow.orchestrator.approval import ApprovalGate
from vulnflow.orchestrator.failure_taxonomy import classify_failure
from vulnflow.orchestrator.graph import VulnFlowWorkflow
from vulnflow.orchestrator.nodes import approve_node
from vulnflow.orchestrator.retry import retry_with_backoff


def test_f31_tracing_spans_and_attributes() -> None:
    """F31: Verify every agent call and node records a structured trace span."""
    trace_manager.spans.clear()

    with trace_span("test.node.execution", {"model": "claude-3-5", "run_id": "RUN-trace-test"}):
        trace_manager.record_llm_call(
            provider="mock-llm",
            model="mock-v1",
            prompt_tokens=150,
            completion_tokens=45,
            latency_ms=120.5,
            cost_usd=0.0004,
        )

    spans = trace_manager.spans
    assert len(spans) >= 2, f"Expected at least 2 spans, found {len(spans)}"
    llm_span = next(s for s in spans if "llm" in s.name)
    assert llm_span.attributes.get("llm.usage.prompt_tokens") == 150
    assert llm_span.attributes.get("llm.model") == "mock-v1"
    assert llm_span.status == "OK"


def test_f32_cryptographic_audit_log_hash_chain() -> None:
    """F32: Verify SHA-256 hash chaining and tamper detection on audit records."""
    temp_dir = tempfile.mkdtemp(prefix="vulnflow_audit_test_")
    try:
        logger = AuditLogger(log_dir=temp_dir)
        run_id = "RUN-audit-hash-01"

        # Record a 4-event sequence
        e1 = logger.log(run_id, "RUN_STARTED", "orchestrator", {"mode": "pr"})
        e2 = logger.log(run_id, "FINDINGS_INGESTED", "ingest", {"count": 2})
        e3 = logger.log(run_id, "PLAN_FORMULATED", "planner", {"version": "1.2.3"})
        e4 = logger.log(run_id, "RUN_COMPLETED", "orchestrator", {"status": "completed"})

        # 1. Verify in-memory and persistent hash chain integrity
        assert e2.previous_hash == e1.entry_hash
        assert e3.previous_hash == e2.entry_hash
        assert e4.previous_hash == e3.entry_hash

        valid, err = logger.verify_chain(run_id)
        assert valid is True, f"Valid chain reported failure: {err}"

        # 2. Simulate disk file tampering (adversary modifying payload)
        audit_file = logger.get_audit_file(run_id)
        assert audit_file and audit_file.exists()
        lines = audit_file.read_text(encoding="utf-8").splitlines()
        tampered_record = json.loads(lines[2])
        tampered_record["payload"]["version"] = "9.9.9"  # Altered version
        lines[2] = json.dumps(tampered_record)
        audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # 3. Verify tamper detection flags the exact altered record
        tampered, err_msg = logger.verify_chain(run_id)
        assert tampered is False, "Audit logger failed to catch tampered record!"
        assert "Tampered record at index 2" in str(err_msg), f"Unexpected error: {err_msg}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_f33_failure_handling_and_orphan_cleanup() -> None:
    """
    F33 acceptance criteria: Timeouts/unhandled failures end in clear terminal
    status ('error') and leave no orphan branches on disk.
    """
    temp_repo = tempfile.mkdtemp(prefix="vulnflow_orphan_test_")
    try:
        # Initialize test git repository
        subprocess.run(["git", "init"], cwd=temp_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=temp_repo, check=True)
        subprocess.run(["git", "config", "user.email", "tester@test.local"], cwd=temp_repo, check=True)

        pkg_json = Path(temp_repo) / "package.json"
        pkg_json.write_text('{"name": "test-orphan", "dependencies": {"lodash": "4.17.15"}}', encoding="utf-8")
        subprocess.run(["git", "add", "package.json"], cwd=temp_repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_repo, stdout=subprocess.PIPE, check=True)

        # Force default branch to main
        subprocess.run(["git", "branch", "-M", "main"], cwd=temp_repo, check=True)

        state = VulnFlowState(
            run_id="RUN-failure-test-01",
            repo_path=temp_repo,
            report_path="non_existent_report.json",
            mode="pr",
            ecosystem="npm",
        )

        # Pre-seed a created branch to simulate branch created before unexpected step crash
        orphan_branch = "vulnflow/fix-orphan-test"
        git_server.git_branch(orphan_branch, temp_repo)
        state.created_branches.append(orphan_branch)
        assert git_server.git_has_branch(orphan_branch, temp_repo) is True

        # Run workflow with a simulated crash in a pipeline node
        wf = VulnFlowWorkflow()

        def crashing_node(s: VulnFlowState) -> VulnFlowState:
            raise RuntimeError("Simulated crash in runner during fix execution")

        wf.nodes["ingest"] = crashing_node
        res = wf.execute(state)

        # Verify clear terminal status
        assert res.terminal_status == "error", f"Expected 'error', got {res.terminal_status}"
        assert res.exit_code == 1, f"Expected exit code 1, got {res.exit_code}"
        assert res.error is not None

        # Verify orphan branch was cleanly deleted by failure handler
        branch_exists = git_server.git_has_branch(orphan_branch, temp_repo)
        assert branch_exists is False, "Orphan branch was not cleaned up after workflow failure!"

        # Verify audit trail records failure and orphan cleanup
        event_types = [e["event_type"] for e in res.audit_events]
        assert "ORPHAN_CLEANUP" in event_types
        assert "RUN_FAILED" in event_types
    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


def test_f33_retry_with_exponential_backoff() -> None:
    """F33: Verify transient failures recover with exponential backoff."""
    call_count = 0

    def flaky_operation() -> str:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("Transient network glitch")
        return "SUCCESS"

    result = retry_with_backoff(flaky_operation, max_retries=4, base_delay=0.01)
    assert result == "SUCCESS"
    assert call_count == 3


def test_f31_tool_call_spans_and_retention_pruning() -> None:
    """F31: Verify MCP tool call spans and retention pruning for traces and audit logs."""
    import time

    tm = TraceManager()
    span = tm.record_tool_call(
        "policy_check",
        attributes={"package": "npm:lodash", "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"},
        duration_ms=12.5,
    )
    assert span.name == "mcp.tool.policy_check"
    assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in str(span.attributes)
    span.start_time = time.time() - (40 * 86400)
    pruned_spans = tm.prune_spans(retention_days=30)
    assert pruned_spans == 1
    assert len(tm.spans) == 0

    temp_dir = tempfile.mkdtemp(prefix="vulnflow_audit_retain_")
    try:
        logger = AuditLogger(log_dir=temp_dir)
        old_file = Path(temp_dir) / "audit_RUN-old.jsonl"
        old_file.write_text("{}\n", encoding="utf-8")
        old_ts = time.time() - (100 * 86400)
        os.utime(old_file, (old_ts, old_ts))
        removed = logger.prune_expired_logs(retention_days=90)
        assert removed == 1
        assert not old_file.exists()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_f32_approver_identity_recorded_in_audit_log() -> None:
    """F32 / §13.8: Approver identity (reviewer & group) is recorded in workflow audit events."""
    from unittest.mock import patch

    temp_repo = tempfile.mkdtemp(prefix="vulnflow_approver_audit_")
    try:
        gate = ApprovalGate(persistence_file=Path(temp_repo) / ".vulnflow" / "approvals.json")
        plan = RemediationPlan(
            id="PLAN-approver-test",
            finding_ids=["FND-1"],
            root_cause_id="PKG-npm:express",
            action=RemediationAction.BUMP,
            target_package="npm:express",
            target_version="5.0.0",
            risk_tier=RiskTier.REVIEW,
            requires_approval=True,
        )
        gate.record_decision(
            plan_id=plan.id,
            approved=True,
            reviewer="alice.security@corp.internal",
            reviewer_group="security-leads",
            reason="Verified breaking changes in staging",
            repo_path=temp_repo,
        )
        state = VulnFlowState(
            run_id="RUN-approver-audit",
            repo_path=temp_repo,
            plans=[plan],
        )
        with patch("vulnflow.orchestrator.nodes.global_approval_gate", gate):
            out = approve_node(state)
        approved_events = [e for e in out.audit_events if e["event_type"] == "PLAN_MANUALLY_APPROVED"]
        assert len(approved_events) == 1
        ev = approved_events[0]
        assert ev["actor"] == "alice.security@corp.internal"
        assert ev["payload"]["reviewer"] == "alice.security@corp.internal"
        assert ev["payload"]["reviewer_group"] == "security-leads"
        assert "Verified breaking changes" in str(ev["payload"]["reason"])
    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


def test_f33_llm_rate_limit_retry_and_auth_fail_fast() -> None:
    """F33: GuardedRecorderClient retries HTTP 429/timeouts with backoff and fails fast on 401."""

    class _RateLimitedLLM(LLMClient):
        def __init__(self) -> None:
            super().__init__(default_model="test-model", max_retries=3)
            self.calls = 0

        def get_provider_name(self) -> str:
            return "mock"

        def complete(self, messages, model=None, temperature=0.0, max_tokens=None, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise LLMRateLimitError("429 Too Many Requests", provider="mock", status_code=429, retry_after=0.0)
            if self.calls == 2:
                raise LLMTimeoutError("Timed out", provider="mock")
            return LLMResponse(
                content="ok",
                model="test-model",
                provider="mock",
                usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            )

    client = GuardedRecorderClient(inner_client=_RateLimitedLLM())
    resp = client.complete([LLMMessage(role="user", content="hello")])
    assert resp.content == "ok"
    assert client.inner_client.calls == 3

    class _AuthFailingLLM(LLMClient):
        def __init__(self) -> None:
            super().__init__(default_model="test-model", max_retries=3)
            self.calls = 0

        def get_provider_name(self) -> str:
            return "mock"

        def complete(self, messages, model=None, temperature=0.0, max_tokens=None, **kwargs):
            self.calls += 1
            raise LLMAuthenticationError("401 Invalid Key", provider="mock", status_code=401)

    auth_inner = _AuthFailingLLM()
    auth_client = GuardedRecorderClient(inner_client=auth_inner)
    try:
        auth_client.complete([LLMMessage(role="user", content="hello")])
        raise AssertionError("Expected LLMAuthenticationError")
    except LLMAuthenticationError:
        assert auth_inner.calls == 1


def test_f33_workflow_timeout_and_partial_artifact_status() -> None:
    """F33 / Phase 4 Gate: Workflow timeouts end in error, clean orphan branches, and classify taxonomy."""
    import time

    temp_repo = tempfile.mkdtemp(prefix="vulnflow_timeout_test_")
    try:
        subprocess.run(["git", "init"], cwd=temp_repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=temp_repo, check=True)
        subprocess.run(["git", "config", "user.email", "tester@test.local"], cwd=temp_repo, check=True)
        (Path(temp_repo) / "package.json").write_text('{"name": "timeout-test"}', encoding="utf-8")
        subprocess.run(["git", "add", "package.json"], cwd=temp_repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_repo, stdout=subprocess.PIPE, check=True)
        subprocess.run(["git", "branch", "-M", "main"], cwd=temp_repo, check=True)

        orphan_branch = "vulnflow/fix-timeout-orphan"
        git_server.git_branch(orphan_branch, temp_repo)
        state = VulnFlowState(
            run_id="RUN-timeout-01",
            repo_path=temp_repo,
            created_branches=[orphan_branch],
            pull_requests=[{"branch": orphan_branch, "status": "draft"}],
            exception_ticket={"ticket_id": "SEC-999"},
        )

        wf = VulnFlowWorkflow(timeout_seconds=0.02)

        def slow_node(s: VulnFlowState) -> VulnFlowState:
            time.sleep(0.05)
            return s

        wf.nodes["ingest"] = slow_node
        res = wf.execute(state)

        assert res.terminal_status == "error"
        assert res.exit_code == 1
        assert "exceeded timeout" in str(res.error)
        assert git_server.git_has_branch(orphan_branch, temp_repo) is False
        assert res.pull_requests[0]["terminal_status"] == "aborted_on_error"
        assert res.exception_ticket["terminal_status"] == "run_failed_with_ticket"
        failed_ev = next(e for e in res.audit_events if e["event_type"] == "RUN_FAILED")
        assert failed_ev["payload"]["taxonomy_code"] == "TIMEOUT"
    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


def test_f34_harness_checks_and_failure_taxonomy() -> None:
    """§13.8: Harness pre/post-patch checks execute cleanly and taxonomy classifies failures."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    pre_check = repo_root / "harness" / "checks" / "pre_patch.sh"
    post_check = repo_root / "harness" / "checks" / "post_patch.sh"
    assert pre_check.exists() and post_check.exists()

    temp_repo = tempfile.mkdtemp(prefix="vulnflow_harness_chk_")
    try:
        subprocess.run(["git", "init"], cwd=temp_repo, stdout=subprocess.PIPE, check=True)
        (Path(temp_repo) / "package.json").write_text('{"name": "ok", "version": "1.0.0"}', encoding="utf-8")
        r_pre = subprocess.run(["bash", str(pre_check), temp_repo], capture_output=True, text=True, check=False)
        assert r_pre.returncode == 0, r_pre.stderr
        r_post = subprocess.run(["bash", str(post_check), temp_repo, "npm"], capture_output=True, text=True, check=False)
        assert r_post.returncode == 0, r_post.stderr

        assert classify_failure("429 rate limit exceeded").code == "RATE_LIMIT"
        assert classify_failure("Prompt injection deflected").code == "PROMPT_INJECTION_BLOCKED"
        assert classify_failure("Secret credential detected").code == "SECRET_LEAK_BLOCKED"
    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


def test_phase4_gate() -> None:
    """
    Phase 4 Gate Acceptance Criteria:
    - All prompt-injection defenses pass.
    - Zero secret leakage in plans, evidence, and audit logs.
    - Audit log hash chain verification passes.
    - Failed runs leave no orphan branches or tickets without clear terminal status.
    """
    test_f31_tracing_spans_and_attributes()
    test_f31_tool_call_spans_and_retention_pruning()
    test_f32_cryptographic_audit_log_hash_chain()
    test_f32_approver_identity_recorded_in_audit_log()
    test_f33_failure_handling_and_orphan_cleanup()
    test_f33_retry_with_exponential_backoff()
    test_f33_llm_rate_limit_retry_and_auth_fail_fast()
    test_f33_workflow_timeout_and_partial_artifact_status()
    test_f34_harness_checks_and_failure_taxonomy()
    print("ALL PHASE 4 HARDENING & GATE TESTS PASSED!")


if __name__ == "__main__":
    test_phase4_gate()
