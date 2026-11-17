"""
tests/integration/test_phase1_spine.py
End-to-end integration tests for Phase 1 core remediation spine.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from vulnflow.adapters.ecosystem.npm import NPMAdapter
from vulnflow.adapters.input.sarif import SARIFAdapter
from vulnflow.adapters.input.trivy import ScannerParseError, TrivyAdapter
from vulnflow.agents.planner import PlannerAgent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import RemediationAction, RiskTier
from vulnflow.contracts.state import VulnFlowState
from vulnflow.core.dedupe import DeduplicationEngine
from vulnflow.mcp_servers.build_server import build_server
from vulnflow.mcp_servers.git_server import git_server
from vulnflow.mcp_servers.policy_server import policy_candidates, policy_check
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.policy.engine import PolicyEngine
from vulnflow.reporting.pr_comment import format_pr_body
from vulnflow.sandbox.runner import SandboxRunner


def test_f01_trivy_and_sarif_adapters() -> None:
    """F01: Test Trivy and SARIF scanner report parsing."""
    trivy_adapter = TrivyAdapter()
    fixture_path = Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_trivy_report.json"

    findings = trivy_adapter.parse_file(fixture_path, repo="test-repo")
    assert len(findings) >= 1
    f = findings[0]
    assert f.package == "npm:lodash"
    assert f.version == "4.17.15"
    assert "CVE-2020-8203" in f.cve
    assert f.fix_versions == ["4.17.21"]
    assert f.severity == SeverityLevel.HIGH

    # SARIF parsing test
    sarif_adapter = SARIFAdapter()
    sarif_doc = {
        "runs": [
            {
                "tool": {"driver": {"name": "trivy-sarif", "rules": [{"id": "CVE-2020-8203", "name": "Prototype pollution"}]}},
                "results": [
                    {
                        "ruleId": "CVE-2020-8203",
                        "level": "error",
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package.json"}, "region": {"startLine": 12}}}],
                        "properties": {"package": "npm:lodash", "version": "4.17.15", "fix_versions": ["4.17.21"]},
                    }
                ],
            }
        ]
    }
    sarif_findings = sarif_adapter.parse_data(sarif_doc, repo="test-repo")
    assert len(sarif_findings) == 1
    assert sarif_findings[0].package == "npm:lodash"
    assert sarif_findings[0].severity == SeverityLevel.HIGH


def test_f03_deduplication() -> None:
    """F03: Test finding deduplication across multiple scanner feeds."""
    engine = DeduplicationEngine()
    f1 = Finding(
        id="FND-1",
        type=FindingType.VULN,
        scanner="trivy",
        repo="repo",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        location=LocationInfo(file_path="package.json"),
        fix_versions=["4.17.21"],
    )
    f2 = Finding(
        id="FND-2",
        type=FindingType.VULN,
        scanner="grype",
        repo="repo",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.CRITICAL,  # Higher severity
        location=LocationInfo(file_path="package.json"),
        fix_versions=["4.17.21"],
    )
    f3 = Finding(
        id="FND-3",
        type=FindingType.VULN,
        scanner="snyk",
        repo="repo",
        package="npm:axios",
        version="0.21.1",
        cve=["CVE-2021-3749"],
        severity=SeverityLevel.MEDIUM,
        location=LocationInfo(file_path="package.json"),
    )

    deduped = engine.deduplicate([f1, f2, f3])
    assert len(deduped) == 2
    lodash_finding = next(f for f in deduped if "lodash" in f.package)
    assert lodash_finding.severity == SeverityLevel.CRITICAL  # Elevated to highest
    assert engine.raw_count == 3
    assert engine.deduped_count == 2
    assert engine.dedupe_ratio == 1.5


def test_f10_and_f11_policy_engine() -> None:
    """F10 & F11: Test policy checks and fix candidate filtering."""
    # Approved version
    check_ok = policy_check("npm:lodash", "4.17.21")
    assert check_ok["status"] == PolicyStatus.APPROVED.value

    # Below approved threshold
    check_old = policy_check("npm:lodash", "4.17.15")
    assert check_old["status"] == PolicyStatus.UNKNOWN.value

    # Banned package
    check_banned = policy_check("npm:left-pad", "1.3.0")
    assert check_banned["status"] == PolicyStatus.BANNED.value

    # Deprecated package
    check_dep = policy_check("npm:moment", "2.29.1")
    assert check_dep["status"] == PolicyStatus.DEPRECATED.value
    assert check_dep["replacement"] == "date-fns"

    # Candidate filtering
    candidates = policy_candidates("npm:lodash", ["4.17.15", "4.17.20", "4.17.21"])
    assert candidates == ["4.17.21"]


def test_f16_planner_agent() -> None:
    """F16: Test PlannerAgent formulation of remediation plans."""
    agent = PlannerAgent()
    finding = Finding(
        id="FND-LODASH",
        type=FindingType.VULN,
        scanner="trivy",
        repo="sample",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        location=LocationInfo(file_path="package.json"),
        fix_versions=["4.17.21"],
    )

    plan = agent.plan_remediation(
        root_cause_id="npm:lodash",
        findings=[finding],
        advisories=[{"cve": "CVE-2020-8203", "title": "Prototype pollution"}],
        ecosystem="npm",
    )
    assert plan.action == RemediationAction.BUMP
    assert plan.target_version == "4.17.21"
    assert plan.risk_tier == RiskTier.AUTO
    assert "4.17.21" in plan.rationale


def test_f17_and_f18_npm_bump_and_sandbox() -> None:
    """F17 & F18: Test npm dependency bumping and sandbox execution."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_pkg = Path(tmpdir) / "package.json"
        with open(tmp_pkg, "w", encoding="utf-8") as f:
            json.dump({"name": "test-pkg", "dependencies": {"lodash": "4.17.15"}}, f)

        # Bump dependency
        changed, diff = NPMAdapter.bump_dependency(tmp_pkg, "lodash", "4.17.21")
        assert changed is True
        assert "4.17.21" in diff

        with open(tmp_pkg, "r", encoding="utf-8") as f:
            updated = json.load(f)
        assert updated["dependencies"]["lodash"] == "4.17.21"

        # Sandbox build and test
        runner = SandboxRunner()
        res = runner.execute_build_and_test(Path(tmpdir), ecosystem="npm")
        assert res["build_clean"] is True


def test_f19_pr_creation_and_idempotency() -> None:
    """F19: Test PR creation, markdown body formatting, and idempotency."""
    plan = PlannerAgent().plan_remediation(
        root_cause_id="npm:lodash",
        findings=[
            Finding(
                id="FND-101",
                type=FindingType.VULN,
                scanner="trivy",
                repo="repo",
                package="npm:lodash",
                version="4.17.15",
                cve=["CVE-2020-8203"],
                severity=SeverityLevel.HIGH,
                location=LocationInfo(file_path="package.json"),
                fix_versions=["4.17.21"],
            )
        ],
    )
    pr_body = format_pr_body(plan=plan)
    assert "VulnFlow Automated Remediation" in pr_body
    assert "lodash" in pr_body
    assert "4.17.21" in pr_body

    # Test PR creation and rerun idempotency
    pr_1 = git_server.pr_create("vulnflow/fix-lodash-test", pr_body, title="fix(deps): bump lodash")
    assert pr_1["status"] == "opened"
    pr_2 = git_server.pr_create("vulnflow/fix-lodash-test", pr_body, title="fix(deps): bump lodash")
    assert pr_1["pr_number"] == pr_2["pr_number"]  # Did not duplicate!


def test_phase_1_gate_core_remediation_spine() -> None:
    """
    PHASE 1 GATE TEST:
    One approved patch bump produces a real PR on a sample repo
    through the real policy server and the real LLM.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_repo = Path(tmpdir)
        pkg_file = sample_repo / "package.json"
        with open(pkg_file, "w", encoding="utf-8") as f:
            json.dump({
                "name": "sample-service",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.15"
                }
            }, f, indent=2)

        fixture_file = Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_trivy_report.json"

        state = VulnFlowState(
            repo_path=str(sample_repo),
            report_path=str(fixture_file),
            scanner="trivy",
            mode="pr",
            ecosystem="npm",
        )

        final_state = run_workflow(state)

        # 1. Gate check: terminal status completed cleanly
        assert final_state.terminal_status == "completed"
        assert final_state.exit_code == 0

        # 2. Gate check: Real policy server approved the plan
        assert len(final_state.plans) == 1
        plan = final_state.plans[0]
        assert plan.action == RemediationAction.BUMP
        assert plan.target_version == "4.17.21"
        assert plan.policy_result.status == "approved"

        # 3. Gate check: package.json dependency was updated
        with open(pkg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["dependencies"]["lodash"] == "4.17.21"

        # 4. Gate check: Real PR opened with formatted markdown body
        assert len(final_state.pull_requests) == 1
        pr = final_state.pull_requests[0]
        assert pr["status"] == "opened"
        assert "pr_url" in pr
        assert "VulnFlow Automated Remediation" in pr["body"]

        # 5. Gate check: Verification passed cleanly
        assert len(final_state.verification_results) == 1
        assert final_state.verification_results[0]["verified"] is True
        assert final_state.verification_results[0]["rescan_clean"] is True


if __name__ == "__main__":
    print("Testing F01: Trivy and SARIF adapters...")
    test_f01_trivy_and_sarif_adapters()
    print("Testing F03: Deduplication engine...")
    test_f03_deduplication()
    print("Testing F10 & F11: Policy engine and server...")
    test_f10_and_f11_policy_engine()
    print("Testing F16: Fix planner agent...")
    test_f16_planner_agent()
    print("Testing F17 & F18: NPM version bump & sandbox runner...")
    test_f17_and_f18_npm_bump_and_sandbox()
    print("Testing F19: PR creation & idempotency...")
    test_f19_pr_creation_and_idempotency()
    print("Testing Phase 1 Gate: Core remediation spine...")
    test_phase_1_gate_core_remediation_spine()
    print("\nALL PHASE 1 FEATURES & GATE TESTS PASSED!")
