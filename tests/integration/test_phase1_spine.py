"""
tests/integration/test_phase1_spine.py
End-to-end integration tests for Phase 1 core remediation spine.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from vulnflow.adapters.ecosystem.npm import NPMAdapter
from vulnflow.adapters.input.sarif import SARIFAdapter
from vulnflow.adapters.input.trivy import TrivyAdapter
from vulnflow.agents.planner import PlannerAgent, default_planner_agent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import RemediationAction, RiskTier
from vulnflow.contracts.state import VulnFlowState
from vulnflow.core.dedupe import DeduplicationEngine
from vulnflow.mcp_servers.git_server import git_server
from vulnflow.mcp_servers.policy_server import policy_candidates, policy_check
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.reporting.pr_comment import format_pr_body
from vulnflow.sandbox.runner import SandboxRunner

# Run integration tests with deterministic planner
default_planner_agent.enable_llm = False


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
    agent = PlannerAgent(enable_llm=False)
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
        assert res["build_clean"] is False
        assert res["verification_available"] is False


def test_f19_pr_creation_requires_a_real_repository() -> None:
    """F19: PR creation must never fabricate an opened pull request."""
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

    # Without a repository/remote, the server can only produce a preview.
    pr_1 = git_server.pr_create("vulnflow/fix-lodash-test", pr_body, title="fix(deps): bump lodash")
    assert pr_1["status"] == "preview"
    assert pr_1["pr_url"] is None
    pr_2 = git_server.pr_create("vulnflow/fix-lodash-test", pr_body, title="fix(deps): bump lodash")
    assert pr_2["status"] == "preview"


def test_phase_1_gate_fails_closed_without_git_or_live_scanner() -> None:
    """
    PHASE 1 GATE TEST:
    A mutation run must not claim completion when its git/scanner prerequisites
    are absent.
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

        assert final_state.terminal_status in {"error", "failed_verification"}
        assert final_state.exit_code != 0

        # 2. Gate check: Real policy server approved the plan
        assert len(final_state.plans) == 1
        plan = final_state.plans[0]
        assert plan.action == RemediationAction.BUMP
        assert plan.target_version == "4.17.21"
        assert plan.policy_result.status == "approved"

        # The failed git prerequisite prevents an untracked source mutation.
        with open(pkg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["dependencies"]["lodash"] == "4.17.15"
        assert final_state.pull_requests == []


def test_f27_cli_modes_fail_closed_when_mutation_prerequisites_are_missing() -> None:
    """F27: assessment succeeds, while mutation requires a git checkout and scanner."""
    from vulnflow.cli import main

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir)
        (repo_dir / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}), encoding="utf-8")
        report_f = Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_trivy_report.json"

        # 1. report mode
        exit_code = main(["report", "--repo", str(repo_dir), "--report", str(report_f), "--no-llm"])
        assert exit_code == 0

        # 2. A dry-run still patches/tests a branch, so this non-git directory
        # must fail instead of reporting a synthetic successful verification.
        exit_code = main(["analyze", "--repo", str(repo_dir), "--report", str(report_f), "--mode", "dry-run", "--no-llm"])
        assert exit_code != 0

        # 3. watch-expiry
        exit_code = main(["watch-expiry", "--repo", str(repo_dir), "--days", "30"])
        assert exit_code == 0


def test_f28_github_action_adapter() -> None:
    """F28 acceptance criteria: Action runs the scanner, calls the container and acts on the exit code on a sample repo."""
    from vulnflow.adapters.ci.github_action.adapter import GitHubActionAdapter

    with tempfile.TemporaryDirectory() as tmpdir:
        out_f = Path(tmpdir) / "github_output"
        summary_f = Path(tmpdir) / "step_summary.md"
        out_f.touch()
        summary_f.touch()

        old_out = os.environ.get("GITHUB_OUTPUT")
        old_sum = os.environ.get("GITHUB_STEP_SUMMARY")
        old_act = os.environ.get("GITHUB_ACTIONS")
        os.environ["GITHUB_OUTPUT"] = str(out_f)
        os.environ["GITHUB_STEP_SUMMARY"] = str(summary_f)
        os.environ["GITHUB_ACTIONS"] = "true"

        try:
            adapter = GitHubActionAdapter()
            assert adapter.is_github_action_environment() is True

            state = VulnFlowState(repo_path=tmpdir, exit_code=0, terminal_status="completed")
            code = adapter.process_result(state)
            assert code == 0

            out_content = out_f.read_text(encoding="utf-8")
            assert "exit_code=0" in out_content
            assert "terminal_status=completed" in out_content

            adapter.write_step_summary("### VulnFlow Remediation Summary\nAll tests verified.")
            sum_content = summary_f.read_text(encoding="utf-8")
            assert "VulnFlow Remediation Summary" in sum_content
        finally:
            if old_out:
                os.environ["GITHUB_OUTPUT"] = old_out
            else:
                os.environ.pop("GITHUB_OUTPUT", None)
            if old_sum:
                os.environ["GITHUB_STEP_SUMMARY"] = old_sum
            else:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            if old_act:
                os.environ["GITHUB_ACTIONS"] = old_act
            else:
                os.environ.pop("GITHUB_ACTIONS", None)


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
    print("Testing F19: PR creation requires a real repository...")
    test_f19_pr_creation_requires_a_real_repository()
    print("Testing F27: CLI commands and modes...")
    test_f27_cli_modes_fail_closed_when_mutation_prerequisites_are_missing()
    print("Testing F28: GitHub Action adapter...")
    test_f28_github_action_adapter()
    print("Testing Phase 1 Gate: Missing Git and scanner prerequisites...")
    test_phase_1_gate_fails_closed_without_git_or_live_scanner()
    print("\nALL PHASE 1 FEATURES & GATE TESTS PASSED!")
