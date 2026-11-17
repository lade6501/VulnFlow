"""
tests/contract/test_contracts.py
Validates serialization, field types, and immutability of data contracts.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)
from vulnflow.contracts.policy import (
    ApprovedPackagesPolicy,
    PackagePolicyEntry,
    PolicyRules,
    PolicyStatus,
)
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
    VerificationResult,
)
from vulnflow.contracts.state import VulnFlowState
from vulnflow.mcp_servers.stubs import stub_mcp
from vulnflow.observability.audit_log import audit_logger
from vulnflow.orchestrator.graph import run_workflow


def test_finding_contract_serialization() -> None:
    """Test Finding model serialization and roundtrip dictionary conversion."""
    fnd_id = compute_finding_id("trivy", "/workspace", "npm:lodash", "4.17.15", ["CVE-2020-8203"])
    assert fnd_id.startswith("FND-")

    loc = LocationInfo(file_path="package.json", line=10, dependency_path=["lodash"])
    finding = Finding(
        id=fnd_id,
        type=FindingType.VULN,
        scanner="trivy",
        repo="/workspace",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        location=loc,
        fix_versions=["4.17.21"],
    )

    data = finding.to_dict()
    assert data["id"] == fnd_id
    assert data["type"] == "vuln"
    assert data["severity"] == "high"
    assert data["package"] == "npm:lodash"

    restored = Finding.from_dict(data)
    assert restored.id == finding.id
    assert restored.type == FindingType.VULN
    assert restored.severity == SeverityLevel.HIGH
    assert restored.location.file_path == "package.json"


def test_remediation_plan_contract() -> None:
    """Test RemediationPlan serialization and risk tier validation."""
    plan = RemediationPlan(
        finding_ids=["FND-12345"],
        root_cause_id="npm:lodash",
        action=RemediationAction.BUMP,
        target_version="4.17.21",
        target_package="npm:lodash",
        policy_result=PolicyResult(status="approved", rule_matched="approved_versions:>=4.17.21"),
        risk_tier=RiskTier.AUTO,
        requires_approval=False,
        rationale="Upgrade lodash to 4.17.21",
    )

    data = plan.to_dict()
    assert data["action"] == "bump"
    assert data["risk_tier"] == "auto"
    assert data["policy_result"]["status"] == "approved"

    restored = RemediationPlan.from_dict(data)
    assert restored.action == RemediationAction.BUMP
    assert restored.risk_tier == RiskTier.AUTO
    assert restored.target_version == "4.17.21"


def test_policy_contract() -> None:
    """Test policy structures and parsing."""
    pol = ApprovedPackagesPolicy(
        packages=[
            PackagePolicyEntry(name="lodash", approved_versions=">=4.17.21", status=PolicyStatus.APPROVED),
            PackagePolicyEntry(name="left-pad", status=PolicyStatus.BANNED, reason="obsolete"),
        ],
        rules=PolicyRules(unknown_package="require_approval"),
    )

    data = pol.to_dict()
    assert len(data["packages"]) == 2
    assert data["packages"][0]["name"] == "lodash"
    assert data["packages"][1]["status"] == "banned"


def test_stub_mcp_servers() -> None:
    """Verify stub MCP tools return contract-compliant canned data."""
    # Policy tool
    res_lodash = stub_mcp.policy_check("lodash", "4.17.21")
    assert res_lodash["status"] == "approved"

    res_banned = stub_mcp.policy_check("left-pad", "1.3.0")
    assert res_banned["status"] == "banned"

    res_deprecated = stub_mcp.policy_check("moment", "2.29.1")
    assert res_deprecated["status"] == "deprecated"
    assert res_deprecated["replacement"] == "date-fns"

    # Scanner tools
    scan_res = stub_mcp.scan_run("sample-repo", "trivy")
    assert len(scan_res) >= 1
    assert scan_res[0]["package"] == "npm:lodash"

    # Git & PR tools
    pr_res = stub_mcp.pr_create("vulnflow/fix-lodash", "body")
    assert pr_res["status"] == "opened"
    assert "pr_url" in pr_res

    # Build & test tool
    test_res = stub_mcp.build_test("sample-repo", "main")
    assert test_res["build_clean"] is True


def test_phase_0_gate_stubbed_run() -> None:
    """
    PHASE 0 GATE TEST:
    A stubbed run goes from a sample scanner report to a fake PR through the orchestrator,
    using only stub tools.
    """
    fixture_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_trivy_report.json")
    repo_path = str(Path(__file__).resolve().parent.parent.parent / "samples" / "npm-simple-bump")

    state = VulnFlowState(
        repo_path=repo_path,
        report_path=fixture_path,
        scanner="trivy",
        mode="pr",
        ecosystem="npm",
    )

    final_state = run_workflow(state)

    # 1. Pipeline reached terminal success
    assert final_state.terminal_status == "completed"
    assert final_state.exit_code == 0

    # 2. Findings ingested and deduped
    assert len(final_state.findings) >= 1
    assert len(final_state.deduped_findings) >= 1
    assert final_state.findings[0].package == "npm:lodash"

    # 3. Root cause grouped
    assert len(final_state.root_cause_groups) >= 1

    # 4. Remediation plan generated and approved
    assert len(final_state.plans) >= 1
    plan = final_state.plans[0]
    assert plan.action == RemediationAction.BUMP
    assert plan.target_version == "4.17.21"
    assert len(final_state.approved_plans) >= 1

    # 5. Patch applied and build tested
    assert len(final_state.patches) >= 1
    assert len(final_state.test_results) >= 1
    assert final_state.test_results[0]["build_clean"] is True

    # 6. Pull request opened
    assert len(final_state.pull_requests) >= 1
    pr = final_state.pull_requests[0]
    assert pr["status"] == "opened"
    assert "pr_url" in pr
    assert "https://github.com" in pr["pr_url"]

    # 7. Verification rescan completed cleanly
    assert len(final_state.verification_results) >= 1
    ver = final_state.verification_results[0]
    assert ver["verified"] is True
    assert ver["rescan_clean"] is True

    # 8. Audit trail recorded events
    assert len(final_state.audit_events) >= 8
    event_types = [e["event_type"] for e in final_state.audit_events]
    assert "INGESTION_COMPLETED" in event_types
    assert "DEDUPLICATION_COMPLETED" in event_types
    assert "ROOTCAUSE_ANALYSIS_COMPLETED" in event_types
    assert "POLICY_EVALUATION_COMPLETED" in event_types
    assert "PLANS_GENERATED" in event_types
    assert "PATCHES_APPLIED" in event_types
    assert "BUILD_TEST_COMPLETED" in event_types
    assert "PR_CREATED" in event_types
    assert "VERIFICATION_COMPLETED" in event_types


if __name__ == "__main__":
    print("Running test_finding_contract_serialization...")
    test_finding_contract_serialization()
    print("Running test_remediation_plan_contract...")
    test_remediation_plan_contract()
    print("Running test_policy_contract...")
    test_policy_contract()
    print("Running test_stub_mcp_servers...")
    test_stub_mcp_servers()
    print("Running test_phase_0_gate_stubbed_run...")
    test_phase_0_gate_stubbed_run()
    print("\nALL CONTRACT & PHASE 0 GATE TESTS PASSED!")
