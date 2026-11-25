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


def test_phase_0_gate_rejects_synthetic_mutation_success() -> None:
    """
    PHASE 0 GATE TEST:
    A mutation run over a fixture directory must stop when real git/scanner
    prerequisites are unavailable; stub contracts cannot authorize side effects.
    """
    from vulnflow.agents.planner import default_planner_agent
    default_planner_agent.enable_llm = False

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

    # 1. Pipeline fails closed before mutating an untracked fixture directory.
    assert final_state.terminal_status == "error"
    assert final_state.exit_code != 0

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

    # 5. No patch, verification, or PR may be fabricated.
    assert final_state.patches == []
    assert final_state.test_results == []
    assert final_state.pull_requests == []
    assert final_state.verification_results == []

    # 8. Audit trail recorded events
    assert len(final_state.audit_events) >= 8
    event_types = [e["event_type"] for e in final_state.audit_events]
    assert "INGESTION_COMPLETED" in event_types
    assert "DEDUPLICATION_COMPLETED" in event_types
    assert "ROOTCAUSE_ANALYSIS_COMPLETED" in event_types
    assert "POLICY_EVALUATION_COMPLETED" in event_types
    assert "PLANS_GENERATED" in event_types
    assert "RUN_FAILED" in event_types


def test_fastmcp_server_protocol() -> None:
    """Verify all MCP servers implement formal FastMCP tool registration, schemas, and dispatch."""
    from vulnflow.mcp_servers.build_server import mcp as build_mcp
    from vulnflow.mcp_servers.git_server import mcp as git_mcp
    from vulnflow.mcp_servers.knowledge_server import mcp as knowledge_mcp
    from vulnflow.mcp_servers.notify_server import mcp as notify_mcp
    from vulnflow.mcp_servers.policy_server import mcp as policy_mcp
    from vulnflow.mcp_servers.registry_server import mcp as registry_mcp
    from vulnflow.mcp_servers.scan_server import mcp as scan_mcp
    from vulnflow.mcp_servers.ticket_server import mcp as ticket_mcp

    servers = [
        ("policy", policy_mcp, ["policy_check", "policy_candidates"]),
        ("git", git_mcp, ["git_clone", "git_branch", "git_patch", "git_commit", "git_replace_text", "pr_create"]),
        ("build", build_mcp, ["build_test", "npm_update_lock"]),
        ("knowledge", knowledge_mcp, ["advisory_search", "graph_query", "root_cause", "blast_radius"]),
        ("scan", scan_mcp, ["scan_run", "scan_verify", "scan_diff"]),
        ("registry", registry_mcp, ["registry_check"]),
        ("ticket", ticket_mcp, ["ticket_create"]),
        ("notify", notify_mcp, ["approval_request", "notify_send"]),
    ]

    for name, srv, expected_tools in servers:
        tools = srv.list_tools()
        tool_names = [t["name"] for t in tools]
        for exp in expected_tools:
            assert exp in tool_names, f"Expected tool '{exp}' not registered on {name} MCP server"
            # Verify inputSchema
            tool_meta = next(t for t in tools if t["name"] == exp)
            assert "inputSchema" in tool_meta
            assert tool_meta["inputSchema"]["type"] == "object"
            assert "properties" in tool_meta["inputSchema"]

    # Test call_tool on FastMCP server
    res = policy_mcp.call_tool("policy_check", {"package": "npm:lodash", "version": "4.17.21"})
    assert res["status"] == "approved"

    ticket_res = ticket_mcp.call_tool("ticket_create", {"ticket_type": "policy_exception", "context": {"target_package": "Django"}})
    assert ticket_res["status"] == "created"
    assert "ticket_id" in ticket_res


if __name__ == "__main__":
    print("Running test_finding_contract_serialization...")
    test_finding_contract_serialization()
    print("Running test_remediation_plan_contract...")
    test_remediation_plan_contract()
    print("Running test_policy_contract...")
    test_policy_contract()
    print("Running test_stub_mcp_servers...")
    test_stub_mcp_servers()
    print("Running test_fastmcp_server_protocol...")
    test_fastmcp_server_protocol()
    print("Running test_phase_0_gate_stubbed_run...")
    test_phase_0_gate_stubbed_run()
    print("\nALL CONTRACT & PHASE 0 GATE TESTS PASSED!")
