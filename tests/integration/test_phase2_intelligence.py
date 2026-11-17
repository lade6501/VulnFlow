"""
tests/integration/test_phase2_intelligence.py
End-to-end integration tests for Phase 2 intelligence, graph queries, and root cause analysis.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from vulnflow.adapters.ecosystem.npm import NPMAdapter
from vulnflow.adapters.input.trivy import TrivyAdapter
from vulnflow.agents.fixer import FixerAgent, default_fixer_agent
from vulnflow.agents.planner import PlannerAgent
from vulnflow.agents.rootcause import RootCauseAgent, default_rootcause_agent
from vulnflow.agents.verifier import default_verifier_agent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import (
    RemediationAction,
    RemediationPlan,
    RiskTier,
    VerificationResult,
)
from vulnflow.contracts.state import VulnFlowState
from vulnflow.knowledge.graph.build_from_tree import (
    DependencyGraph,
    build_graph_from_manifest,
    build_graph_from_tree_dict,
)
from vulnflow.knowledge.graph.queries import find_blast_radius, find_root_cause
from vulnflow.core.risk import (
    calculate_risk_tier,
    classify_semver_bump,
    enforce_stricter_tier,
)
from vulnflow.mcp_servers.knowledge_server import (
    advisory_search as mcp_advisory_search,
    blast_radius as mcp_blast_radius,
    graph_query,
    root_cause as mcp_root_cause,
)
from vulnflow.mcp_servers.registry_server import registry_check, registry_server
from vulnflow.mcp_servers.ticket_server import ticket_server
from vulnflow.orchestrator.approval import global_approval_gate, load_run_state, save_run_state
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.reporting.json_report import generate_json_report, write_json_report
from vulnflow.reporting.markdown import generate_markdown_report, write_markdown_report


def test_f05_graph_builder_and_queries() -> None:
    """F05: Test constructing dependency graphs from manifests and lockfiles."""
    fixtures_dir = Path(__file__).resolve().parent.parent.parent / "samples" / "npm-transitive-only"
    manifest_p = fixtures_dir / "package.json"
    lock_p = fixtures_dir / "package-lock.json"

    graph = build_graph_from_manifest(manifest_p, lock_p)
    assert "npm:my-frontend-lib" in graph.direct_dependencies or "my-frontend-lib" in graph.direct_dependencies

    # Query root cause for transitive lodash
    res = find_root_cause("npm:lodash", version="4.17.15", graph=graph)
    assert res["is_direct"] is False
    assert "my-frontend-lib" in res["root_cause_package"]
    assert res["root_cause_id"] == "PKG-npm:my-frontend-lib"


def test_f05_root_cause_agent_explanation() -> None:
    """F05: Test RootCauseAgent explanations and transitive collapse."""
    agent = RootCauseAgent()
    finding1 = Finding(
        id="FND-001",
        type=FindingType.VULN,
        scanner="trivy",
        repo="test-repo",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        location=LocationInfo(
            file_path="package.json",
            dependency_path=["my-frontend-lib", "lodash"],
        ),
    )
    finding2 = Finding(
        id="FND-002",
        type=FindingType.VULN,
        scanner="trivy",
        repo="test-repo",
        package="npm:set-value",
        version="2.0.0",
        cve=["CVE-2019-10744"],
        severity=SeverityLevel.HIGH,
        location=LocationInfo(
            file_path="package.json",
            dependency_path=["my-frontend-lib", "set-value"],
        ),
    )

    # 1. Individual analysis
    analysis = agent.analyze_finding(finding1)
    assert analysis.is_direct is False
    assert analysis.root_cause_package == "npm:my-frontend-lib"
    assert "transitive dependency" in analysis.explanation.lower()
    assert "my-frontend-lib" in analysis.explanation

    # 2. Grouping collapses multiple transitive findings to one root cause parent
    groups = agent.group_findings([finding1, finding2])
    assert len(groups) == 1
    grp = groups[0]
    assert grp["root_cause_id"] == "PKG-npm:my-frontend-lib"
    assert len(grp["findings"]) == 2


def test_f05_transitive_only_end_to_end_workflow() -> None:
    """F05 acceptance criteria: root_cause collapses a transitive-only sample to one parent dependency."""
    repo_path = str(Path(__file__).resolve().parent.parent.parent / "samples" / "npm-transitive-only")
    report_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_transitive_report.json")

    state = VulnFlowState(
        repo_path=repo_path,
        report_path=report_path,
        scanner="trivy",
        mode="report",
    )
    result = run_workflow(state)

    # Validate that transitive finding in lodash was collapsed under my-frontend-lib
    assert len(result.findings) == 1
    assert result.findings[0].package == "npm:lodash"
    assert len(result.root_cause_groups) == 1

    rc_group = result.root_cause_groups[0]
    assert rc_group["root_cause_id"] == "PKG-npm:my-frontend-lib"
    assert rc_group["is_direct"] is False
    assert "transitive" in rc_group["explanation"].lower()


def test_f06_blast_radius_query() -> None:
    """F06 acceptance criteria: blast_radius returns services and repos affected on seeded graph."""
    # 1. Query lodash blast radius via MCP tool
    res = mcp_blast_radius("npm:lodash", version="4.17.21")
    assert "services" in res
    assert "repos" in res
    assert len(res["services"]) >= 3
    assert "payment-api" in res["services"]
    assert "order-worker" in res["services"]
    assert "report-generator" in res["services"]  # Transitive dependent via frontend-ui

    assert "payment-service" in res["repos"]
    assert "order-service" in res["repos"]
    assert "reporting-service" in res["repos"]
    assert res["blast_radius_tier"] == "HIGH"

    # 2. Query moment blast radius via graph_query dispatcher
    res_moment = graph_query("blast_radius", {"package": "npm:moment"})
    assert "order-worker" in res_moment["services"]
    assert "order-service" in res_moment["repos"]
    assert "payment-api" not in res_moment["services"]
    assert res_moment["blast_radius_tier"] == "MEDIUM"


def test_f07_advisory_search_and_plan_citation() -> None:
    """F07 acceptance criteria: advisory_search returns right chunks filtered by package; plan rationale cites chunk IDs."""
    # 1. Search advisories for lodash
    results = mcp_advisory_search("prototype pollution", package="npm:lodash", ecosystem="npm")
    assert len(results) >= 1
    chunk = results[0]
    assert "chunk_id" in chunk
    assert "lodash" in chunk["package"].lower()
    assert "CVE-2020-8203" in chunk.get("cve", "") or "CVE-2020-8203" in str(chunk.get("aliases", []))

    # 2. Verify cross-package filtering: moment query should not return lodash chunks
    moment_results = mcp_advisory_search("prototype pollution", package="npm:moment", ecosystem="npm")
    for r in moment_results:
        assert "lodash" not in r["package"].lower()

    # 3. Test PlannerAgent citing chunk IDs in rationale
    planner = PlannerAgent()
    finding = Finding(
        id="FND-100",
        type=FindingType.VULN,
        scanner="trivy",
        repo="test-repo",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        fix_versions=["4.17.21"],
        location=LocationInfo(file_path="package.json"),
    )
    plan = planner.plan_remediation(
        root_cause_id="npm:lodash",
        findings=[finding],
        advisories=results,
        ecosystem="npm",
    )
    assert plan.target_version == "4.17.21"
    assert len(plan.evidence) >= 1
    # Check that rationale explicitly cites the chunk ID
    expected_chunk_id = chunk["chunk_id"]
    assert expected_chunk_id in plan.rationale or chunk.get("cve") in plan.rationale


def test_f08_risk_scoring_and_tiering() -> None:
    """F08 acceptance criteria: Tier is computed by code from policy, bump size, tests and evidence; model can only make it stricter."""
    # 1. SemVer bump classification
    assert classify_semver_bump("4.17.15", "4.17.21") == "patch"
    assert classify_semver_bump("4.17.15", "4.18.0") == "minor"
    assert classify_semver_bump("4.17.15", "5.0.0") == "major"

    # 2. Baseline code calculations
    # Safe patch on approved package -> AUTO
    tier_patch = calculate_risk_tier("4.17.15", "4.17.21", policy_status=PolicyStatus.APPROVED)
    assert tier_patch == RiskTier.AUTO

    # Major bump -> REVIEW
    tier_major = calculate_risk_tier("4.17.15", "5.0.0", policy_status=PolicyStatus.APPROVED)
    assert tier_major == RiskTier.REVIEW

    # Banned package -> BLOCKED
    tier_banned = calculate_risk_tier("1.3.0", "1.3.1", policy_status=PolicyStatus.BANNED)
    assert tier_banned == RiskTier.BLOCKED

    # Test failure -> REVIEW
    tier_failed_tests = calculate_risk_tier("4.17.15", "4.17.21", policy_status=PolicyStatus.APPROVED, tests_passed=False)
    assert tier_failed_tests == RiskTier.REVIEW

    # 3. Model override rules: Model can make tier stricter, NEVER looser
    # Stricter: AUTO -> REVIEW (allowed)
    assert enforce_stricter_tier(RiskTier.AUTO, "review") == RiskTier.REVIEW
    assert enforce_stricter_tier(RiskTier.AUTO, "blocked") == RiskTier.BLOCKED

    # Looser: REVIEW -> AUTO (FORBIDDEN, must remain REVIEW)
    assert enforce_stricter_tier(RiskTier.REVIEW, "auto") == RiskTier.REVIEW

    # Looser: BLOCKED -> AUTO / REVIEW (FORBIDDEN, must remain BLOCKED)
    assert enforce_stricter_tier(RiskTier.BLOCKED, "auto") == RiskTier.BLOCKED
    assert enforce_stricter_tier(RiskTier.BLOCKED, "review") == RiskTier.BLOCKED


def test_f09_findings_report_markdown_and_json(tmp_path_factory: Any = None) -> None:
    """F09 acceptance criteria: Markdown and JSON reports group findings by root cause and show policy result and tier."""
    import tempfile

    repo_path = str(Path(__file__).resolve().parent.parent.parent / "samples" / "npm-simple-bump")
    report_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_trivy_report.json")

    state = VulnFlowState(repo_path=repo_path, report_path=report_path, mode="pr")
    result = run_workflow(state)

    # 1. Test Markdown Report
    md_content = generate_markdown_report(result)
    assert "# 🛡️ VulnFlow Vulnerability Remediation Report" in md_content
    assert "Executive Summary" in md_content
    assert "Findings Grouped by Root Cause" in md_content
    assert "npm:lodash" in md_content
    assert "AUTO" in md_content
    assert "APPROVED" in md_content

    # 2. Test JSON Report
    json_data = generate_json_report(result)
    assert json_data["schema_version"] == "1.0.0"
    assert json_data["status"] == "completed"
    assert len(json_data["root_cause_groups"]) >= 1

    rc_grp = json_data["root_cause_groups"][0]
    assert "root_cause_id" in rc_grp
    assert "risk_tier" in rc_grp
    assert "policy_result" in rc_grp
    assert len(rc_grp["findings"]) >= 1

    # 3. Test writing reports to disk
    with tempfile.TemporaryDirectory() as tmp_dir:
        md_file = Path(tmp_dir) / "report.md"
        json_file = Path(tmp_dir) / "report.json"
        write_markdown_report(result, md_file)
        write_json_report(result, json_file)
        assert md_file.exists() and md_file.stat().st_size > 0
        assert json_file.exists() and json_file.stat().st_size > 0


def test_f12_replacement_proposals() -> None:
    """F12 acceptance criteria: Deprecated or banned package gets the approved replacement in the plan with tier review."""
    import json
    import tempfile

    planner = PlannerAgent(enable_llm=False)
    # moment is deprecated in policies/approved_packages.yaml, replacement is date-fns
    finding = Finding(
        id="FND-MOMENT-1",
        type=FindingType.VULN,
        scanner="trivy",
        repo="test-repo",
        package="npm:moment",
        version="2.29.1",
        cve=["CVE-2022-24785"],
        severity=SeverityLevel.HIGH,
        fix_versions=["2.29.2"],
        location=LocationInfo(file_path="package.json"),
    )
    plan = planner.plan_remediation(
        root_cause_id="npm:moment",
        findings=[finding],
        ecosystem="npm",
    )
    assert plan.action == RemediationAction.REPLACE
    assert plan.target_package == "date-fns"
    assert plan.risk_tier == RiskTier.REVIEW
    assert plan.requires_approval is True
    assert "date-fns" in plan.rationale

    # Test manifest replacement via NPMAdapter
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_pkg = Path(tmp_dir) / "package.json"
        tmp_pkg.write_text(json.dumps({"dependencies": {"moment": "2.29.1"}}), encoding="utf-8")
        changed, diff = NPMAdapter.replace_dependency(tmp_pkg, "moment", "date-fns", "latest")
        assert changed is True
        content = json.loads(tmp_pkg.read_text(encoding="utf-8"))
        assert "moment" not in content["dependencies"]
        assert "date-fns" in content["dependencies"]


def test_f13_exception_workflow() -> None:
    """F13 acceptance criteria: When only unapproved fixes exist, a ticket with CVE context is created, no PR is opened, and a rerun creates no duplicate."""
    repo_path = str(Path(__file__).resolve().parent.parent.parent / "samples" / "npm-banned-package")
    report_path = str(Path(__file__).resolve().parent.parent.parent / "data" / "fixtures" / "sample_banned_report.json")

    state = VulnFlowState(repo_path=repo_path, report_path=report_path, mode="pr")
    result = run_workflow(state)

    # 1. Blocked status, exit code 20, no PR opened
    assert result.terminal_status == "blocked_policy"
    assert result.exit_code == 20
    assert len(result.pull_requests) == 0
    assert result.exception_ticket is not None

    ticket = result.exception_ticket
    assert ticket.get("status") in ("created", "existing")
    assert "SEC-" in ticket.get("ticket_id", "")
    # Check CVE context included in ticket
    cves = ticket.get("cves", ticket.get("context", {}).get("cves", []))
    assert "CVE-2020-28469" in str(cves) or "CVE-2020-28469" in ticket.get("summary", "")

    # 2. Rerun creates no duplicate ticket (idempotency)
    state_rerun = VulnFlowState(repo_path=repo_path, report_path=report_path, mode="pr")
    result_rerun = run_workflow(state_rerun)
    assert result_rerun.exception_ticket is not None
    assert result_rerun.exception_ticket.get("ticket_id") == ticket.get("ticket_id")
    assert len(result_rerun.pull_requests) == 0


def test_f14_registry_availability_check() -> None:
    """F14 acceptance criteria: registry_check confirms target version exists in configured registry before a PR."""
    # 1. Existing package versions confirm availability
    res_avail = registry_check("lodash", "4.17.21", "npm")
    assert res_avail.get("available") is True

    # 2. Non-existent synthetic version rejected
    res_unavail = registry_check("lodash", "999.999.999", "npm")
    assert res_unavail.get("available") is False
    assert "not found" in res_unavail.get("reason", "").lower()

    # 3. Candidate filtering in PlannerAgent filters out unavailable versions
    registry_server.set_availability("test-pkg", "2.0.0", False)
    registry_server.set_availability("test-pkg", "1.5.0", True)
    try:
        finding = Finding(
            id="FND-REG-1",
            type=FindingType.VULN,
            scanner="trivy",
            repo="test-repo",
            package="npm:test-pkg",
            version="1.0.0",
            cve=["CVE-2024-0001"],
            severity=SeverityLevel.HIGH,
            fix_versions=["2.0.0", "1.5.0"],
            location=LocationInfo(file_path="package.json"),
        )
        planner = PlannerAgent(enable_llm=False)
        plan = planner.plan_remediation(
            root_cause_id="npm:test-pkg",
            findings=[finding],
            ecosystem="npm",
        )
        # 2.0.0 was filtered out due to registry unavailability, 1.5.0 chosen
        assert plan.target_version == "1.5.0"
    finally:
        registry_server.clear_overrides()


def test_f20_self_correction_loop() -> None:
    """F20 acceptance criteria: Test failure retries with error context up to configured limit, then escalates to review."""
    agent = FixerAgent()
    plan = RemediationPlan(
        id="PLAN-FIX-1",
        finding_ids=["FND-1"],
        root_cause_id="npm:lodash",
        action=RemediationAction.BUMP,
        target_version="5.0.0",
        target_package="npm:lodash",
        risk_tier=RiskTier.AUTO,
        requires_approval=False,
    )

    # 1. Retry 0: test failure with error context triggers fallback version
    error_output = "TypeError: lodash.cloneDeep is not a function\n    at app.js:42:15"
    p1 = agent.analyze_failure_and_correct(plan, error_output, retry_count=0, max_retries=2)
    assert p1.target_version == "4.99.9"
    assert "Self-Correction Retry #1" in p1.rationale
    assert "TypeError" in p1.rationale

    # 2. Retries exhausted (retry_count == 2): escalates to REVIEW tier
    p2 = agent.analyze_failure_and_correct(plan, error_output, retry_count=2, max_retries=2)
    assert p2.risk_tier == RiskTier.REVIEW
    assert p2.requires_approval is True
    assert "Self-Correction Exhausted" in p2.rationale


def test_f21_human_approval_gate() -> None:
    """F21 acceptance criteria: Run pauses for review-tier plans, persists state, and resumes on approve or stops on reject with a stored reason."""
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_dir = Path(tmp_dir)
        (repo_dir / "package.json").write_text(json.dumps({
            "name": "test-approval-repo",
            "version": "1.0.0",
            "dependencies": {"my-unknown-lib": "1.0.0"},
            "scripts": {"test": "node -e \"process.exit(0)\""}
        }), encoding="utf-8")
        report_f = repo_dir / "report.json"
        report_f.write_text(json.dumps([{
            "package": "npm:my-unknown-lib",
            "version": "1.0.0",
            "cve": ["CVE-2024-9999"],
            "severity": "HIGH",
            "file_path": "package.json",
            "fix_versions": ["1.1.0"]
        }]), encoding="utf-8")

        # 1. Initial run: my-unknown-lib is not on whitelist, plan is REVIEW tier -> halts with exit code 10
        state = VulnFlowState(repo_path=str(repo_dir), report_path=str(report_f), mode="pr")
        result = run_workflow(state)
        assert result.terminal_status == "pending_approval"
        assert result.exit_code == 10
        assert len(result.pending_approval_plans) >= 1
        assert len(result.approved_plans) == 0
        assert len(result.pull_requests) == 0

        # State is persisted to disk
        paused_state = load_run_state(repo_path=str(repo_dir))
        assert paused_state is not None
        assert paused_state.terminal_status == "pending_approval"

        plan_id = result.pending_approval_plans[0].id

        # 2. Human rejection stops with stored reason
        global_approval_gate.record_decision(
            plan_id=plan_id,
            approved=False,
            reviewer="lead-sec@corp.internal",
            reason="Library not vetted for production use",
            repo_path=str(repo_dir),
        )
        assert global_approval_gate.is_rejected(plan_id, repo_path=str(repo_dir)) is True
        dec = global_approval_gate.get_decision(plan_id, repo_path=str(repo_dir))
        assert dec["reason"] == "Library not vetted for production use"

        # 3. Human approval resumes run and creates PR
        global_approval_gate.record_decision(
            plan_id=plan_id,
            approved=True,
            reviewer="lead-sec@corp.internal",
            reason="Authorized by security committee",
            repo_path=str(repo_dir),
        )
        assert global_approval_gate.is_approved(plan_id, repo_path=str(repo_dir)) is True

        resumed_result = run_workflow(paused_state)
        assert resumed_result.terminal_status == "completed"
        assert resumed_result.exit_code == 0
        assert len(resumed_result.approved_plans) >= 1
        assert len(resumed_result.pull_requests) >= 1


def test_f22_verification_agent() -> None:
    """F22 acceptance criteria: scan_diff and policy recheck on full tree decide resolved or failed in code; failed verify never reports success."""
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_dir = Path(tmp_dir)
        (repo_dir / "package.json").write_text(json.dumps({
            "name": "verify-test",
            "version": "1.0.0",
            "dependencies": {"lodash": "4.17.21"},
            "scripts": {"test": "node -e \"process.exit(0)\""}
        }), encoding="utf-8")

        finding = Finding(
            id="FND-VER-1",
            type=FindingType.VULN,
            scanner="trivy",
            repo="test-repo",
            package="npm:lodash",
            version="4.17.15",
            cve=["CVE-2020-8203"],
            severity=SeverityLevel.HIGH,
            location=LocationInfo(file_path="package.json"),
        )
        plan = RemediationPlan(
            id="PLAN-VER-1",
            finding_ids=["FND-VER-1"],
            root_cause_id="npm:lodash",
            action=RemediationAction.BUMP,
            target_version="4.17.21",
            target_package="npm:lodash",
        )

        # 1. Clean verification: clean rescan, tests passed, policy recheck passed -> verified = True
        res_clean = default_verifier_agent.verify_remediation(
            repo_path=str(repo_dir),
            plans=[plan],
            before_findings=[finding],
            test_results=[{"passed": True, "build_clean": True}],
            after_finding_ids=[],
        )
        assert res_clean.verified is True
        assert res_clean.rescan_clean is True
        assert "FND-VER-1" in res_clean.resolved_finding_ids
        assert len(res_clean.new_finding_ids) == 0

        # 2. Residual finding remaining -> verified = False (never report success)
        res_residual = default_verifier_agent.verify_remediation(
            repo_path=str(repo_dir),
            plans=[plan],
            before_findings=[finding],
            test_results=[{"passed": True, "build_clean": True}],
            after_finding_ids=["FND-VER-1"],
        )
        assert res_residual.verified is False
        assert res_residual.rescan_clean is False

        # 3. Failed tests -> verified = False
        res_fail_tests = default_verifier_agent.verify_remediation(
            repo_path=str(repo_dir),
            plans=[plan],
            before_findings=[finding],
            test_results=[{"passed": False, "build_clean": False}],
            after_finding_ids=[],
        )
        assert res_fail_tests.verified is False
        assert res_fail_tests.tests_passed is False

        # 4. Manifest with banned dependency -> policy recheck fails -> verified = False
        (repo_dir / "package.json").write_text(json.dumps({
            "dependencies": {"left-pad": "1.3.0"}
        }), encoding="utf-8")
        res_banned = default_verifier_agent.verify_remediation(
            repo_path=str(repo_dir),
            plans=[plan],
            before_findings=[finding],
            test_results=[{"passed": True, "build_clean": True}],
            after_finding_ids=[],
        )
        assert res_banned.verified is False
        assert res_banned.policy_recheck_passed is False


def test_phase_2_gate_end_to_end() -> None:
    """Phase 2 Gate: All policy and vulnerability sample scenarios run end to end with real knowledge tools, including unapproved-fix case producing a ticket and no PR."""
    base_dir = Path(__file__).resolve().parent.parent.parent

    # Scenario 1: Approved simple bump produces verified PR
    s1_repo = str(base_dir / "samples" / "npm-simple-bump")
    s1_report = str(base_dir / "data" / "fixtures" / "sample_trivy_report.json")
    st1 = VulnFlowState(repo_path=s1_repo, report_path=s1_report, mode="pr")
    res1 = run_workflow(st1)
    assert res1.terminal_status == "completed"
    assert res1.exit_code == 0
    assert len(res1.pull_requests) >= 1

    # Scenario 2: Transitive-only vulnerability collapses to direct root cause
    s2_repo = str(base_dir / "samples" / "npm-transitive-only")
    s2_report = str(base_dir / "data" / "fixtures" / "sample_transitive_report.json")
    st2 = VulnFlowState(repo_path=s2_repo, report_path=s2_report, mode="report")
    res2 = run_workflow(st2)
    assert res2.terminal_status == "completed"
    assert "my-frontend-lib" in res2.root_cause_groups[0]["root_cause_id"]

    # Scenario 3: Deprecated package produces replacement proposal
    s3_repo = str(base_dir / "samples" / "npm-deprecated-package")
    s3_report = str(base_dir / "data" / "fixtures" / "sample_deprecated_report.json")
    st3 = VulnFlowState(repo_path=s3_repo, report_path=s3_report, mode="report")
    res3 = run_workflow(st3)
    assert any(p.action == RemediationAction.REPLACE and p.target_package == "date-fns" for p in res3.plans)

    # Scenario 4: Unapproved fix / banned package produces exception ticket and NO PR (idempotent)
    s4_repo = str(base_dir / "samples" / "npm-banned-package")
    s4_report = str(base_dir / "data" / "fixtures" / "sample_banned_report.json")
    st4 = VulnFlowState(repo_path=s4_repo, report_path=s4_report, mode="pr")
    res4 = run_workflow(st4)
    assert res4.terminal_status == "blocked_policy"
    assert res4.exit_code == 20
    assert len(res4.pull_requests) == 0
    assert res4.exception_ticket is not None
    assert "CVE-2020-28469" in str(res4.exception_ticket)


if __name__ == "__main__":
    print("Running test_f05_graph_builder_and_queries...")
    test_f05_graph_builder_and_queries()
    print("Running test_f05_root_cause_agent_explanation...")
    test_f05_root_cause_agent_explanation()
    print("Running test_f05_transitive_only_end_to_end_workflow...")
    test_f05_transitive_only_end_to_end_workflow()
    print("Running test_f06_blast_radius_query...")
    test_f06_blast_radius_query()
    print("Running test_f07_advisory_search_and_plan_citation...")
    test_f07_advisory_search_and_plan_citation()
    print("Running test_f08_risk_scoring_and_tiering...")
    test_f08_risk_scoring_and_tiering()
    print("Running test_f09_findings_report_markdown_and_json...")
    test_f09_findings_report_markdown_and_json()
    print("Running test_f12_replacement_proposals...")
    test_f12_replacement_proposals()
    print("Running test_f13_exception_workflow...")
    test_f13_exception_workflow()
    print("Running test_f14_registry_availability_check...")
    test_f14_registry_availability_check()
    print("Running test_f20_self_correction_loop...")
    test_f20_self_correction_loop()
    print("Running test_f21_human_approval_gate...")
    test_f21_human_approval_gate()
    print("Running test_f22_verification_agent...")
    test_f22_verification_agent()
    print("Running test_phase_2_gate_end_to_end...")
    test_phase_2_gate_end_to_end()
    print("\nALL PHASE 2 FEATURES & GATE TESTS PASSED SUCCESSFULLY!")
