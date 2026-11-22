"""
tests/unit/test_reporting.py
Validates canonical F43 reporting, evidence rules, rendering, and CLI isolation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from vulnflow.agents.planner import PlannerAgent
from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
)
from vulnflow.contracts.report import EvidenceAvailability, RunReport, StepState
from vulnflow.contracts.state import VulnFlowState
from vulnflow.reporting.builder import build_run_report, version_satisfies
from vulnflow.reporting.html_report import generate_html_report
from vulnflow.reporting.json_report import generate_json_report
from vulnflow.reporting.markdown import generate_markdown_report

FIXED_TIME = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def report_state(mode: str = "pr", *, executed_rescan: bool = True) -> VulnFlowState:
    """Build fixed persisted state with explicit successful evidence events."""
    finding = Finding(
        id="FND-LODASH",
        type=FindingType.VULN,
        scanner="trivy",
        repo="sample",
        package="npm:lodash",
        version="4.17.15",
        cve=["CVE-2020-8203"],
        severity=SeverityLevel.HIGH,
        location=LocationInfo(file_path="package.json", dependency_path=["lodash"]),
        fix_versions=["4.17.21"],
    )
    plan = RemediationPlan(
        id="PLAN-LODASH",
        finding_ids=[finding.id],
        root_cause_id="PKG-npm:lodash",
        action=RemediationAction.BUMP,
        target_version="4.17.21",
        target_package="npm:lodash",
        policy_result=PolicyResult(status="approved", rule_matched=">=4.17.21"),
        risk_tier=RiskTier.AUTO,
        requires_approval=False,
        evidence=[
            {
                "chunk_id": "ADV-LODASH",
                "package": "npm:lodash",
                "ecosystem": "npm",
                "cve": "CVE-2020-8203",
                "title": "Prototype pollution",
                "affected_ranges": ["<4.17.21"],
                "fixed_versions": ["4.17.21"],
                "references": ["https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw"],
            }
        ],
        rationale="Upgrade to the validated fixed version.",
    )
    state = VulnFlowState(
        run_id="RUN-F43-FIXED",
        repo_path="samples/npm-simple-bump",
        report_path="data/fixtures/sample_trivy_report.json",
        scanner="trivy",
        mode=mode,
        ecosystem="npm",
        findings=[finding],
        deduped_findings=[finding],
        root_cause_groups=[
            {
                "root_cause_id": "PKG-npm:lodash",
                "root_cause_package": "npm:lodash",
                "is_direct": True,
                "dependency_chain": ["npm:lodash"],
                "explanation": "The dependency is directly declared in package.json.",
                "findings": [finding.to_dict()],
            }
        ],
        plans=[plan],
        approved_plans=[plan],
        patches=[
            {
                "plan_id": plan.id,
                "file": "package.json",
                "diff": "--- package.json\n+++ package.json\n-4.17.15\n+4.17.21",
                "result": {"status": "applied"},
            }
        ],
        test_results=[{"passed": True, "build_clean": True, "exit_code": 0}],
        pull_requests=[
            {
                "status": "opened",
                "pr_url": "https://github.com/acme/sample/pull/7",
                "branch": "vulnflow/fix-lodash",
            }
        ],
        verification_results=[
            {
                "verified": True,
                "rescan_clean": True,
                "resolved_finding_ids": [finding.id],
                "new_finding_ids": [],
            }
        ],
        exit_code=0,
        terminal_status="completed",
    )
    state.audit_events = [
        {"event_type": "PATCH_APPLIED", "payload": {"plan_id": plan.id}},
        {
            "event_type": "BUILD_TEST_EXECUTED",
            "payload": {"passed": True, "exit_code": 0},
        },
        {
            "event_type": "PR_CREATED",
            "payload": {"pr_url": "https://github.com/acme/sample/pull/7"},
        },
    ]
    if executed_rescan:
        state.audit_events.append(
            {
                "event_type": "RESCAN_EXECUTED",
                "payload": {"status": "completed", "success": True},
                "entry_hash": "a" * 64,
            }
        )
    return state


def fixed_report(mode: str = "pr", *, executed_rescan: bool = True) -> RunReport:
    return build_run_report(
        report_state(mode, executed_rescan=executed_rescan), generated_at=FIXED_TIME
    )


def test_run_report_contract_and_cross_format_counts() -> None:
    report = fixed_report()
    payload = generate_json_report(report)
    restored = RunReport.model_validate(payload)
    markdown = generate_markdown_report(report)
    html = generate_html_report(report)
    assert restored.schema_version == "1.0.0"
    assert restored.executive_summary.findings_analyzed == 1
    assert "| Findings analyzed | 1 |" in markdown
    assert "<strong>1</strong><span>Findings</span>" in html
    assert 'data-count="1"' in html
    assert restored.executive_summary.expected_cves_addressed == 1
    assert restored.executive_summary.verified_cves_resolved == 1
    assert restored.provenance.audit_chain_head_hash == "a" * 64


def test_renderer_golden_hashes() -> None:
    report = fixed_report()
    markdown_hash = hashlib.sha256(
        generate_markdown_report(report).encode()
    ).hexdigest()
    html_hash = hashlib.sha256(generate_html_report(report).encode()).hexdigest()
    assert (
        markdown_hash
        == "39866944279bee59fa25f2d522a2b08f31908089b6df6540e3cdef417ae6cfec"
    )
    assert (
        html_hash == "e147c9189a9ca0e249b13d51b36f616b1b3b0de1db315a3f0b12080cca6aac34"
    )


def test_dry_run_never_reports_executed_patch_or_pr_url() -> None:
    from vulnflow.orchestrator.routing import route_after_test

    state = report_state("dry-run")
    assert route_after_test(state) == "verify"
    report = fixed_report("dry-run")
    serialized = json.dumps(generate_json_report(report))
    assert report.execution_evidence.patch == StepState.SIMULATED
    assert report.executive_summary.fixes_applied == 0
    assert report.executive_summary.prs_actually_created == 0
    assert "https://github.com/acme/sample/pull/7" not in serialized


def test_missing_rescan_and_tests_remain_unknown() -> None:
    state = report_state(executed_rescan=False)
    state.audit_events = [
        event
        for event in state.audit_events
        if event["event_type"] != "BUILD_TEST_EXECUTED"
    ]
    report = build_run_report(state, generated_at=FIXED_TIME)
    assert report.execution_evidence.rescan == StepState.NOT_RUN
    assert report.execution_evidence.tests == StepState.NOT_RUN
    assert report.executive_summary.severity_counts_after.total is None
    assert report.executive_summary.unresolved_findings is None
    checks = {item.check: item for item in report.root_causes[0].verification_results}
    assert checks["sandbox_tests"].passed is None


def test_advisory_ranges_and_fixed_versions_are_validated() -> None:
    assert version_satisfies("4.17.15", ">=4.0.0 <4.17.21", "npm")
    assert not version_satisfies("4.17.21", ">=4.0.0 <4.17.21", "npm")
    report = fixed_report()
    assert report.root_causes[0].advisory_evidence[0].validated is True
    state = report_state()
    state.plans[0].target_version = "4.17.20"
    invalid = build_run_report(state, generated_at=FIXED_TIME)
    assert invalid.executive_summary.expected_cves_addressed == 0
    assert invalid.validation_notes.rejected_advisories


def test_invalid_source_and_unsafe_scheme_are_rejected() -> None:
    state = report_state()
    evidence = state.plans[0].evidence[0]
    evidence["package"] = "npm:not-lodash"
    evidence["references"] = ["javascript:alert(1)"]
    report = build_run_report(state, generated_at=FIXED_TIME)
    advisory = report.root_causes[0].advisory_evidence[0]
    assert advisory.validated is False
    assert advisory.source_url is None
    assert report.executive_summary.expected_cves_addressed == 0


def test_actual_changes_are_not_confused_with_proposed_changes() -> None:
    state = report_state()
    state.audit_events = [
        event for event in state.audit_events if event["event_type"] != "PATCH_APPLIED"
    ]
    report = build_run_report(state, generated_at=FIXED_TIME)
    root = report.root_causes[0]
    assert root.proposed_remediation_steps
    assert root.actual_execution_steps == ()
    assert report.executive_summary.fixes_applied == 0


def test_pr_requires_matching_successful_executed_event() -> None:
    state = report_state()
    state.audit_events = [
        event for event in state.audit_events if event["event_type"] != "PR_CREATED"
    ]
    report = build_run_report(state, generated_at=FIXED_TIME)
    assert report.executive_summary.prs_actually_created == 0
    assert report.execution_evidence.pull_request == StepState.FAILED


def test_report_approval_failure_and_transitive_modes() -> None:
    report_only = fixed_report("report")
    assert report_only.header.repo_changes.value == "none"
    assert report_only.executive_summary.fixes_applied == 0
    assert report_only.executive_summary.prs_actually_created == 0

    approval = report_state()
    approval.exit_code = 10
    approval.terminal_status = "pending_approval"
    approval.pending_approval_plans = approval.plans
    approval.approved_plans = []
    approval_report = build_run_report(approval, generated_at=FIXED_TIME)
    assert approval_report.header.outcome == "pending_approval"
    assert any(
        action.action_type == "approve_remediation"
        for action in approval_report.action_required
    )

    failed = report_state(executed_rescan=False)
    failed.exit_code = 30
    failed.terminal_status = "failed_verification"
    failed_report = build_run_report(failed, generated_at=FIXED_TIME)
    assert failed_report.header.outcome == "failed_verification"
    assert failed_report.executive_summary.verified_cves_resolved == 0

    transitive = report_state()
    transitive.root_cause_groups[0]["is_direct"] = False
    transitive.root_cause_groups[0]["dependency_chain"] = ["npm:parent", "npm:lodash"]
    transitive_report = build_run_report(transitive, generated_at=FIXED_TIME)
    assert transitive_report.root_causes[0].origin.value == "transitive"
    assert transitive_report.root_causes[0].dependency_chain[-1] == "npm:lodash"


def test_policy_exception_never_counts_as_resolved() -> None:
    state = report_state()
    state.plans[0].action = RemediationAction.EXCEPTION
    state.plans[0].target_version = None
    state.plans[0].evidence = []
    state.exit_code = 20
    state.terminal_status = "blocked_policy"
    state.verification_results = []
    state.audit_events = []
    report = build_run_report(state, generated_at=FIXED_TIME)
    assert report.executive_summary.expected_cves_addressed == 0
    assert report.executive_summary.verified_cves_resolved == 0


def test_builder_does_not_call_network_or_model(monkeypatch) -> None:
    import urllib.request

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("external service invoked")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    report = build_run_report(report_state(), generated_at=FIXED_TIME)
    assert report.header.run_id == "RUN-F43-FIXED"


def test_no_llm_planner_makes_zero_model_requests() -> None:
    class CountingClient:
        calls = 0

        def structured_complete(self, **_kwargs: object) -> object:
            self.calls += 1
            raise AssertionError("model request must not occur")

    client = CountingClient()
    state = report_state()
    planner = PlannerAgent(client=client, enable_llm=False)  # type: ignore[arg-type]
    planner.plan_remediation(
        root_cause_id="npm:lodash",
        findings=state.findings,
        advisories=state.plans[0].evidence,
        ecosystem="npm",
    )
    assert client.calls == 0


def test_failed_reporting_does_not_mutate_execution_exit_code(
    monkeypatch, tmp_path: Path
) -> None:
    from vulnflow import cli

    state = report_state()
    state.exit_code = 30
    state.terminal_status = "failed_verification"
    args = type(
        "Args",
        (),
        {
            "output": None,
            "out_dir": str(tmp_path),
            "output_format": "json",
            "format": None,
        },
    )()

    def fail_writer(*_args: object, **_kwargs: object) -> Path:
        raise OSError("disk full")

    monkeypatch.setattr(cli, "write_json_report", fail_writer)
    assert cli._write_run_reports(state, args) == []
    assert state.exit_code == 30


def test_severity_bar_values_match_canonical_json() -> None:
    report = fixed_report()
    html = generate_html_report(report)
    json_data = generate_json_report(report)
    before = json_data["executive_summary"]["severity_counts_before"]
    assert f'data-count="{before["critical"]}"' in html
    assert f'data-count="{before["high"]}"' in html
    assert f'data-count="{before["medium"]}"' in html
    assert f'data-count="{before["low"]}"' in html
    assert f'data-count="{before["info"]}"' in html


def test_secret_and_pii_finding_report() -> None:
    finding = Finding(
        id="FND-SEC-01",
        type=FindingType.SECRET,
        scanner="gitleaks",
        repo="sample-repo",
        package="secret:aws-access-key",
        version="0.0.0",
        cve=["aws-access-key"],
        severity=SeverityLevel.CRITICAL,
        location=LocationInfo(file_path="src/config.js", line=15),
        metadata={"rule_id": "aws-access-key", "fingerprint": "abc123sha"},
    )
    plan = RemediationPlan(
        id="PLAN-SEC-01",
        finding_ids=[finding.id],
        root_cause_id="secret:credentials",
        action=RemediationAction.ROTATE,
        target_version="env-var",
        target_package="secret:credentials",
        policy_result=PolicyResult(status="unknown", rule_matched="none"),
        risk_tier=RiskTier.REVIEW,
        requires_approval=True,
        evidence=[],
        rationale="Rotate exposed AWS key to environment variables.",
    )
    state = VulnFlowState(
        run_id="RUN-SEC-TEST",
        repo_path="samples/repo-with-secret",
        report_path="data/fixtures/sample_gitleaks_report.json",
        scanner="gitleaks",
        mode="pr",
        ecosystem="npm",
        findings=[finding],
        deduped_findings=[finding],
        root_cause_groups=[
            {
                "root_cause_id": "secret:credentials",
                "root_cause_package": "secret:credentials",
                "is_direct": True,
                "dependency_chain": ["secret:credentials"],
                "explanation": "Hardcoded secret detected.",
                "findings": [finding.to_dict()],
            }
        ],
        plans=[plan],
        pending_approval_plans=[plan],
        exit_code=10,
        terminal_status="pending_approval",
    )
    report = build_run_report(state, generated_at=FIXED_TIME)
    assert report.header.execution_mode.value == "pr"
    assert report.header.outcome == "pending_approval"
    assert report.header.exit_code == 10
    assert report.root_causes[0].risk_tier == "review"
    assert any(a.action_type == "approve_remediation" for a in report.action_required)
    assert report.executive_summary.fixes_applied == 0
    assert report.executive_summary.prs_actually_created == 0
    md = generate_markdown_report(report)
    html = generate_html_report(report)
    assert report.root_causes[0].package == "[REDACTED]"
    assert r"\[REDACTED\]" in md
    assert "[REDACTED]" in html


def test_failed_remediation_and_test_failure() -> None:
    state = report_state()
    state.exit_code = 30
    state.terminal_status = "failed_verification"
    state.test_results = [{"passed": False, "build_clean": False, "exit_code": 1}]
    state.audit_events = [
        {"event_type": "PATCH_APPLIED", "payload": {"plan_id": state.plans[0].id}},
        {
            "event_type": "BUILD_TEST_EXECUTED",
            "payload": {"passed": False, "exit_code": 1},
        },
    ]
    report = build_run_report(state, generated_at=FIXED_TIME)
    assert report.execution_evidence.tests == StepState.FAILED
    assert report.header.outcome == "failed_verification"
    assert report.header.exit_code == 30
    checks = {item.check: item for item in report.root_causes[0].verification_results}
    assert checks["sandbox_tests"].passed is False


def test_write_run_reports_generates_html_and_json_alongside_markdown(
    tmp_path: Path,
) -> None:
    """Ensure that specifying --output report.md also generates report.html and run-report.json."""
    from vulnflow import cli

    state = report_state()
    md_file = tmp_path / "report.md"
    args = type(
        "Args",
        (),
        {
            "output": str(md_file),
            "out_dir": None,
            "output_format": "html,md,json",
            "format": None,
            "repo": ".",
        },
    )()
    written = cli._write_run_reports(state, args)
    written_names = [p.name for p in written]
    assert "report.md" in written_names
    assert "report.html" in written_names
    assert "run-report.json" in written_names

    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "run-report.json").exists()


def test_write_run_reports_with_env_reports_dir(monkeypatch, tmp_path: Path) -> None:
    """Ensure VULNFLOW_REPORTS_DIR environment variable is respected when output is omitted."""
    from vulnflow import cli

    state = report_state()
    reports_dir = tmp_path / "custom_reports"
    monkeypatch.setenv("VULNFLOW_REPORTS_DIR", str(reports_dir))
    args = type(
        "Args",
        (),
        {
            "output": None,
            "out_dir": None,
            "output_format": "html,md",
            "format": None,
            "repo": ".",
        },
    )()
    written = cli._write_run_reports(state, args)
    written_names = [p.name for p in written]
    assert "report.html" in written_names
    assert "report.md" in written_names
    assert (reports_dir / "report.html").exists()
    assert (reports_dir / "report.md").exists()


def test_applied_fixes_are_prominently_reported() -> None:
    """Objective 1 & 7: Applied fixes appear prominently before investigations."""
    state = report_state()
    report = build_run_report(state, generated_at=FIXED_TIME)
    md = generate_markdown_report(report)
    html = generate_html_report(report)

    # Check section ordering
    assert "## B. Remediation Actions Performed" in md
    assert "## D. AI Investigations and Decisions" in md
    assert md.index("## B. Remediation Actions Performed") < md.index(
        "## D. AI Investigations and Decisions"
    )

    # Check applied fix content
    assert "Applied Fixes & Mitigations (1):" in md
    assert "npm:lodash" in md
    assert "package.json" in md
    assert "Applied Remediation Patches" in html


def test_real_pr_details_appear_when_available() -> None:
    """Objective 1 & 7: Real PR details appear when confirmed by audit events."""
    state = report_state()
    # Add matching PR_CREATED audit event
    state.audit_events.append(
        {
            "event_type": "PR_CREATED",
            "payload": {
                "pr_url": "https://github.com/acme/sample/pull/7",
                "branch": "vulnflow/fix-lodash",
                "title": "fix(deps): bump lodash to 4.17.21",
                "campaign": False,
            },
        }
    )
    report = build_run_report(state, generated_at=FIXED_TIME)
    md = generate_markdown_report(report)
    html = generate_html_report(report)

    assert "## C. Pull Requests Created" in md
    assert "PR #7" in md or "PR" in md
    assert "https://github.com/acme/sample/pull/7" in md
    assert "vulnflow/fix" in md
    assert "https://github.com/acme/sample/pull/7" in html


def test_no_invented_pr_details_appear() -> None:
    """Objective 1 & 7: No PR details appear when PR was not created."""
    state = report_state()
    state.pull_requests = []
    state.audit_events = [
        e for e in state.audit_events if e.get("event_type") != "PR_CREATED"
    ]
    report = build_run_report(state, generated_at=FIXED_TIME)
    md = generate_markdown_report(report)

    assert "No pull requests were opened in this execution." in md
    assert "https://github.com/acme/sample/pull/7" not in md


def test_approval_lists_cannot_dominate_main_report() -> None:
    """Objective 4 & 7: Approval lists cannot dominate the main report; must be grouped."""
    state = report_state()
    # Create 37 pending plans
    pending_plans = []
    for i in range(37):
        p = RemediationPlan(
            id=f"PLAN-{i:04d}",
            finding_ids=["FND-LODASH"],
            root_cause_id=f"PKG-npm:dep-{i}",
            action=RemediationAction.BUMP,
            target_version=f"{i}.0.0",
            target_package=f"npm:dep-{i}",
            policy_result=PolicyResult(status="unknown"),
            risk_tier=RiskTier.REVIEW,
            requires_approval=True,
            evidence=[],
            rationale=f"Bump dep-{i}",
        )
        pending_plans.append(p)

    state.plans.extend(pending_plans)
    state.pending_approval_plans = pending_plans
    report = build_run_report(state, generated_at=FIXED_TIME)
    md = generate_markdown_report(report)

    # Must NOT have 37 individual bullet points flooding the report
    individual_spam = [
        f"- **high**: Review and approve plan PLAN-{i:04d}" for i in range(37)
    ]
    assert sum(item in md for item in individual_spam) < 5

    # Must have grouped summary
    assert "Governance Authorization Gate" in md
    assert "vulnflow approve --all" in md

    # Must stay bounded under 8000 chars without cutting off
    assert len(md) <= 8000
    assert "Report truncated for review safety" not in md


def test_ai_insights_include_valid_evidence_references() -> None:
    """Objective 2 & 7: AI insights include valid evidence references."""
    state = report_state()
    report = build_run_report(state, generated_at=FIXED_TIME)
    root = report.root_causes[0]

    assert len(root.insights) >= 2
    for insight in root.insights:
        assert insight.evidence_availability in {
            EvidenceAvailability.AVAILABLE,
            EvidenceAvailability.NOT_EVALUATED,
            EvidenceAvailability.MISSING,
        }
        if insight.evidence_availability == EvidenceAvailability.AVAILABLE:
            assert len(insight.source_references) >= 1


def test_missing_investigations_display_not_evaluated() -> None:
    """Objective 2 & 7: Missing investigations display NOT_EVALUATED."""
    state = report_state()
    # Remove locations from findings and root cause group so reachability cannot be evaluated
    state.deduped_findings[0].location = None
    state.findings[0].location = None
    state.root_cause_groups[0]["findings"][0]["location"] = {}
    report = build_run_report(state, generated_at=FIXED_TIME)
    root = report.root_causes[0]

    impact_insight = next(
        (i for i in root.insights if i.category == "repository_impact"), None
    )
    assert impact_insight is not None
    assert impact_insight.evidence_availability == EvidenceAvailability.NOT_EVALUATED


def test_zero_verified_fixes_not_presented_as_resolved() -> None:
    """Objective 6 & 7: Zero verified fixes are never presented as resolved."""
    state = report_state(executed_rescan=False)
    report = build_run_report(state, generated_at=FIXED_TIME)
    md = generate_markdown_report(report)

    assert report.executive_summary.verified_cves_resolved == 0
    assert "| Verified CVEs resolved | 0 |" in md
    assert (
        "0 CVE(s) are verified resolved." in md
        or "0 verified" in md
        or "Verified CVEs" in md
    )


def test_markdown_html_json_remain_consistent() -> None:
    """Objective 7: Markdown, HTML and JSON metrics remain strictly consistent."""
    state = report_state()
    report = build_run_report(state, generated_at=FIXED_TIME)
    md = generate_markdown_report(report)
    html = generate_html_report(report)
    json_data = generate_json_report(report)

    summary = report.executive_summary
    # Check consistent counts
    assert f"| Findings analyzed | {summary.findings_analyzed} |" in md
    assert f"<strong>{summary.findings_analyzed}</strong><span>Findings</span>" in html
    assert (
        json_data["executive_summary"]["findings_analyzed"] == summary.findings_analyzed
    )

    assert f"| Fixes applied | {summary.fixes_applied} |" in md
    assert f"<strong>{summary.fixes_applied}</strong><span>Applied fixes</span>" in html
    assert json_data["executive_summary"]["fixes_applied"] == summary.fixes_applied
