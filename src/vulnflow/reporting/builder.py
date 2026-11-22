"""
src/vulnflow/reporting/builder.py
Builds an evidence-backed canonical report without performing external actions.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from vulnflow.contracts.report import (
    ActionRequired,
    AdvisoryEvidence,
    ApprovalDecision,
    CompletionStatus,
    DependencyOrigin,
    EvaluatedRule,
    EvidenceAvailability,
    ExecutionEvidence,
    ExecutionMode,
    ExecutiveSummary,
    FileChange,
    GeneratedBy,
    PolicyCompliance,
    Provenance,
    RemediationOption,
    RepoChanges,
    ReportHeader,
    ResidualRisk,
    RootCauseReport,
    RunReport,
    SecurityInsight,
    SeverityCounts,
    SourceReference,
    StepState,
    TokenUsage,
    ValidationNotes,
    VerificationResult,
)
from vulnflow.contracts.state import VulnFlowState

_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"(?i)(password|passwd|token|secret)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb)://[^\s/@:]+:[^\s/@]+@"),
)


def redact_report_text(value: Any) -> str:
    """Apply report-boundary secret redaction to a scalar value."""
    text = str(value or "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _safe_external_url(value: Any) -> str | None:
    text = redact_report_text(value).strip()
    if not text:
        return None
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return text


def _version_parts(
    version: str, ecosystem: str
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    """Parse common npm, PyPI, and Maven versions without lexical comparison."""
    clean = version.strip().lstrip("v").split("+", 1)[0]
    main, _, suffix = clean.partition("-")
    numbers = tuple(int(item) for item in re.findall(r"\d+", main)) or (0,)
    qualifiers = tuple(re.findall(r"[A-Za-z]+|\d+", suffix.lower()))
    if ecosystem.lower() in {"maven", "java"} and not suffix:
        match = re.search(r"[A-Za-z].*$", clean)
        qualifiers = (
            tuple(re.findall(r"[A-Za-z]+|\d+", match.group(0).lower())) if match else ()
        )
    return numbers, qualifiers


def _compare_versions(left: str, right: str, ecosystem: str) -> int:
    left_numbers, left_suffix = _version_parts(left, ecosystem)
    right_numbers, right_suffix = _version_parts(right, ecosystem)
    width = max(len(left_numbers), len(right_numbers))
    left_padded = left_numbers + (0,) * (width - len(left_numbers))
    right_padded = right_numbers + (0,) * (width - len(right_numbers))
    if left_padded != right_padded:
        return 1 if left_padded > right_padded else -1
    if left_suffix == right_suffix:
        return 0
    if not left_suffix:
        return 1
    if not right_suffix:
        return -1
    return 1 if left_suffix > right_suffix else -1


def version_satisfies(version: str, constraint: str, ecosystem: str) -> bool:
    """Evaluate a bounded set of ecosystem version constraints deterministically."""
    branches = [branch.strip() for branch in constraint.split("||") if branch.strip()]
    if not branches:
        return False
    for branch in branches:
        checks = re.findall(r"(<=|>=|<|>|==|=|~\s*|\^\s*)?\s*v?([0-9][^\s,]*)", branch)
        if not checks:
            continue
        branch_ok = True
        for operator, target in checks:
            comparison = _compare_versions(version, target, ecosystem)
            operator = operator.strip() or "="
            if (
                operator == "<"
                and not comparison < 0
                or operator == "<="
                and not comparison <= 0
                or operator == ">"
                and not comparison > 0
                or operator == ">="
                and not comparison >= 0
                or operator in {"=", "=="}
                and comparison != 0
                or operator == "^"
                and not (
                    comparison >= 0
                    and _version_parts(version, ecosystem)[0][0]
                    == _version_parts(target, ecosystem)[0][0]
                )
                or operator == "~"
                and not (
                    comparison >= 0
                    and _version_parts(version, ecosystem)[0][:2]
                    == _version_parts(target, ecosystem)[0][:2]
                )
            ):
                branch_ok = False
        if branch_ok:
            return True
    return False


def _event_payloads(state: VulnFlowState, event_type: str) -> list[dict[str, Any]]:
    return [
        event.get("payload", {})
        for event in state.audit_events
        if event.get("event_type") == event_type
        and isinstance(event.get("payload", {}), dict)
    ]


def _planner_llm_provenance(
    state: VulnFlowState,
) -> tuple[str | None, str | None, TokenUsage, float | None]:
    """Aggregate persisted planner enrichment metadata without reading model content."""
    enrichments: list[dict[str, Any]] = []
    for payload in _event_payloads(state, "PLAN_FORMULATED"):
        enrichment = payload.get("llm_enrichment")
        if isinstance(enrichment, dict) and enrichment.get("state") == "executed":
            enrichments.append(enrichment)
    if not enrichments:
        return None, None, TokenUsage(), None

    providers = sorted(
        {
            redact_report_text(item.get("provider"))
            for item in enrichments
            if item.get("provider")
        }
    )
    models = sorted(
        {
            redact_report_text(item.get("model"))
            for item in enrichments
            if item.get("model")
        }
    )

    def total(field: str) -> int | None:
        values = [
            item[field]
            for item in enrichments
            if isinstance(item.get(field), int) and not isinstance(item.get(field), bool)
        ]
        return sum(values) if values else None

    costs = [
        float(item["estimated_cost_usd"])
        for item in enrichments
        if isinstance(item.get("estimated_cost_usd"), (int, float))
        and not isinstance(item.get("estimated_cost_usd"), bool)
    ]
    return (
        ", ".join(providers) or None,
        ", ".join(models) or None,
        TokenUsage(
            prompt_tokens=total("prompt_tokens"),
            completion_tokens=total("completion_tokens"),
            total_tokens=total("total_tokens"),
        ),
        sum(costs) if costs else None,
    )


def _result_succeeded(result: dict[str, Any], accepted: set[str]) -> bool:
    status = str(result.get("status", "")).lower()
    return status in accepted or result.get("success") is True


def _derive_execution(
    state: VulnFlowState,
) -> tuple[ExecutionEvidence, RepoChanges, int, int]:
    patch_events = _event_payloads(state, "PATCH_APPLIED")
    patch_ok = bool(patch_events) and any(
        _result_succeeded(patch.get("result", {}), {"applied", "success"})
        for patch in state.patches
        if isinstance(patch, dict) and isinstance(patch.get("result"), dict)
    )
    if state.mode == "report":
        patch_state, repo_changes, fixes = StepState.NOT_RUN, RepoChanges.NONE, 0
    elif state.mode == "dry-run" and (patch_events or state.patches):
        patch_state, repo_changes, fixes = StepState.SIMULATED, RepoChanges.SIMULATED, 0
    elif patch_ok:
        patch_state, repo_changes, fixes = (
            StepState.EXECUTED,
            RepoChanges.MADE,
            len(patch_events),
        )
    elif patch_events or state.patches:
        patch_state, repo_changes, fixes = StepState.FAILED, RepoChanges.NONE, 0
    else:
        patch_state, repo_changes, fixes = StepState.NOT_RUN, RepoChanges.NONE, 0

    test_events = _event_payloads(state, "BUILD_TEST_EXECUTED")
    if state.mode == "dry-run" and test_events:
        test_state = StepState.SIMULATED
    elif not test_events:
        test_state = StepState.NOT_RUN
    elif all(
        event.get("passed") is True and event.get("exit_code") == 0
        for event in test_events
    ):
        test_state = StepState.EXECUTED
    else:
        test_state = StepState.FAILED

    valid_prs = []
    if state.mode == "pr":
        for event in _event_payloads(state, "PR_CREATED"):
            url = _safe_external_url(event.get("pr_url"))
            match = next(
                (
                    pr
                    for pr in state.pull_requests
                    if isinstance(pr, dict)
                    and pr.get("pr_url") == event.get("pr_url")
                    and _result_succeeded(pr, {"opened", "created", "success"})
                ),
                None,
            )
            if url and match:
                valid_prs.append(match)
    if state.mode in {"report", "dry-run"}:
        pr_state = StepState.NOT_RUN if state.mode == "report" else StepState.SIMULATED
    elif valid_prs:
        pr_state = StepState.EXECUTED
    elif _event_payloads(state, "PR_CREATED") or state.pull_requests:
        pr_state = StepState.FAILED
    else:
        pr_state = StepState.NOT_RUN

    rescan_events = _event_payloads(state, "RESCAN_EXECUTED") + _event_payloads(
        state, "SCAN_COMPLETED"
    )
    successful_rescan = [
        event
        for event in rescan_events
        if event.get("success") is True
        or event.get("status") in {"completed", "success"}
    ]
    if not rescan_events:
        rescan_state = StepState.NOT_RUN
    elif successful_rescan:
        rescan_state = StepState.EXECUTED
    else:
        rescan_state = StepState.FAILED

    return (
        ExecutionEvidence(
            patch=patch_state,
            tests=test_state,
            pull_request=pr_state,
            rescan=rescan_state,
        ),
        repo_changes,
        fixes,
        len(valid_prs),
    )


def _severity_counts(findings: Iterable[Any]) -> SeverityCounts:
    counts = {name: 0 for name in ("critical", "high", "medium", "low", "info")}
    total = 0
    for finding in findings:
        severity = getattr(getattr(finding, "severity", None), "value", None)
        severity = str(severity or getattr(finding, "severity", "info")).lower()
        counts[severity if severity in counts else "info"] += 1
        total += 1
    return SeverityCounts(**counts, total=total)


def _unknown_severity(total: int | None = None) -> SeverityCounts:
    return SeverityCounts(total=total)


def _normalized_outcome(state: VulnFlowState, unsupported: list[str]) -> str:
    expected = {
        0: "completed",
        10: "pending_approval",
        20: "blocked_policy",
        30: "failed_verification",
        1: "error",
    }.get(state.exit_code, "error")
    if state.terminal_status != expected:
        unsupported.append(
            f"Terminal status {state.terminal_status!r} contradicted exit code {state.exit_code}; "
            f"reported as {expected!r}."
        )
    return expected


def _hash_file(path: str | None) -> str | None:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.is_file():
        return None
    digest = hashlib.sha256()
    with file_path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bump_class(
    installed: str | None, target: str | None, ecosystem: str
) -> str | None:
    if not installed or not target:
        return None
    current = _version_parts(installed, ecosystem)[0] + (0, 0, 0)
    proposed = _version_parts(target, ecosystem)[0] + (0, 0, 0)
    if proposed[0] != current[0]:
        return "major"
    if proposed[1] != current[1]:
        return "minor"
    if proposed[2] != current[2]:
        return "patch"
    return "none"


def _validate_advisory(
    raw: dict[str, Any],
    package: str,
    ecosystem: str,
    installed: str | None,
    target: str | None,
    finding_cves: set[str],
) -> AdvisoryEvidence:
    evidence_package = redact_report_text(raw.get("package") or package)
    evidence_ecosystem = redact_report_text(raw.get("ecosystem") or ecosystem)
    raw_cves = raw.get("aliases") or ([raw.get("cve")] if raw.get("cve") else [])
    cves = tuple(sorted({redact_report_text(item) for item in raw_cves if item}))
    ranges_value = raw.get("affected_ranges") or raw.get("affected") or []
    if isinstance(ranges_value, str):
        ranges_value = [ranges_value]
    fixed_value = raw.get("fixed_versions") or []
    if isinstance(fixed_value, str):
        fixed_value = [fixed_value]
    ranges = tuple(redact_report_text(item) for item in ranges_value)
    fixed = tuple(redact_report_text(item) for item in fixed_value)
    reason: str | None = None
    if evidence_package.lower().split(":")[-1] != package.lower().split(":")[-1]:
        reason = "Package does not match the affected finding."
    elif evidence_ecosystem.lower() != ecosystem.lower():
        reason = "Ecosystem does not match the affected finding."
    elif cves and finding_cves and not finding_cves.intersection(cves):
        reason = "Advisory identifiers do not match the finding."
    elif not installed or not target:
        reason = "Installed or target version is unavailable."
    elif ranges:
        if not any(version_satisfies(installed, item, ecosystem) for item in ranges):
            reason = "Installed version is not covered by the advisory affected range."
        elif any(version_satisfies(target, item, ecosystem) for item in ranges):
            reason = "Target version remains inside the advisory affected range."
    elif fixed:
        if not any(_compare_versions(installed, item, ecosystem) < 0 for item in fixed):
            reason = "Installed version is not earlier than a documented fixed version."
        elif not any(_compare_versions(target, item, ecosystem) >= 0 for item in fixed):
            reason = "Target version does not reach a documented fixed version."
    else:
        reason = "No deterministic affected range or fixed version was supplied."
    references = raw.get("references") or []
    if isinstance(references, str):
        references = [references]
    return AdvisoryEvidence(
        evidence_id=redact_report_text(
            raw.get("chunk_id") or raw.get("id") or "UNKNOWN"
        ),
        package=evidence_package,
        ecosystem=evidence_ecosystem,
        cves=cves,
        title=redact_report_text(raw.get("title") or raw.get("summary")) or None,
        affected_ranges=ranges,
        fixed_versions=fixed,
        source_url=next(
            (
                _safe_external_url(item)
                for item in references
                if _safe_external_url(item)
            ),
            None,
        ),
        validated=reason is None,
        rejection_reason=reason,
    )


def _file_changes(
    state: VulnFlowState, plan_id: str, state_value: StepState
) -> tuple[FileChange, ...]:
    changes: list[FileChange] = []
    for patch in state.patches:
        if not isinstance(patch, dict) or patch.get("plan_id") != plan_id:
            continue
        paths = [item.strip() for item in str(patch.get("file", "UNKNOWN")).split(",")]
        diff = str(patch.get("diff", ""))
        added = sum(
            1
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        removed = sum(
            1
            for line in diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        )
        changes.extend(
            FileChange(
                path=redact_report_text(path),
                state=state_value,
                lines_added=added,
                lines_removed=removed,
            )
            for path in paths
        )
    return tuple(changes)


def _root_causes(
    state: VulnFlowState,
    execution: ExecutionEvidence,
    rejected: list[str],
    missing: list[str],
) -> tuple[tuple[RootCauseReport, ...], set[str], dict[str, set[str]]]:
    reports: list[RootCauseReport] = []
    expected_cves: set[str] = set()
    finding_cves: dict[str, set[str]] = {}
    for group in state.root_cause_groups:
        root_id = redact_report_text(group.get("root_cause_id", "UNKNOWN"))
        package = redact_report_text(
            group.get("root_cause_package") or root_id.replace("PKG-", "")
        )
        ecosystem = package.split(":", 1)[0] if ":" in package else state.ecosystem
        raw_findings = group.get("findings", [])
        finding_ids = tuple(
            redact_report_text(item.get("id", "UNKNOWN")) for item in raw_findings
        )
        cves = tuple(
            sorted(
                {
                    redact_report_text(cve)
                    for item in raw_findings
                    for cve in item.get("cve", [])
                }
            )
        )
        finding_cves.update(
            {
                redact_report_text(item.get("id", "UNKNOWN")): set(item.get("cve", []))
                for item in raw_findings
            }
        )
        installed = next(
            (
                redact_report_text(item.get("version"))
                for item in raw_findings
                if item.get("version")
            ),
            None,
        )
        plan = next(
            (
                candidate
                for candidate in state.plans
                if candidate.root_cause_id == group.get("root_cause_id")
                or candidate.root_cause_id in root_id
                or root_id in candidate.root_cause_id
            ),
            None,
        )
        target = (
            redact_report_text(plan.target_version)
            if plan and plan.target_version
            else None
        )
        advisories = tuple(
            _validate_advisory(item, package, ecosystem, installed, target, set(cves))
            for item in (plan.evidence if plan else [])
            if isinstance(item, dict)
        )
        for advisory in advisories:
            if advisory.validated:
                expected_cves.update(set(advisory.cves).intersection(cves) or cves)
            else:
                rejected.append(f"{advisory.evidence_id}: {advisory.rejection_reason}")
        if not advisories:
            missing.append(f"No advisory evidence was persisted for {package}.")
        risk = (
            getattr(getattr(plan, "risk_tier", None), "value", "unknown")
            if plan
            else "unknown"
        )
        policy = getattr(plan, "policy_result", None) if plan else None
        risk_reason = redact_report_text(getattr(policy, "reason", None)) or (
            "Deterministic risk tier from policy, version bump, and evidence availability."
        )
        source_ids = tuple(item.evidence_id for item in advisories if item.validated)
        locations = tuple(
            sorted(
                {
                    redact_report_text((item.get("location") or {}).get("file_path"))
                    for item in raw_findings
                    if isinstance(item.get("location"), dict)
                    and (item.get("location") or {}).get("file_path")
                }
            )
        )
        insights = [
            SecurityInsight(
                category="vulnerability_intelligence",
                text=(
                    f"{package} is associated with {len(cves)} persisted vulnerability identifier(s)."
                    if cves
                    else "No vulnerability identifier was persisted for this root cause."
                ),
                generated_by=GeneratedBy.RULES,
                source_references=source_ids or finding_ids,
                evidence_availability=(
                    EvidenceAvailability.AVAILABLE
                    if cves
                    else EvidenceAvailability.MISSING
                ),
            ),
            SecurityInsight(
                category="repository_impact",
                text=(
                    f"Scanner evidence locates dependency usage in {', '.join(locations)}. "
                    "Runtime reachability was not evaluated."
                    if locations
                    else "Repository usage and runtime reachability were not evaluated."
                ),
                generated_by=GeneratedBy.RULES,
                source_references=finding_ids,
                evidence_availability=(
                    EvidenceAvailability.AVAILABLE
                    if locations
                    else EvidenceAvailability.NOT_EVALUATED
                ),
                uncertainty="Scanner locations do not prove runtime reachability.",
            ),
        ]
        if len(cves) > 1:
            insights.append(
                SecurityInsight(
                    category="cross_finding_intelligence",
                    text=f"One root-cause remediation groups {len(cves)} vulnerability identifiers.",
                    generated_by=GeneratedBy.RULES,
                    source_references=finding_ids,
                    evidence_availability=EvidenceAvailability.AVAILABLE,
                )
            )
        options: tuple[RemediationOption, ...] = ()
        if plan:
            options = (
                RemediationOption(
                    action=getattr(plan.action, "value", str(plan.action)),
                    target_version=target,
                    description=redact_report_text(plan.rationale)
                    or "Persisted remediation plan.",
                    accepted=True,
                    reason="Selected by the persisted policy-constrained remediation plan.",
                    source_references=source_ids,
                ),
            )
        verification: list[VerificationResult] = []
        test_passed = execution.tests == StepState.EXECUTED
        verification.append(
            VerificationResult(
                check="sandbox_tests",
                state=execution.tests,
                passed=test_passed
                if execution.tests in {StepState.EXECUTED, StepState.FAILED}
                else None,
                details="Derived from matching BUILD_TEST_EXECUTED audit evidence.",
                source_event="BUILD_TEST_EXECUTED"
                if execution.tests != StepState.NOT_RUN
                else None,
            )
        )
        verification.append(
            VerificationResult(
                check="post_fix_rescan",
                state=execution.rescan,
                passed=(
                    bool(
                        state.verification_results
                        and state.verification_results[0].get("rescan_clean") is True
                    )
                    if execution.rescan == StepState.EXECUTED
                    else None
                ),
                details="A clean result is accepted only with an executed rescan audit event.",
                source_event="RESCAN_EXECUTED"
                if execution.rescan == StepState.EXECUTED
                else None,
            )
        )
        remaining: list[str] = []
        if execution.tests != StepState.EXECUTED:
            remaining.append("Run and review relevant build and test suites.")
        if execution.rescan != StepState.EXECUTED:
            remaining.append(
                "Execute a post-change scanner rescan and review residual findings."
            )
        if plan and plan.requires_approval:
            remaining.append("Obtain the required human approval before execution.")
        action = (
            getattr(getattr(plan, "action", None), "value", "none") if plan else "none"
        )
        proposed = (
            (f"{action} {package} to {target or 'an approved target'}.",)
            if plan
            else ()
        )
        plan_changes = _file_changes(state, plan.id, execution.patch) if plan else ()
        actual = tuple(
            f"Modified {change.path}."
            for change in plan_changes
            if execution.patch == StepState.EXECUTED
        )
        reports.append(
            RootCauseReport(
                root_cause_id=root_id,
                package=package,
                ecosystem=ecosystem,
                installed_version=installed,
                origin=(
                    DependencyOrigin.DIRECT
                    if group.get("is_direct", True)
                    else DependencyOrigin.TRANSITIVE
                ),
                dependency_chain=tuple(
                    redact_report_text(item)
                    for item in group.get("dependency_chain", [])
                ),
                associated_finding_ids=finding_ids,
                associated_cves=cves,
                advisory_evidence=advisories,
                impact_explanation=redact_report_text(group.get("explanation"))
                or "Impact was not evaluated.",
                options_considered=options,
                recommended_change=(
                    f"{action} {package} to {target}."
                    if plan and target
                    else "Manual review required."
                ),
                target_version=target,
                bump_class=_bump_class(installed, target, ecosystem),
                modified_files=plan_changes,
                risk_tier=risk,
                risk_reason=risk_reason,
                insights=tuple(insights),
                proposed_remediation_steps=proposed,
                actual_execution_steps=actual,
                verification_results=tuple(verification),
                remaining_developer_actions=tuple(remaining),
            )
        )
    return tuple(reports), expected_cves, finding_cves


def _verified_cves(
    state: VulnFlowState,
    execution: ExecutionEvidence,
    finding_cves: dict[str, set[str]],
) -> set[str]:
    if execution.rescan != StepState.EXECUTED or not state.verification_results:
        return set()
    verification = state.verification_results[0]
    if (
        verification.get("verified") is not True
        or verification.get("rescan_clean") is not True
    ):
        return set()
    return {
        cve
        for finding_id in verification.get("resolved_finding_ids", [])
        for cve in finding_cves.get(finding_id, set())
    }


def _policy(state: VulnFlowState) -> PolicyCompliance:
    rules: list[EvaluatedRule] = []
    approvals: list[str] = []
    issues: list[str] = []
    statuses: list[str] = []
    for plan in state.plans:
        status = redact_report_text(getattr(plan.policy_result, "status", "unknown"))
        statuses.append(status)
        rule = (
            redact_report_text(getattr(plan.policy_result, "rule_matched", None))
            or "UNKNOWN"
        )
        reason = redact_report_text(getattr(plan.policy_result, "reason", None)) or None
        rules.append(EvaluatedRule(rule=rule, status=status, evidence=reason))
        if plan.requires_approval:
            approvals.append(plan.id)
        if status not in {"approved"}:
            issues.append(f"{plan.target_package or plan.root_cause_id}: {status}")
    decisions: list[ApprovalDecision] = []
    for event in state.audit_events:
        event_type = event.get("event_type", "")
        if event_type not in {
            "PLAN_MANUALLY_APPROVED",
            "PLAN_MANUALLY_REJECTED",
            "PLAN_AUTO_APPROVED",
        }:
            continue
        payload = event.get("payload", {})
        decisions.append(
            ApprovalDecision(
                plan_id=redact_report_text(payload.get("plan_id", "UNKNOWN")),
                decision="rejected" if event_type.endswith("REJECTED") else "approved",
                actor=redact_report_text(event.get("actor")) or None,
                reason=redact_report_text(payload.get("reason")) or None,
            )
        )
    overall = (
        "approved"
        if statuses and all(item == "approved" for item in statuses)
        else (
            statuses[0]
            if len(set(statuses)) == 1 and statuses
            else "mixed"
            if statuses
            else "unknown"
        )
    )
    exceptions: tuple[str, ...] = ()
    if state.exception_ticket:
        exceptions = (
            redact_report_text(
                state.exception_ticket.get("ticket_id", "exception requested")
            ),
        )
    return PolicyCompliance(
        policy_status=overall,
        evaluated_rules=tuple(rules),
        approvals_required=tuple(approvals),
        approval_decisions=tuple(decisions),
        exceptions=exceptions,
        unresolved_policy_issues=tuple(issues),
    )


def build_run_report(
    state: VulnFlowState,
    *,
    generated_at: datetime | None = None,
    vulnflow_version: str = "0.2.0",
) -> RunReport:
    """Create a single report snapshot using only persisted state and audit evidence."""
    missing: list[str] = []
    rejected: list[str] = []
    unknown: list[str] = []
    incomplete: list[str] = []
    unsupported: list[str] = []
    execution, repo_changes, fixes, prs = _derive_execution(state)
    outcome = _normalized_outcome(state, unsupported)
    roots, expected_cves, finding_cves = _root_causes(
        state, execution, rejected, missing
    )
    verified_cves = _verified_cves(state, execution, finding_cves)
    analyzed = state.deduped_findings or state.findings
    before = _severity_counts(analyzed)
    after_total: int | None = None
    if execution.rescan == StepState.EXECUTED and state.verification_results:
        verification = state.verification_results[0]
        after_total = (
            0
            if verification.get("rescan_clean") is True
            else len(verification.get("new_finding_ids", []))
        )
    after = (
        SeverityCounts(critical=0, high=0, medium=0, low=0, info=0, total=0)
        if after_total == 0
        else _unknown_severity(after_total)
    )
    if execution.rescan == StepState.NOT_RUN:
        missing.append("No successful executed post-fix rescan audit event exists.")
        unknown.append(
            "After-state severity counts and unresolved finding count are unknown."
        )
    if execution.tests == StepState.NOT_RUN:
        missing.append("No matching BUILD_TEST_EXECUTED audit event exists.")
    if execution.patch in {StepState.FAILED, StepState.SIMULATED}:
        incomplete.append(
            f"Patch state is {execution.patch.value}; it is not counted as applied."
        )
    if state.mode in {"report", "dry-run"} and state.pull_requests:
        unsupported.append(
            "PR results present in a non-PR run were excluded from the report."
        )

    actions: list[ActionRequired] = []
    approved_ids = {plan.id for plan in state.approved_plans}
    rejected_ids = {plan.id for plan in state.rejected_plans}
    pending_plans = list(state.pending_approval_plans)
    pending_ids = {plan.id for plan in pending_plans}
    pending_plans.extend(
        plan
        for plan in state.plans
        if plan.requires_approval
        and plan.id not in approved_ids
        and plan.id not in rejected_ids
        and plan.id not in pending_ids
    )
    for plan in pending_plans:
        actions.append(
            ActionRequired(
                action_type="approve_remediation",
                priority="high",
                target_root_cause=redact_report_text(plan.root_cause_id),
                description=f"Review and approve plan {redact_report_text(plan.id)}.",
                required_actor="security_reviewer",
                completion_status=CompletionStatus.PENDING,
            )
        )
    if execution.rescan != StepState.EXECUTED and state.plans:
        actions.append(
            ActionRequired(
                action_type="execute_rescan",
                priority="high",
                description="Run a post-change vulnerability scan before claiming resolution.",
                required_actor="developer",
                completion_status=CompletionStatus.PENDING,
            )
        )
    if state.blocking_reason:
        actions.append(
            ActionRequired(
                action_type="resolve_blocker",
                priority="high",
                description=redact_report_text(state.blocking_reason),
                required_actor="security_reviewer",
                completion_status=CompletionStatus.BLOCKED,
            )
        )

    unresolved_ids: tuple[str, ...] = ()
    if execution.rescan == StepState.EXECUTED and state.verification_results:
        resolved = set(state.verification_results[0].get("resolved_finding_ids", []))
        unresolved_ids = tuple(
            finding.id for finding in analyzed if finding.id not in resolved
        )
    unverified = tuple(
        root.package for root in roots if execution.rescan != StepState.EXECUTED
    )
    policy = _policy(state)
    source_refs: list[SourceReference] = []
    for root in roots:
        for advisory in root.advisory_evidence:
            if advisory.validated:
                source_refs.append(
                    SourceReference(
                        source_id=advisory.evidence_id,
                        source_type="advisory",
                        title=advisory.title,
                        url=advisory.source_url,
                    )
                )
    input_hash = _hash_file(state.report_path)
    if input_hash is None:
        unknown.append("Input scanner file hash is unavailable.")
    audit_head = next(
        (
            event.get("entry_hash")
            for event in reversed(state.audit_events)
            if event.get("entry_hash")
        ),
        None,
    )
    if audit_head is None:
        unknown.append(
            "Audit chain head hash is unavailable in the persisted run snapshot."
        )
    branch = next(
        (
            payload.get("branch")
            for event_name in ("PR_CREATED", "BRANCH_CREATED")
            for payload in reversed(_event_payloads(state, event_name))
            if payload.get("branch")
        ),
        None,
    )
    commit_sha = next(
        (
            payload.get("commit_sha")
            for payload in reversed(_event_payloads(state, "COMMIT_CREATED"))
            if payload.get("commit_sha")
        ),
        None,
    )
    if commit_sha is None:
        unknown.append("Repository commit SHA is unavailable.")
    if branch is None:
        unknown.append("Repository branch is unavailable.")
    model_provider, model, token_usage, estimated_cost = _planner_llm_provenance(state)
    unknown.append(
        "Policy file hash and scanner version are not persisted by the current run state."
    )
    if model_provider is None:
        unknown.append(
            "Run-scoped model, prompt, token, cost, and trace metadata are unavailable."
        )
    else:
        unknown.append("Planner prompt version and trace reference are unavailable.")
    summary_sentence = (
        f"Analyzed {len(analyzed)} finding(s) across {len(roots)} root cause(s); "
        f"{len(verified_cves)} CVE(s) are verified resolved."
    )
    return RunReport(
        header=ReportHeader(
            run_id=redact_report_text(state.run_id),
            generated_at=generated_at or datetime.now(UTC),
            repository_name=redact_report_text(
                Path(state.repo_path).name or state.repo_path
            ),
            commit_sha=redact_report_text(commit_sha) if commit_sha else None,
            branch=redact_report_text(branch) if branch else None,
            scanner_name=redact_report_text(state.scanner or "unknown"),
            model=model,
            vulnflow_version=vulnflow_version,
            execution_mode=ExecutionMode(state.mode),
            outcome=outcome,
            exit_code=state.exit_code,
            repo_changes=repo_changes,
        ),
        executive_summary=ExecutiveSummary(
            summary_sentence=summary_sentence,
            severity_counts_before=before,
            severity_counts_after=after,
            findings_analyzed=len(analyzed),
            root_causes_identified=len(roots),
            remediation_plans_proposed=len(state.plans),
            expected_cves_addressed=len(expected_cves),
            verified_cves_resolved=len(verified_cves),
            fixes_applied=fixes,
            prs_actually_created=prs,
            unresolved_findings=(
                len(unresolved_ids) if execution.rescan == StepState.EXECUTED else None
            ),
        ),
        action_required=tuple(actions),
        root_causes=roots,
        policy_and_compliance=policy,
        residual_risk=ResidualRisk(
            unresolved_vulnerabilities=unresolved_ids,
            blocked_remediation=tuple(
                redact_report_text(plan.root_cause_id) for plan in state.rejected_plans
            ),
            accepted_exceptions=policy.exceptions,
            unverified_remediation=unverified,
            exposure_uncertainty=tuple(
                f"Reachability for {root.package} is UNKNOWN." for root in roots
            ),
            remaining_manual_review=tuple(action.description for action in actions),
        ),
        provenance=Provenance(
            input_scanner_file_sha256=input_hash,
            audit_chain_head_hash=audit_head,
            model_provider=model_provider,
            model=model,
            token_usage=token_usage,
            estimated_cost_usd=estimated_cost,
            source_evidence_references=tuple(source_refs),
        ),
        validation_notes=ValidationNotes(
            missing_evidence=tuple(dict.fromkeys(missing)),
            rejected_advisories=tuple(dict.fromkeys(rejected)),
            unknown_values=tuple(dict.fromkeys(unknown)),
            incomplete_execution=tuple(dict.fromkeys(incomplete)),
            unsupported_claims=tuple(dict.fromkeys(unsupported)),
        ),
        execution_evidence=execution,
    )
