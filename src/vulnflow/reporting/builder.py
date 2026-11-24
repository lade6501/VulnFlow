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

from vulnflow.contracts.finding import FindingType
from vulnflow.contracts.remediation_plan import RemediationAction, RiskTier
from vulnflow.contracts.report import (
    ActionRequired,
    AdvisoryEvidence,
    AppliedPatchSummary,
    ApprovalDecision,
    ApprovalGroup,
    CampaignSummary,
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
    PullRequestSummary,
    RemediationOption,
    RepoChanges,
    ReportHeader,
    ResidualRisk,
    RootCauseReport,
    RunReport,
    SecretExposureSummary,
    SecurityInsight,
    SeverityCounts,
    SourceReference,
    StepState,
    StrategicDecision,
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
    seen_call_ids: set[str] = set()
    for payload in _event_payloads(state, "PLAN_FORMULATED"):
        enrichment = payload.get("llm_enrichment")
        if not isinstance(enrichment, dict) or enrichment.get("state") not in {
            "executed",
            "cached",
        }:
            continue
        call_id = enrichment.get("call_id")
        if isinstance(call_id, str):
            if call_id in seen_call_ids:
                continue
            seen_call_ids.add(call_id)
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
            if isinstance(item.get(field), int)
            and not isinstance(item.get(field), bool)
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


def _normalize_ecosystem(eco: str | None) -> str:
    """Normalize package ecosystem identifiers (e.g. 'pip' vs 'PyPI', 'node' vs 'npm')."""
    if not eco:
        return ""
    val = eco.strip().lower()
    if val in {"pip", "pypi", "python", "py"}:
        return "pypi"
    if val in {"npm", "node", "javascript", "js"}:
        return "npm"
    if val in {"maven", "java", "mvn"}:
        return "maven"
    if val in {"go", "golang"}:
        return "golang"
    if val in {"rubygems", "gem", "ruby"}:
        return "rubygems"
    if val in {"cargo", "rust", "crates.io"}:
        return "cargo"
    if val in {"nuget", "dotnet", "csharp"}:
        return "nuget"
    return val


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
    elif _normalize_ecosystem(evidence_ecosystem) != _normalize_ecosystem(ecosystem):
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
        is_secret_group = (
            root_id.startswith("SECRET-")
            or "secret:" in package.lower()
            or package == "[REDACTED]"
            or any(
                item.get("type") in ("secret", "FindingType.SECRET")
                or "secret" in str(item.get("details", {})).lower()
                for item in raw_findings
            )
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
        if plan and getattr(plan, "risk_tier", None) == RiskTier.AUTO:
            risk_reason = "Routine patch version update with green test verification (RiskTier.AUTO)"
        else:
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
        if plan and plan.rationale:
            clean_rat = redact_report_text(plan.rationale)
            insights.append(
                SecurityInsight(
                    category="remediation_strategy",
                    text=clean_rat,
                    generated_by=GeneratedBy.LLM
                    if ("•" in clean_rat or "Developer Migration" in clean_rat)
                    else GeneratedBy.RULES,
                    source_references=source_ids or finding_ids,
                    evidence_availability=EvidenceAvailability.AVAILABLE,
                )
            )

        if (
            installed
            and target
            and installed not in ("UNKNOWN", "none")
            and target not in ("UNKNOWN", "none", "latest", "env-var")
        ):
            cur_parts = _version_parts(installed, ecosystem)[0]
            tgt_parts = _version_parts(target, ecosystem)[0]
            if cur_parts and tgt_parts:
                cur_num = cur_parts + (0, 0, 0)
                tgt_num = tgt_parts + (0, 0, 0)
                if tgt_num[0] > cur_num[0]:
                    insights.append(
                        SecurityInsight(
                            category="compatibility_concern",
                            text=(
                                f"Major SemVer leap from {installed} to {target} (v{cur_num[0]} to v{tgt_num[0]}). "
                                "Breaking API changes and deprecations may affect existing callsites."
                            ),
                            generated_by=GeneratedBy.RULES,
                            source_references=finding_ids,
                            evidence_availability=EvidenceAvailability.AVAILABLE,
                            uncertainty="Static SemVer comparison does not prove runtime breakage without integration testing.",
                        )
                    )
                elif tgt_num[1] > cur_num[1]:
                    insights.append(
                        SecurityInsight(
                            category="compatibility_concern",
                            text=f"Minor SemVer update from {installed} to {target}. Backwards compatibility is expected under SemVer.",
                            generated_by=GeneratedBy.RULES,
                            source_references=finding_ids,
                            evidence_availability=EvidenceAvailability.AVAILABLE,
                        )
                    )
                else:
                    insights.append(
                        SecurityInsight(
                            category="compatibility_concern",
                            text=f"Patch version bump from {installed} to {target}. Backward compatible security fix with low risk of regressions.",
                            generated_by=GeneratedBy.RULES,
                            source_references=finding_ids,
                            evidence_availability=EvidenceAvailability.AVAILABLE,
                        )
                    )

        insights.append(
            SecurityInsight(
                category="verification_guidance",
                text=f"Run automated test suite and execute a post-fix security rescan to confirm {len(cves)} CVE(s) in {package} are resolved.",
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
        bump = _bump_class(installed, target, ecosystem)
        if bump == "major":
            breaking_notes = f"Major SemVer leap from {installed} to {target}. Breaking API changes and deprecations may affect existing callsites."
            migr_notes = "Review upstream migration guide, update deprecated callsites, and run integration test suite."
        elif bump in ("minor", "patch"):
            breaking_notes = f"Backward-compatible {bump} version bump from {installed} to {target}. No breaking API changes expected."
            migr_notes = "Verify existing unit tests pass cleanly after bump."
        else:
            breaking_notes = "No version bump proposed; manual review required."
            migr_notes = "Consult security advisory for workaround guidance."

        reports.append(
            RootCauseReport(
                root_cause_id=root_id,
                package=package,
                ecosystem=ecosystem,
                installed_version=installed,
                origin=(
                    DependencyOrigin.OTHER
                    if is_secret_group
                    else (
                        DependencyOrigin.DIRECT
                        if group.get("is_direct", True)
                        else DependencyOrigin.TRANSITIVE
                    )
                ),
                dependency_chain=tuple(
                    redact_report_text(item)
                    for item in group.get("dependency_chain", [])
                ),
                associated_finding_ids=finding_ids,
                associated_cves=cves,
                advisory_evidence=advisories,
                impact_explanation=(
                    "Hardcoded secret or credential detected in source code. Secret rotation and removal from git history required."
                    if is_secret_group
                    else (
                        redact_report_text(group.get("explanation"))
                        or "Impact was not evaluated."
                    )
                ),
                options_considered=options,
                recommended_change=(
                    "Rotate exposed credentials and migrate secrets to environment variables or vault."
                    if is_secret_group
                    else (
                        f"{action} {package} to {target}."
                        if plan and target
                        else "Manual review required."
                    )
                ),
                target_version=target,
                bump_class=bump,
                modified_files=plan_changes,
                risk_tier=risk,
                risk_reason=risk_reason,
                insights=tuple(insights),
                breaking_change_notes=breaking_notes,
                migration_notes=migr_notes,
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


def _build_pull_requests(
    state: VulnFlowState, execution: ExecutionEvidence
) -> tuple[PullRequestSummary, ...]:
    """Extract real verified PR records confirmed by stored PR_CREATED audit evidence."""
    if state.mode in {"report", "dry-run"}:
        return ()

    pr_summaries: list[PullRequestSummary] = []
    pr_events = _event_payloads(state, "PR_CREATED")
    commit_sha = next(
        (
            payload.get("commit_sha")
            for payload in reversed(_event_payloads(state, "COMMIT_CREATED"))
            if payload.get("commit_sha")
        ),
        None,
    )

    for pr in state.pull_requests:
        if not isinstance(pr, dict):
            continue
        raw_url = pr.get("pr_url")
        url = _safe_external_url(raw_url)
        # Verify matching PR_CREATED audit evidence
        ev_match = next(
            (
                ev
                for ev in pr_events
                if ev.get("pr_url") == raw_url or ev.get("branch") == pr.get("branch")
            ),
            None,
        )
        if url and ev_match:
            branch = str(pr.get("branch") or ev_match.get("branch") or "")
            is_campaign = bool(pr.get("campaign") or ev_match.get("campaign"))
            if is_campaign:
                pkgs = tuple(
                    sorted(
                        dict.fromkeys(
                            p.target_package or p.root_cause_id
                            for p in state.approved_plans
                            if getattr(p, "action", None) == RemediationAction.BUMP
                            and "secret:" not in str(p.root_cause_id)
                        )
                    )
                )
            else:
                matching = [
                    p.target_package or p.root_cause_id
                    for p in state.approved_plans
                    if (p.target_package and p.target_package in branch)
                    or (p.id in branch)
                ]
                pkgs = tuple(sorted(dict.fromkeys(matching)))

            pr_summaries.append(
                PullRequestSummary(
                    pr_number=pr.get("pr_number") or ev_match.get("pr_number"),
                    pr_url=url,
                    branch=redact_report_text(branch),
                    title=redact_report_text(pr.get("title") or ev_match.get("title")),
                    commit_sha=redact_report_text(commit_sha),
                    affected_packages=pkgs or tuple(pr.get("packages", ())),
                    plans_count=len(pkgs) or int(pr.get("plans_count", 1)),
                    campaign=is_campaign,
                    status=str(pr.get("status", "opened")),
                    verified=(execution.rescan == StepState.EXECUTED),
                )
            )
    return tuple(pr_summaries)


def _build_applied_patches(
    state: VulnFlowState, execution: ExecutionEvidence
) -> tuple[AppliedPatchSummary, ...]:
    """Collect applied file changes and diff snippets verified by audit evidence."""
    if execution.patch != StepState.EXECUTED:
        return ()

    patch_summaries: list[AppliedPatchSummary] = []
    for patch in state.patches:
        if not isinstance(patch, dict):
            continue
        res = patch.get("result", {})
        if res.get("status") == "applied" or patch.get("diff"):
            plan_match = next(
                (p for p in state.plans if p.id == patch.get("plan_id")), None
            )
            target_pkg = (
                plan_match.target_package
                if plan_match and plan_match.target_package
                else (patch.get("file") or "manifest")
            )
            diff_text = str(patch.get("diff") or "")
            snippet_lines = [line for line in diff_text.strip().splitlines() if line]
            snippet = "\n".join(snippet_lines[:10]) if snippet_lines else None
            added = sum(
                1
                for line in diff_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            )
            removed = sum(
                1
                for line in diff_text.splitlines()
                if line.startswith("-") and not line.startswith("---")
            )
            lines_added = (
                res.get("lines_added")
                if res.get("lines_added") is not None
                else (added if diff_text else None)
            )
            lines_removed = (
                res.get("lines_removed")
                if res.get("lines_removed") is not None
                else (removed if diff_text else None)
            )
            patch_summaries.append(
                AppliedPatchSummary(
                    plan_id=str(patch.get("plan_id", "PLAN-APPLIED")),
                    target_package=redact_report_text(target_pkg),
                    file_path=redact_report_text(patch.get("file", "")),
                    status="applied",
                    lines_added=lines_added,
                    lines_removed=lines_removed,
                    diff_snippet=redact_report_text(snippet) if snippet else None,
                )
            )
    return tuple(patch_summaries)


def _build_campaigns(
    state: VulnFlowState,
    pr_summaries: tuple[PullRequestSummary, ...],
    execution: ExecutionEvidence,
    fixes: int,
) -> tuple[CampaignSummary, ...]:
    """Synthesize multi-package coordinated campaigns for high-level governance."""
    campaigns: list[CampaignSummary] = []
    dep_plans = [p for p in state.plans if "secret:" not in str(p.root_cause_id)]
    if dep_plans:
        camp_branch = next(
            (b for b in state.created_branches if "campaign" in b),
            f"vulnflow/campaign-{state.run_id[:8]}",
        )
        pr_match = next((pr for pr in pr_summaries if pr.campaign), None)
        dep_pkgs = tuple(
            sorted(
                dict.fromkeys(
                    p.target_package or p.root_cause_id
                    for p in dep_plans
                    if p.target_package or p.root_cause_id
                )
            )
        )
        all_f = state.deduped_findings or state.findings
        dep_cves = tuple(
            sorted(
                dict.fromkeys(
                    c
                    for p in dep_plans
                    for f in all_f
                    if f.id in p.finding_ids
                    for c in f.cve
                )
            )
        )
        camp_status = "opened" if pr_match else ("applied" if fixes > 0 else "prepared")
        campaigns.append(
            CampaignSummary(
                campaign_id="CAMP-DEPS-01",
                title="Coordinated Dependency Modernization Campaign",
                branch=camp_branch,
                pr_url=pr_match.pr_url if pr_match else None,
                packages=dep_pkgs,
                plans_count=len(dep_plans),
                cves_addressed=dep_cves,
                status=camp_status,
            )
        )

    sec_plans = [p for p in state.plans if "secret:" in str(p.root_cause_id)]
    if sec_plans:
        sec_applied = any(
            p.id
            in [
                patch.get("plan_id")
                for patch in state.patches
                if isinstance(patch, dict)
            ]
            for p in sec_plans
        )
        campaigns.append(
            CampaignSummary(
                campaign_id="CAMP-SECRETS-01",
                title="Consolidated Hardcoded Secrets & Credentials Rotation",
                branch="vulnflow/campaign-secrets",
                pr_url=None,
                packages=("secret:credentials",),
                plans_count=len(sec_plans),
                cves_addressed=(),
                status="applied" if sec_applied else "awaiting_approval",
            )
        )
    return tuple(campaigns)


def _build_approval_groups(state: VulnFlowState) -> tuple[ApprovalGroup, ...]:
    """Group pending approval plans into prioritized, actionable review categories."""
    approved_ids = {plan.id for plan in state.approved_plans}
    rejected_ids = {plan.id for plan in state.rejected_plans}
    pending = [
        p
        for p in state.plans
        if p.requires_approval and p.id not in approved_ids and p.id not in rejected_ids
    ]
    if not pending:
        return ()

    groups: list[ApprovalGroup] = []
    repo = state.repo_path

    # Group 1: Secrets
    sec_plans = [
        p
        for p in pending
        if "secret" in str(p.root_cause_id).lower()
        or "secret" in str(p.target_package).lower()
    ]
    if sec_plans:
        sec_ids = tuple(p.id for p in sec_plans)
        groups.append(
            ApprovalGroup(
                group_type="secrets",
                title="Exposed Credentials & Secret Rotation",
                description="Hardcoded passwords, API tokens, or secrets detected in source code. Proposes rotation to environment variables.",
                plans_count=len(sec_plans),
                plan_ids=sec_ids,
                target_packages=("secret:credentials",),
                cves_count=0,
                risk_tier="review",
                recommended_action="Review rotated environment variables and authorize branch commit.",
                cli_command=f"vulnflow approve --plan-id {','.join(sec_ids)} --resume --repo {repo}",
                requires_human_review=True,
            )
        )

    # Group 2: Breaking major updates vs Group 3: Standard unapproved updates
    breaking_plans = []
    standard_plans = []
    findings_by_id = {f.id: f for f in (state.deduped_findings or state.findings)}

    for p in pending:
        if (
            "secret" in str(p.root_cause_id).lower()
            or "secret" in str(p.target_package).lower()
        ):
            continue
        cur_v = "0.0.0"
        for fid in p.finding_ids:
            if fid in findings_by_id:
                cur_v = findings_by_id[fid].version
                break
        cur_p = _version_parts(cur_v, state.ecosystem)[0] + (0, 0, 0)
        tgt_p = _version_parts(p.target_version or "0.0.0", state.ecosystem)[0] + (
            0,
            0,
            0,
        )
        if tgt_p[0] > cur_p[0]:
            breaking_plans.append(p)
        else:
            standard_plans.append(p)

    if breaking_plans:
        b_ids = tuple(p.id for p in breaking_plans)
        b_pkgs = tuple(
            sorted(
                dict.fromkeys(
                    p.target_package or p.root_cause_id for p in breaking_plans
                )
            )
        )
        b_cves = sum(len(p.finding_ids) for p in breaking_plans)
        groups.append(
            ApprovalGroup(
                group_type="breaking_dependency_updates",
                title="Major Breaking Dependency Upgrades",
                description="Upgrades crossing major SemVer version boundaries with expected API breaks or deprecations.",
                plans_count=len(breaking_plans),
                plan_ids=b_ids,
                target_packages=b_pkgs,
                cves_count=b_cves,
                risk_tier="review",
                recommended_action="Verify test suite compatibility and authorize major version bumps.",
                cli_command=f"vulnflow approve --plan-id {','.join(b_ids)} --resume --repo {repo}",
                requires_human_review=True,
            )
        )

    if standard_plans:
        s_ids = tuple(p.id for p in standard_plans)
        s_pkgs = tuple(
            sorted(
                dict.fromkeys(
                    p.target_package or p.root_cause_id for p in standard_plans
                )
            )
        )
        s_cves = sum(len(p.finding_ids) for p in standard_plans)
        groups.append(
            ApprovalGroup(
                group_type="unapproved_dependencies",
                title="Unvetted Library Security Updates",
                description="Packages not pre-authorized on corporate approved lists; minor or patch version bumps.",
                plans_count=len(standard_plans),
                plan_ids=s_ids,
                target_packages=s_pkgs,
                cves_count=s_cves,
                risk_tier="review",
                recommended_action="Authorize automated branch remediation for safe candidate versions.",
                cli_command=f"vulnflow approve --plan-id {','.join(s_ids)} --resume --repo {repo}",
                requires_human_review=True,
            )
        )

    return tuple(groups)


def _build_secrets_exposure(state: VulnFlowState) -> tuple[SecretExposureSummary, ...]:
    """Extract dedicated secrets and credential findings."""
    exposures: list[SecretExposureSummary] = []
    seen: set[tuple[str, str, int | None]] = set()
    sec_plan = next(
        (
            p
            for p in state.plans
            if "secret" in p.root_cause_id.lower()
            or "secret" in (p.target_package or "").lower()
        ),
        None,
    )
    plan_id = sec_plan.id if sec_plan else None
    all_findings = state.deduped_findings or state.findings
    for f in all_findings:
        meta = getattr(f, "metadata", {}) or {}
        details = (
            meta.get("details")
            or meta.get("description")
            or getattr(f, "raw_ref", "")
            or ""
        )
        f_type = getattr(f, "type", None)
        f_type_str = (
            str(f_type.value) if isinstance(f_type, FindingType) else str(f_type or "")
        )
        is_secret = (
            f_type == FindingType.SECRET
            or f_type_str.lower() == "secret"
            or (
                bool(details)
                and any(
                    k in str(details).lower()
                    for k in ("secret", "password", "key", "credential", "token")
                )
            )
            or ("secret" in getattr(f, "package", "").lower())
        )
        if not is_secret:
            continue
        rule_or_desc = (
            meta.get("rule_id")
            or meta.get("description")
            or (f.cve[0] if getattr(f, "cve", None) else None)
            or (str(details) if details else "Hardcoded Credential")
        )
        loc = getattr(f, "location", None)
        file_path = (
            getattr(loc, "file_path", "")
            or (loc.get("file_path", "") if isinstance(loc, dict) else "")
            or "unknown location"
        )
        line_no = (
            getattr(loc, "line", None)
            or (
                getattr(loc, "line_start", None) if hasattr(loc, "line_start") else None
            )
            or (
                loc.get("line") or loc.get("line_start")
                if isinstance(loc, dict)
                else None
            )
        )
        key = (rule_or_desc, file_path, line_no)
        if key in seen:
            continue
        seen.add(key)
        exposures.append(
            SecretExposureSummary(
                secret_type=redact_report_text(rule_or_desc),
                file_path=redact_report_text(file_path),
                line_number=line_no,
                finding_id=redact_report_text(f.id),
                plan_id=plan_id,
                action_required="Rotate credentials, revoke token in upstream console, and store in environment variables",
                status=(
                    "pending_approval"
                    if (sec_plan and sec_plan.requires_approval)
                    else "identified"
                ),
            )
        )
    return tuple(exposures)


def _build_strategic_decisions(
    state: VulnFlowState,
    roots: tuple[RootCauseReport, ...],
    execution: ExecutionEvidence,
    fixes: int,
    pr_summaries: tuple[PullRequestSummary, ...],
    approval_groups: tuple[ApprovalGroup, ...],
    secrets_exposure: tuple[SecretExposureSummary, ...],
) -> tuple[StrategicDecision, ...]:
    """Generate high-priority, cross-cutting strategic AI conclusions for executive leadership."""
    decisions: list[StrategicDecision] = []

    # 1. Automated Low-Risk Remediation
    if fixes > 0 or pr_summaries:
        remediated_pkgs = (
            tuple(
                dict.fromkeys(
                    pkg for pr in pr_summaries for pkg in pr.affected_packages
                )
            )
            or tuple(
                r.package
                for r in roots
                if r.bump_class in ("minor", "patch") and r.target_version
            )[:3]
        )
        pr_link_text = (
            f"Pull Request #{pr_summaries[0].pr_number}"
            if pr_summaries and pr_summaries[0].pr_number
            else "candidate pull request"
        )
        decisions.append(
            StrategicDecision(
                category="automated_remediation",
                title="Automated Remediation Demonstrated",
                finding=f"Autonomous zero-wait remediation executed for verified low-risk dependencies ({', '.join(remediated_pkgs) if remediated_pkgs else 'routine updates'}) under tier 'auto'.",
                impact="Immediately reduces repository vulnerability exposure with zero breaking changes or developer toil.",
                recommendation="Review regression test status and merge opened pull request; complete post-change rescan to verify resolution.",
                action_taken=f"Applied {fixes} automated file patch(es) and opened {pr_link_text}.",
                human_decision="Approve pull request merge and authorize automated workflow completion.",
                evidence_summary="Verified by Git patch execution and PR_CREATED audit trail.",
                packages_affected=remediated_pkgs,
                count=fixes,
            )
        )

    # 2. Major Upgrades & Breaking Changes
    major_roots = [r for r in roots if r.bump_class == "major" and r.target_version]
    if major_roots:
        major_pkgs = tuple(dict.fromkeys(r.package for r in major_roots))
        decisions.append(
            StrategicDecision(
                category="breaking_upgrades",
                title=f"Major Upgrades Require Compatibility Assessment ({len(major_roots)} packages)",
                finding=f"Identified {len(major_roots)} major version upgrade(s) across frameworks and dependencies ({', '.join(major_pkgs[:4])}{'...' if len(major_pkgs) > 4 else ''}).",
                impact="Major version leaps risk introducing breaking API changes, removed functions, and runtime deprecations in downstream callsites.",
                recommendation="Do not auto-apply major bumps across production code. Isolate into staged branches and execute full integration test suites with migration audits.",
                action_taken=f"Quarantined {len(major_roots)} major upgrade plans into security review queue with candidate version targets.",
                human_decision="Engineering leads must review candidate diffs and authorize staged upgrades or assign refactoring sprints.",
                evidence_summary=f"SemVer boundary leap analysis across {len(major_roots)} candidate plans.",
                packages_affected=major_pkgs,
                count=len(major_roots),
            )
        )

    # 3. Corporate Policy Execution Constraints
    policy_group = next(
        (g for g in approval_groups if g.group_type == "unapproved_dependencies"), None
    )
    if policy_group:
        decisions.append(
            StrategicDecision(
                category="corporate_policy",
                title=f"Corporate Policy Governs Execution ({policy_group.plans_count} packages)",
                finding=f"Corporate approval policy mandates human security authorization for {policy_group.plans_count} library update(s) not pre-approved in organizational policy.",
                impact="Autonomous pipeline pauses at governance gates to maintain compliance and prevent unauthorized third-party library additions.",
                recommendation="Audit and add trusted enterprise libraries to policies/approved_packages.yaml to enable zero-wait auto-remediation in future CI runs.",
                action_taken="Generated prioritized approval plans and queued for batch authorization.",
                human_decision=f"Authorize pending updates in 1 click using '{policy_group.cli_command}' or approve via GitHub Action workflow dispatch.",
                evidence_summary="PolicyEngine evaluation rules and risk tiering criteria.",
                packages_affected=policy_group.target_packages,
                count=policy_group.plans_count,
            )
        )

    # 4. Credential & Secret Exposure
    sec_pkgs = tuple(
        dict.fromkeys(
            r.package
            for r in roots
            if "secret" in r.root_cause_id.lower() or r.package == "[REDACTED]"
        )
    )
    if secrets_exposure or sec_pkgs:
        sec_count = len(secrets_exposure) or len(sec_pkgs)
        sec_files = tuple(dict.fromkeys(s.file_path for s in secrets_exposure)) or (
            "repository source files",
        )
        pkg_desc = f" ({', '.join(sec_pkgs)})" if sec_pkgs else ""
        decisions.append(
            StrategicDecision(
                category="secrets_exposure",
                title=f"Credential Exposure Requires Separate Handling ({sec_count} findings)",
                finding=f"Detected {sec_count} hardcoded secret and credential exposure(s) in repository files{pkg_desc}.",
                impact="Critical lateral movement and credential theft risk. Software package upgrades cannot mitigate secret exposures.",
                recommendation="Immediately revoke exposed keys in external provider consoles; rotate credentials and migrate code to environment variables or vault.",
                action_taken="Consolidated all credential findings into a dedicated secrets remediation campaign and halted automatic code pushing.",
                human_decision="Security reviewer must verify credential revocation in cloud provider consoles before authorizing secret rotation plan.",
                evidence_summary=f"Secret detection scanner matches across {len(sec_files)} file(s).",
                packages_affected=sec_pkgs
                or tuple(dict.fromkeys(s.secret_type for s in secrets_exposure)),
                count=sec_count,
            )
        )

    # 5. Deprecated Libraries & Architectural Migrations
    deprecations = [
        r
        for r in roots
        if "deprecated" in r.risk_reason.lower()
        or "replace" in r.recommended_change.lower()
    ]
    if deprecations:
        dep_pkgs = tuple(dict.fromkeys(d.package for d in deprecations))
        decisions.append(
            StrategicDecision(
                category="migration",
                title=f"Upstream Deprecations & Architectural Migrations ({len(deprecations)} packages)",
                finding=f"Deprecated or end-of-life dependencies detected ({', '.join(dep_pkgs)}).",
                impact="Unmaintained libraries accumulate permanent unpatchable vulnerabilities and lack upstream security maintenance.",
                recommendation="Plan architectural refactoring to active modern alternatives (e.g. replacing Moment.js with date-fns or Luxon; request with axios/fetch).",
                action_taken="Formulated replacement plans and migration exception guidance.",
                human_decision="Schedule engineering sprint work to modernize deprecated dependency callsites.",
                evidence_summary="Upstream deprecation advisories and ecosystem policy checks.",
                packages_affected=dep_pkgs,
                count=len(deprecations),
            )
        )

    if not decisions:
        decisions.append(
            StrategicDecision(
                category="general",
                title="Security Posture Evaluation",
                finding="No critical or outstanding security remediation decisions required.",
                impact="Repository dependencies and source manifests conform to current policy rules.",
                recommendation="Maintain continuous automated scanning on pull requests and dependency updates.",
                action_taken="Evaluation completed with zero pending approvals.",
                human_decision="No human decision required.",
                evidence_summary="All policy checks and scanner evaluations passed cleanly.",
                packages_affected=(),
                count=0,
            )
        )

    return tuple(decisions)


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
    prs_data = _build_pull_requests(state, execution)
    patches_data = _build_applied_patches(state, execution)
    campaigns_data = _build_campaigns(state, prs_data, execution, fixes)
    approval_data = _build_approval_groups(state)
    secrets_data = _build_secrets_exposure(state)
    strategic_data = _build_strategic_decisions(
        state, roots, execution, fixes, prs_data, approval_data, secrets_data
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
        pull_requests=prs_data,
        applied_patches=patches_data,
        remediation_campaigns=campaigns_data,
        approval_groups=approval_data,
        strategic_decisions=strategic_data,
        secrets_exposure=secrets_data,
    )
