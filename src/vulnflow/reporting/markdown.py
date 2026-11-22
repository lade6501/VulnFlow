"""
src/vulnflow/reporting/markdown.py
Renders a safe, concise reviewer report from the canonical snapshot.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from vulnflow.contracts.report import RunReport
from vulnflow.contracts.state import VulnFlowState
from vulnflow.reporting.builder import build_run_report

_MARKDOWN_META = re.compile(r"([\\`*_{}\[\]()<>#+.!|>-])")


def escape_markdown(value: object) -> str:
    """Neutralize Markdown syntax, directives, links, and user mentions."""
    text = str(value or "").replace("@", "@\u200b")
    text = text.replace("\r", " ").replace("\n", " ")
    return _MARKDOWN_META.sub(r"\\\1", text)


def _canonical(report: RunReport | VulnFlowState) -> RunReport:
    return report if isinstance(report, RunReport) else build_run_report(report)


def _count(value: object) -> str:
    return "UNKNOWN" if value is None else str(value)


def generate_markdown_report(
    report: RunReport | VulnFlowState, *, html_name: str = "report.html"
) -> str:
    """Render a bounded Markdown summary containing no untrusted Markdown structure."""
    snapshot = _canonical(report)
    header = snapshot.header
    summary = snapshot.executive_summary
    lines = [
        "# VulnFlow Enterprise Run Report",
        "",
        "## Outcome",
        "",
        (
            f"Run `{escape_markdown(header.run_id)}` finished as **{escape_markdown(header.outcome)}** "
            f"with exit code `{header.exit_code}` in `{header.execution_mode.value}` mode."
        ),
        f"Repository files changed: **{header.repo_changes.value}**.",
        "",
        "## Summary of findings and risk",
        "",
        escape_markdown(summary.summary_sentence),
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Findings analyzed | {summary.findings_analyzed} |",
        f"| Root causes | {summary.root_causes_identified} |",
        f"| Expected CVEs addressed | {summary.expected_cves_addressed} |",
        f"| Verified CVEs resolved | {summary.verified_cves_resolved} |",
        f"| Fixes applied | {summary.fixes_applied} |",
        f"| PRs actually created | {summary.prs_actually_created} |",
        f"| Unresolved findings | {_count(summary.unresolved_findings)} |",
        "",
        "## Action required",
        "",
    ]
    if snapshot.action_required:
        for action in snapshot.action_required:
            target = (
                f" for {escape_markdown(action.target_root_cause)}"
                if action.target_root_cause
                else ""
            )
            lines.append(
                f"- **{escape_markdown(action.priority)}**: {escape_markdown(action.description)}"
                f"{target} — actor: `{escape_markdown(action.required_actor)}`; "
                f"status: `{action.completion_status.value}`."
            )
    else:
        lines.append("- No immediate action is recorded.")
    lines.extend(["", "## Root-cause remediation summaries", ""])
    for root in snapshot.root_causes:
        lines.extend(
            [
                f"### {escape_markdown(root.package)}",
                "",
                (
                    f"- Origin: `{root.origin.value}`; installed: "
                    f"`{escape_markdown(root.installed_version or 'UNKNOWN')}`; target: "
                    f"`{escape_markdown(root.target_version or 'UNKNOWN')}`."
                ),
                f"- Findings/CVEs: `{len(root.associated_finding_ids)}` / `{len(root.associated_cves)}`.",
                f"- Recommended: {escape_markdown(root.recommended_change)}",
                f"- Why selected: {escape_markdown(root.risk_reason)}",
                f"- Risk tier: `{escape_markdown(root.risk_tier)}`.",
                f"- Policy status: `{escape_markdown(snapshot.policy_and_compliance.policy_status)}`.",
                "",
            ]
        )
    lines.extend(["## What changed", ""])
    changed = [
        change for root in snapshot.root_causes for change in root.modified_files
    ]
    if changed:
        for change in changed:
            lines.append(
                f"- `{escape_markdown(change.path)}` — `{change.state.value}`; "
                f"+{_count(change.lines_added)} / -{_count(change.lines_removed)} lines."
            )
    else:
        lines.append("- No repository file change has verified execution evidence.")
    lines.extend(["", "## Verification state", ""])
    evidence = snapshot.execution_evidence
    lines.extend(
        [
            f"- Patch: `{evidence.patch.value}`",
            f"- Tests: `{evidence.tests.value}`",
            f"- Pull request: `{evidence.pull_request.value}`",
            f"- Post-fix rescan: `{evidence.rescan.value}`",
            "",
            "## Risks",
            "",
        ]
    )
    risks = (
        list(snapshot.residual_risk.unresolved_vulnerabilities)
        + list(snapshot.residual_risk.blocked_remediation)
        + list(snapshot.residual_risk.unverified_remediation)
        + list(snapshot.residual_risk.exposure_uncertainty)
    )
    lines.extend(f"- {escape_markdown(item)}" for item in risks[:20])
    if not risks:
        lines.append(
            "- No residual risk was recorded; consult validation notes for evidence limitations."
        )
    lines.extend(["", "## Developer next steps", ""])
    next_steps = [
        item
        for root in snapshot.root_causes
        for item in root.remaining_developer_actions
    ]
    lines.extend(f"- {escape_markdown(item)}" for item in dict.fromkeys(next_steps))
    if not next_steps:
        lines.append("- Review the full evidence report before merging.")
    lines.extend(
        [
            "",
            f"Full report: [{escape_markdown(html_name)}]({escape_markdown(html_name)})",
            "",
        ]
    )
    rendered = "\n".join(lines)
    if len(rendered) > 8_000:
        rendered = rendered[:7_700].rstrip() + (
            "\n\nReport truncated for review safety. See "
            f"[{escape_markdown(html_name)}]({escape_markdown(html_name)}) for complete evidence.\n"
        )
    return rendered[:60_000]


def write_markdown_report(
    report: RunReport | VulnFlowState, output_path: str | Path
) -> Path:
    """Atomically persist the canonical Markdown report."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = generate_markdown_report(report) + "\n"
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{out.name}.", dir=out.parent, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_name, out)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    return out
