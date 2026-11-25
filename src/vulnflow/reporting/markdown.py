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


def _approval_lines(snapshot: RunReport) -> list[str]:
    lines = ["## Approval and Developer Actions", ""]
    if snapshot.approval_groups:
        pending = sum(group.plans_count for group in snapshot.approval_groups)
        lines.extend([
            f"> **Governance Authorization Gate** · {pending} plans pending review.",
            "",
            "| Approval group | Plans | Recommended action |",
            "| --- | ---: | --- |",
        ])
        for group in snapshot.approval_groups:
            lines.append(
                f"| {escape_markdown(group.title)} | {group.plans_count} | "
                f"{escape_markdown(group.recommended_action)} |"
            )
        lines.extend([
            "",
            "**Batch approval command**",
            "",
            f"```bash\nvulnflow approve --all --resume --repo {escape_markdown(snapshot.header.repository_name)}\n```",
            "",
        ])

    other_actions = [
        action for action in snapshot.action_required if action.action_type != "approve_remediation"
    ]
    if other_actions:
        lines.extend([
            "| Priority | Action required | Owner |",
            "| --- | --- | --- |",
        ])
        for action in other_actions[:8]:
            lines.append(
                f"| {escape_markdown(action.priority.title())} | {escape_markdown(action.description)} | "
                f"{escape_markdown(action.required_actor)} |"
            )
        lines.append("")
        if len(other_actions) > 8:
            lines.extend(["See the technical report for all recorded actions.", ""])
    elif not snapshot.action_required:
        lines.extend(["No additional actions were recorded.", ""])

    next_steps = list(dict.fromkeys(
        step for root in snapshot.root_causes for step in root.remaining_developer_actions
    ))
    if next_steps:
        lines.extend(["### Developer next steps", ""])
        lines.extend(f"- {escape_markdown(step)}" for step in next_steps[:6])
        lines.append("")
        if len(next_steps) > 6:
            lines.extend(["See the technical report for the remaining component actions.", ""])
    return lines


def generate_markdown_report(
    report: RunReport | VulnFlowState, *, html_name: str = "report.html"
) -> str:
    """Render an execution-first, bounded Markdown summary containing verified evidence."""
    snapshot = _canonical(report)
    header = snapshot.header
    summary = snapshot.executive_summary
    evidence = snapshot.execution_evidence

    lines = [
        "# VulnFlow Enterprise Run Report",
        "",
        "## Run Overview",
        "",
        f"> **{escape_markdown(header.outcome.replace('_', ' ').title())}** · "
        f"{escape_markdown(header.repository_name)} · Run `{escape_markdown(header.run_id)}`",
        "",
        f"Mode `{header.execution_mode.value}` · Exit code `{header.exit_code}` · "
        f"Repository changes `{header.repo_changes.value}`",
        "",
        "[Technical evidence](technical-report.html) · [Run data](run-report.json)",
        "",
        "## Executive Security Assessment",
        "",
        "### Summary of findings and risk",
        "",
        escape_markdown(summary.summary_sentence),
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Findings analyzed | {summary.findings_analyzed} |",
        f"| Root causes | {summary.root_causes_identified} |",
        f"| Proposed plans | {summary.remediation_plans_proposed} |",
        f"| Expected CVEs addressed | {summary.expected_cves_addressed} |",
        f"| Verified CVEs resolved | {summary.verified_cves_resolved} |",
        f"| Fixes applied | {summary.fixes_applied} |",
        f"| PRs actually created | {summary.prs_actually_created} |",
        f"| Unresolved findings | {_count(summary.unresolved_findings)} |",
        "",
    ]
    lines.extend(_approval_lines(snapshot))

    lines.extend(["## Remediation Actions Performed", ""])
    if snapshot.applied_patches:
        lines.append(
            f"**Applied Fixes & Mitigations ({len(snapshot.applied_patches)}):**"
        )
        lines.append("")
        for patch in snapshot.applied_patches:
            diff_note = (
                f" (`{escape_markdown(patch.file_path)}`)" if patch.file_path else ""
            )
            lines.append(
                f"- **{escape_markdown(patch.target_package)}** — `{patch.status}`{diff_note}"
            )
            if patch.diff_snippet:
                lines.extend(["  ```diff", patch.diff_snippet, "  ```"])
        lines.append("")

    lines.append("### What changed")
    lines.append("")
    changed = [
        change for root in snapshot.root_causes for change in root.modified_files
    ]
    if changed:
        for change in changed:
            lines.append(
                f"- `{escape_markdown(change.path)}` — `{change.state.value}`; "
                f"+{_count(change.lines_added)} / -{_count(change.lines_removed)} lines."
            )
    elif not snapshot.applied_patches:
        lines.append("- No repository file change has verified execution evidence.")
    lines.append("")

    lines.extend(["## Pull Requests Created", ""])
    if snapshot.pull_requests:
        for pr in snapshot.pull_requests:
            pr_label = f"PR #{pr.pr_number}" if pr.pr_number else "Pull Request"
            title = escape_markdown(pr.title or "Remediation Pull Request")
            url = pr.pr_url or "#"
            pkgs = (
                f" — packages: `{escape_markdown(', '.join(pr.affected_packages))}`"
                if pr.affected_packages
                else ""
            )
            commit = (
                f"; commit: `{escape_markdown(pr.commit_sha[:8])}`"
                if pr.commit_sha
                else ""
            )
            lines.append(f"- 🚀 **[{pr_label}: {title}]({url})**")
            lines.append(
                f"  - Branch: `{escape_markdown(pr.branch)}`{commit}; status: `{pr.status}`{pkgs}."
            )
    else:
        lines.append("- No pull requests were opened in this execution.")
    lines.append("")

    lines.extend(
        [
            "## AI Investigations and Decisions",
            "",
            "### Root-cause remediation summaries",
            "",
            f"- **Corporate policy compliance status**: `{escape_markdown(snapshot.policy_and_compliance.policy_status)}`.",
            "",
        ]
    )
    if snapshot.strategic_decisions:
        for d in snapshot.strategic_decisions:
            lines.extend(
                [
                    f"#### {escape_markdown(d.title)}",
                    "",
                    f"- **Finding**: {escape_markdown(d.finding)}",
                    f"- **Why it matters**: {escape_markdown(d.impact)}",
                    f"- **AI recommendation**: {escape_markdown(d.recommendation)}",
                    f"- **Action taken**: {escape_markdown(d.action_taken)}",
                    f"- **Human decision**: {escape_markdown(d.human_decision)}",
                    f"- **Evidence**: {escape_markdown(d.evidence_summary)}",
                    "",
                ]
            )
    else:
        for root in snapshot.root_causes[:3]:
            lines.extend(
                [
                    f"#### {escape_markdown(root.package)}",
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
    lines.append(
        "🔍 *For per-package call stacks, advisory validation logs, and sandbox diffs, "
        "see [technical-report.html](technical-report.html).*"
    )
    lines.append("")

    lines.extend(["## Proposed Remediation Campaigns", ""])
    if snapshot.remediation_campaigns:
        for camp in snapshot.remediation_campaigns:
            cve_count = len(camp.cves_addressed)
            pkg_preview = escape_markdown(", ".join(camp.packages[:6])) + (
                "..." if len(camp.packages) > 6 else ""
            )
            pr_link = f" ([PR]({camp.pr_url}))" if camp.pr_url else ""
            lines.append(
                f"- 📦 **{escape_markdown(camp.title)}** (`{escape_markdown(camp.campaign_id)}`): "
                f"`{camp.status}`{pr_link} — branch: `{escape_markdown(camp.branch)}`; "
                f"{camp.plans_count} plan(s), {cve_count} CVE(s). Packages: {pkg_preview}."
            )
    else:
        lines.append("- No multi-package remediation campaigns were active.")
    lines.append("")

    lines.extend(
        [
            "## Verification and Residual Risk",
            "",
            "| Check | State |",
            "| --- | --- |",
            f"| Patch | `{evidence.patch.value}` |",
            f"| Build and tests | `{evidence.tests.value}` |",
            f"| Pull request | `{evidence.pull_request.value}` |",
            f"| Post-fix rescan | `{evidence.rescan.value}` |",
            "",
            "### Risks",
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
    lines.append("")

    lines.extend(
        [
            "## Technical Evidence Appendix",
            "",
            f"- Input Scanner File SHA-256: `{escape_markdown(snapshot.provenance.input_scanner_file_sha256 or 'Live container/filesystem scan')}`",
            f"- Audit Chain Head: `{escape_markdown(snapshot.provenance.audit_chain_head_hash or 'UNKNOWN')}`",
            "",
            "### Associated Reports & Artifacts",
            f"- 📋 **Executive Security Brief**: [{escape_markdown(html_name)}]({escape_markdown(html_name)})",
            "- 🔬 **Technical Remediation & Evidence Report**: [technical-report.html](technical-report.html)",
            "- 📊 **Machine-Readable Snapshot**: [run-report.json](run-report.json)",
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
    try:
        os.chmod(out.parent, 0o755)
    except OSError:
        pass
    payload = generate_markdown_report(report) + "\n"
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{out.name}.", dir=out.parent, text=True
    )
    try:
        try:
            os.fchmod(descriptor, 0o644)
        except (OSError, AttributeError):
            pass
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_name, out)
        try:
            os.chmod(out, 0o644)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    return out
