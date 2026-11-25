"""
src/vulnflow/reporting/html_report.py
Renders self-contained accessible HTML reports from the canonical snapshot:
- Executive Security Intelligence Report (report.html)
- Technical Remediation & Evidence Report (technical-report.html)
"""

from __future__ import annotations

import html
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from vulnflow.contracts.report import RunReport
from vulnflow.contracts.state import VulnFlowState
from vulnflow.reporting.builder import build_run_report


def _escape(value: object) -> str:
    return html.escape(str(value if value is not None else "UNKNOWN"), quote=True)


def _count(value: object) -> str:
    return "UNKNOWN" if value is None else str(value)


def _canonical(report: RunReport | VulnFlowState) -> RunReport:
    return report if isinstance(report, RunReport) else build_run_report(report)


def _list(items: Iterable[object], empty: str = "None recorded.") -> str:
    values = list(items)
    if not values:
        return f'<p class="muted">{_escape(empty)}</p>'
    return "<ul>" + "".join(f"<li>{_escape(item)}</li>" for item in values) + "</ul>"


_ICONS = {
    "shield": '<path d="M12 22s7-3 7-9V5l-7-3-7 3v8c0 6 7 9 7 9z"/><path d="m9 12 2 2 4-4"/>',
    "chart": '<path d="M3 3v18h18M8 16v-3m5 3V9m5 7V5"/>',
    "action": '<path d="M9 5h10a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-6"/><path d="m3 7 2 2 4-5m1 9h6m-6 4h6"/>',
    "branch": '<circle cx="6" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="6" r="2"/><path d="M6 8v8m12-8c0 5-4 7-10 7"/>',
    "file": '<path d="M6 3h8l4 4v14H6zM14 3v5h5M9 13h6m-6 4h6"/>',
    "warning": '<path d="m12 3 10 17H2L12 3zm0 6v4m0 3v1"/>',
    "arrow": '<path d="M5 12h14m-6-6 6 6-6 6"/>',
}


def _icon(name: str) -> str:
    return (
        '<svg class="icon" aria-hidden="true" focusable="false" viewBox="0 0 24 24" '
        'fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" '
        f'stroke-linejoin="round">{_ICONS[name]}</svg>'
    )


def _label(value: object) -> str:
    if value is None:
        return "Unknown"
    label = str(value).replace("_", " ")
    return label[:1].upper() + label[1:]


def _badge(value: object, tone: str | None = None) -> str:
    if tone is None:
        code = str(value).lower()
        if code in {"auto", "approved", "completed", "executed", "opened", "verified"}:
            tone = "auto"
        elif code in {"high", "pending", "pending_approval", "review", "simulated"}:
            tone = "review"
        elif code in {"blocked", "blocked_policy", "critical", "error", "failed", "failed_verification", "rejected"}:
            tone = "secret"
        else:
            tone = "neutral"
    return f'<span class="badge badge-{tone}">{_escape(_label(value))}</span>'


def _section(anchor: str, title: str, icon: str, body: str, css_class: str = "") -> str:
    css = f' class="{css_class}"' if css_class else ""
    return (
        f'<section id="{anchor}"{css}><h2><span class="section-icon">{_icon(icon)}</span>'
        f'{_escape(title)}</h2>{body}</section>'
    )


def _table(label: str, columns: tuple[str, ...], rows: str, empty: str) -> str:
    headings = "".join(f'<th scope="col">{_escape(name)}</th>' for name in columns)
    if not rows:
        rows = f'<tr><td colspan="{len(columns)}">{_escape(empty)}</td></tr>'
    return (
        f'<div class="table-wrap" role="region" aria-label="{_escape(label)}" tabindex="0">'
        f"<table><thead><tr>{headings}</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _external_link(url: str | None, label: str) -> str:
    try:
        # Render URLs defensively even when called with an already-built snapshot.
        parsed = urlsplit(url or "")
        if (
            url
            and parsed.scheme in {"http", "https"}
            and parsed.hostname
            and parsed.username is None
            and not any(char.isspace() or ord(char) < 32 for char in url)
        ):
            return f'<a href="{_escape(url)}" rel="noopener noreferrer">{_escape(label)}</a>'
    except ValueError:
        pass
    return _escape(label)


def _header(
    report: RunReport,
    title: str,
    view: str,
    links: Iterable[tuple[str, str]],
    alternate: tuple[str, str],
) -> str:
    header = report.header
    nav = "".join(f'<a href="#{anchor}">{_escape(label)}</a>' for anchor, label in links)
    alternate_path, alternate_label = alternate
    return (
        '<header class="report-header"><div>'
        f'<p class="eyebrow">{_icon("shield")} VulnFlow · {_escape(view)}</p>'
        f'<h1>{_escape(title)}</h1><p class="hero-meta"><strong>{_escape(header.repository_name)}</strong>'
        f'<code>{_escape(header.run_id)}</code></p></div>'
        f'<div class="outcome"><span class="outcome-label">Run outcome</span>{_badge(header.outcome)}</div></header>'
        f'<nav class="report-nav" aria-label="Report sections">{nav}'
        f'<a class="switch-link" href="{alternate_path}">{_escape(alternate_label)} '
        f'{_icon("arrow")}</a></nav>'
    )


def _metrics(report: RunReport) -> str:
    summary = report.executive_summary
    values = (
        ("Findings", summary.findings_analyzed),
        ("Root causes", summary.root_causes_identified),
        ("Expected CVEs", summary.expected_cves_addressed),
        ("Verified CVEs", summary.verified_cves_resolved),
        ("Applied fixes", summary.fixes_applied),
        ("Created PRs", summary.prs_actually_created),
    )
    return '<div class="metrics">' + "".join(
        f"<div><strong>{_escape(value)}</strong><span>{label}</span></div>" for label, value in values
    ) + "</div>"


def _verification(report: RunReport) -> str:
    evidence = report.execution_evidence
    checks = (
        ("Patch", evidence.patch.value),
        ("Build and tests", evidence.tests.value),
        ("Pull request", evidence.pull_request.value),
        ("Post-fix rescan", evidence.rescan.value),
    )
    return '<div class="verification-grid">' + "".join(
        f'<div><span class="verification-label">{label}</span>{_badge(value)}</div>'
        for label, value in checks
    ) + "</div>"


def _render_page(title: str, body: str) -> str:
    template = (Path(__file__).parent / "templates" / "report.html").read_text(encoding="utf-8")
    return template.replace("{{REPORT_TITLE}}", _escape(title)).replace("{{REPORT_CONTENT}}", body)


def _severity_svg(report: RunReport, title_text: str = "Vulnerability severity before remediation") -> str:
    before = report.executive_summary.severity_counts_before
    after = report.executive_summary.severity_counts_after
    values = [before.critical, before.high, before.medium, before.low, before.info]
    maximum = max([item or 0 for item in values] + [1])
    colors = ["#8b1e2d", "#c2413b", "#c77d14", "#3276a8", "#637083"]
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    bars = []
    for index, (label, value, color) in enumerate(zip(labels, values, colors, strict=False)):
        width = int(((value or 0) / maximum) * 246)
        y = 20 + index * 34
        count = _escape(_count(value))
        bars.append(
            f'<text x="0" y="{y + 14}" class="chart-label">{label}</text>'
            f'<rect x="72" y="{y}" width="{width}" height="18" fill="{color}" '
            f'data-count="{count}" rx="2" />'
            f'<text x="{78 + width}" y="{y + 14}" class="chart-value">{count}</text>'
        )
    after_text = "Pending post-fix rescan" if after.total is None else str(after.total)
    return (
        '<figure><svg viewBox="0 0 370 190" role="img" '
        'aria-labelledby="severity-title severity-desc">'
        f'<title id="severity-title">{_escape(title_text)}</title>'
        f'<desc id="severity-desc">After-state total is {_escape(after_text)}.</desc>'
        + "".join(bars)
        + f"</svg><figcaption>{_escape(title_text)}. "
        f"Post-remediation status: <strong>{_escape(after_text)}</strong>.</figcaption></figure>"
    )


def _atomic_write_file(path: Path, content: str) -> None:
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent, text=True
    )
    try:
        try:
            os.fchmod(descriptor, 0o644)
        except (OSError, AttributeError):
            pass
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_name, path)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _accordion(title: str, body: str, *, meta: str = "", css_class: str = "") -> str:
    css = f' class="{css_class}"' if css_class else ""
    return (
        f'<details{css}><summary><span class="accordion-title">{_escape(title)}</span>'
        f"{meta}</summary><div class=\"details-body\">{body}</div></details>"
    )


def _root_sections(report: RunReport) -> str:
    """Render compact component headings with expandable evidence."""
    sections = []
    for root in report.root_causes:
        advisory_rows = "".join(
            "<tr>"
            f"<td>{_external_link(item.source_url, item.title or item.evidence_id)}</td>"
            f"<td>{_escape(', '.join(item.cves) or 'Unknown')}</td>"
            f"<td>{_badge('validated', 'auto') if item.validated else _badge('rejected')}</td>"
            f"<td>{_escape(item.rejection_reason or 'Evidence matched.')}</td></tr>"
            for item in root.advisory_evidence
        )
        insight_items = "".join(
            '<article class="insight">'
            f"<h4>{_escape(_label(insight.category))}</h4>"
            f'<p class="evidence-text">{_escape(insight.text)}</p>'
            f'<p class="meta">Generated by {_escape(_label(insight.generated_by.value))} · '
            f"Evidence {_escape(_label(insight.evidence_availability.value))} · "
            f"{_escape(', '.join(insight.source_references) or 'Unknown source')}</p></article>"
            for insight in root.insights
        )
        option_rows = "".join(
            f"<tr><td>{_escape(_label(option.action))}</td><td>{_escape(option.target_version)}</td>"
            f"<td>{_badge('accepted', 'auto') if option.accepted else _badge('rejected')}</td>"
            f"<td class=\"evidence-text\">{_escape(option.reason)}</td></tr>"
            for option in root.options_considered
        )
        file_rows = "".join(
            f"<tr><td><code>{_escape(change.path)}</code></td><td>{_badge(change.state.value)}</td>"
            f"<td>{_escape(change.lines_added)}</td><td>{_escape(change.lines_removed)}</td></tr>"
            for change in root.modified_files
        )
        verify_rows = "".join(
            f"<tr><td>{_escape(_label(item.check))}</td><td>{_badge(item.state.value)}</td>"
            f"<td>{_escape(item.passed)}</td><td>{_escape(item.details)}</td></tr>"
            for item in root.verification_results
        )
        advisory_table = _table(
            "Advisory evidence", ("Source", "CVEs", "Validation", "Reason"),
            advisory_rows, "No advisory evidence recorded.",
        )
        options_table = _table(
            "Remediation alternatives", ("Action", "Target", "Decision", "Reason"),
            option_rows, "No alternatives recorded.",
        )
        files_table = _table(
            "Modified files", ("File", "State", "Added", "Removed"),
            file_rows, "No executed change.",
        )
        verification_table = _table(
            "Component verification", ("Check", "State", "Passed", "Evidence"),
            verify_rows, "No verification checks recorded.",
        )

        body = (
            f'<p class="evidence-text">{_escape(root.impact_explanation)}</p><dl>'
            f"<dt>Origin</dt><dd>{_escape(_label(root.origin.value))}</dd>"
            f"<dt>Installed and target</dt><dd>{_escape(root.installed_version)} → {_escape(root.target_version)}</dd>"
            f"<dt>Dependency chain</dt><dd>{_escape(' → '.join(root.dependency_chain) or 'Unknown')}</dd>"
            f"<dt>CVEs</dt><dd>{_escape(', '.join(root.associated_cves) or 'Unknown')}</dd>"
            f"<dt>Risk reason</dt><dd>{_escape(root.risk_reason)}</dd></dl>"
            f"<h3>Recommended change</h3><p>{_escape(root.recommended_change)}</p>"
            + _accordion("AI security intelligence", insight_items or '<p class="muted">Not evaluated.</p>')
            + _accordion("Advisory evidence and alternatives", advisory_table + "<h3>Alternatives</h3>" + options_table)
            + _accordion("Changes and verification", "<h3>Modified files</h3>" + files_table
                         + "<h3>Verification results</h3>" + verification_table)
            + _accordion(
                "Compatibility and developer actions",
                f'<p class="evidence-text">{_escape(root.breaking_change_notes or "No compatibility assessment recorded.")}</p>'
                f'<p class="evidence-text">{_escape(root.migration_notes or "No migration notes recorded.")}</p>'
                f"<h3>Developer action plan</h3>{_list(root.remaining_developer_actions)}",
            )
        )
        meta = (
            f'<span class="accordion-tools"><span class="accordion-meta">{len(root.associated_cves)} CVEs</span>'
            f'{_badge(root.risk_tier)}</span>'
        )
        sections.append(_accordion(root.package, body, meta=meta, css_class="root-accordion"))
    return "".join(sections) or '<p class="muted">No root causes were recorded.</p>'


def _actions_section(report: RunReport) -> str:
    rows = "".join(
        f"<tr><td>{_badge(item.priority)}</td><td>{_escape(_label(item.action_type))}</td>"
        f"<td>{_escape(item.description)}</td><td>{_escape(_label(item.required_actor))}</td>"
        f"<td>{_badge(item.completion_status.value)}</td></tr>"
        for item in report.action_required
    )
    table = _table(
        "Immediate actions", ("Priority", "Action", "Description", "Actor", "Status"),
        rows, "No immediate action recorded.",
    )
    if len(report.action_required) > 8:
        table = _accordion(f"View all {len(report.action_required)} recorded actions", table)
    return _section("actions", "Immediate actions required", "action", table)


def _patch_section(report: RunReport) -> str:
    if not report.applied_patches:
        return ""
    rows = "".join(
        f"<tr><td><strong>{_escape(p.target_package)}</strong></td><td><code>{_escape(p.file_path)}</code></td>"
        f"<td>{_badge(p.status)}</td><td>+{_count(p.lines_added)} / -{_count(p.lines_removed)}</td></tr>"
        for p in report.applied_patches
    )
    return _section(
        "patches", "Applied Remediation Patches", "file",
        _table("Applied patches", ("Package", "File", "Status", "Lines (+/-)"), rows, "No changes recorded."),
    )


def _prs_section(report: RunReport) -> str:
    if not report.pull_requests:
        return ""
    rows = "".join(
        f"<tr><td>#{pr.pr_number or 'N/A'}</td><td>{_external_link(pr.pr_url, pr.title or 'Remediation PR')}</td>"
        f"<td><code>{_escape(pr.branch)}</code></td><td>{_escape(', '.join(pr.affected_packages))}</td>"
        f"<td>{_badge(pr.status)}</td></tr>"
        for pr in report.pull_requests
    )
    return _section(
        "pull-requests", "Created Pull Requests", "branch",
        _table("Pull requests", ("PR #", "Title", "Branch", "Packages", "Status"), rows, "None recorded."),
    )


def _approval_section(report: RunReport) -> str:
    if not report.approval_groups:
        return ""
    rows = "".join(
        f"<tr><td><strong>{_escape(group.title)}</strong></td><td>{group.plans_count}</td>"
        f"<td>{_escape(group.description)}</td><td>{_escape(group.recommended_action)}</td>"
        f"<td><code>{_escape(group.cli_command)}</code></td></tr>"
        for group in report.approval_groups
    )
    return _section(
        "approvals", "Prioritized Approval Groups", "action",
        _table("Approval groups", ("Group", "Plans", "Description", "Action", "CLI command"), rows, "None recorded."),
    )


def _campaigns_section(report: RunReport) -> str:
    if not report.remediation_campaigns:
        return ""
    rows = "".join(
        f"<tr><td><code>{_escape(c.campaign_id)}</code></td><td>{_escape(c.title)}</td>"
        f"<td><code>{_escape(c.branch)}</code></td><td>{c.plans_count}</td><td>{_badge(c.status)}</td></tr>"
        for c in report.remediation_campaigns
    )
    return _section(
        "campaigns", "Remediation Campaigns", "branch",
        _table("Campaigns", ("Campaign ID", "Title", "Branch", "Plans", "Status"), rows, "None recorded."),
    )


def _provenance(report: RunReport) -> str:
    header = report.header
    return _accordion(
        "View execution details and provenance",
        f'<dl class="meta-grid"><dt>Generated</dt><dd>{_escape(header.generated_at.isoformat())}</dd>'
        f"<dt>Mode</dt><dd>{_escape(_label(header.execution_mode.value))}</dd>"
        f"<dt>Exit code</dt><dd>{header.exit_code}</dd>"
        f"<dt>Repository changes</dt><dd>{_escape(_label(header.repo_changes.value))}</dd>"
        f"<dt>Scanner input</dt><dd>{_escape(report.provenance.input_scanner_file_sha256 or 'No file digest recorded')}</dd>"
        f"<dt>Audit chain head</dt><dd>{_escape(report.provenance.audit_chain_head_hash)}</dd>"
        f"<dt>Model and provider</dt><dd>{_escape(report.provenance.model)} / {_escape(report.provenance.model_provider)}</dd>"
        f"<dt>Trace reference</dt><dd>{_escape(report.provenance.trace_reference)}</dd></dl>",
    )


def _exposure_section(report: RunReport) -> str:
    if not report.secrets_exposure:
        return ""
    rows = "".join(
        f"<tr><td>{_badge(item.secret_type, 'secret')}</td><td><code>{_escape(item.file_path)}</code></td>"
        f"<td>{_escape(item.line_number)}</td><td>{_escape(item.action_required)}</td>"
        f"<td>{_badge(item.status)}</td></tr>"
        for item in report.secrets_exposure
    )
    table = _table(
        "Redacted credential locations", ("Type", "File", "Line", "Required action", "Status"),
        rows, "No locations recorded.",
    )
    count = len(report.secrets_exposure)
    location_label = "location" if count == 1 else "locations"
    return _section(
        "credential-exposure", "Credentials & Secret Exposure Alert", "warning",
        '<p class="lead">Review the redacted locations and follow the required rotation or removal action for each finding.</p>'
        + _accordion(f"View {count} flagged {location_label}", table),
        css_class="exposure-alert",
    )


def _decisions_section(report: RunReport) -> str:
    if not report.strategic_decisions:
        return ""
    cards = []
    for decision in report.strategic_decisions:
        category = _label(decision.category)
        tone = "secret" if "secret" in decision.category.lower() else "neutral"
        body = (
            '<dl class="decision-grid">'
            f'<dt>Finding</dt><dd class="evidence-text">{_escape(decision.finding)}</dd>'
            f'<dt>Impact</dt><dd class="evidence-text">{_escape(decision.impact)}</dd>'
            f'<dt>Recommendation</dt><dd class="evidence-text">{_escape(decision.recommendation)}</dd>'
            f"<dt>Action taken</dt><dd>{_escape(decision.action_taken)}</dd>"
            f"<dt>Human decision</dt><dd>{_escape(decision.human_decision)}</dd>"
            f'<dt>Evidence</dt><dd class="evidence-text">{_escape(decision.evidence_summary)}</dd></dl>'
        )
        cards.append(_accordion(
            decision.title, body,
            meta=f'<span class="accordion-tools">{_badge(category, tone)}</span>',
        ))
    return _section("decisions", "Top Strategic AI Decisions & Risk Governance", "shield", "".join(cards))


def generate_executive_html_report(report: RunReport | VulnFlowState) -> str:
    """Render a concise security and approvals brief."""
    snapshot = _canonical(report)
    title = "Executive Security Intelligence Report"
    links = [("summary", "Summary"), ("actions", "Actions"), ("verification", "Verification")]
    if snapshot.approval_groups:
        links.insert(2, ("approvals", "Approvals"))
    if snapshot.secrets_exposure:
        links.append(("credential-exposure", "Credentials"))
    return _render_page(
        title,
        _header(
            snapshot, title, "Executive report", links,
            ("technical-report.html", "Open Technical Remediation Report"),
        )
        + _section(
            "summary", "Executive security summary", "chart",
            f'<p class="lead">{_escape(snapshot.executive_summary.summary_sentence)}</p>'
            + _metrics(snapshot),
        )
        + _actions_section(snapshot)
        + _approval_section(snapshot)
        + _section("verification", "Remediation verification", "shield", _verification(snapshot))
        + _decisions_section(snapshot)
        + _section("severity", "Vulnerability severity before remediation", "chart", _severity_svg(snapshot))
        + _prs_section(snapshot)
        + _patch_section(snapshot)
        + _campaigns_section(snapshot)
        + _section(
            "policy", "Policy and compliance posture", "shield",
            f'<p>Corporate policy status {_badge(snapshot.policy_and_compliance.policy_status)}</p>',
        )
        + _section("provenance", "Provenance and audit", "file", _provenance(snapshot))
        + _exposure_section(snapshot),
    )


def generate_technical_html_report(report: RunReport | VulnFlowState) -> str:
    """Render component-level evidence with native accordions."""
    snapshot = _canonical(report)
    title = "Technical Remediation & Evidence Report"
    policy_rows = "".join(
        f"<tr><td>{_escape(rule.rule)}</td><td>{_badge(rule.status)}</td>"
        f"<td>{_escape(rule.evidence)}</td></tr>"
        for rule in snapshot.policy_and_compliance.evaluated_rules
    )
    validation = (
        snapshot.validation_notes.missing_evidence
        + snapshot.validation_notes.rejected_advisories
        + snapshot.validation_notes.unknown_values
        + snapshot.validation_notes.incomplete_execution
        + snapshot.validation_notes.unsupported_claims
    )
    risks = snapshot.residual_risk
    return _render_page(
        title,
        _header(
            snapshot, title, "Technical report",
            [("components", "Components"), ("verification", "Verification"),
             ("policy", "Policy"), ("appendix", "Audit and limitations")],
            ("report.html", "Open Executive Report"),
        )
        + _section("summary", "Remediation metrics", "chart", _metrics(snapshot))
        + _section("verification", "Verification and execution", "shield", _verification(snapshot))
        + _section(
            "components", f"Root-cause and dependency analysis ({len(snapshot.root_causes)} components)", "branch",
            '<p class="muted">Expand a component to inspect its advisories, proposed changes, and verification evidence.</p>'
            + _root_sections(snapshot),
        )
        + _actions_section(snapshot)
        + _approval_section(snapshot)
        + _prs_section(snapshot)
        + _patch_section(snapshot)
        + _section(
            "policy", "Policy and compliance evaluation", "shield",
            f"<p>Corporate policy status {_badge(snapshot.policy_and_compliance.policy_status)}</p>"
            + _table("Policy evaluation", ("Rule", "Status", "Evidence"), policy_rows, "No rules recorded."),
        )
        + _section(
            "risks", "Residual risk", "warning",
            _accordion("Unresolved vulnerabilities", _list(risks.unresolved_vulnerabilities, "Unknown"))
            + _accordion("Unverified remediation", _list(risks.unverified_remediation))
            + _accordion("Exposure uncertainty", _list(risks.exposure_uncertainty)),
        )
        + _section(
            "appendix", "Technical appendix", "file",
            _provenance(snapshot) + _accordion("Validation notes and limitations", _list(validation)),
        ),
    )


def generate_html_report(report: RunReport | VulnFlowState) -> str:
    """Render executive HTML report by default for single-report backwards compatibility."""
    return generate_executive_html_report(report)


def write_html_report(
    report: RunReport | VulnFlowState, output_path: str | Path
) -> Path:
    """Atomically persist self-contained executive HTML report and technical HTML report."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out.parent, 0o755)
    except OSError:
        pass

    # 1. Write executive report
    exec_content = generate_executive_html_report(report)
    _atomic_write_file(out, exec_content)

    # 2. Write technical report alongside it
    if out.name == "report.html":
        tech_path = out.parent / "technical-report.html"
    else:
        tech_path = out.parent / f"{out.stem}-technical.html"
    tech_content = generate_technical_html_report(report)
    _atomic_write_file(tech_path, tech_content)

    return out
