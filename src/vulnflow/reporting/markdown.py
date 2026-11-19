"""
src/vulnflow/reporting/markdown.py
Generates formatted Markdown remediation summaries and executive reports grouped by root cause.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from vulnflow.contracts.state import VulnFlowState


def generate_markdown_report(state: VulnFlowState) -> str:
    """
    Format an executive Markdown report from workflow state.
    Groups findings by root cause parent and displays policy evaluation and risk tiers.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: List[str] = [
        f"# 🛡️ VulnFlow Vulnerability Remediation Report",
        f"",
        f"**Run ID**: `{state.run_id}`  ",
        f"**Generated**: `{now_iso}`  ",
        f"**Repository**: `{state.repo_path}`  ",
        f"**Execution Mode**: `{state.mode.upper()}`  ",
        f"**Final Status**: `{state.terminal_status.upper()}` (Exit Code: `{state.exit_code}`)  ",
        f"",
    ]

    # Prominent warning explanation if run is paused for human approval
    pending_plans = getattr(state, "pending_approval_plans", []) or [p for p in state.plans if p.requires_approval and p not in state.approved_plans]
    if state.terminal_status == "pending_approval" or (pending_plans and not state.approved_plans):
        lines.extend([
            f"> [!WARNING]",
            f"> ### ⚠️ Human Security Approval Required (Exit Code: 10)",
            f"> **Status**: {len(pending_plans)} remediation plan(s) require human authorization before PR creation.  ",
            f"> **Safeguard Enforcement**: Pull request opening is withheld until authorized by security.  ",
            f"> ",
            f"> **Plans Awaiting Security Authorization**:",
        ])
        for p in pending_plans[:6]:
            pol_s = p.policy_result.status.upper() if p.policy_result else "UNKNOWN"
            reason_s = p.policy_result.reason if p.policy_result else "Review-tier remediation requiring security authorization."
            target_str = p.target_package or p.root_cause_id
            lines.append(f"> - **Plan ID**: `{p.id}` (`{target_str}`)")
            lines.append(f">   • **Proposed Action**: `{p.action.value.upper()}` ➔ `{p.target_version or 'N/A'}` (Risk Tier: `{p.risk_tier.value.upper()}`)")
            lines.append(f">   • **Reason**: {reason_s}")
            lines.append(f">   • **To Approve & Resume**: `python3 src/vulnflow/cli.py approve --plan-id {p.id} --reviewer \"<your-email>\" --resume --repo {state.repo_path}`")
            lines.append(f"> ")
        if len(pending_plans) > 6:
            lines.append(f"> - *... and {len(pending_plans) - 6} additional plan(s)*")
        lines.extend([
            f"> **How to Authorize**:",
            f"> 1. **Via CLI**: Run the approval commands above with `--resume` to trigger PR creation.",
            f"> 2. **Via Web Dashboard**: Open the Plan Approvals UI and click **Approve**.",
            f"> 3. **Non-Interactive CI**: Re-run with `--auto-approve` to bypass the human gate in trusted CI.",
            f"",
        ])
    elif state.terminal_status == "blocked_policy" or state.blocking_reason or state.exception_ticket:
        t_id = state.exception_ticket.get("ticket_id", "SEC-UNKNOWN") if state.exception_ticket else "SEC-ESCALATED"
        t_url = state.exception_ticket.get("ticket_url", "#") if state.exception_ticket else "#"
        reason = state.blocking_reason or "Automated execution blocked by policy or build safety checks."

        lines.extend([
            f"> [!CAUTION]",
            f"> ### 🛑 Execution Blocked: Policy Exception Escalated",
            f"> **Reason**: {reason}  ",
            f"> **Safeguard Enforcement**: Pull request creation was safely halted to prevent pushing broken or unapproved changes to production.  ",
            f"> **Security Ticket**: [{t_id}]({t_url})  ",
            f"> ",
            f"> **Resolution Guidance**:",
            f"> 1. **Inspect Test/Build Output**: If tests failed, review local test runs (`npm test` / `pytest`) on the target fix branch.",
            f"> 2. **Review Policy Compliance**: If unlisted or banned, request exception sign-off via the security ticket linked above.",
            f"> 3. **Manual Resolution**: Run `vulnflow fix --plan-id <ID>` once approved.",
            f"",
        ])

    pending_count = len(pending_plans)
    lines.extend([
        f"---",
        f"",
        f"## 📊 Executive Summary",
        f"",
        f"| Metric | Count / Value |",
        f"|---|---|",
        f"| **Raw Scanner Findings** | {len(state.findings)} |",
        f"| **Unique Deduplicated Findings** | {len(state.deduped_findings)} |",
        f"| **Root Cause Dependency Groups** | {len(state.root_cause_groups)} |",
        f"| **Remediation Plans Generated** | {len(state.plans)} ({len(state.approved_plans)} approved, {pending_count} pending review) |",
        f"| **Patches Applied** | {len(state.patches)} |",
        f"| **Pull Requests Opened** | {len(state.pull_requests)} |",
        f"",
        f"---",
        f"",
        f"## 🔍 Findings Grouped by Root Cause",
        f"",
    ])

    if not state.root_cause_groups:
        lines.append("*No vulnerability findings discovered.*")
        lines.append("")
    else:
        for idx, grp in enumerate(state.root_cause_groups, 1):
            rc_id = grp.get("root_cause_id", "Unknown")
            rc_pkg = grp.get("root_cause_package", rc_id.replace("PKG-", ""))
            is_direct = grp.get("is_direct", True)
            origin_type = "Direct Manifest Dependency" if is_direct else "Transitive Sub-Dependency"
            explanation = grp.get("explanation", "Root cause identified through dependency graph.")

            # Match associated plan
            matched_plan = next(
                (p for p in state.plans if p.root_cause_id == rc_id or rc_id in p.root_cause_id or p.root_cause_id in rc_id),
                None,
            )
            tier_str = matched_plan.risk_tier.value.upper() if matched_plan else "N/A"
            action_str = matched_plan.action.value.upper() if matched_plan else "N/A"
            target_v = matched_plan.target_version or "N/A" if matched_plan else "N/A"
            pol_status = matched_plan.policy_result.status.upper() if matched_plan and matched_plan.policy_result else "APPROVED"

            rationale_text = matched_plan.rationale if matched_plan and matched_plan.rationale else "No specific remediation plan generated."
            approval_note = "Requires Human Authorization" if (matched_plan and matched_plan.requires_approval) else "Automated Bump Eligible"

            plan_id_str = matched_plan.id if matched_plan else "N/A"
            lines.extend([
                f"### Root Cause #{idx}: `{rc_pkg}`",
                f"",
                f"- **Remediation Plan ID**: `{plan_id_str}`",
                f"- **Origin**: {origin_type}",
                f"- **Proposed Action**: `{action_str}` ➔ Target Version: `{target_v}`",
                f"- **Risk Tier**: `{tier_str}` ({approval_note})",
                f"- **Policy Evaluation**: `{pol_status}`",
                f"- **Root Cause Analysis**: {explanation}",
            ])
            if matched_plan and matched_plan.requires_approval:
                lines.append(f"- **Approval CLI Command**: `python3 src/vulnflow/cli.py approve --plan-id {matched_plan.id} --reviewer \"<your-email>\" --resume --repo {state.repo_path}`")
            lines.extend([
                f"",
                f"#### 🧠 AI Remediation Proposal & Guidance (Plan ID: `{plan_id_str}`):",
                f"",
            ])
            for rat_line in rationale_text.split("\n"):
                lines.append(f"> {rat_line}" if rat_line.strip() else ">")
            lines.extend([
                f"",
                f"#### Clustered Findings ({len(grp.get('findings', []))} CVEs resolved by this proposal):",
                f"",
                f"| Package | Installed | Severity | CVE IDs | Fix Versions |",
                f"|---|---|---|---|---|",
            ])

            for f in grp.get("findings", []):
                pkg = f.get("package", "")
                ver = f.get("version", "")
                sev = f.get("severity", "MEDIUM")
                sev_val = sev.value.upper() if hasattr(sev, "value") else str(sev).upper()
                cves = ", ".join(f.get("cve", [])) or "N/A"
                fixes = ", ".join(f.get("fix_versions", [])) or "None"
                lines.append(f"| `{pkg}` | `{ver}` | **{sev_val}** | {cves} | `{fixes}` |")

            if target_v != "N/A" and action_str in ("BUMP", "REPLACE"):
                lines.extend([
                    f"",
                    f"> 💡 **Actionable Developer Step**: Update `{rc_pkg}` to `{target_v}` in repository manifest. Execute automated test suite to verify backward compatibility prior to production merge.",
                ])

            lines.append("")

    # Pull Requests Section
    if state.pull_requests:
        lines.extend([
            f"---",
            f"",
            f"## 🚀 Opened Pull Requests",
            f"",
        ])
        for pr in state.pull_requests:
            lines.append(f"- **{pr.get('title')}**")
            lines.append(f"  - **URL**: [{pr.get('pr_url')}]({pr.get('pr_url')})")
            lines.append(f"  - **Branch**: `{pr.get('branch')}`")
        lines.append("")

    # Verification Section
    if state.verification_results:
        ver = state.verification_results[0]
        rescan_status = "✅ Clean (0 residual findings)" if ver.get("rescan_clean") else "⚠️ Residual findings remain"
        tests_status = "✅ PASSED" if ver.get("tests_passed") else "❌ FAILED"
        lines.extend([
            f"---",
            f"",
            f"## 🧪 Verification & Evidence",
            f"- **Sandbox Tests**: {tests_status}",
            f"- **Post-Fix Rescan**: {rescan_status}",
            f"- **Policy Recheck**: {'✅ PASSED' if ver.get('policy_recheck_passed') else '❌ FAILED'}",
            f"",
        ])

    lines.extend([
        f"---",
        f"*Generated automatically by [VulnFlow](https://github.com/vulnflow/vulnflow).*",
    ])

    return "\n".join(lines)


def write_markdown_report(state: VulnFlowState, output_path: Union[str, Path]) -> Path:
    """Render and persist Markdown report to disk."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = generate_markdown_report(state)
    with open(out, "w", encoding="utf-8") as f:
        f.write(content)
    return out
