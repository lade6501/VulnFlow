"""
src/vulnflow/reporting/pr_comment.py
Formats concise pull request comments summarizing remediation actions taken.
"""

from __future__ import annotations

from vulnflow.contracts.remediation_plan import RemediationPlan, VerificationResult


def format_pr_body(
    plan: RemediationPlan,
    verification: VerificationResult | None = None,
    repo_url: str | None = None,
) -> str:
    """
    Format a rich, structured Markdown description for a remediation pull request.
    Summarizes root cause, policy evaluation, test verification, and AI rationale.
    """
    ver = verification or plan.verification
    resolved_count = len(plan.finding_ids)

    body_lines = [
        "## 🛡️ VulnFlow Automated Remediation",
        "",
        "### Summary of Changes",
        "| Attribute | Value |",
        "|---|---|",
        f"| **Target Dependency** | `{plan.target_package or plan.root_cause_id}` |",
        f"| **Action** | `{plan.action.value.upper()}` |",
        f"| **New Version** | `{plan.target_version or 'N/A'}` |",
        f"| **Risk Tier** | `{plan.risk_tier.value.upper()}` |",
        f"| **Policy Status** | `{plan.policy_result.status.upper()}` (`{plan.policy_result.rule_matched or 'standard'}`) |",
        f"| **Resolved Findings** | `{resolved_count}` finding(s) |",
        "",
        "### 📋 Rationale",
        f"> {plan.rationale}",
        "",
    ]

    if plan.evidence:
        body_lines.extend([
            "### 🔍 Security Intelligence & Advisories",
        ])
        for ev in plan.evidence:
            title = ev.get("title") or ev.get("id") or "Advisory"
            cve = ev.get("cve", "CVE")
            score = ev.get("cvss_score") or ev.get("score")
            score_str = f" (CVSS {score})" if score else ""
            desc = ev.get("description", "")
            body_lines.append(f"- **{title}** [{cve}]{score_str}: {desc[:150]}...")
        body_lines.append("")

    if ver:
        test_status = "✅ PASSED" if ver.tests_passed else "❌ FAILED"
        clean_status = "✅ ZERO REMAINING FINDINGS" if ver.rescan_clean else "⚠️ PARTIAL RESOLUTION"
        body_lines.extend([
            "### 🧪 Verification & Build Evidence",
            f"- **Sandbox Tests**: {test_status}",
            f"- **Rescan Verification**: {clean_status}",
            f"- **Policy Recheck**: {'✅ PASSED' if ver.policy_recheck_passed else '❌ FAILED'}",
            "",
        ])

    body_lines.extend([
        "---",
        "*Generated automatically by [VulnFlow](https://github.com/vulnflow/vulnflow). No human intervention was required.*",
    ])

    return "\n".join(body_lines)
