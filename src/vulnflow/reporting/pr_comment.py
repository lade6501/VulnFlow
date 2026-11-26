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
        if ver.verified and not ver.rescan_clean:
            clean_status = "✅ APPROVED FINDINGS RESOLVED (NO NEW FINDINGS)"
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


def format_campaign_pr_body(
    plans: list[RemediationPlan],
    verification: VerificationResult | None = None,
    repo_url: str | None = None,
) -> str:
    """
    Format a consolidated Markdown description for a multi-dependency campaign PR.
    Includes an executive matrix table of all packages, CVEs resolved, policy status,
    and collapsible details for each package's evidence and code refactorings.
    """
    total_packages = len(plans)
    total_findings = sum(len(p.finding_ids) for p in plans)

    body_lines = [
        "## 🛡️ VulnFlow Consolidated Remediation Campaign",
        "",
        f"This unified pull request resolves **{total_findings} vulnerability finding(s)** across **{total_packages} package(s)** in a single atomic update.",
        "",
        "### 📊 Remediation Matrix",
        "| Package | Action | Target Version | Risk Tier | Policy Status | Findings |",
        "|---|---|---|---|---|---|",
    ]

    for p in plans:
        pkg_name = p.target_package or p.root_cause_id
        action_name = p.action.value.upper()
        target_ver = p.target_version or "N/A"
        tier_name = p.risk_tier.value.upper()
        pol_status = p.policy_result.status.upper() if p.policy_result else "APPROVED"
        f_count = len(p.finding_ids)
        body_lines.append(
            f"| `{pkg_name}` | `{action_name}` | `{target_ver}` | `{tier_name}` | `{pol_status}` | `{f_count}` |"
        )

    body_lines.append("")

    # Check for any code refactorings applied across plans
    refactors = [
        ev
        for p in plans
        for ev in (p.evidence or [])
        if isinstance(ev, dict) and ev.get("type") == "code_refactor"
    ]
    if refactors:
        body_lines.extend([
            "### 🛠️ Automated Code Refactorings Applied",
            "VulnFlow FixerAgent automatically refactored application call sites to resolve breaking API changes:",
            "",
        ])
        for rf in refactors:
            f_path = rf.get("file", "source file")
            sym = rf.get("symbol", "API call")
            rat = rf.get("rationale", "Updated for version compatibility")
            body_lines.append(f"- **`{f_path}`**: Refactored `{sym}` — {rat}")
        body_lines.append("")

    # Collapsible details per package
    body_lines.extend([
        "### 📋 Package Details & Cited Intelligence",
    ])
    for p in plans:
        pkg_name = p.target_package or p.root_cause_id
        body_lines.extend([
            f"<details><summary><strong>{pkg_name}</strong> (Target: {p.target_version or 'N/A'})</summary>",
            "",
            f"> {p.rationale}",
            "",
        ])
        if p.evidence:
            body_lines.append("**Cited Advisories & Notes:**")
            for ev in p.evidence:
                if isinstance(ev, dict) and ev.get("type") != "code_refactor":
                    title = ev.get("title") or ev.get("id") or "Advisory"
                    cve = ev.get("cve", "CVE")
                    score = ev.get("cvss_score") or ev.get("score")
                    score_str = f" (CVSS {score})" if score else ""
                    body_lines.append(f"- {title} [{cve}]{score_str}")
            body_lines.append("")
        body_lines.append("</details>")
        body_lines.append("")

    # Verification summary
    ver = verification or (plans[0].verification if plans and plans[0].verification else None)
    if ver:
        tests_passed = ver.get("tests_passed", True) if isinstance(ver, dict) else getattr(ver, "tests_passed", True)
        rescan_clean = ver.get("rescan_clean", True) if isinstance(ver, dict) else getattr(ver, "rescan_clean", True)
        verified = ver.get("verified", False) if isinstance(ver, dict) else ver.verified
        policy_recheck = (
            ver.get("policy_recheck_passed", True)
            if isinstance(ver, dict)
            else getattr(ver, "policy_recheck_passed", True)
        )
        test_status = "✅ PASSED" if tests_passed else "❌ FAILED"
        clean_status = "✅ ZERO REMAINING FINDINGS" if rescan_clean else "⚠️ PARTIAL RESOLUTION"
        if verified and not rescan_clean:
            clean_status = "✅ APPROVED FINDINGS RESOLVED (NO NEW FINDINGS)"
        policy_status = "✅ PASSED" if policy_recheck else "❌ FAILED"
        body_lines.extend([
            "### 🧪 Verification & Build Evidence",
            f"- **Sandbox Tests**: {test_status}",
            f"- **Rescan Verification**: {clean_status}",
            f"- **Policy Recheck**: {policy_status}",
            "",
        ])

    body_lines.extend([
        "---",
        "*Generated automatically by [VulnFlow](https://github.com/vulnflow/vulnflow). Unified dependency campaign.*",
    ])

    return "\n".join(body_lines)

