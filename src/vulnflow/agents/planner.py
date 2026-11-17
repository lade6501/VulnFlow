"""
src/vulnflow/agents/planner.py
Agent that formulates minimal-risk, policy-compliant remediation plans.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from vulnflow.contracts.finding import Finding
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
)
from vulnflow.core.risk import calculate_risk_tier, enforce_stricter_tier
from vulnflow.llm import LLMClient, LLMMessage, create_llm_client
from vulnflow.mcp_servers.policy_server import policy_candidates, policy_check
from vulnflow.mcp_servers.registry_server import registry_check
from vulnflow.policy.engine import parse_version_tuple

logger = logging.getLogger("vulnflow.agents.planner")


@dataclass
class PlannerOutputSchema:
    """Structured response expected from the Fix Planner LLM agent."""

    target_version: str
    action: str
    risk_tier: str
    rationale: str


def _make_plan_id(root_cause_id: str, target_package: Optional[str], target_version: Optional[str], action: Any) -> str:
    raw = f"{root_cause_id}:{target_package}:{target_version}:{action}".encode("utf-8")
    return f"PLAN-{hashlib.sha256(raw).hexdigest()[:12]}"


class PlannerAgent:
    """
    LLM reasoning agent that synthesizes vulnerability findings, advisory context,
    and organizational policies into a verified RemediationPlan.
    """

    def __init__(self, client: Optional[LLMClient] = None, enable_llm: bool = True) -> None:
        self.client = client or create_llm_client(role="planner")
        self.enable_llm = enable_llm
        self._circuit_broken = False

    def reset_circuit_breaker(self) -> None:
        """Reset the circuit breaker for a new run."""
        self._circuit_broken = False

    def plan_remediation(
        self,
        root_cause_id: str,
        findings: List[Finding],
        advisories: Optional[List[Dict[str, Any]]] = None,
        ecosystem: str = "npm",
    ) -> RemediationPlan:
        """
        Formulate a policy-compliant RemediationPlan for a cluster of related findings.
        """
        clean_package = root_cause_id.replace("PKG-", "").replace(f"{ecosystem}:", "")
        full_package = f"{ecosystem}:{clean_package}" if ":" not in clean_package else clean_package

        # 1. Deterministic policy evaluation
        pol_raw = policy_check(full_package, "latest", ecosystem)
        pol_result = PolicyResult.from_dict(pol_raw)

        # Gather all candidate fix versions from scanner findings
        all_fix_versions: List[str] = []
        finding_ids: List[str] = []
        cve_list: List[str] = []

        for f in findings:
            finding_ids.append(f.id)
            cve_list.extend(f.cve)
            for v_entry in f.fix_versions:
                for sub_v in str(v_entry).replace(",", " ").split():
                    clean_v = sub_v.strip()
                    if clean_v and clean_v not in all_fix_versions:
                        all_fix_versions.append(clean_v)

        # Sort candidate versions by semver (highest first)
        all_fix_versions = sorted(all_fix_versions, key=parse_version_tuple, reverse=True)

        # 2. Filter candidate versions strictly through policy engine
        approved_candidates = policy_candidates(full_package, all_fix_versions, ecosystem)

        # Case B: Package is deprecated or banned with approved replacement (F12)
        if pol_result.replacement and pol_result.status in (
            PolicyStatus.DEPRECATED.value,
            PolicyStatus.BANNED.value,
        ):
            return RemediationPlan(
                id=_make_plan_id(root_cause_id, pol_result.replacement, "latest", RemediationAction.REPLACE.value),
                finding_ids=finding_ids,
                root_cause_id=root_cause_id,
                action=RemediationAction.REPLACE,
                target_version="latest",
                target_package=pol_result.replacement,
                policy_result=pol_result,
                risk_tier=RiskTier.REVIEW,
                requires_approval=True,
                evidence=advisories or [],
                rationale=f"Package {full_package} is {pol_result.status}: {pol_result.reason}. Propose replacing with approved alternative '{pol_result.replacement}'.",
            )

        # Case A: Package is banned or denied by license without replacement
        if pol_result.status in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value):
            return RemediationPlan(
                id=_make_plan_id(root_cause_id, full_package, "none", RemediationAction.EXCEPTION.value),
                finding_ids=finding_ids,
                root_cause_id=root_cause_id,
                action=RemediationAction.EXCEPTION,
                target_version=None,
                target_package=full_package,
                policy_result=pol_result,
                risk_tier=RiskTier.BLOCKED,
                requires_approval=True,
                evidence=advisories or [],
                rationale=f"Package {full_package} is blocked by policy: {pol_result.reason}. Escalated to security exception.",
            )

        # Determine target version with registry availability check (F14):
        # 1. Prefer approved candidate if available in registry
        # 2. Otherwise propose the highest stable upstream fix version available in registry
        available_approved = [v for v in approved_candidates if registry_check(full_package, v, ecosystem).get("available", True)]
        available_all = [v for v in all_fix_versions if registry_check(full_package, v, ecosystem).get("available", True)]

        requires_approval = False
        if available_approved:
            target_version = available_approved[0]
            pol_result = PolicyResult.from_dict(policy_check(full_package, target_version, ecosystem))
        elif available_all:
            target_version = available_all[0]
            requires_approval = True
        else:
            # Case C: No upstream fix version exists anywhere
            return RemediationPlan(
                id=_make_plan_id(root_cause_id, full_package, "none", RemediationAction.EXCEPTION.value),
                finding_ids=finding_ids,
                root_cause_id=root_cause_id,
                action=RemediationAction.EXCEPTION,
                target_version=None,
                target_package=full_package,
                policy_result=pol_result,
                risk_tier=RiskTier.REVIEW,
                requires_approval=True,
                evidence=advisories or [],
                rationale=f"No upstream fix version currently exists for {full_package} to resolve {len(cve_list)} vulnerability(ies). Recommended: apply compensating controls, monitor for upstream patches, or explore alternative libraries.",
            )

        cur_version = findings[0].version if findings else "0.0.0"
        max_cvss = max((float(a.get("cvss_score", 0.0)) for a in (advisories or [])), default=0.0)

        # Determine bump scope
        cur_tuple = parse_version_tuple(cur_version)
        tgt_tuple = parse_version_tuple(target_version)
        if tgt_tuple[0] > cur_tuple[0]:
            bump_type = "Major version upgrade (potential breaking changes)"
            action_advice = f"Major upgrade from {cur_version} to {target_version}. Review upstream release notes for breaking API changes, deprecations, and run comprehensive integration tests."
        elif tgt_tuple[1] > cur_tuple[1]:
            bump_type = "Minor version upgrade (backward-compatible features)"
            action_advice = f"Minor upgrade from {cur_version} to {target_version}. Low risk of breaking changes; verify test suite passes."
        else:
            bump_type = "Patch version bump (bug & security fixes)"
            action_advice = f"Patch upgrade from {cur_version} to {target_version}. High backward compatibility; safe to apply immediately."

        policy_note = (
            "Pre-approved in corporate policy."
            if pol_result.status == PolicyStatus.APPROVED.value
            else "Package is not on corporate pre-approved list; human review/sign-off required before deployment."
        )

        # 3. Use LLM to generate reasoned explanation and assess risk context
        chunk_citations = [a["chunk_id"] for a in (advisories or []) if "chunk_id" in a]
        citation_str = f" Cited advisories: {', '.join(f'[{cid}]' for cid in chunk_citations)}." if chunk_citations else ""

        # Compact prompt to prevent content-safety screening timeouts and payload bloat
        cve_summary = ", ".join(cve_list[:6]) + (f" (and {len(cve_list) - 6} other CVEs)" if len(cve_list) > 6 else "")
        fixes_summary = ", ".join(all_fix_versions[:5])
        advisories_summary = [f"[{a.get('chunk_id')}]: {a.get('title', '')}" for a in (advisories or [])[:3]]

        prompt = (
            f"You are the VulnFlow Remediation Planner AI.\n"
            f"Target Package: {full_package} (currently installed: {cur_version})\n"
            f"Vulnerabilities to resolve: {cve_summary}\n"
            f"Available Upstream Fix Versions: {fixes_summary}\n"
            f"Proposed Target Version: {target_version}\n"
            f"Policy Status: {pol_result.status}\n"
            f"Advisory Context: {advisories_summary}\n\n"
            f"Propose an actionable remediation plan to safely upgrade this package.\n"
            f"Provide:\n"
            f"1. A concise upgrade recommendation explaining why {target_version} resolves the vulnerabilities.\n"
            f"2. Notable breaking changes or risks moving from {cur_version} to {target_version}.\n"
            f"3. Concrete verification advice for the developer.\n"
            f"4. Cite the relevant advisory chunk IDs: {chunk_citations}."
        )

        rationale = (
            f"Upgrade {full_package} from {cur_version} to {target_version} to resolve {len(cve_list)} vulnerability(ies): {', '.join(cve_list[:5])}.\n"
            f"• Scope: {bump_type}.\n"
            f"• Policy Compliance: {policy_note}\n"
            f"• Developer Migration Advice: {action_advice}{citation_str}"
        )

        # Compute baseline risk tier in code from policy, bump size, and CVSS (F08)
        code_tier = calculate_risk_tier(
            current_version=cur_version,
            target_version=target_version,
            policy_status=pol_result.status,
            is_direct=True,
            tests_passed=True,
            max_cvss=max_cvss,
        )
        if requires_approval and code_tier == RiskTier.AUTO:
            code_tier = RiskTier.REVIEW
        risk_tier = code_tier

        # Only invoke LLM if enabled and circuit breaker is unbroken
        if self.enable_llm and not self._circuit_broken:
            try:
                provider_name = self.client.get_provider_name() if hasattr(self.client, "get_provider_name") else "llm"
                model_name = getattr(self.client, "default_model", "default")
                logger.info("Fix Planner invoking LLM (%s/%s) for %s...", provider_name, model_name, full_package)
                resp = self.client.structured_complete(
                    messages=[LLMMessage(role="user", content=prompt)],
                    response_schema=PlannerOutputSchema,
                    temperature=0.0,
                )
                if resp.structured_data:
                    data: PlannerOutputSchema = resp.structured_data
                    parsed_rationale = data.rationale or rationale
                    if chunk_citations and not any(cid in parsed_rationale for cid in chunk_citations):
                        parsed_rationale = f"{parsed_rationale.rstrip('.')}.{citation_str}"
                    rationale = parsed_rationale
                    # The model can only make risk tier stricter, never looser (F08)
                    if data.risk_tier:
                        risk_tier = enforce_stricter_tier(code_tier, data.risk_tier)
                    logger.info(
                        "Fix Planner LLM response received: Action=%s, RiskTier=%s, Rationale=%s",
                        data.action or "BUMP",
                        risk_tier.value,
                        rationale[:80],
                    )
            except Exception as exc:
                err_str = str(exc)
                if any(k in err_str.lower() for k in ("timed out", "timeout", "unreachable", "errno 8", "nodename", "503", "safety", "screening", "server error")):
                    self._circuit_broken = True
                    logger.warning(
                        "LLM provider unavailable or error (%s). Circuit breaker tripped; switching to fast deterministic planner for remaining dependencies.",
                        err_str,
                    )
                else:
                    logger.info("Using deterministic planner fallback (%s)", exc)

        return RemediationPlan(
            id=_make_plan_id(root_cause_id, full_package, target_version, RemediationAction.BUMP.value),
            finding_ids=finding_ids,
            root_cause_id=root_cause_id,
            action=RemediationAction.BUMP,
            target_version=target_version,
            target_package=full_package,
            policy_result=pol_result,
            risk_tier=risk_tier,
            requires_approval=(risk_tier != RiskTier.AUTO),
            evidence=advisories or [],
            rationale=rationale,
        )


# Shared planner agent instance
default_planner_agent = PlannerAgent()
