"""
src/vulnflow/agents/planner.py
Agent that formulates minimal-risk, policy-compliant remediation plans.
"""

from __future__ import annotations

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
from vulnflow.llm import LLMClient, LLMMessage, create_llm_client
from vulnflow.mcp_servers.policy_server import policy_candidates, policy_check

logger = logging.getLogger("vulnflow.agents.planner")


@dataclass
class PlannerOutputSchema:
    """Structured response expected from the Fix Planner LLM agent."""

    target_version: str
    action: str
    risk_tier: str
    rationale: str


class PlannerAgent:
    """
    LLM reasoning agent that synthesizes vulnerability findings, advisory context,
    and organizational policies into a verified RemediationPlan.
    """

    def __init__(self, client: Optional[LLMClient] = None) -> None:
        self.client = client or create_llm_client(role="planner")

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
            all_fix_versions.extend(f.fix_versions)

        # 2. Filter candidate versions strictly through policy engine
        approved_candidates = policy_candidates(full_package, all_fix_versions, ecosystem)

        # Case A: Package is banned or denied by license
        if pol_result.status in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value):
            return RemediationPlan(
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

        # Case B: No approved fix version available
        if not approved_candidates:
            return RemediationPlan(
                finding_ids=finding_ids,
                root_cause_id=root_cause_id,
                action=RemediationAction.EXCEPTION,
                target_version=None,
                target_package=full_package,
                policy_result=pol_result,
                risk_tier=RiskTier.REVIEW,
                requires_approval=True,
                evidence=advisories or [],
                rationale=f"Vulnerability exists in {full_package} but no policy-approved fix version is available.",
            )

        # Target version is the highest approved candidate
        target_version = approved_candidates[0]
        pol_result = PolicyResult.from_dict(policy_check(full_package, target_version, ecosystem))

        # 3. Use LLM to generate reasoned explanation and assess risk context
        prompt = (
            f"You are the VulnFlow Remediation Planner.\n"
            f"Package: {full_package}\n"
            f"Current Vulnerabilities: {cve_list}\n"
            f"Approved Target Version: {target_version}\n"
            f"Advisories: {advisories}\n\n"
            f"Propose a remediation plan to safely upgrade this package."
        )

        rationale = f"Upgrade {full_package} to approved secure version {target_version} to resolve {len(cve_list)} vulnerability(ies)."
        risk_tier = RiskTier.AUTO

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
                rationale = data.rationale or rationale
                # The model can only make risk tier stricter, never looser
                if data.risk_tier.lower() == "review":
                    risk_tier = RiskTier.REVIEW
                logger.info(
                    "Fix Planner LLM response received: Action=%s, RiskTier=%s, Rationale=%s",
                    data.action or "BUMP",
                    risk_tier.value,
                    rationale[:80],
                )
        except Exception as exc:
            logger.info("Using deterministic planner fallback (%s)", exc)

        return RemediationPlan(
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
