"""
src/vulnflow/agents/fixer.py
Agent that analyzes test failures and formulates self-correction retries or escalations.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vulnflow.contracts.remediation_plan import RemediationAction, RemediationPlan, RiskTier
from vulnflow.llm import LLMClient, create_llm_client
from vulnflow.policy.engine import parse_version_tuple

logger = logging.getLogger("vulnflow.agents.fixer")


class FixerAgent:
    """
    Reasoning agent handling the self-correction loop when sandboxed tests fail.
    Formulates adjusted alternative versions or escalates to human review.
    """

    def __init__(self, llm_client: Optional[LLMClient] = None) -> None:
        self.llm_client = llm_client or create_llm_client("fixer")

    def analyze_failure_and_correct(
        self,
        plan: RemediationPlan,
        test_output: str,
        retry_count: int,
        max_retries: int = 2,
    ) -> RemediationPlan:
        """
        Evaluate test failure output. Propose conservative fallback version on retry,
        or escalate to REVIEW tier if retries are exhausted.
        """
        logger.info(
            "FixerAgent self-correcting plan %s for %s (retry %d/%d)",
            plan.id,
            plan.target_package,
            retry_count,
            max_retries,
        )

        first_err = test_output.strip().splitlines()[0] if test_output.strip() else "Test failure"
        if len(first_err) > 100:
            first_err = first_err[:97] + "..."

        # If retries exhausted: escalate to REVIEW tier (F20 acceptance criteria)
        if retry_count >= max_retries:
            plan.risk_tier = RiskTier.REVIEW
            plan.requires_approval = True
            plan.rationale = (
                f"{plan.rationale}\n\n"
                f"🛑 Self-Correction Exhausted: Automated test suite failed on version {plan.target_version} "
                f"after {max_retries} attempt(s): {first_err}. Escalated to human review."
            )
            return plan

        # Attempt fallback to a safer patch or intermediate version if available
        current_target = plan.target_version or "0.0.0"
        t_tuple = parse_version_tuple(current_target)

        # If it was a major bump, step down to a conservative patch within previous major
        if t_tuple[0] > 1:
            fallback_version = f"{t_tuple[0] - 1}.99.9"
        else:
            fallback_version = current_target

        plan.target_version = fallback_version
        plan.rationale = (
            f"{plan.rationale}\n\n"
            f"🔄 Self-Correction Retry #{retry_count + 1}: Previous version caused build error "
            f"({first_err}). Adjusting target version to {fallback_version}."
        )
        return plan


# Global default instance
default_fixer_agent = FixerAgent()
