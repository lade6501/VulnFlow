"""
src/vulnflow/orchestrator/approval.py
Manages human-in-the-loop approval gates before executing patch changes.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from vulnflow.contracts.remediation_plan import RemediationPlan
from vulnflow.observability.audit_log import audit_logger

logger = logging.getLogger("vulnflow.orchestrator.approval")


class ApprovalGate:
    """Coordinates interrupt and resume states for human reviewer authorization."""

    def __init__(self) -> None:
        self._pending_plans: Dict[str, RemediationPlan] = {}
        self._decisions: Dict[str, Dict[str, Any]] = {}

    def submit_for_approval(self, plan: RemediationPlan) -> None:
        """Register a plan that requires explicit human review."""
        self._pending_plans[plan.id] = plan
        logger.info("Plan %s submitted for human approval (tier: %s)", plan.id, plan.risk_tier)
        audit_logger.log(
            run_id="approval_system",
            event_type="APPROVAL_REQUESTED",
            actor="orchestrator",
            payload={"plan_id": plan.id, "risk_tier": str(plan.risk_tier)},
        )

    def record_decision(
        self,
        plan_id: str,
        approved: bool,
        reviewer: str = "security-engineer",
        reason: Optional[str] = None,
    ) -> bool:
        """Record human approval or rejection decision."""
        if plan_id in self._pending_plans:
            del self._pending_plans[plan_id]

        decision = {
            "approved": approved,
            "reviewer": reviewer,
            "reason": reason,
        }
        self._decisions[plan_id] = decision
        audit_logger.log(
            run_id="approval_system",
            event_type="APPROVAL_GRANTED" if approved else "APPROVAL_REJECTED",
            actor=reviewer,
            payload={"plan_id": plan_id, "reason": reason},
        )
        return approved

    def is_approved(self, plan_id: str) -> bool:
        """Check whether a plan has received approval."""
        return self._decisions.get(plan_id, {}).get("approved", False)

    def list_pending(self) -> List[str]:
        """Return list of plan IDs awaiting human decision."""
        return list(self._pending_plans.keys())


# Global approval gate instance
global_approval_gate = ApprovalGate()
