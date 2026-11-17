"""
src/vulnflow/orchestrator/approval.py
Manages human-in-the-loop approval gates before executing patch changes.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from vulnflow.contracts.remediation_plan import RemediationPlan
from vulnflow.contracts.state import VulnFlowState
from vulnflow.observability.audit_log import audit_logger

logger = logging.getLogger("vulnflow.orchestrator.approval")


class ApprovalGate:
    """Coordinates interrupt and resume states for human reviewer authorization."""

    def __init__(self, persistence_file: Optional[Path] = None) -> None:
        self._persistence_file = persistence_file or Path(".vulnflow/approvals.json")
        self._pending_plans: Dict[str, RemediationPlan] = {}
        self._decisions: Dict[str, Dict[str, Any]] = {}
        self._load_persisted()

    def _resolve_persistence_file(self, repo_path: Optional[str] = None) -> Path:
        if repo_path:
            p = Path(repo_path) / ".vulnflow" / "approvals.json"
            return p
        return self._persistence_file

    def _load_persisted(self, repo_path: Optional[str] = None) -> None:
        target_f = self._resolve_persistence_file(repo_path)
        try:
            if target_f.exists():
                with open(target_f, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._decisions.update(data.get("decisions", {}))
        except Exception as exc:
            logger.debug("Could not load persisted approvals: %s", exc)

    def _save_persisted(self, repo_path: Optional[str] = None) -> None:
        target_f = self._resolve_persistence_file(repo_path)
        try:
            target_f.parent.mkdir(parents=True, exist_ok=True)
            with open(target_f, "w", encoding="utf-8") as f:
                json.dump({"decisions": self._decisions}, f, indent=2)
        except Exception as exc:
            logger.debug("Could not save persisted approvals: %s", exc)

    def submit_for_approval(self, plan: RemediationPlan, repo_path: Optional[str] = None) -> None:
        """Register a plan that requires explicit human review."""
        self._pending_plans[plan.id] = plan
        logger.info("Plan %s submitted for human approval (tier: %s)", plan.id, plan.risk_tier)
        audit_logger.log(
            run_id="approval_system",
            event_type="APPROVAL_REQUESTED",
            actor="orchestrator",
            payload={
                "plan_id": plan.id,
                "target_package": plan.target_package,
                "target_version": plan.target_version,
                "risk_tier": str(plan.risk_tier),
            },
        )

    def record_decision(
        self,
        plan_id: str,
        approved: bool,
        reviewer: str = "security-lead",
        reason: Optional[str] = None,
        repo_path: Optional[str] = None,
    ) -> bool:
        """Record human approval or rejection decision with persistence."""
        self._load_persisted(repo_path)
        if plan_id in self._pending_plans:
            del self._pending_plans[plan_id]

        decision = {
            "approved": approved,
            "reviewer": reviewer,
            "reason": reason or ("Approved by human reviewer" if approved else "Rejected by human reviewer"),
            "timestamp": time.time(),
        }
        self._decisions[plan_id] = decision
        self._save_persisted(repo_path)

        audit_logger.log(
            run_id="approval_system",
            event_type="APPROVAL_GRANTED" if approved else "APPROVAL_REJECTED",
            actor=reviewer,
            payload={"plan_id": plan_id, "approved": approved, "reason": decision["reason"]},
        )
        logger.info("Recorded human decision for %s: approved=%s by %s", plan_id, approved, reviewer)
        return approved

    def is_approved(self, plan_id: str, repo_path: Optional[str] = None) -> bool:
        """Check whether a plan has received approval."""
        self._load_persisted(repo_path)
        return self._decisions.get(plan_id, {}).get("approved", False)

    def is_rejected(self, plan_id: str, repo_path: Optional[str] = None) -> bool:
        """Check whether a plan was explicitly rejected."""
        self._load_persisted(repo_path)
        if plan_id in self._decisions:
            return not self._decisions[plan_id].get("approved", False)
        return False

    def get_decision(self, plan_id: str, repo_path: Optional[str] = None) -> Dict[str, Any]:
        """Return the decision record for a plan."""
        self._load_persisted(repo_path)
        return self._decisions.get(plan_id, {})

    def list_pending(self) -> List[str]:
        """Return list of plan IDs awaiting human decision."""
        return list(self._pending_plans.keys())


# Global approval gate instance
global_approval_gate = ApprovalGate()


def save_run_state(state: VulnFlowState, repo_path: Optional[str] = None) -> Path:
    """Persist run state when execution pauses for human approval."""
    base_dir = Path(repo_path) if repo_path else Path(".")
    target_dir = base_dir / ".vulnflow"
    target_dir.mkdir(parents=True, exist_ok=True)
    state_file = target_dir / f"state_{state.run_id}.json"
    latest_file = target_dir / "pending_state.json"

    data = state.to_dict()
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    with open(latest_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    logger.info("Paused run state saved to %s", state_file)
    return state_file


def load_run_state(repo_path: Optional[str] = None, run_id: Optional[str] = None) -> Optional[VulnFlowState]:
    """Load paused run state from disk to resume execution."""
    base_dir = Path(repo_path) if repo_path else Path(".")
    target_dir = base_dir / ".vulnflow"

    if run_id:
        target_f = target_dir / f"state_{run_id}.json"
    else:
        target_f = target_dir / "pending_state.json"

    if not target_f.exists():
        return None

    try:
        with open(target_f, "r", encoding="utf-8") as f:
            data = json.load(f)
            return VulnFlowState.from_dict(data)
    except Exception as exc:
        logger.warning("Could not load run state from %s: %s", target_f, exc)
        return None
