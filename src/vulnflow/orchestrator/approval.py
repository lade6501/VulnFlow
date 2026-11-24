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
from vulnflow.store.supabase_store import SupabaseStore, log_or_raise

logger = logging.getLogger("vulnflow.orchestrator.approval")


class ApprovalGate:
    """Coordinates interrupt and resume states for human reviewer authorization."""

    def __init__(self, persistence_file: Optional[Path] = None) -> None:
        self._persistence_file = persistence_file or Path(".vulnflow/approvals.json")
        self._pending_plans: Dict[str, RemediationPlan] = {}
        self._decisions: Dict[str, Dict[str, Any]] = {}
        self._remote_results: Dict[str, Dict[str, Any]] = {}
        self._load_persisted()

    @staticmethod
    def _supabase() -> Optional[SupabaseStore]:
        """Resolve configuration lazily so CLI/tests may set environment at runtime."""
        return SupabaseStore.from_env()

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

    def resolve_plan(self, state: VulnFlowState, plan: RemediationPlan) -> Dict[str, Any]:
        """Create/reuse a durable request and return its aggregate approval status."""
        store = self._supabase()
        if store:
            try:
                result = store.claim_approval(state, plan)
                self._remote_results[plan.id] = result
                return result
            except Exception as exc:
                log_or_raise(store, "approval claim", exc)

        self._load_persisted(state.repo_path)
        decision = self._decisions.get(plan.id)
        if decision:
            return {
                "plan_id": plan.id,
                "status": "approved" if decision.get("approved", False) else "rejected",
                "decision": decision,
            }
        self.submit_for_approval(plan, repo_path=state.repo_path)
        return {"plan_id": plan.id, "status": "pending", "decision": None}

    def record_decision(
        self,
        plan_id: str,
        approved: bool,
        reviewer: str = "security-lead",
        reviewer_group: str = "security",
        reason: Optional[str] = None,
        repo_path: Optional[str] = None,
    ) -> bool:
        """Record human approval or rejection decision with persistence."""
        decision_reason = reason or ("Approved by human reviewer" if approved else "Rejected by human reviewer")
        store = self._supabase()
        if store:
            try:
                result = store.record_decision(
                    plan_id=plan_id,
                    approved=approved,
                    reviewer=reviewer,
                    reviewer_group=reviewer_group,
                    reason=decision_reason,
                    repo_path=repo_path,
                )
                self._remote_results[plan_id] = result
                aggregate_approved = result.get("status") == "approved"
                audit_logger.log(
                    run_id="approval_system",
                    event_type="APPROVAL_GRANTED" if approved else "APPROVAL_REJECTED",
                    actor=reviewer,
                    payload={
                        "plan_id": plan_id,
                        "approved": approved,
                        "reviewer_group": reviewer_group,
                        "aggregate_status": result.get("status"),
                        "reason": decision_reason,
                    },
                )
                return aggregate_approved
            except Exception as exc:
                log_or_raise(store, "approval decision", exc)

        self._load_persisted(repo_path)
        if plan_id in self._pending_plans:
            del self._pending_plans[plan_id]

        decision = {
            "approved": approved,
            "reviewer": reviewer,
            "reason": decision_reason,
            "reviewer_group": reviewer_group,
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
        remote = self._remote_results.get(plan_id)
        if remote:
            return remote.get("status") == "approved"
        store = self._supabase()
        if store:
            try:
                remote = store.get_plan_approval(plan_id, repo_path)
                if remote:
                    self._remote_results[plan_id] = remote
                    return remote.get("status") == "approved"
            except Exception as exc:
                log_or_raise(store, "approval lookup", exc)
        self._load_persisted(repo_path)
        if self._decisions.get("all", {}).get("approved", False) or self._decisions.get("*", {}).get("approved", False):
            return True
        return self._decisions.get(plan_id, {}).get("approved", False)

    def is_rejected(self, plan_id: str, repo_path: Optional[str] = None) -> bool:
        """Check whether a plan was explicitly rejected."""
        remote = self._remote_results.get(plan_id)
        if remote:
            return remote.get("status") == "rejected"
        store = self._supabase()
        if store:
            try:
                remote = store.get_plan_approval(plan_id, repo_path)
                if remote:
                    self._remote_results[plan_id] = remote
                    return remote.get("status") == "rejected"
            except Exception as exc:
                log_or_raise(store, "approval lookup", exc)
        self._load_persisted(repo_path)
        if plan_id in self._decisions:
            return not self._decisions[plan_id].get("approved", False)
        return False

    def get_decision(self, plan_id: str, repo_path: Optional[str] = None) -> Dict[str, Any]:
        """Return the decision record for a plan."""
        remote = self._remote_results.get(plan_id)
        if remote:
            decision = remote.get("decision")
            return decision if isinstance(decision, dict) else remote
        store = self._supabase()
        if store:
            try:
                remote = store.get_plan_approval(plan_id, repo_path)
                if remote:
                    self._remote_results[plan_id] = remote
                    decision = remote.get("decision")
                    return decision if isinstance(decision, dict) else remote
            except Exception as exc:
                log_or_raise(store, "approval lookup", exc)
        self._load_persisted(repo_path)
        return self._decisions.get(plan_id, {})

    def list_pending(self) -> List[str]:
        """Return list of plan IDs awaiting human decision."""
        return list(self._pending_plans.keys())

    def list_pending_records(self, repo_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return durable pending requests when Supabase is configured."""
        store = self._supabase()
        if not store:
            return []
        try:
            return store.list_pending(repo_path)
        except Exception as exc:
            log_or_raise(store, "pending approval list", exc)
            return []

    def get_resolution(self, plan_id: str) -> Dict[str, Any]:
        """Return the latest aggregate result cached for an approval operation."""
        return self._remote_results.get(plan_id, {})


# Global approval gate instance
global_approval_gate = ApprovalGate()


def save_run_state(state: VulnFlowState, repo_path: Optional[str] = None) -> Path:
    """Persist run state when execution pauses for human approval."""
    store = SupabaseStore.from_env()
    supabase_saved = False
    if store:
        try:
            store.save_checkpoint(state)
            supabase_saved = True
        except Exception as exc:
            log_or_raise(store, "checkpoint save", exc)

    try:
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
    except Exception as exc:
        if supabase_saved:
            logger.warning(
                "Could not save local checkpoint file to %s (%s), but Supabase persistence succeeded.",
                repo_path,
                exc,
            )
            fallback_dir = Path("/tmp/.vulnflow")
            try:
                fallback_dir.mkdir(parents=True, exist_ok=True)
                fallback_file = fallback_dir / f"state_{state.run_id}.json"
                with open(fallback_file, "w", encoding="utf-8") as f:
                    json.dump(state.to_dict(), f, indent=2)
                return fallback_file
            except Exception:
                return Path(f".vulnflow/state_{state.run_id}.json")
        raise


def load_run_state(repo_path: Optional[str] = None, run_id: Optional[str] = None) -> Optional[VulnFlowState]:
    """Load paused run state from disk to resume execution."""
    store = SupabaseStore.from_env()
    if store:
        try:
            remote_state = store.load_checkpoint(repo_path, run_id)
            if remote_state:
                return VulnFlowState.from_dict(remote_state)
        except Exception as exc:
            log_or_raise(store, "checkpoint load", exc)

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
