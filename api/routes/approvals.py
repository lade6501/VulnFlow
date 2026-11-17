"""
api/routes/approvals.py
API endpoints for submitting human approval or rejection of plans.
"""

from __future__ import annotations

from typing import Any, Dict

from vulnflow.orchestrator.approval import global_approval_gate, load_run_state
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.store.run_store import default_run_store


def submit_approval(
    plan_id: str,
    approved: bool,
    reviewer: str = "security-lead",
    reason: str = "Approved via API",
    repo_path: str = ".",
    resume: bool = True,
) -> Dict[str, Any]:
    """Record an approval or rejection decision and optionally resume workflow."""
    global_approval_gate.record_decision(
        plan_id=plan_id,
        approved=approved,
        reviewer=reviewer,
        reason=reason,
        repo_path=repo_path,
    )

    result_payload: Dict[str, Any] = {
        "plan_id": plan_id,
        "approved": approved,
        "reviewer": reviewer,
        "reason": reason,
    }

    if approved and resume:
        saved_state = load_run_state(repo_path=repo_path)
        if saved_state:
            resumed_state = run_workflow(saved_state)
            default_run_store.save_run(resumed_state)
            result_payload["run_id"] = resumed_state.run_id
            result_payload["terminal_status"] = resumed_state.terminal_status
            result_payload["prs_opened"] = len(resumed_state.pull_requests)

    return result_payload
