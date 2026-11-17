"""
src/vulnflow/orchestrator/routing.py
Defines conditional routing logic across workflow states based on risk.
"""

from __future__ import annotations

from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import RiskTier
from vulnflow.contracts.state import VulnFlowState


def route_after_policy(state: VulnFlowState) -> str:
    """Determine whether to proceed with remediation planning or branch to policy exception."""
    for group in state.root_cause_groups:
        pol = group.get("policy", {})
        if pol.get("status") in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value):
            # If package has an approved replacement, allow planning to propose replacement (F12)
            if not pol.get("replacement"):
                return "exception"
    return "plan"


def route_after_plan(state: VulnFlowState) -> str:
    """Route plans through the human approval gate or report verification."""
    if state.mode == "report":
        return "verify"
    return "approve"


def route_after_approve(state: VulnFlowState) -> str:
    """Route after approval evaluation: proceed to fix, pause for review, or halt to exception."""
    if not state.approved_plans:
        if getattr(state, "pending_approval_plans", None):
            return "pause"
        return "exception"
    return "fix"


def route_after_test(state: VulnFlowState) -> str:
    """Route test results: proceed to PR creation, retry fix, or escalate to exception."""
    has_failures = any(not r.get("build_clean", True) or not r.get("passed", True) for r in state.test_results)
    if not has_failures:
        return "pr"

    if state.retry_count < state.max_retries:
        state.retry_count += 1
        return "fix"

    return "exception"
