"""
src/vulnflow/orchestrator/routing.py
Defines conditional routing logic across workflow states based on risk.
"""

from __future__ import annotations

from vulnflow.contracts.policy import PolicyStatus
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
    """Route test results to verification, an evidence-backed retry, or escalation."""
    has_failures = any(
        not result.get("build_clean") or not result.get("passed")
        or result.get("verification_available") is False
        for result in state.test_results
    )
    if not has_failures:
        return "verify"

    if any(result.get("verification_available") is False for result in state.test_results):
        return "exception"

    if state.retry_count < state.max_retries and not any(
        result.get("retry_available") is False for result in state.test_results
    ):
        state.retry_count += 1
        return "fix"

    return "exception"


def route_after_verify(state: VulnFlowState) -> str:
    """Open a PR only after every branch has real successful verification evidence."""
    if state.mode != "pr":
        return "end"
    if state.verification_results and all(
        bool(result.get("verified", False)) for result in state.verification_results
    ):
        return "pr"
    return "end"
