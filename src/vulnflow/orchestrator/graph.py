"""
src/vulnflow/orchestrator/graph.py
Constructs and compiles the LangGraph state machine workflow for VulnFlow.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.nodes import (
    approve_node,
    dedupe_node,
    exception_node,
    fix_node,
    ingest_node,
    plan_node,
    policy_node,
    pr_node,
    rootcause_node,
    test_node,
    verify_node,
)
from vulnflow.orchestrator.routing import (
    route_after_approve,
    route_after_plan,
    route_after_policy,
    route_after_test,
)
from vulnflow.observability.tracing import trace_span

logger = logging.getLogger("vulnflow.orchestrator.graph")


class VulnFlowWorkflow:
    """
    State machine workflow orchestrator executing the 10-node remediation sequence.
    Can be run as a standalone deterministic state machine or compiled into a LangGraph StateGraph.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, Callable[[VulnFlowState], VulnFlowState]] = {
            "ingest": ingest_node,
            "dedupe": dedupe_node,
            "rootcause": rootcause_node,
            "policy": policy_node,
            "plan": plan_node,
            "approve": approve_node,
            "fix": fix_node,
            "test": test_node,
            "pr": pr_node,
            "verify": verify_node,
            "exception": exception_node,
        }

    def execute(self, state: VulnFlowState) -> VulnFlowState:
        """
        Execute the end-to-end workflow transitions following Section 6.5:
        ingest -> dedupe -> rootcause -> policy -> [plan | exception] -> approve -> fix -> test -> [pr | fix | exception] -> verify
        """
        with trace_span("workflow.execute", {"run_id": state.run_id}):
            logger.info("Starting VulnFlow run %s in '%s' mode", state.run_id, state.mode)
            state.append_audit(
                "RUN_STARTED",
                "orchestrator",
                {
                    "run_id": state.run_id,
                    "repo_path": state.repo_path,
                    "report_path": state.report_path,
                    "scanner": state.scanner,
                    "mode": state.mode,
                    "ecosystem": state.ecosystem,
                },
            )

            # 1. Ingest
            state = self.nodes["ingest"](state)

            # 2. Dedupe
            state = self.nodes["dedupe"](state)

            # 3. Root cause
            state = self.nodes["rootcause"](state)

            # 4. Policy check
            state = self.nodes["policy"](state)
            if route_after_policy(state) == "exception":
                state = self.nodes["exception"](state)
                return state

            # 5. Plan
            state = self.nodes["plan"](state)
            if route_after_plan(state) == "verify":  # Report-only mode
                state = self.nodes["verify"](state)
                return state

            # 6. Approve gate
            state = self.nodes["approve"](state)
            if route_after_approve(state) == "exception":
                state = self.nodes["exception"](state)
                return state

            # 7. Fix & Test loop
            while True:
                state = self.nodes["fix"](state)
                state = self.nodes["test"](state)
                route = route_after_test(state)

                if route == "pr":
                    break
                elif route == "fix":
                    logger.warning("Test failed; retrying fix iteration %d", state.retry_count)
                    continue
                else:  # route == "exception"
                    state = self.nodes["exception"](state)
                    return state

            # 8. PR creation
            state = self.nodes["pr"](state)

            # 9. Verification rescan
            state = self.nodes["verify"](state)

            state.append_audit(
                "RUN_COMPLETED",
                "orchestrator",
                {
                    "run_id": state.run_id,
                    "terminal_status": state.terminal_status,
                    "exit_code": state.exit_code,
                    "findings_resolved": len(state.findings),
                    "prs_opened": len(state.pull_requests),
                },
            )

            logger.info("VulnFlow run %s completed with status: %s", state.run_id, state.terminal_status)
            return state


def build_graph() -> Any:
    """Build and return LangGraph StateGraph instance if library is present, else VulnFlowWorkflow."""
    try:
        from langgraph.graph import END, StateGraph

        workflow = StateGraph(VulnFlowState)
        workflow.add_node("ingest", ingest_node)
        workflow.add_node("dedupe", dedupe_node)
        workflow.add_node("rootcause", rootcause_node)
        workflow.add_node("policy", policy_node)
        workflow.add_node("plan", plan_node)
        workflow.add_node("approve", approve_node)
        workflow.add_node("fix", fix_node)
        workflow.add_node("test", test_node)
        workflow.add_node("pr", pr_node)
        workflow.add_node("verify", verify_node)
        workflow.add_node("exception", exception_node)

        workflow.set_entry_point("ingest")
        workflow.add_edge("ingest", "dedupe")
        workflow.add_edge("dedupe", "rootcause")
        workflow.add_edge("rootcause", "policy")

        workflow.add_conditional_edges(
            "policy",
            route_after_policy,
            {"plan": "plan", "exception": "exception"},
        )
        workflow.add_conditional_edges(
            "plan",
            route_after_plan,
            {"approve": "approve", "verify": "verify"},
        )
        workflow.add_conditional_edges(
            "approve",
            route_after_approve,
            {"fix": "fix", "exception": "exception"},
        )
        workflow.add_edge("fix", "test")
        workflow.add_conditional_edges(
            "test",
            route_after_test,
            {"pr": "pr", "fix": "fix", "exception": "exception"},
        )
        workflow.add_edge("pr", "verify")
        workflow.add_edge("verify", END)
        workflow.add_edge("exception", END)

        return workflow.compile()
    except ImportError:
        return VulnFlowWorkflow()


# Helper function to run a workflow run directly
def run_workflow(state: Optional[VulnFlowState] = None, **kwargs: Any) -> VulnFlowState:
    """Run an end-to-end VulnFlow workflow instance."""
    wf_state = state or VulnFlowState(**kwargs)
    runner = build_graph()
    if hasattr(runner, "invoke"):
        result = runner.invoke(wf_state)
        return result if isinstance(result, VulnFlowState) else VulnFlowState(**result)
    return runner.execute(wf_state)
