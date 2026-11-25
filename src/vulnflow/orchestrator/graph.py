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
    route_after_verify,
)
from vulnflow.observability.tracing import trace_span
from vulnflow.observability.langsmith_tracer import langsmith_tracer

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

    def _run_node(self, node_name: str, st: VulnFlowState) -> VulnFlowState:
        """Execute a node while timing and recording child span in LangSmith and local tracer."""
        import time

        t0 = time.time()
        err_msg: Optional[str] = None
        try:
            return self.nodes[node_name](st)
        except Exception as exc:
            err_msg = str(exc)
            raise
        finally:
            dur_ms = round((time.time() - t0) * 1000.0, 2)
            langsmith_tracer.record_node_span(
                workflow_run_id=st.run_id,
                node_name=node_name,
                inputs={"mode": st.mode, "status": st.terminal_status},
                outputs={
                    "status": st.terminal_status,
                    "findings": len(st.findings),
                    "plans": len(st.plans),
                    "exit_code": st.exit_code,
                },
                duration_ms=dur_ms,
                error=err_msg,
            )

    def execute(self, state: VulnFlowState) -> VulnFlowState:
        """
        Execute the end-to-end workflow transitions following Section 6.5:
        ingest -> dedupe -> rootcause -> policy -> [plan | exception] -> approve -> fix -> test -> [pr | fix | exception] -> verify
        """
        with trace_span("workflow.execute", {"run_id": state.run_id}):
            logger.info("Starting VulnFlow run %s in '%s' mode", state.run_id, state.mode)

            # Start root trace in LangSmith
            langsmith_tracer.start_workflow_run(
                run_id=state.run_id,
                name="vulnflow.workflow",
                inputs={
                    "repo_path": state.repo_path,
                    "report_path": state.report_path,
                    "scanner": state.scanner,
                    "mode": state.mode,
                    "ecosystem": state.ecosystem,
                },
                tags=["vulnflow", state.mode, state.scanner],
                metadata={
                    "run_id": state.run_id,
                    "auto_approve": state.auto_approve,
                },
            )

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

            try:
                # If resuming a paused state at approval gate, resume directly from approve
                if state.terminal_status == "pending_approval" and state.plans:
                    logger.info("Resuming paused workflow run %s at approval gate", state.run_id)
                    state.terminal_status = "running"
                else:
                    # 1. Ingest
                    state = self._run_node("ingest", state)

                    # 2. Dedupe
                    state = self._run_node("dedupe", state)

                    # 3. Root cause
                    state = self._run_node("rootcause", state)

                    # 4. Policy check
                    state = self._run_node("policy", state)
                    if route_after_policy(state) == "exception":
                        state = self._run_node("exception", state)
                        langsmith_tracer.end_workflow_run(
                            state.run_id,
                            outputs={"terminal_status": state.terminal_status, "exit_code": state.exit_code},
                            status=state.terminal_status,
                        )
                        return state

                    # 5. Plan
                    state = self._run_node("plan", state)
                    if route_after_plan(state) == "verify":  # Report-only mode
                        state = self._run_node("verify", state)
                        langsmith_tracer.end_workflow_run(
                            state.run_id,
                            outputs={"terminal_status": state.terminal_status, "exit_code": state.exit_code},
                            status=state.terminal_status,
                        )
                        return state

                # 6. Approve gate
                state = self._run_node("approve", state)
                approve_route = route_after_approve(state)
                if approve_route == "pause":
                    langsmith_tracer.end_workflow_run(
                        state.run_id,
                        outputs={"terminal_status": state.terminal_status, "exit_code": state.exit_code},
                        status="PENDING_APPROVAL",
                    )
                    return state
                elif approve_route == "exception":
                    state = self._run_node("exception", state)
                    langsmith_tracer.end_workflow_run(
                        state.run_id,
                        outputs={"terminal_status": state.terminal_status, "exit_code": state.exit_code},
                        status=state.terminal_status,
                    )
                    return state

                # 7. Fix & Test loop
                while True:
                    state = self._run_node("fix", state)
                    state = self._run_node("test", state)
                    route = route_after_test(state)

                    if route == "verify":
                        break
                    elif route == "fix":
                        logger.warning("Test failed; retrying fix iteration %d", state.retry_count)
                        continue
                    else:  # route == "exception"
                        state = self._run_node("exception", state)
                        langsmith_tracer.end_workflow_run(
                            state.run_id,
                            outputs={"terminal_status": state.terminal_status, "exit_code": state.exit_code},
                            status=state.terminal_status,
                        )
                        return state

                # 8. Verification rescan must complete before any remote PR side effect.
                state = self._run_node("verify", state)

                # 9. Create a PR only from verified branch evidence.
                if route_after_verify(state) == "pr":
                    state = self._run_node("pr", state)

                findings_resolved = len({
                    finding_id
                    for result in state.verification_results if result.get("verified")
                    for finding_id in result.get("resolved_finding_ids", [])
                })
                state.append_audit(
                    "RUN_COMPLETED",
                    "orchestrator",
                    {
                        "run_id": state.run_id,
                        "terminal_status": state.terminal_status,
                        "exit_code": state.exit_code,
                        "findings_resolved": findings_resolved,
                        "prs_opened": len(state.pull_requests),
                    },
                )

                logger.info("VulnFlow run %s completed with status: %s", state.run_id, state.terminal_status)
                langsmith_tracer.end_workflow_run(
                    state.run_id,
                    outputs={
                        "terminal_status": state.terminal_status,
                        "exit_code": state.exit_code,
                        "findings_resolved": findings_resolved,
                        "prs_opened": len(state.pull_requests),
                    },
                    status=state.terminal_status,
                )
                return state

            except Exception as exc:
                logger.exception("VulnFlow run %s failed with unhandled exception: %s", state.run_id, exc)
                state.terminal_status = "error"
                state.exit_code = 1
                state.error = str(exc)
                state.blocking_reason = f"Execution failed: {exc}"

                langsmith_tracer.end_workflow_run(
                    state.run_id,
                    outputs={"terminal_status": "error", "exit_code": 1},
                    error=str(exc),
                    status="ERROR",
                )

                # Clean up orphan branches created during this run that don't have opened PRs (F33)
                from vulnflow.mcp_servers.git_server import git_server

                opened_branches = {
                    pr.get("branch")
                    for pr in state.pull_requests
                    if isinstance(pr, dict) and pr.get("branch")
                }
                cleaned_branches: list[str] = []
                for b in getattr(state, "created_branches", []):
                    if b not in opened_branches:
                        try:
                            res = git_server.git_cleanup_branch(b, state.repo_path)
                            if res.get("status") == "deleted":
                                cleaned_branches.append(b)
                        except Exception as c_err:
                            logger.warning("Could not delete orphan branch %s: %s", b, c_err)

                if cleaned_branches:
                    state.append_audit(
                        "ORPHAN_CLEANUP",
                        "orchestrator",
                        {"cleaned_branches": cleaned_branches},
                    )

                state.append_audit(
                    "RUN_FAILED",
                    "orchestrator",
                    {
                        "run_id": state.run_id,
                        "terminal_status": state.terminal_status,
                        "exit_code": state.exit_code,
                        "error": str(exc),
                    },
                )
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

        def route_entry(st: VulnFlowState) -> str:
            if st.terminal_status in ("pending_approval", "running") and st.plans:
                return "approve"
            return "ingest"

        workflow.set_conditional_entry_point(
            route_entry,
            {"ingest": "ingest", "approve": "approve"},
        )
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
            {"fix": "fix", "exception": "exception", "pause": END},
        )
        workflow.add_edge("fix", "test")
        workflow.add_conditional_edges(
            "test",
            route_after_test,
            {"verify": "verify", "fix": "fix", "exception": "exception"},
        )
        workflow.add_conditional_edges(
            "verify",
            route_after_verify,
            {"pr": "pr", "end": END},
        )
        workflow.add_edge("pr", END)
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
        config = {
            "tags": ["vulnflow", wf_state.mode, wf_state.scanner],
            "metadata": {
                "run_id": wf_state.run_id,
                "repo_path": wf_state.repo_path,
                "scanner": wf_state.scanner,
                "mode": wf_state.mode,
            },
        }
        result = runner.invoke(wf_state, config=config)
        return result if isinstance(result, VulnFlowState) else VulnFlowState(**result)
    return runner.execute(wf_state)
