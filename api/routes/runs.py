"""
api/routes/runs.py
API endpoints for listing, triggering, and inspecting remediation runs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.store.run_store import default_run_store


def list_runs(limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent remediation runs."""
    return default_run_store.list_runs(limit=limit)


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    """Return single remediation run details by run ID."""
    return default_run_store.get_run(run_id)


def trigger_run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a run and return the resulting state."""
    state = VulnFlowState(
        repo_path=payload.get("repo_path", "."),
        report_path=payload.get("report_path"),
        scanner=payload.get("scanner", "trivy"),
        mode=payload.get("mode", "report"),
        ecosystem=payload.get("ecosystem", "npm"),
    )
    result = run_workflow(state)
    default_run_store.save_run(result)
    return {
        "run_id": result.run_id,
        "terminal_status": result.terminal_status,
        "exit_code": result.exit_code,
        "plans_count": len(result.plans),
        "prs_count": len(result.pull_requests),
    }
