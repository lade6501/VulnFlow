"""
api/routes/runs.py
API endpoints for listing, triggering, and inspecting remediation runs.
"""

from __future__ import annotations

from pathlib import Path
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


def get_run_report(run_id: str) -> Optional[str]:
    """Retrieve markdown report content for a given run ID from disk or fallback."""
    search_paths = [
        Path(".vulnflow/reports") / f"report_{run_id}.md",
        Path("reports") / f"report_{run_id}.md",
        Path("../fake-vuln-repo/.vulnflow/reports") / f"report_{run_id}.md",
        Path(".vulnflow") / f"report_{run_id}.md",
    ]
    for p in search_paths:
        if p.exists():
            try:
                return p.read_text(encoding="utf-8")
            except Exception:
                pass

    run_data = default_run_store.get_run(run_id)
    if run_data:
        try:
            from vulnflow.reporting.markdown import generate_markdown_report

            st = VulnFlowState(
                run_id=run_id,
                repo_path=run_data.get("repo_path", "."),
                mode=run_data.get("mode", "pr"),
                terminal_status=run_data.get("terminal_status", "completed"),
                exit_code=run_data.get("exit_code", 0),
                pull_requests=run_data.get("prs", []),
                blocking_reason=run_data.get("blocking_reason"),
            )
            return generate_markdown_report(st)
        except Exception:
            pass

    return None


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
