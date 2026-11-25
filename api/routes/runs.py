"""
api/routes/runs.py
API endpoints for listing, triggering, and inspecting remediation runs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import BoundedSemaphore
from typing import Any, Dict, List, Optional

from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.store.run_store import default_run_store

logger = logging.getLogger("vulnflow.api.runs")


class RunQueueFull(RuntimeError):
    """Raised when the bounded API execution queue has no capacity."""


def _positive_int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


_RUN_CAPACITY = _positive_int_env("VULNFLOW_API_MAX_INFLIGHT", 8)
_RUN_EXECUTOR = ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="vulnflow-api-run"
)
_RUN_SLOTS = BoundedSemaphore(_RUN_CAPACITY)


def list_runs(limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent remediation runs."""
    return default_run_store.list_runs(limit=limit)


def get_run(run_id: str) -> Optional[Dict[str, Any]]:
    """Return single remediation run details by run ID."""
    if not re.fullmatch(r"RUN-[a-zA-Z0-9-]+", run_id):
        return None
    return default_run_store.get_run(run_id)


def get_run_report(run_id: str) -> Optional[str]:
    """Retrieve markdown report content for a given run ID from disk or fallback."""
    if not re.fullmatch(r"RUN-[a-zA-Z0-9-]+", run_id):
        return None
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
    if run_data and run_data.get("terminal_status") not in {"queued", "running"}:
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


def _execute_queued_run(state: VulnFlowState, report_data: Any = None) -> None:
    """Execute one accepted API run and persist its terminal state."""
    temp_report_file: str | None = None
    try:
        if report_data is not None and not state.report_path:
            with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8"
            ) as report_file:
                json.dump(report_data, report_file)
                temp_report_file = report_file.name
                state.report_path = temp_report_file
        result = run_workflow(state)
        default_run_store.save_run(result)
    except Exception as exc:
        logger.exception("Queued run %s failed: %s", state.run_id, exc)
        state.terminal_status = "error"
        state.exit_code = 1
        state.error = str(exc)
        state.blocking_reason = str(exc)
        default_run_store.save_run(state)
    finally:
        if temp_report_file:
            try:
                Path(temp_report_file).unlink(missing_ok=True)
            except OSError:
                logger.warning(
                    "Could not remove temporary report for run %s", state.run_id
                )
        _RUN_SLOTS.release()


def enqueue_run(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Accept a bounded asynchronous run and immediately return its run ID."""
    if not _RUN_SLOTS.acquire(blocking=False):
        raise RunQueueFull("VulnFlow API run queue is at capacity")

    state = VulnFlowState(
        repo_path=payload.get("repo_path", "."),
        report_path=payload.get("report_path"),
        scanner=payload.get("scanner", "trivy"),
        mode=payload.get("mode", "report"),
        ecosystem=payload.get("ecosystem", "npm"),
        terminal_status="queued",
    )
    report_data = payload.get("report")
    if report_data is None:
        report_data = payload.get("data")

    try:
        default_run_store.save_run(state)
        _RUN_EXECUTOR.submit(_execute_queued_run, state, report_data)
    except Exception:
        _RUN_SLOTS.release()
        raise

    return {
        "status": "accepted",
        "run_id": state.run_id,
        "terminal_status": "queued",
    }
