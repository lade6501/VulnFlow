"""
api/routes/webhooks.py
Webhook handler endpoints for receiving external scanner and CI triggers.
"""

from __future__ import annotations

import json
import logging
import tempfile
from typing import Any, Dict

from vulnflow.contracts.state import VulnFlowState
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.store.run_store import default_run_store

logger = logging.getLogger("vulnflow.api.webhooks")


def handle_scan_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process incoming scanner webhook payload and trigger remediation run (F30).

    Returns a response containing run_id and execution status.
    """
    repo = payload.get("repo", payload.get("repository", "."))
    scanner = payload.get("scanner", "trivy")
    mode = payload.get("mode", "report")
    report_data = payload.get("report") or payload.get("data")
    report_path = payload.get("report_path")

    # If raw report data was posted in webhook body, write to temporary file
    temp_report_file = None
    if report_data and not report_path:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report_data, f)
            temp_report_file = f.name
            report_path = f.name

    try:
        state = VulnFlowState(
            repo_path=repo,
            report_path=report_path,
            scanner=scanner,
            mode=mode,
            ecosystem=payload.get("ecosystem", "npm"),
        )
        result = run_workflow(state)
        default_run_store.save_run(result)

        logger.info("Webhook triggered run %s completed with status: %s", result.run_id, result.terminal_status)
        return {
            "status": "completed",
            "run_id": result.run_id,
            "terminal_status": result.terminal_status,
            "exit_code": result.exit_code,
            "plans_count": len(result.plans),
            "prs_count": len(result.pull_requests),
        }
    finally:
        if temp_report_file:
            import os
            try:
                os.unlink(temp_report_file)
            except Exception:
                pass
