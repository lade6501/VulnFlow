"""
src/vulnflow/reporting/json_report.py
Serializes the canonical run report as deterministic, validated JSON.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from vulnflow.contracts.report import RunReport
from vulnflow.contracts.state import VulnFlowState
from vulnflow.reporting.builder import build_run_report


def _canonical(report: RunReport | VulnFlowState) -> RunReport:
    snapshot = report if isinstance(report, RunReport) else build_run_report(report)
    return RunReport.model_validate(snapshot.model_dump(mode="python"))


def generate_json_report(report: RunReport | VulnFlowState) -> dict[str, Any]:
    """Return the canonical schema as a JSON-compatible dictionary."""
    return _canonical(report).model_dump(mode="json")


def write_json_report(
    report: RunReport | VulnFlowState, output_path: str | Path
) -> Path:
    """Atomically persist validated canonical report JSON."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out.parent, 0o755)
    except OSError:
        pass
    payload = json.dumps(generate_json_report(report), indent=2, sort_keys=True) + "\n"
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{out.name}.", dir=out.parent, text=True
    )
    try:
        try:
            os.fchmod(descriptor, 0o644)
        except (OSError, AttributeError):
            pass
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temp_name, out)
        try:
            os.chmod(out, 0o644)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise
    return out
