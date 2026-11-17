"""
src/vulnflow/store/run_store.py
Provides persistence operations for run state, history, and approval logs.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.contracts.state import VulnFlowState

logger = logging.getLogger("vulnflow.store.run_store")


class RunStore:
    """Manages persistence and retrieval of VulnFlow remediation runs."""

    def __init__(self, base_dir: str = ".vulnflow/runs") -> None:
        self.base_dir = Path(base_dir)
        self._memory_runs: Dict[str, Dict[str, Any]] = {}

    def save_run(self, state: VulnFlowState) -> None:
        """Save a run state in memory and to disk."""
        data = {
            "run_id": state.run_id,
            "terminal_status": state.terminal_status,
            "exit_code": state.exit_code,
            "repo_path": state.repo_path,
            "mode": state.mode,
            "findings_count": len(state.findings),
            "plans_count": len(state.plans),
            "approved_count": len(state.approved_plans),
            "pending_count": len(state.pending_approval_plans),
            "prs_count": len(state.pull_requests),
            "prs": state.pull_requests,
            "blocking_reason": state.blocking_reason,
            "created_at": state.created_at if hasattr(state, "created_at") else 0,
        }
        self._memory_runs[state.run_id] = data

        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            run_file = self.base_dir / f"{state.run_id}.json"
            with open(run_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning("Could not persist run to disk: %s", exc)

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a run by its ID."""
        if run_id in self._memory_runs:
            return self._memory_runs[run_id]

        run_file = self.base_dir / f"{run_id}.json"
        if run_file.exists():
            try:
                with open(run_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._memory_runs[run_id] = data
                    return data
            except Exception:
                pass
        return None

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List all runs ordered by most recent."""
        runs: Dict[str, Dict[str, Any]] = dict(self._memory_runs)

        if self.base_dir.exists():
            for f in self.base_dir.glob("*.json"):
                r_id = f.stem
                if r_id not in runs:
                    try:
                        with open(f, "r", encoding="utf-8") as fp:
                            runs[r_id] = json.load(fp)
                    except Exception:
                        pass

        sorted_runs = sorted(runs.values(), key=lambda r: r.get("created_at", 0), reverse=True)
        return sorted_runs[:limit]


default_run_store = RunStore()
