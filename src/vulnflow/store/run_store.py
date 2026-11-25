"""
src/vulnflow/store/run_store.py
Provides persistence operations for run state, history, and approval logs.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from vulnflow.contracts.state import VulnFlowState

logger = logging.getLogger("vulnflow.store.run_store")


class RunStore:
    """Manages persistence and retrieval of VulnFlow remediation runs."""

    def __init__(self, base_dir: str = ".vulnflow/runs") -> None:
        self.base_dir = Path(base_dir)
        self._memory_runs: dict[str, dict[str, Any]] = {}

    def save_run(self, state: VulnFlowState) -> None:
        """Save a run summary plus evidence required for later report reconstruction."""
        findings = []
        for finding in state.findings:
            item = finding.to_dict()
            item["raw_ref"] = ""
            item["metadata"] = {}
            findings.append(item)
        deduped = []
        for finding in state.deduped_findings:
            item = finding.to_dict()
            item["raw_ref"] = ""
            item["metadata"] = {}
            deduped.append(item)
        evidence_snapshot = {
            "run_id": state.run_id,
            "repo_path": state.repo_path,
            "report_path": state.report_path,
            "scanner": state.scanner,
            "mode": state.mode,
            "ecosystem": state.ecosystem,
            "findings": findings,
            "deduped_findings": deduped,
            "root_cause_groups": state.root_cause_groups,
            "plans": [plan.to_dict() for plan in state.plans],
            "approved_plans": [plan.to_dict() for plan in state.approved_plans],
            "rejected_plans": [plan.to_dict() for plan in state.rejected_plans],
            "pending_approval_plans": [plan.to_dict() for plan in state.pending_approval_plans],
            "patches": state.patches,
            "test_results": state.test_results,
            "pull_requests": state.pull_requests,
            "verification_results": state.verification_results,
            "audit_events": state.audit_events,
            "error": state.error,
            "blocking_reason": state.blocking_reason,
            "exception_ticket": state.exception_ticket,
            "exit_code": None if state.terminal_status == "queued" else state.exit_code,
            "terminal_status": state.terminal_status,
        }
        data = {
            "run_id": state.run_id,
            "terminal_status": state.terminal_status,
            "exit_code": None if state.terminal_status == "queued" else state.exit_code,
            "repo_path": state.repo_path,
            "mode": state.mode,
            "findings_count": len(state.findings),
            "plans_count": len(state.plans),
            "approved_count": len(state.approved_plans),
            "pending_count": len(state.pending_approval_plans),
            "prs_count": len(state.pull_requests),
            "prs": state.pull_requests,
            "blocking_reason": state.blocking_reason,
            "created_at": getattr(state, "created_at", None) or (time.time() * 1000),
            "evidence_snapshot": evidence_snapshot,
        }
        self._memory_runs[state.run_id] = data

        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.base_dir.parent, 0o755)
                os.chmod(self.base_dir, 0o755)
            except OSError:
                pass
            run_file = self.base_dir / f"{state.run_id}.json"
            with open(run_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            try:
                os.chmod(run_file, 0o644)
            except OSError:
                pass
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Could not persist run to disk: %s", exc)

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Retrieve a run by its ID."""
        if run_id in self._memory_runs:
            return self._memory_runs[run_id]

        run_file = self.base_dir / f"{run_id}.json"
        if run_file.exists():
            try:
                with open(run_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    if not isinstance(loaded, dict):
                        return None
                    data: dict[str, Any] = loaded
                    self._memory_runs[run_id] = data
                    return data
            except (OSError, json.JSONDecodeError) as exc:
                logger.debug("Could not read persisted run %s: %s", run_id, exc)
        return None

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        """List all runs ordered by most recent."""
        runs: dict[str, dict[str, Any]] = dict(self._memory_runs)

        search_dirs = [self.base_dir, Path("../fake-vuln-repo/.vulnflow"), Path(".vulnflow")]
        for s_dir in search_dirs:
            if s_dir.exists():
                for f in s_dir.glob("*.json"):
                    r_id = f.stem.replace("state_", "")
                    if "state_RUN-" in f.name and r_id not in runs:
                        try:
                            with open(f, "r", encoding="utf-8") as fp:
                                st_data = json.load(fp)
                            runs[r_id] = {
                                "run_id": r_id,
                                "terminal_status": st_data.get("terminal_status", "pending_approval"),
                                "exit_code": st_data.get("exit_code", 10),
                                "repo_path": st_data.get("repo_path", "../fake-vuln-repo"),
                                "mode": st_data.get("mode", "pr"),
                                "findings_count": len(st_data.get("findings", [])),
                                "plans_count": len(st_data.get("plans", [])),
                                "approved_count": len(st_data.get("approved_plans", [])),
                                "pending_count": len(st_data.get("pending_approval_plans", [])),
                                "prs_count": len(st_data.get("pull_requests", [])),
                                "prs": st_data.get("pull_requests", []),
                                "blocking_reason": st_data.get("blocking_reason"),
                                "created_at": f.stat().st_mtime * 1000,
                            }
                        except (OSError, json.JSONDecodeError, AttributeError) as exc:
                            logger.debug("Could not read legacy run %s: %s", f, exc)
                    elif f.name.startswith("RUN-") and r_id not in runs:
                        try:
                            with open(f, "r", encoding="utf-8") as fp:
                                item = json.load(fp)
                                if not item.get("created_at"):
                                    item["created_at"] = f.stat().st_mtime * 1000
                                runs[r_id] = item
                        except (OSError, json.JSONDecodeError, AttributeError) as exc:
                            logger.debug("Could not read run %s: %s", f, exc)

        sorted_runs = sorted(runs.values(), key=lambda r: r.get("created_at", 0), reverse=True)
        return sorted_runs[:limit]


default_run_store = RunStore()
