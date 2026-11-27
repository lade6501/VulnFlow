"""
src/vulnflow/adapters/ci/github_action/adapter.py
Translates VulnFlow run results and exit codes into GitHub Actions workflow outputs and summaries.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Optional

from vulnflow.contracts.state import VulnFlowState


class GitHubActionAdapter:
    """Adapter bridging VulnFlow execution results with GitHub Actions runners."""

    def __init__(self) -> None:
        self.step_summary_path = os.getenv("GITHUB_STEP_SUMMARY")
        self.output_path = os.getenv("GITHUB_OUTPUT")

    def is_github_action_environment(self) -> bool:
        """Return True if running inside a GitHub Actions environment."""
        return bool(os.getenv("GITHUB_ACTIONS") == "true")

    def set_output(self, key: str, value: Any) -> None:
        """Write key-value output to $GITHUB_OUTPUT file."""
        if not self.output_path:
            return
        try:
            with open(self.output_path, "a", encoding="utf-8") as f:
                f.write(f"{key}={value}\n")
        except Exception:
            pass

    def emit_annotation(self, level: str, message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
        """Emit workflow annotation command (notice, warning, error)."""
        loc = ""
        if file:
            loc = f" file={file}"
            if line:
                loc += f",line={line}"
        print(f"::{level}{loc}::{message}", file=sys.stderr)

    def write_step_summary(self, markdown_content: str) -> None:
        """Append Markdown content to GitHub Actions job summary."""
        if not self.step_summary_path:
            return
        try:
            with open(self.step_summary_path, "a", encoding="utf-8") as f:
                f.write(markdown_content + "\n")
        except Exception:
            pass

    def process_result(self, state: VulnFlowState) -> int:
        """Set workflow outputs and summaries based on VulnFlow run state."""
        self.set_output("exit_code", state.exit_code)
        self.set_output("terminal_status", state.terminal_status)
        self.set_output("plans_count", len(state.plans))
        self.set_output("prs_count", len(state.pull_requests))

        if state.exit_code == 0:
            self.emit_annotation("notice", f"VulnFlow completed: {len(state.pull_requests)} PR(s) created.")
        elif state.exit_code == 10:
            self.emit_annotation(
                "warning",
                f"VulnFlow paused at Human Approval Gate: {len(state.pending_approval_plans)} plan(s) require review.",
            )
            self.set_output("approval_required", "true")
        elif state.exit_code == 20:
            self.emit_annotation(
                "error",
                f"VulnFlow blocked by policy: {state.blocking_reason or 'Blocked packages detected'}",
            )
            self.set_output("policy_blocked", "true")

        return state.exit_code
