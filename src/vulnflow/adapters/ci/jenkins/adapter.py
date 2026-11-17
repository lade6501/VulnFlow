"""
src/vulnflow/adapters/ci/jenkins/adapter.py
Translates VulnFlow run status and exit codes into Jenkins build outcomes and report files.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from vulnflow.contracts.state import VulnFlowState


class JenkinsAdapter:
    """Adapter bridging VulnFlow execution with Jenkins CI pipelines."""

    def is_jenkins_environment(self) -> bool:
        """Return True if running in a Jenkins build executor."""
        return bool(os.getenv("JENKINS_URL") or os.getenv("BUILD_NUMBER"))

    def process_result(self, state: VulnFlowState) -> Dict[str, Any]:
        """Map VulnFlow state to Jenkins build metadata."""
        if state.exit_code == 0:
            build_status = "SUCCESS"
        elif state.exit_code == 10:
            build_status = "UNSTABLE"
        elif state.exit_code == 20:
            build_status = "BLOCKED"
        else:
            build_status = "FAILURE"

        return {
            "build_status": build_status,
            "exit_code": state.exit_code,
            "plans_count": len(state.plans),
            "prs_count": len(state.pull_requests),
            "approval_required": state.exit_code == 10,
        }
