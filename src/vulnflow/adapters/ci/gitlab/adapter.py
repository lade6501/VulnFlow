"""
src/vulnflow/adapters/ci/gitlab/adapter.py
Translates VulnFlow run status and exit codes into GitLab CI job artifacts and statuses.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from vulnflow.contracts.state import VulnFlowState


class GitLabAdapter:
    """Adapter bridging VulnFlow execution with GitLab CI pipelines."""

    def is_gitlab_environment(self) -> bool:
        """Return True if running in a GitLab CI runner."""
        return bool(os.getenv("GITLAB_CI") == "true")

    def process_result(self, state: VulnFlowState) -> Dict[str, Any]:
        """Map VulnFlow state to GitLab CI job outcomes."""
        if state.exit_code == 0:
            job_status = "success"
        elif state.exit_code == 10:
            job_status = "manual_approval_required"
        elif state.exit_code == 20:
            job_status = "policy_blocked"
        else:
            job_status = "failed"

        return {
            "job_status": job_status,
            "exit_code": state.exit_code,
            "pipeline_id": os.getenv("CI_PIPELINE_ID"),
            "job_id": os.getenv("CI_JOB_ID"),
            "approval_required": state.exit_code == 10,
        }
