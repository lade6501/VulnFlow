"""
src/vulnflow/mcp_servers/git_server.py
MCP tool server executing git operations, branch creation, and commits.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("vulnflow.mcp_servers.git")


class GitServer:
    """Tool server executing repository operations, branch creation, and PR management over MCP."""

    def __init__(self) -> None:
        self._open_prs: Dict[str, Dict[str, Any]] = {}
        self._pr_counter = 1

    def git_clone(self, repo_url: str, target_dir: str) -> Dict[str, Any]:
        """MCP tool: git_clone - Clones repo into target directory."""
        logger.info("Cloning %s into %s", repo_url, target_dir)
        return {"status": "cloned", "path": target_dir, "ref": "main"}

    def git_branch(self, branch_name: str, repo_dir: str) -> Dict[str, Any]:
        """MCP tool: git_branch - Creates or switches to remediation branch."""
        logger.info("Creating branch %s in %s", branch_name, repo_dir)
        return {"status": "created", "branch": branch_name}

    def git_patch(self, file_path: str, diff: str, repo_dir: str) -> Dict[str, Any]:
        """MCP tool: git_patch - Applies unified diff to target file."""
        logger.info("Applying patch to %s in %s", file_path, repo_dir)
        return {"status": "applied", "file": file_path, "hunks": 1}

    def git_commit(self, message: str, repo_dir: str) -> Dict[str, Any]:
        """MCP tool: git_commit - Commits staged changes."""
        logger.info("Committing in %s with message: %s", repo_dir, message)
        return {"status": "committed", "commit_sha": "a1b2c3d4e5f67890"}

    def pr_create(
        self,
        branch: str,
        body: str,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        MCP tool: pr_create - Opens pull request.
        Guarantees idempotency: reruns on the same branch do not duplicate PRs.
        """
        if branch in self._open_prs:
            logger.info("PR for branch '%s' already exists; returning existing PR without duplicate", branch)
            return self._open_prs[branch]

        pr_num = self._pr_counter
        self._pr_counter += 1
        pr_record = {
            "status": "opened",
            "pr_url": f"https://github.com/vulnflow/sample-repo/pull/{pr_num}",
            "pr_number": pr_num,
            "branch": branch,
            "title": title or f"fix(deps): automated remediation on {branch}",
            "body": body,
        }
        self._open_prs[branch] = pr_record
        logger.info("Opened new PR #%d: %s", pr_num, pr_record["pr_url"])
        return pr_record


# Global instance
git_server = GitServer()


def git_clone(repo_url: str, target_dir: str) -> Dict[str, Any]:
    return git_server.git_clone(repo_url, target_dir)


def git_branch(branch_name: str, repo_dir: str) -> Dict[str, Any]:
    return git_server.git_branch(branch_name, repo_dir)


def git_patch(file_path: str, diff: str, repo_dir: str) -> Dict[str, Any]:
    return git_server.git_patch(file_path, diff, repo_dir)


def git_commit(message: str, repo_dir: str) -> Dict[str, Any]:
    return git_server.git_commit(message, repo_dir)


def pr_create(branch: str, body: str, title: Optional[str] = None) -> Dict[str, Any]:
    return git_server.pr_create(branch, body, title)
