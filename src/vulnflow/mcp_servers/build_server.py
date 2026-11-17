"""
src/vulnflow/mcp_servers/build_server.py
MCP tool server triggering package builds and automated test suites.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from vulnflow.sandbox.runner import SandboxRunner, default_sandbox

logger = logging.getLogger("vulnflow.mcp_servers.build")


class BuildServer:
    """Tool server executing sandboxed package builds and tests over MCP."""

    def __init__(self, sandbox: Optional[SandboxRunner] = None) -> None:
        self.sandbox = sandbox or default_sandbox

    def build_test(
        self,
        repo: str,
        branch: str = "main",
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """
        MCP tool: build_test
        Executes build and tests in the sandbox and returns verification metrics.
        """
        logger.info("Executing build_test for %s on branch %s", repo, branch)
        repo_path = Path(repo)
        return self.sandbox.execute_build_and_test(repo_path, ecosystem=ecosystem)


# Global instance
build_server = BuildServer()


def build_test(repo: str, branch: str = "main", ecosystem: str = "npm") -> Dict[str, Any]:
    """Direct callable wrapper for build_test tool."""
    return build_server.build_test(repo, branch, ecosystem)
