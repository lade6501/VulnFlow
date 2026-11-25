"""
src/vulnflow/mcp_servers/build_server.py
MCP tool server triggering sandboxed package builds and automated test suites.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from vulnflow.mcp_servers.fastmcp import FastMCP
from vulnflow.sandbox.runner import SandboxRunner, default_sandbox

logger = logging.getLogger("vulnflow.mcp_servers.build")

# Initialize formal FastMCP server instance
mcp = FastMCP(
    name="vulnflow-build",
    description="MCP server executing sandboxed package builds and verification test suites.",
)


class BuildServer:
    """Tool server executing sandboxed package builds and tests over MCP."""

    def __init__(self, sandbox: Optional[SandboxRunner] = None) -> None:
        self.sandbox = sandbox or default_sandbox
        self.mcp = mcp

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
        return self.sandbox.execute_build_and_test(
            repo_path, ecosystem=ecosystem, branch=branch
        )

    def npm_update_lock(self, repo: str) -> Dict[str, Any]:
        """Resolve an existing lockfile offline without executing dependency scripts."""
        root = Path(repo).resolve()
        manifest = root / "package.json"
        lock = next(
            (root / name for name in ("npm-shrinkwrap.json", "package-lock.json")
             if (root / name).exists() or (root / name).is_symlink()),
            None,
        )
        if lock is None:
            return {"status": "missing"}
        if any(path.is_symlink() or not path.is_file() for path in (manifest, lock)):
            return {"status": "failed", "error": "Manifest and lockfile must be regular files"}
        try:
            with tempfile.TemporaryDirectory(prefix="vulnflow-npm-lock-") as tmp_dir:
                checkout = Path(tmp_dir).resolve()
                shutil.copyfile(manifest, checkout / manifest.name)
                shutil.copyfile(lock, checkout / lock.name)
                code, _, _ = self.sandbox.npm_offline(
                    checkout, "install", "--package-lock-only", "--offline",
                    "--ignore-scripts", "--no-audit", "--no-fund",
                )
                if code != 0:
                    return {"status": "failed", "error": "Offline npm lockfile resolution failed"}
                updated = checkout / lock.name
                if updated.is_symlink() or not updated.is_file():
                    return {"status": "failed", "error": "npm did not return a regular lockfile"}
                if updated.read_bytes() == lock.read_bytes():
                    return {"status": "unchanged"}
                shutil.copyfile(updated, lock)
                return {"status": "updated", "file": lock.name}
        except OSError:
            return {"status": "failed", "error": "Could not prepare the npm lockfile"}


# Global instance
build_server = BuildServer()


@mcp.tool(
    name="build_test",
    description="Executes automated package build and test suite inside sandbox, returning verification metrics.",
)
def build_test(repo: str, branch: str = "main", ecosystem: str = "npm") -> Dict[str, Any]:
    return build_server.build_test(repo, branch, ecosystem)


@mcp.tool(name="npm_update_lock", description="Resolve an existing npm lockfile offline with scripts disabled.")
def npm_update_lock(repo: str) -> Dict[str, Any]:
    return build_server.npm_update_lock(repo)


if __name__ == "__main__":
    mcp.run()
