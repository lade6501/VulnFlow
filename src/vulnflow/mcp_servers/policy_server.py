"""
src/vulnflow/mcp_servers/policy_server.py
MCP tool server providing policy checks, allowlist queries, and license rules.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vulnflow.mcp_servers.fastmcp import FastMCP
from vulnflow.policy.engine import PolicyEngine, default_policy_engine

logger = logging.getLogger("vulnflow.mcp_servers.policy")

# Initialize formal FastMCP server instance
mcp = FastMCP(
    name="vulnflow-policy",
    description="MCP server providing deterministic organization package policy evaluation and version filtering.",
)


@mcp.tool(
    name="policy_check",
    description="Returns approved, deprecated, banned, unknown, or license_denied status for a dependency version.",
)
def policy_check(
    package: str,
    version: str = "latest",
    ecosystem: str = "npm",
) -> Dict[str, Any]:
    """MCP tool: policy_check - Evaluate compliance according to corporate policy."""
    logger.info("MCP policy_check called for %s@%s (ecosystem: %s)", package, version, ecosystem)
    res = default_policy_engine.check(package=package, version=version, ecosystem=ecosystem)
    return res.to_dict()


@mcp.tool(
    name="policy_candidates",
    description="Filters candidate version list down to only policy-approved versions.",
)
def policy_candidates(
    package: str,
    versions: List[str],
    ecosystem: str = "npm",
) -> List[str]:
    """MCP tool: policy_candidates - Filter target upgrade versions strictly through policy."""
    logger.info("MCP policy_candidates called for %s with %d versions", package, len(versions))
    return default_policy_engine.filter_candidates(package=package, versions=versions, ecosystem=ecosystem)


class PolicyServer:
    """Tool server class wrapping policy tools for in-process and MCP interoperability."""

    def __init__(self, engine: Optional[PolicyEngine] = None) -> None:
        self.engine = engine or default_policy_engine
        self.mcp = mcp

    def policy_check(self, package: str, version: str = "latest", ecosystem: str = "npm") -> Dict[str, Any]:
        return self.engine.check(package=package, version=version, ecosystem=ecosystem).to_dict()

    def policy_candidates(self, package: str, versions: List[str], ecosystem: str = "npm") -> List[str]:
        return self.engine.filter_candidates(package=package, versions=versions, ecosystem=ecosystem)


# Global singleton instance
policy_server = PolicyServer()

if __name__ == "__main__":
    mcp.run()
