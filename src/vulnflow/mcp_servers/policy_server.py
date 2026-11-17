"""
src/vulnflow/mcp_servers/policy_server.py
MCP tool server providing policy checks, allowlist queries, and license rules.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vulnflow.policy.engine import PolicyEngine, default_policy_engine

logger = logging.getLogger("vulnflow.mcp_servers.policy")


class PolicyServer:
    """Tool server exposing organizational policy checks and candidate filtering over MCP."""

    def __init__(self, engine: Optional[PolicyEngine] = None) -> None:
        self.engine = engine or default_policy_engine

    def policy_check(
        self,
        package: str,
        version: str = "latest",
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """
        MCP tool: policy_check
        Returns approved, deprecated, banned, unknown, or license_denied status with matched rule.
        """
        res = self.engine.check(package=package, version=version, ecosystem=ecosystem)
        return res.to_dict()

    def policy_candidates(
        self,
        package: str,
        versions: List[str],
        ecosystem: str = "npm",
    ) -> List[str]:
        """
        MCP tool: policy_candidates
        Filters candidate version list down to only policy-approved versions.
        """
        return self.engine.filter_candidates(package=package, versions=versions, ecosystem=ecosystem)


# Global instance
policy_server = PolicyServer()


def policy_check(package: str, version: str = "latest", ecosystem: str = "npm") -> Dict[str, Any]:
    """Direct callable wrapper for policy_check tool."""
    return policy_server.policy_check(package, version, ecosystem)


def policy_candidates(package: str, versions: List[str], ecosystem: str = "npm") -> List[str]:
    """Direct callable wrapper for policy_candidates tool."""
    return policy_server.policy_candidates(package, versions, ecosystem)
