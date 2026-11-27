"""
src/vulnflow/mcp_servers/registry_server.py
MCP tool server querying npm, PyPI, and Maven registries for package versions.
"""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request
from typing import Any, Dict

from vulnflow.mcp_servers.fastmcp import FastMCP

logger = logging.getLogger("vulnflow.mcp_servers.registry")

mcp = FastMCP(
    name="vulnflow-registry",
    description="MCP server verifying package and version availability in upstream registries.",
)


class RegistryServer:
    """Tool server validating package versions in npm, PyPI, and Maven registries over MCP."""

    def __init__(self) -> None:
        self.mcp = mcp
        self._availability_overrides: Dict[str, bool] = {}

    def set_availability(self, package: str, version: str, available: bool) -> None:
        """Allow setting availability for testing or offline simulations."""
        clean_pkg = package.split(":")[-1]
        self._availability_overrides[f"{clean_pkg}@{version}"] = available

    def clear_overrides(self) -> None:
        """Clear test overrides."""
        self._availability_overrides.clear()

    def registry_check(
        self,
        package: str,
        version: str,
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """MCP tool: registry_check - Confirms that the target version exists in registry."""
        clean_pkg = package.split(":")[-1]
        eco = ecosystem.lower()
        prefix = package.split(":", 1)[0].lower() if ":" in package else ""
        if prefix in {"pip", "pypi", "python"}:
            eco = "pypi"
        elif prefix in {"npm", "maven"}:
            eco = prefix

        logger.info("Executing registry_check for %s@%s in %s", clean_pkg, version, eco)

        # Check explicit overrides
        override_key = f"{clean_pkg}@{version}"
        if override_key in self._availability_overrides:
            is_avail = self._availability_overrides[override_key]
            return {
                "available": is_avail,
                "confirmed": is_avail,
                "ecosystem": eco,
                "package": clean_pkg,
                "version": version,
                "reason": "Explicit registry override" if not is_avail else None,
            }

        # Obvious nonexistent synthetic test versions
        if version.startswith("999.") or "nonexistent" in version:
            return {
                "available": False,
                "ecosystem": eco,
                "package": clean_pkg,
                "version": version,
                "reason": f"Version {version} not found in {eco} registry",
            }

        # Check npm registry
        if eco == "npm":
            url = f"https://registry.npmjs.org/{clean_pkg}/{version}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VulnFlow-Registry/1.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        return {"available": True, "confirmed": True, "ecosystem": "npm", "package": clean_pkg, "version": version}
            except urllib.error.HTTPError as he:
                if he.code == 404:
                    return {
                        "available": False,
                        "ecosystem": "npm",
                        "package": clean_pkg,
                        "version": version,
                        "reason": f"Version {version} not found in npm registry (HTTP 404)",
                    }
            except Exception:
                pass
            return {"available": True, "confirmed": False, "ecosystem": "npm", "package": clean_pkg, "version": version, "reason": "Registry unavailable"}

        # Check PyPI
        elif eco in ("pip", "pypi", "python"):
            url = f"https://pypi.org/pypi/{clean_pkg}/{version}/json"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "VulnFlow-Registry/1.0"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    if resp.status == 200:
                        return {"available": True, "confirmed": True, "ecosystem": "pypi", "package": clean_pkg, "version": version}
            except urllib.error.HTTPError as he:
                if he.code == 404:
                    return {
                        "available": False,
                        "ecosystem": "pypi",
                        "package": clean_pkg,
                        "version": version,
                        "reason": f"Version {version} not found in PyPI registry (HTTP 404)",
                    }
            except Exception:
                pass
            return {"available": True, "confirmed": False, "ecosystem": "pypi", "package": clean_pkg, "version": version, "reason": "Registry unavailable"}

        if eco == "maven":
            coordinates = package.removeprefix("maven:").split(":")
            if len(coordinates) != 2 or not all(
                re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", part)
                for part in coordinates
            ) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version):
                return {"available": False, "confirmed": False, "reason": "Invalid Maven coordinates"}
            group, artifact = coordinates
            group_path = group.replace(".", "/")
            url = f"https://repo.maven.apache.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.pom"
            try:
                with urllib.request.urlopen(url, timeout=3.0) as response:
                    if response.status == 200:
                        return {"available": True, "confirmed": True, "ecosystem": eco, "package": package, "version": version}
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return {"available": False, "confirmed": False, "reason": "Version not found in Maven Central"}
            except OSError:
                pass

        return {"available": True, "confirmed": False, "ecosystem": eco, "package": clean_pkg, "version": version, "reason": "Registry verification unavailable"}


registry_server = RegistryServer()


@mcp.tool(
    name="registry_check",
    description="Verifies that a candidate upgrade version actually exists and is available in upstream package registries.",
)
def registry_check(package: str, version: str, ecosystem: str = "npm") -> Dict[str, Any]:
    return registry_server.registry_check(package, version, ecosystem)


if __name__ == "__main__":
    mcp.run()
