"""
src/vulnflow/policy/engine.py
Evaluates remediation plans against approved packages and organizational rules.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from vulnflow.contracts.policy import (
    ApprovedPackagesPolicy,
    PackagePolicyEntry,
    PolicyStatus,
)
from vulnflow.contracts.remediation_plan import PolicyResult
from vulnflow.policy.loaders.yaml_loader import YAMLPolicyLoader

logger = logging.getLogger("vulnflow.policy.engine")


def is_prerelease(v_str: str) -> bool:
    """Return True if version string denotes an alpha, beta, rc, dev, preview, or pre-release."""
    if not v_str:
        return False
    lower = v_str.lower()
    return bool(re.search(r"[-._]?(alpha|beta|rc|dev|preview|pre|snapshot|b\d+|a\d+)", lower))


def parse_version_tuple(v_str: str) -> tuple[int, int, int]:
    """Parse semver string like '4.17.21' or 'v1.2.3-beta' into (major, minor, patch) integer tuple."""
    clean = re.sub(r"^[v^~>=<! ]+", "", v_str).split("-")[0].split("+")[0]
    parts = clean.split(".")
    major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return (major, minor, patch)


def check_version_satisfies(version: str, constraint: str) -> bool:
    """
    Check if a version satisfies a simple range constraint like '>=4.17.21', '<5.0.0', or '^4.0.0'.
    """
    if not constraint or constraint == "*" or version.lower() in ("latest", "*"):
        return True

    target = parse_version_tuple(version)

    # Handle multiple clauses like '>=4.17.21 <5.0.0' or '>=4.17.21, <5.0.0'
    clauses = [c.strip() for c in constraint.replace(",", " ").split() if c.strip()]

    for clause in clauses:
        if clause.startswith(">="):
            req = parse_version_tuple(clause[2:])
            if target < req:
                return False
        elif clause.startswith("<="):
            req = parse_version_tuple(clause[2:])
            if target > req:
                return False
        elif clause.startswith(">"):
            req = parse_version_tuple(clause[1:])
            if target <= req:
                return False
        elif clause.startswith("<"):
            req = parse_version_tuple(clause[1:])
            if target >= req:
                return False
        elif clause.startswith("="):
            req = parse_version_tuple(clause[1:])
            if target != req:
                return False
        elif clause.startswith("^"):
            req = parse_version_tuple(clause[1:])
            # Caret constraint: same major, and target >= req
            if target[0] != req[0] or target < req:
                return False
        else:
            req = parse_version_tuple(clause)
            if target != req:
                return False

    return True


class PolicyEngine:
    """
    Pure deterministic policy evaluation engine.
    Given package, version, and ecosystem, returns compliance decision according to org rules.
    """

    def __init__(
        self,
        policy: ApprovedPackagesPolicy | None = None,
        policy_path: str | Path | None = None,
    ) -> None:
        if policy is not None:
            self.policy = policy
        else:
            loader = YAMLPolicyLoader(policy_path or "policies/approved_packages.yaml")
            self.policy = loader.load()

        # Index packages by (ecosystem, name)
        self._pkg_index: dict[tuple[str, str], PackagePolicyEntry] = {}
        for entry in self.policy.packages:
            eco = entry.ecosystem.lower()
            if eco in ("pip", "python", "pypi"):
                eco = "pypi"
            elif eco in ("npm", "node"):
                eco = "npm"
            elif eco in ("maven", "mvn", "java"):
                eco = "maven"
            key = (eco, entry.name.lower())
            self._pkg_index[key] = entry

    def check(
        self,
        package: str,
        version: str = "latest",
        ecosystem: str = "npm",
    ) -> PolicyResult:
        """
        Evaluate compliance for a target dependency.

        Returns:
            PolicyResult with status in (approved, deprecated, banned, unknown, license_denied).
        """
        # Normalize package identifier
        clean_pkg = package.lower()
        eco_norm = ecosystem.lower()
        if ":" in clean_pkg:
            eco_part, name_part = clean_pkg.split(":", 1)
            eco_norm = eco_part.lower()
            clean_pkg = name_part

        if eco_norm in ("pip", "python", "pypi"):
            eco_norm = "pypi"
        elif eco_norm in ("npm", "node"):
            eco_norm = "npm"
        elif eco_norm in ("maven", "mvn", "java"):
            eco_norm = "maven"

        key = (eco_norm, clean_pkg)
        entry = self._pkg_index.get(key)

        if entry:
            if entry.status == PolicyStatus.BANNED:
                return PolicyResult(
                    status=PolicyStatus.BANNED.value,
                    rule_matched="banned_package",
                    reason=entry.reason or "Package is banned by organizational policy",
                )
            elif entry.status == PolicyStatus.DEPRECATED:
                return PolicyResult(
                    status=PolicyStatus.DEPRECATED.value,
                    rule_matched="deprecated_package",
                    replacement=entry.replacement,
                    reason=entry.reason or "Package is deprecated upstream",
                )
            elif entry.status == PolicyStatus.APPROVED:
                if entry.approved_versions:
                    if check_version_satisfies(version, entry.approved_versions):
                        return PolicyResult(
                            status=PolicyStatus.APPROVED.value,
                            rule_matched=f"approved_versions:{entry.approved_versions}",
                            reason="Version conforms to approved range constraint",
                        )
                    else:
                        return PolicyResult(
                            status=PolicyStatus.UNKNOWN.value,
                            rule_matched=f"unapproved_version_range:{entry.approved_versions}",
                            reason=f"Version {version} does not satisfy approved range {entry.approved_versions}",
                        )
                return PolicyResult(
                    status=PolicyStatus.APPROVED.value,
                    rule_matched="approved_package_unconstrained",
                    reason="Package is explicitly approved without version limits",
                )

        # Package is not in approved list
        rule_unknown = self.policy.rules.unknown_package
        if rule_unknown == "deny":
            return PolicyResult(
                status=PolicyStatus.BANNED.value,
                rule_matched="unknown_package:deny",
                reason="Package is not on organizational approved list",
            )
        elif rule_unknown == "allow":
            return PolicyResult(
                status=PolicyStatus.APPROVED.value,
                rule_matched="unknown_package:allow",
                reason="Default allow policy for unlisted packages",
            )

        return PolicyResult(
            status=PolicyStatus.UNKNOWN.value,
            rule_matched="unknown_package:require_approval",
            reason="Package is not on approved list; human authorization required",
        )

    def filter_candidates(
        self,
        package: str,
        versions: list[str],
        ecosystem: str = "npm",
    ) -> list[str]:
        """Filter candidate version strings to only those approved by policy."""
        allowed: list[str] = []
        for v in versions:
            res = self.check(package=package, version=v, ecosystem=ecosystem)
            if res.status == PolicyStatus.APPROVED.value:
                allowed.append(v)
        return allowed


# Shared default instance
default_policy_engine = PolicyEngine()
