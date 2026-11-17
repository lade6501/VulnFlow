"""
src/vulnflow/contracts/policy.py
Defines schemas for organizational policy rules, approved packages, and licenses.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class PolicyStatus(str, enum.Enum):
    """Evaluation status returned by the policy engine."""

    APPROVED = "approved"
    DEPRECATED = "deprecated"
    BANNED = "banned"
    UNKNOWN = "unknown"
    LICENSE_DENIED = "license_denied"


@dataclass
class PackagePolicyEntry:
    """Policy rules governing a specific package within an ecosystem."""

    name: str
    ecosystem: str = "npm"
    approved_versions: Optional[str] = None  # e.g. ">=4.17.21"
    status: PolicyStatus = PolicyStatus.APPROVED
    replacement: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "approved_versions": self.approved_versions,
            "status": self.status.value if isinstance(self.status, PolicyStatus) else str(self.status),
            "replacement": self.replacement,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PackagePolicyEntry:
        st_val = data.get("status", "approved").lower()
        try:
            status = PolicyStatus(st_val)
        except ValueError:
            status = PolicyStatus.UNKNOWN

        return cls(
            name=data.get("name", ""),
            ecosystem=data.get("ecosystem", "npm"),
            approved_versions=data.get("approved_versions"),
            status=status,
            replacement=data.get("replacement"),
            reason=data.get("reason"),
        )


@dataclass
class PolicyRules:
    """Global organizational policy engine rules."""

    unknown_package: str = "require_approval"  # "require_approval", "deny", "allow"
    apply_to_transitive: bool = True
    licenses_denied: List[str] = field(default_factory=lambda: ["GPL-3.0", "AGPL-3.0"])
    licenses_allowed: List[str] = field(
        default_factory=lambda: ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"]
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PolicyRules:
        return cls(
            unknown_package=data.get("unknown_package", "require_approval"),
            apply_to_transitive=bool(data.get("apply_to_transitive", True)),
            licenses_denied=data.get("licenses_denied", ["GPL-3.0", "AGPL-3.0"]),
            licenses_allowed=data.get(
                "licenses_allowed", ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"]
            ),
        )


@dataclass
class ApprovedPackagesPolicy:
    """Complete container for organization approved packages and rules."""

    packages: List[PackagePolicyEntry] = field(default_factory=list)
    rules: PolicyRules = field(default_factory=PolicyRules)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packages": [p.to_dict() for p in self.packages],
            "rules": self.rules.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApprovedPackagesPolicy:
        pkg_list = [
            PackagePolicyEntry.from_dict(p) if isinstance(p, dict) else p
            for p in data.get("packages", [])
        ]
        rules_data = data.get("rules", {})
        rules = (
            PolicyRules.from_dict(rules_data)
            if isinstance(rules_data, dict)
            else (rules_data or PolicyRules())
        )
        return cls(packages=pkg_list, rules=rules)


@dataclass
class RiskTierThresholds:
    """Criteria governing whether an action is automatically approved or requires human review."""

    allow_auto_patch_bumps: bool = True
    allow_auto_minor_bumps: bool = False
    allow_auto_transitive: bool = True
    require_review_for_direct_dependencies: bool = True
    require_review_for_major_bumps: bool = True
    block_unapproved_packages: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
