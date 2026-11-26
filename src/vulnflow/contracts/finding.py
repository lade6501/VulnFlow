"""
src/vulnflow/contracts/finding.py
Defines normalized Pydantic data schemas representing scanner findings.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class FindingType(str, enum.Enum):
    """Categorization of a discovered security finding."""

    VULN = "vuln"
    SECRET = "secret"
    POLICY = "policy"
    EXPIRY = "expiry"


class SeverityLevel(str, enum.Enum):
    """Normalized severity levels across all scanner sources."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class LocationInfo:
    """Location metadata indicating where a finding exists in source or dependency graph."""

    file_path: str = ""
    line: Optional[int] = None
    dependency_path: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LocationInfo:
        return cls(
            file_path=data.get("file_path", ""),
            line=data.get("line"),
            dependency_path=data.get("dependency_path", []),
        )


def compute_finding_id(
    scanner: str,
    repo: str,
    package: str,
    version: str,
    cve: List[str],
    file_path: str = "",
    *,
    occurrence: str = "",
) -> str:
    """Generate a stable deterministic SHA256 identifier for a unique finding."""
    cve_str = ",".join(sorted(cve))
    raw = f"{scanner.lower()}|{repo}|{package.lower()}|{version}|{cve_str}|{file_path}"
    if occurrence:
        raw = f"{raw}|{occurrence}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"FND-{digest[:16]}"


@dataclass
class Finding:
    """
    Normalized finding contract carrying scanner results between VulnFlow pipeline nodes.
    Conforms strictly to Section 6.1 of the VulnFlow specification.
    """

    id: str
    type: FindingType
    scanner: str
    repo: str
    package: str  # Format: "ecosystem:name", e.g. "npm:lodash"
    version: str
    cve: List[str]
    severity: SeverityLevel
    location: LocationInfo
    fix_versions: List[str] = field(default_factory=list)
    raw_ref: str = ""
    redacted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding to dictionary format."""
        return {
            "id": self.id,
            "type": self.type.value if isinstance(self.type, FindingType) else str(self.type),
            "scanner": self.scanner,
            "repo": self.repo,
            "package": self.package,
            "version": self.version,
            "cve": self.cve,
            "severity": self.severity.value if isinstance(self.severity, SeverityLevel) else str(self.severity),
            "location": self.location.to_dict() if isinstance(self.location, LocationInfo) else self.location,
            "fix_versions": self.fix_versions,
            "raw_ref": self.raw_ref,
            "redacted": self.redacted,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        """Instantiate finding from a dictionary representation."""
        type_val = data.get("type", "vuln")
        try:
            finding_type = FindingType(type_val)
        except ValueError:
            finding_type = FindingType.VULN

        sev_val = data.get("severity", "medium").lower()
        try:
            severity = SeverityLevel(sev_val)
        except ValueError:
            severity = SeverityLevel.MEDIUM

        loc_raw = data.get("location", {})
        if isinstance(loc_raw, dict):
            location = LocationInfo.from_dict(loc_raw)
        elif isinstance(loc_raw, LocationInfo):
            location = loc_raw
        else:
            location = LocationInfo(file_path=str(loc_raw))

        finding_id = data.get("id") or compute_finding_id(
            scanner=data.get("scanner", "unknown"),
            repo=data.get("repo", "workspace"),
            package=data.get("package", "unknown"),
            version=data.get("version", "0.0.0"),
            cve=data.get("cve", []),
            file_path=location.file_path,
        )

        return cls(
            id=finding_id,
            type=finding_type,
            scanner=data.get("scanner", "unknown"),
            repo=data.get("repo", "workspace"),
            package=data.get("package", "unknown"),
            version=data.get("version", "0.0.0"),
            cve=data.get("cve", []),
            severity=severity,
            location=location,
            fix_versions=data.get("fix_versions", []),
            raw_ref=data.get("raw_ref", ""),
            redacted=bool(data.get("redacted", False)),
            metadata=data.get("metadata", {}),
        )
