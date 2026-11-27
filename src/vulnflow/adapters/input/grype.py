"""
src/vulnflow/adapters/input/grype.py
Parses Grype vulnerability scan outputs into normalized Finding models.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from vulnflow.adapters.input.trivy import ScannerParseError
from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)

logger = logging.getLogger("vulnflow.adapters.input.grype")


class GrypeAdapter:
    """Parser for Anchore Grype vulnerability scanner JSON reports."""

    def __init__(self, default_ecosystem: str = "npm") -> None:
        self.default_ecosystem = default_ecosystem

    def parse_file(self, report_path: Union[str, Path], repo: str = "workspace") -> List[Finding]:
        """Load and parse a Grype JSON report file from disk."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Grype report not found at {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ScannerParseError(f"Malformed JSON in Grype report: {exc}") from exc

        return self.parse_data(data, repo=repo, raw_ref=str(path))

    def parse_data(
        self,
        data: Union[Dict[str, Any], List[Any]],
        repo: str = "workspace",
        raw_ref: str = "grype.json",
    ) -> List[Finding]:
        """Parse Grype JSON data structure into normalized Finding models."""
        findings: List[Finding] = []

        if isinstance(data, list):
            matches = data
        elif isinstance(data, dict):
            matches = data.get("matches", [])
        else:
            raise ScannerParseError(f"Expected dict or list in Grype report, got {type(data).__name__}")

        for item in matches:
            vuln = item.get("vulnerability", {})
            artifact = item.get("artifact", {})

            pkg_name = artifact.get("name") or item.get("package", "unknown")
            pkg_type = artifact.get("type", self.default_ecosystem)
            pkg_id = f"{pkg_type}:{pkg_name}" if ":" not in pkg_name else pkg_name
            version = artifact.get("version") or item.get("version", "0.0.0")

            cve_id = vuln.get("id") or item.get("cve_id", "CVE-UNKNOWN")
            related = vuln.get("relatedVulnerabilities", [])
            cves = [cve_id]
            for r in related:
                r_id = r.get("id")
                if r_id and r_id not in cves:
                    cves.append(r_id)

            # Severity mapping
            sev_str = str(vuln.get("severity") or item.get("severity", "MEDIUM")).lower()
            try:
                sev = SeverityLevel(sev_str)
            except ValueError:
                sev = SeverityLevel.MEDIUM

            # Fix versions
            fix_info = vuln.get("fix", {})
            raw_fixes = fix_info.get("versions", []) or item.get("fix_versions", [])
            fix_versions = [str(x) for x in raw_fixes] if isinstance(raw_fixes, list) else [str(raw_fixes)]

            # Location
            locations = artifact.get("locations", [])
            file_path = locations[0].get("path", "package.json") if locations else item.get("file_path", "package.json")
            location = LocationInfo(file_path=file_path)

            finding_id = compute_finding_id("grype", repo, pkg_id, version, cves[0], file_path)
            f = Finding(
                id=finding_id,
                type=FindingType.VULN,
                scanner="grype",
                repo=repo,
                package=pkg_id,
                version=version,
                cve=cves,
                severity=sev,
                location=location,
                fix_versions=fix_versions,
                metadata={"description": vuln.get("description", "")},
                raw_ref=raw_ref,
            )
            findings.append(f)

        logger.info("Parsed %d finding(s) from Grype report %s", len(findings), raw_ref)
        return findings
