"""
src/vulnflow/adapters/input/osv.py
Parses OSV-Scanner output reports into normalized Finding models.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from vulnflow.adapters.input.trivy import ScannerParseError
from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)

logger = logging.getLogger("vulnflow.adapters.input.osv")


class OSVAdapter:
    """Parser for Google OSV-Scanner JSON vulnerability reports."""

    def __init__(self, default_ecosystem: str = "npm") -> None:
        self.default_ecosystem = default_ecosystem

    def parse_file(self, report_path: Union[str, Path], repo: str = "workspace") -> List[Finding]:
        """Load and parse an OSV-Scanner JSON report file from disk."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"OSV report not found at {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ScannerParseError(f"Malformed JSON in OSV report: {exc}") from exc

        return self.parse_data(data, repo=repo, raw_ref=str(path))

    def parse_data(
        self,
        data: Union[Dict[str, Any], List[Any]],
        repo: str = "workspace",
        raw_ref: str = "osv.json",
    ) -> List[Finding]:
        """Parse OSV-Scanner JSON data structure into normalized Finding models."""
        findings: List[Finding] = []

        if isinstance(data, list):
            results = [{"packages": data}]
        elif isinstance(data, dict):
            results = data.get("results", [])
            if not results and "packages" in data:
                results = [data]
        else:
            raise ScannerParseError(f"Expected dict or list in OSV report, got {type(data).__name__}")

        for res in results:
            source = res.get("source", {})
            file_path = source.get("path", "package.json")
            location = LocationInfo(file_path=file_path)

            for pkg_entry in res.get("packages", []):
                pkg_info = pkg_entry.get("package", {})
                pkg_name = pkg_info.get("name") or pkg_entry.get("name", "unknown")
                eco = (pkg_info.get("ecosystem") or self.default_ecosystem).lower()
                pkg_id = f"{eco}:{pkg_name}" if ":" not in pkg_name else pkg_name
                version = pkg_info.get("version") or pkg_entry.get("version", "0.0.0")

                for vuln in pkg_entry.get("vulnerabilities", []):
                    cve_primary = vuln.get("id", "GHSA-UNKNOWN")
                    aliases = vuln.get("aliases", [])
                    cves = [cve_primary]
                    for a in aliases:
                        if a not in cves:
                            cves.append(a)

                    # Extract fix version from affected ranges
                    fix_versions: List[str] = []
                    for aff in vuln.get("affected", []):
                        for rng in aff.get("ranges", []):
                            for ev in rng.get("events", []):
                                if "fixed" in ev:
                                    fix_versions.append(ev["fixed"])

                    # Severity
                    db_spec = vuln.get("database_specific", {})
                    sev_str = str(db_spec.get("severity") or "HIGH").lower()
                    try:
                        sev = SeverityLevel(sev_str)
                    except ValueError:
                        sev = SeverityLevel.HIGH

                    finding_id = compute_finding_id("osv", repo, pkg_id, version, cves[0], file_path)
                    f = Finding(
                        id=finding_id,
                        type=FindingType.VULN,
                        scanner="osv",
                        repo=repo,
                        package=pkg_id,
                        version=version,
                        cve=cves,
                        severity=sev,
                        location=location,
                        fix_versions=fix_versions,
                        metadata={"summary": vuln.get("summary", ""), "details": vuln.get("details", "")},
                        raw_ref=raw_ref,
                    )
                    findings.append(f)

        logger.info("Parsed %d finding(s) from OSV report %s", len(findings), raw_ref)
        return findings
