"""
src/vulnflow/adapters/input/sarif.py
Parses generic SARIF vulnerability reports into normalized Finding models.
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

logger = logging.getLogger("vulnflow.adapters.input.sarif")


class SARIFAdapter:
    """Parser for standard OASIS SARIF (Static Analysis Results Interchange Format) v2.1.0."""

    def __init__(self, default_ecosystem: str = "npm") -> None:
        self.default_ecosystem = default_ecosystem

    def parse_file(self, report_path: Union[str, Path], repo: str = "workspace") -> List[Finding]:
        """Read and parse a SARIF report file from disk."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"SARIF report not found at {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ScannerParseError(f"Malformed JSON in SARIF report: {exc}") from exc

        return self.parse_data(data, repo=repo, raw_ref=str(path))

    def parse_data(
        self,
        data: Dict[str, Any],
        repo: str = "workspace",
        raw_ref: str = "report.sarif",
    ) -> List[Finding]:
        """Convert in-memory SARIF JSON structure into normalized Finding objects."""
        if not isinstance(data, dict) or "runs" not in data:
            raise ScannerParseError("Invalid SARIF document: missing top-level 'runs' array")

        findings: List[Finding] = []
        runs = data.get("runs", [])

        for run_idx, run in enumerate(runs):
            driver = run.get("tool", {}).get("driver", {})
            scanner_name = driver.get("name", "sarif").lower()

            # Map rules by ruleId for description lookups
            rule_map: Dict[str, Dict[str, Any]] = {}
            for rule in driver.get("rules", []):
                rule_id = rule.get("id")
                if rule_id:
                    rule_map[rule_id] = rule

            results = run.get("results", [])
            for res_idx, res in enumerate(results):
                rule_id = res.get("ruleId", "UNKNOWN-RULE")
                rule_info = rule_map.get(rule_id, {})

                # Severity mapping
                level = res.get("level", "warning").lower()
                if level == "error":
                    severity = SeverityLevel.HIGH
                elif level == "warning":
                    severity = SeverityLevel.MEDIUM
                elif level == "note":
                    severity = SeverityLevel.LOW
                else:
                    severity = SeverityLevel.INFO

                # Location resolution
                locations = res.get("locations", [])
                file_path = "package.json"
                start_line = None
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    file_path = phys.get("artifactLocation", {}).get("uri", "package.json")
                    start_line = phys.get("region", {}).get("startLine")

                props = res.get("properties", {})
                pkg_raw = props.get("package") or props.get("PkgName") or rule_id
                if ":" not in pkg_raw:
                    package = f"{self.default_ecosystem}:{pkg_raw}"
                else:
                    package = pkg_raw

                version = str(props.get("version") or props.get("InstalledVersion") or "0.0.0")
                fix_v = props.get("fix_versions") or props.get("FixedVersion") or []
                fix_list = [fix_v] if isinstance(fix_v, str) else list(fix_v)

                cve_list = [rule_id] if rule_id.startswith("CVE-") or rule_id.startswith("GHSA-") else []
                if not cve_list:
                    cve_list = [rule_id]

                msg = res.get("message", {}).get("text", "")

                fnd_id = compute_finding_id(
                    scanner=scanner_name,
                    repo=repo,
                    package=package,
                    version=version,
                    cve=cve_list,
                    file_path=file_path,
                )

                finding = Finding(
                    id=fnd_id,
                    type=FindingType.VULN,
                    scanner=scanner_name,
                    repo=repo,
                    package=package,
                    version=version,
                    cve=cve_list,
                    severity=severity,
                    location=LocationInfo(file_path=file_path, line=start_line, dependency_path=[pkg_raw]),
                    fix_versions=fix_list,
                    raw_ref=f"{raw_ref}#{run_idx}/{res_idx}",
                    metadata={"message": msg, "rule_name": rule_info.get("name", "")},
                )
                findings.append(finding)

        logger.info("Parsed %d finding(s) from SARIF data", len(findings))
        return findings
