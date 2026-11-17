"""
src/vulnflow/adapters/input/trivy.py
Parses Trivy JSON and SARIF reports into normalized Finding models.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)
from vulnflow.core.redaction import redact_secrets

logger = logging.getLogger("vulnflow.adapters.input.trivy")


class ScannerParseError(Exception):
    """Raised when scanner report format is malformed or unreadable."""


class TrivyAdapter:
    """Parser for Trivy JSON vulnerability and secret scanner reports."""

    def __init__(self, default_ecosystem: str = "npm") -> None:
        self.default_ecosystem = default_ecosystem

    def parse_file(self, report_path: Union[str, Path], repo: str = "workspace") -> List[Finding]:
        """Load and parse a Trivy JSON report file from disk."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Trivy report not found at {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ScannerParseError(f"Malformed JSON in Trivy report: {exc}") from exc

        return self.parse_data(data, repo=repo, raw_ref=str(path))

    def parse_data(
        self,
        data: Union[Dict[str, Any], List[Any]],
        repo: str = "workspace",
        raw_ref: str = "trivy.json",
    ) -> List[Finding]:
        """Parse in-memory Trivy JSON data structure into normalized Finding models."""
        findings: List[Finding] = []

        # Case A: Top-level standard Trivy structure with "Results"
        if isinstance(data, dict) and "Results" in data:
            results = data.get("Results", [])
            for target_idx, target_obj in enumerate(results):
                target_file = target_obj.get("Target", "package.json")
                target_type = target_obj.get("Type", self.default_ecosystem).lower()

                # 1. Parse package vulnerabilities
                for vuln_idx, vuln in enumerate(target_obj.get("Vulnerabilities", [])):
                    finding = self._parse_vuln(vuln, target_file, target_type, repo, f"{raw_ref}#{target_idx}/v/{vuln_idx}")
                    if finding:
                        findings.append(finding)

                # 2. Parse secrets
                for sec_idx, sec in enumerate(target_obj.get("Secrets", [])):
                    finding = self._parse_secret(sec, target_file, repo, f"{raw_ref}#{target_idx}/s/{sec_idx}")
                    if finding:
                        findings.append(finding)

        # Case B: Flat list of findings
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, dict):
                    # Check if item has Vulnerabilities inside
                    if "Vulnerabilities" in item:
                        target_file = item.get("Target", item.get("file_path", "package.json"))
                        for v_idx, vuln in enumerate(item.get("Vulnerabilities", [])):
                            finding = self._parse_vuln(vuln, target_file, self.default_ecosystem, repo, f"{raw_ref}#{idx}/v/{v_idx}")
                            if finding:
                                findings.append(finding)
                    else:
                        finding = self._parse_vuln(item, item.get("file_path", "package.json"), self.default_ecosystem, repo, f"{raw_ref}#{idx}")
                        if finding:
                            findings.append(finding)
        elif isinstance(data, dict):
            # Single finding object
            finding = self._parse_vuln(data, data.get("file_path", "package.json"), self.default_ecosystem, repo, raw_ref)
            if finding:
                findings.append(finding)
        else:
            raise ScannerParseError(f"Unsupported Trivy payload type: {type(data)}")

        logger.info("Parsed %d finding(s) from Trivy report %s", len(findings), raw_ref)
        return findings

    def _parse_vuln(
        self,
        item: Dict[str, Any],
        target_file: str,
        ecosystem: str,
        repo: str,
        raw_ref: str,
    ) -> Optional[Finding]:
        pkg_raw = item.get("PkgName") or item.get("package")
        if not pkg_raw:
            return None

        # Normalize package to "ecosystem:name"
        if ":" not in pkg_raw:
            package = f"{ecosystem}:{pkg_raw}"
        else:
            package = pkg_raw

        cve_raw = item.get("VulnerabilityID") or item.get("cve") or []
        cve_list = [cve_raw] if isinstance(cve_raw, str) else list(cve_raw)

        version = str(item.get("InstalledVersion") or item.get("version") or "0.0.0")
        fix_v = item.get("FixedVersion") or item.get("fix_versions") or []
        fix_list = [fix_v] if isinstance(fix_v, str) else list(fix_v)

        sev_str = str(item.get("Severity") or item.get("severity") or "MEDIUM").lower()
        try:
            severity = SeverityLevel(sev_str)
        except ValueError:
            severity = SeverityLevel.MEDIUM

        location = LocationInfo(
            file_path=target_file,
            line=item.get("line"),
            dependency_path=[pkg_raw],
        )

        fnd_id = compute_finding_id(
            scanner="trivy",
            repo=repo,
            package=package,
            version=version,
            cve=cve_list,
            file_path=target_file,
        )

        return Finding(
            id=fnd_id,
            type=FindingType.VULN,
            scanner="trivy",
            repo=repo,
            package=package,
            version=version,
            cve=cve_list,
            severity=severity,
            location=location,
            fix_versions=fix_list,
            raw_ref=raw_ref,
            redacted=False,
            metadata={
                "title": item.get("Title", ""),
                "description": item.get("Description", ""),
                "primary_url": item.get("PrimaryURL", ""),
            },
        )

    def _parse_secret(
        self,
        item: Dict[str, Any],
        target_file: str,
        repo: str,
        raw_ref: str,
    ) -> Finding:
        rule_id = item.get("RuleID", "secret")
        category = item.get("Category", "SECRET")
        title = item.get("Title", "Detected credential in source")
        start_line = item.get("StartLine", 1)

        # Redact any sensitive secret content before persisting into Finding contract
        match_val = item.get("Match", "")
        safe_match = redact_secrets(match_val) if match_val else ""

        fnd_id = compute_finding_id(
            scanner="trivy",
            repo=repo,
            package=f"secret:{category.lower()}",
            version=rule_id,
            cve=[rule_id],
            file_path=target_file,
        )

        return Finding(
            id=fnd_id,
            type=FindingType.SECRET,
            scanner="trivy",
            repo=repo,
            package=f"secret:{category.lower()}",
            version=rule_id,
            cve=[rule_id],
            severity=SeverityLevel.CRITICAL,
            location=LocationInfo(file_path=target_file, line=start_line),
            fix_versions=[],
            raw_ref=raw_ref,
            redacted=True,
            metadata={
                "rule_id": rule_id,
                "category": category,
                "title": title,
                "match_redacted": safe_match,
            },
        )
