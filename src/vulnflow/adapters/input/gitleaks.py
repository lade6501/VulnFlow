"""
src/vulnflow/adapters/input/gitleaks.py
Parses Gitleaks secret detection reports into normalized Finding models with strict redaction.
"""

from __future__ import annotations

import hashlib
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
from vulnflow.core.redaction import redact_secrets

logger = logging.getLogger("vulnflow.adapters.input.gitleaks")


class GitleaksAdapter:
    """Parser for Gitleaks secret detection JSON reports."""

    def parse_file(self, report_path: Union[str, Path], repo: str = "workspace") -> List[Finding]:
        """Load and parse a Gitleaks JSON report file from disk."""
        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Gitleaks report not found at {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ScannerParseError(f"Malformed JSON in Gitleaks report: {exc}") from exc

        return self.parse_data(data, repo=repo, raw_ref=str(path))

    def parse_data(
        self,
        data: Union[Dict[str, Any], List[Any]],
        repo: str = "workspace",
        raw_ref: str = "gitleaks.json",
    ) -> List[Finding]:
        """Parse Gitleaks JSON data structure into normalized Finding models."""
        findings: List[Finding] = []

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("leaks", []) or data.get("findings", [])
        else:
            raise ScannerParseError(f"Expected dict or list in Gitleaks report, got {type(data).__name__}")

        for item in items:
            rule_id = item.get("RuleID") or item.get("rule", "generic-secret")
            desc = item.get("Description") or item.get("description", "Exposed Secret or Token")
            file_path = item.get("File") or item.get("file", "unknown")
            start_line = item.get("StartLine") or item.get("line") or 1
            end_line = item.get("EndLine") or start_line
            col = item.get("StartColumn") or 1

            # Strict rule: Secret value NEVER reaches Finding or traces
            raw_secret = item.get("Secret") or item.get("Match") or ""
            fingerprint = item.get("Fingerprint")
            if not fingerprint and raw_secret:
                fingerprint = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

            location = LocationInfo(
                file_path=file_path,
                line=int(start_line),
            )

            finding_id = compute_finding_id(
                "gitleaks", repo, f"secret:{rule_id}", "0.0.0", [rule_id], file_path,
                occurrence=f"line:{start_line}:column:{col}",
            )
            f = Finding(
                id=finding_id,
                type=FindingType.SECRET,
                scanner="gitleaks",
                repo=repo,
                package=f"secret:{rule_id}",
                version="0.0.0",
                cve=[rule_id],
                severity=SeverityLevel.CRITICAL,
                location=location,
                metadata={
                    "rule_id": rule_id,
                    "description": redact_secrets(desc),
                    "fingerprint": fingerprint,
                },
                raw_ref=raw_ref,
            )
            findings.append(f)

        logger.info("Parsed %d secret finding(s) from Gitleaks report %s", len(findings), raw_ref)
        return findings
