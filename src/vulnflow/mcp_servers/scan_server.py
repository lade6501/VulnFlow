"""
src/vulnflow/mcp_servers/scan_server.py
MCP tool server invoking Trivy, Grype, and Gitleaks security scanners and computing diffs.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.adapters.input.trivy import TrivyAdapter
from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)
from vulnflow.core.redaction import redact_secrets
from vulnflow.mcp_servers.fastmcp import FastMCP

logger = logging.getLogger("vulnflow.mcp_servers.scan")

mcp = FastMCP(
    name="vulnflow-scan",
    description="MCP server executing security scanners and verifying post-fix finding resolution.",
)


class ScanServer:
    """Tool server executing vulnerability scans and comparing diffs over MCP."""

    def __init__(self) -> None:
        self.mcp = mcp

    def scan_source_secrets(self, repo_path: Path, repo: str = "workspace") -> List[Finding]:
        """
        Deep source-code scanner for hardcoded credentials, database passwords, API keys, and PII.
        Complements container/package scanners to ensure all repository credentials generate actionable remediation plans.
        """
        findings: List[Finding] = []
        patterns = [
            ("slack", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
            ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
            ("pii-ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
            ("database-password", re.compile(r"(?i)(?:database_password|db_password|db_pass|database_pass)\s*[:=]\s*[\x27\x22]([^\x27\x22]+)[\x27\x22]")),
            ("api-key", re.compile(r"(?i)(?:api_key|api_secret|secret_token|access_token|auth_token)\s*[:=]\s*[\x27\x22]([^\x27\x22]+)[\x27\x22]")),
        ]
        exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php", ".cs", ".yaml", ".yml", ".env"}
        skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".vulnflow", "dist", "build"}

        for p in repo_path.rglob("*"):
            if not p.is_file() or p.suffix not in exts:
                continue
            if any(part in skip_dirs for part in p.parts):
                continue
            try:
                rel = str(p.relative_to(repo_path))
                content = p.read_text(encoding="utf-8", errors="ignore")
                for line_no, line in enumerate(content.splitlines(), start=1):
                    # Skip lines already using environment variables or redaction
                    if "os.getenv" in line or "process.env" in line or "System.getenv" in line or "ENV[" in line:
                        continue
                    for rule_id, pat in patterns:
                        m = pat.search(line)
                        if m:
                            match_val = m.group(0)
                            safe_match = redact_secrets(match_val)
                            fnd_id = compute_finding_id(
                                scanner="vulnflow-secret",
                                repo=repo,
                                package=f"secret:{rule_id}",
                                version=rule_id,
                                cve=[rule_id],
                                file_path=rel,
                            )
                            findings.append(Finding(
                                id=fnd_id,
                                type=FindingType.SECRET,
                                scanner="vulnflow-secret",
                                repo=repo,
                                package=f"secret:{rule_id}",
                                version=rule_id,
                                cve=[rule_id],
                                severity=SeverityLevel.CRITICAL,
                                location=LocationInfo(file_path=rel, line=line_no),
                                fix_versions=[],
                                raw_ref=f"{rel}:{line_no}",
                                redacted=True,
                                metadata={
                                    "rule_id": rule_id,
                                    "category": "SECRET",
                                    "title": f"Hardcoded {rule_id.replace('-', ' ').title()}",
                                    "match_redacted": safe_match,
                                },
                            ))
                            break
            except Exception as exc:
                logger.debug("Could not scan file %s for secrets: %s", p, exc)

        return findings

    def scan_run(self, repo: str, scanner: str = "trivy") -> List[Dict[str, Any]]:
        """MCP tool: scan_run - Runs vulnerability scan on target repo."""
        logger.info("Executing scan_run with %s on %s", scanner, repo)
        repo_path = Path(repo)
        findings: List[Finding] = []

        # 1. Run live external scanner (Trivy) for dependency CVEs and vendor tokens
        bin_path = shutil.which(scanner)
        if bin_path and repo_path.exists():
            try:
                cmd = [bin_path, "fs", "--format", "json", str(repo_path)]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
                if res.returncode == 0 and res.stdout.strip():
                    adapter = TrivyAdapter()
                    try:
                        data = json.loads(res.stdout)
                        findings.extend(adapter.parse_data(data, repo=repo))
                    except Exception as parse_exc:
                        logger.warning("Failed to parse live %s JSON output: %s", scanner, parse_exc)
            except Exception as exc:
                logger.warning("Live scan_run failed: %s; returning empty baseline", exc)

        # 2. Augment with source-level secret, database password, API key, and PII detection
        if repo_path.exists():
            try:
                sec_findings = self.scan_source_secrets(repo_path, repo=repo)
                existing_locs = {(f.location.file_path, f.location.line) for f in findings if f.location}
                for sf in sec_findings:
                    if sf.location and (sf.location.file_path, sf.location.line) not in existing_locs:
                        findings.append(sf)
                        existing_locs.add((sf.location.file_path, sf.location.line))
            except Exception as sec_exc:
                logger.warning("Source secret scanning error: %s", sec_exc)

        return [f.to_dict() for f in findings]

    def scan_diff(self, before: List[str], after: List[str]) -> Dict[str, Any]:
        """MCP tool: scan_diff - Compares findings before and after fix."""
        logger.info("Executing scan_diff (%d before, %d after)", len(before), len(after))
        resolved = [fid for fid in before if fid not in after]
        new_findings = [fid for fid in after if fid not in before]
        return {
            "resolved": resolved,
            "new": new_findings,
            "clean": len(after) == 0,
            "resolution_ratio": 1.0 if not after else round(len(resolved) / max(len(before), 1), 2),
        }


scan_server = ScanServer()


@mcp.tool(
    name="scan_run",
    description="Executes a security scanner (Trivy, Grype) against a target directory or branch.",
)
def scan_run(repo: str, scanner: str = "trivy") -> List[Dict[str, Any]]:
    return scan_server.scan_run(repo, scanner)


@mcp.tool(
    name="scan_diff",
    description="Compares finding IDs before and after remediation to compute resolved and new findings.",
)
def scan_diff(before: List[str], after: List[str]) -> Dict[str, Any]:
    return scan_server.scan_diff(before, after)


if __name__ == "__main__":
    mcp.run()
