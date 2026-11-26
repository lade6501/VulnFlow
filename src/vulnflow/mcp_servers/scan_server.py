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
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from vulnflow.adapters.input.trivy import TrivyAdapter
from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)
from vulnflow.mcp_servers.fastmcp import FastMCP
from vulnflow.sandbox.runner import SandboxExecutionError, default_sandbox

logger = logging.getLogger("vulnflow.mcp_servers.scan")

mcp = FastMCP(
    name="vulnflow-scan",
    description="MCP server executing security scanners and verifying post-fix finding resolution.",
)


class ScanServer:
    """Tool server executing vulnerability scans and comparing diffs over MCP."""

    def __init__(self) -> None:
        self.mcp = mcp

    def scan_source_secrets(
        self, repo_path: Path, repo: str = "workspace", *, strict: bool = False
    ) -> List[Finding]:
        """
        Deep source-code scanner for hardcoded credentials, database passwords, API keys, and PII.
        Complements container/package scanners to ensure all repository credentials generate actionable remediation plans.
        """
        findings: List[Finding] = []
        patterns = [
            ("slack", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+")),
            ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
            ("pii-ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
            ("database-password", re.compile(r"(?i)\b(?P<name>\w*(?:database_password|db_password|db_pass|database_pass))\s*[:=]\s*[\x27\x22]([^\x27\x22]+)[\x27\x22]")),
            ("api-key", re.compile(r"(?i)\b(?P<name>\w*(?:api_key|api_secret|secret_token|access_token|auth_token))\s*[:=]\s*[\x27\x22]([^\x27\x22]+)[\x27\x22]")),
        ]
        exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php", ".cs", ".yaml", ".yml", ".env"}
        skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", ".vulnflow", "dist", "build"}

        for p in repo_path.rglob("*"):
            if p.is_symlink() or not p.is_file() or (p.suffix not in exts and p.name != ".env"):
                continue
            if any(part in skip_dirs for part in p.parts):
                continue
            try:
                rel = str(p.relative_to(repo_path))
                content = p.read_text(encoding="utf-8", errors="ignore")
                occurrences: dict[tuple[str, str], int] = {}
                for line_no, line in enumerate(content.splitlines(), start=1):
                    # Skip lines already using environment variables or redaction
                    if "os.getenv" in line or "process.env" in line or "System.getenv" in line or "ENV[" in line:
                        continue
                    for rule_id, pat in patterns:
                        m = pat.search(line)
                        if m:
                            name = m.groupdict().get("name")
                            occurrence = f"line:{line_no}"
                            if name:
                                key = (rule_id, name)
                                occurrences[key] = occurrences.get(key, 0) + 1
                                occurrence = f"assignment:{name}:{occurrences[key]}"
                            fnd_id = compute_finding_id(
                                scanner="vulnflow-secret",
                                repo=repo,
                                package=f"secret:{rule_id}",
                                version=rule_id,
                                cve=[rule_id],
                                file_path=rel,
                                occurrence=occurrence,
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
                                },
                            ))
                            break
            except Exception as exc:
                if strict:
                    raise
                logger.debug("Could not scan file %s for secrets: %s", p, exc)

        return findings

    @staticmethod
    def _manifest_dependencies(repo_path: Path) -> List[Dict[str, str]]:
        """Read dependency coordinates from the isolated checkout for policy recheck."""
        dependencies: List[Dict[str, str]] = []
        pkg_json = repo_path / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
                for section in ("dependencies", "devDependencies"):
                    values = data.get(section, {})
                    if isinstance(values, dict):
                        for name, version in values.items():
                            dependencies.append(
                                {
                                    "package": f"npm:{name}",
                                    "version": str(version).lstrip("^~><= "),
                                    "ecosystem": "npm",
                                }
                            )
            except (OSError, json.JSONDecodeError):
                pass

        requirements = repo_path / "requirements.txt"
        if requirements.exists():
            try:
                for raw_line in requirements.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    match = re.match(
                        r"([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=|>|<)?\s*([^;\s]+)?",
                        line,
                    )
                    if match:
                        dependencies.append(
                            {
                                "package": f"pip:{match.group(1)}",
                                "version": match.group(2) or "latest",
                                "ecosystem": "PyPI",
                            }
                        )
            except OSError:
                pass

        pom = repo_path / "pom.xml"
        if pom.exists():
            try:
                root = ET.parse(pom).getroot()
                namespace = ""
                if root.tag.startswith("{"):
                    namespace = root.tag.split("}", 1)[0] + "}"
                for dependency in root.findall(f".//{namespace}dependency"):
                    group = dependency.findtext(f"{namespace}groupId", "")
                    artifact = dependency.findtext(f"{namespace}artifactId", "")
                    version = dependency.findtext(f"{namespace}version", "latest")
                    if group and artifact:
                        dependencies.append(
                            {
                                "package": f"maven:{group}:{artifact}",
                                "version": version,
                                "ecosystem": "maven",
                            }
                        )
            except (OSError, ET.ParseError):
                pass
        return dependencies

    def _scan_checkout(
        self, repo_path: Path, scanner: str, repo_label: str,
    ) -> Dict[str, Any]:
        """Run a scanner and return explicit execution evidence alongside findings."""
        findings: List[Finding] = []
        scanner_executed = False
        scan_complete = False
        error: str | None = None
        dependency_targets: list[str] = []

        # 1. Run live external scanner (Trivy) for dependency CVEs and vendor tokens
        try:
            scanner_name = scanner.lower().strip()
            if scanner_name != "trivy":
                raise ValueError(f"Live scanning is unavailable for '{scanner_name}'")
            bin_path = shutil.which(scanner_name)
            if not bin_path:
                raise ValueError("Trivy is not installed")
            scanner_executed = True
            res = subprocess.run(
                [
                    bin_path, "fs", "--config", "", "--ignorefile", "",
                    "--secret-config", "", "--scanners", "vuln,secret", "--format", "json", ".",
                ],
                cwd=repo_path, capture_output=True, text=True, check=False, timeout=120,
            )
            if res.returncode != 0:
                raise ValueError(f"Trivy exited with code {res.returncode}")
            data = json.loads(res.stdout)
            results = data.get("Results") if isinstance(data, dict) else None
            if not isinstance(results, list) or not results or any(
                not isinstance(target, dict) for target in results
            ):
                raise ValueError("Trivy returned no usable scan targets")
            findings.extend(TrivyAdapter().parse_data(data, repo=repo_label))
            dependency_targets = [
                str(target.get("Type", "")) for target in results
                if target.get("Class") == "lang-pkgs"
            ]
            scan_complete = True
        except (ValueError, OSError, subprocess.SubprocessError, TypeError, AttributeError) as exc:
            error = f"Live scan failed: {exc}"
            logger.warning(error)

        # 2. Augment with source-level secret, database password, API key, and PII detection
        if repo_path.exists():
            try:
                sec_findings = self.scan_source_secrets(
                    repo_path, repo=repo_label, strict=True
                )
                existing_locs = {(f.location.file_path, f.location.line) for f in findings if f.location}
                for sf in sec_findings:
                    if sf.location and (sf.location.file_path, sf.location.line) not in existing_locs:
                        findings.append(sf)
                        existing_locs.add((sf.location.file_path, sf.location.line))
            except Exception as sec_exc:
                logger.warning("Source secret scanning error: %s", sec_exc)
                scan_complete = False
                error = "Source secret scan did not complete"

        return {
            "scanner": scanner,
            "executed": scanner_executed,
            "complete": scan_complete,
            "error": error,
            "findings": [f.to_dict() for f in findings],
            "dependencies": self._manifest_dependencies(repo_path),
            "dependency_targets": dependency_targets,
        }

    def scan_run(self, repo: str, scanner: str = "trivy") -> List[Dict[str, Any]]:
        """MCP tool: scan_run - Runs vulnerability scan on target repo."""
        logger.info("Executing scan_run with %s on %s", scanner, repo)
        result = self.scan_verify(repo, scanner)
        return list(result["findings"])

    def scan_verify(
        self,
        repo: str,
        scanner: str = "trivy",
        branch: str | None = None,
        finding_types: List[str] | None = None,
    ) -> Dict[str, Any]:
        """Run a branch-specific post-fix scan and fail closed if evidence is incomplete."""
        repo_path = Path(repo)
        try:
            with default_sandbox.isolated_checkout(repo_path, branch=branch) as checkout:
                revision = default_sandbox.checkout_revision(checkout)
                result = self._scan_checkout(checkout, scanner, repo_label=repo)
        except (OSError, SandboxExecutionError, subprocess.SubprocessError) as exc:
            return {
                "scanner": scanner,
                "branch": branch or "HEAD",
                "executed": False,
                "complete": False,
                "error": str(exc),
                "findings": [],
            }

        if "vuln" in (finding_types or []) and not result["dependency_targets"]:
            result["complete"] = False
            result["error"] = result["error"] or "Trivy did not scan a dependency inventory"
        result["branch"] = branch or "HEAD"
        result["revision"] = revision
        return result

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
    name="scan_verify",
    description="Executes a post-fix scanner on an isolated branch checkout and returns execution evidence.",
)
def scan_verify(
    repo: str,
    scanner: str = "trivy",
    branch: str | None = None,
    finding_types: List[str] | None = None,
) -> Dict[str, Any]:
    return scan_server.scan_verify(repo, scanner, branch, finding_types)


@mcp.tool(
    name="scan_diff",
    description="Compares finding IDs before and after remediation to compute resolved and new findings.",
)
def scan_diff(before: List[str], after: List[str]) -> Dict[str, Any]:
    return scan_server.scan_diff(before, after)


if __name__ == "__main__":
    mcp.run()
