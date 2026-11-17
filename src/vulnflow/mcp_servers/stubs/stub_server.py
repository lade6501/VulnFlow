"""
src/vulnflow/mcp_servers/stubs/stub_server.py
Canned responses for MCP tool catalog during Phase 0 prototyping.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vulnflow.contracts.finding import Finding, FindingType, LocationInfo, SeverityLevel
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import PolicyResult

logger = logging.getLogger("vulnflow.mcp_servers.stubs")


class StubMCPServer:
    """
    Unified stub implementation of the VulnFlow MCP Tool Catalog (Section 8.1).
    Returns deterministic, contract-conforming data to allow end-to-end pipeline execution in Phase 0.
    """

    def __init__(self) -> None:
        self.call_history: List[Dict[str, Any]] = []

    def _log_call(self, tool_name: str, **kwargs: Any) -> None:
        self.call_history.append({"tool": tool_name, "args": kwargs})
        logger.debug("Stub MCP called '%s' with %s", tool_name, kwargs)

    # 1. Policy tools
    def policy_check(
        self,
        package: str,
        version: str,
        ecosystem: str = "npm",
    ) -> Dict[str, Any]:
        """Check if a package and version are approved by organizational policy."""
        self._log_call("policy_check", package=package, version=version, ecosystem=ecosystem)
        clean_pkg = package.lower().replace(f"{ecosystem}:", "")

        if clean_pkg == "left-pad":
            return {
                "status": PolicyStatus.BANNED.value,
                "rule_matched": "banned_package",
                "replacement": None,
                "reason": "Unmaintained and obsolete utility package",
            }
        elif clean_pkg == "moment":
            return {
                "status": PolicyStatus.DEPRECATED.value,
                "rule_matched": "deprecated_package",
                "replacement": "date-fns",
                "reason": "Deprecated upstream in favor of date-fns",
            }
        elif clean_pkg == "lodash":
            # versions >= 4.17.21 are approved
            parts = version.split(".")
            try:
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2].split("-")[0])
                if (major, minor, patch) >= (4, 17, 21):
                    return {
                        "status": PolicyStatus.APPROVED.value,
                        "rule_matched": "approved_versions:>=4.17.21",
                        "replacement": None,
                        "reason": "Meets minimum patched version",
                    }
            except Exception:
                pass
            return {
                "status": PolicyStatus.UNKNOWN.value,
                "rule_matched": "below_approved_threshold",
                "replacement": None,
                "reason": "Version below approved baseline 4.17.21",
            }

        return {
            "status": PolicyStatus.APPROVED.value,
            "rule_matched": "default_allowed",
            "replacement": None,
            "reason": "No policy restrictions",
        }

    def policy_candidates(
        self,
        package: str,
        versions: List[str],
        ecosystem: str = "npm",
    ) -> List[str]:
        """Filter a list of suggested fix versions to the policy-approved set."""
        self._log_call("policy_candidates", package=package, versions=versions, ecosystem=ecosystem)
        approved = []
        for v in versions:
            res = self.policy_check(package, v, ecosystem)
            if res["status"] == PolicyStatus.APPROVED.value:
                approved.append(v)
        return approved or (["4.17.21"] if "lodash" in package else versions[:1])

    # 2. Knowledge tools
    def advisory_search(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve security advisories, release notes, and changelogs."""
        self._log_call("advisory_search", query=query, filters=filters)
        return [
            {
                "id": "ADV-GHSA-p6mc-m468-83gw",
                "source": "GHSA",
                "package": "lodash",
                "cve": "CVE-2020-8203",
                "title": "Prototype Pollution in lodash",
                "description": "Prototype pollution vulnerability in lodash before 4.17.21 allows attackers to cause a denial of service or code execution.",
                "affected_range": "<4.17.21",
                "fixed_versions": ["4.17.21"],
                "cvss_score": 7.4,
            }
        ]

    def graph_query(
        self,
        name: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute pre-defined Neo4j graph query patterns."""
        self._log_call("graph_query", name=name, params=params)
        if name == "root_cause":
            pkg = (params or {}).get("package", "npm:lodash")
            return {
                "root_cause_id": f"PKG-{pkg}",
                "root_cause_package": pkg,
                "is_direct": True,
                "affected_chain": [f"{pkg}@latest"],
                "affected_services": ["api-service"],
            }
        elif name == "blast_radius":
            return {
                "services": ["api-service", "reporting-worker"],
                "repos": ["vulnflow-sample"],
                "direct_dependents": 1,
                "transitive_dependents": 0,
            }
        return {"result": "success", "nodes": 1, "edges": 1}

    # 3. Scanner tools
    def scan_run(
        self,
        repo: str,
        scanner: str = "trivy",
    ) -> List[Dict[str, Any]]:
        """Run vulnerability scanner against repo path or branch."""
        self._log_call("scan_run", repo=repo, scanner=scanner)
        finding = Finding(
            id="FND-sample-lodash-41715",
            type=FindingType.VULN,
            scanner=scanner,
            repo=repo,
            package="npm:lodash",
            version="4.17.15",
            cve=["CVE-2020-8203"],
            severity=SeverityLevel.HIGH,
            location=LocationInfo(file_path="package.json", line=12, dependency_path=["lodash"]),
            fix_versions=["4.17.21"],
            raw_ref="trivy-out-sample.json#0",
        )
        return [finding.to_dict()]

    def scan_diff(
        self,
        before: List[str],
        after: List[str],
    ) -> Dict[str, Any]:
        """Compare finding IDs before and after remediation."""
        self._log_call("scan_diff", before=before, after=after)
        resolved = [fid for fid in before if fid not in after]
        new_findings = [fid for fid in after if fid not in before]
        return {
            "resolved": resolved,
            "new": new_findings,
            "clean": len(after) == 0,
            "resolution_ratio": 1.0 if not after else 0.0,
        }

    # 4. Git tools
    def git_clone(self, repo_url: str, target_dir: str) -> Dict[str, Any]:
        self._log_call("git_clone", repo_url=repo_url, target_dir=target_dir)
        return {"status": "cloned", "path": target_dir, "ref": "main"}

    def git_branch(self, branch_name: str, repo_dir: str) -> Dict[str, Any]:
        self._log_call("git_branch", branch_name=branch_name, repo_dir=repo_dir)
        return {"status": "created", "branch": branch_name}

    def git_patch(self, file_path: str, diff: str, repo_dir: str) -> Dict[str, Any]:
        self._log_call("git_patch", file_path=file_path, diff=diff, repo_dir=repo_dir)
        return {"status": "applied", "file": file_path, "hunks": 1}

    def git_commit(self, message: str, repo_dir: str) -> Dict[str, Any]:
        self._log_call("git_commit", message=message, repo_dir=repo_dir)
        return {"status": "committed", "commit_sha": "a1b2c3d4e5f67890"}

    def pr_create(
        self,
        branch: str,
        body: str,
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create pull request on the repository hosting platform."""
        self._log_call("pr_create", branch=branch, body=body, title=title)
        return {
            "status": "opened",
            "pr_url": "https://github.com/vulnflow/sample-repo/pull/1",
            "pr_number": 1,
            "branch": branch,
            "title": title or "fix(deps): bump lodash from 4.17.15 to 4.17.21",
        }

    # 5. Build and test tools
    def build_test(self, repo: str, branch: str) -> Dict[str, Any]:
        """Execute clean build and test verification in sandboxed container."""
        self._log_call("build_test", repo=repo, branch=branch)
        return {
            "status": "success",
            "build_clean": True,
            "tests_total": 42,
            "tests_passed": 42,
            "tests_failed": 0,
            "duration_seconds": 3.4,
        }

    # 6. Registry tools
    def registry_check(self, package: str, version: str) -> Dict[str, Any]:
        """Check internal package registry availability and integrity."""
        self._log_call("registry_check", package=package, version=version)
        return {
            "available": True,
            "tarball": f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz",
            "integrity": "sha512-test-stub-checksum",
        }

    # 7. Ticketing tools
    def ticket_create(
        self,
        ticket_type: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create Jira issue or GitHub Issue for policy exceptions or blocked items."""
        self._log_call("ticket_create", ticket_type=ticket_type, context=context)
        return {
            "status": "created",
            "ticket_id": "SEC-1042",
            "ticket_url": "https://jira.corp.internal/browse/SEC-1042",
            "ticket_type": ticket_type,
        }

    # 8. Notification & approval tools
    def approval_request(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch notification asking human security reviewer for plan approval."""
        self._log_call("approval_request", plan=plan)
        return {
            "status": "dispatched",
            "channel": "slack",
            "message_id": "slack-msg-789456",
            "approval_url": "https://vulnflow.internal/approvals/PLAN-1234",
        }


# Global singleton stub server instance
stub_mcp = StubMCPServer()
