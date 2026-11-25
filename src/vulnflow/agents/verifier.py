"""
src/vulnflow/agents/verifier.py
Agent that validates patches by triggering test runs, rescan diffs, and policy compliance rechecks.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.contracts.finding import Finding
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import RemediationPlan, VerificationResult
from vulnflow.mcp_servers.policy_server import policy_check
from vulnflow.mcp_servers.scan_server import scan_server

logger = logging.getLogger("vulnflow.agents.verifier")


class VerifierAgent:
    """
    Reasoning and verification agent ensuring that patches cleanly resolve targeted CVEs,
    introduce no new vulnerabilities, pass full tree policy rechecks, and pass all tests.
    Strict invariant: A failed verification is never reported as success.
    """

    def __init__(self) -> None:
        pass

    def verify_remediation(
        self,
        repo_path: str,
        plans: List[RemediationPlan],
        before_findings: List[Finding],
        test_results: Optional[List[Dict[str, Any]]] = None,
        after_finding_ids: Optional[List[str]] = None,
        ecosystem: str = "npm",
        scanner: str = "trivy",
        branch: str | None = None,
    ) -> VerificationResult:
        """
        Verify that remediation resolved findings using scan_diff and manifest policy recheck.
        Strict invariant: A failed verify is never reported as success.
        """
        before_ids = [f.id for f in before_findings]

        # 1. Execute a real, branch-specific rescan unless the caller supplied
        # explicit recorded scan evidence (used by deterministic contract tests).
        scan_complete = after_finding_ids is not None
        scan_error: str | None = None
        scan_revision: str | None = None
        scanned_dependencies: list[dict[str, str]] = []
        if after_finding_ids is None:
            finding_types = [
                finding.type.value
                if hasattr(finding.type, "value")
                else str(finding.type)
                for finding in before_findings
            ]
            scan_result = scan_server.scan_verify(
                repo=repo_path,
                scanner=scanner,
                branch=branch,
                finding_types=finding_types,
            )
            scan_complete = bool(scan_result.get("executed") and scan_result.get("complete"))
            scan_error = scan_result.get("error")
            scan_revision = scan_result.get("revision")
            after_ids = [
                str(item.get("id"))
                for item in scan_result.get("findings", [])
                if isinstance(item, dict) and item.get("id")
            ]
            scanned_dependencies = [
                item
                for item in scan_result.get("dependencies", [])
                if isinstance(item, dict)
            ]
        else:
            after_ids = after_finding_ids
        diff = scan_server.scan_diff(before=before_ids, after=after_ids)
        rescan_clean = scan_complete and diff.get("clean", False)
        resolved_ids = diff.get("resolved", []) if scan_complete else []
        new_ids = diff.get("new", [fid for fid in after_ids if fid not in before_ids])

        # 2. Check sandboxed test and build outcomes
        test_results = test_results or []
        build_success = bool(test_results)
        tests_passed = bool(test_results)
        for t in test_results:
            if not t.get("build_clean", False):
                build_success = False
            if not t.get("passed", False) or t.get("verification_available") is False:
                tests_passed = False
        revisions_match = after_finding_ids is not None or (
            bool(scan_revision)
            and all(result.get("revision") == scan_revision for result in test_results)
        )

        # 3. Policy recheck on the modified manifest dependencies
        policy_recheck_passed = True
        if scanned_dependencies:
            for dependency in scanned_dependencies:
                pol = policy_check(
                    dependency.get("package", ""),
                    dependency.get("version", "latest"),
                    dependency.get("ecosystem", ecosystem),
                )
                if pol.get("status") in (
                    PolicyStatus.BANNED.value,
                    PolicyStatus.LICENSE_DENIED.value,
                ):
                    logger.warning(
                        "Policy recheck failed: package %s is %s",
                        dependency.get("package"),
                        pol.get("status"),
                    )
                    policy_recheck_passed = False
                    break
        elif after_finding_ids is not None:
            # Explicit scan evidence is primarily a test/replay facility. Preserve
            # the existing full-tree npm recheck for those callers.
            repo_p = Path(repo_path)
            pkg_json = repo_p / "package.json"
            try:
                if pkg_json.exists():
                    manifest_data = json.loads(pkg_json.read_text(encoding="utf-8"))
                    all_deps: dict[str, Any] = {}
                    for sec in ("dependencies", "devDependencies"):
                        if isinstance(manifest_data.get(sec), dict):
                            all_deps.update(manifest_data[sec])
                    for pkg_name, ver_spec in all_deps.items():
                        pol = policy_check(
                            f"npm:{pkg_name}",
                            str(ver_spec).lstrip("^~><="),
                            "npm",
                        )
                        if pol.get("status") in (
                            PolicyStatus.BANNED.value,
                            PolicyStatus.LICENSE_DENIED.value,
                        ):
                            policy_recheck_passed = False
                            break
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Could not read package.json for policy recheck: %s", exc)
                policy_recheck_passed = False

        # 4. Strict verification invariant:
        # Must have resolved target findings, introduced no new findings, rescan must be clean,
        # policy recheck must pass, and sandbox tests/build must pass.
        verified = (
            bool(before_ids)
            and scan_complete
            and rescan_clean
            and policy_recheck_passed
            and tests_passed
            and build_success
            and revisions_match
            and len(new_ids) == 0
        )

        details_parts = []
        if not scan_complete:
            details_parts.append(
                f"Post-fix scan did not complete: {scan_error or 'no scanner evidence'}"
            )
        if not before_ids:
            details_parts.append("No pre-remediation finding baseline was available")
        if not rescan_clean:
            details_parts.append(f"Rescan not clean: {len(after_ids)} residual finding(s)")
        if not policy_recheck_passed:
            details_parts.append("Policy recheck failed on manifest")
        if not tests_passed or not build_success:
            details_parts.append("Sandbox build/test suite failed")
        if scan_complete and not revisions_match:
            details_parts.append("Build and scan evidence did not identify the same Git commit")
        if verified:
            details_parts.append(f"Cleanly resolved {len(resolved_ids)} vulnerability(ies)")

        return VerificationResult(
            verified=verified,
            rescan_clean=rescan_clean,
            resolved_finding_ids=resolved_ids,
            new_finding_ids=new_ids,
            policy_recheck_passed=policy_recheck_passed,
            build_success=build_success,
            tests_passed=tests_passed,
            revision=scan_revision,
            scan_complete=scan_complete,
            details="; ".join(details_parts),
        )


# Global default instance
default_verifier_agent = VerifierAgent()
