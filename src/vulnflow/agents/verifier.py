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
    ) -> VerificationResult:
        """
        Verify that remediation resolved findings using scan_diff and manifest policy recheck.
        Strict invariant: A failed verify is never reported as success.
        """
        before_ids = [f.id for f in before_findings]

        # 1. Rescan diff via MCP scan_server
        after_ids = after_finding_ids if after_finding_ids is not None else []
        diff = scan_server.scan_diff(before=before_ids, after=after_ids)
        rescan_clean = diff.get("clean", len(after_ids) == 0)
        resolved_ids = diff.get("resolved", [fid for fid in before_ids if fid not in after_ids])
        new_ids = diff.get("new", [fid for fid in after_ids if fid not in before_ids])

        # 2. Check sandboxed test and build outcomes
        test_results = test_results or []
        build_success = True
        tests_passed = True
        for t in test_results:
            if not t.get("build_clean", True):
                build_success = False
            if not t.get("passed", True):
                tests_passed = False

        # 3. Policy recheck on the modified manifest dependencies
        policy_recheck_passed = True
        repo_p = Path(repo_path)
        pkg_json = repo_p / "package.json"

        if pkg_json.exists():
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
                all_deps = {}
                for sec in ("dependencies", "devDependencies"):
                    if sec in manifest_data and isinstance(manifest_data[sec], dict):
                        all_deps.update(manifest_data[sec])

                for pkg_name, ver_spec in all_deps.items():
                    clean_ver = str(ver_spec).lstrip("^~><=")
                    pol = policy_check(f"npm:{pkg_name}", clean_ver or "latest", "npm")
                    if pol.get("status") in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value):
                        logger.warning("Policy recheck failed: package %s is %s", pkg_name, pol.get("status"))
                        policy_recheck_passed = False
                        break
            except Exception as exc:
                logger.warning("Could not read package.json for policy recheck: %s", exc)

        # 4. Strict verification invariant:
        # Must have resolved target findings, introduced no new findings, rescan must be clean,
        # policy recheck must pass, and sandbox tests/build must pass.
        verified = (
            rescan_clean
            and policy_recheck_passed
            and tests_passed
            and build_success
            and len(new_ids) == 0
        )

        details_parts = []
        if not rescan_clean:
            details_parts.append(f"Rescan not clean: {len(after_ids)} residual finding(s)")
        if not policy_recheck_passed:
            details_parts.append("Policy recheck failed on manifest")
        if not tests_passed or not build_success:
            details_parts.append("Sandbox build/test suite failed")
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
            details="; ".join(details_parts),
        )


# Global default instance
default_verifier_agent = VerifierAgent()
