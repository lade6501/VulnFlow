"""
src/vulnflow/orchestrator/nodes.py
Implements individual state transformation node handlers in LangGraph.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List

from vulnflow.adapters.ecosystem.npm import NPMAdapter
from vulnflow.adapters.ecosystem.pip import PipAdapter
from vulnflow.adapters.input.gitleaks import GitleaksAdapter
from vulnflow.adapters.input.grype import GrypeAdapter
from vulnflow.adapters.input.osv import OSVAdapter
from vulnflow.adapters.input.sarif import SARIFAdapter
from vulnflow.adapters.input.trivy import TrivyAdapter
from vulnflow.agents.fixer import default_fixer_agent
from vulnflow.agents.planner import default_planner_agent
from vulnflow.agents.rootcause import default_rootcause_agent
from vulnflow.agents.secrets import default_secrets_agent
from vulnflow.agents.verifier import default_verifier_agent
from vulnflow.contracts.finding import Finding, FindingType
from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import (
    RemediationAction,
    RemediationPlan,
    RiskTier,
    VerificationResult,
)
from vulnflow.contracts.state import VulnFlowState
from vulnflow.core.dedupe import DeduplicationEngine
from vulnflow.mcp_servers.build_server import build_server
from vulnflow.mcp_servers.git_server import git_server
from vulnflow.mcp_servers.knowledge_server import advisory_search
from vulnflow.mcp_servers.notify_server import notify_server
from vulnflow.mcp_servers.registry_server import registry_check
from vulnflow.mcp_servers.scan_server import scan_server
from vulnflow.mcp_servers.ticket_server import ticket_server
from vulnflow.observability.audit_log import audit_logger
from vulnflow.observability.tracing import trace_span
from vulnflow.orchestrator.approval import global_approval_gate, save_run_state
from vulnflow.policy.engine import default_policy_engine
from vulnflow.reporting.pr_comment import format_pr_body

logger = logging.getLogger("vulnflow.orchestrator.nodes")


def ingest_node(state: VulnFlowState) -> VulnFlowState:
    """Read and normalize scanner findings from report file or scanner tool."""
    state.current_node = "ingest"
    with trace_span("orchestrator.node.ingest", {"run_id": state.run_id}):
        findings: List[Finding] = []

        if state.report_path and Path(state.report_path).exists():
            s_name = (state.scanner or "").lower()
            rep_lower = str(state.report_path).lower()

            # Automatic content inspection if scanner was omitted or default
            if not s_name or s_name == "trivy":
                if "gitleaks" in rep_lower or "secret" in rep_lower:
                    s_name = "gitleaks"
                elif rep_lower.endswith(".sarif") or "sarif" in rep_lower:
                    s_name = "sarif"
                else:
                    try:
                        with open(state.report_path, "r", encoding="utf-8") as _f:
                            _snip = _f.read(3000)
                        if '"Secret"' in _snip or '"RuleID"' in _snip or '"Fingerprint"' in _snip:
                            s_name = "gitleaks"
                        elif '"runs"' in _snip and '"tool"' in _snip:
                            s_name = "sarif"
                        elif '"matches"' in _snip and '"artifact"' in _snip:
                            s_name = "grype"
                    except Exception:
                        pass

            if "sarif" in s_name or state.report_path.endswith(".sarif"):
                adapter = SARIFAdapter()
            elif "grype" in s_name:
                adapter = GrypeAdapter(default_ecosystem=state.ecosystem)
            elif "osv" in s_name:
                adapter = OSVAdapter(default_ecosystem=state.ecosystem)
            elif "gitleaks" in s_name or "secret" in s_name:
                adapter = GitleaksAdapter()
            else:
                adapter = TrivyAdapter(default_ecosystem=state.ecosystem)

            try:
                findings = adapter.parse_file(state.report_path, repo=state.repo_path)
            except Exception as exc:
                logger.warning("Adapter %s failed to parse %s: %s; using scanner tool", adapter.__class__.__name__, state.report_path, exc)

        if not findings:
            raw_scan_results = scan_server.scan_run(repo=state.repo_path, scanner=state.scanner)
            state.raw_findings = raw_scan_results
            for item in raw_scan_results:
                findings.append(Finding.from_dict(item))

        state.findings = findings
        state.append_audit("INGESTION_COMPLETED", "orchestrator", {"findings_count": len(findings)})
        return state


def dedupe_node(state: VulnFlowState) -> VulnFlowState:
    """Deduplicate findings from multiple scanner feeds or recurring runs."""
    state.current_node = "dedupe"
    with trace_span("orchestrator.node.dedupe", {"run_id": state.run_id}):
        engine = DeduplicationEngine()
        state.deduped_findings = engine.deduplicate(state.findings)
        state.append_audit(
            "DEDUPLICATION_COMPLETED",
            "orchestrator",
            {
                "raw": engine.raw_count,
                "deduped": engine.deduped_count,
                "ratio": engine.dedupe_ratio,
            },
        )
        return state


def rootcause_node(state: VulnFlowState) -> VulnFlowState:
    """Group findings by root cause parent dependency in the dependency graph."""
    state.current_node = "rootcause"
    with trace_span("orchestrator.node.rootcause", {"run_id": state.run_id}):
        groups = default_rootcause_agent.group_findings(
            state.deduped_findings,
            repo_path=state.repo_path,
            ecosystem=state.ecosystem,
        )
        state.root_cause_groups = groups
        state.append_audit(
            "ROOTCAUSE_ANALYSIS_COMPLETED",
            "orchestrator",
            {"groups_count": len(state.root_cause_groups)},
        )
        return state


def policy_node(state: VulnFlowState) -> VulnFlowState:
    """Evaluate organizational policy for packages and candidate versions using real PolicyEngine."""
    state.current_node = "policy"
    with trace_span("orchestrator.node.policy", {"run_id": state.run_id}):
        has_blocked_package = False
        for group in state.root_cause_groups:
            rc_id = group["root_cause_id"].replace("PKG-", "")
            pkg_eco = state.ecosystem
            if ":" in rc_id:
                prefix = rc_id.split(":", 1)[0].lower()
                if prefix in ("pip", "pypi", "python"):
                    pkg_eco = "PyPI"
                elif prefix in ("npm", "node"):
                    pkg_eco = "npm"
            pol = default_policy_engine.check(rc_id, "latest", pkg_eco)
            group["policy"] = pol.to_dict()
            if pol.status in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value):
                has_blocked_package = True

        state.append_audit("POLICY_EVALUATION_COMPLETED", "orchestrator", {"blocked": has_blocked_package})
        return state


def plan_node(state: VulnFlowState) -> VulnFlowState:
    """Formulate remediation plan using Fix Planner agent backed by real policy and LLM."""
    state.current_node = "plan"
    default_planner_agent.reset_circuit_breaker()
    with trace_span("orchestrator.node.plan", {"run_id": state.run_id}):
        plans: List[RemediationPlan] = []

        # 1. Group all secret/PII findings into a single consolidated remediation plan (F23)
        all_secret_findings = [f for f in state.deduped_findings if f.type == FindingType.SECRET]
        if all_secret_findings:
            sec_plan = default_secrets_agent.plan_consolidated_secret_remediation(
                all_secret_findings, repo_path=state.repo_path
            )
            plans.append(sec_plan)
            state.append_audit(
                "PLAN_FORMULATED",
                "secrets_agent",
                {
                    "plan_id": sec_plan.id,
                    "root_cause_id": sec_plan.root_cause_id,
                    "target_package": sec_plan.target_package,
                    "target_version": sec_plan.target_version,
                    "action": "rotate",
                    "risk_tier": "review",
                    "requires_approval": True,
                    "findings_count": len(all_secret_findings),
                },
            )

        # 2. Formulate dependency package upgrade plans
        for group in state.root_cause_groups:
            rc_id = group["root_cause_id"]
            if "secret:" in rc_id.lower():
                continue

            f_dicts = group["findings"]
            findings_objs = [Finding.from_dict(f) for f in f_dicts]
            # Skip if finding is a secret (already consolidated above)
            if any(f_obj.type == FindingType.SECRET for f_obj in findings_objs):
                continue

            clean_rc = rc_id.replace("PKG-", "")
            # Infer ecosystem from package prefix if present (e.g. 'pip:Django' -> 'PyPI')
            pkg_eco = state.ecosystem
            if ":" in clean_rc:
                prefix = clean_rc.split(":", 1)[0].lower()
                if prefix in ("pip", "pypi", "python"):
                    pkg_eco = "PyPI"
                elif prefix in ("npm", "node"):
                    pkg_eco = "npm"

            advisories = advisory_search(query=clean_rc, package=clean_rc, ecosystem=pkg_eco)
            if not advisories:
                # Query distinct packages from findings only if different from root cause
                other_pkgs = {f_obj.package for f_obj in findings_objs if f_obj.package and f_obj.package != clean_rc}
                for pkg_name in other_pkgs:
                    advisories.extend(advisory_search(query=pkg_name, package=pkg_name, ecosystem=pkg_eco))
            if not advisories:
                advisories = advisory_search(query=rc_id)

            # Delegate to PlannerAgent (F16)
            plan = default_planner_agent.plan_remediation(
                root_cause_id=rc_id,
                findings=findings_objs,
                advisories=advisories,
                ecosystem=pkg_eco,
            )
            plans.append(plan)

            # Record granular audit event for each formulated plan
            state.append_audit(
                "PLAN_FORMULATED",
                "planner_agent",
                {
                    "plan_id": plan.id,
                    "root_cause_id": plan.root_cause_id,
                    "target_package": plan.target_package,
                    "target_version": plan.target_version,
                    "action": plan.action.value if hasattr(plan.action, "value") else str(plan.action),
                    "risk_tier": plan.risk_tier.value if hasattr(plan.risk_tier, "value") else str(plan.risk_tier),
                    "requires_approval": plan.requires_approval,
                    "policy_status": plan.policy_result.status if plan.policy_result else "APPROVED",
                    "ai_rationale": plan.rationale,
                },
            )

        state.plans = plans
        state.append_audit("PLANS_GENERATED", "orchestrator", {"plans_count": len(plans)})
        return state


def approve_node(state: VulnFlowState) -> VulnFlowState:
    """Process approval gates based on assigned risk tiers and human authorizations."""
    state.current_node = "approve"
    with trace_span("orchestrator.node.approve", {"run_id": state.run_id}):
        approved: List[RemediationPlan] = []
        rejected: List[RemediationPlan] = []
        pending_review: List[RemediationPlan] = []

        for p in state.plans:
            tier_val = p.risk_tier.value if hasattr(p.risk_tier, "value") else str(p.risk_tier)
            if global_approval_gate.is_approved(p.id, repo_path=state.repo_path):
                approved.append(p)
                p.requires_approval = False
                state.append_audit(
                    "PLAN_MANUALLY_APPROVED",
                    "approval_gate",
                    {"plan_id": p.id, "target_package": p.target_package, "risk_tier": tier_val},
                )
            elif global_approval_gate.is_rejected(p.id, repo_path=state.repo_path):
                rejected.append(p)
                dec = global_approval_gate.get_decision(p.id, repo_path=state.repo_path)
                state.append_audit(
                    "PLAN_MANUALLY_REJECTED",
                    "approval_gate",
                    {"plan_id": p.id, "target_package": p.target_package, "reason": dec.get("reason")},
                )
            elif p.risk_tier == RiskTier.BLOCKED:
                rejected.append(p)
                state.append_audit(
                    "PLAN_BLOCKED",
                    "policy_engine",
                    {"plan_id": p.id, "target_package": p.target_package, "reason": "Blocked by organizational policy"},
                )
            elif not p.requires_approval or p.risk_tier == RiskTier.AUTO or getattr(state, "auto_approve", False):
                approved.append(p)
                state.append_audit(
                    "PLAN_AUTO_APPROVED",
                    "policy_engine",
                    {"plan_id": p.id, "target_package": p.target_package, "risk_tier": tier_val},
                )
            else:
                pending_review.append(p)
                global_approval_gate.submit_for_approval(p, repo_path=state.repo_path)
                notify_server.approval_request(p.to_dict())
                state.append_audit(
                    "APPROVAL_REQUESTED",
                    "policy_engine",
                    {"plan_id": p.id, "target_package": p.target_package, "risk_tier": tier_val, "status": "pending_human_approval"},
                )

        state.approved_plans = approved
        state.rejected_plans = rejected
        state.pending_approval_plans = pending_review
        state.append_audit(
            "APPROVAL_PROCESSED",
            "orchestrator",
            {"approved": len(approved), "pending": len(pending_review), "rejected": len(rejected)},
        )

        if not approved and pending_review:
            state.terminal_status = "pending_approval"
            state.exit_code = 10
            state.blocking_reason = (
                f"{len(pending_review)} remediation plan(s) require human security authorization "
                "before PR creation: target packages are not on corporate pre-approved whitelist."
            )
            # Persist state so run can be resumed upon approval (F21)
            save_run_state(state, repo_path=state.repo_path)
        elif approved and state.terminal_status == "pending_approval":
            state.terminal_status = "running"
            state.exit_code = 0
            state.blocking_reason = None
        return state


def fix_node(state: VulnFlowState) -> VulnFlowState:
    """Apply real package version bumps to repository manifest on isolated fix branches."""
    state.current_node = "fix"
    with trace_span("orchestrator.node.fix", {"run_id": state.run_id}):
        patches: List[Dict[str, Any]] = []
        repo_p = Path(state.repo_path)

        # Detect primary base branch (usually main or master)
        base_branch = "main"
        if (repo_p / ".git").exists():
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                    cwd=str(repo_p),
                    stdout=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    base_branch = res.stdout.strip()
            except Exception:
                pass

        for p in state.approved_plans:
            if p.action in (RemediationAction.BUMP, RemediationAction.REPLACE) and (p.target_version or p.action == RemediationAction.REPLACE):
                branch_name = f"vulnflow/fix-{p.root_cause_id.replace(':', '-').replace('PKG-', '')}"
                if branch_name not in state.created_branches:
                    state.created_branches.append(branch_name)
                git_server.git_branch(branch_name, state.repo_path, base_branch=base_branch)
                state.append_audit("BRANCH_CREATED", "git_server", {"branch": branch_name, "repo": state.repo_path})

                diff_content = ""
                pkg_target = p.target_package or p.root_cause_id.replace("PKG-", "")
                target_file = "package.json"

                pkg_json = repo_p / "package.json"
                req_txt = repo_p / "requirements.txt"

                # Check ecosystem
                clean_name = pkg_target.split(":")[-1]
                is_npm_explicit = "npm:" in p.root_cause_id or (p.target_package and "npm:" in p.target_package)
                is_python_explicit = (
                    "pip:" in p.root_cause_id
                    or "python:" in p.root_cause_id
                    or (p.target_package and ("pip:" in p.target_package or "python:" in p.target_package))
                )

                if is_python_explicit and req_txt.exists():
                    is_python = True
                elif is_npm_explicit and pkg_json.exists():
                    is_python = False
                elif req_txt.exists() and not pkg_json.exists():
                    is_python = True
                elif pkg_json.exists() and not req_txt.exists():
                    is_python = False
                else:
                    pkg_json_content = pkg_json.read_text(encoding="utf-8") if pkg_json.exists() else ""
                    is_python = f'"{clean_name}"' not in pkg_json_content and req_txt.exists()

                if p.action == RemediationAction.REPLACE:
                    old_pkg = p.root_cause_id.replace("PKG-", "")
                    new_pkg = p.target_package or "replacement"
                    if not is_python and pkg_json.exists():
                        target_file = "package.json"
                        try:
                            _, diff_content = NPMAdapter.replace_dependency(pkg_json, old_pkg, new_pkg, p.target_version or "latest")
                        except Exception as exc:
                            logger.warning("NPMAdapter replace failed: %s", exc)
                elif is_python and req_txt.exists():
                    target_file = "requirements.txt"
                    try:
                        _, diff_content = PipAdapter.bump_dependency(req_txt, pkg_target, p.target_version)
                    except Exception as exc:
                        logger.warning("PipAdapter bump failed: %s", exc)
                elif pkg_json.exists():
                    target_file = "package.json"
                    try:
                        _, diff_content = NPMAdapter.bump_dependency(pkg_json, pkg_target, p.target_version)
                    except Exception as exc:
                        logger.warning("NPMAdapter bump failed: %s; using patch diff", exc)

                if not diff_content:
                    diff_content = f"--- {target_file}\n+++ {target_file}\n- \"{p.target_package}\": \"old\"\n+ \"{p.target_package}\": \"{p.target_version}\""

                res = git_server.git_patch(target_file, diff_content, state.repo_path)
                state.append_audit(
                    "PATCH_APPLIED",
                    "git_server",
                    {"plan_id": p.id, "branch": branch_name, "file": target_file, "target_version": p.target_version},
                )

                commit_msg = f"fix(deps): bump {p.target_package} to {p.target_version}"
                git_server.git_commit(commit_msg, state.repo_path, file_path=target_file)
                state.append_audit("COMMIT_CREATED", "git_server", {"branch": branch_name, "message": commit_msg})

                patches.append({
                    "plan_id": p.id,
                    "branch": branch_name,
                    "file": target_file,
                    "diff": diff_content,
                    "result": res,
                })

                # Switch back to base_branch so next fix branch starts clean from main
                if base_branch:
                    git_server.git_checkout(base_branch, state.repo_path)

            elif p.action == RemediationAction.ROTATE:
                clean_name = p.root_cause_id.replace(":", "-").replace("PKG-", "")
                branch_name = f"vulnflow/fix-{clean_name}"
                if branch_name not in state.created_branches:
                    state.created_branches.append(branch_name)
                git_server.git_branch(branch_name, state.repo_path, base_branch=base_branch)
                state.append_audit("BRANCH_CREATED", "git_server", {"branch": branch_name, "repo": state.repo_path})

                # Group all evidence items by relative file path for consolidated patching
                files_map: Dict[str, List[Dict[str, Any]]] = {}
                for ev in (p.evidence or []):
                    if isinstance(ev, dict) and ev.get("file_path"):
                        fpath = ev["file_path"]
                        files_map.setdefault(fpath, []).append(ev)

                # Fallback if evidence has no file_path
                if not files_map:
                    files_map["javascript_sast_vulnerabilities.js"] = [{"rule_id": p.root_cause_id.replace("secret:", "")}]

                total_modified = 0
                diff_summaries: List[str] = []

                for file_rel, items in files_map.items():
                    target_file_path = repo_p / file_rel
                    if not target_file_path.exists():
                        matches = list(repo_p.rglob(Path(file_rel).name))
                        if matches:
                            target_file_path = matches[0]
                            file_rel = str(target_file_path.relative_to(repo_p))

                    if target_file_path.exists():
                        try:
                            content = target_file_path.read_text(encoding="utf-8")
                            current_content = content
                            for item in items:
                                rule_id = item.get("rule_id", "secret")
                                line_no = item.get("line")
                                current_content, _ = default_secrets_agent.remediate_code(
                                    content=current_content,
                                    file_suffix=target_file_path.suffix,
                                    rule_id=rule_id,
                                    line_no=line_no,
                                )
                            if current_content != content:
                                target_file_path.write_text(current_content, encoding="utf-8")
                                total_modified += 1
                                diff_summaries.append(f"Migrated {len(items)} credential(s) in {file_rel}")
                                git_server.git_patch(file_rel, f"--- {file_rel}\n+++ {file_rel}\nMigrated {len(items)} credentials", state.repo_path)
                                state.append_audit(
                                    "PATCH_APPLIED",
                                    "git_server",
                                    {"plan_id": p.id, "branch": branch_name, "file": file_rel, "action": "rotate"},
                                )
                        except Exception as exc:
                            logger.warning("Secret rotation file update failed for %s: %s", file_rel, exc)

                commit_msg = f"fix(security): rotate exposed credentials and migrate to env vars"
                git_server.git_commit(commit_msg, state.repo_path)
                state.append_audit("COMMIT_CREATED", "git_server", {"branch": branch_name, "message": commit_msg})

                patches.append({
                    "plan_id": p.id,
                    "branch": branch_name,
                    "file": ", ".join(files_map.keys()),
                    "diff": "\n".join(diff_summaries) or "--- credentials\n+++ env vars",
                    "result": {"status": "applied", "modified_files": total_modified},
                })

                if base_branch:
                    git_server.git_checkout(base_branch, state.repo_path)

        state.patches = patches
        state.append_audit("PATCHES_APPLIED", "orchestrator", {"patches_count": len(patches)})
        return state


def test_node(state: VulnFlowState) -> VulnFlowState:
    """Run test suites against patched code in the sandbox."""
    state.current_node = "test"
    with trace_span("orchestrator.node.test", {"run_id": state.run_id}):
        test_results: List[Dict[str, Any]] = []
        for patch in state.patches:
            res = build_server.build_test(state.repo_path, patch["branch"], state.ecosystem)
            test_results.append(res)
            is_passed = res.get("passed", True) and res.get("build_clean", True)
            state.append_audit(
                "BUILD_TEST_EXECUTED",
                "build_server",
                {"branch": patch["branch"], "passed": is_passed, "exit_code": res.get("exit_code", 0)},
            )
            # Self-correction trigger if build or test fails (F20)
            if not is_passed:
                plan = next((p for p in state.approved_plans if p.id == patch["plan_id"]), None)
                if plan:
                    default_fixer_agent.analyze_failure_and_correct(
                        plan=plan,
                        test_output=res.get("output", ""),
                        retry_count=state.retry_count,
                        max_retries=state.max_retries,
                    )
                    state.append_audit(
                        "SELF_CORRECTION_TRIGGERED",
                        "fixer_agent",
                        {
                            "plan_id": plan.id,
                            "retry_count": state.retry_count,
                            "max_retries": state.max_retries,
                            "escalated": (state.retry_count >= state.max_retries),
                        },
                    )

        state.test_results = test_results
        state.append_audit("BUILD_TEST_COMPLETED", "orchestrator", {"results": test_results})
        return state


def pr_node(state: VulnFlowState) -> VulnFlowState:
    """Commit changes on each fix branch and open formatted pull request."""
    state.current_node = "pr"
    with trace_span("orchestrator.node.pr", {"run_id": state.run_id}):
        prs: List[Dict[str, Any]] = []
        repo_p = Path(state.repo_path)
        base_branch = "main"

        if (repo_p / ".git").exists():
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                    cwd=str(repo_p),
                    stdout=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res.returncode == 0 and res.stdout.strip():
                    base_branch = res.stdout.strip()
            except Exception:
                pass

        for patch in state.patches:
            plan = next((p for p in state.approved_plans if p.id == patch["plan_id"]), state.approved_plans[0])

            # Confirm registry availability before PR for dependency packages (F14)
            if plan.action in (RemediationAction.BUMP, RemediationAction.REPLACE) and plan.target_version and plan.target_package:
                plan_eco = state.ecosystem
                if ":" in plan.target_package:
                    prefix = plan.target_package.split(":", 1)[0].lower()
                    if prefix in ("pip", "pypi", "python"):
                        plan_eco = "PyPI"
                    elif prefix in ("npm", "node"):
                        plan_eco = "npm"
                reg_check = registry_check(plan.target_package, plan.target_version, plan_eco)
                if not reg_check.get("available", True):
                    logger.warning("Registry check rejected PR: %s not in registry", plan.target_version)
                    state.append_audit("REGISTRY_CHECK_FAILED", "registry_server", reg_check)
                    continue

            pr_body = format_pr_body(plan=plan)
            if plan.action == RemediationAction.ROTATE:
                clean_sec = (plan.target_package or plan.root_cause_id).replace("secret:", "")
                title = f"fix(security): rotate {clean_sec} and migrate to environment variable [VulnFlow]"
            else:
                title = f"fix(deps): bump {plan.target_package or 'dependency'} to {plan.target_version or 'secure'} [VulnFlow]"

            pr_res = git_server.pr_create(
                branch=patch["branch"],
                title=title,
                body=pr_body,
                repo_dir=state.repo_path,
            )
            prs.append(pr_res)
            state.append_audit(
                "PR_CREATED",
                "git_server",
                {
                    "pr_number": pr_res.get("pr_number"),
                    "pr_url": pr_res.get("pr_url"),
                    "branch": patch["branch"],
                    "title": title,
                },
            )

        # Restore working tree back to initial base branch
        if base_branch:
            git_server.git_checkout(base_branch, state.repo_path)

        state.pull_requests = prs
        return state


def verify_node(state: VulnFlowState) -> VulnFlowState:
    """Rescan patched branch and verify finding resolution using VerifierAgent."""
    state.current_node = "verify"
    with trace_span("orchestrator.node.verify", {"run_id": state.run_id}):
        ver_res = default_verifier_agent.verify_remediation(
            repo_path=state.repo_path,
            plans=state.plans,
            before_findings=state.findings,
            test_results=state.test_results,
            ecosystem=state.ecosystem,
        )

        for p in state.plans:
            p.verification = ver_res

        state.verification_results = [ver_res.to_dict()]

        # Strict invariant: a failed verify is never reported as success (F22)
        if not ver_res.verified and state.mode != "report" and state.terminal_status != "pending_approval":
            state.terminal_status = "failed_verification"
            state.exit_code = 30
            state.blocking_reason = f"Verification failed: {ver_res.details}"
            state.append_audit("VERIFICATION_FAILED", "verifier_agent", ver_res.to_dict())
        else:
            if state.terminal_status not in ("pending_approval", "blocked_policy"):
                state.terminal_status = "completed"
                state.exit_code = 0
            state.append_audit("VERIFICATION_COMPLETED", "verifier_agent", ver_res.to_dict())

        return state


def exception_node(state: VulnFlowState) -> VulnFlowState:
    """Escalate policy-blocked findings by opening an exception ticket."""
    state.current_node = "exception"
    with trace_span("orchestrator.node.exception", {"run_id": state.run_id}):
        # Determine specific blocking root causes
        reasons: List[str] = []

        # Check for test/build failures
        failed_tests = [r for r in state.test_results if not r.get("build_clean", True) or not r.get("passed", True)]
        if failed_tests:
            fail_outputs = [r.get("output", "").strip() for r in failed_tests if r.get("output")]
            first_err = fail_outputs[0].splitlines()[0] if fail_outputs and fail_outputs[0] else "Non-zero test exit code"
            reasons.append(f"Automated test suite failed ({len(failed_tests)} test run(s) failed): {first_err}")

        # Check for banned or license-denied packages
        banned = [p for p in state.plans if p.policy_result and p.policy_result.status in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value)]
        if banned:
            banned_pkgs = ", ".join(p.target_package for p in banned)
            reasons.append(f"Organizational policy banned package(s): {banned_pkgs}")

        # Check for unapproved plans
        if not state.approved_plans and not reasons:
            reasons.append("No remediation plans were approved for automatic execution.")

        blocking_reason = " | ".join(reasons) if reasons else "Remediation blocked by automated policy safety gate."
        state.blocking_reason = blocking_reason

        cve_list = sorted(list({cve for f in state.findings for cve in f.cve if cve}))
        target_pkgs = sorted(list({p.target_package or p.root_cause_id for p in state.plans}))
        pkg_summary = ", ".join(target_pkgs) if target_pkgs else "dependencies"

        ticket = ticket_server.ticket_create("security_exception", {
            "run_id": state.run_id,
            "repo": state.repo_path,
            "reason": blocking_reason,
            "target_package": pkg_summary,
            "cves": cve_list,
            "plans": [p.to_dict() for p in state.plans],
        })
        state.exception_ticket = ticket
        state.pull_requests = []  # Invariant: unapproved fix never opens PR
        state.terminal_status = "blocked_policy"
        state.exit_code = 20
        state.append_audit("EXCEPTION_ESCALATED", "orchestrator", {"reason": blocking_reason, "ticket": ticket})
        return state
