"""
src/vulnflow/orchestrator/nodes.py
Implements individual state transformation node handlers in LangGraph.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

from vulnflow.adapters.ecosystem.maven import MavenAdapter
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
from vulnflow.knowledge.graph.queries import find_blast_radius
from vulnflow.mcp_servers.build_server import build_server
from vulnflow.mcp_servers.git_server import git_server
from vulnflow.mcp_servers.knowledge_server import advisory_search, knowledge_server
from vulnflow.mcp_servers.notify_server import notify_server
from vulnflow.mcp_servers.registry_server import registry_check
from vulnflow.mcp_servers.scan_server import scan_server
from vulnflow.mcp_servers.ticket_server import ticket_server
from vulnflow.observability.tracing import trace_span
from vulnflow.orchestrator.approval import global_approval_gate, save_run_state
from vulnflow.policy.engine import default_policy_engine
from vulnflow.reporting.pr_comment import format_campaign_pr_body, format_pr_body
from vulnflow.store.run_store import default_run_store

logger = logging.getLogger("vulnflow.orchestrator.nodes")


def _require_tool_status(
    result: dict[str, Any], expected: str, operation: str
) -> dict[str, Any]:
    """Fail the workflow when a side-effect tool did not confirm its action."""
    if result.get("status") != expected:
        raise RuntimeError(
            f"{operation} was not confirmed: {result.get('error') or result}"
        )
    return result


def _campaign_id(plan: RemediationPlan) -> str:
    """Group equivalent remediation intents under a stable campaign identity."""
    action = plan.action.value if hasattr(plan.action, "value") else str(plan.action)
    raw = f"{plan.target_package}|{action}|{plan.target_version}".lower()
    return f"CAMPAIGN-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def _merge_blast_radius(
    local: dict[str, Any], organization: dict[str, Any]
) -> dict[str, Any]:
    """Merge repository and organization graph results without duplicating nodes."""
    tier_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    tiers = [
        str(local.get("blast_radius_tier", "LOW")),
        str(organization.get("blast_radius_tier", "LOW")),
    ]
    tier = max(tiers, key=lambda value: tier_order.get(value, 0))
    dependents = sorted(
        set(local.get("dependents", [])) | set(organization.get("dependents", []))
    )
    services = sorted(
        set(local.get("affected_services", []))
        | set(organization.get("affected_services", []))
    )
    repos = sorted(
        set(local.get("affected_repos", []))
        | set(organization.get("affected_repos", []))
    )
    return {
        "blast_radius_tier": tier,
        "total_affected_dependents": len(dependents),
        "dependents": dependents,
        "affected_services": services,
        "affected_repos": repos,
    }


def _organization_graph_enabled() -> bool:
    """Require an explicit opt-in because the built-in active graph is demo data."""
    return os.getenv("VULNFLOW_ORGANIZATION_GRAPH_ENABLED", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _previous_plan_outcomes(
    plan: RemediationPlan, limit: int = 3
) -> list[dict[str, Any]]:
    """Retrieve bounded local run history for the same remediation target."""
    outcomes: list[dict[str, Any]] = []
    action = plan.action.value if hasattr(plan.action, "value") else str(plan.action)
    for run in default_run_store.list_runs(limit=100):
        snapshot = run.get("evidence_snapshot", {})
        if not isinstance(snapshot, dict):
            continue
        for old_plan in snapshot.get("plans", []):
            if not isinstance(old_plan, dict):
                continue
            if old_plan.get("target_package") != plan.target_package:
                continue
            if str(old_plan.get("action")) != action:
                continue
            outcomes.append(
                {
                    "run_id": run.get("run_id"),
                    "target_version": old_plan.get("target_version"),
                    "terminal_status": run.get("terminal_status"),
                    "tests_passed": all(
                        result.get("success", result.get("passed", False))
                        for result in snapshot.get("test_results", [])
                        if isinstance(result, dict)
                    )
                    if snapshot.get("test_results")
                    else None,
                    "prs_opened": len(snapshot.get("pull_requests", [])),
                }
            )
            if len(outcomes) >= limit:
                return outcomes
    return outcomes


def _apply_graph_governance(
    plan: RemediationPlan, graph_context: dict[str, Any]
) -> bool:
    """Escalate high-blast-radius automatic work to human review."""
    if (
        graph_context.get("blast_radius_tier") != "HIGH"
        or plan.risk_tier != RiskTier.AUTO
    ):
        return False
    plan.risk_tier = RiskTier.REVIEW
    plan.requires_approval = True
    plan.rationale = (
        f"{plan.rationale.rstrip()}\n"
        "• Graph Governance: Escalated to review because the dependency has a HIGH organizational blast radius."
    )
    return True


def ingest_node(state: VulnFlowState) -> VulnFlowState:
    """Read and normalize scanner findings from report file or scanner tool."""
    state.current_node = "ingest"
    with trace_span("orchestrator.node.ingest", {"run_id": state.run_id}):
        findings: list[Finding] = []

        if state.report_path:
            if not Path(state.report_path).is_file():
                raise ValueError("The submitted scanner report does not exist")
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
                        if (
                            '"Secret"' in _snip
                            or '"RuleID"' in _snip
                            or '"Fingerprint"' in _snip
                        ):
                            s_name = "gitleaks"
                        elif '"runs"' in _snip and '"tool"' in _snip:
                            s_name = "sarif"
                        elif '"matches"' in _snip and '"artifact"' in _snip:
                            s_name = "grype"
                    except (OSError, UnicodeDecodeError):
                        logger.debug(
                            "Failed reading initial report snippet for format detection"
                        )
            adapter: Any
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

            findings = adapter.parse_file(state.report_path, repo=state.repo_path)
        else:
            scan = scan_server.scan_verify(
                repo=state.repo_path, scanner=state.scanner
            )
            if not scan.get("complete"):
                raise RuntimeError(f"Initial scan unavailable: {scan.get('error') or 'missing scan evidence'}")
            raw_scan_results = scan.get("findings", [])
            state.raw_findings = raw_scan_results
            for item in raw_scan_results:
                findings.append(Finding.from_dict(item))

        state.findings = findings
        state.append_audit(
            "INGESTION_COMPLETED", "orchestrator", {"findings_count": len(findings)}
        )
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
            if pol.status in (
                PolicyStatus.BANNED.value,
                PolicyStatus.LICENSE_DENIED.value,
            ):
                has_blocked_package = True

        state.append_audit(
            "POLICY_EVALUATION_COMPLETED",
            "orchestrator",
            {"blocked": has_blocked_package},
        )
        return state


def plan_node(state: VulnFlowState) -> VulnFlowState:
    """Formulate remediation plan using Fix Planner agent backed by real policy and LLM."""
    state.current_node = "plan"
    default_planner_agent.reset_circuit_breaker()
    with trace_span("orchestrator.node.plan", {"run_id": state.run_id}):
        plans: list[RemediationPlan] = []
        plan_contexts: dict[str, dict[str, Any]] = {}
        already_audited: set[str] = set()

        # 1. Group all secret/PII findings into a single consolidated remediation plan (F23)
        all_secret_findings = [
            f for f in state.deduped_findings if f.type == FindingType.SECRET
        ]
        if all_secret_findings:
            sec_plan = default_secrets_agent.plan_consolidated_secret_remediation(
                all_secret_findings, repo_path=state.repo_path
            )
            plans.append(sec_plan)
            already_audited.add(sec_plan.id)
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

            advisories = advisory_search(
                query=clean_rc, package=clean_rc, ecosystem=pkg_eco, limit=3
            )
            if not advisories:
                # Query distinct packages from findings only if different from root cause
                other_pkgs = {
                    f_obj.package
                    for f_obj in findings_objs
                    if f_obj.package and f_obj.package != clean_rc
                }
                for pkg_name in other_pkgs:
                    advisories.extend(
                        advisory_search(
                            query=pkg_name,
                            package=pkg_name,
                            ecosystem=pkg_eco,
                            limit=3,
                        )
                    )
            if not advisories:
                advisories = advisory_search(query=rc_id, package=clean_rc, limit=3)
            advisories = advisories[:3]

            # Delegate to PlannerAgent (F16)
            plan = default_planner_agent.plan_remediation(
                root_cause_id=rc_id,
                findings=findings_objs,
                advisories=advisories,
                ecosystem=pkg_eco,
                is_transitive=not bool(group.get("is_direct", True)),
            )
            plan.campaign_id = _campaign_id(plan)

            local_blast = find_blast_radius(
                package=clean_rc,
                version=findings_objs[0].version if findings_objs else None,
                repo_path=state.repo_path,
                ecosystem=pkg_eco,
            )
            organization_blast: dict[str, Any] = {}
            if _organization_graph_enabled():
                organization_blast = knowledge_server.blast_radius(
                    package=clean_rc,
                    version=findings_objs[0].version if findings_objs else None,
                    ecosystem=pkg_eco,
                )
            graph_context = _merge_blast_radius(local_blast, organization_blast)
            graph_escalated = _apply_graph_governance(plan, graph_context)

            owners = {
                "repository_owner": os.getenv("VULNFLOW_REPOSITORY_OWNER", "unknown"),
                "product_owner": os.getenv("VULNFLOW_PRODUCT_OWNER", "unknown"),
                "required_approver_groups": [
                    group_name.strip()
                    for group_name in os.getenv(
                        "VULNFLOW_APPROVER_GROUPS", "security"
                    ).split(",")
                    if group_name.strip()
                ],
            }
            plan_contexts[plan.id] = {
                "run_id": state.run_id,
                "current_version": findings_objs[0].version
                if findings_objs
                else "unknown",
                "is_direct": bool(group.get("is_direct", True)),
                "dependency_path": group.get("dependency_chain", []),
                "graph": graph_context,
                "owners": owners,
                "campaign_id": plan.campaign_id,
                "advisories": advisories,
                "previous_outcomes": _previous_plan_outcomes(plan),
            }
            plans.append(plan)
            state.append_audit(
                "GRAPH_RAG_CONTEXT_BUILT",
                "knowledge_server",
                {
                    "plan_id": plan.id,
                    "campaign_id": plan.campaign_id,
                    "blast_radius_tier": graph_context["blast_radius_tier"],
                    "affected_services": len(graph_context["affected_services"]),
                    "affected_repositories": len(graph_context["affected_repos"]),
                    "retrieved_chunks": len(advisories),
                    "previous_outcomes": len(
                        plan_contexts[plan.id]["previous_outcomes"]
                    ),
                    "risk_escalated": graph_escalated,
                },
            )

        plans = default_planner_agent.enrich_plans_batch(
            plans,
            plan_contexts,
            repo_path=state.repo_path,
        )

        # Persist one plan event after batch enrichment so reports see final rationale and usage.
        for plan in plans:
            if plan.id in already_audited:
                continue
            state.append_audit(
                "PLAN_FORMULATED",
                "planner_agent",
                {
                    "plan_id": plan.id,
                    "root_cause_id": plan.root_cause_id,
                    "target_package": plan.target_package,
                    "target_version": plan.target_version,
                    "action": plan.action.value
                    if hasattr(plan.action, "value")
                    else str(plan.action),
                    "risk_tier": plan.risk_tier.value
                    if hasattr(plan.risk_tier, "value")
                    else str(plan.risk_tier),
                    "requires_approval": plan.requires_approval,
                    "policy_status": plan.policy_result.status
                    if plan.policy_result
                    else "APPROVED",
                    "ai_rationale": plan.rationale,
                    "llm_enrichment": default_planner_agent.plan_enrichment(plan.id),
                    "campaign_id": plan.campaign_id,
                },
            )

        state.plans = plans
        state.append_audit(
            "PLANNER_LLM_ENRICHMENT_SUMMARY",
            "planner_agent",
            default_planner_agent.enrichment_stats(),
        )
        state.append_audit(
            "PLANS_GENERATED", "orchestrator", {"plans_count": len(plans)}
        )
        return state


def approve_node(state: VulnFlowState) -> VulnFlowState:
    """Process approval gates based on assigned risk tiers and human authorizations."""
    state.current_node = "approve"
    with trace_span("orchestrator.node.approve", {"run_id": state.run_id}):
        approved: list[RemediationPlan] = []
        rejected: list[RemediationPlan] = []
        pending_review: list[RemediationPlan] = []
        newly_requested: list[RemediationPlan] = []

        for p in state.plans:
            tier_val = (
                p.risk_tier.value if hasattr(p.risk_tier, "value") else str(p.risk_tier)
            )
            approval_status = ""
            approval_result: dict[str, Any] = {}
            if (
                p.requires_approval
                and p.risk_tier not in (RiskTier.AUTO, RiskTier.BLOCKED)
                and not getattr(state, "auto_approve", False)
            ):
                approval_result = global_approval_gate.resolve_plan(state, p)
                approval_status = approval_result.get("status", "")

            if approval_status == "approved" or global_approval_gate.is_approved(
                p.id, repo_path=state.repo_path
            ):
                approved.append(p)
                p.requires_approval = False
                state.append_audit(
                    "PLAN_MANUALLY_APPROVED",
                    "approval_gate",
                    {
                        "plan_id": p.id,
                        "target_package": p.target_package,
                        "risk_tier": tier_val,
                    },
                )
            elif approval_status == "rejected" or global_approval_gate.is_rejected(
                p.id, repo_path=state.repo_path
            ):
                rejected.append(p)
                dec = global_approval_gate.get_decision(p.id, repo_path=state.repo_path)
                state.append_audit(
                    "PLAN_MANUALLY_REJECTED",
                    "approval_gate",
                    {
                        "plan_id": p.id,
                        "target_package": p.target_package,
                        "reason": dec.get("reason"),
                    },
                )
            elif p.risk_tier == RiskTier.BLOCKED:
                rejected.append(p)
                state.append_audit(
                    "PLAN_BLOCKED",
                    "policy_engine",
                    {
                        "plan_id": p.id,
                        "target_package": p.target_package,
                        "reason": "Blocked by organizational policy",
                    },
                )
            elif (
                not p.requires_approval
                or p.risk_tier == RiskTier.AUTO
                or getattr(state, "auto_approve", False)
            ):
                approved.append(p)
                state.append_audit(
                    "PLAN_AUTO_APPROVED",
                    "policy_engine",
                    {
                        "plan_id": p.id,
                        "target_package": p.target_package,
                        "risk_tier": tier_val,
                    },
                )
            else:
                pending_review.append(p)
                if not approval_result.get("reused", False):
                    newly_requested.append(p)
                state.append_audit(
                    "APPROVAL_REQUESTED",
                    "policy_engine",
                    {
                        "plan_id": p.id,
                        "target_package": p.target_package,
                        "risk_tier": tier_val,
                        "status": "pending_human_approval",
                    },
                )

        # Dispatch a single consolidated digest notification for the run instead of spamming individual pings
        if newly_requested or approved:
            notify_server.send_run_digest(
                run_id=state.run_id,
                repo=state.repo_path,
                approved_plans=[p.to_dict() for p in approved],
                pending_plans=[p.to_dict() for p in newly_requested],
            )
            state.append_audit(
                "DIGEST_NOTIFICATION_SENT",
                "notify_server",
                {
                    "approved_count": len(approved),
                    "pending_count": len(newly_requested),
                },
            )

        state.approved_plans = approved
        state.rejected_plans = rejected
        state.pending_approval_plans = pending_review
        state.append_audit(
            "APPROVAL_PROCESSED",
            "orchestrator",
            {
                "approved": len(approved),
                "pending": len(pending_review),
                "rejected": len(rejected),
            },
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
    """Apply remediation in a disposable worktree without changing the caller's checkout."""
    state.current_node = "fix"
    repo = Path(state.repo_path).resolve()
    if not (repo / ".git").exists():
        raise RuntimeError("Repository is not a git checkout")
    with build_server.sandbox.isolated_checkout(repo) as worktree:
        return _fix_checkout(state, worktree)


def _fix_checkout(state: VulnFlowState, repo_p: Path) -> VulnFlowState:
    with trace_span("orchestrator.node.fix", {"run_id": state.run_id}):
        patches: list[dict[str, Any]] = []
        worktree = str(repo_p)
        base_branch = build_server.sandbox.checkout_revision(repo_p)

        def _create_branch(branch: str) -> None:
            _require_tool_status(
                git_server.git_branch(
                    branch, worktree, base_branch=base_branch,
                    replace_existing=branch in state.created_branches,
                ),
                "created", f"Create branch {branch}",
            )
            if branch not in state.created_branches:
                state.created_branches.append(branch)

        def _apply_dependency_bump(
            p: RemediationPlan, branch_name: str, is_campaign: bool = False
        ) -> dict[str, Any]:
            diff_content = ""
            pkg_target = p.target_package or p.root_cause_id.replace("PKG-", "")
            target_file = "package.json"

            pkg_json = repo_p / "package.json"
            req_txt = repo_p / "requirements.txt"
            pom_xml = repo_p / "pom.xml"
            if any(path.is_symlink() for path in (pkg_json, req_txt, pom_xml)):
                raise RuntimeError("Refusing to modify a symlinked dependency manifest")

            clean_name = pkg_target.split(":")[-1]
            is_npm_explicit = "npm:" in p.root_cause_id or (
                p.target_package and "npm:" in p.target_package
            )
            is_python_explicit = (
                "pip:" in p.root_cause_id
                or "python:" in p.root_cause_id
                or (
                    p.target_package
                    and ("pip:" in p.target_package or "python:" in p.target_package)
                )
            )
            is_maven_explicit = "maven:" in p.root_cause_id or bool(
                p.target_package and "maven:" in p.target_package
            )

            if is_maven_explicit and pom_xml.exists():
                is_maven = True
                is_python = False
            elif is_python_explicit and req_txt.exists():
                is_maven = False
                is_python = True
            elif is_npm_explicit and pkg_json.exists():
                is_maven = False
                is_python = False
            elif req_txt.exists() and not pkg_json.exists():
                is_maven = False
                is_python = True
            elif pom_xml.exists() and not pkg_json.exists() and not req_txt.exists():
                is_maven = True
                is_python = False
            elif pkg_json.exists() and not req_txt.exists():
                is_maven = False
                is_python = False
            else:
                is_maven = False
                pkg_json_content = (
                    pkg_json.read_text(encoding="utf-8") if pkg_json.exists() else ""
                )
                is_python = (
                    f'"{clean_name}"' not in pkg_json_content and req_txt.exists()
                )

            if is_maven and pom_xml.exists():
                if p.action is RemediationAction.REPLACE:
                    raise RuntimeError("Maven dependency replacement requires manual review")
                target_file = "pom.xml"
                try:
                    _, diff_content = MavenAdapter.bump_dependency(
                        pom_xml, pkg_target, p.target_version or "latest"
                    )
                except (OSError, ValueError, KeyError) as exc:
                    logger.warning("MavenAdapter bump failed: %s", exc)
            elif p.action == RemediationAction.REPLACE:
                old_pkg = p.root_cause_id.replace("PKG-", "")
                new_pkg = p.target_package or "replacement"
                if not is_python and pkg_json.exists():
                    target_file = "package.json"
                    try:
                        _, diff_content = NPMAdapter.replace_dependency(
                            pkg_json, old_pkg, new_pkg, p.target_version or "latest"
                        )
                    except (OSError, ValueError, KeyError) as exc:
                        logger.warning("NPMAdapter replace failed: %s", exc)
            elif is_python and req_txt.exists():
                target_file = "requirements.txt"
                try:
                    _, diff_content = PipAdapter.bump_dependency(
                        req_txt, pkg_target, p.target_version or "latest"
                    )
                except (OSError, ValueError, KeyError) as exc:
                    logger.warning("PipAdapter bump failed: %s", exc)
            elif pkg_json.exists():
                target_file = "package.json"
                try:
                    _, diff_content = NPMAdapter.bump_dependency(
                        pkg_json, pkg_target, p.target_version or "latest"
                    )
                except (OSError, ValueError, KeyError) as exc:
                    logger.warning("NPMAdapter bump failed: %s; using patch diff", exc)

            if not diff_content:
                raise RuntimeError(f"No dependency change was produced for {target_file}")

            res = _require_tool_status(
                git_server.git_patch(target_file, diff_content, worktree),
                "applied",
                f"Patch {target_file}",
            )
            state.append_audit(
                "PATCH_APPLIED",
                "git_server",
                {
                    "plan_id": p.id,
                    "branch": branch_name,
                    "file": target_file,
                    "target_version": p.target_version,
                    "campaign": is_campaign,
                },
            )
            return {
                "plan_id": p.id,
                "branch": branch_name,
                "file": target_file,
                "diff": diff_content,
                "result": res,
                "is_campaign": is_campaign,
            }

        def _update_npm_lockfile(branch_patches: list[dict[str, Any]]) -> bool:
            if not any(patch["file"] == "package.json" for patch in branch_patches):
                return False
            update = build_server.npm_update_lock(worktree)
            if update.get("status") in {"missing", "unchanged"}:
                return False
            _require_tool_status(update, "updated", "Update npm lockfile")
            state.append_audit(
                "LOCKFILE_UPDATED", "build_server",
                {"branch": branch_patches[0]["branch"], "file": update["file"]},
            )
            return True

        # Partition plans by remediation type
        dep_plans = [
            p
            for p in state.approved_plans
            if p.action in (RemediationAction.BUMP, RemediationAction.REPLACE)
            and (p.target_version or p.action == RemediationAction.REPLACE)
        ]
        rotate_plans = [
            p for p in state.approved_plans if p.action == RemediationAction.ROTATE
        ]

        # Multi-dependency campaign batching (Capability 2)
        if len(dep_plans) > 1:
            campaign_branch = f"vulnflow/campaign-{state.run_id[:8]}"
            _create_branch(campaign_branch)
            state.append_audit(
                "BRANCH_CREATED",
                "git_server",
                {"branch": campaign_branch, "repo": state.repo_path, "campaign": True},
            )

            for p in dep_plans:
                patch_record = _apply_dependency_bump(
                    p, campaign_branch, is_campaign=True
                )
                patches.append(patch_record)

            _update_npm_lockfile(patches)
            pkgs_str = ", ".join(
                p.target_package or p.root_cause_id.replace("PKG-", "")
                for p in dep_plans
            )
            commit_msg = f"fix(deps): campaign remediation for {pkgs_str}"
            _require_tool_status(
                git_server.git_commit(commit_msg, worktree),
                "committed",
                f"Commit branch {campaign_branch}",
            )
            state.append_audit(
                "COMMIT_CREATED",
                "git_server",
                {"branch": campaign_branch, "message": commit_msg, "campaign": True},
            )

            if base_branch:
                git_server.git_checkout(base_branch, worktree)

        elif len(dep_plans) == 1:
            p = dep_plans[0]
            branch_name = (
                f"vulnflow/fix-{p.root_cause_id.replace(':', '-').replace('PKG-', '')}"
            )
            _create_branch(branch_name)
            state.append_audit(
                "BRANCH_CREATED",
                "git_server",
                {"branch": branch_name, "repo": state.repo_path},
            )

            patch_record = _apply_dependency_bump(p, branch_name, is_campaign=False)
            commit_msg = f"fix(deps): bump {p.target_package} to {p.target_version}"
            lockfile_updated = _update_npm_lockfile([patch_record])
            _require_tool_status(
                git_server.git_commit(
                    commit_msg, worktree,
                    file_path=None if lockfile_updated else patch_record["file"],
                ),
                "committed",
                f"Commit branch {branch_name}",
            )
            state.append_audit(
                "COMMIT_CREATED",
                "git_server",
                {"branch": branch_name, "message": commit_msg},
            )
            patches.append(patch_record)

            if base_branch:
                git_server.git_checkout(base_branch, worktree)

        # Secret rotation plans
        for p in rotate_plans:
            clean_name = p.root_cause_id.replace(":", "-").replace("PKG-", "")
            branch_name = f"vulnflow/fix-{clean_name}"
            _create_branch(branch_name)
            state.append_audit(
                "BRANCH_CREATED",
                "git_server",
                {"branch": branch_name, "repo": state.repo_path},
            )

            files_map: dict[str, list[dict[str, Any]]] = {}
            for ev in p.evidence or []:
                if isinstance(ev, dict) and ev.get("file_path"):
                    fpath = ev["file_path"]
                    files_map.setdefault(fpath, []).append(ev)

            total_modified = 0
            diff_summaries: list[str] = []

            for file_rel, items in files_map.items():
                target_file_path = repo_p / file_rel
                if Path(file_rel).is_absolute() or target_file_path.resolve() != target_file_path:
                    raise RuntimeError("Refusing to modify a secret finding outside its tracked repository path")

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
                            target_file_path.write_text(
                                current_content, encoding="utf-8"
                            )
                            total_modified += 1
                            diff_summaries.append(
                                f"Migrated {len(items)} credential(s) in {file_rel}"
                            )
                            _require_tool_status(
                                git_server.git_patch(
                                    file_rel,
                                    f"--- {file_rel}\n+++ {file_rel}\nMigrated {len(items)} credentials",
                                    worktree,
                                ),
                                "applied",
                                f"Patch {file_rel}",
                            )
                            state.append_audit(
                                "PATCH_APPLIED",
                                "git_server",
                                {
                                    "plan_id": p.id,
                                    "branch": branch_name,
                                    "file": file_rel,
                                    "action": "rotate",
                                },
                            )
                    except (OSError, ValueError, KeyError) as exc:
                        logger.warning(
                            "Secret rotation file update failed for %s: %s",
                            file_rel,
                            exc,
                        )

            commit_msg = (
                "fix(security): rotate exposed credentials and migrate to env vars"
            )
            _require_tool_status(
                git_server.git_commit(commit_msg, worktree),
                "committed",
                f"Commit branch {branch_name}",
            )
            state.append_audit(
                "COMMIT_CREATED",
                "git_server",
                {"branch": branch_name, "message": commit_msg},
            )

            patches.append(
                {
                    "plan_id": p.id,
                    "branch": branch_name,
                    "file": ", ".join(files_map.keys()),
                    "diff": "\n".join(diff_summaries)
                    or "--- credentials\n+++ env vars",
                    "result": {"status": "applied", "modified_files": total_modified},
                }
            )

            if base_branch:
                git_server.git_checkout(base_branch, worktree)

        state.patches = patches
        state.append_audit(
            "PATCHES_APPLIED", "orchestrator", {"patches_count": len(patches)}
        )
        return state


def test_node(state: VulnFlowState) -> VulnFlowState:
    """Run test suites against patched code in the sandbox with automated refactoring fallback."""
    state.current_node = "test"
    with trace_span("orchestrator.node.test", {"run_id": state.run_id}):
        test_results: list[dict[str, Any]] = []
        tested_branches: dict[str, dict[str, Any]] = {}

        for patch in state.patches:
            branch = patch["branch"]
            if branch in tested_branches:
                test_results.append(tested_branches[branch])
                continue

            res = build_server.build_test(state.repo_path, branch, state.ecosystem)
            is_passed = (
                res.get("passed", False)
                and res.get("build_clean", False)
                and res.get("verification_available", True)
            )
            state.append_audit(
                "BUILD_TEST_EXECUTED",
                "build_server",
                {
                    "branch": branch,
                    "passed": is_passed,
                    "exit_code": res.get("exit_code", 0),
                },
            )

            # Automated Code Refactoring / Self-correction trigger if build or test fails (F20 + Capability 1)
            if not is_passed:
                plan = next(
                    (p for p in state.approved_plans if p.id == patch["plan_id"]), None
                )
                if plan:
                    # 1. Attempt autonomous code refactoring via FixerAgent
                    test_output = res.get("output", "")
                    refactor_res = default_fixer_agent.attempt_code_refactor(
                        plan=plan,
                        test_output=test_output,
                        repo_path=state.repo_path,
                        branch=branch,
                    )
                    if refactor_res:
                        state.append_audit(
                            "CODE_REFACTORING_APPLIED",
                            "fixer_agent",
                            {
                                "plan_id": plan.id,
                                "branch": branch,
                                "file": refactor_res.get("file"),
                                "symbol": refactor_res.get("symbol"),
                                "rationale": refactor_res.get("rationale"),
                            },
                        )
                        retest_res = build_server.build_test(
                            state.repo_path, branch, state.ecosystem
                        )
                        retest_passed = (
                            retest_res.get("passed", False)
                            and retest_res.get("build_clean", False)
                            and retest_res.get("verification_available", True)
                        )
                        if retest_passed:
                            is_passed = True
                            res = retest_res
                            state.append_audit(
                                "BUILD_TEST_EXECUTED",
                                "build_server",
                                {
                                    "branch": branch,
                                    "passed": True,
                                    "exit_code": retest_res.get("exit_code", 0),
                                    "refactored": True,
                                },
                            )

                    # 2. If refactoring was not applied or test still failed, trigger traditional failure analysis
                    if not is_passed:
                        previous_version = plan.target_version
                        default_fixer_agent.analyze_failure_and_correct(
                            plan=plan,
                            test_output=res.get("output", ""),
                            retry_count=state.retry_count,
                            max_retries=state.max_retries,
                        )
                        res["retry_available"] = plan.target_version != previous_version
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

            safe_result = {key: value for key, value in res.items() if key != "output"}
            tested_branches[branch] = safe_result
            test_results.append(safe_result)

        state.test_results = test_results
        state.append_audit(
            "BUILD_TEST_COMPLETED", "orchestrator", {"results": test_results}
        )
        return state


def pr_node(state: VulnFlowState) -> VulnFlowState:
    """Open pull requests for verified commits."""
    state.current_node = "pr"
    with trace_span("orchestrator.node.pr", {"run_id": state.run_id}):
        prs: list[dict[str, Any]] = []
        # Group patches by branch to support both single-fix and campaign PRs
        branch_to_patches: dict[str, list[dict[str, Any]]] = {}
        for patch in state.patches:
            branch_to_patches.setdefault(patch["branch"], []).append(patch)

        for branch, b_patches in branch_to_patches.items():
            verification = next(
                (
                    result for result in state.verification_results
                    if result.get("branch") == branch and result.get("verified") is True
                ),
                {},
            )
            if not verification.get("revision"):
                state.error = "Verified commit evidence is missing for a remediation branch"
                continue
            branch_plan_ids = {p["plan_id"] for p in b_patches}
            branch_plans = [p for p in state.approved_plans if p.id in branch_plan_ids]
            if not branch_plans:
                state.error = "No approved plan matched the remediation branch"
                continue

            # Confirm registry availability before PR for dependency packages (F14)
            registry_rejected = False
            for plan in branch_plans:
                if (
                    plan.action in (RemediationAction.BUMP, RemediationAction.REPLACE)
                    and plan.target_version
                    and plan.target_package
                ):
                    plan_eco = state.ecosystem
                    if ":" in plan.target_package:
                        prefix = plan.target_package.split(":", 1)[0].lower()
                        if prefix in ("pip", "pypi", "python"):
                            plan_eco = "PyPI"
                        elif prefix in ("npm", "node"):
                            plan_eco = "npm"
                    reg_check = registry_check(
                        plan.target_package, plan.target_version, plan_eco
                    )
                    if not reg_check.get("confirmed", False):
                        logger.warning(
                            "Registry check rejected PR: %s not in registry",
                            plan.target_version,
                        )
                        state.append_audit(
                            "REGISTRY_CHECK_FAILED", "registry_server", reg_check
                        )
                        registry_rejected = True
                        state.error = "Dependency registry did not confirm an intended version"
                        break
            if registry_rejected:
                continue

            # Multi-dependency campaign PR format vs single-plan PR
            is_campaign = len(branch_plans) > 1 or any(
                p.get("is_campaign") for p in b_patches
            )
            if is_campaign and len(branch_plans) > 1:
                target_pkgs = [
                    p.target_package or p.root_cause_id.replace("PKG-", "")
                    for p in branch_plans
                ]
                pkgs_preview = ", ".join(target_pkgs[:3]) + (
                    " and more" if len(target_pkgs) > 3 else ""
                )
                title = f"fix(deps): campaign remediation for {pkgs_preview} [VulnFlow]"
                pr_body = format_campaign_pr_body(
                    plans=branch_plans,
                    verification=VerificationResult.from_dict(verification),
                )
            else:
                plan = branch_plans[0]
                pr_body = format_pr_body(plan=plan)
                if plan.action == RemediationAction.ROTATE:
                    clean_sec = (plan.target_package or plan.root_cause_id).replace(
                        "secret:", ""
                    )
                    title = f"fix(security): rotate {clean_sec} and migrate to environment variable [VulnFlow]"
                else:
                    title = f"fix(deps): bump {plan.target_package or 'dependency'} to {plan.target_version or 'secure'} [VulnFlow]"

            pr_res = git_server.pr_create(
                branch=branch,
                title=title,
                body=pr_body,
                repo_dir=state.repo_path,
                expected_revision=verification["revision"],
            )
            if pr_res.get("status") != "opened" or not pr_res.get("pr_url"):
                state.append_audit(
                    "PR_CREATION_FAILED",
                    "git_server",
                    {
                        "branch": branch,
                        "status": pr_res.get("status"),
                        "error": pr_res.get("error"),
                    },
                )
                state.terminal_status = "error"
                state.exit_code = 1
                state.error = str(
                    pr_res.get("error") or "Pull request creation was not confirmed"
                )
                state.blocking_reason = state.error
                continue
            prs.append(pr_res)
            state.append_audit(
                "PR_CREATED",
                "git_server",
                {
                    "pr_number": pr_res.get("pr_number"),
                    "pr_url": pr_res.get("pr_url"),
                    "branch": branch,
                    "title": title,
                    "campaign": is_campaign and len(branch_plans) > 1,
                    "plans_count": len(branch_plans),
                },
            )

        state.pull_requests = prs
        if prs and len(prs) == len(branch_to_patches):
            state.terminal_status = "completed"
            state.exit_code = 0
        else:
            state.terminal_status = "error"
            state.exit_code = 1
            state.blocking_reason = state.error or "No pull request creation was confirmed"
        return state


def verify_node(state: VulnFlowState) -> VulnFlowState:
    """Rescan patched branch and verify finding resolution using VerifierAgent."""
    state.current_node = "verify"
    with trace_span("orchestrator.node.verify", {"run_id": state.run_id}):
        if state.mode == "report":
            assessment = VerificationResult(
                verified=False,
                rescan_clean=False,
                policy_recheck_passed=True,
                build_success=False,
                tests_passed=False,
                details="Assessment only: no patch, build, or post-fix rescan was executed.",
            )
            state.verification_results = [assessment.to_dict()]
            state.terminal_status = "completed"
            state.exit_code = 0
            state.append_audit(
                "ASSESSMENT_COMPLETED", "verifier_agent", assessment.to_dict()
            )
            return state

        branch_to_plan_ids: dict[str, set[str]] = {}
        for patch in state.patches:
            branch = patch.get("branch")
            plan_id = patch.get("plan_id")
            if branch and plan_id:
                branch_to_plan_ids.setdefault(str(branch), set()).add(str(plan_id))

        results: list[dict[str, Any]] = []
        for branch, plan_ids in branch_to_plan_ids.items():
            branch_plans = [plan for plan in state.approved_plans if plan.id in plan_ids]
            finding_ids = {
                finding_id
                for plan in branch_plans
                for finding_id in plan.finding_ids
            }
            branch_findings = [
                finding for finding in state.findings if finding.id in finding_ids
            ]
            branch_tests = [
                result
                for result in state.test_results
                if result.get("branch") == branch
            ]
            ver_res = default_verifier_agent.verify_remediation(
                repo_path=state.repo_path,
                plans=branch_plans,
                before_findings=branch_findings,
                test_results=branch_tests,
                ecosystem=state.ecosystem,
                scanner=state.scanner,
                branch=branch,
            )
            results.append({"branch": branch, **ver_res.to_dict()})
            state.append_audit(
                "RESCAN_EXECUTED", "scan_server",
                {"branch": branch, "revision": ver_res.revision, "success": ver_res.scan_complete},
            )
            for plan in branch_plans:
                plan.verification = ver_res
            for plan in state.plans:
                if plan.id in plan_ids:
                    plan.verification = ver_res

        state.verification_results = results
        verified = bool(results) and all(result["verified"] for result in results)

        # Strict invariant: missing or failed evidence is never reported as success (F22)
        if not verified and state.terminal_status != "pending_approval":
            state.terminal_status = "failed_verification"
            state.exit_code = 30
            details = "; ".join(
                result["details"] or "verification failed" for result in results
            ) or "No patched branch was available for verification"
            state.blocking_reason = f"Verification failed: {details}"
            state.append_audit(
                "VERIFICATION_FAILED",
                "verifier_agent",
                {"branches": state.verification_results, "details": details},
            )
        else:
            if state.terminal_status not in ("pending_approval", "blocked_policy"):
                state.terminal_status = (
                    "completed" if state.mode == "dry-run" else "verified"
                )
                state.exit_code = 0
            state.append_audit("VERIFICATION_COMPLETED", "verifier_agent", {
                "branches": state.verification_results
            })

        return state


def exception_node(state: VulnFlowState) -> VulnFlowState:
    """Escalate policy-blocked findings by opening an exception ticket."""
    state.current_node = "exception"
    with trace_span("orchestrator.node.exception", {"run_id": state.run_id}):
        # Determine specific blocking root causes
        reasons: list[str] = []

        # Check for test/build failures
        failed_tests = [
            r
            for r in state.test_results
            if not r.get("build_clean", True) or not r.get("passed", True)
        ]
        if failed_tests:
            fail_outputs = [
                r.get("output", "").strip() for r in failed_tests if r.get("output")
            ]
            first_err = (
                fail_outputs[0].splitlines()[0]
                if fail_outputs and fail_outputs[0]
                else "Non-zero test exit code"
            )
            reasons.append(
                f"Automated test suite failed ({len(failed_tests)} test run(s) failed): {first_err}"
            )

        # Check for banned or license-denied packages
        banned = [
            p
            for p in state.plans
            if p.policy_result
            and p.policy_result.status
            in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value)
        ]
        if banned:
            banned_pkgs = ", ".join(p.target_package or p.root_cause_id for p in banned)
            reasons.append(f"Organizational policy banned package(s): {banned_pkgs}")

        # Check for unapproved plans
        if not state.approved_plans and not reasons:
            reasons.append(
                "No remediation plans were approved for automatic execution."
            )

        blocking_reason = (
            " | ".join(reasons)
            if reasons
            else "Remediation blocked by automated policy safety gate."
        )
        state.blocking_reason = blocking_reason

        cve_list = sorted({cve for f in state.findings for cve in f.cve if cve})
        target_pkgs = sorted({p.target_package or p.root_cause_id for p in state.plans})
        pkg_summary = ", ".join(target_pkgs) if target_pkgs else "dependencies"

        ticket = ticket_server.ticket_create(
            "security_exception",
            {
                "run_id": state.run_id,
                "repo": state.repo_path,
                "reason": blocking_reason,
                "target_package": pkg_summary,
                "cves": cve_list,
                "plans": [p.to_dict() for p in state.plans],
            },
        )
        state.exception_ticket = ticket
        state.pull_requests = []  # Invariant: unapproved fix never opens PR
        state.terminal_status = "blocked_policy"
        state.exit_code = 20
        state.append_audit(
            "EXCEPTION_ESCALATED",
            "orchestrator",
            {"reason": blocking_reason, "ticket": ticket},
        )
        return state
