"""
api/routes/approvals.py
API endpoints for listing and submitting human approval or rejection of plans.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.contracts.remediation_plan import RemediationPlan
from vulnflow.orchestrator.approval import global_approval_gate, load_run_state
from vulnflow.orchestrator.graph import run_workflow
from vulnflow.reporting.markdown import write_markdown_report
from vulnflow.store.run_store import default_run_store

logger = logging.getLogger("vulnflow.api.approvals")


def list_pending_approvals(repo_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all remediation plans currently awaiting human review."""
    pending: List[Dict[str, Any]] = []
    seen_ids = set()

    # 1. In-memory pending plans from global_approval_gate
    for plan_id, plan in list(global_approval_gate._pending_plans.items()):
        if not global_approval_gate.is_approved(plan_id, repo_path=repo_path) and not global_approval_gate.is_rejected(plan_id, repo_path=repo_path):
            seen_ids.add(plan_id)
            diff_snippet = ""
            if plan.evidence and isinstance(plan.evidence[0], dict):
                diff_snippet = plan.evidence[0].get("diff", "")
            pending.append({
                "id": plan.id,
                "repo": repo_path or "workspace",
                "targetPackage": plan.target_package or plan.root_cause_id,
                "currentVersion": "unknown",
                "proposedVersion": plan.target_version or "N/A",
                "action": plan.action.value.upper() if hasattr(plan.action, "value") else str(plan.action).upper(),
                "riskTier": plan.risk_tier.value.upper() if hasattr(plan.risk_tier, "value") else str(plan.risk_tier).upper(),
                "reason": plan.policy_result.reason if plan.policy_result else "Requires human security review.",
                "rationale": plan.rationale,
                "diff": diff_snippet or "--- manifest\n+++ manifest\n+ Proposed secure update",
            })

    # 2. Check pending state files on disk in .vulnflow directories
    search_dirs = [Path(".vulnflow"), Path("../fake-vuln-repo/.vulnflow"), Path("fake-vuln-repo/.vulnflow")]
    if repo_path:
        search_dirs.insert(0, Path(repo_path) / ".vulnflow")

    for s_dir in search_dirs:
        p_state_f = s_dir / "pending_state.json"
        if p_state_f.exists():
            try:
                with open(p_state_f, "r", encoding="utf-8") as fp:
                    st_data = json.load(fp)
                target_repo = st_data.get("repo_path", str(s_dir.parent))
                for p_dict in st_data.get("pending_approval_plans", []):
                    p_id = p_dict.get("id")
                    if p_id and p_id not in seen_ids:
                        if not global_approval_gate.is_approved(p_id, repo_path=target_repo) and not global_approval_gate.is_rejected(p_id, repo_path=target_repo):
                            seen_ids.add(p_id)
                            diff_snippet = ""
                            ev_list = p_dict.get("evidence", [])
                            if ev_list and isinstance(ev_list[0], dict):
                                diff_snippet = ev_list[0].get("diff", "")
                            pending.append({
                                "id": p_id,
                                "repo": target_repo,
                                "targetPackage": p_dict.get("target_package", p_dict.get("root_cause_id")),
                                "currentVersion": p_dict.get("installed_version", "hardcoded"),
                                "proposedVersion": p_dict.get("target_version", "env-var"),
                                "action": str(p_dict.get("action", "ROTATE")).upper(),
                                "riskTier": str(p_dict.get("risk_tier", "REVIEW")).upper(),
                                "reason": p_dict.get("policy_result", {}).get("reason") if p_dict.get("policy_result") else "Plaintext secret or credential requiring security rotation.",
                                "rationale": p_dict.get("rationale", ""),
                                "diff": diff_snippet or "--- file\n+++ file\n- Hardcoded plaintext credential\n+ Migrated to environment variable",
                            })
            except Exception as exc:
                logger.debug("Could not read pending state file %s: %s", p_state_f, exc)

    return pending


def submit_approval(
    plan_id: str,
    approved: bool,
    reviewer: str = "security-lead",
    reason: str = "Approved via API",
    repo_path: str = ".",
    resume: bool = True,
) -> Dict[str, Any]:
    """Record an approval or rejection decision and optionally resume workflow."""
    effective_repo = repo_path
    if effective_repo in (".", "workspace"):
        for cand in (Path("../fake-vuln-repo"), Path("fake-vuln-repo")):
            if (cand / ".vulnflow" / "pending_state.json").exists():
                effective_repo = str(cand)
                break

    global_approval_gate.record_decision(
        plan_id=plan_id,
        approved=approved,
        reviewer=reviewer,
        reason=reason,
        repo_path=effective_repo,
    )

    result_payload: Dict[str, Any] = {
        "plan_id": plan_id,
        "approved": approved,
        "reviewer": reviewer,
        "reason": reason,
    }

    if approved and resume:
        saved_state = load_run_state(repo_path=effective_repo)
        if saved_state:
            resumed_state = run_workflow(saved_state)
            default_run_store.save_run(resumed_state)
            try:
                reports_dir = Path(".vulnflow/reports")
                reports_dir.mkdir(parents=True, exist_ok=True)
                write_markdown_report(resumed_state, reports_dir / f"report_{resumed_state.run_id}.md")
            except Exception as exc:
                logger.warning("Could not write updated report on resumption: %s", exc)
            result_payload["run_id"] = resumed_state.run_id
            result_payload["terminal_status"] = resumed_state.terminal_status
            result_payload["prs_opened"] = len(resumed_state.pull_requests)

    return result_payload
