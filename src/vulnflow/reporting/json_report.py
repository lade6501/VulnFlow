"""
src/vulnflow/reporting/json_report.py
Exports structured JSON reports containing findings grouped by root cause and remediation status.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Union

from vulnflow.contracts.state import VulnFlowState


def generate_json_report(state: VulnFlowState) -> Dict[str, Any]:
    """
    Format a structured JSON vulnerability report from workflow state.
    Groups findings by root cause parent and shows policy results and risk tiers.
    """
    groups_payload: List[Dict[str, Any]] = []

    for grp in state.root_cause_groups:
        rc_id = grp.get("root_cause_id", "")
        matched_plan = next((p for p in state.plans if p.root_cause_id == rc_id), None)

        groups_payload.append({
            "root_cause_id": rc_id,
            "root_cause_package": grp.get("root_cause_package", rc_id.replace("PKG-", "")),
            "is_direct": grp.get("is_direct", True),
            "explanation": grp.get("explanation", ""),
            "plan": matched_plan.to_dict() if matched_plan else None,
            "policy_result": matched_plan.policy_result.to_dict() if matched_plan and matched_plan.policy_result else None,
            "risk_tier": matched_plan.risk_tier.value if matched_plan else "auto",
            "findings_count": len(grp.get("findings", [])),
            "findings": grp.get("findings", []),
        })

    return {
        "schema_version": "1.0.0",
        "run_id": state.run_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "repository": state.repo_path,
        "mode": state.mode,
        "scanner": state.scanner,
        "status": state.terminal_status,
        "exit_code": state.exit_code,
        "blocking_reason": state.blocking_reason,
        "exception_ticket": state.exception_ticket,
        "summary": {
            "raw_findings_count": len(state.findings),
            "deduped_findings_count": len(state.deduped_findings),
            "root_cause_groups_count": len(state.root_cause_groups),
            "plans_generated_count": len(state.plans),
            "plans_approved_count": len(state.approved_plans),
            "patches_applied_count": len(state.patches),
            "pull_requests_opened_count": len(state.pull_requests),
        },
        "root_cause_groups": groups_payload,
        "pull_requests": state.pull_requests,
        "verification": state.verification_results[0] if state.verification_results else None,
        "audit_events_count": len(state.audit_events),
    }


def write_json_report(state: VulnFlowState, output_path: Union[str, Path]) -> Path:
    """Serialize and write JSON report to disk."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    report_dict = generate_json_report(state)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)
    return out
