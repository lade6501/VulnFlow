"""
src/vulnflow/contracts/state.py
Defines state models passed between LangGraph orchestration nodes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from vulnflow.contracts.finding import Finding
from vulnflow.contracts.remediation_plan import RemediationPlan


@dataclass
class VulnFlowState:
    """
    Unified state payload flowing through LangGraph nodes.
    Conforms strictly to Section 6.5 of the VulnFlow specification.
    """

    run_id: str = field(default_factory=lambda: f"RUN-{uuid.uuid4().hex[:12]}")
    repo_path: str = "/workspace"
    report_path: Optional[str] = None
    scanner: str = "trivy"
    mode: str = "pr"  # "report", "pr", "dry-run"
    ecosystem: str = "npm"
    current_node: str = "start"

    # Ingestion & deduplication
    raw_findings: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    deduped_findings: List[Finding] = field(default_factory=list)

    # Root cause analysis & planning
    root_cause_groups: List[Dict[str, Any]] = field(default_factory=list)
    plans: List[RemediationPlan] = field(default_factory=list)

    # Human-in-the-loop approvals
    auto_approve: bool = False
    approved_plans: List[RemediationPlan] = field(default_factory=list)
    rejected_plans: List[RemediationPlan] = field(default_factory=list)
    pending_approval_plans: List[RemediationPlan] = field(default_factory=list)

    # Remediation, testing & PRs
    patches: List[Dict[str, Any]] = field(default_factory=list)
    created_branches: List[str] = field(default_factory=list)
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    pull_requests: List[Dict[str, Any]] = field(default_factory=list)
    verification_results: List[Dict[str, Any]] = field(default_factory=list)

    # Observability & audit trail
    audit_events: List[Dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 2

    # Exit status & reporting
    error: Optional[str] = None
    blocking_reason: Optional[str] = None
    exception_ticket: Optional[Dict[str, Any]] = None
    exit_code: int = 0  # 0=clean/resolved, 10=pending approval, 20=blocked, 30=verification failed, 1=error
    terminal_status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the complete resumable workflow state.

        Count fields are retained for backwards-compatible reporting, but a checkpoint
        must also contain the underlying findings and audit evidence.  Persisting only
        counts made approval resumes unverifiable because the verifier received an
        empty pre-remediation baseline.
        """
        return {
            "run_id": self.run_id,
            "repo_path": self.repo_path,
            "report_path": self.report_path,
            "scanner": self.scanner,
            "mode": self.mode,
            "ecosystem": self.ecosystem,
            "current_node": self.current_node,
            "raw_findings": self.raw_findings,
            "findings": [finding.to_dict() for finding in self.findings],
            "deduped_findings": [
                finding.to_dict() for finding in self.deduped_findings
            ],
            "raw_findings_count": len(self.raw_findings),
            "findings_count": len(self.findings),
            "deduped_findings_count": len(self.deduped_findings),
            "root_cause_groups": self.root_cause_groups,
            "plans": [p.to_dict() for p in self.plans],
            "approved_plans": [p.to_dict() for p in self.approved_plans],
            "rejected_plans": [p.to_dict() for p in self.rejected_plans],
            "pending_approval_plans": [p.to_dict() for p in self.pending_approval_plans],
            "patches": self.patches,
            "created_branches": self.created_branches,
            "test_results": self.test_results,
            "pull_requests": self.pull_requests,
            "verification_results": self.verification_results,
            "audit_events": self.audit_events,
            "audit_events_count": len(self.audit_events),
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "auto_approve": self.auto_approve,
            "error": self.error,
            "blocking_reason": self.blocking_reason,
            "exception_ticket": self.exception_ticket,
            "exit_code": self.exit_code,
            "terminal_status": self.terminal_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VulnFlowState:
        """Reconstruct VulnFlowState from a dictionary."""
        state = cls(
            repo_path=data.get("repo_path", "."),
            report_path=data.get("report_path"),
            scanner=data.get("scanner", "trivy"),
            mode=data.get("mode", "pr"),
            ecosystem=data.get("ecosystem", "npm"),
        )
        if "run_id" in data:
            state.run_id = data["run_id"]
        if "current_node" in data:
            state.current_node = data["current_node"]
        if "raw_findings" in data:
            state.raw_findings = list(data["raw_findings"])
        if "findings" in data:
            state.findings = [
                Finding.from_dict(finding) if isinstance(finding, dict) else finding
                for finding in data["findings"]
            ]
        if "deduped_findings" in data:
            state.deduped_findings = [
                Finding.from_dict(finding) if isinstance(finding, dict) else finding
                for finding in data["deduped_findings"]
            ]
        if "root_cause_groups" in data:
            state.root_cause_groups = data["root_cause_groups"]
        if "plans" in data:
            state.plans = [RemediationPlan.from_dict(p) if isinstance(p, dict) else p for p in data["plans"]]
        if "approved_plans" in data:
            state.approved_plans = [RemediationPlan.from_dict(p) if isinstance(p, dict) else p for p in data["approved_plans"]]
        if "rejected_plans" in data:
            state.rejected_plans = [RemediationPlan.from_dict(p) if isinstance(p, dict) else p for p in data["rejected_plans"]]
        if "pending_approval_plans" in data:
            state.pending_approval_plans = [RemediationPlan.from_dict(p) if isinstance(p, dict) else p for p in data["pending_approval_plans"]]
        if "patches" in data:
            state.patches = data["patches"]
        if "created_branches" in data:
            state.created_branches = data["created_branches"]
        if "test_results" in data:
            state.test_results = data["test_results"]
        if "pull_requests" in data:
            state.pull_requests = data["pull_requests"]
        if "verification_results" in data:
            state.verification_results = data["verification_results"]
        if "audit_events" in data:
            state.audit_events = list(data["audit_events"])
        if "retry_count" in data:
            state.retry_count = data["retry_count"]
        if "max_retries" in data:
            state.max_retries = data["max_retries"]
        if "auto_approve" in data:
            state.auto_approve = bool(data["auto_approve"])
        if "error" in data:
            state.error = data["error"]
        if "blocking_reason" in data:
            state.blocking_reason = data["blocking_reason"]
        if "exception_ticket" in data:
            state.exception_ticket = data["exception_ticket"]
        if "exit_code" in data:
            state.exit_code = data["exit_code"]
        if "terminal_status" in data:
            state.terminal_status = data["terminal_status"]
        return state

    def append_audit(self, event_type: str, actor: str, payload: Dict[str, Any]) -> None:
        """Append an event to the state's audit trail and central persistent audit log."""
        import time
        from vulnflow.observability.audit_log import audit_logger

        event_dict = {
            "timestamp": time.time(),
            "run_id": self.run_id,
            "node": self.current_node,
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
        }
        persisted_event = audit_logger.log(
            run_id=self.run_id,
            event_type=event_type,
            actor=actor,
            payload={"node": self.current_node, **payload},
        )
        event_dict["previous_hash"] = persisted_event.previous_hash
        event_dict["entry_hash"] = persisted_event.entry_hash
        self.audit_events.append(event_dict)
