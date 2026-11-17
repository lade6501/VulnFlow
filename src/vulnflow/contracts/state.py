"""
src/vulnflow/contracts/state.py
Defines state models passed between LangGraph orchestration nodes.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
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
    approved_plans: List[RemediationPlan] = field(default_factory=list)
    rejected_plans: List[RemediationPlan] = field(default_factory=list)

    # Remediation, testing & PRs
    patches: List[Dict[str, Any]] = field(default_factory=list)
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    pull_requests: List[Dict[str, Any]] = field(default_factory=list)
    verification_results: List[Dict[str, Any]] = field(default_factory=list)

    # Observability & audit trail
    audit_events: List[Dict[str, Any]] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 2

    # Exit status & reporting
    error: Optional[str] = None
    exit_code: int = 0  # 0=clean/resolved, 10=pending approval, 20=blocked, 30=verification failed, 1=error
    terminal_status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize state object for persistence or logging."""
        return {
            "run_id": self.run_id,
            "repo_path": self.repo_path,
            "report_path": self.report_path,
            "scanner": self.scanner,
            "mode": self.mode,
            "ecosystem": self.ecosystem,
            "current_node": self.current_node,
            "raw_findings_count": len(self.raw_findings),
            "findings_count": len(self.findings),
            "deduped_findings_count": len(self.deduped_findings),
            "root_cause_groups": self.root_cause_groups,
            "plans": [p.to_dict() for p in self.plans],
            "approved_plans": [p.to_dict() for p in self.approved_plans],
            "rejected_plans": [p.to_dict() for p in self.rejected_plans],
            "patches": self.patches,
            "test_results": self.test_results,
            "pull_requests": self.pull_requests,
            "verification_results": self.verification_results,
            "audit_events_count": len(self.audit_events),
            "retry_count": self.retry_count,
            "error": self.error,
            "exit_code": self.exit_code,
            "terminal_status": self.terminal_status,
        }

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
        self.audit_events.append(event_dict)
        audit_logger.log(
            run_id=self.run_id,
            event_type=event_type,
            actor=actor,
            payload={"node": self.current_node, **payload},
        )
