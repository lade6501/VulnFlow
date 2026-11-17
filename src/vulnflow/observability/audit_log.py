"""
src/vulnflow/observability/audit_log.py
Records immutable audit logs for all security actions, agent decisions, and human approvals.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vulnflow.observability.audit_log")


@dataclass
class AuditEvent:
    """Immutable audit record documenting a critical security action or decision."""

    run_id: str
    event_type: str
    actor: str
    payload: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    iso_time: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """Manages appending, persisting, and retrieving audit trail events for compliance and verification."""

    def __init__(self, log_dir: Optional[str] = None) -> None:
        self.events: List[AuditEvent] = []
        target_dir = log_dir or os.environ.get("VULNFLOW_AUDIT_DIR", ".vulnflow/audit")
        self.log_dir = Path(target_dir) if target_dir else None
        if self.log_dir:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                logger.warning("Could not create audit directory %s: %s", self.log_dir, exc)
                self.log_dir = None

    def log(
        self,
        run_id: str,
        event_type: str,
        actor: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        """Create and record an audit event to memory and JSONL persistent storage."""
        event = AuditEvent(
            run_id=run_id,
            event_type=event_type,
            actor=actor,
            payload=payload,
        )
        self.events.append(event)
        logger.info("AUDIT [%s] %s by %s: %s", run_id, event_type, actor, payload)

        if self.log_dir:
            out_file = self.log_dir / f"audit_{run_id}.jsonl"
            try:
                with open(out_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event.to_dict()) + "\n")
            except Exception as exc:
                logger.error("Failed to persist audit log to %s: %s", out_file, exc)

        return event

    def get_events(self, run_id: Optional[str] = None) -> List[AuditEvent]:
        """Return all recorded audit events, optionally filtered by run_id."""
        if run_id:
            return [e for e in self.events if e.run_id == run_id]
        return list(self.events)

    def get_audit_file(self, run_id: str) -> Optional[Path]:
        """Return the path to the persistent audit JSONL file for a run."""
        if not self.log_dir:
            return None
        out_file = self.log_dir / f"audit_{run_id}.jsonl"
        return out_file if out_file.exists() else None

    def format_timeline(self, run_id: str) -> List[Dict[str, Any]]:
        """Return a chronological sequence of actions for a given run."""
        events = self.get_events(run_id)
        timeline = []
        for e in events:
            dt = datetime.datetime.fromtimestamp(e.timestamp, tz=datetime.timezone.utc)
            timeline.append({
                "time": dt.strftime("%H:%M:%S.%f")[:-3],
                "event_type": e.event_type,
                "actor": e.actor,
                "payload": e.payload,
            })
        return timeline


# Global audit logger instance
audit_logger = AuditLogger()
