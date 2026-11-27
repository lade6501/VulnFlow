"""
src/vulnflow/observability/audit_log.py
Cryptographic hash-chained audit logging for security actions, decisions, and approvals.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vulnflow.core.redaction import redact_structure

logger = logging.getLogger("vulnflow.observability.audit_log")


def compute_event_hash(
    run_id: str,
    event_type: str,
    actor: str,
    payload: Dict[str, Any],
    timestamp: float,
    previous_hash: str,
) -> str:
    """Compute SHA-256 cryptographic hash over an audit event record."""
    canonical_payload = json.dumps(payload, sort_keys=True)
    raw = f"{previous_hash}|{run_id}|{event_type}|{actor}|{canonical_payload}|{timestamp:.6f}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
    previous_hash: str = field(default_factory=lambda: "0" * 64)
    entry_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """
    Manages appending, persisting, and verifying tamper-evident audit trail events
    secured by SHA-256 cryptographic hash chaining.
    """

    def __init__(self, log_dir: Optional[str] = None) -> None:
        self.events: List[AuditEvent] = []
        self._last_hash: Dict[str, str] = {}
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
        """Create and record a secret-redacted audit event with cryptographic hash chaining."""
        safe_payload = redact_structure(payload)
        safe_actor = redact_structure(actor)
        prev_hash = self._last_hash.get(run_id, "0" * 64)
        ts = time.time()
        entry_hash = compute_event_hash(
            run_id=run_id,
            event_type=event_type,
            actor=safe_actor,
            payload=safe_payload,
            timestamp=ts,
            previous_hash=prev_hash,
        )

        event = AuditEvent(
            run_id=run_id,
            event_type=event_type,
            actor=safe_actor,
            payload=safe_payload,
            timestamp=ts,
            previous_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._last_hash[run_id] = entry_hash
        self.events.append(event)
        logger.info(
            "AUDIT [%s] %s by %s (hash: %s): %s",
            run_id,
            event_type,
            safe_actor,
            entry_hash[:12],
            safe_payload,
        )

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

    def verify_chain(self, run_id: str) -> Tuple[bool, Optional[str]]:
        """
        Verify the cryptographic hash chain for a specific run.
        Returns (True, None) if unbroken, or (False, reason) if tampered or corrupt.
        """
        events: List[Dict[str, Any]] = []
        audit_file = self.get_audit_file(run_id)
        if audit_file and audit_file.exists():
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        else:
            events = [e.to_dict() for e in self.get_events(run_id)]

        if not events:
            return True, None

        expected_prev = "0" * 64
        for idx, ev in enumerate(events):
            if ev.get("previous_hash") != expected_prev:
                return (
                    False,
                    f"Hash chain broken at index {idx}: previous_hash {ev.get('previous_hash')[:12]} "
                    f"does not match expected {expected_prev[:12]}",
                )

            computed = compute_event_hash(
                run_id=ev["run_id"],
                event_type=ev["event_type"],
                actor=ev["actor"],
                payload=ev["payload"],
                timestamp=ev["timestamp"],
                previous_hash=expected_prev,
            )
            if ev.get("entry_hash") != computed:
                return (
                    False,
                    f"Tampered record at index {idx}: entry_hash {ev.get('entry_hash')[:12]} "
                    f"does not match recomputed hash {computed[:12]}",
                )

            expected_prev = ev["entry_hash"]

        return True, None

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
                "entry_hash": e.entry_hash[:12] if e.entry_hash else "",
            })
        return timeline

    def prune_expired_logs(self, retention_days: int = 90) -> int:
        """Remove persisted JSONL audit files older than retention_days."""
        if not self.log_dir or not self.log_dir.exists() or retention_days <= 0:
            return 0
        cutoff = time.time() - (retention_days * 86400)
        removed = 0
        for path in self.log_dir.glob("audit_*.jsonl"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError as exc:
                logger.warning("Could not prune expired audit log %s: %s", path, exc)
        return removed


# Global audit logger instance
audit_logger = AuditLogger()
