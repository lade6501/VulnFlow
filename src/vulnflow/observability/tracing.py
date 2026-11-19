"""
src/vulnflow/observability/tracing.py
Instruments agent workflows and MCP calls using OpenTelemetry spans.
"""

from __future__ import annotations

import contextlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger("vulnflow.observability.tracing")


@dataclass
class SpanRecord:
    """Represents a captured execution span."""

    name: str
    span_id: str
    parent_id: Optional[str]
    start_time: float
    end_time: Optional[float] = None
    duration_ms: float = 0.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "UNSET"  # "OK", "ERROR", "UNSET"
    error_message: Optional[str] = None


class TraceManager:
    """Lightweight tracer that integrates with OpenTelemetry if present or manages local spans."""

    def __init__(self) -> None:
        self.spans: List[SpanRecord] = []
        self._active_stack: List[SpanRecord] = []

    @contextlib.contextmanager
    def span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Generator[SpanRecord, None, None]:
        parent_id = self._active_stack[-1].span_id if self._active_stack else None
        span_id = uuid.uuid4().hex[:16]
        record = SpanRecord(
            name=name,
            span_id=span_id,
            parent_id=parent_id,
            start_time=time.time(),
            attributes=dict(attributes or {}),
        )
        self._active_stack.append(record)
        self.spans.append(record)

        try:
            yield record
            record.status = "OK"
        except Exception as exc:
            record.status = "ERROR"
            record.error_message = str(exc)
            record.attributes["error.type"] = exc.__class__.__name__
            raise
        finally:
            record.end_time = time.time()
            record.duration_ms = round((record.end_time - record.start_time) * 1000.0, 2)
            if self._active_stack and self._active_stack[-1].span_id == span_id:
                self._active_stack.pop()

    def record_llm_call(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        cost_usd: float = 0.0,
        status: str = "OK",
        error: Optional[str] = None,
    ) -> None:
        """Record an LLM call directly as a completed span."""
        span_id = uuid.uuid4().hex[:16]
        parent_id = self._active_stack[-1].span_id if self._active_stack else None
        end_time = time.time()
        start_time = end_time - (latency_ms / 1000.0)

        record = SpanRecord(
            name=f"llm.{provider}.chat",
            span_id=span_id,
            parent_id=parent_id,
            start_time=start_time,
            end_time=end_time,
            duration_ms=latency_ms,
            status=status,
            error_message=error,
            attributes={
                "llm.provider": provider,
                "llm.model": model,
                "llm.usage.prompt_tokens": prompt_tokens,
                "llm.usage.completion_tokens": completion_tokens,
                "llm.usage.total_tokens": prompt_tokens + completion_tokens,
                "llm.cost_usd": cost_usd,
            },
        )
        self.spans.append(record)


# Global tracer instance
global_tracer = TraceManager()
trace_manager = global_tracer

from vulnflow.observability.langsmith_tracer import langsmith_tracer


def trace_span(
    name: str,
    attributes: Optional[Dict[str, Any]] = None,
) -> Any:
    """Convenience context manager for tracing execution blocks."""
    return global_tracer.span(name, attributes)
