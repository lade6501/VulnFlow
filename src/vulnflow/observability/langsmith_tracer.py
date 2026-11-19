"""
src/vulnflow/observability/langsmith_tracer.py
LangSmith distributed tracing and observability integration for VulnFlow.
Enables end-to-end trace collection, agent node execution spans, and LLM call telemetry.
Resilient design: integrates with official langsmith SDK if present, or zero-dependency background HTTP dispatcher.
"""

from __future__ import annotations

import atexit
import datetime
import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

# Ensure .env is loaded before inspecting environment variables
from vulnflow.core import dotenv

logger = logging.getLogger("vulnflow.observability.langsmith")


class LangSmithTracer:
    """Manages LangSmith session telemetry, runs, and span export."""

    def __init__(self) -> None:
        self.api_key: Optional[str] = None
        self.project: str = "vulnflow"
        self.endpoint: str = "https://api.smith.langchain.com"
        self.enabled: bool = False
        self._sdk_client: Any = None
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._worker_thread: Optional[threading.Thread] = None
        self._shutdown_flag: bool = False
        self._active_runs: Dict[str, Dict[str, Any]] = {}
        self.init_from_env()

    def init_from_env(self) -> bool:
        """Initialize LangSmith credentials from standard environment variables."""
        dotenv.load_dotenv()

        raw_key = (
            os.getenv("LANGSMITH_API_KEY")
            or os.getenv("LANGCHAIN_API_KEY")
            or os.getenv("VULNFLOW_LANGSMITH_API_KEY")
        )
        self.api_key = raw_key.strip().strip("'\"") if raw_key else None

        raw_proj = (
            os.getenv("LANGCHAIN_PROJECT")
            or os.getenv("LANGSMITH_PROJECT")
            or os.getenv("VULNFLOW_LANGSMITH_PROJECT")
            or "vulnflow"
        )
        self.project = raw_proj.strip().strip("'\"")

        self.endpoint = (
            os.getenv("LANGCHAIN_ENDPOINT")
            or os.getenv("LANGSMITH_ENDPOINT")
            or "https://api.smith.langchain.com"
        ).rstrip("/")

        # Tracing is active if an API key is present and not explicitly disabled
        explicit_flag = os.getenv("LANGCHAIN_TRACING_V2", "").lower()
        if self.api_key and explicit_flag != "false":
            self.enabled = True
            # Export standard LangChain environment variables so LangGraph also auto-traces
            os.environ["LANGCHAIN_TRACING_V2"] = "true"
            os.environ["LANGCHAIN_API_KEY"] = self.api_key
            os.environ["LANGSMITH_API_KEY"] = self.api_key
            os.environ["LANGCHAIN_PROJECT"] = self.project
            os.environ["LANGCHAIN_ENDPOINT"] = self.endpoint

            self._try_init_sdk()
            self._start_worker()
            # Ensure the project exists in LangSmith
            self._ensure_project_exists()
            logger.info("LangSmith tracing enabled for project '%s'", self.project)
            return True
        elif explicit_flag == "true":
            self.enabled = True
            self._start_worker()
            return True

        self.enabled = False
        return False

    def _ensure_project_exists(self) -> None:
        """Proactively create the project session in LangSmith so it appears in the Web UI immediately."""
        if not self.api_key:
            return
        # Dispatch project creation in worker queue
        self._queue.put((
            "POST",
            f"{self.endpoint}/sessions",
            {
                "name": self.project,
                "description": "VulnFlow Autonomous Security Remediation Platform",
            },
        ))

    def _try_init_sdk(self) -> None:
        """Attempt to initialize official langsmith Client if installed."""
        try:
            import langsmith  # type: ignore

            self._sdk_client = langsmith.Client(
                api_key=self.api_key,
                api_url=self.endpoint,
            )
            logger.debug("Initialized official langsmith SDK client v%s", getattr(langsmith, "__version__", ""))
        except Exception:
            self._sdk_client = None

    def _start_worker(self) -> None:
        """Start asynchronous background worker to send spans without adding latency."""
        if self._worker_thread is None or not self._worker_thread.is_alive():
            self._shutdown_flag = False
            self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
            self._worker_thread.start()
            atexit.register(self.flush)

    def _worker_loop(self) -> None:
        """Worker thread processing outbound LangSmith trace payloads."""
        while not self._shutdown_flag or not self._queue.empty():
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                method, url, payload = item
                self._http_request(url, payload, method=method)
            except Exception as exc:
                logger.debug("Failed to dispatch trace to LangSmith: %s", exc)
            finally:
                self._queue.task_done()

    def _http_request(self, url: str, data: Dict[str, Any], method: str = "POST") -> Optional[Dict[str, Any]]:
        """Send JSON payload to LangSmith HTTP API with specified HTTP method."""
        if not self.api_key:
            return None
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
                "User-Agent": "VulnFlow-LangSmith-Adapter/1.0",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                resp_bytes = resp.read()
                return json.loads(resp_bytes.decode("utf-8")) if resp_bytes else {}
        except urllib.error.HTTPError as err:
            # 409 Conflict simply means project session already exists, which is expected
            if err.code != 409:
                try:
                    err_body = err.read().decode("utf-8")
                    logger.debug("LangSmith HTTP %d: %s - %s", err.code, err.reason, err_body)
                except Exception:
                    logger.debug("LangSmith HTTP %d: %s (url: %s)", err.code, err.reason, url)
        except Exception as exc:
            logger.debug("LangSmith dispatch notice: %s", exc)
        return None

    def is_enabled(self) -> bool:
        """Return True if LangSmith tracing is currently active."""
        return self.enabled and bool(self.api_key)

    def get_run_url(self, run_id: str) -> Optional[str]:
        """Construct the web URL for viewing the run trace in LangSmith dashboard."""
        if not self.is_enabled():
            return None
        return f"https://smith.langchain.com/projects/p/{self.project}?search={run_id}"

    def start_workflow_run(
        self,
        run_id: str,
        name: str = "vulnflow.workflow",
        inputs: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record the start of a root workflow run."""
        if not self.is_enabled():
            return run_id

        trace_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"vulnflow.run.{run_id}"))
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        run_data = {
            "id": trace_uuid,
            "name": name,
            "run_type": "chain",
            "start_time": now_iso,
            "inputs": inputs or {},
            "tags": list(tags or []) + ["vulnflow", "autonomous-remediation"],
            "extra": {
                "metadata": {
                    "vulnflow_run_id": run_id,
                    **(metadata or {}),
                },
                "project_name": self.project,
            },
            "session_name": self.project,
        }

        self._active_runs[run_id] = {
            "uuid": trace_uuid,
            "start_time": time.time(),
            "name": name,
        }

        self._queue.put(("POST", f"{self.endpoint}/runs", run_data))
        return trace_uuid

    def end_workflow_run(
        self,
        run_id: str,
        outputs: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        status: str = "COMPLETED",
    ) -> None:
        """Record the completion of a root workflow run."""
        if not self.is_enabled() or run_id not in self._active_runs:
            return

        run_info = self._active_runs.pop(run_id)
        trace_uuid = run_info["uuid"]
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Direct PATCH payload adhering strictly to LangSmith RunUpdate schema (no "id" field in body)
        patch_data = {
            "end_time": now_iso,
            "outputs": {
                "status": status,
                **(outputs or {}),
            },
            "error": error,
        }

        # Primary PATCH endpoint (/runs/{id})
        self._queue.put(("PATCH", f"{self.endpoint}/runs/{trace_uuid}", patch_data))

        # 2. Secondary batch patch fallback (/runs/batch) as used by official LangSmith SDK
        batch_patch = {
            "patch": [
                {
                    "id": trace_uuid,
                    "end_time": now_iso,
                    "outputs": {
                        "status": status,
                        **(outputs or {}),
                    },
                    "error": error,
                }
            ]
        }
        self._queue.put(("POST", f"{self.endpoint}/runs/batch", batch_patch))

    def record_node_span(
        self,
        workflow_run_id: str,
        node_name: str,
        inputs: Optional[Dict[str, Any]] = None,
        outputs: Optional[Dict[str, Any]] = None,
        duration_ms: float = 0.0,
        error: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Record a discrete agent or orchestrator node execution as a child span."""
        if not self.is_enabled():
            return

        parent_uuid = self._active_runs.get(workflow_run_id, {}).get("uuid")
        span_uuid = str(uuid.uuid4())

        end_dt = datetime.datetime.now(datetime.timezone.utc)
        start_dt = end_dt - datetime.timedelta(milliseconds=max(1.0, duration_ms))

        span_data = {
            "id": span_uuid,
            "name": f"vulnflow.node.{node_name}",
            "run_type": "tool",
            "start_time": start_dt.isoformat(),
            "end_time": end_dt.isoformat(),
            "inputs": inputs or {},
            "outputs": outputs or {},
            "error": error,
            "parent_run_id": parent_uuid,
            "tags": list(tags or []) + ["node", node_name],
            "extra": {
                "metadata": {
                    "workflow_run_id": workflow_run_id,
                    "duration_ms": duration_ms,
                },
                "project_name": self.project,
            },
            "session_name": self.project,
        }

        self._queue.put(("POST", f"{self.endpoint}/runs", span_data))

    def flush(self, timeout: float = 6.0) -> None:
        """Wait for pending trace items to be posted to LangSmith."""
        try:
            self._queue.join()
        except Exception:
            pass
        time.sleep(0.3)


# Global singleton instance
langsmith_tracer = LangSmithTracer()
