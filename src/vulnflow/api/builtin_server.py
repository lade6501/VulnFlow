"""
src/vulnflow/api/builtin_server.py
Zero-dependency, multi-threaded HTTP server for VulnFlow Web Dashboard and API.
Runs out of the box with Python standard library (no uvicorn or fastapi required).
"""

from __future__ import annotations

import http.server
import json
import logging
import mimetypes
from pathlib import Path
import sys
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlparse

# Ensure project root is in sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT / "vulnflow") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "vulnflow"))

from api.routes.approvals import list_pending_approvals, submit_approval
from api.routes.graph import get_graph_data
from api.routes.runs import get_run, get_run_report, list_runs, trigger_run
from api.routes.webhooks import handle_scan_webhook

logger = logging.getLogger("vulnflow.api.server")


class VulnFlowBuiltinHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler routing /api/* calls and serving static UI assets."""

    server_version = "VulnFlow-Server/1.0"
    dist_dir: Path = Path()

    def log_message(self, format: str, *args: Any) -> None:
        """Redirect request logging to python logging module at DEBUG level."""
        logger.debug("%s - %s", self.address_string(), format % args)

    def _set_cors_headers(self, content_type: str = "application/json", length: int = 0) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def _send_json(self, status: int, data: Any) -> None:
        raw = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self._set_cors_headers(content_type="application/json; charset=utf-8", length=len(raw))
        self.wfile.write(raw)

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self._set_cors_headers(content_type=content_type, length=len(body))
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests."""
        self.send_response(200)
        self._set_cors_headers(content_type="text/plain", length=0)

    def do_GET(self) -> None:
        """Handle GET requests for API endpoints and static frontend assets."""
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        params = parse_qs(parsed.query)

        try:
            # 1. Health check
            if path == "/health":
                self._send_json(200, {"status": "healthy", "service": "vulnflow-api", "engine": "builtin"})
                return

            # 2. List runs
            if path == "/api/runs":
                limit = int(params.get("limit", [50])[0])
                self._send_json(200, {"runs": list_runs(limit=limit)})
                return

            # 3. Single run report
            if path.startswith("/api/runs/") and path.endswith("/report"):
                parts = path.strip("/").split("/")
                if len(parts) >= 3:
                    run_id = parts[2]
                    report = get_run_report(run_id)
                    if report:
                        self._send_json(200, {"run_id": run_id, "report": report})
                    else:
                        self._send_json(404, {"detail": f"Report for run {run_id} not found"})
                    return

            # 4. Single run details
            if path.startswith("/api/runs/"):
                run_id = path.strip("/").split("/")[-1]
                run_data = get_run(run_id)
                if run_data:
                    self._send_json(200, run_data)
                else:
                    self._send_json(404, {"detail": f"Run {run_id} not found"})
                return

            # 5. List approvals
            if path == "/api/approvals":
                repo = params.get("repo", [""])[0]
                self._send_json(200, {"plans": list_pending_approvals(repo_path=repo or None)})
                return

            # 6. Graph data
            if path == "/api/graph":
                pkg = params.get("package", ["npm:lodash"])[0]
                repo = params.get("repo", ["workspace"])[0]
                self._send_json(200, get_graph_data(package=pkg, repo=repo))
                return

            # 7. Static files and SPA fallback
            self._serve_static_or_spa(path)

        except Exception as exc:
            logger.exception("Error handling GET %s: %s", path, exc)
            self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:
        """Handle POST requests for API actions."""
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        try:
            content_len = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_len) if content_len > 0 else b"{}"
            try:
                body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except Exception:
                body = {}

            # 1. Trigger run
            if path == "/api/runs":
                res = trigger_run(body)
                self._send_json(200, res)
                return

            # 2. Scanner Webhook
            if path == "/api/webhooks":
                res = handle_scan_webhook(body)
                self._send_json(200, res)
                return

            # 3. Approve plan
            if path.startswith("/api/approvals/"):
                plan_id = path.strip("/").split("/")[-1]
                res = submit_approval(
                    plan_id=plan_id,
                    approved=body.get("approved", True),
                    reviewer=body.get("reviewer", "security-lead"),
                    reason=body.get("reason", "Approved via API"),
                    repo_path=body.get("repo_path", "."),
                    resume=body.get("resume", True),
                )
                self._send_json(200, res)
                return

            self._send_json(404, {"error": "Endpoint not found", "path": path})

        except Exception as exc:
            logger.exception("Error handling POST %s: %s", path, exc)
            self._send_json(500, {"error": str(exc)})

    def _serve_static_or_spa(self, path: str) -> None:
        """Serve built static assets or fallback to index.html for client-side routing."""
        dist = self.dist_dir

        if not dist.exists() or not (dist / "index.html").exists():
            placeholder = """<!DOCTYPE html>
<html>
<head><title>VulnFlow Control Plane</title></head>
<body style="font-family:sans-serif;padding:3rem;background:#0b0f19;color:#e2e8f0;">
    <h1 style="color:#38bdf8;">🛡️ VulnFlow AI Engine</h1>
    <p>API is active and running on built-in server.</p>
    <p>To access the full Web Dashboard, build the frontend UI: <code>cd ui && npm run build</code>.</p>
    <div style="margin-top:1.5rem;">
        <a href="/api/runs" style="color:#38bdf8;margin-right:1rem;">Recent Runs JSON</a>
        <a href="/api/approvals" style="color:#38bdf8;">Pending Approvals JSON</a>
    </div>
</body>
</html>"""
            self._send_bytes(200, placeholder.encode("utf-8"), "text/html; charset=utf-8")
            return

        rel = path.lstrip("/")
        target_file = dist / rel if rel else dist / "index.html"

        # If requesting a specific file that exists, serve it
        if target_file.is_file():
            ctype, _ = mimetypes.guess_type(str(target_file))
            content_type = ctype or "application/octet-stream"
            if target_file.suffix == ".html":
                content_type = "text/html; charset=utf-8"
            elif target_file.suffix == ".js":
                content_type = "application/javascript; charset=utf-8"
            elif target_file.suffix == ".css":
                content_type = "text/css; charset=utf-8"
            elif target_file.suffix == ".svg":
                content_type = "image/svg+xml"

            self._send_bytes(200, target_file.read_bytes(), content_type)
            return

        # Otherwise SPA fallback (return index.html)
        index_file = dist / "index.html"
        self._send_bytes(200, index_file.read_bytes(), "text/html; charset=utf-8")


def run_builtin_server(host: str = "0.0.0.0", port: int = 8000, dist_dir: Optional[Path] = None) -> None:
    """Start the multi-threaded HTTP server."""
    if dist_dir is None:
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        dist_dir = repo_root / "vulnflow" / "ui" / "dist"

    VulnFlowBuiltinHandler.dist_dir = dist_dir

    server = http.server.ThreadingHTTPServer((host, port), VulnFlowBuiltinHandler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    finally:
        server.server_close()
