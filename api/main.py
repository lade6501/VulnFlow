"""
api/main.py
FastAPI application initialization, middleware setup, and route registration.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict

# Automatically inject src/ and project root into sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
for _p in (str(_SRC_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("vulnflow.api")

from api.routes.approvals import submit_approval
from api.routes.graph import get_graph_data
from api.routes.runs import get_run, list_runs, trigger_run
from api.routes.webhooks import handle_scan_webhook

try:
    from fastapi import APIRouter, FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse

    app = FastAPI(
        title="VulnFlow AI API",
        version="1.0.0",
        description="Autonomous vulnerability remediation platform API",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "healthy", "service": "vulnflow-api"}

    @app.get("/api/runs")
    def api_list_runs(limit: int = 50) -> Dict[str, Any]:
        return {"runs": list_runs(limit=limit)}

    @app.get("/api/runs/{run_id}")
    def api_get_run(run_id: str) -> Dict[str, Any]:
        run = get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return run

    @app.post("/api/runs")
    async def api_trigger_run(request: Request) -> Dict[str, Any]:
        payload = await request.json()
        return trigger_run(payload)

    @app.post("/api/webhooks")
    async def api_webhook(request: Request) -> Dict[str, Any]:
        payload = await request.json()
        return handle_scan_webhook(payload)

    @app.post("/api/approvals/{plan_id}")
    async def api_approval(plan_id: str, request: Request) -> Dict[str, Any]:
        body = await request.json()
        return submit_approval(
            plan_id=plan_id,
            approved=body.get("approved", True),
            reviewer=body.get("reviewer", "security-lead"),
            reason=body.get("reason", "Approved via API"),
            repo_path=body.get("repo_path", "."),
            resume=body.get("resume", True),
        )

    @app.get("/api/graph")
    def api_graph(package: str = "npm:lodash", repo: str = "workspace") -> Dict[str, Any]:
        return get_graph_data(package=package, repo=repo)

except ImportError:
    # Pure-Python ASGI 3 fallback when FastAPI is not installed in the environment
    from urllib.parse import parse_qs

    logger.info("FastAPI not installed; running lightweight zero-dependency ASGI engine.")

    class PurePythonASGIApp:
        async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
            if scope.get("type") != "http":
                return

            method = scope.get("method", "GET").upper()
            path = scope.get("path", "/")
            query_string = scope.get("query_string", b"").decode("utf-8")
            params = parse_qs(query_string)

            # Preflight CORS
            if method == "OPTIONS":
                await self._send_response(send, 200, b"")
                return

            try:
                if path == "/health":
                    await self._send_json(send, 200, {"status": "healthy", "service": "vulnflow-api"})
                elif path == "/api/runs" and method == "GET":
                    limit = int(params.get("limit", [50])[0])
                    await self._send_json(send, 200, {"runs": list_runs(limit=limit)})
                elif path.startswith("/api/runs/") and method == "GET":
                    run_id = path.split("/")[-1]
                    run = get_run(run_id)
                    if run:
                        await self._send_json(send, 200, run)
                    else:
                        await self._send_json(send, 404, {"detail": f"Run {run_id} not found"})
                elif path == "/api/runs" and method == "POST":
                    body = await self._read_json(receive)
                    result = trigger_run(body)
                    await self._send_json(send, 200, result)
                elif path == "/api/webhooks" and method == "POST":
                    body = await self._read_json(receive)
                    result = handle_scan_webhook(body)
                    await self._send_json(send, 200, result)
                elif path.startswith("/api/approvals/") and method == "POST":
                    plan_id = path.split("/")[-1]
                    body = await self._read_json(receive)
                    result = submit_approval(
                        plan_id=plan_id,
                        approved=body.get("approved", True),
                        reviewer=body.get("reviewer", "security-lead"),
                        reason=body.get("reason", "Approved via API"),
                        repo_path=body.get("repo_path", "."),
                        resume=body.get("resume", True),
                    )
                    await self._send_json(send, 200, result)
                elif path == "/api/graph" and method == "GET":
                    pkg = params.get("package", ["npm:lodash"])[0]
                    repo = params.get("repo", ["workspace"])[0]
                    await self._send_json(send, 200, get_graph_data(package=pkg, repo=repo))
                else:
                    await self._send_json(send, 404, {"error": "Not found", "path": path})
            except Exception as exc:
                logger.exception("Error processing request: %s", exc)
                await self._send_json(send, 500, {"error": str(exc)})

        async def _read_json(self, receive: Any) -> Dict[str, Any]:
            body = b""
            more_body = True
            while more_body:
                message = await receive()
                body += message.get("body", b"")
                more_body = message.get("more_body", False)
            return json.loads(body.decode("utf-8")) if body else {}

        async def _send_json(self, send: Any, status: int, data: Any) -> None:
            raw = json.dumps(data).encode("utf-8")
            await self._send_response(send, status, raw, "application/json")

        async def _send_response(
            self, send: Any, status: int, body: bytes, content_type: str = "text/plain"
        ) -> None:
            headers = [
                (b"content-type", content_type.encode("utf-8")),
                (b"content-length", str(len(body)).encode("utf-8")),
                (b"access-control-allow-origin", b"*"),
                (b"access-control-allow-methods", b"GET, POST, OPTIONS, PUT, DELETE"),
                (b"access-control-allow-headers", b"Content-Type, Authorization"),
            ]
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": body})

    app = PurePythonASGIApp()  # type: ignore[assignment]
