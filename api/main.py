"""
api/main.py
FastAPI application initialization, middleware setup, and route registration.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

# Automatically inject src/ and project root into sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
for _p in (str(_SRC_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

logger = logging.getLogger("vulnflow.api")

from api.routes.approvals import list_pending_approvals, submit_approval
from api.routes.graph import get_graph_data
from api.routes.runs import get_run, get_run_report, list_runs, trigger_run
from api.routes.webhooks import handle_scan_webhook
from vulnflow.contracts.approval import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    PendingApprovalListResponse,
)

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware

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
    def health() -> dict[str, str]:
        return {"status": "healthy", "service": "vulnflow-api"}

    @app.get("/api/runs")
    def api_list_runs(limit: int = 50) -> dict[str, Any]:
        return {"runs": list_runs(limit=limit)}

    @app.get("/api/runs/{run_id}")
    def api_get_run(run_id: str) -> dict[str, Any]:
        run = get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
        return run

    @app.get("/api/runs/{run_id}/report")
    def api_get_run_report(run_id: str) -> dict[str, Any]:
        report = get_run_report(run_id)
        if not report:
            raise HTTPException(
                status_code=404, detail=f"Report for run {run_id} not found"
            )
        return {"run_id": run_id, "report": report}

    @app.post("/api/runs")
    async def api_trigger_run(request: Request) -> dict[str, Any]:
        payload = await request.json()
        return trigger_run(payload)

    @app.post("/api/webhooks")
    async def api_webhook(request: Request) -> dict[str, Any]:
        payload = await request.json()
        return handle_scan_webhook(payload)

    @app.get("/api/approvals", response_model=PendingApprovalListResponse)
    def api_list_approvals(repo: str = "") -> PendingApprovalListResponse:
        return PendingApprovalListResponse(
            plans=list_pending_approvals(repo_path=repo or None)
        )

    @app.post("/api/approvals/{plan_id}", response_model=ApprovalDecisionResponse)
    def api_approval(
        plan_id: str, body: ApprovalDecisionRequest
    ) -> ApprovalDecisionResponse:
        return submit_approval(
            plan_id=plan_id,
            approved=body.approved,
            reviewer=body.reviewer,
            reviewer_group=body.reviewer_group,
            reason=body.reason,
            repo_path=body.repo_path,
            resume=body.resume,
        )

    @app.get("/api/graph")
    def api_graph(
        package: str = "npm:lodash", repo: str = "workspace"
    ) -> dict[str, Any]:
        return get_graph_data(package=package, repo=repo)

    # Mount static frontend dashboard build if available
    _UI_DIST = _REPO_ROOT / "ui" / "dist"
    if _UI_DIST.exists() and (_UI_DIST / "index.html").exists():
        try:
            from fastapi.staticfiles import StaticFiles

            app.mount(
                "/", StaticFiles(directory=str(_UI_DIST), html=True), name="static_ui"
            )
            logger.info("Mounted static UI dashboard from %s", _UI_DIST)
        except Exception as _e:
            logger.warning("Could not mount static UI files: %s", _e)
    else:
        from fastapi.responses import HTMLResponse

        @app.get("/", response_class=HTMLResponse)
        def ui_placeholder() -> str:
            return """
            <!DOCTYPE html>
            <html>
            <head><title>VulnFlow Control Plane</title></head>
            <body style="font-family:sans-serif;padding:3rem;background:#0b0f19;color:#e2e8f0;">
                <h1 style="color:#38bdf8;">🛡️ VulnFlow AI Engine</h1>
                <p>Backend API is active and running.</p>
                <p>To access the Web Dashboard, build the UI bundle with: <code>cd ui && npm run build</code> or launch with <code>vulnflow serve --build-ui</code>.</p>
                <div style="margin-top:1.5rem;">
                    <a href="/docs" style="color:#38bdf8;margin-right:1rem;">API Documentation (Swagger)</a>
                    <a href="/api/runs" style="color:#38bdf8;">Remediation Runs JSON</a>
                </div>
            </body>
            </html>
            """

except ImportError:
    # Pure-Python ASGI 3 fallback when FastAPI is not installed in the environment
    from urllib.parse import parse_qs

    logger.info(
        "FastAPI not installed; running lightweight zero-dependency ASGI engine."
    )

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
                    await self._send_json(
                        send, 200, {"status": "healthy", "service": "vulnflow-api"}
                    )
                elif path == "/api/runs" and method == "GET":
                    limit = int(params.get("limit", [50])[0])
                    await self._send_json(send, 200, {"runs": list_runs(limit=limit)})
                elif (
                    path.startswith("/api/runs/")
                    and path.endswith("/report")
                    and method == "GET"
                ):
                    run_id = path.split("/")[3]
                    report = get_run_report(run_id)
                    if report:
                        await self._send_json(
                            send, 200, {"run_id": run_id, "report": report}
                        )
                    else:
                        await self._send_json(
                            send, 404, {"detail": f"Report for run {run_id} not found"}
                        )
                elif path.startswith("/api/runs/") and method == "GET":
                    run_id = path.split("/")[-1]
                    run = get_run(run_id)
                    if run:
                        await self._send_json(send, 200, run)
                    else:
                        await self._send_json(
                            send, 404, {"detail": f"Run {run_id} not found"}
                        )
                elif path == "/api/runs" and method == "POST":
                    body = await self._read_json(receive)
                    result = trigger_run(body)
                    await self._send_json(send, 200, result)
                elif path == "/api/webhooks" and method == "POST":
                    body = await self._read_json(receive)
                    result = handle_scan_webhook(body)
                    await self._send_json(send, 200, result)
                elif path == "/api/approvals" and method == "GET":
                    repo_arg = params.get("repo", [""])[0]
                    result = PendingApprovalListResponse(
                        plans=list_pending_approvals(repo_path=repo_arg or None)
                    )
                    await self._send_json(send, 200, result)
                elif path.startswith("/api/approvals/") and method == "POST":
                    plan_id = path.split("/")[-1]
                    body = await self._read_json(receive)
                    try:
                        request_model = ApprovalDecisionRequest.model_validate(body)
                    except ValidationError as exc:
                        await self._send_json(send, 422, {"detail": exc.errors()})
                        return
                    result = submit_approval(
                        plan_id=plan_id,
                        approved=request_model.approved,
                        reviewer=request_model.reviewer,
                        reviewer_group=request_model.reviewer_group,
                        reason=request_model.reason,
                        repo_path=request_model.repo_path,
                        resume=request_model.resume,
                    )
                    await self._send_json(send, 200, result)
                elif path == "/api/graph" and method == "GET":
                    pkg = params.get("package", ["npm:lodash"])[0]
                    repo = params.get("repo", ["workspace"])[0]
                    await self._send_json(
                        send, 200, get_graph_data(package=pkg, repo=repo)
                    )
                elif not path.startswith("/api/"):
                    _UI_DIST = _REPO_ROOT / "ui" / "dist"
                    if _UI_DIST.exists():
                        import mimetypes

                        rel_path = path.lstrip("/")
                        target_file = (
                            _UI_DIST / rel_path if rel_path else _UI_DIST / "index.html"
                        )
                        if not target_file.is_file():
                            target_file = _UI_DIST / "index.html"

                        if target_file.is_file():
                            ctype, _ = mimetypes.guess_type(str(target_file))
                            content_type = ctype or "application/octet-stream"
                            if target_file.suffix == ".html":
                                content_type = "text/html; charset=utf-8"
                            content_bytes = target_file.read_bytes()
                            await self._send_response(
                                send, 200, content_bytes, content_type
                            )
                            return
                    await self._send_json(
                        send, 404, {"error": "Not found", "path": path}
                    )
                else:
                    await self._send_json(
                        send, 404, {"error": "Not found", "path": path}
                    )
            except Exception as exc:
                logger.exception("Error processing request: %s", exc)
                await self._send_json(send, 500, {"error": str(exc)})

        async def _read_json(self, receive: Any) -> dict[str, Any]:
            body = b""
            more_body = True
            while more_body:
                message = await receive()
                body += message.get("body", b"")
                more_body = message.get("more_body", False)
            return json.loads(body.decode("utf-8")) if body else {}

        async def _send_json(self, send: Any, status: int, data: Any) -> None:
            if isinstance(data, BaseModel):
                data = data.model_dump(mode="json", by_alias=True, exclude_none=True)
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
            await send(
                {"type": "http.response.start", "status": status, "headers": headers}
            )
            await send({"type": "http.response.body", "body": body})

    app = PurePythonASGIApp()  # type: ignore[assignment]
