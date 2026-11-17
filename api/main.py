"""
api/main.py
FastAPI application initialization, middleware setup, and route registration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("vulnflow.api")

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

    from api.routes.approvals import submit_approval
    from api.routes.graph import get_graph_data
    from api.routes.runs import get_run, list_runs, trigger_run
    from api.routes.webhooks import handle_scan_webhook

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
    # Lightweight fallback callable if FastAPI is not installed in current environment
    class DummyApp:
        def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
            pass

    app = DummyApp()  # type: ignore[assignment]
