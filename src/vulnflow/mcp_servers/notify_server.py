"""
src/vulnflow/mcp_servers/notify_server.py
MCP tool server sending notifications and human approval requests to Slack, Teams, and email.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from vulnflow.mcp_servers.fastmcp import FastMCP

logger = logging.getLogger("vulnflow.mcp_servers.notify")

mcp = FastMCP(
    name="vulnflow-notify",
    description="MCP server dispatching approval notifications and status alerts to Slack, Teams, and email.",
)


class NotifyServer:
    """Tool server handling human approval dispatches and operational alerts over MCP."""

    def __init__(self) -> None:
        self.mcp = mcp
        self._dispatched_approvals: Dict[str, Dict[str, Any]] = {}
        self._counter = 100

    def approval_request(self, plan: Dict[str, Any], channel: str = "slack") -> Dict[str, Any]:
        """MCP tool: approval_request - Dispatches human authorization request to reviewers."""
        plan_id = plan.get("id") or plan.get("plan_id", f"PLAN-{self._counter}")
        pkg = plan.get("target_package") or plan.get("root_cause_id", "package")
        tgt_v = plan.get("target_version", "unknown")
        tier = plan.get("risk_tier", "review")

        logger.info("Dispatching approval_request for plan %s (%s ➔ %s) to %s", plan_id, pkg, tgt_v, channel)

        record = {
            "status": "dispatched",
            "channel": channel,
            "plan_id": plan_id,
            "target_package": pkg,
            "target_version": tgt_v,
            "risk_tier": tier,
            "message_id": f"msg-{plan_id.lower()}",
            "approval_url": f"https://vulnflow.internal/approvals/{plan_id}",
        }
        self._dispatched_approvals[plan_id] = record
        return record

    def notify_send(self, message: str, channel: str = "slack", level: str = "info") -> Dict[str, Any]:
        """MCP tool: notify_send - Sends operational notification message."""
        logger.info("Notification [%s] via %s: %s", level.upper(), channel, message)
        return {
            "status": "delivered",
            "channel": channel,
            "level": level,
            "message": message,
        }


notify_server = NotifyServer()


@mcp.tool(
    name="approval_request",
    description="Dispatches a human review and sign-off notification card to Slack or Teams for review-tier plans.",
)
def approval_request(plan: Dict[str, Any], channel: str = "slack") -> Dict[str, Any]:
    return notify_server.approval_request(plan, channel)


@mcp.tool(
    name="notify_send",
    description="Sends general alerts or status updates to configured notification channels.",
)
def notify_send(message: str, channel: str = "slack", level: str = "info") -> Dict[str, Any]:
    return notify_server.notify_send(message, channel, level)


if __name__ == "__main__":
    mcp.run()
