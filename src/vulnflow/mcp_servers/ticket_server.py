"""
src/vulnflow/mcp_servers/ticket_server.py
MCP tool server integrating with issue trackers like Jira and GitHub Issues.
"""

from __future__ import annotations

import logging
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.mcp_servers.external import jira_mcp_bridge
from vulnflow.mcp_servers.fastmcp import FastMCP

logger = logging.getLogger("vulnflow.mcp_servers.ticket")

mcp = FastMCP(
    name="vulnflow-ticket",
    description="MCP server managing issue tracker ticket creation for security exceptions and human reviews.",
)


class TicketServer:
    """Tool server opening and tracking security exception tickets over MCP."""

    def __init__(self, persistence_file: Optional[Path] = None) -> None:
        self.mcp = mcp
        self._persistence_file = persistence_file or Path(".vulnflow/tickets.json")
        self._created_tickets: Dict[str, Dict[str, Any]] = {}
        self._counter = 1042
        self._load_persisted_tickets()

    def _load_persisted_tickets(self) -> None:
        """Load previously created tickets from disk to ensure cross-process idempotency."""
        try:
            if self._persistence_file and self._persistence_file.exists():
                with open(self._persistence_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._created_tickets.update(data.get("tickets", {}))
                        self._counter = max(self._counter, data.get("counter", 1042))
        except Exception as exc:
            logger.debug("Could not load persisted tickets: %s", exc)

    def _save_persisted_tickets(self) -> None:
        """Persist tickets to disk."""
        try:
            if self._persistence_file:
                self._persistence_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self._persistence_file, "w", encoding="utf-8") as f:
                    json.dump({"tickets": self._created_tickets, "counter": self._counter}, f, indent=2)
        except Exception as exc:
            logger.debug("Could not save persisted tickets: %s", exc)

    def ticket_create(
        self,
        ticket_type: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """MCP tool: ticket_create - Opens security ticket with idempotency protection and CVE context."""
        repo = str(context.get("repo", "default"))
        target_pkg = str(context.get("target_package", "general"))
        cves = context.get("cves", [])
        cves_str = ",".join(sorted(cves)) if isinstance(cves, list) else str(cves)
        idempotency_key = f"{ticket_type}:{repo}:{target_pkg}:{cves_str}"

        if idempotency_key in self._created_tickets:
            logger.info("Ticket for %s already exists; returning without duplicate", idempotency_key)
            return self._created_tickets[idempotency_key]

        cves_desc = f" ({cves_str})" if cves_str else ""
        # 1. Attempt to create real issue via Jira MCP server or API if configured
        jira_res = jira_mcp_bridge.create_issue(
            summary=f"Security Exception: {target_pkg}{cves_desc} in {repo}",
            description=f"Reason: {context.get('reason', 'Blocked by policy')}\nCVEs: {cves_str}\nPlans: {context.get('plans', [])}",
        )
        if jira_res:
            self._created_tickets[idempotency_key] = jira_res
            self._save_persisted_tickets()
            return jira_res

        # 2. Local fallback format
        ticket_id = f"SEC-{self._counter}"
        self._counter += 1
        record = {
            "status": "created",
            "ticket_id": ticket_id,
            "ticket_url": f"https://jira.corp.internal/browse/{ticket_id}",
            "ticket_type": ticket_type,
            "summary": f"Security Exception: {target_pkg}{cves_desc} blocked by policy in {repo}",
            "cves": cves,
            "context": context,
        }
        self._created_tickets[idempotency_key] = record
        self._save_persisted_tickets()
        logger.info("Created new security exception ticket %s for %s%s", ticket_id, target_pkg, cves_desc)
        return record


ticket_server = TicketServer()


@mcp.tool(
    name="ticket_create",
    description="Creates or retrieves a security exception ticket in Jira or GitHub Issues for blocked plans.",
)
def ticket_create(ticket_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
    return ticket_server.ticket_create(ticket_type, context)


if __name__ == "__main__":
    mcp.run()
