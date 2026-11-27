"""
src/vulnflow/agents/expiry.py
Agent that monitors temporary policy waivers, certificates, and tokens for expiration and renewal.
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from vulnflow.mcp_servers.ticket_server import ticket_server
from vulnflow.policy.loaders.yaml_loader import parse_simple_yaml

logger = logging.getLogger("vulnflow.agents.expiry")


class ExpiryAgent:
    """Monitors artifacts, policy waivers, and credentials for expiry and initiates renewals."""

    def scan_expiring_artifacts(
        self,
        repo_path: str = ".",
        warning_days: int = 30,
        artifacts_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Identify artifacts and credentials expiring within the warning window."""
        repo_p = Path(repo_path)
        candidates: List[Dict[str, Any]] = []
        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Check explicit artifacts file if provided or found
        search_files = []
        if artifacts_file:
            search_files.append(Path(artifacts_file))
        else:
            sample_art = repo_p / "artifacts.yaml"
            if sample_art.exists():
                search_files.append(sample_art)
            sample_yml = repo_p / "samples" / "expiring-artifacts" / "artifacts.yaml"
            if sample_yml.exists():
                search_files.append(sample_yml)

        for fpath in search_files:
            try:
                content = parse_simple_yaml(fpath.read_text(encoding="utf-8")) or {}
                items = content.get("artifacts", [])
                if isinstance(items, list):
                    for item in items:
                        exp_str = item.get("expires_at") or item.get("expiration_date")
                        if exp_str:
                            candidates.append(self._evaluate_artifact(item, exp_str, str(fpath), now, warning_days))
            except Exception as exc:
                logger.warning("Failed parsing artifacts file %s: %s", fpath, exc)

        # 2. Check persistent tickets and policy waivers in .vulnflow/tickets.json
        tickets_file = repo_p / ".vulnflow" / "tickets.json"
        if tickets_file.exists():
            try:
                with open(tickets_file, "r", encoding="utf-8") as tf:
                    t_data = json.load(tf)
                for t_id, t_info in t_data.items():
                    waiver_exp = t_info.get("waiver_expires_at")
                    if waiver_exp:
                        candidates.append(
                            self._evaluate_artifact(
                                {"name": f"Waiver for {t_id}", "type": "policy_waiver", "ticket_id": t_id},
                                waiver_exp,
                                str(tickets_file),
                                now,
                                warning_days,
                            )
                        )
            except Exception as exc:
                logger.warning("Failed parsing tickets file: %s", exc)

        return [c for c in candidates if c.get("in_warning_window", False)]

    def _evaluate_artifact(
        self,
        artifact: Dict[str, Any],
        expires_at_str: str,
        source_path: str,
        now: datetime.datetime,
        warning_days: int,
    ) -> Dict[str, Any]:
        """Compute days remaining and risk window category."""
        try:
            # Parse ISO or date string
            if "T" in expires_at_str:
                exp_dt = datetime.datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            else:
                exp_dt = datetime.datetime.strptime(expires_at_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        except Exception:
            exp_dt = now + datetime.timedelta(days=14)

        delta = exp_dt - now
        days_rem = delta.days

        if days_rem <= 0:
            status = "expired"
            risk_window = "CRITICAL"
        elif days_rem <= 7:
            status = "imminent"
            risk_window = "HIGH"
        elif days_rem <= warning_days:
            status = "warning"
            risk_window = "MEDIUM"
        else:
            status = "healthy"
            risk_window = "LOW"

        return {
            "name": artifact.get("name", "Unknown Artifact"),
            "type": artifact.get("type", "certificate"),
            "expires_at": expires_at_str,
            "days_remaining": max(0, days_rem),
            "status": status,
            "risk_window": risk_window,
            "in_warning_window": days_rem <= warning_days,
            "source": source_path,
            "action": "renew" if days_rem <= warning_days else "monitor",
        }

    def automate_renewals(
        self,
        repo_path: str = ".",
        warning_days: int = 30,
        artifacts_file: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Open idempotent renewal tickets or PRs for artifacts expiring in warning window (F25)."""
        expiring = self.scan_expiring_artifacts(repo_path, warning_days, artifacts_file)
        results: List[Dict[str, Any]] = []

        for item in expiring:
            title = f"Security Renewal Required: {item['name']} expires in {item['days_remaining']} days"
            description = (
                f"Artifact: {item['name']}\n"
                f"Type: {item['type']}\n"
                f"Source: {item['source']}\n"
                f"Expiration Date: {item['expires_at']}\n"
                f"Risk Window: {item['risk_window']}\n"
                f"Action Required: Rotate credential, renew certificate, or extend approved policy waiver."
            )
            # Idempotent ticket creation via ticket_server
            res = ticket_server.ticket_create(
                ticket_type="renewal",
                context={
                    "repo": repo_path,
                    "target_package": item["name"],
                    "cves": [item["type"]],
                    "reason": f"Expires in {item['days_remaining']} days",
                    "title": title,
                    "description": description,
                    "risk_window": item["risk_window"],
                },
            )
            item["ticket"] = res
            results.append(item)

        return results


default_expiry_agent = ExpiryAgent()
