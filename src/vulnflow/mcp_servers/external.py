"""
src/vulnflow/mcp_servers/external.py
Client bridge integrating external production MCP servers for GitHub and Jira.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vulnflow.mcp_servers.external")


class ExternalMCPClient:
    """
    Subprocess JSON-RPC client capable of communicating with standard external MCP servers
    (e.g., @modelcontextprotocol/server-github, @modelcontextprotocol/server-git, Jira MCP).
    """

    def __init__(self, command: List[str], env: Optional[Dict[str, str]] = None, timeout: float = 15.0) -> None:
        self.command = command
        self.env = env or {}
        self.timeout = timeout
        self._proc: Optional[subprocess.Popen[str]] = None
        self._req_id = 1

    def _ensure_process(self) -> bool:
        if self._proc is not None and self._proc.poll() is None:
            return True

        if not self.command or not shutil.which(self.command[0]):
            return False

        merged_env = os.environ.copy()
        merged_env.update(self.env)

        try:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=merged_env,
                bufsize=1,
            )

            # Send MCP initialize
            init_payload = {
                "jsonrpc": "2.0",
                "id": self._req_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "vulnflow-bridge", "version": "1.0.0"},
                },
            }
            self._req_id += 1
            resp = self._send_raw(init_payload)
            if resp and "result" in resp:
                # Send initialized notification
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
                if self._proc and self._proc.stdin:
                    self._proc.stdin.write(json.dumps(notif) + "\n")
                    self._proc.stdin.flush()
                return True
        except Exception as exc:
            logger.warning("Could not launch external MCP server %s: %s", self.command, exc)
            self._proc = None
        return False

    def _send_raw(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self._proc or not self._proc.stdin or not self._proc.stdout:
            return None
        try:
            line = json.dumps(payload) + "\n"
            self._proc.stdin.write(line)
            self._proc.stdin.flush()

            resp_line = self._proc.stdout.readline()
            if resp_line:
                return json.loads(resp_line.strip())
        except Exception as exc:
            logger.warning("Error exchanging JSON-RPC with external MCP server: %s", exc)
        return None

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call a tool on the external MCP server via tools/call."""
        if not self._ensure_process():
            return None

        req = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        self._req_id += 1
        resp = self._send_raw(req)
        if resp and "result" in resp:
            content = resp["result"].get("content", [])
            for c in content:
                if c.get("type") == "text":
                    try:
                        return json.loads(c.get("text", "{}"))
                    except Exception:
                        return {"text": c.get("text")}
            return resp["result"]
        return None

    def close(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
            self._proc = None


class GitHubMCPBridge:
    """
    Integrates with official GitHub MCP server (@modelcontextprotocol/server-github)
    or directly via GitHub REST API if GITHUB_TOKEN is available.
    """

    def __init__(self) -> None:
        self.token = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN") or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        self._mcp_client: Optional[ExternalMCPClient] = None
        if self.token and shutil.which("npx"):
            self._mcp_client = ExternalMCPClient(
                command=["npx", "-y", "@modelcontextprotocol/server-github"],
                env={"GITHUB_PERSONAL_ACCESS_TOKEN": self.token},
            )

    def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        head: str,
        base: str = "main",
        body: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Attempt to open pull request via GitHub MCP server or GitHub API."""
        if not self.token:
            return None

        # 1. Try via external GitHub MCP Server
        if self._mcp_client:
            try:
                res = self._mcp_client.call_tool(
                    "create_pull_request",
                    {
                        "owner": owner,
                        "repo": repo,
                        "title": title,
                        "head": head,
                        "base": base,
                        "body": body,
                    },
                )
                if res and (res.get("html_url") or res.get("url") or res.get("number")):
                    return {
                        "status": "opened",
                        "pr_url": res.get("html_url") or res.get("url"),
                        "pr_number": res.get("number", 1),
                        "provider": "mcp-github",
                    }
            except Exception as exc:
                logger.debug("External GitHub MCP server create_pull_request failed: %s; trying REST API", exc)

        # 2. Direct REST API Fallback
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "VulnFlow-MCP-Bridge",
        }
        payload = json.dumps({"title": title, "head": head, "base": base, "body": body}).encode("utf-8")
        try:
            req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "status": "opened",
                    "pr_url": data.get("html_url"),
                    "pr_number": data.get("number"),
                    "provider": "github-api",
                }
        except urllib.error.HTTPError as exc:
            logger.warning("GitHub API PR creation failed (HTTP %d): %s", exc.code, exc.read().decode("utf-8", errors="ignore"))
        except Exception as exc:
            logger.warning("GitHub PR creation error: %s", exc)

        return None


class JiraMCPBridge:
    """
    Integrates with Jira MCP server or Jira REST API when JIRA_URL and JIRA_API_TOKEN are configured.
    """

    def __init__(self) -> None:
        self.jira_url = os.getenv("JIRA_URL") or os.getenv("JIRA_BASE_URL")
        self.api_token = os.getenv("JIRA_API_TOKEN") or os.getenv("JIRA_TOKEN")
        self.user_email = os.getenv("JIRA_USER_EMAIL") or os.getenv("JIRA_EMAIL")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "SEC")

    def create_issue(
        self,
        summary: str,
        description: str,
        issue_type: str = "Security Task",
        project_key: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create Jira issue via Jira REST API / MCP."""
        if not (self.jira_url and self.api_token and self.user_email):
            return None

        proj = project_key or self.project_key
        base_url = self.jira_url.rstrip("/")
        api_endpoint = f"{base_url}/rest/api/2/issue"

        import base64

        auth_str = base64.b64encode(f"{self.user_email}:{self.api_token}".encode("utf-8")).decode("utf-8")
        headers = {
            "Authorization": f"Basic {auth_str}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "VulnFlow-Jira-Bridge",
        }
        payload = {
            "fields": {
                "project": {"key": proj},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
            }
        }
        try:
            req = urllib.request.Request(api_endpoint, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                key = data.get("key")
                return {
                    "status": "created",
                    "ticket_id": key,
                    "ticket_url": f"{base_url}/browse/{key}",
                    "ticket_type": "jira",
                    "provider": "jira-api",
                }
        except Exception as exc:
            logger.warning("Jira issue creation failed: %s", exc)

        return None


# Global bridge instances
github_mcp_bridge = GitHubMCPBridge()
jira_mcp_bridge = JiraMCPBridge()
