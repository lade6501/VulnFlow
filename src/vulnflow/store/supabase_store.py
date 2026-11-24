"""Durable Supabase persistence for approval requests and workflow checkpoints.

The implementation talks to Supabase's PostgREST API with the Python standard
library.  This keeps the core VulnFlow installation small while still allowing
CI jobs running on ephemeral workers to share approval state.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from vulnflow.contracts.remediation_plan import RemediationPlan
from vulnflow.contracts.state import VulnFlowState

logger = logging.getLogger("vulnflow.store.supabase")


class SupabaseStoreError(RuntimeError):
    """Raised when a configured Supabase persistence operation fails."""


@dataclass(frozen=True)
class SupabaseConfig:
    """Environment-backed connection and tenancy settings."""

    url: str
    key: str
    organization_slug: str
    repository_key: str | None = None
    required: bool = False
    timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> SupabaseConfig | None:
        url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
        key = (
            os.getenv("SUPABASE_SECRET_KEY", "").strip()
            or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
            or os.getenv("SUPABASE_KEY", "").strip()
        )
        if not url or not key:
            return None

        repository_key = (
            os.getenv("VULNFLOW_REPOSITORY", "").strip()
            or os.getenv("GITHUB_REPOSITORY", "").strip()
            or os.getenv("CI_PROJECT_PATH", "").strip()
            or None
        )
        inferred_org = repository_key.split("/", 1)[0] if repository_key and "/" in repository_key else "default"
        org = os.getenv("VULNFLOW_ORG_SLUG", inferred_org).strip() or inferred_org
        required = os.getenv("VULNFLOW_SUPABASE_REQUIRED", "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        timeout_raw = os.getenv("VULNFLOW_SUPABASE_TIMEOUT_SECONDS", "10")
        try:
            timeout_seconds = max(1.0, float(timeout_raw))
        except ValueError:
            timeout_seconds = 10.0
        return cls(
            url=url,
            key=key,
            organization_slug=org,
            repository_key=repository_key,
            required=required,
            timeout_seconds=timeout_seconds,
        )


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _stable_issue_references(plan: RemediationPlan) -> list[str]:
    """Extract scanner-independent advisory or secret-location references."""
    references: set[str] = set()
    for evidence in plan.evidence:
        if not isinstance(evidence, dict):
            continue
        for key in ("cve", "ghsa", "osv_id", "advisory_id", "rule_id"):
            value = evidence.get(key)
            if value:
                references.add(f"{key}:{str(value).lower()}")
        aliases = evidence.get("aliases", [])
        if isinstance(aliases, list):
            references.update(f"alias:{str(item).lower()}" for item in aliases if item)
        # A secret rule may occur in several files and require a different rotation plan.
        if evidence.get("rule_id") and evidence.get("file_path"):
            references.add(f"location:{str(evidence['file_path']).lower()}")
    return sorted(references)


def repository_identity(repo_path: str | None, configured_key: str | None = None) -> str:
    """Return a stable repository identity, preferring CI/provider metadata."""
    if configured_key:
        return configured_key.strip().lower()
    candidate = Path(repo_path or ".").expanduser()
    try:
        return str(candidate.resolve()).lower()
    except OSError:
        return str(candidate).lower()


def explicit_repository_identity(repo_path: str | None, configured_key: str | None = None) -> str:
    """Accept a dashboard-supplied repository key while preserving CI path mapping."""
    raw = (repo_path or "").strip()
    candidate = Path(raw).expanduser() if raw else None
    if raw not in ("", ".", "workspace") and candidate is not None and not candidate.exists() and not candidate.is_absolute():
        return raw.lower()
    return repository_identity(repo_path, configured_key)


def approval_identity(
    plan: RemediationPlan,
    *,
    ecosystem: str = "unknown",
    environment: str | None = None,
    policy_version: str | None = None,
) -> str:
    """Build a deterministic identity for materially equivalent remediation plans."""
    policy = plan.policy_result
    payload = {
        "schema": 1,
        "ecosystem": (ecosystem or "unknown").lower(),
        "environment": environment or os.getenv("VULNFLOW_ENVIRONMENT", "default"),
        "policy_version": policy_version or os.getenv("VULNFLOW_POLICY_VERSION", "default"),
        # Finding IDs currently include the checkout path. They identify an
        # occurrence, not a cross-run remediation intent, so they are excluded.
        "issue_references": _stable_issue_references(plan),
        "root_cause_id": plan.root_cause_id,
        "target_package": plan.target_package,
        "action": _enum_value(plan.action),
        "target_version": plan.target_version,
        "risk_tier": _enum_value(plan.risk_tier),
        "policy_status": getattr(policy, "status", None),
        "policy_rule": getattr(policy, "rule_matched", None),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def configured_approver_groups() -> list[str]:
    """Return the ordered groups required to approve a review-tier plan."""
    raw = os.getenv("VULNFLOW_APPROVER_GROUPS", "security")
    groups = [group.strip().lower() for group in raw.split(",") if group.strip()]
    return list(dict.fromkeys(groups)) or ["security"]


class SupabaseStore:
    """Small PostgREST client for VulnFlow's Supabase schema and RPCs."""

    def __init__(self, config: SupabaseConfig) -> None:
        self.config = config

    @classmethod
    def from_env(cls) -> SupabaseStore | None:
        config = SupabaseConfig.from_env()
        return cls(config) if config else None

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        query: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        url = f"{self.config.url}/rest/v1/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urlencode(query)}"
        body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8") if payload is not None else None
        headers = {
            "apikey": self.config.key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # New sb_secret_* keys are API keys, not JWTs, and must not be sent as
        # bearer tokens. Legacy service_role JWTs still require this header.
        if self.config.key.count(".") == 2:
            headers["Authorization"] = f"Bearer {self.config.key}"
        if extra_headers:
            headers.update(extra_headers)
        request = Request(url=url, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read()
        except HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")[:1000]
            raise SupabaseStoreError(f"Supabase returned HTTP {exc.code}: {details}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SupabaseStoreError(f"Could not reach Supabase: {exc}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SupabaseStoreError("Supabase returned a non-JSON response") from exc

    def _rpc(self, function_name: str, payload: dict[str, Any]) -> Any:
        return self._request("POST", f"rpc/{quote(function_name, safe='')}", payload=payload)

    def _repo_key(self, repo_path: str | None, *, allow_explicit: bool = False) -> str:
        if allow_explicit:
            return explicit_repository_identity(repo_path, self.config.repository_key)
        return repository_identity(repo_path, self.config.repository_key)

    def claim_approval(self, state: VulnFlowState, plan: RemediationPlan) -> dict[str, Any]:
        """Create or reuse the durable approval request for a plan occurrence."""
        approval_key = approval_identity(plan, ecosystem=state.ecosystem)
        result = self._rpc(
            "vulnflow_claim_approval",
            {
                "p_organization_slug": self.config.organization_slug,
                "p_repository_key": self._repo_key(state.repo_path),
                "p_run_id": state.run_id,
                "p_plan_id": plan.id,
                "p_approval_key": approval_key,
                "p_context_hash": approval_key,
                "p_plan_snapshot": plan.to_dict(),
                "p_checkpoint_status": state.terminal_status,
                "p_required_groups": configured_approver_groups(),
            },
        )
        if not isinstance(result, dict):
            raise SupabaseStoreError("vulnflow_claim_approval returned an invalid payload")
        return result

    def get_plan_approval(self, plan_id: str, repo_path: str | None) -> dict[str, Any]:
        """Return the current request and latest decision linked to a plan."""
        result = self._rpc(
            "vulnflow_get_plan_approval",
            {
                "p_organization_slug": self.config.organization_slug,
                "p_repository_key": self._repo_key(repo_path, allow_explicit=True),
                "p_plan_id": plan_id,
            },
        )
        return result if isinstance(result, dict) else {}

    def record_decision(
        self,
        *,
        plan_id: str,
        approved: bool,
        reviewer: str,
        reviewer_group: str,
        reason: str,
        repo_path: str | None,
    ) -> dict[str, Any]:
        """Append a decision and atomically recompute the request's aggregate status."""
        result = self._rpc(
            "vulnflow_record_approval_decision",
            {
                "p_organization_slug": self.config.organization_slug,
                "p_repository_key": self._repo_key(repo_path, allow_explicit=True),
                "p_plan_id": plan_id,
                "p_approved": approved,
                "p_reviewer": reviewer,
                "p_reviewer_group": reviewer_group.strip().lower() or "security",
                "p_reason": reason,
            },
        )
        if not isinstance(result, dict):
            raise SupabaseStoreError("vulnflow_record_approval_decision returned an invalid payload")
        return result

    def list_pending(self, repo_path: str | None = None) -> list[dict[str, Any]]:
        """List pending approvals for an organization, optionally scoped to a repository."""
        query = {
            "organization_slug": f"eq.{self.config.organization_slug}",
            "order": "created_at.desc",
        }
        if repo_path:
            query["repository_key"] = f"eq.{self._repo_key(repo_path, allow_explicit=True)}"
        result = self._request("GET", "vulnflow_pending_approvals", query=query)
        return [item for item in result if isinstance(item, dict)] if isinstance(result, list) else []

    def save_checkpoint(self, state: VulnFlowState) -> None:
        """Upsert the latest serialized checkpoint for one workflow run."""
        self._rpc(
            "vulnflow_save_checkpoint",
            {
                "p_organization_slug": self.config.organization_slug,
                "p_repository_key": self._repo_key(state.repo_path),
                "p_run_id": state.run_id,
                "p_status": state.terminal_status,
                "p_current_node": state.current_node,
                "p_state": state.to_dict(),
            },
        )

    def load_checkpoint(self, repo_path: str | None, run_id: str | None = None) -> dict[str, Any] | None:
        """Load a specific or the latest resumable checkpoint for a repository."""
        result = self._rpc(
            "vulnflow_load_checkpoint",
            {
                "p_organization_slug": self.config.organization_slug,
                "p_repository_key": self._repo_key(repo_path, allow_explicit=True),
                "p_run_id": run_id,
            },
        )
        if isinstance(result, dict):
            state = result.get("state", result)
            return state if isinstance(state, dict) else None
        return None


def should_raise(store: SupabaseStore) -> bool:
    """Whether a remote persistence failure must stop the workflow."""
    return store.config.required


def log_or_raise(store: SupabaseStore, operation: str, exc: Exception) -> None:
    """Apply the configured strict/fallback behavior consistently."""
    if should_raise(store):
        raise SupabaseStoreError(f"Required Supabase operation '{operation}' failed: {exc}") from exc
    logger.warning("Supabase %s failed; using local persistence fallback: %s", operation, exc)


