"""
api/security.py
Enforces API authentication, webhook signatures, CORS, and repository path boundaries.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any, Mapping


class ApiSecurityError(ValueError):
    """Raised when an API request violates a configured trust boundary."""


class RequestBodyTooLarge(ApiSecurityError):
    """Raised before an oversized request is buffered."""


MAX_REQUEST_BYTES = 5 * 1024 * 1024


def configured_cors_origins() -> list[str]:
    """Return explicit browser origins; wildcard credentialed CORS is forbidden."""
    raw = os.getenv(
        "VULNFLOW_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000",
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip() not in {"", "*"}]


def mutation_authorized(headers: Mapping[str, str]) -> bool:
    """Validate a bearer token for state-changing control-plane requests."""
    expected = os.getenv("VULNFLOW_API_TOKEN", "").strip()
    if not expected:
        return False
    supplied = headers.get("authorization", "")
    prefix = "Bearer "
    if not supplied.startswith(prefix):
        return False
    return hmac.compare_digest(supplied[len(prefix) :].encode(), expected.encode())


def webhook_signature_valid(raw_body: bytes, signature: str | None) -> bool:
    """Validate the webhook payload using HMAC-SHA256."""
    secret = os.getenv("VULNFLOW_WEBHOOK_SECRET", "").strip()
    if not secret:
        return False
    supplied = (signature or "").removeprefix("sha256=")
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied.encode(), expected.encode())


def _allowed_roots() -> list[Path]:
    raw = os.getenv("VULNFLOW_ALLOWED_REPO_ROOTS", "").strip()
    values = [value for value in raw.split(os.pathsep) if value] if raw else []
    if not values:
        values = [str(Path(__file__).resolve().parent.parent)]
    return [Path(value).expanduser().resolve() for value in values]


def _validate_path(raw_path: str, *, must_be_file: bool = False) -> str:
    try:
        candidate = Path(raw_path).expanduser().resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        raise ApiSecurityError("Invalid workspace path") from exc
    if not any(candidate == root or candidate.is_relative_to(root) for root in _allowed_roots()):
        raise ApiSecurityError("Requested path is outside configured workspace roots")
    if must_be_file and not candidate.is_file():
        raise ApiSecurityError("Requested report path is not a regular file")
    if not must_be_file and not candidate.is_dir():
        raise ApiSecurityError("Requested repository path is not a directory")
    return str(candidate)


def validate_repo_path(raw_path: str) -> str:
    return _validate_path(raw_path)


def validate_run_payload(payload: Any) -> dict[str, Any]:
    """Validate API-controlled paths and enumerated workflow inputs."""
    if not isinstance(payload, dict):
        raise ApiSecurityError("Expected a JSON object")
    clean = dict(payload)
    repo_keys = [key for key in ("repo_path", "repo", "repository") if key in clean]
    if len(repo_keys) > 1:
        raise ApiSecurityError("Specify only one repository path")
    clean["repo_path"] = validate_repo_path(str(clean.pop(repo_keys[0]))) if repo_keys else validate_repo_path(".")
    if clean.get("report_path"):
        clean["report_path"] = _validate_path(
            str(clean["report_path"]), must_be_file=True
        )

    allowed = {
        "mode": {"report", "pr", "dry-run"},
        "scanner": {"trivy", "grype", "osv", "sarif", "gitleaks"},
        "ecosystem": {"npm", "pip", "pypi", "python", "maven"},
    }
    for field, values in allowed.items():
        if field in clean:
            value = str(clean[field]).lower()
            if value not in values:
                raise ApiSecurityError(f"Unsupported {field}")
            clean[field] = value
    return clean
