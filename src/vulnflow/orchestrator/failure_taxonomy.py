"""
src/vulnflow/orchestrator/failure_taxonomy.py
Classifies workflow, verification, and agent failures into canonical taxonomy codes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from vulnflow.contracts.state import VulnFlowState


@dataclass(frozen=True)
class FailureClassification:
    """Canonical failure taxonomy classification and recommended harness action."""

    code: str
    category: str
    summary: str
    recommended_action: str


def classify_failure(
    error_message: Optional[str] = None,
    state: Optional[VulnFlowState] = None,
) -> FailureClassification:
    """Map an error message or failed state into a canonical harness failure taxonomy entry."""
    msg = (error_message or (state.error if state else "") or "").lower()
    blocking = (state.blocking_reason if state else "") or ""
    combined = f"{msg} {blocking.lower()}"

    if "timeout" in combined or "timed out" in combined:
        return FailureClassification(
            code="TIMEOUT",
            category="execution_resilience",
            summary="Workflow or tool execution exceeded configured timeout.",
            recommended_action="Inspect slow sandbox/scanner step and adjust timeout or retry policy.",
        )
    if "rate limit" in combined or "429" in combined or "quota" in combined:
        return FailureClassification(
            code="RATE_LIMIT",
            category="provider_resilience",
            summary="Upstream LLM or API provider returned a rate-limit error.",
            recommended_action="Enable deterministic fallback or increase backoff/retry budget.",
        )
    if "injection" in combined or "deflected" in combined:
        return FailureClassification(
            code="PROMPT_INJECTION_BLOCKED",
            category="security_guardrail",
            summary="Hostile prompt-injection directive detected and neutralized.",
            recommended_action="Add hostile sample to regression suite and keep deterministic invariants.",
        )
    if "secret" in combined or "credential" in combined or "redacted" in combined:
        return FailureClassification(
            code="SECRET_LEAK_BLOCKED",
            category="security_guardrail",
            summary="Unredacted credential handling blocked or escalated for manual rotation.",
            recommended_action="Verify RedactionGuard coverage and manual rotation checklist.",
        )
    if "sandbox" in combined or "container" in combined or "symlink" in combined:
        return FailureClassification(
            code="SANDBOX_ISOLATION_ERROR",
            category="sandbox_boundary",
            summary="Sandbox boundary, offline container, or filesystem safety check failed.",
            recommended_action="Verify offline container image and repository file permissions.",
        )
    if "policy" in combined or (state and state.exit_code == 20):
        return FailureClassification(
            code="POLICY_CONFLICT",
            category="governance",
            summary="Remediation blocked by corporate whitelist, version, or license policy.",
            recommended_action="Confirm exception ticket context or update approved_packages.yaml.",
        )
    if "test" in combined or "build" in combined or (state and state.retry_count > 0):
        return FailureClassification(
            code="BROKEN_TESTS",
            category="remediation_quality",
            summary="Proposed version upgrade broke repository build or automated tests.",
            recommended_action="Update ecosystem playbook or restrict breaking major bump to REVIEW.",
        )
    if "verify" in combined or "residual" in combined or (state and state.exit_code == 30):
        return FailureClassification(
            code="VERIFICATION_FAILED",
            category="remediation_quality",
            summary="Post-fix rescan still detects target CVEs or introduced regressions.",
            recommended_action="Check candidate version selection and lockfile resolution.",
        )
    return FailureClassification(
        code="UNHANDLED_EXECUTION_ERROR",
        category="runtime",
        summary="Workflow terminated due to an unhandled runtime error.",
        recommended_action="Inspect audit trail and stack trace; add regression case to harness.",
    )


def failure_audit_payload(
    error_message: Optional[str] = None,
    state: Optional[VulnFlowState] = None,
) -> Dict[str, Any]:
    """Return a structured dictionary suitable for state audit logs and run summaries."""
    cls = classify_failure(error_message=error_message, state=state)
    return {
        "taxonomy_code": cls.code,
        "category": cls.category,
        "summary": cls.summary,
        "recommended_action": cls.recommended_action,
    }
