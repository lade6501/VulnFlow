"""Contract tests for approval API request and response payloads."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.routes.approvals import submit_approval
from vulnflow.contracts.approval import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalStatus,
    PendingApprovalListResponse,
    PendingApprovalResponse,
)
from vulnflow.orchestrator.approval import global_approval_gate


def test_approval_request_defaults_and_rejects_unknown_fields() -> None:
    request = ApprovalDecisionRequest.model_validate({"reviewer": "vp@example.com"})

    assert request.approved is True
    assert request.reviewer_group == "security"
    assert request.resume is True

    with pytest.raises(ValidationError):
        ApprovalDecisionRequest.model_validate(
            {"reviewer": "vp@example.com", "unexpected": True}
        )


def test_pending_approval_response_preserves_frontend_aliases() -> None:
    plan = PendingApprovalResponse(
        id="PLAN-1",
        approval_request_id="request-1",
        repo="acme/payments",
        target_package="npm:example",
        current_version="1.0.0",
        proposed_version="2.0.0",
        action="BUMP",
        risk_tier="REVIEW",
        reason="Major upgrade",
        required_groups=["security", "product-owner", "vp"],
        satisfied_groups=["security"],
    )
    payload = PendingApprovalListResponse(plans=[plan]).model_dump(
        mode="json", by_alias=True
    )

    assert payload["plans"][0]["approvalRequestId"] == "request-1"
    assert payload["plans"][0]["targetPackage"] == "npm:example"
    assert payload["plans"][0]["requiredGroups"] == ["security", "product-owner", "vp"]


def test_approval_decision_response_serializes_status_value() -> None:
    response = ApprovalDecisionResponse(
        plan_id="PLAN-1",
        approved=True,
        status=ApprovalStatus.PENDING,
        reviewer="vp@example.com",
        reviewer_group="vp",
        reason="Approved",
    )

    assert response.model_dump(mode="json")["status"] == "pending"


def test_submit_approval_returns_response_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(global_approval_gate, "record_decision", lambda **_kwargs: False)

    response = submit_approval(
        plan_id="PLAN-1",
        approved=True,
        reviewer="owner@example.com",
        reviewer_group="product-owner",
        reason="Approved by repository owner",
        repo_path="acme/payments",
        resume=False,
    )

    assert isinstance(response, ApprovalDecisionResponse)
    assert response.status is ApprovalStatus.PENDING
