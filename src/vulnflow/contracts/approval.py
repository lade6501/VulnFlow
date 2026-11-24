"""Pydantic request and response contracts for the approval API."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ApprovalApiModel(BaseModel):
    """Strict base model shared by approval API contracts."""

    model_config = ConfigDict(
        extra="forbid", populate_by_name=True, str_strip_whitespace=True
    )


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalDecisionRequest(ApprovalApiModel):
    """A reviewer's decision for one remediation plan occurrence."""

    approved: bool = True
    reviewer: str = Field(default="security-lead", min_length=1, max_length=320)
    reviewer_group: str = Field(default="security", min_length=1, max_length=100)
    reason: str = Field(default="Approved via API", min_length=1, max_length=4000)
    repo_path: str = Field(default=".", min_length=1, max_length=2000)
    resume: bool = True


class PendingApprovalResponse(ApprovalApiModel):
    """One remediation proposal currently awaiting human review."""

    id: str
    approval_request_id: str | None = Field(default=None, alias="approvalRequestId")
    repo: str
    target_package: str = Field(alias="targetPackage")
    current_version: str = Field(alias="currentVersion")
    proposed_version: str = Field(alias="proposedVersion")
    action: str
    risk_tier: str = Field(alias="riskTier")
    reason: str
    rationale: str = ""
    diff: str = ""
    required_groups: list[str] = Field(default_factory=list, alias="requiredGroups")
    satisfied_groups: list[str] = Field(default_factory=list, alias="satisfiedGroups")
    created_at: str | None = Field(default=None, alias="createdAt")


class PendingApprovalListResponse(ApprovalApiModel):
    plans: list[PendingApprovalResponse] = Field(default_factory=list)


class ApprovalDecisionResponse(ApprovalApiModel):
    """Aggregate approval status after recording one reviewer decision."""

    plan_id: str
    approved: bool
    status: ApprovalStatus
    reviewer: str
    reviewer_group: str
    reason: str
    run_id: str | None = None
    terminal_status: str | None = None
    prs_opened: int | None = Field(default=None, ge=0)
