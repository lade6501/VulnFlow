"""
src/vulnflow/contracts/__init__.py
Core Pydantic data schemas and contracts for VulnFlow.
"""

from vulnflow.contracts.approval import (
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    ApprovalStatus,
    PendingApprovalListResponse,
    PendingApprovalResponse,
)
from vulnflow.contracts.finding import (
    Finding,
    FindingType,
    LocationInfo,
    SeverityLevel,
    compute_finding_id,
)
from vulnflow.contracts.policy import (
    ApprovedPackagesPolicy,
    PackagePolicyEntry,
    PolicyRules,
    PolicyStatus,
    RiskTierThresholds,
)
from vulnflow.contracts.remediation_plan import (
    PolicyResult,
    RemediationAction,
    RemediationPlan,
    RiskTier,
    VerificationResult,
)
from vulnflow.contracts.report import (
    AppliedPatchSummary,
    ApprovalGroup,
    CampaignSummary,
    PullRequestSummary,
    RunReport,
    SecretExposureSummary,
    StrategicDecision,
)
from vulnflow.contracts.state import VulnFlowState

__all__ = [
    "AppliedPatchSummary",
    "ApprovalDecisionRequest",
    "ApprovalDecisionResponse",
    "ApprovalGroup",
    "ApprovalStatus",
    "ApprovedPackagesPolicy",
    "CampaignSummary",
    "Finding",
    "FindingType",
    "LocationInfo",
    "PackagePolicyEntry",
    "PendingApprovalListResponse",
    "PendingApprovalResponse",
    "PolicyResult",
    "PolicyRules",
    "PolicyStatus",
    "PullRequestSummary",
    "RemediationAction",
    "RemediationPlan",
    "RiskTier",
    "RiskTierThresholds",
    "RunReport",
    "SecretExposureSummary",
    "SeverityLevel",
    "StrategicDecision",
    "VerificationResult",
    "VulnFlowState",
    "compute_finding_id",
]
