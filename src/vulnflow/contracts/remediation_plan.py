"""
src/vulnflow/contracts/remediation_plan.py
Defines schemas for proposed remediation plans, patches, and validation results.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class RemediationAction(str, enum.Enum):
    """Permitted remediation action types."""

    BUMP = "bump"
    OVERRIDE = "override"
    PIN = "pin"
    REPLACE = "replace"
    ROTATE = "rotate"
    RENEW = "renew"
    EXCEPTION = "exception"
    NONE = "none"


class RiskTier(str, enum.Enum):
    """Organizational risk tier determining autonomy vs human approval gate."""

    AUTO = "auto"        # Auto-PR / auto-remediate without human blocking
    REVIEW = "review"    # Requires explicit human approval before patch execution
    BLOCKED = "blocked"  # Prohibited by policy or safety constraints; escalate via ticket


@dataclass
class PolicyResult:
    """Outcome of evaluating proposed fix against organization policy rules."""

    status: str = "unknown"  # "approved", "deprecated", "banned", "unknown", "license_denied"
    rule_matched: Optional[str] = None
    replacement: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PolicyResult:
        return cls(
            status=data.get("status", "unknown"),
            rule_matched=data.get("rule_matched"),
            replacement=data.get("replacement"),
            reason=data.get("reason"),
        )


@dataclass
class VerificationResult:
    """Verification and rescan evidence validating that the fix resolved target findings."""

    verified: bool = False
    rescan_clean: bool = False
    resolved_finding_ids: List[str] = field(default_factory=list)
    new_finding_ids: List[str] = field(default_factory=list)
    policy_recheck_passed: bool = True
    build_success: bool = True
    tests_passed: bool = True
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VerificationResult:
        return cls(
            verified=bool(data.get("verified", False)),
            rescan_clean=bool(data.get("rescan_clean", False)),
            resolved_finding_ids=data.get("resolved_finding_ids", []),
            new_finding_ids=data.get("new_finding_ids", []),
            policy_recheck_passed=bool(data.get("policy_recheck_passed", True)),
            build_success=bool(data.get("build_success", True)),
            tests_passed=bool(data.get("tests_passed", True)),
            details=data.get("details"),
        )


@dataclass
class RemediationPlan:
    """
    Proposed remediation strategy for a set of related findings.
    Conforms strictly to Section 6.2 of the VulnFlow specification.
    """

    finding_ids: List[str]
    root_cause_id: str
    action: RemediationAction
    target_version: Optional[str] = None
    policy_result: PolicyResult = field(default_factory=PolicyResult)
    risk_tier: RiskTier = RiskTier.REVIEW
    requires_approval: bool = True
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    rationale: str = ""
    verification: Optional[VerificationResult] = None
    id: str = field(default_factory=lambda: f"PLAN-{uuid.uuid4().hex[:12]}")
    target_package: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_ids": self.finding_ids,
            "root_cause_id": self.root_cause_id,
            "action": self.action.value if isinstance(self.action, RemediationAction) else str(self.action),
            "target_version": self.target_version,
            "target_package": self.target_package,
            "policy_result": self.policy_result.to_dict() if isinstance(self.policy_result, PolicyResult) else self.policy_result,
            "risk_tier": self.risk_tier.value if isinstance(self.risk_tier, RiskTier) else str(self.risk_tier),
            "requires_approval": self.requires_approval,
            "evidence": self.evidence,
            "rationale": self.rationale,
            "verification": self.verification.to_dict() if isinstance(self.verification, VerificationResult) else self.verification,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RemediationPlan:
        act_val = data.get("action", "bump").lower()
        try:
            action = RemediationAction(act_val)
        except ValueError:
            action = RemediationAction.BUMP

        tier_val = data.get("risk_tier", "review").lower()
        try:
            risk_tier = RiskTier(tier_val)
        except ValueError:
            risk_tier = RiskTier.REVIEW

        pol_raw = data.get("policy_result", {})
        policy_result = (
            PolicyResult.from_dict(pol_raw)
            if isinstance(pol_raw, dict)
            else (pol_raw or PolicyResult())
        )

        ver_raw = data.get("verification")
        verification = (
            VerificationResult.from_dict(ver_raw)
            if isinstance(ver_raw, dict)
            else ver_raw
        )

        return cls(
            id=data.get("id") or f"PLAN-{uuid.uuid4().hex[:12]}",
            finding_ids=data.get("finding_ids", []),
            root_cause_id=data.get("root_cause_id", ""),
            action=action,
            target_version=data.get("target_version"),
            target_package=data.get("target_package"),
            policy_result=policy_result,
            risk_tier=risk_tier,
            requires_approval=bool(data.get("requires_approval", True)),
            evidence=data.get("evidence", []),
            rationale=data.get("rationale", ""),
            verification=verification,
        )
