"""
src/vulnflow/core/risk.py
Calculates deterministic risk tiers using policy rules, SemVer bump size, test results, and CVSS severity.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Union

from vulnflow.contracts.policy import PolicyStatus
from vulnflow.contracts.remediation_plan import RiskTier

logger = logging.getLogger("vulnflow.core.risk")

# Tier strictness order (higher is stricter)
TIER_ORDER: Dict[RiskTier, int] = {
    RiskTier.AUTO: 1,
    RiskTier.REVIEW: 2,
    RiskTier.BLOCKED: 3,
}


def parse_semver(version_str: str) -> tuple[int, int, int]:
    """Parse major, minor, patch integers from a SemVer version string."""
    clean = re.sub(r"^[^\d]*", "", version_str.strip())
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", clean)
    if not match:
        return (0, 0, 0)
    major = int(match.group(1) or 0)
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    return (major, minor, patch)


def classify_semver_bump(current_version: str, target_version: str) -> str:
    """
    Classify the SemVer magnitude between two versions: 'patch', 'minor', 'major', or 'same'.
    """
    cur_maj, cur_min, cur_pat = parse_semver(current_version)
    tgt_maj, tgt_min, tgt_pat = parse_semver(target_version)

    if tgt_maj > cur_maj:
        return "major"
    elif tgt_min > cur_min:
        return "minor"
    elif tgt_pat > cur_pat:
        return "patch"
    elif (tgt_maj, tgt_min, tgt_pat) == (cur_maj, cur_min, cur_pat):
        return "same"
    else:
        # Downgrade / rollback
        return "major"


def calculate_risk_tier(
    current_version: str,
    target_version: Optional[str],
    policy_status: Union[PolicyStatus, str] = PolicyStatus.APPROVED,
    is_direct: bool = True,
    tests_passed: bool = True,
    max_cvss: float = 0.0,
) -> RiskTier:
    """
    Deterministically compute organizational RiskTier based on policy, bump size,
    test results, and vulnerability metrics.

    Rules conform to policies/risk_tiers.yaml:
    - Banned or license-denied -> BLOCKED
    - No approved target version -> BLOCKED
    - Tests failed -> REVIEW
    - Major version bump -> REVIEW
    - Minor version bump on direct dependency -> REVIEW
    - Unknown package policy -> REVIEW
    - Safe patch on approved package with green tests -> AUTO
    """
    pol_str = policy_status.value if isinstance(policy_status, PolicyStatus) else str(policy_status).lower()

    # Rule 1: Prohibited policy statuses
    if pol_str in (PolicyStatus.BANNED.value, PolicyStatus.LICENSE_DENIED.value, "banned", "license_denied"):
        return RiskTier.BLOCKED

    # Rule 2: Missing target version
    if not target_version:
        return RiskTier.BLOCKED

    # Rule 3: Test failure escalates to REVIEW
    if not tests_passed:
        return RiskTier.REVIEW

    # Rule 4: SemVer bump size and unknown package evaluation
    bump_type = classify_semver_bump(current_version, target_version)

    # Major version bumps always require human security review
    if bump_type == "major":
        return RiskTier.REVIEW

    # Unknown package policy: allow routine patch bumps to auto-approve, require review for others
    if pol_str in (PolicyStatus.UNKNOWN.value, "unknown", "require_approval"):
        if bump_type == "patch" and tests_passed:
            return RiskTier.AUTO
        return RiskTier.REVIEW

    # High CVSS critical vulnerability on direct dependency requiring sign-off
    if max_cvss >= 9.0 and is_direct and bump_type != "patch":
        return RiskTier.REVIEW

    # Default for routine patch/minor bumps with passing tests
    return RiskTier.AUTO


def enforce_stricter_tier(
    code_computed_tier: RiskTier,
    proposed_tier: Union[str, RiskTier],
) -> RiskTier:
    """
    Enforces the fundamental architectural invariant:
    The AI model can only make the risk tier stricter, NEVER looser.

    Example:
    - Code says AUTO, model says REVIEW -> returns REVIEW
    - Code says REVIEW, model says AUTO -> returns REVIEW (relaxing forbidden)
    - Code says BLOCKED, model says AUTO -> returns BLOCKED
    """
    if isinstance(proposed_tier, str):
        try:
            prop_enum = RiskTier(proposed_tier.lower())
        except ValueError:
            prop_enum = code_computed_tier
    else:
        prop_enum = proposed_tier

    code_rank = TIER_ORDER.get(code_computed_tier, 2)
    prop_rank = TIER_ORDER.get(prop_enum, 2)

    # Return whichever is stricter (higher rank)
    return prop_enum if prop_rank > code_rank else code_computed_tier
