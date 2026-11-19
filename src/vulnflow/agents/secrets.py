"""
src/vulnflow/agents/secrets.py
Agent handling exposed secret revocation, rotation checklists, and safe code remediation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from vulnflow.contracts.finding import Finding, FindingType
from vulnflow.contracts.remediation_plan import RemediationAction, RemediationPlan, RiskTier
from vulnflow.core.redaction import redact_secrets

logger = logging.getLogger("vulnflow.agents.secrets")


class SecretsAgent:
    """Remediates leaked credentials, secrets, and PII without exposing values to models."""

    def plan_secret_remediation(
        self,
        finding: Finding,
        repo_path: str = ".",
    ) -> RemediationPlan:
        """
        Produce a safe remediation plan for a secret finding.

        Strict invariants (F23):
        - Risk tier is ALWAYS RiskTier.REVIEW.
        - Requires approval is ALWAYS True.
        - The secret value is NEVER included in prompts, plans, or rationales.
        """
        rule_id = finding.metadata.get("rule_id", "generic-secret")
        file_path = finding.location.file_path if finding.location else "unknown"
        raw_fp = str(finding.metadata.get("fingerprint", "N/A"))
        # Never leak raw credential in fingerprint; redact and hash
        masked_fp = redact_secrets(raw_fp)
        if masked_fp == raw_fp and len(raw_fp) > 8 and raw_fp != "N/A":
            import hashlib
            masked_fp = f"SHA256:{hashlib.sha256(raw_fp.encode('utf-8')).hexdigest()[:12]}"

        # Step-by-step security rotation checklist
        checklist = [
            f"1. Revoke the exposed {rule_id} credential immediately in the upstream provider.",
            f"2. Issue a replacement credential and store securely in a vault (e.g., AWS Secrets Manager, Vault, GitHub Secrets).",
            f"3. Refactor {file_path} to read the secret from an environment variable instead of hardcoding.",
            f"4. If this commit is pushed, rotate all other keys associated with this service account.",
            f"5. Scrub repository history using git-filter-repo or BFG Repo-Cleaner if public.",
        ]

        diff_snippet = (
            f"--- {file_path}\n"
            f"+++ {file_path}\n"
            f"- const API_KEY = [REDACTED_SECRET];\n"
            f"+ const API_KEY = process.env.{rule_id.upper()}_KEY;\n"
        )

        rationale = (
            f"Exposed Credential Incident ({rule_id}) detected in {file_path}.\n"
            f"• Fingerprint: {masked_fp}\n"
            f"• Action: ROTATE and remove plaintext credential from codebase.\n"
            f"• Safeguard: Secret values are permanently redacted at ingestion.\n"
            f"• Governance: Secret remediations are strictly classified as REVIEW tier and require human verification.\n\n"
            f"Rotation Checklist:\n" + "\n".join(checklist)
        )
        rationale = redact_secrets(rationale)

        plan = RemediationPlan(
            id=f"PLAN-SEC-{finding.id[:8]}",
            finding_ids=[finding.id],
            root_cause_id=f"secret:{rule_id}",
            action=RemediationAction.ROTATE,
            target_package=f"secret:{rule_id}",
            target_version="env-var",
            risk_tier=RiskTier.REVIEW,
            requires_approval=True,
            rationale=rationale,
            evidence=[{
                "rule_id": rule_id,
                "file_path": file_path,
                "fingerprint": masked_fp,
                "checklist": checklist,
                "diff": diff_snippet,
            }],
        )
        return plan

    formulate_rotation_plan = plan_secret_remediation


default_secrets_agent = SecretsAgent()
