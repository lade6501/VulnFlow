"""
src/vulnflow/agents/secrets.py
Agent handling exposed secret revocation, rotation checklists, and safe code remediation.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vulnflow.contracts.finding import Finding, FindingType
from vulnflow.contracts.remediation_plan import RemediationAction, RemediationPlan, RiskTier
from vulnflow.core.redaction import redact_secrets

logger = logging.getLogger("vulnflow.agents.secrets")


class SecretsAgent:
    """Remediates leaked credentials, secrets, and PII without exposing values to models."""

    @staticmethod
    def get_env_expression(var_name: str, file_ext: str) -> str:
        """
        Produce a language-idiomatic environment variable lookup expression.
        Supports Python, JavaScript/TypeScript, Go, Java/Kotlin, C#, Ruby, PHP, Rust, Shell, and Config formats.
        """
        clean_var = re.sub(r"[^A-Za-z0-9_]", "_", var_name.lstrip("$")).upper()
        ext = file_ext.lower()
        if ext in (".py", ".pyw"):
            return f'os.getenv("{clean_var}", "")'
        elif ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            return f'process.env.{clean_var} || ""'
        elif ext in (".go",):
            return f'os.Getenv("{clean_var}")'
        elif ext in (".java", ".kt", ".kts", ".scala", ".groovy"):
            return f'System.getenv("{clean_var}")'
        elif ext in (".cs",):
            return f'Environment.GetEnvironmentVariable("{clean_var}")'
        elif ext in (".rb",):
            return f'ENV["{clean_var}"]'
        elif ext in (".php",):
            return f'getenv("{clean_var}")'
        elif ext in (".rs",):
            return f'std::env::var("{clean_var}").unwrap_or_default()'
        elif ext in (".sh", ".bash", ".zsh"):
            return f'"${{{clean_var}:-}}"'
        elif ext in (".yaml", ".yml", ".json", ".properties", ".env", ".ini", ".conf", ".toml"):
            return f"${{{clean_var}}}"
        return f'os.getenv("{clean_var}", "")'

    def remediate_code(
        self,
        content: str,
        file_suffix: str,
        rule_id: str,
        line_no: Optional[int] = None,
    ) -> Tuple[str, str]:
        """
        Language-agnostic secret remediation.
        Replaces hardcoded plaintext secret assignment with an environment variable lookup
        appropriate for the target programming language or configuration format.

        Returns:
            Tuple[new_content, diff_content]
        """
        lines = content.splitlines(keepends=True)
        clean_rule = rule_id.lower().replace("secret:", "").replace("rule-", "").replace("-", "_")

        # Regex matching assignment syntax across Python, JS, Go, Java, PHP, C#, Ruby, Shell, Config
        assign_re = re.compile(
            r"^(?P<prefix>\s*(?:(?:export\s+)?(?:const|let|var|final|val|static|private|public|protected|string|String|\$|[A-Za-z0-9_<>\[\]]+)\s+)*)"
            r"(?P<var_name>[A-Za-z0-9_\$]+)"
            r"(?P<infix>\s*(?::=|=|:)\s*)"
            r"(?P<quote>[\x27\x22`])(?P<val>[^\x27\x22`]+)(?P=quote)"
            r"(?P<suffix>\s*;?\s*)$"
        )

        target_idx: Optional[int] = None
        target_match: Optional[re.Match[str]] = None

        # Priority 1: Check by line number if provided from scanner finding
        if line_no and 1 <= line_no <= len(lines):
            for c_idx in (line_no - 1, line_no - 2, line_no):
                if 0 <= c_idx < len(lines):
                    m = assign_re.match(lines[c_idx])
                    if m:
                        target_idx = c_idx
                        target_match = m
                        break

        # Priority 2: Match by rule keywords against variable name or line content
        if target_idx is None:
            rule_tokens = [tok for tok in clean_rule.split("_") if len(tok) >= 3]
            for idx, line in enumerate(lines):
                m = assign_re.match(line)
                if not m:
                    continue
                var_name = m.group("var_name").lower()
                val = m.group("val").lower()
                line_lower = line.lower()

                if "slack" in clean_rule and ("slack" in var_name or "slack.com" in line_lower):
                    target_idx, target_match = idx, m
                    break
                if "aws" in clean_rule and (
                    "aws" in var_name
                    or "access_key" in var_name
                    or "secret_key" in var_name
                    or "akia" in line_lower
                ):
                    target_idx, target_match = idx, m
                    break
                if ("ssn" in clean_rule or "pii" in clean_rule) and ("ssn" in var_name or "pii" in var_name):
                    target_idx, target_match = idx, m
                    break
                if any(tok in var_name for tok in rule_tokens):
                    target_idx, target_match = idx, m
                    break
                if ("api" in clean_rule or "key" in clean_rule or "secret" in clean_rule) and any(
                    k in var_name for k in ("api", "secret", "token", "password", "key")
                ):
                    target_idx, target_match = idx, m
                    break

        if target_idx is not None and target_match is not None:
            prefix = target_match.group("prefix")
            var_name = target_match.group("var_name")
            infix = target_match.group("infix")
            suffix = target_match.group("suffix")
            clean_var = var_name.lstrip("$")
            env_expr = self.get_env_expression(clean_var, file_suffix)

            new_line = f"{prefix}{var_name}{infix}{env_expr}{suffix}"
            if not new_line.endswith("\n") and lines[target_idx].endswith("\n"):
                new_line += "\n"
            old_line = lines[target_idx]
            lines[target_idx] = new_line
            new_content = "".join(lines)

            # Ensure 'import os' is present for Python files using os.getenv
            if file_suffix.lower() in (".py", ".pyw") and "import os" not in new_content:
                new_content = "import os\n" + new_content

            diff = f"--- target\n+++ target\n- {old_line.strip()}\n+ {new_line.strip()}"
            return new_content, diff

        return content, ""

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
        line_no = finding.location.line if finding.location else None
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

        file_ext = Path(file_path).suffix if file_path else ""
        sample_env_expr = self.get_env_expression(rule_id, file_ext)
        diff_snippet = (
            f"--- {file_path}\n"
            f"+++ {file_path}\n"
            f"- [REDACTED_CREDENTIAL_VALUE]\n"
            f"+ {sample_env_expr}\n"
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
                "line": line_no,
                "fingerprint": masked_fp,
                "checklist": checklist,
                "diff": diff_snippet,
            }],
        )
        return plan

    formulate_rotation_plan = plan_secret_remediation


default_secrets_agent = SecretsAgent()
