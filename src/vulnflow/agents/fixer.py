"""
src/vulnflow/agents/fixer.py
Agent that analyzes test failures and formulates self-correction retries or code refactorings.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from vulnflow.contracts.remediation_plan import RemediationPlan, RiskTier
from vulnflow.llm import LLMClient, LLMError, create_llm_client
from vulnflow.mcp_servers.git_server import git_server
from vulnflow.policy.engine import parse_version_tuple

logger = logging.getLogger("vulnflow.agents.fixer")

_STACK_PATTERNS = (
    re.compile(r"(?:at\s+|in\s+)?([a-zA-Z0-9_\-./]+\.(?:js|ts|jsx|tsx|py|mjs|cjs)):(\d+)(?::(\d+))?"),
    re.compile(r"([a-zA-Z0-9_\-./]+\.(?:js|ts|jsx|tsx|py))\s*\((\d+),\s*(\d+)\)"),
    re.compile(r'File "([^"]+)", line (\d+)'),
)

_ERROR_TYPE_PATTERN = re.compile(
    r"\b(TypeError|ReferenceError|SyntaxError|AttributeError|ImportError|TS\d{4}|AssertionError)\b[:\s]*(.*)"
)


class FixerAgent:
    """
    Reasoning agent handling the self-correction loop when sandboxed tests fail.
    Formulates automated code refactorings for breaking API changes, or escalates.
    """

    def __init__(self, llm_client: LLMClient | None = None) -> None:
        self.llm_client = llm_client or create_llm_client("fixer")

    def parse_test_failure(self, test_output: str) -> dict[str, Any]:
        """Extract failing file paths, line numbers, and error descriptions from test output."""
        files: list[dict[str, Any]] = []
        error_desc = "Test failure"
        error_type = "Error"

        for line in test_output.splitlines():
            line_s = line.strip()
            err_m = _ERROR_TYPE_PATTERN.search(line_s)
            if err_m and error_desc == "Test failure":
                error_type = err_m.group(1)
                error_desc = err_m.group(2).strip() or error_type

            for pat in _STACK_PATTERNS:
                match = pat.search(line_s)
                if match:
                    raw_path = match.group(1)
                    if "node_modules" not in raw_path and not raw_path.startswith("internal/"):
                        line_no = int(match.group(2))
                        files.append({"file": raw_path, "line": line_no})
                        break

        first_err = test_output.strip().splitlines()[0] if test_output.strip() else "Test failure"
        if len(first_err) > 100:
            first_err = first_err[:97] + "..."

        return {
            "error_type": error_type,
            "error_desc": error_desc,
            "first_line": first_err,
            "failing_locations": files,
        }

    def attempt_code_refactor(
        self,
        plan: RemediationPlan,
        test_output: str,
        repo_path: str | Path,
        branch: str = "",
    ) -> dict[str, Any] | None:
        """
        Synthesize and apply automated source code refactoring when dependency bumps
        introduce breaking API changes or compiler errors.
        """
        failure_info = self.parse_test_failure(test_output)
        locations = failure_info.get("failing_locations", [])
        if not locations:
            return None

        repo_root = Path(repo_path)
        pkg_name = plan.target_package or plan.root_cause_id
        target_ver = plan.target_version or "latest"

        for loc in locations:
            rel_path = loc["file"]
            target_file = repo_root / rel_path
            if not target_file.exists():
                matches = list(repo_root.rglob(Path(rel_path).name))
                if matches:
                    target_file = matches[0]
                    rel_path = str(target_file.relative_to(repo_root))
                else:
                    continue

            try:
                content = target_file.read_text(encoding="utf-8")
            except OSError:
                continue

            lines = content.splitlines()
            err_line_idx = max(0, loc["line"] - 1)
            start_idx = max(0, err_line_idx - 5)
            end_idx = min(len(lines), err_line_idx + 6)
            context_snippet = "\n".join(lines[start_idx:end_idx])

            refactor_patch = self._synthesize_refactor(
                package=pkg_name,
                target_version=target_ver,
                file_rel=rel_path,
                context_snippet=context_snippet,
                failure_info=failure_info,
            )

            if not refactor_patch:
                continue

            old_code = refactor_patch["old_code"]
            new_code = refactor_patch["new_code"]

            if old_code in content:
                new_content = content.replace(old_code, new_code, 1)
                try:
                    target_file.write_text(new_content, encoding="utf-8")
                    diff_str = f"--- {rel_path}\n+++ {rel_path}\n- {old_code.strip()}\n+ {new_code.strip()}"
                    commit_msg = (
                        f"fix(refactor): update {rel_path} for {pkg_name}@{target_ver} compatibility"
                    )
                    git_server.git_commit(commit_msg, str(repo_root), file_path=rel_path)

                    refactor_evidence = {
                        "type": "code_refactor",
                        "file": rel_path,
                        "symbol": refactor_patch.get("symbol", pkg_name),
                        "rationale": refactor_patch.get("rationale", "Updated for version compatibility"),
                        "diff": diff_str,
                    }
                    if plan.evidence is None:
                        plan.evidence = []
                    plan.evidence.append(refactor_evidence)

                    plan.rationale += (
                        f"\n\n🛠️ Automated Code Refactoring Applied: {refactor_patch.get('rationale')} "
                        f"in `{rel_path}` to adapt to {pkg_name}@{target_ver}."
                    )

                    logger.info("FixerAgent applied automated code refactoring to %s", rel_path)
                    return refactor_evidence
                except OSError as exc:
                    logger.warning("Could not apply refactoring to %s: %s", target_file, exc)

        return None

    def _synthesize_refactor(
        self,
        package: str,
        target_version: str,
        file_rel: str,
        context_snippet: str,
        failure_info: dict[str, Any],
    ) -> dict[str, str] | None:
        """
        Formulate minimal replacement code via LLM or deterministic pattern codemods.
        """
        clean_pkg = package.replace("npm:", "").replace("pip:", "").replace("python:", "")
        error_desc = failure_info.get("error_desc", "")

        # 1. Deterministic pattern-based codemods for well-known breaking changes
        # Example A: Deprecated callback pattern (e.g. jwt.verify, bcrypt, etc.)
        callback_pattern = re.search(
            r"(\b(?:jwt|jsonwebtoken)\.verify\s*\([^,]+,\s*[^,]+),\s*function\s*\([^)]*\)\s*\{",
            context_snippet,
        )
        if callback_pattern:
            old_str = callback_pattern.group(0)
            new_str = f"const decoded = {callback_pattern.group(1)});"
            return {
                "symbol": "jwt.verify",
                "old_code": old_str,
                "new_code": new_str,
                "rationale": "Converted deprecated callback style to direct synchronous verification",
            }

        # Example B: Method renaming (e.g. lodash _.first -> _.head)
        if "first is not a function" in error_desc and "_.first" in context_snippet:
            return {
                "symbol": "_.head",
                "old_code": "_.first(",
                "new_code": "_.head(",
                "rationale": "Replaced deprecated _.first() with modern _.head()",
            }

        # Example C: Axios v1 parameter migration (e.g. config parameters or response encoding)
        if "axios" in clean_pkg.lower() and "maxBodyLength" in error_desc:
            match = re.search(r"maxContentLength:\s*\d+", context_snippet)
            if match:
                old_str = match.group(0)
                return {
                    "symbol": "maxBodyLength",
                    "old_code": old_str,
                    "new_code": f"{old_str}, maxBodyLength: Infinity",
                    "rationale": "Added required maxBodyLength for Axios v1 compatibility",
                }

        # Example D: Generic deprecated method rename mentioned in error string
        # e.g., "Error: [DEPRECATED] method oldName has been replaced with newName"
        dep_match = re.search(r"(\w+)\s+(?:has been replaced with|use instead)\s+(\w+)", error_desc)
        if dep_match:
            old_method, new_method = dep_match.group(1), dep_match.group(2)
            if f".{old_method}(" in context_snippet:
                return {
                    "symbol": new_method,
                    "old_code": f".{old_method}(",
                    "new_code": f".{new_method}(",
                    "rationale": f"Replaced deprecated .{old_method}() with supported .{new_method}()",
                }

        # Example E: urllib3 v2 removed embedded six package
        if "urllib3.packages.six.moves" in context_snippet:
            match = re.search(r"from\s+urllib3\.packages\.six\.moves\s+import\s+(\w+)", context_snippet)
            if match:
                mod_name = match.group(1)
                return {
                    "symbol": mod_name,
                    "old_code": match.group(0),
                    "new_code": f"import {mod_name}",
                    "rationale": f"urllib3 2.0 removed embedded six; replaced with direct standard library import `{mod_name}`",
                }

        # 2. If model client available and role is enabled, use LLM reasoning
        if self.llm_client and hasattr(self.llm_client, "complete"):
            try:
                prompt = (
                    f"Dependency {package} upgraded to {target_version} caused test failure:\n"
                    f"Error: {error_desc}\n"
                    f"File: {file_rel}\n"
                    f"Code context:\n{context_snippet}\n\n"
                    "Identify the exact broken line and output replacement in format:\n"
                    "OLD: <exact substring to replace>\n"
                    "NEW: <replacement substring>\n"
                    "RATIONALE: <one sentence rationale>"
                )
                resp = self.llm_client.complete([{"role": "user", "content": prompt}])
                text = resp.content if hasattr(resp, "content") else str(resp)
                old_m = re.search(r"OLD:\s*(.+)", text)
                new_m = re.search(r"NEW:\s*(.+)", text)
                rat_m = re.search(r"RATIONALE:\s*(.+)", text)
                if old_m and new_m and old_m.group(1).strip() in context_snippet:
                    return {
                        "symbol": clean_pkg,
                        "old_code": old_m.group(1).strip(),
                        "new_code": new_m.group(1).strip(),
                        "rationale": rat_m.group(1).strip() if rat_m else "Automated API adaptation",
                    }
            except (AttributeError, ValueError, TypeError, KeyError, OSError, RuntimeError, LLMError) as exc:
                logger.debug("LLM code refactoring synthesis skipped: %s", exc)

        return None

    def analyze_failure_and_correct(
        self,
        plan: RemediationPlan,
        test_output: str,
        retry_count: int,
        max_retries: int = 2,
    ) -> RemediationPlan:
        """
        Evaluate test failure output. Propose conservative fallback version on retry,
        or escalate to REVIEW tier if retries are exhausted.
        """
        logger.info(
            "FixerAgent self-correcting plan %s for %s (retry %d/%d)",
            plan.id,
            plan.target_package,
            retry_count,
            max_retries,
        )

        first_err = test_output.strip().splitlines()[0] if test_output.strip() else "Test failure"
        if len(first_err) > 100:
            first_err = first_err[:97] + "..."

        # If retries exhausted: escalate to REVIEW tier (F20 acceptance criteria)
        if retry_count >= max_retries:
            plan.risk_tier = RiskTier.REVIEW
            plan.requires_approval = True
            plan.rationale = (
                f"{plan.rationale}\n\n"
                f"🛑 Self-Correction Exhausted: Automated test suite failed on version {plan.target_version} "
                f"after {max_retries} attempt(s): {first_err}. Escalated to human review."
            )
            return plan

        # Attempt fallback to a safer patch or intermediate version if available
        current_target = plan.target_version or "0.0.0"
        t_tuple = parse_version_tuple(current_target)

        # If it was a major bump, step down to a conservative patch within previous major
        if t_tuple[0] > 1:
            fallback_version = f"{t_tuple[0] - 1}.99.9"
        else:
            fallback_version = current_target

        plan.target_version = fallback_version
        plan.rationale = (
            f"{plan.rationale}\n\n"
            f"🔄 Self-Correction Retry #{retry_count + 1}: Previous version caused build error "
            f"({first_err}). Adjusting target version to {fallback_version}."
        )
        return plan


# Global default instance
default_fixer_agent = FixerAgent()

