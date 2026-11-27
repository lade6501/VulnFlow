<!--
harness/failure_taxonomy.md
Catalog of known agent failure modes, root-cause categories, and harness recovery actions.
-->

# VulnFlow Failure Taxonomy

Every failed verification, rejected PR, or runtime error is classified into one of the canonical taxonomy codes below (`src/vulnflow/orchestrator/failure_taxonomy.py`). Humans improve the harness (constraints, playbooks, or eval cases) rather than hand-editing individual outputs.

| Code | Category | Trigger / Signal | Recovery & Harness Action |
|---|---|---|---|
| `WRONG_VERSION` | `remediation_quality` | Proposed version unavailable in registry or fails to resolve target CVE | Tighten candidate filtering in `PlannerAgent` and add version-selection regression test |
| `BROKEN_TESTS` | `remediation_quality` | Build or unit/integration tests fail after patching (`retry_count > 0`) | Escalate major/breaking bumps to `REVIEW`, refine ecosystem playbook (`harness/playbooks/`) |
| `VERIFICATION_FAILED` | `remediation_quality` | Post-fix rescan still reports target CVE or introduces regressions (`exit_code=30`) | Fail closed (no PR); verify lockfile sync and transitive parent resolution |
| `POLICY_CONFLICT` | `governance` | Banned package, unapproved version, or denied license (`exit_code=20`) | Open idempotent exception ticket; never open a PR; review `policies/` |
| `TIMEOUT` | `execution_resilience` | Workflow, sandbox build, or provider request exceeds configured timeout | Clean up orphan branches, mark partial artifacts aborted, set terminal status `error` |
| `RATE_LIMIT` | `provider_resilience` | Upstream LLM or registry returns HTTP 429 / quota exhaustion | Retry with bounded exponential backoff honoring `Retry-After`, then fall back to deterministic mode |
| `PROMPT_INJECTION_BLOCKED` | `security_guardrail` | Hostile directive or boundary breakout detected in advisory/changelog/repo text | Defang untrusted text, log `PROMPT_INJECTION_DEFLECTED`, add hostile input to `tests/security/` |
| `SECRET_LEAK_BLOCKED` | `security_guardrail` | Raw credential or high-entropy token detected in findings, prompts, traces, or logs | Redact via `RedactionGuard`/`redact_secrets`, force `REVIEW` tier, emit rotation checklist |
| `SANDBOX_ISOLATION_ERROR` | `sandbox_boundary` | Missing offline container, symlinked manifest, or path traversal outside repo root | Fail closed before mutation; verify `VULNFLOW_BUILD_SANDBOX_IMAGE` and repo boundaries |
| `UNHANDLED_EXECUTION_ERROR` | `runtime` | Uncaught exception in any orchestrator node | Clean up orphan branches, record terminal status `error`, attach taxonomy to `RUN_FAILED` |
