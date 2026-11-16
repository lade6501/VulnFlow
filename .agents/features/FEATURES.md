<!--
features.md
Registry of every VulnFlow feature with phase, owning paths, dependencies, acceptance criteria and status.
-->

# VulnFlow AI: feature registry

This is the single list of work. Assistants and humans implement **only** features listed here, one per PR, touching only the paths shown for that feature (plus its tests and docs). Rules for how to implement are in `skills.md`.

## How to use this file

1. Pick a feature by ID. Check its phase and that every dependency is `done`.
2. Read its acceptance criteria. They are the test of completion.
3. Branch `feat/<ID>-<short-name>`; commit messages start with the ID (for example `F10: add policy_check MCP tool`).
4. When all acceptance criteria pass and checks are green, set Status to `done`.

**Status values:** `todo`, `in-progress`, `blocked`, `done`. Only change a status for the feature you worked on.

**Phases:** P0 foundation, P1 core spine, P2 intelligence, P3 breadth, P4 hardening, P5 evaluation. Do not start a feature whose phase gate has not passed unless a human says so.

Paths are relative to `src/vulnflow/` unless they start with `api/`, `ui/`, `harness/`, `policies/`, `evals/`, `samples/`, `ci-templates/`, `scripts/` or `tests/`.

## Scope boundaries

**In scope:** all features F01 to F41 below.

**Out of scope (do not build, do not scaffold, do not stub):**

- Auto-merge of PRs (autonomy L3) and fleet-wide campaigns (L4)
- Multi-tenant hosted service and Helm chart
- Reachability analysis, SBOM generation and ingestion
- Replacing or re-implementing a scanner
- A second orchestration framework alongside LangGraph
- Any ecosystem other than npm (primary) and Maven (stretch, F26)

## 3.1 Ingestion and normalization

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F01 | Scanner adapters | P1, P3 | `adapters/input/trivy.py`, `sarif.py`, then `grype.py`, `osv.py`, `gitleaks.py` | F02 | Trivy and SARIF fixtures parse into valid `Finding` lists; P3 adds Grype, OSV-Scanner and Gitleaks the same way; malformed input yields a typed error | todo |
| F02 | Finding normalization | P1 | `contracts/finding.py` | none | One `Finding` schema validates all adapter outputs; ID is a stable hash of scanner, repo, package, version, CVE and location | todo |
| F03 | Deduplication | P1 | `core/dedupe.py` | F02 | Same finding from two scanners or two runs collapses to one; counts before and after are reported | todo |
| F04 | Secret redaction | P1 | `core/redaction.py` | F02 | Seeded fake secrets never appear in `Finding`, state, logs or prompts; only type, location and fingerprint remain | todo |

## 3.2 Analysis and intelligence

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F05 | Root-cause grouping | P2 | `knowledge/graph/queries.py`, `agents/rootcause.py` | F03 | `root_cause` collapses a transitive-only sample to one parent dependency and explains it | todo |
| F06 | Blast-radius query | P2 | `knowledge/graph/queries.py`, `mcp_servers/knowledge_server.py` | F05 | `blast_radius` returns the services and repos affected by a package change on the seeded graph | todo |
| F07 | Advisory-grounded impact analysis | P2 | `knowledge/vector/`, `knowledge/sources/`, `agents/planner.py` | F10 | `advisory_search` returns the right advisory and release-note chunks filtered by package; plan rationale cites chunk IDs | todo |
| F08 | Risk scoring and tiering | P2 | `core/risk.py`, `policies/risk_tiers.yaml` | F10 | Tier is computed by code from policy, bump size, tests and evidence; the model can only make it stricter | todo |
| F09 | Findings report | P2 | `reporting/markdown.py`, `json_report.py`, `pr_comment.py` | F05 | Markdown and JSON reports group findings by root cause and show policy result and tier | todo |

## 3.3 Governance and policy

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F10 | Approved-package check | P1 | `policy/engine.py`, `mcp_servers/policy_server.py`, `policies/approved_packages.yaml` | F02 | `policy_check` returns approved, deprecated, banned, unknown or license_denied with rule and replacement; deterministic; table-driven tests pass | todo |
| F11 | Fix-candidate filtering | P1 | `policy/engine.py`, `mcp_servers/policy_server.py` | F10 | `policy_candidates` removes every version the policy rejects; the unapproved-fix sample yields no candidates | todo |
| F12 | Replacement proposals | P2 | `policy/engine.py`, `agents/planner.py` | F10 | Deprecated or banned package gets the approved replacement in the plan with tier `review` | todo |
| F13 | Exception workflow | P2 | `mcp_servers/ticket_server.py`, `orchestrator/nodes.py`, `orchestrator/routing.py` | F11 | When only unapproved fixes exist, a ticket with CVE context is created, no PR is opened, and a rerun creates no duplicate | todo |
| F14 | Registry availability check | P2 | `mcp_servers/registry_server.py` | F10 | `registry_check` confirms the target version exists in the configured registry before a PR | todo |
| F15 | License rules | P3 | `policy/licenses.py`, `policies/licenses.yaml` | F10 | Denied licenses return `license_denied`; table-driven tests cover allowed and denied cases | todo |

## 3.4 Remediation

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F16 | Fix planner | P1 | `agents/planner.py`, `contracts/remediation_plan.py` | F11 | Produces a valid `RemediationPlan` chosen from policy-allowed candidates only | todo |
| F17 | Sandboxed execution | P1 | `sandbox/runner.py`, `mcp_servers/git_server.py` | F16 | Clone, branch and patch run in an ephemeral container with scoped token and no production secrets | todo |
| F18 | Build and test runner | P1 | `sandbox/runner.py`, `mcp_servers/build_server.py`, `adapters/ecosystem/npm.py` | F17 | `build_test` returns build and test results for the patched branch, with timeouts | todo |
| F19 | PR creation | P1 | `mcp_servers/git_server.py`, `reporting/pr_comment.py` | F18 | `pr_create` opens a PR with root cause, evidence, policy status and test results; rerun does not duplicate it | todo |
| F20 | Self-correction loop | P2 | `orchestrator/routing.py`, `agents/fixer.py` | F18 | Test failure retries with error context up to the configured limit, then escalates to `review` | todo |
| F21 | Human approval gate | P2 | `orchestrator/approval.py`, `mcp_servers/notify_server.py` | F16 | Run pauses for review-tier plans, persists state, and resumes on approve or stops on reject with a stored reason | todo |
| F22 | Verification | P2 | `agents/verifier.py`, `mcp_servers/scan_server.py` | F19 | `scan_diff` and a policy recheck on the full tree decide resolved or failed in code; a failed verify is never reported as success | todo |

## 3.5 Breadth findings

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F23 | Secrets and PII flow | P3 | `agents/secrets.py`, `adapters/input/gitleaks.py`, `core/redaction.py` | F04, F21 | Always `review`; produces a rotation checklist and code-change plan; the value is never seen by the model | todo |
| F24 | Expiry predictor | P3 | `agents/expiry.py`, `knowledge/graph/queries.py` | F05 | `expiring` returns artifacts in the warning window and the predictor estimates a risk window | todo |
| F25 | Renewal automation | P3 | `agents/expiry.py`, `mcp_servers/ticket_server.py` | F24 | A renewal ticket or PR is opened before expiry; idempotent on rerun | todo |
| F26 | Second ecosystem (stretch) | P3 | `adapters/ecosystem/maven.py`, `harness/playbooks/maven.md` | F18 | The maven sample repo reproduces the npm simple-bump outcome; does not gate the MVP | todo |

## 3.6 Integration

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F27 | CLI and Docker image | P1 | `cli.py`, `Dockerfile` | F19 | `analyze`, `fix`, `verify`, `watch-expiry`, `report` work with modes `report`, `pr`, `dry-run`; exit codes match `skills.md` | todo |
| F28 | GitHub Action | P1 | `ci-templates/github-actions.yml`, `adapters/ci/github_action/` | F27 | Action runs the scanner, calls the container and acts on the exit code on a sample repo | todo |
| F29 | Jenkins and GitLab templates | P3 | `ci-templates/Jenkinsfile`, `ci-templates/gitlab-ci.yml` | F27 | Same container and scenarios pass from both templates | todo |
| F30 | Webhook and API mode | P3 | `api/main.py`, `api/routes/` | F27 | A webhook triggers a run and returns a run ID retrievable through the API | todo |

## 3.7 Operations and trust

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F31 | Tracing | P0, P4 | `observability/tracing.py` | none | Every node, agent call and MCP call is a span with model, prompt version, tokens, latency and status; backend swappable by config | todo |
| F32 | Audit log | P4 | `observability/audit_log.py` | F31 | Append-only record of plans, policy decisions, approvals, PRs and verification results | todo |
| F33 | Failure handling | P4 | `orchestrator/`, `config.py` | F20 | Timeouts, retries with backoff and rate-limit handling; every run ends in a clear terminal status with no orphan branches, PRs or tickets | todo |
| F34 | Prompt-injection defenses | P4 | `agents/prompts/`, `tests/security/` | F07 | Hostile changelog and advisory text does not change the plan; retrieved text is delimited as untrusted; the injection scenario passes | todo |
| F35 | Evaluation harness | P5 | `evals/` | F22 | `make eval` runs all scenarios and writes metrics: auto-fix rate, dedupe ratio, time to verified fix, policy violations, bad-fix rate, cost per finding | todo |

## 3.8 User interface

| ID | Feature | Phase | Primary paths | Depends on | Acceptance criteria | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F36 | Runs dashboard | P2 | `ui/src/pages/Runs.tsx`, `api/routes/runs.py`, `store/` | F27 | Lists runs with repo, status, counts, cost and exit code | todo |
| F37 | Plan and approval screen | P2 | `ui/src/pages/PlanApproval.tsx`, `api/routes/plans.py`, `api/routes/approvals.py` | F21 | Shows plan, evidence, policy result, diff and results; approve or reject resumes or stops the run and records the approver | todo |
| F38 | Graph explorer | P3 | `ui/src/pages/GraphExplorer.tsx`, `api/routes/graph.py` | F05, F06 | Renders a root-cause and blast-radius subgraph from the API | todo |
| F39 | Policy and exceptions view | P3 | `ui/src/pages/PolicyExceptions.tsx` | F13 | Lists blocked-by-policy plans and exception tickets; approved-package lookup works | todo |
| F40 | Expiry view | P3 | `ui/src/pages/Expiry.tsx` | F24 | Lists artifacts by expiry date with renewal status | todo |
| F41 | Metrics and eval view | P5 | `ui/src/pages/Metrics.tsx`, `api/routes/metrics.py` | F35 | Shows eval and run metrics with links to traces | todo |

## Cross-cutting items (not features, but required by every PR)

- Header on every new file (`skills.md` section 4.1).
- Tests alongside the change; security-relevant changes also under `tests/security/`.
- Docs updated when behavior or contracts change.
- Status updated here when criteria pass.

## Phase gates

| Phase | Gate (must pass before the next phase's work counts as done) |
| --- | --- |
| P0 | A stubbed run goes from a sample scanner report to a fake PR through the orchestrator using only stub tools |
| P1 | One approved patch bump produces a real PR on a sample repo through the real policy server and the real LLM |
| P2 | All policy and vulnerability sample scenarios run end to end with real knowledge tools, including the unapproved-fix case producing a ticket and no PR |
| P3 | Feature freeze: all scenarios, including secrets and expiry, pass in GitHub Actions, Jenkins and GitLab |
| P4 | All injection and secret-leak tests pass; a failed run leaves no partial branch, PR or ticket without a clear status |
| P5 | One-command demo environment; metrics report generated from a clean run |

## Change log

Record changes to this file here (date, ID, what changed, who). Adding, removing or re-scoping a feature needs human approval.

| Date | ID | Change | By |
| --- | --- | --- | --- |
