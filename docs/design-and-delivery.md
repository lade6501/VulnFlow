<!--
docs/design-and-delivery.md
VulnFlow AI phase-wise design, architecture, delivery roadmap, and harness engineering specification.
-->

# VulnFlow AI – Phase-wise Design & Delivery Document

Nov 6, 2026 · @test

## 1. Overview

VulnFlow AI is an agentic remediation layer that sits on top of existing security scanners and CI/CD pipelines, turning findings into verified fixes with humans approving only the risky ones. It does not replace scanners; it removes the repetitive loop of investigate, fix, rebuild, redeploy and rescan.

### 1.1 Problem

Scanners report vulnerable or deprecated dependencies, exposed secrets and PII, and expiring artifacts. Developers triage duplicates by hand, work out root causes, choose a safe fix, rebuild, redeploy and rescan. The same work repeats across repos and releases.

### 1.2 Goals

- Correlate duplicate findings and group them by root cause.
- Use LLMs, RAG and graph reasoning to judge impact and pick the right remediation.
- Automate safe fixes: branch, patch, build, test, open a PR, rescan.
- Enforce the organization's approved-package policy on every fix.
- Predict artifact and certificate expiry and trigger renewal before a scanner flags it.
- Keep humans in the loop for high-risk changes.
- Verify the issue is resolved, not just claimed resolved.
- Plug into any CI system through one container and one contract.

### 1.3 Non-goals

- Replacing or re-implementing scanners.
- Auto-merging to production without an approval policy.
- Building a full vulnerability management dashboard (a minimal report view only).

### 1.4 Design principles

1. **LLM proposes, tools execute, scanners verify.** No fix counts until a rescan confirms it.
2. **Policy decisions are deterministic.** Approved, banned or unknown status comes from code, never from model judgment.
3. **Scanner- and CI-agnostic.** Everything enters as a normalized `Finding` and leaves as a `RemediationPlan` plus side effects through MCP tools.
4. **Secrets never reach the model.** Values are redacted at ingestion; only type and location travel.
5. **Retrieved text is data, not instructions.** Advisories, changelogs and repo content cannot change agent behavior.
6. **Everything is auditable.** Every decision, tool call and approval is traced.

## 2. Architecture

VulnFlow is layered so that LLM agents propose remediation while deterministic components decide and execute it. CI systems and scanners feed one container, and every side effect leaves through an MCP tool.

&#91;embedded content: architecture · 4 layers, MCP as the only path to side effects\]

Read the figure top down: reports enter the container, the orchestrator drives analysis, decision, action and verification, agents reason through MCP tools, and those tools reach policy, knowledge, the sandbox and external systems.

### 2.1 Components

| Layer | Component | Responsibility |
| --- | --- | --- |
| Input | Scanner adapters | Parse Trivy, Grype, OSV-Scanner, Gitleaks and generic SARIF into `Finding` |
| Input | Dedupe and redaction | Merge duplicates; strip secret and PII values before anything else sees them |
| Orchestration | LangGraph state machine | Run the node sequence, persist state, pause for approval, retry on failure |
| Reasoning | LLM agents | Triage, explain root cause, plan the fix, summarize results; output typed plans only |
| Tools | MCP servers | Policy, knowledge, git and PR, scan, build and test, registry, ticket, approval |
| Governance | Policy engine | Deterministic approved, deprecated, banned, unknown and license decisions |
| Knowledge | Vector store | Advisories, release notes, policy prose, playbooks |
| Knowledge | Graph store | Dependency graph, CVE links, policy links, fix history, artifact inventory |
| Execution | Sandbox | Ephemeral clone, patch, build and test with scoped credentials |
| Trust | Observability and audit | Traces, cost tracking and an append-only decision log |
| Delivery | CLI and CI templates | One container entry point wrapped by GitHub, Jenkins and GitLab templates |

### 2.2 Run lifecycle

1. CI runs a scanner and calls `vulnflow analyze` with the report.
2. Adapters normalize findings, redact secrets and deduplicate.
3. A graph query groups findings by root cause.
4. For each group, the planner retrieves advisories and release notes, lists candidate fix versions and filters them through the policy engine.
5. The risk module assigns a tier. Blocked plans open an exception ticket; review-tier plans pause for approval.
6. Approved or auto-tier plans run in the sandbox: patch, build and test, with a bounded number of retries that carry the error context.
7. A PR opens with root cause, evidence, policy status and test results.
8. The verify step rescans the branch, diffs finding IDs and re-runs the policy check on the full dependency tree.
9. The outcome is written back to the graph and vector stores, a report is produced and an exit code returns to CI.

### 2.3 Agent roles

| Agent | Input | Output | Cannot do |
| --- | --- | --- | --- |
| Triage | Normalized findings | Priority and group hints | Change files or call write tools |
| Root cause | Subgraph from graph query | Plain-language root-cause explanation | Override graph results |
| Planner | Groups, evidence, allowed versions | `RemediationPlan` | Choose a version the policy rejects; set the approval tier |
| Fixer | Approved plan | Patch instructions for the sandbox tools | Run commands outside MCP tools |
| Verifier | Rescan diff | Summary of the verdict | Declare success; the verdict is computed by code |
| Secrets | Redacted secret findings | Rotation checklist and code-change plan | See secret values |
| Expiry | Artifact inventory and dates | Risk window and renewal plan | Renew without approval |

### 2.4 Orchestrator routing

- **Policy blocked:** route to the exception node, open a ticket, end the plan without a PR.
- **Review tier:** interrupt and wait for approval; resume on approve, stop on reject and store the reason.
- **Test failure:** return to the fixer with the error context, up to a configured retry limit, then escalate to review.
- **Verification failure:** mark the plan failed, keep the branch for inspection and notify, never report success.

## 3. Feature catalog

VulnFlow has 41 features in eight groups, each mapped to the phase that delivers it (phases are defined in section 4). P0 is foundation, P1 the core spine, P2 intelligence, P3 breadth, P4 hardening, P5 evaluation.

### 3.1 Ingestion and normalization

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F01 | Scanner adapters | Parse Trivy and generic SARIF first; Grype, OSV-Scanner and Gitleaks later | P1, P3 |
| F02 | Finding normalization | Convert every scanner output to one `Finding` schema | P1 |
| F03 | Deduplication | Merge repeats by package, version, CVE and location across scanners and runs | P1 |
| F04 | Secret redaction | Strip secret and PII values at ingestion so only type and location continue | P1 |

### 3.2 Analysis and intelligence

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F05 | Root-cause grouping | Trace findings through the dependency graph to the parent that introduced them | P2 |
| F06 | Blast-radius query | Answer what else breaks or is affected if a dependency is changed | P2 |
| F07 | Advisory-grounded impact analysis | Retrieve CVE, GHSA and OSV text plus release notes; judge exploitability and breaking-change risk | P2 |
| F08 | Risk scoring and tiering | Combine severity, bump size, test result and reachability into an auto-PR or approval tier | P2 |
| F09 | Findings report | Markdown and JSON summary, plus a PR or pipeline comment grouped by root cause | P2 |

### 3.3 Governance and policy

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F10 | Approved-package check | Classify a package and version as approved, deprecated, banned or unknown | P1 |
| F11 | Fix-candidate filtering | Drop any fix version the policy does not allow before the agent proposes it | P1 |
| F12 | Replacement proposals | Suggest the approved replacement for deprecated or banned packages | P2 |
| F13 | Exception workflow | Open a ticket or issue with CVE context when the only fix is not yet approved | P2 |
| F14 | Registry availability check | Confirm the target version exists in the internal registry or mirror before a PR | P2 |
| F15 | License rules | Deny or flag packages by license (for example GPL, AGPL) | P3 |

### 3.4 Remediation

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F16 | Fix planner | Choose between bump, override, pin or replace and produce a `RemediationPlan` | P1 |
| F17 | Sandboxed execution | Clone, branch and patch inside an ephemeral container with scoped tokens | P1 |
| F18 | Build and test runner | Run the repo's build and tests on the patched branch and capture results | P1 |
| F19 | PR creation | Open a PR with root cause, advisory evidence, policy status and test results | P1 |
| F20 | Self-correction loop | On build or test failure, retry with the error context up to a fixed limit | P2 |
| F21 | Human approval gate | Pause the run for review when the risk tier or policy requires it | P2 |
| F22 | Verification | Rescan the branch, diff finding IDs, re-run the policy check, confirm resolved | P2 |

### 3.5 Breadth findings

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F23 | Secrets and PII flow | Always human-approved: redacted analysis, rotation checklist, code change PR | P3 |
| F24 | Expiry predictor | Read certificate and artifact expiry metadata, estimate risk windows | P3 |
| F25 | Renewal automation | Open a renewal ticket or PR before the scanner would flag expiry | P3 |
| F26 | Second ecosystem | Add a second package ecosystem to the fixer (stretch) | P3 |

### 3.6 Integration

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F27 | CLI and Docker image | One container, one command, any CI | P1 |
| F28 | GitHub Action | Reusable action that calls the container on scan failure | P1 |
| F29 | Jenkins and GitLab templates | Copy-paste pipeline snippets calling the same container | P3 |
| F30 | Webhook and API mode | Optional service mode for event-driven runs | P3 |

### 3.7 Operations and trust

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F31 | Tracing | Trace every LLM call, tool call and decision | P0, P4 |
| F32 | Audit log | Immutable record of plans, approvals and actions | P4 |
| F33 | Failure handling | Timeouts, rate limits, scan flakes and partial-failure recovery | P4 |
| F34 | Prompt-injection defenses | Treat retrieved and repo text as data; test with hostile inputs | P4 |
| F35 | Evaluation harness | Run sample repos, compute metrics, compare against baseline | P5 |

### 3.8 User interface

The UI is a control plane over the same runs the CLI and CI produce; every action in it also works from the CLI or a PR comment (details in section 13.2).

| ID | Feature | What it does | Phase |
| --- | --- | --- | --- |
| F36 | Runs dashboard | List runs with repo, trigger, status, finding counts, cost and exit code | P2 |
| F37 | Plan and approval screen | Show plan, cited evidence, policy result, diff, test and rescan results; approve, reject with reason or request another approach | P2 |
| F38 | Graph explorer | Interactive root-cause and blast-radius subgraph | P3 |
| F39 | Policy and exceptions view | Blocked-by-policy list, exception tickets, approved-package lookup | P3 |
| F40 | Expiry view | Certificates and artifacts by expiry date with renewal status | P3 |
| F41 | Metrics and eval view | Auto-fix rate, time to verified fix, cost per finding, links to traces and eval runs | P5 |

## 4. Phase-wise plan

Delivery runs in six phases over three weeks; each ends in a gate that must pass before the next phase's work is considered done. Phases 2 and 3 run in parallel during Week 2 because breadth features depend only on the Phase 1 spine.

&#91;embedded content: roadmap · 6 phases, 6 gates, 3 weeks\]

Bars show timing within each week and diamonds mark the gate that closes each phase.

### Phase 0: Foundation and contracts (Days 1-2)

**Objective:** lock the interfaces so every later component is built against the same contracts.

- Define `Finding`, `RemediationPlan`, policy and graph schemas (section 6).
- Create the repo skeleton, tooling, linting, CI for the project itself and the Docker Compose environment (section 5).
- Stand up stub MCP servers returning canned data for every tool in section 8.
- Define the LangGraph state object and node names.
- Wire tracing early so every later run is observable (F31).
- Build sample repos with seeded problems (section 11).

**Gate:** a stubbed run goes from a sample scanner report to a fake PR through the orchestrator, using only stub tools.

### Phase 1: Core remediation spine (Days 3-5)

**Objective:** scan fails, a real PR opens, CI is green.

- **Features:** F01 (Trivy, SARIF), F02, F03, F04, F10, F11, F16, F17, F18, F19, F27, F28.
- Real `policy_check` MCP server backed by the YAML policy.
- Orchestrator runs ingest, dedupe, policy filter, plan, fix, test and PR for one ecosystem.
- GitHub MCP integration for branch and PR.
- Docker image and GitHub Action v1.

**Gate:** one approved patch bump produces a real PR on a sample repo through the real policy server and the real LLM.

### Phase 2: Intelligence and verification (Week 2)

**Objective:** make decisions explainable, grouped and verified.

- **Features:** F05, F06, F07, F08, F09, F12, F13, F14, F20, F21, F22.
- Vector store loaded with advisories, release notes and policy prose; retrieval tool replaces the stub.
- Neo4j loaded with dependency graphs; root-cause and blast-radius queries replace the stub.
- Risk tiers decide auto-PR versus approval; approval gate pauses and resumes the run.
- Verify agent rescans the branch, diffs finding IDs and re-runs the policy check.
- Exception workflow for fixes that exist but are not approved.

**Gate:** all policy and vulnerability sample scenarios run end to end with real knowledge tools, including the unapproved-fix case producing a ticket and no PR.

### Phase 3: Breadth (Week 2, in parallel with Phase 2)

**Objective:** cover the remaining finding types and CI systems.

- **Features:** F01 (Grype, OSV-Scanner, Gitleaks), F15, F23, F24, F25, F26 (stretch), F29, F30.
- Secrets flow: redaction, human approval always, rotation checklist.
- Expiry predictor with scheduled job and renewal ticket.
- Jenkins and GitLab templates running the same container.
- License rules in the policy engine.

**Gate (feature freeze):** all sample scenarios, including secrets and expiry, pass in GitHub Actions, Jenkins and GitLab.

### Phase 4: Hardening and trust (Week 3, Days 1-3)

**Objective:** make it safe and predictable to run unattended.

- **Features:** F31 (full), F32, F33, F34.
- Audit log, cost and token tracking, timeouts, retries, rate-limit handling.
- Prompt-injection tests through hostile changelogs, advisories and repo files.
- Secret-leak tests with seeded fake secrets across prompts, traces and logs.
- Review of the tool's own permissions, tokens and sandbox isolation.

**Gate:** all injection and leak tests pass; a failed run leaves no partial branch, PR or ticket without a clear status.

### Phase 5: Evaluation and demo (Week 3, Days 4-5)

**Objective:** produce evidence and a repeatable demo.

- **Features:** F35.
- Run the full sample set, compare against a manual baseline and publish metrics (section 11).
- Record and replay LLM responses for a deterministic demo; keep a recorded backup.
- README, runbook, architecture summary and Phase 2 roadmap.

**Gate:** one-command demo environment; metrics report generated from a clean run.

## 5. Folder structure

The repo is a single monorepo where each top-level folder maps to one architectural layer, so contracts, adapters, tools and agents can evolve independently. The layout assumes Python, LangGraph and the official MCP SDK (see section 10).

```text
vulnflow/
├── README.md
├── pyproject.toml                 # packaging, dependencies, tool config
├── Makefile                       # make up | test | demo | eval
├── docker-compose.yml             # neo4j, vector store, langfuse, mcp servers
├── Dockerfile                     # the single image CI pipelines call
├── .env.example
│
├── docs/
│   ├── architecture.md
│   ├── contracts.md               # Finding, RemediationPlan, state, tool signatures
│   ├── policy-guide.md            # how to write and sync approved-package policy
│   ├── ci-integration.md          # GitHub, Jenkins, GitLab usage
│   ├── runbook.md
│   └── adr/                       # architecture decision records
│
├── src/vulnflow/
│   ├── cli.py                     # vulnflow analyze | fix | verify | watch-expiry
│   ├── config.py                  # settings, env, risk thresholds
│   │
│   ├── contracts/                 # shared schemas (pydantic)
│   │   ├── finding.py
│   │   ├── remediation_plan.py
│   │   ├── policy.py
│   │   └── state.py               # LangGraph state object
│   │
│   ├── adapters/
│   │   ├── input/                 # scanner reports -> Finding
│   │   │   ├── trivy.py
│   │   │   ├── grype.py
│   │   │   ├── osv.py
│   │   │   ├── gitleaks.py
│   │   │   └── sarif.py
│   │   ├── ecosystem/             # package-manager specifics
│   │   │   ├── npm.py
│   │   │   └── maven.py           # stretch
│   │   └── ci/                    # thin CI glue
│   │       ├── github_action/
│   │       ├── jenkins/
│   │       └── gitlab/
│   │
│   ├── core/
│   │   ├── dedupe.py
│   │   ├── redaction.py           # secret/PII stripping
│   │   ├── risk.py                # scoring and tier decision
│   │   └── semver.py              # ecosystem-aware version logic
│   │
│   ├── policy/
│   │   ├── engine.py              # deterministic allow/deny
│   │   ├── loaders/               # yaml, artifactory, nexus, opa
│   │   └── licenses.py
│   │
│   ├── knowledge/
│   │   ├── vector/                # chunking, embeddings, retrieval
│   │   │   ├── ingest_advisories.py
│   │   │   ├── ingest_changelogs.py
│   │   │   ├── ingest_policy_docs.py
│   │   │   └── retriever.py
│   │   ├── graph/                 # neo4j schema and queries
│   │   │   ├── schema.cypher
│   │   │   ├── build_from_tree.py
│   │   │   └── queries.py         # root_cause, blast_radius, policy_usage
│   │   └── sources/               # OSV, GHSA, NVD, internal playbooks
│   │
│   ├── agents/
│   │   ├── triage.py
│   │   ├── rootcause.py
│   │   ├── planner.py
│   │   ├── fixer.py
│   │   ├── verifier.py
│   │   ├── secrets.py
│   │   ├── expiry.py
│   │   └── prompts/               # versioned prompt templates
│   │
│   ├── orchestrator/
│   │   ├── graph.py               # LangGraph state machine
│   │   ├── nodes.py
│   │   ├── approval.py            # interrupt and resume
│   │   └── routing.py             # tier-based edges
│   │
│   ├── mcp_servers/
│   │   ├── policy_server.py       # policy_check
│   │   ├── knowledge_server.py    # advisory_search, graph_query
│   │   ├── git_server.py          # clone, branch, patch, commit, PR
│   │   ├── scan_server.py         # run scanner, fetch report
│   │   ├── registry_server.py     # registry_check
│   │   ├── ticket_server.py       # Jira or GitHub issue
│   │   └── stubs/                 # canned servers for Phase 0
│   │
│   ├── sandbox/                   # ephemeral clone and build runner
│   ├── reporting/                 # markdown, JSON, PR comments
│   └── observability/             # tracing, audit log, cost tracking
│
├── policies/
│   ├── approved_packages.yaml
│   ├── risk_tiers.yaml
│   ├── licenses.yaml
│   └── docs/                      # prose policy documents for RAG
│
├── data/
│   ├── advisories/                # cached OSV/GHSA snapshots
│   ├── changelogs/
│   └── fixtures/                  # recorded scanner reports
│
├── samples/                       # intentionally vulnerable repos
│   ├── npm-simple-bump/
│   ├── npm-transitive-only/
│   ├── npm-unapproved-fix/
│   ├── npm-banned-package/
│   ├── repo-with-secret/
│   └── expiring-artifacts/
│
├── evals/
│   ├── scenarios/                 # input report + expected outcome
│   ├── run_eval.py
│   ├── metrics.py
│   └── recorded_llm/              # record and replay responses
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/                  # prompt injection, secret leakage
│   └── contract/                  # schema and MCP signature checks
│
├── api/                           # FastAPI: runs, plans, approvals, graph, metrics
├── ui/                            # web UI (React + Vite) over the API
├── harness/                       # AGENTS.md templates, ecosystem playbooks, checks, failure taxonomy
├── ci-templates/
│   ├── github-actions.yml
│   ├── Jenkinsfile
│   └── gitlab-ci.yml
│
└── scripts/                       # seed graph, load advisories, demo reset
```

### 5.1 Layer rules

| Folder | Responsibility | May depend on |
| --- | --- | --- |
| `contracts/` | Schemas only, no logic | Nothing |
| `adapters/` | Translate external formats to and from contracts | `contracts` |
| `core/`, `policy/` | Deterministic logic | `contracts` |
| `knowledge/` | Retrieval and graph access | `contracts` |
| `mcp_servers/` | Expose tools over MCP | `core`, `policy`, `knowledge`, `sandbox` |
| `agents/` | LLM reasoning, calling tools only through MCP | `contracts`, MCP client |
| `orchestrator/` | State machine, routing, approvals | `agents`, `contracts` |
| `cli.py` | Entry point | `orchestrator` |

Agents never import `policy` or `sandbox` directly. They reach them through MCP tools, which keeps side effects swappable and auditable.

## 6. Data contracts

Four contracts carry all data between components: `Finding` in, `RemediationPlan` out, the policy file that governs decisions, and the graph schema that models relationships. They are versioned, validated with pydantic, and checked in `tests/contract/`; changing one is a breaking change.

### 6.1 Finding

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Stable hash of scanner, repo, package, version, CVE and location |
| `type` | enum | `vuln`, `secret`, `policy`, `expiry` |
| `scanner` | string | Source tool and version |
| `repo` | string | Repository identifier |
| `package` | string | Name plus ecosystem, for example `npm:lodash` |
| `version` | string | Installed version |
| `cve` | string list | CVE or advisory IDs |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` |
| `location` | object | File, line, dependency path from root |
| `fix_versions` | string list | Versions the scanner says resolve it |
| `raw_ref` | string | Pointer to the original scanner record |
| `redacted` | boolean | True once secret or PII values are stripped |

For `secret` findings the value is never stored; only `kind` (for example API key), `location` and a fingerprint are kept.

### 6.2 RemediationPlan

| Field | Type | Notes |
| --- | --- | --- |
| `finding_ids` | string list | All findings this plan resolves |
| `root_cause_id` | string | Graph node of the parent dependency or source |
| `action` | enum | `bump`, `override`, `pin`, `replace`, `rotate`, `renew`, `exception`, `none` |
| `target_version` | string | Chosen version, if applicable |
| `policy_result` | object | Status, rule matched, replacement if any |
| `risk_tier` | enum | `auto`, `review`, `blocked` |
| `requires_approval` | boolean | Derived from tier and policy, not from the LLM |
| `evidence` | list | Advisory and release-note references used |
| `rationale` | string | Plain-language reason, written by the LLM, shown in the PR |
| `verification` | object | Rescan result, resolved and new finding IDs, policy recheck |

### 6.3 Approved-package policy

```yaml
packages:
  - name: lodash
    ecosystem: npm
    approved_versions: ">=4.17.21"
    status: approved
  - name: moment
    ecosystem: npm
    status: deprecated
    replacement: date-fns
  - name: left-pad
    ecosystem: npm
    status: banned
    reason: unmaintained
rules:
  unknown_package: require_approval
  apply_to_transitive: true
  licenses_denied: [GPL-3.0, AGPL-3.0]
```

The policy engine returns one of `approved`, `deprecated`, `banned`, `unknown`, `license_denied` with the matched rule. It is pure code with no model involved, and the same input always produces the same answer.

### 6.4 Graph schema

| Node | Key properties |
| --- | --- |
| `Repo` | name, url |
| `Service` | name, owner |
| `Package` | name, ecosystem |
| `PackageVersion` | version, release date |
| `CVE` | id, severity, fixed versions |
| `PolicyEntry` | status, rule, reason |
| `Artifact` | name, type, expiry date |
| `Fix` | PR link, outcome, date |

| Relationship | Meaning |
| --- | --- |
| `(Repo)-[:CONTAINS]->(Service)` | Ownership of code |
| `(Service)-[:DEPENDS_ON {direct}]->(PackageVersion)` | Direct or transitive use |
| `(PackageVersion)-[:DEPENDS_ON]->(PackageVersion)` | Transitive chain |
| `(PackageVersion)-[:AFFECTED_BY]->(CVE)` | Vulnerability link |
| `(Package)-[:GOVERNED_BY]->(PolicyEntry)` | Policy status |
| `(Package)-[:REPLACED_BY]->(Package)` | Approved replacement |
| `(Service)-[:USES_ARTIFACT]->(Artifact)` | Cert, image or artifact in use |
| `(Fix)-[:RESOLVED]->(CVE)` | Past remediation history |

### 6.5 Orchestrator state

The LangGraph state carries the normalized findings, root-cause groups, plans, policy results, approval decisions, branch and PR references, test results and verification results. It never holds secret values, and each node appends to the audit log.

Node order: `ingest`, `dedupe`, `rootcause`, `policy`, `plan`, `approve`, `fix`, `test`, `pr`, `verify`, with a retry edge from `test` back to `fix` and an exit edge from `policy` to `exception`.

## 7. Knowledge layer

The knowledge layer gives agents grounded context in two forms: vector RAG for unstructured text and graph RAG for structured relationships. Deterministic code builds both stores; the LLM only queries them and explains results.

### 7.1 Knowledge sources

| Source | Content | Store | Refresh |
| --- | --- | --- | --- |
| OSV, GitHub Advisory Database, NVD | CVE descriptions, affected and fixed ranges, severity | Vector, graph (CVE nodes) | Scheduled sync |
| Package release notes and changelogs | Breaking changes between versions | Vector | On demand per package |
| Organization policy documents | Why packages are banned, exception rules, standards | Vector | On policy change |
| Internal remediation playbooks | Approved fix patterns per ecosystem | Vector | Manual |
| Dependency trees (`npm ls --json`, `mvn dependency:tree`) | Direct and transitive dependencies | Graph | Per scan |
| Past fix history | PRs, outcomes, reviewer feedback | Graph and vector | After each run |
| Certificate and artifact inventory | Names, owners, expiry dates | Graph | Scheduled |

### 7.2 Vector RAG

- **Ingestion:** chunk advisories by advisory, release notes by version section and policy documents by heading; attach metadata (ecosystem, package, version range, source, date).
- **Retrieval:** hybrid search (keyword plus embeddings) filtered by ecosystem and package, so a query about one package never returns another's advisory.
- **Uses:**
  - judge exploitability and breaking-change risk for a proposed version jump
  - choose between bump, override, pin and replace
  - write the PR description with cited evidence
  - explain policy decisions and draft exception requests
- **Output rule:** every claim in a plan cites a retrieved chunk ID; plans without evidence are downgraded to the review tier.

### 7.3 Graph RAG

- **Construction:** deterministic parsers load dependency trees, scanner results and policy entries into Neo4j using the schema in section 6.4.
- **Queries exposed as tools:**
  - `root_cause(finding_ids)`: collapse findings to the parent dependency that introduced them
  - `blast_radius(package, version)`: services and repos affected by a change
  - `policy_usage(status)`: which services use deprecated or banned packages
  - `fix_history(package)`: how this package was fixed before and what happened
  - `expiring(artifacts, days)`: artifacts expiring within a window
- **Graph RAG pattern:** the agent retrieves a subgraph with these queries, then reasons over the subgraph and its linked advisory text instead of over a flat finding list.

### 7.4 How the two stores work together

For a transitive vulnerability, the graph identifies the direct parent and every service that uses it; the vector store supplies the advisory, the fixed range and the parent's changelog; the policy engine says which fix versions are allowed. The planner combines all three into one `RemediationPlan`.

### 7.5 Feedback loop

After each run, the outcome (merged, rejected, reverted, test failures) is written back as `Fix` nodes and indexed text. Later plans retrieve similar past fixes, so reviewer decisions improve future recommendations without retraining a model.

## 8. MCP tools and CI integration

All side effects and knowledge lookups are exposed as MCP tools, and CI systems talk to VulnFlow through one container. Swapping GitHub for GitLab, or Jira for another tracker, means swapping an MCP server or a CI template, not rewriting agents.

### 8.1 MCP tool catalog

| Server | Tool | Purpose | Side effects |
| --- | --- | --- | --- |
| policy | `policy_check(package, version, ecosystem)` | Approved, deprecated, banned, unknown or license-denied, with rule and replacement | None |
| policy | `policy_candidates(package, versions)` | Filter fix versions to the allowed set | None |
| knowledge | `advisory_search(query, filters)` | Retrieve advisory, release-note and policy chunks | None |
| knowledge | `graph_query(name, params)` | Run a named graph query (root cause, blast radius, expiry) | None |
| scan | `scan_run(repo, scanner)` | Run a scanner on a branch and return a normalized report | None |
| scan | `scan_diff(before, after)` | Compare finding IDs before and after | None |
| git | `git_clone`, `git_branch`, `git_patch`, `git_commit` | Prepare a fix in the sandbox | Sandbox only |
| git | `pr_create(branch, body)` | Open a pull request | Writes to the repo host |
| build | `build_test(repo, branch)` | Run build and tests in the sandbox | Sandbox only |
| registry | `registry_check(package, version)` | Confirm the version is available in the internal registry | None |
| ticket | `ticket_create(type, context)` | Open an exception, rotation or renewal ticket | Writes to the tracker |
| notify | `approval_request(plan)` | Ask a human to approve or reject a plan | Writes a comment or message |

Rules for every tool:

- Inputs and outputs are typed with the contracts in section 6 and validated on both sides.
- Read-only tools are separated from write tools; write tools need a scoped credential and are logged to the audit log.
- Phase 0 ships a stub version of each tool returning canned data so agents can be built before real servers exist.
- Existing community MCP servers (GitHub, filesystem, Jira) are reused where they fit.

### 8.2 CI integration model

Every CI system does the same three things: run its scanner, call the VulnFlow container with the report, and act on the exit code.

```bash
docker run --rm \
  -e VULNFLOW_LLM_KEY -e VULNFLOW_REPO_TOKEN \
  -v "$PWD:/workspace" vulnflow/vulnflow:latest \
  analyze --report /workspace/trivy-report.json \
          --repo /workspace --mode pr
```

| CLI command | Purpose |
| --- | --- |
| `vulnflow analyze` | Ingest a report, group, plan and optionally fix |
| `vulnflow fix` | Execute an existing approved plan |
| `vulnflow verify` | Rescan a branch and confirm resolution |
| `vulnflow watch-expiry` | Scheduled check of certificates and artifacts |
| `vulnflow report` | Render the findings and plan summary |

| Mode | Behavior |
| --- | --- |
| `report` | Analyze and comment only; no changes made |
| `pr` | Open PRs for plans in the auto tier; request approval for others |
| `dry-run` | Produce plans and the trace without calling write tools |

Exit codes: `0` nothing to do or all resolved, `10` plans awaiting approval, `20` blocked by policy, `30` verification failed, `1` tool error. A pipeline can fail, warn or continue based on these.

### 8.3 CI templates

| CI system | Delivery | Trigger |
| --- | --- | --- |
| GitHub Actions | Reusable action in `ci-templates/` | Scan job fails or schedule |
| Jenkins | `Jenkinsfile` stage calling the container | Post-scan stage |
| GitLab CI | `.gitlab-ci.yml` job calling the container | After scan job |
| Any other CI | Documented container call plus exit-code table | Any step after the scan |

### 8.4 Approval channels

The approval gate is channel-agnostic. The default posts the plan as a PR comment and resumes when a reviewer approves or rejects; the CLI can prompt interactively in local runs, and the notify server can send to chat. The paused run's state is persisted so approval can arrive hours later.

## 9. Security, guardrails and approval tiers

VulnFlow holds repo write access and sends data to an LLM, so it must be safer than the tools it replaces. Four rules govern the design: the model never executes, policy is code, secrets never reach the model, and nothing counts as fixed until a rescan says so.

### 9.1 Approval tiers

The tier is computed by code from `risk_tiers.yaml`, never chosen by the LLM. The LLM can only move a plan to a stricter tier.

| Situation | Tier | Action |
| --- | --- | --- |
| Patch bump, version approved, build and tests green, rescan clean | `auto` | Open PR with no approval wait |
| Minor bump, approved, tests green | `auto` or `review` per config | PR; approval if configured |
| Major bump, or tests thin or failing | `review` | Human approval before PR is marked ready |
| Deprecated package with replacement | `review` | Migration PR, always human-reviewed |
| Fix exists but version is not approved | `blocked` | Exception ticket with CVE context; no PR |
| Banned or unknown package | `blocked` | Escalate; never auto-fix |
| No approved version resolves the CVE | `blocked` | Report with mitigations such as pin, patch or compensating control |
| Secret or PII finding | `review` always | Rotation checklist and human approval |
| Change touches auth, build config or CI files | `review` always | Human approval |
| Plan has no cited evidence | `review` | Downgraded until evidence exists |

### 9.2 Threats and controls

| Threat | Control |
| --- | --- |
| Secret value reaches the LLM, traces or logs | Redaction at ingestion; values never enter state; seeded fake-secret tests scan prompts, traces and logs |
| Prompt injection through changelogs, advisories, issue text or repo files | Retrieved text wrapped as untrusted data; model output limited to a typed schema; tools execute only schema-valid plans; adversarial tests in `tests/security/` |
| Model chooses a banned or unapproved package | Policy check in code before planning and again at verification |
| Fix introduces new vulnerabilities or transitive packages | Verify step rescans and re-runs the policy check on the full tree |
| Over-privileged credentials | Scoped, short-lived tokens; separate read and write credentials; no production secrets in the sandbox |
| Malicious build or test code run in sandbox | Ephemeral container, no network except allowlisted registries, resource and time limits |
| Runaway cost or loops | Token and cost budget per run; retry caps; timeouts |
| Unreviewed changes reach main | PRs only; no auto-merge in the initial release; branch protection stays in force |
| Silent wrong fix | Test and rescan required; plans with no passing verification marked failed |
| Lost accountability | Immutable audit log of every plan, approval, tool call and model version |

### 9.3 Data handling

- Only package names, versions, advisory text, file paths and redacted snippets are sent to the model.
- Source code excerpts are sent only when a fix needs them and are limited to the changed lines and a small context window.
- The LLM provider is configurable, including a self-hosted or in-region model, for organizations that cannot send data outside.
- Prompts and responses are retained in traces for a configurable period and can be disabled for sensitive repos.

### 9.4 Human-in-the-loop behavior

Approval requests show the plan, evidence, policy result, test and rescan results, and the diff. A reviewer can approve, reject with a reason, or request a different approach. Rejections are stored and fed back into the knowledge layer so the same plan is not proposed again.

## 10. Tech stack, environments and non-functional requirements

The stack below is a recommended default so the team does not spend time debating tools; each row names the swappable alternative.

### 10.1 Technology choices

| Layer | Default | Alternatives |
| --- | --- | --- |
| Language | Python 3.12 | TypeScript |
| Contracts | pydantic | JSON Schema |
| Agent framework | LangGraph (stateful flow, interrupts for approval) | OpenAI Agents SDK, CrewAI, Claude Agent SDK |
| LLM access | Provider-agnostic client; Claude or OpenAI models | Self-hosted or in-region model |
| Tool protocol | MCP (official Python SDK) | None; this is the standard |
| Vector store | Chroma for the MVP | pgvector, Qdrant |
| Embeddings | Provider embedding model | Open-source sentence model |
| Graph store | Neo4j (Docker) | Memgraph; networkx in memory for tests |
| Scanners | Trivy first; Grype, OSV-Scanner, Gitleaks | Any tool that emits SARIF or JSON |
| Primary ecosystem | npm | Maven as the second ecosystem |
| Repo host | GitHub (Actions, PR API) | GitLab, Bitbucket |
| Ticketing | GitHub Issues for the MVP | Jira |
| Sandbox | Ephemeral Docker container | Firecracker, remote runners |
| Tracing | Langfuse | LangSmith, OpenTelemetry |
| Packaging | Docker image plus pip package | Helm chart (later) |
| Project CI | GitHub Actions | Any |

### 10.2 Environments

| Environment | Purpose | Contents |
| --- | --- | --- |
| Local | Development and demos | Docker Compose with Neo4j, vector store, Langfuse and MCP servers; `make up` |
| CI | Project tests | Unit, contract and security tests; integration tests against sample repos |
| Demo | Scripted showcase | Pinned model and settings, replayed LLM responses, seeded graph and vector data |
| Pilot (post-MVP) | Real repos | Read-only first, then PR mode on selected repos |

### 10.3 Non-functional requirements

| Area | Requirement |
| --- | --- |
| Determinism | Policy, dedupe, risk tier and verification are deterministic; same input gives the same result |
| Reproducibility | Pinned model, temperature and prompt versions per run; record and replay for evals |
| Idempotency | Re-running on the same report must not create duplicate branches, PRs or tickets |
| Extensibility | New scanner, ecosystem or CI added by implementing one adapter, with no change to agents |
| Portability | Runs as one container with no cloud dependency required |
| Observability | Every run has a trace ID linking findings, plans, tool calls, approvals and results |
| Resilience | Timeouts, retries with backoff, and a clear terminal status for every run |
| Cost control | Token and cost budget per run and per finding, reported in the output |
| Privacy | Configurable data sent to the model; secrets never sent |
| Auditability | Append-only audit log retained per org policy |

### 10.4 Observability and operations

- **Tracing:** each node and tool call is a span carrying model, prompt version, tokens, latency and result status.
- **Audit log:** structured events for plan created, policy decided, approval requested and granted, PR opened, verification result.
- **Metrics:** findings in, deduped, grouped, auto-fixed, sent to approval, blocked, failed; time from scan to verified fix; cost per finding.
- **Alerts (post-MVP):** failed verification, budget exceeded, policy sync stale.

## 11. Testing, evaluation and sample repos

Success is measured on seeded sample repos with known correct outcomes, comparing VulnFlow against a manual baseline. The same scenarios double as the demo.

### 11.1 Sample scenarios

| Scenario | Seeded problem | Expected behavior |
| --- | --- | --- |
| npm-simple-bump | Old `lodash` with an approved patched version | Auto PR, tests green, clean rescan |
| npm-transitive-only | Vulnerable package pulled in by a direct dependency | Findings collapse to one root cause; fix at the parent or override |
| npm-duplicate-findings | Many findings from several scanners on one package | Deduplicated to one group |
| npm-unapproved-fix | Only fix version is not on the approved list | No PR; exception ticket with CVE context |
| npm-banned-package | Package on the banned list | Blocked; escalation; replacement suggested if one exists |
| npm-deprecated-package | Deprecated package with approved replacement | Migration PR, human approval required |
| npm-major-bump | Fix needs a major version change | Review tier; PR waits for approval |
| npm-fix-breaks-tests | Suggested bump fails existing tests | Retry with error context; escalate if still failing |
| repo-with-secret | Fake API key committed | Value redacted before LLM; rotation checklist; human approval |
| expiring-artifacts | Certificate expiring within the warning window | Renewal ticket opened before any scanner flags it |
| injection-changelog | Changelog containing hostile instructions | Instructions ignored; plan unchanged; test passes |
| maven-simple-bump | Equivalent of the simple bump in Maven (stretch) | Same outcome as npm |

### 11.2 Test layers

| Layer | What it checks |
| --- | --- |
| Unit | Parsers, dedupe, semver logic, policy engine, risk tier rules |
| Contract | Schemas and MCP tool signatures do not drift |
| Integration | Agents with real tools on sample repos, with recorded LLM responses |
| Security | Prompt-injection cases, secret leakage into prompts, traces and logs, sandbox escape attempts |
| End to end | Scanner report in, verified PR or ticket out, in each supported CI |
| Eval | Full scenario run with live model to measure quality and cost |

### 11.3 Metrics

| Metric | Definition | Target |
| --- | --- | --- |
| Auto-fix rate | Share of eligible findings fixed with no human edit | Reported, with per-tier breakdown |
| Dedupe ratio | Raw findings divided by root-cause groups | Reported |
| Time to verified fix | Scan failure to clean rescan, compared with manual baseline | Lower than baseline |
| Policy violations introduced | Unapproved or banned packages added by a fix | Zero |
| Secret exposure to LLM | Seeded secrets found in prompts, traces or logs | Zero |
| Bad-fix rate | Fixes that pass checks but are rejected or reverted by a reviewer | Reported |
| Verification accuracy | Plans marked resolved that the rescan confirms | 100% |
| Cost per finding | LLM cost divided by findings handled | Reported |
| Approval load | Plans needing human review as a share of all plans | Reported |

The manual baseline is measured by timing the same scenarios done by hand, so improvement claims rest on a real comparison.

### 11.4 Definition of done for the MVP

- [ ] All sample scenarios pass in GitHub Actions, Jenkins and GitLab
- [ ] Zero policy violations and zero secret leaks in the full run
- [ ] Injection scenarios pass
- [ ] Metrics report generated from a clean run
- [ ] One-command demo environment starts from scratch
- [ ] Recorded backup of the demo
- [ ] README, runbook and policy guide complete

## 12. Risks, assumptions, open decisions and roadmap

The biggest delivery risk is integration drift between components built in parallel; the biggest product risk is a plausible but wrong fix reaching a reviewer.

### 12.1 Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Components built in parallel do not connect | Late integration failures | Phase 0 contracts and stubs; gate at the end of each phase; main branch always runnable |
| Graph and vector layers consume more time than planned | Delayed Phase 2 | Narrow scope: five graph queries, one retrieval API; load only sample-repo data first |
| LLM non-determinism breaks the demo | Unreliable showcase | Pinned model and temperature; record and replay; backup recording |
| Prompt injection through retrieved or repo text | Wrong or unsafe actions | Untrusted-data handling, typed outputs, tool-side validation, adversarial tests |
| Secrets leak to model or logs | Compliance incident | Redaction at ingestion, seeded-secret tests on prompts, traces and logs |
| Approved list lags upstream releases | Many blocked fixes | Exception workflow; policy sync from registry; report blocked-by-policy as its own metric |
| Flaky builds or tests in target repos | False fix failures | Retry with limit, flake detection, clear "inconclusive" status |
| Scanner output variations | Parser breaks | SARIF-first parsing, recorded fixtures per scanner version, contract tests |
| Second ecosystem doubles fixer work | Schedule slip | One ecosystem fully; second is stretch and does not gate the MVP |
| Over-trust in automation | Bad fixes merged | No auto-merge; review tier defaults; verification required |

### 12.2 Assumptions

- The target organization already runs at least one scanner that emits JSON or SARIF.
- A repo host with a PR API is available, and a bot account can be created with scoped permissions.
- An approved-package list exists in some form, or can be created as YAML for the MVP.
- An LLM provider is approved for use with package metadata and limited code context.
- Sample repos stand in for production repos during the MVP.

### 12.3 Open decisions

| Decision | Options | Needed by |
| --- | --- | --- |
| Primary ecosystem | npm or Maven | Phase 0 |
| Implementation language | Python or TypeScript | Phase 0 |
| LLM provider and model | Hosted API, in-region or self-hosted | Phase 0 |
| Approved-list source for the MVP | YAML in Git, Artifactory or Nexus export, OPA | Phase 0 |
| Ticketing system | GitHub Issues or Jira | Phase 2 |
| Approval channel | PR comment, CLI, chat | Phase 2 |
| Auto-PR eligibility | Patch only, or patch and minor | Phase 2 |
| Data retention for traces | Duration and redaction level | Phase 4 |

### 12.4 Post-MVP roadmap

- Multi-repo and fleet-wide scheduled campaigns (for example, remove a deprecated package everywhere).
- Additional ecosystems: Python, Go, Java Gradle, container base images.
- Policy sync from Artifactory, Nexus and OPA in production.
- Reachability analysis to rank vulnerabilities by actual use.
- Auto-merge for narrowly defined safe classes, behind policy.
- SBOM generation and ingestion (CycloneDX, SPDX).
- Web UI for plans, approvals and metrics.
- Learning from reviewer feedback to tune risk tiers.
- Helm chart and hosted service mode with multi-tenant isolation.

## 13. Addendum: UI, platform options, evaluation and harness engineering

Add a UI, adopt harness engineering as the organizing principle, and use RAGAS, DeepEval and a trace backend for evaluation; treat Glean and Strands as optional adapters, not core dependencies. "AGI" is not an integrable component, so the design handles it as autonomy levels and model swap instead (13.7). Tool facts below come from vendor documentation and recent articles listed in 13.10 as of 6 November 2026; confirm licensing and pricing with vendors before committing.

### 13.1 Decisions at a glance

| Topic | Recommendation | Phase |
| --- | --- | --- |
| UI | Yes. API-first backend plus a web UI for runs, approvals, graph, policy and metrics; CLI and report stay as the CI path | P2 to P5 |
| Glean | Optional knowledge adapter through its MCP server, only if the organization already runs Glean; not needed for the MVP | P3 |
| Strands Agents | Not the primary framework; keep LangGraph. Allow Strands for individual agents if the organization standardizes on AWS | Decide in P0 |
| LangSmith | Supported trace and eval backend, natural with LangGraph; default stays self-hosted Langfuse behind OpenTelemetry | P0 option |
| RAGAS | Yes, for offline evaluation of retrieval and groundedness | P2, P5 |
| DeepEval | Yes, as a pytest-style CI gate for agent and RAG behavior | P4 |
| Harness engineering | Yes. The whole design is the harness; this makes it an explicit, versioned, evaluated artifact | All |
| AGI | No component to integrate; use autonomy levels and a swappable model | Design rule |

### 13.2 User interface

Approvals, root-cause grouping and the graph are hard to read in a terminal, and a UI makes the MVP demonstrable to reviewers and security leads. The UI is a control plane, not a requirement: CI still calls the container, and every UI action has a CLI or PR-comment equivalent.

**Architecture.** The orchestrator writes each run (findings, groups, plans, approvals, results, cost) to a run store, SQLite for the MVP and Postgres later. A small FastAPI service in `api/` exposes it. Approve and reject calls resume the paused LangGraph run. The same service provides the webhook mode (F30). The UI talks only to this API, so the front end can be replaced without touching agents.

| Screen | Shows | Actions |
| --- | --- | --- |
| Runs | Runs by repo, trigger, status, counts, cost, exit code | Filter, open a run |
| Run detail | Findings collapsed into root-cause groups; node-by-node timeline | Expand evidence, jump to trace |
| Plan and approval | Plan, cited evidence, policy result, diff, test and rescan results | Approve, reject with reason, request another approach |
| Graph explorer | Root-cause and blast-radius subgraph | Select a node to see CVEs, services, policy status |
| Policy and exceptions | Blocked-by-policy plans, exception tickets, approved-package lookup | Search, open ticket |
| Expiry | Certificates and artifacts by expiry date, renewal status | Open renewal ticket |
| Metrics | Auto-fix rate, time to verified fix, cost per finding, eval runs | Open traces and eval reports |
| Ask VulnFlow (stretch) | Read-only answers such as why a fix was blocked, grounded by the same RAG tools | Ask, follow citations |

**Technology.** Default to React with TypeScript (Vite) and a graph library such as Cytoscape.js. If no one has front-end capacity, use Streamlit as the fallback; it is faster to build and weaker for the graph and approval flow. MVP authentication is a single-tenant token; SSO through OIDC comes after the MVP. Approver identity is written to the audit log, and the UI never renders secret values.

### 13.3 Glean

Glean documents a permission-aware remote MCP server, authenticated with OAuth, with default tools for search, chat and reading a document; queries enforce the signed-in user's permissions. Its docs also note that exposing Glean Agent Builder agents as MCP tools is coming soon.

- **Where it fits:** the organization's own knowledge, such as security standards, past incident write-ups, package discussions in Confluence, Jira or chat, and exception precedents. Glean can serve this as a retrieval backend so VulnFlow does not build an ingestion connector for each system.
- **Where it does not fit:** advisories (OSV, GHSA, NVD), the dependency graph and the policy decision. These are structured, public or authoritative, and stay under VulnFlow's control. Glean results are context only and never change an allow or deny decision.
- **Integration:** add a `knowledge/providers/` interface with `local_vector` as the default and `glean` as an optional provider, or connect Glean's MCP server as one more MCP server behind `org_knowledge_search`.
- **Watch-outs:** interactive MCP access answers as the signed-in user, but unattended CI runs need a service identity, and its permissions define what the agent can see. Usage is metered, so budget calls per run. Treat returned text as untrusted data, like any retrieved content.
- **Plan:** build the interface and local provider in Phase 2; add the Glean provider in Phase 3 only if a licence and admin enablement exist.

### 13.4 Strands Agents compared with LangGraph

Strands Agents is an open-source AWS SDK (Apache 2.0, Python and TypeScript) with a model-driven agent loop, native MCP client support, multi-agent patterns (agent as tool, swarm, graph, workflow), hooks, interrupts and built-in OpenTelemetry tracing.

| Aspect | LangGraph (current choice) | Strands Agents |
| --- | --- | --- |
| Style | Explicit state machine with persisted state | Model-driven loop; the model decides tool use, with graph and workflow patterns available |
| Fit for a fixed pipeline with an approval gate | Direct: nodes, edges, interrupts | Possible, less natural |
| MCP | Supported through adapters | Native client |
| Models | Provider-agnostic | Provider-agnostic, including Bedrock, Anthropic, OpenAI, Ollama |
| Tracing | LangSmith natively; OpenTelemetry possible | Built-in OpenTelemetry |
| Deployment | Any container host | Local, Lambda, Fargate, EKS, Bedrock AgentCore |

Recommendation: keep LangGraph as the orchestrator because VulnFlow's control flow should be an explicit, auditable state machine, not something the model improvises. Define an `AgentRuntime` interface in `agents/` so a single agent, such as the planner or fixer, can run on Strands if the organization standardizes on AWS and Bedrock AgentCore. Do not run two orchestrators in the MVP.

### 13.5 Observability and evaluation stack

Instrument once with OpenTelemetry, then choose the backend by data policy. Traces contain repo metadata, dependency names and advisory text, so a self-hosted backend is the safer default.

| Tool | Role | Used for | Phase |
| --- | --- | --- | --- |
| OpenTelemetry | Neutral instrumentation | Spans for every node, agent call and MCP tool call; lets the backend change without code changes | P0 |
| Langfuse (self-hosted) | Default trace store, datasets, cost tracking | Debugging runs, token and cost reports | P0 |
| LangSmith | Alternative trace and eval backend, native to LangGraph | Use if the organization allows a hosted service or has an enterprise agreement; switched on by configuration | P0 option |
| RAGAS | Retrieval and generation metrics: faithfulness, answer relevancy, context precision, context recall; reference-free; can generate synthetic test sets | Does `advisory_search` return the right advisory? Is the PR rationale supported by retrieved text? | P2, P5 |
| DeepEval | Pytest-style evaluation in CI | Regression tests on agent behavior: plan cites evidence, correct tool calls, no hallucinated versions, custom checks for secret leakage | P4 |
| VulnFlow's own checks | Deterministic ground truth | Rescan diff, policy recheck, build and test results | P1 onward |

**Evaluation order of trust.** (1) Deterministic outcomes decide whether a finding is fixed. (2) DeepEval gates behavior in CI. (3) RAGAS measures knowledge-layer quality. (4) Production traces feed new test cases. Model-judged metrics are noisy, so pin the judge model, calibrate it against 30 to 50 human-labelled examples, and never use a judged score to approve a policy or security decision.

**CI gates.** Pull requests to the VulnFlow repo run unit, contract and security tests plus a DeepEval subset on recorded LLM responses. A nightly job runs the full scenario set with a live model and RAGAS. Start with a faithfulness threshold around 0.8 and tune it from the first baseline.

### 13.6 Harness engineering

Harness engineering is the discipline of designing everything around the model: tools, context, constraints, feedback loops and verification. The shorthand is Agent = Model + Harness, and the term entered wide use in early 2026. VulnFlow already is a harness; this section makes that explicit so it is built, versioned and evaluated as one artifact.

| Harness element | In VulnFlow |
| --- | --- |
| Tool definitions and permissions | MCP catalog, read and write split, scoped tokens |
| Context | Vector and graph RAG, minimal subgraphs, `AGENTS.md`, per-ecosystem playbooks |
| Constraints | Policy engine, risk tiers, typed outputs, sandbox limits |
| Feedback loops (sensors) | Build and test, rescan diff, policy recheck, bounded retries |
| Human gates | Approval screen, PR comment, tiering |
| Memory | Fix history and reviewer rejections in the graph |
| Observability | Traces, audit log, cost tracking |
| Evaluation | Scenario evals, RAGAS, DeepEval |

New work this adds:

- **`AGENTS.md`:** one for the VulnFlow repo, and a generated guidance file for each target repo (how to build and test, protected paths, conventions) that the fixer reads before patching.
- **`harness/` folder:** ecosystem playbooks, constraint configuration, pre-patch and post-patch check scripts, and a failure taxonomy.
- **Harness changes are code changes:** each one is versioned and reruns the eval set, including ablations such as with and without a playbook, or with and without retrieval.
- **Failure-driven loop:** every rejected PR or failed verification is classified (wrong version, broken tests, policy conflict, unsupported evidence) and turned into a new constraint, playbook entry or eval case. Humans work on the loop, improving the harness, rather than editing individual outputs.
- **Context discipline:** pass the smallest useful subgraph and chunks, not whole graphs or files.

### 13.7 AGI and autonomy levels

AGI is not a framework, API or product that can be integrated, so there is nothing to add to the architecture. Two practical readings:

- **If it means stronger future models:** keep the model behind one interface and let the eval set decide when a stronger model may take more autonomy.
- **If it means more autonomous behavior:** define explicit autonomy levels and promote a repo or fix class only when the metrics support it (low bad-fix rate, zero policy violations).

| Level | Behavior | Scope |
| --- | --- | --- |
| L0 | Report only | MVP |
| L1 | Propose plan; a human executes | MVP |
| L2 | Open PR automatically for the auto tier; a human merges | MVP default |
| L3 | Auto-merge for narrowly defined safe classes under policy | After MVP |
| L4 | Fleet-wide campaigns, such as removing a deprecated package everywhere | After MVP |

### 13.8 Impact on the phases

| Phase | Additions |
| --- | --- |
| P0 | `AgentRuntime` and knowledge-provider interfaces; OpenTelemetry instrumentation; `AGENTS.md` skeleton; run store schema; UI stack decision |
| P1 | Orchestrator writes runs to the store; API skeleton with run list endpoint |
| P2 | API plus Runs, Run detail and Plan and approval screens (F36, F37); RAGAS baseline on retrieval; first ecosystem playbooks in `harness/` |
| P3 | Graph explorer, policy and exceptions, expiry screens (F38 to F40); optional Glean provider; LangSmith backend option |
| P4 | DeepEval CI gate; failure taxonomy loop; UI authentication; approver identity in the audit log |
| P5 | Metrics screen (F41); RAGAS and DeepEval reports in the metrics output; demo runs through the UI |

### 13.9 Open decisions added

| Decision | Options | Needed by |
| --- | --- | --- |
| UI stack | React with FastAPI, or Streamlit | Phase 0 |
| Trace backend | Self-hosted Langfuse or LangSmith | Phase 0 |
| Cloud standard | AWS and Bedrock (Strands optional) or provider-neutral | Phase 0 |
| Glean licence and service identity | Available or not | Phase 2 |
| Judge model for evals | Which model, pinned version | Phase 2 |

### 13.10 Sources

Gathered from search results on 6 November 2026; pages were not independently verified beyond the excerpts.

- [Glean: connecting to the Glean MCP server](https://docs.glean.com/administration/platform/mcp/connecting-to-glean-mcp-server)
- [Best enterprise search platforms with AI agents (Oct 2026)](https://pinggy.io/amp/blog/best_enterprise_search_platforms_with_ai_agents/)
- [Strands Agents overview](https://innfactory.de/en/cloud/aws/products/strands-agents/)
- [Strands Agents technical analysis](https://openapps.pro/packages/strands-agents)
- [What is harness engineering? (Software Improvement Group)](https://www.softwareimprovementgroup.com/blog/what-is-harness-engineering/)
- [Everything about harness engineering (Tutorials Dojo)](https://tutorialsdojo.com/?p=40053)
- [Harness engineering: a source-code study of eleven systems (arXiv)](https://arxiv.org/pdf/2609.00006)
- [DeepEval alternatives, 2026 (Braintrust)](https://braintrust.dev/articles/deepeval-alternatives-2026)
- [Top AI agent evaluation tools in 2026 (DEV Community)](https://dev.to/agdex_ai/top-ai-agent-evaluation-tools-in-2026-ragas-vs-deepeval-vs-gaia-vs-langsmith-4o4j)
