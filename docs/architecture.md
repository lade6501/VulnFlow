<!--
docs/architecture.md
Documents system architecture, agent workflows, and core subsystem interactions.
-->

# VulnFlow AI – Architecture & System Design

Nov 2026 · VulnFlow Architecture Working Group

## 1. Overview & Principles

VulnFlow AI is an agentic remediation layer that sits on top of existing security scanners and CI/CD pipelines, turning findings into verified fixes with humans approving only the risky ones. It does not replace scanners; it eliminates the repetitive manual loop of investigate, fix, rebuild, redeploy, and rescan.

### 1.1 Problem Statement
Modern security scanners (Trivy, Grype, OSV-Scanner, Gitleaks) report hundreds of vulnerable dependencies, exposed secrets/PII, and expiring artifacts across repositories. Engineering teams are overwhelmed triaging duplicate findings across scanners, diagnosing transitive dependency root causes, evaluating breaking changes, navigating organizational package policies, and verifying fixes. The same toil repeats across repos and release cycles.

### 1.2 System Goals
- **Root-Cause Correlation**: Deduplicate raw findings and group them by root-cause dependency using graph reasoning.
- **Grounded Remediation**: Combine LLM reasoning with vector RAG (advisories, changelogs, playbooks) and graph RAG (blast radius, dependency trees) to propose safe fixes.
- **Automated Safe Remediation**: Automatically branch, patch manifests, build, run tests, open pull requests, and rescan.
- **Deterministic Policy Enforcement**: Enforce organizational approved-package, deprecated, banned, and license policies in deterministic code.
- **Proactive Expiry Management**: Predict certificate and artifact expirations, initiating renewals before scanners flag failures.
- **Human-in-the-Loop Governance**: Enforce approval gates based on calculated risk tiers before applying sensitive changes.
- **Closed-Loop Verification**: Require a clean rescan and policy recheck before declaring any finding resolved.
- **CI/CD Portability**: Provide a single container entry point and contract compatible with GitHub Actions, Jenkins, GitLab CI, or custom pipelines.

### 1.3 Non-Goals
- Re-implementing or replacing existing security scanners.
- Unconstrained autonomous production deployment without policy-backed approval gates.
- Building a standalone vulnerability management dashboard (VulnFlow provides an operational control plane and reporting layer).

### 1.4 Core Design Principles (Non-Negotiable)
1. **LLM proposes, tools execute, scanners verify.** No fix counts as resolved until a rescan confirms it.
2. **Policy decisions are deterministic code.** Approved, deprecated, banned, unknown, and license decisions originate from code, never from model judgment.
3. **Scanner- and CI-agnostic.** Everything enters as a normalized `Finding` and leaves as a `RemediationPlan` plus side effects executed via Model Context Protocol (MCP) tools.
4. **Secrets never reach the model, traces, or logs.** Values are redacted at ingestion; only type, location, and fingerprints travel.
5. **Retrieved text is data, not instructions.** Advisories, changelogs, and repo contents are wrapped as untrusted data and cannot alter agent behavior.
6. **Everything is auditable.** Every plan, policy evaluation, tool invocation, and human approval is traced and logged.

---

## 2. System Architecture & Layered Design

VulnFlow enforces strict separation between LLM reasoning, deterministic evaluation, and external execution. CI pipelines feed a single container; all tool invocations and side effects pass strictly through MCP servers.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CI / CD Pipelines                               │
│            (GitHub Actions, Jenkins, GitLab CI, CLI)                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Scanner Reports (SARIF, JSON)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Input Layer: Scanner Adapters ──► Deduplication ──► Secret Redaction   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Normalized Findings
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Orchestration: LangGraph State Machine (Routing & Approval Gates)      │
├────────────────────────────────────────────────────────────────────────┤
│ Reasoning: Specialized Agents (Triage, RootCause, Planner, Verifier)   │
├────────────────────────────────────────────────────────────────────────┤
│ LLM Abstraction: Centralized LLMClient ──► Redaction Guard ──► Adapters│
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ Tool Calls                     │ Context Queries
                    ▼                                ▼
┌──────────────────────────────────┐ ┌───────────────────────────────────┐
│ MCP Tool Servers                 │ │ Knowledge Layer                   │
│ - Policy Server (Allow/Deny)     │ │ - Vector Store (Advisories, RAG)  │
│ - Knowledge Server (Graph/Search)│ │ - Graph Store (Neo4j Blast Radius)│
│ - Git & PR Server                │ │ - Enterprise Providers (Local/    │
│ - Build & Test Server            │ │   Glean)                          │
│ - Scan Server (Trivy, Grype)     │ └───────────────────────────────────┘
│ - Registry & Ticket Servers      │
└───────────────────┬──────────────┘
                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Execution Sandbox (Ephemeral Docker Container) & External Integrations │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Subsystem Layer Responsibilities

| Layer | Subsystem / Package | Responsibility | Allowed Imports |
| --- | --- | --- | --- |
| **Contracts** | `src/vulnflow/contracts/` | Pydantic data models (`Finding`, `RemediationPlan`, `PolicyRule`, `State`) | None (pure schemas) |
| **Input** | `src/vulnflow/adapters/` | Ingest scanner outputs (Trivy, Grype, OSV, Gitleaks, SARIF) and ecosystem manifests (npm, Maven) | `contracts` |
| **Core** | `src/vulnflow/core/` | Deterministic deduplication, secret redaction, risk tier calculation, and semver evaluation | `contracts` |
| **Governance** | `src/vulnflow/policy/` | Pure deterministic package allow/deny engine, loaders (YAML, Artifactory, Nexus, OPA), and license rules | `contracts` |
| **LLM Abstraction** | `src/vulnflow/llm/` | Centralized `LLMClient`, role-based factory, prompt redaction guard, structured output validation, recorder/replay, and vendor adapters | `contracts`, `core`, `observability` |
| **Knowledge** | `src/vulnflow/knowledge/` | Vector RAG (advisories, changelogs, policy docs), Neo4j graph queries (root cause, blast radius), and provider backends | `contracts`, `llm` |
| **Reasoning** | `src/vulnflow/agents/` | LLM agent implementations (`AgentRuntime`) calling tools exclusively via MCP client | `contracts`, `llm`, MCP client |
| **Orchestration** | `src/vulnflow/orchestrator/` | LangGraph state machine, interruptible approval nodes, and conditional tier routing | `agents`, `contracts`, `store` |
| **Tools** | `src/vulnflow/mcp_servers/` | Expose tools over MCP protocol (policy, knowledge, git, scan, build, registry, ticket, notify) | `core`, `policy`, `knowledge`, `sandbox`, `store` |
| **Execution** | `src/vulnflow/sandbox/` | Ephemeral containerized clone, patch, build, and test runner | `contracts` |
| **Trust** | `src/vulnflow/observability/` | OpenTelemetry distributed tracing, append-only audit logging, and token/cost accounting | `contracts` |
| **Storage & API** | `src/vulnflow/store/`, `api/` | Run store persistence and FastAPI service exposing runs, plans, approvals, graph, and metrics | `store`, `contracts`, `orchestrator` |
| **User Interface** | `ui/` | React (Vite) control plane web application communicating exclusively via HTTP API | None (HTTP only) |
| **CLI & Delivery** | `cli.py`, `ci-templates/` | CLI entry point (`vulnflow analyze`, `fix`, `verify`, etc.) and CI pipeline templates | `orchestrator` |

---

## 3. Centralized LLM Provider Abstraction Layer

VulnFlow isolates all generative AI dependencies behind a centralized, provider-agnostic abstraction layer in `src/vulnflow/llm/`.

### 3.1 Architecture & Request Flow

```text
Agent → LLMClient → Redaction Guard → Provider Adapter → LLM Provider
                                                              │
Agent ← Structured Validation ← Usage Reporting (Observability) ←┘
```

### 3.2 Key LLM Abstraction Responsibilities
1. **Vendor SDK Isolation**: Nothing outside `src/vulnflow/llm/` may import a vendor LLM SDK. Agents never communicate directly with vendor SDKs.
2. **Role-Based Model Selection**: The `factory.py` assigns models based on agent roles (e.g., triage uses lightweight/fast models, while planner uses high-reasoning models).
3. **Seamless Swappability**: Providers can be swapped via configuration without modifying agent code or prompts.
4. **Deterministic Record and Replay**: `recorder.py` captures responses and replays them during automated CI tests and evaluations.
5. **Centralized Embeddings**: Embedding generation for vector RAG is managed via `embeddings.py` rather than ad-hoc vendor libraries.
6. **Framework Encapsulation**: Any LangChain or LangGraph model bindings are wrapped behind the `LLMClient` interface.

### 3.3 Configuration Environment Variables
```env
VULNFLOW_LLM_PROVIDER=anthropic
VULNFLOW_LLM_MODEL=claude-3-5-sonnet-20241022
VULNFLOW_LLM_KEY=sk-ant-...

# Optional role-based overrides:
VULNFLOW_LLM_PLANNER_MODEL=claude-3-5-sonnet-20241022
VULNFLOW_LLM_TRIAGE_MODEL=claude-3-5-haiku-20241022
```

### 3.4 Benefits & Tradeoffs
- **Benefits**: Complete vendor independence, centralized security and secret stripping, reproducible testing via record/replay, cost optimization via role-based models, and unified observability.
- **Tradeoffs**: Abstraction maintenance overhead, adapter-level handling for proprietary features, differences in native JSON schema enforcement, and embedding dimension migration constraints.

---

## 4. Run Lifecycle & Agent Workflows

```
  [1] Scanner Report Ingest (CLI / Webhook)
                      │
  [2] Normalize Finding, Redact Secrets, Deduplicate
                      │
  [3] Graph Root-Cause Grouping (Neo4j)
                      │
  [4] Plan Remediation (Vector RAG + Policy Engine Candidate Filter)
                      │
  [5] Calculate Risk Tier (auto, review, blocked)
         │                    │                     │
         ▼                    ▼                     ▼
      [auto]              [review]              [blocked]
         │                    │                     │
         │             Human Approval Gate   Create Exception Ticket
         │             (PR Comment / UI)            │
         │                    │ (Approved)          ▼
         │                    │                End Run (No PR)
         └─────────┬──────────┘
                   ▼
  [6] Ephemeral Sandbox: Patch Manifests, Build, Run Tests
                   │ (Test Failure -> Retry Loop up to limit)
                   ▼
  [7] Open Pull Request with Cited Evidence & Policy Status
                   │
  [8] Rescan Branch & Diff Finding IDs (Verification)
                   │
  [9] Update Knowledge Graph / Audit Log & Emit Exit Code
```

### 4.1 Agent Roles and Boundaries

| Agent | Input | Output | Invariant Constraints |
| --- | --- | --- | --- |
| **Triage** | Normalized findings | Priority and root-cause group hints | Cannot modify files or invoke write tools |
| **Root Cause** | Subgraph from Neo4j query | Plain-language root-cause explanation | Cannot override graph relationship facts |
| **Planner** | Groups, evidence, allowed versions | `RemediationPlan` | Cannot choose a policy-rejected version; cannot loosen approval tier |
| **Fixer** | Approved plan | Patch instructions for sandbox tools | Cannot execute commands outside sandboxed MCP tools |
| **Verifier** | Rescan diff & tree policy check | Summary of verification verdict | Cannot declare success (verdict is calculated deterministically in code) |
| **Secrets** | Redacted secret findings | Rotation checklist and patch plan | Never accesses or stores plaintext secret values |
| **Expiry** | Artifact inventory & metadata | Risk window & renewal plan | Cannot execute renewal without human approval |

---

## 5. Repository & Package Layout

```text
vulnflow/
├── README.md
├── pyproject.toml                 # Package packaging, dependencies, tool configurations
├── Makefile                       # Developer tasks: make up, test, demo, eval
├── docker-compose.yml             # Neo4j, Qdrant/Chroma, Langfuse, MCP servers
├── Dockerfile                     # Unified container image invoked by CI pipelines
├── .env.example
│
├── docs/
│   ├── architecture.md            # Comprehensive system architecture & design (this file)
│   ├── contracts.md               # Pydantic schemas, serialization rules, state models
│   ├── policy-guide.md            # Approved-package policy configuration guide
│   ├── ci-integration.md          # Integration guide for GitHub Actions, Jenkins, GitLab
│   ├── runbook.md                 # Operational runbook & troubleshooting
│   ├── llm-providers.md           # LLM abstraction layer & provider adapter documentation
│   ├── design-and-delivery.md     # Phase-wise design, delivery roadmap, & harness spec
│   └── adr/                       # Architectural Decision Records
│
├── src/vulnflow/
│   ├── cli.py                     # CLI entry point: analyze | fix | verify | watch-expiry
│   ├── config.py                  # Runtime settings, environment options, risk thresholds
│   │
│   ├── contracts/                 # Shared Pydantic data schemas
│   │   ├── finding.py
│   │   ├── remediation_plan.py
│   │   ├── policy.py
│   │   └── state.py               # LangGraph workflow state schema
│   │
│   ├── adapters/
│   │   ├── input/                 # Scanner outputs -> normalized Finding
│   │   │   ├── trivy.py
│   │   │   ├── grype.py
│   │   │   ├── osv.py
│   │   │   ├── gitleaks.py
│   │   │   └── sarif.py
│   │   ├── ecosystem/             # Package-manager specific manifest operations
│   │   │   ├── npm.py
│   │   │   └── maven.py
│   │   └── ci/                    # Thin CI glue scripts
│   │       ├── github_action/
│   │       ├── jenkins/
│   │       └── gitlab/
│   │
│   ├── core/                      # Deterministic logic
│   │   ├── dedupe.py
│   │   ├── redaction.py           # Secret & PII stripping
│   │   ├── risk.py                # Risk scoring and approval tier assignment
│   │   └── semver.py              # Ecosystem-aware semver logic
│   │
│   ├── policy/                    # Deterministic policy engine
│   │   ├── engine.py              # Allow/deny rule evaluation
│   │   ├── loaders/               # YAML, Artifactory, Nexus, OPA loaders
│   │   └── licenses.py            # Software license policy verification
│   │
│   ├── llm/                       # Centralized LLM abstraction layer
│   │   ├── __init__.py
│   │   ├── base.py                # LLMClient interface & usage models
│   │   ├── factory.py             # Role-based model & provider factory
│   │   ├── structured.py          # Pydantic structured output validator with retries
│   │   ├── guard.py               # Outbound prompt redaction & untrusted data wrapping
│   │   ├── recorder.py            # Record & replay responses for deterministic testing
│   │   ├── embeddings.py          # Provider-agnostic embedding interface
│   │   └── providers/             # Concrete vendor provider adapters
│   │       ├── __init__.py
│   │       ├── anthropic.py
│   │       ├── openai.py
│   │       ├── bedrock.py
│   │       ├── ollama.py
│   │       ├── nvidia.py
│   │       └── openrouter.py
│   │
│   ├── knowledge/                 # Knowledge layer: Vector RAG & Graph RAG
│   │   ├── vector/                # Ingestion, chunking, retrieval
│   │   ├── graph/                 # Neo4j Cypher schema & graph queries
│   │   ├── sources/               # OSV, GHSA, NVD clients
│   │   └── providers/             # Swappable org knowledge (local vector, Glean)
│   │
│   ├── agents/                    # LLM reasoning agents (implementing AgentRuntime)
│   │   ├── runtime.py
│   │   ├── triage.py
│   │   ├── rootcause.py
│   │   ├── planner.py
│   │   ├── fixer.py
│   │   ├── verifier.py
│   │   ├── secrets.py
│   │   ├── expiry.py
│   │   └── prompts/               # Versioned prompt templates
│   │
│   ├── orchestrator/              # LangGraph workflow orchestration
│   │   ├── graph.py
│   │   ├── nodes.py
│   │   ├── approval.py            # Interrupt & resume handling
│   │   └── routing.py             # Conditional risk-tier edges
│   │
│   ├── mcp_servers/               # MCP tool servers
│   │   ├── policy_server.py
│   │   ├── knowledge_server.py
│   │   ├── git_server.py
│   │   ├── scan_server.py
│   │   ├── build_server.py
│   │   ├── registry_server.py
│   │   ├── ticket_server.py
│   │   ├── notify_server.py
│   │   └── stubs/                 # Canned stubs for testing
│   │
│   ├── sandbox/                   # Ephemeral container execution runner
│   ├── reporting/                 # Markdown, JSON, and PR comment outputs
│   ├── observability/             # Tracing, audit log, cost accounting
│   └── store/                     # Run store database models and persistence
│
├── api/                           # FastAPI service exposing runs, plans, approvals, graph
├── ui/                            # React + Vite web application control plane
├── harness/                       # AGENTS.md templates, playbooks, check scripts
├── policies/                      # Organization policy data (approved packages, tiers)
├── data/                          # Cached advisories, changelogs, fixtures
├── samples/                       # Seeded vulnerable test repositories
├── evals/                         # Evaluation harness, RAGAS/DeepEval suites, scenarios
├── tests/                         # Unit, integration, security, and contract tests
├── ci-templates/                  # Copy-paste pipeline definitions
└── scripts/                       # Database seeding and demo reset scripts
```

---

## 6. Data Contracts

Communication between layers is governed by versioned contracts defined in `contracts/`, including
the canonical Pydantic `RunReport` added by F43.

### 6.1 `Finding` Contract
```python
class Finding(BaseModel):
    id: str                        # Stable hash: scanner, repo, package, version, CVE, location
    type: Literal["vuln", "secret", "policy", "expiry"]
    scanner: str                   # Tool and version
    repo: str                      # Repository identifier
    package: str                   # Format: <ecosystem>:<name> (e.g. npm:lodash)
    version: str                   # Installed version
    cve: list[str]                 # CVE or advisory identifiers
    severity: Literal["critical", "high", "medium", "low", "info"]
    location: dict[str, Any]       # File, line, dependency path
    fix_versions: list[str]        # Scanner-suggested fixes
    raw_ref: str                   # Pointer to raw scanner record
    redacted: bool                 # True once secret/PII values are stripped
```

### 6.2 `RemediationPlan` Contract
```python
class RemediationPlan(BaseModel):
    finding_ids: list[str]         # Associated finding identifiers
    root_cause_id: str             # Neo4j graph identifier of root package
    action: Literal["bump", "override", "pin", "replace", "rotate", "renew", "exception", "none"]
    target_version: str | None
    policy_result: dict[str, Any]  # Matched policy status, rule, replacement
    risk_tier: Literal["auto", "review", "blocked"]
    requires_approval: bool        # Derived strictly by deterministic code
    evidence: list[dict[str, Any]] # Cited advisory and release-note chunk IDs
    rationale: str                 # LLM-written plain-language explanation
    verification: dict[str, Any]   # Rescan diff, resolved IDs, policy recheck result
```

### 6.3 Approved-Package Policy Schema
Policies are defined in YAML (`policies/approved_packages.yaml`) and evaluated deterministically by `policy/engine.py`:
- `approved`: Allowed for automatic or review remediation.
- `deprecated`: Requires replacement package in remediation plan.
- `banned`: Must be removed or escalated.
- `unknown`: Governed by `unknown_package` rule (default `require_approval`).
- `license_denied`: Prohibited license type (e.g., GPL-3.0, AGPL-3.0).

### 6.4 Knowledge Graph Schema (Neo4j)
- **Nodes**: `Repo`, `Service`, `Package`, `PackageVersion`, `CVE`, `PolicyEntry`, `Artifact`, `Fix`.
- **Key Relationships**:
  - `(Repo)-[:CONTAINS]->(Service)`
  - `(Service)-[:DEPENDS_ON {direct: true/false}]->(PackageVersion)`
  - `(PackageVersion)-[:DEPENDS_ON]->(PackageVersion)` (transitive dependency chain)
  - `(PackageVersion)-[:AFFECTED_BY]->(CVE)`
  - `(Package)-[:GOVERNED_BY]->(PolicyEntry)`
  - `(Package)-[:REPLACED_BY]->(Package)`
  - `(Fix)-[:RESOLVED]->(CVE)`

---

## 7. Knowledge Layer Architecture

Grounded context is supplied through dual RAG stores:
1. **Vector RAG**: Unstructured security advisories (OSV, GHSA, NVD), changelogs, organizational policy prose, and remediation playbooks. Hybrid keyword + embedding search is strictly filtered by ecosystem and package.
2. **Graph RAG (Neo4j)**: Structured dependency graphs and organizational relationships. Core parameterized Cypher queries include:
   - `root_cause(finding_ids)`: Collapses transitive findings to the root parent dependency.
   - `blast_radius(package, version)`: Identifies all downstream services and repositories impacted by a package bump.
   - `policy_usage(status)`: Audits usage of deprecated or banned packages.
   - `fix_history(package)`: Retrieves historical remediation PRs and reviewer decisions.
   - `expiring(artifacts, days)`: Queries certificates and tokens nearing expiration.
3. **Dual-Store Fusion**: The graph establishes the root dependency and blast radius; the vector store supplies advisory text and changelogs; the policy engine restricts allowed target versions. The planner combines all three.
4. **Enterprise Provider Abstraction**: Supports local vector embeddings as default, with optional enterprise search integration (Glean MCP) for internal standards and incident write-ups.

---

## 8. MCP Tool Servers & CI Integration

### 8.1 Model Context Protocol Tools
All agent side effects and environment interactions occur over MCP:
- `policy_check`, `policy_candidates` (Policy evaluation)
- `advisory_search`, `graph_query` (Knowledge retrieval)
- `scan_run`, `scan_verify`, `scan_diff` (Scanner execution, revision evidence, and diffing)
- `git_clone`, `git_branch`, `git_patch`, `git_commit`, `git_replace_text`, `pr_create` (VCS operations)
- `build_test` (Sandboxed build and test execution)
- `registry_check` (Internal package registry availability)
- `ticket_create` (Issue tracker ticketing)
- `approval_request` (Human review notification)

### 8.2 CI Delivery Model
CI pipelines invoke the unified VulnFlow Docker container:
```bash
docker run --rm \
  -e VULNFLOW_LLM_KEY -e VULNFLOW_REPO_TOKEN \
  -v "$PWD:/workspace" vulnflow/vulnflow:latest \
  analyze --report /workspace/trivy-report.json \
          --repo /workspace --mode pr
```

**CLI Exit Codes**:
- `0`: Success (all findings resolved or nothing to do).
- `10`: Plans awaiting human approval.
- `20`: Remediation blocked by policy.
- `30`: Verification rescan failed.
- `1`: Tool or operational error.

---

## 9. Security, Risk Tiers & Guardrails

### 9.1 Calculated Approval Tiers

| Tier | Conditions | Action |
| --- | --- | --- |
| **`auto`** | Patch version bump, approved in policy, tests green, clean rescan | Automatically open PR, no approval hold |
| **`review`** | Major bump, deprecated package replacement, sensitive paths, test failure, secret finding, or missing evidence | Open PR in draft/review state; hold for human approval |
| **`blocked`** | Banned package, unknown package, unapproved fix version, or no fix available | Open exception ticket with context; no PR opened |

### 9.2 Threat Matrix & Security Controls
- **Secret Leaks**: Ingestion-time regex/entropy redaction; secrets never enter state, prompts, or traces.
- **Prompt Injection**: All retrieved text (changelogs, advisories) is wrapped in untrusted-data delimiters; agents output typed Pydantic models only.
- **Malicious Code Execution**: Build and test runs execute in ephemeral Docker sandboxes with scoped network access and no production credentials.
- **Unsound Fixes**: Rescan and full-tree policy check required; unverified plans are marked failed.

---

## 10. Complete Feature Inventory (43 Features)

The VulnFlow implementation encompasses 42 sequential features across eight functional groups:

### 3.1 Ingestion & Normalization
- **F01**: Scanner adapters (P1, P3 — `adapters/input/trivy.py`, `sarif.py`, etc., depends on F02)
- **F02**: Finding normalization (P1 — `contracts/finding.py`, depends on none)
- **F03**: Deduplication (P1 — `core/dedupe.py`, depends on F02)
- **F04**: Secret redaction (P1 — `core/redaction.py`, depends on F02)

### 3.2 Analysis & Intelligence
- **F05**: Root-cause grouping (P2 — `knowledge/graph/queries.py`, `agents/rootcause.py`, depends on F03)
- **F06**: Blast-radius query (P2 — `knowledge/graph/queries.py`, `mcp_servers/knowledge_server.py`, depends on F05)
- **F07**: Advisory-grounded impact analysis (P2 — `knowledge/vector/`, `agents/planner.py`, depends on **F10, F42**)
- **F08**: Risk scoring and tiering (P2 — `core/risk.py`, `policies/risk_tiers.yaml`, depends on F10)
- **F09**: Findings report (P2 — `reporting/markdown.py`, `json_report.py`, depends on F05)

### 3.3 Governance & Policy
- **F10**: Approved-package check (P1 — `policy/engine.py`, `policies/approved_packages.yaml`, depends on F02)
- **F11**: Fix-candidate filtering (P1 — `policy/engine.py`, `mcp_servers/policy_server.py`, depends on F10)
- **F12**: Replacement proposals (P2 — `policy/engine.py`, `agents/planner.py`, depends on F10)
- **F13**: Exception workflow (P2 — `mcp_servers/ticket_server.py`, `orchestrator/nodes.py`, depends on F11)
- **F14**: Registry availability check (P2 — `mcp_servers/registry_server.py`, depends on F10)
- **F15**: License rules (P3 — `policy/licenses.py`, `policies/licenses.yaml`, depends on F10)

### 3.4 Remediation
- **F16**: Fix planner (P1 — `agents/planner.py`, `contracts/remediation_plan.py`, depends on **F11, F42**)
- **F17**: Sandboxed execution (P1 — `sandbox/runner.py`, `mcp_servers/git_server.py`, depends on F16)
- **F18**: Build and test runner (P1 — `sandbox/runner.py`, `mcp_servers/build_server.py`, depends on F17)
- **F19**: PR creation (P1 — `mcp_servers/git_server.py`, `reporting/pr_comment.py`, depends on F18)
- **F20**: Self-correction loop (P2 — `orchestrator/routing.py`, `agents/fixer.py`, depends on F18)
- **F21**: Human approval gate (P2 — `orchestrator/approval.py`, `mcp_servers/notify_server.py`, depends on F16)
- **F22**: Verification (P2 — `agents/verifier.py`, `mcp_servers/scan_server.py`, depends on F19)

### 3.5 Breadth Findings
- **F23**: Secrets and PII flow (P3 — `agents/secrets.py`, `core/redaction.py`, depends on F04, F21)
- **F24**: Expiry predictor (P3 — `agents/expiry.py`, `knowledge/graph/queries.py`, depends on F05)
- **F25**: Renewal automation (P3 — `agents/expiry.py`, `mcp_servers/ticket_server.py`, depends on F24)
- **F26**: Second ecosystem: Maven (P3 stretch — `adapters/ecosystem/maven.py`, depends on F18)

### 3.6 Integration
- **F27**: CLI and Docker image (P1 — `cli.py`, `Dockerfile`, depends on F19)
- **F28**: GitHub Action (P1 — `ci-templates/github-actions.yml`, depends on F27)
- **F29**: Jenkins and GitLab templates (P3 — `ci-templates/Jenkinsfile`, `gitlab-ci.yml`, depends on F27)
- **F30**: Webhook and API mode (P3 — `api/main.py`, `api/routes/`, depends on F27)

### 3.7 Operations & Trust
- **F31**: Tracing (P0, P4 — `observability/tracing.py`, depends on none)
- **F32**: Audit log (P4 — `observability/audit_log.py`, depends on F31)
- **F33**: Failure handling (P4 — `orchestrator/`, `config.py`, depends on F20)
- **F34**: Prompt-injection defenses (P4 — `agents/prompts/`, `tests/security/`, depends on F07)
- **F35**: Evaluation harness (P5 — `evals/`, depends on F22)
- **F42**: **LLM provider abstraction** (P1 — `src/vulnflow/llm/`, depends on **F04, F31**)
- **F43**: **Enterprise run reporting & AI remediation intelligence** (P4 — `contracts/report.py`, `reporting/`, `cli.py`, `store/run_store.py`, depends on F05, F07, F09, F22, F31, F32, F42)

### 3.8 User Interface
- **F36**: Runs dashboard (P2 — `ui/src/pages/Runs.tsx`, `api/routes/runs.py`, depends on F27)
- **F37**: Plan and approval screen (P2 — `ui/src/pages/PlanApproval.tsx`, `api/routes/plans.py`, depends on F21)
- **F38**: Graph explorer (P3 — `ui/src/pages/GraphExplorer.tsx`, `api/routes/graph.py`, depends on F05, F06)
- **F39**: Policy and exceptions view (P3 — `ui/src/pages/PolicyExceptions.tsx`, depends on F13)
- **F40**: Expiry view (P3 — `ui/src/pages/Expiry.tsx`, depends on F24)
- **F41**: Metrics and eval view (P5 — `ui/src/pages/Metrics.tsx`, `api/routes/metrics.py`, depends on F35)

---

## 11. Delivery Plan & Phase Gates

The delivery roadmap spans six phases:
- **Phase 0: Foundation and contracts (Days 1–2)**: Lock Pydantic contracts, stub MCP servers, LangGraph state, OpenTelemetry tracing. *Gate: Stubbed run from sample report to mock PR.*
- **Phase 1: Core remediation spine (Days 3–5)**: Ingest, dedupe, policy check, plan, fix, test, and open PR for primary ecosystem (npm); LLM abstraction layer (F42). *Gate: Approved patch bump produces real PR on sample repo via real policy and real LLM.*
- **Phase 2: Intelligence and verification (Week 2)**: Vector store RAG, Neo4j graph queries, risk tiering, approval gate, verification rescan diff. *Gate: End-to-end run on sample scenarios with real knowledge tools.*
- **Phase 3: Breadth (Week 2 parallel)**: Secrets flow, expiry predictor, Maven ecosystem, Jenkins/GitLab CI templates. *Gate (Feature Freeze): All scenarios pass in GitHub Actions, Jenkins, and GitLab.*
- **Phase 4: Hardening and trust (Week 3 Days 1–3)**: Audit logging, prompt injection tests, fake-secret leakage tests, timeouts/rate-limits. *Gate: Zero injection or secret leaks; clean terminal states.*
- **Phase 5: Evaluation and demo (Week 3 Days 4–5)**: RAGAS / DeepEval suites, metrics reporting, recorded LLM demo replay, runbook completion. *Gate: One-command demo environment; automated metrics report.*

For detailed phase breakdowns, roadmap diagrams, and harness engineering specifications, see [docs/design-and-delivery.md](file:///Users/vishal/Documents/VulnFlow/vulnflow/docs/design-and-delivery.md).

---

## 12. Enterprise run reporting (F43)

After workflow completion, the CLI persists the run evidence and asks the reporting builder for one
immutable `RunReport` snapshot. The builder is read-only: it consumes normalized findings,
root-cause groups, remediation plans, tool results and audit events; it never calls an LLM, executes
a tool, rescans or opens a PR. Deterministic advisory validation separates expected CVEs from CVEs
verified by an executed post-fix rescan.

```text
Persisted run evidence + audit completion events
                    |
                    v
      deterministic report builder
       | validation | redaction |
                    v
         immutable RunReport v1
          /          |          \
       JSON         HTML       Markdown
```

The HTML renderer uses a packaged trusted template, standard-library escaping, inline CSS and a
restrictive CSP; it has no JavaScript or external assets. Markdown neutralizes mentions and syntax.
JSON is schema-validated and deterministically ordered. All renderers write atomically and a failure
does not change the VulnFlow workflow exit code. See [reporting.md](reporting.md) and
[ADR 0001](adr/0001-canonical-run-report.md).

---

## 13. Multi-Dependency Campaigns & Autonomous Code Refactoring

To maximize developer velocity and minimize review fatigue, VulnFlow provides two advanced remediation intelligence capabilities:

### 13.1 Multi-Dependency Campaign PRs
- **Batching & Isolation**: When multiple dependency plans are approved (`len(dep_plans) > 1`), `fix_node` automatically creates a single consolidated campaign branch (`vulnflow/campaign-{run_id[:8]}`) instead of scattering disparate branches across the repository.
- **Atomic Manifest Updates**: All dependency upgrades are applied sequentially and committed together in a unified commit.
- **Single Pull Request**: `pr_node` synthesizes a single, comprehensive Pull Request using `format_campaign_pr_body`. The PR description features an executive remediation matrix table, cited advisories, collapsible package details, and verified build evidence.

### 13.2 Autonomous Code Refactoring via FixerAgent
- **Breaking API Detection**: When an upgraded dependency introduces breaking changes, sandboxed `build_test` fails.
- **Automated Codemods**: `test_node` triggers `FixerAgent.attempt_code_refactor`, which parses compiler diagnostics and stack traces (`parse_test_failure`), locates failing call sites, and synthesizes compatible replacements via deterministic codemod rules or bounded LLM generation (`_synthesize_refactor`).
- **Autonomous Healing & Retesting**: The refactored code is committed to git, recorded in `plan.evidence` (`type: "code_refactor"`), and re-tested in the sandbox. If the re-test passes, the break is healed automatically without human intervention. If unresolvable, the failure falls back to conservative retry or human review escalation (`analyze_failure_and_correct`).
