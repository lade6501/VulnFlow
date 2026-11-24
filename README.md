<!--
README.md
Provides project overview, architecture summary, and getting started instructions for VulnFlow.
-->

# 🛡️ VulnFlow AI

> **Autonomous, Agentic Vulnerability Remediation Platform**  
> Ingests security scanner findings, collapses them by root-cause dependency, plans safe upgrades grounded in advisories, enforces corporate policies, verifies in sandboxes, and opens verifiable pull requests.

---

## 📋 Table of Contents
1. [Overview & Architecture](#-overview--architecture)
2. [Prerequisites](#-prerequisites)
3. [Installation & Setup](#-installation--setup)
4. [Configuration](#-configuration)
5. [Usage & CLI Reference](#-usage--cli-reference)
6. [Human Approval & Exception Workflow](#-human-approval--exception-workflow)
7. [MCP Tool Servers (FastMCP Protocol)](#-mcp-tool-servers-fastmcp-protocol)
8. [Web Dashboard (UI)](#-web-dashboard-ui)
9. [Running Test Suites](#-running-test-suites)

---

## 🏛️ Overview & Architecture

VulnFlow AI replaces noisy, duplicate security alerts with an intelligent, 10-node remediation state machine:

```
[Ingest] ➔ [Dedupe] ➔ [Root Cause Grouping] ➔ [Policy Check]
                                                      │
                                    ┌─────────────────┴─────────────────┐
                                    ▼                                   ▼
                              [Plan Node]                        [Exception Node]
                                    │                             (Idempotent Ticket)
                                    ▼
                             [Approval Gate]
                       (Pause / Human Authorization)
                                    │
                                    ▼
                         [Fix & Sandbox Test Loop]
                       (Self-Correction on Failure)
                                    │
                                    ▼
                           [PR Creation Node]
                                    │
                                    ▼
                             [Verify Node]
                      (Scan Diff & Policy Recheck)
```

- **Root-Cause Grouping**: Collapses cascading transitive vulnerabilities to their direct parent dependencies.
- **FastMCP Protocol**: Zero-dependency Anthropic Model Context Protocol (2024-11-05 JSON-RPC stdio) tool servers for all side-effects.
- **Deterministic Policy Engine**: Enforces pre-approved package whitelists, allowed version ranges, and license constraints across **npm**, **Python (PyPI)**, and **Java (Maven)**.
- **Self-Correction Loop**: Automatically falls back to conservative versions when sandbox tests fail, escalating to human review upon retry exhaustion.
- **Strict Verification Invariant**: A failed verification (residual CVEs, failing tests, or policy violations) is **never** reported as success.

---

## 📦 Prerequisites

- **Python**: `3.11`, `3.12`, or `3.13`
- **Git**: Installed and available on your `PATH`
- **Node.js & npm** (optional): Needed for npm manifest dependency tests and for running the web UI.
- **Security Scanner** (optional): [Trivy](https://github.com/aquasecurity/trivy), Grype, or any scanner outputting JSON or SARIF. (VulnFlow also provides sample scanner reports out of the box).

---

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/lade6501/VulnFlow.git
cd VulnFlow/vulnflow
```

### 2. Create and Activate a Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install VulnFlow

#### Option A: Minimal Core Engine (Fastest)
The core deterministic engine, FastMCP servers, and CLI require only standard library plus YAML/Pydantic:
```bash
pip install -e .
# or: pip install -r requirements.txt
```

#### Option B: Full Stack (With LangGraph, API, and Dev Tools)
```bash
pip install -e ".[all]"
# or: pip install -r requirements-dev.txt
```

Verify installation:
```bash
vulnflow --help
```

---

## ⚙️ Configuration

Copy the example environment file and configure your API keys:

```bash
cp .env.example .env
```

Edit `.env`:
```ini
# LLM Provider: nvidia (default), openrouter, openai, anthropic, ollama, or bedrock
VULNFLOW_LLM_PROVIDER=nvidia

# API Key for chosen provider (e.g. NVIDIA NIM):
NVIDIA_API_KEY="nvapi-..."

# GitHub Personal Access Token (Requires 'repo' scope for opening PRs):
GITHUB_TOKEN="ghp_..."

# Optional Jira integration (for enterprise security ticketing):
# JIRA_URL="https://your-domain.atlassian.net"
# JIRA_API_TOKEN="..."
```

> **Note**: VulnFlow includes a built-in circuit breaker and offline fallback. If no LLM API key is configured or the network is unreachable, VulnFlow automatically switches to its deterministic planner.

---

## 💻 Usage & CLI Reference

VulnFlow can be executed directly as `vulnflow` (after running `./run.sh install` or `.\run.ps1 install`), or via the universal launchers:
- **macOS / Linux**: `./run.sh <command> [options]`
- **Windows PowerShell**: `.\run.ps1 <command> [options]`
- **Windows CMD**: `run.bat <command> [options]`

---

### Command Overview

| Command | Purpose |
|---|---|
| **`vulnflow scan`** / **`analyze`** | Ingest scanner reports, deduplicate findings, evaluate policy, and formulate remediation plans (or open PRs). |
| **`vulnflow report`** | Read-only assessment mode. Generates structured JSON or Markdown reports without modifying repository code. |
| **`vulnflow serve`** | Launches the unified Web Dashboard and REST API on `http://localhost:8000` (zero pip packages required). |
| **`vulnflow approve`** | Authorizes or rejects a `REVIEW`-tier remediation plan and resumes the workflow. |
| **`vulnflow audit`** | Inspects chronological audit trails of past remediation runs. |
| **`vulnflow install`** | Links the `vulnflow` executable into your user `PATH` for direct terminal access. |

---

### Attributes & Options Reference (`scan`, `analyze`, `report`)

| Flag / Option | Short | Type / Choices | Default | Description |
|---|:---:|---|---|---|
| `--repo` | | `PATH` | `.` | Target repository directory to inspect and remediate. |
| `--mode` | | `report` \| `pr` \| `dry-run` | `pr` (in `scan`/`analyze`)<br>`report` (in `report`) | • **`report`**: Read-only assessment; no code changes.<br>• **`pr`**: Generate fixes, test in sandbox, and open GitHub PRs.<br>• **`dry-run`**: Formulate patches and test locally without opening remote PRs. |
| `--report` | | `PATH` | *Auto-detected* | Path to existing scanner JSON or SARIF report. If omitted, auto-detects `gitleaks.json`, `trivy.json`, `grype.json`, or `snyk.json`. |
| `--scanner` | | `trivy` \| `grype` \| `snyk` \| `gitleaks` | `trivy` | Security scanner format used to parse the report. |
| `--ecosystem` | | `npm` \| `maven` \| `pip` | `npm` | Primary dependency ecosystem of the target repository. |
| `--output` | `-o` | `PATH` | `.vulnflow/reports/report_<RUN_ID>.<ext>` | Destination file path to save the generated report. |
| `--format` | | `markdown` \| `json` | `markdown` | Report format to write to disk (`markdown` or `json`). |
| `--auto-approve` | | *Flag* (boolean) | `False` | Auto-approve all `REVIEW`-tier plans (e.g. secret rotations or major bumps) without pausing for human sign-off. |
| `--no-llm` | | *Flag* (boolean) | `False` | Bypasses remote LLM calls and uses the fast, deterministic rule-based planner. Useful for offline runs or low-latency CI. |
| `--langsmith` | | *Flag* (boolean) | `False` | Force-enables LangSmith distributed tracing. |
| `--no-langsmith` | | *Flag* (boolean) | `False` | Explicitly disables LangSmith tracing even if `LANGSMITH_API_KEY` is present. |
| `--langsmith-project` | | `STRING` | `vulnflow` | Overrides the target LangSmith project name. |

---

### Web Dashboard & Server Options (`serve`)

| Flag / Option | Type | Default | Description |
|---|---|---|---|
| `--port` | `INT` | `8000` | Port to listen on. |
| `--host` | `STRING` | `0.0.0.0` | Binding host address. |
| `--dev` | *Flag* | `False` | Launch Vite development server with hot module reloading on `:5173`. |
| `--build-ui` | *Flag* | `False` | Rebuild frontend React bundle before starting. |
| `--reload` | *Flag* | `False` | Auto-reload backend on Python file modifications. |
| `--open` | *Flag* | `False` | Automatically open default browser to Dashboard URL. |

---

### Governance & Approval Options (`approve`)

| Flag / Option | Type | Default | Description |
|---|---|---|---|
| `--plan-id` | `STRING` | *Required* | Remediation plan ID to authorize or reject (e.g. `PLAN-SEC-FND-e750`). |
| `--resume` | *Flag* | `False` | Automatically resume workflow execution and create PR upon approval. |
| `--reviewer` | `STRING` | `security-lead` | Reviewer identifier or email address. |
| `--reviewer-group` | `STRING` | `security` | Approver group represented by the reviewer, such as `security`, `product-owner`, or `vp`. |
| `--reason` | `STRING` | `None` | Explanation or justification for approval/rejection decision. |
| `--reject` | *Flag* | `False` | Reject the remediation plan instead of approving. |

---

### Common Command Recipes

```bash
# 1. Quick read-only report (no code changes)
vulnflow scan --repo fake-vuln-repo --mode report
# Or shorthand:
vulnflow report --repo fake-vuln-repo

# 2. Autonomous PR remediation (pauses on review tier for security approval)
vulnflow scan --repo fake-vuln-repo --mode pr

# 3. Fully unattended CI/CD (auto-approves review tier and opens PRs in one shot)
vulnflow scan --repo fake-vuln-repo --mode pr --auto-approve

# 4. Custom scanner report input with JSON output
vulnflow scan --repo fake-vuln-repo --scanner gitleaks --report data/fixtures/sample_gitleaks_report.json --format json -o audit.json

# 5. Fast offline deterministic execution (zero LLM calls)
vulnflow scan --repo fake-vuln-repo --mode report --no-llm

# 6. Authorize a review-tier plan and resume PR creation
vulnflow approve --plan-id PLAN-SEC-FND-8ba1 --resume --repo fake-vuln-repo

# 7. Start the Web Dashboard & API (zero pip packages required)
vulnflow serve
```

---

## 🚦 Human Approval & Exception Workflow

### Review-Tier Pauses (`Exit Code: 10`)
When a vulnerability involves an unapproved package (`UNKNOWN`), a major SemVer upgrade, or a deprecated library replacement, VulnFlow safely halts execution:
- **Safeguard**: PR creation is withheld to prevent merging unvetted dependencies.
- **State Saved**: With Supabase configured, each execution checkpoint and approval is durable across CI workers and action runs. Local `.vulnflow` files remain as a development fallback.

### Durable Supabase approvals

Apply `supabase/migrations/202611240001_vulnflow_approvals.sql` to the Supabase project, then configure the trusted API/CI environment:

```bash
SUPABASE_URL=https://iozaqfqmyyhqfggiimcm.supabase.co
SUPABASE_SECRET_KEY=<sb_secret_backend-only-key>
VULNFLOW_ORG_SLUG=acme
VULNFLOW_REPOSITORY=acme/payments-api
VULNFLOW_APPROVER_GROUPS=security,product-owner,vp
VULNFLOW_SUPABASE_REQUIRED=true
```

Equivalent plans from later runs reuse the same active approval request. Every group in `VULNFLOW_APPROVER_GROUPS` must reach its quorum before the workflow resumes. Record each decision using the reviewer's actual group:

```bash
vulnflow approve --plan-id PLAN-ebaaef6720e2 --reviewer vp@example.com --reviewer-group vp --resume
```

The service-role key bypasses Row Level Security and must never be exposed to the browser or committed to the repository.

```
====================================================================
🛡️  VulnFlow Execution Summary [Run: RUN-520d7e6e]
====================================================================
Status:       PENDING_APPROVAL
Exit Code:    10
Plans:        1 generated (0 approved, 1 pending review)

⚠️  Human Security Approval Required (Exit Code: 10):
  • Status:      1 plan(s) paused awaiting human authorization.
  • Safeguard:   PR creation withheld to prevent merging unvetted dependencies.
  • Plan ID:     PLAN-ebaaef6720e2 (pip:Django -> 5.2.8)
====================================================================
```

### Approve and Resume
Approve the plan and resume execution to open the PR:
```bash
vulnflow approve \
  --plan-id PLAN-ebaaef6720e2 \
  --repo /path/to/target-repo \
  --reviewer "security-lead@company.com" \
  --reason "Django 5.2.8 is approved for production deployment" \
  --resume
```

### Reject a Plan
Reject a plan with a stored reason (prevents PR creation and logs decision):
```bash
vulnflow approve \
  --plan-id PLAN-ce5a6c2257e0 \
  --repo /path/to/target-repo \
  --reject \
  --reason "Flask 2.3 introduces breaking API changes"
```

### Unapproved / Banned Fixes (`Exit Code: 20`)
When a package is banned or no approved candidates exist, VulnFlow creates an idempotent security exception ticket via Jira/GitHub Issues and opens **no pull requests**.

---

## 🔌 MCP Tool Servers (FastMCP Protocol)

VulnFlow strictly isolates all side-effects behind standardized Model Context Protocol (MCP) tool servers:

| MCP Server | Server Name | Purpose |
|---|---|---|
| `policy_server.py` | `vulnflow-policy` | Evaluates organizational policy, whitelists, and candidates. |
| `git_server.py` | `vulnflow-git` | Creates branches, commits patches, and opens PRs. |
| `build_server.py` | `vulnflow-build` | Executes sandboxed test and build commands. |
| `scan_server.py` | `vulnflow-scan` | Runs scanners and computes rescan diffs (`scan_diff`). |
| `registry_server.py` | `vulnflow-registry` | Validates target versions on npm and PyPI registries. |
| `ticket_server.py` | `vulnflow-ticket` | Opens idempotent Jira / GitHub Issues exception tickets. |
| `notify_server.py` | `vulnflow-notify` | Dispatches approval notifications (Slack, webhook). |
| `knowledge_server.py` | `vulnflow-knowledge` | Queries dependency graph, blast radius, and advisories. |

### Running as Standalone Stdio Servers
Any server can be run standalone:
```bash
PYTHONPATH=src python3 src/vulnflow/mcp_servers/policy_server.py
```

### Claude Desktop / Cursor Integration
See [`mcp_config.example.json`](file:///Users/vishal/Documents/VulnFlow/vulnflow/mcp_config.example.json) to connect VulnFlow's MCP servers directly into Cursor, Claude Desktop, or external AI agents.

---

## 🖥️ Web Dashboard (UI)

VulnFlow includes a modern React + TypeScript dashboard to visualize runs, approval queues, and dependency graphs:

```bash
cd ui
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 🧪 Running Test Suites

VulnFlow maintains a comprehensive test suite across contracts, foundation, and intelligence:

```bash
# 1. Contract & Phase 0 Gate Tests
PYTHONPATH=src python3 tests/contract/test_contracts.py

# 2. Phase 1 Core Remediation Spine Tests (F01-F19)
PYTHONPATH=src python3 tests/integration/test_phase1_spine.py

# 3. Phase 2 Intelligence & Advanced Governance Tests (F05-F22)
PYTHONPATH=src python3 tests/integration/test_phase2_intelligence.py

# Or run everything with pytest:
pytest tests/
```
