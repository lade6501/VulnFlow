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

### 1. Analyze and Remediate a Repository (PR Mode)
Ingests scanner findings, groups by root cause, formulates plans, checks policy, and opens PRs:
```bash
vulnflow analyze \
  --repo /path/to/target-repo \
  --report /path/to/trivy-results.json \
  --mode pr
```

### 2. Report-Only Mode (Read-Only)
Generates an executive vulnerability remediation report without making code changes:
```bash
# Generate Markdown Report
vulnflow report \
  --repo /path/to/target-repo \
  --report /path/to/trivy-results.json \
  --format markdown \
  -o remediation_report.md

# Generate Structured JSON Report
vulnflow report \
  --repo /path/to/target-repo \
  --report /path/to/trivy-results.json \
  --format json \
  -o remediation_report.json
```

### 3. Fast Offline Execution (`--no-llm`)
Skips remote LLM calls and runs entirely on deterministic policy and knowledge rules:
```bash
vulnflow analyze --repo ./samples/npm-simple-bump --mode pr --no-llm
```

### 4. Inspect Chronological Audit Trail
Inspect chronological audit logs from any run:
```bash
vulnflow audit
# Or inspect specific run:
vulnflow audit --run-id RUN-520d7e6e4f40
```

---

## 🚦 Human Approval & Exception Workflow

### Review-Tier Pauses (`Exit Code: 10`)
When a vulnerability involves an unapproved package (`UNKNOWN`), a major SemVer upgrade, or a deprecated library replacement, VulnFlow safely halts execution:
- **Safeguard**: PR creation is withheld to prevent merging unvetted dependencies.
- **State Saved**: Current execution state is persisted to `<repo>/.vulnflow/pending_state.json`.

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
