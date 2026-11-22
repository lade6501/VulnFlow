<!--
docs/adr/0001-canonical-run-report.md
Records the canonical F43 report contract and dependency-free rendering decision.
-->

# ADR 0001: Canonical enterprise run report

Status: Accepted  
Date: 2026-11-21  
Feature: F43

## Context

Legacy JSON and Markdown reports independently interpreted mutable workflow state. That allowed
counts and success language to diverge, and missing test or rescan evidence could appear successful.
F43 also adds a public, versioned contract, which is a breaking contract change under project rules.

## Decision

VulnFlow builds one immutable Pydantic `RunReport` snapshot from persisted workflow state, stored
plans and verified audit/tool evidence. JSON, HTML and Markdown render that same object without
additional analysis or model calls. Execution claims require matching successful audit evidence;
unknown evidence remains null, `UNKNOWN` or `NOT_EVALUATED`.

HTML uses Python's standard-library escaping and a trusted static template. No template-engine
dependency is added: the only replacement token contains already escaped, locally rendered markup.
This keeps the report offline, self-contained and compatible with the project's minimal runtime.

## Consequences

- Consumers must use `schema_version` and tolerate explicit nullability.
- A legacy verification result without an executed-rescan event cannot claim zero residual risk.
- New report fields are added through `contracts/report.py` first, then populated by the builder and
  displayed by every relevant renderer.
- The static HTML template must remain active-content-free and is shipped as package data.

