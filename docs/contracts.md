<!--
docs/contracts.md
Specifies Pydantic schema contracts, serialization rules, and state interfaces.
-->
## RunReport v1 (F43)

`src/vulnflow/contracts/report.py` defines the immutable Pydantic report contract. It contains a
versioned header, executive severity/count summary, required actions, typed root-cause intelligence,
policy and approvals, residual risk, provenance, validation notes and execution evidence. All three
renderers consume the same instance. Nullable counts mean unknown, never zero. Execution evidence
uses `not_run`, `simulated`, `executed` and `failed`; expected and verified CVEs are separate fields.

This contract was introduced by [ADR 0001](adr/0001-canonical-run-report.md).
