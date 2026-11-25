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

## Remediation evidence and control-plane requests

- Approval checkpoints retain normalized findings, their deduped baseline, audit events, and retry
  and approval settings. The count fields remain available. Older checkpoints without a finding
  baseline require a new assessment before a fix can be verified.
- `scan_verify(repo, scanner, branch, finding_types)` returns execution and completion flags,
  normalized findings, dependency evidence, and the Git revision examined. An empty finding list
  is usable only when the scan completed. `VerificationResult` carries the scan status and revision.
- `npm_update_lock` resolves the existing npm lockfile offline with lifecycle scripts disabled.
  `build_test` reports the tested revision and whether verification was available. Automatic PR
  creation requires passing tests and a completed scan for the same revision.
  `pr_create(..., expected_revision)` rejects a moved branch. Preview results have no PR URL.
- `git_replace_text` applies a single exact source replacement within the checkout.
  `CodeRefactorProposal` defines the structured compatibility proposal accepted from the model.
- `registry_check.confirmed` distinguishes a verified version from an offline planning candidate.
  Automated retries and PR creation require confirmation.
- Run creation and signed webhooks return HTTP 202 with a run ID and `queued` status. Clients poll
  `GET /api/runs/{run_id}` for the result. Queued runs have a null exit code.

See [ADR 0002](adr/0002-remediation-evidence.md) for the rollout requirements.
