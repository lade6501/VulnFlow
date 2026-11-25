<!--
docs/reporting.md
Explains enterprise report generation, evidence rules, extension, and troubleshooting.
-->

# Enterprise run reporting

F43 renders these files from one immutable `RunReport` v1 snapshot:

- `run-report.json`: canonical machine-readable evidence and provenance.
- `report.html`: executive summary with run status, approvals, verification, and strategic decisions.
  The final section lists redacted credential locations when the run detects exposures.
- `technical-report.html`: expandable component-level evidence, policy results, and audit details.
- `report.md`: bounded reviewer summary with approvals near the top and links to the HTML evidence.

Both HTML reports work offline. They use inline styles and icons, native accordions, keyboard-accessible
tables, and respect the viewer's reduced-motion setting.

The default directory is `./vulnflow-report/<run-id>/`. Select formats with
`--output-format html,md,json` and change the root with `--out-dir PATH`. The scanner input remains
`--report PATH`; it is never reused as an output option. `--no-llm` disables planner model requests
and retains deterministic descriptions.

## Evidence and provenance

The builder reads normalized findings, root-cause groups, persisted plans, verified tool results and
audit events. It does not invoke a model, scanner, repository host or remediation tool. Patch, test,
PR and rescan states are `not_run`, `simulated`, `executed` or `failed`. An attempt is not an
execution success. After-state counts remain null until a successful executed rescan is recorded.

Advisory evidence must match package and ecosystem, cover the installed version, and show that the
target is outside the affected range or at/after a fixed version. Rejected evidence is retained in
validation notes. Expected CVEs use validated upstream evidence; verified CVEs additionally require
an executed clean rescan that resolves the persisted finding identifiers.

## AI intelligence boundary

Reports reuse persisted agent results and do not add a report-time model call. Factual insights are
rule-derived and cite finding or advisory IDs. Repository locations come only from scanner evidence;
runtime reachability is explicitly not evaluated. LLM narrative may be persisted only for executive
summary, impact or migration prose and must carry source references before it is labeled `llm`.

## Security controls

Report-boundary redaction removes common credential and PII forms. HTML escapes all untrusted data,
uses a restrictive Content Security Policy and checks advisory and PR URLs for HTTP(S). Trace values
are rendered as text. Markdown neutralizes mentions and syntax so scanner text
cannot create headings, links or instructions. All writes are atomic, and renderer failure leaves the
workflow exit code unchanged.

## Extending and debugging

Add a typed nullable field to `contracts/report.py`, document the contract change, populate it only
from evidence in `reporting/builder.py`, and render it from the same snapshot. Do not compute new
facts in a renderer. If evidence shows `UNKNOWN`, inspect the run's `evidence_snapshot`, matching
audit completion event and validation notes. Missing tests require `BUILD_TEST_EXECUTED`; clean
after-state requires `RESCAN_EXECUTED` or `SCAN_COMPLETED` with successful status.

