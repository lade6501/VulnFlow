<!--
docs/adr/0002-remediation-evidence.md
Records how VulnFlow confirms remediation and controls API-triggered runs.
-->

# ADR 0002: Remediation evidence and API boundaries

Status: Accepted  
Date: 2026-11-25  
Features: F17–F22, F27, F30, F34, F36–F37

## Decision

Run builds in a disposable checkout of a committed revision and run repository code in a
pre-provisioned Docker image with networking disabled. Missing tools, dependencies, and tests
prevent an automated success. Run the post-fix scan on a separate checkout of the same revision.
Only a clean, completed rescan and passing checks allow the corresponding revision to be pushed.
Report mode records an assessment. GitHub responses determine whether a PR opened.

Retain findings and audit history in approval checkpoints. Treat model-generated source changes
as structured proposals and accept them only through a repository-scoped Git operation. Retries
need a policy-approved, registry-confirmed version supported by advisory evidence.

Authenticate control-plane mutations with a bearer token and scanner webhooks with an HMAC of
the raw request body. Validate repository and report paths against configured workspace roots.
Queue accepted runs in a bounded, single-worker, in-process queue.

## Consequences

- Live branch verification currently uses Trivy. Uploaded reports may use additional adapters for
  assessment. Unsupported post-fix scanners leave remediation unverified.
- Dependencies must be available offline in the build image. npm dependency projects require a
  committed npm lockfile. VulnFlow updates it with the offline npm cache before running
  `npm ci`. A lockfile update that cannot be produced and verified offline blocks publication.
- API clients handle HTTP 202, 401, 413, 422, and 503. The queue is process-local and accepted jobs
  can be lost if the service stops before execution finishes.
- The shared control-plane token authorizes a trusted operator. Reviewer identity and group values
  remain application inputs. Individual identity binding requires an upstream authenticated service.
