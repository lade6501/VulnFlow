<!--
harness/playbooks/npm.md
Step-by-step agent playbook for safely fixing npm package vulnerabilities.
-->

# npm Remediation Playbook

1. **Pre-Patch Checks:** Run `harness/checks/pre_patch.sh` to verify regular (non-symlinked) `package.json` and lockfile (`package-lock.json` / `npm-shrinkwrap.json`).
2. **Root-Cause Collapse:** Prefer bumping the direct parent dependency when a transitive dependency is vulnerable (`rootcause_node`). Only use `overrides` when no safe direct parent upgrade exists.
3. **Policy & Registry Gate:** Filter candidates through `policy_candidates` and verify existence in `registry_check`. Major SemVer bumps and unapproved versions always require `REVIEW` approval.
4. **Offline Lockfile Sync & Test:** Apply manifest bump in an isolated git worktree, resolve lockfile offline (`npm install --package-lock-only --offline --ignore-scripts`), and run the test suite in the offline sandbox (`--network=none`).
5. **Fallback on Failure:** On test failure, retry with the next lower approved/safe candidate version (`max_retries`). On exhaustion, classify as `BROKEN_TESTS` and open an exception ticket instead of a PR.
6. **Post-Patch Verification:** Confirm `scan_verify` shows zero target CVEs and zero regressions on the exact commit SHA before opening a PR.
