<!--
harness/playbooks/maven.md
Step-by-step agent playbook for resolving Maven vulnerability findings.
-->

# Maven Remediation Playbook

1. **Pre-Patch Checks:** Run `harness/checks/pre_patch.sh` to verify `pom.xml` is a regular file inside the target repository.
2. **Coordinate Mapping:** Normalize coordinates as `groupId:artifactId` and evaluate approved versions via `policy_candidates`.
3. **Policy & Risk Tiering:** Patch/minor bumps on approved coordinates may enter `AUTO` tier; major upgrades, deprecated replacements, or unapproved versions require `REVIEW` human approval.
4. **Offline Sandbox Build:** Update the matching `<dependency>` version in `pom.xml` inside an isolated worktree and run `mvn -o test` against `/opt/maven-repo` with network disabled (`--network=none`).
5. **Post-Patch Verification:** Re-scan the committed branch with `scan_verify` and verify zero residual CVEs and passing tests before opening a PR.
