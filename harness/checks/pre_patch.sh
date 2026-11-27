#!/usr/bin/env bash
# harness/checks/pre_patch.sh
# Executes repository health and baseline safety checks before applying patches.

set -euo pipefail

REPO_DIR="${1:-.}"
cd "$REPO_DIR"

if [ ! -d ".git" ]; then
  echo "ERROR: Target directory is not a git repository: $REPO_DIR" >&2
  exit 1
fi

# Reject symlinked dependency manifests (sandbox traversal guard)
for manifest in package.json package-lock.json npm-shrinkwrap.json requirements.txt pom.xml; do
  if [ -L "$manifest" ]; then
    echo "ERROR: Symlinked manifest is forbidden: $manifest" >&2
    exit 1
  fi
done

echo "OK: Pre-patch repository safety checks passed for $REPO_DIR"
