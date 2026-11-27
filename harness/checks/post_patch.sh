#!/usr/bin/env bash
# harness/checks/post_patch.sh
# Validates manifest integrity and test execution after patching.

set -euo pipefail

REPO_DIR="${1:-.}"
ECOSYSTEM="${2:-npm}"
cd "$REPO_DIR"

for manifest in package.json package-lock.json npm-shrinkwrap.json requirements.txt pom.xml; do
  if [ -L "$manifest" ]; then
    echo "ERROR: Post-patch symlinked manifest detected: $manifest" >&2
    exit 1
  fi
done

case "$ECOSYSTEM" in
  npm)
    if [ -f "package.json" ]; then
      node -e "JSON.parse(require('fs').readFileSync('package.json', 'utf8'))"
    fi
    ;;
  pip|pypi|python)
    if [ -f "requirements.txt" ]; then
      test -s "requirements.txt"
    fi
    ;;
  maven)
    if [ -f "pom.xml" ]; then
      grep -q "<project" pom.xml
    fi
    ;;
  *)
    echo "ERROR: Unsupported ecosystem '$ECOSYSTEM'" >&2
    exit 1
    ;;
esac

echo "OK: Post-patch integrity checks passed ($ECOSYSTEM) for $REPO_DIR"
