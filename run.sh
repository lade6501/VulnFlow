#!/usr/bin/env bash
#
# run.sh - Quickstart unified launcher for VulnFlow AI Engine & Control Plane Dashboard
#
# Quick Commands:
#   ./run.sh                  -> Start unified Web Dashboard & API on http://localhost:8000
#   ./run.sh dev              -> Start in Dev mode with Vite hot-reloading on :5173 + API on :8000
#   ./run.sh scan [options]   -> Run autonomous vulnerability scanner & fix planner
#   ./run.sh approve [options]-> Approve pending review-tier remediation plan
#   ./run.sh docker           -> Build and run self-contained Docker container
#   ./run.sh build            -> Build production frontend UI bundle
#

set -e

# Resolve script directory (handles symlinks and executions from any working directory)
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
VULNFLOW_ROOT="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

# If invoked from workspace root, ensure we are inside vulnflow directory
if [ -d "$VULNFLOW_ROOT/vulnflow" ]; then
  VULNFLOW_ROOT="$VULNFLOW_ROOT/vulnflow"
fi

cd "$VULNFLOW_ROOT"

# Ensure src/ and repo root are on PYTHONPATH
export PYTHONPATH="$VULNFLOW_ROOT/src:$VULNFLOW_ROOT:$PYTHONPATH"

# Color constants
BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RESET="\033[0m"

# Print banner
print_banner() {
  echo -e "${BOLD}${CYAN}====================================================================${RESET}"
  echo -e "${BOLD}${CYAN}🛡️   VulnFlow AI - Autonomous Security Remediation Platform${RESET}"
  echo -e "${BOLD}${CYAN}====================================================================${RESET}"
}

# Subcommand routing
ACTION="${1:-serve}"

case "$ACTION" in
  serve|"")
    print_banner
    # Auto-build UI if missing
    if [ ! -f "$VULNFLOW_ROOT/ui/dist/index.html" ]; then
      echo -e "${YELLOW}📦 First-time run: Building frontend Web Dashboard...${RESET}"
      (cd "$VULNFLOW_ROOT/ui" && npm run build)
      echo -e "${GREEN}✅ Frontend built successfully.${RESET}\n"
    fi
    shift || true
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" serve --open "$@"
    ;;

  dev)
    print_banner
    echo -e "${CYAN}🚀 Starting in Development Mode (Vite HMR on :5173 + API on :8000)${RESET}\n"
    shift || true
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" serve --dev "$@"
    ;;

  build)
    print_banner
    echo -e "${CYAN}📦 Building frontend UI bundle (Vite + React)...${RESET}"
    (cd "$VULNFLOW_ROOT/ui" && npm run build)
    echo -e "${GREEN}✅ Frontend build complete in ui/dist/${RESET}"
    ;;

  docker)
    print_banner
    echo -e "${CYAN}🐳 Building and running VulnFlow Docker container...${RESET}"
    docker build -t vulnflow:latest "$VULNFLOW_ROOT"
    echo -e "${GREEN}✅ Image built. Launching container on http://localhost:8000 ...${RESET}"
    docker run --rm -it -p 8000:8000 -v "$VULNFLOW_ROOT/.vulnflow:/app/.vulnflow" vulnflow:latest
    ;;

  docker-compose|compose)
    print_banner
    echo -e "${CYAN}🐳 Launching with Docker Compose...${RESET}"
    docker compose -f "$VULNFLOW_ROOT/docker-compose.yml" up --build
    ;;

  scan|analyze|report|fix|verify|approve|audit|watch-expiry)
    # Pass directly to VulnFlow CLI
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" "$@"
    ;;

  help|--help|-h)
    print_banner
    echo -e "Usage: ./run.sh [command] [options]\n"
    echo -e "Available Commands:"
    echo -e "  ${BOLD}serve${RESET}            Start unified Web Dashboard & API on http://localhost:8000 (Default)"
    echo -e "  ${BOLD}dev${RESET}              Start in Dev mode with Vite hot-reloading on :5173"
    echo -e "  ${BOLD}scan${RESET}             Scan repository and auto-plan fixes (e.g. ./run.sh scan --repo ../fake-vuln-repo)"
    echo -e "  ${BOLD}report${RESET}           Generate vulnerability report without modifying code"
    echo -e "  ${BOLD}approve${RESET}          Authorize review-tier plan (e.g. ./run.sh approve --plan-id <id> --resume)"
    echo -e "  ${BOLD}docker${RESET}           Build & run containerized VulnFlow on http://localhost:8000"
    echo -e "  ${BOLD}build${RESET}            Build production UI assets in ui/dist/"
    echo -e "  ${BOLD}audit${RESET}            View chronological audit log of remediation runs\n"
    ;;

  *)
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" "$@"
    ;;
esac
