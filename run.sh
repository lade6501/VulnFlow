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

# Preserve original working directory for CLI subcommands
ORIGINAL_PWD="$(pwd)"

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

# Automatically source .env variables if present
if [ -f "$VULNFLOW_ROOT/.env" ]; then
  set -a
  source "$VULNFLOW_ROOT/.env" 2>/dev/null || true
  set +a
elif [ -f "$VULNFLOW_ROOT/../.env" ]; then
  set -a
  source "$VULNFLOW_ROOT/../.env" 2>/dev/null || true
  set +a
fi

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

# If invoked with no arguments, display quick start guide
if [ $# -eq 0 ]; then
  cd "$ORIGINAL_PWD"
  exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py"
fi

# Subcommand routing
ACTION="$1"

case "$ACTION" in
  serve)
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
    # Pass directly to VulnFlow CLI from original caller working directory
    cd "$ORIGINAL_PWD"
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" "$@"
    ;;

  install)
    print_banner
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    ln -sf "$VULNFLOW_ROOT/run.sh" "$INSTALL_DIR/vulnflow"
    chmod +x "$VULNFLOW_ROOT/run.sh"
    echo -e "${GREEN}✅ Successfully installed VulnFlow CLI link to: $INSTALL_DIR/vulnflow${RESET}\n"
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
      echo -e "${YELLOW}Notice: $INSTALL_DIR is not yet in your current PATH.${RESET}"
      echo -e "Add this to your ~/.zshrc or ~/.bashrc:"
      echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\"\n"
    fi
    echo -e "You can now run '${BOLD}vulnflow${RESET}' directly from any directory in your terminal!"
    echo -e "Try:"
    echo -e "  ${CYAN}vulnflow scan --repo fake-vuln-repo --mode report${RESET}"
    echo -e "  ${CYAN}vulnflow serve${RESET}"
    echo -e "  ${CYAN}vulnflow --help${RESET}\n"
    exit 0
    ;;

  help|--help|-h)
    cd "$ORIGINAL_PWD"
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" --help
    ;;

  *)
    cd "$ORIGINAL_PWD"
    exec python3 "$VULNFLOW_ROOT/src/vulnflow/cli.py" "$@"
    ;;
esac
