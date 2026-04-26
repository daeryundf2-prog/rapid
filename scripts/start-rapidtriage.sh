#!/usr/bin/env sh
set -eu

HOST_NAME="${RAPIDTRIAGE_HOST:-127.0.0.1}"
PORT="${RAPIDTRIAGE_PORT:-8765}"
DOCTOR_ONLY=0
NO_BROWSER=0
REINSTALL=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host)
      HOST_NAME="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --doctor-only)
      DOCTOR_ONLY=1
      shift
      ;;
    --no-browser)
      NO_BROWSER=1
      shift
      ;;
    --reinstall)
      REINSTALL=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: scripts/start-rapidtriage.sh [--host 127.0.0.1] [--port 8765] [--doctor-only] [--no-browser] [--reinstall]" >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
WEB_URL="http://$HOST_NAME:$PORT"

step() {
  printf '\n==> %s\n' "$1"
}

system_python() {
  if command -v python3 >/dev/null 2>&1; then
    python3 "$@"
    return $?
  fi
  if command -v python >/dev/null 2>&1; then
    python "$@"
    return $?
  fi
  echo "Python 3.9+ was not found. Install Python, then rerun this script." >&2
  exit 1
}

cd "$REPO_ROOT"

if [ "$REINSTALL" -eq 1 ] && [ -x "$VENV_PYTHON" ]; then
  step "Removing existing virtual environment"
  rm -rf "$REPO_ROOT/.venv"
fi

if [ ! -x "$VENV_PYTHON" ]; then
  step "Creating Python virtual environment"
  system_python -m venv .venv
fi

step "Installing rapidtriage web dependencies"
"$VENV_PYTHON" -m pip install -U pip
"$VENV_PYTHON" -m pip install -e '.[web]'

step "Running rapidtriage doctor"
"$VENV_PYTHON" -m rapidtriage doctor --host "$HOST_NAME" --port "$PORT"

if [ "$DOCTOR_ONLY" -eq 1 ]; then
  exit 0
fi

if [ "$NO_BROWSER" -eq 0 ]; then
  step "Opening $WEB_URL"
  if command -v open >/dev/null 2>&1; then
    open "$WEB_URL" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$WEB_URL" >/dev/null 2>&1 || true
  else
    echo "Open this URL in your browser: $WEB_URL"
  fi
fi

step "Starting rapidtriage web UI"
echo "Press Ctrl+C in this terminal to stop the server."
"$VENV_PYTHON" -m rapidtriage web --host "$HOST_NAME" --port "$PORT"
