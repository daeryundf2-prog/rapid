#!/usr/bin/env sh
set -eu

HOST_NAME="${RAPIDTRIAGE_HOST:-127.0.0.1}"
PORT="${RAPIDTRIAGE_PORT:-8877}"
OUTPUT_DIR="rapidtriage-macos-linux-smoke"
VENV_DIR=".rapidtriage-smoke-venv"
REINSTALL=0
SKIP_WEB=0

usage() {
  echo "Usage: scripts/smoke-test-rapidtriage.sh [--host 127.0.0.1] [--port 8877] [--output-dir rapidtriage-macos-linux-smoke] [--venv-dir .rapidtriage-smoke-venv] [--reinstall] [--skip-web]" >&2
}

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
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --venv-dir)
      VENV_DIR="$2"
      shift 2
      ;;
    --reinstall)
      REINSTALL=1
      shift
      ;;
    --skip-web)
      SKIP_WEB=1
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
case "$VENV_DIR" in
  /*)
    VENV_ROOT="$VENV_DIR"
    ;;
  *)
    VENV_ROOT="$REPO_ROOT/$VENV_DIR"
    ;;
esac
VENV_PYTHON="$VENV_ROOT/bin/python"
case "$OUTPUT_DIR" in
  /*)
    SMOKE_DIR="$OUTPUT_DIR"
    ;;
  *)
    SMOKE_DIR="$REPO_ROOT/$OUTPUT_DIR"
    ;;
esac
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

checked_python() {
  step "$1"
  shift
  output_file=""
  if [ "$1" = "--output-file" ]; then
    output_file="$2"
    shift 2
  fi
  if [ -n "$output_file" ]; then
    "$VENV_PYTHON" "$@" | tee "$output_file"
  else
    "$VENV_PYTHON" "$@"
  fi
}

cd "$REPO_ROOT"
mkdir -p "$SMOKE_DIR"

if [ "$REINSTALL" -eq 1 ] && [ -d "$VENV_ROOT" ]; then
  step "Removing existing smoke-test virtual environment"
  rm -rf "$VENV_ROOT"
fi

if [ ! -x "$VENV_PYTHON" ]; then
  step "Creating smoke-test Python virtual environment"
  system_python -m venv "$VENV_ROOT"
fi

checked_python "Installing RapidTriage web/test dependencies" -m pip install -U pip
checked_python "Installing editable package" -m pip install -e '.[web,test]'
checked_python "Checking CLI entrypoint" --output-file "$SMOKE_DIR/rapidtriage-help.txt" -m rapidtriage --help
checked_python "Running runtime doctor" --output-file "$SMOKE_DIR/doctor.json" -m rapidtriage doctor --host "$HOST_NAME" --port "$PORT" --json
checked_python "Running synthetic sample case" --output-file "$SMOKE_DIR/sample.json" -m rapidtriage sample --output-dir "$SMOKE_DIR/sample" --run --overwrite --read-only --json
checked_python "Searching sample case for password" -m rapidtriage search "$SMOKE_DIR/sample/run-output" -k password --output "$SMOKE_DIR/sample-search.json"
checked_python "Running small benchmark" --output-file "$SMOKE_DIR/benchmark.json" -m rapidtriage benchmark --output-dir "$SMOKE_DIR/benchmark" --file-count 100 --search-iterations 1 --overwrite --json
checked_python "Building validation package" --output-file "$SMOKE_DIR/validation.json" -m rapidtriage validation --output-dir "$SMOKE_DIR/validation" --overwrite --json

DUMMY_VHDX="$SMOKE_DIR/dummy.vhdx"
: > "$DUMMY_VHDX"
checked_python "Checking evidence support guidance" --output-file "$SMOKE_DIR/evidence-vhdx.json" -m rapidtriage evidence "$DUMMY_VHDX" --json

if [ "$SKIP_WEB" -eq 0 ]; then
  step "Starting web server smoke check at $WEB_URL"
  # The API requires a token by default since auth hardening; use a fixed
  # smoke-only token so the contract request can authenticate.
  SMOKE_TOKEN="rapidtriage-smoke-token"
  "$VENV_PYTHON" -m rapidtriage web --host "$HOST_NAME" --port "$PORT" --auth-token "$SMOKE_TOKEN" > "$SMOKE_DIR/web-server.log" 2>&1 &
  WEB_PID=$!
  trap 'kill "$WEB_PID" >/dev/null 2>&1 || true' EXIT INT TERM

  ready=0
  i=0
  while [ "$i" -lt 30 ]; do
    if "$VENV_PYTHON" - "$WEB_URL" "$SMOKE_DIR/web-index.html" >/dev/null 2>&1 <<'PY'
from __future__ import annotations

import sys
from pathlib import Path
from urllib.request import urlopen

url = sys.argv[1]
output = Path(sys.argv[2])
with urlopen(url, timeout=2) as response:
    body = response.read()
    if response.status != 200:
        raise SystemExit(1)
output.write_bytes(body)
PY
    then
      ready=1
      break
    fi
    i=$((i + 1))
    sleep 1
  done

  if [ "$ready" -ne 1 ]; then
    echo "Web UI did not respond with HTTP 200 at $WEB_URL." >&2
    exit 1
  fi

  "$VENV_PYTHON" - "$WEB_URL" "$SMOKE_DIR/workbench-smoke-contract.json" "$SMOKE_TOKEN" >/dev/null 2>&1 <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

url = sys.argv[1].rstrip("/") + "/api/workbench/smoke-contract"
output = Path(sys.argv[2])
token = sys.argv[3]
request = Request(url, headers={"X-RapidTriage-Token": token})
with urlopen(request, timeout=5) as response:
    payload = json.loads(response.read().decode("utf-8"))
    if payload.get("profile_version") != "single-case-workbench-smoke-v1":
        raise SystemExit(1)
output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

  kill "$WEB_PID" >/dev/null 2>&1 || true
  trap - EXIT INT TERM
else
  checked_python "Writing workbench smoke contract artifact" --output-file "$SMOKE_DIR/workbench-smoke-contract.json" - <<'PY'
from __future__ import annotations

import json
from rapidtriage.api.app import build_workbench_smoke_contract

print(json.dumps(build_workbench_smoke_contract(), ensure_ascii=False, indent=2))
PY
fi

if [ "$SKIP_WEB" -eq 0 ]; then
  checked_python "Summarizing smoke outputs" "$REPO_ROOT/scripts/summarize-smoke.py" "$SMOKE_DIR" --platform macos-linux
else
  checked_python "Summarizing smoke outputs" "$REPO_ROOT/scripts/summarize-smoke.py" "$SMOKE_DIR" --platform macos-linux --allow-missing-web
fi

step "macOS/Linux smoke test completed"
echo "Smoke outputs: $SMOKE_DIR"
