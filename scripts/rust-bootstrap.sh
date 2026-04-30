#!/usr/bin/env sh
set -eu

INSTALL=0
SKIP_BUILD=0
SKIP_TESTS=0
TOOLCHAIN="${RAPIDTRIAGE_RUST_TOOLCHAIN:-stable}"
WORKSPACE_RELATIVE="engines/rust"

usage() {
  echo "Usage: scripts/rust-bootstrap.sh [--install] [--toolchain stable] [--skip-build] [--skip-tests]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install)
      INSTALL=1
      shift
      ;;
    --toolchain)
      TOOLCHAIN="$2"
      shift 2
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
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
RUST_WORKSPACE="$REPO_ROOT/$WORKSPACE_RELATIVE"

step() {
  printf '\n==> %s\n' "$1"
}

require_command() {
  command_name="$1"
  install_hint="$2"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "$command_name was not found. $install_hint" >&2
    exit 1
  fi
}

if [ ! -f "$RUST_WORKSPACE/Cargo.toml" ]; then
  echo "Rust workspace not found at $RUST_WORKSPACE" >&2
  exit 1
fi

if [ "$INSTALL" -eq 1 ]; then
  require_command rustup "Install rustup from https://rustup.rs/, then rerun with --install."
  step "Installing Rust toolchain: $TOOLCHAIN"
  rustup toolchain install "$TOOLCHAIN"
  rustup component add rustfmt --toolchain "$TOOLCHAIN"
fi

require_command cargo "Install Rust from https://rustup.rs/ or rerun this script after installing rustup."
require_command rustc "Install Rust from https://rustup.rs/ or rerun this script after installing rustup."

if command -v rustup >/dev/null 2>&1; then
  step "Checking Rust toolchain availability: $TOOLCHAIN"
  rustup run "$TOOLCHAIN" rustc --version
  rustup run "$TOOLCHAIN" cargo --version
  CARGO_PREFIX="rustup run $TOOLCHAIN cargo"
else
  step "Checking Rust toolchain availability"
  rustc --version
  cargo --version
  CARGO_PREFIX="cargo"
fi

cd "$RUST_WORKSPACE"

step "Checking Rust formatting"
$CARGO_PREFIX fmt --all -- --check

step "Checking Rust workspace"
$CARGO_PREFIX check --workspace --all-targets

if [ "$SKIP_TESTS" -eq 0 ]; then
  step "Testing Rust workspace"
  $CARGO_PREFIX test --workspace
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  step "Building rapid-worker"
  $CARGO_PREFIX build --bin rapid-worker
fi

step "Rust bootstrap/check completed"
echo "Workspace: $RUST_WORKSPACE"
