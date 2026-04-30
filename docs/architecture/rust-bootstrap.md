# Rust Worker Bootstrap

RapidTriage uses Python for product orchestration and Rust for high-volume worker engines. The initial Rust workspace lives at `engines/rust` and builds the `rapid-worker` binary.

## Requirements

- Rust stable toolchain with `cargo`, `rustc`, and `rustfmt`.
- `rustup` is recommended so the same script can install or select the stable toolchain.

Install Rust from <https://rustup.rs/> if the commands are not already available.

## Bootstrap And Check

From the repository root:

```sh
scripts/rust-bootstrap.sh --install
```

Use `--install` on a new machine or CI image with `rustup` already present. It installs the configured toolchain and `rustfmt`, then runs the normal checks.

For an already configured machine:

```sh
scripts/rust-bootstrap.sh
```

The script runs these checks in `engines/rust`:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
cargo build --bin rapid-worker
```

Set `RAPIDTRIAGE_RUST_TOOLCHAIN` or pass `--toolchain` to select a different rustup toolchain:

```sh
RAPIDTRIAGE_RUST_TOOLCHAIN=stable scripts/rust-bootstrap.sh
scripts/rust-bootstrap.sh --toolchain stable
```

For a faster local contract check, use:

```sh
scripts/rust-bootstrap.sh --skip-build
```

## Worker Smoke Commands

After a successful build, the worker can be run directly:

```sh
engines/rust/target/debug/rapid-worker --version
engines/rust/target/debug/rapid-worker parse --kind noop --source testdata --case-id CASE-1 --source-id SRC-1
engines/rust/target/debug/rapid-worker parse --kind file-inventory --source testdata --max-records 5
engines/rust/target/debug/rapid-worker parse --kind evtx-inventory --source testdata/Windows/System32/winevt/Logs --max-records 5
```

Worker stdout is newline-delimited `ArtifactRecordV1` JSON. Stderr is reserved for command errors and diagnostics.

`evtx-inventory` is intentionally an inventory/validation-gate worker, not a report-grade event renderer yet. It emits candidate EVTX file records with header version and next-record metadata, and keeps `commercial_grade_ready=false` until native record decoding, provider message rendering, and cross-tool validation are implemented.

## End-To-End Case DB Smoke

To verify the complete worker-to-review path, run:

```sh
python scripts/worker-case-db-smoke.py --output-dir ./worker-case-db-smoke
```

The smoke script builds or locates `rapid-worker`, generates a tiny EVTX fixture, runs `rapidtriage worker-parse --kind evtx-records`, imports the JSONL with `case-db --import-worker-jsonl`, and verifies that `case-search` can find the `PowerShell` event artifact.
