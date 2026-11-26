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

## Opt-In Rust EVTX Decoder (`rapidcore_native`)

The EVTX chunk BinXML decoder has a Rust port in `engines/rust/crates/rapidcore/src/evtx_binxml.rs`, exposed to Python as `rapidcore_native.EvtxChunkDecoder` (PyO3, `src/py.rs`). It is a line-for-line port of the Python `EvtxChunkDecoder` (`evtx-chunk-binxml-decoder-v2`): same value texts (Python float `repr`, 7-digit FILETIME, SID/GUID/SYSTEMTIME formatting), same EventData naming (`data_N`, `_2` de-duplication), same template/name cache and token-budget behaviour, same error types and messages. Chunk walking, slack/duplicate decisions and row building stay in Python, so the rows are identical by construction above the decoder. The mature `evtx` crate was not used: its rendering, naming and error behaviour differ from the Python decoder, and slack/garbage records would not produce the same rows.

Records the port cannot reproduce byte-for-byte (non-ASCII ANSI strings that Python decodes as cp949, lone-surrogate character references, element trees deeper than 200 levels) are reported as unsupported; the bridge (`rapidtriage/artifacts/windows/evtx_engine.py`) then replays the chunk with the Python decoder, so caches and counts still match. The count of such chunks is on the eventlog-file row.

The same engine switch also moves per-row Python work to Rust (`src/py.rs`, `src/py_rows.rs`, `src/py_json.rs`, `src/py_triage.rs`). Each kernel returns exactly what its Python counterpart returns on plain JSON values (exact `dict`/`list`/`str`/`int`/`float`/`bool`/`None`) and declines anything else, which then runs in Python:

- recovery-password redaction walk (`redact_recovery_passwords_in`);
- compaction of the eventlog stage output (`profile_observe_details`, `profile_common`, `profile_strip_level`) and profile expansion by readers of that output (`profile_merge`, chosen by `artifact_profiles.payload_row_kernels`);
- JSONL row text of the eventlog stage (`dump_json_row`, `artifacts._dump_row`);
- triage projection of event rows (`EventlogTriageProjector`, `eventlog.triage_eventlog_details`).

Build and select it:

```sh
python scripts/build-native-accel.py            # stages rapidtriage/native/rapidcore_native.*
RAPIDTRIAGE_EVTX_ENGINE=rust rapidtriage run ...  # or --eventlog-evtx-engine rust
```

The default stays `python`. With `rust` requested, the eventlog-file row carries `native_evtx_engine`, `native_evtx_engine_requested` and `native_evtx_engine_python_fallback_chunk_count`; when the module is missing or was built for another decoder version, Python is used and `native_evtx_engine_notice_ko` says why.

A chunk the Rust decoder cannot reproduce exactly is finished by the Python decoder. The row says why and where: `native_evtx_engine_python_fallback_reason_counts` counts switched chunks per reason (`non-ascii-ansi-string`, `surrogate-character-reference`, `element-nesting-too-deep`, or `unrecognized-native-reason`), and `native_evtx_engine_python_fallback_first_reason`, `…_first_chunk_index`, `…_first_chunk_offset`, `…_first_record_offset` (absolute file offsets) and `…_first_record_id` cite the first switch in the file. These fields are `null` when no chunk switched. They are unrelated to `native_fallback_record_count`, which counts records decoded by the legacy token scan.

Checks:

```sh
RAPIDTRIAGE_REQUIRE_NATIVE_EVTX=1 python -m unittest tests.test_evtx_engine_diff tests.test_evtx_engine_rows_diff
python scripts/evtx-engine-bench.py --records 500000
```

`tests/test_evtx_engine_diff.py` compares every row field by field (full and triage detail, structure rows, provider-level rows) over a synthetic corpus (`tests/evtx_engine_corpus.py`: multi-chunk logs, slack and inactive chunks, truncated files, every BinXML value type and token, duplicate/invalid Data names, Korean and astral text, decoder errors) and seeded byte-level fuzzing. The benchmark reports decoder-only and full-row records/s per engine (process CPU time) and fails on any row difference. CI job "Rust EVTX engine" runs both on Linux, Windows and macOS.
