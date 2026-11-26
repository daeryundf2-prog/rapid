# rapid-ntfs: opt-in Rust $MFT / $UsnJrnl parser

`engines/rust/crates/rapid-ntfs` is a Rust port of the two native NTFS metadata
parsers in `rapidtriage/artifacts/windows/filesystem.py`:

| Python (reference) | Rust | PyO3 (`rapid_ntfs_native`) |
|---|---|---|
| `parse_mft_record_headers(blob)` | `mft::parse_mft_record_headers` | `parse_mft_record_headers(blob)` |
| `parse_usn_record_scan(blob, *, record_limit, start_offset, max_scan_bytes)` | `usn::parse_usn_record_scan` | same signature |

The parity reference is `main` after PR #33 (D22): a clipped record with no
intact neighbour keeps its plausible stride, and `record_number_trusted`
requires the NTFS 3.1 header to name the same slot.

## Switch

The Python parser stays the default. Set

```bash
RAPIDTRIAGE_NTFS_ENGINE=rust
```

to route the NTFS-meta analysis (`parse_mft_file` / `parse_usn_file` in
`rapidtriage/api/app/analysis_kinds.py`) to the extension. Each step resolves
the engine once per input with `rapidtriage.core.ntfs_native.resolve_ntfs_engine`.
The Python parser is used, and the reason recorded, when:

- the value is not `python` or `rust`;
- the consumer reads a field the Rust records leave out (below). The Windows
  filesystem artifact collector (`collect_native_ntfs_artifacts`) is such a
  consumer: its review profiles and record samples read the hashes,
  attribute-list resolution and USN cursor window, so it always parses with
  Python;
- the extension is not built, or reports a version other than
  `ntfs_native.RAPID_NTFS_VERSION` (stale build; bump the crate version and the
  constant together whenever either parser changes);
- the extension raises (a Rust panic is caught and raised as `RuntimeError`).
  The failing call and every later call of the same input use Python.

### Run metadata

With the default engine nothing is added. Otherwise the NTFS-meta summary (and
the collector's `mft-file` / `usn-journal` inventory records) carry, per
artifact (`mft`, `usn`):

| key | value |
|---|---|
| `native_<artifact>_engine` | engine that produced the rows (`rust`, or `python` after a fallback) |
| `native_<artifact>_engine_requested` | the `RAPIDTRIAGE_NTFS_ENGINE` value |
| `native_<artifact>_engine_version` | rapid-ntfs version, when the extension was used |
| `native_<artifact>_engine_python_fallback_count` | parser calls Python served after a Rust error |
| `native_<artifact>_engine_notice_ko` | why Python was used |

## Build

```bash
python scripts/build-rapid-ntfs.py        # cargo build -p rapid-ntfs --features python --release
```

The build targets the interpreter running the script (`PYO3_PYTHON`) and stages
the cdylib as `rapidtriage/native/rapid_ntfs_native<EXT_SUFFIX>` (gitignored),
for example `.cpython-312-darwin.so` or `.cp312-win_amd64.pyd`, so another
Python version never imports it. `build.rs` adds the macOS
`-undefined dynamic_lookup` link arguments (`pyo3-build-config`). Without
`--features python` the crate has no dependencies.

## Fields

Every key of the Python record dicts is emitted with the same value, type and
key order, except:

- left out (Python only; group names of `ntfs_native.PYTHON_ONLY_FIELDS`):
  - `attribute_list_resolution`: `attribute_list_resolution` and the four
    `validation_checks.attribute_list_*` keys added by
    `enrich_mft_records_with_attribute_list_resolution`;
  - `hashes`: `usa_fixup_application.record_sha256_before/after`, resident
    `$DATA` `sha256` / `resident_data_hashes`, `runlist_decode.preview_sha256`;
  - `cursor_window_profile`: the USN scan's `cursor_window_profile`.
- added (Rust only): `timestamps_filetime` next to every `$STANDARD_INFORMATION`
  and `$FILE_NAME` `timestamps` dict, holding the raw 100 ns FILETIME ticks.
  The ISO text stays microsecond text exactly as Python prints it; USN records
  already carry `timestamp_filetime`.

The NTFS-meta analysis reads none of these keys; `tests/test_rapid_ntfs_parity.py`
records every key it reads and fails if one is added, and fails if another
module starts using `resolve_ntfs_engine` without the same audit.

## Verification

- `cargo test -p rapid-ntfs`: unit tests and
  `engines/rust/crates/rapid-ntfs/tests/malformed_input.rs`
  (thousands of seeded corrupted $MFT records and USN journals in a debug build,
  so integer overflow also fails; no panic, every output cap holds).
- `cargo clippy -p rapid-ntfs --all-targets --features python -- -D warnings`.
- `tests/test_rapid_ntfs_parity.py` runs both parsers on synthetic blobs from
  `tests/ntfs_synthetic.py` and asserts zero differences on every shared field,
  including key order and types: corner cases, 4 KiB and stride-less volumes,
  byte-fuzzed copies, seeded adversarial records (hostile headers,
  update-sequence arrays, torn sectors, attribute chains, runlists, ADS names,
  `$SI`/`$FN` times, slack, USN v2/v3/v4 and windows), the output caps (5,000
  records, 64 runs, 250 strings, 10 paths, 64 extents, 65,536-byte USN record),
  5,000 random FILETIMEs over the whole range, the Rust ticks against the
  generator, identical post-#33 USN-to-MFT correlation and identical NTFS-meta
  rows under both engines. The parity class skips without the extension unless
  `RAPIDTRIAGE_REQUIRE_RAPID_NTFS=1` (set in CI's Rust job); the switch,
  provenance and field-read audit tests always run.
- `python scripts/bench-rapid-ntfs.py` generates a 500,000-record $MFT and a
  500,000-record journal in a temporary directory and prints records/s and
  speedup per engine.
