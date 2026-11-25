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
`rapidtriage/api/app/analysis_kinds.py`) through `rapidtriage/core/ntfs_native.py`
to the extension. An unset or other value, a missing extension (warning logged
once) or an exception raised by the extension falls back to the Python parser.
The variable is read on every call.

The Windows filesystem artifact provider (`collect_native_ntfs_artifacts`) keeps
calling the Python parser directly: its review profiles read fields the port
leaves out (below).

## Build

```bash
python scripts/build-rapid-ntfs.py        # cargo build -p rapid-ntfs --features python --release
```

The cdylib is staged as `rapidtriage/native/rapid_ntfs_native.{so,pyd}`
(gitignored). Without `--features python` the crate has no dependencies.

## Fields

Every key of the Python record dicts is emitted with the same value and type,
except:

- left out (Python only): `attribute_list_resolution` and the four
  `validation_checks.attribute_list_*` keys added by
  `enrich_mft_records_with_attribute_list_resolution`; the SHA-256 fields
  (`usa_fixup_application.record_sha256_before/after`, resident `$DATA`
  `sha256` / `resident_data_hashes`, `runlist_decode.preview_sha256`); the USN
  scan's `cursor_window_profile`. None is read by the NTFS-meta analysis.
- added (Rust only): `timestamps_filetime` next to every `$STANDARD_INFORMATION`
  and `$FILE_NAME` `timestamps` dict, holding the raw 100 ns FILETIME ticks.
  The ISO text stays microsecond text exactly as Python prints it; USN records
  already carry `timestamp_filetime`.

## Verification

- `cargo test -p rapid-ntfs` (unit tests) and `cargo clippy -p rapid-ntfs --all-targets --features python -- -D warnings`.
- `tests/test_rapid_ntfs_parity.py` runs both parsers on synthetic blobs from
  `tests/ntfs_synthetic.py` (corner cases, 4 KiB and stride-less volumes,
  fuzzed copies, USN windows) and asserts zero differences on every shared
  field, the Rust ticks against the generator, identical post-#33 USN-to-MFT
  correlation on Rust and Python records, and identical NTFS-meta rows under
  both engines. It skips without the extension unless
  `RAPIDTRIAGE_REQUIRE_RAPID_NTFS=1` (set in CI's Rust job).
- `python scripts/bench-rapid-ntfs.py` generates a 500,000-record $MFT and a
  500,000-record journal in a temporary directory and prints records/s and
  speedup per engine.
