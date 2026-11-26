# Changelog

## Unreleased

### Fixed

- One EVTX record holding a character reference to a lone UTF-16 surrogate
  (`&#xD800;`, found in damaged logs) or one JSON export row with a `"\ud800"`
  escape made the whole streamed eventlog collection fail (`failed-isolated`,
  no rows), because UTF-8 output cannot hold a surrogate. The reference is now
  kept as its text `&#xd800;` (as invalid character references already were),
  and the JSON escape as its text `\ud800`. The row discloses this with
  `evtx_lone_surrogate_references` / `export_lone_surrogate_escapes` and the
  caution labels `lone-surrogate-character-reference` /
  `lone-surrogate-json-escape`. No text is dropped
  (`tests/test_eventlog_lone_surrogates.py`).
- EVTX structural scanners read the chunk free-space offset from byte 44, which
  holds the last-event-record offset, instead of byte 48 (chunk header layout:
  libyal libevtx "Windows XML Event Log (EVTX) format", section "Chunk header").
  As a result the last live record of every chunk was labelled slack. Affected:
  the Python scanner in `rapidtriage.core.native_accel`,
  `rapidcore::evtx::scan_evtx` / `rapidcore_native.scan_evtx`, and
  `rapid-worker evtx-scan` / `parse --kind evtx-records`. All of them now read
  the last record offset from byte 44 and free space from byte 48, and fall
  back to byte 44 when byte 48 is zero, as the BinXML decoder already did.
  **Output change:** these scans now report more `allocated` /
  `allocated-or-live-record` records and fewer slack or recovery candidates.
  On the 500,000-record profiling log the count goes from 497,500 allocated +
  2,525 slack to 500,000 + 25. The BinXML event collector
  (`collect_native_evtx_events`) read byte 48 already and its rows are
  unchanged.

### Added

- Opt-in Rust EVTX chunk decoder (`rapidcore_native.EvtxChunkDecoder`),
  selected with `RAPIDTRIAGE_EVTX_ENGINE=rust` or
  `--eventlog-evtx-engine rust`. The default stays Python. Rows are identical to
  the Python decoder's (`tests/test_evtx_engine_diff.py`). See
  `docs/architecture/rust-bootstrap.md`.
- Indicator extraction can use a Rust worker for URLs, IPv4 addresses and hashes. Set `RAPIDTRIAGE_RUST_INDICATORS=1` to enable it. The worker reads JSONL artifact record streams itself, applying the Python field policy, and returns only scalar fields with candidates. Rows and Unicode text outside its exact subset go to Python. Other outputs send ASCII scalar fields in batches. The indicator output and run disclosures record worker use and fallback; after a worker failure Python resumes from the last applied checkpoint. [Build and validation instructions](docs/architecture/rust-indicators.md)
