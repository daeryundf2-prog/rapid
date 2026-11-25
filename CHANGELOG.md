# Changelog

## Unreleased

### Fixed

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
