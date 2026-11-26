# Changelog

## Unreleased

### Fixed

- On Windows an analysis could vanish from the analysis list for one read. The
  state reader treated the sharing error raised while another thread
  `os.replace`d `analysis.json` (a heartbeat or progress write) as "no state".
  `GET …/search/index` then reported the previous build as `ready` instead of
  `build-failed-swap`. State reads now retry that error the way state writes
  already do (`tests/test_rapidtriage_analyses.py::StateReadRetryTests`).
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
- Native E01 extraction names files and directories with a Win32 device name
  (`CON`, `nul.txt`, `COM1.log`, ...) with a leading `_` on Windows, where the
  plain name opened the device instead of a file in the extraction folder.
  **Output change (Windows only):** such entries are now recovered as
  `_CON`, `_nul.txt`, ... Other platforms keep the names.
- The recovered-root manifest of E01/disk-image extractions lists files depth
  first with names sorted instead of in the output drive's listing order, so
  its first 5,000 entries (and the inventory fingerprint) no longer depend on
  the order files were created in on drives that list in creation order
  (exFAT, tmpfs). **Output change:** manifest entry order.

### Added

- The `macos-unified-log` collector extracts log, activity, signpost and trace
  events from stored tracev3 chunksets in offline evidence. Calibrated events
  appear on the timeline with source offsets. Compressed blocks, damaged
  records and missing format strings carry explicit coverage information.
  [Formats, limits and synthetic example](docs/rapidtriage-macos-unified-log.md)

- The `macos-knowledgec` collector reads system and per-user KnowledgeC
  activity streams, including committed WAL rows. It retains raw time values
  alongside UTC timestamps and flags unknown streams.
- The `linux-journald` collector reads persistent systemd journals in regular
  and compact layouts. Entries carry source offsets and raw clock values.
  Field DATA hashes are recomputed (Jenkins or keyed SipHash-2-4) and
  mismatches are flagged. Undecodable fields and damaged structures carry
  diagnostics. Both collectors are selectable in run plans and contribute
  events to the timeline.
- Explorer taskbar records from NTUSER hives and `.reg` exports, on both
  registry engines: `execution-feature-usage` rows now carry the user, the
  value name and the raw key LastWrite FILETIME, and report a count only for an
  integer value within the DWORD range; `registry-taskband-pin` rows resolve
  Favorites item ID lists and FavoritesResolve Shell Links;
  `registry-taskband-summary` discloses each value's walk (undecoded frames,
  why it stopped, caps).
  **Output change:** a registry row whose own timestamp restates its key-scoped
  LastWrite now joins the single per-key timeline event instead of adding one
  event per value (affects `registry-known-dll`, `registry-network-share`,
  registry `execution-pca`, `execution-feature-usage`, `registry-taskband-pin`,
  `ssh-known-host`, `desktop-wallpaper` and enabled `startup-item` rows;
  artifact rows are unchanged). Every key-scoped timeline event now lists the
  rows it stands for in `details.key_rows` (artifact type, output, row index,
  value; up to 1,000, then `key_rows_truncated`) with the full
  `details.key_row_count`.
- Linux login accounting in `linux-system`: utmp, wtmp, btmp (live and
  uncompressed rotations) and sparse lastlog in the 384/292-byte glibc x86
  layouts, with per-file `linux-login-accounting-summary` rows for damage,
  truncation, caps, unknown layouts and compressed rotations. See
  `docs/rapidtriage-parser-coverage.md`.
- Opt-in Rust EVTX chunk decoder (`rapidcore_native.EvtxChunkDecoder`),
  selected with `RAPIDTRIAGE_EVTX_ENGINE=rust` or
  `--eventlog-evtx-engine rust`. The default stays Python. Rows are identical to
  the Python decoder's (`tests/test_evtx_engine_diff.py`). See
  `docs/architecture/rust-bootstrap.md`.
- Opt-in Rust engine for the native E01 -> NTFS file extraction
  (`RAPIDTRIAGE_E01_EXTRACT_ENGINE=rust`, built with
  `python scripts/build-e01-extract-native.py`): its own EWF v1 reader and
  parallel copies (`RAPIDTRIAGE_E01_EXTRACT_THREADS`), with the tree and stats
  of the Python engine (`tests/test_e01_extract_rust_parity.py`). It hands the
  image to the Python engine, and records why, when it fails, when the output
  drive nears its free-space reserve, when corrupt metadata asks for a read
  over 256 MiB, and on Windows without long-path support when an output path
  reaches 248 characters. Parallel copies whose targets meet on the output
  drive (names equal after sanitizing, case or Unicode normalization) are redone
  sequentially. Segment sets the Rust EWF reader does not take (Ex01, damaged
  chunk tables) and chunks that fail their checksum are read through pyewf.
- Indicator extraction can use a Rust worker for URLs, IPv4 addresses and hashes. Set `RAPIDTRIAGE_RUST_INDICATORS=1` to enable it. The worker reads JSONL artifact record streams itself, applying the Python field policy, and returns only scalar fields with candidates. Rows and Unicode text outside its exact subset go to Python. Other outputs send ASCII scalar fields in batches. The indicator output and run disclosures record worker use and fallback; after a worker failure Python resumes from the last applied checkpoint. [Build and validation instructions](docs/architecture/rust-indicators.md)
- Opt-in Rust $MFT / $UsnJrnl:$J parser (`engines/rust/crates/rapid-ntfs`,
  module `rapid_ntfs_native`), selected with `RAPIDTRIAGE_NTFS_ENGINE=rust` for
  the NTFS-meta analysis. The default stays Python. Rows are identical to the
  Python parser's (`tests/test_rapid_ntfs_parity.py`); a missing or stale
  build, a Rust error, or a consumer that reads Python-only fields (hashes,
  attribute-list resolution, USN cursor window) falls back to Python and
  records why in `native_mft_engine*` / `native_usn_engine*` run metadata.
  Build with `python scripts/build-rapid-ntfs.py`. See
  `docs/architecture/rapid-ntfs.md`.
- With the Rust EVTX engine selected, event and detection rows are walked for
  BitLocker recovery passwords in Rust
  (`rapidcore_native.redact_recovery_passwords_in`). Any string that could hold
  one still goes through the Python `redact_recovery_passwords`, so the output
  is identical (`tests/test_evtx_engine_rows_diff.py`). About 10× faster per
  full-detail row: 580–670 µs down to 50–65 µs.
- With the Rust EVTX engine selected, the eventlog stage folds and strips
  per-type/per-file constant blocks (`artifact_type_profiles`) in Rust
  (`rapidcore_native.profile_observe_details`, `profile_common`,
  `profile_strip_level`), and readers of that eventlog output expand rows with
  `profile_merge`. Equality stays type-strict (`True` ≠ `1` ≠ `1.0`, `-0.0` ≠
  `0.0`), key order and object identity are kept, and anything other than plain
  JSON values goes to the Python code, so profiles and JSONL bytes are identical
  (`tests/test_evtx_engine_rows_diff.py`). On 50,000 events, compaction CPU
  went from 6.4 s to 1.6 s.
- With the Rust EVTX engine selected, the eventlog stage writes its JSONL rows
  with `rapidcore_native.dump_json_row`: the text of
  `json.dumps(ensure_ascii=False, separators=(",", ":"), default=json_default)`,
  including Python float `repr`, `NaN`/`Infinity`, big ints and `default=`
  conversions. Subclasses of str/int/float/list/tuple/dict, non-str keys, lone
  surrogates, deep nesting and errors go to `json.dumps`
  (`tests/test_evtx_engine_rows_diff.py`). About 2.8× faster per row.
- With the Rust EVTX engine selected, triage-detail event rows are projected in
  Rust (`rapidcore_native.EventlogTriageProjector`, the port of
  `triage_eventlog_details`): same keys, order, values and types; values it
  cannot reproduce exactly (subclasses, custom objects, lone surrogates in
  bounded text) go to the Python function
  (`tests/test_evtx_engine_rows_diff.py`). About 2× faster per row (18–23 µs
  down to 9–10 µs).
- Five evidence collectors for AI coding agents: `claude-code`, `codex-cli`,
  `gemini-cli`, `editor-chat` (Cursor and VS Code-family chat storage) and
  `agent-mcp` (MCP server configuration). Dated messages, tool calls and tool
  results appear in the timeline. Secrets are redacted before output, SQLite
  is read from a verified private snapshot, and rows without a recorded
  version carry `version-unknown`. See `docs/ai-agent-artifacts.md`.
