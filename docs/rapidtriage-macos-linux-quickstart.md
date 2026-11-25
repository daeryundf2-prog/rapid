# RapidTriage macOS/Linux Quick Start

This guide is for running the local RapidTriage web UI from a source checkout on macOS or Linux.

## Requirements

- Python 3.10 or newer.
- Git, if cloning from GitHub.
- Internet access for first-time Python package installation.

Optional tools:

- Tesseract OCR enables image OCR.
- `ewfmount`, `mmls`, and `tsk_recover` enable direct E01/Ex01 extraction when installed and compatible with your platform.

## One-Command Start

From the repository root:

```bash
sh scripts/start-rapidtriage.sh
```

The launcher will:

1. Create `.venv` if it does not exist.
2. Install RapidTriage with web dependencies.
3. Run `rapidtriage doctor`.
4. Open `http://127.0.0.1:8765` when possible.
5. Start the local FastAPI web server.

## Useful Options

Run diagnostics only:

```bash
sh scripts/start-rapidtriage.sh --doctor-only
```

Use another port:

```bash
sh scripts/start-rapidtriage.sh --port 8877
```

Recreate the virtual environment:

```bash
sh scripts/start-rapidtriage.sh --reinstall
```

Start without opening a browser:

```bash
sh scripts/start-rapidtriage.sh --no-browser
```

## Recommended First Workflow

1. Start the web UI.
2. Click `Check runtime`.
3. Click `Run sample case`.
4. Practice keyword search, source preview, review marking, hash manifest, and report draft.
5. Use `Check evidence support` on real evidence before running it.
6. Use `Fast first pass` for large cases before any deep extraction.

## KnowledgeC and journald

Point either collector at the root of a mounted evidence volume or a directory
export that preserves its paths. Write the results outside the evidence root.

```bash
python -m rapidtriage artifacts ./mac-export --kind macos-knowledgec --output ./knowledgec.json
python -m rapidtriage artifacts ./linux-export --kind linux-journald --output ./journald.json
```

**macOS activity.** The collector looks for
`private/var/db/CoreDuet/Knowledge/knowledgeC.db` and
`Users/<user>/Library/Application Support/Knowledge/knowledgeC.db`.
Keep the database and its acquired SQLite sidecars together. A committed
activity may exist only in the WAL. The collector uses a private read-only
snapshot and cites the source table and row. [SQLite WAL format](https://www.sqlite.org/wal.html)

App focus and usage, lock and backlight state, Safari history, web usage,
notifications, intents and battery percentage retain their stream names.
Unknown streams carry a flag and their stored values. Read the stream and
source device together when interpreting synced activity. Raw start and end
values are seconds from 2001-01-01 00:00:00 UTC. [Core Foundation absolute time](https://developer.apple.com/documentation/corefoundation/cfabsolutetime)

**Linux system journal.** The collector follows the global entry-array chain
in `var/log/journal/` files ending in `.journal` or `.journal~`. It reads
regular and compact layouts through object offsets in both hash modes.
Real time is UTC microseconds since the Unix epoch. Monotonic time is
meaningful with its boot ID. The entry and its field objects have separate
offsets, so a damaged or compressed field can be located even if its value
is unavailable. Online state is recorded. XZ uses the standard library.
LZ4 and ZSTD fields carry a `compressed-unsupported` limitation.
[Journal File Format](https://systemd.io/JOURNAL_FILE_FORMAT/)

| Collector | Limits and diagnostics |
| --- | --- |
| KnowledgeC | Per database, up to 256 MiB across the database and sidecars, 5,000 events, 16 MiB of serialized event details, 32 value columns and 256 metadata columns. Each value retains up to 4,096 bytes. Clipped values name the affected column. |
| journald | Per collection, up to 64 files, 5,000 indexed entry slots, 65,536 field references and 64 MiB of reads plus inflated data. Each file may use up to 4,096 entry arrays. Each entry may reference up to 256 fields, each limited to 1 MiB stored or decoded. The XZ decoder has a 64 MiB memory limit. |

KnowledgeC binary values are hex-encoded. Journal fields retain their stored
names, repeated fields become lists, and non-UTF-8 values use tagged base64.
Journal coverage follows the global index. Unlinked records, volatile journals
under `run/log/journal`, and cryptographic seal verification are outside its
scope. Fixture validation uses generated inputs for both formats.

## Release Smoke Test

Before handing a macOS/Linux build to another analyst, run the automated smoke test:

```bash
sh scripts/smoke-test-rapidtriage.sh
```

The smoke test installs the package, runs `doctor`, creates and searches the sample case, runs a small benchmark, builds the validation package, checks evidence-support guidance, confirms the web UI returns HTTP 200, and writes `smoke-summary.json` plus `smoke-summary.md`. Outputs are written to:

```text
rapidtriage-macos-linux-smoke
```

If another process is using the default smoke-test port, run:

```bash
sh scripts/smoke-test-rapidtriage.sh --port 8899
```

## Evidence Input Guidance

Mounted folders and exported evidence folders are the safest input.

If you have an E01/Ex01:

```bash
rapidtriage evidence ./case.E01 --json
```

Review the JSON fields before running extraction: `tool_preflight` shows libewf/Sleuth Kit availability and versions, `source_integrity` records bounded source hash metadata, and `fallback_guidance` explains the read-only mount/export path if direct tools are missing.

If direct E01 tools are missing or fail, mount/export the image using your trusted forensic workflow and point RapidTriage at the resulting folder:

```bash
rapidtriage run ./mounted-case-folder --mode fraud --read-only
```

For AD1, AFF/AFF4, VHD/VHDX, VMDK, ISO, DMG, XVA, QCOW, mobile extraction packages, and memory dumps, RapidTriage currently provides preflight detection and guidance. Direct parsing/mounting is not yet the default workflow.

For raw/split images and qemu-convertible virtual disks, direct runs record split-part discovery, partition offsets, qemu-img/Sleuth Kit command history, hashes where bounded, and warnings in `rapidtriage-disk-image.json` or `rapidtriage-virtual-disk.json`. AD1/L01/Lx01/AFF/AFF4/AFF4-L and XVA remain export-first workflows; preserve original container hashes and vendor/export logs with the case.
