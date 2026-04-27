# dashcam-tools + rapidtriage

This repository contains two tool families:

- `dashcam-tools`: dashcam ingest, OCR timestamp detection, and file renaming utilities.
- `rapidtriage`: a lightweight, cross-platform forensic triage toolkit with both CLI and local web UI workflows.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip build
python -m pip install -e '.[web,test]'
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip build
python -m pip install -e ".[web,test]"
```

Windows one-command launcher:

```powershell
.\scripts\windows\start-rapidtriage.ps1
```

macOS/Linux one-command launcher:

```bash
sh scripts/start-rapidtriage.sh
```

See [docs/rapidtriage-windows-quickstart.md](docs/rapidtriage-windows-quickstart.md) for the Windows launcher, diagnostics, and E01 fallback guidance.
See [docs/rapidtriage-macos-linux-quickstart.md](docs/rapidtriage-macos-linux-quickstart.md) for the macOS/Linux launcher and first-run flow.
See [docs/rapidtriage-e01-workflow.md](docs/rapidtriage-e01-workflow.md) for what direct E01/Ex01 input does today and when to mount/export first.
See [docs/rapidtriage-fresh-machine-smoke-test.md](docs/rapidtriage-fresh-machine-smoke-test.md) for the Windows/macOS release usability smoke test.
See [docs/rapidtriage-maestro-wisdom-intake.md](docs/rapidtriage-maestro-wisdom-intake.md) for the Maestro WISDOM-inspired competitive intake and follow-up parser/viewer backlog.
See [docs/rapidtriage-user-convenience-principles.md](docs/rapidtriage-user-convenience-principles.md) for the analyst convenience rules that guide UI and workflow decisions.
See [docs/rapidtriage-community-feedback-intake.md](docs/rapidtriage-community-feedback-intake.md) for public Reddit/Forensic Focus practitioner feedback translated into product requirements.

System dependencies:

- Required for dashcam OCR/video workflows: `ffprobe` from ffmpeg and the `tesseract` binary.
- Optional rapidtriage E01 direct-input workflows: `ewfmount`, `mmls`, and `tsk_recover`; these are primarily Unix/macOS/Linux oriented.
- `rapidtriage` folder-based triage and the local web UI work without those E01 tools.

## Quick Start

Run the local web UI:

```bash
rapidtriage web --host 127.0.0.1 --port 8765
```

Check the local runtime before starting:

```bash
rapidtriage doctor
```

Or use the dedicated entrypoint:

```bash
rapidtriage-web --host 127.0.0.1 --port 8765
```

Then open:

```text
http://127.0.0.1:8765
```

Run the CLI workflow directly:

```bash
rapidtriage run . --mode fraud --output-dir ./rapidtriage-run-fraud --read-only
```

Create and run a synthetic sample case:

```bash
rapidtriage sample --run --overwrite
```

See [docs/rapidtriage-sample-case.md](docs/rapidtriage-sample-case.md) for expected sample outputs and smoke-search examples.

Initialize the experimental SQLite case database:

```bash
rapidtriage case-db ./rapidtriage-case.db --create-case CASE-001 --name "Case 001" --list
```

Import a completed run and search the SQLite case DB:

```bash
rapidtriage case-db ./rapidtriage-case.db --import-run ./rapidtriage-sample/run-output --case-id CASE-001
rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k password --source documents
rapidtriage case-review ./rapidtriage-case.db --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant --verification-status source_opened --include-in-report
rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k password --verification-status source_opened
rapidtriage case-db-report ./rapidtriage-case.db --case-id CASE-001 --output rapidtriage-case-db-report-candidates.json
```

Check which evidence adapter will handle a source path:

```bash
rapidtriage evidence ./case.E01 --json
rapidtriage evidence ./mounted-folder
```

Track performance with a synthetic benchmark:

```bash
rapidtriage benchmark --output-dir ./rapidtriage-benchmark --file-count 1000
```

Build a release validation package before handing a build to analysts:

```bash
rapidtriage validation --output-dir ./rapidtriage-validation --overwrite
```

Register a completed run in the local case catalog:

```bash
rapidtriage case-catalog --add-run ./rapidtriage-sample/run-output --case-id CASE-001 --name "Sample Case" --list
```

Export normalized timeline/model data and a submission bundle:

```bash
rapidtriage timeline-export ./rapidtriage-sample/run-output --output timeline-export.json
rapidtriage normalize ./rapidtriage-sample/run-output --output normalized-case.json
rapidtriage bundle ./rapidtriage-case.json --allowed-root ./rapidtriage-sample/evidence --output-dir ./submission-bundle
rapidtriage plugins --list
```

Run directly from an E01 image when `libewf` and Sleuth Kit tools are installed:

```bash
rapidtriage run ./case.E01 --mode fraud --output-dir ./rapidtriage-run-e01
```

## rapidtriage

`rapidtriage` is designed as an OS-independent core with pluggable artifact collectors. It can be used on macOS, Linux, and Windows against ordinary folders, mounted images, E01-derived exports, or live filesystem roots.

Current structure:

- `rapidtriage/core`: orchestration, manifests, document scanning, file triage, extraction, timelines, reports, cases, and job execution.
- `rapidtriage/artifacts/windows`: Windows-focused artifact providers behind provider interfaces.
- `rapidtriage/artifacts/generic.py`: cross-platform document candidate provider.
- `rapidtriage/api`: FastAPI local API for the web UI.
- `rapidtriage/web/static`: browser UI assets.
- `rapidtriage/schemas/`: JSON Schema contracts for published outputs.
- `docs/rapidtriage-output-schema.md`: output contract summary and sample index.
- `docs/rapidtriage-rule-engine.md`: rule-engine and IOC lookup contract.

CLI help:

```bash
rapidtriage --help
rapidtriage manifest --help
rapidtriage docs --help
rapidtriage files --help
rapidtriage extract --help
rapidtriage artifacts --help
rapidtriage collect-plan --help
rapidtriage collect-export --help
rapidtriage run --help
rapidtriage timeline --help
rapidtriage case --help
rapidtriage web --help
rapidtriage-web --help
```

Common examples:

```bash
rapidtriage manifest . --output rapidtriage-manifest.json
rapidtriage manifest /Volumes/case-mount --input-kind mounted-image --output case-manifest.json
rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json
rapidtriage files . --output rapidtriage-files.json
rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json
rapidtriage files . --name-contains note --path-contains desktop --output desktop-notes.json
rapidtriage collect-plan /Volumes/case-mount --profile intrusion --output rapidtriage-collect-plan.json
rapidtriage collect-export /Volumes/case-mount ./collect-export --profile intrusion --copy
rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf --manifest ./docs-out/rapidtriage-extract-manifest.json
rapidtriage artifacts . --kind browser --output ./rapidtriage-artifacts-browser.json
rapidtriage artifacts . --kind recent-files --output ./rapidtriage-artifacts-recent-files.json
rapidtriage run . --mode seizure --output-dir ./rapidtriage-run-seizure
rapidtriage run . --mode fraud --output-dir ./rapidtriage-run-fraud
rapidtriage run ./case.E01 --mode fraud --output-dir ./rapidtriage-run-e01
rapidtriage run . --mode hacking --output-dir ./rapidtriage-run-hacking
rapidtriage run . --mode recovery --output-dir ./rapidtriage-run-recovery
rapidtriage timeline . --output ./rapidtriage-timeline.json --report ./rapidtriage-timeline-report.md
rapidtriage case ./incident-case.json --source ./rapidtriage-timeline.json --pointer /events/0 --tag suspicious --note "Review this event"
rapidtriage case ./incident-case.json --source ./rapidtriage-files.json --pointer /candidates/0 --bookmark-id file-001 --tag executable
rapidtriage web --host 127.0.0.1 --port 8765
```

## Web UI

The local UI is a browser-based dashboard served by FastAPI. It supports:

- Creating `run` workflows from a folder path, mounted image root, E01-derived folder, direct `.E01` image path, raw/split image, archive image, or qemu-convertible virtual disk when required external tools are present.
- Checking evidence support before a run, including folders, E01/Ex01, AD1/L01/Lx01, AFF/AFF4, DD/RAW/IMG/001, ISO/DMG/WIM, VHD/VHDX/VMDK/VDI/XVA/QCOW, mobile packages, and memory dumps.
- Choosing a processing profile: fast first pass, bounded standard extraction, or uncapped deep processing.
- Previewing KAPE-style collection profiles from the start screen so users can see present/missing Windows/macOS artifact targets before a heavy run.
- Showing a guided first-run workflow, safe read-only default, and remembered local form/search inputs to reduce repeated typing.
- For direct `.E01` input, extracting the image read-only into the run output directory through `ewfmount`, `mmls`, and `tsk_recover`, then running the same triage pipeline on the extracted filesystem.
- For direct DD/RAW/IMG/001 input, recovering files with Sleuth Kit; for ISO/DMG/WIM/SWM, extracting with `7zz`/`7z` or ISO `bsdtar`; for VHD/VHDX/VMDK/VDI/QCOW/QCOW2, converting with `qemu-img` before Sleuth Kit recovery.
- Persisting the local run catalog across server restarts.
- Importing an existing run output directory that contains `rapidtriage-run-summary.json`.
- Viewing run status, summaries, files, docs, artifacts, timeline events, indicator pivots, and generated markdown reports.
- Displaying step-level run status for recovery/retry diagnostics.
- Splitting the case workspace into `Triage`, `Find`, `Review`, and `Deliver` views so large cases are handled by task instead of one overloaded screen.
- Pinning search results, viewer previews, and reviewed evidence into a persistent A/B compare tray for quick back-and-forth inspection.
- Loading large files/docs/artifacts/timeline/indicator outputs in bounded pages instead of rendering entire result sets at once.
- Downloading generated output files directly from the browser.
- Filtering result tables in the browser.
- Previewing source evidence from search results, including text/document snippets, image previews, and safe binary metadata.
- Computing MD5, SHA1, and SHA256 for an opened source file on demand from the viewer.
- Searching either the whole case or only the currently opened evidence file from the viewer.
- Narrowing whole-case search by source, extension, and path fragment before opening results.
- Preparing a run-local SQLite Case DB automatically before DB-backed search so users do not have to manually import JSON outputs first.
- Using keyboard shortcuts for case search, current-file search, workspace switching, and paginated navigation.
- Using keyword presets for common review pivots such as credentials, web activity, financial terms, and intrusion indicators.
- Saving analyst review decisions from the viewer with `Relevant`, `Needs review`, `Not relevant`, tags, notes, and report-candidate flags in `rapidtriage-case.json`.
- Tracking review revisions in `rapidtriage-case.json` and selecting review-board items into a local working set while comparing evidence.
- Reading generated case review boards from the run output directory.
- Generating `rapidtriage-submission-manifest.json` with MD5, SHA1, and SHA256 hashes for report-candidate evidence.
- Drafting `rapidtriage-case-report.md` from case metadata, reviewed evidence, analyst notes, and submission hashes.
- Removing a run from the local web catalog without deleting evidence output files.

API endpoints are served under `/api`, including health, run creation/listing/detail, run import, catalog removal, named outputs, paginated files/docs/artifacts/timeline/indicator views, downloadable output files, source previews, report text, case loading, submission hash manifest generation, case report drafting, and review/bookmark creation.

The web server defaults to `127.0.0.1`. If you bind it to a non-localhost interface, use `--auth-token` unless you intentionally pass `--allow-remote-without-auth`.

By default, the web run catalog is stored in the user state directory:

- Windows: `%LOCALAPPDATA%\rapidtriage\runs.json`
- macOS/Linux: `$XDG_STATE_HOME/rapidtriage/runs.json` or `~/.local/state/rapidtriage/runs.json`

Set `RAPIDTRIAGE_STATE_PATH` to override this location.

## Contracts

Schema and sample references:

- `manifest`: `rapidtriage/schemas/manifest.schema.json` + `docs/samples/rapidtriage-manifest.sample.json`
- `docs`: `rapidtriage/schemas/docs.schema.json` + `docs/samples/rapidtriage-docs.sample.json`
- `files`: `rapidtriage/schemas/files.schema.json` + `docs/samples/rapidtriage-files.sample.json`
- `extract`: `rapidtriage/schemas/extract.schema.json` + `docs/samples/rapidtriage-extract.sample.json`
- `artifacts`: `rapidtriage/schemas/artifacts.schema.json` + `docs/samples/rapidtriage-artifacts.sample.json`
- `run-summary`: `rapidtriage/schemas/run-summary.schema.json` + `docs/samples/rapidtriage-run-summary.sample.json`
- `timeline`: `rapidtriage/schemas/timeline.schema.json`
- `indicators`: `rapidtriage/schemas/indicators.schema.json`
- `compare`: `rapidtriage/schemas/compare.schema.json`
- `carve`: bounded signature carving output written as `rapidtriage-carve.json`
- `case`: `rapidtriage/schemas/case.schema.json`
- `submission-manifest`: `rapidtriage/schemas/submission-manifest.schema.json`
- `rule-engine`: `docs/rapidtriage-rule-engine.md` + `docs/samples/rapidtriage-rules.sample.yaml`

Implemented:

- `docs` searches text/config/log/data files, EML/MBOX email, bounded Outlook MSG/PST/OST strings, HTML/RTF, PDF, Office OpenXML (`docx`, `xlsx`, `pptx`), and OpenDocument (`odt`, `ods`, `odp`) bodies for keywords; it can also write an AXIOM-inspired processed-text inverted index sidecar for faster post-processing keyword pivots.
- `files` performs metadata-only triage over names, paths, extensions, sizes, and mtimes, including document, archive, database, executable/script, email archive, AXIOM-aligned disk/VM/mobile image, memory dump, and vehicle export candidates.
- `collect-plan` previews KAPE-style Windows/macOS collection targets by profile before scanning or copying evidence. It reports present/missing EventLogs, AccountUsage, BrowserHistory, EvidenceOfExecution, Persistence, RemoteAccess, FileSystemTimeline, and CloudAndSync paths without hashing the whole input root.
- `collect-export` creates a profile-based evidence package from `collect-plan` targets. It defaults to a dry-run manifest, copies only with `--copy`, preserves source-relative paths under `OUTPUT_DIR/evidence`, records SHA256/source/destination/size/mtime, and skips broad inventory-only directories to avoid accidental whole-profile exports.
- `vsc-compare` compares a current mounted/exported tree with one or more Volume Shadow Copy snapshot folders, surfacing deleted, added, and modified file candidates with optional SHA256 confirmation. `vsc-extract` copies selected deleted/modified snapshot-side files into an evidence package with source/destination SHA256 values.
- `compare` compares two individual evidence/export files for A/B review, records MD5/SHA1/SHA256, field differences, and a bounded unified text diff when safe.
- `carve` performs capped signature carving for JPEG, PNG, PDF, and ZIP candidates, preserving source path, byte offsets, SHA256, status, and optional extracted bytes under `OUTPUT_DIR/carved`.
- `extract` copies selected `files` or `docs` results into an output directory with overwrite guards, size/count limits, hashes, and manifest/audit output.
- `artifacts` exposes dedicated collectors for `browser`, `recent-files`, `eventlog`, `windows-os-account`, `windows-execution`, `windows-prefetch`, `windows-filesystem`, `windows-system`, `linux-system`, `macos-system`, `android-apk`, `media-image`, `memory-volatility`, and `cloud-export`. Browser artifacts include web usage pivots, source hashes, AI-service visit detections, and review-only AI conversation candidates recovered from browser storage for common tools such as ChatGPT, Claude, Gemini, Perplexity, and Copilot; Linux artifacts include shell history, SSH, auth log, cron, and systemd pivots; macOS artifacts include TCC privacy permissions plus bounded Unified Log, Spotlight, FSEvents, and APFS snapshot-hint pivots; memory artifacts include Volatility imports plus bounded direct dump scans for redacted BitLocker key candidates, suspicious strings, URLs, and IPs.
- `indicators` summarizes URL, domain, IP, and hash indicators from completed run outputs, keeps source pointers, and can apply local `--rules` IOC matches without calling external threat-intelligence APIs.
- `run` orchestrates `manifest`, `docs`, `files`, `extract`, `artifacts`, and `timeline` for `seizure`, `fraud`, `hacking`, and `recovery`; Windows-focused modes automatically include account, event log, execution, filesystem, recent-file, browser, and system-artifact collectors where relevant. `--resume` reuses valid existing stage JSON outputs in the same output directory and reruns missing or invalid stages.
- Direct `.E01` input is supported for `run` when `ewfmount`, `mmls`, and `tsk_recover` are available; `rapidtriage-e01.json` records the extracted filesystem root and selected partition offset.
- `search` searches a completed run across document/log text, file metadata, browser/web/AI-usage artifacts, indicator pivots, timeline rows, and optional OCR over image candidates.
- `timeline` merges `files`, `docs`, and `artifacts` JSON into chronological events and writes JSON plus markdown.
- `case` stores bookmarks from implemented `files`, `docs`, `artifacts`, `timeline`, `indicators`, and `compare` outputs, validates source schemas, and persists stable `reference`, minimal `snapshot`, analyst `review` status, tags, notes, and report-candidate markers.
- `submission-manifest` hashes report-candidate case evidence with MD5, SHA1, and SHA256, preserves review/bookmark context, skips unavailable or out-of-scope paths, and writes an audit sidecar.
- `case-report` writes a Korean/English-friendly Markdown report draft with case metadata, analysis scope, reviewed evidence, IOC/indicator review pivots, A/B compare review pivots, hashes, skipped hash rows, conclusion text, and audit sidecar.
- `web` starts a local FastAPI server with a browser UI for launching runs, importing existing outputs, searching evidence, previewing source files, reviewing hits, organizing case findings, downloading generated files, and reading reports.
- `case-db` initializes the SQLite case database v1 with tables for cases, evidence sources, files, hashes, artifacts, events, indexed documents/FTS, reviews, audit events, report items, jobs, and stable citation ID sequences.
- `case-search` searches imported SQLite case databases across FTS-indexed documents, file records, artifacts, indicator pivots, and timeline events while preserving citation IDs; hits include review-priority guidance and source-reference details, and artifact/indicator hits expose reviewable source paths plus key Windows and macOS metadata for event logs, PowerShell history, MFT/USN rows, browser history, AI-service usage, quarantine events, LaunchAgents, and IOC values.
- `case-review` stores DB-backed review/verification marks, tags, notes, reviewer names, and report-candidate flags for individual search targets.
- `case-db-report` exports DB-backed reviewed report candidates with review citations, target citations, source references, parser/hash context, and analyst review state.
- `evidence` identifies folder, E01/Ex01, raw image, ISO/DMG/WIM/SWM, and virtual-disk source adapters and reports whether required external extraction tooling is available.
- `benchmark` writes JSON and Markdown benchmark results with ingest/search latency, peak memory, output size, and result counts.
- `validation` writes JSON and Markdown release-readiness checks, required command evidence, required documents, known limits, and operator-owned external responsibilities.
- `case-catalog` stores user-facing case metadata, associated run outputs, and portable catalog archives.
- `timeline-export` writes an AXIOM-style normalized timeline with stable event IDs and filters for date, source, event type, and review status.
- `normalize` converts completed run outputs into stable model collections for files, artifacts, events, and indexed documents.
- `bundle` creates a submission folder and zip with report, selected evidence list, hash manifest, audit JSON, and bundle integrity hashes.
- `plugins` lists built-in plugin contracts and validates external `plugin.json` manifests for parsers, evidence adapters, viewers, and report exporters.
- `report` rendering is assembled from a normalized run-report context built from run summary, indicators, artifacts, timeline, and extract outputs.
- `rules` and IOC lookup are implemented additively; matching metadata is appended without breaking existing output shapes.

Experimental:

- `report` keeps an optional compare slot in markdown/context so run-level compare findings can be attached by future workflows.

Planned:

- any future case source beyond `files`, `docs`, `artifacts`, `timeline`, `indicators`, and `compare`

## Integrity

Every top-level `manifest`, `docs`, `files`, `collect-plan`, `collect-export`, `extract`, `artifacts`, `timeline`, `case`, and `run` execution writes audit data. Audit sidecars record command options, input file hashes where applicable, and generated output hashes. `collect-plan` intentionally skips whole-root inventory hashing so large evidence planning stays fast; run `manifest` when you need a full root fingerprint.

Examples:

- `rapidtriage-files.json` -> `rapidtriage-files.audit.json`
- `rapidtriage-extract-manifest.json` -> `rapidtriage-extract-manifest.audit.json`
- `rapidtriage-case.json` -> `rapidtriage-case.audit.json`
- `run` writes `rapidtriage-run-audit.json` in the output directory.

## Dashcam Tools

Installed commands:

```bash
dashcam-report
dashcam-gui
dashcam-rename
dashcam-ingest
```

`dashcam-gui` opens the desktop GUI for source/destination selection and rename options.

## Verification

```bash
python -m unittest discover -s tests
python -m build --wheel --sdist --no-isolation
```
