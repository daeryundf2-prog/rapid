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

System dependencies:

- Required for dashcam OCR/video workflows: `ffprobe` from ffmpeg and the `tesseract` binary.
- Optional rapidtriage E01 direct-input workflows: `ewfmount`, `mmls`, and `tsk_recover`; these are primarily Unix/macOS/Linux oriented.
- `rapidtriage` folder-based triage and the local web UI work without those E01 tools.

## Quick Start

Run the local web UI:

```bash
rapidtriage web --host 127.0.0.1 --port 8765
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

- Creating `run` workflows from a folder path, mounted image root, E01-derived folder, or direct `.E01` image path.
- Showing a guided first-run workflow, safe read-only default, and remembered local form/search inputs to reduce repeated typing.
- For direct `.E01` input, extracting the image read-only into the run output directory through `ewfmount`, `mmls`, and `tsk_recover`, then running the same triage pipeline on the extracted filesystem.
- Persisting the local run catalog across server restarts.
- Importing an existing run output directory that contains `rapidtriage-run-summary.json`.
- Viewing run status, summaries, files, docs, artifacts, timeline events, and generated markdown reports.
- Splitting the case workspace into `Triage`, `Find`, `Review`, and `Deliver` views so large cases are handled by task instead of one overloaded screen.
- Pinning search results, viewer previews, and reviewed evidence into a persistent A/B compare tray for quick back-and-forth inspection.
- Loading large files/docs/artifacts/timeline outputs in bounded pages instead of rendering entire result sets at once.
- Downloading generated output files directly from the browser.
- Filtering result tables in the browser.
- Previewing source evidence from search results, including text/document snippets, image previews, and safe binary metadata.
- Searching either the whole case or only the currently opened evidence file from the viewer.
- Using keyboard shortcuts for case search, current-file search, workspace switching, and paginated navigation.
- Using keyword presets for common review pivots such as credentials, web activity, financial terms, and intrusion indicators.
- Saving analyst review decisions from the viewer with `Relevant`, `Needs review`, `Not relevant`, tags, notes, and report-candidate flags in `rapidtriage-case.json`.
- Tracking review revisions in `rapidtriage-case.json` and selecting review-board items into a local working set while comparing evidence.
- Reading generated case review boards from the run output directory.
- Generating `rapidtriage-submission-manifest.json` with MD5, SHA1, and SHA256 hashes for report-candidate evidence.
- Drafting `rapidtriage-case-report.md` from case metadata, reviewed evidence, analyst notes, and submission hashes.
- Removing a run from the local web catalog without deleting evidence output files.

API endpoints are served under `/api`, including health, run creation/listing/detail, run import, catalog removal, named outputs, paginated files/docs/artifacts/timeline views, downloadable output files, source previews, report text, case loading, submission hash manifest generation, case report drafting, and review/bookmark creation.

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
- `case`: `rapidtriage/schemas/case.schema.json`
- `submission-manifest`: `rapidtriage/schemas/submission-manifest.schema.json`
- `rule-engine`: `docs/rapidtriage-rule-engine.md` + `docs/samples/rapidtriage-rules.sample.yaml`

Implemented:

- `docs` searches text/config/log/data files, HTML/RTF, PDF, Office OpenXML (`docx`, `xlsx`, `pptx`), and OpenDocument (`odt`, `ods`, `odp`) bodies for keywords; it can also write an AXIOM-inspired processed-text inverted index sidecar for faster post-processing keyword pivots.
- `files` performs metadata-only triage over names, paths, extensions, sizes, and mtimes, including document, archive, database, executable/script, email archive, AXIOM-aligned disk/VM/mobile image, memory dump, and vehicle export candidates.
- `extract` copies selected `files` or `docs` results into an output directory with overwrite guards, size/count limits, hashes, and manifest/audit output.
- `artifacts` exposes dedicated collectors for `browser` and `recent-files`.
- `run` orchestrates `manifest`, `docs`, `files`, `extract`, `artifacts`, and `timeline` for `seizure`, `fraud`, `hacking`, and `recovery`.
- Direct `.E01` input is supported for `run` when `ewfmount`, `mmls`, and `tsk_recover` are available; `rapidtriage-e01.json` records the extracted filesystem root and selected partition offset.
- `search` searches a completed run across document/log text, file metadata, browser/web artifacts, timeline rows, and optional OCR over image candidates.
- `timeline` merges `files`, `docs`, and `artifacts` JSON into chronological events and writes JSON plus markdown.
- `case` stores bookmarks only from implemented `files`, `docs`, `artifacts`, and `timeline` outputs, validates source schemas, and persists stable `reference`, minimal `snapshot`, analyst `review` status, tags, notes, and report-candidate markers.
- `submission-manifest` hashes report-candidate case evidence with MD5, SHA1, and SHA256, preserves review/bookmark context, skips unavailable or out-of-scope paths, and writes an audit sidecar.
- `case-report` writes a Korean/English-friendly Markdown report draft with case metadata, analysis scope, reviewed evidence, hashes, skipped hash rows, conclusion text, and audit sidecar.
- `web` starts a local FastAPI server with a browser UI for launching runs, importing existing outputs, searching evidence, previewing source files, reviewing hits, organizing case findings, downloading generated files, and reading reports.
- `report` rendering is assembled from a normalized run-report context built from run summary, artifacts, timeline, and extract outputs.
- `rules` and IOC lookup are implemented additively; matching metadata is appended without breaking existing output shapes.

Experimental:

- `compare` is not a current producer CLI. `case` rejects `compare` JSON sources, and `run`/report output only reserve a placeholder section for future compare findings.
- `report` keeps an optional compare slot in markdown/context so a future compare producer can attach without reworking the template.

Planned:

- a dedicated `compare` producer/CLI with JSON schema and end-to-end case/report integration
- any future case source beyond `files`, `docs`, `artifacts`, and `timeline`

## Integrity

Every top-level `manifest`, `docs`, `files`, `extract`, `artifacts`, `timeline`, `case`, and `run` execution writes audit data. Audit sidecars record input fingerprints, command options, input file hashes, and generated output hashes.

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
