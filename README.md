# dashcam-tools (packaged)

Two CLIs:
- : rename files using on-screen timestamp (OCR) with fallbacks
- : ingest from folders or E01 images, then run renamer

## Install (local dev)
Requirement already satisfied: pip in ./.venv/lib/python3.9/site-packages (21.2.4)
Collecting pip
  Using cached pip-26.0.1-py3-none-any.whl (1.8 MB)
Collecting build
  Downloading build-1.4.0-py3-none-any.whl (24 kB)
Collecting packaging>=24.0
  Downloading packaging-26.0-py3-none-any.whl (74 kB)
Collecting tomli>=1.1.0
  Downloading tomli-2.4.0-py3-none-any.whl (14 kB)
Collecting pyproject_hooks
  Downloading pyproject_hooks-1.2.0-py3-none-any.whl (10 kB)
Collecting importlib-metadata>=4.6
  Downloading importlib_metadata-8.7.1-py3-none-any.whl (27 kB)
Collecting zipp>=3.20
  Downloading zipp-3.23.0-py3-none-any.whl (10 kB)
Installing collected packages: zipp, tomli, pyproject-hooks, packaging, importlib-metadata, pip, build
  Attempting uninstall: pip
    Found existing installation: pip 21.2.4
    Uninstalling pip-21.2.4:
      Successfully uninstalled pip-21.2.4
Successfully installed build-1.4.0 importlib-metadata-8.7.1 packaging-26.0 pip-26.0.1 pyproject-hooks-1.2.0 tomli-2.4.0 zipp-3.23.0
Obtaining file:///Users/shinyoohag/Documents/untitled%20folder
  Installing build dependencies: started
  Installing build dependencies: finished with status 'done'
  Checking if build backend supports build_editable: started
  Checking if build backend supports build_editable: finished with status 'done'
  Getting requirements to build editable: started
  Getting requirements to build editable: finished with status 'done'
  Installing backend dependencies: started
  Installing backend dependencies: finished with status 'done'
  Preparing editable metadata (pyproject.toml): started
  Preparing editable metadata (pyproject.toml): finished with status 'done'
Collecting numpy>=1.23 (from dashcam-tools==0.1.0)
  Using cached numpy-2.0.2-cp39-cp39-macosx_14_0_arm64.whl.metadata (60 kB)
Collecting opencv-python>=4.7 (from dashcam-tools==0.1.0)
  Downloading opencv_python-4.13.0.92-cp37-abi3-macosx_13_0_arm64.whl.metadata (19 kB)
Collecting pytesseract>=0.3.10 (from dashcam-tools==0.1.0)
  Downloading pytesseract-0.3.13-py3-none-any.whl.metadata (11 kB)
Requirement already satisfied: packaging>=21.3 in ./.venv/lib/python3.9/site-packages (from pytesseract>=0.3.10->dashcam-tools==0.1.0) (26.0)
Collecting Pillow>=8.0.0 (from pytesseract>=0.3.10->dashcam-tools==0.1.0)
  Using cached pillow-11.3.0-cp39-cp39-macosx_11_0_arm64.whl.metadata (9.0 kB)
Using cached numpy-2.0.2-cp39-cp39-macosx_14_0_arm64.whl (5.3 MB)
Downloading opencv_python-4.13.0.92-cp37-abi3-macosx_13_0_arm64.whl (46.2 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 46.2/46.2 MB 45.7 MB/s  0:00:01
Downloading pytesseract-0.3.13-py3-none-any.whl (14 kB)
Using cached pillow-11.3.0-cp39-cp39-macosx_11_0_arm64.whl (4.7 MB)
Building wheels for collected packages: dashcam-tools
  Building editable for dashcam-tools (pyproject.toml): started
  Building editable for dashcam-tools (pyproject.toml): finished with status 'done'
  Created wheel for dashcam-tools: filename=dashcam_tools-0.1.0-py3-none-any.whl size=1543 sha256=85bcdb1fc5f1c06e65506fdf02ce2195be06aad25b44e36813cc088719da4ee1
  Stored in directory: /private/var/folders/32/z9wr5xpx5yzbyyynfrz1kjq80000gn/T/pip-ephem-wheel-cache-3x9u3nhr/wheels/f9/69/97/2777d9fff9e51e8b5f58c18de99fe094c87628b304a57dbf8a
Successfully built dashcam-tools
Installing collected packages: Pillow, numpy, pytesseract, opencv-python, dashcam-tools

Successfully installed Pillow-11.3.0 dashcam-tools-0.1.0 numpy-2.0.2 opencv-python-4.13.0.92 pytesseract-0.3.13

## System dependencies
- ffprobe (ffmpeg)
- tesseract-ocr (binary)
- Optional E01:  (libewf), / (sleuthkit)

macOS: ==> Fetching downloads for: ffmpeg, tesseract, libewf and sleuthkit
==> Installing dependencies for ffmpeg: dav1d, lame, libvpx, opus, sdl2, svt-av1, x264 and x265
==> Installing ffmpeg dependency: dav1d
==> Pouring dav1d--1.5.3.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/dav1d/1.5.3: 16 files, 945.0KB
==> Installing ffmpeg dependency: lame
==> Pouring lame--3.100.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/lame/3.100: 28 files, 2.3MB
==> Installing ffmpeg dependency: libvpx
==> Pouring libvpx--1.16.0.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/libvpx/1.16.0: 22 files, 4.4MB
==> Installing ffmpeg dependency: opus
==> Pouring opus--1.6.1.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/opus/1.6.1: 16 files, 1.1MB
==> Installing ffmpeg dependency: sdl2
==> Pouring sdl2--2.32.10.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/sdl2/2.32.10: 94 files, 6.7MB
==> Installing ffmpeg dependency: svt-av1
==> Pouring svt-av1--4.0.1.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/svt-av1/4.0.1: 23 files, 3.1MB
==> Installing ffmpeg dependency: x264
==> Pouring x264--r3222.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/x264/r3222: 12 files, 4.4MB
==> Installing ffmpeg dependency: x265
==> Pouring x265--4.1.arm64_sequoia.bottle.1.tar.gz
🍺  /opt/homebrew/Cellar/x265/4.1: 12 files, 13.2MB
==> Installing ffmpeg
==> Pouring ffmpeg--8.0.1_4.arm64_sequoia.bottle.tar.gz
==> Caveats
ffmpeg-full includes additional tools and libraries that are not included in the regular ffmpeg formula.
==> Summary
🍺  /opt/homebrew/Cellar/ffmpeg/8.0.1_4: 284 files, 53.4MB
==> Running `brew cleanup ffmpeg`...
Disable this behaviour by setting `HOMEBREW_NO_INSTALL_CLEANUP=1`.
Hide these hints with `HOMEBREW_NO_ENV_HINTS=1` (see `man brew`).
==> Installing dependencies for tesseract: openjpeg, webp, leptonica, libb2, libarchive, fribidi, libdatrie, libthai and pango
==> Installing tesseract dependency: openjpeg
==> Pouring openjpeg--2.5.4.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/openjpeg/2.5.4: 512 files, 14.7MB
==> Installing tesseract dependency: webp
==> Pouring webp--1.6.0.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/webp/1.6.0: 64 files, 2.6MB
==> Installing tesseract dependency: leptonica
==> Pouring leptonica--1.87.0.arm64_sequoia.bottle.1.tar.gz
🍺  /opt/homebrew/Cellar/leptonica/1.87.0: 55 files, 7.3MB
==> Installing tesseract dependency: libb2
==> Pouring libb2--0.98.1.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/libb2/0.98.1: 9 files, 132.0KB
==> Installing tesseract dependency: libarchive
==> Pouring libarchive--3.8.6.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/libarchive/3.8.6: 65 files, 4MB
==> Installing tesseract dependency: fribidi
==> Pouring fribidi--1.0.16.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/fribidi/1.0.16: 68 files, 581.6KB
==> Installing tesseract dependency: libdatrie
==> Pouring libdatrie--0.2.14.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/libdatrie/0.2.14: 20 files, 313.5KB
==> Installing tesseract dependency: libthai
==> Pouring libthai--0.1.30.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/libthai/0.1.30: 30 files, 975.3KB
==> Installing tesseract dependency: pango
==> Pouring pango--1.57.0_2.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/pango/1.57.0_2: 69 files, 3.8MB
==> Installing tesseract
==> Pouring tesseract--5.5.2.arm64_sequoia.bottle.tar.gz
==> Caveats
This formula contains only the "eng", "osd", and "snum" language data files.
If you need any other supported languages, run `brew install tesseract-lang`.
==> Summary
🍺  /opt/homebrew/Cellar/tesseract/5.5.2: 75 files, 34.9MB
==> Running `brew cleanup tesseract`...
==> Pouring libewf--20140816.arm64_sequoia.bottle.1.tar.gz
🍺  /opt/homebrew/Cellar/libewf/20140816: 35 files, 10.9MB
==> Running `brew cleanup libewf`...
==> Installing dependencies for sleuthkit: afflib, krb5 and libpq
==> Installing sleuthkit dependency: afflib
==> Pouring afflib--3.7.22.arm64_sequoia.bottle.3.tar.gz
🍺  /opt/homebrew/Cellar/afflib/3.7.22: 52 files, 2.6MB
==> Installing sleuthkit dependency: krb5
==> Pouring krb5--1.22.2.arm64_sequoia.bottle.tar.gz
🍺  /opt/homebrew/Cellar/krb5/1.22.2: 163 files, 5.9MB
==> Installing sleuthkit dependency: libpq
==> Pouring libpq--18.3.arm64_sequoia.bottle.1.tar.gz
🍺  /opt/homebrew/Cellar/libpq/18.3: 2,427 files, 35.6MB
==> Installing sleuthkit
==> Pouring sleuthkit--4.14.0.arm64_sequoia.bottle.1.tar.gz
🍺  /opt/homebrew/Cellar/sleuthkit/4.14.0: 142 files, 19.7MB
==> Running `brew cleanup sleuthkit`...
==> Caveats
==> ffmpeg
ffmpeg-full includes additional tools and libraries that are not included in the regular ffmpeg formula.
==> tesseract
This formula contains only the "eng", "osd", and "snum" language data files.
If you need any other supported languages, run `brew install tesseract-lang`.
Debian/Ubuntu: 
Windows: install ffmpeg+tesseract manually; E01 not supported here.

## Usage


## Build wheel


## Notes
- If tesseract is missing, OCR will fail; install system package first.
- E01 support shells out to ewfmount/mmls/tsk_recover and is read-only.

## rapidtriage

`rapidtriage` is a lightweight forensic triage CLI added alongside the dashcam tools.

Current structure:
- `rapidtriage/core`: OS-independent orchestration, manifest generation, document scanning, file metadata triage, and keyword search.
- `rapidtriage/artifacts/windows`: Windows-only artifact providers kept behind provider interfaces.
- `rapidtriage/artifacts/generic.py`: cross-platform document candidate provider.
- `rapidtriage/schemas/`: JSON Schema contracts for `manifest`, `docs`, `files`, `extract`, `artifacts`, and `run-summary`.
- `docs/rapidtriage-output-schema.md`: human-readable contract summary and sample index.
- `docs/samples/`: representative sample JSON outputs for every published command family.
- `docs/rapidtriage-rule-engine.md`: planned additive contract for rule-engine / IOC lookup work.
- `docs/samples/rapidtriage-rules.sample.yaml`: sample YAML rule file covering ext/path/date/artifact/keyword/hash/domain/url conditions.

CLI help now includes copy/paste examples:

```bash
rapidtriage --help
rapidtriage files --help
rapidtriage extract --help
rapidtriage artifacts --help
rapidtriage run --help
rapidtriage timeline --help
rapidtriage case --help
```

Current usage examples:

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
```

Common command examples:

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
rapidtriage run . --mode hacking --output-dir ./rapidtriage-run-hacking
rapidtriage run . --mode recovery --output-dir ./rapidtriage-run-recovery
rapidtriage timeline . --output ./rapidtriage-timeline.json --report ./rapidtriage-timeline-report.md
rapidtriage case ./incident-case.json --source ./rapidtriage-timeline.json --pointer /events/0 --tag suspicious --note "Review this event"
rapidtriage case ./incident-case.json --source ./rapidtriage-compare.json --pointer /results/0 --bookmark-id compare-001 --tag delta
```

Input root abstraction:

- `folder`: ordinary case folder roots
- `mounted-image`: mounted disk/image roots such as `/Volumes/...`
- `e01-derived`: roots derived from E01/EWF handling or mount output
- `live`: live filesystem roots such as `/`

All root-based commands accept `--input-kind` to override auto-detection while keeping the existing positional `ROOT` interface unchanged.

Schema and sample references:

- `manifest`: `rapidtriage/schemas/manifest.schema.json` + `docs/samples/rapidtriage-manifest.sample.json`
- `docs`: `rapidtriage/schemas/docs.schema.json` + `docs/samples/rapidtriage-docs.sample.json`
- `files`: `rapidtriage/schemas/files.schema.json` + `docs/samples/rapidtriage-files.sample.json`
- `extract`: `rapidtriage/schemas/extract.schema.json` + `docs/samples/rapidtriage-extract.sample.json`
- `artifacts`: `rapidtriage/schemas/artifacts.schema.json` + `docs/samples/rapidtriage-artifacts.sample.json`
- `run-summary`: `rapidtriage/schemas/run-summary.schema.json` + `docs/samples/rapidtriage-run-summary.sample.json`
- `timeline`: `rapidtriage/schemas/timeline.schema.json`
- `rule-engine plan`: `docs/rapidtriage-rule-engine.md` + `docs/samples/rapidtriage-rules.sample.yaml`

Current `docs` support:
- `txt`
- `pdf`
- `docx`

Current `files` behavior:
- performs a fast metadata-only sweep; it relies on file name, full path, extension, and modification time instead of parsing file contents.
- writes JSON output that later triage steps can consume directly.
- includes the built-in heuristic categories `documents`, `archives`, `databases`, and `executables`.
- exposes `images` as an additional non-default category for recovery-oriented workflows.
- exposes path, extension, size, modified timestamp, and matched categories per candidate.

Current `extract` behavior:
- accepts `files` or `docs` result JSON as input.
- copies selected source files into an output directory while preserving relative paths where possible.
- writes a manifest JSON containing original path, extracted path, sha256 hash, modified timestamp, size, and source-specific metadata.
- records missing source files in `skipped` instead of failing the whole run.
- defaults to overwrite protection; use `--overwrite` only when replacement is intentional.
- supports `--dry-run`, `--read-only`, `--max-extract-size-bytes`, and `--max-file-count` for safer evidence handling.

Integrity and provenance:
- every top-level `manifest`, `docs`, `files`, `extract`, `artifacts`, and `run` execution writes a sibling audit JSON.
- audit sidecars record the input root fingerprint, command options, input file hashes, and generated output hashes.
- naming pattern:
  - `rapidtriage-files.json` -> `rapidtriage-files.audit.json`
  - `rapidtriage-extract-manifest.json` -> `rapidtriage-extract-manifest.audit.json`
  - `run` writes `rapidtriage-run-audit.json` in the output directory.

Current `artifacts` behavior:
- exposes independent collector runs outside the `manifest`/`run` pipeline.
- currently supports `browser` and `recent-files`.
- writes JSON output with one provider block, artifact counts, and the collected artifact rows.

Current `run` behavior:
- orchestrates `manifest`, `docs`, `files`, and both extract passes into a single incident-mode workflow.
- implements `seizure`, `fraud`, `hacking`, and `recovery`.
- writes dedicated artifact collector outputs under `artifacts/` when the mode profile uses them.
- writes `rapidtriage-run-summary.json`, `rapidtriage-run-report.md`, `rapidtriage-timeline.json`, and `rapidtriage-timeline-report.md` alongside the component outputs.
- records per-step output paths, artifact counts, keyword hit counts, recent/large file highlights, preferred-location candidates, and timeline event counts in the summary JSON.
- renders a submission-oriented markdown report with case overview, key hits, matched rules, IOC hits, related documents, artifact summary, timeline, extract results, and a compare-results placeholder.
- accepts the same extract safety controls (`--dry-run`, `--read-only`, `--max-extract-size-bytes`, `--max-file-count`, `--overwrite`) and forwards them to both extract stages.

Current `timeline` behavior:
- accepts `files`, `docs`, and one or more `artifacts` JSON outputs, or auto-discovers the default component outputs under a root.
- merges those sources into a chronological event list with `timestamp`, `source`, `path`, and `type`.
- writes both timeline JSON and a markdown report, plus an audit sidecar for provenance/integrity tracking.

Current `case` behavior:
- saves and reloads case-level bookmarks from `files`, `docs`, `artifacts`, `timeline`, or `compare` JSON outputs.
- selects rows by JSON pointer via `--pointer`, stores the original source file, command, timestamp, path, tags, and analyst note.
- supports stable bookmark updates through `--bookmark-id` and prints the saved case JSON with `--show`.
- validates against `rapidtriage/schemas/case.schema.json`.

Smoke test:

```bash
python -m unittest discover -s tests
```

## GUI

Run:

```
 dashcam-gui
```

Pick sources/destination, set options, click Run.
