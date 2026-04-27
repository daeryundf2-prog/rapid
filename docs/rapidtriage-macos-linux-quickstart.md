# RapidTriage macOS/Linux Quick Start

This guide is for running the local RapidTriage web UI from a source checkout on macOS or Linux.

## Requirements

- Python 3.9 or newer.
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

## Release Smoke Test

Before handing a macOS/Linux build to another analyst, run the automated smoke test:

```bash
sh scripts/smoke-test-rapidtriage.sh
```

The smoke test installs the package, runs `doctor`, creates and searches the sample case, runs a small benchmark, builds the validation package, checks evidence-support guidance, and confirms the web UI returns HTTP 200. Outputs are written to:

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

If direct E01 tools are missing or fail, mount/export the image using your trusted forensic workflow and point RapidTriage at the resulting folder:

```bash
rapidtriage run ./mounted-case-folder --mode fraud --read-only
```

For AD1, AFF/AFF4, VHD/VHDX, VMDK, ISO, DMG, XVA, QCOW, mobile extraction packages, and memory dumps, RapidTriage currently provides preflight detection and guidance. Direct parsing/mounting is not yet the default workflow.
