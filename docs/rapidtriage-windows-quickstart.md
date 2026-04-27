# RapidTriage Windows Quick Start

This guide is for running the local RapidTriage web UI from a source checkout on Windows 11.

## Requirements

- Windows 11 or Windows 10.
- Python 3.9 or newer.
- Git, if cloning from GitHub.
- Internet access for first-time Python package installation.

Optional tools:

- Tesseract OCR enables image OCR.
- `ewfmount`, `mmls`, and `tsk_recover` enable direct E01 extraction when available. On Windows, using WSL2 or a pre-mounted/extracted evidence folder is usually more reliable.

## One-Command Start

Open PowerShell in the repository root and run:

```powershell
.\scripts\windows\start-rapidtriage.ps1
```

Or double-click/run the batch wrapper:

```bat
scripts\windows\start-rapidtriage.bat
```

The launcher will:

1. Create `.venv` if it does not exist.
2. Install RapidTriage with the web dependencies.
3. Run `rapidtriage doctor`.
4. Open `http://127.0.0.1:8765`.
5. Start the local FastAPI web server.

## Useful Options

Run diagnostics only:

```powershell
.\scripts\windows\start-rapidtriage.ps1 -DoctorOnly
```

Use another port:

```powershell
.\scripts\windows\start-rapidtriage.ps1 -Port 8877
```

Recreate the virtual environment:

```powershell
.\scripts\windows\start-rapidtriage.ps1 -Reinstall
```

Start without opening a browser:

```powershell
.\scripts\windows\start-rapidtriage.ps1 -NoBrowser
```

## Manual Commands

If you prefer to run each step manually:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e ".[web]"
python -m rapidtriage doctor
python -m rapidtriage web --host 127.0.0.1 --port 8765
```

Then open:

```text
http://127.0.0.1:8765
```

## Evidence Input Guidance

Recommended first workflow:

1. Mount or extract the evidence image using your trusted forensic workflow.
2. Point RapidTriage at the mounted/extracted folder.
3. Use keyword search, source preview, review marks, submission hashes, and report draft features.

Direct E01 input is supported only when the required external tools are available. If `rapidtriage doctor` warns that E01 tools are missing, use WSL2 or scan a mounted/extracted folder instead.

## Try The Synthetic Sample

After the launcher finishes installing dependencies, you can create and run a small sample case:

```powershell
python -m rapidtriage sample --run --overwrite
```

The run output will be written to:

```text
rapidtriage-sample\run-output
```

Use this folder to test search, artifacts, timeline, review, and report workflows before using real evidence.

## Release Smoke Test

Before handing a Windows build to another analyst, run the automated smoke test:

```powershell
.\scripts\windows\smoke-test-rapidtriage.ps1
```

The smoke test installs the package, runs `doctor`, creates and searches the sample case, runs a small benchmark, builds the validation package, checks evidence-support guidance, and confirms the web UI returns HTTP 200. Outputs are written to:

```text
rapidtriage-windows-smoke
```

If another process is using the default smoke-test port, run:

```powershell
.\scripts\windows\smoke-test-rapidtriage.ps1 -Port 8899
```

## Troubleshooting

Run:

```powershell
python -m rapidtriage doctor
```

Common warnings:

- `tool:tesseract`: OCR is disabled until Tesseract is installed and on `PATH`.
- `tools:e01`: direct E01 extraction is disabled until libewf/Sleuth Kit tools are available.
- `web-port`: another process is using the configured port; rerun with `-Port 8877`.

The default app data directory on Windows is:

```text
%LOCALAPPDATA%\RapidTriage
```
