# RapidTriage Fresh Machine Smoke Test

Use this checklist before claiming a release is usable by a normal Windows/macOS analyst.

## Windows 10/11

1. Start from a fresh checkout or downloaded ZIP.
2. Confirm Python 3.10+ is installed.
3. Open PowerShell in the repository root.
4. Run:

```powershell
.\scripts\windows\start-rapidtriage.ps1
```

5. In a second PowerShell window, run:

```powershell
.\scripts\windows\smoke-test-rapidtriage.ps1
```

6. Confirm the browser opens `http://127.0.0.1:8765`.
7. Click `Check runtime` and confirm missing optional tools are warnings, not confusing failures.
8. Click `Run sample case`.
9. Confirm the completed run opens automatically.
10. Run a keyword search for `password`.
11. Open a result in the viewer, search inside the file, compute hashes, mark it relevant, include it in report set, and open the review board.
12. Generate a hash manifest and case report draft.
13. Use `Check evidence support` on a dummy `.ad1` or `.vhdx` path and confirm the UI tells the user to mount/export first.
14. Attach the generated `rapidtriage-windows-smoke` folder to the release evidence package.

## macOS/Linux

1. Start from a fresh checkout or downloaded ZIP.
2. Confirm Python 3.10+ is installed.
3. Open a terminal in the repository root.
4. Run:

```bash
sh scripts/start-rapidtriage.sh
```

5. In a second terminal, run:

```bash
sh scripts/smoke-test-rapidtriage.sh
```

6. Confirm the browser opens `http://127.0.0.1:8765` or the script prints the URL.
7. Repeat the same runtime, sample, search, viewer, review, hash, report, and evidence-support checks from the Windows section.
8. Attach the generated `rapidtriage-macos-linux-smoke` folder to the release evidence package.

## Pass Criteria

- The app starts without manual Python package commands.
- The sample case completes.
- The automated smoke test completes and writes doctor, sample, search, benchmark, validation, evidence-support, `web-index.html`, and `workbench-smoke-contract.json` outputs.
- The automated smoke summary reports `PASS`.
- Windows and macOS/Linux smoke outputs are attached when both platforms are claimed.
- The workbench smoke contract records the Windows/macOS evidence slots and keeps missing fresh-host screenshots/logs as blockers until those folders are attached.
- The first screen tells the user what to do next.
- Unsupported direct image formats produce clear mount/export guidance.
- Missing OCR/E01 tools are visible as optional limitations.
- The user can create at least one reviewed report candidate and a hash manifest.
