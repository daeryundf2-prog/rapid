# RapidTriage Sample Case

RapidTriage includes a synthetic sample case so new users can test the full workflow without real evidence.

## Create The Sample Evidence

```bash
rapidtriage sample
```

This creates:

```text
rapidtriage-sample/
  evidence/
  rapidtriage-sample-expected.json
```

The evidence folder looks like a small Windows user profile. It includes documents, logs, a Chromium `History` SQLite database, Recent Items artifacts, downloads, a PowerShell script, and a deleted/recovery-style note.

## Run The Full Smoke Workflow

```bash
rapidtriage sample --run --overwrite
```

This creates the sample evidence and runs:

```bash
rapidtriage run rapidtriage-sample/evidence --mode fraud --output-dir rapidtriage-sample/run-output
```

Expected outputs include:

- `rapidtriage-sample/run-output/rapidtriage-run-summary.json`
- `rapidtriage-sample/run-output/rapidtriage-run-report.md`
- `rapidtriage-sample/run-output/rapidtriage-docs.json`
- `rapidtriage-sample/run-output/rapidtriage-files.json`
- `rapidtriage-sample/run-output/rapidtriage-timeline.json`
- `rapidtriage-sample/run-output/artifacts/rapidtriage-artifacts-browser.json`
- `rapidtriage-sample/run-output/artifacts/rapidtriage-artifacts-recent-files.json`
- `rapidtriage-sample/rapidtriage-training-lab-manifest.json`

The training lab manifest records the synthetic evidence root, mode, read-only setting, workflow stages, expected search keywords, required viewer/review exercises, output hashes, missing required outputs, and remaining external training blockers. Keep it with smoke and training records when onboarding analysts.

## Useful Smoke Searches

After running the sample workflow:

```bash
rapidtriage search rapidtriage-sample/run-output -k password --no-ocr
rapidtriage search rapidtriage-sample/run-output -k powershell --no-ocr
rapidtriage search rapidtriage-sample/run-output -k download --no-ocr
```

## Review And Viewer Exercise

Use the sample run to practice the analyst loop:

1. Search for at least three terms from `rapidtriage-training-lab-manifest.json`.
2. Open the hit in source preview, timeline, file table, browser artifacts, and report draft views where available.
3. Mark at least three candidates as relevant or include-in-report.
4. Add a note explaining the source path checked, why the item matters, and any limitation.
5. Verify the output hashes in the training lab manifest before treating the exercise as complete.

## Windows

From PowerShell:

```powershell
.\scripts\windows\start-rapidtriage.ps1
python -m rapidtriage sample --run --overwrite
```

Then import or inspect `rapidtriage-sample/run-output` from the web UI.

## Important Limitation

This sample is synthetic. It is useful for verifying installation, web UI startup, search, artifacts, timeline, and report output. It is not a forensic validation dataset and should not be used to prove parser correctness for real cases.
