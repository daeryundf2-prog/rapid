# RapidTriage User Guide

## What Happens When You Add Evidence

RapidTriage is currently strongest when you give it a mounted folder, exported folder, or ordinary filesystem path. If you give it an E01/Ex01 file, it can identify the format and can run direct extraction only when `ewfmount`, `mmls`, and `tsk_recover` are available. On Windows, the most reliable workflow is still WSL2 extraction or mounting/exporting the image first, then scanning the mounted folder.

Use:

```bash
rapidtriage evidence ./case.E01 --json
rapidtriage run ./mounted-case-folder --mode fraud --output-dir ./case-run --read-only
```

## Search Workflow

Run output can be searched directly:

```bash
rapidtriage search ./case-run -k password -k powershell --no-ocr
```

For repeat review work, import the run into the SQLite Case DB:

```bash
rapidtriage case-db ./case.db --import-run ./case-run --case-id CASE-001
rapidtriage case-search ./case.db --case-id CASE-001 -k password --source documents
```

Search reaches indexed document text, file metadata, artifact summaries, and timeline events. Use source filters to narrow heavy cases.

## Review Workflow

A search hit can be marked as relevant, excluded, follow-up, or report-worthy:

```bash
rapidtriage case-review ./case.db \
  --case-id CASE-001 \
  --target-type indexed_document \
  --target-id 1 \
  --status relevant \
  --verification-status source_opened \
  --tag credential \
  --include-in-report
```

The web UI also lets you import a run into the Case DB from the summary page, search it, and mark hits as verified or rejected.

## Case Catalog

The case catalog is a lightweight user-facing list of cases and run outputs. It helps users reopen previous work without remembering raw output folders.

```bash
rapidtriage case-catalog --add-run ./case-run --case-id CASE-001 --name "Laptop case" --list
rapidtriage case-catalog --export CASE-001 --archive ./CASE-001.zip
```

## Benchmarking

Use benchmarks to track whether large-case work is getting faster or slower:

```bash
rapidtriage benchmark --output-dir ./benchmark-small --file-count 1000 --json
```

The command writes JSON and Markdown with ingest time, search p50/p95, peak memory, output size, and result counts.

## Security Notes

RapidTriage web defaults to `127.0.0.1`. If you bind to `0.0.0.0`, pass an auth token:

```bash
rapidtriage web --host 0.0.0.0 --auth-token "change-me"
```

In the browser console, set:

```javascript
localStorage.setItem("rapidtriage.authToken", "change-me")
```

Do not expose RapidTriage directly to the internet. Treat source-file download endpoints as sensitive because they may reveal evidence contents.

## Limitations Compared With AXIOM

RapidTriage is not a full AXIOM replacement yet. It has early evidence routing, run outputs, Case DB search/review, reports, hashes, and a local web UI. It does not yet include broad mobile/cloud acquisition, deep filesystem carving, signed commercial validation, or AXIOM-scale parser coverage.
