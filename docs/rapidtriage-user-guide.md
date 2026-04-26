# RapidTriage User Guide

## What Happens When You Add Evidence

RapidTriage is currently strongest when you give it a mounted folder, exported folder, or ordinary filesystem path. If you give it an E01/Ex01 file, it can identify the format and can run direct extraction only when `ewfmount`, `mmls`, and `tsk_recover` are available. On Windows, the most reliable workflow is still WSL2 extraction or mounting/exporting the image first, then scanning the mounted folder.

For AD1, AFF/AFF4, raw/split images, ISO/DMG/WIM, VHD/VHDX/VMDK/VDI/XVA/QCOW, mobile packages, and memory dumps, use `Check evidence support` or `rapidtriage evidence` first. If RapidTriage says the source must be mounted/exported, do that with your trusted forensic workflow and select the resulting folder.

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

For repeated review, save useful Case DB searches and filter by review state:

```bash
rapidtriage case-search ./case.db --case-id CASE-001 -k password --source documents --save-as "Credential review"
rapidtriage case-search ./case.db --case-id CASE-001 -k password --review-status relevant --verification-status verified
```

The web Case DB panel also supports selecting repetitive results and batch-marking them as verified or rejected.

## Processing Transparency

The web start screen shows a run-plan preview before processing. Use `Fast first pass` first for large evidence because it keeps extraction read-only and focuses on indexing/search. Use `Standard` when you want bounded copied evidence for review, and use `Deep` only when you intentionally want uncapped extraction.

After a run, the Summary tab and generated Markdown report include a processing transparency section. Check warning badges for zero-row parsers, read-only extraction skips, missing source paths, existing destinations, and max-file or max-size caps before treating the run as complete.

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

When generating a case report in the web review board, choose the template that matches the audience:

- `Legal handoff`: balanced narrative plus hashes.
- `Executive summary`: shorter decision-maker framing with evidence details.
- `Technical appendix`: includes processing warning context.
- `Hash-only appendix`: focuses on submission evidence hashes.

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

## Portable Reviewer Bundle

Use a bundle when a reviewer should see selected evidence metadata, review state, hashes, and the report draft without receiving the original evidence image:

```bash
rapidtriage bundle ./rapidtriage-case.json --allowed-root ./mounted-case --output-dir ./review-bundle --json
```

The bundle includes `rapidtriage-reviewer.html`, selected evidence JSON, a hash manifest, a report draft, an audit file, and an archive SHA256.

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
