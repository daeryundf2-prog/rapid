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

Search reaches indexed document text, file metadata, artifact summaries, and timeline events. Artifact results keep reviewable source paths and high-value metadata such as event IDs, usernames, source IPs, command lines, PowerShell script blocks, MFT paths, USN reasons, macOS quarantine URLs, browser history previews, and LaunchAgent labels/programs. Use source filters to narrow heavy cases.

For repeated review, save useful Case DB searches and filter by review state:

```bash
rapidtriage case-search ./case.db --case-id CASE-001 -k password --source documents --save-as "Credential review"
rapidtriage case-search ./case.db --case-id CASE-001 -k password --review-status relevant --verification-status verified
```

The web Case DB panel also supports selecting repetitive results and batch-marking them as verified or rejected.

## Processing Transparency

The web start screen shows a run-plan preview before processing. Use `Fast first pass` first for large evidence because it keeps extraction read-only and focuses on indexing/search. Use `Standard` when you want bounded copied evidence for review, and use `Deep` only when you intentionally want uncapped extraction.

Before running a large mounted image, use `collect-plan` to preview high-value Windows/macOS artifact locations without copying files or hashing the whole tree:

```bash
rapidtriage collect-plan ./mounted-case --profile intrusion --output collect-plan.json
rapidtriage collect-plan ./mounted-case --profile full --json
```

If the plan looks right and you want a bounded KAPE-style package, run `collect-export`. It writes a manifest first by default; add `--copy` only when you intentionally want files copied into `OUTPUT_DIR/evidence`:

```bash
rapidtriage collect-export ./mounted-case ./case-export --profile intrusion
rapidtriage collect-export ./mounted-case ./case-export --profile intrusion --copy
rapidtriage run ./case-export/evidence --mode hacking --read-only
```

The export log records source path, destination path, SHA256, size, modified time, copied/skipped status, and failure reason. Very broad directories such as whole user profile roots are treated as inventory-only targets so a single click does not accidentally copy a huge profile tree.

Profiles:

- `intrusion`: account usage, event logs, execution, persistence, and remote-access leads.
- `windows-core`: Windows EVTX, registry/user hives, browser paths, execution, persistence, remote access, filesystem timeline, and sync folders.
- `macos-core`: macOS users, Safari/Chromium/Firefox history, quarantine, LaunchAgents/Daemons, Trash, shell history, and iCloud-style folders.
- `browser-history`: browser and cloud/sync paths for web-activity-heavy review.
- `filesystem-timeline`: MFT/USN/Recycle Bin and macOS Trash targets.
- `full`: all built-in collection targets.

Treat missing targets as a review cue, not automatically as absence of activity. A mounted image may use different drive layouts, language-specific profile names, or parser-export folders outside the default `analysis` directory.

After a run, the Summary tab and generated Markdown report include a processing transparency section. Check warning badges for zero-row parsers, read-only extraction skips, missing source paths, existing destinations, and max-file or max-size caps before treating the run as complete.

## Windows System Artifacts

On mounted or exported Windows evidence, RapidTriage now collects high-value system artifacts in addition to browser/recent-file data.

Event log workflow:

- Native `.evtx` files are inventoried with source hashes and parser guidance.
- XML/JSON/JSONL/CSV exports from EVTX-oriented tools such as EvtxECmd, Hayabusa, Chainsaw, and Velociraptor are normalized into event rows.
- Important Event IDs such as logons, failed logons, privileged logons, process creation, scheduled task creation, service installation, log clearing, and PowerShell script blocks are categorized with risk flags.
- `eventlog-summary` rows aggregate large exports by Event ID, category, channel, user, source IP, and process name, with high-risk event samples and EventRecordID gap hints for review triage.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind eventlog --output eventlog.json
rapidtriage artifacts ./evtx-tool-output --kind eventlog --output eventlog-import.json
```

OS/account workflow:

- User profile directories are inventoried.
- `.reg` exports can provide computer name, timezone, ProfileList SID, and admin-group hints.
- `windows-registry` also summarizes Run-key persistence values, suspicious command/value hints, and USBSTOR device metadata from `.reg` exports.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind windows-os-account --output os-account.json
rapidtriage artifacts ./registry-exports --kind windows-registry --output registry.json
```

Execution and filesystem workflow:

- `windows-execution` imports Amcache/ShimCache/UserAssist/BAM-style `.reg` exports and PowerShell console history.
- `windows-execution-summary` groups execution-related signals by executable path or command subject so the analyst can pivot from one program to all related BAM/UserAssist/ShimCache/PowerShell rows.
- SRUM CSV/JSON/JSONL/NDJSON exports from trusted tools can be imported as app resource or network usage rows with bytes, energy, user, timestamp, and source hashes.
- `windows-filesystem` imports MFT/USN CSV, JSON, JSONL, or NDJSON exports from trusted external tools.
- These rows are labeled as triage/reportability hints so weak artifacts such as ShimCache are not overclaimed as proof of execution.

Use:

```bash
rapidtriage artifacts ./mounted-case-or-export --kind windows-execution --output execution.json
rapidtriage artifacts ./mounted-case --kind windows-prefetch --output prefetch.json
rapidtriage artifacts ./mft-usn-export --kind windows-filesystem --output filesystem.json
```

Other Windows system artifacts:

- Task Scheduler XML tasks, including command, arguments, author, user SID, and trigger type.
- Windows Defender `MPLog*.log` support logs, with threat/remediation/exclusion-looking lines highlighted.
- Windows Firewall W3C logs, including blocked connection counts and sample rows.
- Windows Error Reporting `Report.wer` files, including crashed app, module, and bucket fields.
- Zone.Identifier sidecar exports, including ZoneId, referrer URL, and host URL.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind windows-system --output windows-system.json
rapidtriage run ./mounted-case --mode hacking --output-dir ./case-run --read-only
```

When you use `rapidtriage run`, the Windows collectors are wired into the case workflow automatically:

- `seizure`, `fraud`, and `hacking` run browser, recent-file, OS/account, event log, execution, filesystem, Windows system, and macOS system collectors.
- `recovery` runs recent-file, OS/account, event log, filesystem, and macOS system collectors so deleted-file and restore clues still enter the timeline without doing carving.
- Search and Case DB import can then find hits across documents, logs, event exports, PowerShell history, MFT/USN imports, and timeline rows from the same run output.

## macOS System Artifacts

On mounted or exported macOS evidence, `macos-system` collects a baseline set of reviewable artifacts:

- User profile inventory under `Users/*`.
- Safari, Chromium, Edge, Brave, and Firefox history/download rows where local profile databases are present.
- LaunchServices quarantine events, useful for downloaded-file provenance.
- User and system LaunchAgent/LaunchDaemon plist inventory, including label, program arguments, and `RunAtLoad`.

Use:

```bash
rapidtriage artifacts ./mounted-mac --kind macos-system --output macos-system.json
rapidtriage run ./mounted-mac --mode hacking --output-dir ./case-run --read-only
```

## Android APK Triage

When a mobile acquisition/export folder contains `.apk` files, RapidTriage can inventory them without performing phone acquisition itself. The APK collector records file hashes, package/version metadata when the manifest is readable, requested permissions, dangerous permissions, dex/native-library counts, certificate entries, and simple risk flags.

Use:

```bash
rapidtriage artifacts ./mobile-export --kind android-apk --output android-apk.json
```

Treat the risk score as a triage aid, not a malware verdict. Confirm suspicious APKs with a dedicated mobile/malware workflow before report conclusions.

## Image Similarity Triage

Use image triage when a case has many screenshots, photos, or scanned documents and you need stable grouping signals before deeper review/OCR:

```bash
rapidtriage artifacts ./mounted-case --kind media-image --output media-images.json
```

The collector records file hashes, dimensions, channel count, an average perceptual hash, a short similarity bucket, and whether the file should be queued for OCR. The perceptual hash is a grouping hint for fast review, not a courtroom-grade similarity conclusion by itself.

## Memory Forensics Imports

RapidTriage does not parse raw RAM dumps directly yet, but it can import Volatility/Volatility3 JSON or JSONL output for review and search. Export plugins such as `pslist`, `cmdline`, `netscan`, or `malfind`, then point the collector at the folder:

```bash
rapidtriage artifacts ./volatility-output --kind memory-volatility --output memory-artifacts.json
```

The importer normalizes process name, PID/PPID, command line, network endpoints, offsets, source hashes, and risk flags such as suspicious command lines, external network connections, malfind rows, and writable executable memory.

## Cloud Export Imports

RapidTriage can normalize cloud exports that were already lawfully exported or collected by another workflow. For Google Takeout-style folders, it recognizes Location History `Records.json` and My Activity JSON. For Apple/general account exports, it records account profile fields from JSON.

```bash
rapidtriage artifacts ./cloud-export --kind cloud-export --output cloud-artifacts.json
```

The collector records source hashes, timestamps, activity titles/products, account profile fields, location coordinates, accuracy, and risk flags such as precise location or user activity. It does not perform live cloud acquisition or API collection.

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

## Release Validation Package

Before handing a build to analysts, generate a validation package:

```bash
rapidtriage validation --output-dir ./release-validation --overwrite --json
```

The package writes JSON and Markdown listing required checks, release commands, user-facing documents, known limitations, chain-of-custody expectations, and external responsibilities such as legal validation, signed installers, and support SLAs. Treat it as the release evidence checklist that should sit next to benchmark output, sample-case output, and build artifacts.

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
