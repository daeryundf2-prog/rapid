# RapidTriage User Guide

## What Happens When You Add Evidence

RapidTriage is currently strongest when you give it a mounted folder, exported folder, or ordinary filesystem path. It can also run direct extraction for E01/Ex01, raw/split images, ISO/DMG/WIM/SWM, and common qemu-convertible virtual disks when the required external tools are installed. On Windows, the most reliable image workflow is still WSL2 extraction or mounting/exporting the image first, then scanning the mounted folder.

For AD1, AFF/AFF4, XVA, mobile packages, and memory dumps, use `Check evidence support` or `rapidtriage evidence` first. If RapidTriage says the source must be mounted/exported, do that with your trusted forensic workflow and select the resulting folder. For raw/split, archive, and virtual-disk inputs, the same support check shows whether Sleuth Kit, 7-Zip/bsdtar, or qemu-img are available for direct extraction.

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

Search reaches indexed document text, EML/MBOX/MSG email text, bounded PST/OST mailbox strings, file metadata, artifact summaries, indicator pivots, and timeline events. Artifact and indicator results keep reviewable source paths and high-value metadata such as event IDs, usernames, source IPs, command lines, PowerShell script blocks, MFT paths, USN reasons, macOS quarantine URLs, browser history previews, LaunchAgent labels/programs, IOC values, risk flags, and matched rules. Use source filters to narrow heavy cases.

`rapidtriage indicators ./case-run` creates a separate URL/domain/IP/hash pivot summary from completed run outputs. It keeps source output names and JSON pointers so an analyst can jump from an IOC to the source artifact, and `--rules iocs.yaml` can mark local IOC hits without sending evidence to an external TI service. Completed run searches and imported Case DB searches include these pivots, so `--source indicators` can isolate IOC rows during review.

In the web UI, open `Triage -> Indicators` after a run to review those pivots in pages, filter the visible rows, inspect source pointers, and save important indicators to the review board.

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

- Native `.evtx` files are inventoried with source hashes and parser guidance; recoverable binary record headers also emit partial `eventlog-event` rows with record ID, timestamp, record SHA256, record-size integrity checks, sequence-gap hints, extracted UTF-16 strings, channel/provider/computer/command/IP/user candidates, and suspicious-term flags.
- XML/JSON/JSONL/CSV exports from EVTX-oriented tools such as EvtxECmd, Hayabusa, Chainsaw, and Velociraptor are normalized into event rows.
- Important Event IDs such as logons, failed logons, privileged logons, process creation, scheduled task creation, service installation, log clearing, PowerShell script blocks, RDP sessions, WMI, Defender, Firewall, USB/device, share access, and Sysmon events are categorized with `event_family`, `channel_family`, `event_tags`, parser confidence, source hashes, and triage recommendations.
- RapidTriage also emits built-in `eventlog-detection` rows for first-pass triage of log clearing, encoded PowerShell, RDP logons/sessions, privileged logons, services, tasks, account changes, group membership changes, suspicious process commands, Defender detections, WMI activity, VSC deletion commands, and Sysmon network/DNS/registry/image-load events.
- `eventlog-summary` rows aggregate large exports by Event ID, event family, category, channel family, channel, user, source IP, process name, parser status, reportability, suspicious term, detection level, detection rule, native EVTX integrity, native sequence status, and native channel-hint source, with high-risk event samples and EventRecordID gap hints for review triage.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind eventlog --output eventlog.json
rapidtriage artifacts ./evtx-tool-output --kind eventlog --output eventlog-import.json
```

OS/account workflow:

- User profile directories are inventoried.
- `.reg` exports can provide computer name, timezone, ProfileList SID, admin-group hints, last boot/shutdown timestamps, and exported account lifecycle fields such as created time, last logon, password-last-set, disabled, and admin hints.
- Native `SAM` hives emit bounded `windows-sam-account-candidate` rows for account-name and RID key candidates with source hashes, offsets, and last-write hints. Treat these as review pivots; full F/V account attributes still need validation with a dedicated SAM parser before final testimony.
- `windows-registry` summarizes Run-key persistence values, suspicious command/value hints, and USBSTOR device metadata from `.reg` exports. It also inventories native hive candidates such as `NTUSER.DAT`, `UsrClass.dat`, `SYSTEM`, and `SOFTWARE` with source hashes, `regf` header fields, sequence/dirty hints, last-write timestamp, bounded string pivots, bounded `nk`/`vk` hive cell candidates, and separate deleted/free-cell candidate rows for review.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind windows-os-account --output os-account.json
rapidtriage artifacts ./registry-exports --kind windows-registry --output registry.json
```

Recent/LNK workflow:

- Recent shortcut rows parse Shell Link metadata when available, including target path, working directory, command-line arguments, target timestamps, link flags, file attributes, source hashes, and embedded path pivots.
- Jump List files are inventoried as automatic/custom destination containers; recoverable embedded Shell Link records are promoted into destination rows with target paths, working directories, target timestamps, link flags, and offsets, with fallback embedded path extraction for search triage.

Remote access workflow:

- `windows-remote-access` extracts RDP connection files, including full address, username hint, gateway host, and modified time.
- Terminal Server Client cache files are inventoried with hashes, timestamps, and bounded PNG/JPEG/BMP/DIB thumbnail signature pivots so analysts can preserve and review RDP thumbnail/cache evidence without forcing heavy decoding up front.
- Exported Terminal Server Client registry keys are normalized into `rdp-destination` rows for quick destination pivots.

Execution and filesystem workflow:

- `windows-execution` imports Amcache/ShimCache/UserAssist/BAM-style `.reg` exports and PowerShell console history.
- `windows-execution-summary` groups execution-related signals by executable path or command subject so the analyst can pivot from one program to all related BAM/UserAssist/ShimCache/PowerShell rows.
- `windows-prefetch` parses SCCA Prefetch headers for executable hints, best-effort run counts, last run timestamps, and referenced path pivots. Treat these as triage leads and validate important claims with a dedicated Prefetch parser.
- SRUM CSV/JSON/JSONL/NDJSON exports from trusted tools can be imported as app resource or network usage rows with bytes, energy, user, timestamp, and source hashes; `SRUDB.dat` is also preserved with ESE header metadata, bounded string/path/URL pivots, and separate native `srum-database-pivot` rows for app/URL review.
- `windows-search-index` inventories `Windows.edb` with ESE header metadata, bounded string/path/URL pivots, and separate `windows-search-edb-pivot` rows. It also imports Windows Search CSV/JSON exports so indexed filenames, paths, URLs, titles, and content snippets can be searched alongside documents and artifacts.
- `windows-filesystem` imports MFT/USN CSV, JSON, JSONL, or NDJSON exports from trusted external tools; it also inventories native `$MFT` and `$J`/USN journal files with hashes, bounded record/header samples, path pivots, and recoverable native USN rows.
- These rows are labeled as triage/reportability hints so weak artifacts such as ShimCache are not overclaimed as proof of execution.

Use:

```bash
rapidtriage artifacts ./mounted-case-or-export --kind windows-execution --output execution.json
rapidtriage artifacts ./mounted-case --kind windows-prefetch --output prefetch.json
rapidtriage artifacts ./mft-usn-export --kind windows-filesystem --output filesystem.json
```

Other Windows system artifacts:

- Task Scheduler XML tasks, including command, arguments, action preview, author, user SID, trigger type, start boundaries, hidden/run-level/logon hints, and risk flags for suspicious LOLBin commands, encoded PowerShell, user-writable payload paths, and Microsoft-path masquerading.
- Windows Defender `MPLog*.log` support logs, with threat/remediation/exclusion-looking lines highlighted.
- Windows Firewall W3C logs, including blocked connection counts and sample rows.
- Windows Error Reporting `Report.wer` files, including crashed app, module, and bucket fields.
- WMI repository files such as `OBJECTS.DATA` are inventoried with hashes plus bounded string pivots for permanent event consumer/filter names, suspicious commands, paths, URLs, and WMI persistence risk flags.
- Zone.Identifier sidecar exports, including ZoneId, referrer URL, and host URL.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind windows-system --output windows-system.json
rapidtriage run ./mounted-case --mode hacking --output-dir ./case-run --read-only
```

Volume Shadow Copy comparison:

- Use `vsc-compare` after mounting or exporting the current volume and one or more VSC snapshots.
- The default comparison is fast and metadata-based; add `--hash` when you need byte-level modified-file confirmation.
- Deleted means present in the snapshot but missing from the current tree, which is useful for ransomware, wiper, and user-deletion review pivots.

```bash
rapidtriage vsc-compare ./current-volume ./vss/snapshot-1 --output vsc-delta.json
rapidtriage vsc-compare ./current-volume ./vss/snapshot-1 ./vss/snapshot-2 --hash --max-records 5000
rapidtriage case-db ./case.db --import-vsc-compare ./vsc-delta.json --case-id CASE-001
rapidtriage case-search ./case.db --case-id CASE-001 -k deleted --source artifacts --metadata status=deleted
```

When you use `rapidtriage run`, the Windows collectors are wired into the case workflow automatically:

- `seizure`, `fraud`, and `hacking` run browser, recent-file, OS/account, event log, execution, filesystem, Windows system, Linux system, and macOS system collectors.
- `recovery` runs recent-file, OS/account, event log, filesystem, Linux system, and macOS system collectors so deleted-file and restore clues still enter the timeline without doing carving.
- Search and Case DB import can then find hits across documents, logs, event exports, PowerShell history, MFT/USN imports, and timeline rows from the same run output.

## macOS System Artifacts

On mounted or exported macOS evidence, `macos-system` collects a baseline set of reviewable artifacts:

- User profile inventory under `Users/*`.
- Safari, Chromium, Edge, Brave, and Firefox history/download rows where local profile databases are present.
- LaunchServices quarantine events, useful for downloaded-file provenance.
- TCC privacy permission rows for camera, microphone, screen capture, accessibility, full-disk access, and protected folders, including risk flags for allowed high-value permissions and user-writable clients.
- User and system LaunchAgent/LaunchDaemon plist inventory, including label, program arguments, and `RunAtLoad`.

Use:

```bash
rapidtriage artifacts ./mounted-mac --kind macos-system --output macos-system.json
rapidtriage run ./mounted-mac --mode hacking --output-dir ./case-run --read-only
```

## Linux System Artifacts

On mounted or exported Linux evidence, `linux-system` collects a bounded IR-oriented baseline:

- `/etc/passwd` user inventory with UID 0 and interactive-shell flags.
- Shell history from common Bash/Zsh/Ash history files, including suspicious command-token flags.
- SSH `authorized_keys` and `known_hosts` pivots with key material redacted to SHA256.
- Auth log events for accepted/failed SSH, sudo commands, account creation, and cron execution.
- Cron entries and systemd service units, including root execution, user-writable paths, and suspicious downloader/reverse-shell command hints.

Use:

```bash
rapidtriage artifacts ./mounted-linux --kind linux-system --output linux-system.json
rapidtriage run ./mounted-linux --mode hacking --output-dir ./case-run --read-only
```

## Android APK Triage

When a mobile acquisition/export folder contains `.apk` files, RapidTriage can inventory them without performing phone acquisition itself. The APK collector records file hashes, package/version metadata when the manifest is readable, requested permissions, dangerous permissions, dex/native-library counts, certificate entries, bounded dex/native string pivots, URL/IP indicators, and simple risk flags.

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

The collector records file hashes, dimensions, channel count, an average perceptual hash, a short similarity bucket, a bounded inline PNG thumbnail preview, and whether the file should be queued for OCR. The perceptual hash is a grouping hint for fast review, not a courtroom-grade similarity conclusion by itself.

## Memory Forensics Imports

RapidTriage can import Volatility/Volatility3 JSON or JSONL output for review and search. Export plugins such as `pslist`, `cmdline`, `netscan`, or `malfind`, then point the collector at the folder:

```bash
rapidtriage artifacts ./volatility-output --kind memory-volatility --output memory-artifacts.json
```

The importer normalizes process name, PID/PPID, command line, network endpoints, offsets, source hashes, and risk flags such as suspicious command lines, external network connections, malfind rows, and writable executable memory.

The same collector also performs a bounded direct scan of `.mem`, `.raw`, `.vmem`, `.vmss`, `.vmsn`, `.hpak`, `.dmp`, and memory-named `.bin` dumps. It records source hashes, scan ranges, redacted BitLocker recovery-key candidates with SHA256 verification hashes, suspicious memory strings, URLs, IPs, and risk flags without attempting full process reconstruction.

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

The web UI prepares the run-local Case DB automatically before DB-backed search. After marking items as report candidates, export the DB-backed report-candidate handoff JSON:

```bash
rapidtriage case-db-report ./case.db --case-id CASE-001 --output case-db-report-candidates.json
```

That export keeps review citations, target citations, parser/source/hash context, and analyst review state together so report drafting does not depend on re-opening raw JSON tables.

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
