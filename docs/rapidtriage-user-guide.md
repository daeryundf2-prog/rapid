# RapidTriage User Guide

## What Happens When You Add Evidence

RapidTriage is currently strongest when you give it a mounted folder, exported folder, or ordinary filesystem path. It can also run direct extraction for E01/Ex01, raw/split images, ISO/DMG/WIM/SWM, and common qemu-convertible virtual disks when the required external tools are installed. On Windows, the most reliable image workflow is still WSL2 extraction or mounting/exporting the image first, then scanning the mounted folder.

For AD1, AFF/AFF4, XVA, proprietary mobile packages, and memory dumps, use `Check evidence support` or `rapidtriage evidence` first. If RapidTriage says the source must be mounted/exported, do that with your trusted forensic workflow and select the resulting folder. For raw/split, archive, and virtual-disk inputs, the same support check shows whether Sleuth Kit, 7-Zip/bsdtar, or qemu-img are available for direct extraction. For mobile cases, RapidTriage can now import already-exported Cellebrite/XRY/GrayKey/AXIOM-style CSV/JSON folders.

For image/container preflight, JSON output now includes source integrity, missing tools, external tool path/version preflight where applicable, safety notes, limitations, fallback guidance, and a `commercial_grade_ready` flag. Large images may defer full SHA256 hashing in preflight so the UI does not freeze; preserve full acquisition hashes from the imaging workflow and compare them in the case record.

Use:

```bash
rapidtriage evidence ./case.E01 --json
rapidtriage run ./mounted-case-folder --mode fraud --output-dir ./case-run --read-only
```

When direct tools are installed, `rapidtriage run IMAGE.E01`, `rapidtriage run IMAGE.001`, or `rapidtriage run IMAGE.vmdk` writes an image metadata JSON beside the normal run outputs. That metadata records tool versions, partition offsets, command history, warnings, source/derived hashes when bounded, read-only extraction guidance, and a `forensic_review` summary that explains the image-format gap, blockers, and validation caveats.

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

Search JSON now includes an `analysis` block by default. It clusters repeated hits, extracts entity pivots such as people, accounts, emails, URLs, domains, IPs, phones, and hashes, builds a capped relationship graph, extracts timestamp anchors, drafts a lightweight workbook of hypotheses/questions, and groups duplicate hits for representative-first review. The block exposes #46~#50 and #60 commercial gap IDs, `core_accuracy_gates`, native-capability disclosure, and report-grade blockers so analysts can separate triage pivots from verified findings. Use these pivots to decide what to open first; do not treat them as report-ready findings until the source viewer, hashes, and parser limitations have been checked. Use `--no-analysis` only when you need the smallest possible search JSON.

The same `analysis` block includes duplicate-hit groups. These groups use hashes when present and otherwise a normalized source/path/title/preview fingerprint, so repeated browser/artifact/document hits can be reviewed as a set instead of one row at a time.

Whole-run search supports repeatable analyst query options:

```bash
rapidtriage search ./case-run -k passwrod --search-mode fuzzy --fuzzy-distance 2
rapidtriage search ./case-run -k "PowerShell\\s+EncodedCommand" --search-mode regex
rapidtriage search ./case-run -k password -k token --proximity-window 8
rapidtriage search ./case-run --keyword-pack credentials --keyword-pack browser-ai -k "case specific term"
rapidtriage keyword-packs
```

Fuzzy, stemming, regex, and proximity modes are tracked as #61 search aids and now emit #61 `core_accuracy_gates` in completed-run search output. Verify the opened source row, query options, offsets/citations, and hashes before reporting, especially in large cases where exact Case DB FTS remains the fastest repeatable review path.

Built-in and JSON keyword packs are tracked as #62 saved keyword-pack library inputs. The pack list exposes pack names, keyword counts, provenance, #62 `core_accuracy_gates`, and validation blockers so the exact search vocabulary can be preserved with the case.

`rapidtriage indicators ./case-run` creates a separate URL/domain/IP/hash pivot summary from completed run outputs. It keeps source output names and JSON pointers so an analyst can jump from an IOC to the source artifact, and `--rules iocs.yaml` can mark local IOC hits without sending evidence to an external TI service. `--ti-feed local-feed.json` can enrich IOCs from an offline JSON/CSV/TXT feed with #63 severity, classification, source, notes, feed/plugin name, feed version, feed path, validation status, match mode such as exact IOC or URL host-domain match, and #63 `core_accuracy_gates`. Completed run searches and imported Case DB searches include these pivots, so `--source indicators` can isolate IOC rows during review.

In the web UI, open `Triage -> Indicators` after a run to review those pivots in pages, filter the visible rows, inspect source pointers, and save important indicators to the review board.

For repeated review, save useful Case DB searches and filter by review state:

```bash
rapidtriage case-search ./case.db --case-id CASE-001 -k password --source documents --save-as "Credential review"
rapidtriage case-search ./case.db --case-id CASE-001 -k password --review-status relevant --verification-status verified
```

The web search view shows the same analysis pivots above the results table, so an analyst can jump from a cluster/entity/hypothesis to filtered rows without losing the current evidence viewer. Search analysis now also exposes #60 duplicate-hit groups so repeated rows can be reviewed by representative first instead of blindly hidden. The web Case DB panel also supports reloading saved searches, replaying recent keyword sets, selecting visible/low-priority repetitive results, and batch-marking them as verified or rejected. In the source viewer, use the verification guide to open the authoritative source, compute hashes on demand, search only the current file, pin A/B/C compare targets, and save a review decision without losing your place. Viewer payloads now expose #51 review assignment/status workflow metadata and #52 compare workflow metadata. Current-file search hits include stable citations such as line/offset, byte offset, or SQLite table/row/column, plus copy, compare, and "add to review note" controls, so those exact hits can be carried into review notes. Image previews include #56 gallery metadata such as dimensions, source hashes, perceptual hash, similarity bucket, tag suggestions, OCR sidecar status, #58 OCR queue assessment, #59 Korean OCR/translation workflow, and report-selection guidance. SQLite previews are read-only and bounded, but include database metadata, schema SQL, column types, primary-key hints, indexes, table profiles, sample rows, text-column search, and #54 viewer assessment. When a file cannot be safely rendered as text/SQLite/JSON/XML/email/image, the viewer now shows a bounded read-only hex table with offsets, hex bytes, ASCII, preview SHA256, offset range, byte navigation metadata, #53 viewer assessment, truncation status, and byte-offset keyword search. EML/MBOX previews also include thread summaries and #55 conversation views so related mail can be reviewed before bookmarking individual messages. Audio/video previews show #57 bounded media metadata, source hashes for reasonably sized files, adjacent transcript sidecars, cue timestamps from SRT/VTT-style text, cue counts, sidecar validation status, and report-selection warnings without playing or transcoding the source media. Review cards and generated reports extract `Current-file hit:`, `Snippet:`, and `Review hint:` lines into structured cited-hit sections for faster reviewer handoff. Use `Alt+R` to save a hit as relevant, `Alt+X` to reject it, `Alt+I` to toggle report inclusion, and `Alt+[` / `Alt+]` to move between opened search hits.

For very large result sets, API-backed tabs use cursor/offset pages and search/Case DB tables render only the first bounded window of rows in the browser. If the notice appears, narrow the keyword/filter set or use the paged evidence tabs to avoid browser memory pressure.

OCR sidecars are searched before engine OCR. For an image named `screen.png`, sidecars such as `screen.png.ocr.txt`, `screen.ocr.txt`, `screen.txt`, `screen.srt`, or `screen.vtt` are treated as OCR/transcript review text. This is useful for Korean OCR pipelines because external OCR output can be preserved unchanged and searched locally even if Tesseract/OpenCV are not installed.

For large image sets, create a persistent OCR queue before running external OCR:

```bash
rapidtriage ocr-queue ./case-root --output rapidtriage-ocr-queue.json
rapidtriage ocr-queue ./case-root --previous rapidtriage-ocr-queue.json --retry-failures --output rapidtriage-ocr-queue-retry.json
```

The queue records each image candidate, current OCR state, sidecar path/hash/text hash, optional sidecar metadata such as language/confidence/engine, translation sidecars such as `screen.translation.txt` or `screen.en.txt`, Korean language-pack recommendations, quality metrics, retryability, #58/#59 `core_accuracy_gates`, validation blockers, and reviewer guidance. It does not modify evidence files or run OCR by itself; use it to coordinate external OCR processing and preserve sidecar provenance.

Case DB review marks can carry a reviewer, assignee, priority (`urgent`, `high`, `normal`, `low`), optional due date, tags, verification state, and report-candidate state:

```bash
rapidtriage case-review ./case.db --case-id CASE-001 --target-type artifact --target-id 3 --status relevant --verification-status source_opened --assignee analyst-a --priority high --include-in-report
```

Every Case DB review update is versioned. `case-db-report` includes both a #64 `citation_index` and each item’s #65 `review_history`, with #64/#65 `core_accuracy_gates`, so a reviewer can see when an item became report-worthy, who changed it, and which source citation the decision refers to.
Report exports also include #86 chain-of-custody workflow rows, #87 acquisition/file hash workflow rows, #88 export-time audit hash chains, #89 deterministic reproducibility hashes, #90 per-item source provenance, #91 parser-confidence scoring, #92 validation-warning metadata, and #93 legal limitation statements. Case DB report exports also summarize #96 acquisition/write-blocker metadata, #97 timezone validation, #98 clock-skew checks, and #99 contamination warnings. Treat these as release/report evidence packages; they still need acquisition notes, write-blocker records, source validation, and analyst sign-off for formal submission.

For A/B/C evidence review, pass three or more files to `compare`; the first path is treated as the baseline and each following file becomes a pairwise comparison row:

```bash
rapidtriage compare ./baseline.txt ./host-a.txt ./host-b.txt --label baseline --label host-a --label host-b --output compare.json
```

## Processing Transparency

The web start screen shows a run-plan preview before processing. Use `Fast first pass` first for large evidence because it keeps extraction read-only and focuses on indexing/search. Use `Standard` when you want bounded copied evidence for review, and use `Deep` only when you intentionally want uncapped extraction.

For long-running or repeated runs, use resume:

```bash
rapidtriage run ./case-root --mode hacking --output-dir ./case-run --read-only --resume
rapidtriage benchmark --output-dir ./bench-100k --file-count 100000 --resume
```

Each run writes `rapidtriage-run-fingerprint.json` and `rapidtriage-run-checkpoints.json` with #68/#70 `core_accuracy_gates`. Resume only reuses stage JSON when the bounded input fingerprint is unchanged; if source metadata changes, RapidTriage disables reuse and records the reason in `safety.resume_disabled_reason`.

Run summaries also include `resource_caps` and artifact scheduler metadata. Artifact parsers are isolated per kind (#71), so one parser failure is recorded in that parser output instead of aborting the whole run. Set `--memory-cap-bytes` or `RAPIDTRIAGE_MEMORY_CAP_BYTES` to stop at safe stage boundaries when RSS exceeds the cap (#72). Source previews include #73 `viewer_sandbox` metadata showing that active content is not executed and previews are read-only/bounded. SQLite and Case DB search paths expose #74 FTS/index optimization metadata, while artifact stages expose #75 parallel scheduler assessment.

The commercial re-architecture introduces isolated Rust parser workers while keeping Python as the CLI/API/UI shell. Use `rearchitecture-status` to see which foundations are ready and which local tools are blocked:

```bash
rapidtriage rearchitecture-status --json
```

When a `rapid-worker` binary is available, `worker-parse` can run it as a separate process and stage normalized `ArtifactRecordV1` rows without loading a whole evidence source into Python memory:

```bash
rapidtriage worker-parse ./mounted-case --kind file-inventory --output ./worker-artifacts.jsonl
rapidtriage case-db ./case.db --import-worker-jsonl ./worker-artifacts.jsonl --case-id CASE-001
rapidtriage case-search ./case.db --case-id CASE-001 -k PowerShell --source artifacts
```

This worker path is still an engineering foundation, not a replacement for the validated Python artifact collectors. Treat worker rows as validation-required until the corresponding Rust parser has known-answer fixtures and large-case performance evidence. To smoke-test the full worker-to-search path, run `python scripts/worker-case-db-smoke.py --output-dir ./worker-case-db-smoke`.

For high-volume review, paged API responses include both offsets and cursor tokens:

```text
pagination.next_cursor = offset:1000
```

Use the cursor on the next request to avoid keeping giant result arrays in the browser. Paged responses expose #78 pagination assessment metadata, visible tables expose #79 bounded-DOM virtualization notices, file scans report #77 bounded `duplicate_content_groups`, and repeated hash requests expose #76 in-process path/size/mtime hash-cache metadata. Long-running web jobs expose #80 cancellation/retry assessment; running parser cancellation is still cooperative and stage-boundary limited.

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

Browser and AI usage workflow:

- Browser rows normalize Chrome/Edge/Brave/Firefox history and downloads into profile-scoped history/download lists, internet usage pivots, AI service visit rows, bounded unified timeline rows, and #20 `forensic_review`. Chromium and Firefox are supported on Windows and macOS through local profile databases; Safari is currently macOS history-only and should not be treated as full browser-cache/session parity.
- Chromium-family cache, session, extension, sync, cookie, credential, Local Storage, and IndexedDB paths are inventoried as review candidates with file counts, total bytes, bounded sample hashes, sensitivity flags, #19 `forensic_review`, and strict legal/privacy warnings. RapidTriage does not decrypt cookies, passwords, tokens, or raw session secrets.
- AI conversation candidates are recovered from browser storage as review-only snippets. Rows include service labels, question/answer direction, source storage kind, profile-relative path, source hashes, offset candidates, transcript pairing confidence, completeness score, orphan counts, validation checks, and #21 `forensic_review`. Validate against raw source files or service exports before reporting prompt/answer content.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind browser --output browser.json
```

Event log workflow:

- Native `.evtx` files are inventoried with source hashes and parser guidance; recoverable binary record headers also emit partial `eventlog-event` rows with record ID, timestamp, record SHA256, record-size integrity checks, sequence-gap hints, extracted UTF-16 strings, first-pass BinXML token scans, inline scalar decoding for common String/ANSI/integer/bool/GUID/SID/FILETIME/SYSTIME/binary values, TemplateInstance IDs, TemplateInstance value spec/value decoding, substitution value fields, promoted `Event/System`, ordered duplicate-preserving `EventData` sequences, grouped EventData values by name, and `UserData` fields, rendered previews where possible, channel/provider/computer/command/IP/user SID candidates, explicit `evtx_binxml_status`, `evtx_recovery_context`, and suspicious-term flags. Native `eventlog-chunk` rows expose chunk bounds, slack offsets, and checksum observations to help review deleted/corrupt candidates. Treat native rows as triage pivots unless an EVTX-capable export validates complete provider message rendering.
- XML/JSON/JSONL/CSV exports from EVTX-oriented tools such as EvtxECmd, Hayabusa, Chainsaw, and Velociraptor are normalized into event rows.
- Event rows include `event_message` and `message_rendering` provenance. Exported/rendered messages are preserved when present; native EVTX rows can use built-in high-value fallback templates for common Security, PowerShell, and log-clear events, but those native fallback messages are marked validation-required until provider message resources are resolved.
- Slack/deleted/corrupt EVTX recovery is cautious by design. Parseable rows can be labeled `slack-or-deleted-record-candidate` when chunk free-space metadata supports that interpretation, and invalid record headers emit `eventlog-record-candidate` rows with offsets, size checks, confidence, and `do-not-report-without-validation` caution labels.
- Important Event IDs such as logons, failed logons, privileged logons, process creation, scheduled task creation, service installation, log clearing, PowerShell script blocks, RDP sessions, WMI, Defender, Firewall, USB/device, share access, and Sysmon events are categorized with `event_family`, `channel_family`, `event_tags`, parser confidence, source hashes, and triage recommendations.
- RapidTriage also emits built-in `eventlog-detection` rows for first-pass triage of log clearing, encoded PowerShell, RDP logons/sessions, privileged logons, services, tasks, account changes, group membership changes, suspicious process commands, Defender detections, WMI activity, VSC deletion commands, and Sysmon network/DNS/registry/image-load events.
- `eventlog-summary` rows aggregate large exports by Event ID, event family, category, channel family, channel, user, source IP, process name, parser status, reportability, suspicious term, detection level, detection rule, native EVTX integrity, native sequence status, native channel-hint source, and native BinXML status, with high-risk event samples and EventRecordID gap hints for review triage.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind eventlog --output eventlog.json
rapidtriage artifacts ./evtx-tool-output --kind eventlog --output eventlog-import.json
```

OS/account workflow:

- User profile directories are inventoried.
- `.reg` exports can provide computer name, timezone, ProfileList SID, admin-group hints, current control set, service configuration, mounted devices, SECURITY/LSA sensitive locations, privilege assignments, last boot/shutdown timestamps, exported group membership hints, and exported account lifecycle fields such as created time, last logon, password-last-set, disabled, and admin hints. Account lifecycle rows now include an `account_security_context` that links builtin group SID candidates to inherited privilege assignments, plus #6 `core_accuracy_gates` so RID/name/SID, UAC, group membership, privilege attribution, and secret-redaction coverage is visible before report selection.
- Native `SAM` hives emit bounded `windows-sam-account-candidate` rows for account-name and RID key candidates plus `windows-sam-group-candidate` rows for likely group/alias keys with source hashes, offsets, and last-write hints. Treat these as review pivots; full F/V account attributes and native alias-member reconstruction still need validation with a dedicated SAM parser before final testimony.
- Service, mounted-device, LSA-sensitive-location, privilege-assignment, and group-membership rows are emitted separately so analysts can review persistence, device history, permission risk, and exported group membership hints without opening raw registry text first. Group rows expose builtin SID candidates where known, and privilege rows expose assigned principal hints for builtin aliases. SECURITY/LSA secret values are hashed and described with metadata only; RapidTriage does not decrypt secrets.
- `windows-registry` summarizes Run-key persistence values, suspicious command/value hints, and USBSTOR device metadata from `.reg` exports. It also inventories native hive candidates such as `NTUSER.DAT`, `UsrClass.dat`, `SYSTEM`, and `SOFTWARE` with source hashes, `regf` header fields, sequence/dirty hints, last-write timestamp, bounded string pivots, hbin-aware `nk`/`vk` hive cell candidates, best-effort `registry-key-tree-node` rows, separate deleted/free-cell candidate rows, key-specific `registry-key-recovery-candidate` rows, and value-specific `registry-value-recovery-candidate` rows for review. NTUSER/UsrClass user-hive activity pivots are promoted as `registry-user-activity` rows for UserAssist, TypedURLs/TypedPaths, RecentDocs, Run/RunOnce, Explorer/MRU, ShellBags, MountPoints2, Network, and ComDlg32/OpenSavePidlMRU review.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind windows-os-account --output os-account.json
rapidtriage artifacts ./registry-exports --kind windows-registry --output registry.json
```

Recent/LNK workflow:

- Recent shortcut rows parse Shell Link metadata when available, including target path, working directory, command-line arguments, target timestamps, link flags, file attributes, source hashes, and embedded path pivots.
- Jump List files are inventoried as automatic/custom destination containers; recoverable OLE/CFB streams are listed, and embedded Shell Link records are promoted into destination rows with stream provenance, stream hashes, target paths, working directories, target timestamps, link flags, and offsets. Automatic Jump Lists also expose bounded DestList header/entry metadata candidates with validation checks and explicit commercial blockers when full OS-version-specific field decoding is not yet report-grade. When stream parsing is not possible, RapidTriage falls back to embedded path extraction for search triage.

Remote access workflow:

- `windows-remote-access` extracts RDP connection files, including full address, username hint, gateway host, and modified time.
- Terminal Server Client cache files are inventoried with hashes, timestamps, and bounded PNG/JPEG/BMP/DIB thumbnail signature pivots so analysts can preserve and review RDP thumbnail/cache evidence without forcing heavy decoding up front.
- Exported Terminal Server Client registry keys are normalized into `rdp-destination` rows for quick destination pivots.

Execution and filesystem workflow:

- `windows-execution` imports Amcache/ShimCache/UserAssist/BAM-style `.reg` exports, scans native `Amcache.hve` for bounded path/hash candidates, and imports PowerShell console history. Amcache, ShimCache, BAM/DAM, and SRUM rows expose #7~#10 `core_accuracy_gates` showing which required validation checks are satisfied and which commercial-grade blockers remain.
- `windows-execution-summary` groups execution-related signals by executable path or command subject so the analyst can pivot from one program to all related BAM/UserAssist/ShimCache/PowerShell rows.
- `windows-prefetch` parses SCCA Prefetch headers for executable hints, version-specific common-layout metadata, best-effort run counts, last run timestamps, run-count/last-run validation checks, referenced path pivots, bounded volume/file-reference candidates, and separate `prefetch-reference` rows. Treat these as triage leads: RapidTriage now records explicit commercial blockers where full file metrics, authoritative volume tables, trace chains, directory sections, MFT file references, or validation corpus coverage are incomplete.
- SRUM CSV/JSON/JSONL/NDJSON exports from trusted tools can be imported as app resource or network usage rows with bytes totals, interface/profile, energy, user, timestamp, and source hashes; `SRUDB.dat` is also preserved with ESE header and native validation metadata, bounded string/path/URL pivots, native `srum-database-pivot` rows, `srum-table-candidate` rows, and bounded `srum-row-candidate` string-cluster rows for app/network/energy/user review. Treat native SRUDB candidates as validation-required until a dedicated SRUM/ESE parser confirms tables, counters, and timestamps.
- `windows-search-index` inventories `Windows.edb` with ESE header metadata, bounded string/path/URL/content pivots, native validation metadata, explicit commercial-readiness blockers, separate `windows-search-edb-pivot`, `windows-search-edb-page-candidate`, and `windows-search-edb-table-candidate` rows, and correlated `windows-search-edb-row-candidate` rows that pair path/URL/content strings for review while clearly marking timestamp/deleted-state gaps. Page candidates preserve ESE page index, byte offset, page SHA256, page-local table marker hits, and page-local path/URL/content/risk strings so reviewers can jump back to a stable source location. It also imports Windows Search CSV/JSON exports so indexed filenames, paths, URLs, titles, and content snippets can be searched alongside documents and artifacts.
- `kakaotalk-windows` is a PC KakaoTalk triage view that follows the same style used by commercial tools: it inventories KakaoTalk application `.edb`/`.db`/`.dat` stores first, preserves DB/WAL/SHM/copy hashes, labels likely roles such as chat log, chat list, profile, contact, media, login state, and post-BigBang adjacent indexes, then checks `Windows.edb`, Registry exports/native hives, and memory dumps together. It emits KakaoTalk source candidates with source hash, source family, matched term, path/URL/process/chat-store classification, ESE page hash/offset where available, and privacy/legal warnings. Use it to find and preserve KakaoTalk install/profile/chat-store/process traces, not as final decrypted message testimony.
- For legacy Windows KakaoTalk research workflows, the collector also records decryption-readiness metadata: whether an app DB looks like an encrypted/custom store rather than plain SQLite, whether its size is aligned to 4096-byte pages, whether a successful authorized decoder should produce a `SQLite format 3` header, whether `DeviceInfo` context candidates such as `sys_uuid`, `hdd_model`, and `hdd_serial` are present in registry exports or native hives, and whether registry account identifier candidates such as `talk_user_id`, `tuid`, `uuid`, or `dev_id` exist. Sensitive device/account identifiers are redacted and hashed. RapidTriage does not ship or extract a proprietary KakaoTalk application key and does not attempt message decryption by default.
- `kakaotalk-decrypt` is a separate authorization-gated command for Windows KakaoTalk `chatLogs_*.edb` files. It accepts direct `--key-hex/--iv-hex`, `--pragma/--user-id`, or the research workflow `DeviceInfo + pragma-key + userId` material. Prefer environment variables such as `RAPIDTRIAGE_KAKAO_KEY_HEX`/`RAPIDTRIAGE_KAKAO_IV_HEX`, `RAPIDTRIAGE_KAKAO_PRAGMA`/`RAPIDTRIAGE_KAKAO_USER_ID`, or `RAPIDTRIAGE_KAKAO_PRAGMA_KEY_HEX` plus `RAPIDTRIAGE_KAKAO_USER_ID` to avoid shell history. When using the DeviceInfo workflow, RapidTriage can read `sys_uuid`, `hdd_model`, and `hdd_serial` from `NTUSER.DAT`, derives multiple research-backed pragma variants from the externally supplied pragma-key, then derives DB key/IV from pragma+userId. If exactly one high-confidence userId is found, it can use it internally; if multiple candidates exist, it tries candidate-derived keys and accepts only the one that produces the expected SQLite header. It decrypts 4096-byte AES-CBC pages, confirms the `SQLite format 3` header, opens the decrypted DB read-only, identifies message-table candidates, counts rows, and only includes bounded message previews when `--include-message-preview` is explicitly set. Without complete authorized material it still reports the chat DB count and which material is missing.
- `scripts/kakaotalk_zip_to_report.py` is the operator-facing PC KakaoTalk report wrapper. It accepts ZIP, extracted folders, and single evidence files such as `NTUSER.DAT` or `DMG` inputs; non-ZIP archives are accepted as evidence metadata with a clear "extract first" note. ZIP extraction rejects path traversal, symbolic links, oversized members, excessive total uncompressed size, and suspicious compression ratios. The report writes `kakaotalk_summary.json`, room/message/media CSVs, and `kakaotalk_database_counts.csv` so analysts can distinguish `raw_recovered_message_row_count` from `visible_message_count`. This matters on large cases because a DB can be opened and counted even when the bounded viewer/CSV only shows the displayable subset.
- `kakaotalk-key-store-inspect` is the post-BigBang EDB key-store mapping command. It parses `appstate.dat` and `appstate.dat.backup` as definite-length CBOR, reports `info_prefix`, salt length/hash, `wrapped_dek_map` entry counts, chatLog-to-wrapped-DEK matches, matched EDB file hashes, and optional memory-residency checks. Raw wrapped DEKs, unwrapped DEKs, KEKs, and candidate secrets are never exported. A `key-store-mapped` result means the next reverse-engineering step is KEK/IKM recovery and wrapped-DEK unwrapping, not the legacy PRAGMA workflow.
- `windows-filesystem` imports MFT/USN CSV, JSON, JSONL, or NDJSON exports from trusted external tools; it also inventories native `$MFT` and `$J`/USN journal files with hashes, bounded record/header samples, path pivots, separate native MFT rows with common attribute/timestamp/update-sequence validation metadata, `mft_record_evidence`, and explicit commercial-readiness blockers, plus recoverable native USN rows with cursor/next-cursor, large-record metadata, `usn_record_evidence`, and validation metadata.

Windows, browser, image-adapter, mobile, iOS, Android, email, and cloud rows for #6~#45 now also include shared review objects where applicable. `forensic_review`, `chat_app_forensic_review`, and sensitive-artifact review fields give reviewers a consistent quick read of the backlog gap ID, artifact goal, triage/commercial status, primary evidence strings, blockers, caveats, and the next validation step before adding an item to a report.
- These rows are labeled as triage/reportability hints so weak artifacts such as ShimCache are not overclaimed as proof of execution.

Use:

```bash
rapidtriage artifacts ./mounted-case-or-export --kind windows-execution --output execution.json
rapidtriage artifacts ./mounted-case --kind windows-prefetch --output prefetch.json
rapidtriage artifacts ./mft-usn-export --kind windows-filesystem --output filesystem.json
```

Other Windows system artifacts:

- Task Scheduler XML tasks, including normalized action/trigger/principal metadata, command line, executable name, author, user SID, trigger type, start boundaries, hidden/run-level/logon hints, source hashes, validation checks, commercial-readiness blockers, and risk flags for suspicious LOLBin commands, encoded PowerShell, user-writable payload paths, and Microsoft-path masquerading.
- Windows Defender `MPLog*.log` support logs, with threat/remediation/exclusion-looking lines highlighted.
- Windows Firewall W3C logs, including blocked connection counts and sample rows.
- Windows Error Reporting `Report.wer` files, including normalized crashed app/module paths, exception code, report ID, event time, problem signature values, source hashes, validation checks, and explicit blockers when dump/cab/ReportQueue validation is not available.
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
- Use `vsc-extract` when deleted/modified snapshot-side files should be copied into a preservation package with source and destination SHA256 values.

```bash
rapidtriage vsc-compare ./current-volume ./vss/snapshot-1 --output vsc-delta.json
rapidtriage vsc-compare ./current-volume ./vss/snapshot-1 ./vss/snapshot-2 --hash --max-records 5000
rapidtriage vsc-extract ./current-volume ./vss/snapshot-1 --output-dir ./vsc-evidence --status deleted --status modified
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
- Native inventory/string pivots for Unified Logs (`tracev3`/`uuidtext`), Spotlight stores, FSEvents files, and APFS snapshot hints so large macOS evidence can be searched and reviewed before dedicated macOS parser validation.

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
- Auditd event rows, dpkg package/status events, and Docker container config rows for quick IR pivots.
- Cron entries and systemd service units, including root execution, user-writable paths, and suspicious downloader/reverse-shell command hints.

Use:

```bash
rapidtriage artifacts ./mounted-linux --kind linux-system --output linux-system.json
rapidtriage run ./mounted-linux --mode hacking --output-dir ./case-run --read-only
```

## Android APK Triage

When a mobile acquisition/export folder contains `.apk` files, RapidTriage can inventory them without performing phone acquisition itself. The APK collector records file hashes, package/version metadata when the manifest is readable, requested permissions, dangerous permissions, component summaries, dex/native-library counts, entry hashes, native architectures, certificate entries, bounded dex/native string pivots, URL/IP indicators, validation checks, #30 `forensic_review`, and risk flags. It also inventories Android app-data export files under common `Android/data`, `Android/media`, and `data/data` paths by inferred package/category with #29/#30 `forensic_review` and without decoding secrets.

Use:

```bash
rapidtriage artifacts ./mobile-export --kind android-apk --output android-apk.json
```

Treat the risk score as a triage aid, not a malware verdict. Confirm suspicious APKs with a dedicated mobile/malware workflow before report conclusions. App-data rows are package/path/file-hash inventory only; do not infer message, account, cookie, or token contents from them.

## Mobile Export Imports

Use this when a trusted mobile tool has already produced export folders or reports. RapidTriage scans CSV/JSON/JSONL files and normalizes common Cellebrite, XRY, GrayKey, and AXIOM-style rows into messages, contacts, calls, installed apps, file listings, accounts, media, mobile browser rows, and per-source summary rows. It also inventories authorized iOS backup `Manifest.db`, `Info.plist`, `Status.plist`, and keychain database candidates:

```bash
rapidtriage artifacts ./mobile-export --kind mobile-export --output mobile-artifacts.json
```

The collector records source hashes, source tool hints, row indexes, source record IDs, normalized timestamps, participants, message text and text hash, contact/call fields, app package/version fields, account identifier hashes, media/browser pivots, file hashes/paths, validation checks, #26 `forensic_review`, and risk flags such as OTP/password text, AI-service app/conversation references, privacy/evasion apps, and structured data files. KakaoTalk, WhatsApp, Telegram, Signal, WeChat, LINE, Discord, and Instagram rows from authorized exports are service-labeled with chat/message IDs, conversation titles, participants, media references, reactions, validation blockers, service-specific #31~#35 gap mapping, and `chat_app_forensic_review`. KakaoTalk rows additionally expose `kakaotalk_compatibility_assessment`; 25.7.2 / 2025-08-13 and later is treated as post-BigBang and not compatible with legacy decoding assumptions until a known-answer corpus proves otherwise. App SQLite/DB candidates are inventory-only: table names, columns, row counts, message-table candidates, hashes, and warnings are recorded, but encrypted stores and deleted records are not decoded. Each mobile export source also emits a correlation summary with message/media/contact/call counts, detected services, participants, schema-version candidates, message-media links, unified contact/call/SMS actor pivots, #43~#45 `forensic_review`, and correlation-readiness checks. iOS backup/keychain rows include #27/#28 `forensic_review`; keychain handling is inventory/redaction-only and records table names, columns, row counts, and hashes, but does not decrypt or expose passwords, tokens, cookies, or protected values. It imports vendor exports; it does not decrypt proprietary acquisition packages or replace the original mobile forensic tool validation.

## Image Similarity Triage

Use image triage when a case has many screenshots, photos, or scanned documents and you need stable grouping signals before deeper review/OCR:

```bash
rapidtriage artifacts ./mounted-case --kind media-image --output media-images.json
```

The collector records file hashes, dimensions, channel count, an average perceptual hash, a short similarity bucket, a bounded inline PNG thumbnail preview, and whether the file should be queued for OCR. The perceptual hash avoids optional NumPy aggregate helpers so image grouping remains more tolerant of mixed OpenCV/NumPy installs; thumbnail generation is isolated so a preview failure does not abort artifact collection. If a sidecar such as `image.png.ocr.txt`, `image.ocr.txt`, or `image.txt` exists, it records sidecar hashes, bounded OCR text, Korean/English language hints, and whether translation review is required. The perceptual hash and visual classification fields are grouping hints for fast review, not courtroom-grade similarity, deepfake, or classifier conclusions by themselves.

## Memory Forensics Imports

RapidTriage can import Volatility/Volatility3 JSON or JSONL output for review and search. Export plugins such as `pslist`, `cmdline`, `netscan`, or `malfind`, then point the collector at the folder:

```bash
rapidtriage artifacts ./volatility-output --kind memory-volatility --output memory-artifacts.json
```

The importer normalizes process name, PID/PPID, command line, network endpoints, offsets, source hashes, and risk flags such as suspicious command lines, external network connections, malfind rows, and writable executable memory.

The same collector also performs a bounded direct scan of `.mem`, `.raw`, `.vmem`, `.vmss`, `.vmsn`, `.hpak`, `.dmp`, and memory-named `.bin` dumps. It records source hashes, scan ranges, redacted BitLocker recovery-key candidates with SHA256 verification hashes and group-level checksum validation, suspicious process string candidates, suspicious memory strings, URLs, IPs, and risk flags without claiming full process reconstruction.

## Cloud Export Imports

RapidTriage can normalize cloud exports that were already lawfully exported or collected by another workflow. For Google Takeout-style folders, it recognizes Location History `Records.json` and My Activity JSON. For Apple/general account exports, it records account profile fields from JSON.

```bash
rapidtriage artifacts ./cloud-export --kind cloud-export --output cloud-artifacts.json
```

The collector records source hashes, timestamps, activity titles/products, account profile fields, location coordinates, accuracy, and risk flags such as precise location or user activity. It also normalizes Gmail/Drive-style mail and file JSON, Apple/iCloud account/file/photo-style JSON, Microsoft 365/OneDrive/Teams/Audit JSON, and collaboration-SaaS message/file-style JSON into mail, file, chat message, and audit pivots with `cloud_provider_profile`, `cloud_issue_matrix`, and validation blockers. It does not perform unrestricted live cloud acquisition, provider-side deletion recovery, permission graph reconstruction, or eDiscovery validation.

## Email And Mailbox Review

Use the `email` collector when you have exported mail files or mailbox containers:

```bash
rapidtriage artifacts ./mail-export --kind email --output email-artifacts.json
```

EML, EMLX, MBOX, and Maildir rows include headers, message IDs, body previews and hashes, attachment metadata and hashes, source hashes, `email_format_profile`, `email_issue_matrix`, risk flags, and legal warnings. PST, OST, and MSG rows are bounded mailbox inventory only: RapidTriage records source hashes plus email/subject/string candidates for triage, but does not decode native folder trees, deleted items, MAPI properties, or full attachments. Validate report-grade mailbox findings with a dedicated mailbox parser.

## Authorized Cloud API Collection

When you already have lawful API authorization, `cloud-collect` can fetch selected JSON endpoints from a request manifest, save raw responses, hash each response, and write a collection/audit record without storing the Bearer token in output files. Token handling is environment-variable based by default; output metadata records `credential_handling`, redacts Authorization/API-key headers, and records `tokens_written_to_output=false`.

Example manifest:

```json
{
  "requests": [
    {
      "name": "google-activity",
      "service": "google",
      "url": "https://example.com/api/activity",
      "bearer_token_env": "RAPIDTRIAGE_CLOUD_BEARER_TOKEN"
    }
  ]
}
```

Use:

```bash
RAPIDTRIAGE_CLOUD_BEARER_TOKEN=... rapidtriage cloud-collect ./cloud-api-manifest.json --output-dir ./cloud-api-raw
rapidtriage artifacts ./cloud-api-raw/responses --kind cloud-export --output cloud-artifacts.json
```

By default, non-local plain HTTP is refused, only `GET` and `POST` are supported, and responses are capped by `--max-response-bytes`. Treat the API manifest, authorization basis, and original provider records as part of the case documentation.

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
rapidtriage columnar-benchmark --output-dir ./columnar-benchmark --record-count 100000 --json
rapidtriage columnar-convert --input-jsonl ./worker-artifacts.jsonl --output-parquet ./worker-artifacts.parquet --json
rapidtriage stress-plan --output-dir ./stress-plan --size-tb 1 --size-tb 10 --json
```

`benchmark` records #66 scale-target metadata for 100k, 1M, and 10M record claims, including p50/p95 search latency, records/sec, peak memory, run-summary links, #66 `core_accuracy_gates`, and validation blockers. `columnar-benchmark` writes synthetic `ArtifactRecordV1` rows to JSONL, scans the JSONL baseline for p50/p95 query timing, records platform/Python/dependency versions, writes Parquet in row groups when `pyarrow` is installed, and runs DuckDB Parquet query timing when `duckdb` is installed. `columnar-convert` promotes real `worker-parse` JSONL into row-grouped Parquet when `pyarrow` is installed, preserving input SHA256 and a conversion manifest. Attach columnar benchmark evidence to release checks with `python scripts/verify-release-evidence.py --columnar-benchmark-dir ./columnar-benchmark ...`; the verifier checks JSONL metrics, environment capture, optional Parquet/DuckDB evidence, and the required warning that synthetic runs do not prove commercial readiness by themselves. `stress-plan` does not generate terabytes of synthetic evidence. It writes a #67 repeatable 1TB-10TB validation runbook with wall-clock estimates, output reserve, checkpoint interval, resource caps, stop thresholds, required evidence bundle, and #67 `core_accuracy_gates`.

The command writes JSON and Markdown with ingest time, search p50/p95, peak memory, output size, and result counts.

## Release Validation Package

Before handing a build to analysts, generate a validation package:

```bash
rapidtriage validation --output-dir ./release-validation --overwrite --json
```

If you have known-answer or third-party review evidence, attach it:

```bash
rapidtriage validation \
  --output-dir ./release-validation \
  --known-answer-manifest ./known-answer-runs.json \
  --independent-report ./independent-validation.md \
  --overwrite --json
```

The package writes JSON, Markdown, and a validation artifact hash manifest. It lists required checks, #81 NIST CFReDS/CFTT-style known-answer datasets, #82 parser fixture corpus coverage, #83 parser-specific false-positive/false-negative notes, #84 independent validation report SHA256, #85 validation-package automation metadata, user-facing documents, known limitations, chain-of-custody expectations, release artifact requirements, signing/notarization evidence, and support SLA template. Treat it as the release evidence checklist that should sit next to benchmark output, sample-case output, checksums, SBOM/dependency inventory, and build artifacts.

Use `rapidtriage commercial-readiness --output-dir ./commercial-readiness --json` to track the full 120-item parity backlog. Each item is now scored through four gates: `implemented`, `usable`, `validated`, and `commercial_grade`. Do not describe an item as commercial-grade until the report shows all four gates passing for that item. The report also emits `priority_work_plan`, `next_gate_samples`, and `next_gate_blocker_counts` so reviewers can choose the next work item by evidence instead of intuition. It now also emits `commercial_uplift_plan`, a prioritized 70-goal execution plan split into five-item batches; each goal includes the objective, implementation track, acceptance evidence, external blocker status, and large-data processing strategy. To tune that plan, run `rapidtriage commercial-readiness --uplift-targets 70 --uplift-batch-size 5 --output-dir ./commercial-uplift --json`. To focus on validation blockers, run `rapidtriage commercial-readiness --next-gate validated --limit 10`. To plan the next validation batch, run `rapidtriage commercial-readiness --next-gate validated --limit 5 --write-known-answer-template ./known-answer-runs.template.json`; the generated datasets stay `status: "not-run"` until a real known-answer or cross-tool validation run fills evidence paths and assertions. To cover the full backlog in repeatable five-item batches, run `rapidtriage commercial-readiness --template-items 1-120 --template-batch-size 5 --write-known-answer-template-dir ./known-answer-batches`. If known-answer evidence is available, pass `--validation-package ./validation/rapidtriage-validation-package.json`; only datasets marked `status: "pass"` with explicit `backlog_items`/`commercial_items` mappings and present evidence paths can satisfy an item's `validated` gate, and commercial blockers still remain until separately resolved. For the first core-forensics validation block, the repository now ships `docs/validation/rapidtriage-core-forensics-001-025-known-answer.json`; run `rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-025-known-answer.json --json` to attach the internal fixture-backed #1~#25 evidence and move those items to the `commercial_grade` next gate while keeping native-parser and external-corpus blockers visible.

For trusted-tool validation, use `rapidtriage cross-tool-validate --rapid-output ./case-run/artifacts/eventlog.json --reference-output evtxecmd=./EvtxECmd.csv --source-evidence ./Security.evtx --tool-version evtxecmd="EvtxECmd 1.5.0" --tool-command evtxecmd="EvtxECmd.exe -f Security.evtx --csv out" --independent-report ./independent-review.md --corpus-scope "NIST Security.evtx plus local corrupt-record fixture" --backlog-item 1 --backlog-item 2 --output ./evtx-cross-tool.json --json`. When the comparison passes and the output JSON exists, that report can be supplied directly as `commercial-readiness --validation-package ./evtx-cross-tool.json`; the embedded dataset maps the evidence to the selected backlog items. The report preserves SHA256/size/mtime for source, independent review, RapidTriage output, and reference output paths, plus tool version/command metadata and corpus scope. Use this for EVTX/Registry/MFT/USN-style external comparisons; the report-level commercial-grade envelope can pass, but item-level commercial grade still depends on the backlog item's remaining native-parser and external-corpus blockers.

Release builds created by `scripts/build-release.py` now include `release-manifest.json`, `SHA256SUMS`, `dependency-inventory.txt`, `packaging-plan.json`, `packaging-plan.md`, and `update-manifest.json`. Reviewer bundles include #94 court exhibit indexes and #100 tamper-evident audit-bundle hash chains for generated outputs. The packaging plan records #101 Windows Authenticode, #102 macOS codesign/notarization, #103 Linux deb/rpm/AppImage, #104 update-channel, smoke-test, and required evidence gates. The release ZIP also carries #112 release notes, #113 LTS/hotfix policy, #114 support SLA, #115 training curriculum, #116 quickstart lab material, #117 admin deployment guidance, #118 hardening guidance, #119 malicious-evidence handling notes, and #120 dependency monitoring script. The update manifest is manual/local by default and records artifact hashes, rollback guidance, enterprise-disable status, and signature policy; public auto-update distribution still requires signed hosting infrastructure.

The web/API process writes local-only crash reports for unhandled exceptions. Set `RAPIDTRIAGE_CRASH_LOG_DIR` or launch with `rapidtriage web --crash-log-dir ./crash-reports` to choose the directory. Crash reports redact sensitive context keys and are never uploaded automatically.

For enterprise review, run `rapidtriage enterprise-policy --json` or open `/api/enterprise/policy`. This records #105 local-only crash reporting, #106 telemetry-free local-only mode, #107 offline license-file hash/status when configured, #108 documented local roles, role permission matrix, export-control notes, #109 multi-user server disabled guardrails, #110 Case DB audit-trail/hash-chain scope, and #118/#119 security/sandboxing limits.

Back up Case DB work before upgrades or handoff:

```bash
rapidtriage case-backup ./case.db --output-dir ./case-backup --json
rapidtriage case-restore ./case-backup/rapidtriage-case-backup-manifest.json --output ./case-restored.db --json
```

The #111 backup manifest records schema version, table inventory, migration readiness, and restore-rehearsal steps. Treat a restored copy as the upgrade test target before opening the original database with a newer release.

Record acquisition/write-blocker metadata before final reporting:

```bash
rapidtriage case-acquisition ./case.db --case-id CASE-001 \
  --operator "Analyst One" \
  --started-at "2026-04-28T09:00:00+09:00" \
  --completed-at "2026-04-28T10:00:00+09:00" \
  --source-identifier "Disk SN ABC123" \
  --write-blocker "Tableau TX1 SN WB-01 verified read-only" \
  --tool "RapidTriage" \
  --tool-version "dev" \
  --whole-source-sha256 "<64 hex chars>" \
  --notes "Recorded before processing" \
  --json
rapidtriage case-acquisition ./case.db --case-id CASE-001 --list --json
```

Administrators should also review `docs/rapidtriage-admin-deployment-guide.md`, `docs/rapidtriage-training-curriculum.md`, `docs/rapidtriage-lts-hotfix-policy.md`, and `docs/rapidtriage-support-sla.md`, then run `scripts/check-dependencies.py` as part of release preparation.

Case DB report exports also include legal-defensibility metadata for reviewed items: `custody_workflow`, `acquisition_hash_workflow`, `audit_integrity`, `reproducibility`, `acquisition_metadata`, `timezone_validation`, `clock_skew_analysis`, `contamination_warnings`, per-item `provenance`, `validation_assessment`, and `legal_limitations`. These sections help an analyst explain where a report candidate came from, which review action selected it, what hash/parser/offset data exists, what warnings remain, and which audit rows form the export-time hash chain.

## Portable Reviewer Bundle

Use a bundle when a reviewer should see selected evidence metadata, review state, hashes, and the report draft without receiving the original evidence image:

```bash
rapidtriage bundle ./rapidtriage-case.json --allowed-root ./mounted-case --output-dir ./review-bundle --json
```

The bundle includes `rapidtriage-reviewer.html`, selected evidence JSON, a hash manifest, report drafts/exports, report export hashes, `rapidtriage-court-exhibit-index.json`, `rapidtriage-tamper-evident-audit-bundle.json`, `rapidtriage-bundle-manifest.json`, an audit file, and an archive SHA256. The court exhibit index assigns exhibit IDs to selected rows, records generated-output hashes, and lists verification steps. The tamper-evident audit bundle records an export-time hash chain for generated outputs. The reviewer HTML includes a quick preview, review status counts, reviewer checklist, selected evidence table, and the report draft. It does not include the original evidence image, so reviewers must request the authoritative source evidence if a path needs re-checking.

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
