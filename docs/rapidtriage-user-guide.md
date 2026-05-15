# RapidTriage User Guide

## What Happens When You Add Evidence

RapidTriage is currently strongest when you give it a mounted folder, exported folder, or ordinary filesystem path. It can also run direct extraction for E01/Ex01, raw/split images, ISO/DMG/WIM/SWM, and common qemu-convertible virtual disks when the required external tools are installed. E01/RAW/virtual-disk/container support checks now emit `image_analyst_review_profile`, which gives the UI a concise source hash, workflow status, blocked-stage, "not proof of", and trusted-diff blocker card. Evidence preflight also emits `recovery_unlock_profile`, which surfaces VSS/APFS snapshot handoff, FDE indicator/required-material guidance, `fde_operator_runbook`, and bounded carving workflow before extraction so the analyst can decide whether to unlock externally, attach proof, mount snapshots, or queue carving. On Windows, the most reliable image workflow is still WSL2 extraction or mounting/exporting the image first, then scanning the mounted folder.

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

For document-heavy cases, you can preserve a processed-text sidecar and query it later without re-extracting every PDF/Office/mail document:

```bash
rapidtriage docs ./mounted-case-folder -k password --index-output ./docs-index.json
rapidtriage docs-index-search ./docs-index.json -k password --output ./docs-index-password-hits.json
```

The sidecar stores token postings, document metadata, and text hashes, not full extracted text. Treat `docs-index-search` as a fast lead finder: open the source document or source viewer hit context before reporting a finding.

For repeat review work, import the run into the SQLite Case DB:

```bash
rapidtriage case-db ./case.db --import-run ./case-run --case-id CASE-001
rapidtriage case-search ./case.db --case-id CASE-001 -k password --source documents
```

Search reaches indexed document text, EML/MBOX/MSG email text, bounded PST/OST mailbox strings, file metadata, artifact summaries, indicator pivots, and timeline events. Artifact and indicator results keep reviewable source paths and high-value metadata such as event IDs, usernames, source IPs, command lines, PowerShell script blocks, MFT paths, USN reasons, macOS quarantine URLs, browser history previews, LaunchAgent labels/programs, IOC values, risk flags, and matched rules. Use source filters to narrow heavy cases.

Search JSON now includes an `analysis` block by default. It clusters repeated hits, extracts entity pivots such as people, accounts, emails, URLs, domains, IPs, phones, and hashes, builds a capped relationship graph, extracts timestamp anchors, drafts a lightweight workbook of hypotheses/questions, and groups duplicate hits for representative-first review. The block exposes #46~#50 and #60 commercial gap IDs, `core_accuracy_gates`, native-capability disclosure, and report-grade blockers so analysts can separate triage pivots from verified findings. Use these pivots to decide what to open first; do not treat them as report-ready findings until the source viewer, hashes, and parser limitations have been checked. Use `--no-analysis` only when you need the smallest possible search JSON.

The same `analysis` block includes duplicate-hit groups. These groups use hashes when present and otherwise a normalized source/path/title/preview fingerprint, so repeated browser/artifact/document hits can be reviewed as a set instead of one row at a time. The web analysis panel now shows a dedupe card with representative hit index, hidden duplicate count, and "not suppressed" status; treat this as a review shortcut only until a Case DB suppression decision and trusted duplicate manifest are attached.

Whole-run search supports repeatable analyst query options:

```bash
rapidtriage search ./case-run -k passwrod --search-mode fuzzy --fuzzy-distance 2
rapidtriage search ./case-run -k "PowerShell\\s+EncodedCommand" --search-mode regex
rapidtriage search ./case-run -k password -k token --proximity-window 8
rapidtriage search ./case-run --keyword-pack credentials --keyword-pack browser-ai -k "case specific term"
rapidtriage keyword-packs
```

Fuzzy, stemming, regex, and proximity modes are tracked as #61 search aids and now emit #61 `core_accuracy_gates` plus `advanced_search_profile` in completed-run search output. The web search form exposes Search mode, Fuzzy distance, and Proximity window controls, and result JSON records regex validity, mode counts, proximity hit counts, and review warnings. Verify the opened source row, query options, offsets/citations, and hashes before reporting, especially in large cases where exact Case DB FTS remains the fastest repeatable review path.

Built-in and JSON keyword packs are tracked as #62 saved keyword-pack library inputs. The pack list exposes pack names, keyword counts, provenance, #62 `core_accuracy_gates`, and validation blockers so the exact search vocabulary can be preserved with the case. The web search form includes built-in pack checkboxes, and API search responses include `keyword_pack_selection_profile` with selected pack names, expanded keyword count, provenance refs, and report-use warnings.

`rapidtriage indicators ./case-run` creates a separate URL/domain/IP/hash pivot summary from completed run outputs. It keeps source output names and JSON pointers so an analyst can jump from an IOC to the source artifact, and `--rules iocs.yaml` or `--rules iocs.yar` can mark local IOC hits without sending evidence to an external TI service. Rule hits from files, documents, artifacts, and timeline outputs are also normalized into `ioc_scanner_hits` with rule id, hit type/value, count, source pointer, row hash, and a scanner manifest; `.yar/.yara` files are imported as YARA-lite literal string IOC rules, which is practical for hash/domain/URL/keyword triage but still not a full native YARA grammar engine. `--ti-feed local-feed.json` can enrich IOCs from an offline JSON/CSV/TXT feed with #63 severity, classification, source, notes, feed/plugin name, feed version, feed path, feed SHA-256/size, validation status, match mode such as exact IOC or URL host-domain match, and #63 `core_accuracy_gates`. Completed run searches and imported Case DB searches include both IOC pivots and scanner hits, so `--source indicators` can isolate IOC rows during review.

In the web UI, open `Triage -> Indicators` after a run to review those pivots in pages, filter the visible rows, inspect source pointers, and save important indicators to the review board. The same tab has a local TI enrichment panel: paste a JSON/CSV/TXT feed path from the analysis workstation, run enrichment, and review matched IOCs with feed provenance and reportability warnings. This is still an offline triage label, not a live TI verdict.

For repeated review, save useful Case DB searches and filter by review state:

```bash
rapidtriage case-search ./case.db --case-id CASE-001 -k password --source documents --save-as "Credential review"
rapidtriage case-search ./case.db --case-id CASE-001 -k password --review-status relevant --verification-status verified
```

Each Case DB search response includes `review_workflow_summary`, which shows #51 review status counts, verification counts, assignee/priority counts, a bounded review queue, report-candidate counts, active review filters, and the remaining role-based queue/notification/multi-user blockers. If document text extraction failed during Case DB import, `summary.document_error_count` and `documents.errors[]` are returned with the search result so a no-hit document search is not mistaken for complete coverage.

The web search view shows the same analysis pivots above the results table, so an analyst can jump from a cluster/entity/hypothesis to filtered rows without losing the current evidence viewer. Search analysis now also exposes #60 duplicate-hit groups so repeated rows can be reviewed by representative first instead of blindly hidden. The web Case DB panel also supports reloading saved searches, replaying recent keyword sets, selecting visible/low-priority repetitive results, and batch-marking them as verified or rejected. In the source viewer, use the verification guide to open the authoritative source, compute hashes on demand, search only the current file, pin A/B/C compare targets, and save a review decision without losing your place. Viewer payloads now expose #51 review assignment/status workflow metadata and #52 compare workflow metadata. Current-file search hits include stable citations such as line/offset, byte offset, or SQLite table/row/column, plus copy, compare, and "add to review note" controls, so those exact hits can be carried into review notes. Image previews include #56 gallery metadata such as dimensions, source hashes, perceptual hash, similarity bucket, tag suggestions, OCR sidecar status, #58 OCR queue assessment, #59 Korean OCR/translation workflow, report-selection guidance, `/source-image-gallery` bounded folder pages for hash/dimension/bucket review across nearby images, `/source-ocr-queue` queue pages, and `/source-ocr-translation` side-by-side OCR/translation review packages for Korean text citation checks. SQLite previews are read-only and bounded, but include database metadata, schema SQL, column types, primary-key hints, indexes, table profiles, sample rows, text-column search, #54 viewer assessment, and `/source-sqlite-table` JSON pages for schema-validated table pagination plus restricted contains filters without arbitrary SQL execution. When a file cannot be safely rendered as text/SQLite/JSON/XML/email/image, the viewer now shows a bounded read-only hex table with offsets, hex bytes, ASCII, preview SHA256, offset range, byte navigation metadata, #53 viewer assessment, truncation status, byte-offset keyword search, and a `/source-hex-range` JSON citation package for bounded byte ranges with range hashes and copy-safe citation text. EML/MBOX previews also include thread summaries, #55 conversation views, attachment hash inventory, and `/source-email-attachment` JSON packages for bounded attachment citation/content review so related mail and files can be reviewed before bookmarking individual messages. Audio/video previews show #57 bounded media metadata, source hashes for reasonably sized files, adjacent transcript sidecars, cue timestamps from SRT/VTT-style text, cue counts, `/source-media-cue` JSON citation packages for selected transcript cues, sidecar validation status, and report-selection warnings without playing or transcoding the source media. Review cards and generated reports extract `Current-file hit:`, `Snippet:`, and `Review hint:` lines into structured cited-hit sections for faster reviewer handoff. Use `Alt+R` to save a hit as relevant, `Alt+X` to reject it, `Alt+I` to toggle report inclusion, and `Alt+[` / `Alt+]` to move between opened search hits.
The workbench preview rail follows `analyst-preview-detail-contract-v1`: the right side always starts with an analyst summary, source locator, hash/citation card, limitation warning, evidence tray, and report tray. Verbose run metadata is hidden inside a collapsed disclosure by default, so large cases keep the reviewer focused on "verify source -> hash/cite -> review state" before any technical details are expanded.
Opened source previews now keep a per-run browser-local navigation history under `viewer-navigation-history-contract-v1`. Use Back/Forward in the source viewer to move between recently opened hits without losing review context or compare-pin compatibility; this is a reviewer convenience layer, not an audit log.
The browser workbench also stores `workbench-session-restore-contract-v1` state locally: selected run, active tab/view group, table filters, column preset, virtual-window offsets, and compare/review sidebars. Refreshing the page should return an analyst to the same working area instead of forcing them back to the first overview.
Search results expose `search-source-verification-contract-v1` in the web workbench. The card counts hits with source-viewer paths, flags truncated result sets, and each row shows a compact locator so analysts remember that a search hit is only a lead until the source viewer citation and hash are checked.
Current-file searches expose `current-file-search-ui-contract-v1` next to the hit list. It shows result limits, truncation state, SQLite scanned-row counts when applicable, large-file byte-window offsets when applicable, and the reportability warning from the API so a large SQLite/EDB-derived table or large log cannot be mistaken for a complete unbounded search. When a SQLite search hits the result limit or row-scan cap, the API returns `sqlite_resume_token` and the GUI shows "Continue SQLite search" so the analyst can resume from the next table row. When a non-document file is larger than the inline text limit, the API searches a bounded byte window, returns `file_resume_token`, and the GUI shows "Continue large file search" so the analyst can continue from the next byte offset instead of silently stopping at the first chunk. Resume tokens are bound to the source path, keyword set, and required next-row/next-byte state; malformed, mismatched, or state-less tokens are rejected with a 400 response rather than silently restarting the scan.
Source viewer path resolution accepts absolute paths, run-root relative paths, and Windows-style `C:\Users\...` paths. For E01/Ex01 extraction trees this lets locator links map Windows artifact paths back to files under the extracted analysis root when the matching relative path exists.
If a source preview or hex-range link cannot be resolved, the API now returns `source-path-resolution-diagnostics-v1` with the allowed roots and candidate paths it tried, so broken E01 locator links can be fixed by checking extraction-root mapping rather than guessing.
The web viewer renders that same diagnostic as an expandable troubleshooting card on failed preview loads, including the requested path, allowed roots, candidate paths, and whether each candidate was inside the case root, missing, or a file.
For SQLite-backed evidence such as browser history, messenger databases, SRUM/Windows.edb exports, or app caches, `source-read` can now open a bounded read-only table locator directly from the completed run root: `rapidtriage source-read ./case-run --path Users/alice/AppData/Local/History --sqlite-table urls --sqlite-where-column url --sqlite-where-contains example --hash --json`. The payload includes row hashes, table/offset/limit metadata, a `source-read-sqlite-table-locator-v1` manifest hash, and a clear warning that deleted-row/WAL replay and trusted SQLite/schema diff are still required before report-grade use. Every `source-read` payload also includes `source_citation_package`, which provides copy-safe citation text, source locator, optional source SHA256, snippet hash, package hash, and a `Current-file hit:` review-note template so verified viewer hits can be carried into review marks or report candidates without losing provenance.

For very large result sets, API-backed tabs use cursor/offset pages and search/Case DB tables render bounded 300-row windows in the browser. Use the previous/next window controls or `[` / `]` shortcuts to move through the current result set without mounting every row at once. If the notice appears, narrow the keyword/filter set or use the paged evidence tabs to avoid browser memory pressure.

OCR sidecars are searched before engine OCR. For an image named `screen.png`, sidecars such as `screen.png.ocr.txt`, `screen.ocr.txt`, `screen.txt`, `screen.srt`, or `screen.vtt` are treated as OCR/transcript review text. This is useful for Korean OCR pipelines because external OCR output can be preserved unchanged and searched locally even if Tesseract/OpenCV are not installed.

For large image sets, create a persistent OCR queue before running external OCR:

```bash
rapidtriage ocr-queue ./case-root --output rapidtriage-ocr-queue.json
rapidtriage ocr-queue ./case-root --previous rapidtriage-ocr-queue.json --retry-failures --output rapidtriage-ocr-queue-retry.json
```

The queue records each image candidate, current OCR state, sidecar path/hash/text hash, optional sidecar metadata such as language/confidence/engine, translation sidecars such as `screen.translation.txt` or `screen.en.txt`, Korean language-pack recommendations, quality metrics, retryability, #58/#59 `core_accuracy_gates`, validation blockers, and reviewer guidance. It does not modify evidence files or run OCR by itself; use it to coordinate external OCR processing and preserve sidecar provenance. In the web source viewer, image previews expose `/source-ocr-queue` so the current image folder can be opened as a bounded OCR queue JSON with queue status counts, sidecar hashes, retry projection, and a copy-safe queue citation. For Korean text review, `/source-ocr-translation` returns a bounded side-by-side package showing original OCR text and translated sidecar text with hashes, quality metrics, truncation state, and explicit blockers for native OCR, machine translation, and certified translation evidence.

Case DB review marks can carry a reviewer, assignee, priority (`urgent`, `high`, `normal`, `low`), optional due date, tags, verification state, and report-candidate state:

```bash
rapidtriage case-review ./case.db --case-id CASE-001 --target-type artifact --target-id 3 --status relevant --verification-status source_opened --assignee analyst-a --priority high --include-in-report
```

Every Case DB review update is versioned. `case-db-report` includes both a #64 `citation_index` and each item’s #65 `review_history`, with #64/#65 `core_accuracy_gates`, so a reviewer can see when an item became report-worthy, who changed it, and which source citation the decision refers to. The #65 export also includes per-row history hashes and an export-time history head hash so the final report bundle can preserve a tamper-evident selection snapshot, while still warning that signed multi-user append-only history is not yet implemented.
Report exports also include #86 chain-of-custody workflow rows, #87 acquisition/file hash workflow rows, #88 export-time audit hash chains, #89 deterministic reproducibility hashes, #90 per-item source provenance, #91 parser-confidence scoring, #92 validation-warning metadata, and #93 legal limitation statements. Case DB report exports also summarize #96 acquisition/write-blocker metadata with row hashes and an acquisition handoff manifest, #97 timezone validation, #98 clock-skew checks, and #99 contamination warnings. Treat these as release/report evidence packages; they still need acquisition notes, write-blocker records, source validation, and analyst sign-off for formal submission.

For A/B/C evidence review, pass three or more files to `compare`; the first path is treated as the baseline and each following file becomes a pairwise comparison row:

```bash
rapidtriage compare ./baseline.txt ./host-a.txt ./host-b.txt --label baseline --label host-a --label host-b --selection-rationale "Compare the same config across hosts" --review-note "Host A matches baseline" --review-note "Host B differs" --output compare.json
```

The compare JSON includes `compare_review_profile` with input inventory, comparison review queue, selection rationale, bounded review notes, and #52 blockers for persistent notes plus binary/image/SQLite/timeline-aware semantic diff.

## Processing Transparency

The web start screen shows a run-plan preview before processing. Use `Fast first pass` first for large evidence because it keeps extraction read-only and focuses on indexing/search. Use `Standard` when you want bounded copied evidence for review, and use `Deep` only when you intentionally want uncapped extraction.

For long-running or repeated runs, use resume:

```bash
rapidtriage run ./case-root --mode hacking --output-dir ./case-run --read-only --resume
rapidtriage benchmark --output-dir ./bench-100k --file-count 100000 --resume
```

Each run writes `rapidtriage-run-fingerprint.json` and `rapidtriage-run-checkpoints.json` with #68/#70 `core_accuracy_gates`. The fingerprint includes path/size/mtime metadata, bounded per-file SHA-256 hashes, and an incremental reuse plan on resumed runs. Resume only reuses stage JSON when the bounded input fingerprint is unchanged; if source metadata or bounded content hashes change, RapidTriage disables reuse and records the reason in `safety.resume_disabled_reason`.

Run summaries also include `resource_caps`, artifact scheduler metadata, and `processing.runtime_defensibility_profiles`. Artifact parsers are isolated per kind (#71), so one parser failure is recorded in that parser output instead of aborting the whole run. Set `--memory-cap-bytes` or `RAPIDTRIAGE_MEMORY_CAP_BYTES` to stop at safe stage boundaries when RSS exceeds the cap (#72). Source previews include #73 `viewer_sandbox` metadata showing that active content is not executed and previews are read-only/bounded. SQLite and Case DB search paths expose #74 FTS/index optimization metadata, while artifact stages expose #75 parallel scheduler assessment. The runtime profile intentionally keeps commercial blockers visible until trusted crash, RSS, no-exec preview, query-plan, scheduler, and large-case validation manifests exist.

The commercial re-architecture introduces isolated Rust parser workers while keeping Python as the CLI/API/UI shell. Use `rearchitecture-status` to see which foundations are ready and which local tools are blocked:

```bash
rapidtriage rearchitecture-status --json
rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --output-dir ./commercial-readiness --json
```

For QC-prep and large-case validation evidence, use the helper commands below. These commands do not make a parser commercial-grade by themselves; they create reproducible evidence, blocker records, and trusted-diff handoff artifacts that a reviewer can attach to a case or release QC package.

```bash
rapidtriage macos-live-smoke --output-dir ./qc/macos-live --overwrite --json
rapidtriage e01-hash ./case.E01 --output-dir ./qc/e01-hash --json
rapidtriage known-answer-qc --manifest ./known-answer.json --trusted-manifest ./trusted-known-answer.json --output-dir ./qc/known-answer --json
rapidtriage sqlite-fts-benchmark --output-dir ./qc/fts-100k --record-count 100000 --json
rapidtriage large-case-readiness --case-db ./case.db --benchmark ./qc/fts-100k/sqlite-fts-benchmark.json --output ./qc/large-case-readiness.json --json
rapidtriage sqlite-wal-preview ./History --output-dir ./qc/sqlite-wal --json
rapidtriage email-external-parse ./mailbox.pst --output-dir ./qc/email-external --json
rapidtriage browser-stress --base-url http://127.0.0.1:8765 --output-dir ./qc/browser-stress --json
```

`large-case-readiness` is the Mac-first gate for large evidence sets. It combines one or more `sqlite-fts-benchmark` JSON files with an optional RapidTriage Case DB profile, then records whether 100k/1M/10M search evidence, FTS table/index metadata, p95 latency thresholds, and remaining commercial blockers are present. A failed status does not mean the tool cannot search; it means the evidence is not strong enough yet for 1TB/10TB or commercial-grade claims.

`macos-live-smoke` is designed for the analyst's current Mac. It writes a macOS collect-plan summary, redacted live artifact counts, a small triage benchmark, SQLite FTS benchmark evidence, a `large-case-readiness.json` gate built from that benchmark, and validation-tool availability. By default it stores path hashes and counts only; it does not print browser history URLs, quarantine URLs, or TCC client paths. Use `--include-path-details` only for authorized local debugging.

Use `--overwrite` only for intentionally repeated QC runs. The overwrite paths now clear stale parser exports, SQLite benchmark sidecars, and SQLite WAL safe-copy artifacts before writing fresh evidence, so reruns do not accidentally preserve old parser output as if it came from the current source.

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

Use the cursor on the next request to avoid keeping giant result arrays in the browser. Paged responses expose #78 pagination assessment metadata plus `pagination-cursor-manifest-v1` page-window IDs and manifest hashes, visible tables expose #79 bounded-DOM virtualization notices plus `ui-virtualization-manifest-v1` row-window IDs and manifest hashes, file scans report #77 bounded `duplicate_content_groups` plus a `duplicate-content-manifest-v1` not-suppressed analyst-review manifest, and repeated hash requests expose #76 in-process path/size/mtime hash-cache metadata. File scans and full web/API runs can also take analyst-supplied known-good hash feeds with `rapidtriage files ./case --known-good-hash-feed ./known-good.txt`, `rapidtriage run ./case --mode fraud --known-good-hash-feed ./known-good.txt`, or the GUI's "Known-good hash feed path(s)" field; TXT/CSV/JSON feeds, ZIP archives containing those feeds, and NSRL RDS CSV/`NSRLFile.txt` exports are accepted. For repeatable cases, build a normalized local feed first with `rapidtriage known-good-index ./NSRLFile.txt --output known-good-index.json` or `rapidtriage known-good-index ./NSRL-RDS.zip --output known-good-index.json` and pass that JSON to `--known-good-hash-feed`. Matching rows are marked by default and only hidden when `--hide-known-good` / "Hide known-good rows" is explicitly enabled, with `known_good_suppression_profile`, `known_good_match.source_detail`, and `known_good_suppressed_candidates` preserved for review. Completed-run search can also hide those known-good file hits with `rapidtriage search ./rapidtriage-run -k password --hide-known-good` or the web search checkbox "Hide known-good / NSRL file hits"; search outputs preserve `known_good_search_suppression_profile` so hidden counts stay auditable. Known-extension candidates also receive bounded magic-header checks, and PE/PDF/ZIP/SQLite/image/OLE/RAR/7z/GZIP extension mismatches are surfaced through `file_signature_profile` and `signature_mismatch_candidates`; the Files tab now shows a summary card, row badges, hidden known-good rows, NSRL row/feed source chips, and a signature-mismatch review queue. Long-running web jobs expose #80 cancellation/retry assessment, `retry_lineage_profile`, `job-partial-output-policy-v1`, and `cancellation-retry-manifest-v1` hashes; running parser cancellation is still cooperative and stage-boundary limited.

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

The Documents tab now also shows skipped extraction warnings. If a very large PDF/log/mailbox or corrupt Office/PDF file cannot be safely converted to text, RapidTriage keeps searching the remaining documents and records `extraction_errors[]` plus a GUI warning. Completed-run Search imports those same warnings into `documents.errors[]` and shows a document-error card next to OCR warnings. Treat either warning as "search was partial for these files" and use source-viewer byte-window search or a dedicated parser before concluding that a keyword is absent.

## Windows System Artifacts

On mounted or exported Windows evidence, RapidTriage now collects high-value system artifacts in addition to browser/recent-file data.

Browser and AI usage workflow:

- Browser rows normalize Chrome/Edge/Brave/Firefox history and downloads into profile-scoped history/download lists, internet usage pivots, AI service visit rows, bounded unified timeline rows, #20 `forensic_review`, and `browser_analyst_review_profile`. Chromium and Firefox are supported on Windows and macOS through local profile databases; Safari is currently macOS history-only and should not be treated as full browser-cache/session parity.
- Chromium-family cache, session, extension, sync, cookie, credential, Local Storage, and IndexedDB paths are inventoried as review candidates with file counts, total bytes, bounded sample hashes, sensitivity flags, #19 `forensic_review`, `browser_analyst_review_profile`, and strict legal/privacy warnings. RapidTriage does not decrypt cookies, passwords, tokens, or raw session secrets.
- `WebCacheV01.dat` is surfaced as `webcachev01-ese-file` with ESE header metadata, bounded URL/domain/path string pivots, `ese_page_map` page-local marker candidates, and a `webcachev01_review_profile` for the right-side detail pane. Treat these values as browser/WebView review pivots only until a WebCache ESE row/container/deleted-state decoder or trusted-parser diff confirms visit/cache/cookie semantics.
- BITS transfer stores are surfaced as `bits-qmgr-transfer-candidate` rows. If `qmgr.db` is SQLite-like, RapidTriage also emits bounded `bits-qmgr-sqlite-job-candidate` rows with table/rowid locators, URL/path/owner/state/job candidates, and row hashes so reviewers can jump from the GUI to the source SQLite context. Treat these rows as schema-guided transfer candidates until a BITS parser confirms job state, owner, retry history, and timestamps.
- OneDrive/Google Drive desktop sync databases are surfaced as `desktop-cloud-sync-db` plus bounded `desktop-cloud-sync-row-candidate` rows. The row candidates expose local path, remote/resource ID, sync status, owner/account, deleted state, timestamp candidates, and `cloud_sync_row_review_profile` so reviewers can pivot to file-system timelines before alleging upload/delete/share behavior.
- AI conversation candidates are recovered from browser storage as review-only snippets. Rows include service labels, question/answer direction, source storage kind, profile-relative path, source hashes, offset candidates, transcript pairing confidence, completeness score, orphan counts, validation checks, #21 `forensic_review`, and `ai_transcript_analyst_review_profile`. Validate against raw source files or service exports before reporting prompt/answer content; the review profile explicitly warns that these rows are not complete service-side transcripts.
- Local LLM traces are surfaced by `generic-documents` as `local-llm-artifact` and `local-llm-prompt-candidate` rows for Ollama, LM Studio, GPT4All, and local model/config/log/database paths. Prompt candidates are bounded text fragments or SQLite rows with `local_llm_review_profile`, content hashes, direction hints, and legal/report blockers; treat them as local-use pivots until app-version fixtures and conversation pairing validate the source.
- Desktop AI app stores are inventoried by `generic-documents` as `desktop-ai-app-artifact` rows when ChatGPT/OpenAI, Copilot, Claude, Gemini, or Perplexity app/cache paths contain SQLite, JSON, LevelDB, log, or metadata files. SQLite candidates are opened read-only to list bounded tables, row counts, and message-table candidates; message-like tables now emit `desktop-ai-conversation-candidate` rows with role/direction, timestamp, conversation-id hints, content hashes, and `desktop_ai_conversation_review_profile`. Treat prompt/answer content as local-row candidates until app-version schema fixtures, thread pairing, and service-export diffs validate completeness.
- Mobile vendor/iOS/Android rows include compact analyst review cards for the GUI: `mobile_analyst_review_profile` on Cellebrite/XRY/GrayKey/AXIOM-style rows and iOS backup/keychain rows, and `android_analyst_review_profile` on APK/app-data rows. Vendor export imports now include `mobile-location`, `mobile-health`, and `mobile-screen-time` rows with map/health/screen-time review profiles for alibi and device-use triage. These cards preserve source hashes, viewer locators, primary pivots, trusted-tool diff targets, "not proof of" warnings, and report blockers so reviewers can decide what to correlate before selecting evidence for a report.
- Email and cloud rows use the same review-card model. `email_analyst_review_profile`, `cloud_analyst_review_profile`, and `cloud_api_analyst_review_profile` are designed for the right-side preview/detail pane: they show the source hash, citation manifest, primary pivots, trusted-parser/provider diff targets, legal/privilege/scope questions, and clear non-claims before the analyst marks the row as evidence.
- Search analysis results include `analysis_analyst_review_profile`, which is the overview card for cluster/entity/graph/timeline/workbook/dedup review. Use it to decide where to start, then open the underlying source rows before adding anything to the report.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind browser --output browser.json
```

Event log workflow:

- Native `.evtx` files are inventoried with source hashes and parser guidance; recoverable binary record headers also emit partial `eventlog-event` rows with record ID, timestamp, record SHA256, record-size integrity checks, sequence-gap hints, extracted UTF-16 strings, first-pass BinXML token scans, inline scalar decoding for common String/ANSI/integer/bool/GUID/SID/FILETIME/SYSTIME/binary values, best-effort CDATA/character-reference/entity-reference/processing-instruction token capture, TemplateInstance IDs, TemplateInstance value spec/value decoding, substitution value fields, promoted `Event/System`, ordered duplicate-preserving `EventData` sequences, grouped EventData values by name, and `UserData` fields, rendered previews where possible, channel/provider/computer/command/IP/user SID candidates, explicit `evtx_binxml_status`, `evtx_recovery_context`, and suspicious-term flags. Native `eventlog-chunk` rows expose chunk bounds, slack offsets, and checksum observations to help review deleted/corrupt candidates. Treat native rows as triage pivots unless an EVTX-capable export validates complete provider message rendering.
- XML/JSON/JSONL/CSV exports from EVTX-oriented tools such as EvtxECmd, Hayabusa, Chainsaw, and Velociraptor are normalized into event rows.
- Event rows include `event_message` and `message_rendering` provenance. Exported/rendered messages are preserved when present; native EVTX rows can use built-in high-value fallback templates for common Security, PowerShell, and log-clear events. The collector also auto-discovers bounded case-local provider catalogs: `.man` files, plus JSON/XML files with message-catalog/provider-manifest naming hints. Use `--eventlog-message-catalog` when you need to supplement or override discovered entries with a curated JSON catalog or Windows Event Manifest XML (`.man`/`.xml`) string table. Catalog templates support named `{Field}` placeholders and Windows-style positional `%1`, `%2` placeholders using ordered EventData/TemplateValue values. Native fallback messages are marked validation-required until provider message resources or trusted-tool rendered-message diffs are resolved.
- Slack/deleted/corrupt EVTX recovery is cautious by design. Parseable rows can be labeled `slack-or-deleted-record-candidate` when chunk free-space metadata supports that interpretation, and invalid record headers emit `eventlog-record-candidate` rows with offsets, size checks, confidence, and `do-not-report-without-validation` caution labels.
- Important Event IDs and provider families such as logons, failed logons, privileged logons, process creation, scheduled task creation, service installation, log clearing, PowerShell script blocks, RDP sessions, WMI, Defender, Firewall, USB/device, WLAN AutoConfig, PrintService, BITS Client, share access, and Sysmon events are categorized with `event_family`, `channel_family`, `event_tags`, parser confidence, source hashes, and triage recommendations. Provider-specific pivots expose `device_instance_id`, `ssid`/`interface_guid`, `document_name`/`printer_name`, and BITS `job_id`/`remote_name`/`local_file` fields so GUI reviewers can jump from EventLog evidence to USBSTOR/MountedDevices/SetupAPI, WLAN profile XML/NetworkList, SPL/SHD spool files, and qmgr stores. Each event row also emits `event_semantics_profile`, which gives analyst-facing severity, review questions, primary pivots, populated source field values, correlation targets such as Prefetch/Amcache/MFT/USN/Defender/TaskCache, risk tags, and validation requirements so the GUI/search/report workflow can explain what to check next without treating a native EVTX row as final testimony.
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
- `windows-registry` summarizes Run-key persistence values, suspicious command/value hints, and USBSTOR device metadata from `.reg` exports. It also inventories native hive candidates such as `NTUSER.DAT`, `UsrClass.dat`, `SYSTEM`, and `SOFTWARE` with source hashes, `regf` header fields, sequence/dirty hints, last-write timestamp, bounded string pivots, hbin-aware `nk`/`vk` hive cell candidates, best-effort `registry-key-tree-node` rows, separate deleted/free-cell candidate rows, key-specific `registry-key-recovery-candidate` rows, and value-specific `registry-value-recovery-candidate` rows for review. NTUSER/UsrClass user-hive activity pivots are promoted as `registry-user-activity` rows for UserAssist, TypedURLs/TypedPaths, RecentDocs, Run/RunOnce, Explorer/MRU, ShellBags, MountPoints2, Network, and ComDlg32/OpenSavePidlMRU review. Key-tree, deleted/free-cell, and user-activity rows include `registry_analyst_review_profile` so the GUI can show severity, review questions, primary pivots, populated source values, correlation targets, transaction-log status, validation requirements, and commercial blockers next to the raw source/citation.

Use:

```bash
rapidtriage artifacts ./mounted-case --kind windows-os-account --output os-account.json
rapidtriage artifacts ./registry-exports --kind windows-registry --output registry.json
```

Recent/LNK workflow:

- Recent shortcut rows parse Shell Link metadata when available, including target path, working directory, command-line arguments, target timestamps, link flags, file attributes, source hashes, and embedded path pivots. Each parsed shortcut now includes `lnk_analyst_review_profile` so the GUI/report flow can show target/working-directory/tracker pivots, "not proof of" caveats, LECmd diff blockers, and ShellBags/MFT/USN correlation targets beside the row.
- Jump List files are inventoried as automatic/custom destination containers; recoverable OLE/CFB streams are listed, and embedded Shell Link records are promoted into destination rows with stream provenance, stream hashes, target paths, working directories, target timestamps, link flags, and offsets. Automatic Jump Lists also expose bounded DestList header/entry metadata candidates with validation checks, `jumplist_analyst_review_profile`, analyst pivots, ShellBags/MFT/USN/Windows Search correlation targets, and explicit commercial blockers when full OS-version-specific field decoding is not yet report-grade. When stream parsing is not possible, RapidTriage falls back to embedded path extraction for search triage.

Remote access workflow:

- `windows-remote-access` extracts RDP connection files, including full address, username hint, gateway host, and modified time.
- Terminal Server Client cache files are inventoried with hashes, timestamps, and bounded PNG/JPEG/BMP/DIB thumbnail signature pivots so analysts can preserve and review RDP thumbnail/cache evidence without forcing heavy decoding up front.
- Exported Terminal Server Client registry keys are normalized into `rdp-destination` rows for quick destination pivots.
- Third-party remote-control traces for AnyDesk, TeamViewer, RustDesk, and Chrome Remote Desktop are also surfaced in the remote-access workflow as `third-party-remote-control-artifact` rows with product tags, bounded string samples, URL/IP pivots, `remote_control_session_profile`, session candidates, remote ID candidates, file-transfer indicators, risk flags, hashes, and explicit report-grade blockers for missing product-specific state validation.

Execution and filesystem workflow:

- `windows-execution` imports Amcache/ShimCache/UserAssist/BAM-style `.reg` exports, scans native `Amcache.hve` for bounded path/hash candidates, and imports PowerShell console history. Amcache, ShimCache, BAM/DAM, and SRUM rows expose #7~#10 `core_accuracy_gates` showing which required validation checks are satisfied and which commercial-grade blockers remain. They also emit `execution_analyst_review_profile` so the reviewer sees severity, "not proof of" caveats, primary pivots, populated source values, and the exact artifacts to correlate before reporting.
- `windows-execution-summary` groups execution-related signals by executable path or command subject so the analyst can pivot from one program to all related BAM/UserAssist/ShimCache/PowerShell rows.
- `windows-prefetch` parses SCCA Prefetch headers for executable hints, version-specific common-layout metadata, best-effort run counts, last run timestamps, run-count/last-run validation checks, referenced path pivots, bounded volume/file-reference candidates, and separate `prefetch-reference` rows. Rows include `prefetch_analyst_review_profile`, which tells the reviewer which executable/run-count/last-run/path pivots are populated, which Amcache/MFT/USN/SRUM correlations should be checked, and why Prefetch alone is not standalone execution attribution. Treat these as triage leads: RapidTriage now records explicit commercial blockers where full file metrics, authoritative volume tables, trace chains, directory sections, MFT file references, or validation corpus coverage are incomplete.
- SRUM CSV/JSON/JSONL/NDJSON exports from trusted tools can be imported as app resource or network usage rows with bytes totals, interface/profile, energy, user, timestamp, and source hashes; `SRUDB.dat` is also preserved with ESE header and native validation metadata, bounded string/path/URL pivots, native `srum-database-pivot` rows, `srum-table-candidate` rows, and bounded `srum-row-candidate` string-cluster rows for app/network/energy/user review. Treat native SRUDB candidates as validation-required until a dedicated SRUM/ESE parser confirms tables, counters, and timestamps.
- `windows-search-index` inventories `Windows.edb` with ESE header metadata, bounded string/path/URL/content pivots, native validation metadata, explicit commercial-readiness blockers, separate `windows-search-edb-pivot`, `windows-search-edb-page-candidate`, and `windows-search-edb-table-candidate` rows, and correlated `windows-search-edb-row-candidate` rows that pair path/URL/content strings for review while clearly marking timestamp/deleted-state gaps. Page candidates preserve ESE page index, byte offset, page SHA256, page-local table marker hits, and page-local path/URL/content/risk strings so reviewers can jump back to a stable source location. Rows now include `windows_search_analyst_review_profile` so the UI can show not-proof-of warnings, source pivots, and MFT/USN/browser/document correlation targets beside each hit. It also imports Windows Search CSV/JSON exports so indexed filenames, paths, URLs, titles, and content snippets can be searched alongside documents and artifacts.
- `kakaotalk-windows` is a PC KakaoTalk triage view that follows the same style used by commercial tools: it inventories KakaoTalk application `.edb`/`.db`/`.dat` stores first, preserves DB/WAL/SHM/copy hashes, labels likely roles such as chat log, chat list, profile, contact, media, login state, and post-BigBang adjacent indexes, then checks `Windows.edb`, Registry exports/native hives, and memory dumps together. It emits KakaoTalk source candidates with source hash, source family, matched term, path/URL/process/chat-store classification, ESE page hash/offset where available, and privacy/legal warnings. Use it to find and preserve KakaoTalk install/profile/chat-store/process traces, not as final decrypted message testimony.
- `kakaotalk-macos` adds the MacBook-side KakaoTalk triage path. It scans known macOS sandbox/application-support roots such as `~/Library/Containers/com.kakao.KakaoTalkMac*/Data` and `~/Library/Application Support/Kakao*`, inventories `.db`/`.sqlite`/`.sqlite3`/`.edb`/`.dat` candidates plus extensionless 78-character hash-named store files, preserves source hashes and WAL/SHM companions, tests whether each DB opens as plain SQLite, and records table names, row counts, schema samples, message-table candidates, and estimated message-row counts without exporting message text. If a DB does not expose a SQLite header, RapidTriage now tries the public Mac KakaoTalk SQLCipher workflow: collect plist `AlertKakaoIDsList`/revision/user-directory evidence, derive candidate DB names and keys from `IOPlatformUUID + UserID`, and run `sqlcipher` in read-only mode with compatibility 3/4. Raw UserID/key values are not written to JSON; only hashes, match counts, and schema/count evidence are recorded. If UserID cannot be recovered automatically, set `RAPIDTRIAGE_KAKAO_MAC_USER_ID` or `RAPIDTRIAGE_KAKAO_MAC_USER_IDS`; for mounted images set `RAPIDTRIAGE_KAKAO_MAC_UUID` to the source Mac `IOPlatformUUID`. The optional `RAPIDTRIAGE_KAKAO_MAC_SHA512_BRUTE_MAX` gate enables bounded UserID recovery from the 40-hex user-directory SHA512 slice, but keep it off for normal large case scans unless you intentionally budget the brute-force time. Use `rapidtriage artifacts ./mounted-mac-or-home --kind kakaotalk-macos --output kakaotalk-macos.json` to check whether Mac KakaoTalk DB analysis is possible on the current case. When an authorized reviewer needs usable outputs, run `rapidtriage kakaotalk-macos-report ./mounted-mac-or-home --output-dir ./kakao-mac-report`; it writes summary/report JSON, messages/rooms/media CSVs, an audit sidecar, and a static no-script HTML viewer. Message text stays redacted by default; add `--include-message-text` only for authorized review exports. Room/user context tables are exported up to `--max-context-rows` per table, and any truncation is shown in CLI output, `summary.context_limit_reached`, `context_row_coverage[]`, and the HTML viewer warning panel so large KakaoTalk cases do not fail silently. If the UserID was recovered by a separate authorized helper, pass it through a protected file with `--user-id-file ./uid.txt` so the raw value is read in memory rather than typed into the command line.
- For legacy Windows KakaoTalk research workflows, the collector also records decryption-readiness metadata: whether an app DB looks like an encrypted/custom store rather than plain SQLite, whether its size is aligned to 4096-byte pages, whether a successful authorized decoder should produce a `SQLite format 3` header, whether `DeviceInfo` context candidates such as `sys_uuid`, `hdd_model`, and `hdd_serial` are present in registry exports or native hives, and whether registry account identifier candidates such as `talk_user_id`, `tuid`, `uuid`, or `dev_id` exist. Sensitive device/account identifiers are redacted and hashed. RapidTriage does not ship or extract a proprietary KakaoTalk application key and does not attempt message decryption by default.
- `kakaotalk-decrypt` is a separate authorization-gated command for Windows KakaoTalk `chatLogs_*.edb` files. It accepts direct `--key-hex/--iv-hex`, `--pragma/--user-id`, or the research workflow `DeviceInfo + pragma-key + userId` material. Prefer environment variables such as `RAPIDTRIAGE_KAKAO_KEY_HEX`/`RAPIDTRIAGE_KAKAO_IV_HEX`, `RAPIDTRIAGE_KAKAO_PRAGMA`/`RAPIDTRIAGE_KAKAO_USER_ID`, or `RAPIDTRIAGE_KAKAO_PRAGMA_KEY_HEX` plus `RAPIDTRIAGE_KAKAO_USER_ID` to avoid shell history. When using the DeviceInfo workflow, RapidTriage can read `sys_uuid`, `hdd_model`, and `hdd_serial` from `NTUSER.DAT`, derives multiple research-backed pragma variants from the externally supplied pragma-key, then derives DB key/IV from pragma+userId. If exactly one high-confidence userId is found, it can use it internally; if multiple candidates exist, it tries candidate-derived keys and accepts only the one that produces the expected SQLite header. It decrypts 4096-byte AES-CBC pages, confirms the `SQLite format 3` header, opens the decrypted DB read-only, identifies message-table candidates, counts rows, and only includes bounded message previews when `--include-message-preview` is explicitly set. Without complete authorized material it still reports the chat DB count and which material is missing.
- `scripts/kakaotalk_zip_to_report.py` is the operator-facing PC KakaoTalk report wrapper. It accepts ZIP, extracted folders, and single evidence files such as `NTUSER.DAT` or `DMG` inputs; non-ZIP archives are accepted as evidence metadata with a clear "extract first" note. ZIP extraction rejects path traversal, symbolic links, oversized members, excessive total uncompressed size, and suspicious compression ratios. The report writes `kakaotalk_summary.json`, room/message/media CSVs, and `kakaotalk_database_counts.csv` so analysts can distinguish `raw_recovered_message_row_count` from `visible_message_count`. This matters on large cases because a DB can be opened and counted even when the bounded viewer/CSV only shows the displayable subset.
- `kakaotalk-key-store-inspect` is the post-BigBang EDB key-store mapping command. It parses `appstate.dat` and `appstate.dat.backup` as definite-length CBOR, reports `info_prefix`, salt length/hash, `wrapped_dek_map` entry counts, chatLog-to-wrapped-DEK matches, matched EDB file hashes, and optional memory-residency checks. Raw wrapped DEKs, unwrapped DEKs, KEKs, and candidate secrets are never exported. A `key-store-mapped` result means the next reverse-engineering step is KEK/IKM recovery and wrapped-DEK unwrapping, not the legacy PRAGMA workflow.
- `windows-filesystem` imports MFT/USN CSV, JSON, JSONL, or NDJSON exports from trusted external tools; it also inventories native `$MFT` and `$J`/USN journal files with hashes, bounded record/header samples, path pivots, separate native MFT rows with common attribute/timestamp/update-sequence validation metadata, `mft_record_evidence`, bounded parent-chain path candidates for records whose parents are present in the scanned `$MFT` window, and explicit commercial-readiness blockers, plus recoverable native USN rows with cursor/next-cursor, large-record metadata, `usn_record_evidence`, validation metadata, and bounded MFT path correlation when the USN FRN or parent FRN matches a scanned MFT record. MFT/USN rows include `ntfs_analyst_review_profile` to show whether the row is a path/content/timeline pivot, what it cannot prove, and which MFT/USN/search/execution artifacts should be checked next. Journal inventory rows also include `bounded_mft_replay_preview` counts/path samples, `mft_bounded_path_cache_profile` quality counts/warnings, `usn_path_reliability_profile` review confidence, `usn_state_replay_validation_profile` validation gating, `rename_pair_preview` candidates, `delete_lifecycle_preview` create/delete candidates, `bounded_state_replay_preview` state-transition samples, and `timeline_review_candidates` for bounded rename/create/delete timeline pivots so large `$J` review can start from correlated create/delete/rename leads. Rename previews prefer parent-cache plus USN OLD/NEW names for event-time path candidates and keep the raw FRN/MFT correlation side-by-side for source review. The bounded state replay is useful for reviewer navigation, but not a report-grade full journal replay; the UI shows the same state validation wording so analysts do not mistake record-level trusted diff for state-machine replay validation. Treat bounded parent-chain, rename-pair, delete-lifecycle, state-replay, timeline-review, and USN-correlated paths as analyst navigation aids until a full-volume path cache, complete journal replay, and trusted parser diff confirm them.
- In the web workbench, MFT/USN rows now surface these bounded path, replay, and rename-pair candidates in the artifact preview/detail cards instead of requiring analysts to open raw JSON first. When source paths and offsets/cursors are available, the same card exposes `source-hex-range` locator links with hashes so an analyst can jump from a candidate rename/path lead back to the raw `$MFT`/`$J` byte range.

Windows, browser, image-adapter, mobile, iOS, Android, email, and cloud rows for #6~#45 now also include shared review objects where applicable. `forensic_review`, `chat_app_forensic_review`, and sensitive-artifact review fields give reviewers a consistent quick read of the backlog gap ID, artifact goal, triage/commercial status, primary evidence strings, blockers, caveats, and the next validation step before adding an item to a report.
- These rows are labeled as triage/reportability hints so weak artifacts such as ShimCache are not overclaimed as proof of execution.

Use:

```bash
rapidtriage artifacts ./mounted-case-or-export --kind windows-execution --output execution.json
rapidtriage artifacts ./mounted-case --kind windows-prefetch --output prefetch.json
rapidtriage artifacts ./mft-usn-export --kind windows-filesystem --output filesystem.json
```

Other Windows system artifacts:

- SetupAPI USB install rows include `usb_device_review_profile` so the GUI can show parsed USB family, storage vendor/product/revision, serial-number candidate plus hash, first/last install-context timestamp hints, and correlation targets for USBSTOR, Enum USB, MountedDevices, `$MFT`, and `$UsnJrnl`. Treat these as install evidence until registry and filesystem timelines confirm connection time, drive letter, and file-copy activity.
- WLAN profile XML rows include `wifi_profile_review_profile` with interface GUID, security level, hidden-network flag, auto-connect status, MAC randomization, and whether credential material exists. Raw Wi-Fi key material is redacted and only length/presence is exposed; actual connection/physical-presence claims still require WLAN-AutoConfig EVTX/ETL and NetworkList registry correlation.
- Task Scheduler XML tasks, including normalized action/trigger/principal metadata, command line, executable name, author, user SID, trigger type, start boundaries, hidden/run-level/logon hints, source hashes, validation checks, commercial-readiness blockers, `system_analyst_review_profile`, and risk flags for suspicious LOLBin commands, encoded PowerShell, user-writable payload paths, and Microsoft-path masquerading.
- Windows Defender `MPLog*.log` support logs, with threat/remediation/exclusion-looking lines highlighted and `system_analyst_review_profile` reminders that support-log hits require Defender EVTX/quarantine/policy correlation before final malware conclusions. Defender policy exports such as `.reg` files under Windows Defender paths or `Get-MpPreference` text dumps also emit `defender-policy-artifact` rows with `defender_policy_profile`, exclusion entries, disabled protection entries, TamperProtection candidates, risk flags, hashes, and explicit EVTX 5007/registry transaction/admin attribution blockers.
- Windows Firewall W3C logs, including blocked connection counts, sample rows, and `system_analyst_review_profile` pivots for Firewall policy store, event log, SRUM, browser, and socket/process correlation.
- Windows Error Reporting `Report.wer` files, including normalized crashed app/module paths, exception code, report ID, event time, problem signature values, source hashes, validation checks, `system_analyst_review_profile`, and explicit blockers when dump/cab/ReportQueue validation is not available.
- WMI repository files such as `OBJECTS.DATA` are inventoried with hashes plus bounded string pivots for permanent event consumer/filter names, suspicious commands, paths, URLs, WMI persistence risk flags, and `system_analyst_review_profile` warnings that native WMI binding reconstruction is still required for report-grade persistence claims.
- Print Spooler `.SPL`/`.SHD` rows include `print_spooler_job_profile` with bounded document-name, printer-name, owner/user, and source-path candidates. They also include `print_spooler_companion_profile` so the GUI can show whether the SHD metadata file and SPL payload file are both present for the same job id. They remain triage-grade until correlated with PrintService EVTX, `$MFT`/`$UsnJrnl`, and source document metadata.
- OOXML/ODF documents emit `document-metadata-risk` rows with author/timestamp candidates, `metadata_profile`, `macro_profile` for `vbaProject.bin`/script presence, and external relationship targets such as remote templates. Treat these as leakage/macro triage pivots until legacy OLE parsing, macro static analysis, sandboxing, and trusted parser diffs validate the document family.
- Sticky Notes `plum.sqlite` rows include `sticky_note_schema_profile` and `sticky_note_review_profile` so the GUI can show note table/column readiness, deleted-state status, account/email hints, and source-viewer blockers. The collector also emits `sticky-note-recovery-candidate` rows from bounded SQLite string fragments that are not present in live note rows; treat them as recovery leads until verified in the SQLite/hex viewer or a trusted parser diff.
- Windows Recall/CoreAIPlatform candidates are exposed as `windows-recall-database` and `windows-recall-snapshot-file` rows. SQLite-like Recall DB candidates are opened read-only for bounded table, row-count, and semantic table-role metadata; snapshot files are inventoried by path, hash, signature, and profile attribution. Recall rows always carry legal/privacy warnings and remain triage-grade until real Windows 11 Recall corpus validation, protected-store authority, and snapshot-to-DB linkage are attached.
- Zone.Identifier sidecar exports, including ZoneId, referrer URL, and host URL.
- ADS exports are also surfaced by `windows-filesystem` as `ads-stream-candidate` rows. This catches `file:Zone.Identifier`, `file.Zone.Identifier`, and arbitrary named streams such as `file:hidden.ps1:$DATA`, with host-file presence, stream family, source hash, bounded preview, source hex locator, and flags for download provenance, suspicious stream names, script streams, and embedded PE/PDF/ZIP signatures. Treat these as stream-export review leads until the original NTFS image, MFT/USN `STREAM_CHANGE`, and the extraction manifest confirm the native stream.
- ZIP/RAR/7z files are surfaced as `archive-file-inventory` rows before extraction. ZIP central-directory metadata is read safely to show encrypted entries, path traversal risks, executable/script entries, nested archives, compression ratio, and `archive_review_profile`; RAR/7z currently remain metadata-only. Use this to decide whether an archive should go through a sandboxed recursive extraction/password workflow before content search.

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

The collector records file hashes, dimensions, channel count, an average perceptual hash, a short similarity bucket, a bounded inline PNG thumbnail preview, and whether the file should be queued for OCR. The perceptual hash avoids optional NumPy aggregate helpers so image grouping remains more tolerant of mixed OpenCV/NumPy installs; thumbnail generation is isolated so a preview failure does not abort artifact collection. If a sidecar such as `image.png.ocr.txt`, `image.ocr.txt`, or `image.txt` exists, it records sidecar hashes, bounded OCR text, Korean/English language hints, and whether translation review is required. Image rows also expose `exif_gps_profile` and `exif_map_review_profile` for EXIF GPS latitude/longitude/altitude/datetime map pivots, plus `steganography_suspicion_profile` and `media_authenticity_profile` so the GUI can queue location, trailing-data, embedded payload signature, AI-generation metadata, and editing-tool metadata candidates for review. These fields are suspicion/review pivots only: EXIF GPS does not prove the user was physically present, and the perceptual hash, visual classification, steganography profile, and authenticity profile are not courtroom-grade similarity, hidden-message, deepfake, or manipulation conclusions by themselves.

## Memory Forensics Imports

RapidTriage can import Volatility/Volatility3 JSON or JSONL output for review and search. Export plugins such as `pslist`, `cmdline`, `netscan`, or `malfind`, then point the collector at the folder:

```bash
rapidtriage artifacts ./volatility-output --kind memory-volatility --output memory-artifacts.json
```

The importer normalizes process name, PID/PPID, command line, network endpoints, offsets, source hashes, and risk flags such as suspicious command lines, external network connections, malfind rows, and writable executable memory.

The same collector also performs a bounded direct scan of `.mem`, `.raw`, `.vmem`, `.vmss`, `.vmsn`, `.hpak`, `.dmp`, and memory-named `.bin` dumps. It records source hashes, scan ranges, redacted BitLocker recovery-key candidates with SHA256 verification hashes and group-level checksum validation, suspicious process string candidates, suspicious memory strings, URLs, IPs, and risk flags without claiming full process reconstruction.

## Cloud Export Imports

RapidTriage can normalize cloud exports that were already lawfully exported or collected by another workflow. For Google Takeout-style folders, it recognizes Location History `Records.json` and My Activity JSON. For Apple/general account exports, it records account profile fields from JSON. ZIP provider exports are now inventoried without extraction as `cloud-export-archive` rows so the original archive SHA256, bounded entry manifest, provider/product counts, JSON entry counts, and archive-scope blockers can be reviewed before parsing individual rows.

```bash
rapidtriage artifacts ./cloud-export --kind cloud-export --output cloud-artifacts.json
```

The collector records source hashes, timestamps, activity titles/products, account profile fields, location coordinates, accuracy, and risk flags such as precise location or user activity. It also normalizes Gmail/Drive-style mail and file JSON, Apple/iCloud account/file/photo-style JSON, Microsoft 365/OneDrive/Teams/Audit JSON, and collaboration-SaaS message/file-style JSON into mail, file, chat message, and audit pivots with `cloud_provider_profile`, `cloud_issue_matrix`, and validation blockers. ZIP archive rows include `cloud_archive_manifest`, `cloud_archive_manifest_hash`, product counts such as Gmail/Drive/Location/Teams/OneDrive/iCloud, and `core_accuracy_gates` evidence refs for GUI/report citation. It does not perform unrestricted live cloud acquisition, provider-side deletion recovery, permission graph reconstruction, split-archive completeness proof, or eDiscovery validation.

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

`benchmark` records #66 scale-target metadata for 100k, 1M, and 10M record claims, including p50/p95 search latency, raw latency samples, records/sec, peak memory, run-summary links, environment profile, internal release-threshold guardrail status, #66 `core_accuracy_gates`, and validation blockers. `columnar-benchmark` writes synthetic `ArtifactRecordV1` rows to JSONL, scans the JSONL baseline for p50/p95 query timing, records platform/Python/dependency versions, writes Parquet in row groups when `pyarrow` is installed, and runs DuckDB Parquet query timing when `duckdb` is installed. `columnar-convert` promotes real `worker-parse` JSONL into row-grouped Parquet when `pyarrow` is installed, preserving input SHA256 and a conversion manifest. Attach columnar benchmark evidence to release checks with `python scripts/verify-release-evidence.py --columnar-benchmark-dir ./columnar-benchmark ...`; the verifier checks JSONL metrics, environment capture, optional Parquet/DuckDB evidence, and the required warning that synthetic runs do not prove commercial readiness by themselves. `stress-plan` does not generate terabytes of synthetic evidence. It writes a #67 repeatable 1TB-10TB validation runbook with wall-clock estimates, output reserve, checkpoint interval, resource caps, stop thresholds, required evidence bundle, run-log templates, and telemetry/evidence capture requirements.

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

The package writes JSON, Markdown, and a validation artifact hash manifest. It lists required checks, #81 NIST CFReDS/CFTT-style known-answer datasets, #82 parser fixture corpus coverage, #83 parser-specific false-positive/false-negative notes, #84 independent validation report SHA256, #85 validation-package automation metadata, user-facing documents, known limitations, chain-of-custody expectations, release artifact requirements, signing/notarization evidence, and support SLA template. The final package self-assessment records that the required JSON, Markdown, and artifact-manifest outputs exist, while the separate artifact manifest records SHA256/size evidence for the generated JSON and Markdown files. Treat it as the release evidence checklist that should sit next to benchmark output, sample-case output, checksums, SBOM/dependency inventory, and build artifacts.

Use `rapidtriage validation-diff-runners --json` to print the #76~#81 trusted-tool runner matrix. The matrix records the NIST CFReDS/CFTT-style public corpus evidence contract plus EVTX, Registry, NTFS, ESE, and execution/user-activity trusted-tool command templates for EvtxECmd, Hayabusa, RECmd, Registry Explorer, MFTECmd, analyzeMFT, UsnJrnl2Csv, SrumECmd, libesedb, Windows Search DB Analyzer, PECmd, JLECmd, and ShellBagsExplorer/SBECmd. It also preflights whether those binaries are on `PATH` and lists the required `cross-tool-validate` metadata flags: source evidence hash, tool version, tool command, independent report, and corpus scope. If trusted tools live outside `PATH`, add one or more `--search-path <dir>` flags. Add `--probe-versions` only in an analyst-controlled environment; it runs detected tools with bounded version probes, captures output previews/hashes, and makes the runner matrix easier to attach as QC setup evidence.

Use `rapidtriage final-qc-report --validation-package ./validation/rapidtriage-validation-package.json --runner-matrix ./runner-matrix.json --chain-of-custody ./custody.json --audit-bundle ./tamper-bundle.json --exhibit-bundle ./exhibit.zip --performance-run ./benchmark.json --browser-trace ./trace.json --reviewer-signoff ./review.md --output ./final-qc.json --json` to generate the #81~#90 QC wrapper. The report hashes attached validation, runner, custody, audit, exhibit, performance, browser, and reviewer files, then emits the Windows 11 E01 known-answer contract, adverse fixture corpus contract, large-case/browser-trace contract, legal submission QC contract, final report sections, and a pass/fail checklist. A clean checklist means the QC evidence bundle is ready for human review; it is still not a commercial-grade claim until the attached external evidence itself passes.

Use `rapidtriage commercial-readiness --output-dir ./commercial-readiness --json` to track the full 120-item parity backlog. Each item is now scored through four gates: `implemented`, `usable`, `validated`, and `commercial_grade`. Do not describe an item as commercial-grade until the report shows all four gates passing for that item. The report also emits `priority_work_plan`, `next_gate_samples`, and `next_gate_blocker_counts` so reviewers can choose the next work item by evidence instead of intuition. It now also emits `commercial_uplift_plan`, a prioritized 70-goal execution plan split into five-item batches; each goal includes the objective, implementation track, acceptance evidence, external blocker status, and large-data processing strategy. To tune that plan, run `rapidtriage commercial-readiness --uplift-targets 70 --uplift-batch-size 5 --output-dir ./commercial-uplift --json`. To focus on validation blockers, run `rapidtriage commercial-readiness --next-gate validated --limit 10`. To plan the next validation batch, run `rapidtriage commercial-readiness --next-gate validated --limit 5 --write-known-answer-template ./known-answer-runs.template.json`; the generated datasets stay `status: "not-run"` until a real known-answer or cross-tool validation run fills evidence paths and assertions. To cover the full backlog in repeatable five-item batches, run `rapidtriage commercial-readiness --template-items 1-120 --template-batch-size 5 --write-known-answer-template-dir ./known-answer-batches`. If known-answer evidence is available, pass `--validation-package ./validation/rapidtriage-validation-package.json`; repeat `--validation-package` to combine multiple batch manifests in one readiness run, for example `rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-025-known-answer.json --validation-package docs/validation/rapidtriage-core-forensics-026-030-known-answer.json --json`. Only datasets marked `status: "pass"` with explicit `backlog_items`/`commercial_items` mappings and present evidence paths can satisfy an item's `validated` gate, and commercial blockers still remain until separately resolved. For the first core-forensics validation blocks, the repository now ships `docs/validation/rapidtriage-core-forensics-001-025-known-answer.json` and later batch manifests; attach them together to move internally validated items to the `commercial_grade` next gate while keeping native-parser and external-corpus blockers visible.

For focused execution through the full #1~#120 readiness backlog, run `rapidtriage forensic-validation-plan --items 1-120 --output-dir ./forensic-validation-plan --json`. By default the command now covers #1~#120, not just the first 65 user-facing forensic features. It writes a JSON/Markdown matrix with each item's lane, current maturity, next required gate, required checks, next internal work, external evidence requirements, and five-item execution batches. The command does not mark the items commercial-ready; it prevents vague "done" claims by turning the whole backlog into a repeatable implementation and validation queue.

For a concrete five-item execution bundle, run `rapidtriage forensic-validation-pack --items 1-5 --output-dir ./evtx-registry-validation-pack --json`. The pack writes a machine-readable dataset template, trusted-reference command checklist, required row-level diff fields, source/reference hash placeholders, and pass/fail contract for EVTX/Registry validation. This is the preferred handoff artifact before claiming #1~#5 progress because it forces source evidence, RapidTriage output, independent reference output, diff output, and reviewer sign-off to exist as separate files.

After the evidence paths are populated in `rapidtriage-forensic-validation-pack.json`, run `rapidtriage forensic-validation-pack-assess --pack ./evtx-registry-validation-pack/rapidtriage-forensic-validation-pack.json --output ./evtx-registry-validation-pack/assessment.json --json`. The assessment checks source/RapidTriage/reference/diff/sign-off path presence, optional SHA256 expectations, row-level diff status, mismatch counts, and whether the pack is ready for the validated gate. It still keeps commercial-grade false unless the underlying cross-tool validation output also contains commercial-grade evidence such as source hashes, tool versions/commands, corpus scope, and independent sign-off.

To run this process across the full backlog, use `rapidtriage forensic-validation-batches --items 1-120 --output-dir ./forensic-validation-batches --json`. This writes the global plan plus twenty-four five-item pack folders. After each pack has evidence paths and cross-tool diff outputs, run `rapidtriage forensic-validation-batches-assess --root-dir ./forensic-validation-batches --output ./forensic-validation-batches/assessment.json --json` to aggregate every pack's validated/commercial readiness without silently skipping unpopulated items.

For CI or plumbing verification only, `rapidtriage forensic-validation-smoke-populate --root-dir ./forensic-validation-batches --output ./forensic-validation-batches/smoke-manifest.json --json` fills all generated packs with deterministic synthetic source/RapidTriage/reference/diff/sign-off files and reruns the aggregate assessment. This should produce `ready_dataset_count=120` for the default `--items 1-120`, proving the validation loop is wired end-to-end. It must not be used as commercial or court validation because the evidence is synthetic internal smoke data.

When real external validation files are available, create a JSON manifest with one `datasets[]` entry per `dataset_id` and `evidence_paths` for `source_evidence`, `rapid_output`, `trusted_reference_output`, `row_level_diff_output`, and `reviewer_signoff`, then run `rapidtriage forensic-validation-evidence-import --root-dir ./forensic-validation-batches --manifest ./external-evidence-manifest.json --output ./forensic-validation-batches/external-import.json --json`. Evidence paths may be absolute or relative to the manifest file. A complete external manifest for the default `--items 1-120` should produce `external_ready_dataset_count=120`; `rapidtriage forensic-validation-batches-assess --root-dir ./forensic-validation-batches --strict-external` then exits `0`. If any dataset is missing real external evidence, `--strict-external` exits non-zero.

For trusted-tool validation, use `rapidtriage cross-tool-validate --rapid-output ./case-run/artifacts/eventlog.json --reference-output evtxecmd=./EvtxECmd.csv --source-evidence ./Security.evtx --tool-version evtxecmd="EvtxECmd 1.5.0" --tool-command evtxecmd="EvtxECmd.exe -f Security.evtx --csv out" --independent-report ./independent-review.md --corpus-scope "NIST Security.evtx plus local corrupt-record fixture" --backlog-item 1 --backlog-item 2 --output ./evtx-cross-tool.json --json`. When the comparison passes and the output JSON exists, that report can be supplied directly as `commercial-readiness --validation-package ./evtx-cross-tool.json`; the embedded dataset maps the evidence to the selected backlog items. The report preserves SHA256/size/mtime for source, independent review, RapidTriage output, and reference output paths, plus tool version/command metadata and corpus scope. For EVTX-style rows it now adds `record_field_comparison`, which compares common fields such as EventRecordID, EventID, provider, channel, computer, and event time for overlapping records so a key-overlap pass cannot hide field-level parser mismatches. Use this for EVTX/Registry/MFT/USN-style external comparisons; USN validation now includes `usn_state_replay_field_comparison`, which expands nested `bounded_state_replay_preview.transitions` rows and compares transition, previous/new path, timestamp, file name, cursor, and state effect against known-answer replay CSV/JSON rows. The report also emits `validation_qc_contract` (`validation-qc-controls-v1`) with a trusted-diff mismatch dashboard, FP/FN recording schema, parser confidence/reportability matrix, legal limitation guardrails, and an automatic QC checklist. The report-level commercial-grade envelope can pass, but item-level commercial grade still depends on the backlog item's remaining native-parser and external-corpus blockers.

`cross-tool-validate` now treats input quality as part of the validation gate. If either side is truncated by the row cap, contains duplicate record keys, or cannot produce stable row keys, the comparison fails even when overlap looks high. Re-export or split the affected parser output before using the diff as validation evidence; otherwise duplicate IDs or capped files can hide missing rows in a large EVTX/MFT/USN/Registry corpus.

To start a USN state replay validation dataset, run `rapidtriage usn-state-replay-template --output ./usn-state-replay-known-answer.csv --json`. This writes a UTF-8-SIG CSV plus `.manifest.json` sidecar with the required `known-answer-state-replay` reference name, columns, SHA256 hashes, example create/rename/delete rows, required evidence, and the matching `cross-tool-validate` command. Use `--empty` if the lab will populate all rows from a trusted replay export or independent case note.

After a trusted-tool or known-answer diff is produced, attach it to the completed run so the API and web workbench can show it beside the case outputs: `rapidtriage run-attach-validation-diff ./case-run --diff-output usn_state=./usn-state-replay-cross-tool.json --json`. The command copies the JSON into `./case-run/validation-diffs/`, updates `rapidtriage-run-summary.json` outputs, writes `validation-diff-attachments.json`, preserves SHA256 hashes, and rejects non-JSON attachments. Use `--overwrite` only when replacing a previous attachment with the same logical name. This does not make the item commercial-grade by itself; it makes the validation evidence visible, hashed, and reviewable in the run package.

Release builds created by `scripts/build-release.py` now include `release-manifest.json`, `SHA256SUMS`, `dependency-inventory.txt`, `packaging-plan.json`, `packaging-plan.md`, and `update-manifest.json`. Reviewer bundles include #94 court exhibit indexes and #100 tamper-evident audit-bundle hash chains for generated outputs. The packaging plan records #101 Windows Authenticode, #102 macOS codesign/notarization, #103 Linux deb/rpm/AppImage, #104 update-channel, smoke-test, and required evidence gates. The release ZIP also carries #112 release notes, #113 LTS/hotfix policy, #114 support SLA, #115 training curriculum, #116 quickstart lab material, #117 admin deployment guidance, #118 hardening guidance, #119 malicious-evidence handling notes plus `scripts/parser-sandbox-smoke.py`, and #120 dependency monitoring script. The update manifest is manual/local by default and records artifact hashes, rollback guidance, enterprise-disable status, and signature policy; public auto-update distribution still requires signed hosting infrastructure.

The web/API process writes local-only crash reports for unhandled exceptions. Set `RAPIDTRIAGE_CRASH_LOG_DIR` or launch with `rapidtriage web --crash-log-dir ./crash-reports` to choose the directory. Crash reports redact sensitive context keys and are never uploaded automatically. In the web workbench, use `Crash reports` to open the local dashboard, inspect a redacted report, and create a ZIP export bundle containing the redacted JSON plus `crash-export-manifest.json`. Release operators can run `python scripts/crash-export-smoke.py --output-dir logs/crash-export-smoke --json` to generate a local smoke log proving redaction, dashboard listing, ZIP export, manifest hash preservation, and no automatic upload on the release build host. Then run `python scripts/crash-redaction-review.py logs/crash-export-smoke/crash-export-smoke.json --json` to re-open the bundle and produce a review JSON for release evidence. `python scripts/security-hardening-review.py --output logs/security-hardening-review.json --json` records the local hardening baseline, document hashes, auth/no-upload boundaries, and explicit AppSec/sandbox blockers. `scripts/verify-release-evidence.py` can now enforce these outputs with `--crash-smoke-json logs/crash-export-smoke/crash-export-smoke.json --crash-redaction-review-json logs/crash-export-smoke/crash-redaction-review.json --parser-sandbox-smoke-json logs/parser-sandbox-smoke.json --dependency-monitoring-json logs/dependency-monitoring.json --security-hardening-review-json logs/security-hardening-review.json`, including ZIP hash, trusted redaction review, no-upload, parser-isolation limitation, dependency CI/SBOM configuration, release-blocking dependency policy, and security hardening self-review checks.

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

The bundle includes `rapidtriage-reviewer.html`, selected evidence JSON, a hash manifest, report drafts/exports, report export hashes, `rapidtriage-court-exhibit-index.json`, `rapidtriage-tamper-evident-audit-bundle.json`, `rapidtriage-bundle-manifest.json`, an audit file, and an archive SHA256. The court exhibit index assigns exhibit IDs to selected rows, records exhibit row hashes, generated-output hashes, selected-evidence manifest hashes, `court-exhibit-package-manifest-v1`, external signing slots, and verification steps. The tamper-evident audit bundle records an export-time hash chain for generated outputs, `tamper-evident-audit-manifest-v1`, and an external signing slot. The reviewer HTML includes a quick preview, review status counts, reviewer checklist, selected evidence table, and the report draft. It does not include the original evidence image, so reviewers must request the authoritative source evidence if a path needs re-checking.

## Security Notes

RapidTriage web defaults to `127.0.0.1`. If you bind to `0.0.0.0`, pass an auth token:

```bash
rapidtriage web --host 0.0.0.0 --auth-token "change-me"
```

In the browser console, set:

```javascript
localStorage.setItem("rapidtriage.authToken", "change-me")
```

RapidTriage only accepts the token through the `X-RapidTriage-Token` header. Do not place tokens in URLs or query strings.

Do not expose RapidTriage directly to the internet. Treat source-file download endpoints as sensitive because they may reveal evidence contents.

## Limitations Compared With AXIOM

RapidTriage is not a full AXIOM replacement yet. It has early evidence routing, run outputs, Case DB search/review, reports, hashes, and a local web UI. It does not yet include broad mobile/cloud acquisition, deep filesystem carving, signed commercial validation, or AXIOM-scale parser coverage.
