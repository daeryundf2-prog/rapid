# RapidTriage Known Limitations

RapidTriage is a local triage and review tool, not a full commercial forensic suite.

## Evidence Handling

- Mounted folders and exported evidence folders are the most reliable input.
- E01/Ex01 direct handling requires external `libewf` and Sleuth Kit tools.
- Raw/split images can be extracted with Sleuth Kit (`mmls`, `tsk_recover`) when those tools are installed.
- ISO/DMG/WIM/SWM images can be extracted when supported archive tooling is available (`7zz`/`7z`, or `bsdtar` for ISO).
- VHD/VHDX/VMDK/VDI/QCOW/QCOW2 virtual disks can be converted with `qemu-img` and then recovered with Sleuth Kit when those tools are installed.
- AD1, L01/Lx01, AFF/AFF4, XVA, and proprietary mobile acquisition packages are still adapter-detected only and require vendor/tool export first. Mobile CSV/JSON/JSONL export folders can be imported for normalized review. Memory dumps also receive bounded indicator scanning, not full process reconstruction.
- `rapidtriage evidence PATH --json` now reports `support_level`, `scan_strategy`, `next_actions`, `warnings`, and missing tools so analysts can decide whether to scan directly, install tooling, mount read-only, or vendor-export first.
- XFS/ext partition selection is supported for direct image recovery, but actual XFS file recovery depends on the installed Sleuth Kit build. XVA virtual-server dump workflows are not implemented yet.
- Deep deleted-file carving is available as a bounded signature workflow for JPEG, PNG, PDF, and ZIP candidates. It is intentionally capped and does not replace full filesystem-aware carving or commercial media validation.

## Parser Coverage

- Browser, recent-file, EventLog export, Registry export, ShellBags export, Prefetch inventory, Task Scheduler XML, Defender MPLog, Firewall W3C log, WER report, and Zone.Identifier sidecar artifacts are implemented first.
- macOS user profile, browser history, quarantine event, TCC privacy permission, LaunchAgent plist triage, and bounded Unified Log/Spotlight/FSEvents/APFS snapshot hint pivots are implemented as a baseline; full native Unified Log, Spotlight, FSEvents, and APFS snapshot semantic decoding remains planned.
- Linux user, shell history, SSH, auth log, auditd, dpkg package status/logs, Docker container config, cron, and systemd triage is implemented as a baseline; full filesystem-level XFS parsing, binary journal replay, RPM database decoding, and deeper container/runtime artifact reconstruction remain planned.
- Full EVTX provider DLL/resource-table message rendering, full deleted-EVTX validation corpus coverage, full MFT attribute decoding, full Prefetch file-reference decoding, full Jump List DestList MRU/account metadata decoding, full SAM F/V decoding, SECURITY secret decryption, native Amcache/ShimCache/BAM binary decoding, full SRUDB/Windows.edb table decoding, full proprietary mobile package imports, and live cloud acquisition are roadmap items. Native EVTX record-header scanning emits partial rows with file-header/chunk context, parameter candidates, native message previews, first-pass BinXML token scans, inline scalar decoding for common String/ANSI/integer/bool/GUID/SID/FILETIME/SYSTIME/binary values, TemplateInstance IDs, TemplateInstance value spec/value decoding for common scalar types, promoted `Event/System`, `EventData`, and `UserData` fields when recoverable, rendered previews or built-in high-value fallback messages where possible, explicit `message_rendering` validation warnings, explicit `evtx_binxml_status`, `evtx_recovery_context`, separate native `eventlog-chunk` rows, and separate corrupt `eventlog-record-candidate` rows with caution labels, and EVTX-oriented XML/JSON/JSONL/CSV exports from tools such as EvtxECmd, Hayabusa, Chainsaw, or Velociraptor can be imported and normalized; native `$MFT` scans emit bounded FILE-header rows and path pivots; Prefetch SCCA header/version/executable hints, common-version run counts, last-run timestamps, and referenced-path pivots are parsed when available. Direct SRUDB and Windows.edb files are currently inventoried with ESE header metadata, hashes, and bounded string/path/URL pivots; SRUDB also emits table-family candidates, and both emit native pivot rows for review and search. Jump Lists traverse recoverable OLE/CFB streams and promote embedded Shell Link destinations with stream provenance when recoverable. NTUSER/UsrClass user-hive activity pivots are now surfaced for common keys such as UserAssist, TypedURLs/TypedPaths, RecentDocs, Run/RunOnce, Explorer/MRU, ShellBags, MountPoints2, Network, and ComDlg32/OpenSavePidlMRU; native registry hives now also prefer bounded hbin cell walking and emit best-effort key-tree, key-recovery, and value-recovery candidates, but transaction-log replay, binary value decoding, and report-grade deleted-value testimony still require a dedicated registry parser.
- Full native MFT attribute decoding, full USN replay/correlation, direct VSC mounting from evidence images, service-side AI transcript acquisition, and deeper LotL command correlation are roadmap items. Browser-storage AI prompt/answer candidates can be extracted and paired with completeness scoring, but source services should still be validated before report conclusions. MFT/USN CSV/JSON/JSONL exports can be imported and normalized; native `$MFT` and `$J` files currently provide bounded inventory, path pivots, and recoverable v2/v3 USN rows with structural validation, reason/source/file-attribute flags, delete/rename hints, and parser confidence. Mounted/exported VSC folders can be compared with `rapidtriage vsc-compare`, and selected deleted/modified snapshot files can be copied with hashes using `rapidtriage vsc-extract`.
- APK inventory/risk triage works on exported `.apk` files. Cellebrite/XRY/GrayKey/AXIOM-style mobile CSV/JSON/JSONL exports can be normalized into message, contact, call, app, file, and source-summary rows with source hashes. Volatility/Volatility3 JSON/JSONL memory output import and bounded direct memory dump indicator scans are supported.
- Google Takeout-style location/activity JSON and Apple/general account JSON imports are supported. Authorized API collection from analyst-provided request manifests is supported for bounded JSON responses, but RapidTriage does not manage OAuth consent flows, provider-specific pagination semantics, or account acquisition authority.
- Full direct memory process reconstruction, password cracking, live USB collection, and remote-agent collection are deferred until the security and validation model matures. Bounded memory scans can surface process string candidates and checksum-validated BitLocker recovery-key candidates, but Volatility/Volatility3 or equivalent validation is still required for report-grade process reconstruction.
- Image perceptual hashes, similarity buckets, OCR sidecar language hints, translation-needed markers, and rule-based visual classifications are triage hints only; they do not replace full media forensics, OCR quality validation, translation review, visual similarity review, deepfake analysis, or ML classifier validation.
- Parser output should be verified against source evidence before report inclusion.

## Search And OCR

- Case DB search currently uses SQLite FTS5 for documents and artifact metadata, plus metadata scans for file/timeline/review filters.
- OCR depends on local Tesseract availability and quality varies by image.
- Large-case performance must be tracked with `rapidtriage benchmark`.

## Reporting

- Markdown, browser-friendly HTML, portable DOCX, dependency-free PDF, and report export hash manifests are available from the web API and reviewer bundle.
- Reviewer bundles are review packages, not source evidence. They include selected evidence metadata, hashes, review notes, report exports, audit JSON, and a bundle manifest, but they intentionally do not copy the original evidence image.
- Digital signing, notarization, and court-specific certification packets still require external release infrastructure and independent validation.
- Reports should include analyst review notes and hash manifests for defensibility.
- The validation package is a release-readiness checklist; it does not replace independent legal validation, signed installer infrastructure, or a maintained support program.

## Security

- The web UI is designed for localhost use.
- Remote binding requires explicit auth-token configuration.
- Do not expose RapidTriage directly to the internet.
