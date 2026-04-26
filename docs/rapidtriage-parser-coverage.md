# RapidTriage Parser Coverage Matrix

| Area | Status | Notes |
| --- | --- | --- |
| File metadata | Implemented | Names, paths, extensions, sizes, modified time, categories. |
| KAPE-style collect planning/export | Implemented baseline | `collect-plan` profiles preview present/missing Windows/macOS collection targets before heavy scanning or copying. `collect-export` can build a bounded source-relative export package with SHA256 copy logs. |
| Document text | Implemented | Text/log/config/data, EML/MBOX email, bounded Outlook MSG/PST/OST strings, PDF, Office OpenXML, and OpenDocument where dependencies support extraction. |
| Browser history/downloads | Implemented baseline+ | Chrome, Edge, Brave, Firefox local profiles; history/download fixture coverage; internet usage summaries, top-domain/category pivots, source hashes, browser-derived AI service usage detections, and browser-storage AI conversation candidates are normalized for Windows and macOS. |
| Recent files | Implemented baseline+ | Recent shortcuts parse Shell Link header/string fields for target path, working directory, arguments, timestamps, flags, hashes, and embedded path pivots; Jump Lists promote recoverable embedded Shell Link destination records and fall back to embedded path extraction. |
| Timeline merge | Implemented baseline | Files, docs, artifacts, and normalized timeline export. |
| Case DB FTS | Implemented baseline | Documents and artifact metadata are indexed with SQLite FTS5; file metadata, timeline rows, review status filters, verification filters, and promoted artifact metadata filters are supported. |
| OCR | Partial | Depends on local Tesseract and image quality. |
| Image/media triage | Partial+ | Image dimensions, file hashes, perceptual average hash, similarity bucket, bounded inline thumbnail previews, and OCR queue hints are implemented for common image files. |
| Windows OS/account summary | Implemented baseline+ | User profile inventory plus `.reg` export hints for computer name, timezone, ProfileList SIDs, admin-group hints, last boot/shutdown timestamps, and exported account lifecycle fields such as created, last logon, password-last-set, disabled, and admin hints. Full SAM binary traversal remains planned. |
| Windows Event Logs | Partial+ | XML/JSON/JSONL/CSV exports from EVTX-oriented tools parse into normalized event/detection rows with hashes, categories, event/channel families, typed parameters, parser confidence, risk flags, reportability status, expanded built-in detections for high-value Windows/Sysmon/Defender/WMI/RDP behaviors, high-risk summary pivots, and EventRecordID gap hints; binary EVTX is inventoried and recoverable native record headers emit partial rows with timestamps, record IDs, extracted strings, and suspicious-term flags. |
| Registry hives | Partial+ | `.reg` exports parse into key/value rows including Run keys, suspicious persistence value hints, and USBSTOR device metadata. Native hive candidates such as `NTUSER.DAT`, `UsrClass.dat`, `SYSTEM`, and `SOFTWARE` are inventoried with `regf` header metadata, source hashes, sequence/dirty hints, last-write timestamp, and bounded UTF-16 string pivots; full cell traversal and deleted-key recovery remain planned. |
| MFT | Partial+ | MFT CSV/JSON/JSONL exports are normalized with record number, path, timestamps, and deleted hints; native `$MFT` files are inventoried with hashes, bounded FILE record-header samples, and UTF-16 path pivots while full attribute decoding remains planned. |
| Zone.Identifier ADS | Partial | Exported `:Zone.Identifier`/`.Zone.Identifier` sidecar files parse ZoneId, referrer URL, and host URL. |
| Defender/Firewall/WER/Task Scheduler/WMI | Partial+ | Fixture-backed inventory for Defender MPLog, Windows Firewall W3C logs, WER reports, Task Scheduler XML, and WMI repository files; Task Scheduler rows promote hidden/run-level/start-boundary fields and suspicious command/user-writable-path risk flags, while WMI repository files include bounded string pivots for permanent event consumer/filter terms, commands, paths, URLs, and risk flags. |
| Prefetch | Partial+ | `.pf` inventory with executable hints, SCCA header detection, version hints, header executable-name extraction, best-effort common-version run count, last run timestamps, and referenced path pivots; validate critical findings with PECmd or another dedicated parser. Execution-related registry export and PowerShell history imports are available through `windows-execution`, with a grouped execution summary for review pivots. |
| SRUM | Partial+ | SRUM CSV/JSON/JSONL/NDJSON exports can be normalized into app resource and network usage rows; direct `SRUDB.dat` is inventoried with ESE header metadata, hashes, bounded strings, path/URL pivots, and suspicious-term flags while full SRUM table decoding remains planned. |
| Windows Search EDB | Partial+ | `Windows.edb` is inventoried with ESE header metadata, hashes, bounded strings, path/URL pivots, and export-tool guidance; CSV/JSON/JSONL exports are normalized into searchable index entries with path, title, URL, extension, timestamps, and content snippets. |
| Windows remote access | Implemented baseline+ | RDP files, Terminal Server Client cache files, and exported Terminal Server Client registry destinations are normalized for remote-access triage; cache files include bounded PNG/JPEG/BMP/DIB thumbnail signature pivots while full vendor-specific cache decoding remains planned. |
| Jump Lists/LNK | Partial+ | LNK header/string parsing and embedded path extraction implemented; Jump Lists are inventoried with OLE/custom hints and recover embedded Shell Link destination records when present, while full OLE stream traversal remains planned. |
| USN Journal | Partial+ | USN CSV/JSON/JSONL exports are normalized with FRN/parent/reason/timestamp fields; native `$J`/USN journal files are inventoried and recoverable v2/v3 records are emitted as triage `usn-record` rows. |
| macOS user/browser/quarantine | Implemented baseline | User home inventory, Safari/Chromium/Firefox history imports with web/AI usage pivots, LaunchServices quarantine events, and LaunchAgent plist inventory are available through `macos-system`. |
| Volume Shadow Copy compare | Implemented baseline | `vsc-compare` compares current vs one or more snapshot folders and emits deleted/added/modified candidates with optional SHA256 confirmation; VSC deletion command hints can also be surfaced from EVTX/PowerShell history imports. |
| Linux XFS | Planned | Filesystem adapter/extraction requirement for Linux server images. |
| Forensic containers AD1/L01/Lx01/AFF/AFF4 | Detection | UI/API adapter detection exists; direct parsing requires vendor/tool export first. |
| Raw/split images DD/RAW/IMG/001 | Detection | UI/API adapter detection exists; mount or recover externally, then scan the folder. |
| Optical/archive images ISO/DMG/WIM/SWM | Detection | UI/API adapter detection exists; mount/extract externally, then scan the folder. |
| Virtual disks VHD/VHDX/VMDK/VDI/XVA/QCOW/QCOW2 | Detection | UI/API adapter detection exists with platform tool hints; extraction/mount orchestration is planned. |
| Memory dumps MEM/DMP/VMEM/VMSS/VMSN/HPAK | Detection + import | Memory dump detection exists; Volatility/Volatility3 JSON/JSONL outputs can be imported as process, network, cmdline, and malfind artifacts. |
| APK malware triage | Partial | Exported `.apk` files are inventoried with hashes, manifest metadata, permissions, dex/native-library counts, and risk flags. |
| Memory forensics | Partial | Volatility-style output normalization is implemented; direct RAM parsing, BitLocker key search, and process-risk visualization remain long-term work. |
| Threat intelligence enrichment | Planned | Optional URL/IP/hash enrichment plugin, disabled by default. |
| AI prompt artifacts | Partial+ | Browser history detects common AI service visits such as ChatGPT, Claude, Gemini, Perplexity, Copilot, Poe, Hugging Face Chat, Grok, You.com, Phind, Mistral, DeepSeek, Meta AI, Character.AI, and Notion AI. Browser Local Storage, Session Storage, IndexedDB, and Cache files are scanned for role/content, prompt, question, answer, response, and completion snippets as review-only conversation candidates; full transcript completeness still requires service-specific validation. |
| Cloud export import | Partial | Google Takeout-style location/activity JSON and Apple/general account JSON exports are normalized with source hashes. |
| Mobile/cloud acquisition | Partial | Exported APK and cloud export imports exist; direct cloud acquisition/API collection remains deferred. |

Every new parser should publish:

- Stable parser ID and version.
- Input evidence type.
- Normalized output model.
- Fixture path and expected output.
- Known limitations.
