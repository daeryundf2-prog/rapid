# RapidTriage Parser Coverage Matrix

| Area | Status | Notes |
| --- | --- | --- |
| File metadata | Implemented | Names, paths, extensions, sizes, modified time, categories. |
| KAPE-style collect planning/export | Implemented baseline | `collect-plan` profiles preview present/missing Windows/macOS collection targets before heavy scanning or copying. `collect-export` can build a bounded source-relative export package with SHA256 copy logs. |
| Document text | Implemented | Text/log/config/data, PDF, Office OpenXML, OpenDocument where dependencies support extraction. |
| Browser history/downloads | Implemented baseline | Chrome, Edge, Brave, Firefox local profiles; history/download fixture coverage. |
| Recent files | Implemented baseline | Recent shortcuts and Jump List file inventory from user profiles. |
| Timeline merge | Implemented baseline | Files, docs, artifacts, and normalized timeline export. |
| Case DB FTS | Implemented baseline | Documents, file metadata, artifacts, timeline, review status filters. |
| OCR | Partial | Depends on local Tesseract and image quality. |
| Image/media triage | Partial | Image dimensions, file hashes, perceptual average hash, similarity bucket, and OCR queue hints are implemented for common image files. |
| Windows OS/account summary | Implemented baseline | User profile inventory plus `.reg` export hints for computer name, timezone, ProfileList SIDs, and admin-group hints. Last boot and full account lifecycle remain planned. |
| Windows Event Logs | Partial+ | XML/JSON/JSONL/CSV exports from EVTX-oriented tools parse into normalized event/detection rows with hashes, categories, risk flags, reportability status, high-risk summary pivots, and EventRecordID gap hints; binary EVTX is inventoried with external-parser guidance. |
| Registry hives | Partial+ | `.reg` exports parse into key/value rows including Run keys, suspicious persistence value hints, USBSTOR device metadata, and registry summary pivots. |
| MFT | Import baseline | MFT CSV/JSON/JSONL exports are normalized with record number, path, timestamps, and deleted hints; native `$MFT` parsing remains planned. |
| Zone.Identifier ADS | Partial | Exported `:Zone.Identifier`/`.Zone.Identifier` sidecar files parse ZoneId, referrer URL, and host URL. |
| Defender/Firewall/WER/Task Scheduler | Partial | Fixture-backed inventory for Defender MPLog, Windows Firewall W3C logs, WER reports, and Task Scheduler XML. |
| Prefetch | Partial | `.pf` inventory with executable hints; full binary run-count parsing remains planned. Execution-related registry export and PowerShell history imports are available through `windows-execution`, with a grouped execution summary for review pivots. |
| SRUM | Import baseline | SRUM CSV/JSON/JSONL/NDJSON exports can be normalized into app resource and network usage rows; direct `SRUDB.dat` ESE parsing remains planned. |
| Jump Lists/LNK | Partial | Recent/Jumplist file inventory implemented; full binary destination parsing remains planned. |
| USN Journal | Import baseline | USN CSV/JSON/JSONL exports are normalized with FRN/parent/reason/timestamp fields; native `$J` parsing remains planned. |
| macOS user/browser/quarantine | Implemented baseline | User home inventory, Safari/Chromium/Firefox history imports, LaunchServices quarantine events, and LaunchAgent plist inventory are available through `macos-system`. |
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
| AI prompt artifacts | Planned | Browser/search/AI assistant prompt extraction when source formats are understood. |
| Cloud export import | Partial | Google Takeout-style location/activity JSON and Apple/general account JSON exports are normalized with source hashes. |
| Mobile/cloud acquisition | Partial | Exported APK and cloud export imports exist; direct cloud acquisition/API collection remains deferred. |

Every new parser should publish:

- Stable parser ID and version.
- Input evidence type.
- Normalized output model.
- Fixture path and expected output.
- Known limitations.
