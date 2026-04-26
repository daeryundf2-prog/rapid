# RapidTriage Parser Coverage Matrix

| Area | Status | Notes |
| --- | --- | --- |
| File metadata | Implemented | Names, paths, extensions, sizes, modified time, categories. |
| Document text | Implemented | Text/log/config/data, PDF, Office OpenXML, OpenDocument where dependencies support extraction. |
| Browser history/downloads | Implemented baseline | Chrome, Edge, Brave, Firefox local profiles; history/download fixture coverage. |
| Recent files | Implemented baseline | Recent shortcuts and Jump List file inventory from user profiles. |
| Timeline merge | Implemented baseline | Files, docs, artifacts, and normalized timeline export. |
| Case DB FTS | Implemented baseline | Documents, file metadata, artifacts, timeline, review status filters. |
| OCR | Partial | Depends on local Tesseract and image quality. |
| Image/media triage | Partial | Image dimensions, file hashes, perceptual average hash, similarity bucket, and OCR queue hints are implemented for common image files. |
| Windows OS/account summary | Planned | Hostname, timezone, last boot, user/admin status, account lifecycle. |
| Windows Event Logs | Partial | XML/JSON exports parse into normalized event rows; binary EVTX is inventoried with export guidance. |
| Registry hives | Partial | `.reg` exports parse into key/value rows including Run keys and USB hints. |
| MFT | Planned | File record/timeline source with deleted/recovered status where validated. |
| Zone.Identifier ADS | Partial | Exported `:Zone.Identifier`/`.Zone.Identifier` sidecar files parse ZoneId, referrer URL, and host URL. |
| Defender/Firewall/WER/Task Scheduler | Partial | Fixture-backed inventory for Defender MPLog, Windows Firewall W3C logs, WER reports, and Task Scheduler XML. |
| Prefetch | Partial | `.pf` inventory with executable hints; full binary run-count parsing remains planned. |
| Jump Lists/LNK | Partial | Recent/Jumplist file inventory implemented; full binary destination parsing remains planned. |
| Volume Shadow Copy compare | Planned | Current-vs-snapshot deleted file delta and VSC deletion-command detection. |
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
