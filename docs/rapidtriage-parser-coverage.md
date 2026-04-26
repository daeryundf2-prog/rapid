# RapidTriage Parser Coverage Matrix

| Area | Status | Notes |
| --- | --- | --- |
| File metadata | Implemented | Names, paths, extensions, sizes, modified time, categories. |
| Document text | Implemented | Text/log/config/data, PDF, Office OpenXML, OpenDocument where dependencies support extraction. |
| Browser history/downloads | Partial | Dedicated browser artifact collector exists for supported local fixtures/profiles. |
| Recent files | Partial | Dedicated recent-files collector exists. |
| Timeline merge | Implemented baseline | Files, docs, artifacts, and normalized timeline export. |
| Case DB FTS | Implemented baseline | Documents, file metadata, artifacts, timeline, review status filters. |
| OCR | Partial | Depends on local Tesseract and image quality. |
| Windows OS/account summary | Planned | Hostname, timezone, last boot, user/admin status, account lifecycle. |
| Windows Event Logs | Planned | EVTX parser contract should emit normalized Event records. |
| Registry hives | Planned | USB history/ShellBags/UserAssist style parser coverage pending. |
| MFT | Planned | File record/timeline source with deleted/recovered status where validated. |
| Zone.Identifier ADS | Planned | Download provenance and source URL/referrer tracking. |
| Defender/Firewall/WER/Task Scheduler | Planned | High-value Windows operating-system artifacts. |
| Prefetch | Planned | Execution artifacts pending. |
| Jump Lists/LNK | Planned | Link and destination parsing pending. |
| Volume Shadow Copy compare | Planned | Current-vs-snapshot deleted file delta and VSC deletion-command detection. |
| Linux XFS | Planned | Filesystem adapter/extraction requirement for Linux server images. |
| Forensic containers AD1/L01/Lx01/AFF/AFF4 | Detection | UI/API adapter detection exists; direct parsing requires vendor/tool export first. |
| Raw/split images DD/RAW/IMG/001 | Detection | UI/API adapter detection exists; mount or recover externally, then scan the folder. |
| Optical/archive images ISO/DMG/WIM/SWM | Detection | UI/API adapter detection exists; mount/extract externally, then scan the folder. |
| Virtual disks VHD/VHDX/VMDK/VDI/XVA/QCOW/QCOW2 | Detection | UI/API adapter detection exists with platform tool hints; extraction/mount orchestration is planned. |
| Memory dumps MEM/DMP/VMEM/VMSS/VMSN/HPAK | Detection | Inventory/hash detection exists; deep memory parsing remains deferred to Volatility-style tools. |
| APK malware triage | Deferred | APK extraction/hash/YARA-style scan can precede full mobile acquisition. |
| Memory forensics | Deferred | RAM dump parsing, BitLocker key search, and process-risk visualization are separate long-term work. |
| Threat intelligence enrichment | Planned | Optional URL/IP/hash enrichment plugin, disabled by default. |
| AI prompt artifacts | Planned | Browser/search/AI assistant prompt extraction when source formats are understood. |
| Mobile/cloud acquisition | Deferred | Long-term domain, not current desktop triage scope. |

Every new parser should publish:

- Stable parser ID and version.
- Input evidence type.
- Normalized output model.
- Fixture path and expected output.
- Known limitations.
