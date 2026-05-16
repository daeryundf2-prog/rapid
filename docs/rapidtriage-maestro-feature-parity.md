# RapidForensic Maestro-Style Practical Feature Parity

This document maps the Maestro-style forensic workbench screenshot into practical RapidForensic feature goals.
The goal is not to copy the UI pixel-for-pixel. The goal is that a single Windows 11 E01 case can be ingested,
analyzed, searched, reviewed, and reported with the same practical forensic coverage expected by an analyst.

Status legend:

- `usable`: works in the current workflow for folder/exported evidence or completed run outputs.
- `partial`: exists, but depth, validation, GUI flow, or direct E01 integration is not sufficient yet.
- `missing`: not implemented as a practical user-facing feature.
- `external`: requires an outside tool, mounted/exported source, credentials, or operator-provided evidence.

## 1. Image-Level Workflow

| Screenshot capability | Practical requirement | Current status | Gap to close |
| --- | --- | --- | --- |
| Case / examiner | Create one case, preserve examiner/case metadata, attach runs, export case package. | `usable` | GUI flow needs to make this the first-class start screen. |
| Evidence source extraction | Select E01/Ex01/raw/virtual/exported folder and process it end-to-end. | `partial` | E01 preflight and tool orchestration exist; real Windows 11 E01 end-to-end known-answer validation is still needed. |
| Disk / partition | Show partition table, choose partition, record selected start sector. | `partial` | CLI supports auto/manual sector; GUI partition browser and multi-partition processing are missing. |
| Volume Shadow Copy analysis | Compare/extract mounted VSC snapshots. | `partial` | Direct VSC discovery/mount from E01 is external. |
| File hash / evidence hash | Preserve source/run/output hashes and reviewed evidence citations. | `usable` | GUI should expose hash/citation panels beside every source viewer. |
| Chain/custody / audit | Record case actions and review decisions. | `partial` | Baseline audit exists; immutable hash-chain and full custody UI need hardening. |

## 2. Core Windows Artifacts

| Screenshot capability | Practical requirement | Current status | Gap to close |
| --- | --- | --- | --- |
| File system analysis | File inventory, metadata, category filtering, extracted file review. | `usable` | Large-case virtualized GUI and full source preview polish needed. |
| MFT | Native `$MFT` records, timestamps, parent path reconstruction, deleted state. | `partial` | Full attribute-list, runlist, parent path reconstruction, trusted diff validation. |
| USN journal | USN v2/v3/v4 decode, rename/delete replay, path cache. | `partial` | Full journal replay with FRN path cache and large cursor validation. |
| Event log analysis | EVTX/XML/CSV event parsing, high-risk event classification, timeline. | `partial` | Native BinXML full grammar, provider message rendering, corrupt/deleted recovery validation. |
| Registry analysis | NTUSER/UsrClass/SYSTEM/SAM/SECURITY hive inventory, user activity, deleted cells. | `partial` | Transaction LOG1/LOG2 replay, full binary value decode, deleted key/value proof. |
| System info | Host/user/account/system configuration artifacts. | `partial` | More Windows 11 host profile fields and trusted parser comparison. |
| User/group | Account lifecycle, admin/group membership, SAM/SECURITY/SYSTEM evidence. | `partial` | Deep SAM alias membership and LSA/privilege parser completeness. |
| USB info | USB/removable/storage traces from registry/system artifacts. | `partial` | Dedicated USB timeline and device correlation view. |
| Execution/script | PowerShell, tasks, WMI, services, scripts, Amcache/ShimCache/BAM/SRUM. | `partial` | Deeper native schemas, version-specific semantics, cross-artifact correlation. |
| Prefetch | Prefetch file inventory and execution pivots. | `partial` | Full version 17/23/26/30/31 sections and compressed PF support. |
| ShellBags | Folder view history from NTUSER/UsrClass. | `partial` | Binary shell item decoding, BagMRU/Bags relationship validation, transaction replay. |

## 3. Web, AI, SNS, Mail, Cloud

| Screenshot capability | Practical requirement | Current status | Gap to close |
| --- | --- | --- | --- |
| Web browser integrated analysis | Chrome/Edge/Firefox/Safari history, downloads, cache/session/storage, unified timeline. | `partial+` | macOS Safari downloads now correlate from LaunchServices quarantine; cache/session/extension/sync depth and deleted history validation remain. |
| Download file | Browser downloads, Zone.Identifier, source URL correlation. | `partial` | Stronger ADS + browser + filesystem correlation UI. |
| AI use history | ChatGPT/Claude/Gemini/Perplexity visits and recoverable Q/A candidates. | `partial` | Service/export-specific transcript parsers and Q/A pairing validation. |
| SNS / CHAT | KakaoTalk and messenger export/mobile import parsing. | `partial` | Version/schema matrix, post-patch KakaoTalk fixtures, media/deleted/ephemeral validation. |
| Email | Email artifacts from PST/OST/MBOX/MSG or exports. | `partial` | Full PST/OST object model, deleted items, thread viewer, attachment viewer. |
| Cloud storage | Google/iCloud/M365/Teams/Drive exports and API collection. | `partial` | Provider-specific completeness, OAuth/device flow UX, pagination/delta validation. |

## 4. Media, OCR, Documents, DB

| Screenshot capability | Practical requirement | Current status | Gap to close |
| --- | --- | --- | --- |
| OCR extraction / translation | OCR queue, sidecar text import, search OCR results. | `partial` | Korean OCR quality workflow, translation sidecar, GUI queue control. |
| Image/video analysis | Image gallery, thumbnails, metadata, OCR action, media evidence review. | `partial` | True gallery review mode, video/audio playback/transcript, perceptual similarity. |
| Document / DB file | Office/PDF/text extraction, SQLite/DB detection, source review. | `partial` | Dedicated SQLite/table viewer, deleted row modules, large DB paging. |
| Metadata | EXIF/document/file metadata extraction and display. | `partial` | Unified metadata viewer with citation and hash context. |
| Compression/encrypted files | Archive detection/extraction and encrypted file inventory. | `partial` | Password workflows, safe preview sandbox, archive recursion policy. |
| Hidden/suspicious files | ADS, hidden files, scripts, suspicious paths/rules. | `partial` | More rule packs and analyst-tunable scoring. |
| Deleted/file trace | Recycle/deleted candidates, VSC diff, carving candidates. | `partial` | Deep deleted recovery and filesystem-level validation. |
| File carving | Bounded signature carving with offsets/hashes. | `usable` | Large-scale carving queue and more file signatures. |

## 5. DFIR / Threat / Memory

| Screenshot capability | Practical requirement | Current status | Gap to close |
| --- | --- | --- | --- |
| Threat intelligence | IOC extraction/enrichment for IP/domain/URL/hash. | `partial` | Offline signed feeds, STIX/TAXII import, confidence decay, local-only policy. |
| LotL / fileless | PowerShell/WMI/WMIC/scripts, suspicious command timeline. | `partial` | Stronger Windows event + registry + script correlation. |
| Memory dump analysis | Memory artifact inventory and KakaoTalk memory-assisted workflows. | `partial` | General Volatility-style process/network/credential artifact parsing. |
| WebShell / hacking | Web shell/source/script suspicious pattern detection. | `partial` | Dedicated web root parser, webshell rule packs, source code viewer. |
| External program connection | Import/export with trusted tools and cross-tool validation. | `partial` | User-facing import wizard for EvtxECmd/Hayabusa/RECmd/MFTECmd exports. |
| Remote system connection | Remote acquisition/agent workflow. | `missing` | Out of scope until a safe authorized remote collector is designed. |

## 6. Analyst Workbench UX

| Screenshot capability | Practical requirement | Current status | Gap to close |
| --- | --- | --- | --- |
| Left forensic artifact tree | Counts by artifact family/type, fast filtering. | `partial` | GUI taxonomy exists, but live tree must bind to case database counts. |
| Central result table | Large sortable/filterable table for 100k+ rows. | `partial` | Cursor API and real virtualized DOM table need completion. |
| Right preview/detail | Source preview, metadata, hash, path, OCR/media actions. | `partial` | Dedicated source viewers for EVTX/Registry/Hex/SQLite/Email/Image/Video. |
| Global search | Search across files, docs, browser, logs, registry, OCR, email, messenger. | `usable` | Needs GUI result verification, current-file search, and saved keyword packs. |
| Review workflow | relevant/needs-review/excluded/include-in-report, notes, tags, shortcuts. | `usable` | GUI must make it fluid with evidence tray and compare/back navigation. |
| Timeline | Unified time correlation from artifacts/files/docs. | `usable` | Need timezone/skew overlay and graph/correlation view. |
| Report | Report candidates, citation, hashes, export package. | `partial` | Better final report formats and court-style exhibit bundle. |

## Practical Priority Order

1. Make the web GUI launch reliably on fresh Windows/macOS installs.
2. Bind the GUI to a single-case workbench: case intake, artifact tree, result table, preview/detail, review tray, report export.
3. Run a real Windows 11 E01 known-answer image end-to-end and record what actually extracts.
4. Deepen EVTX to full native BinXML/message/recovery validation.
5. Deepen Registry to transaction replay and deleted key/value validation.
6. Deepen MFT/USN to path reconstruction, rename/delete replay, and large cursor pagination.
7. Improve browser/download/AI transcript parsers and unified browser timeline.
8. Improve document/SQLite/email viewers and report citation workflow.
9. Improve image/video/OCR review and media attachment handling.
10. Add import wizards for external tool exports so partial native parsers can be verified against trusted outputs.

## Current Honest Summary

RapidForensic currently has enough practical pieces for CLI-based triage: run, artifact extraction, timeline, search,
Case DB review, report candidate export, E01 preflight, Registry/ShellBags exposure, Windows artifact pivots, and
default run coverage for email, cloud exports, mobile/chat exports, KakaoTalk Windows inventory, Android APKs,
media/image metadata, and memory-dump inventory.
It does not yet match the full Maestro-style analyst workstation because the GUI is not reliably packaged, several parsers
are still triage-depth rather than report-grade, and the workbench viewers are not yet deep enough for high-volume review.
