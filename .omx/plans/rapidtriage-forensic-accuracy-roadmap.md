# RapidTriage Forensic Accuracy Roadmap

Date: 2026-04-26

## Goal

Move RapidTriage from a useful lightweight triage/review tool toward a defensible forensic analysis tool, with priority on Windows artifacts whose correctness matters in real investigations.

This plan does not try to copy every AXIOM/WISDOM feature. It focuses on:

- Accurate parsing, source validation, and reporting for high-value artifacts.
- Fast triage defaults inspired by KAPE, Hayabusa, Chainsaw, Velociraptor, Autopsy, Plaso/log2timeline, and Magnet AXIOM workflows.
- Clear status levels so users know whether a result is inventory-only, parsed, detection-enriched, validated, or reportable.

## External Findings Used

- EvtxECmd is a mature EVTX parser with standardized CSV/XML/JSON output, custom maps, and locked-file support.
  Source: https://www.sans.org/tools/evtxecmd
- Chainsaw emphasizes rapid Windows Event Log triage and Sigma/custom detection logic for large log volumes.
  Source: https://github.com/WithSecureLabs/chainsaw
- Hayabusa focuses on Sigma-based threat hunting and fast forensic timelines for Windows event logs, with output profiles and detection metadata.
  Source: https://github.com/Yamato-Security/hayabusa
- Velociraptor's EVTX docs highlight full-event parsing, filtering by glob/time/channel/event ID, high resource cost, and the value of narrowing scope.
  Source: https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.evtx/
- Velociraptor's Hayabusa artifact shows a practical integration pattern: run Hayabusa over an EVTX directory and emit CSV/JSONL for downstream analysis.
  Source: https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/
- KAPE separates target collection from module execution and groups useful forensic artifacts by investigative category.
  Source: https://www.kroll.com/en-us/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape
- SANS describes KAPE as fast targeted collection and parsing from live systems or forensic images.
  Source: https://www.sans.org/blog/3minmax-series-topic-review---using-kape-in-forensics
- Magnet AXIOM sets the user-experience bar for evidence source integration, artifact-first review, timeline, filtering, reporting, and cross-source analysis.
  Source: https://www.magnetforensics.com/products/magnet-axiom
- Magnet AXIOM timeline guidance reinforces that artifacts with multiple timestamps must expose each timestamp and support filtering/pivoting.
  Source: https://www.magnetforensics.com/resources/using-the-new-timeline-explorer-in-magnet-axiom-3-0/
- Reddit practitioner feedback repeatedly points to EvtxECmd for EVTX parsing and warns that Windows API-based readers may not expose everything in the file.
  Source: https://www.reddit.com/r/computerforensics/comments/jrhjv5
- Reddit practitioner feedback around AXIOM reporting emphasizes selecting/tagging relevant items and producing readable reports instead of dumping noisy columns.
  Source: https://www.reddit.com/r/computerforensics/comments/kaed02

## Current Codebase Baseline

- `rapidtriage/artifacts/windows/eventlog.py` currently parses XML/JSON event log exports, but binary `.evtx` files are inventory-only.
- `docs/rapidtriage-parser-coverage.md` marks binary EVTX, Prefetch run-count parsing, full LNK/JumpList parsing, SRUM, MFT, VSC, XFS, virtual-disk mounting, and direct memory parsing as partial/planned.
- `README.md` documents CLI/web workflows, source viewer, review marks, hash generation, case DB, timeline export, and bundle/report output.
- `rapidtriage/core/timeline_export.py` has normalized timeline export, but event timestamp semantics and source confidence need to become richer for EVTX/MFT/VSC evidence.

## Accuracy Status Model

Every artifact provider should emit a `coverage_status` and `reportability` field:

- `detected`: file or artifact exists, but content is not parsed.
- `parsed`: structured fields extracted from source.
- `mapped`: raw fields normalized into analyst-friendly names, with parser/map version.
- `detected-by-rule`: matched detection logic such as Sigma, Hayabusa-style rules, or RapidTriage rules.
- `validated`: fixture-backed parser behavior with expected counts and source references.
- `reportable`: safe for report inclusion when reviewed by an analyst; includes source path, timestamp, parser version, raw preview/reference, hashes, and confidence.

Acceptance:

- No UI or report should present `detected` rows as if they were fully parsed.
- Search results must show status and parser confidence.
- Reports must include only `reportable` rows by default, or clearly label weaker rows.

## Phase 1: EVTX Foundation

Priority: critical.

Objective: make Windows Event Logs genuinely useful and defensible.

Implementation tasks:

- Add a binary EVTX parser integration layer.
- Prefer a pure Python/library parser only if it preserves full records and works cross-platform.
- Add optional external parser adapters for EvtxECmd and Hayabusa/Chainsaw-style output import.
- Support input forms:
  - Native `.evtx` files under `Windows/System32/winevt/Logs`.
  - XML exports.
  - JSON/JSONL exports from EvtxECmd, Hayabusa, Chainsaw, or Velociraptor.
- Normalize core EVTX fields:
  - provider, channel, event ID, record ID, level, task, opcode, keywords, computer, user SID/name, process ID, thread ID, timestamp, event data, rendering info if available.
- Preserve source validation:
  - source path, original file hash, record number, source index, raw event JSON/XML preview, parser name/version, map version.
- Add high-value channel presets:
  - Security, System, Application, PowerShell Operational, Sysmon, TaskScheduler, TerminalServices, Defender, Windows Firewall, WMI-Activity, RDP-related logs.
- Add event ID knowledge packs:
  - Logon/logoff, failed logon, privilege use, process creation, service install, scheduled task creation, PowerShell script block, log clearing, account creation/group change, RDP/network logon, Defender detections.
- Add EVTX timeline rows with timestamp kind and event-category tags.
- Add “important events” filtered view in UI.

Acceptance criteria:

- Native `.evtx` fixture with at least 100 events parses into normalized rows.
- XML export and native EVTX fixture produce matching event IDs/record IDs/timestamps for shared records.
- Corrupt/truncated EVTX fixture produces partial rows and visible parser warnings, not silent success.
- Security 4624/4625/4672/4688/4698/4720/4728/4732/7045/1102/4104 fixture rows are recognized and categorized.
- Case DB search can filter `source=eventlog`, channel, event ID, provider, user, computer, level, and rule severity.
- Reports include source file hash and parser version for each selected event.

## Phase 2: Sigma/Hayabusa/Chainsaw-Style Detection

Priority: critical after EVTX foundation.

Objective: move from raw event rows to analyst-prioritized detections.

Implementation tasks:

- Add a detection-rule engine for normalized EVTX rows.
- Start with a small built-in RapidTriage rule pack before full Sigma compatibility.
- Import Sigma YAML rules in a limited but explicit subset:
  - selection maps, condition all/any/contains/endswith, level, title, id, tags, false positives.
- Add mappings for common Windows/Sysmon fields.
- Support external Hayabusa/Chainsaw JSONL/CSV imports as first-class detection artifacts.
- Store rule hits in Case DB with stable citation IDs.
- UI should show:
  - severity, rule title, MITRE tags, matched fields, event link, false-positive note.
- Add detection suppressions and analyst status:
  - relevant, benign, needs follow-up, false positive, report candidate.

Acceptance criteria:

- Rule hit generation is deterministic for fixture logs.
- At least 30 built-in rules covering account abuse, PowerShell, service install, scheduled task, log clearing, RDP, Sysmon process/network indicators.
- Importing Hayabusa/Chainsaw output retains rule ID/title/severity/tags/source EVTX path.
- Search for `powershell`, `rundll32`, `wmic`, or `4624` returns both raw event rows and detection rows.

## Phase 3: KAPE-Style Target Collection Profiles

Priority: high.

Objective: make the user stop guessing what to collect.

Implementation tasks:

- Add target profiles inspired by KAPE categories:
  - EvidenceOfExecution.
  - AccountUsage.
  - BrowserHistory.
  - EventLogs.
  - Persistence.
  - RemoteAccess.
  - FileSystemTimeline.
  - CloudAndSync.
- Build a `collect-plan` command that lists what will be copied/scanned before running.
- Add read-only copy/export mode for mounted evidence.
- Preserve copy log with hashes, size, mtime, source path, destination path, and errors.
- UI should allow selecting a profile rather than individual parser internals.

Acceptance criteria:

- A Windows mounted image root can produce a KAPE-like artifact package without copying the whole disk.
- Collection output can be re-ingested by RapidTriage and keeps chain-of-custody metadata.
- Missing paths are summarized by category, not treated as errors.

## Phase 4: Execution Artifacts

Priority: high.

Objective: answer “what ran?” accurately.

Implementation tasks:

- Prefetch binary parser:
  - executable name, run count, last run times, referenced files/directories, volume info, hash/version.
- Amcache parser:
  - program ID, path, SHA1 where available, compile/link timestamp, install/execution hints.
- ShimCache/AppCompat parser:
  - path, modified time, execution caveats clearly labeled.
- UserAssist parser:
  - ROT13 decode, run count, focus time where available.
- BAM/DAM parser:
  - executable path, last execution timestamp.
- SRUM parser:
  - app/network/resource usage tables.

Acceptance criteria:

- Execution dashboard groups signals by executable/path.
- Each signal labels whether it proves execution, indicates execution, or only indicates presence.
- Report wording avoids overclaiming weak artifacts.

## Phase 5: File-System Forensics

Priority: high.

Objective: support deletion/recovery/timeline questions.

Implementation tasks:

- MFT parser/import:
  - record number, sequence, flags, parent, filename attributes, timestamps, deleted/in-use status.
- USN Journal parser/import:
  - reason flags, file reference, timestamp, filename.
- $LogFile import if feasible through external tool output first.
- VSC compare workflow:
  - compare current filesystem with VSC/exported snapshot folder.
  - identify deleted/changed/new files.
  - detect VSC deletion commands from EVTX/PowerShell/WMI where present.

Acceptance criteria:

- Timeline includes MFT, USN, and artifact timestamps with source labels.
- Deleted file candidates are clearly separated from live files.
- VSC comparison can produce a deleted-file delta report.

## Phase 6: Registry Accuracy

Priority: high.

Objective: replace `.reg`-only support with hive-backed parsing or validated imports.

Implementation tasks:

- Add direct hive parser or external RECmd-compatible import.
- Parse SYSTEM/SOFTWARE/SAM/SECURITY/NTUSER.DAT/UsrClass.dat.
- Normalize:
  - Run keys, Services, USBStor, MountedDevices, NetworkList, ShellBags, UserAssist, MUICache, TypedPaths, RecentDocs, RDP MRU, OpenSavePidlMRU, AppCompatCache.
- Include key path, value name/type, value data, last write time, hive path, parser version.
- Track deleted/recovered key support separately.

Acceptance criteria:

- Registry fixtures validate key paths, timestamps, and decoded values.
- UI can pivot from a registry artifact to related files/events/timeline rows.

## Phase 7: LNK, Jump Lists, Shell Items

Priority: medium-high.

Objective: support user activity and file access narratives.

Implementation tasks:

- Add full LNK parser:
  - target path, arguments, working directory, volume serial, MAC times, tracker data, machine ID.
- Add AutomaticDestinations/CustomDestinations parser:
  - destination list entries, access counts, timestamps, embedded LNK fields.
- Improve ShellBags:
  - direct hive parsing, path reconstruction, bag timestamps.

Acceptance criteria:

- Report can explain “user opened/accessed X” with artifact-specific caveats.
- Timeline exposes all relevant LNK/Jump List timestamps separately.

## Phase 8: Browser, Email, Chat, Cloud Expansion

Priority: medium.

Objective: improve user-facing evidence review.

Implementation tasks:

- Browser:
  - Chrome/Edge/Brave/Firefox history, downloads, cookies metadata, logins metadata, sessions/tabs, cache inventory.
  - Preserve SQLite WAL/SHM awareness when collecting live/extracted browser DBs.
- Email:
  - PST/OST/MBOX/EML ingestion through import adapters first.
  - Message headers, sender/recipient, attachments, dates, body text index.
- Chat/cloud exports:
  - Expand Google Takeout, Apple data, Microsoft account exports.
  - Add source hash and account identity mapping.

Acceptance criteria:

- Case-wide search returns browser/email/cloud text with source filters.
- Viewer supports conversation/thread grouping where source data supports it.

## Phase 9: Search and Indexing Upgrade

Priority: high for large cases.

Objective: avoid overloading with large data and make search trustworthy.

Implementation tasks:

- Replace or augment JSON scanning with persistent SQLite/FTS ingestion by default.
- Add per-source indexes:
  - documents, logs, EVTX, registry, file metadata, browser, email, OCR.
- Add query modes:
  - exact keyword, phrase, regex, fielded query, current file only, selected artifact family only.
- Add result ranking:
  - reviewed/report candidate first, severity, timestamp proximity, source confidence.
- Add index build progress and resumability.

Acceptance criteria:

- 100k rows search p95 target under 2 seconds on a normal laptop for common fielded queries.
- Search explains whether a source was indexed, skipped, capped, or failed.

## Phase 10: Viewer and Review UX

Priority: high.

Objective: make evidence review comfortable with large cases.

Implementation tasks:

- Add dedicated viewers:
  - EVTX event viewer.
  - Registry key/value viewer.
  - Timeline event viewer.
  - Hex/text fallback viewer.
  - Image/OCR viewer.
  - Email/message viewer.
- Add multi-pane workflow:
  - search results, source preview, related artifacts, timeline context, notes.
- Add compare/pivot tools:
  - compare two events/files.
  - show surrounding timeline.
  - show same user/same host/same process/same file path.
- Add keyboard shortcuts:
  - next/previous result, mark relevant, mark benign, add note, open source, add to report, focus search.

Acceptance criteria:

- Analyst can review 200 search hits without losing place.
- Every report item can be traced back to source, parser, timestamp, and reviewer action.

## Phase 11: Reporting and Court/Submission Outputs

Priority: high.

Objective: produce less noisy, more defensible reports.

Implementation tasks:

- Add report modes:
  - executive summary.
  - technical appendix.
  - court/legal handoff.
  - hash manifest only.
  - EVTX detection appendix.
- Add PDF and DOCX export.
- Include:
  - scope, tools/version, evidence IDs, source hashes, parser versions, skipped/failed areas, analyst notes, review status.
- Add report preview with “why included” and “what source proves this”.

Acceptance criteria:

- Report defaults to selected/reviewed evidence only.
- No noisy raw columns unless technical appendix is selected.
- PDF/DOCX exports match Markdown content and include hash appendices.

## Phase 12: Validation Corpus and Cross-Tool Comparison

Priority: critical for credibility.

Objective: prevent silent parser mistakes.

Implementation tasks:

- Build fixture corpus:
  - EVTX native, exported XML, exported JSONL.
  - Registry hives and `.reg` exports.
  - Prefetch, LNK, Jump Lists, MFT, USN.
  - Browser DB with WAL/SHM.
  - Corrupt/truncated fixtures.
- For each fixture:
  - expected row counts.
  - expected key field values.
  - expected warnings.
  - cross-tool comparison output where legally redistributable.
- Add validation command:
  - parser coverage table.
  - fixture pass/fail.
  - known false negatives.
  - reportability status.

Acceptance criteria:

- Any parser change must pass fixture contract tests.
- Validation report shows exact parser coverage and known limitations.
- At least EVTX, registry, prefetch, LNK, MFT, browser fixtures have cross-tool comparison notes.

## Phase 13: Platform and Packaging

Priority: medium-high.

Objective: make Windows/macOS users actually able to run it.

Implementation tasks:

- Windows:
  - signed or at least repeatably built portable package.
  - PowerShell launcher.
  - optional bundled external parser adapters where license permits.
- macOS/Linux:
  - shell launcher.
  - Homebrew/venv-friendly install docs.
  - external tool diagnostics.
- Add “first run self-test”:
  - sample case.
  - doctor check.
  - validation package.

Acceptance criteria:

- Fresh Windows/macOS user can run sample, search, review, and export report in under 15 minutes.
- Installer/portable package includes version, build hash, and dependency manifest.

## Suggested Implementation Order

1. EVTX parser/import foundation.
2. EVTX detection/rules and UI views.
3. KAPE-style collection profiles.
4. Execution artifacts: Prefetch, Amcache, ShimCache, UserAssist, BAM.
5. MFT/USN and VSC comparison.
6. Direct registry hive parsing/import.
7. LNK/Jump List/ShellItem deep parsing.
8. Search/indexing default to Case DB/FTS with source filters.
9. Dedicated viewers and keyboard-driven review flow.
10. PDF/DOCX report exports.
11. Validation corpus and cross-tool comparison.
12. Packaging and fresh-machine validation.

## Near-Term Milestone: EVTX Reportable Release

Target score improvement: 68/100 to 74/100 from a real analyst perspective.

Scope:

- Binary EVTX parsing/import.
- Core Windows event normalization.
- Event ID categorization.
- Timeline and Case DB integration.
- Search filters by channel/event ID/provider/user/computer.
- EVTX viewer.
- Fixture tests.
- Report-safe output with source hash and parser version.

Exit criteria:

- Analyst can point RapidTriage at a mounted Windows image and get Security/System/PowerShell/Sysmon EVTX events in search/timeline without manually exporting XML first.
- Analyst can select important EVTX events and include them in a report with source validation.
- Unsupported/corrupt logs show warnings instead of silent success.

