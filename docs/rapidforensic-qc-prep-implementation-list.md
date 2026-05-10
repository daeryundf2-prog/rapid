# RapidForensic QC-Prep Implementation List

Last updated: 2026-05-11

## Current Evidence Snapshot

- Branch: `codex/rapidforensic-complete`
- Latest reviewed commit: `d8b0d76 Make source reads verify SQLite rows`
- Commercial readiness score: `79`
- Commercial claim allowed: `false`
- Maturity gates: implemented `120/120`, usable `120/120`, validated `0/120`, commercial-grade `0/120`
- Taxonomy audit: `48/48` targets covered, partial `0`, missing `0`, strict pass `true`, artifact type literals `146`

Interpretation: RapidForensic has broad internal feature coverage and a usable single-case scaffold, but QC should not be treated as final acceptance yet. The next work must turn broad coverage into source-verifiable, large-case-tolerant, trusted-diff-ready workflows.

## QC-Prep Goal

Before formal QC, a Windows 11 E01 single-case workflow should let an analyst:

1. Select evidence and see dependency, image, partition, and risk status.
2. Process or resume the case without losing stage evidence.
3. Search files, documents, logs, browser/AI traces, OCR text, email, messenger, and normalized artifacts.
4. Open the original source, table row, record, offset, or attachment behind each result.
5. Mark review decisions, compare evidence, and include selected items in a report.
6. Export a defensible report bundle with hashes, provenance, warnings, limitations, and validation slots.

## Phase 1: Single-Case E01 Workflow

1. Wire E01 selection to one end-to-end command and GUI flow: preflight, partition selection, extraction, run, search, review, report. Current implementation emits `qc-prep-e01-end-to-end-handoff-v1` in E01 evidence preflight and shows an `e01-end-to-end-handoff` GUI card with Start/Search/Review/Report handoff actions; remaining QC still requires a real Windows 11 E01 smoke run and trusted extraction logs.
2. Add GUI partition browser with partition number, start sector, size, filesystem guess, recommendation, and manual override. Current implementation emits `e01-partition-browser-v1` in the E01 workflow and renders an `e01-partition-browser` GUI table with manual start-sector handoff into the run form; remaining QC still requires a real E01/mmls partition transcript and trusted-tool comparison evidence.
3. Add VSC discovery and extraction handoff for E01/RAW workflows, not only already-mounted folder comparison.
4. Surface stage checkpoint, resume, cancel, retry, and failure classification in GUI and JSON outputs.
5. Add fresh Windows/macOS GUI launch smoke evidence for the single-case workflow.

## Phase 2: Source Verification And Viewer Locators

6. Connect search-result rows to source viewer actions in the GUI.
7. Add EVTX record locator with file path, record ID, channel, provider, event ID, record offset where available, source hash, and validation warning.
8. Add Registry key/value/cell locator with hive path, key path, value name, cell offset, allocation/deleted status, source hash, and transaction replay status.
9. Add MFT/USN record locator with FRN, parent FRN, sequence, USN, reason flags, path confidence, and source citation.
10. Add email attachment locator with message ID, attachment index/name, hash, bounded preview, and export warning.
11. Connect SQLite row locator to the GUI source viewer and review note flow.
12. Connect hex range citations to report candidates and comparison pins.
13. Connect image, video, audio, OCR, and translation sidecar viewers to the evidence tray.
14. Let current-file search hits append structured citations to review notes and report drafts.

## Phase 3: Windows Core Parser Depth

15. Complete EVTX BinXML grammar coverage beyond current best-effort structures.
16. Add provider/resource message rendering matrix and unresolved-template warnings.
17. Build corrupt, slack, and deleted EVTX recovery fixtures with offset/confidence reporting.
18. Implement Registry LOG1/LOG2 transaction replay or prove equivalent output through trusted diffs.
19. Strengthen Registry deleted key/value recovery with allocator-state checks and false-positive fixtures.
20. Deepen NTUSER/UsrClass user activity parsing: RunMRU, RecentDocs, TypedURLs, UserAssist, ComDlg32, MountPoints, ShellBags linkage.
21. Deepen SAM/SECURITY/SYSTEM parsing for F/V records, aliases, memberships, LSA metadata, privileges, services, ControlSets, mounted devices.
22. Deepen Amcache schema/version decoding and timestamp semantics.
23. Deepen ShimCache/AppCompatCache OS-version binary layouts and "not direct execution proof" UX.
24. Deepen BAM/DAM binary value decoding and SID/path/timestamp correlation.
25. Deepen SRUM native ESE table/page decoding and counter semantics.
26. Deepen Windows.edb ESE table, property, content, and deleted-state decoding.
27. Complete MFT attribute-list, runlist, resident/nonresident data, parent path reconstruction, and deleted-state validation.
28. Complete USN v2/v3/v4 replay, FRN path cache, rename/delete reconstruction, and large-journal cursor handling.
29. Deepen JumpList DestList, CFB/OLE stream, AppID mapping, deleted entry recovery, and embedded LNK linkage.
30. Deepen ShellBags binary shell item decoding, BagMRU/Bags relationship, transaction logs, and deleted/slack checks.
31. Deepen Prefetch version 17/23/26/30/31 support, compressed PF handling, volume/file metrics, and trace-chain evidence.
32. Deepen LNK ShellLinkHeader, LinkInfo, StringData, ExtraData, TrackerDataBlock, and target/source citation.

## Phase 4: Web, AI, Messenger, Mail, And Cloud Evidence

33. Reconstruct browser cache objects with request/response metadata and validation warnings.
34. Decode browser session, local storage, extension, sync, and IndexedDB stores with profile attribution.
35. Keep cookies/passwords/tokens behind lawful authority gates, redaction, and audit logs.
36. Parse AI service exports and browser traces for ChatGPT, Claude, Gemini, Perplexity, Copilot-style Q/A pairing.
37. Formalize PC KakaoTalk legacy and post-patch schema/version matrix with fixtures and Windows packaging notes.
38. Add WhatsApp export/native parser with message, contacts, calls, media, deleted-row limitations, and lawful key workflow.
39. Add Telegram export/native parser with account, media, cache, and encrypted-store warning.
40. Add Signal parser with SQLCipher/key handling separated into secure lawful workflow.
41. Add LINE, Discord, Instagram, WeChat service-specific export/native schema mappers.
42. Add PST/OST mailbox parsing depth for folders, messages, attachments, deleted items, headers, and threading.
43. Add Google Takeout product matrix for Gmail, Drive, Photos, Activity, Location, account, and device attribution.
44. Add iCloud export parser for Photos, albums, shares, devices, EXIF, and account context.
45. Add M365/Teams/OneDrive/eDiscovery parser for permissions, reactions, attachments, SharePoint, and audit exports.
46. Deepen iOS backup parser for Manifest.db, domains, app DB mapping, SMS, media, and encrypted-backup lawful key workflow.
47. Deepen Android artifact parser for SMS, call log, contacts, browser, media, app DBs, packages, signatures, and permissions.

## Phase 5: Search And Large-Case Performance

48. Add a SearchBackend abstraction so the UI and CLI can target different indexing engines consistently.
49. Keep SQLite FTS as the default local backend with explicit limits and query-plan metadata.
50. Evaluate a local Lucene/Tantivy-style backend for million-row text/artifact search.
51. Add optional Elasticsearch/OpenSearch adapter for lab/server deployments without making it mandatory.
52. Normalize index schema across documents, file metadata, EVTX, Registry, OCR, email, messenger, browser, AI, and timeline rows.
53. Add 100k, 1M, and 10M synthetic benchmark generators with reproducible manifests.
54. Make cursor pagination uniform across files, docs, artifacts, search, timeline, report candidates, and review queues.
55. Enforce true UI virtualization and persisted viewport for massive tables.
56. Replace any silent SQLite row cap in current-file search with full cursor scan, truncation disclosure, and resume state.
57. Persist hash cache across runs with size/mtime/inode/content-hash invalidation.
58. Add duplicate grouping for exact hashes, fuzzy text, and perceptual image/video candidates.
59. Move risky/heavy parsers behind subprocess isolation with crash quarantine.
60. Add hard memory caps where OS support exists and clear warnings where only cooperative caps exist.

## Phase 6: Review, Reporting, And Evidence Packages

61. Harden evidence tray state for selected, pinned, compared, and report-candidate evidence.
62. Stabilize relevant, needs-review, excluded, include-in-report, tags, notes, assignee, priority, and verification status.
63. Persist A/B/C compare notes and connect compared snippets to report candidates.
64. Strengthen report citation manager with source path, source hash, parser version, offset/row/record locator, confidence, and limitation text.
65. Strengthen selected evidence version history with immutable local history hashes.
66. Automate court exhibit bundle generation with selected evidence, report outputs, manifest, hashes, provenance, and signing slot.
67. Strengthen chain-of-custody workflow and acquisition metadata capture.
68. Strengthen audit hash chain and tamper-evident bundle export.
69. Generate per-run validation package with commands, tool versions, source hashes, output hashes, parser versions, diffs, warnings, limitations, and reviewer status.
70. Add trusted-tool import wizard for EvtxECmd, Hayabusa, RECmd, MFTECmd, JLECmd, PECmd, ShellBagsExplorer, SrumECmd, and libesedb outputs.
71. Add mismatch dashboard for trusted diffs with missing rows, extra rows, field mismatches, truncation, and severity.
72. Add false-positive/false-negative recording UI and JSON export.
73. Calibrate parser confidence scoring and reportability state per artifact family.
74. Add limitation/legal warning copy per artifact type with report wording guardrails.
75. Generate a QC checklist automatically from the run, validation package, and remaining blockers.

## Phase 7: Validation Corpus And QC Execution

76. Connect NIST CFReDS/CFTT and other public forensic corpora where licensing permits.
77. Add EvtxECmd and Hayabusa diff runners for EVTX validation.
78. Add RECmd and Registry Explorer diff runners for Registry validation.
79. Add MFTECmd, analyzeMFT, and UsnJrnl2Csv diff runners for NTFS validation.
80. Add SrumECmd, libesedb, and Windows Search export diff runners for ESE validation.
81. Add PECmd, JLECmd, and ShellBagsExplorer diff runners for execution and user activity artifacts.
82. Build or attach a real Windows 11 E01 known-answer case manifest.
83. Build corrupt, deleted, slack, encrypted, and malformed fixture corpora.
84. Build large-case performance corpus and browser trace evidence.
85. Generate final QC report from validation results, mismatch dashboard, performance runs, reviewer signoff, and remaining blocker ledger.

## Recommended Execution Order

1. Finish Phase 1 and Phase 2 first so the analyst workflow is usable end-to-end.
2. Work Phase 3 in small trusted-diff-ready batches: EVTX, Registry, MFT/USN, ESE, then execution artifacts.
3. Add Phase 5 search/large-case work before testing large real cases.
4. Complete Phase 6 reporting and validation packages before formal QC.
5. Run Phase 7 with real corpora and trusted tool outputs.

## Non-Negotiable QC Rule

Do not treat taxonomy coverage, smoke fixtures, or internal manifests as final QC. A feature becomes QC-passable only when it has source-viewer proof, source hashes, row/record/offset locator, tests, limitation text, and either known-answer validation or trusted-tool diff evidence.
