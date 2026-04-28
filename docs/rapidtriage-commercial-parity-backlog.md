# RapidTriage Commercial Parity Backlog

This backlog is the ordered 1-121 gap list for moving RapidTriage toward AXIOM/WISDOM-class usefulness. It is intentionally conservative: an item is not "Done" unless it is implemented, fixture-backed where practical, documented, and safe to explain to a forensic user without overstating evidence strength.

Status legend: `Done`, `Partial+`, `Partial`, `Planned`, `External`.

## Execution Rule

Work proceeds in number order unless a dependency makes a later item necessary first. Each commit should update this file when the status or acceptance evidence changes.

## 1-25 Native Evidence And Windows Core

1. Native EVTX field fidelity. Status: Partial+. Acceptance: emit native record ID, timestamp, hash, integrity, sequence, file/chunk metadata, searchable strings, parameter candidates, explicit BinXML status, and guidance for report-grade validation.
2. EVTX BinXML template decoding. Status: Planned. Acceptance: decode Event/System/EventData/UserData nodes from binary EVTX without external exports.
3. EVTX deleted/slack record recovery. Status: Planned. Acceptance: identify recovered records separately with offset, integrity, confidence, and caution labels.
4. EVTX semantic tagging. Status: Partial+. Acceptance: map high-value IDs and channels to analyst categories, families, risk flags, and review recommendations.
5. EVTX timeline correlation. Status: Partial. Acceptance: correlate logon, process, PowerShell, service, task, RDP, WMI, Defender, and firewall events into scenario pivots.
6. Windows account and OS profile parsing. Status: Partial+. Acceptance: hostname, timezone, boot/shutdown, profiles, account hints, RID/name candidates, admin/disabled hints where available.
7. SAM binary account decoding. Status: Planned. Acceptance: decode SAM user records, RID, flags, timestamps, and group membership from native hives.
8. SECURITY hive policy and secrets triage. Status: Planned. Acceptance: inventory policy, LSA, audit, and sensitive-key presence without unsafe secret disclosure by default.
9. SYSTEM hive control set reconstruction. Status: Planned. Acceptance: resolve current control set, mounted devices, services, timezone, USB, and computer metadata.
10. SOFTWARE hive application inventory. Status: Planned. Acceptance: installed programs, uninstall keys, App Paths, Run keys, shell extensions, and policy pivots.
11. Registry key-tree reconstruction. Status: Partial. Acceptance: native hive key/value tree with last-write timestamps and source offsets.
12. Registry deleted cell testimony. Status: Partial. Acceptance: distinguish allocated/free/deleted key/value candidates with confidence and validation warnings.
13. Registry value binary decoding. Status: Planned. Acceptance: decode common REG_BINARY/FILETIME/MRUListEx/ShellBag/UserAssist value structures.
14. Registry timeline export. Status: Partial. Acceptance: unified key/value/user-activity timeline with source hive, path, value, timestamp, and confidence.
15. Prefetch binary parsing. Status: Partial. Acceptance: executable name, run count, last run times, volume info, referenced files, hash, and version handling.
16. Amcache parsing. Status: Planned. Acceptance: app execution/install records, SHA1, paths, publisher, timestamps, and source hive provenance.
17. Shimcache/AppCompatCache parsing. Status: Planned. Acceptance: parse SYSTEM hive cache entries with path, timestamps, flags, and OS-version caution.
18. BAM/DAM execution parsing. Status: Planned. Acceptance: user SID, executable path, last execution timestamp, and confidence.
19. SRUM table decoding. Status: Partial. Acceptance: native SRUDB app/network/resource tables with app, user, bytes, energy, and timestamps.
20. Windows Search EDB table decoding. Status: Partial. Acceptance: native index entries with paths, URLs, content snippets, metadata, and deleted/index status.
21. MFT attribute decoding. Status: Partial. Acceptance: native FILE records, filenames, timestamps, resident data hints, deleted/in-use status, and sequence validation.
22. USN journal native parsing. Status: Partial+. Acceptance: v2/v3 records, reasons, FRN/parent FRN, file names, timestamps, and validation warnings.
23. Volume Shadow Copy orchestration. Status: Partial+. Acceptance: compare, extract, hash, and report deleted/changed files across snapshots.
24. BitLocker evidence handling. Status: Planned. Acceptance: identify encrypted volumes, metadata, recovery-key candidates, and safe mount/decrypt workflow guidance.
25. Windows recycle bin parsing. Status: Planned. Acceptance: parse `$I`/`$R` pairs with original path, deletion time, size, hashes, and user SID.

## 26-50 User Activity, Browser, Internet, And AI

26. Unified browser history. Status: Done. Acceptance: Chrome, Edge, Brave, Firefox history/download rows and internet category pivots.
27. Browser cache inventory. Status: Planned. Acceptance: cache entries with URL, timestamps, MIME, size, hashes, and preview-safe extraction.
28. Browser cookies and sessions. Status: Planned. Acceptance: cookie/session metadata with redaction controls and secure handling.
29. Browser autofill and logins inventory. Status: Planned. Acceptance: identify presence and metadata without dumping secrets by default.
30. Browser extension inventory. Status: Planned. Acceptance: extension IDs, names, versions, permissions, install paths, and risk flags.
31. AI service usage detection. Status: Partial+. Acceptance: ChatGPT and common assistant/search visits, prompts, storage candidates, and service labels.
32. AI question/answer transcript reconstruction. Status: Partial+. Acceptance: pair candidate user/assistant messages with completeness and validation status.
33. Per-file search within viewer. Status: Partial. Acceptance: search current file preview separately from whole-case search.
34. Whole-case keyword search. Status: Done. Acceptance: indexed case search across paths, text previews, metadata, and artifact rows.
35. OCR queue and OCR sidecar import. Status: Partial. Acceptance: queue images/PDFs, import OCR text sidecars, preserve language and confidence hints.
36. Korean OCR execution. Status: Planned. Acceptance: optional OCR runtime path with Korean language support and reproducible confidence metadata.
37. Translation workflow. Status: Planned. Acceptance: mark translation-needed items and import translated sidecars without changing original evidence.
38. Web artifact threat intelligence. Status: Planned. Acceptance: optional URL/IP/hash enrichment with offline-safe mode and source/version metadata.
39. Download provenance. Status: Partial+. Acceptance: browser downloads, Zone.Identifier, paths, URLs, timestamps, and hashes correlated.
40. Email container parsing. Status: Planned. Acceptance: PST/OST/MBOX/EML/MSG inventory, messages, attachments, headers, hashes, and search text.
41. Chat exports. Status: Partial. Acceptance: normalize common JSON/CSV chat exports with participants, timestamps, messages, attachments.
42. Cloud account export imports. Status: Partial+. Acceptance: Google/Apple/general JSON exports normalized with source hashes and bounded schemas.
43. Social media export imports. Status: Planned. Acceptance: normalize posts, messages, media references, account metadata, and timestamps.
44. Remote desktop artifacts. Status: Partial+. Acceptance: Default.rdp, cache inventory, RDP registry exports, and event correlations.
45. VPN and remote access clients. Status: Planned. Acceptance: known config/log locations, connection history candidates, and credential-safe metadata.
46. Shell history. Status: Partial+. Acceptance: PowerShell PSReadLine and command history rows with risk flags.
47. ConsoleHost and PowerShell module pivots. Status: Planned. Acceptance: module/log/profile/script artifacts with paths, commands, and timestamps.
48. UserAssist deep decoding. Status: Partial. Acceptance: ROT13 names, run counts/timestamps from native/exported user hives.
49. ShellBags deep decoding. Status: Partial. Acceptance: folder paths, node timestamps, source key paths, and confidence.
50. RecentDocs/OpenSave/LastVisited MRUs. Status: Partial. Acceptance: user activity pivots with key path, value, decoded target, and source.

## 51-75 Viewer, Review, Reporting, And Case Workflow

51. Large-case virtualized viewer. Status: Partial. Acceptance: paged result rendering without loading all rows into browser memory.
52. Side-by-side comparison. Status: Done. Acceptance: compare tray and text diff for selected evidence.
53. Evidence pinning and review board. Status: Done. Acceptance: mark, verify, reject, candidate, and report states persist in Case DB.
54. Batch review actions. Status: Done. Acceptance: apply review status to selected search results.
55. Keyboard shortcuts. Status: Partial. Acceptance: documented next/previous, open, pin, verify, reject, search, compare shortcuts.
56. Saved searches and keyword packs. Status: Done. Acceptance: persist searches and reuse per case.
57. Review audit trail. Status: Partial. Acceptance: who/when/action/source fields for review changes and report inclusion.
58. Evidence hash appendix. Status: Done. Acceptance: export source/item hashes in report and reviewer bundle.
59. Chain-of-custody package. Status: Partial. Acceptance: evidence IDs, source hashes, tool versions, run profile, warnings, and audit links.
60. Report templates. Status: Done. Acceptance: executive, technical, legal handoff, and hash-only modes.
61. Report citation model. Status: Partial. Acceptance: every report item cites source path, hash, parser, offset when available, and review status.
62. PDF/DOCX report validation. Status: Partial. Acceptance: exported reports render consistently and include manifest hashes.
63. Portable reviewer bundle. Status: Done. Acceptance: static HTML/JSON/report/hash package without original image data.
64. Redaction workflow. Status: Planned. Acceptance: mark and export redacted previews while preserving original hashes.
65. Evidence notes and annotations. Status: Partial. Acceptance: notes attach to artifact rows and appear in reports when selected.
66. Cross-case search. Status: Planned. Acceptance: search multiple Case DBs with clear case/evidence boundaries.
67. Case merge/split. Status: Planned. Acceptance: import/export selected evidence and review state safely between cases.
68. Case backup/restore. Status: Planned. Acceptance: portable archive with DB, reports, manifests, and integrity verification.
69. Multi-user collaboration. Status: Planned. Acceptance: users, roles, locks, conflict handling, and audit trail.
70. Role-based permissions. Status: Planned. Acceptance: analyst/reviewer/admin permissions for case, export, and settings.
71. Dashboard triage. Status: Partial. Acceptance: high-risk summaries, source warnings, parser gaps, and next actions.
72. Timeline view. Status: Partial. Acceptance: unified artifact/event timeline with filtering and pivots.
73. Entity pivots. Status: Partial. Acceptance: user, host, IP, URL, hash, process, file, and service pivot pages.
74. Parser transparency view. Status: Partial+. Acceptance: show processed/skipped/capped/failed parsers and warnings.
75. Unsupported evidence guidance. Status: Done. Acceptance: unsupported images/formats show mount/export guidance instead of silent failure.

## 76-100 Evidence Adapters, Performance, Packaging, And Validation

76. E01/Ex01 adapter. Status: Partial+. Acceptance: libewf/Sleuth Kit extraction when installed, otherwise clear guidance.
77. Raw/dd/split image adapter. Status: Partial+. Acceptance: recover through Sleuth Kit where available and record tool versions.
78. ISO/DMG/WIM/SWM adapter. Status: Partial+. Acceptance: safe read-only extraction through available archive tools.
79. VHD/VHDX/VMDK/VDI/QCOW adapter. Status: Partial+. Acceptance: qemu-img conversion plus extraction where available.
80. AFF/AFF4 adapter. Status: Planned. Acceptance: detect and route through supported tooling with hashes and warnings.
81. AD1/L01/Lx01 adapter. Status: Planned. Acceptance: detect, document export-first path, and parse trusted exported folders.
82. XVA adapter. Status: Planned. Acceptance: detect Xen exports and route to extraction/conversion path.
83. Mobile extraction imports. Status: Partial. Acceptance: Cellebrite/XRY/GrayKey/AXIOM-style export normalization where legally feasible.
84. APK malware triage. Status: Partial+. Acceptance: APK manifest, permissions, strings, URLs/IPs, hashes, and risk flags.
85. iOS backup import. Status: Planned. Acceptance: parse authorized backup/export metadata, messages, files, apps, and accounts.
86. Android backup/export import. Status: Partial. Acceptance: normalize exported app/message/file artifacts and APKs.
87. Memory dump imports. Status: Partial+. Acceptance: Volatility JSON/JSONL plus bounded direct string/indicator scans.
88. Memory process tree and malfind view. Status: Partial. Acceptance: normalize process, cmdline, netscan, malfind, and risk flags.
89. BitLocker key candidates from memory. Status: Partial+. Acceptance: redacted candidate detection with group validation and source offsets.
90. YARA/Sigma rule execution. Status: Planned. Acceptance: optional rule packs, versioning, matches, false-positive notes, and report links.
91. Malware sandbox/export import. Status: Planned. Acceptance: ingest sandbox JSON/CSV reports and correlate hashes/URLs/IPs.
92. Image perceptual hash. Status: Done. Acceptance: pHash buckets and image similarity hints.
93. Visual similarity grouping. Status: Partial. Acceptance: perceptual hash clusters and reviewer workflow.
94. Deepfake/media authenticity triage. Status: Planned. Acceptance: metadata and optional classifier output with model/version cautions.
95. Thumbnail generation. Status: Partial. Acceptance: bounded safe previews with no full evidence exposure in reviewer bundle.
96. Document text extraction. Status: Partial. Acceptance: PDFs/Office/text/logs indexed with limits, source hashes, and error reporting.
97. Archive recursion. Status: Partial. Acceptance: bounded ZIP/7z/tar extraction/indexing with bomb protections and provenance.
98. Carving workflow. Status: Planned. Acceptance: optional, explicit deep mode with file signatures, offsets, hashes, and time/cap warnings.
99. Incremental indexing. Status: Partial. Acceptance: resume/reuse completed outputs and avoid duplicate Case DB imports.
100. Large-case benchmarks. Status: Partial. Acceptance: 10k/100k/1M synthetic and existing-root modes with published latency/resource targets.

## 101-121 Cross-Platform, Security, Release, And Final Parser Depth

101. Windows launcher and quickstart. Status: Done. Acceptance: non-developer Windows user can start web UI with documented steps.
102. macOS launcher and quickstart. Status: Done. Acceptance: macOS user can start web UI with documented steps.
103. Linux support. Status: Partial+. Acceptance: CLI/web flow works on common Linux environments with documented optional tools.
104. Signed Windows installer. Status: External. Acceptance: repeatable build plus code-signing certificate and verification evidence.
105. macOS notarization. Status: External. Acceptance: notarized package with Gatekeeper validation evidence.
106. Portable/offline release bundle. Status: Partial. Acceptance: dependency-light reviewer/operator package with checksums.
107. Schema versioning. Status: Partial+. Acceptance: parser/output schema versions and changelog for breaking changes.
108. Release validation package. Status: Partial+. Acceptance: validation command emits required checks, docs, limitations, and evidence fields.
109. Independent validation corpus. Status: Planned. Acceptance: public or controlled corpus with expected parser counts and false-negative notes.
110. Parser fuzz/safety tests. Status: Planned. Acceptance: malformed files do not crash or escape configured bounds.
111. Local-only security default. Status: Done. Acceptance: remote bind requires explicit auth/guardrails.
112. Export/report sanitization. Status: Done. Acceptance: HTML escaping, CSP/no-referrer, path traversal protections.
113. Secrets handling policy. Status: Partial. Acceptance: redact secrets by default, expose controlled reveal/export workflow, and audit access.
114. Plugin/parser SDK. Status: Planned. Acceptance: documented parser interface, fixtures, schema checks, and compatibility tests.
115. External parser import contracts. Status: Partial+. Acceptance: EvtxECmd/Hayabusa/Chainsaw/Velociraptor and common CSV/JSON imports documented/tested.
116. Training materials. Status: Partial. Acceptance: guided sample case, analyst workflow, and known limitations.
117. Support/SLA package. Status: External. Acceptance: staffed support model, escalation, and release/patch expectations.
118. Legal defensibility notes. Status: Partial. Acceptance: evidence-strength labels, validation warnings, hash provenance, and limitation disclosure.
119. Commercial comparison scoring. Status: Partial+. Acceptance: cold score against AXIOM/WISDOM expectations is documented and updated per milestone.
120. End-to-end forensic scenario tests. Status: Partial. Acceptance: sample cases cover intrusion, insider, malware, browser/AI usage, and report handoff.
121. NTUSER.DAT and UsrClass.dat deep user-hive analysis. Status: Partial+. Acceptance: user activity pivots for UserAssist, TypedURLs/TypedPaths, RecentDocs, Run/RunOnce, Explorer/MRU, ShellBags, MountPoints2, Network, and ComDlg32/OpenSavePidlMRU; full key-tree, binary values, deleted values, and per-key last-write testimony remain to be completed.
