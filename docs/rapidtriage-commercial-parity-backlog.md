# RapidTriage Commercial Parity Backlog

This is the current 120-item commercial parity backlog for moving RapidTriage toward AXIOM/WISDOM-class usefulness. It is intentionally strict: an item is not `Done` unless it is implemented, fixture-backed where practical, documented, and safe to explain to a forensic user without overstating evidence strength.

Status legend: `Done`, `Partial+`, `Partial`, `Planned`, `External`.

Compatibility note: the earlier historical item 121, NTUSER.DAT and UsrClass.dat deep analysis, is now folded into items 4, 5, 6, 15, 18, 65, 90, and 91 so the active execution list follows the user's latest 120-item structure.

## Execution Rule

Work proceeds in number order unless a dependency makes a later item necessary first. Each commit should update this file when the status or acceptance evidence changes.

## A. Core Forensic Capability

1. Native EVTX BinXML full parsing. Status: Partial+. Acceptance: decode binary EVTX records into full Event/System/EventData/UserData fields without relying on external exports; current native rows expose record metadata, strings, integrity, explicit `evtx_binxml_status`, first-pass BinXML token scans for fragment headers/elements/attributes/value text/template headers, inline String/ANSI/integer/bool/GUID/SID/FILETIME/SYSTIME/binary scalar decoding, TemplateInstance IDs, TemplateInstance value spec/value decoding for common scalar types, substitution value fields, promoted `Event/System`, `EventData`/named `Data`, and `UserData` fields, normalized EventID/provider/channel/computer/level/timestamp/process/thread/user-SID/command pivots, rendered previews, and `eventlog-chunk` structure rows for native chunk bounds/checksum observations. Remaining commercial gap: complete provider-specific BinXML grammar coverage and independent corpus validation.
2. EVTX event template/message rendering. Status: Partial+. Acceptance: render provider templates/messages where available and preserve unresolved template IDs with validation warnings; current rows preserve imported rendered messages from XML/JSON/CSV exports, expose `event_message` plus `message_rendering` provenance, render high-value built-in fallback templates for common Security/PowerShell/log-clear/account/process/service/task/Sysmon/Defender/WMI/Firewall events, retain native TemplateInstance IDs, and mark native fallback messages as validation-required until provider DLL/resource-table rendering is implemented.
3. EVTX deleted/corrupt record recovery validation. Status: Partial+. Acceptance: recover slack/deleted/corrupt candidate records with offset, integrity, confidence, and caution labels; current native scans emit `evtx_recovery_context` on parseable rows, flag chunk slack/deleted candidates when chunk free-space metadata is present, emit `eventlog-record-candidate` rows for corrupt/out-of-bounds record headers, emit `eventlog-chunk` rows with structure plausibility/checksum observations, and summarize recovery/allocation/chunk integrity counts. Remaining commercial gap: large validation corpus coverage for real-world deleted EVTX slack and corrupt chunk edge cases.
4. Registry hive full key tree reconstruction. Status: Partial+. Acceptance: reconstruct native hive key/value tree with last-write timestamps, source offsets, cell allocation state, and parser confidence; current native hive scans now prefer bounded `hbin` cell walking, fall back to signature scanning, and emit `registry-key-tree-node` rows from `nk` parent/subkey/value-list metadata, preserving key paths where parent chains are recoverable plus offsets, subkey/value names, last-write hints, allocation state, confidence, and validation guidance. Remaining commercial gap: transaction-log replay and broad corpus validation across malformed/large hives.
5. Registry deleted key/value recovery. Status: Partial+. Acceptance: distinguish allocated/free/deleted key/value candidates and report recovery confidence without overstating testimony; current scans emit generic `registry-deleted-cell-candidate` rows plus key-specific `registry-key-recovery-candidate` and value-specific `registry-value-recovery-candidate` rows for free `nk`/`vk` cells with offsets, cautious path/data previews, caution labels, confidence, and validation-required guidance. Remaining commercial gap: deleted-key/value testimony validation against full hive allocator state and transaction logs.
6. SAM/SECURITY/SYSTEM account and permission deep parser. Status: Partial+. Acceptance: decode users, groups, privileges, current control set, LSA/policy-sensitive locations, services, mounted devices, and timezone/boot metadata; current rows include account/profile summaries, native SAM account/RID candidates, service configuration rows, mounted-device rows, LSA sensitive-location rows, privilege-assignment rows, current control set hints, boot/shutdown/timezone pivots, hashes, confidence, and validation guidance. Remaining commercial gap: full SAM F/V binary decoding, SECURITY secret decryption, group membership reconstruction, and transaction-log validation.
7. Amcache parser. Status: Partial+. Acceptance: extract application execution/install records, hashes, paths, publisher metadata, and timestamps; current registry export rows normalize Amcache keys/values and native `Amcache.hve` rows emit bounded hive string-pivot `amcache-hive` and `amcache-entry` candidates with paths, SHA1 candidates, publisher strings, confidence, hashes, and validation guidance. Remaining commercial gap: full Amcache.hve schema/version decoding and report-grade install/execution timestamp extraction.
8. ShimCache/AppCompatCache parser. Status: Partial+. Acceptance: parse SYSTEM hive cache entries with OS-version handling, paths, timestamps, flags, and caveats; current export rows emit `shimcache-entry` with path/timestamp extraction, confidence, risk flags, and an explicit not-proof-of-execution caveat. Remaining commercial gap: native binary AppCompatCache layout decoding across Windows versions.
9. BAM/DAM execution parser. Status: Partial+. Acceptance: parse user SID, executable path, last execution timestamp, and confidence; current export rows emit `bam-entry` with user SID, device/executable path, FILETIME timestamp decoding when present, confidence, risk flags, and correlation guidance. Remaining commercial gap: native SYSTEM hive binary value interpretation and broad version validation.
10. SRUM full ESE table parser. Status: Partial+. Acceptance: decode native SRUDB tables for app, network, resource, user, bytes, energy, and timestamps; current imports normalize app/network/resource rows with bytes total, interface/profile, energy/CPU, and native SRUDB emits ESE header/string pivots plus `srum-table-candidate` rows for likely network/app/energy/user table families. Remaining commercial gap: full native ESE catalog/table/page decoding and row-level timestamp/counter extraction.
11. Windows.edb full ESE parser. Status: Partial. Acceptance: decode native Windows Search tables into paths, URLs, content snippets, metadata, deleted/index state, and timestamps.
12. `$MFT` full attribute parser. Status: Partial. Acceptance: decode FILE records, attributes, filenames, timestamps, resident/nonresident data hints, deleted/in-use status, and sequence validation.
13. `$UsnJrnl` large-scale timeline parser. Status: Partial+. Acceptance: parse v2/v3 records at scale with FRN/parent FRN, reason flags, timestamps, and pagination-friendly output.
14. JumpList DestList deep parser. Status: Partial. Acceptance: decode DestList MRU/account metadata, embedded LNK streams, timestamps, and source stream provenance.
15. ShellBags native hive parser. Status: Partial. Acceptance: decode ShellBag folder nodes, paths, timestamps, bag IDs, source key paths, and confidence from native user hives.
16. Prefetch full version parser. Status: Partial. Acceptance: support common Prefetch versions with run count, last run times, volume info, file references, and hash metadata.
17. LNK full metadata parser. Status: Partial+. Acceptance: parse target path, working dir, arguments, timestamps, drive/network metadata, tracker data, and shell item metadata.
18. WER/Defender/Firewall/Task Scheduler/WMI deep parser. Status: Partial+. Acceptance: parse high-value logs/configs with normalized fields, risk flags, source hashes, and report-ready pivots.
19. Browser cache/session/extension/sync artifacts. Status: Planned. Acceptance: parse cache, sessions, extensions, sync metadata, cookies, and sensitive browser artifacts with strict legal warnings.
20. Chrome/Edge/Firefox/Safari unified browser timeline. Status: Partial+. Acceptance: normalize cross-browser history, downloads, typed URLs, visits, and source profile metadata into one timeline.
21. AI service transcript parser for ChatGPT/Claude/Gemini/Perplexity. Status: Partial+. Acceptance: recover service-labeled question/answer candidates, pairing confidence, source storage, and validation status.
22. E01/Ex01 fully integrated workflow. Status: Partial+. Acceptance: run libewf/Sleuth Kit workflow where installed, record tool versions, mount/extract safely, and show actionable fallback guidance.
23. RAW/split image robust partition/filesystem handling. Status: Partial+. Acceptance: enumerate partitions/filesystems, recover supported content read-only, and preserve extraction audit metadata.
24. VHD/VHDX/VMDK/VDI/QCOW direct handling polish. Status: Partial+. Acceptance: route through qemu-img/Sleuth Kit safely with clear progress, errors, hashes, and warnings.
25. AD1/L01/Lx01/AFF/AFF4/XVA support. Status: Planned. Acceptance: detect, route, import, or document export-first workflows with evidence hashes and limitation warnings.

## B. Mobile, Cloud, And Apps

26. Cellebrite/XRY/GrayKey/AXIOM export deep import. Status: Partial. Acceptance: normalize vendor export messages, contacts, calls, files, apps, accounts, media, source IDs, and hashes.
27. iOS backup parser. Status: Planned. Acceptance: parse authorized iOS backup files, domains, manifest DBs, app data, messages, media, accounts, and timestamps.
28. iOS keychain/artifact parser. Status: Planned. Acceptance: inventory keychain/artifact records with strict authorization, redaction, and legal warnings.
29. Android backup/artifact parser. Status: Partial. Acceptance: normalize Android backup/export app, file, SMS, call, contact, browser, and media artifacts.
30. Android app package/data parser. Status: Partial+. Acceptance: parse APK metadata, permissions, manifests, strings, native libraries, app data exports, and risk flags.
31. KakaoTalk parser. Status: Planned. Acceptance: parse authorized exports/backups for chats, participants, media references, timestamps, and schema versions.
32. WhatsApp parser. Status: Planned. Acceptance: parse authorized exports/backups for chats, contacts, media, calls, and timestamps.
33. Telegram parser. Status: Planned. Acceptance: parse Telegram desktop/mobile exports with chats, media references, contacts, and account metadata.
34. Signal parser. Status: Planned. Acceptance: parse authorized Signal exports/backups where technically and legally feasible with strong limitations.
35. WeChat/LINE/Discord/Instagram parser. Status: Planned. Acceptance: normalize authorized exports for messages, users, media, reactions, and timestamps.
36. Email PST/OST full mailbox parser. Status: Planned. Acceptance: parse mailbox folders, messages, headers, attachments, conversation threading, hashes, and search text.
37. Gmail/Google Takeout deep parser. Status: Partial. Acceptance: normalize mail, account activity, location, Drive metadata, photos, browser/account events, and timestamps.
38. Apple iCloud export parser. Status: Partial. Acceptance: normalize Apple account exports, device/account metadata, photos/files references, and timestamps.
39. Microsoft 365/OneDrive/Teams export parser. Status: Planned. Acceptance: parse M365 exports for mail, Teams chats, files, sharing, audit logs, and account metadata.
40. Cloud API acquisition workflow. Status: Partial. Acceptance: authorized request manifests, bounded API collection, redacted credentials, response hashes, and audit output.
41. Cloud token/credential secure handling. Status: Planned. Acceptance: redact secrets by default, store tokens safely, log access, and support controlled reveal/export.
42. Browser password/cookie/session artifact handling with strict legal warning. Status: Planned. Acceptance: sensitive artifacts are opt-in, redacted by default, audited, and legally warned.
43. Mobile app media/message timeline correlation. Status: Planned. Acceptance: correlate chats, media, contacts, app events, and filesystem timestamps.
44. Contact/call/SMS unified mobile view. Status: Partial. Acceptance: show normalized contacts, calls, SMS/messages, participants, timestamps, and source app/export.
45. App-specific known schema version management. Status: Planned. Acceptance: track parser schema versions, app DB versions, compatibility notes, and migration tests.

## C. Search, Analysis, And UX

46. Large-result clustering. Status: Planned. Acceptance: cluster similar search hits, files, media, entities, and repeated artifacts for review efficiency.
47. Entity view: people, accounts, email, phone, IP, and domain. Status: Partial. Acceptance: pivot by normalized entities with linked evidence, counts, first/last seen, and risk indicators.
48. Graph view: account-file-URL-time relationships. Status: Planned. Acceptance: visualize entities and evidence relationships with filters and source citations.
49. Unified timeline correlation. Status: Partial. Acceptance: correlate filesystem, event logs, browser, mobile, cloud, and review annotations into one scalable timeline.
50. Incident hypothesis/workbook feature. Status: Planned. Acceptance: let analysts create hypotheses, attach evidence, track questions, and export workbook sections.
51. Reviewer assignment/status workflow. Status: Partial. Acceptance: assign items, track status, priorities, reviewer notes, and report candidate state.
52. A/B/C multi-evidence compare. Status: Partial. Acceptance: compare more than two evidence items with diff, metadata, hash, and note panels.
53. Raw/source hex viewer. Status: Planned. Acceptance: safe bounded hex/bytes view with offsets, search, copy-safe snippets, and source hash.
54. SQLite/table specialized viewer. Status: Partial. Acceptance: browse tables, schemas, rows, FTS hits, and source DB metadata without loading all rows.
55. Email conversation viewer. Status: Planned. Acceptance: render threaded mail conversations, attachments, headers, and citations.
56. Image gallery review mode. Status: Partial. Acceptance: review thumbnails, similarity buckets, perceptual hashes, tags, and report selections.
57. Video/audio preview and transcript. Status: Planned. Acceptance: preview bounded media metadata, transcripts/sidecars, hashes, and review marks.
58. OCR queue manager. Status: Partial. Acceptance: queue files, show OCR state, import sidecars, preserve confidence/language metadata, and retry failures.
59. Korean OCR/translation workflow hardening. Status: Partial. Acceptance: support Korean OCR/translation sidecars, language hints, confidence, and unchanged originals.
60. Search hit deduplication. Status: Partial. Acceptance: deduplicate repeated hits by source hash, normalized text, entity, artifact ID, and preview.
61. Fuzzy search/stemming/regex proximity search. Status: Planned. Acceptance: support analyst-grade query modes with performance warnings and tested syntax.
62. Saved keyword pack library. Status: Partial+. Acceptance: reusable keyword packs, saved searches, recent searches, and case-scoped history.
63. IOC/TI enrichment plugin. Status: Planned. Acceptance: optional offline-safe enrichment for IPs, domains, URLs, hashes, rule IDs, and source/version metadata.
64. Report citation manager. Status: Partial. Acceptance: manage citations, source paths, hashes, parser versions, offsets, reviewer state, and exhibit numbers.
65. Evidence selection/version history. Status: Partial. Acceptance: preserve selection changes, notes, review state changes, and report inclusion history.

## D. Performance And Large Scale

66. 100k/1M/10M record benchmark. Status: Partial. Acceptance: benchmark index/search/report behavior at these scales with documented latency/resource targets.
67. 1TB-10TB evidence stress test. Status: Planned. Acceptance: publish repeatable stress runs, bottlenecks, resource caps, and known failure thresholds.
68. Incremental indexing. Status: Partial. Acceptance: reuse completed outputs, detect changed sources, and avoid duplicate Case DB imports.
69. Background job queue. Status: Partial. Acceptance: run jobs asynchronously with progress, state, warnings, cancellation, and retry.
70. Stage checkpoint/resume hardening. Status: Partial. Acceptance: checkpoint each stage, safely resume skipped/failed/capped work, and preserve previous outputs.
71. Parser crash isolation. Status: Planned. Acceptance: isolate parser failures so one bad artifact cannot crash a whole case run.
72. Memory cap enforcement. Status: Partial. Acceptance: enforce bounded reads/previews/extractions and record cap warnings.
73. Preview sandboxing. Status: Planned. Acceptance: render previews safely without executing active content or exposing host paths unnecessarily.
74. Large SQLite/FTS optimization. Status: Partial. Acceptance: tune indexes, pagination, inserts, FTS queries, and vacuum/maintenance for large cases.
75. Parallel parser scheduler. Status: Planned. Acceptance: schedule independent parsers with CPU/I/O limits, progress, and deterministic output ordering.
76. File hash cache. Status: Planned. Acceptance: cache hashes by path/size/mtime/inode where safe and invalidate on change.
77. Duplicate file/content detection. Status: Partial. Acceptance: group duplicate hashes, similar names, near-duplicate media/text, and source occurrences.
78. Artifact pagination/cursor API. Status: Partial. Acceptance: return cursor-paged artifacts/search results for massive datasets.
79. UI virtualization for massive result tables. Status: Partial. Acceptance: display large result sets without loading all rows in browser memory.
80. Long-running job cancellation/retry. Status: Partial. Acceptance: cancel/retry jobs safely and record partial outputs/warnings.

## E. Validation And Legal Defensibility

81. NIST CFReDS/CFTT based known-answer tests. Status: Planned. Acceptance: run known-answer validation against public corpora and document results.
82. Parser-specific fixture corpus. Status: Partial. Acceptance: each parser has fixtures, expected counts, edge cases, and regression tests.
83. Parser-specific false positive/false negative documentation. Status: Partial. Acceptance: document known misses, noise, unsupported structures, and validation needs.
84. Independent validation report. Status: Planned. Acceptance: produce third-party or independent validation evidence per release.
85. Tool validation package automation hardening. Status: Partial+. Acceptance: generate validation JSON/Markdown with commands, checks, docs, limitations, and artifacts.
86. Chain-of-custody full workflow. Status: Partial. Acceptance: evidence IDs, acquisition/source hashes, custody events, tool versions, and report links.
87. Evidence acquisition hash workflow. Status: Partial. Acceptance: hash source images/exports, extracted files, reports, bundles, and acquisition metadata.
88. Analyst action immutable audit log. Status: Partial. Acceptance: append-only audit for review, tagging, export, report, and settings changes.
89. Report reproducibility: same input, same output. Status: Partial. Acceptance: deterministic ordering, timestamps normalization, schema versions, and reproducibility tests.
90. Report item source provenance completeness. Status: Partial. Acceptance: every report item cites source path, hash, parser, offset/index where available, and review status.
91. Parser confidence scoring. Status: Partial+. Acceptance: every normalized artifact has evidence strength, parser confidence, reportability, and validation warnings.
92. Validation-required warning UX. Status: Partial. Acceptance: UI and reports clearly show partial/native/unsupported/parser-required states.
93. Legal limitation statement per artifact. Status: Partial. Acceptance: artifact-specific limitations appear in reports and reviewer views.
94. Court exhibit export package. Status: Planned. Acceptance: export selected evidence, reports, hashes, audit, and provenance in a court-ready bundle.
95. External tool version capture. Status: Partial. Acceptance: capture versions and command evidence for ewfmount, Sleuth Kit, qemu-img, OCR, and parser imports.
96. Write-blocker/acquisition metadata recording. Status: Planned. Acceptance: record acquisition device, write-blocker, operator, time, source, and notes.
97. Timezone normalization validation. Status: Partial. Acceptance: preserve original timestamps, normalized UTC, source timezone, and parser assumptions.
98. Clock skew analysis. Status: Planned. Acceptance: detect host/device time skew and annotate timelines/reports.
99. Evidence contamination warning. Status: Planned. Acceptance: warn on writable sources, changed mtimes, generated files inside evidence, and unsafe output paths.
100. Tamper-evident audit bundle. Status: Planned. Acceptance: hash-chain or manifest-sign audit/report/export packages for tamper evidence.

## F. Deployment, Operations, And Commercialization

101. Windows signed installer. Status: External. Acceptance: signed installer, verification evidence, reproducible build steps, and fresh-machine smoke test.
102. macOS notarized package. Status: External. Acceptance: notarized package, Gatekeeper validation, reproducible build steps, and smoke test.
103. Linux package/deb/rpm/AppImage. Status: Planned. Acceptance: installable Linux packages with dependency handling and smoke tests.
104. Auto-update channel. Status: Planned. Acceptance: controlled update channel with signed artifacts, release notes, rollback, and enterprise disable option.
105. Crash reporting. Status: Planned. Acceptance: local-first crash logs with opt-in export and no evidence exfiltration.
106. Telemetry-free/local-only enterprise mode. Status: Partial+. Acceptance: local-only default, explicit remote bind/auth, and no hidden telemetry.
107. License/activation system, if needed. Status: Planned. Acceptance: license flow does not touch evidence and supports offline enterprise workflows.
108. Role-based access control. Status: Planned. Acceptance: roles, permissions, case access, export controls, and audit logs.
109. Multi-user case server. Status: Planned. Acceptance: shared case server with auth, locking/conflict handling, and scalable search/review.
110. Collaboration audit trail. Status: Planned. Acceptance: immutable user/action/time/source audit for collaboration workflows.
111. Backup/restore/migration. Status: Planned. Acceptance: versioned backups, restore validation, schema migrations, and integrity checks.
112. Release notes/changelog discipline. Status: Partial. Acceptance: every release has changes, known limits, validation state, migration notes, and checksums.
113. LTS branch/hotfix policy. Status: Planned. Acceptance: documented support windows, patch policy, branch rules, and backport criteria.
114. Support SLA documentation. Status: External. Acceptance: staffed response targets, severity levels, escalation, and patch delivery expectations.
115. Training curriculum. Status: Partial. Acceptance: structured analyst/admin training, labs, examples, and validation exercises.
116. Analyst quickstart lab. Status: Partial. Acceptance: guided sample case from ingest to search, review, report, and export.
117. Admin deployment guide. Status: Planned. Acceptance: enterprise install, update, backup, auth, network, logging, and policy guidance.
118. Security hardening review. Status: Partial. Acceptance: periodic security review for auth, path handling, export rendering, dependencies, and parser safety.
119. Malicious evidence sandboxing. Status: Planned. Acceptance: isolate previews/parsers for hostile files and active content.
120. Dependency vulnerability monitoring. Status: Planned. Acceptance: scan dependencies, track advisories, patch cadence, and release-blocking severity policy.
