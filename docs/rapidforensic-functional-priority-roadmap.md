# RapidForensic Functional Priority Roadmap

Last updated: 2026-05-08

## Fresh Assessment Snapshot

Generated from `rapidtriage commercial-readiness` on 2026-05-08.

- Readiness score: `81/100`
- Status: `commercial-gaps-present`
- Commercial claim allowed: `false`
- Items tracked: `120`
- Commercial-ready items: `0/120`
- Validated gate: `0 passed / 120 failed`
- Commercial-grade gate: `0 passed / 120 failed`

Interpretation: broad implementation and usability scaffolding exists, but no item may be called commercial-grade until known-answer validation, trusted-tool diff evidence, large-case proof, and release/platform evidence are attached.

## Immediate Next Execution Queue

This queue is the next practical work order. It intentionally starts with a single Windows 11 E01 case because that is the fastest path to a product that an analyst can actually use.

1. Build a Windows 11 E01 known-answer fixture manifest.
Acceptance: one case manifest records image identity, expected partitions, expected high-value artifacts, source hashes, and validation commands.
Current internal progress: `rapidtriage e01-known-answer SOURCE.E01 --output windows11-e01-known-answer.json` now generates a draft manifest with source integrity, EWF segment inventory, expected partition assertions, expected high-value artifact assertions, default plus analyst-provided validation commands, a report-grade validation plan (`e01-ex01-report-grade-validation-plan-v1`), #22 validation matrix, #22 core accuracy gate, reportability decision, blocker list, evidence slots, and manifest SHA-256. Remaining commercial blocker: run this against a real Windows 11 E01 case, fill trusted expected artifacts, execute the commands, attach transcripts, and diff outputs against trusted tool exports.

2. Add an E01 end-to-end smoke command.
Acceptance: one command runs preflight, partition selection, extraction/resume, artifact collection, search index, review summary, and report bundle generation.
Current internal progress: `rapidtriage e01-smoke SOURCE.E01 --output-dir case-smoke --case-id CASE-001` now writes `windows11-e01-known-answer.json`, `rapidtriage-evidence-preflight.json`, `rapidforensic-e01-validation-plan.json`, stage status, and `rapidforensic-e01-smoke.json`. The smoke report records stage status for known-answer generation, dependency/evidence preflight, validation-plan generation, and the triage run; when extraction cannot proceed it preserves classified `failure_guidance` instead of silently failing. Remaining commercial blocker: run this against a real Windows 11 E01 with libewf/Sleuth Kit or a trusted export, attach the resulting run/report outputs, and diff high-value artifacts against trusted tools.

3. Attach trusted EVTX diffs.
Acceptance: native EVTX rows can be diffed against EvtxECmd/Hayabusa exports at record ID, provider, event ID, timestamp, field, and rendered-message levels.
Current internal progress: `cross-tool-validate` now indexes EVTX records by both `channel+record_id` and bare `record_id`, compares canonical provider/event/channel/computer/timestamp fields, compares rendered messages through `event_message`/`Message` aliases, and expands nested `EventData`/`UserData`/native `binxml_event_data_fields` into per-field comparisons. Functional profile evidence now records support for EVTX key variants, rendered-message diffing, and EventData field diffing. Remaining commercial blocker: run this against real RapidForensic native EVTX output plus EvtxECmd/Hayabusa exports from a known Windows 11 corpus, attach tool versions/commands/source hashes/independent signoff, and resolve any field mismatches before claiming report-grade EVTX support.

4. Attach trusted Registry diffs.
Acceptance: registry key/value/recovery rows can be diffed against RECmd/Registry Explorer exports, including deleted-cell offset and transaction-log disclosure.
Current internal progress: `cross-tool-validate` now builds a Registry field index for key paths, value names, value types, value-data digests, last-write times, deleted/free cell offsets, candidate classes, allocation status, parent key paths, and transaction replay status. It normalizes common root aliases such as `HKEY_CURRENT_USER` and `HKCU`, compares RapidForensic nested artifact rows against RECmd/Registry Explorer-style CSV/JSON exports, and reports `registry_field_comparison` with mismatch samples plus functional profile evidence for key/value diff, deleted-cell offset diff, and transaction replay status diff support. Native key-tree rows now expose subkey-list/value-list cell profiles with decoded `lf`/`lh`/`li`/`ri` structures, list-cell hashes, decoded child/value counts, root reachability, parent-child backlink consistency, bounded reconstruction profiles, stable citation manifest hashes, and nested-manifest-aware trusted diff coverage for cell offset, parent offset, subkey/value ownership, last-write time, root reachability, and backlink consistency. Remaining commercial blocker: run against real NTUSER/UsrClass/SYSTEM/SOFTWARE hives with LOG1/LOG2 context, attach RECmd/Registry Explorer output, source hashes, command/tool versions, and independent reviewer signoff; transaction replay itself remains disclosed as not implemented unless externally proven equivalent.

5. Attach trusted MFT/USN diffs.
Acceptance: MFT/USN rows can be diffed against MFTECmd/UsnJrnl2Csv or equivalent outputs, including FRN, parent FRN, reason flags, timestamps, and path reconstruction.
Current internal progress: `cross-tool-validate` now builds MFT and USN field indexes for RapidForensic nested artifact rows and MFTECmd/UsnJrnl2Csv-style CSV/JSON exports. MFT comparison normalizes record number, sequence number, parent reference, path, deleted state, timestamps, record offset, attribute types, resident-data hash, and runlist decode status. USN comparison normalizes USN, FRN, parent FRN, file name, reason flags, timestamp, major version, source info, file attributes, record cursor, and v4 extent count. It also expands nested `bounded_state_replay_preview.transitions` rows into a separate `usn_state_replay_field_comparison` so create/rename/delete state transitions can be checked against known-answer replay exports instead of being implied by record-level overlap. `rapidtriage usn-state-replay-template` writes a CSV/template manifest pair for labs to populate those known-answer replay rows, and `rapidtriage run-attach-validation-diff` copies completed diff JSON into a run's `validation-diffs/` folder, updates `rapidtriage-run-summary.json`, and exposes the attached USN replay pass/fail state through the web validation panel. Functional profile evidence now records MFT record/parent/path/attribute diff support, USN FRN/reason/timestamp diff support, and USN state replay transition diff support. Remaining commercial blocker: run against a real Windows 11 NTFS corpus with RapidForensic output plus MFTECmd/analyzeMFT/UsnJrnl2Csv/known-answer replay exports, attach source hashes/tool versions/commands/independent signoff, and prove full-volume parent path reconstruction plus rename/delete replay at scale.

6. Attach trusted SRUM/Windows.edb diffs.
Acceptance: SRUM and Windows.edb ESE rows can be compared with SrumECmd/libesedb/Windows Search exports and clearly mark unsupported row-level decoding.
Current internal progress: `cross-tool-validate` now builds a shared ESE field index for SRUM and Windows.edb rows. It infers SRUM/Windows.edb family from artifact/source metadata, keys rows by `table+row_id`, `table+item_path`, and `page+offset`, and compares normalized table name, row ID, page number, source offset, path/URL/app ID, timestamp, deleted state, user SID, sent/received byte counters, content hash, and decode status. Functional profile evidence now records SRUM row diff support, Windows.edb row diff support, and page/offset/deleted-state diff support. Remaining commercial blocker: run against real SRUDB.dat and Windows.edb evidence with SrumECmd/libesedb/WinSearchDBAnalyzer exports, attach tool versions/commands/source hashes/independent signoff, and separately disclose that native ESE catalog/table/long-value/deleted-row decoding is still not complete unless trusted diff proves equivalence.

Latest #11 hardening: Windows.edb source-tool exports, database inventory, string pivots, page/table candidates, and row candidates now carry stable `windows_edb_report_citation_manifest_hash`, `edb_semantics_warning`, and a `windows-edb-trusted-diff-contract-v1`. The row-diff normalizer flattens manifest row identity/page locators before comparing path, URL, content, deleted-state semantics, timestamp semantics, table/page/source-format fields, and warning text, which makes GUI/report consumers less likely to overstate native string candidates as decoded ESE rows.

7. Make the GUI case workflow browser-testable.
Acceptance: Playwright or equivalent smoke opens the workbench, selects an existing run, verifies artifact validation summary, opens a source viewer, marks evidence, and exports a report.
Current internal progress: the web console now exposes stable `data-testid` selectors for the single-case workbench shell, evidence input, sample run, run list, detail panel, case hero, artifact validation summary, global search, source viewer, source-verification trail, viewer review form, and report tab. `/api/workbench/smoke-contract` returns a machine-readable browser smoke contract with required steps, API routes, selectors, implemented controls, and explicit blockers for missing Playwright/screenshot/fresh-Windows evidence. The GUI also renders a browser-smoke checkpoint panel so analysts and test authors can see the exact testable workflow. Remaining commercial blocker: run the smoke contract in a real browser with Playwright or equivalent, attach logs/screenshots/video, and repeat on fresh Windows 11.

8. Add large-result UI performance evidence.
Acceptance: a generated 100k-row case proves cursor pagination, virtual table behavior, search latency, and no DOM explosion.
Current internal progress: `/api/workbench/large-result-evidence?record_count=100000` now emits a synthetic large-result UI evidence package with row-window manifests, manifest hashes, DOM budget estimate, search latency budget, viewport/keyboard/windowing controls, and explicit browser-trace blockers. The workbench smoke panel links to this 100k evidence JSON, and tests verify the bounded 300-row visible window plus DOM budget pass state. Remaining commercial blocker: execute the same contract in a real browser with 100k+ rows, collect Playwright trace/screenshots/memory profile/p95 latency, and repeat on fresh Windows 11 hardware.

9. Generate a validation package automatically.
Acceptance: each run can export commands, tool versions, source hashes, output hashes, parser versions, diff results, warnings, limitations, and reviewer status.
Current internal progress: `/api/runs/{run_id}/validation-package` now writes `rapidforensic-run-validation-package.json` with run request/command context, source integrity or explicit directory-hash limitation, output file hashes, parser/job execution inventory, warning and parser-error inventory, trusted-diff attachment inventory, reviewer status counts, limitation inventory, manifest hash, audit sidecar, and a GUI link from the single-case workbench. Remaining commercial blocker: attach real trusted-tool diffs, independent review, and operator-signed validation transcripts for the specific case.

10. Separate internal blockers from external blockers.
Acceptance: commercial readiness shows which blockers can be solved by code now and which require external signing, independent review, real 1TB+ hardware tests, or staffed support evidence.
Current internal progress: `rapidtriage commercial-readiness` now emits `blocker_separation_profile` with immediate queue item #10, internal-only/internal-then-external/external-only counts, next internal batch, next external evidence batch, lane action map, and an operator rule that prevents commercial-grade claims after internal-only work. The console and Markdown report also summarize internal work versus external/trusted evidence. Remaining commercial blocker: none for blocker classification itself; every underlying item still needs its own implementation, trusted diff, independent review, signed platform, large-hardware, or support evidence before `commercial_grade` can pass.

This roadmap reorganizes the existing 120 commercial-parity items into the order that matters most for a single-case forensic analyst workflow. The goal is not to add more shallow parsers. The goal is to make one Windows 11 E01 case usable end-to-end: ingest, extract or mount, parse high-value artifacts, search across all evidence, inspect original sources, mark review decisions, and export defensible reports.

## Product Target

RapidForensic should first be credible as a local, single-case forensic review console.

Primary user story:

1. Analyst selects a Windows 11 E01 or a mounted/exported evidence folder.
2. The tool checks support, missing dependencies, partitions, and risk before processing.
3. The tool runs a fast first pass without overwhelming the workstation.
4. The analyst searches documents, logs, web history, AI service traces, OCR text, file metadata, and normalized artifacts from one interface.
5. The analyst opens source files, searches inside the current file, computes hashes when needed, and compares multiple evidence items.
6. The analyst marks items as relevant, needs-review, excluded, or report-set.
7. The tool produces a report, selected-evidence manifest, hashes, provenance, and audit bundle.

## Status Baseline

Current state from existing project evidence:

- Broad function coverage exists.
- Implemented/usability gates are broad, but commercial-grade claims remain blocked.
- The most important blockers are parser correctness depth, validation corpora, large-data proof, and release/platform evidence.
- Current E01 handling depends on external tools such as `ewfmount`, `mmls`, and `tsk_recover`.
- Current UX now has a clearer analyst workflow, but browser-scale e2e performance evidence is still needed.

## Ordered Implementation List

### Phase 1: Make Windows 11 E01 Cases Reliable

1. E01 dependency preflight hardening.
Acceptance: UI/API clearly reports `ewfmount`, `mmls`, `tsk_recover`, versions, missing tools, and exact remediation.
Current internal progress: structured dependency preflight now records each tool's role, package hint, install/remediation text, Windows guidance, attempted version commands, availability, version result, and a user-facing `preflight_summary` for the evidence API and GUI. Remaining commercial blocker: real Windows/WSL2/macOS/Linux tool-matrix smoke logs and independent E01 corpus validation.

2. E01 partition selection.
Acceptance: show all partitions with filesystem, size, offset, and recommended default instead of silently selecting the first likely filesystem.
Current internal progress: direct E01 extraction now accepts an explicit partition start sector through CLI/API/job payloads and records `partition_selection` metadata with selected, recommended, requested, source, supported-count, description, and mismatch warning. The GUI exposes the optional sector and shows the current plan. Remaining commercial blocker: a full partition browser with byte size/sector-size display and real multi-partition E01 fixture validation.

3. E01 extraction checkpoint/resume.
Acceptance: mount, partition detection, recovery, triage, and indexing write durable stage status and can resume failed stages.
Current internal progress: direct E01 extraction now writes `rapidtriage-e01-stage-status.json` with source signature, requested sector, dependency preflight, mount, partition enumeration, recovery status, command history, selected partition, and resume readiness. A completed recovery can be reused on rerun even if external tools are not currently available. Remaining commercial blocker: partial failed-stage resume for interrupted mount/recovery jobs and UI progress visualization.

4. E01 source and extraction provenance.
Acceptance: record source image hash where feasible, mounted path, selected partition offset, external commands, tool versions, recovered-root hash manifest, and limitations.
Current internal progress: E01 metadata now includes source integrity, tool preflight/version attempts, command history, selected partition, resume status, and a bounded `recovered_root_manifest` with relative path, size, mtime, SHA-256 when feasible, truncation, skipped-large-file, and error counters. `rapidtriage-e01.json` and direct E01 run summaries now also emit `e01_ex01_workflow_manifest` (`e01-ex01-integrated-workflow-manifest-v1`) tying source selection, dependency preflight, partition selection, read-only extraction, artifact analysis, unified search/indexing, review/source verification, and report export into one #22 stage contract with a stable manifest hash. Remaining commercial blocker: validated full-image hash workflow for very large E01 sets, trusted-tool stage diffs, real Windows 11 E01 logs, and chain-of-custody signoff packaging.

5. E01 failure UX.
Acceptance: if direct extraction fails, the UI explains whether the issue is missing tool, unsupported image, encrypted volume, partition ambiguity, permission, or external-tool failure.
Current internal progress: E01 failures are now classified into `missing-tool`, `unsupported-image`, `encrypted-volume`, `partition-ambiguity`, `permission`, and `external-tool-failure`, with analyst-facing messages and next actions. Evidence identify responses and GUI readiness cards expose this guidance, and run-mode E01 exceptions include the same category. Remaining commercial blocker: screenshots/UX validation on Windows 11 plus real encrypted/corrupt E01 fixture evidence.

### Phase 2: Finish Windows Core Forensic Artifacts

6. Native EVTX BinXML parsing.
Acceptance: decode record structure, System, EventData, UserData, template instances, typed values, and record integrity with record-level provenance.
Current internal progress: native EVTX rows now attach `evtx_record_provenance` and `evtx_native_parse_profile`, including source/record hashes, record offset/size, chunk boundary context, validation matrix IDs, BinXML status, scalar value counts, decoded type counts, best-effort CDATA/character-reference/entity-reference/processing-instruction token capture, bounded nested `BinXmlType` payload parsing through `evtx-nested-binxml-value-v1`, promoted System/EventData/UserData fields, template IDs, provider manifest catalog rendering with `valueMap`/`bitMap` labels and raw-value provenance, and reportability blockers. Remaining commercial blocker: full BinXML object model coverage and EvtxECmd/Hayabusa record-level diff corpus.

7. EVTX message rendering.
Acceptance: use manifest/resource catalogs where available, preserve unresolved provider/template IDs, and label fallback rendering as validation-required.
Current internal progress: event rows now expose `evtx_message_rendering_profile` with renderer, provider resource resolution state, provider catalog source, validation requirement, used-field count, template IDs, analyst wording, and blockers when built-in/unresolved rendering is used. Catalog rendering supports both named `{Field}` templates and Windows-style `%1`, `%2` positional message inserts using ordered EventData/TemplateValue values. Remaining commercial blocker: Windows provider DLL/resource-table extraction across locale/version matrix and rendered-message trusted diff.

8. EVTX deleted/corrupt recovery.
Acceptance: recovered candidates include offset, chunk/slack context, confidence, reason, and non-reportable default until validated.
Current internal progress: slack/deleted/corrupt candidates already carry recovery context/evidence/validation profile; parseable slack/deleted rows and corrupt candidates now also emit `evtx_recovery_report_citation_manifest` with source hash, candidate offset/size/hash, chunk/free-space context, candidate class, independent-check requirements, caution labels, reportability blockers, and a stable manifest hash so offset review can be cited without overclaiming recovered records. The recovery corpus diff helper also reads nested `evtx_recovery_evidence`/`evtx_recovery_context` fields from generated artifact rows, including candidate reason and chunk-boundary status, so validation oracles can compare real outputs directly. Remaining commercial blocker: broad deleted/corrupt known-answer corpus and independent parser diff.

9. Registry hive transaction replay.
Acceptance: LOG1/LOG2 presence is detected and replayed or explicitly marked as not replayed with impact statement.
Current internal progress: registry hive/key/recovery rows now include `registry_transaction_replay_profile` plus transaction-log evidence with expected LOG names, replay policy, replay status, and impact statement. Remaining commercial blocker: actual LOG1/LOG2 replay implementation or second-parser diff proving replay equivalence.

10. Registry deleted key/value recovery validation.
Acceptance: deleted/free-cell rows require allocator-state checks, parent-chain evidence, and independent fixture comparison before report-grade use.
Current internal progress: deleted key/value recovery profiles now include independent validation status, false-positive controls, false-positive risk, analyst wording, allocator context, allocator neighbor context, parent/path confidence, transaction replay profile, stable recovery identity hashes, allocator context hashes, and do-not-report-as-fact decision. The allocator neighbor context records previous/next scanned cell summaries, same-hbin checks, relative gaps, and context-quality wording so reviewers can spot overwritten/slack false positives before relying on a deleted/free `nk` or `vk` candidate. Trusted deleted-cell diff normalization now compares nested generated rows against oracle fields for signature, size, hbin offset, allocation status, name, value/data, parent, allocator, and identity-hash coverage. Remaining commercial blocker: labeled deleted-cell fixture corpus and trusted offset diff.

11. NTUSER/UsrClass user activity parser.
Acceptance: UserAssist, RecentDocs, RunMRU, TypedURLs, OpenSaveMRU, ShellBags, MountPoints2, Network, and ComDlg32 are normalized into searchable user activity rows.
Current internal progress: registry user-activity rows now carry `registry_user_activity_profile` with normalized artifact family coverage, source integrity, decoded value count, reportability decision, large-data controls, and required validation before report use. Registry exports now also emit `normalized_activity_rows` for UserAssist, RecentDocs, RunMRU, TypedURLs/TypedPaths, OpenSavePidlMRU/LastVisitedPidlMRU, ShellBag pivots, MountPoints2, Network, and ComDlg32-family keys. Binary MRU/PIDL payloads are bounded to SHA-256 plus UTF-16 string hints instead of raw expansion, so they are safe for search indexing and review citations. Native ShellBags rows now emit `shellbag_relationship_profile` and `shellbag_depth_manifest` with source hive/key provenance, BagMRU/Bags candidate relationships, key-lineage hashes, timestamp hints, binary shell-item decode state, transaction-log/deleted-slack validation state, citation refs, reportability limits, and commercial blockers. Native hive string pivots remain non-final until key/value payload decoding and transaction replay are complete. Remaining commercial blocker: full native binary payload decoding for UserAssist/ShellBags/MRU artifacts, LOG replay, and trusted RECmd/ShellBagsExplorer/UserAssist diff corpus.

12. SAM/SECURITY/SYSTEM deep parser.
Acceptance: user/account lifecycle, group membership, privilege assignment, current ControlSet, services, timezone, boot/shutdown, and LSA-sensitive metadata are separately surfaced.
Current internal progress: account lifecycle rows now include `sam_security_system_deep_parser_profile` with SAM/SECURITY/SYSTEM target hives, decoded component flags, legal handling for redacted LSA-sensitive data, reportability decision, and required pre-report checks. Account rows also emit `normalized_security_context_rows` for group-membership hints, inherited privilege hints, service-account matches, and LSA-sensitive location summaries, with a schema marked safe for Case DB indexing while keeping secret values metadata-only. New `sam_security_context_manifest` output records account identity, source hash, normalized context row hashes, context type counts, high-risk privileges, redaction policy, reportability blockers, and citation refs so the reviewer can tie group/privilege/service/LSA pivots back to stable source evidence. Account, group, privilege, LSA secret-metadata, and native SAM candidate rows now also emit `sam_security_system_row_manifest` with stable row identity hashes, source hashes, required trusted-diff fields, and reportability blockers; trusted diffs expose missing required fields before any commercial-evidence claim. Existing account, privilege, service, mounted device, ControlSet, timezone, boot/shutdown, and LSA metadata rows remain searchable. Remaining commercial blocker: native SAM alias/member binary decode, SECURITY secret authority-gated workflow, transaction log replay, domain SID context, and trusted parser diff.

13. MFT full parser.
Acceptance: FILE records, attributes, USA validation, parent references, deleted/in-use state, timestamps, and path reconstruction are available at scale.
Current internal progress: MFT inventory/import/native rows now expose `mft_full_parser_profile` with decoded component flags for FILE record headers, USA sequence fixup validation, USA sector-trailer restoration before attribute decoding, `$STANDARD_INFORMATION`, `$FILE_NAME`, parent reference decode, resident data hashing, nonresident runlist preview, source provenance, reportability decision, and large-data controls. Native rows now also include `mft_path_reconstruction_profile`, `mft_attribute_list_profile`, `mft_data_run_summary`, bounded parent-chain path candidates when the required parent records are available inside the native scan window, and `mft_parser_depth_manifest` with a stable hash over source, row identity, USA validation/application, attribute-list status, data-run state, path reconstruction status, citation refs, reportability limits, and commercial blockers. This lets analysts distinguish record-local filename/full-path string evidence from bounded-scan reconstruction and unvalidated full-volume path reconstruction. Remaining commercial blocker: ATTRIBUTE_LIST extension record merging, full nonresident runlist validation, full-volume parent path reconstruction, and MFTECmd/analyzeMFT/TSK known-answer diff.

14. USN journal replay.
Acceptance: v2/v3/v4 records, FRN path cache, rename/delete replay, reason flags, and cursor pagination are usable on large journals.
Current internal progress: USN inventory/import/native rows now expose `usn_journal_replay_profile` with v2/v3 decode state, reason flag support, FRN/parent references, rename/delete hints, cursor provenance, timestamp range, record limits, and reportability decision. Native rows now include `usn_replay_transition_profile`, `usn_cursor_pagination_profile`, bounded MFT path correlation when a USN FRN or parent FRN matches the scanned MFT path cache, and `usn_timeline_depth_manifest` with a stable hash over record cursor identity, record layout validation, reason/source/file-attribute semantics, path correlation, cursor pagination, replay state, citation refs, reportability limits, and commercial blockers. Journal inventory includes `usn_replay_inventory_profile`, `cursor_window_profile` with resume token/hash metadata, `bounded_mft_replay_preview`, `mft_bounded_path_cache_profile`, `usn_path_reliability_profile`, `usn_state_replay_validation_profile`, `rename_pair_preview`, `delete_lifecycle_preview`, `bounded_state_replay_preview`, and `timeline_review_candidates` for create/delete/rename class counts, rename balance, MFT cache quality counts/warnings, path reliability/review priority, state-replay validation gate wording, OLD/NEW candidate pairs, create/delete lifecycle candidates, bounded state-transition samples, timeline pivots, cursor window, correlated path counts/samples, and explicit FRN path-cache blockers. Remaining commercial blocker: full FRN-to-path cache replay, v4 extent coverage over real journals, complete-journal rename/delete ordering, large-journal pagination proof, and UsnJrnl2Csv/MFTECmd diff.

15. Execution artifacts.
Acceptance: Amcache, ShimCache, BAM/DAM, Prefetch, LNK, JumpList, SRUM, Windows.edb expose validation-gated normalized rows with clear execution-evidence caveats.
ShimCache #8 reinforcement: rows now carry `shimcache_layout_profile`, `shimcache_row_manifest`, `shimcache_row_manifest_hash`, source-viewer locators, cache-order/source-offset identity, and trusted-diff required field coverage so program-presence/cache-order evidence stays separated from execution proof.
BAM/DAM #9 reinforcement: rows now carry `bam_dam_row_manifest`, `bam_dam_row_manifest_hash`, ControlSet/source-key/source-offset identity, SID/device-path/timestamp semantics, source-viewer locators, and trusted-diff required field coverage so recent-execution pivots stay tied to correlation-before-testimony rules.
SRUM #10 reinforcement: rows now carry `srum_report_citation_manifest`, `srum_report_citation_manifest_hash`, source-format and semantics-warning trusted-diff requirements, table/app identity, counter values, timestamp source, network profile/interface pivots, and source-offset/row-cluster locators so native SRUDB string candidates are not confused with decoded ESE rows.
Current internal progress: Amcache, ShimCache, BAM/DAM, and SRUM profiles now include `execution_artifact_validation_profile` with a normalized row contract, caveat enforcement, validation summary, large-data controls, and required correlation/trusted-diff checks. Amcache rows additionally emit `amcache_schema_version_profile`, `amcache_row_manifest`, and `amcache_report_citation_manifest` with source hash, registry key or native source offset, normalized executable identity, SHA1 candidates, schema-family hint, timestamp semantics, row-cluster locator, required trusted-diff coverage, reportability blockers, and explicit standalone-execution-proof denial. ShimCache rows additionally emit `shimcache_report_citation_manifest` with source hash, registry key or native source offset, normalized executable identity, cache-order/timestamp citation, native row-cluster locator, OS-build layout validation blockers, and explicit standalone-execution-proof denial. BAM/DAM rows additionally emit `bam_dam_row_manifest` and `bam_dam_report_citation_manifest` with source hash, ControlSet/source key/source offset, SID, device path, timestamp semantics, native row-cluster locator, binary FILETIME row validation blockers, required trusted-diff source coverage, and correlation-before-testimony wording. SRUM rows additionally emit `srum_report_citation_manifest` for imports, database inventory, string pivots, table candidates, and row candidates with source hash, table/app identity, counter names, timestamp semantics, row-cluster/source-offset locators, native ESE row-decoding blockers, and standalone-execution-proof denial. Windows.edb rows additionally emit `windows_edb_report_citation_manifest` for source-tool exports, database inventory, string pivots, page candidates, table candidates, and row candidates with source hash, path/URL/content identity, page locator, table/deleted-state semantics, row-cluster hints, native ESE row/deleted-state blockers, and decoded-row-fact denial. JumpList rows additionally emit `jumplist_destlist_depth_manifest` with source hash, CFB stream inventory, DestList candidate decoding, layout-selection profiles, entry citation hashes, embedded LNK destination linkage, AppID hash mapping state, deleted/unlinked entry recovery limits, citation refs, reportability limits, and commercial blockers. Prefetch rows additionally emit `prefetch_execution_depth_manifest` with SCCA/version layout validation, run count and last-run timestamp evidence, bounded referenced-path/volume/file-reference candidates, compressed PF handling state, citation refs, reportability limits, and commercial blockers. LNK shortcut rows additionally emit `lnk_metadata_depth_manifest` with Shell Link header validation, StringData/LinkInfo target fields, Shell Item candidate state, ExtraData/TrackerDataBlock metadata, citation refs, reportability limits, and commercial blockers. Windows system rows for Task Scheduler, Defender support logs, Firewall logs, WER reports, and WMI repository files additionally emit `system_deep_parser_manifest` with normalized semantics, risk/review pivots, validation matrix pass/fail IDs, native depth capabilities, citation refs, reportability limits, and cross-artifact correlation blockers. The Windows execution summary now adds `execution_correlation_profile` and per-executable `correlation_profile` data so analysts can see single-signal versus multi-signal corroboration, source formats, source artifact refs, validation-required counts, and whether a standalone execution claim is blocked. Existing Prefetch, LNK, JumpList, Windows system, and Windows.edb collectors already expose validation-gated rows separately. Remaining commercial blocker: full native binary layout decoders for all execution artifacts, eventlog/prefetch/MFT integrated correlation, trusted parser diffs, and broad Windows 11 fixture validation.

### Phase 3: Make Search And Review Feel Like A Real Analyst Workbench

16. Unified search correctness.
Acceptance: one search reaches documents, file metadata, browser/web/AI artifacts, EVTX-derived rows, Registry-derived rows, timeline, OCR sidecars, and Case DB FTS.
Current internal progress: run-level unified search now emits `workbench_search_profile` for item #16, recording target source families, implemented source coverage for the current result set, exact/regex/fuzzy mode state, review-flow contract, large-data result limits, and the rule that search hits are triage pivots until verified in the source viewer. Each returned hit now also carries `search_result_id` and `source_verification_profile` with viewer support, pointer/hash availability, current-file search support, required pre-report checks, and blockers; the workbench profile summarizes source-verifiable hit counts through `source_verification_summary`. Remaining commercial blocker: large-case latency benchmark, run-search/Case DB parity diff, and source-verified report item workflow evidence.

17. Current-file search.
Acceptance: opened source files support in-file search with line/offset/table citations and “add to review note”.
Current internal progress: `/source-search` now emits `source_search_profile` for item #17 with searchable/truncated state, result limit, context bounds, line/offset/table citation requirement, and reportability decision. Each current-file hit now also includes `citation_profile` with locator type (`text-line-offset`, `byte-offset`, or `sqlite-table-row`), citation text, source path/name, keyword, line/offset/table/row fields, review-note readiness, and explicit pre-report blockers. Text, binary/hex, SQLite, and extracted document text paths are covered by existing search handlers. Remaining commercial blocker: trusted locator diff and large-file search benchmark.

18. Source viewer specialization.
Acceptance: text, hex, SQLite, JSON, XML, image, media, and email viewers show useful summaries without dumping raw metadata by default.
Current internal progress: source previews now emit `analyst_workbench_profile` for the Stage 10 #51~#60 review/viewer bundle, including reviewer workflow, A/B/C compare, raw hex, SQLite, email, image gallery, media transcript, OCR queue, Korean OCR/translation, and search dedup review entries. The profile includes a `stage10_capability_matrix` plus stable matrix hash so the GUI can render one source-review workbench without guessing which forensic viewer applies. Source previews also emit `source_viewer_specialization_profile` for item #18 with default layout rules, supported viewer feature matrix, source-search/hash/download citation URLs, large-data controls, and reportability blockers. Existing preview builders cover text, hex, SQLite, JSON, XML, image, media, and email. Remaining commercial blocker: browser e2e visual validation, trusted viewer-rendering diff, and large preview corpus.

19. Review board workflow.
Acceptance: relevant, needs-review, not-relevant/excluded, include-in-report, tags, notes, selection tray, review history, and batch decisions are reliable.
Current internal progress: source preview and Case DB review workflows already expose review status, verification status, tags, notes, assignee, priority, include-in-report, immutable local history, and batch review. The analyst workbench profile ties those controls to item #19, and source preview now emits `review_evidence_tray_profile` with tray item fields, default review/verification states, source actions, reportability decision, and audit/conflict blockers for GUI/API consumers. Remaining commercial blocker: role-based multi-user queues, conflict handling, and independent review/audit diff.

20. Compare workflow.
Acceptance: A/B/C pinned evidence comparison supports text, hex, metadata, timeline, and selected-source snippets.
Current internal progress: source preview now advertises item #20 compare support through the analyst workbench profile: A/B/C pinned evidence, bounded text diff, hash comparison, and source preview integration. Source preview also emits `compare_pin_profile` with max pinned items, pin contract fields, compare action URLs, supported/unsupported comparison modes, reportability decision, and persistent-note/diff blockers. The GUI already persists a compare tray locally. Remaining commercial blocker: persistent compare notes, binary/table-aware semantic diff, visual diff, and trusted expected-diff validation.

21. Citation manager.
Acceptance: every report candidate has source path, source hash where available, parser ID/version, pointer/offset/index, reviewer status, confidence, and legal limitation.
Current internal progress: Case DB report exports now emit `functional_reporting_profiles` item #21 with citation counts, review/source citation coverage, source-reference coverage, user-visible blockers, and recommended validation actions. Each exported item also carries `functional_priority_gap_ids` plus a `report_citation_profile` that records the review citation, source citation, source path/hash status, parser ID/version, locator status, review/verification status, parser confidence, legal limitation coverage, item-level blockers, and a stable profile hash. The export summary now includes a report-citation workflow summary so GUI/report consumers can show which candidates are ready for report export and which still need source validation. Remaining commercial blocker: trusted citation-index diff, external exhibit-numbering review, and source-hash completeness proof on a real case corpus.

22. Report generation.
Acceptance: selected report-set items produce Markdown, HTML, DOCX/PDF when dependencies exist, manifest JSON, and hash bundle.
Current internal progress: Case DB report exports now emit item #22 report-generation controls for JSON export, bounded item limits, review/verification status counts, and Markdown report availability through the run report export path. The Case DB export also includes a `report_generation_package` with a bounded Markdown report document, generation manifest, item/citation row hash bundle, manifest hash, and large-case truncation controls so GUI consumers can preview and verify selected report candidates without dumping all rows into the browser. Remaining commercial blocker: rendered DOCX/PDF layout smoke evidence, template approval, and end-to-end hash bundle validation against a real report package.

23. Court exhibit package.
Acceptance: selected evidence manifest, report outputs, audit chain, hashes, provenance, and limitation statements are bundled with a clear verification checklist.
Current internal progress: Case DB report exports now emit item #23 court-exhibit package readiness with citation index, selected item count, provenance rows, custody/hash/audit/reproducibility component availability, and external-signature slot status. The export also includes a `court_exhibit_package` with exhibit IDs, review/source citation IDs, source path/hash/parser/locator status, report citation profile hashes, provenance manifest hashes, package input manifest hashes, an external-signature slot, package hash, and court-use blockers. Remaining commercial blocker: external signing/notarization evidence, copied source-file bundle validation, and independent court-exhibit package review.

24. UX warning language.
Acceptance: UI distinguishes triage-only, review-grade, report-grade, validation-required, and external-evidence-needed states.
Current internal progress: Case DB report exports now emit item #24 warning UX controls with validation-assessment coverage, warning counts, legal limitation counts, limitation-assessment coverage, and explicit blockers for trusted wording review. Each report item also carries a `warning_display_profile` with triage-only/review-grade/report-grade-candidate/validation-required/external-evidence-needed badges, display actions, warning/legal details, and a GUI contract for table badges, collapsible detail panels, and report-export warnings. The export summary includes warning state and badge counts. Remaining commercial blocker: browser UI visual audit and trusted legal/validation wording checklist diff.

25. Browser e2e performance validation.
Acceptance: large tables/search results are tested in a browser with 100k+ records without DOM or memory collapse.
Current internal progress: paginated API responses now include `functional_priority_profile` item #25 under `pagination.ui_virtualization`, recording bounded visible rows, total rows, API pagination, large-table windowing support, and missing browser-e2e evidence blockers. `/api/workbench/large-result-evidence` now also emits a browser e2e performance contract with stable selectors, required Playwright steps, DOM/latency/memory budgets, required artifacts, window manifest hashes, and a large-result evidence manifest hash so later real-browser traces can be attached and compared. Remaining commercial blocker: 100k+ record browser run with DOM node count, memory, p95 latency, keyboard navigation, viewport persistence, and screenshot evidence.

### Phase 4: Large Evidence Performance

26. Streaming parser boundary.
Acceptance: large binary inputs avoid full-file reads unless explicitly bounded and documented.
Current internal progress: run summaries now emit `processing.functional_large_data_profiles` item #26 with read-only/dry-run state, extract size/file caps, bounded JSON stage outputs, and an explicit “not all parsers are streaming-safe” blocker. They now also emit `processing.streaming_parser_boundary`, a per-stage manifest with bounded-output status, source-content read risk, selected/extracted/skipped counts, parser error counts, zero default streaming-safe claims, required audit/benchmark evidence, and a manifest hash that item #26 references. Remaining commercial blocker: per-parser full-read audit and large binary streaming benchmark evidence.

27. Persistent job queue.
Acceptance: parser jobs persist progress, warnings, cancellation, retry eligibility, and stage outputs.
Current internal progress: API job payloads now emit `job_queue_assessment.functional_priority_profile` item #27 with job status, step count, state-file persistence, cancel/retry support, and local-threadpool limitation. Existing state persistence restores completed jobs from disk. Job payloads now also include a `job_persistence_manifest` with progress percent, terminal step count, step rows, retry eligibility, cancellation state, output keys, transition head hash, local queue model, blockers, and manifest hash; the job queue assessment references the same manifest and adds `job_queue_report_grade_validation_plan` hashes with ready/blocking slots. Remaining commercial blocker: distributed worker queue, externally trusted transition logs, parser-level percentage progress/resource telemetry, cancellation validation under load, and multi-worker retry idempotency validation.

28. Parser crash isolation.
Acceptance: parser crashes are captured per artifact without killing the whole run.
Current internal progress: run summaries now emit item #28 under `functional_large_data_profiles`, tied to the existing isolated parser error payload, failed parser JSON output, and run-continuation contract. Isolated parser error outputs now also include `parser_crash_isolation_manifest` with parser kind, input kind, root hash, error hashes, quarantine policy, retry guidance, required external evidence, and manifest hash; the parser crash assessment references that manifest hash. Remaining commercial blocker: native process sandboxing/fuzz corpus and trusted parser-crash corpus diff.

29. Memory cap enforcement.
Acceptance: per-parser memory limits and user-facing warnings exist for heavy stages.
Current internal progress: run summaries now emit item #29 with a `memory-cap-enforcement-manifest-v1` hash, configured memory cap, current RSS, utilization, platform, stage-boundary mode, warning count, and explicit non-hard-limit disclosure. The same manifest hash is referenced by the large-data functional profile so reviewers can trace UI/report claims back to one run artifact. Remaining commercial blocker: hard OS-level Job Object/cgroup limit, live per-parser RSS telemetry, and trusted RSS diff on Windows/macOS/Linux.

30. Incremental indexing.
Acceptance: unchanged files/artifacts are skipped by fingerprint/hash cache when rerunning a case.
Current internal progress: run summaries now emit item #30 with an `incremental-indexing-manifest-v1` hash that binds the run fingerprint, file-record head hash, content-hash policy hash, resume/reindex recommendation, and reuse-plan hash when a prior fingerprint exists. Existing checkpoint/fingerprint files record stage reuse, and the large-data profile now references the same manifest hash for reviewer traceability. Remaining commercial blocker: true row-level per-file content-hash reindexing and large-case changed-source replay validation.

31. Cursor APIs everywhere.
Acceptance: files, docs, artifacts, timeline, indicators, search, review, and report candidates support bounded cursor or offset pagination.
Current internal progress: run-output API pagination now emits item #31 `functional_priority_profile` plus `cursor-api-coverage-manifest-v1` with cursor token, offset compatibility, bounded limit, collection totals, page-window hash, covered endpoint families, and missing review/report/search-family disclosure. Existing coverage includes files, docs, timeline, indicators, and artifact groups. Remaining commercial blocker: endpoint-level proof for Case DB review/report/search candidates and trusted cursor manifest diff.

32. SQLite/FTS optimization.
Acceptance: bulk insert, WAL, maintenance, index strategy, and search latency metrics are recorded.
Current internal progress: Case DB initialization and source SQLite preview now emit item #32 profiles. Case DB records FTS5 tables, hot-path indexes, WAL-when-supported, temp/cache pragmas, and optimize-on-close; source preview records bounded row preview, searchable text column counts, query-plan hash, and `sqlite-fts-optimization-manifest-v1` tying the source DB metadata to the functional profile. Remaining commercial blocker: 10M query-plan regression evidence, source SQLite WAL/journal replay, and trusted FTS diff.

33. Duplicate suppression.
Acceptance: exact hash duplicates collapse by default with analyst override and report-safe representative selection.
Current internal progress: file scan duplicate assessment now emits item #33 with same-size bucketing, bounded SHA256 confirmation, duplicate group/file counts, representative paths, analyst verification warning, and `duplicate-suppression-manifest-v1` tying the duplicate-content manifest hash to the report-suppression policy. Remaining commercial blocker: persisted UI collapse/suppression state, near-duplicate text/media similarity, and trusted duplicate manifest diff.

34. Benchmark command.
Acceptance: 100k, 1M, and 10M synthetic/fixture runs emit JSON with records/sec, p50/p95 latency, memory, and output size.
Current internal progress: benchmark JSON now emits item #34 with file count, 100k/1M/10M scale targets, ingest/search latency, raw latency samples, environment profile, release-threshold guardrail status, peak memory, output size, synthetic/existing-root support, and `benchmark-command-manifest-v1` binding metrics, environment hash, release-threshold hash, and covered scale labels. Remaining commercial blocker: published 100k/1M/10M hardware matrix, trusted threshold manifest, and release-approved threshold comparison.

35. Hardware-scale evidence.
Acceptance: 1TB, 5TB, and 10TB run logs are attached before commercial performance claims.
Current internal progress: stress-plan JSON now emits item #35 with TB scenario sizes, resource caps, required evidence lists, largest-size tracking, explicit “actual hardware run not attached” status, and `hardware-scale-evidence-manifest-v1` binding scenario rows, failure-threshold hash, and evidence-capture profile hash. Remaining commercial blocker: actual 1TB/5TB/10TB run logs, hardware profile, bottleneck traces, and independent reproduction logs.

### Phase 5: Validation And Defensibility

36. Known-answer manifest pipeline.
Acceptance: each report-grade parser has expected rows/counts/fields, evidence hashes, commands, and pass/fail output.
Current internal progress: validation output now emits item #36 with manifest attachment state, dataset/status counts, expected assertion count, evidence path checks, trusted known-answer diff blocker, and `known-answer-pipeline-manifest-v1` binding manifest digest, status counts, evidence hash counts, trusted diff state, and independent-review blocker. Remaining commercial blocker: public-corpus manifests for every report-grade parser plus independent expected-answer review.

37. Trusted tool diff.
Acceptance: EVTX, Registry, MFT, USN, Prefetch, LNK, browser, email, and mobile exports can be compared against trusted tools.
Current internal progress: cross-tool validation assessment now emits item #37 plus `trusted-tool-diff-manifest-v1` with mapped backlog items, configured/observed overlap, per-reference comparison summaries, field-diff mismatch counts, output-written state, source/reference hash counts, external tool version/command checks, corpus scope hash, independent review attachment state, and a stable manifest SHA-256. Functional profile evidence now carries the manifest hash so validation packages can cite the exact trusted-tool comparison bundle. Remaining commercial blocker: trusted-tool export coverage across every claimed parser family and signed reviewer signoff.

38. Parser FP/FN reports.
Acceptance: every parser documents known misses, noisy cases, unsupported formats, and quantified rates where corpus exists.
Current internal progress: parser FP/FN notes now emit item #38 per parser family with risk counts, validation-required guidance, trusted risk-register diff blocker, and a top-level `parser-fp-fn-risk-register-manifest-v1`. The manifest records parser count, risk row count, minimum quantification fields, per-parser quantification field presence, measured FP/FN counts/rates when supplied, missing-quantification parser names, commercial-claim decision, and a stable manifest SHA-256 carried by the register profile. Remaining commercial blocker: quantified FP/FN rates from fixture and public-corpus runs plus reviewer signoff for every report-grade parser family.

39. Independent reviewer package.
Acceptance: attach third-party or independent reviewer report with SHA256 and signoff metadata.
Current internal progress: independent validation output now emits item #39 with report attachment status, SHA256 presence, required signoffs, minimum sections, trusted signoff diff blocker, and `independent-validation-package-manifest-v1`. The package manifest wraps the report manifest hash, section completeness, missing signoff roles, trusted diff status/hash, ready-for-court decision, external evidence requirements, and a stable manifest SHA-256 carried by the functional profile. Remaining commercial blocker: actual independent report, signed reviewer identity package, forensic lead/release-owner signoff, and external trusted signoff diff.

40. Chain-of-custody workflow.
Acceptance: evidence source, acquisition, transfer, review, export, and report events are hash-linked and exportable.
Current internal progress: Case DB custody export now emits item #40 with evidence source count, SHA256/citation coverage, custody event count, actor/timestamp coverage, limitations, trusted custody manifest diff blocker, and `custody-chain-manifest-v1`. The chain manifest records row-hash sequence/head, chained custody head hash, event stage counts for acquisition/transfer/review/export/report, missing stage names, source/event coverage counts, custody-event manifest hash, trusted diff status/hash, and external evidence requirements. Remaining commercial blocker: full acquisition/transfer metadata, external custody diff, write-blocker handoff evidence, and complete lifecycle event coverage.

41. Acquisition metadata UI.
Acceptance: write-blocker, operator, source identifier, acquisition tool/version, timestamps, and notes can be entered and audited.
Current internal progress: Case DB acquisition metadata output now emits item #41 with metadata/evidence counts, operator/write-blocker/tool/timestamp coverage, required-field gaps, trusted handoff diff state, reportability decision, and `acquisition-metadata-input-manifest-v1`. The input manifest gives the GUI/API a stable field schema for evidence source, operator, source identifier, write-blocker, acquisition tool/version, start/end timestamps, whole-source SHA-256, and notes; it also records evidence-source choices, per-field presence/missing counts, audit action, ready-for-submission state, and a stable manifest SHA-256. Remaining commercial blocker: polished GUI input flow wired to this manifest, real write-blocker handoff evidence, and external acquisition manifest diff.

42. Timezone and clock skew.
Acceptance: preserve original timestamps, UTC normalization, source timezone, parser assumptions, and skew warnings.
Current internal progress: timezone validation and clock-skew outputs now emit item #42 with event counts, missing timezone counts, timezone inventory, sample counts, warning counts, UTC assumption disclosure, trusted baseline diff blockers, and `time-semantics-manifest-v1`. The semantics manifest preserves per-sample original timestamp, source timezone, normalized UTC value, timestamp kind, source/event type, parser assumption, parse status, sample row hash, source-viewer field list, and a stable manifest SHA-256. Remaining commercial blocker: parser-specific timezone matrix and acquisition-time baseline evidence for each evidence source.

43. Contamination detection.
Acceptance: warn on output inside evidence root, writable source, generated files under evidence, zero-byte sources, and changed acquisition metadata when known.
Current internal progress: contamination warnings now emit item #43 with evidence source count, warning count/types, output-inside-evidence-root checks, staged-output checks, zero-byte source checks, stat failure checks, trusted checklist diff blocker, and `contamination-acquisition-context-manifest-v1`. The context manifest records acquisition metadata coverage, missing write-blocker count, writable-source permission warnings, source-to-metadata linkage, redacted write-blocker hashes, per-source warning types, and a stable manifest SHA-256. Remaining commercial blocker: OS-level write-blocker integration, authoritative writable-source policy per platform, and acquisition metadata change tracking across time.

44. Tamper-evident audit.
Acceptance: review/export/report actions form a hash chain with a verifiable head hash.
Current internal progress: Case DB audit integrity now emits item #44 with event count, event-hash coverage, previous-hash coverage, head-hash state, external notarization requirement, trusted hash-chain diff blocker, and `audit-replay-manifest-v1`. The replay manifest recomputes each audit event hash, validates previous-hash continuity, records mismatch indexes, verifies the recomputed head hash against the exported head, and emits a stable manifest SHA-256 for independent replay. Remaining commercial blocker: external signing/notarization and immutable storage policy.

45. Claim discipline.
Acceptance: no UI, report, or doc claims commercial-grade unless validation and external evidence gates pass.
Current internal progress: commercial-readiness output now emits item #45 with commercial-claim gate state, non-commercial count, readiness score, mapped validation evidence count, release-claim guard, explicit blocked wording, and `claim-discipline-manifest-v1`. The manifest gives UI/report/docs a stable claim policy with blocked wording, allowed wording, required disclaimer, badge/template guardrails, all-items evidence requirement, and a manifest SHA-256 carried by the functional profile. Remaining commercial blocker: all #1~#120 validation evidence attached, readiness score 100, and zero non-commercial items.

### Phase 6: Expand High-Value Data Sources

46. Browser history and downloads parity.
Acceptance: Chrome, Edge, Firefox, Brave, and Safari where applicable normalize visits, downloads, searches, transitions, profiles, timestamps, and deleted/export caveats.
Current internal progress: browser artifacts now emit item #46 with browser/profile, supported browser family list, history/download counts, unified timeline count, top-domain count, Safari applicability note, deleted-state caveat, and trusted timeline diff blocker. Visit/download rows now preserve source SQLite table and row ID where available, and `browser-history-download-citation-manifest-v1` records bounded row citations, source-viewer locators, row hashes, source SHA-256, timeline row hashes, review workflow hints, and a stable manifest SHA-256 for report/source verification. Browser history/download rows additionally emit `browser_timeline_depth_manifest` for #20 with unified visit/download timeline scope, timestamp/source-index integrity, browser-family native depth, citation refs, Safari/deleted-state limits, and exact blockers. macOS Safari downloads now correlate LaunchServices `QuarantineEventsV2` source rows into the unified timeline with quarantine source table/row/path/hash and agent provenance. Remaining commercial blocker: browser-version transition semantics, deleted-history validation, Safari cache/session/deleted-state parity corpus, and trusted browser export diff.

47. Browser storage inventory.
Acceptance: cache, cookies, Local Storage, Session Storage, IndexedDB, extensions, sync, and credential stores are inventoried without exposing secrets by default.
Current internal progress: browser artifacts now emit item #47 with cache/session/extension/sync/cookie/credential inventory state, sensitive store count, redaction-by-default control, legal warning, and trusted storage diff blocker. Storage rows now also emit `browser-storage-citation-manifest-v1` with source file locators, per-row hashes, sample file SHA-256 citations, sensitive-store counts, metadata-collapsed review workflow hints, and a stable manifest SHA-256 so analysts can open the exact raw store only after authority/scope review. Browser history/download and storage-inventory rows additionally emit `browser_storage_depth_manifest` for #19 with storage-family presence, native decode depth, legal-scope review controls, citation refs, reportability limits, and commercial blockers so cache/session/extension/sync inventory is not overstated as complete browser-version schema decoding. Remaining commercial blocker: full cache/session/extension schema decode, audited authority gate for secrets, and trusted storage fixture diff.

48. AI service transcript candidates.
Acceptance: ChatGPT, Claude, Gemini, Perplexity, Copilot, Poe, DeepSeek, Mistral, Meta AI, Character.AI, and related services produce Q/A candidate pivots with confidence and source validation warnings.
Current internal progress: AI browser artifacts now emit item #48 with supported AI service list, detected service counts, candidate row count, question/answer/pair counts, completeness score, source file count, pairing confidence, and trusted service-export diff blocker. AI conversation records now also emit `ai-transcript-candidate-manifest-v1` with candidate text hashes/previews, source storage paths, offsets, JSON Pointer locators for service exports, source SHA-256s, pair citations, source-viewer locators, chat-like review workflow hints, large-data caps, and a stable manifest SHA-256. AI conversation rows additionally emit `ai_transcript_schema_validation_manifest` for #21 with detected service counts, service/schema validation state, source storage coverage, JSON Pointer locator coverage, Q/A pairing quality, candidate manifest linkage, reportability limits, and exact blockers for service-side export/schema/deleted-fragment/trusted-diff validation. Remaining commercial blocker: service-side export validation, schema-version fixtures, deleted-fragment recovery, and FP/FN measurement.

49. Email expansion.
Acceptance: EML, EMLX, MBOX, Maildir remain strong; PST/OST/MSG require libpff or dedicated parser integration for folder/message/deleted-item support.
Current internal progress: email artifacts now emit item #49 with source format/family/support tier, native-decode state, message/attachment/candidate counts, source SHA256 state, supported format list, and trusted mailbox diff blocker. Message and mailbox rows now also emit `email-expansion-citation-manifest-v1` with message citations, attachment citations, bounded PST/OST/MSG candidate citations, source-viewer locators, row hashes, source SHA-256, review workflow hints, and large-data caps. Remaining commercial blocker: libpff/native MAPI decode, folder/deleted item support, threading/dedup validation, and broad mailbox known-answer corpus.

50. Messenger export framework.
Acceptance: KakaoTalk, WhatsApp, Telegram, Signal, LINE, WeChat, Discord, Instagram, iMessage, Messenger, Slack, Teams, Viber, Skype, Matrix, Wire, Threema, Session, Wickr are handled first as authorized export/schema mappers.
Current internal progress: messenger artifacts now emit item #50 with service/profile detection, supported service count/list, source hash state, conversation/message/media/reaction fields, chat database table count, legacy #31~#35 mapping, and trusted messenger export/native DB diff blocker. Remaining commercial blocker: per-service schema mappers, encrypted/deleted store workflows, attachment recovery validation, and known-answer corpora for each messenger.
Latest hardening: mobile message and chat-database records now emit `messenger-export-framework-manifest-v1` with `#50` plus legacy gap mapping, stable manifest hash, row citation, source-viewer locator, bounded SQLite table citations, hash-only text handling, redaction defaults, and large-data caps. Core accuracy gates and uplift evidence now require the manifest/source locator before treating the row as fully framework-normalized.

51. KakaoTalk Windows split strategy.
Acceptance: legacy decrypt workflow, post-BigBang key-store inventory, memory/registry/Windows.edb correlation, and limitation reporting are separate modes.
Current internal progress: PC KakaoTalk collect/decrypt/key-store/sqlcipher outputs now emit item #51 `functional_priority_profile` with separated mode list, legacy decrypt state, post-BigBang key-store inventory state, memory/registry correlation counts, raw-secret redaction, and known-answer/trusted-tool blockers. Remaining commercial blocker: before/after-BigBang known-answer ZIP corpus, trusted extractor diff, and Windows 11 runtime smoke evidence.
Latest hardening: #51 profile now embeds `kakaotalk-windows-split-strategy-manifest-v1` with stable hash, per-mode status blocks for legacy decrypt, userdir brute force, post-BigBang key-store inventory, SQLCipher probe, memory/registry/Windows.edb correlation, and authorized Windows collection. The manifest records evidence counts, source JSON pointers, large-case caps, raw-secret redaction defaults, and explicit commercial blockers so GUI/report workflows can show which path produced each KakaoTalk conclusion.

52. Mobile vendor import.
Acceptance: Cellebrite, XRY, GrayKey, AXIOM exports have schema registry, version mapper, validation warnings, and source hashes.
Current internal progress: mobile import rows now emit item #52 functional profiles inside commercial uplift evidence, recording source tool/format/index/hash, vendor setting verification, schema/version presence, source row identity preservation, and trusted vendor diff status. Remaining commercial blocker: per-vendor schema version fixtures and trusted Cellebrite/XRY/GrayKey/AXIOM export diffs.
Latest hardening: #52 mobile rows now emit `mobile-vendor-import-manifest-v1` with stable hash, source row locator, source record ID, vendor family/schema registry expectations, source/export hash linkage, sidecar manifest status, row cap/redaction controls, and explicit diff/corpus blockers. #26 core gates and #52 functional profiles now require this manifest/locator before treating a vendor row as fully import-normalized.

53. iOS backup parser.
Acceptance: Manifest.db, Info.plist, Status.plist, SMS, media, app DB candidates, and encrypted-backup lawful-key workflow.
Current internal progress: iOS backup/keychain rows now emit item #53 functional profiles covering Manifest/domain mapping, Info/Status plist inventory, SMS/media/app DB candidate detection, redacted keychain inventory, encrypted-backup lawful-key workflow requirement, and no-secret-export stance. Remaining commercial blocker: encrypted backup unlock workflow evidence, protected-data validation, and trusted iOS backup corpus.
Latest hardening: #53 iOS backup/keychain rows now emit `ios-backup-parser-manifest-v1` with stable hash, source-viewer locator, Manifest.db fileID/domain/path citation, backup root/scope metadata, keychain table/redaction/authority state, lawful-key workflow flags, row caps, and explicit known-answer/protected-data blockers. #27/#28 gates and #53 functional profiles now require the manifest/locator before treating iOS backup rows as parser-normalized.

54. Android backup/app data parser.
Acceptance: SMS, call, contacts, browser, media, APK metadata, permissions, app DB inventory, and encrypted-store limitation gate.
Current internal progress: Android APK/app-data rows now emit item #54 functional profiles covering package/path attribution, communication/browser/media/app DB inventory, APK manifest/permission inventory, secret extraction state, encrypted-store limitation, and app-schema/known-answer blockers. Remaining commercial blocker: native Android backup payload decoding, app-specific schema fixtures, deleted-row validation, and trusted Android export diff.
Latest hardening: #54 Android APK/app-data rows now emit `android-backup-app-data-parser-manifest-v1` with stable hash, source-viewer locator, package/source hash, APK permission/component/DEX/native/signing inventory, app-data SQLite table counts, artifact family matrix, source-layout classification, secret/schema boundary, and large-data caps. #29/#30 gates and #54 profiles now require the manifest/locator before treating Android rows as parser-normalized.

55. Cloud export import.
Acceptance: Google Takeout, Gmail, Drive, Photos, Location, iCloud, M365, Teams, OneDrive, SharePoint, Slack, Dropbox, Box are normalized with provider completeness warnings.
Current internal progress: cloud export rows now emit item #55 functional profiles with provider family/service/artifact, source hash, Google/iCloud/M365 inventory controls, provider scope verification state, deleted-object and tenant-permission limitations, and trusted provider diff blockers. Remaining commercial blocker: provider export scope proof, known-answer exports, deleted-state/share-permission validation, and provider-native export/API diff.
Latest hardening: #55 cloud export rows now emit `cloud-export-import-manifest-v1` with stable hash, source-viewer locator, provider strategy track, product/workload review family, row pivots, original source hash, redaction defaults, and explicit provider-scope/known-answer/deleted-state/native-diff blockers. #37/#38/#39 gates and #55 profiles now require the manifest/locator before treating cloud export rows as reviewable provider imports.

56. Cloud API acquisition.
Acceptance: OAuth/device-flow or token-based collection is scoped, paginated, rate-limited, audited, redacted, and local-only by default.
Current internal progress: cloud collection output now emits item #56 `functional_priority_profile` with manifest-driven HTTPS request support, dry-run validation, credential redaction, environment-token boundary, response hashing, bounded response size, local-only default, and explicit blockers for provider OAuth/device flow, scope discovery, pagination/delta collection, token vaulting, and trusted provider API diff. Remaining commercial blocker: provider-specific OAuth/device-flow implementations, scope/consent capture, pagination/backoff proof, legal-hold workflow, and provider known-answer response diffs.
Latest hardening: #56 `cloud-collect` output now emits `cloud-api-acquisition-manifest-v1` with stable manifest hash, source manifest hash, output/response directories, request locators, response hashes, retry/pagination declarations, provider scope profile, credential boundary, large-response caps, and OAuth/scope/pagination/known-answer/token-vault blockers. #40 gates and #56 functional profiles now surface this manifest for GUI/report provenance.

### Phase 7: Packaging And Operations

57. Windows installer.
Acceptance: double-click install, bundled runtime/dependencies where appropriate, Start Menu launcher, smoke test on fresh Windows 11.
Current internal progress: release manifest and packaging plan now emit item #57 functional profiles for Windows installer readiness, including MSI/EXE targets, portable payload, Windows launcher packaging, Windows smoke script packaging, and explicit Authenticode/timestamp/fresh-Windows-smoke blockers. Remaining commercial blocker: actual signed MSI/EXE, timestamp authority proof, Start Menu installer behavior, and fresh Windows 11 smoke logs.
Latest hardening: release manifests now include `windows-installer-workflow-manifest-v1` with stable hash, payload hashes, Windows launcher entries, installer workflow steps, MSI/EXE wrapper evidence slot, Authenticode/timestamp/fresh-Windows-smoke evidence slots, verification commands, and explicit non-commercial blockers. This makes #57 internally auditable while keeping actual signed installer and Windows 11 smoke evidence as external blockers.

58. Windows portable mode.
Acceptance: unzip-and-run package works without developer tools and clearly reports missing optional forensic utilities.
Current internal progress: packaging plan now emits item #58 functional profile for portable ZIP readiness, including Windows double-click launcher, shell launcher, dependency inventory, optional forensic tool preflight documentation, and SHA256/release manifest verification path. Remaining commercial blocker: fresh Windows portable smoke evidence proving unzip-and-run works without developer tooling.
Latest hardening: packaging plans now include `windows-portable-mode-manifest-v1` with stable hash, portable ZIP hash, dependency/SHA256/release-manifest presence, required Windows launcher/preflight/documentation ZIP entries, double-click entrypoints, preflight commands, case/log/tool placeholder controls, and explicit fresh-Windows smoke blockers.

59. macOS package.
Acceptance: signed/notarized package and Gatekeeper evidence before commercial claim.
Current internal progress: release manifest and packaging plan now emit item #59 functional profiles for macOS package readiness, including PKG/DMG targets, portable payload, macOS/Linux launcher packaging, smoke script packaging, and explicit codesign/notarization/Gatekeeper blockers. Remaining commercial blocker: actual signed/notarized package, notary ticket, Gatekeeper assessment, and fresh macOS smoke logs.
Latest hardening: release manifests now include `macos-package-workflow-manifest-v1` with stable hash, payload hashes, launcher entries, pkg/dmg workflow steps, pkg/dmg build log slot, codesign/notarization/Gatekeeper evidence slots, verification commands, and explicit external notarization blockers.

60. Linux packages.
Acceptance: deb, rpm, and AppImage builds with clean install/uninstall smoke logs.
Current internal progress: release manifest and packaging plan now emit item #60 functional profiles for Linux packaging readiness, including deb/rpm/AppImage targets, portable ZIP/wheel/sdist support, dependency inventory, smoke script packaging, and explicit distro package/install/uninstall blockers. Remaining commercial blocker: real deb/rpm/AppImage builds, clean-container install/uninstall logs, and distro smoke evidence.
Latest hardening: release manifests now include `linux-package-workflow-manifest-v1` with stable hash, portable/wheel payload hashes, Linux launcher entries, deb/rpm/AppImage workflow steps, package evidence slots, install/uninstall smoke slot, verification commands, and explicit clean-container/package-wrapper blockers.

61. Local-only enterprise policy.
Acceptance: no telemetry, no hidden upload, localhost default, remote bind requires explicit auth token and warning.
Current internal progress: enterprise policy output now emits item #61 functional profile with telemetry disabled, evidence/crash uploads disabled, localhost default, remote auth-token requirement, auth configured state, and explicit network-egress/local-only policy diff blockers. Remaining commercial blocker: independent local-only deployment review, network egress smoke evidence, and remote-bind auth test logs.
Latest hardening: enterprise policy telemetry output now includes `local-only-deployment-manifest-v1` with stable hash, upload surface inventory, zero known outbound endpoint inventory, network bind/auth boundary, crash upload boundary, verification commands, egress/auth evidence slots, and explicit external network-smoke/deployment-policy blockers.

62. Backup/restore/migration.
Acceptance: Case DB backups, WAL/SHM handling, restore verification, schema versioning, and migration corpus.
Current internal progress: case backup and restore outputs now emit item #62 functional profiles with backup manifest state, WAL/SHM copy attempts, database hash capture, schema/table inventory, restore hash verification, and migration rehearsal requirement. Remaining commercial blocker: scheduled backup drill, migration corpus, and trusted backup/restore rehearsal evidence.
Latest hardening: case backup and restore outputs now include `backup-restore-continuity-manifest-v1` with stable hash, source/backup/restored database linkage, copied file hashes, WAL/SHM presence, schema snapshot hash, migration-readiness hash, restore hash verification state, and explicit restore-drill/migration-corpus/scheduled-backup external evidence requirements.

63. Security hardening.
Acceptance: path traversal, archive extraction, report HTML escaping, malicious evidence preview, auth token, and export safety are tested.
Current internal progress: enterprise security-hardening output now emits item #63 functional profile covering documented path/archive/export/preview/auth/crash-redaction/parser-isolation controls and explicitly marking OS-level sandboxing plus independent AppSec/fuzz/malicious-corpus evidence as missing. Remaining commercial blocker: independent AppSec review, malicious evidence sandbox corpus, archive/path traversal fuzz suite, and OS-level parser sandbox.
Latest hardening: enterprise security-hardening output now includes `security-hardening-baseline-manifest-v1` with stable hash, control inventory for path traversal, archive extraction, report HTML escaping, active-content preview blocking, remote auth token guard, crash redaction, and parser crash isolation, plus explicit external fuzz/AppSec/malicious-corpus/OS-sandbox validation blockers.

64. Dependency monitoring.
Acceptance: SBOM/dependency baseline, pip-audit or equivalent, scheduled CI advisory scan, and release-blocking severity.
Current internal progress: dependency monitoring output now emits item #64 functional profile with dependency inventory, pip-audit attempt, release-blocking policy, packaged monitoring script, scan output sizes, and blockers for scheduled CI advisory scan, SBOM publication, and trusted advisory/SBOM diff. Remaining commercial blocker: CI scheduled scan evidence, SBOM publication, and dependency exception review process.
Latest hardening: dependency monitoring output now includes `dependency-sbom-manifest-v1` with stable hash, CycloneDX-style Python component inventory, component inventory hash, publication status, and advisory/SBOM blockers. The dependency evidence manifest now references the SBOM manifest hash so release evidence can connect pip inventory, vulnerability scan, and SBOM publication.

65. Crash reporting.
Acceptance: local-only crash capture, redaction, export button, and no evidence upload.
Current internal progress: local crash reports now emit item #65 functional profile with local file path, automatic upload disabled, sensitive context redaction, runtime metadata, operator-export requirement, and redaction/export review blockers. Remaining commercial blocker: UI export smoke evidence and trusted crash redaction/no-upload review.
Latest hardening: crash reports now include `crash-no-upload-manifest-v1` with stable hash, local report path, automatic-upload disabled state, zero known upload endpoint inventory, privacy-note hash, export manifest linkage, redacted context key count, local storage boundary, and operator-export/no-upload review blockers.

66. Admin guide.
Acceptance: install, update, auth, backup, logging, security, dependency, and evidence handling guide.
Current internal progress: release manifest operations evidence now emits item #66 functional profile with admin guide packaging, install/update/auth/network/backup/logging/security/dependency/evidence-handling guidance, and explicit deployment-proof/operator-signoff blockers. Remaining commercial blocker: fresh admin deployment proof and operator acceptance signoff.
Latest hardening: release builds now emit `admin-guide-coverage-manifest-v1` and `admin-guide-coverage-manifest.json`, hashing the admin/security/release/quickstart documents and machine-checking install, update, auth, network, backup, restore, logging, security, dependency, and evidence-handling coverage. The admin deployment guide was expanded into an operator runbook with install/update, network/auth, backup/restore/logging, security, and evidence handoff sections. Remaining commercial blocker: fresh admin deployment proof and operator acceptance signoff.

67. Training lab.
Acceptance: sample case walks through ingest, search, viewer, review, report, and manifest verification.
Current internal progress: release manifest operations evidence now emits item #67 functional profile with packaged training curriculum, Windows/macOS/Linux quickstarts, sample-case workflow, ingest/search/viewer/review/report steps, and manifest verification guidance. Remaining commercial blocker: real analyst training run logs, scoring rubric results, and training delivery signoff.
Latest hardening: `rapidtriage sample --run` now writes `rapidtriage-training-lab-manifest.json` with stable hash, expected keywords, workflow stages, viewer/review exercises, output hashes, missing-output checks, and external training blockers. The sample-case guide and training curriculum now describe how analysts should verify search hits, source preview, review marks, notes, report output, and manifest hashes. Remaining commercial blocker: real analyst training run logs, scoring rubric results, and training delivery signoff.

68. Support process.
Acceptance: support SLA docs exist, but staffed desk and contractual response remain external/operator-owned.
Current internal progress: release manifest operations evidence now emits item #68 functional profile with SLA document packaging, severity levels, response targets, secure evidence intake requirement, and emergency patch policy. Remaining commercial blocker: staffed support desk, contractual SLA evidence, and secure intake runbook signoff.
Latest hardening: release builds now emit `support-process-readiness-manifest-v1` and `support-process-readiness-manifest.json`, hashing support/LTS/security/release documents and machine-checking severity levels, response targets, secure intake, escalation, hotfix gates, and release attachment coverage. Remaining commercial blocker: staffed support desk, contractual SLA evidence, secure intake runbook signoff, and emergency parser hotfix drill logs.

69. Release discipline.
Acceptance: release notes, known limits, migration notes, validation state, checksums, and smoke logs are mandatory.
Current internal progress: release manifest operations evidence now emits item #69 functional profile with release notes template, known limits, LTS/hotfix policy, migration-note requirement, validation-state requirement, checksum generation, and smoke-log requirement. Remaining commercial blocker: CI release-note gate, required smoke logs, and migration-note review evidence.
Latest hardening: release builds now emit `release-discipline-manifest-v1` and `release-discipline-manifest.json`, hashing release checklist/notes/known-limit/parser-coverage/LTS documents and machine-checking supported-input limits, validation state, migration notes, checksums, smoke logs, signing/notarization status, and hotfix policy coverage. Remaining commercial blocker: CI release-note gate, fresh smoke logs, release-owner signoff, and migration-note review evidence.

70. External blocker ledger.
Acceptance: independent validation, large hardware tests, code signing, notarization, and staffed support are tracked as blockers instead of being falsely marked done.
Current internal progress: release manifest operations evidence now emits item #70 functional profile tracking independent validation, large hardware tests, code signing, notarization, staffed support, and commercial-claim guard state as explicit blockers. Remaining commercial blocker: attaching those external evidence packages and rerunning release evidence verification.
Latest hardening: release builds now emit `external-blocker-ledger-manifest-v1` and `external-blocker-ledger-manifest.json`, consolidating independent validation, large-hardware performance, Windows signing, macOS notarization, staffed support, admin deployment proof, and smoke-log blockers with owners and required evidence. The ledger explicitly sets `commercial_claim_allowed=false` until those external packages are attached.

## Recommended Execution Order

1. Finish Phase 1 and Phase 2 before adding more niche parsers.
2. After Windows core artifacts are trustworthy enough, finish Phase 3 so analysts can actually use the data.
3. Then run Phase 4 because large evidence can make a correct parser unusable if it is too slow or memory-heavy.
4. Phase 5 is required before any report-defensible or commercial-grade claim.
5. Phase 6 should expand data sources only after the core Windows flow is stable.
6. Phase 7 makes the tool usable outside a developer machine.

## Non-Negotiable Product Rule

Every feature must report one of these states:

- `triage-only`: useful lead, not report-ready.
- `review-grade`: analyst can inspect and mark, but external validation may be required.
- `report-grade`: enough provenance, hash, parser confidence, and source citation for report inclusion.
- `commercial-validated`: report-grade plus corpus/trusted-tool/independent/scale/platform evidence.

Do not collapse these states. Overstating confidence is worse than missing a feature.
