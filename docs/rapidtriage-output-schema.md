# rapidtriage output schema

`rapidtriage` output is frozen by two artifacts in this repository:

- machine-readable JSON Schema files in `rapidtriage/schemas/*.schema.json`
- representative samples in `docs/samples/*.sample.json`

Any change to command output, nested object layout, field naming, or timestamp/path semantics must update the schema files, sample JSON, README examples, and tests in the same change.

Planned rule-engine / IOC lookup additions are tracked separately in `docs/rapidtriage-rule-engine.md` so the future additive fields are documented before the core implementation lands.

## Schema files

- `rapidtriage/schemas/manifest.schema.json`
- `rapidtriage/schemas/docs.schema.json`
- `rapidtriage/schemas/files.schema.json`
- `rapidtriage/schemas/extract.schema.json`
- `rapidtriage/schemas/artifacts.schema.json`
- `rapidtriage/schemas/run-summary.schema.json`
- `rapidtriage/schemas/timeline.schema.json`
- `rapidtriage/schemas/indicators.schema.json`
- `rapidtriage/schemas/compare.schema.json`
- `rapidtriage/schemas/case.schema.json`
- `rapidtriage/schemas/submission-manifest.schema.json`

## Sample files

- `docs/samples/rapidtriage-manifest.sample.json`
- `docs/samples/rapidtriage-docs.sample.json`
- `docs/samples/rapidtriage-files.sample.json`
- `docs/samples/rapidtriage-extract.sample.json`
- `docs/samples/rapidtriage-artifacts.sample.json`
- `docs/samples/rapidtriage-run-summary.sample.json`

## Command overview

| Command | Default output | Notes |
| --- | --- | --- |
| `rapidtriage manifest ROOT` | `rapidtriage-manifest.json` | provider inventory plus embedded artifact rows |
| `rapidtriage docs ROOT -k KEYWORD` | `rapidtriage-docs.json` | document candidate list and keyword hits |
| `rapidtriage files ROOT` | `rapidtriage-files.json` | metadata-only candidate file scan |
| `rapidtriage extract INPUT_JSON OUTPUT_DIR` | `OUTPUT_DIR/rapidtriage-extract-manifest.json` | copied originals plus hash/mtime manifest |
| `rapidtriage artifacts ROOT --kind KIND` | `./rapidtriage-artifacts-KIND.json` | dedicated collector output for one artifact family |
| `rapidtriage vsc-compare CURRENT SNAPSHOT...` | `rapidtriage-vsc-compare.json` | current-vs-VSC snapshot deleted/added/modified candidates, optionally hash-confirmed |
| `rapidtriage vsc-extract CURRENT SNAPSHOT... --output-dir DIR` | `DIR/rapidtriage-vsc-extract.json` | copied VSC deleted/modified snapshot files with source/destination hashes |
| `rapidtriage compare LEFT RIGHT` | `rapidtriage-compare.json` | two-file A/B review with hashes, changed fields, and bounded text diff preview |
| `rapidtriage carve ROOT --output-dir DIR` | `DIR/rapidtriage-carve.json` | bounded JPEG/PNG/PDF/ZIP carving candidates with source offsets, SHA256, status, and optional extracted bytes |
| `rapidtriage run ROOT --mode MODE` | `OUTPUT_DIR/rapidtriage-run-summary.json` | workflow summary JSON plus `rapidtriage-run-report.md`, `rapidtriage-timeline.json`, and `rapidtriage-timeline-report.md` |
| `rapidtriage search RUN_OUTPUT -k KEYWORD` | `rapidtriage-search.json` | unified keyword search over completed run outputs, including optional OCR |
| `rapidtriage validation --output-dir DIR` | `DIR/rapidtriage-validation-package.json` | release checks, required commands, required documents, known limits, and validation report sidecar |

## `validation` JSON

Top-level keys:

- `command`
- `generated_at`
- `platform`
- `score_target`
- `status`
- `output_dir`
- `outputs`
- `checks`
- `release_artifact_requirements`
- `independent_validation_plan`
- `support_sla_template`
- `recommended_commands`
- `required_documents`
- `known_limits`
- `release_decision`

## `manifest` JSON

Top-level keys:

- `generated_at`
- `root`
- `platform`
- `keywords`
- `providers`

Each provider row contains:

- `name`
- `description`
- `target_platform`
- `supported`
- `artifacts`

Each artifact row contains:

- `provider`
- `artifact_type`
- `path`
- `supported`
- `details`

Current Windows artifact collector rows surfaced through `manifest` include:

- `windows-browser-artifacts`
- `windows-recent-files`
- `windows-os-account`
- `windows-execution`
- `windows-filesystem`
- `windows-eventlog`
- `windows-registry`
- `windows-shellbags`
- `windows-prefetch`
- `windows-system`
- `linux-system-artifacts`
- `macos-system-artifacts`

Browser artifact `details` include the raw `history`/`downloads` rows plus normalized review pivots:

- `internet_usage_count`
- `ai_usage_count`
- `ai_conversation_candidate_count`
- `internet_category_counts`
- `top_domains`
- `internet_usage[]` rows with `url`, `domain`, `category`, `visit_count`, and `last_visited_at`
- `ai_usage[]` rows with `ai_service`, `url`, `domain`, `title`, `query_hint`, `prompt_hint`, `confidence`, and `last_visited_at`
- `ai_conversation_candidates[]` preview rows recovered from browser storage when available
- `source_path` and `source_hashes` for the browser database

When AI service visits are detected, the browser collector also emits `browser-ai-usage` on Windows or `macos-browser-ai-usage` on macOS. These rows are review-oriented evidence that a browser visited an AI service; they do not claim complete prompt recovery unless the prompt appears in URL parameters, titles, cache, or another parsed source.

When browser storage contains recoverable AI-like message snippets, the collector emits `browser-ai-conversation` or `macos-browser-ai-conversation`. These rows include `conversation_candidates[]` with `direction` (`question`, `answer`, or `context`), `role`, `text`, `ai_service`, `storage_area`, source path, and confidence. They also include `transcript_pairs[]`, `complete_pair_count`, orphan question/answer counts, `transcript_completeness_score`, and `transcript_validation_status` so reviewers can prioritize paired question/answer evidence. Treat them as review candidates because browser caches and LevelDB fragments may be partial or stale.
AI conversation rows may include `ai_transcript_schema_validation_manifest`, a stable hashable #21 manifest that separates detected service counts, service/schema validation state, source storage coverage, Q/A pairing quality, candidate manifest linkage, reportability limits, and exact blockers for service-side export, schema-version, deleted-fragment, and trusted-diff validation. AI usage and conversation rows may also include `ai_transcript_analyst_review_profile`, a compact GUI/report card with Q/A counts, completeness score, source manifest hashes, "not complete transcript" warnings, service-export validation blockers, and correlation targets such as raw browser storage, service exports, downloads, documents, and cloud exports.
Browser history/download and storage inventory rows may also include `browser_storage_depth_manifest`, a stable hashable #19 manifest that separates cache/session/extension/sync/cookie/credential inventory scope, native decode depth, legal-scope review controls, citation refs, reportability limits, and exact blockers. This prevents cache/session/extension/sync inventory rows from being overstated as complete browser-version schema decoding.
Browser history/download rows may also include `browser_timeline_depth_manifest`, a stable hashable #20 manifest that separates unified visit/download timeline scope, timestamp/source-index integrity, browser-family native depth, source citation refs, Safari/deleted-state limits, and exact blockers. This prevents normalized timeline rows from being overstated as a complete cross-browser chronology without trusted diff and known-answer validation.

## `docs` JSON

Top-level keys:

- `command`
- `root`
- `generated_at`
- `summary`
- `manifest`
- `candidates`
- `results`
- optional `scan_scope_root` when produced inside `run`
- optional `index` metadata when a processed-text index sidecar is written

Current supported document kinds include:

- plain text/config/log/data: `txt`, `log`, `csv`, `tsv`, `md`, `json`, `jsonl`, `xml`, `yaml`, `yml`, `ini`, `cfg`, `conf`, `eml`
- markup/rich text: `html`, `htm`, `rtf`
- office/open document: `docx`, `xlsx`, `pptx`, `odt`, `ods`, `odp`
- PDF: `pdf`

`summary` contains:

- `candidate_count`
- `match_count`
- `supported_extensions`

When indexing is enabled, `rapidtriage` writes a sidecar such as `rapidtriage-docs-index.json` with command `docs-index`, strategy `processed-text-inverted-index`, per-document text hashes/lengths, and a lower-cased inverted token map. The sidecar intentionally stores no full extracted text.

`results[]` contains:

- `path`
- `kind`
- `matched_keywords`
- `preview`
- `size`

## `files` JSON

Top-level keys:

- `command`
- `root`
- `generated_at`
- `filters`
- `summary`
- `candidates`
- optional `scan_scope_root` when produced inside `run`

`filters` contains:

- `categories`
- `name_contains`
- `path_contains`
- `extensions`
- `modified_after`
- `modified_before`
- `limit`

Default file categories remain:

- `documents`
- `archives`
- `databases`
- `executables`
- `emails`
- `disk-images`
- `mobile-images`
- `memory-dumps`
- `vehicle-images`
- `images`

The evidence-container categories are aligned with common Magnet AXIOM evidence source formats, including EnCase/FTK/AFF4/raw/VM/mobile image families, memory dumps, and iVe vehicle exports.

Each candidate row contains:

- `path`
- `name`
- `extension`
- `size`
- `modified_at`
- `modified_epoch`
- `categories`
- `reasons`

## `extract` JSON

Top-level keys:

- `command`
- `source_command`
- `input_json`
- `root`
- `generated_at`
- `output_dir`
- `filters`
- `summary`
- `entries`
- `skipped`

Common `entries[]` fields:

- `original_path`
- `extracted_path`
- `relative_path`
- `sha256`
- `modified_at`
- `size`

Source-specific `entries[]` fields:

- from `files`: `categories`
- from `docs`: `kind`, `matched_keywords`

## `submission-manifest` JSON

The web API can generate `rapidtriage-submission-manifest.json` from reviewed case evidence. By default it hashes only bookmarks marked as report candidates.

Top-level keys:

- `command`
- `generated_at`
- `case_id`
- `title`
- `hash_algorithms`
- `options`
- `summary`
- `items`
- `skipped`

Each `items[]` row preserves bookmark/review context plus an `evidence` object containing:

- `path`
- `name`
- `size`
- `modified_at`
- `hashes.md5`
- `hashes.sha1`
- `hashes.sha256`

Rows are skipped when the source path is unavailable, missing, outside the run evidence roots, or exceeds the configured item cap.

## `case-report` exports

The web API can generate `rapidtriage-case-report.md`, `rapidtriage-case-report.html`, `rapidtriage-case-report.docx`, `rapidtriage-case-report.pdf`, and `rapidtriage-case-report.exports.json` from `rapidtriage-case.json` and `rapidtriage-submission-manifest.json`.

The report draft includes:

- case metadata such as title, case number, investigator, organization, and requester
- analysis target/scope and run output directory
- run step summary
- reviewed item counts and report-candidate counts
- per-evidence file path, size, modified time, MD5, SHA1, SHA256, tags, and analyst note
- skipped hash rows and reasons
- conclusion/opinion text
- attachment list for case JSON, hash manifest, audit sidecars, and run report

The HTML export is intended for browser review and printing. The DOCX export is a dependency-free OpenXML handoff draft for analyst/legal editing. The PDF export is generated without external rendering tools for quick sharing. The export manifest records each report file path, filename, size, and SHA256 so the delivered report set can be verified later.

## `artifacts` JSON

The independent `artifacts` command exposes one collector per invocation.

Artifact rows preserve the legacy shape (`provider`, `artifact_type`, `path`, `supported`, `details`) for compatibility, and also attach `artifact_record` to every emitted row. `artifact_record` follows `ArtifactRecordV1` so GUI, search, review, report, JSONL, and future columnar stores can share one row contract while individual collectors are still being deepened. The payload-level `artifact_record_contract` records adapter version, valid/invalid row counts, and whether the output is GUI-usable.

Top-level keys:

- `command`
- `kind`
- `generated_at`
- `root`
- `provider`
- `summary`
- `artifacts`
- `artifact_record_contract`

Current CLI kinds:

- `browser`
- `recent-files`

The collector interface is intentionally narrow so additional Windows-specific collectors such as shellbags, eventlog, and registry can be exposed without changing the top-level output contract.

Event log artifact rows use open-ended `details` so parser-specific fields can evolve. Current normalized event rows include `event_id`, `provider_name`, `channel`, `event_family`, typed user/process/network pivots, `event_message`, `message_rendering`, and `event_semantics_profile`. The semantics profile is a GUI/report aid that records analyst severity, review questions, primary pivot fields, populated source values, risk tags, correlation targets, and validation requirements for high-value Windows events. The `message_rendering` object records whether the message came from an imported export field, a RapidTriage built-in fallback template, or an unresolved native provider template, and native EVTX fallback rows carry validation warnings plus preserved TemplateInstance IDs, rendering confidence, provenance, and limitations when available. Native EVTX rows can also include `evtx_record_provenance`, `evtx_native_parse_profile`, `evtx_message_rendering_profile`, `evtx_validation_checks`, `evtx_recovery_context`, and `evtx_report_citation_manifest`; invalid record headers are emitted as `eventlog-record-candidate` rows with offset, integrity, confidence, and caution-label fields. Native BinXML value fields now include best-effort CDATA, character-reference, entity-reference, processing-instruction target, and processing-instruction data token rows when present, while keeping unsupported-token counts explicit. The EVTX citation manifest preserves record offset/hash locators, rendered-message hash, bounded EventData field citations, validation-matrix pass/fail IDs, reportability blockers, and a stable manifest hash for review/report handoff. Recovery candidate rows also include `evtx_recovery_report_citation_manifest`, which preserves source hash, candidate offset/size/hash, chunk/free-space context, recovery class, required independent checks, caution labels, and a stable manifest hash while forcing `evtx-recovery-triage-pivot-only` reportability until known-answer/deleted-corrupt corpus validation is attached. Native chunk structure rows are emitted as `eventlog-chunk` with `evtx_chunk_header`, `evtx_chunk_integrity`, slack bounds, and checksum-observation fields.

Registry artifact rows also keep parser-specific `details` open-ended. Native hive rows can include `registry-key-tree-node` for best-effort key reconstruction, `registry-key-recovery-candidate` for free/deleted `nk` key cells, and `registry-value-recovery-candidate` for free/deleted `vk` value cells, with source offsets, hbin scan method, allocation state, confidence, validation guidance, transaction-log evidence, `registry_transaction_replay_profile`, and cautious recovery metadata. Key-tree rows, deleted/free-cell rows, and user-activity rows can also include `registry_analyst_review_profile`, which gives GUI/report consumers severity, review questions, primary pivots, populated source values, correlation targets, validation requirements, and commercial blockers. Key-tree rows also carry `registry_subkey_list_profile`, `registry_value_list_profile`, and `registry_key_tree_reconstruction_profile` so reviewers can see the exact `lf`/`lh`/`li`/`ri` subkey-list cells, value-list offsets, decoded child/value counts, list-cell hashes, parent-chain/root reachability, backlink consistency, and bounded reconstruction blockers instead of relying only on a final path string. Key-tree and deleted-cell rows can include `registry_report_citation_manifest`, which preserves hive hash, cell offset, key/value locator, transaction-log context, recovery validation state, validation-matrix pass/fail IDs, reportability blockers, and a stable manifest hash for review/report handoff. Adjacent `LOG1`/`LOG2` files are now hashed, header-inspected for recognized transaction-log signatures such as `HvLE`/`HvLG`, and summarized as replay input readiness without applying replay. Deleted/free-cell profiles include false-positive controls, allocator neighbor context (`registry-allocator-neighbor-context-v1`), previous/next scanned cell summaries, same-hbin checks, gap-to-next-cell hints, and do-not-report-as-fact wording until independent offset/corpus validation is attached.

Windows commercial-readiness profiles are intentionally emitted inside artifact `details` instead of being kept only in documentation. Current Windows rows may include `registry_user_activity_profile`, `sam_security_system_deep_parser_profile`, `mft_full_parser_profile`, `usn_journal_replay_profile`, nested `execution_artifact_validation_profile` objects, `execution_analyst_review_profile`, `windows_search_analyst_review_profile`, `ntfs_analyst_review_profile`, `jumplist_analyst_review_profile`, `shellbag_analyst_review_profile`, `prefetch_analyst_review_profile`, `lnk_analyst_review_profile`, `system_analyst_review_profile`, and `browser_analyst_review_profile`. These profiles record the normalized row contract, decoded component flags, source provenance, reportability decision, large-data controls, commercial blockers, and exact checks required before court/report-grade use. The analyst review profiles are optimized for GUI/report handoff: they expose severity, evidence interpretation, "not proof of" warnings, analyst questions, primary pivots with populated source values, correlation targets, risk tags, failed validation checks, and commercial blockers for weak or partially decoded Windows artifacts.

Mobile and Android commercial-readiness profiles follow the same row-level pattern. Vendor/iOS rows for #26~#28 may include `mobile_analyst_review_profile`, which exposes source tool/format/index, primary row pivots, source hash, viewer locator, "not proof of" warnings, trusted vendor/mobile-tool diff targets, acquisition-hash questions, schema-version checks, failed validation IDs, and report blockers. Android APK/app-data rows for #29~#30 may include `android_analyst_review_profile`, which exposes package identity, manifest format, dangerous permission counts, DEX/native pivots, app-data SQLite table counts, trusted aapt/apkanalyzer/MobSF/ALEAPP diff targets, and explicit warnings that the row is not a malware verdict, signature-trust validation, decoded app content, or deleted-record recovery.

Email and cloud rows for #36~#40 also expose compact analyst review cards. `email_analyst_review_profile` covers EML/MBOX/Maildir/PST/OST/MSG rows with source hashes, mailbox/message pivots, attachment counts, citation manifest hashes, privilege-scope warnings, and trusted mailbox-parser diff targets. `cloud_analyst_review_profile` covers Google/iCloud/Microsoft/cloud export rows with provider family, source hash, row pivots, viewer locator, provider-native diff targets, sharing/retention/deleted-state warnings, and report blockers. `cloud_api_analyst_review_profile` covers #40 collection runs with manifest hash, response hash samples, credential boundary, provider/API diff targets, pagination/legal-authority questions, and explicit non-claims for complete provider acquisition.

Search analysis output for #46~#50 and #60 may include `analysis_analyst_review_profile`, a top-level workbench card that summarizes match, cluster, entity, graph, timeline, workbook, and duplicate counts with review entrypoints, top source pivots, non-claims, correlation targets, and report blockers. It is intentionally a review-routing layer: reports should cite the underlying source rows and saved review decisions, not the analysis card by itself.

Windows OS/account, execution, and Windows Search rows use the same open-ended `details` model. OS/account rows may include account lifecycle, service configuration, mounted-device, LSA-sensitive-location, privilege-assignment, exported group-membership hint, SAM account-candidate, SAM group-candidate, and profile summary records; account lifecycle rows can include SAM F/V binary presence metadata, first-pass SAM F timestamp/RID/UAC candidates, SAM V UTF-16 string candidates, SAM V offset/length layout string candidates such as user name, full name, comments, home/profile paths, validation checks, and commercial-readiness blockers. Account lifecycle rows also include `sam_security_context_manifest`, a stable hashable citation package for normalized group/privilege/service/LSA context rows with per-row hashes, account identity, source hash, secret-redaction policy, reportability blockers, and Case DB indexing safety. SECURITY/LSA rows may include exported secret value names, value types, byte counts, hashes, entropy, and timestamp candidates without decrypting secrets. Exported group-membership rows include member SID/name lists, source typing, count semantics, validation checks, and native SAM alias-member blockers. Execution rows may include Amcache export/native-hive candidates, bounded native Amcache nearby-string row clusters with source offsets, SHA1 candidates, timestamp candidates, and metadata candidates; Amcache rows now include `amcache_report_citation_manifest` with source hash, source key/offset, normalized path/hash identity, timestamp semantics, row-cluster locator, reportability blockers, and explicit `standalone_execution_proof=false`. Execution rows may also include ShimCache caveated entries, native SYSTEM hive ShimCache/AppCompatCache bounded path clusters with `cache_order`, `source_offset`, nearby timestamp candidates, and not-proof-of-execution warnings; ShimCache rows now include `shimcache_report_citation_manifest` with source hash, source key/offset, normalized path identity, cache-order or timestamp citation, native row-cluster locator, OS-build layout validation blockers, and explicit `standalone_execution_proof=false`. BAM/DAM rows include `bam_dam_report_citation_manifest` with source hash, ControlSet/source key, SID, device path, timestamp semantics, native row-cluster locator, binary FILETIME row validation blockers, and explicit correlation-before-testimony wording. SRUM rows now include `srum_report_citation_manifest` for source-tool imports, database inventory, string pivots, table candidates, and row candidates; it preserves source hash, table/app identity, counter names, timestamp semantics, row-cluster/source-offset locator, native ESE row-decoding blockers, and `standalone_execution_proof=false`. These Amcache/ShimCache/BAM/DAM/SRUM rows also emit `execution_analyst_review_profile` so the GUI can show the right severity, pivots, correlation checklist, and caveat wording without treating a weak execution-related artifact as final proof. Execution rows may also include PowerShell history commands, SRUM imports, SRUDB string pivots, native SRUDB validation metadata, SRUM table-family candidates, and bounded `srum-row-candidate` string-cluster rows with `nearby_string_count`, `nearby_offsets`, row-cluster string samples, field-presence profiles, validation checks, and commercial-readiness blockers where native decoding is not yet report-grade. Windows Search EDB rows include `windows_edb_report_citation_manifest` and `windows_search_analyst_review_profile` for source-tool exports, database inventory, string pivots, page candidates, table candidates, and row candidates; they preserve source hash, path/URL/content identity, page locator, table/deleted-state semantics, row-cluster hints, not-proof-of warnings, and native ESE row/deleted-state validation blockers. Windows Search EDB row candidates may include page-local `page_offset`, `page_sha256`, `page_table_marker_hits`, `field_presence_profile`, and page-local correlation flags; these are source-citation aids, not full native ESE row decoding.
Windows system rows for Task Scheduler, Defender support logs, Firewall logs, WER reports, and WMI repository files may include `system_deep_parser_manifest` and `system_analyst_review_profile`, separating normalized semantics, risk/review pivots, validation matrix pass/fail IDs, native depth capabilities, citation refs, analyst questions, reportability limits, and the exact cross-artifact correlation blockers required before report-grade claims.

Windows system rows may also include Explorer cache, Activities/Notifications/UWP, web-server log, and webshell triage records. `webshell-source-candidate` rows can include `webshell_semantic_profile`, source-code evidence spans, external rule sidecars, IIS site correlation, web-log correlation, filesystem/log timeline correlation, and `webshell_report_citation_package`. The citation package is a bounded review/report handoff with source hashes, text locators, rule sidecar hashes, IIS/log/timeline references, a stable manifest hash, and explicit blockers. Its allowed use is `webshell-triage-correlation-package`; it must not be described as court-ready malware attribution until trusted rule-pack diff, full server-log corpus, MFT/USN timeline correlation, and manual malware review evidence are attached.

Windows filesystem rows may include MFT/USN import records and native `$MFT`/`$J` inventory. Native MFT rows can include update-sequence validation, common attribute summaries, FILETIME timestamp validation, resident data hashes, bounded nonresident `$DATA` runlist preview decoding, bounded parent-chain path candidates when parent records are present in the scanned window, validation checks, parser confidence, and `commercial_grade_ready=false` blockers because full attribute-list/data-run/path reconstruction still requires dedicated validation. Native USN rows can include bounded scan metadata, record cursor/next-cursor offsets, v2/v3 reference metadata, filename UTF-16 validation, v4 extent offset/length previews, bounded MFT path correlation when a USN FRN or parent FRN matches the scanned MFT cache, journal-level `bounded_mft_replay_preview` counts/path samples, `mft_bounded_path_cache_profile` cache quality counts/warnings, `usn_path_reliability_profile` correlation/cache confidence and review priority, `usn_state_replay_validation_profile` when a trusted export diff is attached, `rename_pair_preview` OLD/NEW candidate pairs, `delete_lifecycle_preview` create/delete candidate lifecycles, `bounded_state_replay_preview` create/rename/delete state-transition samples, `timeline_review_candidates` rename/create/delete timestamp pivots, large-record sizing, timestamp ranges where available, validation checks, and `commercial_grade_ready=false` blockers because full replay/correlation and large-corpus pagination validation still require dedicated validation. Rename-pair path candidates prefer parent-cache plus the USN OLD/NEW filename for the event-time path, while preserving `old_frn_path_correlation`/`new_frn_path_correlation` so reviewers can see the bounded MFT cache evidence separately from the event-name path. The bounded state replay sorts by USN/cursor and applies create, rename, and delete effects to a limited in-memory FRN path state; each transition carries `timeline_type`, `reportability`, `validation_required`, and blocker fields so timeline/report output keeps the same caution instead of presenting a replay preview as fact. `usn_state_replay_validation_profile` deliberately separates record-level trusted parser diff success from state-machine replay validation, so a passing UsnJrnl2Csv/MFTECmd row diff is not overstated as a validated rename/delete state replay. Use `build_usn_state_replay_trusted_diff` to compare nested RapidTriage state transitions against known-answer or trusted replay transition rows before treating the state-machine output as validated. Native `mft-record` and `usn-record` rows also include `ntfs_report_citation_manifest`, a stable hashable source-citation object containing source SHA256, row identity, byte offset/cursor, validation pass/fail IDs, viewer entrypoints, reportability limits, and record-specific refs such as MFT `$FILE_NAME`/`$DATA`/`$ATTRIBUTE_LIST` evidence or USN reason/rename/delete/v4-extent/path-correlation refs.
Native `mft-record` rows additionally include `mft_parser_depth_manifest` and `ntfs_analyst_review_profile`, separating USA validation, attribute decoding, ATTRIBUTE_LIST resolution status, resident/nonresident data-run decoding, parent path reconstruction state, citation refs, reportability limits, analyst questions, and exact commercial blockers so reports cannot accidentally overstate bounded native MFT parsing as complete file content/path reconstruction.
Native `usn-record` rows additionally include `usn_timeline_depth_manifest` and `ntfs_analyst_review_profile`, separating record layout validation, reason/source/file-attribute semantics, bounded MFT path correlation, cursor pagination state, replay validation state, citation refs, reportability limits, analyst questions, and exact blockers so reports cannot accidentally overstate sampled USN records as a complete replayed timeline.
JumpList rows may include `jumplist_destlist_depth_manifest` and `jumplist_analyst_review_profile`, separating CFB stream inventory, DestList candidate decoding, embedded LNK destination linkage, AppID hash mapping state, deleted/unlinked entry recovery limits, citation refs, reportability limits, analyst pivots, and commercial blockers so reports cannot accidentally overstate candidate DestList fields as final OS-version semantics.
Native ShellBags rows may include `shellbag_depth_manifest` and `shellbag_analyst_review_profile`, separating source hive/key provenance, BagMRU/Bags candidate relationships, timestamp hints, binary shell-item decode state, transaction-log/deleted-slack validation state, citation refs, reportability limits, analyst pivots, and commercial blockers so reports cannot accidentally overstate key-path candidates as final folder-access testimony.
Prefetch rows may include `prefetch_execution_depth_manifest` and `prefetch_analyst_review_profile`, separating SCCA/version layout validation, run count and last-run timestamp evidence, bounded referenced-path/volume/file-reference candidates, compressed PF handling state, citation refs, analyst questions, reportability limits, and commercial blockers so reports cannot accidentally overstate common-header triage as complete file metrics or standalone execution proof.
LNK shortcut rows may include `lnk_metadata_depth_manifest` and `lnk_analyst_review_profile`, separating Shell Link header validation, StringData/LinkInfo target fields, Shell Item candidate state, ExtraData/TrackerDataBlock metadata, citation refs, analyst questions, reportability limits, and commercial blockers so reports cannot accidentally overstate shortcut target context as fully validated without LECmd or known-answer diff evidence.
Browser rows may include `browser_analyst_review_profile`, separating browser/profile attribution, history/download counts, unified timeline state, storage/sensitive-store review priority, legal-scope warnings, source pivots, correlation targets, and trusted-diff blockers for #19/#20 browser review.
The web artifact workbench reads the same MFT/USN fields for preview/detail cards, showing bounded path candidates, journal replay correlation counts, OLD/NEW rename pair samples, create/delete lifecycle samples, and `source-hex-range` locator links for available record offsets/cursors with the same court-readiness warning.

## `run-summary` JSON

`run` produces:

- `rapidtriage-manifest.json`
- `rapidtriage-docs.json`
- `rapidtriage-files.json`
- `rapidtriage-e01.json` when the input is a direct `.E01` image
- `artifacts/rapidtriage-artifacts-*.json`
- `docs-extract/rapidtriage-extract-manifest.json`
- `files-extract/rapidtriage-extract-manifest.json`
- `rapidtriage-run-summary.json`
- `rapidtriage-run-report.md`
- `rapidtriage-timeline.json`
- `rapidtriage-timeline-report.md`
- `rapidtriage-indicators.json`

Current run modes:

- `seizure`: browser, recent files, Windows OS/account, event log, execution, filesystem, system-artifact, Linux system, and macOS system collectors.
- `fraud`: browser, recent files, Windows OS/account, event log, execution, filesystem, system-artifact, Linux system, and macOS system collectors.
- `hacking`: browser, recent files, Windows OS/account, event log, execution, filesystem, system-artifact, Linux system, and macOS system collectors.
- `recovery`: recent files, Windows OS/account, event log, filesystem, Linux system, and macOS system collectors.

`rapidtriage-run-summary.json` top-level keys:

- `command`
- `mode`
- `generated_at`
- `root`
- `source`
- `scan_scope_root`
- `output_dir`
- `profile`
- `outputs`
- `steps`
- `workflow`
- `processing`
- `summary`
- `highlights`

`profile` contains:

- `description`
- `keywords`
- `docs_extract_kinds`
- `file_extract_categories`
- `file_scan_categories`
- `file_scan_path_contains`
- `preferred_locations`
- `artifacts_kinds`

`source` records the original input and the analysis root. For direct `.E01` input, `source.type` is `e01`, `source.source_path` points to the evidence image, and `source.analysis_root` points to the read-only extracted filesystem under the run output directory. Direct E01/Ex01 runs also emit `source.e01_ex01_workflow_manifest` with `profile_version=e01-ex01-integrated-workflow-manifest-v1`, item `#22`, source hash status, segment profile, dependency preflight, partition selection, extraction provenance, run output keys, stage status from selection through report export, large-data controls, reportability decision, and a stable `manifest_sha256`. The same manifest is present in `rapidtriage-e01.json` as `e01_ex01_workflow_manifest`; in that extraction-only file, artifact/search/review/report stages are marked as ready or blocked until the full run summary connects downstream outputs. Direct raw/split image runs use `source.type=raw-image` and preserve `image_paths`, `partition_start_sector`, and `recovery_mode`. They also emit `source.raw_split_workflow_manifest` and `rapidtriage-disk-image.json.raw_split_workflow_manifest` with `profile_version=raw-split-integrated-workflow-manifest-v1`, item `#23`, split-set order/gap evidence, dependency preflight, partition-or-whole-image decision, extraction provenance, downstream run outputs, large-data controls, reportability decision, and `manifest_sha256`. Direct ISO/DMG/WIM/SWM runs use `source.type=archive-image` and record the extraction `tool`; qemu-convertible virtual disks use `source.type=virtual-disk`, `converted_raw_path`, `conversion_tool`, and the downstream Sleuth Kit recovery metadata. Direct virtual-disk runs also emit `source.virtual_disk_workflow_manifest` and `rapidtriage-virtual-disk.json.virtual_disk_workflow_manifest` with `profile_version=virtual-disk-integrated-workflow-manifest-v1`, item `#24`, qemu-img info/convert provenance, source and converted RAW hashes, snapshot/differencing chain risk, nested RAW recovery summary, downstream run outputs, reportability decision, and `manifest_sha256`. Evidence adapter and image workflow records may also include `image_analyst_review_profile`, which condenses #22~#25 E01/RAW/virtual-disk/container evidence into UI-ready source hash, format, support level, blocked stages, "not proof of" warnings, correlation targets, and exact commercial blockers.

`processing` records user-facing run evidence:

- inferred profile label
- read-only, dry-run, overwrite, resume, and cap settings
- reused output count and reused step names when `run --resume` accepts existing stage JSON
- warning count and highest warning level
- per-step warning messages for empty outputs, read-only skips, capped extraction, or missing source paths

`workflow` records the GUI-facing single-case pipeline contract (`run-workflow-contract-v1`). It maps low-level run steps into six analyst stages: `ingest`, `extract`, `parse`, `index`, `review`, and `report`. Each stage records status (`completed`, `warning`, `blocked`, or `pending`), contributing step names, output keys, warning messages, primary GUI tab/action, and `handoff_outputs`. The handoff rows name the exact output file, its user-facing role, recommended viewer, GUI action, and reportability note, so the web workbench can link each stage directly to the files an analyst must open before trusting the stage.

The web API also exposes `/api/runs/{run_id}/outputs/{output_name}/preview` (`run-output-preview-v1`) for bounded read-only output review. This preview route reuses the same safe renderer as source preview, rewrites the action URLs to run-output download routes, and marks the preview as a review aid rather than standalone proof.

`summary` contains aggregated counters for:

- document candidates and matches
- scanned files and file candidates
- provider artifact counts
- dedicated artifact collector outputs
- matched keywords
- file categories
- docs/files extraction counts
- preferred-location candidate counts
- timeline event counts

`highlights` currently contains:

- `document_hits`
- `recent_file_candidates`
- `large_file_candidates`
- `preferred_location_candidates`

The generated `rapidtriage-run-report.md` is now a submission-oriented template with sections for case overview, processing transparency, key hits, `matched_rules`, `ioc_hits`, indicator pivots, related documents, artifact summary, timeline, extract results, and optional compare findings.

## CLI help examples

Keep `--help` output aligned with the current interface for:

- `rapidtriage --help`
- `rapidtriage docs --help`
- `rapidtriage files --help`
- `rapidtriage extract --help`
- `rapidtriage artifacts --help`
- `rapidtriage run --help`
