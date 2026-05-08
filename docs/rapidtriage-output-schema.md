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

Top-level keys:

- `command`
- `kind`
- `generated_at`
- `root`
- `provider`
- `summary`
- `artifacts`

Current CLI kinds:

- `browser`
- `recent-files`

The collector interface is intentionally narrow so additional Windows-specific collectors such as shellbags, eventlog, and registry can be exposed without changing the top-level output contract.

Event log artifact rows use open-ended `details` so parser-specific fields can evolve. Current normalized event rows include `event_id`, `provider_name`, `channel`, `event_family`, typed user/process/network pivots, `event_message`, and `message_rendering`. The `message_rendering` object records whether the message came from an imported export field, a RapidTriage built-in fallback template, or an unresolved native provider template, and native EVTX fallback rows carry validation warnings plus preserved TemplateInstance IDs, rendering confidence, provenance, and limitations when available. Native EVTX rows can also include `evtx_record_provenance`, `evtx_native_parse_profile`, `evtx_message_rendering_profile`, `evtx_validation_checks`, and `evtx_recovery_context`; invalid record headers are emitted as `eventlog-record-candidate` rows with offset, integrity, confidence, and caution-label fields. Native chunk structure rows are emitted as `eventlog-chunk` with `evtx_chunk_header`, `evtx_chunk_integrity`, slack bounds, and checksum-observation fields.

Registry artifact rows also keep parser-specific `details` open-ended. Native hive rows can include `registry-key-tree-node` for best-effort key reconstruction, `registry-key-recovery-candidate` for free/deleted `nk` key cells, and `registry-value-recovery-candidate` for free/deleted `vk` value cells, with source offsets, hbin scan method, allocation state, confidence, validation guidance, transaction-log evidence, `registry_transaction_replay_profile`, and cautious recovery metadata. Adjacent `LOG1`/`LOG2` files are now hashed, header-inspected for recognized transaction-log signatures such as `HvLE`/`HvLG`, and summarized as replay input readiness without applying replay. Deleted/free-cell profiles include false-positive controls and do-not-report-as-fact wording until independent offset/corpus validation is attached.

Windows commercial-readiness profiles are intentionally emitted inside artifact `details` instead of being kept only in documentation. Current Windows rows may include `registry_user_activity_profile`, `sam_security_system_deep_parser_profile`, `mft_full_parser_profile`, `usn_journal_replay_profile`, and nested `execution_artifact_validation_profile` objects. These profiles record the normalized row contract, decoded component flags, source provenance, reportability decision, large-data controls, commercial blockers, and exact checks required before court/report-grade use.

Windows OS/account, execution, and Windows Search rows use the same open-ended `details` model. OS/account rows may include account lifecycle, service configuration, mounted-device, LSA-sensitive-location, privilege-assignment, exported group-membership hint, SAM account-candidate, SAM group-candidate, and profile summary records; account lifecycle rows can include SAM F/V binary presence metadata, first-pass SAM F timestamp/RID/UAC candidates, SAM V UTF-16 string candidates, SAM V offset/length layout string candidates such as user name, full name, comments, home/profile paths, validation checks, and commercial-readiness blockers. SECURITY/LSA rows may include exported secret value names, value types, byte counts, hashes, entropy, and timestamp candidates without decrypting secrets. Exported group-membership rows include member SID/name lists, source typing, count semantics, validation checks, and native SAM alias-member blockers. Execution rows may include Amcache export/native-hive candidates, bounded native Amcache nearby-string row clusters with source offsets, SHA1 candidates, timestamp candidates, and metadata candidates, ShimCache caveated entries, native SYSTEM hive ShimCache/AppCompatCache bounded path clusters with `cache_order`, `source_offset`, nearby timestamp candidates, and not-proof-of-execution warnings, BAM/DAM user-SID/device-path/timestamp entries, native SYSTEM hive BAM/DAM bounded path/SID/timestamp clusters with `source_offset` and correlation-required warnings, PowerShell history commands, SRUM imports, SRUDB string pivots, native SRUDB validation metadata, SRUM table-family candidates, and bounded `srum-row-candidate` string-cluster rows with `nearby_string_count`, `nearby_offsets`, row-cluster string samples, field-presence profiles, validation checks, and commercial-readiness blockers where native decoding is not yet report-grade. Windows Search EDB row candidates may include page-local `page_offset`, `page_sha256`, `page_table_marker_hits`, `field_presence_profile`, and page-local correlation flags; these are source-citation aids, not full native ESE row decoding.

Windows filesystem rows may include MFT/USN import records and native `$MFT`/`$J` inventory. Native MFT rows can include update-sequence validation, common attribute summaries, FILETIME timestamp validation, resident data hashes, bounded nonresident `$DATA` runlist preview decoding, validation checks, parser confidence, and `commercial_grade_ready=false` blockers because full attribute-list/data-run/path reconstruction still requires dedicated validation. Native USN rows can include bounded scan metadata, record cursor/next-cursor offsets, v2/v3 reference metadata, filename UTF-16 validation, v4 extent offset/length previews, large-record sizing, timestamp ranges where available, validation checks, and `commercial_grade_ready=false` blockers because full replay/correlation and large-corpus pagination validation still require dedicated validation.

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

`source` records the original input and the analysis root. For direct `.E01` input, `source.type` is `e01`, `source.source_path` points to the evidence image, and `source.analysis_root` points to the read-only extracted filesystem under the run output directory. Direct raw/split image runs use `source.type=raw-image` and preserve `image_paths`, `partition_start_sector`, and `recovery_mode`; direct ISO/DMG/WIM/SWM runs use `source.type=archive-image` and record the extraction `tool`; qemu-convertible virtual disks use `source.type=virtual-disk`, `converted_raw_path`, `conversion_tool`, and the downstream Sleuth Kit recovery metadata.

`processing` records user-facing run evidence:

- inferred profile label
- read-only, dry-run, overwrite, resume, and cap settings
- reused output count and reused step names when `run --resume` accepts existing stage JSON
- warning count and highest warning level
- per-step warning messages for empty outputs, read-only skips, capped extraction, or missing source paths

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
