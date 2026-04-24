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
| `rapidtriage run ROOT --mode MODE` | `OUTPUT_DIR/rapidtriage-run-summary.json` | workflow summary JSON plus `rapidtriage-run-report.md`, `rapidtriage-timeline.json`, and `rapidtriage-timeline-report.md` |
| `rapidtriage search RUN_OUTPUT -k KEYWORD` | `rapidtriage-search.json` | unified keyword search over completed run outputs, including optional OCR |

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
- `windows-eventlog`
- `windows-registry`
- `windows-shellbags`

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

## `case-report` Markdown

The web API can generate `rapidtriage-case-report.md` from `rapidtriage-case.json` and `rapidtriage-submission-manifest.json`.

The report draft includes:

- case metadata such as title, case number, investigator, organization, and requester
- analysis target/scope and run output directory
- run step summary
- reviewed item counts and report-candidate counts
- per-evidence file path, size, modified time, MD5, SHA1, SHA256, tags, and analyst note
- skipped hash rows and reasons
- conclusion/opinion text
- attachment list for case JSON, hash manifest, audit sidecars, and run report

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

Current run modes:

- `seizure`
- `fraud`
- `hacking`
- `recovery`

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

`source` records the original input and the analysis root. For direct `.E01` input, `source.type` is `e01`, `source.source_path` points to the evidence image, and `source.analysis_root` points to the read-only extracted filesystem under the run output directory.

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

The generated `rapidtriage-run-report.md` is now a submission-oriented template with sections for case overview, key hits, `matched_rules`, `ioc_hits`, related documents, artifact summary, timeline, extract results, and optional compare findings.

## CLI help examples

Keep `--help` output aligned with the current interface for:

- `rapidtriage --help`
- `rapidtriage docs --help`
- `rapidtriage files --help`
- `rapidtriage extract --help`
- `rapidtriage artifacts --help`
- `rapidtriage run --help`
