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
| `rapidtriage run ROOT --mode MODE` | `OUTPUT_DIR/rapidtriage-run-summary.json` | workflow summary JSON plus `rapidtriage-run-report.md` |

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

Current supported document kinds:

- `txt`
- `pdf`
- `docx`

`summary` contains:

- `candidate_count`
- `match_count`
- `supported_extensions`

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

Additional category currently available for profile-specific workflows:

- `images`

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
- `artifacts/rapidtriage-artifacts-*.json`
- `docs-extract/rapidtriage-extract-manifest.json`
- `files-extract/rapidtriage-extract-manifest.json`
- `rapidtriage-run-summary.json`
- `rapidtriage-run-report.md`

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

`summary` contains aggregated counters for:

- document candidates and matches
- scanned files and file candidates
- provider artifact counts
- dedicated artifact collector outputs
- matched keywords
- file categories
- docs/files extraction counts
- preferred-location candidate counts

`highlights` currently contains:

- `document_hits`
- `recent_file_candidates`
- `large_file_candidates`
- `preferred_location_candidates`

## CLI help examples

Keep `--help` output aligned with the current interface for:

- `rapidtriage --help`
- `rapidtriage docs --help`
- `rapidtriage files --help`
- `rapidtriage extract --help`
- `rapidtriage artifacts --help`
- `rapidtriage run --help`
