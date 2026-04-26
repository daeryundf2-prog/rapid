# rapidtriage output schemas

This document fixes the current JSON result shape emitted by the `rapidtriage` CLI.

## Conventions

- Every result file is written as UTF-8 JSON with two-space indentation and a trailing newline.
- Paths are emitted as strings. In real runs they are normally absolute because the CLI resolves user input before scanning or writing.
- Timestamps are emitted as ISO-8601 strings. Filesystem-derived timestamps currently use `datetime.isoformat()` from the local machine. Some Windows browser collector timestamps are emitted in UTC with an explicit offset (for example `+00:00`). When a timestamp cannot be determined, the value is `null`.
- Samples in `docs/rapidtriage/samples/` are representative. Field names and nesting are stable; paths, counts, timestamps, and artifact contents vary by run.

## Sample files

- `docs/rapidtriage/samples/rapidtriage-manifest.sample.json`
- `docs/rapidtriage/samples/rapidtriage-docs.sample.json`
- `docs/rapidtriage/samples/rapidtriage-files.sample.json`
- `docs/rapidtriage/samples/rapidtriage-extract-from-files.sample.json`
- `docs/rapidtriage/samples/rapidtriage-extract-from-docs.sample.json`

## `rapidtriage manifest`

Top-level object:

| Field | Type | Notes |
| --- | --- | --- |
| `generated_at` | string | Run timestamp. |
| `root` | string | Scanned root path. |
| `platform` | string | `platform.platform()` string from the machine that generated the manifest. |
| `keywords` | array of strings | Empty for the standalone `manifest` command. Reused when the same manifest object is embedded under `docs`. |
| `providers` | array of objects | One entry per provider returned by `rapidtriage.artifacts.all_providers()`. |

Provider object:

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | Stable machine-readable provider identifier. |
| `description` | string | Human-readable description. |
| `target_platform` | string | Provider target such as `any` or `windows`. |
| `supported` | boolean | Whether the provider reports support in the current runtime. |
| `artifacts` | array of artifact objects | Provider-specific rows. |

Artifact object:

| Field | Type | Notes |
| --- | --- | --- |
| `provider` | string | Provider identifier repeated on each row. |
| `artifact_type` | string | Stable machine-readable artifact type. |
| `path` | string | Filesystem path associated with the row. |
| `supported` | boolean | Mirrors provider support for that row. |
| `details` | object | Provider-specific JSON-serializable payload. |

Current Windows collector detail shapes inside `providers[].artifacts[]`:

- `windows-browser-artifacts` / `browser-history-downloads`
  - `details.user`, `browser`, `profile`, `history_count`, `download_count`
  - `details.history[]`: `url`, `title`, `visit_count`, `last_visited_at`
  - `details.downloads[]`: `source_url`, `target_path`, `tab_url`, `total_bytes`, `state`, `started_at`, `ended_at`
- `windows-browser-artifacts` / `browser-history`
  - same outer keys as above, but `downloads` is an empty array and `download_count` is `0`
- `windows-recent-files`
  - `artifact_type` is one of `recent-shortcut`, `jumplist-automatic`, `jumplist-custom`
  - `details.user`, `entry_name`, `entry_hint`, `size`, `modified_at`
- `windows-eventlog`, `windows-registry`, `windows-shellbags`
  - placeholder rows currently expose `details.note`
- `generic-documents`
  - `artifact_type` is `document-pattern`
  - `details.extension` is one of the supported document-search suffixes.

See: `docs/rapidtriage/samples/rapidtriage-manifest.sample.json`

## `rapidtriage docs`

Top-level object:

| Field | Type | Notes |
| --- | --- | --- |
| `command` | string | Always `docs`. |
| `root` | string | Scanned root path. |
| `generated_at` | string | Run timestamp. |
| `summary.candidate_count` | integer | Number of supported document files discovered before keyword filtering. |
| `summary.match_count` | integer | Number of result rows that matched at least one keyword. |
| `summary.supported_extensions` | array of strings | Sorted list of supported suffixes, including text/config/log/data files, HTML/RTF, PDF, Office OpenXML, and OpenDocument formats. |
| `index` | object | Optional sidecar metadata when a processed-text inverted index is written. |
| `manifest` | object | Full manifest object with the same schema as `rapidtriage manifest`. |
| `candidates` | array of objects | All supported document candidates. |
| `results` | array of objects | Keyword hits only. |

When indexing is enabled, the sidecar command is `docs-index` and uses a `processed-text-inverted-index` strategy. It stores per-document text hashes/lengths and lower-cased token postings, but not full extracted text.

Candidate row:

| Field | Type | Notes |
| --- | --- | --- |
| `path` | string | Candidate file path. |
| `kind` | string | Extension without the leading dot, such as `txt`, `pdf`, `docx`, `xlsx`, `pptx`, `odt`, `html`, or `log`. |
| `size` | integer | File size in bytes. |
| `modified_at` | string | Filesystem modified timestamp. |

Result row:

| Field | Type | Notes |
| --- | --- | --- |
| `path` | string | Matching file path. |
| `kind` | string | Same values as candidate `kind`. |
| `matched_keywords` | array of strings | Lower-cased keywords that matched the extracted text. |
| `preview` | string | Text preview around the first match. |
| `size` | integer | File size in bytes. |

See: `docs/rapidtriage/samples/rapidtriage-docs.sample.json`

## `rapidtriage files`

Top-level object:

| Field | Type | Notes |
| --- | --- | --- |
| `command` | string | Always `files`. |
| `root` | string | Scanned root path. |
| `generated_at` | string | Run timestamp. |
| `filters` | object | Echo of normalized CLI filters. |
| `summary` | object | Counts plus newest/oldest candidate timestamps. |
| `candidates` | array of objects | Metadata-only file triage rows. |

`filters` object:

| Field | Type | Notes |
| --- | --- | --- |
| `categories` | array of strings | Selected categories after normalization. |
| `name_contains` | array of strings | Lower-cased basename substrings. |
| `path_contains` | array of strings | Lower-cased full-path substrings. |
| `extensions` | array of strings | Lower-cased extensions, each including the leading dot. |
| `modified_after` | string or `null` | Normalized ISO timestamp bound. |
| `modified_before` | string or `null` | Normalized ISO timestamp bound. |
| `limit` | integer | Result cap; `0` means unlimited. |

Default file categories are `documents`, `archives`, `databases`, `executables`, `emails`, `disk-images`, `mobile-images`, `memory-dumps`, `vehicle-images`, and `images`. Evidence-container categories are aligned with common Magnet AXIOM evidence source formats, including EnCase/FTK/AFF4/raw/VM/mobile image families, memory dumps, and iVe vehicle exports.

`summary` object:

| Field | Type | Notes |
| --- | --- | --- |
| `scanned_file_count` | integer | Number of files stat-ed during traversal. |
| `candidate_count` | integer | Number of emitted candidate rows. |
| `category_counts` | object | Per-category hit counts. |
| `newest_modified_at` | string or `null` | Max candidate timestamp. |
| `oldest_modified_at` | string or `null` | Min candidate timestamp. |

Candidate row:

| Field | Type | Notes |
| --- | --- | --- |
| `path` | string | Candidate file path. |
| `name` | string | Basename. |
| `extension` | string | Lower-cased suffix, including the leading dot, or empty string. |
| `size` | integer | File size in bytes. |
| `modified_at` | string | Filesystem modified timestamp. |
| `modified_epoch` | number | Raw `st_mtime` float used for sorting. |
| `categories` | array of strings | One or more matched built-in categories. |
| `reasons` | object | Map of category -> array of reason strings such as `extension:.txt` or `mode:executable`. |

See: `docs/rapidtriage/samples/rapidtriage-files.sample.json`

## `rapidtriage extract`

Top-level object:

| Field | Type | Notes |
| --- | --- | --- |
| `command` | string | Always `extract`. |
| `source_command` | string | `files` or `docs`, depending on the input JSON. |
| `input_json` | string | Source result JSON path. |
| `root` | string or `null` | Resolved source root from the input payload. |
| `generated_at` | string | Run timestamp. |
| `output_dir` | string | Extraction target directory. |
| `filters` | object | Echo of normalized extraction filters. |
| `summary` | object | Selection, extraction, and skip counts. |
| `entries` | array of objects | Successfully copied files. |
| `skipped` | array of objects | Missing source files only. |

`filters` object:

| Field | Type | Notes |
| --- | --- | --- |
| `name_contains` | array of strings | Lower-cased basename filters. |
| `path_contains` | array of strings | Lower-cased path filters. |
| `extensions` | array of strings | Extension filters with leading dots. |
| `categories` | array of strings | Only populated when `source_command` is `files`. |
| `kinds` | array of strings | Only populated when `source_command` is `docs`. |
| `limit` | integer | Result cap; `0` means unlimited. |

`summary` object:

| Field | Type | Notes |
| --- | --- | --- |
| `input_count` | integer | Number of source rows read from the input JSON. |
| `selected_count` | integer | Number of rows selected after filters. |
| `extracted_count` | integer | Number of files successfully copied. |
| `skipped_count` | integer | Number of selected rows skipped because the source file was missing. |

Common entry fields:

| Field | Type | Notes |
| --- | --- | --- |
| `original_path` | string | Source file path. |
| `extracted_path` | string | Copied output path. |
| `relative_path` | string | Relative path inside `output_dir`. |
| `sha256` | string | Hex digest of the source file bytes. |
| `modified_at` | string | Source file modified timestamp. |
| `size` | integer | Source file size in bytes. |

Source-specific entry fields:

- When `source_command` is `files`, each entry also includes `categories`.
- When `source_command` is `docs`, each entry may include `kind` and `matched_keywords`.

Skipped row:

| Field | Type | Notes |
| --- | --- | --- |
| `original_path` | string | Missing source path. |
| `reason` | string | Currently always `missing`. |

See:

- `docs/rapidtriage/samples/rapidtriage-extract-from-files.sample.json`
- `docs/rapidtriage/samples/rapidtriage-extract-from-docs.sample.json`

## `rapidtriage submission-manifest`

The local web API writes `rapidtriage-submission-manifest.json` for reviewed evidence marked as report candidates.

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

Each `items[]` row includes bookmark context, review state, and an `evidence` object with `path`, `name`, `size`, `modified_at`, and `hashes` (`md5`, `sha1`, `sha256`). `skipped[]` records unavailable, missing, out-of-scope, or capped evidence rows.

## `rapidtriage case-report`

The local web API writes `rapidtriage-case-report.md`, `rapidtriage-case-report.html`, and `rapidtriage-case-report.docx` from case review data and the submission hash manifest.

The report draft includes case metadata, analyst/requester fields, analysis scope, run summary, reviewed/report-candidate counts, report-candidate evidence with MD5/SHA1/SHA256, skipped hash rows, conclusion/opinion text, and attachment references. HTML is optimized for browser review/printing; DOCX is a portable OpenXML handoff draft.
