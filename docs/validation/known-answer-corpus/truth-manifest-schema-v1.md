# Truth Manifest Schema v1

Status: designed only
Date: 2026-06-17
Schema ID: `rapidforensic-e01-ex01-truth-manifest-v1`
Machine-readable schema: [truth-manifest-schema-v1.schema.json](truth-manifest-schema-v1.schema.json)

This schema records the expected answers for E01/Ex01 known-answer recovery validation. It is designed to be independent from RapidForensic output and suitable for later `known-answer-qc`, trusted diff, and release evidence checks.

## Top-Level Fields

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Must equal `rapidforensic-e01-ex01-truth-manifest-v1`. |
| `corpus_id` | string | yes | Stable corpus ID, for example `rapid-e01-ex01-t1`. |
| `case_id` | string | yes | Stable unique case ID, for example `E01-T1-ALLOCATED-DELETED-001`. |
| `image_id` | string | yes | Stable image ID inside the corpus. |
| `image_format` | string | yes | `E01`, `Ex01`, or `folder-baseline` for Tier 0 only. |
| `filesystem_type` | string | yes | Expected filesystem, for example `NTFS`. |
| `image_segments` | array | yes | Segment list with path hints, indexes, hashes, and sizes. |
| `image_sha256` | string | yes | SHA256 of the complete image or normalized folder baseline manifest. |
| `image_size_bytes` | integer | yes | Total image byte size. |
| `acquisition_tool` | string | yes | Tool or workflow used to create the evidence. |
| `acquisition_tool_version` | string | yes | Exact tool version or build. |
| `source_os` | string | yes | Source operating system. |
| `source_os_version` | string | yes | Source OS version/build. |
| `creation_timestamp_utc` | string | yes | ISO 8601 UTC creation timestamp. |
| `timezone` | string | yes | Source timezone or `UTC` when not applicable. |
| `corpus_tier` | string | yes | One of `T0`, `T1`, `T2`, `T3`, `T4`, `T5`. |
| `license` | string | yes | Corpus license or consent basis. |
| `pii_status` | string | yes | `none`, `synthetic`, `redacted`, or `restricted`. |
| `malware_status` | string | yes | `none`, `synthetic-benign`, `restricted`, or `unknown-blocked`. |
| `retention_policy` | string | yes | Storage and deletion rule. |
| `chain_of_custody` | array | yes | Creation, storage, hash, and review records. |
| `trusted_tool_runs` | array | yes | Reference extraction, listing, verification, and review rows. |
| `expected_items` | array | yes | Expected allocated, deleted, carved, unsupported, and negative-control outcomes. |
| `expected_global_outcomes` | object | yes | Required pass thresholds, logs, and reports. |
| `notes` | string | yes | Operator/reviewer notes. |

## `image_segments` Fields

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `segment_path` | string | yes | External controlled storage path hint. It must not require a Git path. |
| `segment_index` | integer | yes | Zero-based segment order. |
| `size_bytes` | integer | yes | Segment byte size. |
| `sha256` | string | yes | SHA256 of the segment. |

## `chain_of_custody` Fields

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `created_by` | string | yes | Operator or lab identity that created the corpus. |
| `reviewed_by` | array | yes | Independent reviewer identities. Must contain at least one entry when `review_status` is `approved`; may be empty while draft. |
| `creation_method` | string | yes | Synthetic folder, lab image, acquisition suite, or reviewer-built workflow. |
| `storage_location` | string | yes | Controlled external storage URI. |
| `hash_algorithm` | string | yes | Usually `sha256`. |
| `hash_recorded_at` | string | yes | ISO 8601 UTC timestamp. |
| `review_status` | string | yes | `draft`, `approved`, `rejected`, or `needs-review`. |

## Trusted Tool Run Fields

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `run_id` | string | yes | Stable run ID referenced by `expected_items[].trusted_tool_run_ids`. |
| `tool_name` | string | yes | Example: `ewfverify`, `ewfinfo`, `ewfmount`, `mmls`, `fls`, `tsk_recover`, `manual-review`, `vendor-export`. |
| `tool_version` | string | yes | Exact version or build string. |
| `command` | string | yes | Full command or documented GUI workflow summary. |
| `run_timestamp_utc` | string | yes | ISO 8601 UTC timestamp. |
| `host_os` | string | yes | OS and version. |
| `output_path` | string | yes | External path or controlled evidence URI. |
| `output_sha256` | string | yes | Hash of normalized reference output. |
| `notes` | string | yes | Limitations, GUI steps, export settings, or reviewer notes. |

## Expected Item Fields

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `item_id` | string | yes | Stable item ID. |
| `original_path` | string | no | Original expected logical path. |
| `normalized_path` | string | no | Expected normalized path. |
| `expected_status` | string | yes | See expected status values below. |
| `expected_recovery` | string | yes | See expected recovery values below. |
| `expected_recovery_mode` | string | yes | See expected recovery mode values below. |
| `file_type` | string | yes | Example: `jpg`, `png`, `pdf`, `zip`, `sqlite`, `text`, `binary`, `ads`, `metadata`. |
| `size_bytes` | integer | no | Expected logical size if known. |
| `sha256` | string | no | Required when byte-exact complete recovery is expected. |
| `md5_optional` | string | no | Optional MD5 for tool compatibility. |
| `created_time_utc` | string | no | Expected created time. |
| `modified_time_utc` | string | no | Expected modified time. |
| `accessed_time_utc` | string | no | Expected accessed time. |
| `deleted_time_utc_optional` | string | no | Expected deletion time when known. |
| `path_encoding` | string | yes | Example: `utf-8`, `utf-16le`, `unknown`. |
| `unicode_normalization` | string | yes | `exact`, `NFC`, `NFD`, or `not-applicable`. |
| `ads_name_optional` | string | no | ADS stream name when applicable. |
| `is_sparse` | boolean | yes | True for sparse files. |
| `is_fragmented` | boolean | yes | True for fragmented files. |
| `is_carved_only` | boolean | yes | True for carving-only expectations. |
| `trusted_tool_run_ids` | array | yes | Stable trusted tool run IDs supporting this expected item. Must contain at least one entry. |
| `expected_metadata` | object | yes | Record IDs, offsets, partition, stream, timestamps, or other required metadata. |
| `accepted_variants` | array | yes | Accepted alternate paths, timestamp tolerances, or tool-specific equivalents. |
| `expected_failure_reason` | string | no | Required and non-null for `deleted_unrecoverable`, `partially_overwritten`, `metadata_only`, `unsupported`, `inconclusive`, `may_recover_partial`, `must_not_recover`, `expected_unsupported`, and `expected_inconclusive`. |
| `notes` | string | no | Reviewer-facing notes. |

## Expected Status Values

- `allocated`
- `deleted_recoverable`
- `deleted_unrecoverable`
- `partially_overwritten`
- `carved_only`
- `metadata_only`
- `unsupported`
- `inconclusive`

## Expected Recovery Values

- `must_recover_byte_exact`
- `must_list_metadata`
- `may_recover_partial`
- `must_not_recover`
- `expected_unsupported`
- `expected_inconclusive`

## Expected Recovery Mode Values

- `filesystem`
- `carve`
- `metadata`
- `none`

## Expected Global Outcomes

| Field | Type | Required | Initial pass threshold |
| --- | --- | --- | --- |
| `min_recall` | number | yes | `0.990` for recovery candidates, `1.0` for allocated export. |
| `min_precision` | number | yes | `0.995` for recovery candidates, `1.0` for allocated export. |
| `max_false_positives` | integer | yes | Maximum false positive count for the case. |
| `max_inconclusive` | integer | yes | Maximum inconclusive item count for the case. |
| `max_runtime_seconds` | integer | yes | Maximum runtime for the case. |
| `max_peak_memory_mb` | integer | yes | Maximum peak memory in MiB. |
| `required_logs` | array | yes | Required log file names or classes. |
| `required_reports` | array | yes | Required report or evidence bundle names. |

## Example Skeleton

This example is intentionally non-executable and contains placeholder hashes only.

```json
{
  "schema_version": "rapidforensic-e01-ex01-truth-manifest-v1",
  "corpus_id": "rapid-e01-ex01-t1-placeholder",
  "case_id": "E01-T1-ALLOCATED-DELETED-001",
  "image_id": "E01-T1-IMAGE-001",
  "image_format": "E01",
  "filesystem_type": "NTFS",
  "image_segments": [
    {
      "segment_path": "external://controlled-lab-storage/e01-t1/case.E01",
      "segment_index": 0,
      "size_bytes": 0,
      "sha256": "PLACEHOLDER_SHA256_SEGMENT"
    }
  ],
  "image_sha256": "PLACEHOLDER_SHA256_SOURCE",
  "image_size_bytes": 0,
  "acquisition_tool": "placeholder-lab-tool",
  "acquisition_tool_version": "0.0-placeholder",
  "source_os": "Windows",
  "source_os_version": "Windows 11 lab",
  "creation_timestamp_utc": "2026-06-17T00:00:00Z",
  "timezone": "UTC",
  "corpus_tier": "T1",
  "license": "placeholder-lab-consent",
  "pii_status": "synthetic",
  "malware_status": "none",
  "retention_policy": "external-controlled-storage-only",
  "chain_of_custody": [
    {
      "created_by": "lab-operator-placeholder",
      "reviewed_by": [],
      "creation_method": "synthetic lab image",
      "storage_location": "external://controlled-lab-storage/e01-t1/",
      "hash_algorithm": "sha256",
      "hash_recorded_at": "2026-06-17T00:00:00Z",
      "review_status": "draft"
    }
  ],
  "trusted_tool_runs": [
    {
      "run_id": "TRUSTED-RUN-001",
      "tool_name": "ewfverify",
      "tool_version": "PLACEHOLDER_VERSION",
      "command": "ewfverify /evidence/corpus/T1/case.E01",
      "run_timestamp_utc": "2026-06-17T00:00:00Z",
      "host_os": "Windows 11 lab",
      "output_path": "external://controlled-lab-storage/e01-t1/trusted/ewfverify.txt",
      "output_sha256": "PLACEHOLDER_SHA256_OUTPUT",
      "notes": "placeholder only"
    }
  ],
  "expected_items": [
    {
      "item_id": "ALLOCATED-TXT-001",
      "original_path": "Users/alice/Documents/allocated.txt",
      "normalized_path": "Users/alice/Documents/allocated.txt",
      "expected_status": "allocated",
      "expected_recovery": "must_recover_byte_exact",
      "expected_recovery_mode": "filesystem",
      "file_type": "text",
      "size_bytes": 0,
      "sha256": "PLACEHOLDER_SHA256_FILE",
      "md5_optional": "PLACEHOLDER_MD5_FILE",
      "created_time_utc": "2026-06-17T00:00:00Z",
      "modified_time_utc": "2026-06-17T00:00:00Z",
      "accessed_time_utc": "2026-06-17T00:00:00Z",
      "deleted_time_utc_optional": null,
      "path_encoding": "utf-16le",
      "unicode_normalization": "NFC",
      "ads_name_optional": null,
      "is_sparse": false,
      "is_fragmented": false,
      "is_carved_only": false,
      "trusted_tool_run_ids": ["TRUSTED-RUN-001"],
      "expected_metadata": {
        "partition_start_sector": 2048,
        "record_number": "known-after-creation"
      },
      "accepted_variants": [],
      "expected_failure_reason": null,
      "notes": "placeholder only"
    }
  ],
  "expected_global_outcomes": {
    "min_recall": 0.99,
    "min_precision": 0.995,
    "max_false_positives": 0,
    "max_inconclusive": 0,
    "max_runtime_seconds": 600,
    "max_peak_memory_mb": 4096,
    "required_logs": ["run_log.txt", "tool_versions.json", "evidence_hashes.txt"],
    "required_reports": ["rapid_results.json", "trusted_results.json", "diff.json", "diff_summary.md"]
  },
  "notes": "placeholder only; no actual evidence path is provided by this example"
}
```

## Verification Rules

- `status=approved` requires at least one independent reviewer.
- Every complete recoverable file must include SHA256.
- Every source segment must include SHA256 and size.
- Every trusted tool run must expose a stable `run_id`.
- Every expected item must reference at least one trusted tool run through `trusted_tool_run_ids`.
- Every unsupported, unrecoverable, inconclusive, metadata-only, or partial expected item must include a non-null `expected_failure_reason`.
- Every release metric must be computed from item-level outcomes, not manually typed into the final report.
- Any schema deletion or field removal in future versions requires migration notes and fixture validation.
