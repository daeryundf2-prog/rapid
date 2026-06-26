# Trusted Tool Diff Protocol

Status: designed only
Date: 2026-06-17
Applies to: E01/Ex01 source validation, extracted filesystem listings, recovered file outputs, metadata rows, and report/export claims

## Purpose

The trusted-tool diff protocol prevents RapidForensic from validating itself. Every report-defensible recovery claim must compare RapidForensic output with independently produced expected answers or trusted tool exports.

Trusted/reference tools are independent references, not absolute truth. A mismatch requires triage before either RapidForensic or the reference output is treated as wrong.

## Trusted/Reference Tool Principles

| Required evidence | Rule |
| --- | --- |
| Tool name | Record exact tool or workflow name. |
| Version | Record exact version, build, or release date. |
| Command | Preserve command line or GUI workflow steps. |
| Host OS | Record OS, version, architecture, and environment notes. |
| Acquisition/mount mode | Record read-only mode, mount method, filesystem exposure, and write-blocking state. |
| Output hash | Hash every normalized reference output. |
| Logs | Preserve stdout, stderr, GUI export log, and reviewer notes where available. |
| Limitations | Record licensing, redistribution, parsing, filesystem, and operator limitations. |

## Accepted Reference Sources

| Reference | Use | Minimum requirement |
| --- | --- | --- |
| `ewfverify` | EWF integrity and checksum validation. | Command transcript, tool version, source hash, pass/fail result. |
| `ewfinfo` | Segment and acquisition metadata. | Normalized metadata export and segment list. |
| `ewfmount` or equivalent libewf mount | Read-only raw exposure. | Mount transcript, exposed raw hash where feasible, FUSE/platform notes. |
| `mmls` | Partition table and start-sector expectations. | Partition rows with sector size and selected start sector. |
| `fls` | Filesystem listing and deleted-entry visibility. | Recursive allocated/deleted listing with metadata flags. |
| `icat` / `istat` | File content and record metadata spot checks. | Record IDs, hashes, timestamps, and content extraction logs. |
| `tsk_recover` | File recovery baseline. | Recovered path list, hashes, error log, and skipped item list. |
| Windows GUI forensic tool | Separate manual review workflow when command-line normalized export is not available. | Tool name, version, operator, export settings, normalized CSV/JSON output, and review notes. |
| Commercial forensic tool export | Independent GUI or commercial workflow comparison. | License, redistribution restriction, tool version, export settings, output hash, and review notes. |
| Manual reviewer manifest | Expected answer review independent from RapidForensic output. | Reviewer identity, method, item IDs, decision, and signoff hash. |

Vendor tool usage must respect licensing and must not place proprietary outputs in Git unless policy explicitly allows sanitized metadata.

## Diff Units

| Unit | Required keys | Required compared fields |
| --- | --- | --- |
| Source image | `case_id`, `source_format` | source SHA256, segment count, segment hashes, ewfverify status. |
| Partition | `case_id`, `partition_index` | start sector, sector size, filesystem type, partition label. |
| File listing | `case_id`, `path_or_record_id` | allocation state, logical path, record ID, size, timestamps, ADS name. |
| Complete recovered file | `case_id`, `item_id` | output SHA256, size, source locator, candidate kind, status. |
| Partial candidate | `case_id`, `item_id` | source locator, readable byte count, limitation IDs, confidence class. |
| Carved candidate | `case_id`, `offset`, `signature` | offset, length, file type, boundary method, SHA256 when complete. |
| Negative control | `case_id`, `item_id` | must-not-recover status, false positive flag, limitation or rejection reason. |
| Report/export row | `case_id`, `item_id` | citation, source hash, output hash, review state, validation status. |

## Normalization Rules

- Normalize path separators to `/` for comparison.
- Preserve original path in an unmodified field.
- Normalize Unicode according to the case manifest rule: exact, NFC, or NFD.
- Compare timestamps in UTC with the manifest-defined tolerance.
- Remove dynamic fields before deterministic rerun comparison, including wall-clock run time, absolute temp paths, process IDs, and unordered JSON object key order.
- Sort unordered result sets by stable keys before hashing.

## Diff Categories

| Category | Meaning | Release effect |
| --- | --- | --- |
| `MATCH` | RapidForensic and reference agree. | Supports the scoped claim. |
| `RAPID_ONLY` | RapidForensic emitted an item not present in truth or reference. | Possible false positive; blocks if not justified. |
| `TRUSTED_ONLY` | Reference has an expected item RapidForensic missed. | Possible false negative; blocks if item is in scope. |
| `HASH_MISMATCH` | Complete file hash differs. | Blocks complete recovery claim. |
| `PATH_MISMATCH` | Original or normalized path differs. | Blocks path/provenance claim unless accepted variant applies. |
| `METADATA_MISMATCH` | Required metadata differs. | Blocks until explained or fixed. |
| `TIMESTAMP_TOLERANCE` | Timestamp differs but remains inside declared tolerance. | Warn or pass according to manifest rule. |
| `EXPECTED_UNSUPPORTED` | Manifest says the feature is unsupported and RapidForensic reports unsupported. | Does not support stronger claim. |
| `EXPECTED_UNRECOVERABLE` | Manifest says content must not be recovered and RapidForensic does not recover it. | Supports honest nonrecovery handling. |
| `INCONCLUSIVE` | Evidence does not support a defensible conclusion. | Blocks until reviewed or excluded from claim scope. |
| `TOOL_LIMITATION` | Reference tool has a documented limitation or export gap. | Requires reviewer classification. |
| `MANIFEST_ERROR` | Truth manifest is missing, inconsistent, or wrong. | Blocks until manifest is corrected and reviewed. |

## Triage Workflow

1. Run automated diff.
2. Sample mismatched artifacts.
3. Perform manual review for sampled and critical mismatches.
4. Classify root cause.
5. Correct the manifest if the truth set is wrong.
6. File a RapidForensic bug if RapidForensic output is wrong.
7. Record a trusted tool limitation if the reference misses an item.
8. Mark inconclusive if no defensible conclusion exists.

## Output Format

| File | Purpose |
| --- | --- |
| `rapid_results.json` | Normalized RapidForensic result rows. |
| `trusted_results.json` | Normalized trusted/reference result rows. |
| `diff.json` | Machine-readable diff rows and categories. |
| `diff_summary.md` | Reviewer-readable summary, counts, blockers, and signoff state. |
| `run_log.txt` | RapidForensic, reference tool, and normalization run log. |
| `tool_versions.json` | RapidForensic and trusted/reference tool versions. |
| `evidence_hashes.txt` | Source, segment, result, and report hashes. |

## Workflow

1. Hash the source image and segments.
2. Run `ewfverify` and preserve transcript.
3. Run `ewfinfo` and preserve normalized metadata.
4. Mount or expose the image read-only using libewf or a controlled vendor workflow.
5. Run `mmls` and confirm expected partition start sector.
6. Run `fls`, `istat`, `icat`, and `tsk_recover` as appropriate for filesystem expectations.
7. Run RapidForensic with read-only source handling and external output directory.
8. Normalize RapidForensic and reference outputs.
9. Run `rapidtriage image-workflow-validate` for source, segment, partition, and extraction workflow comparison.
10. Run `rapidtriage cross-tool-validate` for row-level recovery and metadata comparison.
11. Run `rapidtriage known-answer-qc` for manifest and reviewed expected-answer checks.
12. Attach technical, forensic methodology, operator, and legal review records before release claims.

## Required Output Package

| Output | Required |
| --- | --- |
| Source hash report | yes |
| Segment hash report | yes |
| ewfverify transcript | yes |
| ewfinfo metadata export | yes |
| Partition table export | yes |
| Trusted file listing export | yes |
| Trusted recovered file hash list | yes |
| RapidForensic run output | yes |
| RapidForensic report/export package | yes |
| image-workflow-validate JSON | yes |
| cross-tool-validate JSON | yes |
| known-answer-qc JSON and Markdown | yes |
| Reviewer signoff records | yes |

## Pass/Fail Rule

A case passes only when:

1. Source and segment hashes match manifest values.
2. Trusted tool outputs are approved and hashed.
3. RapidForensic output satisfies every case threshold.
4. No unreviewed `rapid-extra`, `rapid-missing`, `hash-mismatch`, `locator-mismatch`, or `status-mismatch` rows remain.
5. Report/export rows contain citation, source hash, output hash when materialized, limitation, validation status, and review state.

Any missing required output is `blocked`, not `pass`.

## Future Command Candidates

These commands are design candidates only; this document does not implement them.

```bash
rapidtriage validate-known-answer \
  --manifest path/to/manifest.json \
  --evidence path/to/image.E01 \
  --trusted-results path/to/trusted_results.json \
  --out path/to/validation-output \
  --strict

rapidtriage trusted-diff \
  --rapid-results rapid_results.json \
  --trusted-results trusted_results.json \
  --manifest manifest.json \
  --out diff.json
```
