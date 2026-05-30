# RapidForensic Recovery Engine PRD

Status: approved for engineering implementation
Date: 2026-05-31
Authority: `docs/plans/rapidforensic-recovery-review-plan-2026-05-30.md`

## Product Goal

Build a Windows/macOS-capable forensic recovery workflow that can ingest mounted evidence folders, raw images, and E01/Ex01-derived exports, then recover, index, review, and export existing and recovered files with measurable accuracy, resumability, provenance, multilingual filename safety, and report-defensible output packages.

## Users

| User | Need |
| --- | --- |
| Forensic operator | Recover useful evidence from Windows SSD/E01 cases without losing provenance or overstating recovery. |
| Analyst | Filter and review millions of files quickly by type, path, app location, confidence, and review state. |
| Reviewer | Validate recovered outputs against source hashes, offsets, filesystem records, and limitations. |
| Release owner | Prove pass/fail release gates with reproducible evidence. |

## MVP Scope

| Capability | Status target | Acceptance criteria |
| --- | --- | --- |
| Existing-file export | Implemented | Selected files, filtered result sets, and reviewed files export with safe paths, hashes, citations, duplicate handling, and manifest rows. |
| Recovery indexing | Implemented | Existing, deleted-entry, orphan-record, carved, partial, and corrupt candidates are queryable by kind, path, extension, size, confidence, and review state. |
| Checkpoint/resume | Implemented | Long-running run, E01 extraction, hashing, source search, and carving stages emit checkpoint/resume evidence; reruns never silently trust stale partial outputs. |
| NTFS recovery MVP | Partial implementation | MFT/USN inventory and resident/nonresident metadata are parsed as candidates; full deleted file claims require trusted-tool diff evidence. |
| Signature carving MVP | Implemented with limits | PDF, JPG, PNG, ZIP/OOXML, and SQLite carving runs bounded streaming scans with offsets, confidence, validation state, and resume metadata. |
| Viewer integration | Implemented/partial | Viewer separates existing, deleted, carved, partial, corrupt, reviewed, and report-selected records; source-read/search/export actions preserve citations. |
| Multilingual path safety | Implemented | Korean and Unicode filenames are preserved in manifests and sanitized only for unsafe export path components. |
| Reporting | Implemented/partial | Export/report packages include source citation, hashes, limitations, review state, and explicit blocker IDs. |

## Out of Scope for MVP Release Claims

- Universal recovery-rate claims.
- Report-defensible deleted SSD recovery without TRIM/acquisition evidence.
- Full NTFS nonresident file reconstruction across fragmented/overwritten runs without trusted-tool diff.
- Legal suitability claims without the Legal and Operator Review Gate.
- 10TB-class release claim without an attached completed corpus run.

## Candidate Classes

| Class | Meaning | Required provenance |
| --- | --- | --- |
| `existing` | Allocated/current file exported from mounted or extracted source | source path, source hash, export hash |
| `deleted-entry` | Filesystem metadata marks candidate deleted | filesystem record id, deletion state, source offset/record, confidence |
| `orphan-record` | Metadata record exists without reliable parent path | record id, available names/timestamps, limitation |
| `carved` | Signature-based byte recovery | source offset, signature type, boundary method, hash, validation state |
| `partial-corrupt` | Candidate is incomplete, overwritten, or structurally invalid | failure reason, readable bytes, limitation |

## Quantitative Targets

| Metric | MVP target |
| --- | --- |
| Existing-file export precision | 1.000 on complete allocated-file CI corpus |
| Existing-file export recall | 1.000 on complete allocated-file CI corpus |
| Recovery candidate precision | >= 0.995 on approved CI known-answer corpus |
| Recovery candidate recall | >= 0.990 on approved CI known-answer corpus |
| False positive rate | <= 0.005; 0 false positives in negative controls |
| Complete recovered-file hash match | 100% for candidates marked complete |
| Deterministic rerun equivalence | 100% normalized material equivalence |
| Memory | <= 4 GiB RSS for 100k-file and 1M-row MVP profiles |
| Metadata throughput | >= 5,000 rows/sec metadata-only profile |
| Sequential scan throughput | >= 20 MB/s on local SSD profile |
| UI p95 latency | <= 2.0s for search/filter/page load on 100k-row case |
| UI p99 latency | <= 5.0s for search/filter/page load on 100k-row case |

## Acceptance Criteria

| ID | Criterion |
| --- | --- |
| AC-01 | Export rejects source paths outside the analysis root and records the rejection. |
| AC-02 | Exported files preserve safe relative paths, deduplicate name collisions, and write SHA-256 hashes. |
| AC-03 | Recovery/index rows include candidate kind, source id, source path or record id, offsets when known, confidence, limitation, and validation status. |
| AC-04 | Interruption/resume leaves no duplicate completed outputs and no silently trusted partial output. |
| AC-05 | Carving emits offset, signature, boundary, validation status, output hash, and false-positive rejection rows. |
| AC-06 | NTFS candidates are clearly marked as candidate/partial until trusted-tool diff and known-answer evidence pass. |
| AC-07 | Korean and mixed Unicode filenames round-trip through scan, index, viewer, and export manifests. |
| AC-08 | Viewer supports fast review by extension, app path, user folder, category, candidate kind, confidence, and review state. |
| AC-09 | Every report/export item has source citation, hash, limitation, and review status. |
| AC-10 | Release scorecard is pass/fail and blocks release when any quantitative gate fails. |

## Approval

Engineering PRD approval: approved for implementation in the 2026-05-31 project completion pass.

Release approval: blocked until external validation, large-case survival evidence, Windows runtime evidence, operator review, forensic methodology review, and legal review are attached.
