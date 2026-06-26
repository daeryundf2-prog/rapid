# E01/Ex01 Known-Answer Corpus Plan

Status: designed only
Date: 2026-06-17
Applies to: E01/Ex01 source evidence, extracted files, recovery candidates, carving candidates, metadata index, viewer/export/report outputs

## Purpose

Define an independently reviewable known-answer corpus that can measure RapidForensic and RapidTriage E01/Ex01 recovery accuracy, reproducibility, resilience, and report-defensible evidence handling.

The corpus must prove what was recovered, what was not recoverable, what was incorrectly recovered, and what limitations must appear in reports.

This plan separates internal MVP confidence from production or release evidence. Internal fixtures can prove contracts and smoke behavior; production evidence requires approved corpus images, trusted/reference tool comparison, repeatable logs, and independent review.

## Scope

| Area | Scope decision |
| --- | --- |
| E01 | In scope for Tier 1 and later. |
| Ex01 | In scope for Tier 1 and later. |
| Multi-segment E01 | In scope for Tier 2 and Tier 3. |
| Filesystem priority | NTFS first. FAT32 and exFAT are follow-up tiers after NTFS evidence is stable. |
| Evidence folder / mounted input | Folder and mounted-source cases are Tier 0 baseline controls; they do not replace E01/Ex01 image validation. |
| macOS development | Suitable for docs, schema, parser smoke, and tool availability checks. |
| Windows validation | Required for Windows E01/Ex01 runtime, external tools, Unicode paths, and packaging evidence. |

## Non-Scope

- No real evidence images are stored in this repository.
- No external downloads are performed by this design.
- No proprietary vendor output is bundled.
- No release blocker is closed by documentation alone.
- No deleted SSD recovery claim is allowed without acquisition and TRIM evidence.
- No recovery engine, parser, API, UI, database, or test implementation is changed by this plan.
- No claim is made that RapidForensic replaces commercial forensic tools.
- No production release is approved by this document.
- No legal, operator, or methodology review is considered complete by this document.

## Corpus Tiers

| Tier | Name | Purpose | Storage rule | Release role |
| --- | --- | --- | --- | --- |
| Tier 0 | Synthetic folder baseline | Small folder truth set that can run quickly in CI. It is not E01/Ex01 and is only for parser/recovery smoke. | Git allowed when text-only fixtures are approved. | Internal smoke baseline only. |
| Tier 1 | Small E01/Ex01 known-answer images | Small NTFS E01 and Ex01 images with allocated files, deleted recoverable files, Unicode path, Korean filename, spaces, nested directories, simple timestamps, and hash-exact expectations. | External lab storage, hashes in manifest. | First executable release blocker reduction step. |
| Tier 2 | Realistic Windows NTFS cases | Windows-created NTFS evidence with deleted files, fragmented files, alternate data streams, long paths, Recycle Bin artifacts, user profiles, application artifacts, timezone and timestamp checks. | External lab storage. | Required for Windows report-defensible claim. |
| Tier 3 | Recovery edge cases | Partially overwritten files, zero-filled ranges, corrupted metadata, carved-only candidates, unsupported compression/encryption, expected failure, and expected inconclusive cases. | External lab storage. | Required for reliability and honest failure reporting. |
| Tier 4 | Scale and stress corpus | 100k files, 1M files or rows, multi-GB image, 10TB proxy or sparse simulation, runtime, memory, and throughput checks. | External generated corpus, not Git. | Required for large dataset survival claim. |
| Tier 5 | Independent review corpus | Independently reproducible sample, pinned toolchain versions, chain-of-custody metadata, and technical/methodology/operator/legal review linkage. | Controlled external evidence room. | Required before release claims beyond internal engineering. |

## Required Case Categories

| Category | Minimum contents |
| --- | --- |
| Allocated file recovery | Current files with known SHA256, size, path, timestamps, and source locator. |
| Deleted file recovery | Deleted resident and nonresident NTFS entries with expected recoverable state. |
| Unrecoverable deleted file | Deleted entries whose content is overwritten, trimmed, zero-filled, or intentionally unrecoverable. |
| Partially overwritten file | Files with partial readable ranges and required limitation text. |
| Carved JPEG | JPEG signature carving with expected offset, size, and hash when complete. |
| Carved PNG | PNG signature carving with expected offset, size, and hash when complete. |
| Carved PDF | PDF signature carving with expected offset, size, and hash when complete. |
| Carved ZIP | ZIP/OOXML signature carving with expected offset, size, and hash when complete. |
| Non-carvable random data | Random or adversarial bytes that must not be emitted as false positives. |
| Nested directory | Deep directory structures with stable source locators. |
| Korean filename | Korean filename preservation through scan, index, viewer, export, and report. |
| Unicode normalization | NFC/NFD variants and normalization rule checks. |
| Emoji filename | Emoji-named file handling where filesystem and export policy allow it. |
| Spaces in path | Paths with spaces and punctuation. |
| Very long path | Windows long path over 260 characters and nested app paths. |
| Alternate data stream | ADS presence, stream name, stream hash, and export/report limitations. |
| Sparse file | Sparse allocation metadata, logical size, physical ranges, and limitation text. |
| Zero-byte file | Zero-byte allocated and deleted files with metadata-only expectations. |
| Duplicate filename in different directories | Same basename under different parents. |
| Same content different paths | Duplicate content hash with distinct source paths. |
| Timestamp edge case | Boundary timestamps, missing timestamps, and filesystem timestamp source notes. |
| Timezone edge case | Source timezone, UTC normalization, and tolerance checks. |
| Multi-segment E01 | Segment inventory, ordering, hash, and continuity checks. |
| Corrupted E01 segment | Corrupt segment with expected warning, fail, or inconclusive status. |
| Missing segment | Missing middle or trailing segment with expected blocked status. |
| Unsupported encrypted evidence | BitLocker or encrypted container indicator with expected unsupported status and no recovery claim. |
| TRIM/SSD expected-non-recovery case | SSD case with TRIM state, acquisition method, known deleted files, and expected nonrecovery outcomes. |

## Pass/Fail Decision Model

| Status | Meaning | Release effect |
| --- | --- | --- |
| `PASS` | RapidForensic result matches expected answer and trusted/reference output within declared tolerance. | May support only the matching scoped claim. |
| `FAIL` | RapidForensic result differs materially from expected answer or trusted/reference output. | Blocks the matching scoped claim. |
| `WARN` | Non-critical mismatch or limitation is reported and reviewed. | Does not support stronger claims; may be acceptable with reviewer signoff. |
| `SKIP` | Case is intentionally not run in this environment. | Cannot support the scoped claim. |
| `INCONCLUSIVE` | Evidence or tool outputs do not support a defensible conclusion. | Blocks until resolved or excluded from claim scope. |
| `EXPECTED_UNSUPPORTED` | Feature is intentionally unsupported and reported as unsupported. | Does not block if the release claim excludes it. |
| `EXPECTED_UNRECOVERABLE` | Item is known not to be recoverable and must not be claimed recovered. | Passes only if RapidForensic avoids overstating recovery. |

## Pass Criteria

| Criterion | Required behavior |
| --- | --- |
| Byte-exact SHA256 match | Complete recovered files match expected SHA256 exactly. |
| Expected path match | Original path matches when the manifest requires exact path preservation. |
| Normalized path match | Normalized path matches when the manifest declares a Unicode/path normalization rule. |
| File size match | Complete recovered files match expected logical size. |
| Recovered content hash match | Recovered content hash matches expected MD5/SHA256 where declared. |
| Metadata match | Required metadata fields match expected values or accepted variants. |
| Timestamp tolerance | Timestamp differences stay inside manifest-defined tolerance. |
| False positive threshold | False positives stay under the declared maximum and negative controls remain clean. |
| No evidence mutation | Source image and segments are never modified. |
| No silent truncation | Partial or truncated output is explicitly reported. |
| No unreported error | Every tool or parser error is surfaced in logs and result status. |
| Reproducible run log | Rerun log is reproducible after approved dynamic fields are normalized. |
| Tool version captured | RapidForensic and reference tool versions are recorded. |
| Command line captured | RapidForensic and reference command lines or GUI workflow steps are recorded. |

## Required Metrics

| Metric | Required calculation |
| --- | --- |
| Recovery precision | `true_positive_count / (true_positive_count + false_positive_count)` |
| Recovery recall | `true_positive_count / (true_positive_count + false_negative_count)` |
| Byte-exact match rate | Complete byte-exact matches divided by expected complete recoveries. |
| Metadata match rate | Required metadata matches divided by required metadata comparisons. |
| False positive count | RapidForensic outputs not present in truth or accepted reference. |
| False-negative count | Expected recoverable items missing from RapidForensic output. |
| Expected unsupported count | Items intentionally outside current support scope. |
| Expected unrecoverable count | Items known to be unrecoverable and expected not to be recovered. |
| Complete file hash match | Count and percent of complete recoveries whose SHA256 matches expected SHA256. |
| Partial recovery correctness | Count and percent of partial candidates with correct source locator and limitation. |
| Deterministic rerun equivalence | Percent of normalized material fields equal across reruns. |
| Resume correctness | Interrupted run plus resumed run equals clean run after dynamic fields are removed. |
| Runtime | Wall-clock seconds per corpus run and per stage. |
| Peak RSS memory | Maximum resident memory observed during corpus execution. |
| Output bundle size | Total byte size of validation output package. |
| Error rate | Failed or errored stages divided by attempted stages. |
| Inconclusive rate | Inconclusive items divided by expected items. |
| Throughput | Bytes/sec for image scan and rows/sec for metadata/index stages. |
| UI/API latency | p95 and p99 latency for corpus-backed filter, page, export, and preview actions. |

## Initial Quantitative Release Targets

| Gate | Pass threshold |
| --- | --- |
| Allocated export precision | 1.000 |
| Allocated export recall | 1.000 |
| Recovery candidate precision | >= 0.995 |
| Recovery candidate recall | >= 0.990 |
| Negative-control false-positive rate | <= 0.005 and zero false positives in empty or random-byte controls |
| Complete recovered-file hash match | 1.000 for candidates marked complete |
| Deterministic rerun equivalence | 1.000 after approved dynamic fields are normalized |
| Resume equivalence | 1.000 against uninterrupted run after approved dynamic fields are normalized |
| 100k file and 1M row profile completion | 1.000 completion rate |
| Peak RSS memory | <= 4 GiB for T1 through T4 MVP profiles |
| Metadata throughput | >= 5,000 rows/sec on local SSD profile |
| Sequential scan throughput | >= 20 MB/sec on local SSD profile |
| Viewer/API p95 latency | <= 2.0 sec on 100k row case |
| Viewer/API p99 latency | <= 5.0 sec on 100k row case |

## Evidence Handling Rules

- Use synthetic, lab-created, or explicitly authorized evidence only.
- Prioritize a synthetic-only public corpus.
- Do not store E01/Ex01 binaries, recovered user files, PII, real user data, malware, contraband, or customer evidence in Git.
- Record license and consent for every corpus source.
- Store corpus binaries in controlled external storage with case ID, access log, retention rule, and SHA256 manifest.
- Record source creation method, acquisition method, tool versions, operator, timestamps, and environment.
- Record hash before and after transfer for the source image, each segment, each trusted export, each RapidForensic output, and each recovered complete file.
- Maintain chain-of-custody metadata for creation, transfer, review, execution, and retirement.
- Preserve read-only source handling and write all derived outputs to a separate analysis directory.
- Keep evidence input directories and output directories separate.
- Apply retention policy and access control to external evidence storage.
- Keep RapidForensic expected answers independent from RapidForensic generated output.
- Require reviewer signoff for expected-answer manifests and every manual classification.
- Redact or hash sensitive filenames in public summaries when necessary, while preserving full values in controlled evidence.
- Treat legal suitability as blocked until technical, forensic methodology, operator, and legal review are complete.

## Release Claim Policy

- Passing this corpus does not allow a claim that all E01 files or all deleted files are recoverable.
- Claims are allowed only for the image formats, filesystems, candidate classes, and edge cases covered by passing rows.
- Unsupported, expected unrecoverable, and inconclusive cases must remain visible in reports and release notes.
- Differences from trusted/reference tools require root-cause classification before claim promotion.
- Trusted tools are independent references, not absolute truth.
- Report-defensible claims require the corpus results plus technical, forensic methodology, operator, and legal review.

## Planned Execution Commands

These commands are current or repo-aligned execution surfaces. Paths are placeholders and must point to approved external corpus storage.

```bash
rapidtriage e01-known-answer /evidence/corpus/T1/case.E01 \
  --case-id E01-T1-ALLOCATED-DELETED \
  --expected-partition-start-sector 2048 \
  --expected-artifact "allocated file hashes match manifest" \
  --expected-artifact "deleted resident file candidate is recovered" \
  --output /validation/E01-T1/truth-draft.json \
  --json

rapidtriage e01-smoke /evidence/corpus/T1/case.E01 \
  --output-dir /validation/E01-T1/rapid \
  --case-id E01-T1-ALLOCATED-DELETED \
  --resume \
  --json

rapidtriage image-workflow-validate \
  --item-number 22 \
  --rapid-output /validation/E01-T1/rapid/run/rapidtriage-e01.json \
  --trusted-output /validation/E01-T1/trusted/e01-workflow.csv \
  --trusted-tool ewfverify \
  --output /validation/E01-T1/diff/e01-trusted-diff.json \
  --json

rapidtriage cross-tool-validate \
  --rapid-output /validation/E01-T1/rapid/recovery-results.json \
  --reference-output sleuthkit=/validation/E01-T1/trusted/sleuthkit-files.csv \
  --reference-output vendor-review=/validation/E01-T1/trusted/vendor-review.csv \
  --min-overlap 0.99 \
  --backlog-item 22 \
  --json

rapidtriage known-answer-qc \
  --manifest /validation/E01-T1/truth-manifest.json \
  --trusted-manifest /validation/E01-T1/trusted/truth-manifest-reviewed.json \
  --output-dir /validation/E01-T1/qc \
  --overwrite \
  --json
```

## Release Blocker Mapping

| Existing blocker | Corpus evidence needed to reduce blocker |
| --- | --- |
| Real E01/Ex01 recovery validation missing | T1 plus T2 pass with E01 and Ex01 images, tool logs, trusted diffs, and reviewer signoff. |
| Deleted SSD recovery truth missing | T3 SSD/TRIM case with acquisition note, known deleted files, expected nonrecovery cases, and trusted diff. |
| Large-case survival missing | T4 pass for 100k files, 1M metadata rows, interruption/resume, and approved 10TB-class proxy or real run. |
| Windows packaging/runtime missing | T2 and T4 runs on Windows 10/11 with Korean path and external tool discovery evidence. |
| Legal/operator review missing | T5 review package with technical, forensic methodology, operator, and legal signoff. |

## Completion Rule

This corpus is not release evidence until every required case has:

1. Approved manifest.
2. Source and segment hashes.
3. RapidForensic output hashes.
4. Trusted tool or independent reference output.
5. Pass/fail metrics.
6. Reviewer signoff.
7. Release checklist link.
