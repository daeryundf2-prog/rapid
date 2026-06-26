# T1 Minimal E01/Ex01 Corpus Procedure

Status: designed only
Date: 2026-06-17
Scope: Future external T1 E01/Ex01 known-answer execution

This procedure defines how to create and validate minimal E01/Ex01 known-answer corpora outside Git. It has not been executed in this repository.

## Purpose

Create one minimal Windows-generated NTFS E01 corpus and, where tooling is available, one matching Ex01 corpus. The goal is to produce report-defensible engineering evidence for recovery behavior, path handling, hashes, and independent reference comparison.

## Scope

- Synthetic source tree only.
- No customer data.
- No PII.
- No malware.
- No raw evidence binary committed to Git.
- External storage path controlled by the operator.

## Non-Scope

- Large scale performance evidence.
- SSD/TRIM truth-set validation.
- Legal approval.
- Operator training signoff.
- Vendor endorsement.

## External Storage Layout

```text
external-evidence-root/
  source-tree/
  images/
    e01/
    ex01/
  manifests/
  trusted-exports/
  rapid-results/
  diffs/
  logs/
  hashes/
  reviews/
```

## Synthetic Source Tree Recipe

Create a deterministic source tree on the Windows host:

```text
source-tree/
  hello.txt
  same-content-a.txt
  same-content-b.txt
  unicode/
    한글파일.txt
  spaces/
    file with spaces.txt
  nested/
    level1/
      level2/
        nested-example.txt
  duplicates/
    a/
      duplicate.txt
    b/
      duplicate.txt
  zero-byte/
    empty.txt
```

Record SHA-256 and size for every file before imaging.

## Windows NTFS Generation Path

1. Prepare a clean Windows test host or VM.
2. Confirm long-path support policy and filesystem type.
3. Create an NTFS volume or VHDX for the synthetic tree.
4. Copy the synthetic tree onto the NTFS volume.
5. Create any planned deleted-file cases and record the operation log.
6. Shut down writes before acquisition.
7. Record host OS, timezone, filesystem, and volume metadata.

## Non-Windows Exploratory Path Limit

macOS/Linux folder fixtures are allowed for plumbing checks only. They cannot prove Windows NTFS semantics, deleted-file behavior, E01 acquisition correctness, Ex01 encryption/container behavior, or trusted tool parity.

## E01 Acquisition Procedure

1. Use an approved acquisition tool on the Windows-generated NTFS source.
2. Store E01 segments outside Git.
3. Record tool name, version, command/options, host OS, run timestamp, and operator.
4. Compute SHA-256 for every segment.
5. Populate a truth manifest using `truth-manifest-schema-v1.schema.json`.
6. Run `scripts/known-answer-qc.py` against the manifest.

## Ex01 Acquisition Procedure

1. Use an approved Ex01-capable acquisition workflow.
2. Store Ex01 segments outside Git.
3. Record encryption/compression settings if used.
4. Record tool name, version, command/options, host OS, run timestamp, and operator.
5. Compute SHA-256 for every segment.
6. Populate a truth manifest using `truth-manifest-schema-v1.schema.json`.
7. Run `scripts/known-answer-qc.py` against the manifest.

## Trusted Tool Export

1. Export independent reference results with approved trusted/reference tools.
2. Do not treat a vendor tool as absolute truth by itself.
3. Normalize exports with `scripts/normalize-trusted-export.py`.
4. Store raw restricted exports outside public Git when license terms require it.
5. Store normalized comparison JSON in the evidence bundle when policy allows.

## RapidForensic Run

1. Run RapidForensic against the external E01/Ex01 image.
2. Export normalized observed results.
3. Capture logs, tool versions, host details, and exit code.
4. Do not edit observed results except through documented normalization.

## Pass/Fail Status

| Gate | PASS | FAIL |
| --- | --- | --- |
| Manifest QC | Schema-valid and file/hash metadata complete. | Invalid schema or missing required metadata. |
| Trusted normalization | Output validates against observed results schema. | Invalid output or unsupported export without approved exception. |
| Trusted diff | No critical mismatches beyond approved expected limitations. | Critical mismatch without approved explanation. |
| Bundle | No release-blocking policy issue. | Forbidden file, missing required artifact, or review gap. |

## State Transitions

`designed -> implemented -> executed -> reviewed -> approved`

This repository is currently at `designed` for real T1 E01/Ex01 execution. Tier 0 synthetic folder checks are implemented and executed only as engineering plumbing.

## Procedure Status

This procedure is documented only. It is not executed until the external Windows host, approved evidence storage, trusted tool exports, and review records exist.
