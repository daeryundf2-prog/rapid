# E01/Ex01 Known-Answer Corpus Design

Status: designed only
Date: 2026-06-17
Scope: E01/Ex01 recovery validation design for future external evidence runs

This directory defines the known-answer corpus needed before RapidForensic can make report-defensible E01/Ex01 recovery claims.

It does not contain evidence images, recovered files, external tool exports, or executed validation results. Those artifacts must stay outside Git unless a future policy explicitly approves a tiny synthetic text fixture.

## Documents

| Document | Purpose |
| --- | --- |
| `e01-ex01-known-answer-corpus.md` | Corpus tiers, required cases, pass/fail status model, metrics, and evidence handling policy. |
| `truth-manifest-schema-v1.md` | Versioned schema for expected answers, evidence provenance, hashes, tool runs, and measurable outcomes. |
| [truth-manifest-schema-v1.schema.json](truth-manifest-schema-v1.schema.json) | Machine-readable JSON Schema for the designed truth manifest contract. |
| [validation-result-schema-v1.schema.json](validation-result-schema-v1.schema.json) | Machine-readable JSON Schema for `known-answer-qc --json` PASS, FAIL, and ERROR output. |
| [observed-results-schema-v1.schema.json](observed-results-schema-v1.schema.json) | Normalized comparison input schema for RapidForensic, trusted/reference tools, manual review, or synthetic fixtures. |
| [trusted-diff-result-schema-v1.schema.json](trusted-diff-result-schema-v1.schema.json) | Machine-readable schema for `trusted-diff` PASS, FAIL, and ERROR output. |
| `trusted-tool-diff-protocol.md` | Protocol for comparing RapidForensic results with libewf, Sleuth Kit, and vendor or manual review exports. |
| `validation-matrix.md` | Pass/fail execution matrix for E01, Ex01, recovery, corruption, Unicode, SSD/TRIM, and scale cases. |
| `t1-minimal-e01-ex01-corpus-procedure.md` | External T1 E01/Ex01 execution procedure; documented only, not executed. |
| `templates/` | Schema-valid T1 manifest examples with dummy hashes; not release evidence. |

## Current Evidence Boundary

- Existing internal fixture evidence: `docs/validation/rapidtriage-core-forensics-021-025-known-answer.json`
- Existing hard blocker: `docs/validation/release-hard-blockers-2026-05-31.md`
- Existing design authority: `docs/plans/rapidforensic-recovery-engine-prd.md`
- Existing test authority: `docs/plans/rapidforensic-recovery-engine-test-spec.md`
- This directory adds corpus design only.

The internal `core-forensics-022-e01-fixture` dataset is useful for smoke and contract checks, but it is not a replacement for real or approved lab E01/Ex01 known-answer evidence.

## Manifest Validator Usage

Validate the Tier 0 synthetic folder manifest against the v1 truth-manifest JSON Schema:

```bash
python scripts/known-answer-qc.py \
  --manifest tests/fixtures/known_answer/tier0-basic/manifest.json
```

Validate the older minimal manifest fixture against the same schema:

```bash
python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/valid-t1-minimal-manifest.json
```

Emit machine-readable output for CI or release evidence bundles:

```bash
python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/valid-t1-minimal-manifest.json --json
```

Use an explicit schema path when validating a migrated or staged schema:

```bash
python scripts/known-answer-qc.py \
  --manifest tests/fixtures/known_answer/valid-t1-minimal-manifest.json \
  --schema docs/validation/known-answer-corpus/truth-manifest-schema-v1.schema.json
```

By default, this validator checks manifest structure only. It does not read E01/Ex01 images, run recovery tools, or validate trusted-tool outputs.

Run the Tier 0 synthetic folder plumbing check with fixture file size and SHA-256 comparison:

```bash
python scripts/known-answer-qc.py \
  --manifest tests/fixtures/known_answer/tier0-basic/manifest.json \
  --check-files \
  --fixture-root tests/fixtures/known_answer/tier0-basic/files
```

Emit the same Tier 0 file-check result as schema-validated JSON:

```bash
python scripts/known-answer-qc.py \
  --manifest tests/fixtures/known_answer/tier0-basic/manifest.json \
  --check-files \
  --fixture-root tests/fixtures/known_answer/tier0-basic/files \
  --json
```

This Tier 0 command only reads tiny repository text fixtures under `tests/fixtures/known_answer/tier0-basic/files`. It is not E01/Ex01 release evidence and does not exercise recovery, parsing, trusted-tool comparison, or customer data handling.

The `--json` output is a pure JSON object and must validate against `validation-result-schema-v1.schema.json`. The result status is one of `PASS`, `FAIL`, or `ERROR`, and Tier 0 fixture runs set `release_evidence_status` to `engineering_check_only`.

## Trusted Diff Usage

Compare normalized synthetic RapidForensic and trusted/reference outputs:

```bash
python scripts/trusted-diff.py \
  --manifest tests/fixtures/known_answer/tier0-basic/manifest.json \
  --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json \
  --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json \
  --json
```

Write release-bundle candidate artifacts:

```bash
python scripts/trusted-diff.py \
  --manifest tests/fixtures/known_answer/tier0-basic/manifest.json \
  --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json \
  --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json \
  --out /tmp/tier0-trusted-diff.json \
  --summary /tmp/tier0-trusted-diff-summary.md
```

This comparator treats trusted/reference output as an independent reference, not absolute truth. It does not execute trusted tools and does not open E01/Ex01 images.

## Trusted Export Normalizer Usage

Convert the deterministic Tier 0 TSV fixture to normalized observed results:

```bash
python scripts/normalize-trusted-export.py \
  --tool synthetic-tsv \
  --input tests/fixtures/known_answer/tier0-basic/synthetic-trusted-export.tsv \
  --json
```

The non-synthetic tool modes are placeholders until real export formats are approved and tested outside Git.

## Release Evidence Bundle Usage

Build an engineering-only bundle manifest over small synthetic artifacts:

```bash
python scripts/build-evidence-bundle.py \
  --root tests/fixtures/known_answer/tier0-basic \
  --json
```

The bundle generator flags forbidden image-like extensions and large files. A passing Tier 0 bundle manifest is not release approval.

## Release State Labels

| Label | Meaning |
| --- | --- |
| Designed | Documentation defines what evidence is required. |
| Implemented | Code and scripts can generate, validate, and diff the manifest and result files. |
| Executed | Approved corpora were run and output artifacts were produced. |
| Reviewed | Technical, forensic methodology, operator, and legal review records are attached. |

This directory currently satisfies `Designed` for external T1 E01/Ex01 execution and `Implemented` for in-repo Tier 0 synthetic validation plumbing.

## Release Checklist Connection

`docs/rapidtriage-release-checklist.md` links to this directory as the E01/Ex01 known-answer corpus design authority. That checklist link is not execution evidence. Release evidence still requires implemented validation commands, executed corpus runs, trusted/reference diffs, and independent review records.

## Next Implementation Path

1. Create one minimal synthetic E01 and one minimal synthetic Ex01 lab image outside Git.
2. Populate a `truth-manifest-schema-v1` JSON manifest for each image.
3. Run `python scripts/known-answer-qc.py --manifest <manifest.json>` before executing tool comparisons.
4. Run `rapidtriage e01-smoke` and `rapidtriage e01-hash` against each image.
5. Export trusted reference rows using libewf, Sleuth Kit, and at least one independent reviewer or vendor workflow.
6. Run `rapidtriage image-workflow-validate`, `rapidtriage cross-tool-validate`, and `rapidtriage known-answer-qc`.
7. Attach pass/fail outputs and review signoffs before changing any release blocker status.
