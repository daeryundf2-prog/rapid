# RapidTriage #81-#90 Internal Validation

This package records internal fixture evidence for known-answer validation, parser fixture/FP-FN documentation, independent validation report intake, validation package automation, chain of custody, acquisition hashes, immutable audit, report reproducibility, and source provenance items #81 through #90.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-081-090 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-081-090-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-081-090/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-081-090 \
  --json
```

## Internal Fixture Scope

| Item | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #81 Known-answer tests | Validation output records manifest ingestion, dataset counts, evidence-path checks, public-corpus guidance, release gate, and #81 `core_accuracy_gates`. | Real CFReDS/CFTT corpus runs for each report-grade parser claim. |
| #82 Fixture corpus | Validation output inventories parser areas, fixture/test counts, edge cases, coverage status, release gate, and #82 `core_accuracy_gates`. | Broader malformed/deleted/native fixture corpora and release-blocking coverage policy. |
| #83 FP/FN docs | Parser-family notes record false-positive risks, false-negative risks, validation-required guidance, scope, and #83 `core_accuracy_gates`. | Quantified FP/FN rates by corpus and parser version. |
| #84 Independent validation | Validation output records independent report status, required signoffs, minimum sections, optional hash/size, and #84 `core_accuracy_gates`. | Actual third-party signed review for the target release. |
| #85 Validation package | Validation package and artifact manifest record JSON/Markdown/hash outputs, validation sections, limitations, and #85 `core_accuracy_gates`. | Operator-attached test logs and independent release evidence. |
| #86 Chain of custody | Case DB report exports evidence-source inventory, custody events, citation IDs, status/hash fields, limitations, and #86 `core_accuracy_gates`. | Signed handoff forms, acquisition-device metadata, and lab custody policy. |
| #87 Acquisition hashes | Case DB report exports evidence-source hashes, hash records, algorithms, timestamps, missing-hash warnings, and #87 `core_accuracy_gates`. | Whole-device acquisition hash workflow and write-blocker/operator metadata. |
| #88 Immutable audit | Case DB report exports audit events, previous/event hashes, actor/action/target/time fields, head hash, and #88 `core_accuracy_gates`. | Database-level append-only enforcement and external notarization/signing. |
| #89 Reproducibility | Report exports stable payload SHA256, deterministic sorting, item/citation counts, volatile-field disclosure, and #89 `core_accuracy_gates`. | Cross-platform same-input byte-level replay tests. |
| #90 Provenance | Report items preserve source path, hashes, parser/version/confidence, offsets/source index when available, review/reportability fields, and #90 `core_accuracy_gates`. | Completeness validation across every parser and final report template. |

## Interpretation

Passing this manifest promotes #81 through #90 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until public corpus, independent validation, external signing, acquisition metadata, and court/lab process evidence are attached.
