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
| #81 Known-answer tests | Validation output records manifest ingestion, dataset counts, expected assertions, evidence-path checks, evidence file SHA256 values, dataset hashes, `known_answer_validation.manifest_digest`, `known-answer-report-grade-validation-plan-v1` ready/blocking slots, public-corpus guidance, release gate, trusted manifest diff helpers/gates, and #81 `core_accuracy_gates`. | Real CFReDS/CFTT corpus runs, trusted known-answer manifests, parser-scope coverage maps, chain-of-custody rows, independent expected-answer review, and release signoff for each report-grade parser claim. |
| #82 Fixture corpus | Validation output inventories parser areas, fixture/test counts, fixture/test file SHA256 values, area manifest hashes, `fixture_corpus_digest`, `fixture-corpus-report-grade-validation-plan-v1` ready/blocking slots, edge cases, coverage status, release gate, trusted fixture-manifest diff helpers/gates, and #82 `core_accuracy_gates`. | Broader malformed/deleted/native/versioned fixture corpora, parser-version compatibility matrix, trusted fixture corpus manifests, release-blocking fixture policy, coverage threshold signoff, and broad platform fixture corpus. |
| #83 FP/FN docs | Parser-family notes record false-positive risks, false-negative risks, validation-required guidance, scope, `risk_note_hash`, minimum quantification fields, reportability boundaries, `parser-fp-fn-risk-register-v1` digest, trusted FP/FN register diff helpers/gates, and #83 `core_accuracy_gates`. | Quantified FP/FN rates by corpus/parser version and a reviewed risk register. |
| #84 Independent validation | Validation output records independent report status, required signoffs, signoff slots, minimum sections, minimum-section presence checks, optional hash/size, `independent-validation-report-manifest-v1` with report manifest hash, trusted signoff diff helpers/gates, and #84 `core_accuracy_gates`. | Actual third-party signed review for the target release and trusted signoff manifest. |
| #85 Validation package | Validation package and artifact manifest record JSON/Markdown/hash outputs, `validation-package-manifest-v1`, artifact hash rows, `package_manifest_hash`, reproduction commands, validation sections, limitations, trusted package-manifest diff helpers/gates, and #85 `core_accuracy_gates`. | Operator-attached test logs, release evidence, independent review, and trusted validation package manifest. |
| #86 Chain of custody | Case DB report exports evidence-source inventory, custody events, citation IDs, status/hash fields, custody row hashes, `custody-event-manifest-v1`, custody manifest hash, limitations, trusted custody-manifest diff helpers/gates, and #86 `core_accuracy_gates`. | Signed handoff forms, acquisition-device metadata, lab custody policy, and trusted custody event manifests. |
| #87 Acquisition hashes | Case DB report exports evidence-source hashes, hash records, algorithms, timestamps, per-row acquisition hash digests, `acquisition-hash-manifest-v1` manifest hashes, algorithm coverage, missing-hash warnings, trusted hash-manifest diff helpers/gates, and #87 `core_accuracy_gates`. | Whole-device acquisition hash workflow, write-blocker/operator metadata, and trusted acquisition hash manifests. |
| #88 Immutable audit | Case DB report exports audit events, previous/event hashes, actor/action/target/time fields, head hash, `audit-hash-chain-manifest-v1` manifest hash, trusted hash-chain diff helpers/gates, and #88 `core_accuracy_gates`. | Database-level append-only enforcement, trusted audit chain manifests, and external notarization/signing. |
| #89 Reproducibility | Report exports stable payload SHA256, deterministic sorting, item/citation counts, item/citation row digests, `report-replay-manifest-v1` manifest hash, volatile-field disclosure, trusted replay diff helpers/gates, and #89 `core_accuracy_gates`. | Cross-platform same-input byte-level replay tests and trusted report replay manifests. |
| #90 Provenance | Report items preserve source path, hashes, parser/version/confidence, offsets/source index when available, review/reportability fields, provenance row hashes, `report-provenance-row-manifest-v1` manifest hashes, trusted provenance diff helpers/gates, and #90 `core_accuracy_gates`. | Completeness validation across every parser, trusted provenance manifests, and final report template review. |

## Interpretation

Passing this manifest promotes #81 through #90 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until public corpus, trusted manifests, independent validation, external signing, acquisition metadata, and court/lab process evidence are attached.
