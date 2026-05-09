# RapidTriage #61-#70 Internal Validation

This package records internal fixture evidence for advanced search, keyword packs, IOC/TI enrichment, report citation/version history, benchmarking, stress planning, incremental indexing, job queues, and checkpoint/resume items #61 through #70.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-061-070 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-061-070-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-061-070/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-061-070 \
  --json
```

## Internal Fixture Scope

| Item | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #61 Advanced search | Search output records query mode/options, fuzzy/stem/regex behavior, proximity metadata, hit pointers, `advanced_search_profile`, regex query validation, web mode/fuzzy/proximity controls, trusted query-hit diff helper/gate, and #61 `core_accuracy_gates`. | Large multilingual relevance corpus, trusted query-hit manifest, tuned false-positive/false-negative measurements, and full browser query-builder validation. |
| #62 Keyword packs | Built-in packs and JSON custom-pack support preserve keyword counts, provenance, deduplication, per-pack/library/selection manifests, keyword row hashes, expansion head hashes, manifest hashes, API search `keyword_pack_selection_profile`, web pack-selection controls, trusted expansion diff helper/gate, and #62 `core_accuracy_gates`. | Per-case pack editor, signed pack library, trusted expansion manifest corpus, language/domain-specific packs, and release-reviewed pack versions. |
| #63 IOC/TI enrichment | Indicator summaries and the API/web local enrichment review package preserve source links, local rule hits, offline feed provenance with feed hash/size, match mode, no-external-call warning, trusted enrichment diff helper/gate, and #63 `core_accuracy_gates`. | Signed/STIX/TAXII feeds, trusted enrichment manifest, confidence decay, feed trust workflow, and external enrichment governance. |
| #64 Citation manager | Case DB report exports preserve review/source citation IDs, copy-safe citation strings, source references, source-hash/parser-version coverage profile, citation counts, report-use warnings, trusted citation-index diff helper/gate, and #64 `core_accuracy_gates`. | Exhibit numbering UI, trusted citation manifest, jurisdiction templates, and source-hash completeness validation across every parser. |
| #65 Evidence history | Review history preserves version rows, changed fields, previous/current state, report inclusion changes, per-row hashes, export-time history hash chain/head hash, trusted history diff helper/gate, and #65 `core_accuracy_gates`. | Multi-user signed history, trusted history manifest, conflict handling, database-level append-only enforcement. |
| #66 Benchmark | Benchmark outputs preserve scale matrix, ingest/search metrics, latency samples, environment profile, release-threshold guardrail profile, memory/output size, run-summary link, trusted threshold diff helper/gate, #66 `core_accuracy_gates`, and #66 `commercial_uplift_evidence` with large-data controls. | Published 100k/1M/10M hardware matrix, trusted threshold manifest, and release-approved thresholds. |
| #67 Stress plan | Stress-plan outputs preserve TB scenarios, resource caps, failure thresholds, evidence bundle requirements, per-scenario run-log templates, telemetry/evidence capture profile, trusted run-log diff helper/gate, #67 `core_accuracy_gates`, and #67 `commercial_uplift_evidence` on plan/scenario payloads. | Actual 1TB-10TB hardware runs, trusted run-log manifest, bottleneck logs, and independent reproduction. |
| #68 Incremental indexing | Run fingerprints preserve path/size/mtime metadata, bounded per-file SHA-256 hashes, truncation/reuse warnings, changed-source handling, an incremental reuse plan, trusted reuse diff helper/gate, #68 `core_accuracy_gates`, and #68 `commercial_uplift_evidence`. | Full large-file content-hash delta reindexing, trusted reuse manifests, and large-case validation. |
| #69 Background jobs | Job payloads preserve status, step progress, persisted-state assessment, append-intent transition logs, transition head hashes, cancellation/retry state, local-threadpool warning, trusted transition-log diff helper/gate, #69 `core_accuracy_gates`, and #69 `commercial_uplift_evidence` on queue/step payloads. | Distributed workers, externally trusted transition logs, parser-level progress percentages, and cooperative cancellation validation under load. |
| #70 Checkpoint/resume | Run checkpoints preserve stage outputs, sizes, reused flags, row hashes, checkpoint integrity head hashes, resume state, partial-stage warnings, trusted checkpoint diff helper/gate, #70 `core_accuracy_gates`, and #70 `commercial_uplift_evidence` on summary/stage records. | Mid-parser checkpointing, trusted checkpoint/resume manifest, failed-stage resume, and long-running case replay validation. |

The #61 through #65 rows now include reportability decisions and trusted diff helper/gates. Advanced search is limited to `advanced-search-triage-pivot`; keyword packs to `keyword-pack-expansion-triage-pivot`; IOC/TI enrichment to `offline-ioc-ti-triage-pivot`; citation exports to `report-citation-index-triage-pivot`; and evidence-selection history to `evidence-selection-history-triage-pivot`. These are not source-proof, release-reviewed pack, live TI verdict, court exhibit, or multi-user signed-history claims until the missing corpus, trusted manifests, signing, feed provenance, source-hash, reviewer, and append-only evidence is attached.

The #66 through #70 rows also emit reportability decisions and trusted diff helper/gates. Benchmarks are limited to `benchmark-run-and-scale-plan-triage-pivot`, stress plans to `stress-runbook-triage-pivot`, incremental fingerprints to `bounded-input-fingerprint-triage-pivot`, background jobs to `local-background-job-triage-pivot`, and checkpoint outputs to `stage-checkpoint-resume-triage-pivot`. They are not published scale proof, executed TB validation, content-hash-complete incremental indexing, distributed parser scheduling, or mid-parser resume proof without hardware runs, trusted manifests, replay logs, distributed worker telemetry, and long-running corpus evidence.

## Interpretation

Passing this manifest promotes #61 through #70 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until broad relevance, scale, multi-user, hardware, and independent validation evidence is attached.
