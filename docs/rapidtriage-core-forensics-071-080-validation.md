# RapidTriage #71-#80 Internal Validation

This package records internal fixture evidence for parser crash isolation, memory caps, preview sandboxing, SQLite/FTS large-case handling, parser scheduling, hash caching, duplicate detection, cursor pagination, UI virtualization, and cancellation/retry items #71 through #80.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-071-080 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-071-080-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-071-080/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-071-080 \
  --json
```

## Internal Fixture Scope

| Item | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #71 Parser crash isolation | Parser-stage exceptions are isolated into failed parser JSON with error hashes, crash context, parser-error inventory head hash, run summaries keep parser error counts, `parser-crash-continuation-manifest-v1`, `parser_crash_report_grade_validation_plan` hashes/ready slots/blocking slots, trusted crash-corpus diff helpers/gates, and #71 `core_accuracy_gates` are attached. | Native process sandboxing for every parser, trusted crash-corpus manifests, fuzz/corrupt crash corpus, subprocess crash-boundary validation, long-running corrupt evidence replay, and cross-platform parser isolation validation. |
| #72 Memory cap enforcement | Run safety metadata records configured caps, RSS readings, utilization/over-cap policy profiles, stage-boundary enforcement, `memory-cap-stage-telemetry-manifest-v1`, `memory_cap_report_grade_validation_plan` hashes/ready slots/blocking slots, trusted RSS diff helpers/gates, and #72 `core_accuracy_gates`. | Hard OS cgroup/job-object limits, per-parser live RSS telemetry, trusted RSS manifests, 1TB+ RSS graphs, platform-specific RSS validation on Windows/macOS/Linux, and allocation-level enforcement validation. |
| #73 Preview sandboxing | Source previews record read-only bounded rendering, active-content blocking, no network execution, caps, `preview-sandbox-policy-profile-v1`, escaped bounded renderer strategy, `preview-sandbox-report-grade-validation-plan-v1` ready/blocking slots, trusted no-exec diff helpers/gates, and #73 `core_accuracy_gates`; run summaries attach the same validation-plan hash and slot counts to `rapidtriage-preview-sandbox-policy.json`. | Separate OS sandbox for risky codecs/macros, trusted no-exec manifests, browser/renderer exploit validation, malicious active-content corpus, and browser E2E no-exec/no-network validation. |
| #74 Large SQLite/FTS | Case DB and SQLite preview metadata record WAL/cache pragmas, text column/table profiles, bounded rows, source preview query-plan profiles, Case DB query-plan head hashes, `large-sqlite-fts-report-grade-validation-plan-v1` ready/blocking slots, trusted query-plan diff helpers/gates, and #74 `core_accuracy_gates`; run summaries attach the same validation-plan hash and slot counts to `rapidtriage-sqlite-fts-optimization.json`. | 10M-row query-plan regression, trusted query-plan manifests, deleted-row/WAL replay validation, browser pagination/query-plan E2E, index-maintenance/vacuum regression, and very large source DB corpus. |
| #75 Parallel parser scheduler | Artifact collection records bounded worker count, deterministic outputs, per-parser capture, resume awareness, `rapidtriage-parser-scheduler.json` run manifests with quota policy/per-parser duration/output-order/error hashes, `parser-scheduler-report-grade-validation-plan-v1` ready/blocking slots, trusted scheduler diff helpers/gates, and #75 `core_accuracy_gates`. | Distributed priority scheduler, live worker telemetry UI/stream, trusted scheduler manifests, cross-platform quota validation, priority-starvation regression, and TB-scale backpressure validation. |
| #76 File hash cache | Hash metadata records MD5/SHA1/SHA256 support, path-size-mtime-inode cache keys, hit/miss/invalidation counters, `hash-cache-manifest-v1` entries with hashed paths and manifest hash, stale same-path invalidation policy, `hash-cache-persistence-manifest-v1` content-addressed rows, explicit snapshot export/import support, `hash-cache-report-grade-validation-plan-v1` ready/blocking slots, trusted hash-cache manifest diff helpers/gates, and #76 `core_accuracy_gates`. | Automatic on-disk cache wiring, trusted hash-cache manifests, large-case hit-ratio validation, cross-platform cache-key semantics, content-addressed lookup mode, and multi-run stale-cache replay. |
| #77 Duplicate detection | File scans record same-size buckets, bounded SHA256 duplicate groups, bounded normalized-text near-duplicate candidates, stable group IDs/fingerprints, representative paths, not-suppressed analyst-review policy, `duplicate-content-manifest-v1` exact/fuzzy manifest hashes, `duplicate-content-report-grade-validation-plan-v1` ready/blocking slots, trusted duplicate-manifest diff helpers/gates, and #77 `core_accuracy_gates`. | Perceptual media duplicate grouping, trusted external duplicate group manifests, analyst suppression workflow validation, large-case dedupe performance validation, near-duplicate text known-answer corpus, and cross-run suppression version history. |
| #78 Cursor pagination | API pages record cursor tokens, offsets, limits, totals, bounded rows, corrected last-page `has_more` semantics, `pagination-cursor-manifest-v1` page-window IDs/manifest hashes, `pagination-cursor-report-grade-validation-plan-v1` ready/blocking slots, trusted cursor-manifest diff helpers/gates, and #78 `core_accuracy_gates`. | Snapshot-isolated database cursors, trusted external pagination manifests, endpoint-wide compatibility validation, cursor invalidation/replay validation, large-case page latency evidence, and cross-client cursor compatibility. |
| #79 UI virtualization | API pagination and web UI expose bounded visible row windows, `ui-virtualization-manifest-v1` row-window IDs/manifest hashes, row-count notices, previous/next 300-row windows, keyboard/filter support, trusted virtualization-manifest diff helpers/gates, and #79 `core_accuracy_gates`. | Full recycling virtual scroller, trusted browser row-window manifests, persisted viewport restoration across reloads, and browser e2e performance evidence. |
| #80 Cancellation/retry | Job payloads record queued/running cancellation, failed/canceled retry support, persisted cancel flags, `retry_lineage_profile`, `job-partial-output-policy-v1`, `cancellation-retry-manifest-v1` hashes, trusted transition diff helpers/gates, and #80 `core_accuracy_gates`. | Parser-level cooperative cancellation under load, trusted cancellation/retry transition manifests, and partial-output cleanup/resume validation. |

## Interpretation

Passing this manifest promotes #71 through #80 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until process isolation, OS-level resource controls, trusted manifests, browser e2e, large-case, cancellation-under-load, and independent validation evidence is attached.
