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
| #71 Parser crash isolation | Parser-stage exceptions are isolated into failed parser JSON, run summaries keep parser error counts, trusted crash-corpus diff helpers/gates, and #71 `core_accuracy_gates` are attached. | Native process sandboxing for every parser, trusted crash-corpus manifests, fuzz/corrupt crash corpus, and long-running corrupt evidence replay. |
| #72 Memory cap enforcement | Run safety metadata records configured caps, RSS readings, stage-boundary enforcement, trusted RSS diff helpers/gates, and #72 `core_accuracy_gates`. | Hard OS cgroup/job-object limits, trusted RSS manifests, and platform-specific RSS validation on Windows/macOS/Linux. |
| #73 Preview sandboxing | Source previews record read-only bounded rendering, active-content blocking, no network execution, caps, trusted no-exec diff helpers/gates, and #73 `core_accuracy_gates`. | Separate OS sandbox for risky codecs/macros, trusted no-exec manifests, and browser/renderer exploit validation. |
| #74 Large SQLite/FTS | Case DB and SQLite preview metadata record WAL/cache pragmas, text column/table profiles, bounded rows, trusted query-plan diff helpers/gates, and #74 `core_accuracy_gates`. | 10M-row query-plan regression, trusted query-plan manifests, deleted-row/WAL replay validation, and very large source DB corpus. |
| #75 Parallel parser scheduler | Artifact collection records bounded worker count, deterministic outputs, per-parser capture, resume awareness, trusted scheduler diff helpers/gates, and #75 `core_accuracy_gates`. | Distributed priority scheduler, trusted scheduler manifests, live per-worker telemetry, and TB-scale backpressure validation. |
| #76 File hash cache | Hash metadata records MD5/SHA1/SHA256 support, path-size-mtime cache, hit/miss counters, trusted hash-cache manifest diff helpers/gates, and #76 `core_accuracy_gates`. | Persistent content-addressed cache, trusted hash-cache manifests, and large-case hit-ratio validation. |
| #77 Duplicate detection | File scans record same-size buckets, bounded SHA256 duplicate groups, representative paths, trusted duplicate-manifest diff helpers/gates, and #77 `core_accuracy_gates`. | Fuzzy text/media duplicate detection, trusted duplicate group manifests, and analyst suppression workflow validation. |
| #78 Cursor pagination | API pages record cursor tokens, offsets, limits, totals, bounded rows, trusted cursor-manifest diff helpers/gates, and #78 `core_accuracy_gates`. | Snapshot-isolated database cursors, trusted pagination manifests, and pagination compatibility validation across every future endpoint. |
| #79 UI virtualization | API pagination and web UI expose bounded visible row windows, row-count notices, keyboard/filter support, trusted virtualization-manifest diff helpers/gates, and #79 `core_accuracy_gates`. | Full recycling virtual scroller, trusted browser row-window manifests, persisted viewport restoration, and browser e2e performance evidence. |
| #80 Cancellation/retry | Job payloads record queued/running cancellation, failed/canceled retry support, persisted cancel flags, trusted transition diff helpers/gates, and #80 `core_accuracy_gates`. | Parser-level cooperative cancellation under load, trusted cancellation/retry transition manifests, and partial-output cleanup/resume validation. |

## Interpretation

Passing this manifest promotes #71 through #80 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until process isolation, OS-level resource controls, trusted manifests, browser e2e, large-case, cancellation-under-load, and independent validation evidence is attached.
