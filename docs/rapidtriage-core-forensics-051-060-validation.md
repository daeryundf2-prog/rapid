# RapidTriage #51-#60 Internal Validation

This package records internal fixture evidence for review workflow, compare/viewer UX, media/OCR review, and search deduplication items #51 through #60.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-051-060 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-051-060-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-051-060/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-051-060 \
  --json
```

## Internal Fixture Scope

| Item | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #51 Reviewer workflow | Review status, verification, reviewer, assignee, priority, due date, report inclusion, history, and #51 `core_accuracy_gates` are emitted. | Multi-user RBAC server, conflict handling, notifications, and signed reviewer SOP. |
| #52 Compare | A/B and A/B/C compare outputs preserve hashes, bounded text diffs, status counts, report pivots, and #52 `core_accuracy_gates`. | Binary/image/SQLite semantic diff and analyst-selected comparison corpus. |
| #53 Hex viewer | Source preview emits bounded hex rows, offsets, preview hashes, byte-search citations, and #53 `core_accuracy_gates`. | Full-file jump/export-range UI and byte-level citation package validation. |
| #54 SQLite viewer | Source preview opens SQLite read-only and emits schema/table/column/index/row metadata plus #54 `core_accuracy_gates`. | Deleted-row/WAL validation, WHERE-builder UI, and large database corpus. |
| #55 Email viewer | Source preview emits message threads, message order, participants, headers, attachments, and #55 `core_accuracy_gates`. | Native PST/OST/MSG conversations, deleted items, attachment extraction, and mailbox corpus validation. |
| #56 Image gallery | Image rows/previews preserve dimensions, hashes, thumbnails, perceptual buckets, tags/report hints, and #56 `core_accuracy_gates`. | Dedicated gallery UI, persistent tags, ML similarity, sensitive/deepfake classifier validation. |
| #57 Media transcript | Media preview preserves metadata, hashes, transcript sidecars, cue timestamps, warnings, and #57 `core_accuracy_gates`. | Safe playback sandbox, ASR execution, waveform/thumb previews, and transcript alignment corpus. |
| #58 OCR queue | OCR queue/manifests preserve queue state, sidecars, hashes, retry handling, metadata, and #58 `core_accuracy_gates`. | Native OCR worker execution, engine logs, web queue persistence. |
| #59 Korean OCR/translation | OCR/media flows preserve Korean hints, quality metrics, translation sidecars, confidence/engine metadata, and #59 `core_accuracy_gates`. | OCR calibration, certified translation workflow, and side-by-side review UI. |
| #60 Search dedup | Search analysis emits duplicate fingerprints, group counts, representative links, source/path references, and #60 `core_accuracy_gates`. | UI collapse/suppression workflow, fuzzy text near-duplicate grouping, and media duplicate validation. |

## Interpretation

Passing this manifest promotes #51 through #60 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until broader UX, multi-user, external-tool, large-case, and independent validation evidence is attached.
