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
| #51 Reviewer workflow | Review status, verification, reviewer, assignee, priority, due date, report inclusion, history, bounded review queue rows, source-viewer locators, queue row hashes, assignment manifest hash, trusted reviewer workflow audit diff gates, and #51 `core_accuracy_gates` are emitted. | Multi-user RBAC server, conflict handling, notifications, signed reviewer SOP, and trusted analyst review log diff. |
| #52 Compare | A/B and A/B/C compare outputs preserve hashes, bounded text diffs, status counts, report pivots, per-side source-viewer locators, diff locators, comparison entry hashes, `multi-evidence-compare-citation-manifest-v1`, `compare_report_grade_validation_plan`, trusted expected-diff gates, and #52 `core_accuracy_gates`. | Web three-pane compare UI, binary/image/SQLite/mailbox semantic diff, persistent Case DB compare notes, citation signoff, analyst-selected comparison corpus, and trusted expected-diff manifest. |
| #53 Hex viewer | Source preview emits bounded hex rows, offsets, preview hashes, byte-search citations, `hex-preview-source-locator-manifest-v1` with row hashes, bounded `/source-hex-range` citation packages, `hex-range-proof-manifest-v1` with range/source locators and row hashes, `hex_viewer_report_grade_validation_plan`, trusted offset manifest gates, and #53 `core_accuracy_gates`. | Interactive full-file jump UI, byte-selection hashing, trusted offset manifest diff, sector/partition navigation, and byte-level citation package validation against an external oracle. |
| #54 SQLite viewer | Source preview opens SQLite read-only and emits schema/table/column/index/row metadata, `sqlite-preview-source-manifest-v1` table/schema/sample-row hashes, API-backed table pages, `sqlite-table-page-proof-manifest-v1` query/page row hashes, restricted contains filters, `sqlite_viewer_report_grade_validation_plan` ready/blocking slots on preview and table-page payloads, trusted query/schema diff gates, and #54 `core_accuracy_gates`. | Deleted-row/WAL validation, browser E2E pagination proof, trusted sqlite3 query/schema diff, selected-row export workflow, FTS/virtual-table review, and large database corpus. |
| #55 Email viewer | Source preview emits message threads, message order, participants, headers, `email-conversation-source-manifest-v1` message/thread hashes, attachment hash inventory, bounded attachment citation packages, `email-attachment-proof-manifest-v1`, `email_viewer_report_grade_validation_plan` ready/blocking slots on conversation and attachment payloads, trusted thread/export diff gates, and #55 `core_accuracy_gates`. | Native PST/OST/MSG conversations, deleted items, native mailbox attachment extraction, Message-ID graph validation, trusted mail-client thread export diff, and mailbox corpus validation. |
| #56 Image gallery | Image rows/previews preserve dimensions, hashes, thumbnails, perceptual buckets, `image-gallery-source-manifest-v1` row hashes, folder gallery pages, `image-gallery-page-manifest-v1` page row hashes, bucket filters, tags/report hints, `image_gallery_report_grade_validation_plan` ready/blocking slots, trusted image gallery manifest gates, and #56 `core_accuracy_gates`. | Dedicated virtualized gallery UI, persistent tags, ML similarity, sensitive/deepfake classifier validation, trusted image manifest diff, and selected-image report export. |
| #57 Media transcript | Media preview preserves metadata, hashes, transcript sidecars, cue timestamps, `media-transcript-source-manifest-v1` sidecar/cue hashes, bounded cue citation packages, `media-cue-proof-manifest-v1`, warnings, trusted transcript cue/alignment gates, and #57 `core_accuracy_gates`. | Safe playback sandbox, ASR execution, waveform/thumb previews, trusted cue/alignment diff, and transcript alignment corpus. |
| #58 OCR queue | OCR queue/source-preview pages preserve queue state, sidecars, hashes, retry handling, metadata, `ocr-queue-source-manifest-v1`, `ocr-queue-item-manifest-v1`, `source-ocr-queue-page-manifest-v1`, source-viewer locators, trusted OCR engine/sidecar gates, and #58 `core_accuracy_gates`. | Native OCR worker execution, engine logs, trusted engine/sidecar diff, editable web queue state, and Case DB persistence. |
| #59 Korean OCR/translation | OCR/media flows preserve Korean hints, quality metrics, translation sidecars, confidence/engine metadata, source-viewer side-by-side OCR/translation review packages, `source-ocr-translation-review-manifest-v1` row hashes/source locator, trusted Korean OCR/translation gates, and #59 `core_accuracy_gates`. | OCR calibration, trusted Korean OCR review diff, certified translation workflow, and reviewer signoff persistence. |
| #60 Search dedup | Search analysis emits duplicate fingerprints, group counts, representative links, hidden duplicate counts, source/path references, collapse review profiles, `search-dedup-citation-manifest-v1` member row hashes/source locators, web analysis cards, trusted duplicate manifest gates, and #60 `core_accuracy_gates`. | Persistent Case DB suppression workflow, fuzzy text near-duplicate grouping, trusted duplicate manifest diff, and media duplicate validation. |

The #51 through #55 rows now include explicit reportability decisions and trusted-diff blockers. #51 is limited to `single-user-review-status-triage-pivot` with a bounded `case-review-assignment-manifest-v1`, #52 to `bounded-file-compare-triage-pivot` with a bounded `multi-evidence-compare-citation-manifest-v1`, #53 to `bounded-hex-preview-triage-pivot` with bounded preview/range proof manifests, #54 to `read-only-sqlite-preview-triage-pivot` with bounded preview/page proof manifests plus `sqlite_viewer_report_grade_validation_plan`, and #55 to `bounded-email-conversation-triage-pivot` with bounded conversation/attachment proof manifests plus `email_viewer_report_grade_validation_plan`. These outputs must not be described as role-based case management, semantic-diff-complete, full byte citation, deleted-row/WAL-complete, or native mailbox-thread-complete until the named external validation, trusted diff, and workflow evidence is attached.

The #56 through #60 rows follow the same rule and now include trusted-diff blockers. Image gallery output is limited to `image-gallery-metadata-triage-pivot` with bounded source/page manifests; media transcript output to `media-transcript-sidecar-triage-pivot` with bounded transcript/cue proof manifests; OCR/translation output to `ocr-sidecar-and-queue-triage-pivot` with bounded queue/item/page and side-by-side review manifests; and deduplication output to `duplicate-hit-triage-pivot` with bounded duplicate citation manifests. They must not be described as ML similarity complete, safe-playback/ASR validated, certified Korean OCR/translation, or suppression-ready duplicate handling without the required corpora, trusted diffs, engine logs, reviewer decisions, and Case DB persistence evidence.

## Interpretation

Passing this manifest promotes #51 through #60 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until broader UX, multi-user, external-tool, large-case, and independent validation evidence is attached.
