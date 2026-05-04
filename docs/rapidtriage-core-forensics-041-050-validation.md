# RapidTriage #41-#50 Internal Validation

This package records internal fixture evidence for credential handling, browser secret handling, mobile correlation/schema management, and search-analysis UX items #41 through #50.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-041-050 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-041-050-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-041-050/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-041-050 \
  --json
```

## Internal Fixture Scope

| Item | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #41 Cloud credential handling | Tokens are redacted, env/vault boundary metadata is recorded, scope/consent and rotation/revocation warnings are emitted, and #41 `core_accuracy_gates` are attached. | Provider OAuth consent records, enterprise vault integration, rotation/revocation audit, legal authority sign-off. |
| #42 Browser secrets | Sensitive browser stores are inventoried without exposing secrets, strict legal warnings are present, and #42 `core_accuracy_gates` are attached. | Lawful audited reveal workflow, DPAPI/keychain/browser-version known-answer fixtures. |
| #43 Mobile correlation | Mobile summaries preserve message/media/contact/call counts, candidate media-message links, timeline readiness, and #43 `core_accuracy_gates`. | Device-wide timeline join, timezone validation, attachment recovery, vendor-tool diff corpus. |
| #44 Mobile unified view | Mobile summaries build contact/call/SMS actor pivots with participants, source links, scope warnings, and #44 `core_accuracy_gates`. | Dedupe/entity merge-split workflow and cross-app actor known-answer validation. |
| #45 App schema versions | Mobile summaries record app/service schema registry entries, compatibility warnings, migration warnings, and #45 `core_accuracy_gates`. | Per-app schema compatibility matrix, migration fixtures, and release-gated parser support policy. |
| #46 Clustering | Search analysis emits bounded clusters, representative match links, source/keyword grouping, truncation disclosure, and #46 `core_accuracy_gates`. | Persistent review state, large-case performance evidence, and near-duplicate clustering corpus. |
| #47 Entities | Search analysis emits entity pivots with source/path references, match links, risk flags, merge/split warnings, and #47 `core_accuracy_gates`. | False-positive tuning and analyst-verified entity merge/split decisions. |
| #48 Graph | Search analysis emits bounded graph nodes/edges with source citation references, truncation disclosure, causal-proof warning, and #48 `core_accuracy_gates`. | Scalable graph UI, saved layouts, server-side graph paging, and graph source-row review. |
| #49 Timeline | Search analysis extracts timestamps, normalizes UTC, builds date buckets, preserves source anchors, and emits #49 `core_accuracy_gates`. | Full Case DB timeline join, timezone/skew validation, annotations, and large cursor-paged timeline tests. |
| #50 Workbook | Search analysis emits draft hypotheses, cluster evidence links, review questions/tasks, report-readiness flags, and #50 `core_accuracy_gates`. | Editable persistent workbook, evidence attachment workflow, reviewer assignments, report export, and version history. |

The #41 through #45 rows now emit explicit reportability decisions so internal triage output cannot be mistaken for commercial-grade proof. #41 is limited to `redacted-credential-handling-triage-pivot` until OAuth consent, provider scope inventory, secure token vault, and rotation audit evidence exists. #42 is limited to `browser-secret-store-inventory-triage-pivot` until lawful reveal authority, DPAPI/keychain/browser-version validation, and reveal audit logging exist. #43 through #45 are limited to `mobile-correlation-and-schema-triage-pivot` until device-wide timeline/timezone/attachment recovery, identity merge/split, and schema migration/release matrix evidence is attached.

## Interpretation

Passing this manifest promotes #41 through #50 to the internal `validated` maturity stage only. These rows remain `commercial_grade_ready=false` until broader corpus, cross-tool diff, independent validation, and operator-controlled legal evidence are attached.
