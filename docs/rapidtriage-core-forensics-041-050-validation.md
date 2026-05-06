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
| #41 Cloud credential handling | Tokens are redacted, env/vault boundary metadata is recorded, scope/consent and rotation/revocation warnings are emitted, #41 `core_accuracy_gates` are attached, and trusted authority diff is required. | Provider OAuth consent records, enterprise vault integration, rotation/revocation audit, legal authority sign-off, trusted authority/audit row diff. |
| #42 Browser secrets | Sensitive browser stores are inventoried without exposing secrets, strict legal warnings are present, #42 `core_accuracy_gates` are attached, and trusted secret authority diff is required. | Lawful audited reveal workflow, DPAPI/keychain/browser-version known-answer fixtures, trusted authority/audit row diff. |
| #43 Mobile correlation | Mobile summaries preserve message/media/contact/call counts, candidate media-message links, timeline readiness, #43 `core_accuracy_gates`, and trusted correlation diff requirement. | Device-wide timeline join, timezone validation, attachment recovery, vendor-tool diff corpus. |
| #44 Mobile unified view | Mobile summaries build contact/call/SMS actor pivots with participants, source links, scope warnings, #44 `core_accuracy_gates`, and trusted actor diff requirement. | Dedupe/entity merge-split workflow and cross-app actor known-answer validation. |
| #45 App schema versions | Mobile summaries record app/service schema registry entries, compatibility warnings, migration warnings, #45 `core_accuracy_gates`, and trusted schema migration diff requirement. | Per-app schema compatibility matrix, migration fixtures, and release-gated parser support policy. |
| #46 Clustering | Search analysis emits bounded clusters, representative match links, source/keyword grouping, truncation disclosure, #46 `core_accuracy_gates`, and trusted cluster review diff requirement. | Persistent review state, large-case performance evidence, near-duplicate clustering corpus, and hand-labeled review diff. |
| #47 Entities | Search analysis emits entity pivots with source/path references, match links, risk flags, merge/split warnings, #47 `core_accuracy_gates`, and trusted entity review diff requirement. | False-positive tuning, analyst-verified entity merge/split decisions, and trusted entity review diff. |
| #48 Graph | Search analysis emits bounded graph nodes/edges with source citation references, truncation disclosure, causal-proof warning, #48 `core_accuracy_gates`, and trusted graph citation diff requirement. | Scalable graph UI, saved layouts, server-side graph paging, graph source-row review, and trusted citation diff. |
| #49 Timeline | Search analysis extracts timestamps, normalizes UTC, builds date buckets, preserves source anchors, emits #49 `core_accuracy_gates`, and trusted timeline known-answer diff requirement. | Full Case DB timeline join, timezone/skew validation, annotations, large cursor-paged timeline tests, and known-answer timeline diff. |
| #50 Workbook | Search analysis emits draft hypotheses, cluster evidence links, review questions/tasks, report-readiness flags, #50 `core_accuracy_gates`, and trusted workbook rubric diff requirement. | Editable persistent workbook, evidence attachment workflow, reviewer assignments, report export, version history, and rubric-reviewed workbook diff. |

The #41 through #45 rows now emit explicit reportability decisions and trusted-diff blockers so internal triage output cannot be mistaken for commercial-grade proof. #41 is limited to `redacted-credential-handling-triage-pivot` until OAuth consent, provider scope inventory, secure token vault, rotation audit evidence, and a trusted credential authority/audit diff exist. #42 is limited to `browser-secret-store-inventory-triage-pivot` until lawful reveal authority, DPAPI/keychain/browser-version validation, reveal audit logging, and trusted browser secret authority diffs exist. #43 through #45 are limited to `mobile-correlation-and-schema-triage-pivot` until device-wide timeline/timezone/attachment recovery, identity merge/split, schema migration/release matrix evidence, and vendor/native known-answer diffs are attached.

Trusted diff helpers added for this batch:

- `build_cloud_credential_trusted_diff` compares RapidTriage credential handling rows against provider OAuth consent, native audit, enterprise vault, security signoff, or legal authority records.
- `build_browser_secret_trusted_diff` compares browser sensitive-store inventory rows against browser-native store inventory, DPAPI/keychain known-answer, legal authority, or audit-log exports.
- `build_mobile_correlation_trusted_diff` compares mobile correlation, actor, and schema rows against vendor/native known-answer or schema migration fixture rows before #43, #44, or #45 can satisfy their trusted checks.

The #46 through #50 rows also emit reportability decisions and trusted-diff blockers. Their allowed use is `bounded-search-analysis-triage-pivot`, not a reviewed finding. Clusters, entities, graph edges, timeline events, and workbook hypotheses are blocked from report-ready claims until analyst review state, entity merge/split decisions, full-case graph/timeline joins, timezone/parser-confidence validation, source-row citations, and trusted review diffs are attached.

`build_analysis_trusted_diff` compares RapidTriage rows against hand-labeled or analyst-reviewed rows for cluster membership, entity resolution, graph source citations, timeline order, and workbook hypotheses. A passing diff can satisfy the corresponding #46~#50 trusted check, but it still does not replace independent validation or full-case review evidence.

## Interpretation

Passing this manifest promotes #41 through #50 to the internal `validated` maturity stage only. These rows remain `commercial_grade_ready=false` until broader corpus, cross-tool diff, independent validation, and operator-controlled legal evidence are attached.
