# RapidTriage #91-#100 Internal Validation

This package records internal fixture evidence for parser confidence, validation warning UX, legal limitations, court exhibit packages, external tool version capture, acquisition metadata, timezone validation, clock-skew checks, contamination warnings, and tamper-evident audit bundle items #91 through #100.

## Commands

```bash
rapidtriage validation \
  --output-dir /tmp/rapidtriage-validation-091-100 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-091-100-known-answer.json \
  --json

rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-091-100/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-091-100 \
  --json
```

## Internal Fixture Scope

| Item | Internal validated claim | Still not commercial-grade without |
| --- | --- | --- |
| #91 Parser confidence | Case DB report items preserve parser confidence, confidence band, reportability score, reportability, coverage status, warning derivation, evidence strength, `parser-confidence-calibration-manifest-v1` manifest hashes, `parser-confidence-report-grade-validation-plan-v1`, plan hash/counts, trusted calibration diff helpers/gates, and #91 `core_accuracy_gates`. | Parser-specific calibration tables, trusted calibration manifests, cross-tool confidence validation, low-confidence FP/FN corpus, reportability threshold review, and release parser-confidence policy locks. |
| #92 Validation warnings | Report items and summaries preserve warning reasons, warning counts, warning detail metadata, severity/category counts, UX badges, `validation-warning-checklist-manifest-v1` manifest hashes, `validation-warning-report-grade-validation-plan-v1`, plan hash/counts, report guidance, validation-required state, trusted warning-checklist diff helpers/gates, and #92 `core_accuracy_gates`. | All-table warning badge coverage, trusted warning checklists, UX e2e checks across every table, final report-template warning review, action playbook review, and accessibility warning-badge review. |
| #93 Legal limitations | Report items preserve parser/source limitation text, limitation detail metadata, category/scope counts, `legal-limitation-wording-manifest-v1` manifest hashes, jurisdiction caveats, analyst-review blockers, limitation counts, trusted legal wording diff helpers/gates, and #93 `core_accuracy_gates`. | Jurisdiction-approved wording, trusted legal wording manifests, and formal legal review signoff. |
| #94 Court exhibits | Reviewer bundles preserve exhibit IDs, exhibit row hashes, selected evidence hashes, selected-evidence manifest hashes, generated output hashes, source references, signing slots, `court-exhibit-package-manifest-v1` manifest hashes, verification steps, trusted exhibit-manifest diff helpers/gates, and #94 `core_accuracy_gates`. | Signed/notarized exhibit manifests and court-specific forms. |
| #95 External tools | Validation packages preserve tool inventory, availability/path/command/version/capture errors, version-output hashes, per-tool row hashes, `external-tool-version-manifest-v1` manifest hashes, limitation warnings, trusted transcript diff helpers/gates, and #95 `core_accuracy_gates`. | Per-run capture for every external parser/import, trusted tool transcripts, and original tool logs. |
| #96 Acquisition metadata | Case DB exports preserve operator/source metadata, write-blocker fields, whole-source hash fields, acquisition metadata row hashes, evidence-source row hashes, `acquisition-metadata-handoff-manifest-v1` manifest hashes, missing-field checks, readiness flag, trusted acquisition-handoff diff helpers/gates, and #96 `core_accuracy_gates`. | Integrated write-blocker device capture, trusted handoff manifests, and signed handoff forms. |
| #97 Timezone validation | Report exports preserve timezone inventory, missing timezone counts, timestamp samples, timezone sample row hashes, `timezone-normalization-manifest-v1` manifest hashes, UTC assumption, review flag, trusted timezone-matrix diff helpers/gates, and #97 `core_accuracy_gates`. | Parser-specific timezone matrix, trusted normalization manifests, and multi-source reconciliation. |
| #98 Clock skew | Report exports preserve parsed timestamp range, skew warnings, clock-skew warning row hashes, warning counts, baseline requirement, `clock-skew-baseline-manifest-v1` manifest hashes, heuristic caveat, trusted clock-skew baseline diff helpers/gates, and #98 `core_accuracy_gates`. | Host/device baseline model, trusted baseline manifests, and multi-device skew validation. |
| #99 Contamination warnings | Report exports preserve contamination warnings, contamination warning row hashes, warning count, output-under-evidence checks, `contamination-checklist-manifest-v1` manifest hashes, write-blocker limitation, review flag, trusted contamination-checklist diff helpers/gates, and #99 `core_accuracy_gates`. | Persistent acquisition-time mtime comparison, trusted contamination checklist, and write-blocker integration. |
| #100 Tamper bundle | Reviewer bundles preserve generated output hashes, previous-entry chain, entry hashes, head hash, `tamper-evident-audit-manifest-v1` manifest hashes, external signing slots, signing limitation, trusted signature-attestation diff helpers/gates, and #100 `core_accuracy_gates`. | External signing/notarization and trusted signature attestations. |

## Interpretation

Passing this manifest promotes #91 through #100 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until calibration, trusted manifests, independent review, signed court packages, acquisition hardware/process evidence, and external notarization are attached.
