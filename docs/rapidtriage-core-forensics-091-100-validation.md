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
| #91 Parser confidence | Case DB report items preserve parser confidence, reportability, coverage status, warning derivation, evidence strength, trusted calibration diff helpers/gates, and #91 `core_accuracy_gates`. | Parser-specific calibration tables, trusted calibration manifests, and cross-tool confidence validation. |
| #92 Validation warnings | Report items and summaries preserve warning reasons, warning counts, report guidance, validation-required state, trusted warning-checklist diff helpers/gates, and #92 `core_accuracy_gates`. | Full web badge coverage, trusted warning checklists, and UX e2e checks across every table. |
| #93 Legal limitations | Report items preserve parser/source limitation text, jurisdiction caveats, analyst-review blockers, limitation counts, trusted legal wording diff helpers/gates, and #93 `core_accuracy_gates`. | Jurisdiction-approved wording, trusted legal wording manifests, and formal legal review signoff. |
| #94 Court exhibits | Reviewer bundles preserve exhibit IDs, selected evidence hashes, generated output hashes, source references, verification steps, trusted exhibit-manifest diff helpers/gates, and #94 `core_accuracy_gates`. | Signed/notarized exhibit manifests and court-specific forms. |
| #95 External tools | Validation packages preserve tool inventory, availability/path/command/version/capture errors, limitation warnings, trusted transcript diff helpers/gates, and #95 `core_accuracy_gates`. | Per-run capture for every external parser/import, trusted tool transcripts, and original tool logs. |
| #96 Acquisition metadata | Case DB exports preserve operator/source metadata, write-blocker fields, whole-source hash fields, missing-field checks, readiness flag, and #96 `core_accuracy_gates`. | Integrated write-blocker device capture and signed handoff forms. |
| #97 Timezone validation | Report exports preserve timezone inventory, missing timezone counts, timestamp samples, UTC assumption, review flag, and #97 `core_accuracy_gates`. | Parser-specific timezone matrix and multi-source reconciliation. |
| #98 Clock skew | Report exports preserve parsed timestamp range, skew warnings, warning counts, baseline requirement, heuristic caveat, and #98 `core_accuracy_gates`. | Host/device baseline model and multi-device skew validation. |
| #99 Contamination warnings | Report exports preserve contamination warnings, warning count, output-under-evidence checks, write-blocker limitation, review flag, and #99 `core_accuracy_gates`. | Persistent acquisition-time mtime comparison and write-blocker integration. |
| #100 Tamper bundle | Reviewer bundles preserve generated output hashes, previous-entry chain, entry hashes, head hash, signing limitation, and #100 `core_accuracy_gates`. | External signing/notarization. |

## Interpretation

Passing this manifest promotes #91 through #100 to the internal `validated` maturity stage only. These features remain `commercial_grade_ready=false` until calibration, trusted manifests, independent review, signed court packages, acquisition hardware/process evidence, and external notarization are attached.
