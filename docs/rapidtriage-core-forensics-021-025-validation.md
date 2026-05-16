# RapidTriage Core Forensics #21-#25 Validation

This package records internal fixture validation for AI transcript candidates and evidence-image/container workflows.

Run it with:

```bash
rapidtriage validation \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-021-025-known-answer.json \
  --output-dir /tmp/rapidtriage-validation-021-025
```

Then attach it to readiness scoring:

```bash
rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-021-025/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-021-025
```

Passing this package means internal `implemented + usable + validated` maturity only. Commercial-grade claims still require trusted-tool diffs, real image/container corpora, corrupt/encrypted edge cases, independent reviewer sign-off, and large-case repeatability.

This batch adds trusted-diff gates for every #21~#25 item. `build_ai_transcript_trusted_diff` compares RapidTriage AI Q/A candidates against recognized service/export rows before the #21 gate can pass. `cross-tool-validate` also emits `ai_transcript_field_comparison` for #21 service-export/browser-storage handoff files, including generated rows with nested `details.transcript_pairs`, nested `details.transcript.pairs`, or adjacent question/answer `details.conversation_rows`; it compares service, conversation/pair IDs, Q/A text, timestamps, source hashes, source paths/offsets, storage area, and pairing confidence so simple key overlap cannot pass as transcript parity. `build_image_workflow_trusted_diff` compares RapidTriage E01/RAW/VM/container rows against trusted image workflow, TSK/qemu-img, or vendor export manifest rows before the #22~#25 gates can pass. These helpers prevent internal fixtures from being mistaken for external commercial validation.

The #21~#25 rows now also emit explicit reportability decisions in their commercial-uplift evidence. AI transcript rows remain `ai-conversation-triage-pivot` until service-side exports, provider schema versions, orphan handling, and deleted-fragment recovery are validated. E01/Ex01 rows remain `e01-ex01-extraction-triage-pivot` until native segment metadata, corrupt/encrypted image corpora, and trusted-tool diffs exist. E01/Ex01 extraction and direct E01 run summaries additionally expose `e01-ex01-integrated-workflow-manifest-v1` so #22 can be checked from selection through report export. RAW/split rows remain `raw-split-extraction-triage-pivot` until large damaged split sets, native partition/filesystem interpretation, and encrypted-volume workflows are validated. RAW/split extraction and direct RAW/split run summaries now expose `raw-split-integrated-workflow-manifest-v1` so #23 can be checked from part-order validation through downstream analysis/report outputs. Virtual disk rows remain `virtual-disk-extraction-triage-pivot` until snapshot/differencing chains, hypervisor metadata, and qemu-img conversion fidelity are proven. Virtual-disk evidence preflight and extraction metadata now expose `virtual-disk-report-grade-validation-plan-v1`, and virtual-disk extraction/direct run summaries expose `virtual-disk-integrated-workflow-manifest-v1`, so #24 can be checked from qemu-img metadata capture and RAW conversion through nested recovery, trusted conversion/recovery diff, and report output blockers. AD1/L01/Lx01/AFF/AFF4 rows remain `vendor-export-container-triage-pivot` until native parsing or verified vendor export manifests are attached; they now expose `forensic-container-export-workflow-manifest-v1` so #25 can be checked from container detection and source hashing through sidecar export-manifest linkage and derived-export scan readiness.

Current external blockers:

- #21: service-side transcript export validation, service schema version matrix, deleted fragment recovery.
- #22: real E01/Ex01 known-answer images, encrypted/corrupt image validation, libewf/Sleuth Kit version matrix.
- #23: damaged/gapped split-set validation, native partition/filesystem validation, encrypted volume workflow.
- #24: snapshot/differencing chain resolution, hypervisor metadata preservation, qemu-img matrix and large VM-disk corpus.
- #25: native AD1/L01/Lx01/AFF/AFF4 parsing, metadata/deleted-entry validation, encrypted/compressed proprietary container support.
