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

Current external blockers:

- #21: service-side transcript export validation, service schema version matrix, deleted fragment recovery.
- #22: real E01/Ex01 known-answer images, encrypted/corrupt image validation, libewf/Sleuth Kit version matrix.
- #23: damaged/gapped split-set validation, native partition/filesystem validation, encrypted volume workflow.
- #24: snapshot/differencing chain resolution, hypervisor metadata preservation, qemu-img matrix and large VM-disk corpus.
- #25: native AD1/L01/Lx01/AFF/AFF4 parsing, metadata/deleted-entry validation, encrypted/compressed proprietary container support.
