# Core Forensics #1-#5 Validation Evidence

This package is the internal fixture-backed validation bridge for the first five-item commercial-readiness batch.

It covers:

- `#1` Native EVTX BinXML field promotion and accuracy gates.
- `#2` EVTX message rendering provenance, fallback, and unresolved-template warnings.
- `#3` EVTX corrupt/slack recovery candidates and non-reportable defaults.
- `#4` Registry key-tree reconstruction evidence.
- `#5` Registry deleted key/value recovery evidence.

Use it with:

```bash
rapidtriage validation \
  --output-dir ./validation-001-005 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-001-005-known-answer.json \
  --overwrite

rapidtriage commercial-readiness \
  --validation-package ./validation-001-005/rapidtriage-validation-package.json
```

Boundary: this evidence is enough to satisfy the internal `validated` maturity gate for the implemented fixture claims. It is not commercial-grade proof by itself. External EVTX/Registry known-answer corpora, trusted-tool record/cell-level diffs, transaction-log replay validation, and independent reviewer sign-off remain blockers for AXIOM/WISDOM-class wording.
