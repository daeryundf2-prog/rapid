# Core Forensics #6-#10 Validation Evidence

This package is the internal fixture-backed validation bridge for the second five-item commercial-readiness batch.

It covers:

- `#6` SAM/SECURITY/SYSTEM account and permission rows.
- `#7` Amcache registry export and native hive string-pivot rows.
- `#8` ShimCache/AppCompatCache caveated execution-presence rows.
- `#9` BAM/DAM SID/path/FILETIME execution rows.
- `#10` SRUM source-tool imports and native ESE header/table/row candidates.

Use it with:

```bash
rapidtriage validation \
  --output-dir ./validation-006-010 \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-006-010-known-answer.json \
  --overwrite

rapidtriage commercial-readiness \
  --validation-package ./validation-006-010/rapidtriage-validation-package.json
```

Boundary: this evidence is enough to satisfy the internal `validated` maturity gate for the implemented fixture claims. It is not commercial-grade proof by itself. External known-answer corpora, trusted-tool diffs, broad Windows-version coverage, and independent reviewer sign-off remain blockers for AXIOM/WISDOM-class wording.
