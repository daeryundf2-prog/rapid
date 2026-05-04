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

The #6 rows now include a row-level account reportability decision: account/group/privilege/LSA findings remain `do-not-report-as-final-account-state` and `account-security-triage-pivot` until SAM F/V layout, SAM alias/member binary values, SECURITY authority gates, domain context, and transaction logs are validated. SECURITY secret values also carry a `secret_handling_decision` that keeps protected values redacted and limits use to metadata inventory unless a separate lawful decrypt workflow produces audited output.

The #7~#10 execution rows now include artifact-specific reportability decisions. Amcache remains a program presence/install/execution-related pivot, ShimCache is explicitly not execution proof, BAM/DAM is a recent-execution pivot that still requires correlation, and native SRUM rows stay `do-not-report-native-row-as-decoded-fact` until ESE catalog/page/row decoding and trusted-tool diffs are attached. These decisions are also copied into the batch commercial-uplift evidence so readiness reports can show why internal fixture validation does not equal commercial-grade testimony.
