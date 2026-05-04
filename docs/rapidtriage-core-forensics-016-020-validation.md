# RapidTriage Core Forensics #16-#20 Validation

This package records internal fixture validation for Prefetch, LNK, Windows system artifacts, browser storage, and unified browser timelines.

Run it with:

```bash
rapidtriage validation \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-016-020-known-answer.json \
  --output-dir /tmp/rapidtriage-validation-016-020
```

Then attach it to readiness scoring:

```bash
rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-016-020/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-016-020
```

Passing this package means internal `implemented + usable + validated` maturity only. Commercial-grade claims still require trusted-tool diffs, broader OS/browser corpora, malformed/deleted/compressed cases, independent sign-off, and large-case repeatability evidence.

The #16~#20 rows now carry reportability decisions in commercial-uplift evidence. Prefetch remains an execution triage pivot until PECmd/known-answer diffs and file-metrics/volume validation exist. LNK remains a shortcut target/metadata pivot until Shell Item, LinkInfo, tracker, and property-store semantics are validated. Windows system artifacts remain triage pivots until TaskCache, WMI, Defender, Firewall, and WER correlations are complete. Browser storage and timeline rows remain browser triage pivots with secrets redacted by default until cache/session/deleted-history/schema validation and audited legal opt-in handling are attached.

Current external blockers:

- #16: compressed Prefetch, full file metrics, authoritative volume tables, PECmd diff corpus.
- #17: full shell-item property store semantics, drive/network provider validation, LECmd diff corpus.
- #18: TaskCache, WMI native decode, Defender/Firewall policy correlation, WER dump/CAB linkage.
- #19: cache/session/schema decoding, audited legal opt-in secret handling, extension/sync validation.
- #20: multi-profile dedupe, Safari parity, deleted history, browser-version transition semantics.
