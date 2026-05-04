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

## Cross-Tool Diff Bridge

For real corpus validation, compare RapidTriage output with trusted tool exports and map passing comparisons to the relevant backlog items:

```bash
rapidtriage cross-tool-validate \
  --rapid-output ./case-run/artifacts/eventlog.json \
  --reference-output evtxecmd=./reference/EvtxECmd-Security.csv \
  --source-evidence ./evidence/Security.evtx \
  --tool-version evtxecmd="EvtxECmd 1.5.0" \
  --tool-command evtxecmd="EvtxECmd.exe -f ./evidence/Security.evtx --csv ./reference" \
  --independent-report ./validation-001-005/independent-evtx-review.md \
  --corpus-scope "NIST/CFReDS Security.evtx plus local deleted-record fixture set" \
  --backlog-item 1 \
  --backlog-item 2 \
  --backlog-item 3 \
  --min-overlap 0.95 \
  --output ./validation-001-005/evtx-cross-tool.json \
  --json

rapidtriage commercial-readiness \
  --validation-package ./validation-001-005/evtx-cross-tool.json \
  --json
```

The cross-tool report now emits a `datasets` section compatible with `commercial-readiness`. It also records SHA256/size/mtime for the RapidTriage output, each external reference output, any `--source-evidence` path, and any `--independent-report` path, plus operator-supplied external tool versions, commands, and corpus scope. A passing report can satisfy the `validated` gate for mapped items only when the JSON report exists and the overlap threshold is met. The report-level `ready_for_commercial_grade` flag turns true only when source hashes, external tool versions/commands, corpus scope, and independent review hashes are all attached; item-level commercial-grade still depends on the backlog item's native parser-depth blockers such as Registry transaction-log/deleted-cell validation.

For #1 EVTX work, review the `record_field_comparison` block in the cross-tool report. It compares overlapping EventRecordID rows across common fields such as EventID, provider, channel, computer, and event time. Any field mismatch or missing common field fails the comparison even when key overlap is high; this prevents a record-level overlap pass from masking BinXML field-promotion errors.

The native EVTX collector now records `evtx_reader_strategy=mmap-bounded-record-scan` on native rows and uses streaming SHA256 for source hashing. This removes the earlier whole-file `Path.read_bytes()` parser path from the EVTX record scan, while retaining explicit large-data proof blockers until real multi-GB/TB EVTX corpora and p95 memory/latency logs are attached. The fixture suite also includes a native chunk with matching header/events CRC32 values so checksum success, not only checksum-warning paths, is regression-tested.
