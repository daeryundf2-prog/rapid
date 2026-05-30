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

The native EVTX code also exposes a row-level `evtx-trusted-tool-record-diff-v1` helper for fixture and validation tooling. It normalizes RapidTriage rows and EvtxECmd/Hayabusa/Windows Event Viewer-style exports by EventRecordID, then compares EventID, provider, channel, computer, timestamp, rendered-message hash, and template hash. If the trusted export is absent, unrecognized, mismatched, missing rows, or has extra rows, the native EVTX output remains `do-not-use-native-evtx-as-final` and the `trusted-tool-record-diff-required` commercial blocker stays attached.

The native EVTX collector now records `evtx_reader_strategy=mmap-bounded-record-scan` on native rows and uses streaming SHA256 for source hashing. This removes the earlier whole-file `Path.read_bytes()` parser path from the EVTX record scan, while retaining explicit large-data proof blockers until real multi-GB/TB EVTX corpora and p95 memory/latency logs are attached. The fixture suite also includes a native chunk with matching header/events CRC32 values so checksum success, not only checksum-warning paths, is regression-tested.

For #2 EVTX message rendering, curated provider message catalogs now preserve `source_type`, `message_id`, `extraction_tool`, locale, catalog path, and template SHA256 in `message_rendering.provenance.provider_message_resource_source`. Native EVTX rows can use those catalogs to render provider-template messages without falling back to RapidTriage built-in wording. Windows Event Manifest XML (`.man`/`.xml`) catalogs are also accepted when provider events reference localization strings such as `message="$(string.Provider.Event.message)"`; the loader resolves the string table value, maps manifest insertions such as `%1`/`%2` through the event template's ordered `<data name="...">` fields, records `source_type=windows-event-manifest`, and keeps the same provenance chain. This is still not a replacement for automatic provider DLL/resource-table extraction across real systems.

For report-grade wording, #2 now has a separate `evtx-rendered-message-diff-v1` gate. It compares RapidTriage rendered messages with Windows Event Viewer, EvtxECmd, Hayabusa, Chainsaw, or Velociraptor rendered-message exports by EventRecordID after whitespace/HTML normalization. If the trusted rendered message is absent or differs from RapidTriage output, `trusted-rendered-message-diff-required` stays attached and the allowed use remains triage-only wording.

For #3 EVTX recovery candidates, native rows now include a confidence band, positive confidence factors, confidence penalties, and a reportability decision object. Slack/deleted/corrupt records remain `do-not-report-as-fact` and `triage-pivot-only` until secondary parser confirmation, source hash/chunk context, and known-answer or case-specific validation notes are attached.

#3 also has an `evtx-recovery-corpus-diff-v1` gate for deleted/corrupt recovery validation. It compares recovered candidates with a hand-labeled corpus or second-parser recovery export by byte offset, record SHA256, declared size, allocation status, and recovery status. Any unmatched offset, hash mismatch, or extra oracle row keeps `deleted-corrupt-recovery-corpus-diff-required` attached and prevents recovered EVTX candidates from being reported as facts.

For #4 Registry key-tree reconstruction, native hive and key-tree rows now record transaction-log evidence separately from replay support. If sibling `LOG1`/`LOG2` files are present, output records `present-not-replayed` with log names, sizes, and hashes; if absent, it records explicit absence. This helps analysts distinguish “no transaction context supplied” from “transaction context supplied but not replayed,” while preserving the commercial blocker until real replay/diff validation exists.

#4 now also has a `registry-key-tree-diff-v1` helper. It compares RapidTriage native key-tree rows with Registry Explorer, RegRipper, python-registry, RECmd, or exported `.reg`-style trusted rows by normalized key path, value names, last-write timestamp, and root reachability. Without a clean trusted key-tree diff, the #4 accuracy gate leaves `trusted registry key-tree diff pass` missing and `registry-key-tree-cross-tool-diff-required` remains a commercial blocker.

For #5 Registry deleted key/value recovery, recovered `nk`/`vk` rows now carry allocator context and an explicit reportability decision. Positive-size free cells are preserved as `free-cell-candidate-validation-required`, transaction-log status is copied onto each recovery candidate, and the row-level decision remains `do-not-report-as-fact` with `triage-pivot-only` allowed use. This makes deleted-cell output usable for investigation without letting analysts accidentally promote stale or partially overwritten cells to report-defensible facts before second-parser offset confirmation, transaction-log replay/diff evidence, and known-answer deleted-cell corpus validation are attached.

#5 now includes a `registry-deleted-cell-diff-v1` helper. It compares deleted/free key and value candidates with hand-labeled corpus rows or trusted parser review output by cell offset, candidate class, name, data-preview hash, and parent key path. Any offset gap or field mismatch keeps `registry-deleted-cell-cross-tool-diff-required` attached, and the row remains `do-not-report-deleted-cell-as-fact`.
