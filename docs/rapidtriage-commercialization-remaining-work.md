# RapidForensic Commercialization Remaining Work

Last checked with:

```bash
python -m rapidtriage commercial-readiness --output-dir /tmp/rapidforensic-readiness-current --json
```

Current baseline state without attaching a validation package:

- Readiness score: `81/100`
- Implemented gate: `120/120`
- Usable gate: `120/120`
- Validated gate: `0/120`
- Commercial-grade gate: `0/120`
- Commercial claim: not allowed

Current state when the internal `#1-#5` known-answer validation package is generated and attached:

- Validated gate: `5/120`
- Commercial-grade gate: `0/120`
- Commercial claim: not allowed

This means RapidForensic has broad analyst-facing triage functionality, but it must not be described as AXIOM/WISDOM-class or court-ready commercial parity yet. The remaining work is mostly proof depth, native parser completeness, large-evidence performance proof, platform packaging proof, and independent validation.

## Remaining Work Groups

1. Core Windows forensic parser depth `#1-#25`: finish native EVTX BinXML/message rendering/recovery, Registry transaction replay/deleted cells, SAM/SECURITY/SYSTEM deep decoding, Amcache/ShimCache/BAM/SRUM/Windows.edb/ESE/MFT/USN/JumpList/ShellBags/Prefetch/LNK/browser/AI transcript/image workflow validation.
2. Mobile, cloud, app, messenger, and email `#26-#45`: add provider schema matrices, authorized export fixtures, encrypted-store limitation gates, app-version compatibility evidence, mailbox/cloud API pagination/backoff/token security proof.
3. Search, analysis, and UX `#46-#65`: prove massive clustering/entity/graph/timeline/workbook/reviewer/compare/viewer/OCR/search/report-citation/evidence-history workflows with real analyst-scale fixtures and UI performance evidence.
4. Large-scale performance `#66-#80`: collect 100k/1M/10M and 1TB-10TB benchmark JSON, enforce streaming/checkpoint/cursor APIs, isolate parser crashes, cap memory, sandbox preview, and publish cancellation/retry behavior.
5. Validation and legal defensibility `#81-#100`: build NIST/CFReDS/CFTT known-answer packages, parser FP/FN reports, independent validation signoff, chain-of-custody, audit hash chain, provenance completeness, timezone/skew/contamination checks, and court exhibit export proof.
6. Deployment and operations `#101-#120`: produce signed Windows installer, notarized macOS package, Linux packages, update channel, crash redaction, local-only enterprise proof, RBAC/server/collaboration hardening, backup/migration drills, support/training/admin docs, sandboxing, and dependency advisory CI.

## Next Internal Queue

The next tasks should keep reducing real blockers, not just wording:

1. `#2` EVTX event template/message rendering: support Windows Event Manifest XML catalogs and preserve provider resource provenance.
2. `#1` EVTX BinXML: expand token/value grammar and compare record-level output against trusted EVTX exports.
3. `#3` EVTX recovery: add more corrupt/slack/deleted fixtures with offset, confidence, and non-reportable defaults.
4. `#4` Registry tree: implement transaction-log replay evidence paths and malformed hive tests.
5. `#5` Registry deleted recovery: validate deleted key/value candidates against allocator state and second-parser fixtures.

## External Evidence Blockers

These cannot be honestly closed by code alone in the current local environment:

- Independent validation reports and reviewer signoff.
- Real NIST/CFReDS/CFTT or equivalent known-answer corpora for every parser claim.
- EvtxECmd/Hayabusa/RECmd/other trusted-tool diff outputs for real evidence sets.
- Actual 1TB-10TB hardware benchmark logs and p95 memory/latency evidence.
- Authenticode signing, Apple notarization, commercial support desk/SLA execution, and enterprise deployment proof.

When blocked by those, continue implementing internal code, tests, docs, and validation-package hooks, but keep `commercial_grade_ready=false`.
