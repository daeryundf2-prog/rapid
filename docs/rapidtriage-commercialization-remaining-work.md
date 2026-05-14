# RapidForensic Commercialization Remaining Work

Last checked with:

```bash
python -m rapidtriage commercial-readiness --output-dir /tmp/rapidforensic-readiness-current --json
python -m rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --json
python -m rapidtriage taxonomy-audit --repo-root /Users/shinyoohag/rapidforensic/repo --strict --json
```

Current baseline state without attaching a validation package:

- Readiness score: `88/100`
- Implemented gate: `120/120`
- Usable gate: `120/120`
- Validated gate: `0/120`
- Commercial-grade gate: `0/120`
- Commercial claim: not allowed

Current state when the internal `#1-#120` known-answer validation package is attached:

- Readiness score: `90/100`
- Implemented gate: `120/120`
- Usable gate: `120/120`
- Validated gate: `120/120`
- Commercial-grade gate: `0/120`
- Commercial claim: not allowed

Current user-visible taxonomy gate:

- `taxonomy-audit --strict`: pass
- User-visible forensic targets: `51/51` covered
- Artifact collector count: `23`
- Artifact type literals/dynamic registrations: `171`

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

1. `#1~#5` EVTX/Registry native depth: raise BinXML, message rendering, recovery, registry transaction replay, and deleted allocator validation beyond triage pivots.
2. `#6~#15` Windows core artifacts: deepen SAM/SECURITY/SYSTEM, Amcache/ShimCache/BAM, SRUM/Windows.edb/ESE, MFT/USN, JumpList, and ShellBags native decoders.
3. `#16~#25` execution/browser/image workflows: harden Prefetch/LNK/System artifacts, browser/AI transcripts, E01/RAW/VM image workflows, and export-only image-family gates.
4. `#66~#80` 대용량: attach repeatable local benchmark/stress evidence, cursor/drop-row checks, memory/cancel/retry proofs, and hardware profile logs.
5. `#81~#100` 법정성: attach NIST-style corpus evidence, trusted-tool diffs, provenance completeness, chain-of-custody, audit hash chain, and exhibit bundle proofs.
6. `#101~#120` 배포/운영: attach real platform build/signing/smoke/security evidence where possible and keep impossible items as external blockers.

## External Evidence Blockers

These cannot be honestly closed by code alone in the current local environment:

- Independent validation reports and reviewer signoff.
- Real NIST/CFReDS/CFTT or equivalent known-answer corpora for every parser claim.
- EvtxECmd/Hayabusa/RECmd/other trusted-tool diff outputs for real evidence sets.
- Actual 1TB-10TB hardware benchmark logs and p95 memory/latency evidence.
- Authenticode signing, Apple notarization, commercial support desk/SLA execution, and enterprise deployment proof.

When blocked by those, continue implementing internal code, tests, docs, and validation-package hooks, but keep `commercial_grade_ready=false`.
