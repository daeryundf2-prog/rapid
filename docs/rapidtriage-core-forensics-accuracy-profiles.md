# RapidTriage #1-#100 Accuracy Profiles

This document explains the validation and accuracy layer for commercial-parity backlog items #1 through #100.

The goal is not to overclaim that every parser is commercial-grade. The goal is to make every parser claim measurable: each item now has a machine-readable profile that states the artifact surface, required known-answer corpus, independent oracle, required checks, minimum evidence, and reportability gate.

## How To Use

Run:

```bash
rapidtriage validation --output-dir ./validation --overwrite
```

The generated `rapidtriage-validation-package.json` includes `core_forensics_accuracy_profiles`.

It also includes `core_forensics_known_answer_template`, a 100-dataset skeleton that can be copied into a real known-answer manifest after evidence paths, expected assertions, observed outputs, and pass/fail status are filled in.

For each #1-#100 item, attach evidence before report-grade wording:

- Source file or export hash.
- Tool/parser version and command.
- Expected-answer manifest.
- Observed RapidTriage output.
- Record-level or row-level diff.
- Reviewer sign-off and limitation note.

## Pass/Fail Rule

- `pass`: every required check has explicit observed evidence.
- `fail`: parser output loses record order, source path/hash, record ID, offset, required timestamp semantics, or secret redaction.
- `open`: fixture evidence exists but broad corpus, cross-tool, or independent validation is missing.
- `blocked`: recovered/deleted/native-candidate artifacts are reportable without secondary validation.

## Scope

The profiles cover:

- #1-#5: EVTX and Registry correctness, recovery, and deleted/corrupt evidence handling.
- #6-#18: Windows account, execution, ESE, NTFS, JumpList, ShellBags, Prefetch, LNK, and system artifact accuracy.
- #19-#21: Browser and AI artifact validation, privacy, and completeness warnings.
- #22-#25: Evidence image/container handling, hashes, partition provenance, and export-first limitations.
- #26-#30: Vendor mobile exports, iOS/Android artifacts, APK risk triage, schema validation, and legal gates.
- #31-#35: KakaoTalk, WhatsApp, Telegram, Signal, and extended messenger export/database evidence boundaries.
- #36-#40: Email mailbox parsing, Google/iCloud/Microsoft 365 cloud exports, and cloud API acquisition workflow.
- #41-#45: Cloud credential handling, browser secret inventory, mobile correlation, unified mobile actor view, and app schema version management.
- #46-#50: Search-result clustering, entity pivots, relationship graphing, timeline correlation, and hypothesis/workbook review aids.
- #51-#55: Reviewer workflow, multi-evidence compare, raw hex, SQLite, and email conversation viewers.
- #56-#60: Image gallery review, media transcript preview, OCR queue, Korean OCR/translation workflow, and search hit deduplication.
- #61-#65: Advanced search modes, keyword packs, IOC/TI enrichment, report citations, and evidence selection history.
- #66-#70: Benchmarking, stress-test runbooks, incremental indexing, background jobs, and stage checkpoint/resume.
- #71-#75: Parser crash isolation, memory cap enforcement, preview sandboxing, large SQLite/FTS optimization, and parallel parser scheduling.
- #76-#80: File hash caching, duplicate detection, cursor pagination, UI virtualization, and long-running cancellation/retry.
- #81-#85: Known-answer validation, fixture corpus, FP/FN documentation, independent validation report intake, and validation package automation.
- #86-#90: Chain of custody, acquisition hashes, immutable audit hash chains, report reproducibility, and report item provenance completeness.
- #91-#95: Parser confidence scoring, validation warning UX, legal limitations, court exhibit packages, and external tool version capture.
- #96-#100: Acquisition/write-blocker metadata, timezone validation, clock-skew analysis, contamination warnings, and tamper-evident audit bundles.

## Court/Report Posture

Every #1-#100 profile defaults to `validation-required`. This is deliberate. A parser may be useful for triage while still needing known-answer, cross-tool, or independent validation before a report can claim commercial-grade certainty.
