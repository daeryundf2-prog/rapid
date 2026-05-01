# RapidTriage #1-#40 Accuracy Profiles

This document explains the validation and accuracy layer for commercial-parity backlog items #1 through #40.

The goal is not to overclaim that every parser is commercial-grade. The goal is to make every parser claim measurable: each item now has a machine-readable profile that states the artifact surface, required known-answer corpus, independent oracle, required checks, minimum evidence, and reportability gate.

## How To Use

Run:

```bash
rapidtriage validation --output-dir ./validation --overwrite
```

The generated `rapidtriage-validation-package.json` includes `core_forensics_accuracy_profiles`.

It also includes `core_forensics_known_answer_template`, a 40-dataset skeleton that can be copied into a real known-answer manifest after evidence paths, expected assertions, observed outputs, and pass/fail status are filled in.

For each #1-#40 item, attach evidence before report-grade wording:

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

## Court/Report Posture

Every #1-#40 profile defaults to `validation-required`. This is deliberate. A parser may be useful for triage while still needing known-answer, cross-tool, or independent validation before a report can claim commercial-grade certainty.
