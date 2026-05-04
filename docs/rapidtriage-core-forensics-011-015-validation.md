# RapidTriage Core Forensics #11-#15 Validation

This package records the current internal fixture validation for #11 through #15:

- #11 Windows.edb native ESE search-index evidence
- #12 `$MFT` native FILE record evidence
- #13 `$UsnJrnl` native change-record evidence
- #14 JumpList DestList and embedded LNK evidence
- #15 ShellBags native user-hive evidence

## What Is Validated

The internal fixtures assert that RapidTriage emits reviewable rows with source hashes, parser versions, row/page/record provenance, `forensic_review`, commercial blockers, and `core_accuracy_gates` for the implemented evidence surfaces.

The #11~#15 rows also emit reportability decisions in their commercial-uplift evidence. Windows.edb native rows remain `search-index-triage-pivot` until ESE catalog/table/row and deleted-state validation exists. `$MFT` rows stay record-structure/timestamp pivots until attribute-list, runlist, and full-volume parent path reconstruction are diffed. `$UsnJrnl` rows stay change-record pivots until full FRN path-cache replay and large-journal cursor validation are complete. JumpList rows stay recent-destination pivots until DestList version semantics, deleted-entry recovery, and AppID mapping are validated. ShellBags rows stay folder-view-history pivots until binary shell item decoding, BagMRU/Bags relationship validation, transaction logs, and deleted/slack validation are attached.

The manifest is:

```bash
rapidtriage validation \
  --known-answer-manifest docs/validation/rapidtriage-core-forensics-011-015-known-answer.json \
  --output-dir /tmp/rapidtriage-validation-011-015
```

Attach the generated validation package to readiness scoring:

```bash
rapidtriage commercial-readiness \
  --validation-package /tmp/rapidtriage-validation-011-015/rapidtriage-validation-package.json \
  --output-dir /tmp/rapidtriage-commercial-011-015
```

## Claim Boundary

Passing this package means `implemented + usable + validated` for the internal fixture claims. It does not mean commercial-grade parity with AXIOM/WISDOM/EnCase.

Commercial-grade still needs:

- Cross-tool row/record diffs against MFTECmd, UsnJrnl2Csv, JLECmd, LECmd, ShellBagsExplorer/SBECmd, libesedb/esedbexport, or equivalent trusted tools.
- Larger OS-version corpora and damaged/deleted/slack cases.
- Independent reviewer sign-off.
- Large-volume stress and repeatability evidence.

## Current Blockers Kept

- #11: full native ESE catalog/table/row decoding, authoritative row timestamps/properties, deleted/index-state validation.
- #12: attribute-list extension resolution, full nonresident runlist decoding, full-volume parent path reconstruction.
- #13: full FRN path-cache replay, large journal pagination validation, timeline replay/correlation.
- #14: OS-version-specific DestList field semantics, deleted-entry recovery, AppID mapping database.
- #15: binary shell-item payload decoding, transaction log replay, deleted/slack ShellBag validation.
