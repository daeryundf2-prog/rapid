# RapidTriage Core Forensics #11-#15 Validation

This package records the current internal fixture validation for #11 through #15:

- #11 Windows.edb native ESE search-index evidence
- #12 `$MFT` native FILE record evidence
- #13 `$UsnJrnl` native change-record evidence
- #14 JumpList DestList and embedded LNK evidence
- #15 ShellBags native user-hive evidence

## What Is Validated

The internal fixtures assert that RapidTriage emits reviewable rows with source hashes, parser versions, row/page/record provenance, `forensic_review`, commercial blockers, and `core_accuracy_gates` for the implemented evidence surfaces.

This batch now also includes trusted-diff helper gates for #11~#15. The helpers compare RapidTriage rows against recognized external/reference parsers and only satisfy the new commercial-readiness checks when there is a clean row-level match with no missing rows, no extra rows, no field mismatches, and a recognized trusted tool name. Fixture parsing alone intentionally leaves those checks missing.

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

## Trusted Diff Gates Added

- #11: `build_windows_edb_trusted_diff` compares Windows.edb path, URL, content, deleted/index-state, and table-family fields against `esentutl`, `libesedb`, `esedbexport`, WinSearchDBAnalyzer, or equivalent exports.
- #12: native MFT rows now apply USA sector-trailer restoration before attribute decoding, resolve `$ATTRIBUTE_LIST` extension references when the base and extension records are present in the same bounded MFT scan window, and `build_mft_trusted_diff` compares MFT record number, parent reference, path, timestamp, and deleted-state fields against MFTECmd/TSK-style exports.
- #13: `build_usn_trusted_diff` compares USN, FRN, parent FRN, filename/path, reason, and timestamp fields against MFTECmd/UsnJrnl2Csv-style exports. `build_usn_state_replay_trusted_diff` separately compares derived create/rename/delete state transitions against known-answer or trusted replay transition rows so record-level parser agreement is not mistaken for state-machine replay validation.
- #14: `build_jumplist_trusted_diff` compares AppID, DestList entry/stream ID, target path, timestamp, and MRU/pin fields against JLECmd/LECmd-style exports.
- #15: `build_shellbag_trusted_diff` compares source key/folder path, bag ID, node ID, timestamp, and source hive fields against ShellBagsExplorer/SBECmd-style exports.

These helpers are validation gates, not a shortcut to a commercial claim. They need real tool outputs, source hashes, tool versions, command lines, corpus scope, and reviewer sign-off before a release can call the related parser commercial-grade.

## Current Blockers Kept

- #11: full native ESE catalog/table/row decoding, authoritative row timestamps/properties, deleted/index-state validation.
- #12: attribute-list extension resolution, full nonresident runlist decoding, full-volume parent path reconstruction.
- #13: full FRN path-cache replay, million-record cursor resume validation, timeline replay/correlation.
- #14: OS-version-specific DestList field semantics, deleted-entry recovery, AppID mapping database.
- #15: binary shell-item payload decoding, transaction log replay, deleted/slack ShellBag validation.
