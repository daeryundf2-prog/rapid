# Windows T1 Operator Inputs

Status: partially filled (environment + staging stage recorded); approvals and acquisition still pending
Date: 2026-08-30
Filled by: ZCode automated Phase 1 staging (not a human signoff)

Fill this file before a real Windows T1 E01/Ex01 execution. Do not enter secrets, tokens, customer data, or actual case data.

| Field | Value | Required | Notes |
| --- | --- | --- | --- |
| `external_corpus_root` | `C:\Users\Daeryun\rapid-forensic-corpus` | yes | Outside Git; runbook layout created (source-tree, images, manifests, trusted-exports, rapid-results, diffs, logs, hashes, reviews, bundle). |
| `case_id` | `case-t1-windows-synthetic` | yes | Synthetic T1 case identifier. |
| `operator_name` | `<pending>` | yes | Requires human assignment before acquisition. |
| `reviewer_name` | `<pending>` | yes | Requires human assignment before review. |
| `windows_version` | `Windows 11 Pro (build 10.0.26200.9168)` | yes | Recorded 2026-08-30. |
| `timezone` | `Korea Standard Time (UTC+09:00)` | yes | `tzutil /g` = `Korea Standard Time`. |
| `python_version` | `3.12.8` | yes | `python --version`. |
| `rapid_commit` | `c1c5be0ea7f68f4b1d04894ed8191ad2a2f71d85` (tag v0.2.0) | yes | Baseline for this staging run. |
| `acquisition_tool` | `<pending>` | yes | `ewfacquire`/`ftkimager` absent on host at staging time; E01 acquisition blocked until an approved tool is installed. |
| `ex01_capable_tool` | `<pending>` | conditional | Same blocker as acquisition tool. |
| `trusted_tool_paths` | `C:\Users\Daeryun\rapid-forensic-corpus\tools\` (EvtxECmd 2026.5.0, LECmd 2026.5.0, JLECmd 2026.5.0, RECmd 2026.5.0, PECmd 2026.5.0, MFTECmd 2026.5.0, SrumECmd 2026.5.0) | yes | Downloaded from download.ericzimmermanstools.com/net9; RECmd/PECmd/MFTECmd/SrumECmd awaiting admin-gated artifacts (hives, Prefetch, MFT, SRUDB). |
| `retention_policy` | Synthetic fixtures retained while T1 evidence is approved; dispose per operator policy | yes | Mirrored in `manifests/t1-source-tree-manifest.json`. |
| `license_restrictions` | Synthetic-only corpus; no vendor outputs collected yet; vendor-license review pending before trusted tool exports | yes | To be re-filled when trusted tools are installed. |
| `evidence_storage_access_control` | Single-operator local host; external corpus directory is user-profile scoped; formal ACL record pending | yes | Must be re-recorded for shared storage. |
| `review_ticket` | `<pending>` | yes | Assign before review stage. |
| `long_path_policy` | `LongPathsEnabled=1` | yes | Registry `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`. |
| `ntfs_volume_id` | `C:` NTFS fixed volume (serial not recorded; record at acquisition) | required after creation | Source tree staged on the system drive NTFS volume. |
| `e01_image_path` | `<pending acquisition>` | required after acquisition | Will live under `<external_corpus_root>/images/e01/`. |
| `ex01_image_path` | `<pending acquisition>` | conditional | Under `<external_corpus_root>/images/ex01/`. |
| `trusted_export_path` | `<pending export>` | required after export | Under `<external_corpus_root>/trusted-exports/`. |
| `rapid_results_path` | `<pending run>` | required after run | Under `<external_corpus_root>/rapid-results/`. |
| `diff_result_path` | `<pending diff>` | required after diff | Under `<external_corpus_root>/diffs/`. |

## Completed Staging Record (2026-08-30)

- T1 synthetic source tree staged at `<external_corpus_root>/source-tree/files/`
  (byte-identical copy of the Tier 0 fixture tree; 9 files, including the
  Korean filename and space-containing filename).
- Per-file SHA-256 and size recorded under `hashes/`.
- Truth manifest written to `manifests/t1-source-tree-manifest.json`
  (`rapidforensic-e01-ex01-truth-manifest-v1`, folder-baseline stage).
- `scripts/known-answer-qc.py --check-files` result: PASS, 9/9 files checked,
  0 errors (see `logs/known-answer-qc-t1-source-tree.json`).
- Windows smoke run output: `logs/windows-smoke/` — smoke summary PASS
  (doctor/sample/search/benchmark/validation/evidence-guidance/web/
  workbench-smoke-contract all pass on Windows 11 Pro 26200).
- E01/Ex01 acquisition: NOT executed (no approved acquisition tool on host).

## Phase 2 Trusted Diff Record (2026-08-30)

- Trusted tools staged under `<external_corpus_root>/tools/` (Zimmerman net9
  builds): EvtxECmd, LECmd, JLECmd, RECmd, PECmd, MFTECmd, SrumECmd — all
  2026.5.0. Only EvtxECmd/LECmd/JLECmd were executable against non-admin
  artifacts so far.
- Host artifacts staged under `source-artifacts/` (wevtutil epl exports of
  System/Application full + 24h channels, 197 LNK, 339 JumpList containers),
  SHA-256 recorded in `source-artifacts/source-artifacts-hashes.json`.
- Rapid outputs in `rapid-results/`, reference exports in `trusted-exports/`,
  diff reports and `recovery-accuracy.json` in `diffs/`.
- Findings: LNK field-level trusted diff PASS (234/234); JumpList entry-level
  rows not emitted by RapidForensic (gap documented); EVTX record identity
  mismatch (physical header id vs BinXML EventRecordID) blocks record-level
  diff — BinXML EventRecordID surfacing is the next required parser fix.
- Registry/MFT/USN/SRUM/Prefetch/Amcache diffs pending an elevated host.

## Approval Checkboxes

- [x] External evidence storage approved. (operator-provided local path outside Git)
- [x] Synthetic-only source tree approved. (byte-identical Tier 0 fixture copy)
- [ ] Disk creation/formatting command approved.
- [ ] E01 acquisition command approved.
- [ ] Ex01 acquisition command approved or explicitly skipped.
- [ ] Trusted/reference export command approved.
- [x] RapidForensic actual run approved. (smoke run + folder-baseline QC only)
- [x] No Git storage for binary evidence confirmed.
- [ ] Technical review owner assigned.
- [ ] Methodology review owner assigned.
- [ ] Operator review owner assigned.
- [ ] Legal review owner assigned.

## Not Evidence

This document is an input form. It is not proof that E01/Ex01, trusted export, RapidForensic execution against a real E01/Ex01, or review has been completed. The folder-baseline known-answer QC and the smoke run do not substitute for trusted-tool diffs or independent validation.
