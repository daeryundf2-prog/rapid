# Real-image engineering measurement — BSH 126 GB E01 (2026-10-06)

Status: **Engineering Baseline** (per `AGENTS.md`, this is not Release Evidence —
no reviewer sign-off, no second-operator reproduction).

## Evidence source

- Image: `D:\devin\bsh-e01\BSH.E01`–`BSH.E17` (17 segments, 126.3 GB total)
- Main NTFS partition: GPT slot 006, sector offset 567296 (≈228 GB span)
- Volume serial: 52A8F718A8F6F975; MFT entry range 0–1,422,080

## Trusted-tool reference exports (Sleuth Kit 4.15.0)

- `ils -e -o 567296 BSH.E01` → `bsh-ils.txt` (95 MB, 1,379,052 lines)
- `icat -o 567296 BSH.E01 0` → `bsh-mft.bin` (1.46 GB raw MFT)
- `fls -rp -o 567296 BSH.E01` → `bsh-fls.txt` (in progress at time of writing)

## Result — `scripts/mft-reference-diff.py` output (`bsh-mft-diff.json`)

| Metric | Value |
|---|---|
| Raw MFT records parsed | 1,423,368 |
| ils inode coverage | **99.9999%** (1,379,048 / 1,379,049; parser missed 1) |
| Deleted-flag detection | precision **1.0**, recall **1.0** (TP 731,301 / FP 0 / FN 0) |
| Attribute flag agreement | 1.0 |
| Size agreement (common inodes) | **99.9958%** (811,884 / 811,918) |
| Path agreement | pending `fls` completion |

Input hashes: MFT sha256 `ab00ad06…f12d`, ils sha256 `4e5b31f4…894ca`
(full values in `bsh-mft-diff.json`, kept outside Git with the image).

## Interpretation

- The native Python MFT parser (dissect.ntfs path) matches Sleuth Kit's
  deleted/in-use flag classification exactly on 1.38 M real records.
- The 34 size mismatches (0.0042%) and 1 missed inode are the residual gap;
  samples are listed in the diff JSON for follow-up.
- This measures the *extraction/parser layer* only. Artifact-layer row
  parity (the AXIOM comparison axis) still requires the `0be94beb4160`
  seizure-mode run to finish; `fls-coverage-diff.py` will compare our
  `files.json` against `bsh-fls.txt` once both complete.

## `fls -rp` export — completed (780,645 entries)

`fls` produced 623,770 allocated file paths, 93,219 dir paths,
63,656 deleted entries.

**Important caveat**: the `_e01/filesystem` tree inherited from the
2025-09-24 run was extracted incompletely (`stage-status.completed =
false`, 92,173 files on disk). A first `fls-coverage-diff` against
that partial tree shows 8.7% coverage — measuring the *incomplete
extraction*, not parser parity. The resumed seizure run
`0be94beb4160` is completing extraction; re-run the diff against the
run's real `files.json` when it finishes. Samples of the current gap
(mostly NTFS 8.3 aliases, `$Extend` ADS streams, `$RECYCLE.BIN`
recovered items) are in `bsh-fls-diff.json` next to the image.

## Engine fix — mmls mojibake partition selection (2026-10-06)

The resumed native run `0be94beb4160` was cancelled: on this Windows TSK
build `mmls` prints GPT partition names as `?????`, so
`mmls_first_filesystem()` found no filesystem token and the pipeline
silently stayed on the engineering-grade `python-native-ewf` path
(estimated days for 624k files). Fix (commits `0a3f955`, `374f424`):
when no description token matches, select the largest data partition and
label `selection_source = largest-data-partition-unknown-filesystem`;
fsstat/tsk_recover fail loudly if the pick is wrong. On BSH this picks
start sector 567296 — the same 233.9 GB NTFS partition verified earlier
with `fsstat`.

A replacement run `0f1f32c78b0a` (output `rt-run-tsk/`) was started with
`RAPIDTRIAGE_E01_ENGINE=external`; its stage checkpoint records
`mount_strategy: sleuthkit-direct-ewf`, `recovery_tool: tsk_recover -e`,
selected start sector 567296 — the trusted-tool path, not the native
fallback. The earlier native run's numbers remain engineering evidence
only.

## `tsk_recover -e` extraction vs `fls -rp` — measured 2026-10-08

The first external-engine run `0f1f32c78b0a` was killed by the fixed
3600 s child timeout at ~190k files (rc=124). Timeout was changed to a
partition-size-proportional bound (commit `835a42c`, ~12.4 h for the
234 GB partition) and the run retried as `8c821ed6a78d`.

`tsk_recover` completed after ~19.5 h and wrote **646,661 files** to
`rt-run-tsk/_e01/filesystem`. Path-level comparison against the
`fls -rp` allocated namespace (623,770 paths), run against a synthesized
`files.json` of the extracted tree (`bsh-extracted-files-tsk.json`,
sha256 `6df0433e…c3c85`):

| Metric | Value |
|---|---|
| fls allocated paths covered by extraction | **589,929 / 623,770 = 94.57%** |
| fls allocated paths not extracted | 33,841 |
| extracted paths absent from fls allocated set | 56,732 |

Breakdown of the 33,841 uncovered paths:

- **27** NTFS metafiles (`$MFT`, `$LogFile`, `$Boot`, `$Secure:$*`,
  `$Extend/$UsnJrnl`, …) — `tsk_recover` does not emit metafiles as
  regular files; they are recovered via `icat`/system-artifact capture
  (`$MFT` was extracted separately at 1.46 GB for the MFT diff above).
- **1,825** alternate data streams (`:Zone.Identifier`, `:encryptable`,
  …) — `tsk_recover` does not write ADS as standalone files.
- **~31,989** regular paths, dominated by `Users/user` (27,363),
  `ProgramData/Microsoft` (1,797), `Windows/SoftwareDistribution`
  (1,688). MFT-level check on 3,000 sampled inodes: **2,762 are
  zero-byte** (92%) — `tsk_recover` skips files with no data runs by
  design. The remaining ~8% are small (45–~200 B) files; likely the
  same zero-content/near-empty class plus isolated extraction errors
  recorded in stderr (`Error writing file`, compressed-deleted-entry
  decompress failures).

Of the 56,732 extracted-but-not-in-fls-allocated paths, 2,649 sit under
`$Extend/$Deleted` (deleted entries recovered by `-e`); the remainder
are recovered deleted content placed elsewhere plus 8.3 alias names —
consistent with the 63,656 deleted entries `fls` enumerated but
excluded from the allocated set.

**Verdict**: the trusted-tool extraction covers **94.6%** of the fls
allocated file namespace; the 5.4% gap is almost entirely structural
(NTFS metafiles, ADS, zero-byte records), not lost user content.
Engineering check only — Release Evidence still requires reviewer
sign-off and artifact-layer row parity.

## Pending

- [x] `fls -rp` export (780,645 entries)
- [x] `fls-coverage-diff` baseline against the *partial* tree
      (8.7% — incomplete extraction artifact, not parity verdict)
- [x] Engine switched to trusted-tool path for the parity run
      (`0f1f32c78b0a`, `sleuthkit-direct-ewf` + `tsk_recover -e`)
- [x] `tsk_recover -e` extraction completed (646,661 files, ~19.5 h)
- [x] `fls-coverage-diff` against the real extracted tree —
      **94.57%** allocated-path coverage; gap = metafiles + ADS +
      zero-byte records (see breakdown above)
- [ ] Triage/collection of the extracted tree → artifact row counts
      per type vs the AXIOM category list in
      `axiom-coverage-comparison-2026-10-06.md`
- [ ] Reviewer sign-off to graduate any figure above into Release Evidence

## Run failure — 8c821ed6a78d (2026-10-08 21:38 UTC)

Run `8c821ed6a78d` **failed** after 41.7 h total during the
`manifest` stage write. Recorded detail:

- Error: `Object of type bytes is not JSON serializable`.
- `rapidtriage-manifest.json` (7.2 GB) was **truncated mid-stream**
  (`"IdBlob": ` at file tail) when `json.dump` hit a bytes value
  inside the manifest payload.
- Root cause — code-version skew: the running server process
  (started 2026-10-07 12:59 KST) had loaded `write_result()`
  **without** `default=json_default`. Current HEAD already contains
  the fix (`json_default` encodes bytes losslessly as
  `{"__type__": "bytes", "hex": …}`), so the crash cannot recur on a
  restarted server.
- Preserved outputs: `_e01` extraction tree (646,661 files),
  `rapidtriage-run-fingerprint.json`, `rapidtriage-e01.json`,
  `rapidtriage-docs-index.json` (5.2 GB, valid JSON — verified tail).
- Lost outputs: `rapidtriage-manifest.json` (truncated — unusable),
  `rapidtriage-docs.json`, `rapidtriage-files.json` (never written).
- Per-stage timing: `bsh-run-timing.json` — prepare <1 s,
  `tsk_recover` extraction ~7 h, scan/collect inside `triage`
  ~34.6 h until the manifest write crash.
- Structural lesson: the ~33 h file-scan stage holds its results
  only in memory and writes `files.json` at the end; a late crash
  forfeits all of it. Incremental persistence of scan/artifact
  output is required for large-case viability.
