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

## Pending

- [ ] `fls -rp` export completion → `fls-coverage-diff.py` run
- [ ] RapidTriage seizure run `0be94beb4160` completion → artifact row counts
      per type vs the AXIOM category list in `axiom-coverage-comparison-2026-10-06.md`
- [ ] Reviewer sign-off to graduate any figure above into Release Evidence
