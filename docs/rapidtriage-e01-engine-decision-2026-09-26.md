# E01 Decoding Engine Decision — 2026-09-26

Status: accepted (engineering-grade). Real-evidence sign-off remains a
separate gate per the RapidForensic Validation Contract.

## Context

`extract_e01_to_directory` previously required `ewfmount`, `mmls`, and
`tsk_recover` on PATH and only fell back to the in-process
`pyewf + dissect.ntfs` path (`rapidtriage/core/e01_native.py`) when the
external tools were blocked. On locked-down Windows workstations (no FUSE,
no WSL2, no Sleuth Kit install rights) E01 ingestion depended entirely on
the fallback path while the product surface described it as experimental.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| External `ewfmount` + Sleuth Kit | Trusted-tool provenance; `fls`/`tsk_recover` coverage incl. non-NTFS filesystems | Requires FUSE/WSL2 or a TSK install; subprocess orchestration; unusable on closed-network Windows |
| **Native `pyewf` + `dissect.ntfs`** (chosen default in `auto`) | In-process, no drivers, works offline on Windows; native MBR/GPT enumeration; allocated tree walk + deleted-record MFT sweep; dumps `$MFT` for `mft-reference-diff` | NTFS only; best-effort deleted sweep (no unallocated-dir recursion like `fls`); engineering-grade, not a trusted-tool substitute |
| `pytsk3` | One binding covers EWF open + volume + FS, incl. FAT/exFAT; familiar TSK semantics | Heavier native dependency with platform build pain historically; duplicates what pyewf+dissect already covers for NTFS; keeps TSK lineage without adding independent cross-validation value |
| Rust `engines/rapidcore` | Highest throughput ceiling | Workspace incomplete; no EWF decoder today; premature before parsing contract stabilizes (R4) |

`dissect.evidence` was also evaluated: it reads EWF/QCOW/VHD in pure Python
but adds a second EWF implementation without clear gain over the pyewf
binding already exercised by the codebase.

## Decision

`extract_e01_to_directory` gains an `engine` parameter
(`RAPIDTRIAGE_E01_ENGINE` env override): `auto` (default), `native`,
`external`.

- `auto`: native first when `pyewf` + `dissect.ntfs` import; on native
  failure the run records a `native-filesystem-recovery` failure entry in
  command history and falls through to the external path.
- `native`: forces the in-process path; errors if modules are missing.
- `external`: forces ewfmount/Sleuth Kit; blocked error if tools missing.

Provenance marks `mount_strategy: python-native-ewf` and
`tool_inputs.engine_note` (`preferred`/`requested`/`fallback`) so reports
keep the distinction between trusted-tool and native decode.

## Install

```bash
pip install "rapidtriage[native-e01]"   # dissect.ntfs + libewf-python(pyewf)
```

## Validation wiring (R1-4)

- Native extraction writes `$MFT` to `<stage>/_system/MFT.bin` → input for
  `scripts/mft-reference-diff.py`.
- Recovered tree feeds the normal run → `rapidtriage-files.json` →
  `scripts/fls-coverage-diff.py` vs `fls -rp`.
- Tier-0 known-answer fixtures (`known-answer-qc`, `trusted-diff`) remain
  engineering checks only — real-image + trusted-tool output still required
  for release evidence.

## Consequences / open limits

- Native path remains NTFS-only; unsupported-FS partitions fall through to
  external tools in `auto` or raise in `native`/`external`.
- Deleted-file coverage is a bounded MFT sweep (`_deleted_mft/`), not
  `fls` unallocated recursion — coverage gap vs TSK expected; measure via
  `fls-coverage-diff` on real images.
- `pytsk3` stays an evaluated-but-deferred option; revisit if FAT/exFAT
  in-process coverage becomes a requirement.
