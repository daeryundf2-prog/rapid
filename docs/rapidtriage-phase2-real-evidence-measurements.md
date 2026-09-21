# Phase 2 — Real-Evidence Accuracy Measurements

Engineering evidence only. These measurements come from internal tooling
against a real 232 GB E01 image on Windows 11. They are **not** release
evidence: no recognized trusted commercial tool was used, no independent
reviewer signed off, and `commercial_claim_allowed` remains `False`.

Evidence artifacts live outside the repository (not committed):

- `D:\devin\trusted-ref\` — Sleuth Kit exports, diff reports, slim cache
- `D:\devin\carve-ka\` — carving known-answer corpus + report
- `D:\devin\ntfs-meta-out\` — extracted `$MFT` / `$UsnJrnl:$J`
- `D:\e01-full-extract\` — full file extraction tree

## Source image

- `D:\devin\BSH.E01` multi-segment (~232 GB), NTFS partition at sector
  offset 567296 (verified via `fsstat` OEM-ID probe).
- Reference tools: Sleuth Kit 4.15.0 (fls, ils, icat, mmls, fsstat),
  python-evtx 0.8.1.

## MFT / filesystem enumeration (A2)

Commands:

```
fls -rpo 567296 <E01>   -> bsh-fls-recursive.txt   (780,645 entries)
ils -eo 567296 <E01>    -> bsh-ils-all.txt         (1,379,052 inodes)
```

`scripts/mft-reference-diff.py` parses the extracted 1.39 GiB `$MFT` with
the native parser and diffs against both references.

| Metric | Result |
|--------|--------|
| Inode coverage vs ils | 99.9999% (1,379,048/1,379,049) |
| Deleted-entry detection | P=1.0, R=1.0, FPR=0.0 (731k TP / 648k TN) |
| Path agreement vs fls | 94.4% (rest = hardlink aliases, cp949 names) |
| `$DATA` real_size agreement | 99.9958% (811,884/811,918) |

Limitations: windowed parse (5,000 records/window), path agreement is
bounded by hardlink aliasing and cp949 filename encoding in fls output.
Full-volume completeness is not claimed.

Report: `D:\devin\trusted-ref\mft-diff-report.json`,
`fls-coverage-report.json`.

## Carving known-answer (A3)

`scripts/carve-known-answer.py` builds a deterministic synthetic image
with 12 valid planted files, truncated variants, and 3 false-signature
plants, then measures the scanner.

| Metric | Result |
|--------|--------|
| Precision | 1.0 |
| Recall | 1.0 |
| FPR | 0.0 |
| TP / FP / FN | 12 / 0 / 0 |

Synthetic engineering corpus only — not real-evidence accuracy.

Report: `D:\devin\carve-ka\carve-known-answer-report.json`.

## EVTX native parse vs python-evtx (B1)

`scripts/evtx-reference-diff.py` (requires `python-evtx`) diffs native
collection against the independent BinXML decoder on 18 real logs from
the extracted image (`winevt/Logs`).

Before the chunk-template fix: matched 0/5,664 on a 2-file subset —
provider/event_id/computer were empty and channel was often wrong
(heuristic fallback).

Fixes applied:

- Wired `decode_evtx_system_section` into the record loop (was dead
  code): resolves each record's template via the chunk template table.
- Handle both TemplateInstance layouts (inline definition vs chunk-table
  reference); the referenced form stores the value count where the
  inline marker sits.
- Collect static element text from template definitions — real
  templates bake literal values such as `<Computer>` into the def.

After the fix, on 18 real files:

| Metric | Result |
|--------|--------|
| Records compared | 9,369 |
| Field match | 9,361 (99.91%) |
| Mismatches | 8 — all sub-ms FILETIME serialization boundary flips |
| Rapid-only records | 334 — all `slack-or-deleted-record-candidate` (recovery region records python-evtx skips) |
| Trusted-only records | 0 |
| Sub-ms timestamp deltas audited | 5,158 |

Timestamps are truncated to milliseconds on both sides before field
comparison (python-evtx uses `float(qword)*1e-7`, which drifts ~1 µs at
FILETIME magnitude; RapidTriage truncates at `//10`). Sub-ms deltas are
counted in `timestamp_normalization`, not hidden.

Limitations: `MAX_NATIVE_EVTX_RECORDS = 10,000` caps large logs
(Security.evtx has ~34k records — coverage is bounded by the cap).
Message rendering (provider DLL resources) is not compared; EventData
field agreement beyond System-section fields is not yet measured.

Report: `D:\devin\trusted-ref\evtx-diff-report.json`,
`evtx-diff-small.json`.

## Release-gate impact

`quantitative-accuracy-thresholds` stays `blocked`: the gate requires
known-answer corpus + trusted-tool evidence attached through the
release-evidence path, and python-evtx/Sleuth Kit comparisons are
engineering references, not the recognized trusted-tool set.
