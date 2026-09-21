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

## LNK native parse vs LnkParse3 (B-series)

`scripts/lnk-reference-diff.py` (requires `LnkParse3`) diffs
`parse_lnk_metadata` against the independent parser on all 298 real
`.lnk` files found under the extracted image.

The comparison exposed a real RapidTriage defect, now fixed:

- `target_path` used only `LocalBasePath`. Some writers store a
  truncated base (`C:\Users`) with the remainder in
  `CommonPathSuffix`; MS-SHLLINK reconstruction appends the suffix.
  Fixed via `join_lnk_base_suffix` (`recent_files.py`).
- ANSI string fields were decoded as cp1252, mangling the writer's
  system codepage (cp949 on this image). ANSI LinkInfo/StringData/embedded
  paths now decode via the host ANSI codepage (`mbcs` on Windows,
  cp1252 fallback). LnkParse3's latin-1 output is re-decoded the same
  way inside the diff script (counted, not hidden).

Final result on 298 files:

| Metric | Result |
|--------|--------|
| Files compared | 298 |
| Fully matched | 281 |
| Field mismatches | 0 |
| One-sided fields | 15 — all `target_path` where LnkParse3 emits nothing (shell-folder links with `ForceNoLinkInfo`; RapidTriage recovers a path from embedded shell-item strings — unverifiable by this reference) |
| RapidTriage parse failures | 0 |
| LnkParse3 parse failures | 2 (`unpack requires a buffer`, $Recycle.Bin links) |

LnkParse3 additionally emitted warnings (`size must be 76`,
`METADATA_PROPERTIES_BLOCK`, unsupported `sort_index_value`) — logged
as reference-parser limitations, not RapidTriage failures.

Limitations: shell-folder/CLSID link targets are not semantically
validated (both tools surface strings, not resolved objects); 15
one-sided files mean the comparison cannot confirm those targets;
8.3 short names in TargetIDList-derived paths are not expanded.

Report: `D:\devin\trusted-ref\lnk-diff-report.json`.

## Registry native scan vs regipy (B-series)

`scripts/registry-reference-diff.py` (requires `regipy`) diffs
`collect_registry_hive` against regipy's live-tree walk on 6 real hives
from the extracted image (4× NTUSER.DAT, 2× UsrClass.dat; 8 KiB –
18 MiB).

| Metric | Result |
|--------|--------|
| Hives compared | 6, 0 errors |
| Base-block header fields | 0 diffs (sequence numbers, FILETIME last-write, versions, hbin size) |
| Rapid-only root-reachable key paths | **0** — every confidently reconstructed path exists in the reference live tree |
| Rapid-only stale/orphaned cells | 5 — flagged `root_reachable=False` by our parser; live-tree walks legitimately skip stale cells |
| Common-key timestamps | 1,049/1,050 match (1 mismatch on a stale cell) |
| Common-key value names | 1,285 consistent (⊆), 1 conflict (same stale cell) |
| Key coverage vs reference | 0.007%–100% — bounded by `MAX_HIVE_CELL_SCAN_BYTES=16MiB` / `MAX_HIVE_CELL_RECORDS=500`; large hives intentionally cover only the first cells |

The value-name comparison uses subset-consistency (rapid ⊆ trusted):
the bounded scan decodes fewer vk cells than a full walk, so incomplete
lists are expected; any rapid name absent from the reference is a
conflict. Exactly one conflict was found, on a stale cell.

Limitations: value *data* payloads, deleted-cell recovery candidates,
and transaction-log replay are not compared; coverage on the 18 MiB
NTUSER.DAT is ~2% by design.

Report: `D:\devin\trusted-ref\registry-diff-report.json`.

## Prefetch native parse vs windowsprefetch (B-series)

`scripts/prefetch-reference-diff.py` (requires `windowsprefetch`) diffs
`prefetch_header_hints` against the independent parser on all 42 real
`.pf` files under `Windows\Prefetch`.

The comparison exposed a real capability gap, now fixed: every real
file was MAM-compressed v31 and RapidTriage previously detected but did
not decompress them (all fields empty). Native MAM decompression via
`ntdll.RtlDecompressBufferEx` (XPRESS_HUFF, CRC32-checked when the flag
is set) was added; non-Windows hosts report the limitation instead of
silently parsing nothing (`decompression_status` /
`not-attempted-non-windows-host`).

Final result on 42 files:

| Metric | Result |
|--------|--------|
| Files compared | 42 |
| Fully matched | 42 |
| Field mismatches | 0 |
| Fields compared | SCCA version, executable name, run count, last-run timestamp, full run-time set |
| RapidTriage parse failures | 0 |
| windowsprefetch parse failures | 0 |

Timestamps are truncated to milliseconds and normalized to naive-UTC on
both sides (RapidTriage emits tz-aware ISO; windowsprefetch emits
naive).

Limitations: file-metrics array, trace chains, and the authoritative
volume table remain undecoded by both parsers at this level; referenced
paths are string-candidate pivots only.

Report: `D:\devin\trusted-ref\prefetch-diff-report.json`.

## Amcache native schema decode vs regipy (B-series)

`scripts/amcache-reference-diff.py` (requires `regipy`) diffs the
Amcache hive against regipy's schema-decoded
`Root\InventoryApplicationFile` / `Root\File` rows on the real
`Windows\appcompat\Programs\Amcache.hve` (~6.8 MB, 2,255 declared
InventoryApplicationFile subkeys).

Before this stage RapidTriage used bounded string pivots only
(`native_amcache_schema_decode: False`) and measured path recall of
~2% / precision ~46% / SHA1 overlap 1-of-29 — the pivot surface could
not compete with schema decode. A native decoder
(`decode_amcache_schema_rows` in `execution.py`) now walks the hive's
`nk`/`vk` cells via the shared registry primitives and emits
`amcache-schema-row` records with decoded values (`LowerCaseLongPath`,
`FileId`, `Name`, `Publisher`, `Size`, version/language fields), cell
offsets, and per-section decode coverage. String-pivot `amcache-entry`
records are retained as supplemental candidates.

Final result on the real hive:

| Metric | Before (string pivot) | After (schema decode) |
|--------|----------------------|----------------------|
| Declared subkeys decoded | 0 | 2,255 / 2,255 (+ 333 InventoryApplication) |
| Path recall vs regipy | 0.0204 | **1.0** |
| Path precision | 0.46 | 0.9766 (54 extra = string-pivot candidates) |
| SHA1 `FileId` common | 1 / 29 | 2,104 / 2,132 |
| Trusted-only SHA1s | — | 0 |

Limitations: `InventoryApplicationFile` field semantics (e.g. which
timestamps mean install vs execution) are decoded structurally but not
semantically validated — schema-row records carry
`amcache-schema-row-field-semantics-validation-required` and stay
`reportability: review`. Non-file sections (`InventoryApplication`,
`Programs`) are decoded but excluded from the path comparison.
regipy remains an engineering reference, not a recognized trusted
tool.

Report: `D:\devin\trusted-ref\amcache-diff-report.json`.

## ShimCache native binary decode vs regipy (B-series)

`scripts/shimcache-reference-diff.py` (requires `regipy`) diffs the
SYSTEM hive AppCompatCache value against regipy's `ShimCachePlugin`
(which embeds the Mandiant ShimCacheParser) on the real
`Windows\System32\config\SYSTEM` hive (~25.7 MB).

Before this stage RapidTriage used string-pivot clusters only
(`native_shimcache_binary_decode: False`). A native decoder now walks
the hive `nk`/`vk` cells, locates `ControlSet*\Control\Session
Manager\AppCompatCache`, reads the (potentially `db`-segmented) binary
value, detects the Win8/8.1/10/10-Creators `00ts`/`10ts` layouts, and
emits `shimcache-schema-entry` records with ordered
(`cache_order`, path, last-mod FILETIME) rows. NT5.2/NT6.1/XP magics
are detected but reported `detected-unsupported-layout` rather than
silently misparsed.

Final result on the real hive:

| Metric | Result |
|--------|--------|
| regipy ShimCache rows | 849 |
| RapidTriage schema-entry rows | 849 |
| Ordered (order, path, timestamp) row matches | **849 / 849** |
| Path recall / precision | **1.0 / 1.0** |
| Timestamp agreement (ms) | **1.0** |

Limitations: `exec_flag` semantics (Win8 CSRSS flag) are decoded but
not independently validated; ShimCache presence remains
presence-not-execution and schema-entry records stay
`reportability: review` with
`shimcache-entry-semantic-validation-required` /
`os-build-layout-validation-required` blockers. NT5.2/NT6.1/XP layouts
are detected but not decoded. regipy is an engineering reference, not
a recognized trusted tool.

Report: `D:\devin\trusted-ref\shimcache-diff-report.json`.

## Release-gate impact

`quantitative-accuracy-thresholds` stays `blocked`: the gate requires
known-answer corpus + trusted-tool evidence attached through the
release-evidence path, and python-evtx/Sleuth Kit comparisons are
engineering references, not the recognized trusted-tool set.
