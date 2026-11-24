# rapid-r8-overhaul - Work Plan

## TL;DR (For humans)

**Who this is for and what changes for them:** Analysts reviewing seized disk images get results sooner, see more of what was deleted, and work through a faster, cleaner, keyboard-first console that tells them plainly what was and was not recovered.

**What you'll get:** A measured speed-up of disk-image processing, higher and honestly reported recovery coverage, a redesigned review console, and a one-command benchmark that proves both on the real images on drive D.

**Why this approach:** Speed and recovery are measured on real images against an independent reference before and after every change, so no improvement is claimed without numbers; the console work targets the open review findings and the large-case freezes first.

**What it will NOT do:** It will not modify, copy into Git, or report contents of any evidence image; it will not merge the open pull requests; it will not touch the four in-flight lanes from the previous session.

**Effort:** XL
**Risk:** High - core engine changes measured on multi-hundred-GB real evidence
**Decisions I made for you:** Work on a new branch `feat/r8-overhaul` off `feat/r6-ux`; benchmark on the BSH (126 GB, has an existing Sleuth Kit extraction) and notebook (98 GB) images, sample-only on the 773 GB HDD; independent reference = pytsk3 (Sleuth Kit CLI not installed); speed target 40% faster end-to-end; caps lifted only in recovery mode, always disclosed.

Your next move: none - approval was granted up front; execution runs as mass-ulw workflows.

---

> TL;DR (machine): XL, high risk; parallel+single-pass E01 extraction, multi-partition, cap disclosure, carving over unallocated, process-pool parsers, virtualized tree, raw-key cleanup, design refresh, review-queue UX, r8-bench + pytsk3 reference diff.

## Scope
### Affected user and ideal state
**Affected user:** (1) Forensic analysts in a law firm who load an E01, explore, tag, and report in the v2 web console; today they wait for full extraction and hit freezes on large trees. (2) Developers/agents maintaining rapid who need repeatable speed and recovery numbers. (3) Reviewers of the report who must trust that evidence was untouched and coverage is disclosed.

| Row | Statement | Reason |
| --- | --- | --- |
| IS-1 | End-to-end `rapidtriage run` on the BSH image in `recovery` mode finishes in <= 60% of the baseline wall time on this PC, same flags. | Waiting is the analyst's largest cost. |
| IS-2 | Allocated-file recall vs the pytsk3 reference is >= 99.5% across EVERY partition with a supported filesystem; deleted-entry recall is >= baseline and >= 95% of pytsk3 deleted entries. | Missed files are missed evidence. |
| IS-3 | Every limit that truncates parsing (record caps, scan caps, unsupported filesystem, skipped partition) is recorded in `rapidtriage-run-summary.json` under `coverage` and shown in the console Process stage in Korean. | Silent truncation misleads a court. |
| IS-4 | Evidence segments are byte-for-byte untouched: size and LastWriteTime of every segment identical before/after every run. | Chain of custody. |
| IS-5 | The evidence tree stays responsive with 100k+ nodes (virtualized; mounted rows bounded) and the review loop (next unreviewed, tag, note) is fully keyboard-driven. | Large cases freeze today. |
| IS-6 | No raw keys or English sentences on analyst screens (R-7, R-10, R-11 closed); terminology 검사관 -> 분석관 everywhere. | Open review findings. |
| IS-7 | The redesigned console passes visual QA at 1440x900 and 390x844, dark and light, with contrast check green. | "디자인을 개쩔게". |
| IS-8 | `python scripts/r8-bench.py --image <E01> --label <x>` reproduces stage timings and recovery metrics in one command, writing JSON outside Git. | Speed work must keep looping on evidence. |
| IS-9 | All repository gates stay green except the pre-listed known flakes. | No regressions. |
| GAP-1 | Whole volume extracted to `_e01/` serially with one pyewf handle; per-file hashes re-read files. | Main speed sink (core/e01.py:1622, core/e01_native.py). |
| GAP-2 | Native path processes NTFS only and possibly one partition; FAT/exFAT unparsed (core/e01_native.py:57-63). | Lost files on multi-partition or FAT disks. |
| GAP-3 | Caps (EVTX 10k records, registry 8 MiB string scan/500 cell records, carving 256 MiB/250 candidates) silently truncate (core/carving.py:29-44). | Recovery loss, undisclosed. |
| GAP-4 | CPU-bound parsers run on threads only (core/run/__init__.py:2008), GIL-bound. | Cores idle. |
| GAP-5 | Carving scans a bounded prefix, not unallocated clusters. | Deleted content not recovered. |
| GAP-6 | EvidenceTree not virtualized (frontend/src/features/tree/EvidenceTree.tsx). | Freeze on big trees. |
| GAP-7 | R-7/R-10/R-11 raw strings; 검사관 terminology; possible tree-collapse regression shell/Layout.tsx:423-437. | Readability. |
| GAP-8 | No integrated benchmark/reference-diff command. | Cannot prove IS-1/IS-2. |
| GAP-9 | Manifest/docs-index JSON written indented (multi-GB). | Write time and disk. |

### Must have
- Every speed or recovery claim backed by r8-bench JSON from a real image run, baseline and after, same machine, same flags.
- Evidence opened read-only; segment size+mtime snapshot before/after each run.
- All work in worktree `D:\devin\rapid\.claude\worktrees\ulw-r8`, branch `feat/r8-overhaul` from `feat/r6-ux` (081c97a).
- Run outputs only under `D:\rapid-qa\derived\r8\` (outside Git).
### Must NOT have (guardrails, anti-slop, scope boundaries)
- No evidence bytes, file names from evidence, PII, hashes of evidence content, or case identifiers in Git or in reports (counts and field names only).
- No merge of PRs #18/#19/#20; no edits in `.claude/worktrees/agent-*` lanes; no contact with the user's server on port 8710.
- No `git add -A`; LF line endings; no skipped/xfail tests; no lowered thresholds to make gates pass.
- No new heavyweight dependency beyond what is installed (pyewf, dissect.ntfs, pytsk3, Evtx, regipy) without recording the reason in the plan notes.

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: tests-after, python unittest for engine/bench, vitest + Playwright for console.
- Evidence: `.omo/evidence/rapid-r8-overhaul/task-<N>.<ext>` in the worktree (git-ignored by path choice is NOT assumed: evidence files stay uncommitted) plus bench JSON under `D:\rapid-qa\derived\r8\`.
- Gate commands (worktree root): `python -m unittest discover -s tests` (background, ~60 min), `python -m ruff check rapidtriage tests scripts`, `python -m vulture rapidtriage tests scripts --min-confidence 80`, `python -m compileall -q rapidtriage tests scripts`; frontend: `npm run typecheck`, `npm run lint`, `npx vitest run --pool=forks --no-watch <chunk>`, `npm run check:contrast`, `npm run build`, `npm run e2e`.
- Known flakes (not regressions): WinError 183 in derived_engine/triage_rules tests (core/derived/stage.py:77); `test_rapidtriage_email_external...returns_nonzero_when_selected_tool_fails` under PowerShell; 2-3 vitest timeouts under load (rerun alone).

## Execution strategy
### Parallel execution waves
- Wave 0 (lead): todo 1.
- Wave 1 (measurement): todos 2, 3, then 4 (baseline runs, lead-driven long jobs).
- Wave 2 (engine speed, disjoint files): 5, 6, 7, 8, 9.
- Wave 3 (recovery, disjoint files, after wave 2 review): 10, 11, 12, 13.
- Wave 4 (console, disjoint files, runs in parallel with waves 2-3): 14, 15, 16, 17, 18, 19.
- Wave 5: 20 (bundle + after-bench + full gates), then F1-F4.

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | - | all | - |
| 2 | 1 | 4, 20 | 3, 14-19 |
| 3 | 1 | 4, 20 | 2, 14-19 |
| 4 | 2, 3 | 5-13 | 14-19 |
| 5 | 4 | 10, 20 | 6, 7, 8, 9 |
| 6 | 4 | 20 | 5, 7, 8, 9 |
| 7 | 4 | 20 | 5, 6, 8, 9 |
| 8 | 4 | 13, 20 | 5, 6, 7, 9 |
| 9 | 4, 12 | 20 | 5, 6, 7, 8 |
| 10 | 5 | 11, 19, 20 | 12, 13 |
| 11 | 10 | 20 | 12, 13 |
| 12 | 4 | 9, 13, 19, 20 | 5, 6, 7, 8 |
| 13 | 8, 12 | 20 | 10, 11 |
| 14-18 | 1 | 20 | each other, waves 1-3 |
| 19 | 10, 12 | 20 | - |
| 20 | all | F1-F4 | - |

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->
- [ ] 1. Create worktree and capture baseline gate state
  What to do / Must NOT do: `git -C D:\devin\rapid worktree add -b feat/r8-overhaul D:\devin\rapid\.claude\worktrees\ulw-r8 081c97a`; junction `frontend\node_modules` via `cmd /c mklink /J` to `D:\devin\rapid\frontend\node_modules`; run ruff, vulture, compileall, typecheck, lint and record pass/fail; start full unittest in background and record failures as the baseline list. Do not modify code.
  Closes: GAP-8 (precondition)
  Parallelization: Wave 0 | Blocked by: - | Blocks: all
  References: docs/plans/session-handoff-2026-10-27.md section 7; AGENTS.md "RapidForensic Validation Contract".
  Acceptance criteria: `git -C <wt> branch --show-current` = feat/r8-overhaul; baseline file `.omo/evidence/rapid-r8-overhaul/task-1-baseline.txt` lists every gate result.
  QA scenarios: happy = commands above exit as recorded; failure = a gate that fails at baseline is listed as pre-existing, never fixed silently. Evidence task-1-baseline.txt
  Commit: N
  Recommended task executor category: quick

- [ ] 2. scripts/r8-bench.py one-command benchmark
  What to do / Must NOT do: New script: args `--image <E01 path> --label <name> --mode recovery --out-root D:\rapid-qa\derived\r8 [--extra-run-args ...]`. Steps: snapshot size+LastWriteTime of every segment; run `python -m rapidtriage run <image> --mode <mode> --read-only --output-dir <out-root>\<label>\<image-stem>` with `subprocess`, sampling peak RSS of the process tree every 2 s via psutil if installed else `tasklist`; parse `rapidtriage-run-checkpoints.json` for per-stage durations; parse summary for file/deleted/artifact counts and `coverage`; re-snapshot segments and fail with exit 3 if any differ; write `<out>\r8-bench.json` (schema `r8-bench-v1`: label, image_set_id = sha256 of the image path string truncated to 12 hex, wall_s, stages{name:seconds}, counts{}, coverage{}, peak_rss_mb, segments_unchanged:true). Never print evidence file names. Add `tests/test_r8_bench.py` using a fake runner (monkeypatched subprocess) covering JSON shape and the segment-changed exit 3.
  Closes: GAP-8
  Parallelization: Wave 1 | Blocked by: 1 | Blocks: 4, 20
  References: core/run/__init__.py:766 (summary path), :773 (checkpoints path); scripts/mft-reference-diff.py for CLI style.
  Acceptance criteria: `python -m unittest tests.test_r8_bench` passes; `python scripts/r8-bench.py --help` exits 0; ruff clean.
  QA scenarios: happy = run against `D:\tmp\apfs-test\apfs_pool.E01` produces r8-bench.json with segments_unchanged true; failure = test proves exit 3 on changed segment. Evidence task-2.json
  Commit: Y | feat(bench): r8-bench one-command run benchmark (counts only)
  Recommended task executor category: quick

- [ ] 3. scripts/r8-recovery-diff.py independent pytsk3 reference
  What to do / Must NOT do: New script: open the E01 with pyewf + pytsk3 (`pytsk3.Img_Info` subclass over a pyewf handle), enumerate EVERY partition via `pytsk3.Volume_Info` (or whole image if no volume system), walk each filesystem recursively collecting (partition index, inode/MFT ref, normalized path, size, allocated flag); compare with the run's files manifest/extraction under `--run-dir` (use the same normalization as scripts/fls-coverage-diff.py: strip `_e01/...` prefixes, case-insensitive NTFS paths); output JSON `r8-recovery-diff-v1`: per partition {fs_type, ref_allocated, ref_deleted, rapid_allocated_matched, rapid_deleted_matched, allocated_recall, deleted_recall, rapid_only}. Counts only, no paths in output. Add `tests/test_r8_recovery_diff.py` exercising the comparison function on synthetic lists.
  Closes: GAP-8, proves IS-2
  Parallelization: Wave 1 | Blocked by: 1 | Blocks: 4, 20
  References: scripts/fls-coverage-diff.py (normalization, schema fls-coverage-diff-v2-inode); scripts/mft-reference-diff.py.
  Acceptance criteria: unit test passes; `--help` exits 0; ruff clean.
  QA scenarios: happy = on apfs_pool.E01 emits JSON (unsupported fs listed, not crash); failure = unit test with a missing file lowers recall below 1.0. Evidence task-3.json
  Commit: Y | feat(bench): pytsk3 reference recovery diff (counts only)
  Recommended task executor category: unspecified-low (reason: pyewf/pytsk3 bridging across partitions needs judgment a template cannot make)

- [ ] 4. Baseline measurements on real images (lead-run)
  What to do / Must NOT do: From the worktree at commit after todos 2-3, run r8-bench + r8-recovery-diff on BSH (`D:\devin\bsh-e01\BSH.E01`) and notebook (`D:\한종인\#914_260812_notebook_002\Image\#914_260812_PC_002.E01`), label `baseline`. Run as background processes watched by monitors. Record results (counts only) in the notepad and `.omo/evidence/rapid-r8-overhaul/task-4-baseline.json`.
  Closes: precondition for IS-1/IS-2
  Parallelization: Wave 1 | Blocked by: 2, 3 | Blocks: 5-13
  References: todo 2, 3 outputs.
  Acceptance criteria: two r8-bench.json + two r8-recovery-diff.json exist with segments_unchanged true.
  QA scenarios: happy = both runs complete; failure = a crashing run is recorded as a baseline defect with its error class and becomes a todo in wave 2. Evidence task-4-baseline.json
  Commit: N
  Recommended task executor category: quick

- [ ] 5. Parallel single-pass native extraction
  What to do / Must NOT do: In core/e01_native.py and core/e01.py native path: extract files with a pool of N workers (default `min(8, os.cpu_count())`, env `RAPIDTRIAGE_E01_WORKERS`), each worker owning its own pyewf handle and dissect.ntfs instance (handles are not thread-safe); stream each file once through md5/sha1/sha256 while writing, and record the digests in the extraction manifest so later stages reuse them instead of re-reading. Keep output layout byte-identical. Must NOT change the external (ewfmount/tsk) path.
  Closes: GAP-1
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: 10, 20
  References: core/e01.py:1622 extract_e01_to_directory, :2116 native fallback; core/e01_native.py:23-63; docs/rapidtriage-e01-engine-decision-2026-09-26.md.
  Acceptance criteria: existing e01 tests pass; new test asserts digests in manifest equal hashlib over extracted bytes on a fixture; r8-bench on BSH stage `extract` faster than baseline.
  QA scenarios: happy = BSH extract stage seconds < baseline and file count identical; failure = worker exception surfaces as a run error, not a silent skip (unit test with a raising worker). Evidence task-5.json
  Commit: Y | perf(e01): parallel single-pass native extraction with reused digests
  Recommended task executor category: deep-low (reason: concurrency across non-thread-safe pyewf/dissect handles)

- [ ] 6. Reuse extraction digests in hashing call sites
  What to do / Must NOT do: Find the shared hashing helper used by providers (`source_hashes` and its definition); add a run-scoped digest cache keyed by (absolute path, size, mtime_ns) pre-seeded from the extraction manifest of todo 5 and filled on first compute; compute all three digests in one read loop (1 MiB chunks). No behavior change in reported values.
  Closes: GAP-1
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: 20
  References: shared helper is `compute_hashes` (callers: artifacts/cloud.py:551, artifacts/email.py:190 assign `source_hashes = compute_hashes(path)`); core/files.py:283 run-scoped snapshot cache pattern.
  Acceptance criteria: unit test: two calls on same file read it once (patched open counter); digests equal hashlib.
  QA scenarios: happy = test green; failure = modified file (mtime change) invalidates cache (test). Evidence task-6.txt
  Commit: Y | perf(hash): single-pass multi-digest with run-scoped cache
  Recommended task executor category: quick

- [ ] 7. Compact JSON manifest writes
  What to do / Must NOT do: Replace indented `json.dump(..., indent=2)` for manifest and docs-index outputs in core/docs.py (and any other writer of files > 10 MB found by grep `indent=2` under rapidtriage/core) with compact separators `(",", ":")`; readers unchanged. Do not change small human-facing JSON (summary, plan).
  Closes: GAP-9
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: 20
  References: core/docs.py:217 build_manifest; writer `json.dump(..., indent=indent)` at core/docs.py:858 (docs-index already indent=None at :521). FIRST check which default indent the manifest path passes; if already compact, close GAP-9 with evidence and change nothing.
  Acceptance criteria: tests pass; round-trip test loads identical object.
  QA scenarios: happy = manifest size on BSH run smaller than baseline; failure = reader test on compact file passes. Evidence task-7.txt
  Commit: Y | perf(docs): compact JSON for large manifests
  Recommended task executor category: quick

- [ ] 8. Process pool for CPU-bound artifact parsers
  What to do / Must NOT do: In core/run/__init__.py:2008 artifact stage, route EVTX, registry, and ESE/SRUM collectors to a ProcessPoolExecutor (spawn context, workers = env `RAPIDTRIAGE_PARSE_PROCS` default `max(2, cpu_count//2)`), passing only picklable inputs (paths, options) and returning results; keep others on threads; preserve result ordering. Fallback to threads if the pool cannot start.
  Closes: GAP-4
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: 13, 20
  References: core/run/__init__.py:1805 collect_artifact_stages, :2008; rapidtriage/artifacts/windows/.
  Acceptance criteria: artifact outputs on tier0 fixture identical before/after (test compares JSON); r8-bench parse stage faster on BSH.
  QA scenarios: happy = identical outputs and faster stage; failure = pool start failure falls back (test with patched executor raising). Evidence task-8.json
  Commit: Y | perf(run): process pool for CPU-bound artifact parsers
  Recommended task executor category: deep-low (reason: pickling boundaries and ordering across many collectors)

- [ ] 9. Carving over unallocated clusters, parallel
  What to do / Must NOT do: In core/carving.py add a mode that, given an NTFS volume, reads $Bitmap and scans only unallocated cluster runs, in parallel chunks (ProcessPool, 8 MiB chunks, 4 KiB overlap retained); recovery mode uses this with caps disabled (scan all unallocated, candidate cap raised to 100000); other modes keep current caps. Every cap that stops a scan writes a coverage entry (see todo 12).
  Closes: GAP-3, GAP-5
  Parallelization: Wave 2 | Blocked by: 4 | Blocks: 20
  References: core/carving.py:29-44, :312, :520; scripts/carve-known-answer.py.
  Acceptance criteria: `python scripts/carve-known-answer.py --output-dir <tmp> --extract --json` precision/recall unchanged (1.0); new test on synthetic bitmap only scans unallocated runs.
  QA scenarios: happy = BSH carved candidate count >= baseline; failure = cap hit produces coverage entry (test). Evidence task-9.json
  Commit: Y | feat(carving): parallel unallocated-cluster carving in recovery mode
  Recommended task executor category: deep-low (reason: bitmap-to-offset mapping and chunk overlap correctness)

- [ ] 10. All partitions in native engine
  What to do / Must NOT do: Make native extraction iterate every partition from MBR/GPT; NTFS via dissect.ntfs, others via pytsk3 (FAT/exFAT/ext supported by TSK); unsupported ones recorded in coverage. Output under `_e01/p<index>/...` only when more than one partition is extracted; single-partition layout unchanged.
  Closes: GAP-2
  Parallelization: Wave 3 | Blocked by: 5 | Blocks: 11, 19, 20
  References: core/e01_native.py:57-63; core/e01.py prepare_run_input_root; docs/rapidtriage-e01-engine-decision-2026-09-26.md.
  Acceptance criteria: test with a synthetic 2-partition raw image (FAT + NTFS built in test or fixture under tests/fixtures, small) extracts both.
  QA scenarios: happy = r8-recovery-diff shows every supported partition with allocated_recall >= 99.5%; failure = unsupported fs shows in coverage, run continues. Evidence task-10.json
  Commit: Y | feat(e01): extract every partition in the native engine
  Recommended task executor category: deep-low (reason: partition model change across extraction and run input)

- [ ] 11. Deleted-entry recovery parity
  What to do / Must NOT do: Using the baseline r8-recovery-diff, close the deleted-recall gap: in recovery mode make the `_deleted_mft` sweep unbounded and include entries whose data runs are partially overwritten (mark `partial`); for non-NTFS partitions use pytsk3 deleted entries.
  Closes: GAP-2, GAP-5
  Parallelization: Wave 3 | Blocked by: 10 | Blocks: 20
  References: decision doc "Consequences" (bounded MFT sweep); baseline task-4 JSON.
  Acceptance criteria: BSH deleted_recall >= baseline and >= 0.95.
  QA scenarios: happy = diff JSON meets threshold; failure = partial entries flagged, never presented as intact (unit test). Evidence task-11.json
  Commit: Y | feat(recovery): unbounded deleted MFT sweep with partial flag
  Recommended task executor category: unspecified-high (reason: correctness against real-evidence reference across NTFS and TSK paths)

- [ ] 12. Coverage disclosure in run summary
  What to do / Must NOT do: Add `coverage` to rapidtriage-run-summary.json: list of {area, reason_code, limit, observed, unit} for every cap hit (EVTX records, registry bytes/records, carving bytes/candidates, skipped partition, unsupported fs). Expose via existing GET run summary endpoint (routes_runs.py:572) and update the OpenAPI snapshot via `python scripts/update-api-snapshot.py`.
  Closes: GAP-3
  Parallelization: Wave 2 (moved up per plan review) | Blocked by: 4 | Blocks: 9, 13, 19, 20
  References: routes_runs.py:572; caps in artifacts/windows/eventlog.py ~:220, artifacts/windows/registry.py:32-35 (8 MiB/500), core/carving.py:29-31. Entry shape (fixed for todos 9 and 13): {"area": str, "reason_code": str, "limit": int|null, "observed": int|null, "unit": str}, appended through one helper `record_coverage(area, reason_code, limit, observed, unit)` in a new module rapidtriage/core/coverage.py.
  Acceptance criteria: unit test triggering each cap yields its entry; API test returns coverage.
  QA scenarios: happy = BSH run summary lists coverage entries; failure = run with no caps hit has empty list. Evidence task-12.json
  Commit: Y | feat(run): disclose truncation coverage in run summary and API
  Recommended task executor category: quick

- [ ] 13. Lift EVTX/registry caps in recovery mode
  What to do / Must NOT do: In recovery mode parse full EVTX files and full hives (stream, no full-file buffering); other modes keep caps and report them via todo 12.
  Closes: GAP-3
  Parallelization: Wave 3 | Blocked by: 8 | Blocks: 20
  References: artifacts/windows/eventlog.py ~:220 (MAX_NATIVE_EVTX_RECORD_SIZE and record caps); artifacts/windows/registry.py:32-35 (MAX_HIVE_STRING_SCAN_BYTES = 8 MiB, MAX_HIVE_CELL_RECORDS = 500); docs/rapidtriage-phase2-real-evidence-measurements.md.
  Acceptance criteria: test with a fixture exceeding old caps parses all records in recovery mode.
  QA scenarios: happy = BSH Security.evtx record count > 10000 in recovery mode; failure = triage mode still capped and disclosed. Evidence task-13.json
  Commit: Y | feat(artifacts): full EVTX and hive parsing in recovery mode
  Recommended task executor category: quick

- [ ] 14. Virtualize EvidenceTree
  What to do / Must NOT do: Flatten the visible tree to rows and render with @tanstack/react-virtual (same pattern as DataGrid.tsx:778-784), keep roving tabindex, treeitem aria-level/expanded, keyboard expand/collapse, and focused row always mounted.
  Closes: GAP-6
  Parallelization: Wave 4 | Blocked by: 1 | Blocks: 20
  References: frontend/src/features/tree/EvidenceTree.tsx; frontend/src/features/grid/DataGrid.tsx:778-784; frontend/e2e/a11y.spec.ts treeitem rule.
  Acceptance criteria: vitest renders a 100k-node tree and asserts mounted treeitems < 200; existing tree tests and a11y e2e pass.
  QA scenarios: happy = vitest + browser scroll through 100k fixture smoothly; failure = keyboard ArrowDown past viewport keeps focus visible (test). Evidence task-14.png
  Commit: Y | perf(console): virtualize evidence tree
  Recommended task executor category: visual-engineering

- [ ] 15. Close raw-key findings and terminology
  What to do / Must NOT do: Map the 19 raw keys and English sentences in accept-stage "단계 상세" (R-7), source section `보고 가능성`/`증거 강도` raw values (R-10), browser column header hint (R-11) to Korean labels via the existing glossary; replace 검사관 with 분석관 across frontend/src (UI strings only); extend e2e raw-values spec to cover these screens.
  Closes: GAP-7
  Parallelization: Wave 4 | Blocked by: 1 | Blocks: 20
  References: docs/research/console-adversarial-rereview-r7s1-2026-10-27.md section 5; frontend/e2e/raw-values spec.
  Acceptance criteria: raw-values e2e green; `grep -r 검사관 frontend/src` returns 0.
  QA scenarios: happy = screenshots show Korean labels; failure = e2e fails if a raw key reappears. Evidence task-15.png
  Commit: Y | fix(console): close R-7/R-10/R-11 raw strings and 분석관 terminology
  Recommended task executor category: quick

- [ ] 16. Design refresh of shell and tokens
  What to do / Must NOT do: Refresh tokens.css typography scale, spacing, density, surface elevation and accent within the 40-colour budget; refine TopBar, StatusBar, stage tabs, GridEmpty and loading skeletons for a calmer, denser, higher-contrast analyst console; no component library added.
  Closes: IS-7
  Parallelization: Wave 4 | Blocked by: 1 | Blocks: 20
  References: frontend/src/tokens/tokens.css; frontend/src/shell/*; scripts/check-contrast.mjs.
  Acceptance criteria: `npm run check:contrast` green; visual QA screenshots at 1440x900 and 390x844, dark and light, no overlap or clipping.
  QA scenarios: happy = 4 screenshots reviewed; failure = contrast script fails on a token change (must be fixed). Evidence task-16-*.png
  Commit: Y | style(console): refreshed tokens and shell
  Recommended task executor category: visual-engineering

- [ ] 17. Keyboard review queue
  What to do / Must NOT do: Add commands "다음 미검토"/"이전 미검토" (keys N / Shift+N) that move selection to the next item without a review tag in the current view, auto-open in viewer; announce position "미검토 k/n" via announce(); dedupe toasts; live announce sort changes; drawer focus restore. Register in KEY_MAP (contracts/command.ts) and HelpOverlay.
  Closes: IS-5
  Parallelization: Wave 4 | Blocked by: 1 | Blocks: 20
  References: frontend/src/shortcuts.ts; contracts/command.ts KEY_MAP; a11y/announcer.ts.
  Acceptance criteria: vitest for queue navigation; e2e review-tools extended with N/tag/N loop.
  QA scenarios: happy = e2e loop tags 3 items by keyboard only; failure = no unreviewed items announces "미검토 없음". Evidence task-17.txt
  Commit: Y | feat(console): keyboard review queue
  Recommended task executor category: quick

- [ ] 18. Tree collapse regression check
  What to do / Must NOT do: Check whether branch fix/r7-s1-final contains the fix for shell/Layout.tsx:423-437 (tree collapses after viewer opens); if merged into feat/r6-ux already, add only a regression e2e; otherwise port the fix and add the e2e.
  Closes: GAP-7
  Parallelization: Wave 4 | Blocked by: 1 | Blocks: 20
  References: frontend/src/shell/Layout.tsx:423-437.
  Acceptance criteria: e2e opens viewer, goes to review board, tree still expanded.
  QA scenarios: happy = e2e green; failure = e2e red on the pre-fix code. Evidence task-18.txt
  Commit: Y | fix(console): keep evidence tree expanded across viewer and review
  Recommended task executor category: quick

- [ ] 19. Coverage panel in Process stage
  What to do / Must NOT do: Show run summary `coverage` (todo 12) and per-partition status (todo 10) in ProcessStage as a Korean "복구 범위" panel: each limit in plain words with observed vs limit; empty state "제한 없이 처리됨".
  Closes: IS-3
  Parallelization: Wave 4 tail | Blocked by: 10, 12 | Blocks: 20
  References: frontend/src/features/stages/ProcessStage.tsx; regenerated schemas `npm run gen:schemas`.
  Acceptance criteria: vitest renders entries; e2e on fixture run shows panel.
  QA scenarios: happy = screenshot with entries; failure = empty coverage shows empty state. Evidence task-19.png
  Commit: Y | feat(console): 복구 범위 coverage panel
  Recommended task executor category: visual-engineering

- [ ] 20. Rebuild bundle, after-bench, full gates
  What to do / Must NOT do: `npm run build` -> commit rapidtriage/web/static/v2; rerun r8-bench + r8-recovery-diff on BSH and notebook with label `after`; run every gate; compare to baseline; any IS miss becomes a new todo.
  Closes: IS-1, IS-2, IS-8, IS-9
  Parallelization: Wave 5 | Blocked by: all | Blocks: F1-F4
  References: todo 4 baseline JSON.
  Acceptance criteria: IS-1 ratio <= 0.60; IS-2 thresholds; all gates green except listed flakes; segments_unchanged true.
  QA scenarios: happy = comparison table; failure = a missed threshold opens a new todo with the measured gap. Evidence task-20.json
  Commit: Y | build(web): rebuild v2 bundle (R8)
  Recommended task executor category: quick

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [ ] F1. Plan compliance audit
- [ ] F2. Code quality review
- [ ] F3. Real manual QA
- [ ] F4. Ideal-state fidelity

## Commit strategy
One atomic commit per todo in feat/r8-overhaul, history style of feat/r6-ux (`type(scope): imperative`, English), trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` per handoff section 1, footer `Plan: .omo/plans/rapid-r8-overhaul.md` on the final commit. Push the branch; open no merge; PR only as draft if the user asks.

## Success criteria
| IS | Delivering todo(s) | Proving QA scenario | Evidence |
| --- | --- | --- | --- |
| IS-1 | 5, 6, 7, 8, 9 | todo 20 after/baseline wall ratio | task-20.json |
| IS-2 | 10, 11 | todo 20 recovery diff | task-20.json |
| IS-3 | 12, 19 | todo 12 + 19 scenarios | task-12.json, task-19.png |
| IS-4 | 2 | segments_unchanged in every bench | task-4, task-20 JSON |
| IS-5 | 14, 17 | todo 14 vitest + 17 e2e | task-14.png, task-17.txt |
| IS-6 | 15, 18 | raw-values e2e, grep 0 | task-15.png |
| IS-7 | 16 | visual QA 4 screenshots + contrast | task-16-*.png |
| IS-8 | 2, 3 | bench --help + baseline runs | task-2.json, task-3.json |
| IS-9 | 20 | full gate run | task-20.json |
