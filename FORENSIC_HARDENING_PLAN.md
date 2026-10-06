# RapidForensic Hardening Plan

Status: active execution record
Date: 2026-05-31
Plan authority: `docs/plans/rapidforensic-recovery-review-plan-2026-05-30.md` at commit `9973672931e31a40174d0087a72feae6a0f7620c`

## 2026-09-17 Sequential Remediation Plan

Baseline: `f7eb329ec94642d78499af06ac4cf6a9d994aa22`. This pass supersedes historical PASS claims only for the paths actually changed and tested. Historical records below are not fresh release evidence.

### Requirements and execution boundaries

- Preserve acquired evidence bytes and directory membership; query working copies rather than original SQLite databases.
- Keep engineering checks, declared dataset status, verified evidence, and court/report suitability separate.
- Fix existing correctness and security paths before adding parser families or increasing parallelism.
- Preserve source citations and public output fields where possible; explicitly label hash scope and partial results.
- Work in the review checkout without commits, pushes, real evidence acquisition, live cloud collection, or use of private credentials.
- Each numbered stage requires focused regressions and static checks before the next stage begins. Remaining platform/corpus checks stay blocked, not passed.

### Stage 1 — Fail-closed report readiness

Source: `rapidtriage/core/validation.py:368`; regression home: `tests/test_rapidtriage_final_roadmap.py`.

1. Retain dataset `status` as the declared result for compatibility.
2. Require nonempty passing datasets, existing evidence, and no unresolved blockers before `ready_for_court_report` can be true.
3. Do not treat a supplied trusted-diff pass as a substitute for external coverage and methodology review.

Acceptance: absent manifest, empty datasets, missing files, absent paths, mixed statuses, and supplied pass with unresolved blockers all produce false readiness. Existing valid data still produces the expected dataset counts and hashes.

Status: implemented; seven new regressions plus six existing final-roadmap tests passed. Mandatory review blockers intentionally prevent automatic court suitability. File existence alone does not establish evidence adequacy.

### Stage 2 — SQLite working snapshots and source preservation

Sources: `rapidtriage/artifacts/windows/common.py:31`, `rapidtriage/core/source_reader.py:398`, `rapidtriage/api/app/sqlite.py`; reuse patterns from `rapidtriage/core/sqlite_wal.py:142`.

1. Introduce one private temporary DB/WAL snapshot lifecycle shared by browser, CLI preview/search, and Web API SQLite reads.
2. Never connect SQLite to the evidence database. Rebuild shared-memory indexes only in the working directory.
3. Detect evidence-set changes during copying and reject unsupported hot rollback-journal states; never silently omit a present WAL.
4. Preserve original paths in citations; identify DB and WAL as a participating evidence set rather than imply the DB hash covers WAL-derived rows.
5. Close connections and remove all working sidecars on success or exceptions.

Acceptance: a committed WAL-only marker appears in browser and preview/search results; original file membership/content/mtime is unchanged, including when no source SHM exists. No-WAL, WITHOUT ROWID, bounded queries and cleanup behavior remain compatible. Ordinary reads may change atime; use write-blocked/no-atime acquisition storage for stronger guarantees. Copy stability detection is not an atomic live acquisition.

### Stage 3 — Hash scope, recovery selection, and resume integrity

Sources: `rapidtriage/core/e01_hash.py:22`, `rapidtriage/core/e01.py:1400`, `rapidtriage/core/disk_image.py:768`, `rapidtriage/core/hash_cache.py:46`, `rapidtriage/core/submission.py:91`.

1. Label container-file hashing separately from decoded-media hashing; record each segment digest and aggregate scope without calling container bytes an acquisition-media hash.
2. Remove contradictory allocated/all recovery flags; retain an explicit documented recovery scope.
3. Bind extraction resume to every source segment and current recovered-file inventory, tool inputs and options. Invalidate older/incomplete checkpoints safely.
4. Bypass metadata caches for explicit integrity/submission verification; retain cache only for performance paths that do not claim fresh verification.

Acceptance: a changed secondary segment or recovered file rejects reuse; unchanged data can resume; same-size metadata-preserving modifications change freshly verified hashes; multi-segment manifests include every segment and do not claim decoded-media verification. Real deleted-file recovery and libewf hash comparisons remain external validation requirements.

Status: implemented; thirteen new regressions in `tests/test_rapidtriage_stage3_integrity.py` plus existing e01/raw/hash/submission suites passed. `run_e01_streaming_hash` now hashes every discovered EWF segment, emits per-segment digests and a `hash_scope` record that explicitly disclaims decoded/acquisition-media hashing. `tsk_recover` runs with `-e` only; the contradictory `-a` allocated-only flag was removed and each extraction records an explicit `recovery_scope`. Stage checkpoints moved to `e01-stage-checkpoint-v2`/`raw-image-stage-checkpoint-v2` bound to every source segment signature, recovery tool inputs, and a recovered-inventory content fingerprint; legacy or incomplete checkpoints no longer resume. `build_submission_manifest` bypasses the metadata-keyed hash cache via `compute_hashes_fresh`; `compute_hashes` remains the documented performance path. The run-level incremental checkpoint system already binds reuse to input fingerprints and was out of scope. File mtime/size binding still cannot detect same-size same-mtime same-inode source modification before extraction; per-segment content hashing at intake remains external evidence.

### Stage 4 — Consistent trust-boundary defenses

Sources: `rapidtriage/web/static/app_utils.js:4`, `rapidtriage/cli/web.py:32`, `rapidtriage/api/app/factory.py:31`, `rapidtriage/core/cloud_api.py`.

1. Escape imported metric values, preserving valid number rendering.
2. Reject auth-disable settings when authenticated remote operation is requested; do not silently weaken explicit authentication requirements.
3. Scope credential forwarding to approved origins on pagination and redirects; reject HTTPS downgrades and validate each hop.
4. Record sidecar confinement, output symlink defenses, native-tool sandboxing and recursive diagnostic redaction as separate bounded follow-ups rather than imply these are covered by one API fix.

Acceptance: benign imported markup renders as text; contradictory remote auth settings fail before server startup; cross-origin pagination/redirects never receive credential headers; same-origin acquisition and bounded pagination still work. Use dummy credentials and mocked transports only.

Status: implemented; thirteen new regressions in `tests/test_rapidtriage_stage4_boundaries.py` plus existing remote-mode/API-security/cloud suites passed. `metric()` now escapes the value through `escapeHtml` alongside the label, so imported markup renders as text while numeric rendering is preserved. `run_web_server` rejects `--remote` combined with `RAPIDTRIAGE_DISABLE_AUTH`, and `create_app` raises on `require_auth=False`/`RAPIDTRIAGE_DISABLE_AUTH` combined with an explicit token argument or `RAPIDTRIAGE_AUTH_TOKEN`, so conflicting settings fail before server startup instead of silently weakening authentication. Cloud collection adds `CredentialScopedRedirectHandler`, `validate_hop_url`, `url_origin`, and `strip_credential_headers`: every redirect and pagination hop is revalidated against the same HTTP/HTTPS policy (including `allow_insecure_http` propagation), HTTPS-to-HTTP downgrades to non-loopback hosts are refused, and credential headers (`Authorization`, `X-Api-Key`, `api-key`) are stripped on any cross-origin hop; the pagination execution profile records `cross_origin_hop_count` and `credential_headers_stripped_cross_origin`. Dummy credentials and local test servers were used only; no live cloud collection. Sidecar confinement, output symlink defenses, native-tool sandboxing, and recursive diagnostic redaction remain separate bounded follow-ups, not covered by this stage.

### Stage 5 — Remove measured structural performance costs

Sources: `rapidtriage/artifacts/windows/filesystem.py:1320`, `rapidtriage/core/hash_cache.py:50`, `rapidtriage/core/case_db/database.py:538`, `rapidtriage/core/jobs.py:296`, `rapidtriage/web/static/app.js:8910`.

1. Compute MFT/USN source hashes once per source, not twice per row.
2. Replace whole-cache scans with direct per-path invalidation; do not trade away fresh verification guarantees.
3. Repair columnar next/previous offset propagation and test page boundaries.
4. Separately design schema initialization outside search, health diagnostics off the request path, stable keyset pagination, and streamed storage ingestion. These need compatibility tests and representative cases before broad refactoring.

Acceptance: N emitted MFT/USN rows cause a constant number of source hash calls; cache warm lookup does not iterate unrelated entries; first/middle/last columnar pages preserve navigation. No end-to-end speedup claim from call-count tests. Publish actual timings only on executed comparable workloads.

Status: implemented; eight new regressions in `tests/test_rapidtriage_stage5_performance.py` plus existing windows-collector/columnar/stage-3 suites passed. `collect_native_ntfs_artifacts` now hashes each MFT/USN source exactly once and threads the digest through `build_mft_inventory_record`, `build_usn_journal_inventory_record`, `build_native_mft_record`, and `build_native_usn_record` via a `source_hashes` keyword, so N emitted rows cost one source hash call instead of 4+N·2 full-file reads. `compute_hashes_cached` keeps a `_HASH_CACHE_PATH_INDEX` so warm lookups and same-path stale invalidation no longer iterate unrelated cache entries; snapshot import registers keys in the index and fresh-verification guarantees (`compute_hashes_fresh` bypass) are unchanged. Columnar pagination now propagates `next_offset`/`previous_offset` end to end: `query_columnar_artifact_records` emits `previous_offset`, and a pure `columnarPagination` helper in `app_utils.js` maps the response into the `renderPaginationControls` contract, fixing Next-page self-reloads and permanently-enabled Previous. Schema initialization inside `search_case`, health diagnostics on the request path, stable keyset pagination, and streamed storage ingestion remain separately designed follow-ups; they are not claimed by this stage. Call-count and iteration tests measure structural behavior only — no end-to-end speedup is claimed.

### Stage 6 — Accuracy, containment, and release gates

1. Add capability tiers separating inventory, bounded native parsing, external import, and independent validation; keep taxonomy coverage an omission check.
2. Build a versioned synthetic and externally acquired known-answer matrix for WAL, image segments, timestamps, archive member identity and parser omissions.
3. Enforce child-process resource and filesystem/network boundaries before treating hostile evidence handling as sandboxed.
4. Split parser decoding from reportability policies; undertake search/storage/UI migrations as separately reviewed changes.
5. Require coverage execution, real build/install smoke, actionable dependency advisory disposition, and explicit platform validation for release.
6. Keep Windows E01/Ex01 recovery, trusted-tool record diffs, TB-scale runs, installer signing and independent human review blocked until externally supplied evidence exists.

Acceptance: each capability links to executed tests and known limitations; unexecuted checks report unavailable/blocked. No signing, legal suitability, recovery recall, or TB performance is inferred from synthetic fixtures.

Status: implemented; twelve new regressions in `tests/test_rapidtriage_stage6_release_gates.py` plus existing e01/hash/stage-3/4/5 suites passed. New `rapidtriage/core/process_bounds.py` provides `run_bounded_command`, a shared runner enforcing wall-clock timeout (default 3600 s, `RAPIDTRIAGE_CHILD_TIMEOUT_SECONDS`) plus POSIX RLIMIT_CPU/RLIMIT_FSIZE/RLIMIT_NOFILE, converting timeouts into a synthetic `returncode=124` CompletedProcess so existing nonzero-returncode failure paths stay intact; the four tool `default_runner`s (e01, disk_image, virtual_disk, archive_image) now route through it. `child_process_boundary_profile` explicitly records filesystem isolation, network isolation, RLIMIT_AS, and RLIMIT_NPROC as not enforced and `hostile_evidence_sandboxed=False` — bounded execution is not claimed as sandboxing. New `rapidtriage/core/release_gates.py` emits `build_release_gate_manifest` aggregating: a capability-tier manifest mapping every `visible_capabilities` entry to inventory / bounded-native-parsing / external-import / independent-validation with per-group executed-test links and known limitations (taxonomy coverage remains an omission check); a versioned known-answer coverage matrix for WAL, image segments, timestamps, archive member identity, and parser omissions with the external corpus slot blocked; a parser/reportability boundary record; and release gate slots where coverage measurement, build/install smoke, Windows/Linux platform validation, Windows E01/Ex01 recovery, trusted-tool diffs, TB-scale runs, installer signing, and independent human review stay blocked until externally supplied evidence exists. `release_ready` and `ready_for_court_report` remain False.

### Post-stage bounded follow-ups

Status: executed; six regressions in `tests/test_rapidtriage_hardening_followups.py` pass.

- **Output symlink defenses** — `run_extract` now rejects a destination that is itself a symlink or resolves outside the resolved output directory (`destination-outside-output-dir` skip reason), so `shutil.copy2`/`overwrite=True` cannot write through an attacker-planted symlink; symlinked destination parents are rejected on the same `resolve()` check. Source-side symlink and evidence-root confinement were already enforced.
- **Recursive diagnostic redaction** — `sanitize_context` now walks nested mappings and sequences; sensitive keys (`token`, `secret`, `password`, `credential`, `cookie`) redact at any depth, strings truncate at 500 chars, recursion is depth-bounded (8) and collections are size-bounded (200 items). Crash reports remain local-only with no automatic upload.
- **Schema initialization off the search path** — `apply_schema` returns early when the database is already at `SCHEMA_VERSION` with all migration columns, so `search_case` no longer replays the full DDL script per query; missing columns still migrate and unsupported versions still fail closed.
- **Sidecar confinement** — covered by `sqlite_snapshot` (Stage 2): WAL/SHM/journal files are only ever materialized inside the private temp working directory and are removed on exit.
- **Child-process boundaries** — covered by `process_bounds` (Stage 6): time/CPU/output limits enforced; filesystem and network isolation remain explicitly unimplemented and unclaimed.

Remaining open follow-ups (design-level, require separate review and representative cases): stable keyset pagination for large case searches, streamed storage ingestion, native-tool OS-level filesystem/network sandboxing, and historical fixture DB migration coverage.

### Verification protocol and risks

- Use the isolated Python 3.12 validation environment; redirect HOME, TMPDIR and crash/app-data paths outside real user state; remove credentials from subprocess environments.
- Run changed-module unittest suites, then broader safe suites. Full discovery has network scans and home-directory probes; execute only after isolation or explicit exclusions are recorded.
- Run `python -m ruff check rapidtriage tests scripts`, `python -m vulture rapidtriage tests scripts --min-confidence 80`, Python compilation, and `node --check` for changed JavaScript.
- The repository has no configured Python typechecker. Do not describe compilation as type checking; choose a gradual typecheck baseline separately.
- Use `git diff --check` and independent patch review. Record exact counts and failures, not only summaries.
- Main risks: SQLite live-copy races, full hashing I/O cost, checkpoint compatibility, remote-auth configuration changes, pagination order changes, optional dependency/platform gaps. Fail closed for evidence ambiguity; preserve existing output contracts where possible; test unaffected behavior.

## Purpose

This plan records the hardening work required to move RapidForensic/RapidTriage from a Mac-local engineering build toward a production release. It is governed by the canonical priority order:

1. Security.
2. Correctness.
3. Reproducibility.
4. Defensibility.
5. Performance.
6. Features.

## Current Execution Scope

The 2026-05-31 execution pass covers Mac-local work that can be implemented and verified without a Windows host, commercial forensic tools, a signed installer pipeline, or external legal/operator review.

Completed Mac-local hardening areas:

| Area | Status | Evidence |
| --- | --- | --- |
| Baseline tests | PASS | `python3.12 -m unittest discover -s tests`: ran 753 tests; OK (skipped=59) |
| Python syntax | PASS | `python3.12 -m compileall -q rapidtriage tests scripts` |
| JavaScript syntax | PASS | `node --check rapidtriage/web/static/app_workbench_config.js`, `app_state.js`, `app.js` |
| Rust engine build | PASS | `cargo check --workspace --all-targets --locked` in `engines/rust` |
| Static analysis | PASS | `ruff check rapidtriage tests scripts`; `vulture rapidtriage tests scripts --min-confidence 80` |
| Dependency audit | PASS | `pip-audit .`: no known vulnerabilities found |
| Extraction path safety | PASS | outside-root extraction now fails closed |
| Bundle manifest authority | PASS | in-archive manifest is marked non-authoritative; external manifest carries archive hashes |
| Case DB schema safety | PASS | unsupported existing schemas are rejected before mutation |
| Case DB audit immutability | PASS | `audit_event` rejects update and delete |
| XML parser safety | PASS | Office/API XML preview rejects DTD/entity constructs |
| Web API default auth | PASS | `/api` routes require a header token by default and reject untrusted Host/Origin |

## Security Hardening Decisions

| Finding | Decision | Verification |
| --- | --- | --- |
| Extraction path traversal | Reject selected source files that resolve outside the declared analysis root. No `_external` fallback when a trusted root exists. | `tests.test_rapidtriage_extract_contract` |
| Stale zip bundle manifest | Keep the zip member manifest as a pre-archive member list and require the external manifest for archive hashes. | `tests.test_rapidtriage_api` when FastAPI is available |
| Unsupported Case DB mutation | Read existing `schema_info` through a read-only URI before applying schema. | `tests.test_rapidtriage_case_db` |
| Mutable audit log rows | Add append-only SQLite triggers for `audit_event`. | `tests.test_rapidtriage_case_db` |
| Unsafe XML parsing | Add bounded unsafe construct rejection before `ElementTree.fromstring`. | `tests.test_rapidtriage_docs`, `tests.test_rapidtriage_api` |
| Unauthenticated local API | Generate a token by default and require `X-RapidTriage-Token` for `/api`. | `tests.test_rapidtriage_api`, `tests.test_rapidtriage_ops` with FastAPI test env |

## Release Gate Status

| Gate | Status | Reason |
| --- | --- | --- |
| Security Review | PASS for Mac-local blockers fixed; external release review pending | Code review blockers from the local pass were fixed. Formal external security signoff is not attached. |
| Static Analysis | PASS | Ruff and Vulture pass in the temporary static-tools environment. |
| Unit Tests | PASS | `unittest` ran 753 tests in the base Python 3.12 environment; OK (skipped=59). |
| Integration Tests | PARTIAL | FastAPI-dependent tests require optional dependencies; targeted FastAPI env was executed separately. |
| Migration Validation | PARTIAL | Current schema safety tests pass; historical fixture DB migration set is still absent. |
| Accuracy Validation | PARTIAL | Internal known-answer package exists; external trusted-tool diffs are absent. |
| Reproducibility Validation | PARTIAL | Deterministic sample and fixture tests pass; same-machine normalized rerun package is not yet attached for every release artifact. |
| Performance Validation | PARTIAL | Existing benchmark/readiness commands exist; 100k/1M/10TB release evidence is not attached. |
| Large Dataset Validation | FAIL BLOCKER | No 10TB representative corpus or 1M-file completed run evidence is present. |
| Report Defensibility Review | FAIL BLOCKER | Technical package fields exist, but forensic methodology, operator, and legal reviews are not attached. |
| Documentation Review | PARTIAL | New PRD, test spec, architecture, and blocker ledger are created; external release-doc review is not complete. |

## Hard Blockers

These blockers cannot be closed on the current Mac-only host without external evidence or review:

1. Real Windows/E01 recovery accuracy: requires representative Windows E01/Ex01 evidence, known answers, and trusted-tool exports from EnCase, X-Ways, Sleuth Kit, MFTECmd/analyzeMFT, or equivalent.
2. SSD deleted-file recovery truth: TRIM and wear-leveling can make deleted data unrecoverable; claims require case-specific device/acquisition evidence and trusted comparisons.
3. 10TB/1M-file survival: requires a representative large corpus, long-run telemetry, and completion artifacts.
4. Legal/operator release signoff: requires technical, forensic methodology, operator, and legal review completion.
5. Windows packaging and runtime: requires Windows host smoke tests, installer/signing decisions, external tool discovery, and path/encoding validation.

## Next Required Evidence Package

Before production release, create and attach:

- `trusted-tool-diff.json` for each source type claimed beyond internal fixtures.
- `recovery-accuracy.json` with precision, recall, false positive, false negative, and hash-match metrics.
- `reproducibility-diff.json` with 100% normalized material equivalence or explicit release failure.
- `large-case-benchmark.json` for 100k files, 1M metadata rows, and the approved 10TB-class corpus.
- `legal-operator-review-checklist.md` with completed technical, forensic methodology, operator, and legal reviews.
- Windows runtime logs for E01/Ex01, Korean filename handling, viewer smoke, extraction export, and interruption/resume.

## UI/UX Follow-up Roadmap

Implemented in the intake/UX pass (see git history around `5db5293`+):

- Evidence path picker (`GET /api/browse` + `core/browse.py`), browse buttons on all path inputs, intake cards opening the picker, auto support-check on image selection, EWF segment-count/warning surfacing.
- Readability floor: font-size floor 0.72rem, `--rf-type-*` scale bump, 44px primary / 34px compact controls.
- First-screen declutter, mission strip made into real step navigation, dev/QC diagnostics stay behind `details` drawers.

Remaining structured work (not claimable as done):

1. `app.js` (~9.5k lines) module split: tab renderers, search, viewers, report into separate ES modules — review each split as an independent change.
2. CSS `!important` reduction: safe only after the op-*/rf-* alias layer stabilizes; remove in per-section commits with visual diff checks.
3. Remote deployment: `/api/browse` enumerates the API host filesystem (see `core/browse.py` docstring). A remote-capable picker requires an upload or local-agent design — not implemented and not claimed.
4. Historical fixture DB migration coverage, stable keyset pagination, streamed storage ingestion, OS-level process sandboxing: unchanged from earlier stages.
