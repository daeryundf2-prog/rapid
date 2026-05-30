# RapidForensic Hardening Plan

Status: active execution record
Date: 2026-05-31
Plan authority: `docs/plans/rapidforensic-recovery-review-plan-2026-05-30.md` at commit `9973672931e31a40174d0087a72feae6a0f7620c`

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
