# RapidForensic Project Status

Date: 2026-08-30
Branch: `codex/rapidforensic-complete`
Tag: `v0.2.0` (restart baseline)

## Phase 4 Release Infrastructure Update (2026-08-30)

- **CI "Run tests" failures fixed on Linux runners** (the 6 failures in run 33302473677
  were pre-existing, not regressions): output-sample fixtures embedded timestamps
  rendered in the generating machine's local timezone (KST), so UTC CI runners
  mismatched by 9 hours; `docs`/`files`/`extract` mtime rendering now always emits
  UTC (`fromtimestamp(..., tz=timezone.utc)`), and the affected sample fixtures were
  regenerated against UTC output. The print-spooler SHD/SPL companion detector used
  lowercase suffix lookups that only worked on case-insensitive filesystems —
  sibling matching is now case-insensitive, fixing the Linux-only
  `orphan-spool-file` misclassification.
- CI lint gate restored: ruff's expanded default rule set (0.16.x) reported ~1,400
  findings that predate this baseline; `ruff` is now pinned to `0.8.*` in the test
  extra until a cleanup pass upgrades the codebase (all checks pass on 0.8.6).
- Dependency monitoring workflow hardened: clean-venv advisory scan now also
  records scanner/environment versions, generates a CycloneDX SBOM
  (`pip-audit --format cyclonedx-json`, verified locally at 324 components), and
  uploads the SBOM + monitoring JSON + scanner environment as CI artifacts —
  closing the "SBOM publication" and "scanner version capture" slots of #120
  (artifact URLs pending the next CI run; the workflow commit itself requires a
  push credential with `workflow` scope).
- `docs/validation/legal-operator-review-checklist.md` created: the four-track
  (technical / forensic methodology / operator / legal) review gate required before
  any release suitability claim. It is prepared and awaiting human reviewer signoff;
  automation must not mark reviews complete.
- `docs/release-signing-runbook.md` created with exact Authenticode, codesign+
  notarization, and deb/rpm/AppImage commands plus the evidence to attach to the
  installer workflow manifests. Signing itself remains blocked on external
  certificates, Apple Developer identity, and packaging host approval.

## Phase 3 Performance Evidence Update (2026-08-30, Windows 11 laptop)

Hardware context recorded in the external corpus (`hashes/hardware-scale-matrix.json`): i7-1165G7, 15.7GB RAM, NVMe SSD. All outputs in the external corpus `logs/` directory; nothing committed but findings.

- 100k-file synthetic benchmark (ingest + 20-iteration search): ingest 2,467.5s (40.5 rec/s, above the 25 rec/s floor), search p50 7.63s / p95 8.38s (release threshold 2.0s exceeded), peak Python memory 844MB (threshold 512MB exceeded). `release_threshold_status=needs-review` — search latency and memory are the performance work targets.
- 1M-record columnar benchmark: JSONL baseline 650MB, query p50 20.87s / p95 21.43s; Parquet 20.1MB (32x smaller) with DuckDB query p50 0.165s / p95 0.188s (~126x faster). This quantifies the columnar/Rust-sidecar payoff for large-case search.
- Browser e2e on the real workbench with the imported 100k run (run_id f962ebbebf1a): files table renders a bounded 251-row window for the 100k dataset (6,334 DOM nodes, 9MB JS heap), in-page full-case search measured at 8.1s (consistent with server-side p95), `/api/workbench/large-result-evidence?record_count=100000` DOM budget passes (2400 estimated nodes vs 5000 budget). Screenshot capture unavailable in the automation environment; numeric evidence retained.
- 1TB/5TB/10TB stress runs remain pending approved forensic hardware.

## Phase 2 Trusted-Diff Update (2026-08-30, Windows 11 host, non-admin)

Trusted reference tools installed outside Git (`EvtxECmd`/`LECmd`/`JLECmd` 2026.5.0) and run against staged host artifacts. Evidence in the external corpus (`diffs/`, `trusted-exports/`, `rapid-results/`); nothing committed but the findings.

- LNK (#17): RapidForensic vs LECmd over 187 staged .lnk files — reference key coverage 291/291 (1.0), field diff on 78 common records 234/234 fields match, 0 mismatches. Internal trusted-diff pass; status stays Partial++ (single-host corpus).
- JumpList (#14): JLECmd emits one row per DestList entry (4,181 automatic); RapidForensic emits container-level rows only — entry-level trusted diff not possible yet. Gap confirmed by diff and recorded as the next parser-depth target.
- EVTX (#1-#3): record identity semantics mismatch exposed. `wevtutil epl` renumbers physical record headers to 1..N while BinXML keeps original EventRecordIds (116896+). EvtxECmd reports the BinXML id (Event Viewer semantics); RapidForensic reports the physical header id and its BinXML System decode does not surface EventRecordID. Record-level join is 0 until RapidForensic surfaces and prefers the BinXML EventRecordID. This is the top parser-depth blocker coming out of the diff.
- Cross-tool plumbing fixes: LECmd/JLECmd CSV column aliases (`LocalPath`, `EntryNumber`, `SourceFile` key field), user-activity family inference for destinations paths, and directory-source integrity hashing.
- Registry (#4-#5), MFT/USN (#12-#13), SRUM/Windows.edb (#10-#11), Prefetch (#16), Amcache/ShimCache (#7-#8) diffs remain pending: hives/locked files and Prefetch require an elevated host; see `docs/validation/windows-t1-operator-inputs.md`.

## Restart Baseline Update (2026-08-30, Windows 11 host)

- Windows platform defects fixed: the full unit suite now passes on a real
  Windows 11 host (790 tests, OK, skipped=2; previously 24 failures + 17
  errors). Root causes included CRLF checkout breaking known-answer hashes,
  an unclosed read-only sqlite3 handle locking case.db, Windows-only path
  mapping and input-root detection gaps, and loose mobile-artifact
  classification against `AppData` paths.
- `.gitattributes` now pins checkout bytes (`* -text`) so fixture SHA-256
  values are platform-independent; Windows shell scripts check out CRLF.
- Repository hygiene: bulk QC run outputs, dashcam-era run artifacts, and the
  broken legacy `windows/build-windows.ps1` were removed; the distribution
  name is now `rapidtriage` (version 0.2.0).
- Windows smoke run passes 8/8 checks; smoke scripts were fixed to
  authenticate the workbench smoke-contract request after default-token
  hardening.
- T1 staging outside Git at `C:\Users\Daeryun\rapid-forensic-corpus`:
  source-tree staged, hashes recorded, truth manifest written, folder
  baseline `known-answer-qc.py` PASS 9/9. E01/Ex01 acquisition and trusted
  tools remain pending; see `docs/validation/windows-t1-operator-inputs.md`.
- Known pre-existing issue: `ruff check` (ruff>=0.8 current release) reports
  ~1400 findings repo-wide due to lint version drift; CI lint gate needs
  pinning or a cleanup pass before the next release.

## Project Purpose

RapidForensic / rapidtriage is being hardened toward report-defensible forensic recovery validation. The current work focuses on in-repo engineering plumbing for known-answer validation, normalized result comparison, and release evidence packaging.

## Engineering Baseline Status

Status: Green for in-repo engineering baseline.

Implemented in-repo tooling:

- Truth manifest schema for E01/Ex01 known-answer cases.
- Known-answer QC validator with JSON output and Tier 0 file hash checking.
- Tier 0 synthetic folder fixture.
- Validation result JSON schema.
- Observed results JSON schema.
- Trusted diff result JSON schema.
- Trusted diff skeleton.
- Trusted export normalizer skeleton.
- Release evidence bundle manifest generator.
- Unit tests for the validation tooling.
- Release checklist and CI linkage for the validation commands.
- Windows T1 execution runbook, operator input form, and PowerShell command template.

Verified on 2026-06-26 with clean `/tmp` venv:

- VENV: `/tmp/rapid-next-validation-20260626T081620Z`
- Evidence log: `.omo/ulw-loop/evidence/rapid-next-commit.txt`
- `python -m unittest discover -s tests`: 774 tests OK, skipped=1.
- `python -m ruff check rapidtriage tests scripts`: PASS.
- `python -m vulture rapidtriage tests scripts --min-confidence 80`: PASS.
- `python -m compileall -q rapidtriage tests scripts`: PASS.
- `python -m pip_audit --format=json`: PASS, no known vulnerabilities found.
- `git diff --check`: PASS.
- `python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --check-files --fixture-root tests/fixtures/known_answer/tier0-basic/files --json`: PASS.
- `python scripts/trusted-diff.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json --json`: PASS.
- `python scripts/normalize-trusted-export.py --tool synthetic-tsv --input tests/fixtures/known_answer/tier0-basic/synthetic-trusted-export.tsv --json`: PASS.
- `python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json`: PASS.

## Release Evidence Status

Status: blocked external.

The repository does not contain actual E01/Ex01 binary evidence, trusted forensic tool exports, Windows-generated NTFS proof, large scale run evidence, or independent review records. Those must be produced outside Git and attached to a release evidence bundle before any release suitability claim.

## Primary Commands

```bash
python -m unittest discover -s tests
python -m ruff check rapidtriage tests scripts
python -m vulture rapidtriage tests scripts --min-confidence 80
python -m compileall -q rapidtriage tests scripts
python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --check-files --fixture-root tests/fixtures/known_answer/tier0-basic/files --json
python scripts/trusted-diff.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json --json
python scripts/normalize-trusted-export.py --tool synthetic-tsv --input tests/fixtures/known_answer/tier0-basic/synthetic-trusted-export.tsv --json
python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json
```

## Remaining Blockers

Engineering blockers:

- None known for in-repo engineering baseline as of 2026-06-26.

Release evidence blockers:

- Actual T1 E01 corpus generation outside Git.
- Actual T1 Ex01 corpus generation outside Git.
- Windows-generated NTFS evidence.
- Real trusted/reference tool exports.
- RapidForensic real E01/Ex01 run outputs.
- SSD/TRIM truth-set.
- Large dataset survival run.
- Dependency/SBOM/release checksum evidence for the release build.
- Technical review.
- Forensic methodology review.
- Operator review.
- Legal review.

## Next External Work

1. Review and commit the in-repo engineering changes.
2. Re-run the engineering baseline from a clean clone.
3. Prepare Windows host and external evidence storage.
4. Fill `docs/validation/windows-t1-operator-inputs.md`.
5. Follow `docs/validation/windows-t1-execution-runbook.md`.
6. Generate T1 Windows NTFS synthetic source tree.
7. Acquire E01 and Ex01 images outside Git.
8. Record hashes, tool versions, and chain-of-custody.
9. Run trusted/reference exports and normalize them.
10. Run RapidForensic and export normalized results.
11. Run trusted diff and build the release evidence bundle.
12. Complete independent reviews.

## Cautions

- Do not commit actual E01/Ex01 binaries or recovered evidence.
- Do not use customer data, PII, malware, secrets, or tokens.
- Do not describe Tier 0 synthetic checks as release evidence.
- Do not change recovery engine, parser, core forensic logic, API, Web UI, or DB schema as part of validation plumbing work.
- Complete `git status --short` after every substantial handoff.
