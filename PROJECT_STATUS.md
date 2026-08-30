# RapidForensic Project Status

Date: 2026-08-30
Branch: `codex/rapidforensic-complete`
Tag: `v0.2.0` (restart baseline)

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
