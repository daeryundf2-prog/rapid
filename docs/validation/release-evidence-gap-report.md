# Release Evidence Gap Report

Status: current in-repo assessment
Date: 2026-06-18

## Engineering Complete Status

In-repo validation plumbing is implemented for:

- Truth manifest schema validation.
- Known-answer QC JSON output.
- Tier 0 synthetic file hash checks.
- Observed results schema.
- Trusted diff schema and skeleton comparator.
- Synthetic trusted export normalizer.
- Release evidence bundle manifest generator.
- T1 E01/Ex01 procedure and schema-valid templates.
- Windows smoke checklist.

This is engineering evidence only. It is not production release evidence.

## Engineering Baseline Verification

Status: Green for in-repo engineering baseline.

Verification evidence:

- Clean venv: `/tmp/rapidtriage-green-baseline-venv-20260618-061922`
- Logs: `/tmp/rapidtriage-green-baseline-logs-20260618-061922`
- Dependency install: PASS.
- JSON Schema `Draft202012Validator.check_schema`: PASS.
- Validation scripts: PASS.
- Unit tests: 774 tests OK, skipped=1.
- Ruff: PASS.
- Vulture: PASS.
- Compileall: PASS.
- Pip-audit: PASS, no known vulnerabilities found.
- JS syntax: PASS.
- Rust fmt/check/test: PASS.
- `git diff --check`: PASS.

## In-Repo Validation Plumbing

| Area | State | Evidence |
| --- | --- | --- |
| Truth manifest schema | implemented | `docs/validation/known-answer-corpus/truth-manifest-schema-v1.schema.json` |
| Known-answer QC | implemented | `rapidtriage/validation/known_answer.py`, `scripts/known-answer-qc.py` |
| Tier 0 fixture | implemented | `tests/fixtures/known_answer/tier0-basic/` |
| Validation result schema | implemented | `docs/validation/known-answer-corpus/validation-result-schema-v1.schema.json` |
| Observed results schema | implemented | `docs/validation/known-answer-corpus/observed-results-schema-v1.schema.json` |
| Trusted diff | implemented | `rapidtriage/validation/trusted_diff.py`, `scripts/trusted-diff.py` |
| Trusted export normalizer | implemented | `rapidtriage/validation/normalizers.py`, `scripts/normalize-trusted-export.py` |
| Evidence bundle generator | implemented | `rapidtriage/validation/evidence_bundle.py`, `scripts/build-evidence-bundle.py` |
| Windows smoke checklist | designed | `docs/validation/windows-smoke-checklist.md` |
| Windows T1 execution runbook | designed | `docs/validation/windows-t1-execution-runbook.md` |
| Windows T1 operator inputs | designed | `docs/validation/windows-t1-operator-inputs.md` |
| Windows T1 command template | designed | `docs/validation/windows-t1-command-template.ps1.md` |
| T1 procedure/templates | designed | `docs/validation/known-answer-corpus/t1-minimal-e01-ex01-corpus-procedure.md` |

## Release Evidence Blockers

| Blocker | State | Needed Artifact | Status |
| --- | --- | --- | --- |
| Actual T1 E01 corpus | designed | External E01 image, hashes, truth manifest, logs | blocked external |
| Actual T1 Ex01 corpus | designed | External Ex01 image, hashes, truth manifest, logs | blocked external |
| Windows-generated NTFS proof | designed | Windows host record and NTFS source procedure logs | blocked external |
| Real trusted/reference export | implemented skeleton | Normalized trusted output plus raw export custody record | blocked external |
| RapidForensic real E01/Ex01 run | not executed | Rapid observed results and logs | blocked external |
| SSD/TRIM truth-set | designed only | Controlled SSD/TRIM corpus and expected outcomes | blocked external |
| Scale validation | not executed | Large dataset run log, runtime, memory, completion evidence | blocked external |
| SBOM/advisory/checksum evidence | checklist only | SBOM, dependency audit, release checksums | blocked external |
| Technical review | not reviewed | Signed technical review record | blocked external |
| Forensic methodology review | not reviewed | Signed methodology review record | blocked external |
| Operator review | not reviewed | Operator workflow review record | blocked external |
| Legal review | not reviewed | Legal wording and suitability review record | blocked external |

## Required Windows Work

1. Prepare Windows host and external evidence storage.
2. Generate T1 synthetic NTFS source tree.
3. Acquire E01 and Ex01 outside Git.
4. Record SHA-256, tool versions, and chain-of-custody.
5. Run engineering scripts and capture JSON outputs.
6. Run RapidForensic and trusted/reference tools.
7. Build release evidence bundle manifest.

## Required Trusted Tool Work

1. Choose approved trusted/reference tools.
2. Execute exports outside Git.
3. Normalize outputs with `scripts/normalize-trusted-export.py`.
4. Compare with `scripts/trusted-diff.py`.
5. Attach raw export custody notes where license policy permits.

## Required Review Signoff

Release blockers remain until these records exist:

- Technical review.
- Forensic methodology review.
- Operator review.
- Legal review.

## Production/Release Claim

Not allowed yet.

The repository can claim in-repo engineering validation plumbing only after verification passes. It cannot claim production readiness or release suitability until the external evidence blockers above are resolved.

## Next Execution Order

1. Review and commit in-repo engineering changes.
2. Re-run engineering baseline from a clean clone.
3. Prepare Windows host and external evidence storage.
4. Fill `docs/validation/windows-t1-operator-inputs.md`.
5. Follow `docs/validation/windows-t1-execution-runbook.md`.
6. Generate T1 NTFS source tree.
7. Acquire E01.
8. Acquire Ex01 if approved tooling is available.
9. Capture hashes and chain-of-custody.
10. Generate trusted/reference exports.
11. Normalize trusted/reference exports.
12. Run RapidForensic and export normalized results.
13. Run known-answer QC.
14. Run trusted diff.
15. Build release evidence bundle manifest.
16. Run scale validation.
17. Complete independent technical, methodology, operator, and legal review.
18. Make final release decision.
