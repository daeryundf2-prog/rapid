# RapidTriage Release Checklist

## Required Checks

- Run `python -m unittest discover -s tests`.
- Run `python -m compileall -q rapidtriage`.
- Run `python -m ruff check rapidtriage tests scripts`.
- Run `python -m vulture rapidtriage tests scripts --min-confidence 80`.
- Run `python scripts/known-answer-qc.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --check-files --fixture-root tests/fixtures/known_answer/tier0-basic/files --json`.
- Run `python scripts/trusted-diff.py --manifest tests/fixtures/known_answer/tier0-basic/manifest.json --rapid-results tests/fixtures/known_answer/tier0-basic/rapid-results.json --trusted-results tests/fixtures/known_answer/tier0-basic/trusted-results.json --json`.
- Run `python scripts/normalize-trusted-export.py --tool synthetic-tsv --input tests/fixtures/known_answer/tier0-basic/synthetic-trusted-export.tsv --json`.
- Run `python scripts/build-evidence-bundle.py --root tests/fixtures/known_answer/tier0-basic --json`.
- Run `node --check rapidtriage/web/static/app.js`.
- Run `python -m build --wheel --sdist`.
- Run `rapidtriage sample --run --overwrite`.
- Run `rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite`.
- Run `rapidtriage columnar-benchmark --output-dir ./release-columnar-benchmark --record-count 100000 --json`.
- Run `rapidtriage validation --output-dir ./release-validation --overwrite`.
- On Windows, run `.\scripts\windows\smoke-test-rapidtriage.ps1`.
- On macOS/Linux, run `sh scripts/smoke-test-rapidtriage.sh`.
- Run `python scripts/build-release.py --output-dir release` and attach `SHA256SUMS` plus `dependency-inventory.txt`.
- Run `python scripts/build-release.py --output-dir release --verify`.
- Run `python scripts/check-dependencies.py --output logs/dependency-monitoring.json` and attach the dependency monitoring/SBOM evidence.
- Run `python scripts/operations-security-readiness.py --output logs/operations-security-readiness.json --work-dir logs/operations-security-readiness --overwrite --json` and attach the numbered #108/#109/#110/#111/#118/#119/#120 readiness manifest plus component hashes.
- Run `python scripts/internal-release-evidence-bundle.py --output-dir logs/internal-release-evidence --overwrite` before external sign-off. This creates internal #116-#120 evidence for the analyst quickstart lab, admin deployment smoke, security-hardening review, synthetic hostile corpus, parser sandbox smoke, dependency monitoring, release checksum linkage, and an explicit `commercial_claim_allowed=false` blocker manifest.
- Run `python scripts/external-release-evidence-template.py --output logs/external-commercial-evidence.json`, then fill it with real CI/SBOM/signing/notarization/platform-smoke/package-smoke evidence before the final verifier run.
- Run `python scripts/hostile-evidence-containment-template.py --output logs/hostile-evidence-containment.json`, then fill it with real sandbox design, OS-level sandbox, hostile probe, malicious corpus, and fuzz/quarantine evidence before the final verifier run.
- Run `python scripts/independent-operations-evidence-template.py --output logs/independent-operations-evidence.json`, then fill it with real independent review, support SLA, hotfix drill, and final commercial release gate evidence before the final verifier run.
- Run `python scripts/crash-export-smoke.py --output-dir logs/crash-export-smoke --json`, `python scripts/crash-redaction-review.py logs/crash-export-smoke/crash-export-smoke.json --json`, `python scripts/parser-sandbox-smoke.py --output logs/parser-sandbox-smoke.json --json`, and `python scripts/security-hardening-review.py --output logs/security-hardening-review.json --json` on the release host.
- Run `python scripts/verify-release-evidence.py --release-dir release --validation-dir release-validation --benchmark-dir release-benchmark --columnar-benchmark-dir release-columnar-benchmark --smoke-dir rapidtriage-windows-smoke --smoke-dir rapidtriage-macos-linux-smoke --require-smoke-platform windows --require-smoke-platform macos-linux --crash-smoke-json logs/crash-export-smoke/crash-export-smoke.json --crash-redaction-review-json logs/crash-export-smoke/crash-redaction-review.json --parser-sandbox-smoke-json logs/parser-sandbox-smoke.json --dependency-monitoring-json logs/dependency-monitoring.json --security-hardening-review-json logs/security-hardening-review.json --external-release-evidence-json logs/external-commercial-evidence.json --hostile-evidence-containment-json logs/hostile-evidence-containment.json --independent-operations-evidence-json logs/independent-operations-evidence.json`.
- Attach `release-manifest.json`, `smoke-summary.json`, and `smoke-summary.md` for each smoke-tested platform.
- If `release-evidence-report.md` fails, resolve its Next Actions before distributing the build.
- Run the Windows/macOS usability checklist in `docs/rapidtriage-fresh-machine-smoke-test.md` before calling the release analyst-ready.
- Attach SHA256 checksums, dependency inventory/SBOM, and signing/notarization verification output for every distributed artifact.
- Attach independent validation notes for parser corpus, large-case performance, and legal/report wording review.
- Designed: E01/Ex01 known-answer corpus requirements are documented in `docs/validation/known-answer-corpus/README.md`.
- Implemented: Tier 0 synthetic validation plumbing, observed-result normalization, trusted-diff skeleton, and bundle manifest generation are implemented for engineering checks only.
- Executed: Real E01/Ex01, Windows NTFS, trusted/reference tool, scale, and review evidence remains required before any E01/Ex01 recovery readiness claim.
- Reviewed: Technical, forensic methodology, operator, and legal review records must be attached before release suitability can be claimed.
- Track external commercial blockers in `docs/rapidtriage-external-commercial-evidence-plan.md` and do not remove release blockers until the required external evidence is attached.

## Artifact Build

```bash
python scripts/build-release.py --output-dir release
```

Expected artifacts:

- Wheel and source distribution when build is not skipped.
- `rapidtriage-portable.zip`.
- Windows launchers.
- User guide and Windows quick-start docs.
- macOS/Linux quick-start docs, E01 workflow docs, and fresh-machine smoke test docs.
- Release validation JSON/Markdown package.
- SHA256SUMS, signing/notarization evidence, and dependency inventory/SBOM.
- Optional operations/security readiness bundle containing `operations-security-readiness.json`, `enterprise-policy.json`, `rbac-permission-smoke.json`, `backup-restore-drill-smoke.json`, `case-backup.json`, `case-restore.json`, `security-hardening-review.json`, `parser-sandbox-smoke.json`, `dependency-monitoring.json`, and component `SHA256SUMS`.
- Optional internal evidence bundle under `logs/internal-release-evidence/` containing `internal-release-evidence-bundle.json`, `quickstart-lab-run.json`, `admin-deployment-smoke.json`, `synthetic-hostile-corpus-manifest.json`, `parser-sandbox-smoke.json`, `security-hardening-review.json`, `dependency-monitoring.json`, `dependency-release-linkage.json`, and bundle `SHA256SUMS`.
- `release-evidence-report.json` and `release-evidence-report.md` showing PASS/FAIL for release, validation, benchmark, optional columnar benchmark, platform smoke, crash-export/redaction, parser-isolation smoke, dependency-monitoring, and security-hardening self-review evidence.
- Support contact/SLA document and emergency parser-fix policy.

## Release Notes Must Include

- Supported evidence inputs and limitations.
- E01/Ex01 external tool requirements.
- Test and benchmark result summary.
- Known parser coverage gaps.
- Security note for non-localhost web binding.
- Signing/notarization status for Windows/macOS artifacts.
- Independent validation scope, known false positives/false negatives, and support SLA/escalation contact.
- Migration notes for Case DB, report format, parser output, and deployment changes.
