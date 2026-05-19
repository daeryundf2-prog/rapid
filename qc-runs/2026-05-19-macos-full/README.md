# macOS full verification run - 2026-05-19

This folder captures Mac-local evidence generated before the Windows handoff.
It is intentionally scoped to what can be verified on macOS without external
signing, independent lab validation, or real multi-TB evidence hardware.

## Result

- Smoke suite: PASS (`smoke/smoke-summary.json`)
- macOS live smoke: 85.71 local score, 6/7 checks passed (`macos-live-smoke/macos-live-smoke.json`)
- Commercial readiness: 90/100 internal readiness, 120/120 implemented/usable/validated, 0/120 commercial-grade (`commercial-readiness/rapidtriage-commercial-readiness.json`)
- Taxonomy audit: strict pass, 51/51 targets covered (`taxonomy-audit.json`)
- Release evidence verifier: PASS, 52 pass / 0 fail / 4 skip (`release-evidence-python312/release-evidence-report.json`)
- Internal release evidence bundle: all internal checks passed, commercial claim still blocked (`internal-release-evidence/internal-release-evidence-bundle.json`)

## Mac evidence produced

- Portable release package and SHA256 manifest: `release/`
- Sample case smoke, benchmark, validation package, web static check: `smoke/`
- macOS live collection/readiness evidence: `macos-live-smoke/`
- Dependency monitoring, crash redaction, parser sandbox, hardening review: `ops-security/`
- External evidence templates for later trusted evidence attachment: `ops-security/*template.json`

## Important findings

- Python 3.9 verification environment could not upgrade `filelock` to the fixed
  line because current fixed releases require Python 3.10+.
- A separate Python 3.12 verification environment resolved that dependency
  issue: `filelock=3.29.0`, `pip=26.1.1`, and `pip-audit` reported zero
  vulnerable packages in `ops-security/dependency-monitoring-python312-after-pip-upgrade.json`.
- Commercial-grade claims remain blocked. This run supports Mac-local readiness
  only; it does not replace Windows signed installer evidence, Apple
  notarization, independent AppSec review, trusted forensic cross-tool diffs,
  or real 1TB-10TB stress runs.

## Verification commands

- `scripts/smoke-test-rapidtriage.sh --output-dir qc-runs/2026-05-19-macos-full/smoke --venv-dir .venv --port 8879`
- `rapidtriage macos-live-smoke --output-dir qc-runs/2026-05-19-macos-full/macos-live-smoke --benchmark-file-count 500 --fts-record-count 5000 --keyword password --overwrite --json`
- `rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --output-dir qc-runs/2026-05-19-macos-full/commercial-readiness --json`
- `rapidtriage taxonomy-audit --repo-root /Users/shinyoohag/rapidforensic/repo --strict --json`
- `scripts/verify-release-evidence.py --release-dir qc-runs/2026-05-19-macos-full/release --validation-dir qc-runs/2026-05-19-macos-full/smoke/validation --benchmark-dir qc-runs/2026-05-19-macos-full/smoke/benchmark --smoke-dir qc-runs/2026-05-19-macos-full/smoke --require-smoke-platform macos-linux --dependency-monitoring-json qc-runs/2026-05-19-macos-full/ops-security/dependency-monitoring-python312-after-pip-upgrade.json --output-dir qc-runs/2026-05-19-macos-full/release-evidence-python312`
- `python -m unittest tests.test_rapidtriage_web_static tests.test_rapidtriage_macos_live_smoke tests.test_rapidtriage_large_case_readiness tests.test_commercial_readiness_validation_bundle tests.test_internal_release_evidence_bundle`
- `python3.12 -m unittest tests.test_rapidtriage_web_static tests.test_rapidtriage_macos_live_smoke tests.test_internal_release_evidence_bundle`
- `git diff --check`
