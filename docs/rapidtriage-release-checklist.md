# RapidTriage Release Checklist

## Required Checks

- Run `python -m unittest discover -s tests`.
- Run `python -m compileall -q rapidtriage`.
- Run `node --check rapidtriage/web/static/app.js`.
- Run `python -m build --wheel --sdist`.
- Run `rapidtriage sample --run --overwrite`.
- Run `rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite`.
- Run `rapidtriage validation --output-dir ./release-validation --overwrite`.
- On Windows, run `.\scripts\windows\smoke-test-rapidtriage.ps1`.
- On macOS/Linux, run `sh scripts/smoke-test-rapidtriage.sh`.
- Run `python scripts/build-release.py --output-dir release` and attach `SHA256SUMS` plus `dependency-inventory.txt`.
- Run `python scripts/build-release.py --output-dir release --verify`.
- Run `python scripts/verify-release-evidence.py --release-dir release --validation-dir release-validation --benchmark-dir release-benchmark --smoke-dir rapidtriage-windows-smoke --smoke-dir rapidtriage-macos-linux-smoke --require-smoke-platform windows --require-smoke-platform macos-linux`.
- Attach `release-manifest.json`, `smoke-summary.json`, and `smoke-summary.md` for each smoke-tested platform.
- If `release-evidence-report.md` fails, resolve its Next Actions before distributing the build.
- Run the Windows/macOS usability checklist in `docs/rapidtriage-fresh-machine-smoke-test.md` before calling the release analyst-ready.
- Attach SHA256 checksums, dependency inventory/SBOM, and signing/notarization verification output for every distributed artifact.
- Attach independent validation notes for parser corpus, large-case performance, and legal/report wording review.

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
- `release-evidence-report.json` and `release-evidence-report.md` showing PASS/FAIL for release, validation, benchmark, and smoke evidence.
- Support contact/SLA document and emergency parser-fix policy.

## Release Notes Must Include

- Supported evidence inputs and limitations.
- E01/Ex01 external tool requirements.
- Test and benchmark result summary.
- Known parser coverage gaps.
- Security note for non-localhost web binding.
- Signing/notarization status for Windows/macOS artifacts.
- Independent validation scope, known false positives/false negatives, and support SLA/escalation contact.
