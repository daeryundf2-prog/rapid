# RapidTriage Training Curriculum

## Analyst Quickstart Lab

1. Run `rapidtriage sample --run --overwrite --read-only`.
2. Open the web UI and search for credentials, URLs, and AI-service terms.
3. Preview sources, mark at least three report candidates, and add notes.
4. Export Case DB report candidates and review `provenance`, `validation_assessment`, and `legal_limitations`.
5. Build a reviewer bundle and verify archive/output hashes.

## Admin Lab

1. Build release artifacts with `scripts/build-release.py`.
2. Verify `SHA256SUMS`.
3. Generate a validation package with known-answer and independent-report placeholders.
4. Run `rapidtriage enterprise-policy --json`.
5. Run `scripts/check-dependencies.py`.

## Validation Exercise

- Compare one parser output against a known-answer dataset.
- Record false-positive and false-negative notes.
- Attach the independent validation report hash in `rapidtriage validation`.

