# RapidTriage Training Curriculum

## Analyst Quickstart Lab

1. Run `rapidtriage sample --run --overwrite --read-only`.
2. Open the web UI and search for credentials, URLs, and AI-service terms.
3. Preview sources, mark at least three report candidates, and add notes.
4. Export Case DB report candidates and review `provenance`, `validation_assessment`, and `legal_limitations`.
5. Build a reviewer bundle and verify archive/output hashes.
6. Preserve `rapidtriage-training-lab-manifest.json` with the training record. It lists expected keywords, required viewer/review exercises, output hashes, missing required outputs, and external signoff blockers.

## Quickstart Lab Scoring Rubric

- Pass: sample run completes, required output hashes are present, and the analyst can explain one source citation from search hit to report draft.
- Pass: at least three review candidates have a tag, note, and include/exclude decision.
- Pass: analyst verifies `rapidtriage-training-lab-manifest.json` and can identify why it is not a real forensic validation dataset.
- Fail: analyst reports synthetic sample output as court-validated evidence.
- Fail: analyst cannot trace a selected result back to a source file/path/hash.

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
