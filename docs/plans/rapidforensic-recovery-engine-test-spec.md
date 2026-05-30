# RapidForensic Recovery Engine Test Specification

Status: approved for engineering validation
Date: 2026-05-31
Authority: `docs/plans/rapidforensic-recovery-review-plan-2026-05-30.md`

## Test Strategy

The recovery test strategy is layered so each claim has a measurable oracle:

1. Unit tests for path safety, parsers, metadata normalization, and manifest contracts.
2. Integration tests for CLI/API/viewer workflows.
3. Known-answer corpus tests for precision, recall, false positives, false negatives, and hash matches.
4. Reproducibility tests for normalized reruns.
5. Performance tests for memory, throughput, latency, resume, and large-result pagination.
6. External validation tests against trusted commercial/open forensic tool outputs.

## Acceptance Mapping

| PRD AC | Test layer | Required tests |
| --- | --- | --- |
| AC-01 | Unit/integration | outside-root path rejection, symlink escape rejection, absolute path rejection |
| AC-02 | Unit/integration | duplicate filename export, Korean filename export, filtered export, reviewed-only export |
| AC-03 | Unit/schema | recovery row schema validation, candidate class normalization, limitation presence |
| AC-04 | Integration/performance | interrupt after N items, resume checkpoint, corrupt partial output detection, cancel then resume |
| AC-05 | Unit/integration | embedded PDF/JPG/PNG/ZIP/SQLite carving, chunk-boundary signature, missing footer, false-positive control |
| AC-06 | Unit/external | MFT resident candidate fixture, nonresident runlist fixture, trusted MFTECmd/analyzeMFT diff |
| AC-07 | Unit/integration | NFC/NFD Korean names, mixed path separators, export manifest round-trip |
| AC-08 | UI/API | 100k-row filter/search latency, pagination, app-location quick lanes |
| AC-09 | Integration/report | report item citation completeness, hash completeness, limitation completeness |
| AC-10 | Release | scorecard fails closed for any missing quantitative evidence |

## Known-Answer Corpus Profiles

| Profile | Location | Purpose | Status |
| --- | --- | --- | --- |
| Tiny developer corpus | generated in temp dirs by unit tests | fast path/export/parser checks | implemented through existing tests |
| CI known-answer corpus | `docs/validation/rapidtriage-core-forensics-001-120-known-answer.json` | internal parser/readiness validation | present |
| Recovery-specific CI corpus | `tests/fixtures/recovery/` | deleted/carved recovery metrics | required before release |
| Local stress corpus | generated outside Git | 100k files, 1M metadata rows, sparse large files | required before release |
| External Windows corpus | operator supplied | E01/Ex01, NTFS deleted files, trusted-tool diffs | hard blocker |

## Quantitative Validation Commands

Required commands for release evidence:

```bash
python3.12 -m unittest discover -s tests
python3.12 -m compileall -q rapidtriage tests scripts
ruff check rapidtriage tests scripts
vulture rapidtriage tests scripts --min-confidence 80
pip-audit .
rapidtriage commercial-readiness --validation-package docs/validation/rapidtriage-core-forensics-001-120-known-answer.json --json
rapidtriage large-case-readiness --json
rapidtriage benchmark --profile recovery-ci --json
rapidtriage e01-smoke CASE.E01 --output-dir OUTPUT --resume --json
rapidtriage cross-tool-validate --rapid-output RAPID.json --reference-output TOOL=REFERENCE.json --source-evidence SOURCE --json
```

## Current Executed Evidence

| Command | Result |
| --- | --- |
| `python3.12 -m unittest discover -s tests` | PASS: ran 753 tests; OK (skipped=59) |
| `python3.12 -m compileall -q rapidtriage tests scripts` | PASS |
| `node --check rapidtriage/web/static/app_workbench_config.js && node --check rapidtriage/web/static/app_state.js && node --check rapidtriage/web/static/app.js` | PASS |
| `cargo check --workspace --all-targets --locked` in `engines/rust` | PASS |
| `ruff check rapidtriage tests scripts` | PASS |
| `vulture rapidtriage tests scripts --min-confidence 80` | PASS |
| `pip-audit .` | PASS: no known vulnerabilities found |

## Release Failure Rules

The release fails if any of these are true:

- Precision, recall, false-positive, false-negative, or hash-match thresholds are missing or below target.
- Reproducibility diff has any material difference outside approved dynamic fields.
- Any exported/report item lacks citation, hash, limitation, or review state.
- Any destructive schema change lacks pre-migration backup and fixture migration evidence.
- Any API route is remotely reachable without the configured auth policy.
- Any trusted-tool comparison required for a strong source claim is missing.
- Any legal/operator review item is missing.

## External Blocker Tests

The following tests cannot be completed on the current Mac-only host:

| Test | Required input |
| --- | --- |
| Windows E01/Ex01 end-to-end recovery | real or lab Windows E01/Ex01, libewf/Sleuth Kit logs, trusted commercial exports |
| Deleted SSD recovery truth | acquisition note, TRIM status, source device/media behavior, known deleted files |
| 10TB survival | representative 10TB-class corpus or approved sparse/metadata proxy plus telemetry |
| Windows installer/runtime | Windows 10/11 host, packaged build, tool discovery, Korean path smoke |
| Legal/operator gate | named reviewers and signed review artifacts |
