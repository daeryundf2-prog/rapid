# RapidTriage Quality Checks

Local quality infrastructure that complements the test suite and static
analysis gates. All commands assume an environment with the `test` extra
installed (`python -m pip install -e ".[web,test]"`).

## Local gate (one line)

`scripts/dev/gate.py` runs every local check in a fixed order and prints one
line per step (`pass` / `FAIL` / `TIMEOUT` / `skip`, seconds, exit code) and
the total wall time. Each step runs under `scripts/dev/run.py --timeout`, so a
hung step kills only its own process tree. Step output goes to a log file
under the temp dir; the last 30 lines are printed when a step fails.

```bash
python scripts/dev/gate.py --tier fast            # default; every task before hand-back
python scripts/dev/gate.py --tier static          # L0 only
python scripts/dev/gate.py --tier full --json     # coordinator, end of a batch
python scripts/dev/gate.py --fast --changed       # unit tests only for modules touched vs --base
python scripts/dev/gate.py --list                 # print the planned steps
```

`--fast`, `--full` and `--static` are short for `--tier ...`. `--base`
defaults to `feat/r6-ux` (then `main`); it decides whether `frontend/`
changed and which modules `--changed` selects.

| Level | Step | Command | Tiers |
|---|---|---|---|
| L0 | check-eol | `python scripts/dev/check-eol.py` | all |
| L0 | check-staged | `python scripts/dev/check-staged.py` (staged size, EOL, bundle path) | all |
| L0 | ruff | `python -m ruff check rapidtriage tests scripts` | all |
| L0 | vulture | `python -m vulture rapidtriage tests scripts --min-confidence 80` | all |
| L0 | compileall | `python -m compileall -q rapidtriage tests scripts` | all |
| L0 | exec-bits | `python -m unittest tests.test_script_exec_bits` | all |
| L0 | architecture | `python -m unittest tests.test_architecture` (import boundaries) | all |
| L0 | fe-typecheck, fe-lint, fe-bundle | `npm run typecheck`, `npm run lint`, `npm run check:bundle` | when `frontend/` changed; always in full |
| L1 | unit-tests | `python scripts/dev/run-tests.py --tier fast\|full [--changed]` | fast, full |
| L1 | fe-vitest | `npx vitest run` | fast (frontend changed), full |
| L2 | ui-contract | `node scripts/extract-ui-contract.mjs --check` | fast, full |
| L2 | known-answer-qc, trusted-diff, normalize-trusted-export, build-evidence-bundle | the Tier 0 commands of the RapidForensic Validation Contract in `AGENTS.md` | fast, full |
| L2 | pip-audit | `python -m pip_audit -r requirements.lock -r requirements-dev.lock --require-hashes --disable-pip` | fast, full |
| L3 | e2e-smoke | `npm run e2e -- case-intake.spec.ts` (port from `.rt-dev.env`) | full |

A failing L0 step stops the run (later steps are reported `not-run`;
`--keep-going` overrides). L1-L3 failures do not stop later steps, so one run
shows every failure. Frontend steps and the UI contract check need
`frontend/node_modules`; worktrees made with `python scripts/dev/wt.py new`
link it. Exit code 0 = every step passed or was skipped.

`--json` prints `{tier, ok, total_seconds, failed, steps: [{name, level,
status, exit_code, seconds, command, reason, log}]}` on stdout (the table then
goes to stderr); the same JSON is kept as `gate.json` in the log directory.
The whole-suite `python -m unittest discover -s tests` run is replaced by the
parallel runner `scripts/dev/run-tests.py` (one process per module batch,
per-module time limits).

## Test coverage

`coverage` is included in the `test` extra and configured in
`pyproject.toml` (`[tool.coverage.run]`, `[tool.coverage.report]`). Coverage
carries a **`fail_under = 80`** floor: `coverage report` exits non-zero
when total branch coverage drops below 80%. The measured baseline is 82%
(846 tests, 2026-09); the floor is deliberately a little below the
baseline so minor fluctuations do not break the build — raise it as
coverage grows rather than lowering it.

```bash
python -m coverage run -m unittest discover -s tests
python -m coverage combine   # merges parallel data files into .coverage
python -m coverage report    # per-file table; fails under 80% total
python -m coverage html      # optional browsable report in htmlcov/
```

The config measures `rapidtriage/` with branch coverage enabled and omits
`tests/` and package `__init__.py` files. `.coverage` data files and
`htmlcov/` are gitignored.

## API contract snapshot

`tests/test_rapidtriage_api_contract.py` pins the public API surface: every
path, HTTP method, and operationId from `create_app().openapi()` is compared
against the checked-in fixture `tests/fixtures/api_openapi_snapshot.json`.

The test fails when an endpoint is added, removed, or renamed without
regenerating the fixture. When the API change is intentional, regenerate:

```bash
python scripts/update-api-snapshot.py
# or inside the test run:
RAPIDTRIAGE_UPDATE_API_SNAPSHOT=1 python -m unittest tests.test_rapidtriage_api_contract
```

Commit the regenerated fixture together with the API change.

## Doc reference scanner

`scripts/check-doc-refs.py` scans `README.md` and `docs/**/*.md` for inline
code tokens and markdown link targets that reference repository paths
(`rapidtriage/core/run/` package, `scripts/build-release.py`, `api/app/factory.py`-style
package-relative tokens, `tests/test_rapidtriage_api.py::test_name`,
`file.py:123` line-number suffixes) and
reports references that no longer resolve to a real file or directory.

```bash
python scripts/check-doc-refs.py            # exits 1 on stale refs in maintained docs
python scripts/check-doc-refs.py --json     # structured report
python scripts/check-doc-refs.py --warn-only # report only, always exits 0
```

Historical record documents — `docs/plans/`, `docs/validation/`, dated
`release-notes-*` files, and the `rapidtriage-core-forensics-*-validation.md`
batch records — are listed as informational `STALE (historical)` entries and
do not fail the check; they record what was true when written. A historical
doc whose stale paths are acknowledged records carries the banner

```markdown
> _Historical document — paths may reference pre-refactor layout._
```

directly after its first heading; the scanner detects that marker and
suppresses the file's findings entirely. CI runs the scanner as a real
gate — it exits 1 on stale refs in maintained docs (see the "Check doc
path references" step in `.github/workflows/rapidtriage-ci.yml`).
