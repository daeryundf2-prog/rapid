# RapidTriage Quality Checks

Local quality infrastructure that complements the test suite and static
analysis gates. All commands assume an environment with the `test` extra
installed (`python -m pip install -e ".[web,test]"`).

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
(`rapidtriage/core/run.py`, `scripts/build-release.py`, `api/app/factory.py`-style
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
