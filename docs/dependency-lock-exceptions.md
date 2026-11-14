# Dependency lock exceptions (T-009)

Audit target: the hashed lock files only (`requirements.lock` = runtime, 20 packages;
`requirements-dev.lock` = runtime + `[test]` extra, 64 packages), never the global
site-packages. Command:

```bash
python -m pip_audit -r requirements.lock -r requirements-dev.lock --require-hashes --disable-pip --format=json
python scripts/check-dependencies.py -r requirements.lock -r requirements-dev.lock --output dependency-monitoring.json
```

The locks pin the versions resolved in the 2026-11-12 development environment.
No version was raised in T-009. Every advisory below has a fixed release and stays
open as a documented exception until the owner approves the upgrade.
`python-multipart` is not a dependency (not in either lock).

Audit of 2026-11-12 (pip-audit 2.10.1, unique advisory ids):

| Package | Locked | Lock | Advisories | Lowest version fixing all | Upgrade class | Status |
|---|---|---|---|---|---|---|
| starlette | 0.52.1 | runtime | 5 | 1.3.1 | major, with fastapi | exception: decision D25 (this audit is its evidence) |
| pillow | 11.3.0 | dev (`[test]`) | 57 | 13.0.0 (12.3.0 fixes 18) | major | exception: bundle with D25 |
| anyio | 4.12.1 | runtime | 2 | 4.14.2 | minor | proposed |
| idna | 3.11 | runtime | 1 | 3.15 | minor | proposed |
| python-dotenv | 1.0.1 | runtime (`uvicorn[standard]`) | 1 | 1.2.2 | minor | proposed |
| urllib3 | 2.2.3 | dev | 8 | 2.8.0 | minor | proposed |
| certifi | 2026.1.4 | dev | 1 | 2026.10.18 | calendar | proposed |
| pygments | 2.19.2 | dev | 1 | 2.20.0 | minor | proposed |
| msgpack | 1.2.1 | dev | 1 | 1.2.3 | patch | proposed |
| filelock | 3.18.0 | dev | 4 | 4.2.1 (3.20.3 fixes 2) | major | proposed (3.20.3 now, 4.x later) |
| pip | 25.1.1 | dev (pip-audit dependency) | 6 | 26.2 | calendar | proposed |

Release gate: disclosed-blocker mode (see `.github/workflows/dependency-monitoring.yml`).
These exceptions do not clear a release claim; they record the open findings.
