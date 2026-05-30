# Release Hard Blockers - 2026-05-31

Status: release blocked
Plan authority: `docs/plans/rapidforensic-recovery-review-plan-2026-05-30.md` at commit `9973672931e31a40174d0087a72feae6a0f7620c`

## Completed Locally

| Area | Evidence |
| --- | --- |
| Unit and regression tests | `unittest` ran 753 tests; OK (skipped=59) |
| Python syntax | compileall passed |
| Web static syntax | node checks passed |
| Rust engine build | cargo check passed |
| Static analysis | ruff and vulture passed |
| Dependency audit | pip-audit found no known vulnerabilities |
| Security fixes | extraction path safety, API auth, XML DTD/entity rejection, DB schema preflight, audit append-only triggers |

## Blocking Conditions

| Blocker | Affected files/areas | Evidence | Recommended next action |
| --- | --- | --- | --- |
| Real E01/Ex01 recovery validation missing | `rapidtriage/core/e01.py`, `rapidtriage/core/run.py`, recovery reports | Local tests use synthetic or invalid E01 smoke paths; no real Windows E01/Ex01 plus trusted-tool export is attached. | On Windows, run E01 smoke/recovery against approved cases and attach EnCase/X-Ways/Sleuth Kit/MFTECmd/analyzeMFT diff outputs. |
| Deleted SSD recovery truth missing | NTFS/MFT/USN candidate recovery, carving | SSD TRIM and wear-leveling can destroy deleted data; no acquisition note or deleted-file known-answer package is attached. | Build a lab SSD case with TRIM status, acquisition method, known deleted files, and trusted-tool comparison. |
| Large-case survival missing | run pipeline, job store, viewer, index/search | No completed 10TB-class or 1M-file release telemetry exists in repo. | Generate 100k-file and 1M-row MVP evidence first, then an approved 10TB-class corpus run. |
| Legal/operator review missing | README, docs, reports, release notes, UI wording | No signed technical, forensic methodology, operator, or legal review artifacts are attached. | Complete `legal-operator-review-checklist.md`, methodology review, operator notes, and release claims map. |
| Windows packaging/runtime missing | CLI, web, external tools, Unicode paths | Current execution was Mac-local; Windows host packaging and Korean path smoke logs are absent. | Run Windows 10/11 smoke suite, package/install test, E01 tool discovery, and Korean filename export/viewer tests. |

## Production Readiness Decision

Production release status: FAIL.

Reason: Mac-local code hardening and validation passed, but external evidence required by the committed release gates is absent. No production release may claim report-defensible recovery performance, deleted SSD recovery accuracy, 10TB survival, or legal suitability until the blockers above are closed with attached evidence.
