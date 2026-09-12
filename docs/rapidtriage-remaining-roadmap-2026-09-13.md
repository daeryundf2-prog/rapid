# RapidTriage Remaining Roadmap (2026-09-13)

> Post-`main`-branch status document. Everything implementable in code is
> done; what remains is blocked on external assets, operator decisions, or
> external processes. Supersedes the open items in
> `docs/rapidforensic-next-roadmap.md`.

## Verified this cycle (local + CI)

| Item | Evidence |
|---|---|
| Full suite | 908 tests OK (2 skipped) — ubuntu/macos/windows CI all green on `main` |
| Lint/quality | ruff clean, vulture clean, compileall clean, doc-ref gate green |
| `run.py` split | monolith → `rapidtriage/core/run/` thematic package; public API + patch points preserved; doc-ref gate caught and fixed the stale refs |
| Release signing | `scripts/sign-release.py` round-trip verified locally — sign → verify → tamper-detection all exercised |
| SBOM | `scripts/generate-sbom.py` emits CycloneDX (64 components) |
| Branch state | `codex/rapidforensic-complete` → `main` published; `main` is now the default branch |

## Remaining items — all blocked on external input

| # | Item | Blocker | What unblocks it |
|---|---|---|---|
| 1 | Real E01/Ex01 corpus validation (Windows T1) | no real acquisition images on this host | runbook-ready: `docs/validation/windows-t1-*` — needs operator approval + external storage |
| 2 | Trusted-tool diff vs reference exporter | needs a reference tool export on real images | XWF/EnCase/Autopsy export on the T1 corpus |
| 3 | Scale run on a real large case | synthetic fixtures only | production-size evidence set |
| 4 | Release-signing key operations | `RAPIDTRIAGE_SIGNING_KEY` is a dev secret | real key-management decision (HSM/KMS or documented operator key) |
| 5 | Platform signing (Authenticode/codesign) | needs certs + Apple/Windows infra | signing identity procurement |

## Score trajectory

`8.4 (branch complete) → ~8.7 on main`. The remaining ~1.0 is
evidence-grade validation (items 1–3), which is blocked-external, not
code.
