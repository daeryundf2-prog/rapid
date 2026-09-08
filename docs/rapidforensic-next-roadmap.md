# RapidForensic Next Roadmap (Post-Engineering-Baseline)

Created: 2026-09-08
Branch: `codex/rapidforensic-complete`
Predecessor: `docs/rapidforensic-functional-priority-roadmap.md` (functional
priority phases — its internal-engineering ledger is now fully closed)

## Where We Are

As of 2026-09-08, every gate that can be closed inside this repository is
closed:

- Engineering baseline green: 792 tests OK, ruff 0.16.6 repo-wide (upgraded
  from the 0.8 pin with documented behavior-rule ignore contracts), vulture
  clean, compileall clean, pip-audit clean.
- Tier 0 validation plumbing green: known-answer QC, trusted-diff,
  trusted-export normalizer, evidence bundle all PASS.
- Full analyst workflow verified end-to-end: triage run, search, source
  read/search, timeline, Case DB import/review/report, submission bundle
  (MD/HTML/DOCX/PDF + court exhibit index + tamper-evident audit).
- Web workbench smoke 8/8 PASS; workbench API contract + auth hardening
  verified on a live server.
- Large-case FTS evidence: 100k p95 7.2ms, 1M p95 0.13s, 10M p95 1.99s
  (under the 2.0s threshold); `large-case-readiness` scale checks PASS.
- JumpList entry-level trusted diff enabled (nested DestList expansion +
  entry_id/pin_status candidates); case-review rejects unknown targets.
- Columnar proof: Parquet 32x smaller, DuckDB query ~34x faster than JSONL.
- Commercial-readiness 90/100, `commercial_claim_allowed=false` — by design.

Everything that remains is either (a) an explicitly authorized engineering
pass that changes core forensic/DB/UI surfaces, or (b) external evidence
that cannot be produced in-repo. This roadmap sequences both.

## Track A — External Evidence Campaign (the critical path)

Goal: convert `commercial-gaps-present` into defensible, signed, reviewed
release evidence. Nothing here is code; it is acquisition, runs, and
signoffs. Order matters because later items reuse earlier corpora.

### A1. Windows T1 corpus (unblocks most trusted diffs)

1. Prepare the Windows 11 analysis host (elevated) and external storage
   outside Git; follow `docs/validation/windows-t1-execution-runbook.md`
   and fill `docs/validation/windows-t1-operator-inputs.md`.
2. Generate the synthetic source tree; acquire real E01 and Ex01 images;
   record hashes, tool versions, chain of custody.
3. Run RapidForensic e01-smoke/e01-known-answer end-to-end; attach
   transcripts; export normalized results.
4. Trusted-tool diffs in this order (each builds on the host setup):
   - EVTX vs EvtxECmd/Hayabusa — verify the BinXML EventRecordID join
     lands record-level matches (the fix `67c1e69`/`1ac6ed2` and the
     timestamp-anchored identity were built for exactly this).
   - Registry vs RECmd (NTUSER/UsrClass/SYSTEM/SOFTWARE, LOG1/LOG2 context).
   - MFT/USN vs MFTECmd/UsnJrnl2Csv (full-volume path reconstruction).
   - SRUM/Windows.edb vs SrumECmd (native ESE decode disclosure).
   - LNK vs LECmd (repeat at scale; prior internal diff was 234/234).
   - JumpList vs JLECmd — first entry-level diff, using the new nested
     expansion and entry_id/pin_status candidates.
   - Prefetch, Amcache/ShimCache, SAM/SECURITY/SYSTEM.
5. Deliverable: release evidence bundle per
   `scripts/build-evidence-bundle.py`, attached outside Git, referenced by
   hash in the release manifest.

### A2. Scale and browser evidence

6. 100k/1M/10M FTS benchmarks re-run on the release target hardware and
   attached (local Mac numbers exist; target-platform numbers are the
   release gate).
7. 1TB/5TB/10TB stress runs on approved forensic hardware with memory and
   latency profiles (`rapidtriage stress-plan` scenarios).
8. Browser e2e: run the workbench smoke contract and large-result evidence
   contract in Playwright on fresh Windows 11 and macOS; attach DOM/latency
   traces, screenshots, p95 numbers.
9. Cursor-API regression evidence for search/timeline/report endpoints.

### A3. Independent review and legal gates

10. Four-track review per
    `docs/validation/legal-operator-review-checklist.md`: technical,
    forensic methodology, operator, legal. Human signoff only; automation
    must not mark these complete.
11. Independent AppSec review + hostile-evidence containment validation
    (`scripts/hostile-evidence-containment-template.py` slots).

### A4. Release infrastructure (budget/credential dependent)

12. Authenticode signing for Windows installers/portable; attach
    timestamp-authority evidence.
13. macOS codesign + notarization + Gatekeeper assessment; attach notary
    tickets.
14. deb/rpm/AppImage builds in clean containers with install/uninstall
    smoke logs.
15. SBOM publication wired into the release manifest (the CycloneDX
    pipeline already runs in CI; attach artifact URLs to the release).
16. Staffed support/SLA evidence and secure intake runbook signoff.

## Track B — Authorized Engineering Passes (require explicit scope approval)

Per AGENTS.md, these change recovery engine, core logic, DB schema, or Web
UI and must not proceed as part of validation plumbing. Each needs its own
change plan with regression criteria before starting.

### B1. Columnar/Parquet adoption in the run pipeline — FIRST SLICE DONE

- Evidence in hand: Parquet 32x smaller than JSONL; DuckDB p50 0.165s vs
  20.87s baseline on 1M records; FTS scale checks green to 10M.
- **Done 2026-09-08 (authorized pass)**: opt-in `--columnar-store` run flag
  adds `build_columnar_artifacts_sidecar` after the sqlite-fts stage — it
  stages every `artifacts_{kind}` payload's per-row `artifact_record`
  (ArtifactRecordV1) into one JSONL audit file and converts it to
  row-grouped Parquet; outputs registered as `columnar_artifacts` /
  `columnar_artifacts_jsonl` in the summary and the workflow contract
  ("index" stage); run never fails on the sidecar (dependency-missing →
  `skipped` with install hint, conversion error → `failed` with reason).
  Verified end-to-end: run → Parquet → DuckDB family aggregation query.
- **Remaining for full adoption (next slice)**: point workbench large-table
  and case-search backends at the Parquet sidecar (schema/versioning
  contract for Parquet run outputs, cursor pagination over DuckDB), and a
  1M-record API-level p95 measurement. JSONL stays the canonical audit
  format.

### B2. e01-smoke resume-stage UI visualization — DONE

- **Done 2026-09-08 (authorized pass)**: `register_stage_status_with_run`
  copies the stage-status sidecar into the run output dir and registers
  `e01_smoke_stage_status` in the run summary's `outputs` map, so the
  existing `/api/runs/{id}/outputs/...` endpoints serve it under the same
  path-validation rules (no security surface change). The workbench summary
  tab now renders an `e01-smoke-stage-status` panel (JSON preview link +
  guidance) whenever the output is registered.
- Acceptance kept: browser smoke contract extension with automated
  stage-status screenshots is still an external evidence slot (Playwright
  on fresh Windows 11 / macOS).

### B3. Deferred lint-judgment cleanup (optional)

- The ruff 0.16 ignore list in `pyproject.toml` documents each deferred
  rule (BLE001 intentional for parser crash isolation, DTZ audited via the
  UTC-rendering pass, SIM/C4/FLY style calls). Revisit per rule only with
  a dedicated review; do not bulk-remove ignores without tests.

## Track C — Sustaining

- Keep CI green on the ruff 0.16 pin; treat any new finding as a
  regression, not a cleanup backlog.
- Every parser change ships with a candidate-vs-decoded state update and a
  trusted-diff slot; no silent promotions past `validation-required`.
- `commercial_claim_allowed` stays `false` until Track A evidence is
  attached; readiness score improvements must cite attached evidence paths.

## Non-Negotiable Rule (unchanged)

Every feature reports one of: `triage-only`, `review-grade`,
`report-grade`, `commercial-validated`. Do not collapse these states.
Overstating confidence is worse than missing a feature. Tier 0 fixtures
are engineering checks, not release evidence.
