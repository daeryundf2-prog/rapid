# RapidForensic Next Roadmap (Post-Engineering-Baseline)

Created: 2026-09-08
Last updated: 2026-09-09 (Track B complete)
Branch: `codex/rapidforensic-complete`
Predecessor: `docs/rapidforensic-functional-priority-roadmap.md` (functional
priority phases — its internal-engineering ledger is fully closed)

## Where We Are

Every gate that can be closed inside this repository is closed. Three
engineering passes (2026-09-08/09) took the project from a lint-drifted,
CI-red baseline to:

- **Engineering baseline green**: 802 tests OK, ruff 0.16.6 repo-wide
  (upgraded from the 0.8 pin with documented behavior-rule ignore
  contracts), vulture clean, compileall clean, pip-audit clean.
- **Tier 0 validation plumbing green**: known-answer QC, trusted-diff,
  trusted-export normalizer, evidence bundle all PASS.
- **Full analyst workflow verified end-to-end**: triage run, search,
  source read/search, timeline, Case DB import/review/report, submission
  bundle, web workbench smoke 8/8.
- **Large-case evidence**: FTS 100k p95 7.2ms / 1M p95 0.13s / 10M
  p95 1.99s — under the 2.0s release threshold; readiness scale checks
  PASS.
- **Columnar lane complete (Track B)**: opt-in `--columnar-store` run
  sidecar (JSONL audit + Parquet), query API
  (`GET /api/runs/{id}/columnar-artifacts`), and workbench artifacts-tab
  preference with automatic JSON fallback.
- **JumpList entry diff enabled**, case-review target validation, e01-smoke
  failure classification + stage-status UI, EVTX/roady fixes from the
  earlier passes.
- CI green on all three OSes for the last four commits.
- Commercial-readiness 90/100, `commercial_claim_allowed=false` — by
  design, until Track A evidence lands.

## Track A — External Evidence Campaign (the only remaining critical path)

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
     lands record-level matches.
   - Registry vs RECmd (NTUSER/UsrClass/SYSTEM/SOFTWARE, LOG1/LOG2).
   - MFT/USN vs MFTECmd/UsnJrnl2Csv (full-volume path reconstruction).
   - SRUM/Windows.edb vs SrumECmd (native ESE decode disclosure).
   - LNK vs LECmd (repeat at scale; prior internal diff 234/234).
   - JumpList vs JLECmd — first entry-level diff (nested expansion +
     entry_id/pin_status candidates are ready).
   - Prefetch, Amcache/ShimCache, SAM/SECURITY/SYSTEM.
5. Deliverable: release evidence bundle via
   `scripts/build-evidence-bundle.py`, attached outside Git, referenced
   by hash in the release manifest.

### A2. Scale and browser evidence

6. Re-run 100k/1M/10M FTS benchmarks on the release target hardware and
   attach (local Mac numbers exist; target-platform numbers gate release).
7. 1TB/5TB/10TB stress runs on approved forensic hardware with memory and
   latency profiles (`rapidtriage stress-plan` scenarios).
8. Browser e2e: workbench smoke contract and large-result contract in
   Playwright on fresh Windows 11 and macOS; attach DOM/latency traces,
   screenshots, p95 numbers.
9. Cursor-API regression evidence for search/timeline/report endpoints.

### A3. Independent review and legal gates

10. Four-track review per
    `docs/validation/legal-operator-review-checklist.md`: technical,
    forensic methodology, operator, legal. Human signoff only; automation
    must not mark these complete.
11. Independent AppSec review + hostile-evidence containment validation.

### A4. Release infrastructure (budget/credential dependent)

12. Authenticode signing for Windows installers/portable; timestamp-
    authority evidence.
13. macOS codesign + notarization + Gatekeeper assessment; notary tickets.
14. deb/rpm/AppImage builds in clean containers with install/uninstall
    smoke logs.
15. SBOM publication wired into the release manifest (CycloneDX pipeline
    already runs in CI; attach artifact URLs).
16. Staffed support/SLA evidence and secure intake runbook signoff.

## Track B — Authorized Engineering Passes: COMPLETE (2026-09-09)

All three passes executed under explicit scope approval, with regression
criteria and zero test regressions.

### B1. Columnar/Parquet adoption in the run pipeline — DONE (all slices)

- **Sidecar (slice 1)**: opt-in `--columnar-store` run flag;
  `build_columnar_artifacts_sidecar` stages every `artifacts_{kind}`
  payload's per-row `artifact_record` (ArtifactRecordV1) into one JSONL
  audit file (+ manifest) and converts to row-grouped Parquet; outputs
  registered as `columnar_artifacts`/`columnar_artifacts_jsonl` in the
  summary and the workflow "index" stage; run never fails on the sidecar
  (dependency-missing → `skipped` with install hint, conversion error →
  `failed` with reason).
- **Query API (slice 2)**: `GET /api/runs/{run_id}/columnar-artifacts`
  via `query_columnar_artifact_records` — DuckDB parameterized
  family/type/keyword filters, bounded offset pagination, query timing,
  reportability warning; 404 carries a `--columnar-store` rerun hint;
  missing duckdb → 200 `skipped` so callers fall back to JSONL/JSON.
- **Workbench preference (slice 3)**: the artifacts tab loads through
  `loadArtifactsPayload` — tries the columnar endpoint first, renders
  through the unchanged artifact table contract when `status=queried`,
  and falls back to the JSON artifact outputs on 404/skipped. Verified
  live end-to-end; covered by web-static contract tests.
- JSONL remains the canonical audit format; Parquet is a derived index.

### B2. e01-smoke resume-stage UI visualization — DONE

- `register_stage_status_with_run` copies the stage-status sidecar into
  the run output dir and registers `e01_smoke_stage_status` in the run
  summary's `outputs` map; existing `/api/runs/{id}/outputs/...`
  endpoints serve it under unchanged path validation. The workbench
  summary tab renders the `e01-smoke-stage-status` panel when the output
  is registered.
- External slot kept: automated stage-status screenshots in the browser
  smoke contract (Playwright on fresh Windows 11/macOS) belong to Track
  A item 8.

### B3. Deferred lint-judgment cleanup — STANDING POLICY

- The ruff 0.16 ignore list in `pyproject.toml` documents each deferred
  rule (BLE001 intentional for parser crash isolation, DTZ audited via
  the UTC-rendering pass, SIM/C4/FLY style calls). Revisit per rule only
  with a dedicated review; do not bulk-remove ignores without tests.

## Track C — Sustaining

- Keep CI green on the ruff 0.16 pin; treat any new finding as a
  regression, not a cleanup backlog.
- Every parser change ships with a candidate-vs-decoded state update and
  a trusted-diff slot; no silent promotions past `validation-required`.
- `commercial_claim_allowed` stays `false` until Track A evidence is
  attached; readiness score improvements must cite attached evidence
  paths.
- Columnar adoption follow-ups (1M-record API p95 on target hardware;
  Parquet schema versioning note in the release checklist) are recorded
  under Track A measurement items, not as new engineering work.

## Non-Negotiable Rule (unchanged)

Every feature reports one of: `triage-only`, `review-grade`,
`report-grade`, `commercial-validated`. Do not collapse these states.
Overstating confidence is worse than missing a feature. Tier 0 fixtures
are engineering checks, not release evidence.
