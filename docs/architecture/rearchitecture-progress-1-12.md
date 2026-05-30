# Re-Architecture Progress 1-12

This note records the current 12-step engineering pass for moving RapidTriage from a Python-only prototype toward a hybrid Python/Rust forensic platform.

## Status

1. Rust toolchain installed and verified.
   - Status: done in the current development environment.
   - Evidence: `cargo`, `rustc`, and `rustfmt` are available; `scripts/rust-bootstrap.sh` passes.

2. `rapid-worker` build and CLI smoke path connected.
   - Status: done.
   - Evidence: `rapid-worker --version`, direct worker JSONL, and `rapidtriage worker-parse` smoke paths pass.

3. EVTX file/chunk/record header parser moved into Rust worker.
   - Status: implemented as a validated foundation.
   - Evidence: `evtx-inventory` and `evtx-records` emit `ArtifactRecordV1` rows.

4. EVTX BinXML object model foundation added.
   - Status: strengthened, still not commercial-grade complete.
   - Current scope: fragment header, elements, attributes, substitutions, common scalar values, promoted `Event/System` and `EventData` fields.
   - Remaining: complete token coverage, edge-case corpus, and cross-tool validation.

5. EVTX template/substitution decoding foundation added.
   - Status: strengthened, still not commercial-grade complete.
   - Current scope: TemplateInstance IDs, template body object model, value specs, decoded substitution values, and indexed substitution metadata.
   - Remaining: full EVTX type matrix, malformed template recovery, and provider-specific validation.

6. EVTX message rendering design and built-in preview added.
   - Status: design plus validation-required built-in rendering.
   - Current scope: built-in preview text and high-value fallback messages for selected event IDs with `validation_required=true`.
   - Remaining: provider resource DLL/MUI loading, event template rendering, locale control, and report-defensible validation.

7. EVTX deleted/slack/corrupt recovery metadata added.
   - Status: implemented as triage/recovery candidate metadata.
   - Evidence: worker records include recovery status, allocation status, and caution labels.
   - Remaining: fixture corpus with known deleted/corrupt records and false-positive documentation.

8. EVTX known-answer fixture added.
   - Status: done for the current worker contract.
   - Evidence: Rust integration test checks chunk/event rows and PowerShell preview rendering.

9. Rust worker output connected to Python Case DB and indexer.
   - Status: done.
   - Evidence: `case-db --import-worker-jsonl` imports worker JSONL into `artifact`, `artifact_fts`, `indexed_document`, and `indexed_document_fts`.

10. Re-architecture status gate updated.
    - Status: done.
    - Evidence: `rapidtriage rearchitecture-status --json` now reports toolchain checks as passing and tracks worker JSONL Case DB import.

11. End-to-end worker/Case DB smoke test added.
    - Status: done.
    - Evidence: `scripts/worker-case-db-smoke.py` builds or locates `rapid-worker`, generates a tiny EVTX fixture, runs `worker-parse`, imports JSONL into Case DB, and searches for `PowerShell`.

12. Remaining commercial-grade gaps recorded.
    - Status: done.
    - Important caveat: steps 1-12 make the pipeline real and testable, but they do not make EVTX commercially equivalent to AXIOM/WISDOM yet.

13. EVTX BinXML/message-rendering upgrade pass.
    - Status: done as a validation-required triage upgrade.
    - Evidence: Rust tests now cover promoted provider/EventID/channel/computer/process fields, EventData command extraction, TemplateInstance decoded values, and built-in message rendering.
    - Important caveat: provider DLL/MUI resource rendering is still not implemented, so native rows remain validation-required.

14. EVTX large-file memory-safety pass.
    - Status: done as a first streaming upgrade.
    - Evidence: `evtx-records` now reads EVTX data in 64KB chunk units after the file header, honors `--max-records` during parsing, and has a unit test proving chunk-bounded parsing.
    - Important caveat: this is not a full 1TB/10TB benchmark gate yet; real corpus stress testing remains required.

15. Columnar benchmark gate scaffold.
    - Status: done as a dependency-independent planning and smoke gate.
    - Evidence: `rearchitecture-status` emits a `columnar_benchmark_plan`; `rapidtriage columnar-benchmark` writes JSONL baseline rows, query p50/p95 measurements, platform/Python/dependency versions, JSON/Markdown reports, row-grouped Parquet output when `pyarrow` is installed, and DuckDB Parquet query timing when `duckdb` is installed.
    - Important caveat: when `pyarrow`/`duckdb` are not installed the Parquet/DuckDB part remains skipped, not a measured benchmark result.

16. Columnar benchmark release evidence gate.
    - Status: done as an optional release verifier gate.
    - Evidence: `scripts/verify-release-evidence.py --columnar-benchmark-dir ./release-columnar-benchmark` now validates `columnar-benchmark.json`, Markdown, JSONL output, JSONL p50/p95 query metrics, environment/dependency capture, optional Parquet row-group manifest, optional DuckDB query metrics, and the required non-commercial overclaim disclosure.
    - Important caveat: this proves the benchmark output is attached and internally consistent; it still does not replace real 1M/10M hardware benchmark runs or independent performance reproduction.

17. Worker JSONL to Parquet conversion path.
    - Status: done as an optional dependency-gated storage path.
    - Evidence: `rapidtriage columnar-convert --input-jsonl ./worker-artifacts.jsonl --output-parquet ./worker-artifacts.parquet` converts validated `ArtifactRecordV1` JSONL into row-grouped Parquet when `pyarrow` is installed, records input SHA256, writes a conversion manifest, and keeps source-parser validation blockers visible.
    - Important caveat: conversion does not make the underlying parser findings report-defensible; source parser validation and large-corpus query benchmarks are still required.

18. Balanced multi-lane status plan.
    - Status: done as an execution-control upgrade.
    - Evidence: `rapidtriage rearchitecture-status` now reports a balanced 1-18 plan across EVTX, Registry/NTUSER/SAM/SECURITY, execution artifacts, SRUM/Windows.edb/ESE, MFT/USN/LNK/JumpList/ShellBags, browser/AI, disk images, mobile/cloud, search/UX, reporting, performance, validation, deployment, and commercial-readiness governance.
    - Important caveat: this is not a claim that all lanes are commercial-grade; it prevents roadmap tunnel vision and keeps every lane explicitly validation-required until fixtures and release evidence prove readiness.

## Remaining Commercial-Grade Gates

- Complete native EVTX BinXML token coverage beyond the current common-token set.
- Implement provider message rendering from Windows resource DLL/MUI files with deterministic locale handling.
- Validate deleted/corrupt EVTX recovery against independent corpora.
- Promote Registry/NTUSER/SAM/SECURITY, execution, ESE, filesystem, browser-AI, mobile/cloud, and viewer lanes from candidate/triage rows into known-answer validated parser outputs.
- Add large EVTX benchmarks and memory caps.
- Run release columnar benchmarks with optional `pyarrow`/`duckdb` dependencies and preserve Parquet/DuckDB evidence.
- Convert real worker JSONL corpora with `columnar-convert` and benchmark query behavior on that converted data.
- Add real Windows fixture validation, including Security/System/Application/Sysmon logs.
- Keep `commercial_grade_ready=false` until validation packages prove parser accuracy and report reproducibility.

## Current Operator Path

```bash
scripts/rust-bootstrap.sh
python scripts/worker-case-db-smoke.py --output-dir ./worker-case-db-smoke
python -m rapidtriage columnar-benchmark --output-dir ./release-columnar-benchmark --record-count 100000 --json
python -m rapidtriage columnar-convert --input-jsonl ./worker-artifacts.jsonl --output-parquet ./worker-artifacts.parquet --json
python -m rapidtriage rearchitecture-status
```
