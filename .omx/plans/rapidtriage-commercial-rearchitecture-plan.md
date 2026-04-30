# RapidTriage Commercial Re-Architecture Plan

## 1. Goal

RapidTriage should move from a Python-first triage application into a hybrid forensic platform:

- Python remains the product shell: CLI, API, web UI orchestration, reports, case management, validation packages.
- Rust becomes the forensic engine: large binary parsers, streaming hash/index pipelines, memory-safe worker processes, high-throughput search ingestion.
- SQLite remains the local case database for review state and citations.
- Arrow/Parquet becomes the high-volume artifact/timeline storage layer.
- Tantivy or an equivalent embedded search engine becomes the scalable full-text index.
- Every parser must emit provenance, offsets, source hashes, confidence, validation status, and legal limitations.

The product claim should remain "triage/review accelerator" until known-answer corpus validation, large-case benchmarks, signed packages, and support operations are complete.

## 2. Language Split

### Python

Use Python for:

- CLI command routing and compatibility with the current `rapidtriage` commands.
- FastAPI/local web server.
- Case DB review workflow, report generation, validation packages, release packaging.
- Job orchestration, task dispatch, configuration, plugin loading.
- Calling Rust workers through CLI subprocess, JSONL/Arrow IPC, or PyO3 bindings.

Do not use Python for:

- Full-file reads of evidence images.
- Native EVTX/MFT/USN/Registry/ESE binary parsing at scale.
- CPU-heavy hash/carving/OCR/media processing loops.
- Massive in-memory JSON aggregation.

### Rust

Use Rust for:

- Native parsers: EVTX, Registry hive, SAM/SECURITY/SYSTEM, NTUSER/UsrClass, MFT, USN, Prefetch, LNK, JumpList, SRUM/Windows.edb ESE.
- Streaming file walkers and hash pipelines.
- Chunked artifact writers.
- Parser isolation workers with bounded memory.
- Search indexing ingestion.
- Optional PyO3 modules only after the Rust CLI/worker interface is stable.

Rust crate layout:

- `rapidcore`: shared artifact model, error model, provenance, confidence, hashing, path normalization.
- `rapid-evtx`: EVTX BinXML parser and recovery.
- `rapid-registry`: hive/key/value/deleted-cell parser.
- `rapid-ntfs`: MFT/USN/parser and path reconstruction.
- `rapid-ese`: ESE page/catalog/table reader for SRUM and Windows.edb.
- `rapid-search`: Tantivy indexing/search adapter.
- `rapid-worker`: parser runner with JSONL/Arrow output and crash isolation.

### TypeScript

Use TypeScript only for:

- Web UI state, keyboard workflows, virtualized tables, viewer panels.
- No forensic parsing logic.
- No direct evidence mutation.

### SQL

Use SQLite for:

- Case metadata, citations, review marks, audit events, saved searches, report selections.
- Small/medium FTS where convenient.

Use DuckDB optionally for:

- Local analytical queries over Parquet timelines/artifacts.
- Large timeline aggregation without loading data into Python.

### Arrow/Parquet

Use Arrow/Parquet for:

- High-volume artifacts, events, file inventory, extracted text, IOC pivots.
- Partition by `case_id/source_id/artifact_family/date`.
- Store row groups sized for query and report extraction, not one giant JSON.

## 3. Target Architecture

Pipeline:

1. Evidence preflight
2. Source registration and acquisition metadata
3. Read-only mount/export adapter
4. Streaming file inventory and hash cache
5. Parser scheduler
6. Rust parser workers
7. Artifact/event storage to Parquet plus summary rows to SQLite
8. Search indexing to Tantivy
9. Case review UI/API
10. Report/court bundle/validation package

Worker rule:

- Parser workers are separate processes, not in-process Python calls.
- Each worker has memory, time, input-size, and output-size budgets.
- Worker output is append-only JSONL or Arrow IPC.
- Worker crash produces a structured parser failure row, never a whole-case crash.

## 4. Storage Design

SQLite tables:

- `case_record`
- `evidence_source`
- `acquisition_metadata`
- `artifact_summary`
- `event_summary`
- `search_index_manifest`
- `review_mark`
- `review_mark_history`
- `audit_event`
- `report_item`

Parquet datasets:

- `files.parquet`
- `artifacts/{family}.parquet`
- `events/{family}.parquet`
- `text_chunks.parquet`
- `ioc.parquet`
- `parser_errors.parquet`

Tantivy index fields:

- `case_id`
- `source_id`
- `artifact_id`
- `artifact_family`
- `path`
- `timestamp`
- `body`
- `entities`
- `hashes`
- `review_status`

Never store large evidence content in SQLite.

## 5. Implementation Phases

### Phase 0: Freeze Current Product Boundary

Acceptance:

- Keep existing Python CLI/API behavior.
- Mark current native parser outputs as validation-required.
- Keep all 229 tests passing.
- Add architecture decision records for Python/Rust/Parquet/Tantivy split.

### Phase 1: Rust Worker Foundation

Deliverables:

- Create Rust workspace under `engines/rust`.
- Implement `rapid-worker --version`, `rapid-worker parse --kind noop`, and JSONL output.
- Python job scheduler can call the Rust worker as a subprocess.
- Worker output includes `artifact_id`, `source_ref`, `offset`, `hash`, `confidence`, `validation_required`.

Acceptance:

- One parser crash does not crash Python.
- 10GB synthetic file walk runs streaming without full memory load.
- Python tests cover worker success, timeout, crash, and malformed output.

### Phase 2: High-Volume Storage

Deliverables:

- Add Parquet artifact writer.
- Add manifest linking SQLite summaries to Parquet row groups.
- Add cursor API that pages from Parquet/Tantivy without loading all rows.

Acceptance:

- 1M synthetic artifact rows import under fixed memory budget.
- UI can page results without rendering all rows.
- Reports can cite exact Parquet row/source offset.

### Phase 3: Search Engine Migration

Deliverables:

- Add Tantivy index builder.
- Keep SQLite FTS as fallback for small cases.
- Add index manifests, segment stats, rebuild/resume support.

Acceptance:

- 1M text chunks searchable with p95 query latency target.
- Search results include source citation, offsets, parser confidence, legal limitation.
- Index can be rebuilt deterministically from Parquet.

### Phase 4: Core Windows Parsers In Rust

Priority order:

1. EVTX BinXML and recovery.
2. Registry hive and deleted cells.
3. SAM/SECURITY/SYSTEM account parser.
4. MFT and USN.
5. Prefetch/LNK/JumpList/ShellBags.
6. SRUM and Windows.edb ESE.

Acceptance:

- Each parser has fixtures, known-answer outputs, false-positive/false-negative notes.
- Each parser emits source offsets and hashes.
- Each parser has `commercial_grade_ready=false` until independently validated.

### Phase 5: Legal/Validation Hardening

Deliverables:

- Known-answer corpus runner.
- External tool comparison runner.
- Independent validation package builder.
- Reproducibility kit that reruns parsers and compares hashes/counts.

Acceptance:

- EVTX, Registry, MFT, USN have public fixture validation.
- Report items include parser version, source hash, offset, confidence, and limitations.
- Same input produces same normalized artifact IDs.

### Phase 6: Distribution And Operations

Deliverables:

- Windows signed installer pipeline.
- macOS notarized package pipeline.
- Linux deb/rpm/AppImage pipeline.
- Dependency vulnerability CI.
- Crash report export UI.
- Admin deployment and backup rehearsal.

Acceptance:

- Fresh-machine smoke tests for Windows/macOS/Linux.
- Release cannot pass without checksums, validation package, dependency scan, and known limitations.
- Commercial claim remains blocked unless external evidence is attached.

## 6. Team Execution Tracks

Track A: Rust engine

- Owns `engines/rust`.
- Builds parsers, worker contracts, performance tests.

Track B: Python orchestration

- Owns `rapidtriage/core`, `rapidtriage/cli.py`, `rapidtriage/api`.
- Integrates workers, storage manifests, job cancellation/retry.

Track C: Storage/search

- Owns Parquet writer, Tantivy index, cursor APIs, benchmark harness.

Track D: UI/UX

- Owns viewer, virtualized tables, compare workflows, review/report UX.

Track E: Validation/legal

- Owns fixture corpus, known-answer tests, FP/FN docs, report defensibility.

Track F: Release/security

- Owns packaging, signing evidence gates, dependency monitoring, AppSec review.

## 7. First 10 Engineering Tasks

1. Add `docs/architecture/adr-001-hybrid-python-rust.md`.
2. Add Rust workspace skeleton under `engines/rust`.
3. Define `ArtifactRecordV1` JSON schema shared by Python/Rust.
4. Add Python `RustWorkerClient`.
5. Add worker timeout/crash tests.
6. Add JSONL artifact sink.
7. Add Parquet proof-of-concept writer.
8. Add `rapid-worker parse --kind file-inventory`.
9. Add benchmark for 1M synthetic file rows.
10. Add UI/API cursor path that reads paged rows from the new store.

## 8. Main Risks

- Rust rewrite can stall feature work. Mitigation: keep Python product shell stable and migrate parser by parser.
- PyO3 can create packaging complexity. Mitigation: start with Rust subprocess workers, add PyO3 later only where needed.
- Parquet/Tantivy adds operational complexity. Mitigation: store manifests and rebuild commands with every case.
- Commercial claims can overrun validation evidence. Mitigation: keep `commercial-readiness` gate strict.
- Multi-user server is a separate product. Mitigation: do not build it until local workstation product is stable.

## 9. Definition Of Commercial Grade

An item becomes commercial grade only when:

- It is implemented without full-memory evidence reads.
- It has known-answer fixtures and regression tests.
- It has large-case performance evidence.
- It preserves source hashes, offsets, parser versions, confidence, and limitations.
- It has report and UI behavior that does not overclaim.
- It survives malformed input and parser crash tests.
- It is included in release validation output.
