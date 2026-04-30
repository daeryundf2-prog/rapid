# ADR-001: Hybrid Python And Rust For Commercial-Scale Forensics

## Status

Accepted for phased implementation.

## Context

RapidTriage started as a Python-first forensic triage application. That is productive for CLI/API/UI/reporting work, but commercial-scale forensic data can involve hundreds of gigabytes to multiple terabytes, millions of records, malformed binary structures, and hostile files. Keeping every parser and high-volume processing loop in Python risks excessive memory use, slow CPU-bound parsing, weak crash isolation, and difficult performance claims.

## Decision

RapidTriage will use a hybrid architecture:

- Python owns product orchestration: CLI, FastAPI, web workflow, Case DB, review/report logic, release validation, and compatibility with existing commands.
- Rust owns high-volume and binary forensic engine work: EVTX, Registry, SAM/SECURITY/SYSTEM, NTUSER/UsrClass, MFT, USN, ESE, Prefetch, LNK, JumpList, hashing, streaming inventory, and search ingestion.
- Rust parsers start as isolated subprocess workers. PyO3 bindings may be added later only for stable APIs that benefit from in-process calls.
- Workers emit newline-delimited `ArtifactRecordV1` JSON first, then Arrow/Parquet sinks will be introduced for high-volume storage.
- SQLite remains the local Case DB for case metadata, review state, citations, and audit events, not for raw massive artifact storage.

## Consequences

Positive:

- Parser crashes can be isolated from Python UI/API processes.
- Rust can parse hostile binary formats with better memory-safety and predictable performance.
- Existing Python workflows can keep working while individual parsers migrate.
- The release gate can separate "implemented" from "commercial-grade validated".

Negative:

- Build, packaging, and CI become more complex.
- Cross-platform release work must cover Rust binaries as well as Python packages.
- Two-language schemas and test fixtures must stay synchronized.

## Acceptance Criteria

- A Rust workspace exists under `engines/rust`.
- A `rapid-worker` binary can emit an `ArtifactRecordV1` JSONL row for a noop parser.
- Python has a worker client that handles success, timeout, nonzero exit, and malformed JSONL.
- Worker outputs include source reference, parser name/version, confidence, validation status, and commercial-readiness flags.
- Existing Python tests continue to pass.
