from __future__ import annotations

import contextlib
import datetime as dt
import platform
import sqlite3
import statistics
import time
from pathlib import Path
from typing import Sequence

from .benchmark import BENCHMARK_SCALE_TARGETS, DEFAULT_BENCHMARK_KEYWORD, percentile, scale_label
from .docs import write_result
from .search_backend import build_synthetic_benchmark_generator_manifest, stable_backend_sha256


SQLITE_FTS_BENCHMARK_VERSION = "sqlite-fts-synthetic-benchmark-v1"
SQLITE_FTS_BENCHMARK_SCHEMA_VERSION = "sqlite-fts-benchmark-schema-v1"
SQLITE_FTS_DEFAULT_RECORD_COUNT = 100_000
SQLITE_FTS_DEFAULT_QUERY_ITERATIONS = 5
SQLITE_FTS_DEFAULT_HIT_EVERY = 10
SQLITE_FTS_DEFAULT_RESULT_WINDOW = 100


class SqliteFtsBenchmarkError(ValueError):
    """Raised when SQLite FTS benchmark input is invalid."""


def run_sqlite_fts_benchmark(
    *,
    output_dir: Path,
    record_count: int = SQLITE_FTS_DEFAULT_RECORD_COUNT,
    keyword: str = DEFAULT_BENCHMARK_KEYWORD,
    query_iterations: int = SQLITE_FTS_DEFAULT_QUERY_ITERATIONS,
    hit_every: int = SQLITE_FTS_DEFAULT_HIT_EVERY,
    overwrite: bool = False,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise SqliteFtsBenchmarkError(f"SQLite FTS benchmark output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    if record_count <= 0:
        raise SqliteFtsBenchmarkError("record_count must be greater than zero")
    if query_iterations <= 0:
        raise SqliteFtsBenchmarkError("query_iterations must be greater than zero")
    if hit_every <= 0:
        raise SqliteFtsBenchmarkError("hit_every must be greater than zero")
    normalized_keyword = keyword.strip() or DEFAULT_BENCHMARK_KEYWORD

    db_path = output_dir / "sqlite-fts-benchmark.db"
    json_path = output_dir / "sqlite-fts-benchmark.json"
    markdown_path = output_dir / "sqlite-fts-benchmark.md"
    if db_path.exists() and overwrite:
        db_path.unlink()
    if overwrite:
        for sidecar_path in (db_path.with_name(db_path.name + "-wal"), db_path.with_name(db_path.name + "-shm")):
            if sidecar_path.exists():
                sidecar_path.unlink()

    manifest = build_sqlite_fts_synthetic_manifest(record_count=record_count, keyword=normalized_keyword, hit_every=hit_every)
    started = time.perf_counter()
    with contextlib.closing(sqlite3.connect(db_path)) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        create_sqlite_fts_benchmark_schema(connection)
        insert_sqlite_fts_synthetic_rows(connection, record_count=record_count, keyword=normalized_keyword, hit_every=hit_every)
        connection.commit()
        optimize_started = time.perf_counter()
        connection.execute("INSERT INTO benchmark_fts(benchmark_fts) VALUES ('optimize')")
        connection.commit()
        optimize_seconds = time.perf_counter() - optimize_started
        query_plan = sqlite_fts_query_plan_profile(connection, normalized_keyword)
        query_samples = []
        total_hit_count = 0
        result_window_count = 0
        for _ in range(query_iterations):
            sample_started = time.perf_counter()
            total_hit_count = connection.execute(
                "SELECT COUNT(*) FROM benchmark_fts WHERE benchmark_fts MATCH ?",
                (normalized_keyword,),
            ).fetchone()[0]
            rows = connection.execute(
                """
                SELECT rowid, title, source_path, rank
                FROM benchmark_fts
                WHERE benchmark_fts MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (normalized_keyword, SQLITE_FTS_DEFAULT_RESULT_WINDOW),
            ).fetchall()
            query_samples.append(time.perf_counter() - sample_started)
            result_window_count = len(rows)
        checkpoint_rows = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        table_counts = {
            "benchmark_document": connection.execute("SELECT COUNT(*) FROM benchmark_document").fetchone()[0],
            "benchmark_fts": connection.execute("SELECT COUNT(*) FROM benchmark_fts").fetchone()[0],
        }
    ingest_seconds = time.perf_counter() - started
    file_sizes = sqlite_fts_benchmark_file_sizes(db_path)
    db_size = int(file_sizes.get("total_bytes") or 0)
    expected_hits = expected_sqlite_fts_hit_count(record_count=record_count, hit_every=hit_every)
    metric_values = {
        "record_count": record_count,
        "expected_hit_count": expected_hits,
        "returned_hit_count": total_hit_count,
        "result_window_count": result_window_count,
        "result_window_limit": SQLITE_FTS_DEFAULT_RESULT_WINDOW,
        "truncated_by_result_window": total_hit_count > result_window_count,
        "ingest_seconds": ingest_seconds,
        "optimize_seconds": optimize_seconds,
        "query_p50_seconds": statistics.median(query_samples),
        "query_p95_seconds": percentile(query_samples, 95),
        "records_per_second": record_count / ingest_seconds if ingest_seconds else None,
        "database_size_bytes": db_size,
    }
    proof_manifest = build_sqlite_fts_benchmark_proof_manifest(
        manifest=manifest,
        metrics=metric_values,
        query_plan=query_plan,
        db_path=db_path,
        json_path=json_path,
        markdown_path=markdown_path,
    )
    payload: dict[str, object] = {
        "command": "sqlite-fts-benchmark",
        "profile_version": SQLITE_FTS_BENCHMARK_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "output_dir": str(output_dir),
        "database_path": str(db_path),
        "options": {
            "record_count": record_count,
            "keyword": normalized_keyword,
            "query_iterations": query_iterations,
            "hit_every": hit_every,
            "scale_targets": list(BENCHMARK_SCALE_TARGETS),
        },
        "environment": sqlite_fts_benchmark_environment_profile(),
        "synthetic_manifest": manifest,
        "synthetic_manifest_hash": manifest["manifest_hash"],
        "metrics": {
            key: round(float(value), 6) if isinstance(value, float) else value
            for key, value in metric_values.items()
        },
        "query_latency_samples_seconds": [round(value, 6) for value in query_samples],
        "table_counts": table_counts,
        "query_plan_profile": query_plan,
        "checkpoint_profile": {
            "profile_version": "sqlite-fts-wal-checkpoint-profile-v1",
            "mode": "TRUNCATE",
            "rows": [list(row) for row in checkpoint_rows],
            "purpose": "Flush benchmark writes so database and sidecar sizes are not misleading in QC evidence.",
        },
        "file_sizes": file_sizes,
        "proof_manifest": proof_manifest,
        "proof_manifest_hash": proof_manifest["manifest_hash"],
        "scale_matrix": sqlite_fts_scale_matrix(record_count),
        "summary": {
            "scale_label": scale_label(record_count),
            "expected_hit_count": expected_hits,
            "returned_hit_count": total_hit_count,
            "result_window_count": result_window_count,
            "result_window_limit": SQLITE_FTS_DEFAULT_RESULT_WINDOW,
            "truncated_by_result_window": total_hit_count > result_window_count,
            "expected_counts_match": total_hit_count == expected_hits,
            "commercial_gap_ids": ["#53", "#74"],
            "commercial_grade_ready": record_count >= 1_000_000,
        },
        "commercial_grade_blockers": sqlite_fts_commercial_blockers(record_count),
        "outputs": {"json": str(json_path), "markdown": str(markdown_path), "database": str(db_path)},
    }
    write_result(payload, json_path)
    markdown_path.write_text(render_sqlite_fts_benchmark_markdown(payload), encoding="utf-8")
    return payload


def create_sqlite_fts_benchmark_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE benchmark_document (
            id INTEGER PRIMARY KEY,
            artifact_family TEXT NOT NULL,
            source_path TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            expected_keyword_hit INTEGER NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE VIRTUAL TABLE benchmark_fts USING fts5(
            title,
            body,
            source_path UNINDEXED,
            content='benchmark_document',
            content_rowid='id'
        )
        """
    )


def insert_sqlite_fts_synthetic_rows(
    connection: sqlite3.Connection,
    *,
    record_count: int,
    keyword: str,
    hit_every: int,
) -> None:
    families = ("document", "file_metadata", "evtx", "registry", "ocr", "email", "messenger", "browser", "timeline")
    rows = []
    for index in range(1, record_count + 1):
        is_hit = index % hit_every == 0
        family = families[index % len(families)]
        body_keyword = f" {keyword} seeded-known-answer" if is_hit else " ordinary benign text"
        rows.append(
            (
                index,
                family,
                f"/synthetic/{family}/{index:09d}.txt",
                f"Synthetic {family} record {index}",
                f"RapidTriage deterministic SQLite FTS benchmark row {index}.{body_keyword}",
                1 if is_hit else 0,
            )
        )
        if len(rows) >= 10_000:
            _flush_sqlite_fts_rows(connection, rows)
            rows.clear()
    if rows:
        _flush_sqlite_fts_rows(connection, rows)


def _flush_sqlite_fts_rows(connection: sqlite3.Connection, rows: Sequence[tuple[object, ...]]) -> None:
    connection.executemany(
        """
        INSERT INTO benchmark_document (id, artifact_family, source_path, title, body, expected_keyword_hit)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    connection.executemany(
        """
        INSERT INTO benchmark_fts(rowid, title, body, source_path)
        VALUES (?, ?, ?, ?)
        """,
        [(row[0], row[3], row[4], row[2]) for row in rows],
    )


def build_sqlite_fts_synthetic_manifest(*, record_count: int, keyword: str, hit_every: int) -> dict[str, object]:
    generator_manifest = build_synthetic_benchmark_generator_manifest(targets=(record_count,))
    manifest_core = {
        "profile_version": "sqlite-fts-synthetic-corpus-manifest-v1",
        "schema_version": SQLITE_FTS_BENCHMARK_SCHEMA_VERSION,
        "record_count": record_count,
        "keyword": keyword,
        "hit_every": hit_every,
        "expected_keyword_count": expected_sqlite_fts_hit_count(record_count=record_count, hit_every=hit_every),
        "deterministic_row_order": True,
        "source_locator_pattern": "/synthetic/{artifact_family}/{row_id}.txt",
        "generator_manifest_hash": generator_manifest["manifest_hash"],
    }
    return {**manifest_core, "manifest_hash": stable_backend_sha256(manifest_core)}


def expected_sqlite_fts_hit_count(*, record_count: int, hit_every: int) -> int:
    return int(record_count) // int(hit_every)


def sqlite_fts_query_plan_profile(connection: sqlite3.Connection, keyword: str) -> dict[str, object]:
    rows = connection.execute(
        "EXPLAIN QUERY PLAN SELECT rowid FROM benchmark_fts WHERE benchmark_fts MATCH ? LIMIT 100",
        (keyword,),
    ).fetchall()
    plans = [
        {"id": row[0], "parent": row[1], "notused": row[2], "detail": str(row[3])}
        for row in rows
    ]
    row_hashes = [stable_backend_sha256(plan) for plan in plans]
    profile_core = {
        "profile_version": "sqlite-fts-query-plan-profile-v1",
        "plan_row_count": len(plans),
        "plans": [{**plan, "row_hash": row_hash} for plan, row_hash in zip(plans, row_hashes)],
        "plan_row_head_hash": row_hashes[0] if row_hashes else "",
    }
    return {**profile_core, "plan_hash": stable_backend_sha256(profile_core)}


def build_sqlite_fts_benchmark_proof_manifest(
    *,
    manifest: dict[str, object],
    metrics: dict[str, object],
    query_plan: dict[str, object],
    db_path: Path,
    json_path: Path,
    markdown_path: Path,
) -> dict[str, object]:
    proof_core = {
        "profile_version": "sqlite-fts-benchmark-proof-manifest-v1",
        "synthetic_manifest_hash": manifest["manifest_hash"],
        "query_plan_hash": query_plan["plan_hash"],
        "record_count": metrics["record_count"],
        "expected_hit_count": metrics["expected_hit_count"],
        "returned_hit_count": metrics["returned_hit_count"],
        "result_window_count": metrics["result_window_count"],
        "result_window_limit": metrics["result_window_limit"],
        "truncated_by_result_window": metrics["truncated_by_result_window"],
        "query_p95_seconds": metrics["query_p95_seconds"],
        "database_size_bytes": metrics["database_size_bytes"],
        "outputs": {
            "database": str(db_path),
            "json": str(json_path),
            "markdown": str(markdown_path),
        },
    }
    return {**proof_core, "manifest_hash": stable_backend_sha256(proof_core)}


def sqlite_fts_benchmark_environment_profile() -> dict[str, object]:
    return {
        "profile_version": "sqlite-fts-benchmark-environment-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "sqlite_version": sqlite3.sqlite_version,
    }


def sqlite_fts_benchmark_file_sizes(db_path: Path) -> dict[str, object]:
    files = []
    for path in (db_path, db_path.with_name(db_path.name + "-wal"), db_path.with_name(db_path.name + "-shm")):
        files.append({"path": str(path), "exists": path.exists(), "size_bytes": path.stat().st_size if path.exists() else 0})
    return {
        "profile_version": "sqlite-fts-benchmark-file-sizes-v1",
        "files": files,
        "total_bytes": sum(int(row["size_bytes"]) for row in files),
        "wal_sidecar_present_after_checkpoint": any(row["path"].endswith("-wal") and row["exists"] and row["size_bytes"] for row in files),
    }


def sqlite_fts_scale_matrix(record_count: int) -> list[dict[str, object]]:
    return [
        {
            "target_rows": target,
            "label": scale_label(target),
            "covered_by_this_run": record_count >= target,
            "status": "covered" if record_count >= target else "missing-larger-run",
        }
        for target in BENCHMARK_SCALE_TARGETS
    ]


def sqlite_fts_commercial_blockers(record_count: int) -> list[str]:
    blockers = []
    if record_count < 100_000:
        blockers.append("100k-sqlite-fts-runtime-evidence-required")
    if record_count < 1_000_000:
        blockers.append("1m-sqlite-fts-runtime-evidence-required")
    if record_count < 10_000_000:
        blockers.append("10m-sqlite-fts-runtime-evidence-required")
    blockers.append("external-known-answer-search-parity-diff-required")
    return blockers


def render_sqlite_fts_benchmark_markdown(payload: dict[str, object]) -> str:
    metrics = payload["metrics"]
    return "\n".join(
        [
            "# SQLite FTS Synthetic Benchmark",
            "",
            f"- Records: {metrics['record_count']}",
            f"- Expected keyword hits: {metrics['expected_hit_count']}",
            f"- Total returned hits: {metrics['returned_hit_count']}",
            f"- Result window hits: {metrics['result_window_count']} / {metrics['result_window_limit']}",
            f"- Result window truncated: {metrics['truncated_by_result_window']}",
            f"- Ingest seconds: {metrics['ingest_seconds']}",
            f"- Query p50 seconds: {metrics['query_p50_seconds']}",
            f"- Query p95 seconds: {metrics['query_p95_seconds']}",
            f"- Query plan hash: {payload['query_plan_profile']['plan_hash']}",
            f"- Proof manifest hash: {payload['proof_manifest_hash']}",
            "",
            "## Blockers",
            *[f"- {blocker}" for blocker in payload["commercial_grade_blockers"]],
            "",
        ]
    )
