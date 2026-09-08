from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import platform
import statistics
import sys
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .artifact_store import (
    ARTIFACT_RECORD_SCHEMA,
    JsonlArtifactStreamWriter,
    read_jsonl_artifacts,
    validate_artifact_record,
)


class ColumnarStoreUnavailable(RuntimeError):
    """Raised when optional columnar dependencies are not installed."""


@dataclass(frozen=True)
class ColumnarWriteResult:
    path: str
    record_count: int
    rejected_count: int
    format: str
    manifest: dict[str, object]


def columnar_capabilities() -> dict[str, object]:
    pyarrow_available = importlib.util.find_spec("pyarrow") is not None
    duckdb_available = importlib.util.find_spec("duckdb") is not None
    return {
        "pyarrow_available": pyarrow_available,
        "duckdb_available": duckdb_available,
        "parquet_write_available": pyarrow_available,
        "duckdb_query_available": duckdb_available,
        "optional_dependency_group": "columnar",
        "install_hint": "pip install .[columnar]",
    }


def build_columnar_benchmark_plan(
    *,
    record_counts: Iterable[int] = (100_000, 1_000_000, 10_000_000),
    target_row_group_size: int = 100_000,
) -> dict[str, object]:
    capabilities = columnar_capabilities()
    matrix = []
    for record_count in record_counts:
        normalized_count = max(1, int(record_count))
        row_groups = max(1, (normalized_count + target_row_group_size - 1) // target_row_group_size)
        matrix.append(
            {
                "record_count": normalized_count,
                "target_row_group_size": target_row_group_size,
                "target_row_group_count": row_groups,
                "jsonl_baseline_required": True,
                "parquet_write_expected": bool(capabilities["parquet_write_available"]),
                "duckdb_query_expected": bool(capabilities["duckdb_query_available"]),
                "required_metrics": [
                    "write_seconds",
                    "read_seconds",
                    "query_seconds_p50",
                    "query_seconds_p95",
                    "peak_rss_bytes",
                    "output_size_bytes",
                ],
            }
        )
    status = (
        "ready-to-run"
        if capabilities["parquet_write_available"] and capabilities["duckdb_query_available"]
        else "blocked-on-optional-columnar-dependencies"
    )
    return {
        "component": "columnar-benchmark-plan",
        "status": status,
        "capabilities": capabilities,
        "commercial_gap_ids": ["#66", "#74"],
        "target_format": "parquet",
        "fallback_format": "jsonl",
        "matrix": matrix,
        "acceptance_notes": [
            "Run JSONL and Parquet paths on the same generated ArtifactRecordV1 corpus.",
            "Publish hardware profile, dependency versions, row-group settings, p50/p95 query latency, and peak RSS.",
            "Do not claim 1M/10M commercial readiness without saved benchmark outputs and release evidence.",
        ],
    }


def run_columnar_benchmark(
    *,
    output_dir: Path,
    record_count: int = 10_000,
    keyword: str = "PowerShell",
    query_iterations: int = 3,
) -> dict[str, object]:
    if record_count <= 0:
        raise ValueError("record_count must be greater than zero")
    if query_iterations <= 0:
        raise ValueError("query_iterations must be greater than zero")
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    keyword = keyword or "PowerShell"
    jsonl_path = output_dir / "artifact-records.jsonl"
    parquet_path = output_dir / "artifact-records.parquet"
    json_path = output_dir / "columnar-benchmark.json"
    markdown_path = output_dir / "columnar-benchmark.md"

    jsonl_started = time.perf_counter()
    with JsonlArtifactStreamWriter(output_path=jsonl_path) as writer:
        for record in synthetic_artifact_records(record_count=record_count, keyword=keyword):
            writer.write(record)
        jsonl_result = writer.close()
    jsonl_seconds = elapsed(jsonl_started)

    query_samples = []
    keyword_lower = keyword.lower()
    for _ in range(query_iterations):
        started = time.perf_counter()
        match_count = 0
        for record in read_jsonl_artifacts(jsonl_path):
            if keyword_lower in json.dumps(record, ensure_ascii=False).lower():
                match_count += 1
        query_samples.append({"seconds": elapsed(started), "match_count": match_count})

    capabilities = columnar_capabilities()
    parquet_payload: dict[str, object]
    duckdb_payload: dict[str, object]
    if capabilities["parquet_write_available"]:
        parquet_started = time.perf_counter()
        parquet_result = write_parquet_artifacts(
            synthetic_artifact_records(record_count=record_count, keyword=keyword),
            output_path=parquet_path,
        )
        parquet_payload = {
            "status": "written",
            "seconds": elapsed(parquet_started),
            "path": parquet_result.path,
            "record_count": parquet_result.record_count,
            "rejected_count": parquet_result.rejected_count,
            "size_bytes": parquet_path.stat().st_size if parquet_path.exists() else 0,
            "manifest": parquet_result.manifest,
        }
        duckdb_payload = benchmark_duckdb_parquet_query(
            parquet_path=parquet_path,
            keyword=keyword,
            query_iterations=query_iterations,
            capabilities=capabilities,
        )
    else:
        parquet_payload = {
            "status": "skipped",
            "reason": "pyarrow-not-installed",
            "install_hint": capabilities["install_hint"],
        }
        duckdb_payload = {
            "status": "skipped",
            "reason": "parquet-not-written",
            "install_hint": capabilities["install_hint"],
        }

    payload = {
        "command": "columnar-benchmark",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "record_count": record_count,
        "keyword": keyword,
        "capabilities": capabilities,
        "environment": columnar_benchmark_environment(),
        "plan": build_columnar_benchmark_plan(record_counts=(record_count,)),
        "jsonl_baseline": {
            "status": "written",
            "seconds": jsonl_seconds,
            "records_per_second": round(record_count / jsonl_seconds, 2) if jsonl_seconds > 0 else None,
            "path": jsonl_result.path,
            "manifest_path": jsonl_result.manifest_path,
            "record_count": jsonl_result.record_count,
            "rejected_count": jsonl_result.rejected_count,
            "size_bytes": jsonl_result.size_bytes,
            "sha256": jsonl_result.sha256,
            "query_iterations": query_iterations,
            "query_seconds_p50": percentile(query_samples, "seconds", 50),
            "query_seconds_p95": percentile(query_samples, "seconds", 95),
            "query_match_count": query_samples[-1]["match_count"] if query_samples else 0,
        },
        "parquet": parquet_payload,
        "duckdb_parquet_query": duckdb_payload,
        "resource_usage": current_resource_usage(),
        "commercial_readiness": {
            "ready_for_1m_10m_claim": False,
            "commercial_gap_ids": ["#66", "#74"],
            "blockers": [
                "single-machine-synthetic-run-only",
                "release-hardware-profile-and-independent-reproduction-required",
                "parquet-path-requires-pyarrow-and-duckdb-for-full-query-comparison",
            ],
        },
        "outputs": {
            "json": str(json_path),
            "markdown": str(markdown_path),
            "jsonl": str(jsonl_path),
            "parquet": str(parquet_path) if parquet_path.exists() else "",
        },
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(render_columnar_benchmark_markdown(payload), encoding="utf-8")
    return payload


def convert_jsonl_to_parquet(
    *,
    input_jsonl: Path,
    output_parquet: Path,
    row_group_size: int = 100_000,
) -> dict[str, object]:
    input_jsonl = input_jsonl.expanduser().resolve()
    output_parquet = output_parquet.expanduser().resolve()
    if not input_jsonl.is_file():
        raise ValueError(f"ArtifactRecordV1 JSONL input does not exist: {input_jsonl}")
    if row_group_size <= 0:
        raise ValueError("row_group_size must be greater than zero")

    started = time.perf_counter()
    result = write_parquet_artifacts(
        read_jsonl_artifacts(input_jsonl),
        output_path=output_parquet,
        row_group_size=row_group_size,
    )
    seconds = elapsed(started)
    manifest_path = output_parquet.with_suffix(output_parquet.suffix + ".conversion.json")
    payload = {
        "command": "columnar-convert",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "input_jsonl": str(input_jsonl),
        "input_jsonl_size_bytes": input_jsonl.stat().st_size,
        "input_jsonl_sha256": hash_file(input_jsonl),
        "output_parquet": result.path,
        "output_parquet_size_bytes": output_parquet.stat().st_size if output_parquet.exists() else 0,
        "seconds": seconds,
        "records_per_second": round(result.record_count / seconds, 2) if seconds > 0 else None,
        "record_count": result.record_count,
        "rejected_count": result.rejected_count,
        "row_group_size": row_group_size,
        "manifest": result.manifest,
        "manifest_path": str(manifest_path),
        "capabilities": columnar_capabilities(),
        "resource_usage": current_resource_usage(),
        "commercial_readiness": {
            "storage_path_ready": result.record_count > 0 and result.rejected_count == 0,
            "commercial_gap_ids": ["#66", "#74"],
            "blockers": [
                "requires-validation-of-source-parser-records",
                "requires-large-case-query-benchmark-before-commercial-performance-claim",
            ],
        },
    }
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def synthetic_artifact_records(*, record_count: int, keyword: str) -> Iterable[dict[str, object]]:
    for index in range(record_count):
        include_keyword = index % 10 == 0
        text = f"{keyword} encoded command candidate" if include_keyword else "routine artifact row"
        yield {
            "schema": ARTIFACT_RECORD_SCHEMA,
            "artifact_id": f"BENCH:SRC:eventlog:{index:012d}",
            "artifact_family": "windows-eventlog",
            "artifact_type": "eventlog-event",
            "parser": "rapidtriage-columnar-benchmark",
            "parser_version": "1",
            "source": {
                "case_id": "BENCH",
                "source_id": "SRC",
                "source_path": "synthetic.evtx",
                "offset": index * 128,
                "length": 128,
                "hashes": {},
            },
            "confidence": 0.5,
            "validation_required": True,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": ["synthetic-benchmark-row"],
            "legal_limitations": ["Synthetic benchmark records are not forensic evidence."],
            "fields": {
                "record_id": index,
                "event_id": "4104" if include_keyword else "4624",
                "channel": "Microsoft-Windows-PowerShell/Operational" if include_keyword else "Security",
                "message": text,
            },
        }


def benchmark_duckdb_parquet_query(
    *,
    parquet_path: Path,
    keyword: str,
    query_iterations: int,
    capabilities: Mapping[str, object],
) -> dict[str, object]:
    if not capabilities.get("duckdb_query_available"):
        return {
            "status": "skipped",
            "reason": "duckdb-not-installed",
            "install_hint": capabilities.get("install_hint", "pip install .[columnar]"),
        }
    try:
        import duckdb  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return {
            "status": "skipped",
            "reason": "duckdb-not-installed",
            "install_hint": capabilities.get("install_hint", "pip install .[columnar]"),
        }
    keyword_pattern = f"%{keyword.lower()}%"
    samples = []
    match_count = 0
    for _ in range(query_iterations):
        started = time.perf_counter()
        with duckdb.connect(database=":memory:") as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS match_count
                FROM read_parquet(?)
                WHERE lower(fields_json) LIKE ?
                """,
                [str(parquet_path), keyword_pattern],
            ).fetchone()
        match_count = int(row[0] if row else 0)
        samples.append({"seconds": elapsed(started), "match_count": match_count})
    return {
        "status": "queried",
        "engine": "duckdb",
        "query_iterations": query_iterations,
        "query_seconds_p50": percentile(samples, "seconds", 50),
        "query_seconds_p95": percentile(samples, "seconds", 95),
        "query_match_count": match_count,
        "query": "SELECT COUNT(*) FROM read_parquet(?) WHERE lower(fields_json) LIKE ?",
    }


def elapsed(started: float) -> float:
    return round(max(time.perf_counter() - started, 0.000001), 6)


def percentile(samples: list[dict[str, object]], key: str, percentile_value: int) -> float:
    values = sorted(float(sample[key]) for sample in samples if key in sample)
    if not values:
        return 0.0
    if len(values) == 1:
        return round(values[0], 6)
    if percentile_value == 50:
        return round(float(statistics.median(values)), 6)
    index = min(len(values) - 1, max(0, int(round((percentile_value / 100) * (len(values) - 1)))))
    return round(values[index], 6)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_resource_usage() -> dict[str, object]:
    try:
        import resource
    except ModuleNotFoundError:
        return {"peak_rss_bytes": None, "source": "resource-module-unavailable"}
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # macOS reports bytes; Linux reports KiB. Keep both visible to avoid hiding platform variance.
    return {
        "max_rss_raw": usage.ru_maxrss,
        "max_rss_platform_units": "bytes-on-macos-kib-on-linux",
        "source": "resource.getrusage",
    }


def columnar_benchmark_environment() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "dependency_versions": {
            "pyarrow": module_version("pyarrow"),
            "duckdb": module_version("duckdb"),
        },
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def module_version(module_name: str) -> str:
    try:
        module = __import__(module_name)
    except ModuleNotFoundError:
        return ""
    return str(getattr(module, "__version__", "unknown"))


def render_columnar_benchmark_markdown(payload: Mapping[str, object]) -> str:
    jsonl = payload.get("jsonl_baseline") if isinstance(payload.get("jsonl_baseline"), Mapping) else {}
    parquet = payload.get("parquet") if isinstance(payload.get("parquet"), Mapping) else {}
    duckdb_query = payload.get("duckdb_parquet_query") if isinstance(payload.get("duckdb_parquet_query"), Mapping) else {}
    environment = payload.get("environment") if isinstance(payload.get("environment"), Mapping) else {}
    lines = [
        "# Columnar Benchmark",
        "",
        f"- Records: `{payload.get('record_count')}`",
        f"- Keyword: `{payload.get('keyword')}`",
        f"- Platform: `{environment.get('platform', '')}`",
        f"- Python: `{environment.get('python_version', '')}`",
        f"- JSONL write seconds: `{jsonl.get('seconds')}`",
        f"- JSONL records/sec: `{jsonl.get('records_per_second')}`",
        f"- JSONL query p50: `{jsonl.get('query_seconds_p50')}`",
        f"- JSONL query p95: `{jsonl.get('query_seconds_p95')}`",
        f"- Parquet status: `{parquet.get('status')}`",
        f"- DuckDB query status: `{duckdb_query.get('status')}`",
        f"- DuckDB query p50: `{duckdb_query.get('query_seconds_p50', '')}`",
        f"- DuckDB query p95: `{duckdb_query.get('query_seconds_p95', '')}`",
        "",
        "This benchmark is synthetic and does not prove commercial readiness by itself.",
        "",
    ]
    return "\n".join(lines)


def write_parquet_artifacts(
    records: Iterable[Mapping[str, object]],
    *,
    output_path: Path,
    reject_invalid: bool = True,
    row_group_size: int = 100_000,
) -> ColumnarWriteResult:
    try:
        import pyarrow as pa  # type: ignore[import-not-found]
        import pyarrow.parquet as pq  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        raise ColumnarStoreUnavailable("pyarrow is required for Parquet artifact output; install .[columnar]") from exc

    output_path = output_path.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if row_group_size <= 0:
        raise ValueError("row_group_size must be greater than zero")
    writer = None
    rows: list[dict[str, object]] = []
    record_count = 0
    rejected_count = 0
    row_group_count = 0
    for index, record in enumerate(records, start=1):
        validation_errors = validate_artifact_record(record)
        if validation_errors:
            rejected_count += 1
            if reject_invalid:
                continue
        rows.append(normalize_artifact_record_for_columnar(record, fallback_id=f"invalid-{index}"))
        if len(rows) >= row_group_size:
            table = pa.Table.from_pylist(rows)
            if writer is None:
                writer = pq.ParquetWriter(output_path, table.schema)
            writer.write_table(table)
            record_count += len(rows)
            row_group_count += 1
            rows.clear()
    if rows:
        table = pa.Table.from_pylist(rows)
        if writer is None:
            writer = pq.ParquetWriter(output_path, table.schema)
        writer.write_table(table)
        record_count += len(rows)
        row_group_count += 1
        rows.clear()
    if writer is not None:
        writer.close()
    else:
        table = pa.Table.from_pylist([empty_columnar_row()]).slice(0, 0)
        pq.write_table(table, output_path)
        row_group_count = 0
    manifest = {
        "command": "parquet-artifact-store",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "schema": ARTIFACT_RECORD_SCHEMA,
        "format": "parquet",
        "path": str(output_path),
        "record_count": record_count,
        "rejected_count": rejected_count,
        "row_group_size": row_group_size,
        "row_group_count": row_group_count,
        "streaming_safe": True,
        "column_count": len(table.schema),
        "storage_role": "high-volume-artifact-columnar-store",
    }
    return ColumnarWriteResult(
        path=str(output_path),
        record_count=record_count,
        rejected_count=rejected_count,
        format="parquet",
        manifest=manifest,
    )


def normalize_artifact_record_for_columnar(record: Mapping[str, object], *, fallback_id: str) -> dict[str, object]:
    source = record.get("source") if isinstance(record.get("source"), Mapping) else {}
    return {
        "schema": str(record.get("schema") or ARTIFACT_RECORD_SCHEMA),
        "artifact_id": str(record.get("artifact_id") or fallback_id),
        "artifact_family": str(record.get("artifact_family") or ""),
        "artifact_type": str(record.get("artifact_type") or ""),
        "parser": str(record.get("parser") or ""),
        "parser_version": str(record.get("parser_version") or ""),
        "case_id": str(source.get("case_id") or ""),
        "source_id": str(source.get("source_id") or ""),
        "source_path": str(source.get("source_path") or ""),
        "offset": optional_int(source.get("offset")),
        "length": optional_int(source.get("length")),
        "confidence": float(record.get("confidence") or 0),
        "validation_required": bool(record.get("validation_required")),
        "commercial_grade_ready": bool(record.get("commercial_grade_ready")),
        "commercial_grade_blockers_json": json.dumps(record.get("commercial_grade_blockers") or []),
        "legal_limitations_json": json.dumps(record.get("legal_limitations") or []),
        "fields_json": json.dumps(record.get("fields") or {}, ensure_ascii=False, sort_keys=True),
        "source_hashes_json": json.dumps(source.get("hashes") or {}, ensure_ascii=False, sort_keys=True),
    }


def empty_columnar_row() -> dict[str, object]:
    return {
        "schema": ARTIFACT_RECORD_SCHEMA,
        "artifact_id": "",
        "artifact_family": "",
        "artifact_type": "",
        "parser": "",
        "parser_version": "",
        "case_id": "",
        "source_id": "",
        "source_path": "",
        "offset": None,
        "length": None,
        "confidence": 0.0,
        "validation_required": False,
        "commercial_grade_ready": False,
        "commercial_grade_blockers_json": "[]",
        "legal_limitations_json": "[]",
        "fields_json": "{}",
        "source_hashes_json": "{}",
    }


def optional_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


COLUMNAR_ARTIFACTS_QUERY_PROFILE_VERSION = "columnar-artifacts-query-v1"
COLUMNAR_ARTIFACTS_QUERY_MAX_LIMIT = 1000


def query_columnar_artifact_records(
    *,
    parquet_path: Path,
    offset: int = 0,
    limit: int = 200,
    artifact_family: str | None = None,
    artifact_type: str | None = None,
    keyword: str | None = None,
) -> dict[str, object]:
    """Query the run columnar sidecar Parquet with bounded pagination.

    Large-case query path over the opt-in ``columnar_artifacts`` sidecar:
    DuckDB scans the Parquet file with parameterized filters and returns a
    bounded page plus an offset cursor. Degrades to a ``skipped`` payload
    when the duckdb optional dependency is missing — callers must treat
    that as "use the JSONL/JSON outputs", never as an error.
    """
    capabilities = columnar_capabilities()
    if not capabilities.get("duckdb_query_available"):
        return {
            "profile_version": COLUMNAR_ARTIFACTS_QUERY_PROFILE_VERSION,
            "status": "skipped",
            "reason": "duckdb-not-installed",
            "install_hint": capabilities.get("install_hint", "pip install .[columnar]"),
            "parquet_path": str(parquet_path),
        }
    try:
        import duckdb  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return {
            "profile_version": COLUMNAR_ARTIFACTS_QUERY_PROFILE_VERSION,
            "status": "skipped",
            "reason": "duckdb-not-installed",
            "install_hint": capabilities.get("install_hint", "pip install .[columnar]"),
            "parquet_path": str(parquet_path),
        }
    bounded_limit = max(1, min(int(limit), COLUMNAR_ARTIFACTS_QUERY_MAX_LIMIT))
    bounded_offset = max(0, int(offset))
    conditions: list[str] = []
    parameters: list[object] = [str(parquet_path)]
    if artifact_family:
        conditions.append("artifact_family = ?")
        parameters.append(artifact_family)
    if artifact_type:
        conditions.append("artifact_type = ?")
        parameters.append(artifact_type)
    if keyword:
        conditions.append("lower(fields_json) LIKE ?")
        parameters.append(f"%{keyword.lower()}%")
    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    started = time.perf_counter()
    with duckdb.connect(database=":memory:") as connection:
        total_row = connection.execute(
            f"SELECT COUNT(*) FROM read_parquet(?) {where_clause}",
            parameters,
        ).fetchone()
        total_count = int(total_row[0] if total_row else 0)
        page_rows = connection.execute(
            f"""
            SELECT artifact_id, artifact_family, artifact_type, parser, parser_version,
                   case_id, source_id, source_path, "offset", length, confidence,
                   validation_required, commercial_grade_ready,
                   commercial_grade_blockers_json, legal_limitations_json,
                   fields_json, source_hashes_json
            FROM read_parquet(?)
            {where_clause}
            ORDER BY artifact_id
            LIMIT ? OFFSET ?
            """,
            [*parameters, bounded_limit, bounded_offset],
        ).fetchall()
    query_seconds = elapsed(started)
    records: list[dict[str, object]] = [
        {
            "artifact_id": row[0],
            "artifact_family": row[1],
            "artifact_type": row[2],
            "parser": row[3],
            "parser_version": row[4],
            "case_id": row[5],
            "source_id": row[6],
            "source_path": row[7],
            "offset": row[8],
            "length": row[9],
            "confidence": float(row[10] or 0),
            "validation_required": bool(row[11]),
            "commercial_grade_ready": bool(row[12]),
            "commercial_grade_blockers": json.loads(row[13] or "[]"),
            "legal_limitations": json.loads(row[14] or "[]"),
            "fields": json.loads(row[15] or "{}"),
            "source_hashes": json.loads(row[16] or "{}"),
        }
        for row in page_rows
    ]
    end = bounded_offset + len(records)
    return {
        "profile_version": COLUMNAR_ARTIFACTS_QUERY_PROFILE_VERSION,
        "status": "queried",
        "engine": "duckdb",
        "parquet_path": str(parquet_path),
        "query_seconds": query_seconds,
        "filters": {
            "artifact_family": artifact_family or None,
            "artifact_type": artifact_type or None,
            "keyword": keyword or None,
        },
        "total_count": total_count,
        "offset": bounded_offset,
        "limit": bounded_limit,
        "returned_count": len(records),
        "has_more": end < total_count,
        "next_offset": end if end < total_count else None,
        "records": records,
        "reportability_warning": (
            "Columnar sidecar rows are derived index views of ArtifactRecordV1 rows; "
            "cite the JSONL audit sidecar and source viewer before report use."
        ),
    }
