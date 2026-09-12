"""Benchmark, smoke-test, and readiness subcommand handlers."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from ..core.benchmark import BenchmarkError, build_stress_test_plan, run_benchmark
from ..core.benchmark_fts import SqliteFtsBenchmarkError, run_sqlite_fts_benchmark
from ..core.browser_stress import run_browser_large_result_stress
from ..core.columnar_store import (
        ColumnarStoreUnavailable,
        convert_jsonl_to_parquet,
        run_columnar_benchmark,
)
from ..core.docs import write_result
from ..core.e01 import build_windows11_e01_known_answer_manifest
from ..core.e01_hash import E01StreamingHashError, run_e01_streaming_hash
from ..core.e01_smoke import run_windows11_e01_smoke
from ..core.large_case_readiness import (
        LargeCaseReadinessError,
        build_large_case_readiness_report,
)
from ..core.macos_live_smoke import MacOsLiveSmokeError, run_macos_live_smoke
from ..core.run import RunModeError
from ..core.search import SearchError
from ..core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview


def handle_benchmark(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_benchmark(
                root=Path(args.root).expanduser().resolve() if args.root else None,
                output_dir=Path(args.output_dir).expanduser().resolve(),
                file_count=args.file_count,
                keyword=args.keyword,
                mode=args.mode,
                search_iterations=args.search_iterations,
                overwrite=args.overwrite,
                resume=args.resume,
            )
        except (BenchmarkError, SearchError, RunModeError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            metrics = payload["metrics"]
            print(f"Saved benchmark JSON: {payload['outputs']['json']}")
            print(f"Saved benchmark report: {payload['outputs']['markdown']}")
            print(
                "Ingest: "
                f"{metrics['ingest_seconds']}s  Search p50: {metrics['search_p50_seconds']}s  "
                f"Search p95: {metrics['search_p95_seconds']}s"
            )
        return 0



def handle_macos_live_smoke(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_macos_live_smoke(
                output_dir=Path(args.output_dir),
                root=Path(args.root),
                home=Path(args.home) if args.home else None,
                case_db_path=Path(args.case_db) if args.case_db else None,
                benchmark_file_count=args.benchmark_file_count,
                fts_record_count=args.fts_record_count,
                keyword=args.keyword,
                overwrite=args.overwrite,
                include_path_details=args.include_path_details,
            )
        except (MacOsLiveSmokeError, BenchmarkError, SearchError, RunModeError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            summary = payload.get("summary", {})
            print(f"Saved macOS live smoke JSON: {payload['outputs']['json']}")
            print(f"Saved macOS live smoke report: {payload['outputs']['markdown']}")
            print(
                f"Local smoke score: {summary.get('local_smoke_score')} "
                f"({summary.get('passed_count')}/{summary.get('check_count')} checks)"
            )
        return 0



def handle_e01_smoke(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = run_windows11_e01_smoke(
            Path(args.source),
            output_dir=Path(args.output_dir),
            case_id=args.case_id,
            mode=args.mode,
            input_kind=args.input_kind,
            expected_partition_start_sector=args.expected_partition_start_sector,
            expected_artifacts=args.expected_artifact,
            validation_commands=args.validation_command,
            execute=not args.plan_only,
            read_only=not args.write_extracts,
            resume=args.resume,
            max_file_count=args.max_file_count,
            max_extract_size_bytes=args.max_extract_size_bytes,
            memory_cap_bytes=args.memory_cap_bytes,
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"E01 smoke report: {payload['case_id']}")
            print(f"Status: {payload['status']}")
            print(f"Source: {payload['source_path']}")
            print(f"Saved: {payload['outputs']['smoke_report']['path']}")
            print("Stages:")
            for stage in payload["stages"]:
                print(f"- {stage['id']}: {stage['status']}")
            run_error = payload.get("run_error")
            if isinstance(run_error, dict) and run_error.get("failure_guidance"):
                guidance = run_error["failure_guidance"]
                print(f"Run blocker: {guidance.get('title', run_error.get('error'))}")
                for action in guidance.get("next_actions", []):
                    print(f"- {action}")
        return 0



def handle_e01_hash(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_e01_streaming_hash(
                source_path=Path(args.source).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                algorithms=tuple(args.algorithm or ["sha256", "sha1", "md5"]),
                chunk_size=args.chunk_size,
                checkpoint_interval_bytes=args.checkpoint_interval_bytes,
                overwrite=args.overwrite,
            )
        except (E01StreamingHashError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved E01 hash JSON: {payload['outputs']['json']}")
            print(f"Saved E01 hash report: {payload['outputs']['markdown']}")
            print(f"SHA256: {payload['digests'].get('sha256', '')}")
        return 0



def handle_e01_known_answer(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = build_windows11_e01_known_answer_manifest(
            Path(args.source),
            case_id=args.case_id,
            expected_partition_start_sector=args.expected_partition_start_sector,
            expected_artifacts=args.expected_artifact,
            validation_commands=args.validation_command,
        )
        if args.output:
            write_result(payload, Path(args.output).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"E01 known-answer manifest: {payload['case_id']}")
            print(f"Status: {payload['status']}")
            print(f"Source: {payload['source_image']['path']}")
            if args.output:
                print(f"Saved: {Path(args.output).expanduser().resolve()}")
            print(f"Manifest SHA256: {payload['manifest_sha256']}")
            print("Next steps:")
            for action in payload["operator_next_steps"]:
                print(f"- {action}")
        return 0



def handle_columnar_benchmark(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_columnar_benchmark(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                record_count=args.record_count,
                keyword=args.keyword,
                query_iterations=args.query_iterations,
            )
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            jsonl = payload["jsonl_baseline"]
            parquet = payload["parquet"]
            print(f"Saved columnar benchmark JSON: {payload['outputs']['json']}")
            print(f"Saved columnar benchmark report: {payload['outputs']['markdown']}")
            print(
                "JSONL: "
                f"{jsonl['record_count']} rows in {jsonl['seconds']}s "
                f"({jsonl['records_per_second']} rows/s), query p95 {jsonl['query_seconds_p95']}s"
            )
            print(f"Parquet: {parquet['status']}")
            print(f"DuckDB Parquet query: {payload['duckdb_parquet_query']['status']}")
        return 0



def handle_columnar_convert(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = convert_jsonl_to_parquet(
                input_jsonl=Path(args.input_jsonl).expanduser().resolve(),
                output_parquet=Path(args.output_parquet).expanduser().resolve(),
                row_group_size=args.row_group_size,
            )
        except (ColumnarStoreUnavailable, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved Parquet: {payload['output_parquet']}")
            print(f"Saved conversion manifest: {payload['manifest_path']}")
            print(
                "Rows: "
                f"{payload['record_count']}  Rejected: {payload['rejected_count']}  "
                f"Rows/s: {payload['records_per_second']}"
            )
        return 0



def handle_stress_plan(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_stress_test_plan(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                evidence_sizes_tb=tuple(args.size_tb or [1, 5, 10]),
                expected_throughput_mb_s=args.expected_throughput_mb_s,
                overwrite=args.overwrite,
            )
        except (BenchmarkError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved stress plan JSON: {payload['outputs']['json']}")
            print(f"Saved stress plan report: {payload['outputs']['markdown']}")
            print(f"Scenarios: {payload['summary']['scenario_count']}")
        return 0



def handle_browser_stress(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        payload = run_browser_large_result_stress(
            base_url=args.base_url,
            output_dir=Path(args.output_dir).expanduser().resolve(),
            record_count=args.record_count,
            headless=not args.headed,
            require_playwright=args.require_playwright,
            timeout_ms=args.timeout_ms,
        )
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved browser stress JSON: {Path(args.output_dir).expanduser().resolve() / 'browser-large-result-stress.json'}")
            print(f"Status: {payload['status']}")
            if payload.get("skip_reason"):
                print(f"Reason: {payload['skip_reason']}")
        return 1 if payload["status"] in {"failed", "blocked"} else 0



def handle_sqlite_fts_benchmark(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = run_sqlite_fts_benchmark(
                output_dir=Path(args.output_dir).expanduser().resolve(),
                record_count=args.record_count,
                keyword=args.keyword,
                query_iterations=args.query_iterations,
                hit_every=args.hit_every,
                overwrite=args.overwrite,
            )
        except (SqliteFtsBenchmarkError, OSError, sqlite3.Error) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            metrics = payload["metrics"]
            print(f"Saved SQLite FTS benchmark JSON: {payload['outputs']['json']}")
            print(f"Saved SQLite FTS benchmark report: {payload['outputs']['markdown']}")
            print(
                "SQLite FTS: "
                f"{metrics['record_count']} rows, query p95 {metrics['query_p95_seconds']}s, "
                f"expected hits {metrics['expected_hit_count']}"
            )
        return 0



def handle_large_case_readiness(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_large_case_readiness_report(
                case_db_path=Path(args.case_db).expanduser().resolve() if args.case_db else None,
                benchmark_paths=[Path(path).expanduser().resolve() for path in args.benchmark],
                keyword=args.keyword,
                max_query_p95_ms=args.max_query_p95_ms,
                memory_cap_bytes=args.memory_cap_bytes,
                output=Path(args.output).expanduser().resolve() if args.output else None,
            )
        except (LargeCaseReadinessError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Large-case readiness: {payload['status']}")
            print(
                "Checks: "
                f"{payload['summary']['passed_check_count']}/{payload['summary']['check_count']} passed"
            )
            print(f"Largest benchmark: {payload['summary']['largest_benchmark_record_count']} rows")
            print(f"Commercial blockers: {payload['summary']['commercial_blocker_count']}")
            if args.output:
                print(f"Saved readiness JSON: {Path(args.output).expanduser().resolve()}")
        return 0 if payload["status"] == "internal-evidence-present" else 2



def handle_sqlite_wal_preview(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
        try:
            payload = build_sqlite_wal_preview(
                database_path=Path(args.database).expanduser().resolve(),
                output_dir=Path(args.output_dir).expanduser().resolve(),
                max_frames=args.max_frames,
                preferred_trusted_tool=args.preferred_trusted_tool,
                trusted_tool_timeout_seconds=args.trusted_tool_timeout_seconds,
            )
        except (SqliteWalPreviewError, OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Saved SQLite WAL preview JSON: {payload['outputs']['json']}")
            print(f"Saved SQLite WAL preview report: {payload['outputs']['markdown']}")
            print(f"WAL status: {payload['wal']['status']}")
        return 0



__all__ = ["HANDLERS"]


HANDLERS = {
    "benchmark": handle_benchmark,
    "macos-live-smoke": handle_macos_live_smoke,
    "e01-smoke": handle_e01_smoke,
    "e01-hash": handle_e01_hash,
    "e01-known-answer": handle_e01_known_answer,
    "columnar-benchmark": handle_columnar_benchmark,
    "columnar-convert": handle_columnar_convert,
    "stress-plan": handle_stress_plan,
    "browser-stress": handle_browser_stress,
    "sqlite-fts-benchmark": handle_sqlite_fts_benchmark,
    "large-case-readiness": handle_large_case_readiness,
    "sqlite-wal-preview": handle_sqlite_wal_preview,
}
