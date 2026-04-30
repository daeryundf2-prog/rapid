from __future__ import annotations

import json
import os
import tempfile
import textwrap
import unittest
import contextlib
import io
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.worker import RustWorkerClient, WorkerError, parse_jsonl_records


class RapidTriageWorkerClientTests(unittest.TestCase):
    def test_parser_exposes_worker_parse_command(self) -> None:
        commands = build_parser()._subparsers._group_actions[0].choices

        self.assertIn("worker-parse", commands)
        self.assertIn("--kind", commands["worker-parse"].format_help())
        self.assertIn("--worker", commands["worker-parse"].format_help())

    def test_parse_jsonl_records_separates_records_and_malformed_lines(self) -> None:
        records, errors = parse_jsonl_records('{"schema":"ArtifactRecordV1"}\nnot-json\n[]\n')

        self.assertEqual(records, [{"schema": "ArtifactRecordV1"}])
        self.assertEqual(errors[0]["type"], "malformed-jsonl")
        self.assertEqual(errors[1]["type"], "non-object-jsonl")

    def test_worker_client_reads_successful_jsonl_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            worker = write_worker_script(
                Path(tmp_dir),
                """
                import json
                print(json.dumps({
                    "schema": "ArtifactRecordV1",
                    "artifact_id": "CASE:SRC:noop:0",
                    "artifact_family": "worker-health",
                    "artifact_type": "noop-worker-record",
                    "parser": "fake-worker",
                    "parser_version": "0.1",
                    "source": {
                        "case_id": "CASE",
                        "source_id": "SRC",
                        "source_path": "source.bin",
                        "offset": None,
                        "length": None,
                        "hashes": {}
                    },
                    "confidence": 1.0,
                    "validation_required": False,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": ["contract-test"],
                    "legal_limitations": ["not evidence"],
                    "fields": {}
                }))
                """,
            )
            client = RustWorkerClient(executable=worker, timeout_seconds=3)

            result = client.parse(kind="noop", source=Path("source.bin"), case_id="CASE", source_id="SRC")

            self.assertTrue(result.ok)
            self.assertEqual(result.records[0]["schema"], "ArtifactRecordV1")
            self.assertIn("--kind", result.command)

    def test_worker_client_reports_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            worker = write_worker_script(
                Path(tmp_dir),
                """
                import sys
                print("bad stdout")
                print("boom", file=sys.stderr)
                raise SystemExit(7)
                """,
            )
            client = RustWorkerClient(executable=worker, timeout_seconds=3)

            result = client.parse(kind="noop", source=Path("source.bin"))

            self.assertFalse(result.ok)
            self.assertEqual(result.return_code, 7)
            self.assertTrue(any(error["type"] == "worker-nonzero-exit" for error in result.errors))

    def test_worker_client_reports_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            worker = write_worker_script(
                Path(tmp_dir),
                """
                import time
                time.sleep(2)
                """,
            )
            client = RustWorkerClient(executable=worker, timeout_seconds=0.1)

            result = client.parse(kind="noop", source=Path("source.bin"))

            self.assertTrue(result.timed_out)
            self.assertEqual(result.errors[0]["type"], "worker-timeout")

    def test_worker_client_can_stream_output_to_jsonl_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_path = root / "worker-artifacts.jsonl"
            worker = write_worker_script(
                root,
                """
                import json
                for index in range(2):
                    print(json.dumps({
                        "schema": "ArtifactRecordV1",
                        "artifact_id": f"CASE:SRC:file:{index}",
                        "artifact_family": "file-system",
                        "artifact_type": "file-inventory-record",
                        "parser": "fake-worker",
                        "parser_version": "0.1",
                        "source": {
                            "case_id": "CASE",
                            "source_id": "SRC",
                            "source_path": "source.bin",
                            "offset": None,
                            "length": 10,
                            "hashes": {}
                        },
                        "confidence": 0.9,
                        "validation_required": False,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": ["contract-test"],
                        "legal_limitations": ["not evidence"],
                        "fields": {"index": index}
                    }))
                """,
            )
            client = RustWorkerClient(executable=worker, timeout_seconds=3)

            payload = client.parse_to_jsonl(
                kind="file-inventory",
                source=Path("source.bin"),
                output_path=output_path,
                case_id="CASE",
                source_id="SRC",
            )

            self.assertEqual(payload["pipeline_status"], "ok")
            self.assertEqual(payload["worker"]["record_count"], 2)
            self.assertEqual(payload["artifact_store"]["record_count"], 2)
            self.assertTrue(output_path.is_file())
            self.assertFalse(output_path.with_name(output_path.name + ".partial").exists())

    def test_worker_parse_to_jsonl_quarantines_failed_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_path = root / "worker-artifacts.jsonl"
            worker = write_worker_script(
                root,
                """
                import json
                import sys
                print(json.dumps({
                    "schema": "ArtifactRecordV1",
                    "artifact_id": "CASE:SRC:file:1",
                    "artifact_family": "file-system",
                    "artifact_type": "file-inventory-record",
                    "parser": "fake-worker",
                    "parser_version": "0.1",
                    "source": {
                        "case_id": "CASE",
                        "source_id": "SRC",
                        "source_path": "source.bin",
                        "offset": None,
                        "length": 10,
                        "hashes": {}
                    },
                    "confidence": 0.9,
                    "validation_required": False,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": ["contract-test"],
                    "legal_limitations": ["not evidence"],
                    "fields": {}
                }))
                print("boom", file=sys.stderr)
                raise SystemExit(9)
                """,
            )
            client = RustWorkerClient(executable=worker, timeout_seconds=3)

            payload = client.parse_to_jsonl(
                kind="file-inventory",
                source=Path("source.bin"),
                output_path=output_path,
                case_id="CASE",
                source_id="SRC",
            )

            self.assertEqual(payload["pipeline_status"], "review-required")
            self.assertFalse(output_path.exists())
            self.assertTrue(output_path.with_name(output_path.name + ".partial").is_file())
            self.assertEqual(payload["artifact_store"]["record_count"], 1)
            self.assertEqual(payload["worker"]["return_code"], 9)

    def test_worker_parse_cli_writes_jsonl_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_path = root / "worker-artifacts.jsonl"
            worker = write_worker_script(
                root,
                """
                import json
                print(json.dumps({
                    "schema": "ArtifactRecordV1",
                    "artifact_id": "CASE:SRC:file:1",
                    "artifact_family": "file-system",
                    "artifact_type": "file-inventory-record",
                    "parser": "fake-worker",
                    "parser_version": "0.1",
                    "source": {
                        "case_id": "CASE",
                        "source_id": "SRC",
                        "source_path": "source.bin",
                        "offset": None,
                        "length": 10,
                        "hashes": {}
                    },
                    "confidence": 0.9,
                    "validation_required": False,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": ["contract-test"],
                    "legal_limitations": ["not evidence"],
                    "fields": {}
                }))
                """,
            )
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "worker-parse",
                        "source.bin",
                        "--kind",
                        "file-inventory",
                        "--worker",
                        str(worker),
                        "--output",
                        str(output_path),
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["pipeline_status"], "ok")
            self.assertTrue(output_path.is_file())
            self.assertTrue(output_path.with_suffix(".jsonl.manifest.json").is_file())

    def test_worker_parse_cli_reads_worker_from_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_path = root / "worker-artifacts.jsonl"
            worker = write_worker_script(
                root,
                """
                import json
                print(json.dumps({
                    "schema": "ArtifactRecordV1",
                    "artifact_id": "CASE:SRC:noop:1",
                    "artifact_family": "worker-health",
                    "artifact_type": "noop-worker-record",
                    "parser": "fake-worker",
                    "parser_version": "0.1",
                    "source": {
                        "case_id": "CASE",
                        "source_id": "SRC",
                        "source_path": "source.bin",
                        "offset": None,
                        "length": None,
                        "hashes": {}
                    },
                    "confidence": 1.0,
                    "validation_required": False,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": ["contract-test"],
                    "legal_limitations": ["not evidence"],
                    "fields": {}
                }))
                """,
            )
            stdout = io.StringIO()
            previous = os.environ.get("RAPIDTRIAGE_RUST_WORKER")
            os.environ["RAPIDTRIAGE_RUST_WORKER"] = str(worker)
            try:
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(
                        [
                            "worker-parse",
                            "source.bin",
                            "--kind",
                            "noop",
                            "--output",
                            str(output_path),
                            "--json",
                        ]
                    )
            finally:
                if previous is None:
                    os.environ.pop("RAPIDTRIAGE_RUST_WORKER", None)
                else:
                    os.environ["RAPIDTRIAGE_RUST_WORKER"] = previous

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["pipeline_status"], "ok")
            self.assertTrue(output_path.is_file())

    def test_missing_worker_is_clear_error(self) -> None:
        client = RustWorkerClient(executable=Path("/definitely/missing/rapid-worker"))

        with self.assertRaises(WorkerError):
            client.parse(kind="noop", source=Path("source.bin"))


def write_worker_script(root: Path, body: str) -> Path:
    path = root / "fake_worker.py"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "_args = sys.argv[1:]\n"
        + textwrap.dedent(body).strip()
        + "\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | 0o111)
    return path


if __name__ == "__main__":
    unittest.main()
