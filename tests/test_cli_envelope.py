"""Contract tests for the additive CLI ``_envelope`` key (T-160, D.8 / D71)."""

from __future__ import annotations

import io
import json
import time
import unittest

from rapidtriage import __version__
from rapidtriage.cli import output
from rapidtriage.core.plugins import load_plugin_registry

ENVELOPE_FIELDS = {
    "schema",
    "command",
    "status",
    "exit_code",
    "tool_version",
    "elapsed_ms",
    "truncated",
    "warnings",
    "errors",
}

DOCTOR_LIKE = {
    "command": "doctor",
    "status": "warn",
    "summary": {"ok": 5, "warn": 1, "error": 0, "check_count": 6},
    "checks": [{"name": "tesseract", "status": "warn"}],
}


def _emit(payload, **kwargs):
    stream = io.StringIO()
    returned = output.emit(payload, stream=stream, **kwargs)
    return returned, json.loads(stream.getvalue())


class EmitTests(unittest.TestCase):
    def test_emit_adds_exactly_one_key_and_preserves_doctor_status(self) -> None:
        before = json.loads(json.dumps(DOCTOR_LIKE))
        returned, printed = _emit(DOCTOR_LIKE, command="doctor")
        self.assertEqual(set(printed) - set(DOCTOR_LIKE), {"_envelope"})
        self.assertEqual(set(printed), set(DOCTOR_LIKE) | {"_envelope"})
        self.assertEqual(printed["status"], "warn")
        self.assertEqual(printed["_envelope"]["status"], "ok")
        self.assertEqual(returned, printed)
        self.assertEqual(DOCTOR_LIKE, before, "emit must not mutate the caller's payload")

    def test_emit_preserves_plugins_errors_key(self) -> None:
        payload = load_plugin_registry([])
        payload["errors"] = [{"path": "x.json", "error": "bad manifest"}]
        _, printed = _emit(payload, command="plugins")
        self.assertEqual(set(printed), set(payload) | {"_envelope"})
        self.assertEqual(printed["errors"], payload["errors"])
        self.assertEqual(printed["_envelope"]["errors"], [])

    def test_emit_without_command_key_does_not_add_top_level_command(self) -> None:
        payload = {"path": "evidence.E01", "kind": "e01"}
        _, printed = _emit(payload, command="evidence")
        self.assertNotIn("command", printed)
        self.assertEqual(printed["_envelope"]["command"], "evidence")

    def test_envelope_fields_and_values(self) -> None:
        started = time.monotonic()
        _, printed = _emit(
            {"command": "search"},
            command="search",
            status="partial",
            exit_code=output.EXIT_PARTIAL,
            started=started,
            warnings=[{"code": "SCAN_BUDGET_STOPPED", "message": "예산에서 멈춤"}],
        )
        envelope = printed["_envelope"]
        self.assertEqual(set(envelope), ENVELOPE_FIELDS)
        self.assertEqual(envelope["schema"], "rapidtriage.cli.v1")
        self.assertEqual(envelope["tool_version"], __version__)
        self.assertEqual(envelope["status"], "partial")
        self.assertEqual(envelope["exit_code"], 3)
        self.assertIsInstance(envelope["elapsed_ms"], int)
        self.assertGreaterEqual(envelope["elapsed_ms"], 0)
        self.assertFalse(envelope["truncated"])
        self.assertEqual(envelope["warnings"], [{"code": "SCAN_BUDGET_STOPPED", "message": "예산에서 멈춤"}])

    def test_emit_keeps_existing_json_formatting(self) -> None:
        stream = io.StringIO()
        output.emit({"command": "x", "이름": "값"}, command="x", stream=stream)
        text = stream.getvalue()
        self.assertIn('"이름": "값"', text)
        self.assertTrue(text.startswith('{\n  "command"'))

    def test_rejects_existing_envelope_and_bad_status_or_code(self) -> None:
        with self.assertRaises(ValueError):
            output.emit({"_envelope": {}}, command="x", stream=io.StringIO())
        with self.assertRaises(ValueError):
            output.emit({}, command="x", status="warn", stream=io.StringIO())
        with self.assertRaises(ValueError):
            output.emit({}, command="x", errors=[{"code": "not a code", "message": "m"}], stream=io.StringIO())


class BudgetTests(unittest.TestCase):
    def test_no_budget_means_full_output(self) -> None:
        payload = {"command": "files", "rows": [{"i": i, "pad": "x" * 100} for i in range(1000)]}
        _, printed = _emit(payload, command="files")
        self.assertEqual(len(printed["rows"]), 1000)
        self.assertFalse(printed["_envelope"]["truncated"])
        self.assertNotIn("full_output", printed["_envelope"])

    def test_budget_truncates_lists_and_keeps_key_set(self) -> None:
        payload = {
            "command": "files",
            "summary": {"count": 1000},
            "rows": [{"i": i, "pad": "x" * 100} for i in range(1000)],
            "small": [1, 2],
        }
        stream = io.StringIO()
        output.emit(
            payload,
            command="files",
            budget_bytes=output.DEFAULT_BUDGET_BYTES,
            full_output="C:/out/files-full.json",
            stream=stream,
        )
        text = stream.getvalue()
        printed = json.loads(text)
        self.assertLessEqual(len(text.encode("utf-8")), output.DEFAULT_BUDGET_BYTES + 1024)
        self.assertEqual(set(printed), set(payload) | {"_envelope"})
        self.assertLess(len(printed["rows"]), 1000)
        self.assertEqual(printed["rows"][0], payload["rows"][0])
        self.assertEqual(printed["summary"], {"count": 1000})
        self.assertTrue(printed["_envelope"]["truncated"])
        self.assertEqual(printed["_envelope"]["full_output"], "C:/out/files-full.json")
        self.assertEqual(len(payload["rows"]), 1000, "budget must not mutate the caller's payload")

    def test_apply_budget_within_limit_is_noop(self) -> None:
        payload = {"rows": [1, 2, 3]}
        result, truncated = output.apply_budget(payload, 1024)
        self.assertEqual(result, payload)
        self.assertFalse(truncated)


class FailTests(unittest.TestCase):
    def _fail(self, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            output.fail(stdout=out, stderr=err, **kwargs)
        return ctx.exception.code, out.getvalue(), err.getvalue()

    def test_fail_json_mode_prints_one_json_document_and_one_stderr_line(self) -> None:
        code, out, err = self._fail(
            code="RUN_NOT_FOUND",
            message="처리 기록을 찾지 못했습니다: run-404",
            hint="run-control list로 처리 ID를 확인하세요.",
            command="search",
            json_mode=True,
        )
        self.assertEqual(code, 2, "exit code stays 2 until T-249")
        document = json.loads(out)
        self.assertEqual(set(document), {"_envelope"})
        envelope = document["_envelope"]
        self.assertEqual(envelope["status"], "error")
        self.assertEqual(envelope["exit_code"], 2)
        self.assertEqual(envelope["command"], "search")
        self.assertEqual(envelope["errors"][0]["code"], "RUN_NOT_FOUND")
        self.assertEqual(envelope["errors"][0]["hint"], "run-control list로 처리 ID를 확인하세요.")
        lines = err.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("RUN_NOT_FOUND: 처리 기록을"))
        self.assertLessEqual(len(err.rstrip("\n").encode("utf-8")), 200)
        self.assertNotIn("usage:", err)

    def test_fail_text_mode_prints_korean_line_on_stderr_only(self) -> None:
        code, out, err = self._fail(
            code="RUN_NOT_FOUND", message="처리 기록을 찾지 못했습니다", command="search", json_mode=False
        )
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(err, "RUN_NOT_FOUND: 처리 기록을 찾지 못했습니다\n")

    def test_fail_stderr_line_is_capped_at_200_bytes(self) -> None:
        long_message = "증거 경로가 너무 깁니다 " * 40 + "\n둘째 줄"
        _, _, err = self._fail(code="PATH_TOO_LONG", message=long_message, command="evidence", json_mode=True)
        self.assertEqual(len(err.splitlines()), 1)
        self.assertLessEqual(len(err.rstrip("\n").encode("utf-8")), output.STDERR_LINE_MAX_BYTES)
        err.rstrip("\n").encode("utf-8").decode("utf-8")

    def test_fail_keeps_payload_keys_and_explicit_exit_code(self) -> None:
        code, out, _ = self._fail(
            code="RUN_NOT_FOUND",
            message="없음",
            command="search",
            json_mode=True,
            payload={"command": "search", "results": []},
            exit_code=output.EXIT_NOT_FOUND,
        )
        self.assertEqual(code, 4)
        document = json.loads(out)
        self.assertEqual(set(document), {"command", "results", "_envelope"})
        self.assertEqual(document["_envelope"]["exit_code"], 4)

    def test_exit_code_table(self) -> None:
        self.assertEqual(
            (output.EXIT_OK, output.EXIT_FAILURE, output.EXIT_USAGE, output.EXIT_PARTIAL, output.EXIT_NOT_FOUND),
            (0, 1, 2, 3, 4),
        )
        self.assertEqual(output.TRANSITIONAL_FAIL_EXIT_CODE, 2)


if __name__ == "__main__":
    unittest.main()
