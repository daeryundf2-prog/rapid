"""R8 T-359: ``rapidtriage audit-verify <file> --json`` over T-029's export audit chain."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.audit import (
    VERIFICATION_METHOD_FIELD,
    VERIFICATION_METHOD_LINES,
    audit_path_for,
    export_audit_log_path,
    write_audit_record,
)


def _run(*argv: str) -> tuple[int, dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["audit-verify", *argv])
    return code, json.loads(out.getvalue())


def _export_four(folder: Path) -> Path:
    for index in range(4):
        output = folder / f"report-{index}.md"
        output.write_text(f"report {index}\n", encoding="utf-8")
        write_audit_record(audit_path_for(output), command="report", output_files=[("report", output)])
    return export_audit_log_path(audit_path_for(folder / "report-0.md"))


class AuditVerifyCliTests(unittest.TestCase):
    def test_intact_chain_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            code, payload = _run(str(log_path), "--json")
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["first_broken_line"])
        self.assertEqual((payload["records"], payload["chained"], payload["pre_chain_lines"]), (4, 4, 0))
        self.assertEqual(payload["command"], "audit-verify")

    def test_one_byte_changed_in_line_2_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            data = bytearray(log_path.read_bytes())
            start = data.index(b"\n") + 1  # first byte of line 2
            offset = data.index(b'"command":"report"', start) + len(b'"command":"r')
            data[offset] = ord("E")  # "report" -> "rEport": one byte, still valid JSON
            log_path.write_bytes(bytes(data))
            code, payload = _run(str(log_path), "--json")
        self.assertEqual(code, 3)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["first_broken_line"], 2)

    def test_pre_chain_file_exits_0_and_counts_lines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "rapidtriage-export-audit.jsonl"
            old = {"command": "report", "generated_at": "2026-04-23T10:00:00", "provenance": {}, "integrity": {}}
            log_path.write_text("".join(json.dumps(old) + "\n" for _ in range(4)), encoding="utf-8", newline="\n")
            code, payload = _run(str(log_path), "--json")
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["pre_chain_lines"], 4)

    def test_sidecar_and_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _export_four(Path(tmp))
            code, payload = _run(str(audit_path_for(Path(tmp) / "report-3.md")), "--json")
            self.assertEqual(code, 0)
            self.assertEqual(payload["layout"], "sidecar")
            code, payload = _run(str(Path(tmp) / "absent.jsonl"), "--json")
        self.assertEqual(code, 4)
        self.assertFalse(payload["ok"])

    def test_text_output_names_broken_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            lines = log_path.read_text(encoding="utf-8").splitlines()
            lines[1] = lines[1][:-1]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["audit-verify", str(log_path)])
        self.assertEqual(code, 3)
        self.assertIn("첫 번째 깨진 줄 2", out.getvalue())

    def test_export_record_carries_verification_method_header(self) -> None:
        self.assertLessEqual(len(VERIFICATION_METHOD_LINES), 5)
        joined = "\n".join(VERIFICATION_METHOD_LINES)
        for needle in ("record_sha256", "previous_record_sha256", "rapidtriage audit-verify", "순서"):
            self.assertIn(needle, joined)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            first = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
            sidecar = json.loads(audit_path_for(Path(tmp) / "report-3.md").read_text(encoding="utf-8"))
        self.assertEqual(first[VERIFICATION_METHOD_FIELD], list(VERIFICATION_METHOD_LINES))
        self.assertEqual(sidecar[VERIFICATION_METHOD_FIELD], list(VERIFICATION_METHOD_LINES))


if __name__ == "__main__":
    unittest.main()
