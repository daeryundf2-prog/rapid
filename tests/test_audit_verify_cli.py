"""R8 T-359: ``rapidtriage audit-verify <file> --json`` over T-029's export audit chain."""

from __future__ import annotations

import contextlib
import hashlib
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

    def test_one_line_history_edit_exits_3(self) -> None:
        # Review P0-1: one export = one-line .jsonl, which used to be read as a sidecar and skipped.
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.md"
            output.write_text("report\n", encoding="utf-8")
            write_audit_record(audit_path_for(output), command="export", output_files=[("report", output)])
            log_path = export_audit_log_path(audit_path_for(output))
            self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 1)
            code, payload = _run(str(log_path), "--json")
            self.assertEqual((code, payload["layout"], payload["records"]), (0, "lines", 1))
            log_path.write_text(log_path.read_text(encoding="utf-8").replace('"command":"export"', '"command":"EDITED"'),
                                encoding="utf-8", newline="\n")
            code, payload = _run(str(log_path), "--json")
        self.assertEqual(code, 3)
        self.assertEqual(payload["first_broken_line"], 1)

    def test_sidecar_edit_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _export_four(Path(tmp))
            sidecar = audit_path_for(Path(tmp) / "report-3.md")
            sidecar.write_text(sidecar.read_text(encoding="utf-8").replace('"command": "report"', '"command": "EDITED"'),
                               encoding="utf-8", newline="\n")
            code, payload = _run(str(sidecar), "--json")
        self.assertEqual((code, payload["layout"]), (3, "sidecar"))

    def test_sidecar_recomputed_but_not_in_history_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _export_four(Path(tmp))
            sidecar = audit_path_for(Path(tmp) / "report-3.md")
            record = json.loads(sidecar.read_text(encoding="utf-8"))
            record["command"] = "forged"
            record.pop("record_sha256")
            canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            record["record_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            sidecar.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
            code, payload = _run(str(sidecar), "--json")
        self.assertEqual(code, 3)
        self.assertFalse(payload["history_contains_sidecar"])

    def test_last_line_edited_with_hash_key_removed_exits_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            lines = log_path.read_text(encoding="utf-8").splitlines()
            last = json.loads(lines[-1])
            last["command"] = "EDITED"
            last.pop("record_sha256")
            lines[-1] = json.dumps(last, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            code, payload = _run(str(log_path), "--json")
        self.assertEqual(code, 3)
        self.assertEqual(payload["first_broken_line"], 4)

    def test_tail_deletion_is_disclosed_and_caught_by_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            lines = log_path.read_text(encoding="utf-8").splitlines()
            kept_last = json.loads(lines[-1])["record_sha256"]
            code, payload = _run(str(log_path), "--json", "--expect-last", kept_last)
            self.assertEqual((code, payload["anchor"]["matched"], payload["not_proven"]), (0, True, []))
            log_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8", newline="\n")
            # Unanchored: the chain of the first two lines is intact, but the output says what it cannot prove.
            code, payload = _run(str(log_path), "--json")
            self.assertEqual(code, 0)
            self.assertTrue(any("끝 줄 삭제" in item for item in payload["not_proven"]))
            code, payload = _run(str(log_path), "--json", "--expect-last", kept_last)
            self.assertEqual(code, 3)
            self.assertFalse(payload["anchor"]["matched"])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["audit-verify", str(log_path)])
        self.assertIn("알 수 없는 것: 끝 줄 삭제", out.getvalue())

    def test_empty_file_and_non_audit_json_exit_3(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "rapidtriage-export-audit.jsonl"
            empty.write_text("", encoding="utf-8")
            code, payload = _run(str(empty), "--json")
            self.assertEqual((code, payload["records"], payload["ok"]), (3, 0, False))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["audit-verify", str(empty)]), 3)
            self.assertIn("감사 기록이 0줄", out.getvalue())
            summary = Path(tmp) / "summary.json"
            summary.write_text(json.dumps({"run_id": "x", "outputs": {}}, indent=2), encoding="utf-8")
            code, payload = _run(str(summary), "--json")
        self.assertEqual(code, 3)

    def test_unreadable_path_exits_4(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, payload = _run(tmp, "--json")
        self.assertEqual((code, payload["ok"]), (4, False))

    def test_method_names_exact_json_encoding(self) -> None:
        joined = "\n".join(VERIFICATION_METHOD_LINES)
        for needle in ("ensure_ascii=False", "sort_keys=True", "separators=(',', ':')", "이스케이프 안 함"):
            self.assertIn(needle, joined)
        # A third party following the text reproduces the hash of a record holding Korean text.
        with tempfile.TemporaryDirectory() as tmp:
            log_path = _export_four(Path(tmp))
            record = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])
        own = record.pop("record_sha256")
        canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(hashlib.sha256(canonical.encode("utf-8")).hexdigest(), own)

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
