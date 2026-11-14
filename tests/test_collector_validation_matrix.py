"""scripts/collector-validation-matrix.py on synthetic inputs (T-213): pass / fail / not measured."""

from __future__ import annotations

import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from tests.reference_diff_helpers import REPO_ROOT, load_script, write_csv, write_jsonl

MATRIX_PATH = REPO_ROOT / "docs" / "validation" / "collector-validation-matrix.json"
EXAMPLE_INPUTS = REPO_ROOT / "docs" / "validation" / "collector-validation-inputs.example.json"

USB_HEADER = ["SerialNumber", "FriendlyName", "FirstInstalled", "LastConnected"]
DEVICES = [
    ("AA00000000000001&0", "Example Flash USB Device", "2024-01-02T03:04:05+00:00", "2024-03-01T10:00:00+00:00"),
    ("BB00000000000002&0", "Sample Disk USB Device", "2024-01-05T08:00:00+00:00", "2024-03-02T11:30:00+00:00"),
    ("CC00000000000003&0", "Test Stick USB Device", "2024-02-01T09:15:00+00:00", "2024-03-03T12:45:30+00:00"),
]
VISIT_HEADER = ["url", "title", "visit_time"]
VISITS = [
    ("https://example.com/a", "A", "2024-01-02T03:04:05Z"),
    ("https://example.com/b", "B", "2024-01-02T04:05:06Z"),
]


def usb_row(serial, name, first, last):
    return {
        "provider": "windows-registry",
        "artifact_type": "windows-usb-device",
        "path": "C:/synthetic/SYSTEM",
        "supported": True,
        "details": {"serial_number": serial, "friendly_name": name, "first_install_at": first, "last_arrival_at": last},
    }


def visit_row(url, title, when):
    return {"provider": "browser", "artifact_type": "browser-visit", "path": "C:/synthetic/History",
            "timestamp": when, "details": {"url": url, "title": title}}


class CollectorValidationMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.module = load_script("collector-validation-matrix")

    def run_matrix(self, *argv: str) -> tuple[int, dict[str, object], str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.module.main([*argv, "--json"])
        report = json.loads(stdout.getvalue()) if stdout.getvalue().strip().startswith("{") else {}
        return code, report, stdout.getvalue(), stderr.getvalue()

    def write_inputs(self, rows: dict[str, object], corpus: str = "C2") -> Path:
        path = self.tmp / "inputs.json"
        path.write_text(json.dumps({"corpora": {corpus: {"base_dir": ".", "rows": rows}}}), encoding="utf-8")
        return path

    def usb_inputs(self, devices_ours, devices_reference) -> dict[str, object]:
        write_jsonl(self.tmp / "usb.jsonl", [usb_row(*d) for d in devices_ours])
        write_csv(self.tmp / "usb.csv", USB_HEADER, devices_reference)
        return {"ours": "usb.jsonl", "reference": "usb.csv"}

    def row(self, report: dict[str, object], row_id: str) -> dict[str, object]:
        return next(row for row in report["rows"] if row["id"] == row_id)  # type: ignore[union-attr]

    # -- the committed table -------------------------------------------------------------

    def test_matrix_has_twenty_rows_with_runnable_templates(self) -> None:
        matrix = self.module.load_matrix(MATRIX_PATH)
        self.assertEqual(len(matrix["rows"]), 20)
        example = json.loads(EXAMPLE_INPUTS.read_text(encoding="utf-8"))["corpora"]["C2"]["rows"]
        for row in matrix["rows"]:
            self.assertIn(row["id"], example, row["id"])
            for run in row["runs"]:
                placeholders = set(re.findall(r"\{([A-Za-z0-9_]+)\}", " ".join(run["args"])))
                self.assertLessEqual(placeholders, set(run["files"]), row["id"])
                if "not_measured" not in example[row["id"]]:
                    self.assertLessEqual(set(run["files"]), set(example[row["id"]]), row["id"])

    def test_without_inputs_every_row_is_not_measured_with_reason(self) -> None:
        code, report, _, _ = self.run_matrix()
        self.assertEqual(code, 0)
        self.assertEqual(report["corpora"], ["C2", "C3", "C5"])
        self.assertEqual(report["summary"], {"rows": 20, "pass": 0, "fail": 0, "not_measured": 20})
        self.assertEqual(report["release_evidence_status"], "engineering_check_only")
        for row in report["rows"]:
            for cell in row["cells"].values():
                self.assertEqual((cell["status"], cell["reason"]), ("not_measured", "입력 설정(--inputs) 없음"))

    # -- pass / fail / not measured ------------------------------------------------------

    def test_pass(self) -> None:
        inputs = self.write_inputs({"usb": self.usb_inputs(DEVICES, DEVICES)})
        code, report, _, _ = self.run_matrix("--inputs", str(inputs), "--corpus", "C2", "--rows", "usb")
        self.assertEqual(code, 0)
        row = self.row(report, "usb")
        self.assertEqual((row["status"], row["label"]), ("pass", "통과"))
        check = row["cells"]["C2"]["runs"][0]["checks"][0]
        self.assertEqual((check["metric"], check["value"], check["ok"]), ("recall", 1.0, True))
        self.assertEqual(row["cells"]["C2"]["runs"][0]["exit_code"], 0)

    def test_fail_reports_the_number_and_exits_1(self) -> None:
        inputs = self.write_inputs({"usb": self.usb_inputs(DEVICES[:2], DEVICES)})
        out = self.tmp / "out"
        code, report, _, _ = self.run_matrix("--inputs", str(inputs), "--corpus", "C2", "--rows", "usb", "--output-dir", str(out))
        self.assertEqual(code, 1)
        row = self.row(report, "usb")
        self.assertEqual(row["status"], "fail")
        check = row["cells"]["C2"]["runs"][0]["checks"][0]
        self.assertAlmostEqual(check["value"], 2 / 3, places=5)
        self.assertFalse(check["ok"])
        markdown = (out / "collector-validation-matrix.md").read_text(encoding="utf-8")
        self.assertIn("미달 recall 0.6667 (기준 >= 1.00)", markdown)
        self.assertTrue((out / "collector-validation-matrix.json").is_file())
        cell_report = Path(row["cells"]["C2"]["runs"][0]["report"])
        self.assertEqual(cell_report, out / "cells" / "C2" / "usb.json")
        self.assertEqual(json.loads(cell_report.read_text(encoding="utf-8"))["matched"], 2)

    def test_not_measured_reasons(self) -> None:
        write_csv(self.tmp / "empty.csv", USB_HEADER, [])
        (self.tmp / "blank.csv").write_text("", encoding="utf-8")
        write_jsonl(self.tmp / "usb.jsonl", [usb_row(*d) for d in DEVICES])
        inputs = self.write_inputs({
            "shellbags": {"ours": "usb.jsonl", "reference": "no-such.csv"},
            "shimcache": {"not_measured": "기준 도구 내보내기 전"},
            "userassist": {"ours": "usb.jsonl"},
            "recyclebin": {"ours": "usb.jsonl", "reference": "blank.csv"},
            "usb": {"ours": "usb.jsonl", "reference": "empty.csv", "extra_args": ["--time-tolerance", "1"]},
        })
        code, report, _, _ = self.run_matrix(
            "--inputs", str(inputs), "--corpus", "C2,C9",
            "--rows", "usb,shimcache,userassist,recyclebin,shellbags,mft",
        )
        self.assertEqual(code, 0)
        reasons = {row["id"]: row["cells"]["C2"]["reason"] for row in report["rows"]}
        self.assertTrue(reasons["shellbags"].startswith("기준 출력 파일 없음: reference = "))
        self.assertEqual(reasons["shimcache"], "기준 도구 내보내기 전")
        self.assertEqual(reasons["userassist"], "기준 출력 미지정: 입력 설정에 'reference' 없음")
        self.assertIn("대조 스크립트 입력 오류(종료 2)", reasons["recyclebin"])
        self.assertIn("기준 파일이 비어 있습니다", reasons["recyclebin"])
        self.assertEqual(reasons["usb"], "지표 값 없음(기준 행 0건?): recall")
        self.assertEqual(reasons["mft"], "기준 출력 미지정: 입력 설정에 이 행 없음")
        for row in report["rows"]:
            self.assertEqual(row["status"], "not_measured")
            self.assertEqual(row["cells"]["C9"]["reason"], "입력 설정에 코퍼스 C9 없음")
            self.assertEqual(row["reason"], "미측정 코퍼스: C2, C9")

    def test_two_run_row_partly_measured_is_not_measured_and_fail_wins(self) -> None:
        write_jsonl(self.tmp / "visits.jsonl", [visit_row(*v) for v in VISITS])
        write_csv(self.tmp / "visits.csv", VISIT_HEADER, VISITS)
        inputs = self.write_inputs({"browser": {"visit_ours": "visits.jsonl", "visit_reference": "visits.csv"}})
        code, report, _, _ = self.run_matrix("--inputs", str(inputs), "--corpus", "C2", "--rows", "browser")
        self.assertEqual(code, 0)
        cell = self.row(report, "browser")["cells"]["C2"]
        self.assertEqual([run["status"] for run in cell["runs"]], ["pass", "not_measured"])
        self.assertEqual(cell["status"], "not_measured")
        self.assertTrue(cell["reason"].startswith("download: 기준 출력 미지정"))

        write_csv(self.tmp / "visits.csv", VISIT_HEADER, [*VISITS, ("https://example.com/c", "C", "2024-01-03T00:00:00Z")])
        code, report, _, _ = self.run_matrix("--inputs", str(inputs), "--corpus", "C2", "--rows", "browser")
        self.assertEqual(code, 1)
        self.assertEqual(self.row(report, "browser")["status"], "fail")

    # -- helpers and config errors -------------------------------------------------------

    def test_metric_path_walks_lists_and_aggregates(self) -> None:
        report = {"results": [{"key_coverage_vs_reference": 0.995}, {"key_coverage_vs_reference": 0.98}, {}]}
        check = {"metric": "results[].key_coverage_vs_reference", "aggregate": "min", "op": ">=", "value": 0.99}
        self.assertEqual(self.module.evaluate_check(report, check)["value"], 0.98)
        self.assertFalse(self.module.evaluate_check(report, check)["ok"])
        boolean = self.module.evaluate_check({"match": True}, {"metric": "match", "op": "==", "value": True})
        self.assertEqual((boolean["value"], boolean["ok"]), (True, True))
        self.assertIsNone(self.module.evaluate_check({"recall": None}, {"metric": "recall", "op": ">=", "value": 1})["ok"])

    def test_config_errors_exit_2(self) -> None:
        code, _, _, stderr = self.run_matrix("--rows", "no-such-row")
        self.assertEqual(code, 2)
        self.assertIn("검증표에 없는 행", stderr)
        bad = self.tmp / "bad-matrix.json"
        bad.write_text(json.dumps({"schema_version": "collector-validation-matrix-v1", "rows": [
            {"id": "x", "runs": [{"script": "no-such-script", "args": [], "checks": []}]}]}), encoding="utf-8")
        code, _, _, stderr = self.run_matrix("--matrix", str(bad))
        self.assertEqual(code, 2)
        self.assertIn("대조 스크립트를 찾지 못했습니다", stderr)
        code, _, _, stderr = self.run_matrix("--inputs", str(self.tmp / "missing.json"))
        self.assertEqual(code, 2)
        self.assertIn("입력 설정 파일이 없습니다", stderr)


if __name__ == "__main__":
    unittest.main()
