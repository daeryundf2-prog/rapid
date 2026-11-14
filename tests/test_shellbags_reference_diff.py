"""scripts/shellbags-reference-diff.py on synthetic ShellBags rows (T-209)."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "shellbags-reference-diff.py"


def _load():
    spec = importlib.util.spec_from_file_location("rt_shellbags_reference_diff_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shellbags = _load()

HIVE = "D:/extract/C/Users/tester/AppData/Local/Microsoft/Windows/UsrClass.dat"
REF_HIVE = r"C:\Users\tester\AppData\Local\Microsoft\Windows\UsrClass.dat"
FOLDERS = [
    (r"My Computer\C:\Projects", "2024-04-01T01:00:00+00:00", "2024-03-30T05:00:00+00:00"),
    (r"My Computer\C:\Projects\Alpha", "2024-04-02T02:00:00+00:00", "2024-03-31T06:00:00+00:00"),
    (r"My Computer\D:\Exports", "2024-04-03T03:00:00+00:00", "2024-04-01T07:00:00+00:00"),
]


def _ours(path, last, created, *, root=False):
    return {
        "provider": "windows-shellbags",
        "artifact_type": "shellbag-entry",
        "path": HIVE,
        "supported": True,
        "details": {
            "shell_path": path,
            "bagmru_root": root,
            "user_sid": "S-1-5-21-1-2-3-1001",
            "source_path": HIVE,
            "key_last_written_at": last,
            "item_created_at": created,
            "item_modified_at": "",
            "item_accessed_at": "",
        },
    }


def _ref(path, last, created):
    return {"AbsolutePath": path, "LastWriteTime": last, "CreatedOn": created, "SourceFile": REF_HIVE}


class ShellbagsReferenceDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, ours, reference, *extra):
        ours_path = self.root / "ours.jsonl"
        ours_path.write_text("".join(json.dumps(row) + "\n" for row in ours), encoding="utf-8")
        ref_path = self.root / "reference.csv"
        with ref_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(reference[0]))
            writer.writeheader()
            writer.writerows(reference)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = shellbags.main(["--ours", str(ours_path), "--reference", str(ref_path), "--json", *extra])
        self.assertEqual(code, 0)
        return json.loads(stdout.getvalue())

    def test_full_match(self) -> None:
        ours = [_ours("", "2024-04-01T00:00:00+00:00", "", root=True)] + [_ours(*f) for f in FOLDERS]
        report = self._run(ours, [_ref(*f) for f in FOLDERS])
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["matched"], 3)
        self.assertEqual(report["missing"], [])
        self.assertEqual(report["mismatched"], [])
        for key in ("recall", "matched", "missing", "mismatched", "reference_tool"):
            self.assertIn(key, report)
        self.assertEqual(report["fields_compared"], ["last_written", "item_created"])
        self.assertEqual(report["fields_not_compared"], ["item_modified", "item_accessed"])

    def test_one_folder_missing(self) -> None:
        report = self._run([_ours(*f) for f in FOLDERS[:2]], [_ref(*f) for f in FOLDERS])
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(report["missing"], [r"tester|my computer\d:\exports"])

    def test_one_time_mismatch(self) -> None:
        reference = [_ref(*f) for f in FOLDERS]
        reference[0]["LastWriteTime"] = "2024-04-01 01:00:07"
        report = self._run([_ours(*f) for f in FOLDERS], reference)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(report["mismatched"][0]["key"], r"tester|my computer\c:\projects")
        self.assertEqual(
            report["mismatched"][0]["fields"],
            {"last_written": {"ours": "2024-04-01T01:00:00Z", "reference": "2024-04-01T01:00:07Z"}},
        )

    def test_timezone_case_and_desktop_prefix_normalised(self) -> None:
        reference = [
            {"AbsolutePath": "Desktop\\" + path.upper() + "\\", "LastWriteTime": "2024-04-01 10:00:00",
             "CreatedOn": "2024-03-30 14:00:00", "SourceFile": REF_HIVE}
            for path, _last, _created in FOLDERS[:1]
        ]
        report = self._run([_ours(*f) for f in FOLDERS[:1]], reference, "--reference-tz", "+09:00")
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"], [])

    def test_ignore_account(self) -> None:
        reference = [{**_ref(*f), "SourceFile": r"E:\export\UsrClass.dat"} for f in FOLDERS]
        keyed = self._run([_ours(*f) for f in FOLDERS], reference)
        self.assertEqual(keyed["recall"], 0.0)
        report = self._run([_ours(*f) for f in FOLDERS], reference, "--ignore-account")
        self.assertEqual(report["recall"], 1.0)

    def test_missing_input_exits_2(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            code = shellbags.main(["--ours", str(self.root / "a.jsonl"), "--reference", str(self.root / "b.csv")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
