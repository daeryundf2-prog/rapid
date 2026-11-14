"""scripts/srum-reference-diff.py export mode on synthetic SRUM/Search tables (T-210)."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "srum-reference-diff.py"


def _load():
    spec = importlib.util.spec_from_file_location("rt_srum_reference_diff_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


srum = _load()

APPS = [r"\Device\HarddiskVolume3\Windows\System32\svchost.exe", r"\Device\HarddiskVolume3\Tools\example.exe"]
NETWORK = [(APPS[0], "2024-05-01T10:00:00+00:00"), (APPS[1], "2024-05-01T11:00:00+00:00"),
           (APPS[1], "2024-05-01T12:00:00+00:00")]
RESOURCE = [(APPS[0], "2024-05-01T10:00:00+00:00"), (APPS[1], "2024-05-01T10:00:00+00:00")]
SEARCH = [(r"C:\Users\tester\Documents\plan.txt", "2024-05-02T09:00:00+00:00")]


def _ours(table, app, stamp, artifact_type="srum-row-candidate"):
    return {"provider": "windows-execution", "artifact_type": artifact_type, "path": "C:/synthetic/SRUDB.dat",
            "supported": True, "details": {"table_name": table, "app_id": app, "timestamp": stamp}}


def _ours_all(*, drop_table=None, drop_row=None):
    rows = [{"artifact_type": "srum-database-file", "details": {"table_family": "srudb"}}]
    for table, items in (("{973F5D5C-1D90-4944-BE8E-24B94231A174}", NETWORK),
                         ("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", RESOURCE),
                         ("SystemIndex_PropertyStore", SEARCH)):
        if table == drop_table:
            continue
        for index, (app, stamp) in enumerate(items):
            if drop_row == (table, index):
                continue
            rows.append(_ours(table, app, stamp))
    return rows


class SrumReferenceDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ref = self.root / "reference"
        self.ref.mkdir()
        self._table("20240601_SrumECmd_NetworkUsages_Output.csv", NETWORK)
        self._table("20240601_SrumECmd_AppResourceUseInfo_Output.csv", RESOURCE)
        with (self.ref / "SystemIndex_PropertyStore.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["WorkID", "System_ItemPathDisplay", "System_DateModified"])
            for index, (path, stamp) in enumerate(SEARCH):
                writer.writerow([index + 1, path, stamp])

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _table(self, name, items, *, stamp_format=None):
        with (self.ref / name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Id", "Timestamp", "ExeInfo", "AppId"])
            for index, (app, stamp) in enumerate(items):
                writer.writerow([index, stamp_format(stamp) if stamp_format else stamp, app, 100 + index])

    def _run(self, ours, *extra):
        ours_path = self.root / "ours.jsonl"
        ours_path.write_text("".join(json.dumps(row) + "\n" for row in ours), encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = srum.main(["--ours", str(ours_path), "--reference", str(self.ref), "--json", *extra])
        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        report["by_name"] = {table["name"]: table for table in report["tables"]}
        return report

    def test_full_match(self) -> None:
        report = self._run(_ours_all())
        self.assertEqual(report["missing_tables"], [])
        self.assertEqual(sorted(report["by_name"]), ["app_resource_usage", "network_usage", "systemindexpropertystore"])
        self.assertTrue(all(table["recall"] == 1.0 for table in report["tables"]))
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"], [])
        self.assertEqual(report["extra_tables"], [])
        self.assertIn("reference_tool", report)

    def test_one_table_missing(self) -> None:
        report = self._run(_ours_all(drop_table="{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"))
        self.assertEqual(report["missing_tables"], ["app_resource_usage"])
        self.assertEqual(report["by_name"]["app_resource_usage"]["recall"], 0.0)
        self.assertEqual(report["by_name"]["network_usage"]["recall"], 1.0)

    def test_one_row_missing(self) -> None:
        report = self._run(_ours_all(drop_row=("{973F5D5C-1D90-4944-BE8E-24B94231A174}", 2)))
        self.assertEqual(report["missing_tables"], [])
        network = report["by_name"]["network_usage"]
        self.assertAlmostEqual(network["recall"], 2 / 3, places=5)
        self.assertEqual(network["missing_rows"], 1)
        self.assertEqual(report["mismatched"], [{"table": "network_usage", "reference_rows": 3, "ours_rows": 2}])
        self.assertEqual(len(report["missing"]), 1)

    def test_reference_local_time_and_app_basename(self) -> None:
        def kst(stamp: str) -> str:
            hour = int(stamp[11:13]) + 9
            return f"{stamp[:10]} {hour:02d}{stamp[13:19]}"

        self._table("20240601_SrumECmd_NetworkUsages_Output.csv",
                    [(app.rsplit("\\", 1)[-1], stamp) for app, stamp in NETWORK], stamp_format=kst)
        report = self._run(_ours_all(), "--reference-tz", "+09:00", "--app-match", "basename")
        self.assertEqual(report["by_name"]["network_usage"]["recall"], 1.0)

    def test_missing_input_exits_2(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            code = srum.main(["--ours", str(self.root / "none.jsonl"), "--reference", str(self.ref)])
        self.assertEqual(code, 2)
        ours_path = self.root / "ours.jsonl"
        ours_path.write_text("", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()):
            code = srum.main(["--ours", str(ours_path), "--reference", str(self.root / "no-folder")])
        self.assertEqual(code, 2)

    def test_canon_table(self) -> None:
        self.assertEqual(srum.canon_table("{973F5D5C-1D90-4944-BE8E-24B94231A174}"), "network_usage")
        self.assertEqual(srum.canon_table("20240601_SrumECmd_NetworkUsages_Output.csv"), "network_usage")
        self.assertEqual(srum.canon_table("srum-app-resource-usage"), "app_resource_usage")


if __name__ == "__main__":
    unittest.main()
