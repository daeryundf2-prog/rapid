"""scripts/srum-reference-diff.py export mode on synthetic SRUM/Search tables (T-210)."""

from __future__ import annotations

import unittest

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

APPS = [r"\Device\HarddiskVolume3\Windows\System32\svchost.exe", r"\Device\HarddiskVolume3\Tools\example.exe"]
NETWORK = [(APPS[0], "2024-05-01T10:00:00+00:00"), (APPS[1], "2024-05-01T11:00:00+00:00"),
           (APPS[1], "2024-05-01T12:00:00+00:00")]
RESOURCE = [(APPS[0], "2024-05-01T10:00:00+00:00"), (APPS[1], "2024-05-01T10:00:00+00:00")]
SEARCH = [(r"C:\Users\tester\Documents\plan.txt", "2024-05-02T09:00:00+00:00")]
NETWORK_GUID = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
RESOURCE_GUID = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
SRUM_HEADER = ["Id", "Timestamp", "ExeInfo", "AppId"]


def ours_rows(*, drop_table=None, drop_row=None):
    rows = [{"artifact_type": "srum-database-file", "details": {"table_family": "srudb"}}]
    for table, items in ((NETWORK_GUID, NETWORK), (RESOURCE_GUID, RESOURCE), ("SystemIndex_PropertyStore", SEARCH)):
        if table == drop_table:
            continue
        for index, (app, stamp) in enumerate(items):
            if drop_row != (table, index):
                rows.append({"provider": "windows-execution", "artifact_type": "srum-row-candidate",
                             "path": "C:/synthetic/SRUDB.dat", "supported": True,
                             "details": {"table_name": table, "app_id": app, "timestamp": stamp}})
    return rows


def srum_rows(items, stamp_format=None):
    return [[index, stamp_format(stamp) if stamp_format else stamp, app, 100 + index]
            for index, (app, stamp) in enumerate(items)]


class SrumReferenceDiffTests(ReferenceDiffCase):
    script_name = "srum-reference-diff"

    def setUp(self) -> None:
        super().setUp()
        self.ref = self.tmp / "reference"
        self.ref.mkdir()
        write_csv(self.ref / "20240601_SrumECmd_NetworkUsages_Output.csv", SRUM_HEADER, srum_rows(NETWORK))
        write_csv(self.ref / "20240601_SrumECmd_AppResourceUseInfo_Output.csv", SRUM_HEADER, srum_rows(RESOURCE))
        write_csv(self.ref / "SystemIndex_PropertyStore.csv", ["WorkID", "System_ItemPathDisplay", "System_DateModified"],
                  [[index + 1, path, stamp] for index, (path, stamp) in enumerate(SEARCH)])

    def _diff(self, ours, *extra):
        code, report, stderr = self.run_diff(write_jsonl(self.tmp / "ours.jsonl", ours), self.ref, *extra)
        report["by_name"] = {table["name"]: table for table in report.get("tables", [])}
        return code, report, stderr

    def test_full_match(self) -> None:
        code, report, _ = self._diff(ours_rows())
        self.assertEqual(code, 0)
        self.assert_contract(report)
        self.assertEqual(report["missing_tables"], [])
        self.assertEqual(sorted(report["by_name"]), ["app_resource_usage", "network_usage", "systemindexpropertystore"])
        self.assertTrue(all(table["recall"] == 1.0 for table in report["tables"]))
        self.assertEqual((report["recall"], report["mismatched"], report["extra_tables"]), (1.0, [], []))

    def test_one_table_missing(self) -> None:
        code, report, _ = self._diff(ours_rows(drop_table=RESOURCE_GUID))
        self.assertEqual(code, 1)
        self.assertEqual(report["missing_tables"], ["app_resource_usage"])
        self.assertEqual(report["by_name"]["app_resource_usage"]["recall"], 0.0)
        self.assertEqual(report["by_name"]["network_usage"]["recall"], 1.0)

    def test_one_row_missing(self) -> None:
        code, report, _ = self._diff(ours_rows(drop_row=(NETWORK_GUID, 2)))
        self.assertEqual(code, 1)
        self.assertEqual(report["missing_tables"], [])
        network = report["by_name"]["network_usage"]
        self.assertAlmostEqual(network["recall"], 2 / 3, places=5)
        self.assertEqual(network["missing_rows"], 1)
        self.assertEqual(report["mismatched"], [
            {"key": "network_usage", "fields": {"row_count": {"ours": 2, "reference": 3}}}])
        self.assertEqual([item["table"] for item in report["missing"]], ["network_usage"])

    def test_reference_local_time_and_app_basename(self) -> None:
        def kst(stamp: str) -> str:
            return f"{stamp[:10]} {int(stamp[11:13]) + 9:02d}{stamp[13:19]}"

        write_csv(self.ref / "20240601_SrumECmd_NetworkUsages_Output.csv", SRUM_HEADER,
                  srum_rows([(app.rsplit("\\", 1)[-1], stamp) for app, stamp in NETWORK], kst))
        code, report, _ = self._diff(ours_rows(), "--reference-tz", "+09:00", "--app-match", "basename")
        self.assertEqual(code, 0)
        self.assertEqual(report["by_name"]["network_usage"]["recall"], 1.0)

    def test_missing_input_exits_2(self) -> None:
        code, report, stderr = self.run_diff(self.tmp / "none.jsonl", self.ref)
        self.assertEqual((code, report), (2, {}))
        self.assertIn("입력 파일이 없습니다", stderr)
        code, report, stderr = self.run_diff(write_jsonl(self.tmp / "ours.jsonl", []), self.tmp / "no-folder")
        self.assertEqual((code, report), (2, {}))
        self.assertIn("폴더가 없습니다", stderr)

    def test_canon_table(self) -> None:
        self.assertEqual(self.module.canon_table(NETWORK_GUID), "network_usage")
        self.assertEqual(self.module.canon_table("20240601_SrumECmd_NetworkUsages_Output.csv"), "network_usage")
        self.assertEqual(self.module.canon_table("srum-app-resource-usage"), "app_resource_usage")


if __name__ == "__main__":
    unittest.main()
