"""D12 review items 6, 7 and 14 for SRUM exports and the native ESE reader.

- A generic CSV under a path that merely contains "srum" is not a SRUM export.
- Counter presence is separate from a reported 0; integer counters are parsed
  and summed exactly (no binary-float rounding above 2**53).
- A SRUDB.dat whose table root page lies past the end of the file reports a
  partial decode with the loss location instead of a complete one.
"""

from __future__ import annotations

import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from rapidtriage.artifacts.windows.ese_native import EseDatabase
from rapidtriage.artifacts.windows.execution import (
    collect_srum_dat_inventory,
    collect_srum_imports,
    number_value,
    numeric_total,
)
from tests.windows_artifact_fixtures import _minimal_ese_database_with_catalog

ESE_PAGE = 4096


def import_rows(root: Path) -> dict[str, dict[str, object]]:
    return {
        str(record.details["app_id"]): {"artifact_type": record.artifact_type, **record.details}
        for record in collect_srum_imports(root)
    }


class SrumExportCountersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_export(self, text: str) -> None:
        folder = self.root / "exports"
        folder.mkdir()
        (folder / "srum-network.csv").write_text(text, encoding="ascii")

    def test_zero_network_counters_stay_network_rows(self) -> None:
        self.write_export("AppId,BytesSent,BytesReceived\nA,0,0\nC,2,3\n")
        rows = import_rows(self.root)
        zero = rows["A"]
        self.assertEqual(zero["artifact_type"], "srum-network-usage")
        self.assertEqual(zero["srum_table_family"], "network-usage")
        self.assertEqual((zero["bytes_sent"], zero["bytes_received"], zero["bytes_total"]), (0, 0, 0))
        self.assertEqual(zero["srum_counter_presence"]["bytes_sent"], "present")
        self.assertTrue(zero["validation_checks"]["has_network_counters"])
        self.assertEqual(zero["srum_usage_evidence"]["counter_fields_present"], ["bytes_received", "bytes_sent"])
        # A reported 0 is cited; it is not dropped as "not reported".
        cited = zero["srum_report_citation_manifest"]["row_identity"]["counter_values"]
        self.assertEqual(cited, {"bytes_sent": 0, "bytes_received": 0, "bytes_total": 0})
        self.assertEqual(rows["C"]["bytes_total"], 5)

    def test_integer_counters_sum_exactly_past_float_precision(self) -> None:
        self.write_export("AppId,BytesSent,BytesReceived\nB,9007199254740993,1\n")
        row = import_rows(self.root)["B"]
        self.assertEqual(row["artifact_type"], "srum-network-usage")
        self.assertIs(type(row["bytes_sent"]), int)
        self.assertEqual(row["bytes_sent"], 9_007_199_254_740_993)
        self.assertEqual(row["bytes_total"], 9_007_199_254_740_994)
        cited = row["srum_report_citation_manifest"]["row_identity"]["counter_values"]
        self.assertEqual(cited["bytes_total"], 9_007_199_254_740_994)

    def test_absent_zero_large_and_invalid_counters_have_distinct_meanings(self) -> None:
        self.write_export(
            "AppId,BytesSent,BytesReceived,CpuTime\n"
            "absent,,,7\n"
            "zero,0,,\n"
            "invalid,abc,4,\n"
        )
        rows = import_rows(self.root)
        absent = rows["absent"]
        self.assertEqual(absent["artifact_type"], "srum-app-resource-usage")
        self.assertEqual(absent["srum_counter_presence"]["bytes_sent"], "absent")
        self.assertEqual((absent["bytes_sent"], absent["bytes_total"]), ("", ""))
        self.assertEqual(absent["cpu_time"], 7)
        zero = rows["zero"]
        self.assertEqual(zero["artifact_type"], "srum-network-usage")
        self.assertEqual((zero["bytes_sent"], zero["bytes_received"], zero["bytes_total"]), (0, "", 0))
        invalid = rows["invalid"]
        self.assertEqual(invalid["srum_counter_presence"]["bytes_sent"], "invalid")
        self.assertEqual(invalid["bytes_total"], "")
        self.assertFalse(invalid["validation_checks"]["counter_fields_normalized"])
        self.assertEqual(invalid["srum_usage_evidence"]["counter_fields_invalid"], ["bytes_sent"])

    def test_generic_csv_under_a_srum_named_folder_is_not_srum(self) -> None:
        for name in ("plain", "srum-review"):
            folder = self.root / name
            folder.mkdir()
            (folder / "stock.csv").write_text("Item,Quantity\npencil,3\n", encoding="ascii")
            with self.subTest(folder=name):
                self.assertEqual(list(collect_srum_imports(folder)), [])

    def test_number_helpers(self) -> None:
        self.assertEqual(number_value(""), "")
        self.assertEqual(number_value(None), "")
        self.assertEqual(number_value("0"), 0)
        self.assertEqual(number_value(" 18446744073709551615 "), 18446744073709551615)
        self.assertEqual(number_value("1.5"), 1.5)
        self.assertEqual(number_value("nan"), "nan")
        self.assertEqual(number_value(True), "True")
        self.assertEqual(numeric_total("", ""), "")
        self.assertEqual(numeric_total(0, ""), 0)
        self.assertEqual(numeric_total(2**63, 2**63), 2**64)
        self.assertEqual(numeric_total(1, "x"), "")
        self.assertEqual(numeric_total(0.1, 0.2), 0.30000000000000004)


class SrumEsePageCompletenessTests(unittest.TestCase):
    def collect(self, blob: bytes) -> list:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "SRUDB.dat").write_bytes(blob)
            return list(collect_srum_dat_inventory(folder))

    @staticmethod
    def inventory(records: list) -> dict[str, object]:
        return next(record.details for record in records if record.artifact_type == "srum-database-file")

    def test_intact_control_is_a_complete_decode(self) -> None:
        records = self.collect(_minimal_ese_database_with_catalog())
        info = self.inventory(records)
        catalog = info["native_ese_catalog"]
        self.assertEqual(catalog["decode_status"], "decoded")
        self.assertEqual(catalog["loss_locations"], [])
        self.assertEqual(catalog["errors"], [])
        self.assertEqual(catalog["tables"][0]["walk_status"], "complete")
        self.assertEqual(info["native_srudb_validation"]["validation_status"], "ese-catalog-and-rows-decoded")
        self.assertEqual(info["coverage_status"], "ese-catalog-and-rows-decoded")
        rows = [record.details for record in records if record.artifact_type == "srum-schema-row"]
        self.assertEqual([row["row_fields"] for row in rows], [{"Counter": 42, "Label": "hello"}])
        self.assertEqual(rows[0]["table_walk_status"], "complete")

    def test_missing_table_root_page_is_a_partial_decode_with_loss_location(self) -> None:
        original = _minimal_ese_database_with_catalog()
        short = original[:-ESE_PAGE]
        info = self.inventory(self.collect(short))
        catalog = info["native_ese_catalog"]
        table = catalog["tables"][0]
        self.assertEqual(catalog["decode_status"], "partial")
        self.assertEqual(table["walk_status"], "root-page-unreadable")
        self.assertEqual(table["row_count"], 0)
        loss = catalog["loss_locations"]
        self.assertEqual(len(loss), 1)
        self.assertEqual(loss[0]["table"], table["name"])
        self.assertEqual(loss[0]["page_number"], table["root_page"])
        self.assertEqual(loss[0]["reason"], "beyond-file-end")
        self.assertEqual(loss[0]["declared_file_offset"], len(short))
        self.assertEqual(loss[0]["file_size"], len(short))
        self.assertTrue(catalog["errors"])
        validation = info["native_srudb_validation"]
        self.assertEqual(validation["validation_status"], "ese-partial-decode-pages-unreadable")
        self.assertFalse(validation["ese_decode_complete"])
        self.assertEqual(validation["ese_unreadable_page_count"], 1)
        self.assertNotEqual(info["coverage_status"], "ese-catalog-and-rows-decoded")

    def test_reader_records_each_unreadable_page_reference(self) -> None:
        db = EseDatabase(_minimal_ese_database_with_catalog()[:-ESE_PAGE])
        self.assertEqual(db.page_failures, [])
        start = len(db.page_failures)
        self.assertEqual(list(db.iter_table_rows(db.tables[0])), [])
        self.assertEqual([loss["page_number"] for loss in db.page_failure_locations(start)], [db.tables[0].root_page])

    def test_independent_reader_agrees_on_control_and_loss(self) -> None:
        try:
            from dissect.esedb import EseDB
        except ImportError as exc:
            raise unittest.SkipTest("dissect.esedb comparison reader unavailable") from exc
        original = _minimal_ese_database_with_catalog()
        reference = [record.as_dict() for table in EseDB(BytesIO(original)).tables() for record in table.records()]
        self.assertEqual(reference, [{"Counter": 42, "Label": "hello"}])
        with self.assertRaises(IndexError):
            [record for table in EseDB(BytesIO(original[:-ESE_PAGE])).tables() for record in table.records()]


if __name__ == "__main__":
    unittest.main()
