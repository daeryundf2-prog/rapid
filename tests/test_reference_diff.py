"""Shared reference-diff core (rapidtriage/validation/reference_diff.py) used by T-204..T-207."""

from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.validation import reference_diff as rd

UTC = dt.timezone.utc


class TimestampTests(unittest.TestCase):
    def test_formats_normalise_to_the_same_utc_second(self) -> None:
        expected = dt.datetime(2026, 3, 2, 1, 5, 0, tzinfo=UTC)
        for text in (
            "2026-03-02T01:05:00Z",
            "2026-03-02 01:05:00.1234567",  # MFTECmd: 7 fractional digits
            "2026-03-02T10:05:00+09:00",
            "2026-03-02 01:05:00 (UTC)",
            "3/2/2026 1:05:00 AM",
            "2026-03-02 01:05:00:123:4567",  # UsnJrnl2Csv-style separators
        ):
            with self.subTest(text=text):
                self.assertEqual(rd.parse_timestamp(text).replace(microsecond=0), expected)

    def test_filetime_naive_zone_and_placeholders(self) -> None:
        filetime = 134168871000000000  # 2026-03-02T01:05:00Z
        self.assertEqual(rd.format_timestamp(rd.parse_timestamp(filetime)), "2026-03-02T01:05:00Z")
        self.assertEqual(rd.format_timestamp(rd.parse_timestamp(str(filetime))), "2026-03-02T01:05:00Z")
        kst = rd.parse_tz("+09:00")
        self.assertEqual(rd.format_timestamp(rd.parse_timestamp("2026-03-02 10:05:00", kst)), "2026-03-02T01:05:00Z")
        for empty in ("", None, 0, "1601-01-01 00:00:00", "1970-01-01T00:00:00Z"):
            self.assertIsNone(rd.parse_timestamp(empty))
        with self.assertRaises(ValueError):
            rd.parse_timestamp("yesterday")

    def test_unknown_zone_is_an_input_error(self) -> None:
        with self.assertRaises(rd.ReferenceDiffInputError):
            rd.parse_tz("Mars/Olympus")


class NormaliseTests(unittest.TestCase):
    def test_paths(self) -> None:
        self.assertEqual(rd.normalize_path(r"\\?\C:\Users\KIM\a.TXT"), "users/kim/a.txt")
        self.assertEqual(rd.normalize_path("D:/runs/r1/_e01/fs/Users/a.txt", "_e01/fs"), "users/a.txt")
        self.assertEqual(rd.normalize_path("_e01/fs/Users/a.txt", "_e01\\fs"), "users/a.txt")
        self.assertEqual(rd.normalize_path("Users/a.txt", "_e01/fs"), "users/a.txt")

    def test_header_keys_and_values(self) -> None:
        self.assertEqual(rd.header_key("Last Executed (UTC)"), "lastexecutedutc")
        self.assertEqual(rd.parse_int("0x10"), 16)
        self.assertEqual(rd.parse_int("1,024"), 1024)
        self.assertIsNone(rd.parse_int("n/a"))
        self.assertIs(rd.parse_bool("예"), True)
        self.assertIs(rd.parse_bool("FALSE"), False)
        self.assertIsNone(rd.parse_bool(""))


class DiffTests(unittest.TestCase):
    def test_primary_keys_pair_before_aliases(self) -> None:
        ours = [rd.KeyedRow(["a|1", "a|*"], {"n": 1}), rd.KeyedRow(["a|2", "a|*"], {"n": 2})]
        # Reference row a|9 would take ours a|1 through the alias if aliases ran first.
        reference = [rd.KeyedRow(["a|9", "a|*"], {"n": 9}), rd.KeyedRow(["a|1", "a|*"], {"n": 1})]
        result = rd.diff_rows(ours, reference)
        self.assertEqual(result.matched, 2)
        self.assertEqual([(m.keys[0], r.keys[0]) for m, r in result.matched_pairs], [("a|2", "a|9"), ("a|1", "a|1")])
        self.assertEqual(result.field_mismatch_counts, {"n": 1})

    def test_empty_reference_fields_are_skipped_and_duplicates_counted(self) -> None:
        stamp = dt.datetime(2026, 1, 1, tzinfo=UTC)
        ours = [rd.KeyedRow(["k"], {"t": None, "s": "x"})]
        reference = [rd.KeyedRow(["k"], {"t": stamp, "s": ""}), rd.KeyedRow(["k"], {})]
        result = rd.diff_rows(ours, reference)
        self.assertEqual(result.duplicate_reference_keys, 1)
        self.assertEqual(result.mismatched[0]["fields"], {"t": {"ours": None, "reference": "2026-01-01T00:00:00Z"}})

    def test_recall_is_none_for_empty_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "x"
            source.write_text("x", encoding="utf-8")
            report = rd.build_report(
                comparison="t", reference_tool="r", result=rd.diff_rows([], []), inputs={"ours": source},
                settings={}, key_fields=[], compared_fields=[], warnings=[], max_list=10,
            )
        self.assertIsNone(report["recall"])


class RapidRowsTests(unittest.TestCase):
    def test_jsonl_backed_output_expands_profiles_and_filters_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [
                {"artifact_type": "usn-record", "profile_ref": "usn-record", "details": {"usn": 8}},
                {"artifact_type": "mft-record", "details": {"usn": 9}},
            ]
            (root / "records.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            payload = {
                "records_file": "records.jsonl",
                "artifact_type_profiles": {"usn-record": {"details": {"parser": "windows-usn-native"}}},
                "artifacts": [],
            }
            (root / "out.json").write_text(json.dumps(payload), encoding="utf-8")
            warnings: list[str] = []
            got = list(rd.iter_rapid_rows(root / "out.json", ["usn-record"], warnings))
            self.assertEqual(len(got), 1)
            self.assertEqual(rd.rapid_field(got[0], "parser"), "windows-usn-native")
            self.assertEqual(warnings, [])
            # The bare JSONL keeps profile_ref: a warning tells QA to pass the .json instead.
            list(rd.iter_rapid_rows(root / "records.jsonl", ["usn-record"], warnings))
            self.assertEqual(len(warnings), 1)

    def test_table_sniffs_delimiter_and_bom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.csv"
            path.write_text("\ufeffUSN|Time Stamp\n1|2026-01-01 00:00:00\n\n", encoding="utf-8")
            rows, header = rd.read_table(path)
        self.assertEqual(header, ["usn", "timestamp"])
        self.assertEqual(rows, [{"usn": "1", "timestamp": "2026-01-01 00:00:00"}])


if __name__ == "__main__":
    unittest.main()
