"""browser-reference-diff.py and recyclebin-reference-diff.py on synthetic rows (T-211)."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
WEBKIT_TO_UNIX_US = 11_644_473_600_000_000


def webkit(iso: str) -> int:
    delta = datetime.fromisoformat(iso) - WEBKIT_EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


VISITS = [
    ("https://example.com/a", "Example A", "2024-06-01T01:02:03.456789+00:00"),
    ("https://example.com/b", "Example B", "2024-06-01T02:00:00+00:00"),
    ("https://example.org/c?q=1", "Example C", "2024-06-02T03:00:00+00:00"),
]
DOWNLOADS = [
    (r"C:\Users\tester\Downloads\one.zip", "https://example.com/one.zip", 1024, "2024-06-01T01:00:00+00:00",
     "2024-06-01T01:00:05+00:00"),
    (r"C:\Users\tester\Downloads\two.pdf", "https://example.com/two.pdf", 2048, "2024-06-01T02:00:00+00:00",
     "2024-06-01T02:00:09+00:00"),
    (r"C:\Users\tester\Downloads\three.exe", "https://example.net/three.exe", 4096, "2024-06-02T02:00:00+00:00",
     "2024-06-02T02:00:30+00:00"),
]
RECYCLED = [
    ("$IA1B2C3.txt", r"C:\Users\tester\Documents\notes.txt", 120, "2024-06-03T04:05:06+00:00"),
    ("$ID4E5F6.docx", r"C:\Users\tester\Documents\report.docx", 34567, "2024-06-03T05:00:00+00:00"),
    ("$IG7H8I9.png", r"C:\Users\tester\Pictures\shot.png", 890123, "2024-06-04T06:00:00+00:00"),
]
SID_DIR = r"C:\$Recycle.Bin\S-1-5-21-1-2-3-1001"


def visit_row(url, title, stamp):
    return {"provider": "browser", "artifact_type": "browser-visit", "path": "C:/synthetic/History", "supported": True,
            "details": {"url": url, "title": title, "visit_time_raw": webkit(stamp), "timestamp": stamp}}


def download_row(target, url, size, start, end):
    return {"provider": "browser", "artifact_type": "browser-download", "path": "C:/synthetic/History",
            "supported": True, "details": {"target_path": target, "tab_url": url, "source_url": url,
                                           "total_bytes": size, "started_at": start, "ended_at": end}}


def recycled_row(name, original, size, deleted):
    source = f"D:/extract/C/$Recycle.Bin/S-1-5-21-1-2-3-1001/{name}"
    return {"provider": "windows-filesystem", "artifact_type": "recycle-bin-entry", "path": source, "supported": True,
            "details": {"source_path": source, "recycle_id": name[2:], "original_path": original,
                        "deleted_file_size": size, "deleted_at": deleted}}


class _Case(ReferenceDiffCase):
    def _diff(self, ours, header, reference, *extra):
        code, report, stderr = self.run_diff(
            write_jsonl(self.tmp / "ours.jsonl", ours), write_csv(self.tmp / "ref.csv", header, reference), *extra
        )
        self.assert_contract(report)
        return code, report, stderr


class BrowserVisitTests(_Case):
    script_name = "browser-reference-diff"
    header = ("url", "title", "visit_time")

    def _reference(self):
        # Direct query output: raw WebKit microseconds, as sqlite3 prints them.
        return [[url, title, webkit(stamp)] for url, title, stamp in VISITS]

    def test_full_match(self) -> None:
        code, report, _ = self._diff([visit_row(*v) for v in VISITS], self.header, self._reference(), "--kind", "visit")
        self.assertEqual((code, report["recall"], report["matched"], report["mismatched"]), (0, 1.0, 3, []))
        self.assertEqual(report["kind"], "visit")

    def test_one_row_missing(self) -> None:
        code, report, _ = self._diff([visit_row(*v) for v in VISITS[1:]], self.header, self._reference())
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual([item["key"] for item in report["missing"]], ["https://example.com/a|2024-06-01T01:02:03Z"])

    def test_one_value_mismatch(self) -> None:
        reference = self._reference()
        reference[2][1] = "Example C (changed)"
        code, report, _ = self._diff([visit_row(*v) for v in VISITS], self.header, reference)
        self.assertEqual((code, report["recall"], len(report["mismatched"])), (1, 1.0, 1))
        self.assertEqual(report["mismatched"][0]["fields"]["title"]["reference"], "Example C (changed)")

    def test_firefox_prtime_and_local_text(self) -> None:
        reference = [[VISITS[0][0], VISITS[0][1], webkit(VISITS[0][2]) - WEBKIT_TO_UNIX_US],
                     [VISITS[1][0], VISITS[1][1], "2024-06-01 11:00:00"]]
        code, report, _ = self._diff([visit_row(*v) for v in VISITS[:2]], ["url", "title", "visit_date"], reference,
                                     "--reference-tz", "+09:00")
        self.assertEqual((code, report["recall"]), (0, 1.0))


class BrowserDownloadTests(_Case):
    script_name = "browser-reference-diff"
    header = ("target_path", "tab_url", "total_bytes", "start_time", "end_time")

    def _reference(self):
        return [[t, u, s, webkit(a), webkit(b)] for t, u, s, a, b in DOWNLOADS]

    def test_full_match(self) -> None:
        code, report, _ = self._diff([download_row(*d) for d in DOWNLOADS], self.header, self._reference(),
                                     "--kind", "download")
        self.assertEqual((code, report["recall"], report["mismatched"]), (0, 1.0, []))
        self.assertEqual(report["compared_fields"], ["url", "total_bytes", "ended"])

    def test_one_row_missing(self) -> None:
        code, report, _ = self._diff([download_row(*d) for d in DOWNLOADS[:2]], self.header, self._reference(),
                                     "--kind", "download")
        self.assertEqual((code, len(report["missing"])), (1, 1))
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)

    def test_one_value_mismatch(self) -> None:
        reference = self._reference()
        reference[0][2] = 1000
        code, report, _ = self._diff([download_row(*d) for d in DOWNLOADS], self.header, reference, "--kind", "download")
        self.assertEqual((code, report["recall"]), (1, 1.0))
        self.assertEqual(report["mismatched"][0]["fields"], {"total_bytes": {"ours": 1024, "reference": 1000}})


class RecycleBinTests(_Case):
    script_name = "recyclebin-reference-diff"
    header = ("SourceName", "FileType", "FileName", "FileSize", "DeletedOn")

    def _reference(self):
        # RBCmd-style columns: SourceName is the full $I path, DeletedOn naive UTC text.
        return [[f"{SID_DIR}\\{name}", "$I", original, size, deleted.replace("T", " ").replace("+00:00", "")]
                for name, original, size, deleted in RECYCLED]

    def test_full_match(self) -> None:
        code, report, _ = self._diff([recycled_row(*r) for r in RECYCLED], self.header, self._reference())
        self.assertEqual((code, report["recall"], report["matched"], report["mismatched"]), (0, 1.0, 3, []))

    def test_one_row_missing(self) -> None:
        code, report, _ = self._diff([recycled_row(*r) for r in RECYCLED[:2]], self.header, self._reference())
        self.assertEqual(code, 1)
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual([item["key"] for item in report["missing"]], ["$ig7h8i9.png"])

    def test_one_value_mismatch(self) -> None:
        reference = self._reference()
        reference[1][4] = "2024-06-03 05:00:02"
        code, report, _ = self._diff([recycled_row(*r) for r in RECYCLED], self.header, reference)
        self.assertEqual((code, report["recall"]), (1, 1.0))
        self.assertEqual([(item["key"], item["fields"]) for item in report["mismatched"]], [(
            "$id4e5f6.docx", {"deleted_at": {"ours": "2024-06-03T05:00:00Z", "reference": "2024-06-03T05:00:02Z"}})])

    def test_missing_input_exits_2(self) -> None:
        self.assert_missing_input_exit_2(write_csv(self.tmp / "present.csv", self.header, self._reference()))


if __name__ == "__main__":
    unittest.main()
