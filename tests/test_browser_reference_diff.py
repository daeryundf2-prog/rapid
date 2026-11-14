"""browser-reference-diff.py and recyclebin-reference-diff.py on synthetic rows (T-211)."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"rt_{name.replace('-', '_')}_test", SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


browser = _load("browser-reference-diff")
recyclebin = _load("recyclebin-reference-diff")

WEBKIT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


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


def _visit(url, title, stamp):
    return {"provider": "browser", "artifact_type": "browser-visit", "path": "C:/synthetic/History",
            "supported": True, "details": {"url": url, "title": title, "visit_time_raw": webkit(stamp),
                                           "timestamp": stamp}}


def _download(target, url, size, start, end):
    return {"provider": "browser", "artifact_type": "browser-download", "path": "C:/synthetic/History",
            "supported": True, "details": {"target_path": target, "tab_url": url, "source_url": url,
                                           "total_bytes": size, "started_at": start, "ended_at": end,
                                           "timestamp": start}}


def _recycled(name, original, size, deleted):
    return {"provider": "windows-filesystem", "artifact_type": "recycle-bin-entry",
            "path": f"D:/extract/C/$Recycle.Bin/S-1-5-21-1-2-3-1001/{name}", "supported": True,
            "details": {"source_path": f"D:/extract/C/$Recycle.Bin/S-1-5-21-1-2-3-1001/{name}",
                        "recycle_id": name[2:], "original_path": original, "deleted_file_size": size,
                        "deleted_at": deleted}}


class _Base(unittest.TestCase):
    module = None

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, ours, reference, *extra):
        ours_path = self.root / "ours.jsonl"
        ours_path.write_text("".join(json.dumps(row) + "\n" for row in ours), encoding="utf-8")
        ref_path = self.root / "reference.csv"
        with ref_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(reference[0]))
            writer.writeheader()
            writer.writerows(reference)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = self.module.main(["--ours", str(ours_path), "--reference", str(ref_path), "--json", *extra])
        self.assertEqual(code, 0)
        report = json.loads(stdout.getvalue())
        for key in ("recall", "matched", "missing", "mismatched", "reference_tool"):
            self.assertIn(key, report)
        return report


class BrowserVisitTests(_Base):
    module = browser

    def _reference(self):
        # Direct query output: raw WebKit microseconds, as sqlite3 prints them.
        return [{"url": url, "title": title, "visit_time": webkit(stamp)} for url, title, stamp in VISITS]

    def test_full_match(self) -> None:
        report = self._run([_visit(*v) for v in VISITS], self._reference(), "--kind", "visit")
        self.assertEqual((report["recall"], report["matched"], report["mismatched"]), (1.0, 3, []))
        self.assertEqual(report["reference_tool"], "sqlite3-direct-query-visits")

    def test_one_row_missing(self) -> None:
        report = self._run([_visit(*v) for v in VISITS[1:]], self._reference())
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(report["missing"], ["https://example.com/a|2024-06-01T01:02:03Z"])

    def test_one_value_mismatch(self) -> None:
        reference = self._reference()
        reference[2]["title"] = "Example C (changed)"
        report = self._run([_visit(*v) for v in VISITS], reference)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(len(report["mismatched"]), 1)
        self.assertEqual(report["mismatched"][0]["fields"]["title"]["reference"], "Example C (changed)")

    def test_firefox_prtime_and_local_text(self) -> None:
        reference = [{"url": VISITS[0][0], "title": VISITS[0][1], "visit_date": webkit(VISITS[0][2]) - 11644473600000000},
                     {"url": VISITS[1][0], "title": VISITS[1][1], "visit_date": "2024-06-01 11:00:00"}]
        report = self._run([_visit(*v) for v in VISITS[:2]], reference, "--reference-tz", "+09:00")
        self.assertEqual(report["recall"], 1.0)


class BrowserDownloadTests(_Base):
    module = browser

    def _reference(self):
        return [{"target_path": t, "tab_url": u, "total_bytes": s, "start_time": webkit(a), "end_time": webkit(b)}
                for t, u, s, a, b in DOWNLOADS]

    def test_full_match(self) -> None:
        report = self._run([_download(*d) for d in DOWNLOADS], self._reference(), "--kind", "download")
        self.assertEqual((report["recall"], report["mismatched"]), (1.0, []))
        self.assertEqual(report["fields_compared"], ["url", "total_bytes", "ended"])

    def test_one_row_missing(self) -> None:
        report = self._run([_download(*d) for d in DOWNLOADS[:2]], self._reference(), "--kind", "download")
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(len(report["missing"]), 1)

    def test_one_value_mismatch(self) -> None:
        reference = self._reference()
        reference[0]["total_bytes"] = 1000
        report = self._run([_download(*d) for d in DOWNLOADS], reference, "--kind", "download")
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"][0]["fields"], {"total_bytes": {"ours": "1024", "reference": "1000"}})


class RecycleBinTests(_Base):
    module = recyclebin

    def _reference(self):
        # RBCmd-style columns: SourceName is the full $I path, DeletedOn naive UTC text.
        return [{"SourceName": f"{SID_DIR}\\{name}", "FileType": "$I", "FileName": original, "FileSize": size,
                 "DeletedOn": deleted.replace("T", " ").replace("+00:00", "")}
                for name, original, size, deleted in RECYCLED]

    def test_full_match(self) -> None:
        report = self._run([_recycled(*r) for r in RECYCLED], self._reference())
        self.assertEqual((report["recall"], report["matched"], report["mismatched"]), (1.0, 3, []))

    def test_one_row_missing(self) -> None:
        report = self._run([_recycled(*r) for r in RECYCLED[:2]], self._reference())
        self.assertAlmostEqual(report["recall"], 2 / 3, places=5)
        self.assertEqual(report["missing"], ["$ig7h8i9.png"])

    def test_one_value_mismatch(self) -> None:
        reference = self._reference()
        reference[1]["DeletedOn"] = "2024-06-03 05:00:02"
        report = self._run([_recycled(*r) for r in RECYCLED], reference)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"], [{"key": "$id4e5f6.docx", "fields": {
            "deleted_at": {"ours": "2024-06-03T05:00:00Z", "reference": "2024-06-03T05:00:02Z"}}}])

    def test_missing_input_exits_2(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            code = recyclebin.main(["--ours", str(self.root / "a"), "--reference", str(self.root / "b")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
