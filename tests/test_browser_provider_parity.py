"""Visit-row golden outputs from before the browser provider optimization."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path

from rapidtriage.artifacts.windows import browser


class BrowserVisitParityTests(unittest.TestCase):
    def test_ordered_visit_rows(self) -> None:
        # No primary keys here: partially recovered stores can have duplicate
        # IDs. The last row in visit order supplies the referrer in both readers.
        for family, urls, visits, url_id, stamp, reader, expected in (
            (
                "chromium",
                "urls",
                "visits",
                "url",
                "visit_time",
                browser.chromium_history_row_reader,
                "e41c4d90756013ff692a4dd94f4b76ce3bdc1bc6027e5a7f0d4de63db25253b7",
            ),
            (
                "firefox",
                "moz_places",
                "moz_historyvisits",
                "place_id",
                "visit_date",
                browser.firefox_places_reader,
                "79e7f82bb8e8141c3bda54589f9cfdbbfb952fd463ea9ebcc78d415bf6d0f1f0",
            ),
        ):
            with (
                self.subTest(browser=family),
                closing(sqlite3.connect(":memory:")) as db,
            ):
                db.row_factory = sqlite3.Row
                db.execute(f"CREATE TABLE {urls}(id INTEGER, url TEXT, title TEXT)")
                db.executemany(
                    f"INSERT INTO {urls} VALUES (?, ?, ?)",
                    [
                        (-1, "https://fallback.invalid/", None),
                        (0, "https://zero.invalid/", ""),
                        (1, "https://example.invalid/한글", "제목" * 32768),
                        (2, "http://[", None),
                        (3, None, None),
                    ],
                )
                db.execute(
                    f"CREATE TABLE {visits}(id INTEGER, {url_id}, {stamp} INTEGER, from_visit)"
                )
                db.executemany(
                    f"INSERT INTO {visits} VALUES (?, ?, ?, ?)",
                    [
                        (3, 2, 5, 2),
                        (1, "01", 1, "03"),
                        (3, 1, 6, 1),
                        (4, 0, None, None),
                        (2, None, 5, 99),
                        (5, 8, 2**63 - 1, 4),
                    ],
                )
                context = browser.BrowserRowContext(
                    provider="browser", user="sample", browser=family, profile="sample"
                )
                rows = reader(context)(db, Path("store"))
                self.assertEqual(len(rows), 11)
                by_visit = [
                    r.details for r in rows if r.artifact_type == "browser-visit"
                ]
                self.assertEqual(
                    [v["source_row_id"] for v in by_visit], [4, 1, 2, 3, 3, 5]
                )
                self.assertEqual(
                    by_visit[1]["from_url"], "https://example.invalid/한글"
                )
                data = json.dumps(
                    [vars(r) for r in rows], ensure_ascii=True, separators=(",", ":")
                ).encode("ascii")
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
