"""Browser provider outputs pinned to the revision before the provider optimization."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unicodedata
import unittest
from contextlib import closing
from pathlib import Path

from rapidtriage.artifacts.windows import browser

LONG_URL = "https://long.example/" + "a" * 100_000 + "?q=" + "가" * 20_000 + "#" + "%41" * 500

# (stored URL, domain the unoptimized reader produced for it)
ODD_URL_DOMAINS = (
    ("", ""),
    ("https://bücher.example/straße?q=ä", "bücher.example"),
    ("https://xn--bcher-kva.example/", "xn--bcher-kva.example"),
    ("https://BÜCHER.Example./", "bücher.example"),
    ("https://한국.example/경로?q=검색어#조각", "한국.example"),
    ("https://%ED%95%9C%EA%B5%AD.example/%ED%95%9C?q=%EA%B2%80", "%ed%95%9c%ea%b5%ad.example"),
    ("https://user:pa%40ss@Host.Invalid:8080/p?x=1", "host.invalid"),
    ("https://user@[::1]:443/path", "["),
    ("http://[::1", ""),
    ("http://[v1.fe]/", "[v1.fe]"),
    ("http://[2001:db8::1]:8443/x", "[2001"),
    ("http://a@b@c.example:99/", "c.example"),
    ("http://exa\uff0fmple.com/", ""),
    ("http://example.com\u2100/", ""),
    ("data:text/html;base64,PGgxPmhpPC9oMT4=", ""),
    ("file:///C:/Users/sample/Desktop/%EA%B3%84%EC%95%BD.pdf", ""),
    ("file://server/share/문서.docx", "server"),
    ("javascript:alert(document.cookie)", ""),
    ("chrome://settings/passwords", "settings"),
    ("blob:https://example.invalid/0f1e", ""),
    ("//no-scheme.example/path", "no-scheme.example"),
    (" https://lead.example/ ", "lead.example"),
    ("https://tab\t.example/\n", "tab.example"),
    ("https://nul\x00.example/", "nul\x00.example"),
    ("HTTPS://UPPER.EXAMPLE:443/PATH", "upper.example"),
    ("https://trailing.example.../", "trailing.example"),
    (LONG_URL, "long.example"),
    ("https://例え.テスト/パス", "例え.テスト"),
    ("https://ex%41mple.invalid/", "ex%41mple.invalid"),
    ("https://\u1112\u1161\u11ab.example/", "\u1112\u1161\u11ab.example"),
    ("https://\ud55c.example/", "\ud55c.example"),
    ("https://\u212a.example/", "k.example"),
)

READERS = (
    ("chromium", "urls", "visits", "url", "visit_time", browser.chromium_history_row_reader),
    ("firefox", "moz_places", "moz_historyvisits", "place_id", "visit_date", browser.firefox_places_reader),
)


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


class BrowserOddUrlParityTests(unittest.TestCase):
    def test_odd_url_domains_and_referrers(self) -> None:
        urls = [url for url, _ in ODD_URL_DOMAINS]
        domains = [domain for _, domain in ODD_URL_DOMAINS]
        count = len(urls)
        expected_hashes = {  # captured from the unoptimized readers
            "chromium": "0c3c707812cda8246a3a88422a26108824a423188b1d7a20e2b9285bdfd541a9",
            "firefox": "cfd16087ba98a3207a6055ffd069b4763f5e69bd835ccc4e5d0121a6c3744bb0",
        }
        for family, url_table, visit_table, url_id, stamp, reader in READERS:
            with self.subTest(browser=family), closing(sqlite3.connect(":memory:")) as db:
                db.row_factory = sqlite3.Row
                db.execute(f"CREATE TABLE {url_table}(id INTEGER, url TEXT, title TEXT, last_visit_time INTEGER)")
                db.executemany(
                    f"INSERT INTO {url_table} VALUES (?, ?, ?, ?)",
                    [(index + 1, url, None, None) for index, url in enumerate(urls)],
                )
                db.execute(f"CREATE TABLE {visit_table}(id INTEGER, {url_id}, {stamp} INTEGER, from_visit)")
                # Two visits per URL; referrers point forward, at themselves, nowhere and at a missing visit.
                db.executemany(
                    f"INSERT INTO {visit_table} VALUES (?, ?, ?, ?)",
                    [(index + 1, 1 + index % count, index // 3, (index + 2, index + 1, 0, 9999)[index % 4]) for index in range(2 * count)],
                )
                if family == "chromium":
                    db.execute("CREATE TABLE keyword_search_terms(keyword_id, url_id, term, normalized_term)")
                    db.executemany(
                        "INSERT INTO keyword_search_terms VALUES (1, ?, 'q', 'q')", [(index + 1,) for index in range(count)]
                    )
                context = browser.BrowserRowContext(provider="browser", user="sample", browser=family, profile="sample")
                rows = reader(context)(db, Path("store"))
                details = {kind: [r.details for r in rows if r.artifact_type == kind] for kind in ("browser-history", "browser-visit", "browser-search")}
                self.assertEqual([row["domain"] for row in details["browser-history"]], domains)
                self.assertEqual(len(details["browser-visit"]), 2 * count)
                for visit in details["browser-visit"]:
                    self.assertEqual(visit["domain"], domains[visit["url_id"] - 1])
                    referrer = visit["from_visit"]
                    expected_from = urls[(referrer - 1) % count] if 0 < referrer <= 2 * count else ""
                    self.assertEqual(visit["from_url"], expected_from)
                self.assertEqual(
                    [row["search_engine_host"] for row in details["browser-search"]],
                    domains if family == "chromium" else [],
                )
                data = json.dumps([vars(r) for r in rows], ensure_ascii=True, separators=(",", ":")).encode("ascii")
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected_hashes[family])


class BrowserDamagedStoreParityTests(unittest.TestCase):
    def test_corrupt_page_reported_before_malformed_visit_id(self) -> None:
        # The malformed id sorts first through the timestamp index and the
        # corrupt table page later. Reading every visit row before converting
        # any id keeps the parse-error row instead of an escaping ValueError.
        for family, url_table, visit_table, url_id, stamp, reader in READERS:
            with self.subTest(browser=family), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "store.sqlite"
                with closing(sqlite3.connect(path)) as db:
                    db.execute("PRAGMA page_size=512")
                    db.execute(f"CREATE TABLE {url_table}(id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
                    db.execute(f"INSERT INTO {url_table} VALUES (1, 'https://example.invalid/', 't')")
                    db.execute(f"CREATE TABLE {visit_table}(id, {url_id} INTEGER, {stamp} INTEGER, from_visit INTEGER, filler TEXT)")
                    db.executemany(
                        f"INSERT INTO {visit_table} VALUES (?, 1, ?, 0, ?)",
                        [("abc" if index == 0 else index, index, f"row-{index:04d}-" + "x" * 100) for index in range(600)],
                    )
                    db.execute(f"CREATE INDEX visit_time_index ON {visit_table}({stamp})")
                    db.commit()
                data = bytearray(path.read_bytes())
                page = data.index(b"row-0500-") // 512
                data[page * 512 : (page + 1) * 512] = b"\xff" * 512
                path.write_bytes(bytes(data))
                context = browser.BrowserRowContext(provider="browser", user="sample", browser=family, profile="sample")
                errors: list = []
                rows = browser.browser_sqlite_rows(context, path, errors, reader(context))
                self.assertEqual(rows, [])
                self.assertEqual(
                    [(error.artifact_type, error.details["error_type"]) for error in errors],
                    [("browser-parse-error", "DatabaseError")],
                )


class BrowserCitationPathParityTests(unittest.TestCase):
    def test_each_row_resolves_its_own_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = root / "real"
            real.mkdir()
            (real / "History").write_bytes(b"")
            link = root / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                link = real
            candidates = [
                real / "History",
                link / "History",
                root / "real" / ".." / "real" / "History",
                root / "REAL" / "History",
                root / unicodedata.normalize("NFC", "한글") / "q.db",
                root / unicodedata.normalize("NFD", "한글") / "q.db",
                root / "e\u0301" / "q.db",
                Path("relative") / "q.db",
                *(root / f"store-{index}" / "QuarantineEventsV2" for index in range(24)),
            ]
            for source in (link / "History", real / "History"):
                history = [
                    {"url": "https://example.invalid/", "last_visited_at": f"2025-01-01T00:00:{index:02d}", "source_row_id": index}
                    for index in range(3)
                ]
                downloads = [
                    {
                        "source_url": "https://example.invalid/file",
                        "started_at": f"2025-01-02T00:{index // 60:02d}:{index % 60:02d}",
                        "source_row_id": index,
                        **({"source_path": str(candidates[(index * 7) % len(candidates)])} if index % 5 else {}),
                    }
                    for index in range(120)
                ]
                # Pre-optimization formula, evaluated per row.
                expected = [str(Path(str(row.get("source_path") or source)).resolve()) for row in downloads]
                arguments = dict(browser="b", profile="p", user="u", source_path=source, source_hashes={"sha256": "ab"})
                timeline = browser.build_unified_browser_timeline(**arguments, history_rows=history, download_rows=downloads, ai_rows=[])
                manifest = browser.build_browser_history_download_citation_manifest(
                    **arguments, history_rows=history, download_rows=downloads, unified_timeline=timeline
                )
                with self.subTest(source=str(source)):
                    for row in timeline:
                        want = expected[row["source_row_id"]] if row["timeline_type"] == "download" else str(source.resolve())
                        self.assertEqual(row["source_path"], want)
                    for citation in manifest["history_citations"]:
                        self.assertEqual(citation["source_viewer_locator"]["source_path"], str(source.resolve()))
                    self.assertEqual(
                        [citation["source_viewer_locator"]["source_path"] for citation in manifest["download_citations"]],
                        expected,
                    )
