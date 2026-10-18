"""R5 L3 web: URL classes (webmail / torrent / Flickr / OWA / magnet), map-URL location candidates,
added Chromium roots and Google Analytics cookies (synthetic fixtures only)."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows.browser import (
    CHROMIUM_BROWSER_ROOTS,
    WindowsBrowserArtifactsProvider,
)
from rapidtriage.artifacts.windows.browser_analytics import parse_analytics_cookie
from rapidtriage.core.derived.engine import run_derived
from rapidtriage.core.derived.map_urls import parse_map_url, web_mercator_to_wgs84
from rapidtriage.core.derived.normalize import normalize
from rapidtriage.core.derived.url_classes import (
    UrlClassError,
    load_url_classes,
    parse_url_classes,
)
from rapidtriage.core.triage_rules.engine import TriageInputs

WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
VISIT = dt.datetime(2026, 3, 4, 5, 6, 7, tzinfo=dt.timezone.utc)
GA_VISITOR_ID = "1987654321"  # synthetic "client ID" part: must never reach a row
GA_RANDOM = "424242424"


def webkit(moment: dt.datetime) -> int:
    return int((moment - WEBKIT_EPOCH).total_seconds() * 1_000_000)


def sqlite_file(path: Path, script: str, rows: dict[str, list[tuple]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(script)
        for table, values in rows.items():
            for row in values:
                connection.execute(f"INSERT INTO {table} VALUES ({', '.join('?' for _ in row)})", row)
        connection.commit()
    finally:
        connection.close()


HISTORY_SQL = """
CREATE TABLE urls(id INTEGER PRIMARY KEY,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER,typed_count INTEGER,last_visit_time INTEGER,hidden INTEGER);
CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER,segment_id INTEGER,visit_duration INTEGER);
"""
COOKIES_SQL = (
    "CREATE TABLE cookies(creation_utc INTEGER,host_key TEXT,top_frame_site_key TEXT,name TEXT,value TEXT,"
    "encrypted_value BLOB,path TEXT,expires_utc INTEGER,is_secure INTEGER,is_httponly INTEGER,last_access_utc INTEGER,"
    "has_expires INTEGER,is_persistent INTEGER,priority INTEGER,samesite INTEGER,source_scheme INTEGER,source_port INTEGER,"
    "last_update_utc INTEGER);"
)
GOOGLE_PLACE = (
    "https://www.google.com/maps/place/Seoul+Station/@37.5546788,126.9706069,17z/"
    "data=!3m1!4b1!4m6!3m5!1s0x0:0x0!8m2!3d37.5559!4d126.9723"
)
NAVER_SEARCH = "https://map.naver.com/v5/search/%EC%84%9C%EC%9A%B8%EC%97%AD?c=14135893.887,4518355.9333,15,0,0,0,dh"
KAKAO_LINK = "https://map.kakao.com/link/map/%ED%85%8C%EC%8A%A4%ED%8A%B8%EC%9E%A5%EC%86%8C,37.402056,127.108212"


class UrlClassTests(unittest.TestCase):
    def test_webmail_torrent_flickr_classes(self) -> None:
        classes = load_url_classes()
        for host in ("mail.google.com", "outlook.live.com", "outlook.office365.com", "mail.yahoo.com", "www.gmx.net",
                     "e.mail.ru", "hushmail.com", "www.mailinator.com", "mail.naver.com", "mail.daum.net", "mail.kakao.com"):
            self.assertEqual(classes.classify(host), "webmail", host)
        self.assertEqual(classes.classify("www.google.com"), "search")  # longest domain wins
        self.assertEqual(classes.classify("thepiratebay.org"), "torrent")
        self.assertEqual(classes.classify("nyaa.si"), "torrent")
        self.assertEqual(classes.classify("www.flickr.com"), "social")
        self.assertEqual(classes.classify("magnet:" + "a" * 40), "torrent")
        self.assertEqual(classes.classify_path("/owa/auth/logon.aspx"), "webmail")
        self.assertEqual(classes.classify_path("/OWA"), "webmail")
        self.assertIsNone(classes.classify_path("/owasp/"))
        for urls in classes.sources.values():
            self.assertTrue(all(url.startswith("https://") for url in urls))

    def test_bad_path_and_scheme_rules_are_korean_errors(self) -> None:
        base = b"classes: [{id: a, label_ko: A, sources: [https://x], domains: [a.com], "
        for tail in (b"paths: [owa]}]", b"schemes: [https]}]", b"schemes: ['Bad Scheme']}]"):
            with self.assertRaises(UrlClassError) as caught:
                parse_url_classes(base + tail)
            self.assertRegex(str(caught.exception), "[가-힣]")

    def test_magnet_key(self) -> None:
        link = "magnet:?xt=urn:btih:ABCDEF0123456789ABCDEF0123456789ABCDEF01&dn=test&tr=udp://tracker.example:80"
        self.assertEqual(normalize("urls", link), "magnet:abcdef0123456789abcdef0123456789abcdef01")
        self.assertIsNone(normalize("urls", "magnet:?dn=nohash"))


class MapUrlTests(unittest.TestCase):
    def test_google_place_pin_wins_over_viewport(self) -> None:
        parsed = parse_map_url(GOOGLE_PLACE)
        assert parsed is not None
        self.assertEqual(parsed["map_url_kind"], "place")
        self.assertEqual((parsed["latitude"], parsed["longitude"]), (37.5559, 126.9723))
        self.assertEqual(parsed["coordinate_basis"], "url-place-pin")
        self.assertEqual(parsed["query"], "Seoul Station")
        self.assertEqual(parsed["zoom"], 17.0)

    def test_google_search_directions_and_query(self) -> None:
        search = parse_map_url("https://www.google.co.kr/maps/search/%EC%B9%B4%ED%8E%98/@37.49,127.02,15z")
        assert search is not None
        self.assertEqual((search["map_url_kind"], search["query"], search["coordinate_basis"]), ("search", "카페", "url-viewport-center"))
        route = parse_map_url("https://www.google.com/maps/dir/Seoul+Station/Mid/Gangnam+Station/@37.5,127.0,12z")
        assert route is not None
        self.assertEqual((route["origin"], route["destination"], route["waypoints"]), ("Seoul Station", "Gangnam Station", ["Mid"]))
        api = parse_map_url("https://maps.google.com/?q=37.1,127.2")
        assert api is not None
        self.assertEqual((api["latitude"], api["longitude"]), (37.1, 127.2))
        self.assertIsNone(parse_map_url("https://www.google.com/search?q=maps"))
        self.assertIsNone(parse_map_url("https://www.google.com/maps"))  # says nothing

    def test_naver_epsg3857_and_zoom_only(self) -> None:
        parsed = parse_map_url(NAVER_SEARCH)
        assert parsed is not None
        lat, lon = web_mercator_to_wgs84(14135893.887, 4518355.9333)
        self.assertAlmostEqual(parsed["latitude"], round(lat, 7))
        self.assertAlmostEqual(parsed["longitude"], 126.98, delta=0.01)
        self.assertAlmostEqual(parsed["latitude"], 37.566, delta=0.01)
        self.assertEqual((parsed["coordinate_basis"], parsed["query"]), ("url-epsg3857-converted", "서울역"))
        zoom_only = parse_map_url("https://map.naver.com/p/search/%EC%B9%B4%ED%8E%98?c=15.00,0,0,0,dh")
        assert zoom_only is not None
        self.assertIsNone(zoom_only["latitude"])
        self.assertEqual(zoom_only["query"], "카페")
        legacy = parse_map_url("https://map.naver.com/index.nhn?lng=126.9784&lat=37.5666&dlevel=11")
        assert legacy is not None
        self.assertEqual((legacy["latitude"], legacy["longitude"]), (37.5666, 126.9784))

    def test_kakao_link_and_plane_coordinates(self) -> None:
        parsed = parse_map_url(KAKAO_LINK)
        assert parsed is not None
        self.assertEqual((parsed["latitude"], parsed["longitude"], parsed["query"]), (37.402056, 127.108212, "테스트장소"))
        route = parse_map_url("https://map.kakao.com/link/to/%EB%8F%84%EC%B0%A9,37.5,127.0")
        assert route is not None
        self.assertEqual((route["map_url_kind"], route["destination"]), ("directions", "도착"))
        plane = parse_map_url("https://map.kakao.com/?urlX=523953&urlY=1084098&urlLevel=3")
        assert plane is not None
        self.assertIsNone(plane["latitude"])
        self.assertEqual(plane["plane_coordinates"], "523953,1084098")

    def test_corrupt_inputs_never_raise(self) -> None:
        for url in ("https://[::1/maps", "https://www.google.com/maps/@999,999,3z", "https://map.naver.com/?c=abc,def",
                    "https://map.naver.com/?c=99999999999,99999999999", "ftp://map.naver.com/?c=1,2", "x" * 10000):
            parse_map_url(url)


class BrowserProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.user = self.root / "Users" / "kim"

    def chromium_profile(self, relative: tuple[str, ...], urls: list[str], *, cookies: list[tuple] | None = None) -> Path:
        profile = self.user.joinpath(*relative, "Default")
        t0 = webkit(VISIT)
        sqlite_file(
            profile / "History",
            HISTORY_SQL,
            {
                "urls": [(index + 1, url, f"title {index}", 1, 0, t0 + index, 0) for index, url in enumerate(urls)],
                "visits": [(100 + index, index + 1, t0 + index, 0, 1, 0, 0) for index in range(len(urls))],
            },
        )
        if cookies is not None:
            sqlite_file(profile / "Network" / "Cookies", COOKIES_SQL, {"cookies": cookies})
        return profile

    def collect(self) -> list:
        return list(WindowsBrowserArtifactsProvider().collect(self.root))

    def test_new_chromium_roots_and_location_candidates(self) -> None:
        names = {name for name, _parts in CHROMIUM_BROWSER_ROOTS}
        self.assertTrue({"360se", "360chrome", "yandex", "chromium", "coccoc", "qqbrowser"} <= names)
        self.chromium_profile(("AppData", "Roaming", "360se6", "User Data"), [GOOGLE_PLACE, "https://example.org/"])
        self.chromium_profile(("AppData", "Local", "Yandex", "YandexBrowser", "User Data"), [NAVER_SEARCH, KAKAO_LINK])
        records = self.collect()
        browsers = {record.details.get("browser") for record in records if record.artifact_type == "browser-visit"}
        self.assertEqual(browsers, {"360se", "yandex"})
        candidates = [record for record in records if record.artifact_type == "location-url-candidate"]
        # One candidate per (browser, profile, URL, time): the URL row's last visit equals its visit row.
        self.assertEqual(len(candidates), 3)
        by_provider = {record.details["map_provider"]: record.details for record in candidates}
        self.assertEqual(set(by_provider), {"google-maps", "naver-map", "kakao-map"})
        google = by_provider["google-maps"]
        self.assertEqual((google["latitude"], google["longitude"]), (37.5559, 126.9723))
        for details in by_provider.values():
            self.assertEqual(details["recovery_method"], "derived")
            self.assertTrue(details["parser_version"].startswith("map-url-location"))
            self.assertTrue(str(details["source_path"]).endswith("History"))
            self.assertIn(details["source_artifact_type"], {"browser-history", "browser-visit"})

    def test_ga_cookies_parsed_without_client_id(self) -> None:
        t0 = webkit(VISIT)
        first, previous, current = 1_700_000_000, 1_700_100_000, 1_700_200_000
        utma = f"173272373.{GA_VISITOR_ID}.{first}.{previous}.{current}.7"
        utmz = f"173272373.{current}.7.2.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=%EC%A4%91%EA%B3%A0%EC%B0%A8|utmgclid=CLICKID999"
        ga = f"GA1.2.{GA_RANDOM}.{first}"

        def cookie(name: str, value: str, encrypted: bytes = b"") -> tuple:
            return (t0, ".shop.example", "", name, value, encrypted, "/", 0, 0, 0, t0, 0, 1, 1, -1, 2, 443, t0)

        self.chromium_profile(
            ("AppData", "Local", "Chromium", "User Data"),
            ["https://shop.example/"],
            cookies=[cookie("__utma", utma), cookie("__utmz", utmz), cookie("_ga", ga), cookie("_ga", "", b"v10secret"), cookie("other", "x")],
        )
        records = self.collect()
        rows = [record.details for record in records if record.artifact_type == "browser-analytics-cookie"]
        self.assertEqual(len(rows), 4)
        utma_row = next(row for row in rows if row["cookie_name"] == "__utma")
        self.assertEqual(utma_row["session_count"], 7)
        self.assertEqual(utma_row["first_visit_at"], "2023-11-14T22:13:20Z")
        self.assertEqual(utma_row["timestamp_kind"], "ga-current-visit")
        utmz_row = next(row for row in rows if row["cookie_name"] == "__utmz")
        self.assertEqual((utmz_row["source"], utmz_row["medium"], utmz_row["search_term"]), ("google", "organic", "중고차"))
        encrypted = [row for row in rows if row["value_status"] == "encrypted-not-read"]
        self.assertEqual(len(encrypted), 1)
        serialized = json.dumps([record.details for record in records], ensure_ascii=False, default=str)
        for secret in (GA_VISITOR_ID, GA_RANDOM, "CLICKID999", "173272373"):
            self.assertNotIn(secret, serialized)

    def test_parse_analytics_cookie_formats(self) -> None:
        self.assertEqual(parse_analytics_cookie("__utma", "garbage")["value_status"], "unparsed-format")
        self.assertEqual(parse_analytics_cookie("_ga", "GA1.2.1.99999999999")["value_status"], "unparsed-format")
        parsed = parse_analytics_cookie("_ga", f"GA1.2.{GA_RANDOM}.1700000000")
        self.assertEqual(set(parsed), {"value_status", "first_visit_at"})

    def test_firefox_ga_cookie(self) -> None:
        profile = self.user / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abc.default"
        sqlite_file(
            profile / "places.sqlite",
            "CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,typed INTEGER,hidden INTEGER,last_visit_date INTEGER);",
            {"moz_places": [(1, GOOGLE_PLACE, "Seoul", 1, 0, 0, 1_700_000_000_000_000)]},
        )
        sqlite_file(
            profile / "cookies.sqlite",
            "CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY,name TEXT,value TEXT,host TEXT,path TEXT,creationTime INTEGER);",
            {"moz_cookies": [(1, "__utma", f"1.{GA_VISITOR_ID}.1700000000.1700000001.1700000002.3", ".ff.example", "/", 1_700_000_000_000_000)]},
        )
        records = self.collect()
        ga = [record.details for record in records if record.artifact_type == "browser-analytics-cookie"]
        self.assertEqual(len(ga), 1)
        self.assertEqual(ga[0]["session_count"], 3)
        self.assertNotIn(GA_VISITOR_ID, json.dumps(ga, default=str))
        self.assertEqual(sum(record.artifact_type == "location-url-candidate" for record in records), 1)


class DerivedUrlTests(unittest.TestCase):
    def test_owa_path_class_magnet_and_location_count(self) -> None:
        rows = [
            {"artifact_type": "browser-visit", "details": {"url": "https://mail.corp.example/owa/auth/logon.aspx", "timestamp": "2026-01-01T00:00:00Z"}},
            {"artifact_type": "browser-visit", "details": {"url": "https://mail.corp.example/", "timestamp": "2026-01-02T00:00:00Z"}},
            {"artifact_type": "browser-visit", "details": {"url": "magnet:?xt=urn:btih:" + "B" * 40 + "&dn=x", "timestamp": "2026-01-03T00:00:00Z"}},
            {"artifact_type": "browser-visit", "details": {"url": GOOGLE_PLACE, "timestamp": "2026-01-04T00:00:00Z"}},
            {"artifact_type": "browser-visit", "details": {"url": "https://mail.naver.com/v2/folders/0", "timestamp": "2026-01-05T00:00:00Z"}},
        ]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            records = base / "browser.jsonl"
            records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            payload = base / "browser.json"
            payload.write_text(json.dumps({"records_path": str(records), "record_count": len(rows), "artifacts": []}), encoding="utf-8")
            summary = run_derived(TriageInputs(output_dir=base, artifact_payloads={"browser": payload}), base / "out", source_label="test")
            table = {row["normalized"]: row for row in map(json.loads, (base / "out" / "urls.jsonl").read_text(encoding="utf-8").splitlines())}
        self.assertEqual((table["mail.corp.example"]["url_class"], table["mail.corp.example"]["url_class_basis"]), ("webmail", "path"))
        magnet = table["magnet:" + "b" * 40]
        self.assertEqual((magnet["url_class"], magnet["url_class_basis"]), ("torrent", "scheme"))
        self.assertEqual(table["www.google.com"]["location_candidates"], 1)
        self.assertEqual(table["mail.naver.com"]["url_class"], "webmail")
        self.assertEqual(summary["tables"]["urls"]["by_class"]["webmail"], 2)
        self.assertEqual(summary["tables"]["urls"]["location_candidates"], 1)


if __name__ == "__main__":
    unittest.main()
