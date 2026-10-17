"""Browser depth (plan r2-communication §3.3 M3, QA Q-R2-4/5/6/8): Chromium cache entries,
legacy Edge/IE WebCacheV01 container rows, extra Chromium profile roots, web upload candidates."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows import browser_cache
from rapidtriage.artifacts.windows.browser import (
    WindowsBrowserArtifactsProvider,
    collect_webcachev01_artifacts,
)
from rapidtriage.artifacts.windows.browser_cache import (
    CacheBudget,
    chromium_cache_directories,
    decode_blockfile_directory,
    decode_simple_cache_directory,
    parse_cache_key,
)
from rapidtriage.artifacts.windows.browser_webcache import decode_webcache
from rapidtriage.artifacts.windows.web_upload import (
    UploadPatternError,
    load_upload_patterns,
    match_upload_url,
    parse_upload_patterns,
)
from rapidtriage.core.models import ArtifactRecord
from tests.browser_cache_fixtures import (
    BODY_MARKER,
    sample_webcache,
    write_blockfile_cache,
    write_cache_storage,
    write_simple_cache,
)

CHROME = ("AppData", "Local", "Google", "Chrome", "User Data", "Default")
WEBKIT_2024 = 13_356_000_000_000_000  # 2024-03-xx in WebKit microseconds


def write_history(path: Path, urls: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
                               typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
            CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,
                                 transition INTEGER, segment_id INTEGER, visit_duration INTEGER);
            """
        )
        for index, url in enumerate(urls, start=1):
            connection.execute("INSERT INTO urls VALUES (?, ?, ?, 1, 0, ?, 0)", (index, url, f"page {index}", WEBKIT_2024 + index))
            connection.execute("INSERT INTO visits VALUES (?, ?, ?, 0, 805306368, 0, 0)", (index, index, WEBKIT_2024 + index))
        connection.commit()
    finally:
        connection.close()


def collect(root: Path) -> list[ArtifactRecord]:
    return list(WindowsBrowserArtifactsProvider().collect(root))


def by_type(records: list[ArtifactRecord], artifact_type: str) -> list[ArtifactRecord]:
    return [record for record in records if record.artifact_type == artifact_type]


class SimpleCacheTests(unittest.TestCase):
    def test_ten_simple_entries_decode_url_status_type_and_body_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "Cache_Data"
            expected = write_simple_cache(directory)
            result = decode_simple_cache_directory(directory, CacheBudget(), cache_format="chromium-simple")
            self.assertEqual(result.error_count, 0, result.error_samples)
            self.assertEqual(len(result.entries), 10)
            entries = {entry["url"]: entry for entry in result.entries}
            for item in expected:
                entry = entries[item["url"]]
                self.assertEqual(entry["http_status"], item["status"])
                self.assertEqual(entry["method"], item["method"])
                self.assertEqual(entry["body_sha256"], item["body_sha256"])
                self.assertEqual(entry["body_size"], item["body_size"])
                self.assertEqual(entry["response_time"], item["response_time"])
                self.assertEqual(entry["body_hash_scope"], "full")
                self.assertFalse(entry["body_stored"])
                self.assertTrue(str(entry["content_type"]).startswith("text/html"))
            self.assertEqual(entries[expected[2]["url"]]["compression"], "gzip")
            self.assertEqual(entries[expected[6]["url"]]["file_name_candidate"], "report.pdf")
            self.assertEqual(entries[expected[3]["url"]]["method_basis"], "cache-key-upload-id")

    def test_cache_storage_protobuf_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "cache"
            expected = write_cache_storage(directory)
            result = decode_simple_cache_directory(directory, CacheBudget(), cache_format="chromium-cachestorage")
            (entry,) = result.entries
            self.assertEqual(entry["url"], expected["url"])
            self.assertEqual(entry["http_status"], 200)
            self.assertEqual(entry["content_type"], "application/json")
            self.assertEqual(entry["method"], "GET")
            self.assertEqual(entry["metadata_format"], "cache-storage-protobuf")
            self.assertEqual(entry["response_time"], expected["response_time"])
            self.assertEqual(entry["body_sha256"], expected["body_sha256"])

    def test_cache_key_forms(self) -> None:
        self.assertEqual(parse_cache_key("1/0/_dk_https://a.com https://a.com https://a.com/x")["url"], "https://a.com/x")
        post = parse_cache_key("1/12/_dk_https://a.com https://a.com https://a.com/upload")
        self.assertEqual((post["method"], post["upload_id"]), ("POST", 12))
        self.assertEqual(parse_cache_key("https://plain.example/x")["url"], "https://plain.example/x")


class BlockfileTests(unittest.TestCase):
    def test_ten_blockfile_entries_with_chain_external_body_and_missing_block_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "Cache_Data"
            expected = write_blockfile_cache(directory)
            result = decode_blockfile_directory(directory, CacheBudget())
            self.assertEqual(result.error_count, 0, result.error_samples)
            self.assertEqual(len(result.entries), 10)
            entries = {entry["url"]: entry for entry in result.entries}
            self.assertEqual(set(entries), {item["url"] for item in expected})
            for item in expected:
                entry = entries[item["url"]]
                self.assertEqual(entry["method"], item["method"])
                self.assertEqual(entry["body_sha256"], item["body_sha256"])
                self.assertEqual(entry["body_size"], item["body_size"])
                self.assertEqual(entry["recovery_method"], "parsed")
                if item["headers_missing"]:
                    self.assertEqual(entry["headers_status"], "missing-file:data_3")
                    self.assertNotIn("http_status", entry)
                else:
                    self.assertEqual(entry["headers_status"], "parsed")
                    self.assertEqual(entry["http_status"], 200)
                    self.assertEqual(entry["response_time"], item["response_time"])
                if item["external_body"]:
                    self.assertTrue(str(entry["body_file"]).startswith("f_"))
                self.assertIsNotNone(entry["last_used_at"])
                self.assertIsInstance(entry["source_offset"], int)
            png = entries[expected[2]["url"]]
            self.assertEqual((png["content_type"], png["body_signature"]), ("image/png", "png"))
            self.assertEqual(entries[expected[6]["url"]]["file_name_candidate"], "report.pdf")
            self.assertEqual(result.entries[0]["index_version"], "3.0")

    def test_short_external_body_is_not_reported_as_a_full_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "Cache_Data"
            expected = write_blockfile_cache(directory)
            external = next(directory.glob("f_*"))
            external.write_bytes(external.read_bytes()[:100])
            result = decode_blockfile_directory(directory, CacheBudget())
            entry = next(item for item in result.entries if item["url"] == expected[3]["url"])
            self.assertIsNone(entry["body_sha256"])
            self.assertEqual(entry["body_hash_scope"], f"short-read-100-of-{expected[3]['body_size']}-bytes")

    def test_unusable_index_falls_back_to_a_data_1_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "Cache_Data"
            write_blockfile_cache(directory)
            (directory / "index").write_bytes(b"\x00" * 16)
            self.assertTrue(browser_cache.is_blockfile_directory(directory))
            result = decode_blockfile_directory(directory, CacheBudget())
            self.assertEqual(len(result.entries), 10)
            self.assertTrue(all(entry["recovery_method"] == "carved" for entry in result.entries))
            self.assertEqual(result.error_count, 1)  # the unreadable index itself


class CapsAndCorruptionTests(unittest.TestCase):
    def test_entry_cap_is_shared_across_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            write_simple_cache(Path(temp) / "a")
            write_blockfile_cache(Path(temp) / "b")
            budget = CacheBudget(cap=12)
            first = decode_simple_cache_directory(Path(temp) / "a", budget, cache_format="chromium-simple")
            second = decode_blockfile_directory(Path(temp) / "b", budget)
            self.assertEqual((len(first.entries), len(second.entries)), (10, 2))
            self.assertIn("entry-cap-reached", second.notes)
            self.assertTrue(budget.capped)

    def test_body_read_cap_keeps_a_prefix_digest_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "c"
            write_simple_cache(directory)
            with mock.patch.object(browser_cache, "MAX_BODY_READ_BYTES", 16):
                result = decode_simple_cache_directory(directory, CacheBudget(), cache_format="chromium-simple")
            entry = result.entries[0]
            self.assertIsNone(entry["body_sha256"])
            self.assertIsNotNone(entry["body_prefix_sha256"])
            self.assertEqual(entry["body_hash_scope"], "prefix-16-bytes")
            self.assertGreater(int(entry["body_size"]), 16)

    def test_corrupt_entries_are_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "Cache_Data"
            write_simple_cache(directory)
            names = sorted(path.name for path in directory.glob("*_0"))
            (directory / names[0]).write_bytes(b"\x00" * 100)  # bad magic
            path = directory / names[1]
            path.write_bytes(path.read_bytes()[:-10])  # truncated EOF
            (directory / "ffffffffffffffff_0").write_bytes(b"short")
            result = decode_simple_cache_directory(directory, CacheBudget(), cache_format="chromium-simple")
            self.assertEqual(len(result.entries), 8)
            self.assertEqual(result.error_count, 3)
            self.assertEqual(len(result.error_samples), 3)

    def test_corrupt_blockfile_entry_is_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "Cache_Data"
            write_blockfile_cache(directory)
            index = bytearray((directory / "index").read_bytes())
            # Point an empty bucket at an appended block holding garbage.
            data1 = bytearray((directory / "data_1").read_bytes())
            garbage_block = (len(data1) - 8192) // 256
            data1 += b"\xff" * 256
            (directory / "data_1").write_bytes(bytes(data1))
            index[368 + 4 * 200 : 368 + 4 * 201] = (0x80000000 | (2 << 28) | (1 << 16) | garbage_block).to_bytes(4, "little")
            (directory / "index").write_bytes(bytes(index))
            result = decode_blockfile_directory(directory, CacheBudget())
            self.assertEqual(len(result.entries), 10)
            self.assertEqual(result.error_count, 1)


class ProviderTests(unittest.TestCase):
    def build_root(self, root: Path) -> Path:
        profile = root.joinpath("Users", "alice", *CHROME)
        write_history(
            profile / "History",
            [
                "https://www.example.com/",
                "https://mail.naver.com/write/bigfile/upload",
                "https://mail.google.com/mail/u/0/?ui=2&ik=abc&attid=0.1&disp=safe",
            ],
        )
        write_simple_cache(profile / "Service Worker" / "CacheStorage" / "origin" / "cache")
        write_blockfile_cache(profile / "Cache" / "Cache_Data")
        return profile

    def test_provider_emits_cache_entries_upload_candidates_and_never_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.build_root(root)
            records = collect(root)
            cache = by_type(records, "browser-cache-entry")
            self.assertEqual(len(cache), 20)
            self.assertEqual({record.details["cache_format"] for record in cache}, {"chromium-blockfile", "chromium-cachestorage"})
            for record in cache:
                details = record.details
                self.assertEqual(details["browser"], "chrome")
                self.assertEqual(details["parser_version"], "chromium-cache-v1")
                self.assertIn("source_offset", details)
                self.assertTrue(details["source_path"])
                self.assertTrue(details["timestamp"])
            serialized = json.dumps([record.details for record in records], default=str, ensure_ascii=False)
            self.assertNotIn(BODY_MARKER.decode(), serialized)
            candidates = by_type(records, "web-upload-candidate")
            services = sorted((record.details["service"], record.details["strength"], record.details["source_artifact_type"]) for record in candidates)
            self.assertIn(("naver-mail", "strong", "browser-cache-entry"), services)  # POST cache entry
            self.assertIn(("google-drive", "strong", "browser-cache-entry"), services)
            self.assertIn(("wetransfer", "medium", "browser-cache-entry"), services)
            self.assertIn(("naver-mail", "medium", "browser-history"), services)
            # The History url row and its visit share URL and time: one candidate.
            self.assertEqual([item for item in services if item[0] == "gmail"], [("gmail", "weak", "browser-history")])
            for record in candidates:
                self.assertTrue(record.details["match_sources"])
                self.assertEqual(record.details["recovery_method"], "derived")
            drive = next(record for record in candidates if record.details["service"] == "google-drive")
            self.assertEqual(drive.details["method"], "POST")
            self.assertIsInstance(drive.details["size"], int)
            self.assertFalse(by_type(records, "browser-parse-error"))

    def test_corrupt_cache_directory_yields_one_error_row_and_keeps_the_rest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile = self.build_root(root)
            cache_dir = profile / "Service Worker" / "CacheStorage" / "origin" / "cache"
            first = sorted(cache_dir.glob("*_0"))[0]
            first.write_bytes(b"\x00" * 64)
            records = collect(root)
            errors = by_type(records, "browser-parse-error")
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].details["reason"], "cache-entries-corrupt")
            self.assertEqual(errors[0].details["corrupt_entry_count"], 1)
            self.assertEqual(len(by_type(records, "browser-cache-entry")), 19)
            self.assertTrue(by_type(records, "browser-history"))

    def test_extra_chromium_profile_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "Users" / "bob"
            roots = {
                "whale": home / "AppData" / "Local" / "Naver" / "Naver Whale" / "User Data" / "Default",
                "vivaldi": home / "AppData" / "Local" / "Vivaldi" / "User Data" / "Default",
                "brave": home / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default",
            }
            for browser, profile in roots.items():
                write_history(profile / "History", [f"https://{browser}.example.com/"])
            opera_roaming = home / "AppData" / "Roaming" / "Opera Software" / "Opera Stable"
            write_history(opera_roaming / "History", ["https://opera.example.com/"])
            write_simple_cache(home / "AppData" / "Local" / "Opera Software" / "Opera Stable" / "Cache" / "Cache_Data")
            records = collect(Path(temp))
            history = {(record.details["browser"], record.details["url"]) for record in by_type(records, "browser-history")}
            for browser in ("whale", "vivaldi", "brave", "opera"):
                self.assertIn((browser, f"https://{browser}.example.com/"), history)
            opera_cache = [record for record in by_type(records, "browser-cache-entry") if record.details["browser"] == "opera"]
            self.assertEqual(len(opera_cache), 10)
            self.assertEqual({record.details["profile"] for record in opera_cache}, {"Opera Stable"})
            # Opera's own sub-folders are not treated as profiles.
            self.assertFalse([record for record in records if record.details.get("browser") == "opera" and record.details.get("profile") == "Cache"])

    def test_cache_directory_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp)
            write_blockfile_cache(profile / "Cache" / "Cache_Data")
            write_cache_storage(profile / "Service Worker" / "CacheStorage" / "o1" / "c1")
            (profile / "Code Cache" / "js").mkdir(parents=True)
            found = chromium_cache_directories(profile)
            self.assertEqual([layout for _path, layout in found], ["chromium-blockfile", "chromium-cachestorage"])


class WebCacheTests(unittest.TestCase):
    def write(self, root: Path) -> Path:
        blob, _expected = sample_webcache()
        path = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "WebCache" / "WebCacheV01.dat"
        path.parent.mkdir(parents=True)
        path.write_bytes(blob)
        cached = path.parent.parent / "INetCache" / "IE" / "WXYZ5678" / "logo[1].gif"
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"GIF89a" + b"\x00" * 28)
        return path

    def test_decoder_maps_history_content_cookies_downloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = self.write(Path(temp))
            decoded = decode_webcache(path)
            self.assertEqual(decoded.errors, [])
            summary = decoded.summary()
            self.assertEqual(
                summary["rows_by_type"],
                {"browser-history": 3, "browser-cache-entry": 2, "browser-cookie": 2, "browser-download": 1},
            )
            domstore = next(item for item in summary["containers"] if item["name"] == "DOMStore")
            self.assertEqual((domstore["mapped_type"], domstore["row_count"]), ("", 1))

    def test_collector_emits_rows_on_existing_types(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root)
            records = list(collect_webcachev01_artifacts(root))
            inventory = by_type(records, "webcachev01-ese-file")[0]
            self.assertEqual(inventory.details["webcache_decode"]["row_count"], 8)
            history = by_type(records, "browser-history")
            first = next(record for record in history if record.details["entry_id"] == 11)
            self.assertEqual(first.details["url"], "https://intranet.example.com/home")
            self.assertEqual(first.details["webcache_user"], "alice")
            self.assertEqual(first.details["visit_count"], 3)
            self.assertEqual(first.details["timestamp"], "2024-07-01T10:05:00+00:00")
            self.assertEqual(first.details["browser"], "ie-edge-legacy")
            self.assertEqual(first.details["user"], "alice")
            self.assertIsInstance(first.details["source_offset"], int)
            content = {record.details["url"]: record.details for record in by_type(records, "browser-cache-entry")}
            gif = content["https://www.example.com/logo.gif"]
            self.assertEqual((gif["http_status"], gif["content_type"], gif["body_signature"]), (200, "image/gif", "gif"))
            self.assertEqual(gif["body_status"], "hashed")
            self.assertEqual(len(str(gif["body_sha256"])), 64)
            self.assertEqual(content["https://www.example.com/missing.js"]["body_status"], "cached-file-not-found")
            cookies = {record.details["host"]: record.details for record in by_type(records, "browser-cookie")}
            self.assertEqual(set(cookies), {"example.com", "shop.example.org"})
            self.assertEqual(cookies["shop.example.org"]["path"], "/cart")
            (download,) = by_type(records, "browser-download")
            self.assertEqual(download.details["source_url"], "https://files.example.com/setup.exe")
            self.assertEqual(download.details["target_path"], r"C:\Users\alice\Downloads\setup.exe")

    def test_corrupt_webcache_keeps_inventory_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.write(root)
            path.write_bytes(path.read_bytes()[:6000])
            records = list(collect_webcachev01_artifacts(root))
            self.assertEqual(len(by_type(records, "webcachev01-ese-file")), 1)
            self.assertFalse(by_type(records, "browser-history"))
            path.write_bytes(b"\x00" * 100)
            records = list(collect_webcachev01_artifacts(root))
            self.assertEqual(len(by_type(records, "webcachev01-ese-file")), 1)
            self.assertEqual(len(by_type(records, "browser-parse-error")), 1)

    def test_webcache_upload_url_becomes_a_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write(root)
            candidates = by_type(collect(root), "web-upload-candidate")
            self.assertEqual([(c.details["service"], c.details["browser"]) for c in candidates], [("naver-mail", "ie-edge-legacy")])


class UploadPatternTests(unittest.TestCase):
    def test_pattern_file_loads_with_https_sources(self) -> None:
        patterns = load_upload_patterns()
        self.assertGreaterEqual(len(patterns), 10)
        self.assertEqual({pattern.category for pattern in patterns}, {"webmail", "filesharing", "cloud"})
        for pattern in patterns:
            self.assertTrue(all(source.startswith("https://") for source in pattern.sources), pattern.id)

    def test_matching(self) -> None:
        patterns = load_upload_patterns()
        cases = [
            ("https://mail.naver.com/json/write/upload", "GET", ("naver-mail", "medium")),
            ("https://mail.naver.com/json/write/upload", "POST", ("naver-mail", "strong")),
            ("https://bigfile.mail.daum.net/upload?x=1", "GET", ("daum-mail", "medium")),
            ("https://mail.google.com/mail/u/1/?ui=2&ik=x&attid=0.2", "GET", ("gmail", "weak")),
            ("https://content.dropboxapi.com/2/files/upload", "POST", ("dropbox", "strong")),
            ("https://www.webhard.co.kr/pages/fileup.php", "GET", ("webhard", "medium")),
            ("https://my.webhard-example.com/anything", "POST", ("webhard", "medium")),
            ("https://send-anywhere.com/web/key", "GET", ("sendanywhere", "medium")),
        ]
        for url, method, expected in cases:
            matched = match_upload_url(url, method, patterns)
            self.assertIsNotNone(matched, url)
            assert matched is not None
            self.assertEqual((matched[0].service, matched[1]), expected, url)
        for url in (
            "https://mail.naver.com/v2/folders/0",
            "https://www.example.com/upload",
            "https://my.webhard-example.com/anything",
            "https://evil-mail.naver.com.example.net/upload",
            "ftp://mail.naver.com/upload",
        ):
            self.assertIsNone(match_upload_url(url, "GET", patterns), url)

    def test_malformed_pattern_file_is_rejected_in_korean(self) -> None:
        with self.assertRaisesRegex(UploadPatternError, "sources"):
            parse_upload_patterns(
                b"patterns:\n- id: x\n  category: webmail\n  strength: weak\n  hosts: [a.com]\n  path_regex: up\n  sources: [http://a]\n"
            )
        with self.assertRaisesRegex(UploadPatternError, "path_regex"):
            parse_upload_patterns(b"patterns:\n- id: x\n  category: webmail\n  strength: weak\n  hosts: [a.com]\n  sources: [https://a]\n")


class CatalogTests(unittest.TestCase):
    def test_new_types_have_a_family_with_semantic_columns(self) -> None:
        from rapidtriage.core.triage_rules.catalog import load_catalog

        catalog = load_catalog()
        self.assertEqual(catalog.family_for("browser-cache-entry", "browser"), "browser-cache-entry")
        self.assertEqual(catalog.family_for("web-upload-candidate", "browser"), "web-upload-candidate")
        families = {family["id"]: family for family in catalog.families}
        for family_id in ("browser-cache-entry", "web-upload-candidate"):
            columns = [*families[family_id]["core_columns"], *families[family_id]["aux_columns"]]
            semantics = {column.get("semantic") for column in columns}
            self.assertTrue({"url", "attachment"} <= semantics, family_id)
            self.assertTrue(all(any("가" <= char <= "힣" for char in column["label"]) or "(" in column["label"] for column in columns))
        self.assertEqual(catalog.specs["browser.webmail_upload"].grade, "B")
        self.assertEqual(catalog.specs["browser.filesharing_upload"].grade, "B")


class RunPipelineTests(unittest.TestCase):
    def test_run_writes_cache_entries_upload_candidates_and_flags(self) -> None:
        from rapidtriage.artifacts import clear_collect_cache
        from rapidtriage.core.run import run_triage_mode

        clear_collect_cache()
        self.addCleanup(clear_collect_cache)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "case-root"
            ProviderTests().build_root(root)
            output_dir = Path(temp) / "run-out"
            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir)
            browser_output = json.loads(Path(summary["outputs"]["artifacts_browser"]).read_text(encoding="utf-8"))
            counts = browser_output["summary"]["artifact_type_counts"]
            self.assertEqual(counts["browser-cache-entry"], 20)
            self.assertGreaterEqual(counts["web-upload-candidate"], 4)
            step = next(item for item in summary["steps"] if item["name"] == "triage-flags")
            self.assertEqual(step["status"], "completed", step)
            flags = (output_dir / "analyses" / str(step["analysis_id"]) / "flags.jsonl").read_text(encoding="utf-8")
            self.assertIn("browser.webmail_upload", flags)
            self.assertIn("browser.filesharing_upload", flags)
            # 통합 보기: cache-entry URLs feed the URL table, Content-Disposition names the 첨부 table.
            (derived_dir,) = sorted((output_dir / "analyses").glob("run-derived-*"))
            urls = (derived_dir / "urls.jsonl").read_text(encoding="utf-8")
            self.assertIn("browser-cache-entry", urls)
            self.assertIn("cdn.example.net", urls)
            attachments = (derived_dir / "attachments.jsonl").read_text(encoding="utf-8")
            self.assertIn("report.pdf", attachments)
            self.assertIn("web-upload-candidate", urls)


if __name__ == "__main__":
    unittest.main()
