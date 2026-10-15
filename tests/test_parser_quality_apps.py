"""Parser-quality round 1, W5 (application/user data) regression tests.

All fixtures are synthetic and built in temporary directories; none of the
evidence used for the review is needed to run them.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.windows.browser import (
    WindowsBrowserArtifactsProvider,
    snss_parse_navigation,
    webkit_micros_to_iso,
)
from rapidtriage.core import sqlite_snapshot
from rapidtriage.core.sqlite_snapshot import (
    SqliteSnapshotError,
    classify_rollback_journal,
    open_sqlite_snapshot,
)

WEBKIT_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)


def webkit(moment: dt.datetime) -> int:
    delta = moment - WEBKIT_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def inventory(root: Path) -> dict[str, tuple[str, int, int]]:
    rows = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            stat = path.stat()
            rows[str(path.relative_to(root))] = (hashlib.sha256(path.read_bytes()).hexdigest(), stat.st_mtime_ns, stat.st_size)
    return rows


class SqliteJournalSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def make_db(self, path: Path, *, journal_mode: str = "DELETE", rows: int = 200) -> sqlite3.Connection:
        connection = sqlite3.connect(path, isolation_level=None)
        connection.execute(f"PRAGMA journal_mode={journal_mode}")
        connection.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, body TEXT)")
        connection.execute("BEGIN")
        connection.executemany("INSERT INTO t VALUES (?, ?)", [(index, "가" * 400) for index in range(rows)])
        connection.execute("COMMIT")
        return connection

    def test_zero_header_committed_journal_is_ignored(self) -> None:
        producer = self.root / "producer.db"
        connection = self.make_db(producer, journal_mode="PERSIST")
        connection.execute("UPDATE t SET body = 'committed' WHERE id = 1")
        connection.close()
        journal = Path(str(producer) + "-journal")
        self.assertTrue(journal.exists())
        self.assertGreater(journal.stat().st_size, 0)
        self.assertEqual(bytes(28), journal.read_bytes()[:28])  # PERSIST zeroes the header on commit
        target = self.evidence / "History"
        shutil.copyfile(producer, target)
        shutil.copyfile(journal, Path(str(target) + "-journal"))
        before = inventory(self.evidence)
        self.assertEqual("committed-or-invalid", classify_rollback_journal(Path(str(target) + "-journal"))["status"])
        provenance: dict[str, object] = {}
        with open_sqlite_snapshot(target, provenance=provenance) as snapshot:
            self.assertEqual("committed", snapshot.execute("SELECT body FROM t WHERE id = 1").fetchone()[0])
        self.assertEqual("committed-or-invalid", provenance["journal_status"])
        self.assertEqual("zeroed-header", provenance["journal_reason"])
        self.assertEqual(before, inventory(self.evidence))

    def test_real_hot_journal_is_rejected(self) -> None:
        producer = self.root / "producer.db"
        connection = self.make_db(producer, rows=400)
        connection.execute("PRAGMA cache_size=1")
        connection.execute("BEGIN")
        connection.execute("UPDATE t SET body = 'uncommitted'")
        journal = Path(str(producer) + "-journal")
        target = self.evidence / "History"
        # Copy while the write transaction is open: the journal is hot.
        shutil.copyfile(producer, target)
        shutil.copyfile(journal, Path(str(target) + "-journal"))
        connection.execute("ROLLBACK")
        connection.close()
        status = classify_rollback_journal(Path(str(target) + "-journal"))
        self.assertTrue(status["hot"], status)
        before = inventory(self.evidence)
        with mock.patch.object(sqlite_snapshot.sqlite3, "connect") as connect:
            with self.assertRaisesRegex(SqliteSnapshotError, "hot journal"):
                with open_sqlite_snapshot(target):
                    self.fail("snapshot yielded")
            connect.assert_not_called()
        self.assertEqual(before, inventory(self.evidence))

    def test_magic_with_zero_records_is_not_hot(self) -> None:
        journal = self.evidence / "x-journal"
        journal.write_bytes(bytes.fromhex("d9d505f920a163d7") + bytes(4) + bytes(12) + (512).to_bytes(4, "big") + (4096).to_bytes(4, "big") + bytes(600))
        self.assertFalse(classify_rollback_journal(journal)["hot"])
        journal.write_bytes(bytes.fromhex("d9d505f920a163d7") + (3).to_bytes(4, "big") + bytes(1000))
        self.assertTrue(classify_rollback_journal(journal)["hot"])

    def test_wal_snapshot_reads_wal_rows_without_touching_source(self) -> None:
        producer = self.root / "producer.db"
        connection = sqlite3.connect(producer, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE t(v TEXT)")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("INSERT INTO t VALUES ('WAL 전용 행')")
        target = self.evidence / "History"
        shutil.copyfile(producer, target)
        shutil.copyfile(Path(str(producer) + "-wal"), Path(str(target) + "-wal"))
        connection.close()
        before = inventory(self.evidence)
        provenance: dict[str, object] = {}
        with open_sqlite_snapshot(target, provenance=provenance) as snapshot:
            self.assertEqual("WAL 전용 행", snapshot.execute("SELECT v FROM t").fetchone()[0])
        self.assertTrue(provenance["wal_included"])
        self.assertEqual(before, inventory(self.evidence))
        self.assertFalse(Path(str(target) + "-shm").exists())

    def test_database_only_copy_is_opened_immutable(self) -> None:
        target = self.evidence / "plain.db"
        self.make_db(target, rows=2).close()
        original = sqlite3.connect
        uris: list[str] = []

        def connect(database, **kwargs):
            uris.append(str(database))
            return original(database, **kwargs)

        with mock.patch.object(sqlite_snapshot.sqlite3, "connect", side_effect=connect):
            with open_sqlite_snapshot(target) as snapshot:
                self.assertEqual(2, snapshot.execute("SELECT COUNT(*) FROM t").fetchone()[0])
        self.assertTrue(uris and "immutable=1" in uris[0])
        self.assertNotIn(str(self.evidence.as_uri()), uris[0])


def _pickle_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<i", len(raw)) + raw + bytes((-len(raw)) % 4)


def _pickle_string16(text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<i", len(text)) + raw + bytes((-len(raw)) % 4)


def snss_navigation(tab_id: int, index: int, url: str, title: str, when: dt.datetime, transition: int = 1) -> bytes:
    body = (
        struct.pack("<ii", tab_id, index)
        + _pickle_string(url)
        + _pickle_string16(title)
        + _pickle_string("")  # page state
        + struct.pack("<ii", transition, 0)
        + _pickle_string("")  # referrer
        + struct.pack("<i", 0)
        + _pickle_string("")  # original request url
        + struct.pack("<i", 0)
        + struct.pack("<q", webkit(when))
        + struct.pack("<i", 200)
    )
    payload = struct.pack("<I", len(body)) + body
    return struct.pack("<H", len(payload) + 1) + bytes([6]) + payload


class EdgeProfileRowsTests(unittest.TestCase):
    VISIT_TIME = dt.datetime(2025, 3, 4, 1, 8, 53, 790224, tzinfo=dt.timezone.utc)
    COOKIE_SECRET = "cookie-secret-value-123"
    PASSWORD_SECRET = b"password-secret-blob"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "image"
        self.profile = self.root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default"
        self.profile.mkdir(parents=True)
        self.build_history()
        self.build_cookies()
        self.build_logins()
        self.build_web_data()
        self.build_small_stores()

    def sqlite(self, path: Path, script: str, rows: dict[str, list[tuple]] | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.executescript(script)
        for table, values in (rows or {}).items():
            if values:
                marks = ",".join("?" * len(values[0]))
                connection.executemany(f"INSERT INTO {table} VALUES ({marks})", values)
        connection.commit()
        connection.close()

    def build_history(self) -> None:
        t0 = webkit(self.VISIT_TIME)
        self.sqlite(
            self.profile / "History",
            """
            CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
            CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,opener_visit INTEGER, external_referrer_url TEXT);
            CREATE TABLE downloads (id INTEGER PRIMARY KEY,guid VARCHAR NOT NULL,current_path LONGVARCHAR NOT NULL,target_path LONGVARCHAR NOT NULL,start_time INTEGER NOT NULL,received_bytes INTEGER NOT NULL,total_bytes INTEGER NOT NULL,state INTEGER NOT NULL,danger_type INTEGER NOT NULL,interrupt_reason INTEGER NOT NULL,hash BLOB NOT NULL,end_time INTEGER NOT NULL,opened INTEGER NOT NULL,last_access_time INTEGER NOT NULL,transient INTEGER NOT NULL,referrer VARCHAR NOT NULL,site_url VARCHAR NOT NULL,tab_url VARCHAR NOT NULL,tab_referrer_url VARCHAR NOT NULL,http_method VARCHAR NOT NULL,by_ext_id VARCHAR NOT NULL,by_ext_name VARCHAR NOT NULL,etag VARCHAR NOT NULL,last_modified VARCHAR NOT NULL,mime_type VARCHAR(255) NOT NULL,original_mime_type VARCHAR(255) NOT NULL);
            CREATE TABLE downloads_url_chains (id INTEGER NOT NULL,chain_index INTEGER NOT NULL,url LONGVARCHAR NOT NULL, PRIMARY KEY (id, chain_index));
            CREATE TABLE keyword_search_terms (keyword_id INTEGER NOT NULL,url_id INTEGER NOT NULL,term LONGVARCHAR NOT NULL,normalized_term LONGVARCHAR NOT NULL);
            """,
            {
                "urls": [
                    (1, "https://www.naver.com/", "네이버 메인", 2, 1, t0 + 5_000_000, 0),
                    (2, "https://search.naver.com/search.naver?query=%EC%A7%84%EB%A3%8C", "진료 : 네이버 검색", 1, 0, t0 + 9_000_000, 0),
                ],
                "visits": [
                    (10, 1, t0, 0, 0x30000001, 0, 1_618_632, 0, ""),
                    (11, 1, t0 + 5_000_000, 0, 0x01000000 | 8, 0, 0, 0, ""),
                    (12, 2, t0 + 9_000_000, 11, 0x20000000, 0, 2_000_000, 0, "https://ref.example/"),
                ],
                "downloads": [
                    (
                        7, "guid-7", "C:\\Users\\alice\\Downloads\\계약서.pdf", "C:\\Users\\alice\\Downloads\\계약서.pdf",
                        t0 + 1_000_000, 900, 1000, 4, 3, 40, b"", t0 + 2_000_000, 1, t0 + 3_000_000, 0,
                        "https://ref.example/page", "https://files.example/", "https://files.example/list", "", "GET",
                        "", "", "", "", "application/pdf", "application/pdf",
                    )
                ],
                "downloads_url_chains": [(7, 0, "https://files.example/a"), (7, 1, "https://cdn.example/a.pdf")],
                "keyword_search_terms": [(2, 2, "진료", "진료")],
            },
        )
        # Committed, zeroed-header rollback journal (as left by PERSIST mode).
        Path(str(self.profile / "History") + "-journal").write_bytes(bytes(4096))

    def build_cookies(self) -> None:
        t0 = webkit(self.VISIT_TIME)
        self.sqlite(
            self.profile / "Network" / "Cookies",
            "CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,top_frame_site_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,encrypted_value BLOB NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL,is_persistent INTEGER NOT NULL,priority INTEGER NOT NULL,samesite INTEGER NOT NULL,source_scheme INTEGER NOT NULL,source_port INTEGER NOT NULL,last_update_utc INTEGER NOT NULL);",
            {
                "cookies": [
                    (t0, ".naver.com", "", "NID_SES", self.COOKIE_SECRET, b"", "/", t0 + 10**12, 1, 1, t0 + 1, 1, 1, 1, 1, 2, 443, t0 + 2),
                    (t0 + 5, "example.com", "", "sess", "", b"v10encrypted", "/", 0, 0, 0, t0 + 6, 0, 0, 1, -1, 2, 443, t0 + 7),
                ]
            },
        )

    def build_logins(self) -> None:
        t0 = webkit(self.VISIT_TIME)
        self.sqlite(
            self.profile / "Login Data",
            "CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, submit_element VARCHAR, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, blacklisted_by_user INTEGER NOT NULL, scheme INTEGER NOT NULL, password_type INTEGER, times_used INTEGER, id INTEGER PRIMARY KEY AUTOINCREMENT, date_last_used INTEGER NOT NULL DEFAULT 0, date_password_modified INTEGER NOT NULL DEFAULT 0);",
            {
                "logins": [
                    ("https://nid.naver.com/", "https://nid.naver.com/login", "id", "홍길동", "pw", self.PASSWORD_SECRET, "", "https://nid.naver.com/", t0, 0, 0, 0, 3, 1, t0 + 100, 0),
                ]
            },
        )

    def build_web_data(self) -> None:
        self.sqlite(
            self.profile / "Web Data",
            """
            CREATE TABLE autofill (name VARCHAR, value VARCHAR, value_lower VARCHAR, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, count INTEGER DEFAULT 1, PRIMARY KEY (name, value));
            CREATE TABLE credit_cards (guid VARCHAR PRIMARY KEY, name_on_card VARCHAR, expiration_month INTEGER, expiration_year INTEGER, card_number_encrypted BLOB, date_modified INTEGER NOT NULL DEFAULT 0, origin VARCHAR DEFAULT '', use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, billing_address_id VARCHAR, nickname VARCHAR);
            CREATE TABLE masked_credit_cards (id VARCHAR, name_on_card VARCHAR, network VARCHAR, last_four VARCHAR, exp_month INTEGER, exp_year INTEGER);
            CREATE TABLE addresses (guid VARCHAR PRIMARY KEY, use_count INTEGER NOT NULL DEFAULT 0, use_date INTEGER NOT NULL DEFAULT 0, date_modified INTEGER NOT NULL DEFAULT 0, language_code VARCHAR, label VARCHAR);
            CREATE TABLE address_type_tokens (guid VARCHAR, type INTEGER, value VARCHAR, verification_status INTEGER DEFAULT 0, observations BLOB, PRIMARY KEY (guid, type));
            CREATE TABLE autofill_edge_field_client_info (field_id VARCHAR PRIMARY KEY, label VARCHAR, domain_value VARCHAR, date_created INTEGER DEFAULT 0);
            CREATE TABLE autofill_edge_field_values (field_id VARCHAR, value VARCHAR, count INTEGER DEFAULT 1, date_created INTEGER DEFAULT 0, date_last_used INTEGER DEFAULT 0, submission_source INTEGER NOT NULL DEFAULT 0, is_masked BOOLEAN NOT NULL DEFAULT FALSE, PRIMARY KEY (field_id, value));
            """,
            {
                "autofill": [
                    ("usrId", "alice01", "alice01", 1707990777, 1744865309, 2),
                    ("userPassword", "hunter2-pw", "hunter2-pw", 1707990778, 1707990778, 1),
                ],
                "credit_cards": [("card-1", "홍길동", 2, 2029, b"\x01\x02encrypted-card", 1740022497, "", 2, 1740022535, "", "")],
                "masked_credit_cards": [("card-1", "홍길동", "visa", "4242", 2, 2029)],
                "addresses": [("addr-1", 1, 1719634502, 1719634486, "ko", "")],
                "address_type_tokens": [("addr-1", 9, "alice@example.com", 0, b""), ("addr-1", 33, "서울특별시", 0, b"")],
                "autofill_edge_field_client_info": [("f1", "인증서 암호", "is.kdca.go.kr", 0), ("f2", "면허번호", "hurb.or.kr", 0)],
                "autofill_edge_field_values": [("f1", "cert-secret-77", 137, 1698487799, 1724461459, 0, 0), ("f2", "12345", 4, 1703302662, 1711893550, 0, 0)],
            },
        )

    def build_small_stores(self) -> None:
        t0 = webkit(self.VISIT_TIME)
        self.sqlite(
            self.profile / "Shortcuts",
            "CREATE TABLE omni_box_shortcuts (id VARCHAR PRIMARY KEY, text VARCHAR, fill_into_edit VARCHAR, url VARCHAR, document_type INTEGER, contents VARCHAR, contents_class VARCHAR, description VARCHAR, description_class VARCHAR, transition INTEGER, type INTEGER, keyword VARCHAR, last_access_time INTEGER, number_of_hits INTEGER);",
            {"omni_box_shortcuts": [("s1", "nav", "naver.com", "https://www.naver.com/", 0, "naver.com", "", "네이버", "", 1, 0, "", t0, 4)]},
        )
        self.sqlite(
            self.profile / "Top Sites",
            'CREATE TABLE "top_sites"(url TEXT NOT NULL PRIMARY KEY,url_rank INTEGER NOT NULL,title TEXT NOT NULL);',
            {"top_sites": [("https://www.naver.com/", 0, "NAVER")]},
        )
        bookmarks = {
            "roots": {
                "bookmark_bar": {
                    "type": "folder",
                    "name": "즐겨찾기 모음",
                    "children": [
                        {"type": "url", "id": "3", "name": "질병관리청", "url": "https://is.kdca.go.kr/", "date_added": str(t0), "date_last_used": "0"}
                    ],
                },
                "other": {"type": "folder", "name": "기타", "children": []},
            }
        }
        (self.profile / "Bookmarks").write_text(json.dumps(bookmarks, ensure_ascii=False), encoding="utf-8")
        secure = {
            "extensions": {
                "settings": {
                    "abcdefghijklmnopabcdefghijklmnop": {
                        "first_install_time": str(t0),
                        "last_update_time": str(t0 + 1),
                        "from_webstore": True,
                        "location": 1,
                        "state": 1,
                    },
                    "residualonlyresidualonlyresidual": {"account_extension_type": 0},
                }
            }
        }
        (self.profile / "Secure Preferences").write_text(json.dumps(secure), encoding="utf-8")
        extension_dir = self.profile / "Extensions" / "abcdefghijklmnopabcdefghijklmnop" / "1.2.3_0"
        (extension_dir / "_locales" / "ko").mkdir(parents=True)
        (extension_dir / "manifest.json").write_text(
            json.dumps({"name": "__MSG_extName__", "version": "1.2.3", "default_locale": "ko", "manifest_version": 3, "permissions": ["tabs", "storage"], "host_permissions": ["<all_urls>"]}),
            encoding="utf-8",
        )
        (extension_dir / "_locales" / "ko" / "messages.json").write_text(
            json.dumps({"extName": {"message": "번역 도우미"}}, ensure_ascii=False), encoding="utf-8"
        )
        (self.profile / "Preferences").write_bytes(b'{"a":1}' + bytes(10_000))
        sessions = self.profile / "Sessions"
        sessions.mkdir()
        session = b"SNSS" + struct.pack("<i", 3)
        session += snss_navigation(25, 0, "https://statement.example/detective", "형사 진술서", self.VISIT_TIME)
        session += snss_navigation(25, 0, "https://statement.example/detective", "형사 진술서", self.VISIT_TIME)
        session += struct.pack("<H", 5) + bytes([8]) + b"\x00\x00\x00\x00"
        (sessions / f"Session_{t0}").write_bytes(session)

    def collect(self):
        return list(WindowsBrowserArtifactsProvider().collect(self.root))

    def by_type(self, records):
        result: dict[str, list] = {}
        for record in records:
            result.setdefault(record.artifact_type, []).append(record)
        return result

    def test_profile_rows_cover_all_stores_without_secrets(self) -> None:
        before = inventory(self.root)
        records = self.collect()
        self.assertEqual(before, inventory(self.root), "evidence files changed during collection")
        types = self.by_type(records)
        self.assertEqual(2, len(types["browser-history"]))
        self.assertEqual(3, len(types["browser-visit"]))
        self.assertEqual(1, len(types["browser-download"]))
        self.assertEqual(1, len(types["browser-search"]))
        self.assertEqual(2, len(types["browser-cookie"]))
        self.assertEqual(1, len(types["browser-login"]))
        self.assertEqual(4, len(types["browser-autofill"]))
        self.assertEqual(1, len(types["browser-credit-card"]))
        self.assertEqual(1, len(types["browser-autofill-address"]))
        self.assertEqual(1, len(types["browser-omnibox-shortcut"]))
        self.assertEqual(1, len(types["browser-top-site"]))
        self.assertEqual(1, len(types["browser-bookmark"]))
        self.assertEqual(1, len(types["browser-session-tab"]))
        self.assertEqual(2, len(types["browser-extension"]))
        self.assertEqual(1, len(types["browser-history-downloads"]))
        self.assertNotIn("browser-parse-error", types)

        visit = next(r.details for r in types["browser-visit"] if r.details["source_row_id"] == 10)
        self.assertEqual("네이버 메인", visit["title"])
        self.assertEqual("2025-03-04T01:08:53.790224+00:00", visit["timestamp"])
        self.assertEqual("visited", visit["timestamp_kind"])
        self.assertEqual("TYPED", visit["transition_core"])
        self.assertEqual(["CHAIN_START", "CHAIN_END"], visit["transition_qualifiers"])
        self.assertEqual(1_618_632, visit["visit_duration_micros"])
        hop = next(r.details for r in types["browser-visit"] if r.details["source_row_id"] == 12)
        self.assertEqual(11, hop["from_visit"])
        self.assertEqual("https://www.naver.com/", hop["from_url"])

        download = types["browser-download"][0].details
        self.assertEqual("C:\\Users\\alice\\Downloads\\계약서.pdf", download["target_path"])
        self.assertEqual(900, download["received_bytes"])
        self.assertEqual("INTERRUPTED", download["state_name"])
        self.assertEqual("DANGEROUS_CONTENT", download["danger_type_name"])
        self.assertEqual("application/pdf", download["mime_type"])
        self.assertEqual(["https://files.example/a", "https://cdn.example/a.pdf"], download["url_chain"])
        self.assertTrue(download["opened"])
        self.assertEqual(webkit_micros_to_iso(webkit(self.VISIT_TIME) + 1_000_000), download["timestamp"])

        self.assertEqual("진료", types["browser-search"][0].details["term"])
        cookie = next(r.details for r in types["browser-cookie"] if r.details["name"] == "NID_SES")
        self.assertTrue(cookie["value_present"])
        self.assertFalse(cookie["value_encrypted"])
        self.assertEqual("LAX", cookie["samesite"])
        session_cookie = next(r.details for r in types["browser-cookie"] if r.details["name"] == "sess")
        self.assertTrue(session_cookie["session_cookie"])
        self.assertIsNone(session_cookie["expires_at"])
        login = types["browser-login"][0].details
        self.assertEqual("홍길동", login["username"])
        self.assertEqual(3, login["times_used"])
        self.assertTrue(login["password_stored"])
        card = types["browser-credit-card"][0].details
        self.assertEqual("**** **** **** 4242", card["card_number_masked"])
        self.assertEqual("[마스킹됨]", card["name_on_card"])  # personal name: masked (parser-quality r2)
        autofill = {r.details["field_name"]: r.details for r in types["browser-autofill"]}
        # parser-quality r3: autofill values are masked by default (sha256 kept).
        self.assertEqual("[마스킹됨]", autofill["usrId"]["value_preview"])
        self.assertEqual("form-input-default", autofill["usrId"]["mask_reason"])
        self.assertEqual("[마스킹됨]", autofill["userPassword"]["value_preview"])
        self.assertEqual("2024-02-15T09:52:57+00:00", autofill["usrId"]["timestamp"])
        self.assertEqual("[마스킹됨]", autofill["인증서 암호"]["value_preview"])
        self.assertEqual("[마스킹됨]", autofill["면허번호"]["value_preview"])
        self.assertEqual("hurb.or.kr", autofill["면허번호"]["domain"])
        address = types["browser-autofill-address"][0].details
        self.assertEqual({"EMAIL_ADDRESS", "ADDRESS_HOME_CITY"}, {item["field_name"] for item in address["address_fields"]})
        extension = next(r.details for r in types["browser-extension"] if r.details["on_disk"])
        self.assertEqual("번역 도우미", extension["name"])
        self.assertEqual(["<all_urls>", "storage", "tabs"], extension["permissions"])
        self.assertTrue(extension["from_webstore"])
        self.assertEqual("INTERNAL", extension["location_name"])
        self.assertEqual("installed", extension["timestamp_kind"])
        residual = next(r.details for r in types["browser-extension"] if not r.details["on_disk"])
        self.assertTrue(residual["settings_residual_only"])
        tab = types["browser-session-tab"][0].details
        self.assertEqual("형사 진술서", tab["title"])
        self.assertEqual("2025-03-04T01:08:53.790224+00:00", tab["timestamp"])
        bookmark = types["browser-bookmark"][0].details
        self.assertEqual("즐겨찾기 모음", bookmark["folder"])
        self.assertIsNone(bookmark["date_last_used"])
        anomaly = types["browser-acquisition-anomaly"][0].details
        self.assertEqual("null-filled-file", anomaly["anomaly"])
        self.assertTrue(anomaly["source_path"].endswith("Preferences"))

        row_types = [record for record in records if record.details.get("parser") == "browser-profile-rows-v1"]
        self.assertTrue(all("timestamp" in record.details for record in row_types))
        serialized = json.dumps([record.to_dict() for record in records], ensure_ascii=False, default=str)
        self.assertNotIn(self.COOKIE_SECRET, serialized)
        self.assertNotIn(self.PASSWORD_SECRET.decode(), serialized)
        self.assertNotIn("hunter2-pw", serialized)
        self.assertNotIn("cert-secret-77", serialized)
        self.assertNotIn("encrypted-card", serialized)

    def test_unified_timeline_is_not_capped(self) -> None:
        connection = sqlite3.connect(self.profile / "History")
        base = webkit(self.VISIT_TIME)
        connection.executemany(
            "INSERT INTO urls(url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (?, ?, 1, 0, ?, 0)",
            [(f"https://example.com/{index}", f"페이지 {index}", base + index) for index in range(1_200)],
        )
        connection.commit()
        connection.close()
        summary = next(r for r in self.collect() if r.artifact_type == "browser-history-downloads")
        self.assertEqual(1_202, summary.details["history_count"])
        self.assertEqual(1_203, summary.details["unified_timeline_count"])

    def test_corrupt_history_records_parse_error_and_keeps_inventory(self) -> None:
        (self.profile / "History").write_bytes(b"SQLite format 3\x00" + b"\xff" * 2000)
        Path(str(self.profile / "History") + "-journal").unlink()
        types = self.by_type(self.collect())
        errors = [r.details for r in types["browser-parse-error"]]
        self.assertTrue(any(error["source_path"].endswith("History") and error["parser_error"] for error in errors))
        self.assertIn("browser-storage-inventory", types)
        self.assertNotIn("browser-history-downloads", types)
        self.assertEqual(2, len(types["browser-cookie"]))

    def test_snss_navigation_rejects_garbage(self) -> None:
        self.assertIsNone(snss_parse_navigation(b"\x00" * 8))
        self.assertIsNone(snss_parse_navigation(struct.pack("<Iii", 20, 1, 0) + _pickle_string("not a url")))


if __name__ == "__main__":
    unittest.main()
