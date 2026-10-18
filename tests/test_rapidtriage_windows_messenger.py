"""windows-messenger provider (plan r2-communication §3.1 M1; QA Q-R2-1, Q-R2-8).

Synthetic fixtures only (``tests/messenger_fixtures.py``): every app store is
generated in code. Covers the pure-Python LevelDB/Snappy reader, the V8/JSON
carving, per-app rows for all nine apps, corrupt-input isolation, caps, the
catalogue mapping, and that runs schedule the provider.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import struct
import tempfile
import time
import tracemalloc
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts import artifact_collectors, clear_collect_cache
from rapidtriage.artifacts.windows import messenger as messenger_module
from rapidtriage.artifacts.windows.leveldb import (
    MAX_KEY_BYTES,
    LevelDBError,
    ReadStats,
    SnappyError,
    iter_block_entries,
    iter_log_records,
    iter_table_records,
    snappy_decompress,
)
from rapidtriage.artifacts.windows.messenger import (
    PARSER_VERSION,
    MessengerLimits,
    WindowsMessengerProvider,
    classify_object,
    decode_v8_value,
    json_fragments,
    parse_chat_time,
    parse_zoom_chat_log,
    v8_key_objects,
)
from rapidtriage.core.artifacts import run_artifact_collection
from rapidtriage.core.run import RUN_PROFILES, SUPPORTED_RUN_MODES
from rapidtriage.core.triage_rules.catalog import load_catalog
from tests import messenger_fixtures as fx

DATA_TYPES = ("chat-message", "chat-attachment", "chat-contact")


def collect(root: Path, limits: MessengerLimits | None = None) -> list[dict[str, object]]:
    return [record.to_dict() for record in WindowsMessengerProvider(limits).collect(root)]


def by_app(rows: list[dict[str, object]], app_id: str, artifact_type: str | None = None) -> list[dict[str, object]]:
    return [
        row
        for row in rows
        if row["details"]["app_id"] == app_id and (artifact_type is None or row["artifact_type"] == artifact_type)  # type: ignore[index]
    ]


def details(row: dict[str, object]) -> dict[str, object]:
    return row["details"]  # type: ignore[return-value]


class SnappyAndLevelDBTests(unittest.TestCase):
    def test_snappy_round_trip_with_overlapping_copies(self) -> None:
        for data in (b"", b"a", b"abcd" * 500, "가나다라마바사".encode() * 300, fx.pseudo_random(5000) + b"xyz" * 900):
            with self.subTest(size=len(data)):
                self.assertEqual(snappy_decompress(fx.snappy_compress(data)), data)
        # Hand-made stream: literal "ab" then a copy-1 of length 6 at offset 2 (period-2 overlap).
        self.assertEqual(snappy_decompress(bytes([8, 1 << 2]) + b"ab" + bytes([((6 - 4) << 2) | 1, 2])), b"abababab")

    def test_snappy_rejects_damage_and_oversized_output(self) -> None:
        with self.assertRaises(SnappyError):
            snappy_decompress(bytes([4, ((4 - 4) << 2) | 1, 9]))  # copy before any output
        with self.assertRaises(SnappyError):
            snappy_decompress(bytes([10, 3 << 2]) + b"ab")  # literal runs past the input
        with self.assertRaises(SnappyError):
            snappy_decompress(fx.varint(1 << 30) + b"\x00a", max_output=1024)

    def test_log_reader_assembles_fragments_across_blocks_and_counts_damage(self) -> None:
        big = b"V" * 80_000  # spans three 32 KiB blocks: FIRST, MIDDLE, LAST
        log = fx.leveldb_log([fx.write_batch(7, [(b"k1", b"v1"), (b"k2", None)]), fx.write_batch(9, [(b"big", big)])])
        stats = ReadStats()
        records = list(iter_log_records(log, stats))
        self.assertEqual([(r.user_key, r.sequence, r.deleted) for r in records], [(b"k1", 7, False), (b"k2", 8, True), (b"big", 9, False)])
        self.assertEqual(records[2].value, big)
        self.assertTrue(all(record.checksum_ok for record in records))
        self.assertEqual(stats.deletions, 1)
        # Flip one payload byte: the record is still read but its checksum is reported.
        damaged = bytearray(log)
        damaged[20] ^= 0xFF
        stats = ReadStats()
        list(iter_log_records(bytes(damaged), stats))
        self.assertEqual(stats.checksum_mismatches, 1)
        # A garbage header never loops or raises: counted as a corrupt fragment.
        stats = ReadStats()
        self.assertEqual(list(iter_log_records(b"\x01\x02\x03\x04\xff\xff\x09garbage", stats)), [])
        self.assertEqual(stats.corrupt_fragments, 1)

    def test_table_reader_reads_snappy_blocks_deletions_and_isolates_a_bad_block(self) -> None:
        records = [(b"a1", 3, b"one"), (b"a2", 4, None), (b"b1", 5, b"two" * 50), (b"c1", 6, b"three")]
        for compress in (False, True):
            with self.subTest(compress=compress):
                stats = ReadStats()
                table = fx.leveldb_table(records, compress=compress, per_block=2)
                found = list(iter_table_records(table, stats))
                self.assertEqual([(r.user_key, r.sequence, r.deleted, r.value) for r in found],
                                 [(b"a1", 3, False, b"one"), (b"a2", 4, True, None), (b"b1", 5, False, b"two" * 50), (b"c1", 6, False, b"three")])
                self.assertEqual(stats.snappy_blocks > 0, compress)
        table = bytearray(fx.leveldb_table(records, compress=False, per_block=2))
        table[0:4] = b"\xff\xff\xff\xff"  # first data block: entry varints now run past the block
        stats = ReadStats()
        found = list(iter_table_records(bytes(table), stats))
        self.assertEqual(stats.corrupt_blocks, 1)
        self.assertEqual([r.user_key for r in found], [b"b1", b"c1"])
        with self.assertRaises(LevelDBError):
            list(iter_table_records(bytes(table[:-20])))  # truncated: footer magic gone


class CarvingTests(unittest.TestCase):
    def test_v8_values_and_key_runs(self) -> None:
        blob = fx.v8_serialize({"content": "안녕", "composetime": "2024-03-01T01:00:00Z", "n": 7, "isFromMe": True})
        groups = v8_key_objects(blob)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][1]["content"], "안녕")
        self.assertIs(groups[0][1]["isFromMe"], True)
        self.assertEqual(decode_v8_value(b"I" + fx.varint(13), 0)[0], -7)
        self.assertEqual(decode_v8_value(b"N" + struct.pack("<d", 1.5), 0)[0], 1.5)
        self.assertNotIsInstance(decode_v8_value(b'"\x05ab', 0)[0], str)  # declared length past the blob: missing
        two = fx.v8_serialize([{"content": "first", "ts": "1709251200.1"}, {"content": "second", "ts": "1709251260.2"}])
        self.assertEqual([group["content"] for _pos, group in v8_key_objects(two)], ["first", "second"])

    def test_json_fragments_are_bounded(self) -> None:
        text = 'xx{"text":"a","ts":"1709251200.000100","user":"U1"} junk [{"name":"b.pdf","size":3}]'
        found = json_fragments(text, max_attempts=10, max_window=1000)
        self.assertEqual([value for _pos, value in found], [{"text": "a", "ts": "1709251200.000100", "user": "U1"}, [{"name": "b.pdf", "size": 3}]])
        self.assertEqual(json_fragments('{"a' * 1000, max_attempts=3, max_window=100), [])

    def test_time_parsing_never_guesses_an_offset(self) -> None:
        self.assertEqual(parse_chat_time("1709251200.000100")[0], "2024-03-01T00:00:00.000100+00:00")
        self.assertEqual(parse_chat_time(1709251200000)[0], "2024-03-01T00:00:00+00:00")
        self.assertEqual(parse_chat_time("2024-03-01T09:00:00+09:00")[0], "2024-03-01T00:00:00+00:00")
        self.assertEqual(parse_chat_time("2024-03-01T09:00:00")[0], "")  # naive local time: not an instant
        self.assertEqual(parse_chat_time(12)[0], "")

    def test_classification_skips_secret_fields(self) -> None:
        rows = classify_object({"text": "hi", "user": "U1", "ts": "1709251200.1", "token": "xoxc-1"}, max_text_chars=100)
        self.assertEqual([item.artifact_type for item in rows], ["chat-message"])
        self.assertNotIn("xoxc", json.dumps([item.fields for item in rows]))

    def test_zoom_chat_log_formats(self) -> None:
        messages = parse_zoom_chat_log(fx.ZOOM_CHAT + "09:00:01\t From  Old Client : 예전 형식\n")
        self.assertEqual([(m["sender"], m["recipient"]) for m in messages][:2], [("김민수", "Everyone"), ("이영희", "Everyone")])
        self.assertEqual(messages[-1]["text"], "예전 형식")


class ProviderFixtureTests(unittest.TestCase):
    """Q-R2-1: one positive fixture per app (messages 2+ · attachment 1+ · contact 1+, or inventory)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.home = fx.build_all(cls.root)
        cls.rows = collect(cls.root)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def assert_minimums(self, app_id: str, messages: int, attachments: int, contacts: int) -> None:
        counts = Counter(row["artifact_type"] for row in by_app(self.rows, app_id))
        self.assertGreaterEqual(counts["chat-message"], messages, (app_id, counts))
        self.assertGreaterEqual(counts["chat-attachment"], attachments, (app_id, counts))
        self.assertGreaterEqual(counts["chat-contact"], contacts, (app_id, counts))
        self.assertGreaterEqual(counts["chat-app-inventory"], 1, app_id)
        self.assertEqual(counts["chat-parse-error"], 0, app_id)

    def test_every_row_carries_the_provenance_contract(self) -> None:
        self.assertEqual({details(row)["app_id"] for row in self.rows}, set(fx.BUILDERS))
        for row in self.rows:
            info = details(row)
            for key in ("recovery_method", "parser_version", "source_path", "source_offset", "service", "user"):
                self.assertIn(key, info, (row["artifact_type"], key))
            self.assertEqual(info["parser_version"], PARSER_VERSION)
            self.assertEqual(info["user"], "analyst")
        carved = [row for row in self.rows if details(row)["recovery_method"] == "carved"]
        self.assertTrue(carved)
        self.assertTrue(all(isinstance(details(row)["source_offset"], int) for row in carved))
        dump = json.dumps(self.rows, ensure_ascii=False)
        for secret in ("xoxc-should-never-be-copied", "mfa.SECRETSECRET"):
            self.assertNotIn(secret, dump)

    def test_teams_classic(self) -> None:
        self.assert_minimums("teams-classic", 3, 1, 1)
        texts = {details(row)["message_text"] for row in by_app(self.rows, "teams-classic", "chat-message")}
        self.assertIn("견적서 검토 부탁드립니다", texts)  # HTML reduced to text
        self.assertIn("작년 회의록 공유", texts)  # from the Snappy-compressed .ldb
        attachment = by_app(self.rows, "teams-classic", "chat-attachment")[0]
        self.assertEqual(details(attachment)["file_name"], "q3_budget.xlsx")
        self.assertEqual(details(attachment)["conversation_id"], "19:meeting_abc@thread.v2")

    def test_teams_new(self) -> None:
        self.assert_minimums("teams-new", 2, 1, 1)
        directions = {details(row)["message_text"]: details(row)["direction"] for row in by_app(self.rows, "teams-new", "chat-message")}
        self.assertEqual(directions["신규 Teams 첫 메시지"], "outgoing")

    def test_slack_local_storage_json(self) -> None:
        self.assert_minimums("slack", 2, 1, 1)
        message = next(row for row in by_app(self.rows, "slack", "chat-message") if details(row)["message_text"] == "고객 명단 보내드립니다")
        self.assertEqual(details(message)["timestamp"], "2024-03-01T00:00:00.000100+00:00")
        self.assertEqual(details(message)["attachment_name"], "customers.csv")
        inventory = by_app(self.rows, "slack", "chat-app-inventory")[0]
        self.assertEqual(details(inventory)["app_version"], "4.36.140")

    def test_discord_cache_gzip_bodies(self) -> None:
        self.assert_minimums("discord", 2, 1, 1)
        message = by_app(self.rows, "discord", "chat-message")[0]
        self.assertEqual(details(message)["message_text"], "자료 올렸어")
        self.assertEqual(details(message)["sender"], "민수")
        self.assertEqual(details(message)["source_format"], "chromium-cache")

    def test_telegram_is_inventory_plus_saved_files(self) -> None:
        inventory = by_app(self.rows, "telegram-desktop", "chat-app-inventory")[0]
        self.assertTrue(details(inventory)["inventory_only"])
        self.assertIn("암호화", details(inventory)["reason_ko"])
        tdata = next(store for store in details(inventory)["stores"] if store["kind"] == "encrypted-directory")
        self.assertTrue(tdata["key_file_present"])
        self.assertEqual(tdata["account_dir_candidates"], ["D877F783D5D3EF8C"])
        attachments = by_app(self.rows, "telegram-desktop", "chat-attachment")
        self.assertEqual([details(row)["file_name"] for row in attachments], ["invoice_2024.pdf"])  # encrypted cache not listed
        self.assertRegex(str(details(attachments[0])["sha256"]), r"^[0-9a-f]{64}$")
        self.assertEqual(details(attachments[0])["direction"], "incoming")

    def test_whatsapp_desktop(self) -> None:
        self.assert_minimums("whatsapp-desktop", 2, 0, 0)
        directions = sorted(details(row)["direction"] for row in by_app(self.rows, "whatsapp-desktop", "chat-message"))
        self.assertEqual(directions, ["incoming", "outgoing"])
        conversations = {details(row)["conversation_id"] for row in by_app(self.rows, "whatsapp-desktop", "chat-message")}
        self.assertEqual(conversations, {"821012345678@c.us"})
        inventories = by_app(self.rows, "whatsapp-desktop", "chat-app-inventory")
        uwp = next(row for row in inventories if "LocalState" in str(details(row)["app_root"]))
        self.assertEqual(details(uwp)["encrypted_store_count"], 1)
        self.assertIn("msgstore.db", details(uwp)["reason_ko"])

    def test_skype_main_db(self) -> None:
        self.assert_minimums("skype", 2, 1, 1)
        messages = by_app(self.rows, "skype", "chat-message")
        self.assertEqual(sorted(details(row)["direction"] for row in messages), ["incoming", "outgoing", "outgoing"])
        deleted = [row for row in messages if details(row)["deleted_state"] == "deleted-in-app"]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(details(messages[0])["conversation_title"], "Bob")
        transfer = by_app(self.rows, "skype", "chat-attachment")[0]
        self.assertEqual((details(transfer)["direction"], details(transfer)["recipient"]), ("outgoing", "live:bob.partner"))
        roles = {details(row).get("contact_role", "") for row in by_app(self.rows, "skype", "chat-contact")}
        self.assertIn("account-owner", roles)
        self.assertTrue(all(details(row)["recovery_method"] == "sqlite-table" for row in messages))

    def test_line_is_inventory_only(self) -> None:
        inventory = by_app(self.rows, "line", "chat-app-inventory")[0]
        self.assertTrue(details(inventory)["inventory_only"])
        self.assertEqual(details(inventory)["encrypted_store_count"], 1)
        self.assertEqual(details(inventory)["stores"][0]["encryption_state"], "encrypted-or-unknown")

    def test_wechat_is_inventory_plus_file_storage(self) -> None:
        inventory = by_app(self.rows, "wechat", "chat-app-inventory")[0]
        self.assertTrue(details(inventory)["inventory_only"])
        states = {store["encryption_state"] for store in details(inventory)["stores"] if store["kind"] == "database"}
        self.assertEqual(states, {"encrypted-sqlcipher"})
        self.assertEqual(details(inventory)["encrypted_store_count"], 3)
        names = sorted(details(row)["file_name"] for row in by_app(self.rows, "wechat", "chat-attachment"))
        self.assertEqual(names, ["contract_final.docx", "photo.jpg"])

    def test_zoom_sqlite_and_saved_chat(self) -> None:
        self.assert_minimums("zoom", 4, 0, 1)
        methods = Counter(details(row)["recovery_method"] for row in by_app(self.rows, "zoom", "chat-message"))
        self.assertEqual(methods, Counter({"text-log": 3, "sqlite-table": 2}))
        log_row = next(row for row in by_app(self.rows, "zoom", "chat-message") if details(row)["recovery_method"] == "text-log")
        self.assertEqual(details(log_row)["timestamp"], "")  # wall-clock time without offset
        self.assertEqual(details(log_row)["local_timestamp"], "2024-03-01T10:01:02")
        inventory = by_app(self.rows, "zoom", "chat-app-inventory")[0]
        self.assertEqual(details(inventory)["encrypted_store_count"], 1)

    def test_every_type_maps_to_a_catalogue_family_with_semantic_tags(self) -> None:
        catalog = load_catalog()
        types = {row["artifact_type"] for row in self.rows} | {"chat-parse-error"}
        families = {artifact_type: catalog.family_for(str(artifact_type), "windows-messenger") for artifact_type in types}
        self.assertNotIn(None, families.values(), families)
        semantics = {
            column.get("semantic")
            for family in catalog.families
            if family["id"] in families.values()
            for column in [*(family.get("core_columns") or []), *(family.get("aux_columns") or [])]
        }
        self.assertTrue({"person_sender", "person_recipient", "attachment", "url", "person", "account"} <= semantics)


class IsolationAndCapsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = fx.build_all(self.root)

    def test_corrupt_inputs_become_parse_errors_and_the_collect_continues(self) -> None:
        bad = fx.corrupt_stores(self.home)
        rows = collect(self.root)
        errors = [row for row in rows if row["artifact_type"] == "chat-parse-error"]
        self.assertEqual(sorted(Path(str(row["path"])).name for row in errors), ["000006.ldb", "main.db"])
        self.assertTrue(all(details(row)["parser_error"] is True for row in errors))
        self.assertTrue(all(details(row)["reason_ko"] for row in errors))
        # Good stores of the same apps and every other app still produce rows.
        self.assertGreaterEqual(len(by_app(rows, "teams-classic", "chat-message")), 3)
        self.assertGreaterEqual(len(by_app(rows, "skype", "chat-message")), 3)
        self.assertEqual({details(row)["app_id"] for row in rows}, set(fx.BUILDERS))
        teams_store = next(
            store for store in details(by_app(rows, "teams-classic", "chat-app-inventory")[0])["stores"] if store["kind"] == "leveldb"
        )
        self.assertEqual(teams_store["damaged_files"][0]["file"], bad["garbage_log"].name)
        # Through the artifacts command: errors counted, collection completed.
        clear_collect_cache()
        payload = run_artifact_collection(self.root, kind="windows-messenger", use_cache=False)
        self.assertEqual(payload["summary"]["collection_status"], "completed")
        self.assertEqual(payload["summary"]["parser_error_count"], 2)

    def test_caps_bound_rows_files_and_bytes(self) -> None:
        rows = collect(self.root, MessengerLimits(max_rows_per_app=1, max_store_files=1, max_attachment_files=1))
        for app_id in fx.BUILDERS:
            data_rows = [row for row in by_app(rows, app_id) if row["artifact_type"] in DATA_TYPES]
            self.assertLessEqual(len(data_rows), 1 * len(by_app(rows, app_id, "chat-app-inventory")), app_id)
        caps = {cap for row in rows if row["artifact_type"] == "chat-app-inventory" for cap in details(row)["caps_hit"]}
        self.assertTrue({"row-cap", "attachment-file-cap"} <= caps, caps)
        provider = WindowsMessengerProvider(MessengerLimits(max_file_bytes=64, max_app_bytes=100))
        rows = [record.to_dict() for record in provider.collect(self.root)]
        caps = {cap for row in rows if row["artifact_type"] == "chat-app-inventory" for cap in details(row)["caps_hit"]}
        self.assertTrue({"file-byte-cap", "app-byte-cap"} <= caps, caps)
        self.assertTrue(any("상한" in note for note in provider.collection_notes))
        for row in rows:
            if row["artifact_type"] == "chat-app-inventory":
                self.assertLessEqual(int(details(row)["bytes_read"]), 100)

    def test_no_messenger_folders_explains_itself(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            (Path(empty) / "Users" / "nobody" / "AppData").mkdir(parents=True)
            provider = WindowsMessengerProvider()
            self.assertEqual(list(provider.collect(Path(empty))), [])
            self.assertIn("발견되지 않았습니다", provider.collection_notes[0])


class ReviewRegressionTests(unittest.TestCase):
    """Adversarial-review findings: per-user stores once, per-database owner, WhatsApp contacts."""

    def test_home_stores_are_read_once_when_an_app_has_two_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "Users" / "analyst"
            fx.build_telegram(home)
            uwp = home.joinpath(*fx.PACKAGES, "TelegramMessengerLLP.TelegramDesktop_t4vj0pshhgkwm", "LocalCache", "Roaming", "Telegram Desktop UWP")
            fx.write(uwp / "tdata" / "key_datas", fx.pseudo_random(64, 3))
            rows = collect(root)
            self.assertEqual(len(by_app(rows, "telegram-desktop", "chat-app-inventory")), 2)
            self.assertEqual(len(by_app(rows, "telegram-desktop", "chat-attachment")), 1)

    def test_owner_does_not_leak_between_skype_databases(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "Users" / "analyst"
            fx.build_skype(home)
            second = home.joinpath(*fx.ROAMING, "Skype", "live#3azz.other", "main.db")
            second.parent.mkdir(parents=True)
            connection = sqlite3.connect(second)
            connection.executescript(
                "CREATE TABLE Messages (id INTEGER PRIMARY KEY, convo_id INTEGER, author TEXT, timestamp INTEGER, body_xml TEXT);"
                "INSERT INTO Messages VALUES (1, 1, 'live:alice.kim', 1709200000, 'no owner table here');"
            )
            connection.commit()
            connection.close()
            rows = collect(root)
            other = [row for row in by_app(rows, "skype", "chat-message") if "zz.other" in str(row["path"])]
            self.assertEqual([details(row)["direction"] for row in other], ["unknown"])

    def test_a_newer_tombstone_marks_the_carved_message_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = root.joinpath("Users", "analyst", *fx.ROAMING, "Slack", "IndexedDB", "https_app.slack.com_0.indexeddb.leveldb")
            message = fx.v8_serialize({"text": "지워질 메시지", "user": "U1", "ts": "1709251200.000100", "channel": "C1"})
            kept = fx.v8_serialize({"text": "남은 메시지", "user": "U1", "ts": "1709251300.000100", "channel": "C1"})
            # The tombstone lives in a later file than the value: applied after the whole store is read.
            fx.write(store / "000003.ldb", fx.leveldb_table([(b"m1", 1, message), (b"m2", 2, kept)]))
            fx.write(store / "000004.log", fx.leveldb_log([fx.write_batch(3, [(b"m1", None)])]))
            rows = by_app(collect(root), "slack", "chat-message")
            states = {details(row)["message_text"]: details(row)["deleted_state"] for row in rows}
            self.assertEqual(states, {"지워질 메시지": "deleted", "남은 메시지": "unknown"})

    def test_whatsapp_contact_objects(self) -> None:
        found = classify_object({"id": "821012345678@c.us", "name": "홍길동", "pushname": "Gildong", "isMyContact": True}, max_text_chars=100)
        self.assertEqual([(item.artifact_type, item.fields["contact_name"]) for item in found], [("chat-contact", "홍길동")])


def _skype_transfers_root(temp: str) -> Path:
    """Skype ``main.db``: one file sent to two partners and one incoming transfer (review repro exp5)."""
    root = Path(temp)
    db_path = root.joinpath("Users", "u", *fx.ROAMING, "Skype", "live#3aowner", "main.db")
    db_path.parent.mkdir(parents=True)
    connection = sqlite3.connect(db_path)
    connection.executescript(
        r"""CREATE TABLE Accounts(skypename TEXT, fullname TEXT);
        INSERT INTO Accounts VALUES('live:owner','Owner');
        CREATE TABLE Contacts(skypename TEXT, displayname TEXT);
        INSERT INTO Contacts VALUES('live:colleague','Colleague');
        CREATE TABLE Transfers(id INTEGER, type INTEGER, partner_handle TEXT, partner_dispname TEXT, status INTEGER,
                               starttime INTEGER, filepath TEXT, filename TEXT, filesize TEXT, convo_id INTEGER);
        INSERT INTO Transfers VALUES(1,2,'live:colleague','C',8,1709251200,'C:\x\plan.pdf','plan.pdf','1000',1);
        INSERT INTO Transfers VALUES(2,2,'rival@gmail.com','R',8,1709251300,'C:\x\plan.pdf','plan.pdf','1000',2);
        INSERT INTO Transfers VALUES(3,1,'outsider@gmail.com','O',8,1709251400,'C:\dl\in.pdf','in.pdf','5',3);"""
    )
    connection.commit()
    connection.close()
    return root


class HostileInputRegressionTests(unittest.TestCase):
    """Second adversarial review (R2 fix): hostile LevelDB shapes, deep JSON, V8 grouping, dedupe, redaction, Zoom."""

    def assert_bounded(self, action, *, max_seconds: float, max_peak_mb: float) -> object:
        tracemalloc.start()
        started = time.monotonic()
        try:
            result = action()
        finally:
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.assertLess(time.monotonic() - started, max_seconds)
        self.assertLess(peak / 1e6, max_peak_mb)
        return result

    # B2 ------------------------------------------------------------------------------------------
    def test_b2_prefix_amplified_block_is_bounded(self) -> None:
        # exp1 (full shared key) and exp2 (shared key + 1 new byte): 10 000 entries re-emitting a 16 KiB key.
        for tail in (b"", b"B"):
            with self.subTest(tail=tail):
                block = fx.prefix_bomb_block(16 * 1024, 10_000, tail=tail)

                def drain(block: bytes = block) -> int:
                    count = 0
                    with self.assertRaises(LevelDBError):
                        for _entry in iter_block_entries(block):
                            count += 1
                    return count

                count = self.assert_bounded(drain, max_seconds=5, max_peak_mb=8)
                self.assertLess(count, 200)
                stats = ReadStats()
                table = fx.table_with_blocks([(fx.snappy_compress(block), 1)])
                self.assert_bounded(lambda table=table, stats=stats: list(iter_table_records(table, stats)), max_seconds=5, max_peak_mb=8)
                self.assertEqual(stats.corrupt_blocks, 1)
        with self.assertRaises(LevelDBError):  # one key over 64 KiB
            list(iter_block_entries(fx.prefix_bomb_block(MAX_KEY_BYTES + 1, 0)))

    # M4 ------------------------------------------------------------------------------------------
    def test_m4_repeated_index_handles_decompress_once_and_charge_the_budget(self) -> None:
        # exp3: 20 index entries pointing at one Snappy block that expands to 4 MiB.
        table = fx.table_with_blocks([(fx.snappy_run(4 * 1024 * 1024), 1)], repeat_first_handle=20)
        stats = ReadStats()
        self.assert_bounded(lambda: list(iter_table_records(table, stats)), max_seconds=10, max_peak_mb=40)
        self.assertEqual(stats.snappy_blocks, 1)
        self.assertEqual(stats.decompressed_bytes, 4 * 1024 * 1024)
        self.assertGreaterEqual(stats.corrupt_blocks, 19)
        budget = ReadStats()
        self.assertEqual(list(iter_table_records(table, budget, max_decompressed=1024 * 1024)), [])
        self.assertEqual((budget.snappy_blocks, budget.budget_exhausted, budget.truncated), (0, True, True))

    def test_short_keys_count_one_corrupt_block_not_one_per_entry(self) -> None:
        raw = fx._block([(b"k%d" % number, b"v") for number in range(5)])  # keys shorter than the 8-byte trailer
        stats = ReadStats()
        self.assertEqual(list(iter_table_records(fx.table_with_blocks([(raw, 0)]), stats)), [])
        self.assertEqual(stats.corrupt_blocks, 1)

    def test_log_full_record_resets_a_dangling_first_fragment(self) -> None:
        # exp4: FIRST(garbage) FULL MIDDLE LAST - the MIDDLE+LAST tail must not become a ghost batch.
        ghost = fx.write_batch(99, [(b"ghost", b"phantom")])
        log = (
            fx.log_fragment(2, b"junkjunk")
            + fx.log_fragment(1, fx.write_batch(5, [(b"b", b"y")]))
            + fx.log_fragment(3, ghost[:6])
            + fx.log_fragment(4, ghost[6:])
        )
        stats = ReadStats()
        self.assertEqual([record.user_key for record in iter_log_records(log, stats)], [b"b"])
        self.assertEqual(stats.dropped_partial_batches, 3)

    # M5 ------------------------------------------------------------------------------------------
    def test_m5_deep_json_does_not_stop_the_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = root.joinpath("Users", "u", *fx.ROAMING, "Slack", "Local Storage", "leveldb")
            deep = '{"text":"x","user":"U1","ts":"1709251200.1",' + '"properties":{' * 1500 + "}" * 1500 + "}"
            good = json.dumps({"text": "later file message", "user": "U2", "ts": "1709251300.1", "channel": "C1"})
            fx.write(store / "000003.log", fx.leveldb_log([fx.write_batch(1, [(b"k1", b"\x01" + deep.encode())])]))
            fx.write(store / "000005.log", fx.leveldb_log([fx.write_batch(2, [(b"k2", b"\x01" + good.encode())])]))
            deep_object = json.loads(deep)
            self.assertEqual(classify_object(deep_object, max_text_chars=100)[0].fields["message_text"], "x")
            rows = collect(root)
            texts = [details(row)["message_text"] for row in by_app(rows, "slack", "chat-message")]
            self.assertIn("later file message", texts)
            self.assertEqual(by_app(rows, "slack", "chat-parse-error"), [])

    def test_m5_a_failing_file_is_isolated_per_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = root.joinpath("Users", "u", *fx.ROAMING, "Slack", "Local Storage", "leveldb")
            good = json.dumps({"text": "survivor", "user": "U2", "ts": "1709251300.1", "channel": "C1"})
            fx.write(store / "000003.log", fx.leveldb_log([fx.write_batch(1, [(b"k1", b"\x01" + b'{"text":"boom","ts":"1709251200.1"}')])]))
            fx.write(store / "000005.log", fx.leveldb_log([fx.write_batch(2, [(b"k2", b"\x01" + good.encode())])]))
            original = messenger_module.classify_object

            def flaky(record, **kwargs):
                if record.get("text") == "boom":
                    raise RecursionError("synthetic")
                return original(record, **kwargs)

            with mock.patch.object(messenger_module, "classify_object", flaky):
                rows = collect(root)
            errors = by_app(rows, "slack", "chat-parse-error")
            self.assertEqual([(Path(str(row["path"])).name, details(row)["error_type"]) for row in errors], [("000003.log", "RecursionError")])
            self.assertEqual([details(row)["message_text"] for row in by_app(rows, "slack", "chat-message")], ["survivor"])

    # M10 -----------------------------------------------------------------------------------------
    def test_m10_v8_sender_never_leaks_between_neighbouring_objects(self) -> None:
        two_users = fx.v8_serialize([{"user": "U1", "text": "a", "ts": "1709251200.1"}, {"user": "U2", "text": "b", "ts": "1709251260.1"}])
        self.assertEqual(
            [group for _pos, group in v8_key_objects(two_users)],
            [{"user": "U1", "text": "a", "ts": "1709251200.1"}, {"user": "U2", "text": "b", "ts": "1709251260.1"}],
        )
        for first in ({"text": "system notice", "ts": "1709251200.1"}, {"content": "system: call ended", "composetime": "2024-03-01T00:00:00Z"}):
            with self.subTest(first=first):
                blob = fx.v8_serialize([first, {"imdisplayname": "Mallory", "content": "send me the file", "composetime": "2024-03-01T00:01:00Z"}])
                senders = {
                    candidate.fields["message_text"]: candidate.fields["sender"]
                    for _pos, group in v8_key_objects(blob)
                    for candidate in classify_object(group, max_text_chars=100)
                }
                self.assertEqual(senders[str(first.get("text") or first.get("content"))], "")
                self.assertEqual(senders["send me the file"], "Mallory")
        # Keys of a nested object join the message; the message's own ``id`` wins over the nested one.
        nested = fx.v8_serialize({"content": "hi", "composetime": "2024-03-01T00:00:00Z", "properties": {"id": "nested", "files": "[]"}, "id": "own"})
        self.assertEqual([group for _pos, group in v8_key_objects(nested)], [{"content": "hi", "composetime": "2024-03-01T00:00:00Z", "files": "[]", "id": "own"}])

    def test_max_pairs_counts_decode_attempts(self) -> None:
        junk = b'"\x04text\x99' * 50
        good = fx.v8_serialize({"text": "late", "ts": "1709251200.1"})
        self.assertEqual(v8_key_objects(junk + good, max_pairs=10), [])
        self.assertTrue(v8_key_objects(junk + good, max_pairs=1000))

    # M11 / M12 -----------------------------------------------------------------------------------
    def test_m11_one_file_sent_to_two_people_is_two_transfers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rows = by_app(collect(_skype_transfers_root(temp)), "skype", "chat-attachment")
            plan = sorted(details(row)["recipient"] for row in rows if details(row)["file_name"] == "plan.pdf")
            self.assertEqual(plan, ["live:colleague", "rival@gmail.com"])
            self.assertTrue(all("duplicate_count" not in details(row) for row in rows))

    def test_m12_skype_transfer_sender_and_recipient_follow_direction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rows = by_app(collect(_skype_transfers_root(temp)), "skype", "chat-attachment")
            sides = {(details(row)["file_name"], details(row)["recipient"]): (details(row)["direction"], details(row)["sender"]) for row in rows}
            self.assertEqual(sides[("plan.pdf", "rival@gmail.com")], ("outgoing", "live:owner"))
            self.assertEqual(sides[("in.pdf", "live:owner")], ("incoming", "outsider@gmail.com"))

    # Decision (3) --------------------------------------------------------------------------------
    def test_attachment_urls_have_tokens_redacted_and_keep_the_raw_sha256(self) -> None:
        raw_url = "https://cdn.discordapp.com/attachments/1/2/plan.docx?ex=65f1&is=65e0&hm=deadbeef"
        record = {"content": "file", "timestamp": "2024-03-01T02:10:00+00:00", "author": {"username": "minsu"},
                  "attachments": [{"filename": "plan.docx", "size": 3, "url": raw_url}]}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            body = gzip.compress(json.dumps([record]).encode("utf-8"))
            fx.write(root.joinpath("Users", "u", *fx.ROAMING, "discord", "Cache", "Cache_Data", "f_000001"), b"\x00" * 8 + body)
            rows = collect(root)
        attachment = details(by_app(rows, "discord", "chat-attachment")[0])
        self.assertEqual(attachment["url"], "https://cdn.discordapp.com/attachments/1/2/plan.docx?ex=[가림]&is=[가림]&hm=[가림]")
        self.assertEqual(attachment["url_sha256"], hashlib.sha256(raw_url.encode()).hexdigest())
        self.assertIs(attachment["url_tokens_redacted"], True)
        self.assertNotIn("deadbeef", json.dumps(rows, ensure_ascii=False))

    # Minors --------------------------------------------------------------------------------------
    def test_teams_message_id_prefers_the_server_id(self) -> None:
        found = classify_object(
            {"id": "1709251200123", "clientmessageid": "8812", "content": "x", "composetime": "2024-03-01T00:00:00Z"}, max_text_chars=100
        )
        self.assertEqual(found[0].fields["message_id"], "1709251200123")

    def test_tombstone_keys_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = root.joinpath("Users", "u", *fx.ROAMING, "Slack", "IndexedDB", "https_app.slack.com_0.indexeddb.leveldb")
            fx.write(store / "000004.log", fx.leveldb_log([fx.write_batch(3, [(b"m%d" % n, None) for n in range(5)])]))
            rows = collect(root, MessengerLimits(max_deleted_keys=2))
        self.assertIn("leveldb-tombstone-cap", details(by_app(rows, "slack", "chat-app-inventory")[0])["caps_hit"])

    def test_snapshot_hash_and_inflated_bytes_are_charged_to_the_app_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "Users" / "analyst"
            fx.build_skype(home)
            fx.build_telegram(home)
            fx.build_discord(home)
            db_size = home.joinpath(*fx.ROAMING, "Skype", "live#3aalice.kim", "main.db").stat().st_size
            rows = collect(root, MessengerLimits(max_app_bytes=db_size - 1))
            skype = details(by_app(rows, "skype", "chat-app-inventory")[0])
            self.assertEqual([store["status"] for store in skype["stores"]], ["skipped-app-byte-cap"])
            self.assertIn("app-byte-cap", skype["caps_hit"])
            telegram = [details(row) for row in by_app(collect(root, MessengerLimits(max_app_bytes=10)), "telegram-desktop", "chat-attachment")]
            self.assertEqual([item["sha256"] for item in telegram], [""])
            discord = details(by_app(collect(root), "discord", "chat-app-inventory")[0])
            cache_file = home.joinpath(*fx.ROAMING, "discord", "Cache", "Cache_Data", "f_000001")
            log_file = home.joinpath(*fx.ROAMING, "discord", "Local Storage", "leveldb", "000003.log")
            self.assertGreater(int(discord["bytes_read"]), cache_file.stat().st_size + log_file.stat().st_size)

    def test_multi_member_gzip_body_is_read_whole_or_marked_truncated(self) -> None:
        text = json.dumps([{"id": "1", "channel_id": "9", "content": "두 조각 본문", "timestamp": "2024-03-01T02:10:00+00:00",
                            "author": {"username": "minsu"}}], ensure_ascii=False).encode("utf-8")
        body = gzip.compress(text[:20]) + gzip.compress(text[20:])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fx.write(root.joinpath("Users", "u", *fx.ROAMING, "discord", "Cache", "Cache_Data", "f_000001"), b"\x00" * 8 + body)
            rows = collect(root)
            messages = [details(row) for row in by_app(rows, "discord", "chat-message")]
            self.assertEqual([item["message_text"] for item in messages], ["두 조각 본문"])
            self.assertNotIn("cache_body_truncated", messages[0])
            small = collect(root, MessengerLimits(max_json_window=8))
        self.assertTrue(all(details(row).get("cache_body_truncated") for row in by_app(small, "discord") if details(row).get("cache_body") == "gzip"))

    def test_zoom_old_format_line_with_to_and_a_colon_in_the_body(self) -> None:
        messages = parse_zoom_chat_log("10:00:00 From Alice : I want to go: now\n")
        self.assertEqual([(m["sender"], m["recipient"], m["text"]) for m in messages], [("Alice", "", "I want to go: now")])

    def test_zoom_saved_chat_after_midnight_rolls_the_date_over(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root.joinpath("Users", "u", "Documents", "Zoom", "2024-03-01 23.30.00 Late Sync 81234567890")
            fx.write(folder / "meeting_saved_chat.txt", "23:59:10 From A to Everyone:\n\tbefore\n00:01:00 From B to Everyone:\n\tafter\n")
            fx.write(root.joinpath("Users", "u", *fx.ROAMING, "Zoom", "Zoom.exe"), b"MZ")
            rows = collect(root)
        times = {details(row)["message_text"]: details(row)["local_timestamp"] for row in by_app(rows, "zoom", "chat-message")}
        self.assertEqual(times, {"before": "2024-03-01T23:59:10", "after": "2024-03-02T00:01:00"})

    def test_zoom_saved_chat_row_full_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "Users" / "analyst"
            fx.build_zoom(home)
            rows = collect(root)
            log_path = home / "Documents" / "Zoom" / "2024-03-01 10.00.00 Weekly Sync 81234567890" / "meeting_saved_chat.txt"
        row = next(row for row in by_app(rows, "zoom", "chat-message") if details(row)["recovery_method"] == "text-log")
        self.assertEqual((row["artifact_type"], row["path"]), ("chat-message", str(log_path)))
        self.assertEqual(
            details(row),
            {
                "parser": "windows-messenger",
                "parser_version": PARSER_VERSION,
                "service": "Zoom",
                "app": "Zoom",
                "app_id": "zoom",
                "app_label_ko": "Zoom",
                "user": "analyst",
                "recovery_method": "text-log",
                "source_path": str(log_path),
                "source_offset": 0,
                "source_format": "text",
                "store_path": str(log_path),
                "reportability": "triage",
                "validation_required": True,
                "timestamp": "",
                "local_timestamp": "2024-03-01T10:01:02",
                "timestamp_source": "zoom-chat-log-local-time-no-offset",
                "timezone": "local-unknown",
                "local_day_offset": 0,
                "conversation_id": "2024-03-01 10.00.00 Weekly Sync 81234567890",
                "conversation_title": "2024-03-01 10.00.00 Weekly Sync 81234567890",
                "sender": "김민수",
                "recipient": "Everyone",
                "direction": "unknown",
                "message_text": "안녕하세요",
                "message_text_preview": "안녕하세요",
                "message_text_sha256": hashlib.sha256("안녕하세요".encode()).hexdigest(),
                "message_text_truncated": False,
                "message_format": "text",
                "message_id": "line-1",
                "message_type": "zoom-meeting-chat",
                "attachment_name": "",
                "attachment_count": 0,
                "edited_at": "",
                "deleted_state": "live",
                "source_line": 1,
                "coverage_status": "mapped",
                "confidence": "medium",
            },
        )


class RunPipelineTests(unittest.TestCase):
    def test_every_run_mode_schedules_the_provider(self) -> None:
        self.assertIn("windows-messenger", artifact_collectors())
        for mode in SUPPORTED_RUN_MODES:
            self.assertIn("windows-messenger", RUN_PROFILES[mode].artifacts_kinds, mode)

    def test_a_run_writes_the_windows_messenger_step(self) -> None:
        from rapidtriage.core.run import run_triage_mode

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "case"
            fx.build_teams_classic(root / "Users" / "analyst")
            clear_collect_cache()
            summary = run_triage_mode(root, mode="seizure", output_dir=Path(temp) / "out")
            clear_collect_cache()
            self.assertIn("windows-messenger", summary["summary"]["artifacts"])
            output = Path(summary["outputs"]["artifacts_windows-messenger"])
            self.assertTrue(output.is_file())
            counts = summary["summary"]["artifacts"]["windows-messenger"]
            self.assertGreaterEqual(int(counts["artifact_count"]), 5)


if __name__ == "__main__":
    unittest.main()
