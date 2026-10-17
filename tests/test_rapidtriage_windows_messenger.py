"""windows-messenger provider (plan r2-communication §3.1 M1; QA Q-R2-1, Q-R2-8).

Synthetic fixtures only (``tests/messenger_fixtures.py``): every app store is
generated in code. Covers the pure-Python LevelDB/Snappy reader, the V8/JSON
carving, per-app rows for all nine apps, corrupt-input isolation, caps, the
catalogue mapping, and that runs schedule the provider.
"""

from __future__ import annotations

import json
import sqlite3
import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts import artifact_collectors, clear_collect_cache
from rapidtriage.artifacts.windows.leveldb import (
    LevelDBError,
    ReadStats,
    SnappyError,
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
