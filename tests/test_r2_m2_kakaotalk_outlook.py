"""r2 M2: KakaoTalk PC messages / shared pictures, Outlook PST/OST + ICS rows (Q-R2-2, Q-R2-3, Q-R2-8).

Fixtures are synthetic (``tests/kakaotalk_message_fixtures.py``, ``tests/email_pst_fixtures.py``).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts import kakaotalk_messages
from rapidtriage.artifacts.email import EmailArtifactsProvider
from rapidtriage.artifacts.email_pst import (
    collect_outlook_container,
    normalize_pffexport_tree,
    normalize_readpst_tree,
    parse_ics_events,
    parse_tool_time,
)
from rapidtriage.artifacts.kakaotalk_messages import (
    decrypt_pages_to_file,
    derive_deviceinfo_pragmas,
    gather_key_material,
)
from rapidtriage.artifacts.kakaotalk_windows import KakaoTalkWindowsProvider
from rapidtriage.cli import main
from rapidtriage.core.aes_cbc import aes_cbc_decrypt, aes_cbc_encrypt
from rapidtriage.core.doc_text import _aes_cbc_decrypt
from rapidtriage.core.kakaotalk import derive_pragma_candidates_from_deviceinfo
from tests.email_pst_fixtures import (
    ICS_THREE_EVENTS,
    PST_HEADER,
    fake_pffexport_runner,
    fake_tool_resolver,
    no_tools,
    write_pffexport_tree,
    write_readpst_tree,
)
from tests.kakaotalk_message_fixtures import (
    DEVICEINFO,
    PAGE_SIZE,
    build_chatlogs_sqlite,
    encrypt_pagewise,
    fixture_key_iv,
    write_kakaotalk_pc_profile,
    write_registry_export,
)
from tests.test_rapidtriage_kakaotalk_windows import write_kakaotalk_windows_fixture

NEW_KAKAO_TYPES = {"kakaotalk-message", "kakaotalk-app-inventory", "kakaotalk-shared-picture"}
NO_OPERATOR_ENV = {
    name: ""
    for name in (
        "RAPIDTRIAGE_KAKAO_KEY_HEX",
        "RAPIDTRIAGE_KAKAO_IV_HEX",
        "RAPIDTRIAGE_KAKAO_PRAGMA",
        "RAPIDTRIAGE_KAKAO_USER_ID",
    )
}


def kakao_rows(root: Path) -> list[dict[str, object]]:
    with mock.patch.dict(os.environ, NO_OPERATOR_ENV):
        return [record.to_dict() for record in KakaoTalkWindowsProvider().collect(root) if record.artifact_type in NEW_KAKAO_TYPES]


def of_type(rows: list[dict[str, object]], artifact_type: str) -> list[dict[str, object]]:
    return [row for row in rows if row["artifact_type"] == artifact_type]


class AesTests(unittest.TestCase):
    def test_fips197_vectors_and_round_trip(self) -> None:
        plain = bytes.fromhex("00112233445566778899aabbccddeeff")
        key128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.assertEqual(aes_cbc_encrypt(key128, bytes(16), plain).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes_cbc_encrypt(bytes(range(32)), bytes(16), plain).hex(), "8ea2b7ca516745bfeafc49904b496089")
        data = os.urandom(PAGE_SIZE)
        iv = os.urandom(16)
        self.assertEqual(aes_cbc_decrypt(key128, iv, aes_cbc_encrypt(key128, iv, data)), data)
        with self.assertRaises(ValueError):
            aes_cbc_decrypt(key128, iv, b"short")

    def test_pdf_wrapper_strips_pkcs5_padding(self) -> None:
        key, iv = os.urandom(16), os.urandom(16)
        encrypted = iv + aes_cbc_encrypt(key, iv, b"hello pdf" + bytes([7]) * 7)
        self.assertEqual(_aes_cbc_decrypt(key, encrypted), b"hello pdf")

    @unittest.skipIf(shutil.which("openssl") is None, "OpenSSL cross-check")
    def test_matches_openssl_and_core_deviceinfo_pragmas(self) -> None:
        key, iv, data = os.urandom(16), os.urandom(16), os.urandom(PAGE_SIZE * 2)
        expected = subprocess.run(
            ["openssl", "enc", "-aes-128-cbc", "-e", "-K", key.hex(), "-iv", iv.hex(), "-nopad"],
            input=data,
            capture_output=True,
            check=True,
        ).stdout
        self.assertEqual(aes_cbc_encrypt(key, iv, data), expected)
        pragma_key = bytes.fromhex("00112233445566778899aabbccddeeff")
        core = derive_pragma_candidates_from_deviceinfo(pragma_key=pragma_key, openssl_bin="openssl", **DEVICEINFO)
        self.assertEqual(derive_deviceinfo_pragmas(DEVICEINFO, pragma_key=pragma_key), core)


class KakaoTalkMessageTests(unittest.TestCase):
    def test_key_present_emits_messages_inventory_and_linked_pictures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_export(root)
            paths = write_kakaotalk_pc_profile(root)
            rows = kakao_rows(root)

        messages = of_type(rows, "kakaotalk-message")
        self.assertEqual(len(messages), 4)
        first = messages[0]["details"]
        self.assertEqual(first["service"], "KakaoTalk PC")
        self.assertEqual(first["conversation_id"], "42")
        self.assertEqual(first["sender"], "12345")
        self.assertEqual(first["direction"], "발신")
        self.assertEqual(first["timestamp"], "2024-03-09T16:00:00Z")
        self.assertEqual(first["message_text"], "견적서 보내드립니다")
        self.assertEqual(first["recovery_method"], "decrypted-legacy-page-aes")
        self.assertEqual(first["key_source"], "user-id-candidate")
        self.assertTrue(first["pragma_variant"].startswith("builtin-deviceinfo-key-"))
        self.assertIn("parser_version", first)
        self.assertIn("source_offset", first)
        self.assertEqual(messages[1]["details"]["direction"], "수신")
        photo = messages[2]["details"]
        self.assertEqual(photo["attachment_name"], paths["thumb"].name)
        self.assertEqual(len(photo["attachment_local_paths"]), 2)  # saved copy (checksum) + cached thumbnail (name)
        self.assertEqual(messages[3]["details"]["deleted_state"], "확인 필요(type ≥ 16384 표식)")

        inventory = of_type(rows, "kakaotalk-app-inventory")
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["details"]["decryption_status"], "decrypted")
        self.assertEqual(inventory[0]["details"]["message_row_count"], 4)
        self.assertTrue(inventory[0]["details"]["reason"].startswith("복호 완료"))

        pictures = {Path(row["path"]).name: row["details"] for row in of_type(rows, "kakaotalk-shared-picture")}
        saved = pictures[paths["saved"].name]
        self.assertEqual(saved["linked_message_id"], "103")
        self.assertEqual(saved["link_method"], "checksum")
        self.assertEqual(saved["conversation_id"], "42")
        self.assertEqual(saved["download_time"], "2024-03-09T16:02:00.123")
        self.assertEqual(saved["mime"], "image/jpeg")
        self.assertFalse(saved["is_thumbnail"])
        self.assertEqual(saved["location_kind"], "saved-file")
        self.assertEqual(len(saved["sha256"]), 64)
        thumb = pictures[paths["thumb"].name]
        self.assertTrue(thumb["is_thumbnail"])
        self.assertEqual(thumb["mime"], "image/png")
        self.assertEqual(thumb["link_method"], "basename")
        self.assertEqual(thumb["location_kind"], "app-cache")

        # Key material never leaves memory: no pragma or derived key in any row.
        payload = json.dumps(rows, ensure_ascii=False)
        key, _iv = fixture_key_iv()
        self.assertNotIn(derive_deviceinfo_pragmas(DEVICEINFO)[0]["pragma"], payload)
        self.assertNotIn(key.hex(), payload)
        self.assertNotIn("SERIAL1234", payload)

    def test_key_absent_reports_korean_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_kakaotalk_pc_profile(root)  # no registry export: no key material
            rows = kakao_rows(root)
        self.assertEqual(of_type(rows, "kakaotalk-message"), [])
        inventory = of_type(rows, "kakaotalk-app-inventory")
        self.assertEqual(len(inventory), 1)
        details = inventory[0]["details"]
        self.assertEqual(details["decryption_status"], "no-key-material")
        self.assertEqual(details["status_label"], "복호 키 없음")
        self.assertTrue(details["reason"].startswith("복호 키 없음 — "))
        # Pictures are still listed (no message link).
        self.assertTrue(all(row["details"]["link_status"] == "메시지 연결 없음" for row in of_type(rows, "kakaotalk-shared-picture")))

    def test_wrong_key_material_is_key_mismatch_not_cracked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_kakaotalk_windows_fixture(root)  # registry + an opaque chatLogs_12345.edb (existing helper)
            rows = kakao_rows(root)
        inventory = of_type(rows, "kakaotalk-app-inventory")
        self.assertEqual(len(inventory), 1)
        details = inventory[0]["details"]
        self.assertEqual(details["decryption_status"], "key-mismatch")
        self.assertIn("복호 키 없음 — 키 후보", details["reason"])
        self.assertGreater(details["key_material"]["key_candidate_count"], 0)
        self.assertTrue(details["key_material"]["values_redacted"])
        self.assertEqual(of_type(rows, "kakaotalk-message"), [])

    def test_traces_without_chat_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_export(root)
            rows = kakao_rows(root)
        inventory = of_type(rows, "kakaotalk-app-inventory")
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["details"]["decryption_status"], "no-chat-database")
        self.assertTrue(inventory[0]["details"]["reason"].startswith("대화 DB 없음 — "))

    def test_corrupt_database_after_valid_header_is_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_export(root)
            paths = write_kakaotalk_pc_profile(root)
            key, iv = fixture_key_iv()
            first_page = encrypt_pagewise(build_chatlogs_sqlite(root / "p.sqlite")[:PAGE_SIZE], key, iv)
            paths["database"].write_bytes(first_page + os.urandom(PAGE_SIZE * 3))
            rows = kakao_rows(root)
        details = of_type(rows, "kakaotalk-app-inventory")[0]["details"]
        self.assertEqual(details["decryption_status"], "error")
        self.assertTrue(details["reason"].startswith("복호 오류 — "))
        self.assertEqual(of_type(rows, "kakaotalk-message"), [])
        self.assertTrue(of_type(rows, "kakaotalk-shared-picture"))

    def test_message_row_cap_is_disclosed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_export(root)
            write_kakaotalk_pc_profile(root, rows=20)
            with mock.patch.object(kakaotalk_messages, "MESSAGE_ROW_LIMIT", 5):
                rows = kakao_rows(root)
        self.assertEqual(len(of_type(rows, "kakaotalk-message")), 5)
        self.assertTrue(of_type(rows, "kakaotalk-app-inventory")[0]["details"]["message_rows_truncated"])

    def test_operator_key_from_environment(self) -> None:
        key, iv = fixture_key_iv()
        material = gather_key_material([], [], environ={"RAPIDTRIAGE_KAKAO_KEY_HEX": key.hex(), "RAPIDTRIAGE_KAKAO_IV_HEX": iv.hex()})
        self.assertTrue(material.operator_supplied)
        self.assertEqual(material.candidates[0]["source"], "operator-key-iv")
        self.assertEqual(material.public_summary()["key_candidate_count"], 1)

    def test_in_process_page_decryption_round_trip(self) -> None:
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, iv = os.urandom(16), os.urandom(16)
            plain = os.urandom(PAGE_SIZE * 70)  # spans more than one read chunk
            source = root / "chatLogs_1.edb"
            source.write_bytes(encrypt_pagewise(plain, key, iv) + b"tail")  # a non-block tail is ignored
            target = root / "plain.sqlite"
            digest = decrypt_pages_to_file(source, key, iv, target)
            self.assertEqual(target.read_bytes(), plain)
            self.assertEqual(digest, hashlib.sha256(plain).hexdigest())


class R2FixKakaoTests(unittest.TestCase):
    """Regression tests for the r2 review fixes of ``kakaotalk_messages`` (B1, M8 and minors)."""

    def profile_with_two_databases(self, root: Path) -> dict[str, Path]:
        write_registry_export(root)
        paths = write_kakaotalk_pc_profile(root)
        second = paths["database"].with_name("chatLogs_43.edb")
        second.write_bytes(paths["database"].read_bytes())
        paths["second"] = second
        return paths

    def test_b1_key_and_iv_never_in_rows_or_logs_on_failure_and_timeout(self) -> None:
        import logging

        class CapturingHandler(logging.Handler):
            def __init__(self, level: int) -> None:
                super().__init__(level)
                self.lines: list[str] = []

            def emit(self, record: logging.LogRecord) -> None:
                self.lines.append(f"{record.getMessage()} {record.args!r} {record.exc_info!r} {record.exc_text or ''}")

        key, iv = fixture_key_iv()
        command = ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nopad"]
        failures = {
            "called-process-error": subprocess.CalledProcessError(1, command, stderr=f"bad decrypt {key.hex()}".encode()),
            "timeout": subprocess.TimeoutExpired(command, 300),
            "os-error": OSError(f"openssl -K {key.hex()} -iv {iv.hex()} failed"),
        }
        for name, error in failures.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_registry_export(root)
                write_kakaotalk_pc_profile(root)
                handler = CapturingHandler(logging.DEBUG)
                logger = logging.getLogger()
                previous_level = logger.level
                logger.addHandler(handler)
                logger.setLevel(logging.DEBUG)
                try:
                    with (
                        mock.patch.dict(os.environ, {"RAPIDTRIAGE_KAKAO_OPENSSL": "1"}),
                        mock.patch.object(kakaotalk_messages, "decrypt_pages_to_file", side_effect=error),
                        mock.patch("subprocess.run", side_effect=error) as run,
                    ):
                        rows = kakao_rows(root)
                finally:
                    logger.removeHandler(handler)
                    logger.setLevel(previous_level)
                run.assert_not_called()  # no external program, opt-in or not
                details = of_type(rows, "kakaotalk-app-inventory")[0]["details"]
                self.assertEqual(details["decryption_status"], "error")
                self.assertIn(details["chat_databases"][0]["reason_code"], {"read-error", "unexpected-error"})
                payload = json.dumps(rows, ensure_ascii=False) + "\n".join(handler.lines)
                for secret in (key.hex(), iv.hex(), key.hex().upper(), iv.hex().upper()):
                    self.assertNotIn(secret, payload)
                self.assertNotIn("openssl", details["reason"])

    def test_m8_no_external_program_and_shared_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.profile_with_two_databases(root)
            with (
                mock.patch.dict(os.environ, {"RAPIDTRIAGE_KAKAO_OPENSSL": "1"}),
                mock.patch("subprocess.run", side_effect=AssertionError("external program")) as run,
                mock.patch("subprocess.Popen", side_effect=AssertionError("external program")) as popen,
            ):
                decrypted = kakao_rows(root)
            run.assert_not_called()
            popen.assert_not_called()
            size = (root / "Users" / "alice" / "AppData" / "Local" / "Kakao" / "KakaoTalk" / "users" / "abc123" / "chat_data" / "chatLogs_42.edb").stat().st_size
            with mock.patch.object(kakaotalk_messages, "DECRYPT_TOTAL_BYTES", size + 1):
                byte_budget = kakao_rows(root)
            with mock.patch.object(kakaotalk_messages, "DECRYPT_TIME_BUDGET_SECONDS", 0.0):
                time_budget = kakao_rows(root)
            with mock.patch.object(kakaotalk_messages, "MESSAGE_ROW_LIMIT", 4), mock.patch.object(
                kakaotalk_messages, "decrypt_pages_to_file", wraps=kakaotalk_messages.decrypt_pages_to_file
            ) as decrypt:
                row_budget = kakao_rows(root)
            with mock.patch.object(kakaotalk_messages, "DECRYPT_LIMIT_BYTES", size - 1), mock.patch.dict(os.environ, {"RAPIDTRIAGE_KAKAO_OPENSSL": "1"}):
                size_cap = kakao_rows(root)

        def statuses(rows: list[dict[str, object]]) -> list[str]:
            return [item["status"] for item in of_type(rows, "kakaotalk-app-inventory")[0]["details"]["chat_databases"]]

        self.assertEqual(statuses(decrypted), ["decrypted", "decrypted"])
        self.assertEqual(len(of_type(decrypted, "kakaotalk-message")), 8)
        self.assertEqual(statuses(byte_budget), ["decrypted", "budget"])
        self.assertEqual(statuses(time_budget), ["budget", "budget"])
        self.assertEqual(of_type(time_budget, "kakaotalk-app-inventory")[0]["details"]["decryption_status"], "budget")
        self.assertEqual(statuses(row_budget), ["decrypted", "budget"])  # row budget used up: second DB not decrypted
        self.assertEqual(decrypt.call_count, 1)
        self.assertEqual(of_type(row_budget, "kakaotalk-app-inventory")[0]["details"]["chat_databases"][1]["reason_code"], "row-budget")
        self.assertEqual(statuses(size_cap), ["size-cap", "size-cap"])

    def test_plaintext_temp_unlink_is_retried_and_failure_disclosed(self) -> None:
        before = set(Path(tempfile.gettempdir()).glob("rt-kakao-*"))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain.sqlite"
            target.write_bytes(b"x")
            real_unlink = Path.unlink
            calls: list[int] = []

            def flaky(path: Path, missing_ok: bool = False) -> None:
                calls.append(1)
                if len(calls) < 3:
                    raise PermissionError(32, "sharing violation")
                real_unlink(path, missing_ok=missing_ok)

            with mock.patch.object(Path, "unlink", flaky), mock.patch.object(kakaotalk_messages.time, "sleep"):
                self.assertTrue(kakaotalk_messages.remove_plaintext(target))
            self.assertEqual(len(calls), 3)
            self.assertFalse(target.exists())

            root = Path(tmp) / "evidence"
            write_registry_export(root)
            write_kakaotalk_pc_profile(root)
            with mock.patch.object(kakaotalk_messages, "remove_plaintext", return_value=False):
                rows = kakao_rows(root)
        for leftover in set(Path(tempfile.gettempdir()).glob("rt-kakao-*")) - before:
            leftover.unlink()
        details = of_type(rows, "kakaotalk-app-inventory")[0]["details"]
        self.assertEqual(details["plaintext_temp_cleanup_failed"], 1)
        self.assertTrue(details["chat_databases"][0]["plaintext_temp_cleanup_failed"])
        self.assertNotIn("rt-kakao-", json.dumps(rows, ensure_ascii=False))

    def test_unreadable_file_does_not_abort_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_registry_export(root)
            write_kakaotalk_pc_profile(root)
            memory = root / "memory.raw"
            memory.write_bytes(b"RAM")
            with (
                mock.patch.object(kakaotalk_messages, "compute_hashes", side_effect=PermissionError(13, "locked")),
                mock.patch.object(kakaotalk_messages, "scan_pk_candidates_from_file", side_effect=OSError("locked")),
            ):
                rows = [record.to_dict() for record in kakaotalk_messages.collect_kakaotalk_message_rows(
                    root,
                    app_databases=list(root.rglob("chatLogs_*.edb")),
                    registry_paths=list(root.rglob("*.reg")),
                    memory_paths=[memory],
                    has_traces=True,
                )]
        self.assertEqual(len(of_type(rows, "kakaotalk-message")), 4)
        pictures = of_type(rows, "kakaotalk-shared-picture")
        self.assertEqual(len(pictures), 2)
        self.assertTrue(all(row["details"]["sha256"] == "" for row in pictures))

    def test_key_candidates_truncated_by_priority_before_building(self) -> None:
        pk = {"pk": "A" * 40, "uid": "12345", "source_path": "memory.raw", "source_offset": 0}
        builder = kakaotalk_messages.build_candidate_key_materials_from_pragma_candidates
        with tempfile.TemporaryDirectory() as tmp:
            reg = write_registry_export(Path(tmp))
            with (
                mock.patch.object(kakaotalk_messages, "KEY_CANDIDATE_LIMIT", 3),
                mock.patch.object(kakaotalk_messages, "scan_pk_candidates_from_file", return_value=[pk]),
                mock.patch.object(kakaotalk_messages, "build_candidate_key_materials_from_pragma_candidates", wraps=builder) as spy,
            ):
                material = gather_key_material([reg], [Path(tmp) / "memory.raw"], environ={})
        self.assertEqual(len(material.candidates), 3)
        self.assertEqual(material.candidates[0]["source"], "pk-memory-candidate")
        self.assertEqual(len(spy.call_args.args[0]), 1)  # 2 slots / (2 keys x 1 user id): one pragma built, not all

    def test_page_size_is_read_from_the_sqlite_header(self) -> None:
        import sqlite3

        self.assertEqual(kakaotalk_messages.sqlite_page_size(bytes(16) + b"\x00\x01"), 65536)
        self.assertEqual(kakaotalk_messages.sqlite_page_size(bytes(16) + b"\x10\x00"), 4096)
        key, iv = fixture_key_iv()
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "big-pages.sqlite"
            connection = sqlite3.connect(scratch)
            connection.execute("PRAGMA page_size = 8192")
            connection.execute("CREATE TABLE chatLogs (logId INTEGER PRIMARY KEY, sendAt INTEGER, message TEXT)")
            connection.commit()
            connection.close()
            source = Path(tmp) / "chatLogs_9.edb"
            source.write_bytes(encrypt_pagewise(scratch.read_bytes(), key, iv))
            material = kakaotalk_messages.KeyMaterial(candidates=[{"key": key, "iv": iv, "source": "test"}])
            result = kakaotalk_messages.decrypt_chat_database(source, material, remaining_rows=10)
        self.assertEqual((result.status, result.reason_code), ("error", "page-size-mismatch"))

    def test_epoch_to_iso_rejects_non_numeric(self) -> None:
        for value in ("abc", "", None, object(), [1], b"x", float("nan"), float("inf"), 3e18, -5, True):
            with self.subTest(value=value):
                self.assertEqual(kakaotalk_messages.epoch_to_iso(value), "")
        self.assertEqual(kakaotalk_messages.epoch_to_iso(1710000000), "2024-03-09T16:00:00Z")
        self.assertEqual(kakaotalk_messages.epoch_to_iso("1710000000123"), "2024-03-09T16:00:00.123000Z")

    def test_overall_status_ranks_error_above_decrypted(self) -> None:
        results = [
            kakaotalk_messages.DatabaseResult(Path("chatLogs_1.edb"), "decrypted"),
            kakaotalk_messages.failed(Path("chatLogs_2.edb"), "sqlite-error"),
        ]
        self.assertEqual(kakaotalk_messages.overall_status(results), "error")
        reason = kakaotalk_messages.inventory_reason("error", material=kakaotalk_messages.KeyMaterial(), db_count=2, results=results)
        self.assertTrue(reason.startswith("복호 오류 — 대화 DB 2개 중 1개 오류"))
        self.assertIn("복호 완료 1개", reason)

    def test_find_picture_paths_is_bounded_without_sorting_the_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "카카오톡 받은 파일"
            folder.mkdir()
            for index in (5, 3, 9, 1, 7):
                (folder / f"photo{index}.jpg").write_bytes(b"\xff\xd8\xff")
            (folder / "notes.txt").write_text("x")
            with (
                mock.patch.object(kakaotalk_messages, "PICTURE_ROW_LIMIT", 2),
                mock.patch.object(kakaotalk_messages, "sorted", side_effect=AssertionError("full sort"), create=True),
            ):
                found = [path.name for path, _kind in kakaotalk_messages.find_picture_paths(Path(tmp))]
        self.assertEqual(found, ["photo1.jpg", "photo3.jpg"])

    def test_basename_link_only_for_distinctive_names(self) -> None:
        def picture(name: str) -> dict[str, object]:
            return {"path": Path("cache") / name, "hashes": {}, "link": None}

        generic, generic_numeric = picture("image.jpg"), picture("1.png")
        saved, hashed = picture("KakaoTalk_20240309_160200123.jpg"), picture("i_3f9a1c7e5b2d4086.jpg")
        message = {
            "message_id": "7",
            "attachments": [{"checksums": [], "basenames": ["image.jpg", "1.png", "KakaoTalk_20240309_160200123.jpg", "i_3f9a1c7e5b2d4086.jpg"]}],
        }
        kakaotalk_messages.link_pictures([generic, generic_numeric, saved, hashed], [message])
        self.assertIsNone(generic["link"])
        self.assertIsNone(generic_numeric["link"])
        self.assertEqual(saved["link"]["method"], "basename")  # type: ignore[index]
        self.assertEqual(hashed["link"]["method"], "basename")  # type: ignore[index]
        self.assertTrue(kakaotalk_messages.distinctive_name("abcdef.jpg", ["ABCDEF"]))  # checksum-named file


class OutlookAndIcsTests(unittest.TestCase):
    def test_ics_three_events_and_unterminated_event_skipped(self) -> None:
        events, errors = parse_ics_events(ICS_THREE_EVENTS)
        self.assertEqual(len(events), 3)
        self.assertEqual(errors, 1)
        self.assertEqual(events[0]["summary"], "분기 실적 검토, 1차")
        self.assertEqual(events[0]["dtstart"], "2024-03-05T01:00:00Z")
        self.assertEqual(events[0]["description"], "첫 줄\n둘째 줄 접힌 줄 이어짐")
        self.assertEqual(events[0]["attendees"], ["Bob Lee <bob@example.com>", "Partner, Inc <carol@partner.example.net>"])
        self.assertEqual(events[1]["dtstart"], "2024-03-06T00:00:00Z")  # 09:00 Asia/Seoul
        self.assertEqual(events[1]["timezone"], "Asia/Seoul")
        self.assertEqual(events[2]["dtstart"], "2024-03-10")
        self.assertTrue(events[2]["all_day"])

    def test_windows_tzid_is_mapped(self) -> None:
        text = ICS_THREE_EVENTS.replace("TZID=Asia/Seoul", 'TZID="Korea Standard Time"')
        events, _errors = parse_ics_events(text)
        self.assertEqual(events[1]["dtstart"], "2024-03-06T00:00:00Z")
        self.assertEqual(events[1]["timezone"], "Korea Standard Time")

    def test_tool_time_formats(self) -> None:
        self.assertEqual(parse_tool_time("Mar 04, 2024 01:02:03.123456789 UTC"), "2024-03-04T01:02:03.123456Z")
        self.assertEqual(parse_tool_time("Not set"), "")
        self.assertEqual(parse_tool_time("Mon, 04 Mar 2024 10:02:03 +0900"), "2024-03-04T01:02:03Z")

    def test_provider_without_tool_emits_container_inventory_and_ics_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "alice.pst").write_bytes(PST_HEADER)
            (root / "meetings.ics").write_text(ICS_THREE_EVENTS, encoding="utf-8")
            (root / "broken.ics").write_bytes(b"\x00\xff" * 512)
            with mock.patch("rapidtriage.artifacts.email_pst.shutil.which", no_tools):
                rows = [record.to_dict() for record in EmailArtifactsProvider().collect(root)]
        inventory = of_type(rows, "email-container-inventory")
        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["details"]["status"], "tool-missing")
        self.assertTrue(inventory[0]["details"]["reason"].startswith("외부 도구 없음 — "))
        self.assertIn("tools:email-pst", inventory[0]["details"]["reason"])
        events = of_type(rows, "calendar-event")
        self.assertEqual(len(events), 3)
        self.assertTrue(all(row["path"].endswith("meetings.ics") for row in events))
        self.assertEqual(events[0]["details"]["source_format"], "ics")
        self.assertEqual(len(of_type(rows, "email-mailbox")), 1)  # the existing string inventory stays

    def test_fake_pffexport_run_is_normalised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pst = Path(tmp) / "alice.pst"
            pst.write_bytes(PST_HEADER)
            rows = [
                record.to_dict()
                for record in collect_outlook_container(pst, tool_resolver=fake_tool_resolver, command_runner=fake_pffexport_runner, environ={"RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS": "1"})
            ]
            leftovers = [path for path in Path(tempfile.gettempdir()).glob("rt-pst-*") if path.is_dir()]
        messages = {row["details"]["subject"]: row["details"] for row in of_type(rows, "email-message")}
        self.assertEqual(set(messages), {"견적 요청", "자료 송부", "삭제한 메일", "복구된 메일"})
        sent = messages["자료 송부"]
        self.assertEqual(sent["to"], "Mallory <mallory@gmail.com>")
        self.assertEqual(sent["cc"], "Bob Lee <bob@example.com>")
        self.assertEqual(sent["bcc"], "Hidden <hidden@partner.example.net>")
        self.assertEqual(sent["folder"], "Top of Personal Folders/Sent Items")
        self.assertEqual(sent["submit_time"], "2024-03-05T10:00:00Z")
        self.assertEqual(sent["attachment_count"], 2)
        self.assertEqual(sent["recovery_method"], "external-tool:pffexport")
        inbox = messages["견적 요청"]
        self.assertEqual(inbox["message_id"], "<inbox-1@example.com>")
        self.assertEqual(inbox["read_state"], "읽음")
        self.assertEqual(inbox["thread_id"], "01D9 AABB CCDD")
        self.assertEqual(inbox["delivery_time"], "2024-03-04T01:02:03.123456Z")
        self.assertEqual(messages["삭제한 메일"]["deleted_state"], "deleted-folder")
        self.assertEqual(messages["삭제한 메일"]["read_state"], "읽지 않음")
        self.assertEqual(messages["복구된 메일"]["deleted_state"], "recovered")
        attachments = of_type(rows, "email-attachment")
        self.assertEqual(sorted(row["details"]["filename"] for row in attachments), ["고객명단.xlsx", "설계도.pdf"])
        self.assertTrue(all(len(row["details"]["sha256"]) == 64 and row["details"]["message_subject"] == "자료 송부" for row in attachments))
        event = of_type(rows, "calendar-event")[0]["details"]
        self.assertEqual((event["title"], event["start"], event["location"]), ("주간 회의", "2024-03-07T01:00:00Z", "대회의실"))
        self.assertEqual(event["attendees"], ["Bob Lee <bob@example.com>"])
        contact = of_type(rows, "contact")[0]["details"]
        self.assertEqual((contact["display_name"], contact["email"], contact["organization"]), ("Lee, Bob", "bob@example.com", "Example Corp"))
        self.assertEqual(contact["phones"], ["+82-2-555-0100", "010-5555-0101"])
        inventory = of_type(rows, "email-container-inventory")[0]["details"]
        self.assertEqual(inventory["status"], "normalized")
        self.assertEqual((inventory["message_count"], inventory["attachment_count"]), (4, 2))
        self.assertEqual(inventory["item_error_count"], 1)  # the damaged Message00002 is skipped, not fatal
        self.assertEqual(leftovers, [])  # the temporary export is removed

    def test_failed_tool_and_disabled_tool(self) -> None:
        def failing(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "", "libpff: unable to open file")

        with tempfile.TemporaryDirectory() as tmp:
            pst = Path(tmp) / "broken.ost"
            pst.write_bytes(PST_HEADER)
            failed = collect_outlook_container(pst, tool_resolver=fake_tool_resolver, command_runner=failing, environ={"RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS": "1"})
            disabled = collect_outlook_container(pst, tool_resolver=fake_tool_resolver, environ={})  # default: off
            wrong_header = Path(tmp) / "fake.pst"
            wrong_header.write_bytes(b"not a pst")
            blocked = collect_outlook_container(wrong_header, tool_resolver=fake_tool_resolver, command_runner=fake_pffexport_runner, environ={"RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS": "1"})
        self.assertEqual([record.details["status"] for record in failed], ["failed"])
        self.assertIn("unable to open", failed[0].details["reason"])
        self.assertEqual([record.details["status"] for record in disabled], ["disabled"])
        self.assertEqual([record.details["status"] for record in blocked], ["blocked"])
        self.assertTrue(blocked[0].details["reason"].startswith("헤더 불일치"))

    def test_readpst_tree_is_normalised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tree = write_readpst_tree(Path(tmp))
            records, counts = normalize_readpst_tree(tree, base={"source_path": "x.pst"})
        self.assertEqual((counts["messages"], counts["attachments"], counts["events"], counts["contacts"]), (2, 1, 3, 1))
        message = next(record.details for record in records if record.artifact_type == "email-message")
        self.assertEqual((message["subject"], message["read_state"], message["folder"]), ("readpst one", "읽음", "Personal Folders/Inbox"))
        self.assertEqual(message["attachments"][0]["filename"], "a.pdf")

    def test_pffexport_tree_survives_missing_and_odd_folders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            records, counts = normalize_pffexport_tree(Path(tmp) / "missing", base={"source_path": "x.pst"})
            self.assertEqual((records, counts["messages"]), ([], 0))
            tree = write_pffexport_tree(Path(tmp) / "export")
            (tree / "mailbox.export" / "Top of Personal Folders" / "Inbox" / "Message00009").write_text("a file, not a folder")
            records, counts = normalize_pffexport_tree(tree, base={"source_path": "x.pst"})
        self.assertEqual(counts["messages"], 4)


class RunPipelineTests(unittest.TestCase):
    def test_run_writes_new_rows_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "evidence"
            root.mkdir()
            write_registry_export(root)
            from tests.kakaotalk_message_fixtures import TRIAGE_ROWS

            write_kakaotalk_pc_profile(root, extra=TRIAGE_ROWS)  # logId gap, a we.tl link, a missing attachment
            (root / "Users" / "alice" / "meetings.ics").write_text(ICS_THREE_EVENTS, encoding="utf-8")
            (root / "Users" / "alice" / "alice.pst").write_bytes(PST_HEADER)
            output_dir = Path(tmp) / "out"
            with (
                mock.patch.dict(os.environ, NO_OPERATOR_ENV),
                mock.patch("rapidtriage.artifacts.email_pst.shutil.which", no_tools),
            ):
                self.assertEqual(main(["run", str(root), "--mode", "hacking", "--output-dir", str(output_dir), "--read-only"]), 0)
            types: dict[str, int] = {}
            for name in ("kakaotalk-windows", "email"):
                path = output_dir / "artifacts" / f"rapidtriage-artifacts-{name}.jsonl"
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        artifact_type = json.loads(line)["artifact_type"]
                        types[artifact_type] = types.get(artifact_type, 0) + 1
            flag_dirs = sorted((output_dir / "analyses").glob("run-triage-flags-*"))
            self.assertEqual(len(flag_dirs), 1)
            flagged: dict[str, set[str]] = {}
            for line in (flag_dirs[0] / "flags.jsonl").read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entry = json.loads(line)
                    for flag in entry["flags"]:
                        flagged.setdefault(flag["id"], set()).add(entry["kind"])
            summary = json.loads((flag_dirs[0] / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(types.get("kakaotalk-message"), 6)
        self.assertEqual(types.get("kakaotalk-app-inventory"), 1)
        self.assertEqual(types.get("kakaotalk-shared-picture"), 2)
        self.assertEqual(types.get("calendar-event"), 3)
        self.assertEqual(types.get("email-container-inventory"), 1)
        # The triage stage flags the decrypted KakaoTalk rows (the PST has no tool, so no mail rows to flag).
        expected = {"messenger.id_gap", "messenger.external_share_link", "messenger.attachment_missing"}
        self.assertLessEqual(expected, set(flagged))
        self.assertTrue(all(flagged[rule_id] == {"kakaotalk-windows"} for rule_id in expected))
        self.assertTrue(all(summary["by_rule"].get(rule_id) == 1 for rule_id in expected))


class R2FixEmailTests(unittest.TestCase):
    """R2 fix regressions for Outlook PST/OST rows, the external-tool wrapper and the e-mail triage rules."""

    # --- M9: external tool guard rails -------------------------------------------------------

    def test_m9_monitored_tool_is_killed_past_export_cap_and_output_is_bounded(self) -> None:
        import sys
        import time

        from rapidtriage.artifacts.email_external import (
            EMAIL_EXTERNAL_OUTPUT_TAIL_BYTES,
            run_monitored_command,
        )

        script = (
            "import pathlib, sys, time\n"
            "sys.stdout.write('x' * 300000)\n"
            "sys.stdout.flush()\n"
            "target = pathlib.Path(sys.argv[1])\n"
            "for index in range(100000):\n"
            "    (target / f'{index}.bin').write_bytes(b'x' * 65536)\n"
            "    time.sleep(0.01)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            watch = Path(tmp) / "export"
            watch.mkdir()
            started = time.monotonic()
            completed, reason = run_monitored_command(
                [sys.executable, "-c", script, str(watch)], timeout=60, watch_dir=watch, max_bytes=512 * 1024, poll_seconds=0.1
            )
            elapsed = time.monotonic() - started
        self.assertEqual(reason, "export-size-cap")
        self.assertNotEqual(completed.returncode, 0)
        self.assertLess(elapsed, 45)
        self.assertLessEqual(len(completed.stdout), EMAIL_EXTERNAL_OUTPUT_TAIL_BYTES)

    def test_m9_wrapper_checks_free_space_and_export_size(self) -> None:
        from rapidtriage.artifacts import email_external

        calls: list[list[str]] = []

        def big_export(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            target = Path(command[command.index("-t") + 1])
            target.parent.mkdir(parents=True, exist_ok=True)
            (target.parent / "huge.bin").write_bytes(b"\0" * 4096)
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with tempfile.TemporaryDirectory() as tmp:
            pst = Path(tmp) / "alice.pst"
            pst.write_bytes(PST_HEADER)
            capped = email_external.run_email_external_parse(
                source_path=pst, output_dir=Path(tmp) / "a", tool_resolver=fake_tool_resolver, command_runner=big_export, max_export_bytes=1024
            )
            with mock.patch.object(email_external.shutil, "disk_usage", return_value=mock.Mock(free=10)):
                no_space = email_external.run_email_external_parse(
                    source_path=pst, output_dir=Path(tmp) / "b", tool_resolver=fake_tool_resolver, command_runner=big_export
                )
        self.assertEqual(capped["status"], "failed")
        self.assertEqual(capped["execution"]["limit_exceeded"], "export-size-cap")
        self.assertEqual(no_space["status"], "failed")
        self.assertEqual(no_space["execution"]["limit_exceeded"], "insufficient-free-space")
        self.assertEqual(len(calls), 1)  # the tool never ran without free space

    def test_m9_container_is_hashed_once(self) -> None:
        from rapidtriage.artifacts import email as email_module
        from rapidtriage.artifacts import email_external, email_pst
        from rapidtriage.core.hash_cache import compute_hashes_fresh

        hashed: list[str] = []

        def counting(path: Path, **_kwargs: object) -> dict[str, str]:
            hashed.append(Path(path).name)
            return compute_hashes_fresh(Path(path))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "alice.pst").write_bytes(PST_HEADER)
            with (
                mock.patch.object(email_module, "compute_hashes", counting),
                mock.patch.object(email_pst, "compute_hashes", counting),
                mock.patch.object(email_external, "compute_hashes", counting),
                mock.patch.object(email_pst.shutil, "which", no_tools),
            ):
                rows = [record.to_dict() for record in EmailArtifactsProvider().collect(root)]
                hashes = compute_hashes_fresh(root / "alice.pst")
                hashed.clear()
                exported = collect_outlook_container(
                    root / "alice.pst",
                    tool_resolver=fake_tool_resolver,
                    command_runner=fake_pffexport_runner,
                    environ={"RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS": "1"},
                    source_hashes=hashes,
                )
        self.assertEqual(len(of_type(rows, "email-container-inventory")), 1)
        self.assertEqual(hashed.count("alice.pst"), 0)
        self.assertEqual(exported[-1].details["source_sha256"], hashes["sha256"])

    # --- M13 / M14 / M15 / M23 rules ------------------------------------------------------

    def run_regression_case(self, name: str) -> None:
        from tests.triage_cases import run_case
        from tests.triage_cases.email import REGRESSION_CASES

        rule_id, case = REGRESSION_CASES[name]
        flagged, expected, summary = run_case(case, rule_id)
        self.assertNotIn(rule_id, summary.get("rule_errors") or {})
        self.assertEqual(flagged, expected, name)

    def test_m13_inbound_heavy_mailbox_does_not_fire_bulk_attachments(self) -> None:
        self.run_regression_case("inbound_heavy_mailbox")

    def test_m13_owner_from_sent_folder(self) -> None:
        self.run_regression_case("sent_folder_owner")

    def test_m14_duplicate_message_id_and_inline_parts_not_counted(self) -> None:
        self.run_regression_case("duplicate_and_inline")

    def test_m15_future_dated_spam_does_not_hide_recent_deletion(self) -> None:
        self.run_regression_case("future_dated_spam")

    def test_m23_x500_sender_uses_smtp_property_in_rules(self) -> None:
        self.run_regression_case("x500_sender")

    def test_m23_pffexport_x500_sender_prefers_smtp_and_records_address_type(self) -> None:
        from tests.email_pst_fixtures import write_item

        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "export"
            write_item(
                tree / "mailbox.export" / "Top of Personal Folders" / "Sent Items" / "Message00001",
                {
                    "OutlookHeaders.txt": (
                        "Client submit time:\t\tMar 05, 2024 10:00:00 UTC\nSubject:\t\t\tX500\nSender name:\t\t\tAlice Kim\n"
                        "Sender email address:\t\t/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP (FYDIBOHF23SPDLT)/CN=RECIPIENTS/CN=ALICE\n"
                        "Sender address type:\t\tEX\nSender SMTP address:\t\talice@example.com\n"
                    ),
                    "Recipients.txt": (
                        "Recipient: 1\nDisplay name:\t\tBob\nEmail address:\t\t/O=EXCHANGELABS/OU=X/CN=RECIPIENTS/CN=BOB\n"
                        "SMTP address:\t\tbob@example.com\nRecipient type:\t\tTo\n"
                    ),
                },
            )
            records, _counts = normalize_pffexport_tree(tree, base={"source_path": "x.pst"})
        message = records[0].details
        self.assertEqual(message["from"], "Alice Kim <alice@example.com>")
        self.assertEqual(message["address_type"], "EX")
        self.assertEqual(message["sender_smtp_address"], "alice@example.com")
        self.assertTrue(message["sender_x500_address"].startswith("/O=EXCHANGELABS/"))
        self.assertEqual(message["to"], "Bob <bob@example.com>")

    # --- M21: time zones without tzdata ---------------------------------------------------

    def test_m21_ics_timezones_without_tzdata(self) -> None:
        from rapidtriage.artifacts.email_pst import parse_ics_time

        def no_tzdata(key: str) -> object:
            raise KeyError(key)

        with mock.patch("zoneinfo.ZoneInfo", side_effect=no_tzdata):
            seoul = parse_ics_time("20240306T090000", {"TZID": "Korea Standard Time"})
            iana = parse_ics_time("20240306T090000", {"TZID": "Asia/Tokyo"})
            eastern_summer = parse_ics_time("20240701T090000", {"TZID": "Eastern Standard Time"})
            eastern_winter = parse_ics_time("20240115T090000", {"TZID": "Eastern Standard Time"})
            berlin_summer = parse_ics_time("20240701T090000", {"TZID": "W. Europe Standard Time"})
            london_winter = parse_ics_time("20240115T090000", {"TZID": "GMT Standard Time"})
            unknown = parse_ics_time("20240306T090000", {"TZID": "Custom Zone"})
            old_dst = parse_ics_time("19900701T090000", {"TZID": "Pacific Standard Time"})
        self.assertEqual(seoul, ("2024-03-06T00:00:00Z", False, "Korea Standard Time", "converted-offset-table"))
        self.assertEqual(iana[0], "2024-03-06T00:00:00Z")
        self.assertEqual(eastern_summer[0], "2024-07-01T13:00:00Z")
        self.assertEqual(eastern_winter[0], "2024-01-15T14:00:00Z")
        self.assertEqual(berlin_summer[0], "2024-07-01T07:00:00Z")
        self.assertEqual(london_winter[0], "2024-01-15T09:00:00Z")
        for value in (unknown, old_dst):
            self.assertEqual(value[3], "unconverted")
            self.assertFalse(value[0].endswith("Z"))
            self.assertNotIn("UTC", value[2])

    def test_m21_offset_table_matches_zoneinfo_around_transitions(self) -> None:
        import datetime as dt

        from rapidtriage.artifacts.email_pst import DST_TZ_RULES, fallback_utc_offset

        try:
            from zoneinfo import ZoneInfo

            ZoneInfo("America/New_York")
        except Exception:
            self.skipTest("tzdata not installed")
        for zone in ("America/New_York", "America/Los_Angeles", "Europe/London", "Europe/Berlin"):
            self.assertIn(zone, DST_TZ_RULES)
            info = ZoneInfo(zone)
            for day in (dt.datetime(2024, 3, 10), dt.datetime(2024, 3, 31), dt.datetime(2024, 10, 27), dt.datetime(2024, 11, 3)):
                for half_hours in range(48):
                    wall = day + dt.timedelta(minutes=30 * half_hours)
                    self.assertEqual(fallback_utc_offset(zone, wall), wall.replace(tzinfo=info).utcoffset(), f"{zone} {wall}")

    # --- minors ------------------------------------------------------------------------------

    def test_minor_deleted_folder_names_exact_segments_and_languages(self) -> None:
        from rapidtriage.artifacts import email_pst
        from rapidtriage.core.triage_rules import email as email_rules

        self.assertIs(email_pst.folder_is_deleted, email_rules.folder_is_deleted)
        for folder in (
            "Top/Deleted Items",
            "Top/지운 편지함",
            "削除済みアイテム",
            "已删除邮件",
            "已刪除的郵件",
            "Gelöschte Elemente",
            "Éléments supprimés",
            "Elementos eliminados",
            "Recoverable Items/Deletions",
        ):
            self.assertTrue(email_pst.folder_is_deleted(folder), folder)
        for folder in ("Inbox/Undeleted", "Projects/deleted-reports", "Inbox", ""):
            self.assertFalse(email_pst.folder_is_deleted(folder), folder)

    def test_minor_export_item_limit_is_disclosed(self) -> None:
        from rapidtriage.artifacts import email_pst

        with tempfile.TemporaryDirectory() as tmp:
            tree = write_pffexport_tree(Path(tmp) / "export")
            with mock.patch.object(email_pst, "EXPORT_ITEM_LIMIT", 2):
                _records, counts = normalize_pffexport_tree(tree, base={"source_path": "x.pst"})
                pst = Path(tmp) / "alice.pst"
                pst.write_bytes(PST_HEADER)
                inventory = email_pst.container_inventory(pst, source_sha256="0" * 64, status="normalized", reason="", counts=counts)
        self.assertEqual(counts["items"], 2)
        self.assertEqual(counts["truncated"], 1)
        self.assertTrue(inventory.details["export_truncated"])
        self.assertEqual(inventory.details["export_item_limit"], 2)

    def test_minor_tool_timeout_upper_bound(self) -> None:
        from rapidtriage.artifacts.email_pst import MAX_TOOL_TIMEOUT, tool_timeout

        self.assertEqual(tool_timeout({"RAPIDTRIAGE_EMAIL_TOOL_TIMEOUT": "99999999"}), MAX_TOOL_TIMEOUT)
        self.assertEqual(tool_timeout({"RAPIDTRIAGE_EMAIL_TOOL_TIMEOUT": "1"}), 30)

    def test_minor_readpst_folder_dots_kept_and_dotdot_neutralised(self) -> None:
        from rapidtriage.artifacts.email_pst import safe_folder

        with tempfile.TemporaryDirectory() as tmp:
            export = Path(tmp)
            folder = export / ".Archive" / "Inbox"  # the old .strip(".") turned this into "Archive/Inbox"
            folder.mkdir(parents=True)
            (folder / "1").write_bytes(b"From: a@example.com\nSubject: dots\n\nbody\n")
            records, _counts = normalize_readpst_tree(export, base={"source_path": "x.pst"})
        self.assertEqual(records[0].details["folder"], ".Archive/Inbox")
        self.assertEqual(safe_folder(["Top", "..", "x"]), "Top/．．/x")
        self.assertNotIn("..", safe_folder(["..", "."]).split("/"))

    def test_minor_inline_parts_excluded_from_attachment_count(self) -> None:
        import email as email_lib
        from email import policy

        from rapidtriage.artifacts.email_pst import file_attachment, mbox_message

        raw = (
            b"From: a@example.com\nTo: b@example.net\nSubject: sig\nMIME-Version: 1.0\n"
            b"Content-Type: multipart/mixed; boundary=XX\n\n--XX\nContent-Type: text/plain\n\nbody\n"
            b"--XX\nContent-Type: image/png\nContent-ID: <image001.png@01DA>\nContent-Disposition: inline; filename=\"image001.png\"\n\nPNG\n"
            b"--XX\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=\"a.pdf\"\n\n%PDF\n--XX--\n"
        )
        message = mbox_message(email_lib.message_from_bytes(raw, policy=policy.default), folder="Sent Items", deleted="")
        self.assertEqual((message["attachment_count"], message["inline_attachment_count"]), (1, 1))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image002.jpg"
            path.write_bytes(b"\xff\xd8\xff")
            self.assertTrue(file_attachment(path)["inline"])

    def test_minor_mime_header_fuzz_raises_nothing(self) -> None:
        import email as email_lib
        import random
        from email import policy

        from rapidtriage.artifacts.email_pst import mbox_message

        rng = random.Random(1)
        names = ["From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "In-Reply-To", "Reply-To", "Return-Path", "Received", "Content-Type", "Content-Disposition", "Content-ID"]
        alphabet = list('<>@"(),;:\\=?.[] \t\r\nabc/O') + ["=?utf-8?q?", "=?", "?=", "=?x?b?", "\x00", "\udcff"]
        for _ in range(500):
            lines = [name + ": " + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 25))) for name in rng.sample(names, 6)]
            raw = ("\n".join(lines) + "\n\nbody").encode("utf-8", "surrogateescape")
            try:
                mbox_message(email_lib.message_from_bytes(raw, policy=policy.default), folder="x", deleted="")
            except (OSError, ValueError, UnicodeError, LookupError):
                pass  # the normaliser counts these as item errors


if __name__ == "__main__":
    unittest.main()
