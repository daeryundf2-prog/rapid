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
        self.assertEqual(photo["attachment_name"], "i_sample.jpg")
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
        thumb = pictures["i_sample.jpg"]
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

    @unittest.skipIf(shutil.which("openssl") is None, "OpenSSL fast path")
    def test_openssl_and_pure_python_page_decryption_agree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, iv = os.urandom(16), os.urandom(16)
            plain = os.urandom(PAGE_SIZE * 5)
            source = root / "chatLogs_1.edb"
            source.write_bytes(encrypt_pagewise(plain, key, iv))
            fast, slow = root / "fast.sqlite", root / "slow.sqlite"
            digest_fast = decrypt_pages_to_file(source, key, iv, fast, openssl_bin=shutil.which("openssl"))
            digest_slow = decrypt_pages_to_file(source, key, iv, slow, openssl_bin=None)
            self.assertEqual(fast.read_bytes(), plain)
            self.assertEqual(slow.read_bytes(), plain)
            self.assertEqual(digest_fast, digest_slow)


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
            write_kakaotalk_pc_profile(root)
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
        self.assertEqual(types.get("kakaotalk-message"), 4)
        self.assertEqual(types.get("kakaotalk-app-inventory"), 1)
        self.assertEqual(types.get("kakaotalk-shared-picture"), 2)
        self.assertEqual(types.get("calendar-event"), 3)
        self.assertEqual(types.get("email-container-inventory"), 1)


if __name__ == "__main__":
    unittest.main()
