from __future__ import annotations

import json
import hashlib
import hmac
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.kakaotalk import (
    PAGE_SIZE,
    derive_kakaotalk_key_iv,
    derive_kakaotalk_key_iv_from_pk,
    derive_kakaotalk_userdir,
    derive_pragma_candidates_from_deviceinfo,
    derive_pragma_from_deviceinfo,
    build_kakaotalk_postpatch_room_evidence,
    build_kakaotalk_media_inventory,
    derive_kakaotalk_postpatch_v2_dek_candidates,
    extract_postpatch_chat_room_previews,
    parse_tasklist_pids,
)
from rapidtriage.core.kakaotalk_algorithms import (
    build_sqlcipher_raw_key_with_salt,
    decrypt_legacy_pages,
    derive_legacy_key_iv,
    derive_postpatch_v2_database_key,
    derive_postpatch_v2_profile_material,
)

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - optional KakaoTalk post-patch dependency
    AES = None


@unittest.skipIf(shutil.which("openssl") is None, "OpenSSL is required for KakaoTalk decrypt tests")
class RapidTriageKakaoTalkDecryptTests(unittest.TestCase):
    def test_parser_exposes_kakaotalk_decrypt_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("kakaotalk-decrypt", commands)
        self.assertIn("kakaotalk-memory-carve", commands)
        self.assertIn("kakaotalk-sqlcipher-probe", commands)
        self.assertIn("kakaotalk-key-store-inspect", commands)
        self.assertIn("kakaotalk-collect-windows", commands)

    def test_kakaotalk_decrypt_opens_decrypted_sqlite_and_extracts_previews(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source = root / "KakaoTalk" / "users" / "12345" / "chat_data" / "chatLogs_42.edb"
            source.parent.mkdir(parents=True)
            key, iv = derive_kakaotalk_key_iv("sample-pragma", "12345")
            plaintext = build_sqlite_chat_database(root / "plain.sqlite")
            source.write_bytes(encrypt_pagewise(plaintext, key=key, iv=iv))
            output = root / "decrypt.json"

            exit_code = main(
                [
                    "kakaotalk-decrypt",
                    str(root),
                    "--pragma",
                    "sample-pragma",
                    "--user-id",
                    "12345",
                    "--include-message-preview",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["chat_database_count"], 1)
            self.assertEqual(payload["summary"]["decrypt_success_count"], 1)
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertEqual(payload["summary"]["message_row_count"], 2)
            self.assertEqual(payload["summary"]["message_preview_count"], 2)
            entry = payload["entries"][0]
            self.assertEqual(entry["chat_id"], "42")
            self.assertEqual(entry["sqlite_status"], "opened")
            self.assertTrue(entry["validation"]["sqlite_header_confirmed"])
            self.assertEqual(entry["message_table_candidates"][0]["table"], "chat_logs")
            self.assertEqual(entry["message_previews"][0]["message_text"], "hello from kakao")
            self.assertEqual(len(entry["message_previews"][0]["message_text_sha256"]), 64)
            self.assertNotIn("sample-pragma", json.dumps(payload))

    def test_kakaotalk_decrypt_auto_uses_unambiguous_registry_user_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            reg_path = root / "Users" / "alice" / "NTUSER-kakao.reg"
            reg_path.parent.mkdir(parents=True)
            reg_path.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk]" "\n"
                r'"talk_user_id"="12345"' "\n",
                encoding="utf-16",
            )
            source = root / "chat_data" / "chatLogs_42.edb"
            source.parent.mkdir(parents=True)
            key, iv = derive_kakaotalk_key_iv("sample-pragma", "12345")
            source.write_bytes(encrypt_pagewise(build_sqlite_chat_database(root / "plain.sqlite"), key=key, iv=iv))
            output = root / "decrypt-auto-userid.json"

            exit_code = main(
                [
                    "kakaotalk-decrypt",
                    str(root),
                    "--pragma",
                    "sample-pragma",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["auth_material"]["user_id_auto_selected"])
            self.assertEqual(payload["auth_material"]["user_id_candidate_count"], 1)
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertNotIn("12345", json.dumps(payload))

    def test_kakaotalk_decrypt_tries_multiple_user_id_candidates_until_sqlite_header_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            reg_path = root / "Users" / "alice" / "NTUSER-kakao.reg"
            reg_path.parent.mkdir(parents=True)
            reg_path.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk]" "\n"
                r'"talk_user_id"="99999"' "\n"
                r'"tuid"="12345"' "\n",
                encoding="utf-16",
            )
            source = root / "chat_data" / "chatLogs_43.edb"
            source.parent.mkdir(parents=True)
            key, iv = derive_kakaotalk_key_iv("sample-pragma", "12345")
            source.write_bytes(encrypt_pagewise(build_sqlite_chat_database(root / "plain.sqlite"), key=key, iv=iv))
            output = root / "decrypt-candidate-userids.json"

            exit_code = main(
                [
                    "kakaotalk-decrypt",
                    str(root),
                    "--pragma",
                    "sample-pragma",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(payload["auth_material"]["user_id_auto_selected"])
            self.assertEqual(payload["auth_material"]["candidate_key_count"], 4)
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertTrue(payload["entries"][0]["validation"]["candidate_key_validated_by_sqlite_header"])
            self.assertNotIn("12345", json.dumps(payload))
            self.assertNotIn("99999", json.dumps(payload))

    def test_kakaotalk_decrypt_tries_direct_md5_derivation_for_candidate_user_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            reg_path = root / "Users" / "alice" / "NTUSER-kakao.reg"
            reg_path.parent.mkdir(parents=True)
            reg_path.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk]" "\n"
                r'"talk_user_id"="12345"' "\n",
                encoding="utf-16",
            )
            source = root / "chat_data" / "chatLogs_45.edb"
            source.parent.mkdir(parents=True)
            key, iv = derive_kakaotalk_key_iv_from_pk("sample-pragma12345", repeat_to_512=False)
            source.write_bytes(encrypt_pagewise(build_sqlite_chat_database(root / "plain.sqlite"), key=key, iv=iv))
            output = root / "decrypt-direct-md5-candidate.json"

            exit_code = main(
                [
                    "kakaotalk-decrypt",
                    str(root),
                    "--pragma",
                    "sample-pragma",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["auth_material"]["candidate_key_count"], 2)
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertEqual(payload["entries"][0]["matched_key_derivation"], "direct-md5")
            self.assertNotIn("sample-pragma", json.dumps(payload))
            self.assertNotIn("12345", json.dumps(payload))

    def test_kakaotalk_decrypt_classifies_dev_id_as_stored_pragma_not_user_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            reg_path = root / "Users" / "alice" / "NTUSER-kakao.reg"
            reg_path.parent.mkdir(parents=True)
            reg_path.write_text(
                "Windows Registry Editor Version 5.00\n\n"
                r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk\DeviceInfo]" "\n"
                r'"dev_id"="abcdef0123456789TOKEN"' "\n",
                encoding="utf-16",
            )
            source = root / "chat_data" / "chatLogs_46.edb"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"\x00" * PAGE_SIZE)
            output = root / "decrypt-dev-id-classification.json"

            exit_code = main(["kakaotalk-decrypt", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["auth_material"]["user_id_candidate_count"], 0)
            self.assertEqual(payload["auth_material"]["stored_pragma_candidate_count"], 1)
            self.assertFalse(payload["auth_material"]["ready"])
            self.assertNotIn("abcdef0123456789TOKEN", json.dumps(payload))

    def test_kakaotalk_decrypt_uses_full_pk_candidate_from_memory_dump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source = root / "chat_data" / "chatLogs_44.edb"
            source.parent.mkdir(parents=True)
            pragma = "A" * 86 + "=="
            uid = "12345"
            key, iv = derive_kakaotalk_key_iv(pragma, uid)
            source.write_bytes(encrypt_pagewise(build_sqlite_chat_database(root / "plain.sqlite"), key=key, iv=iv))
            memory = root / "KakaoTalk-process-memory.raw"
            memory.write_bytes(b"noise\x00" + (pragma + uid).encode("ascii") + b"\x00tail")
            output = root / "decrypt-memory-pk.json"

            exit_code = main(["kakaotalk-decrypt", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["auth_material"]["source"], "pk-memory-candidates")
            self.assertEqual(payload["auth_material"]["pk_candidate_count"], 1)
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertEqual(payload["entries"][0]["matched_key_source"], "pk-memory-candidate")
            self.assertNotIn(pragma, json.dumps(payload))
            self.assertNotIn(uid, json.dumps(payload))

    def test_kakaotalk_memory_carve_extracts_sqlite_schema_from_dmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            memory = root / "KakaoTalk.DMP"
            message_json = (
                b'{"attachment":"","authorId":42,"chatId":100,"deleted":false,'
                b'"logId":200,"message":"memory message","sendAt":1700000000,"type":1}'
            )
            sqlcipher_key_literal = b"x'" + (b"ab" * 48) + b"'"
            memory.write_bytes(
                b"noise-before"
                + build_sqlite_chat_database(root / "plain-memory.sqlite")
                + b"noise-mid"
                + message_json
                + b"TalkChatDB::_InternalOpen PRAGMA kdf_iter sqlcipher_export "
                + sqlcipher_key_literal
            )
            output = root / "memory-carve.json"
            message_csv = root / "memory-messages.csv"

            exit_code = main(
                [
                    "kakaotalk-memory-carve",
                    str(root),
                    "--output",
                    str(output),
                    "--include-row-preview",
                    "--message-csv",
                    str(message_csv),
                    "--max-rows-per-table",
                    "2",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["memory_source_count"], 1)
            self.assertEqual(payload["summary"]["sqlite_header_count"], 1)
            self.assertEqual(payload["summary"]["carved_database_count"], 1)
            self.assertEqual(payload["summary"]["chat_message_residue_count"], 1)
            self.assertGreaterEqual(payload["summary"]["reverse_indicator_count"], 3)
            self.assertEqual(payload["summary"]["sqlcipher_key_residue_count"], 1)
            tables = payload["entries"][0]["tables"]
            self.assertEqual(tables[0]["name"], "chat_logs")
            self.assertEqual(tables[0]["row_status"], "counted")
            self.assertEqual(tables[0]["row_count"], 2)
            self.assertEqual(tables[0]["row_preview"][0]["message"], "hello from kakao")
            self.assertEqual(payload["chat_message_residues"][0]["message_text"], "memory message")
            self.assertEqual(payload["sqlcipher_key_residues"][0]["byte_length"], 48)
            self.assertEqual(payload["sqlcipher_key_residues"][0]["salt_byte_length"], 16)
            self.assertNotIn(("ab" * 48), output.read_text(encoding="utf-8"))
            self.assertIn("memory message", message_csv.read_text(encoding="utf-8-sig"))

    def test_kakaotalk_memory_carve_accepts_zip_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source_root = root / "source" / "KakaoTalk"
            source_root.mkdir(parents=True)
            message_json = (
                b'{"attachment":"","authorId":42,"chatId":100,"deleted":false,'
                b'"logId":200,"message":"zip memory message","sendAt":1700000000,"type":1}'
            )
            (source_root / "KakaoTalk.DMP").write_bytes(message_json)
            archive = root / "kakao.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.write(source_root / "KakaoTalk.DMP", "KakaoTalk/KakaoTalk.DMP")
            output = root / "zip-memory-carve.json"

            exit_code = main(
                [
                    "kakaotalk-memory-carve",
                    str(archive),
                    "--output",
                    str(output),
                    "--include-message-preview",
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["input"]["source_type"], "zip")
            self.assertEqual(payload["summary"]["chat_message_residue_count"], 1)
            self.assertEqual(payload["chat_message_residues"][0]["message_text"], "zip memory message")

    def test_kakaotalk_decrypt_without_auth_reports_missing_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source = root / "chat_data" / "chatLogs_77.edb"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"\x00" * PAGE_SIZE)
            output = root / "decrypt.json"

            exit_code = main(["kakaotalk-decrypt", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["chat_database_count"], 1)
            self.assertEqual(payload["summary"]["decrypt_success_count"], 0)
            self.assertFalse(payload["auth_material"]["ready"])
            self.assertEqual(payload["entries"][0]["decrypt_status"], "not-attempted-auth-material-missing")

    def test_kakaotalk_decrypt_derives_pragma_from_deviceinfo_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source = root / "chat_data" / "chatLogs_88.edb"
            source.parent.mkdir(parents=True)
            pragma_key = bytes.fromhex("00112233445566778899aabbccddeeff")
            pragma = derive_pragma_from_deviceinfo(
                pragma_key=pragma_key,
                sys_uuid="SSSS",
                hdd_model="MMMMM",
                hdd_serial="RRRRR",
                openssl_bin="openssl",
            )
            key, iv = derive_kakaotalk_key_iv(pragma, "12345")
            source.write_bytes(encrypt_pagewise(build_sqlite_chat_database(root / "plain.sqlite"), key=key, iv=iv))
            output = root / "decrypt-deviceinfo.json"

            exit_code = main(
                [
                    "kakaotalk-decrypt",
                    str(root),
                    "--pragma-key-hex",
                    pragma_key.hex(),
                    "--user-id",
                    "12345",
                    "--sys-uuid",
                    "SSSS",
                    "--hdd-model",
                    "MMMMM",
                    "--hdd-serial",
                    "RRRRR",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["auth_material"]["source"], "deviceinfo-pragma-key-user-id-variants")
            self.assertEqual(payload["auth_material"]["deviceinfo_present_fields"], ["hdd_model", "hdd_serial", "sys_uuid"])
            self.assertEqual(payload["auth_material"]["candidate_key_count"], 18)
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertEqual(payload["summary"]["message_row_count"], 2)
            self.assertEqual(payload["entries"][0]["matched_pragma_variant"], "pipe-pkcs7-aes-ciphertext-base64")
            self.assertNotIn("SSSS", json.dumps(payload))

    def test_kakaotalk_decrypt_tries_sha512_deviceinfo_pragma_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source = root / "chat_data" / "chatLogs_89.edb"
            source.parent.mkdir(parents=True)
            pragma_key = bytes.fromhex("00112233445566778899aabbccddeeff")
            pragma_candidates = derive_pragma_candidates_from_deviceinfo(
                pragma_key=pragma_key,
                sys_uuid="SSSS",
                hdd_model="MMMMM",
                hdd_serial="RRRRR",
                openssl_bin="openssl",
            )
            sha512_pragma = next(
                item["pragma"] for item in pragma_candidates if item["variant"] == "pipe-pkcs7-sha512-ciphertext-base64"
            )
            key, iv = derive_kakaotalk_key_iv(sha512_pragma, "12345")
            source.write_bytes(encrypt_pagewise(build_sqlite_chat_database(root / "plain.sqlite"), key=key, iv=iv))
            output = root / "decrypt-deviceinfo-sha512.json"

            exit_code = main(
                [
                    "kakaotalk-decrypt",
                    str(root),
                    "--pragma-key-hex",
                    pragma_key.hex(),
                    "--user-id",
                    "12345",
                    "--sys-uuid",
                    "SSSS",
                    "--hdd-model",
                    "MMMMM",
                    "--hdd-serial",
                    "RRRRR",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["sqlite_open_count"], 1)
            self.assertEqual(payload["entries"][0]["matched_pragma_variant"], "pipe-pkcs7-sha512-ciphertext-base64")
            self.assertNotIn(sha512_pragma, json.dumps(payload))

    def test_kakaotalk_userdir_derivation_matches_bruteforce_command(self) -> None:
        if sys.platform != "darwin" or shutil.which("cc") is None:
            self.skipTest("native CommonCrypto userDir brute force helper requires macOS cc")
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            userdir_home = r"C:\Users\alice\AppData\Local\Kakao\KakaoTalk\users"
            pragma = "sample-pragma"
            userdir = derive_kakaotalk_userdir(
                pragma=pragma,
                userdir_home=userdir_home,
                user_id="123",
                openssl_bin="openssl",
            )
            (root / userdir / "chat_data").mkdir(parents=True)
            output = root / "userdir-brute.json"

            exit_code = main(
                [
                    "kakaotalk-userdir-bruteforce",
                    str(root),
                    "--userdir-home",
                    userdir_home,
                    "--pragma",
                    pragma,
                    "--start-id",
                    "120",
                    "--end-id",
                    "130",
                    "--chunk-size",
                    "5",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["status"], "matched")
            self.assertEqual(payload["summary"]["matched_user_id"], "123")
            self.assertEqual(payload["summary"]["matched_pragma_variant"], "provided-pragma")
            self.assertEqual(len(payload["summary"]["matched_user_id_sha256"]), 64)
            self.assertNotIn(pragma, json.dumps(payload))

    def test_kakaotalk_key_store_inspect_maps_appstate_wrapped_deks_without_raw_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            user = root / "KakaoTalk" / "users" / ("a" * 40)
            chat_dir = user / "chat_data"
            chat_dir.mkdir(parents=True)
            chat_db = chat_dir / "chatLogs_42.edb"
            chat_db.write_bytes(b"encrypted-chat-db")
            wrapped = bytes(range(40))
            appstate = user / "appstate.dat"
            appstate.write_bytes(
                cbor_map(
                    {
                        "info_prefix": cbor_array_bytes(b"v2:"),
                        "salt": cbor_array_bytes(b"s" * 32),
                        "wrapped_dek_map": [cbor_pair_array(b"chat_data\\chatLogs_42.edb", wrapped)],
                    }
                )
            )
            memory = root / "KakaoTalk.DMP"
            path_bytes = b"chat_data\\chatLogs_42.edb"
            memory_blob = bytearray(b"\x00" * 1024)
            memory_blob[0x20 : 0x20 + appstate.stat().st_size] = appstate.read_bytes()
            memory_blob[0x180 : 0x180 + len(path_bytes)] = path_bytes
            node_metadata = bytearray(0x40)
            node_metadata[0x20:0x28] = (0x180).to_bytes(8, "little")
            node_metadata[0x30:0x38] = len(path_bytes).to_bytes(8, "little")
            node_metadata[0x38:0x40] = (0x2F).to_bytes(8, "little")
            memory_blob[0x240:0x280] = node_metadata
            memory_blob[0x280 : 0x280 + len(wrapped)] = wrapped
            memory.write_bytes(bytes(memory_blob))
            output = root / "key-store.json"

            exit_code = main(["kakaotalk-key-store-inspect", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["parsed_key_store_count"], 1)
            self.assertEqual(payload["summary"]["chatlog_wrapped_dek_entry_count"], 1)
            self.assertEqual(payload["summary"]["chat_database_key_store_match_count"], 1)
            entry = payload["key_stores"][0]["wrapped_dek_entries"][0]
            self.assertEqual(entry["relative_path_normalized"], "chat_data/chatLogs_42.edb")
            self.assertEqual(entry["wrapped_dek_length"], 40)
            self.assertEqual(len(entry["wrapped_dek_sha256"]), 64)
            self.assertTrue(entry["matched_file"].endswith("chatLogs_42.edb"))
            self.assertTrue(payload["key_stores"][0]["memory_hits"][0]["appstate_blob_present"])
            runtime_node = payload["key_stores"][0]["runtime_key_store_nodes"][0]
            self.assertEqual(runtime_node["runtime_path_normalized"], "chat_data/chatLogs_42.edb")
            self.assertTrue(runtime_node["runtime_path_matches_appstate"])
            self.assertEqual(runtime_node["runtime_path_storage"], "external-pointer")
            self.assertNotIn(wrapped.hex(), json.dumps(payload))

    @unittest.skipIf(AES is None, "pycryptodome is required for post-patch IKM tests")
    def test_kakaotalk_key_store_inspect_recovers_postpatch_ikm_hash_without_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            user = root / "KakaoTalk" / "users" / ("b" * 40)
            chat_dir = user / "chat_data"
            chat_dir.mkdir(parents=True)
            (chat_dir / "chatLogs_42.edb").write_bytes(b"encrypted-chat-db")

            appstate = user / "appstate.dat"
            appstate.write_bytes(
                cbor_map(
                    {
                        "info_prefix": cbor_array_bytes(b"v2:"),
                        "salt": cbor_array_bytes(b"s" * 32),
                        "wrapped_dek_map": [cbor_pair_array(b"chat_data\\chatLogs_42.edb", bytes(range(40)))],
                    }
                )
            )

            object_key = b"k" * 32
            entropy = b"2xU78xUIRNKi4z7N74Kg5KKHvjopoFmNEMcNJQn9xxCcEX9Q/BMXbBn1/BCaQ89+sYzoZGLNgIUdPA4AOtZhhQ=="
            ikm = b"i" * 32
            ikm_wrap_kek = hmac.new(object_key, entropy + b"ikm-wrap", hashlib.sha256).digest()
            (user / "profile.dat").write_bytes(AES.new(ikm_wrap_kek, AES.MODE_KW).seal(ikm))

            memory = bytearray(b"\x00" * 4096)
            object_offset = 0x100
            entropy_offset = 0x500
            memory[object_offset + 0x68 : object_offset + 0x88] = object_key
            memory[object_offset + 0x88 : object_offset + 0x90] = entropy_offset.to_bytes(8, "little")
            memory[entropy_offset : entropy_offset + len(entropy)] = entropy
            (root / "KakaoTalk.DMP").write_bytes(bytes(memory))
            output = root / "key-store.json"

            exit_code = main(["kakaotalk-key-store-inspect", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["postpatch_ikm_candidate_count"], 1)
            candidate = payload["postpatch_ikm_candidates"][0]
            self.assertEqual(candidate["status"], "ikm-unwrapped")
            self.assertEqual(candidate["ikm_sha256"], hashlib.sha256(ikm).hexdigest())
            self.assertNotIn(object_key.hex(), json.dumps(payload))
            self.assertNotIn(ikm.hex(), json.dumps(payload))

    @unittest.skipIf(AES is None, "pycryptodome is required for post-patch v2 DEK tests")
    def test_postpatch_v2_derives_wrapped_dek_without_exporting_raw_key_by_default(self) -> None:
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import HKDF

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            user = root / "KakaoTalk" / "users" / ("c" * 40)
            chat_dir = user / "chat_data"
            chat_dir.mkdir(parents=True)
            chat_db = chat_dir / "chatLogs_42.edb"
            chat_db.write_bytes(b"s" * 16 + b"encrypted-chat-db")

            object_key = b"k" * 32
            entropy = b"2xU78xUIRNKi4z7N74Kg5KKHvjopoFmNEMcNJQn9xxCcEX9Q/BMXbBn1/BCaQ89+sYzoZGLNgIUdPA4AOtZhhQ=="
            ikm = b"i" * 32
            app_salt = b"a" * 32
            raw_sqlcipher_key = b"d" * 32
            bound_ikm = hmac.new(object_key, ikm + b"entropy-bound-kek", hashlib.sha256).digest()
            kek = HKDF(
                bound_ikm,
                32,
                app_salt,
                SHA256,
                context=b"v2:" + b"chat_data\\chatLogs_42.edb",
            )
            wrapped_dek = AES.new(kek, AES.MODE_KW).seal(raw_sqlcipher_key)

            (user / "appstate.dat").write_bytes(
                cbor_map(
                    {
                        "info_prefix": cbor_array_bytes(b"v2:"),
                        "salt": cbor_array_bytes(app_salt),
                        "wrapped_dek_map": [cbor_pair_array(b"chat_data\\chatLogs_42.edb", wrapped_dek)],
                    }
                )
            )
            ikm_wrap_kek = hmac.new(object_key, entropy + b"ikm-wrap", hashlib.sha256).digest()
            (user / "profile.dat").write_bytes(AES.new(ikm_wrap_kek, AES.MODE_KW).seal(ikm))

            memory = bytearray(b"\x00" * 4096)
            object_offset = 0x100
            entropy_offset = 0x500
            memory[object_offset + 0x68 : object_offset + 0x88] = object_key
            memory[object_offset + 0x88 : object_offset + 0x90] = entropy_offset.to_bytes(8, "little")
            memory[entropy_offset : entropy_offset + len(entropy)] = entropy
            memory_source = root / "KakaoTalk.DMP"
            memory_source.write_bytes(bytes(memory))

            redacted = derive_kakaotalk_postpatch_v2_dek_candidates(
                root=root,
                memory_sources=[memory_source],
            )
            with_raw = derive_kakaotalk_postpatch_v2_dek_candidates(
                root=root,
                memory_sources=[memory_source],
                include_raw=True,
            )

            self.assertEqual(len(redacted), 1)
            self.assertEqual(redacted[0]["status"], "derived")
            self.assertEqual(redacted[0]["role"], "chatlog")
            self.assertEqual(redacted[0]["derived_key_sha256"], hashlib.sha256(raw_sqlcipher_key).hexdigest())
            self.assertNotIn("key_hex", redacted[0])
            self.assertEqual(with_raw[0]["key_hex"], raw_sqlcipher_key.hex())
            self.assertNotIn(raw_sqlcipher_key.hex(), json.dumps(redacted))

    def test_postpatch_chat_room_previews_extract_last_chatlog_from_auxiliary_edb(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            export = root / "chatListInfo.edb.sqlite"
            connection = sqlite3.connect(export)
            try:
                connection.execute(
                    "CREATE TABLE chatRoomList ("
                    "chatId UNSIGNED BIG INT primary key, "
                    "type TEXT, "
                    "activeMembersCount INTEGER, "
                    "newMessageCount INTEGER, "
                    "chatRoomTitle TEXT, "
                    "lastUpdatedAt INTEGER, "
                    "lastChatMessage TEXT, "
                    "lastLogId_ByCHATLOGS UNSIGNED BIG INT, "
                    "lastLogId UNSIGNED BIG INT, "
                    "directChatMemberId UNSIGNED BIG INT, "
                    "lastChatlog TEXT)"
                )
                connection.execute(
                    "INSERT INTO chatRoomList VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        445329368518230,
                        "DirectChat",
                        2,
                        0,
                        "테스트 방",
                        1710000000,
                        "마지막 메시지",
                        3814819507945314306,
                        3814819507945314306,
                        1234,
                        json.dumps(
                            {
                                "authorId": 431643851,
                                "chatId": 445329368518230,
                                "deleted": False,
                                "logId": 3814819507945314306,
                                "message": "한글 메시지 본문",
                                "msgId": 1811787120,
                            },
                            ensure_ascii=False,
                        ),
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            previews = extract_postpatch_chat_room_previews([export], root=root)

            self.assertEqual(len(previews), 1)
            self.assertEqual(previews[0]["chat_id"], "445329368518230")
            self.assertEqual(previews[0]["room_title"], "테스트 방")
            self.assertEqual(previews[0]["message_text"], "한글 메시지 본문")
            self.assertEqual(previews[0]["last_chatlog_json_status"], "parsed")
            self.assertEqual(previews[0]["validation"]["full_history_available"], False)

    def test_postpatch_room_evidence_combines_room_preview_and_memory_residues(self) -> None:
        evidence = build_kakaotalk_postpatch_room_evidence(
            room_previews=[
                {
                    "chat_id": "445329368518230",
                    "room_title": "테스트 방",
                    "room_type": "DirectChat",
                    "message_text": "최근 메시지",
                    "message_text_sha256": hashlib.sha256("최근 메시지".encode("utf-8")).hexdigest(),
                    "last_updated_at": 1710000000,
                }
            ],
            message_residues=[
                {
                    "source_path": "/tmp/KakaoTalk.DMP",
                    "source_offset": 123,
                    "chat_id": 445329368518230,
                    "log_id": 3814819507945314306,
                    "author_id": 431643851,
                    "send_at_utc": "2026-04-09T01:45:23+00:00",
                    "message_text_length": 7,
                    "message_text_sha256": hashlib.sha256("복구 메시지".encode("utf-8")).hexdigest(),
                    "message_text": "복구 메시지",
                }
            ],
        )

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["chat_id"], "445329368518230")
        self.assertEqual(evidence[0]["preview"]["room_title"], "테스트 방")
        self.assertEqual(evidence[0]["memory_message_count"], 1)
        self.assertEqual(evidence[0]["memory_message_samples"][0]["message_text"], "복구 메시지")
        self.assertFalse(evidence[0]["validation"]["full_history_available"])

    def test_media_inventory_links_attachment_metadata_to_local_media_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "KakaoTalk"
            media = root / "users" / "abc" / "chat_data" / "i_sample.jpg"
            media.parent.mkdir(parents=True)
            media.write_bytes(b"\xff\xd8\xff\xe0sample-jpeg-bytes")
            cng = root / "users" / "abc" / "chat_data" / "cli" / "thumbnail_opaque.cng"
            cng.parent.mkdir(parents=True)
            cng.write_bytes(b"\x8a\x2f\xd0\xd6opaque-cache")
            export = Path(tmp_dir) / "KakaoTalk_users_abc_chat_data_chatLogs_123.edb.sqlite"
            connection = sqlite3.connect(export)
            try:
                connection.execute(
                    "CREATE TABLE chatLogs ("
                    "logId INTEGER, authorId INTEGER, type INTEGER, sendAt INTEGER, "
                    "message TEXT, attachement TEXT)"
                )
                connection.execute(
                    "INSERT INTO chatLogs VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        1,
                        7,
                        2,
                        1710000000,
                        "사진 확인",
                        json.dumps(
                            {
                                "k": "remote/path/i_sample.jpg",
                                "mt": "image/jpg",
                                "s": media.stat().st_size,
                                "cs": hashlib.sha1(media.read_bytes()).hexdigest(),
                                "url": "https://talk.kakaocdn.net/dna/remote/path/i_sample.jpg",
                            }
                        ),
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            inventory = build_kakaotalk_media_inventory(
                root=root,
                exported_sqlite_paths=[export],
                include_message_preview=True,
            )

            self.assertEqual(inventory["summary"]["attachment_count"], 1)
            self.assertEqual(inventory["summary"]["local_match_count"], 1)
            self.assertEqual(inventory["summary"]["local_cng_cache_file_count"], 1)
            attachment = inventory["attachments"][0]
            self.assertEqual(attachment["chat_id"], "123")
            self.assertEqual(attachment["media_class"], "image")
            self.assertEqual(attachment["review_status"], "local-file-present")
            self.assertEqual(attachment["local_matches"][0]["signature"], "jpeg")
            self.assertEqual(attachment["message_preview"], "사진 확인")
            self.assertNotIn("cs", json.dumps(attachment))

    def test_standalone_legacy_algorithm_matches_existing_derivation(self) -> None:
        key_iv = derive_legacy_key_iv("sample-pragma", "12345")
        expected_key, expected_iv = derive_kakaotalk_key_iv("sample-pragma", "12345")
        self.assertEqual(key_iv.key, expected_key)
        self.assertEqual(key_iv.iv, expected_iv)

        plaintext = b"SQLite format 3" + (b"\x00" * (PAGE_SIZE - len("SQLite format 3")))
        encrypted = openssl_aes(plaintext, key=key_iv.key, iv=key_iv.iv, decrypt=False)
        self.assertTrue(decrypt_legacy_pages(encrypted, key_iv=key_iv).startswith(b"SQLite format 3"))

    @unittest.skipIf(AES is None, "pycryptodome is required for post-patch primitive tests")
    def test_standalone_postpatch_v2_primitives_round_trip(self) -> None:
        from Crypto.Hash import SHA256
        from Crypto.Protocol.KDF import HKDF

        object_key = bytes(range(32))
        entropy = b"reference-entropy"
        ikm = bytes(range(32, 64))
        raw_key = bytes(range(64, 96))
        appstate_salt = bytes(range(96, 128))
        relative_path = "users/test/chat_data/chatLogs_1.edb"
        ikm_wrap_kek = hmac.new(object_key, entropy + b"ikm-wrap", hashlib.sha256).digest()
        wrapped_profile = AES.new(ikm_wrap_kek, AES.MODE_KW).seal(ikm)
        material = derive_postpatch_v2_profile_material(
            object_key=object_key,
            entropy=entropy,
            wrapped_profile=wrapped_profile,
        )
        bound_ikm = hmac.new(object_key, material.ikm + b"entropy-bound-kek", hashlib.sha256).digest()
        kek = HKDF(
            bound_ikm,
            32,
            appstate_salt,
            SHA256,
            context=b"v2:" + relative_path.replace("/", "\\").encode("utf-8"),
        )
        wrapped_dek = AES.new(kek, AES.MODE_KW).seal(raw_key)

        derived = derive_postpatch_v2_database_key(
            object_key=object_key,
            ikm=material.ikm,
            appstate_salt=appstate_salt,
            info_prefix="v2:",
            relative_path=relative_path,
            wrapped_dek=wrapped_dek,
        )

        self.assertEqual(derived, raw_key)
        self.assertEqual(
            build_sqlcipher_raw_key_with_salt(raw_key=derived, edb_salt=b"0" * 16),
            (raw_key + b"0" * 16).hex(),
        )

    def test_kakaotalk_collect_windows_creates_zip_and_hash_manifest_from_explicit_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            kakao_root = root / "KakaoTalk"
            chat_db = kakao_root / "users" / "abc" / "chat_data" / "chatLogs_1.edb"
            chat_db.parent.mkdir(parents=True)
            chat_db.write_bytes(b"sample encrypted db")
            output_root = root / "cases"

            exit_code = main(
                [
                    "kakaotalk-collect-windows",
                    "--kakao-root",
                    str(kakao_root),
                    "--output-root",
                    str(output_root),
                    "--json",
                ]
            )

            self.assertEqual(exit_code, 0)
            case_dirs = list(output_root.glob("kakaotalk_collection_*"))
            self.assertEqual(len(case_dirs), 1)
            collection = case_dirs[0] / "collection"
            self.assertTrue((collection / "KakaoTalk" / "users" / "abc" / "chat_data" / "chatLogs_1.edb").exists())
            self.assertTrue((collection / "hash_manifest.csv").exists())
            metadata = json.loads((collection / "collection_metadata.json").read_text(encoding="utf-8"))
            profile = metadata["functional_priority_profile"]
            self.assertEqual(profile["item_number"], 51)
            self.assertEqual(profile["batch_id"], "commercial-uplift-051-055")
            self.assertFalse(profile["implemented_controls"]["raw_sensitive_keys_exported"])
            self.assertTrue(profile["implemented_controls"]["split_strategy_manifest_emitted"])
            self.assertEqual(len(profile["implemented_controls"]["split_strategy_manifest_hash"]), 64)
            self.assertIn("kakaotalk-split-strategy-manifest-emitted", profile["passed_validation_check_ids"])
            manifest = profile["split_strategy_manifest"]
            self.assertEqual(manifest["manifest_version"], "kakaotalk-windows-split-strategy-manifest-v1")
            self.assertEqual(manifest["item_number"], 51)
            self.assertEqual(manifest["command"], "kakaotalk-collect-windows")
            self.assertEqual(manifest["manifest_sha256"], profile["implemented_controls"]["split_strategy_manifest_hash"])
            self.assertTrue(manifest["mode_statuses"]["authorized_windows_collection"]["implemented"])
            self.assertFalse(manifest["mode_statuses"]["authorized_windows_collection"]["raw_sensitive_keys_exported"])
            self.assertEqual(manifest["evidence_counts"]["chat_database_count"], 1)
            self.assertTrue(manifest["large_case_controls"]["raw_values_redacted_by_default"])
            self.assertIn(
                "trusted-pc-kakaotalk-extractor-diff-required",
                manifest["commercial_blockers"],
            )
            self.assertIn("known-answer-before-and-after-bigbang-corpus-required", profile["failed_validation_check_ids"])
            zips = [path for path in case_dirs[0].glob("*.zip") if not path.name.endswith(".audit.zip")]
            self.assertEqual(len(zips), 1)
            with zipfile.ZipFile(zips[0]) as archive:
                self.assertIn("KakaoTalk/users/abc/chat_data/chatLogs_1.edb", archive.namelist())

    def test_parse_tasklist_pids_handles_csv_rows(self) -> None:
        output = '"KakaoTalk.exe","1234","Console","1","100,000 K"\n"Other.exe","55","Console","1","1 K"'
        self.assertEqual(parse_tasklist_pids(output), [1234, 55])


def build_sqlite_chat_database(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE chat_logs (id INTEGER PRIMARY KEY, message TEXT, sender_id TEXT, sent_at INTEGER)")
        connection.execute(
            "INSERT INTO chat_logs (message, sender_id, sent_at) VALUES (?, ?, ?)",
            ("hello from kakao", "alice", 1700000000),
        )
        connection.execute(
            "INSERT INTO chat_logs (message, sender_id, sent_at) VALUES (?, ?, ?)",
            ("second message", "bob", 1700000001),
        )
        connection.commit()
    finally:
        connection.close()
    data = path.read_bytes()
    padding = (PAGE_SIZE - (len(data) % PAGE_SIZE)) % PAGE_SIZE
    return data + (b"\x00" * padding)


def encrypt_pagewise(plaintext: bytes, *, key: bytes, iv: bytes) -> bytes:
    encrypted = bytearray()
    for offset in range(0, len(plaintext), PAGE_SIZE):
        encrypted.extend(openssl_aes(plaintext[offset : offset + PAGE_SIZE], key=key, iv=iv, decrypt=False))
    return bytes(encrypted)


def openssl_aes(data: bytes, *, key: bytes, iv: bytes, decrypt: bool) -> bytes:
    proc = subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-128-cbc",
            "-d" if decrypt else "-e",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
            "-nopad",
        ],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.decode("utf-8", errors="replace"))
    return proc.stdout


def cbor_len(major: int, size: int) -> bytes:
    prefix = major << 5
    if size < 24:
        return bytes([prefix | size])
    if size <= 0xFF:
        return bytes([prefix | 24, size])
    if size <= 0xFFFF:
        return bytes([prefix | 25]) + size.to_bytes(2, "big")
    return bytes([prefix | 26]) + size.to_bytes(4, "big")


def cbor_text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return cbor_len(3, len(raw)) + raw


def cbor_array_bytes(value: bytes) -> bytes:
    return cbor_len(4, len(value)) + b"".join(cbor_len(0, byte) for byte in value)


def cbor_pair_array(path: bytes, wrapped: bytes) -> bytes:
    return cbor_len(4, 2) + cbor_array_bytes(path) + cbor_array_bytes(wrapped)


def cbor_value(value: object) -> bytes:
    if isinstance(value, str):
        return cbor_text(value)
    if isinstance(value, bytes):
        return value
    if isinstance(value, list):
        return cbor_len(4, len(value)) + b"".join(cbor_value(item) for item in value)
    raise AssertionError(f"unsupported cbor fixture value: {type(value)!r}")


def cbor_map(values: dict[str, object]) -> bytes:
    return cbor_len(5, len(values)) + b"".join(cbor_text(key) + cbor_value(value) for key, value in values.items())


if __name__ == "__main__":
    unittest.main()
