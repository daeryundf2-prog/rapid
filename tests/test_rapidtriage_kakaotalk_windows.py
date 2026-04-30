from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.artifacts.kakaotalk_windows import decode_vk_value_at_name_offset


class RapidTriageKakaoTalkWindowsTests(unittest.TestCase):
    def test_parser_exposes_kakaotalk_windows_collector_kind(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices
        help_text = commands["artifacts"].format_help()

        self.assertIn("kakaotalk-windows", help_text)

    def test_kakaotalk_windows_correlates_edb_registry_and_memory_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            write_kakaotalk_windows_fixture(root)
            output = root / "kakaotalk-windows.json"

            exit_code = main(["artifacts", str(root), "--kind", "kakaotalk-windows", "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["provider"]["name"], "kakaotalk-windows-correlation")
            artifacts = payload["artifacts"]
            candidates = [item for item in artifacts if item["artifact_type"] == "kakaotalk-windows-source-candidate"]
            app_databases = [item for item in artifacts if item["artifact_type"] == "kakaotalk-windows-app-database"]
            crypto_contexts = [
                item for item in artifacts if item["artifact_type"] == "kakaotalk-windows-crypto-material-candidate"
            ]
            user_id_contexts = [
                item for item in artifacts if item["artifact_type"] == "kakaotalk-windows-user-id-candidate"
            ]
            summary = next(item for item in artifacts if item["artifact_type"] == "kakaotalk-windows-correlation-summary")

            self.assertGreaterEqual(len(candidates), 3)
            families = {item["details"]["source_family"] for item in candidates}
            self.assertEqual(families, {"windows-edb", "registry", "memory-dump"})
            self.assertEqual(len(app_databases), 1)
            app_database = app_databases[0]
            self.assertEqual(app_database["details"]["source_family"], "kakaotalk-app-db")
            self.assertEqual(app_database["details"]["database_role"], "chat-log")
            self.assertTrue(app_database["details"]["has_wal"])
            self.assertFalse(app_database["details"]["sqlite_access"]["sqlite_header"])
            self.assertIn("kakaotalk-custom-or-encrypted-db", app_database["details"]["risk_flags"])
            self.assertTrue(
                app_database["details"]["kakaotalk_decryption_readiness"]["encrypted_page_model_candidate"]
            )
            self.assertFalse(app_database["details"]["kakaotalk_decryption_readiness"]["decrypt_attempted"])
            self.assertFalse(app_database["details"]["commercial_grade_ready"])
            self.assertEqual(len(crypto_contexts), 1)
            crypto_context = crypto_contexts[0]
            self.assertEqual(crypto_context["details"]["present_fields"], ["hdd_model", "hdd_serial", "sys_uuid"])
            self.assertTrue(crypto_context["details"]["values_redacted"])
            self.assertFalse(crypto_context["details"]["kakaotalk_decryption_context"]["hardcoded_application_key_included"])
            self.assertEqual(len(crypto_context["details"]["field_hashes"]["sys_uuid"]), 64)
            self.assertEqual(len(user_id_contexts), 1)
            user_id_context = user_id_contexts[0]
            self.assertEqual(user_id_context["details"]["field_names"], ["talk_user_id"])
            self.assertTrue(user_id_context["details"]["values_redacted"])
            self.assertEqual(user_id_context["details"]["field_shapes"]["talk_user_id"], "numeric-id")
            self.assertTrue(user_id_context["details"]["auto_decrypt_eligible"])
            self.assertNotIn("12345", json.dumps(user_id_context))
            self.assertTrue(any(item["details"]["candidate_kind"] == "path" for item in candidates))
            self.assertTrue(any(item["details"]["candidate_kind"] == "chat-store" for item in candidates))
            self.assertTrue(any(item["details"]["source_offset"] != "" for item in candidates))
            self.assertTrue(all(item["details"]["validation_required"] for item in candidates))
            self.assertTrue(all(not item["details"]["commercial_grade_ready"] for item in candidates))
            self.assertTrue(all(item["details"]["forensic_review"]["gap_id"] == "#31" for item in candidates))
            self.assertTrue(
                any(
                    "KakaoTalk.exe" in item["details"]["candidate_value"]
                    or "KakaoTalk" in item["details"]["candidate_value"]
                    for item in candidates
                )
            )
            edb_candidate = next(
                item
                for item in candidates
                if item["details"]["source_family"] == "windows-edb" and item["details"]["page_sha256"]
            )
            self.assertEqual(len(edb_candidate["details"]["page_sha256"]), 64)
            self.assertIn("kakaotalk", edb_candidate["details"]["matched_terms"])
            memory_candidate = next(item for item in candidates if item["details"]["source_family"] == "memory-dump")
            self.assertIn("volatile-memory-kakaotalk-string", memory_candidate["details"]["risk_flags"])
            self.assertIn("private communications", memory_candidate["details"]["privacy_legal_warning"])
            self.assertEqual(summary["details"]["correlation_strength"], "strong")
            self.assertEqual(
                summary["details"]["candidate_count"],
                len(candidates) + len(app_databases) + len(crypto_contexts) + len(user_id_contexts),
            )
            self.assertEqual(summary["details"]["app_database_count"], len(app_databases))
            self.assertEqual(summary["details"]["crypto_material_candidate_count"], len(crypto_contexts))
            self.assertEqual(summary["details"]["user_id_candidate_count"], len(user_id_contexts))
            self.assertFalse(summary["details"]["commercial_grade_ready"])

    def test_native_hive_vk_deviceinfo_value_decoder(self) -> None:
        blob = bytearray(8192)
        value = "Samsung SSD 970 EVO 500GB".encode("utf-16le") + b"\x00\x00"
        value_offset = 4300
        blob[value_offset : value_offset + len(value)] = value
        signature_offset = 4104
        cell_offset = signature_offset - 4
        name = b"hdd_model"
        cell_size = 24 + len(name)
        blob[cell_offset:signature_offset] = (-cell_size).to_bytes(4, "little", signed=True)
        blob[signature_offset : signature_offset + 2] = b"vk"
        blob[signature_offset + 2 : signature_offset + 4] = len(name).to_bytes(2, "little")
        blob[signature_offset + 4 : signature_offset + 8] = len(value).to_bytes(4, "little")
        blob[signature_offset + 8 : signature_offset + 12] = (value_offset - 4096).to_bytes(4, "little")
        blob[signature_offset + 12 : signature_offset + 16] = (1).to_bytes(4, "little")
        blob[signature_offset + 16 : signature_offset + 18] = (1).to_bytes(2, "little")
        blob[signature_offset + 20 : signature_offset + 20 + len(name)] = name

        candidate = decode_vk_value_at_name_offset(bytes(blob), signature_offset + 20)

        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["name"], "hdd_model")
        self.assertEqual(candidate["value_type"], "REG_SZ")


def write_kakaotalk_windows_fixture(root: Path) -> None:
    edb_path = root / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows" / "Windows.edb"
    edb_path.parent.mkdir(parents=True, exist_ok=True)
    edb_path.write_bytes(
        minimal_ese_database(
            [
                "SystemIndex_PropertyStore System.ItemPathDisplay System.FileName",
                r"C:\Users\alice\AppData\Local\Kakao\KakaoTalk\users\12345\chatLogs",
                "KakaoTalk cache indexed conversation metadata candidate",
            ]
        )
    )
    reg_path = root / "Users" / "alice" / "NTUSER-kakao.reg"
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(
        "Windows Registry Editor Version 5.00\n\n"
        r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk]" "\n"
        r'"InstallPath"="C:\\Users\\alice\\AppData\\Local\\Kakao\\KakaoTalk\\KakaoTalk.exe"' "\n"
        r'"talk_user_id"="12345"' "\n"
        r"[HKEY_CURRENT_USER\Software\Kakao\KakaoTalk\DeviceInfo]" "\n"
        r'"sys_uuid"="550e8400-e29b-41d4-a716-446655440000"' "\n"
        r'"hdd_model"="Sample SSD"' "\n"
        r'"hdd_serial"="SERIAL1234"' "\n",
        encoding="utf-16",
    )
    memory_path = root / "incident.raw"
    memory_path.write_bytes(
        b"RAM\x00"
        + "KakaoTalk.exe C:\\Users\\alice\\AppData\\Local\\Kakao\\KakaoTalk\\users\\12345\\chatLogs".encode("utf-16le")
        + b"\x00"
    )
    app_db_path = root / "Users" / "alice" / "chat_data" / "chatLogs_12345.edb"
    app_db_path.parent.mkdir(parents=True, exist_ok=True)
    app_db_path.write_bytes(bytes.fromhex("7fe43f1b") + b"encrypted-or-custom-kakaotalk-store")
    app_db_path.with_name(f"{app_db_path.name}-wal").write_bytes(b"kakaotalk-wal-companion")


def minimal_ese_database(strings: list[str]) -> bytes:
    page_size = 8192
    header = bytearray(8192)
    header[4:8] = bytes.fromhex("efcdab89")
    header[8:12] = (0x620).to_bytes(4, "little")
    header[12:16] = (1).to_bytes(4, "little")
    header[0xEC:0xF0] = page_size.to_bytes(4, "little")
    payload = b"\x00\x00".join(value.encode("utf-16le") for value in strings)
    database = bytes(header) + payload
    padding = (page_size - (len(database) % page_size)) % page_size
    return database + (b"\x00" * padding)


if __name__ == "__main__":
    unittest.main()
