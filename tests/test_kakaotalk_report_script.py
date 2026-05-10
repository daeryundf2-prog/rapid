from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rapidtriage.core.kakaotalk import KakaoTalkDecryptError, extract_zip_archive_safely


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "kakaotalk_zip_to_report.py"
SPEC = importlib.util.spec_from_file_location("kakaotalk_zip_to_report", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
kakao_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kakao_report)

ALGORITHM_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "kakaotalk_algorithm_reference.py"
ALGORITHM_SPEC = importlib.util.spec_from_file_location("kakaotalk_algorithm_reference", ALGORITHM_SCRIPT_PATH)
assert ALGORITHM_SPEC is not None and ALGORITHM_SPEC.loader is not None
kakao_algorithm = importlib.util.module_from_spec(ALGORITHM_SPEC)
ALGORITHM_SPEC.loader.exec_module(kakao_algorithm)


class KakaoTalkReportScriptTests(unittest.TestCase):
    def test_raw_key_output_requires_lab_disclosure_gate(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SystemExit):
                kakao_algorithm.require_raw_key_disclosure_gate(True)

        with patch.dict(
            os.environ,
            {
                kakao_algorithm.RAW_KEY_DISCLOSURE_ENV: kakao_algorithm.RAW_KEY_DISCLOSURE_VALUE,
            },
            clear=True,
        ):
            kakao_algorithm.require_raw_key_disclosure_gate(True)

    def test_detect_source_kind_and_operator_notes_cover_common_inputs(self) -> None:
        self.assertEqual(kakao_report.detect_source_kind(Path("case.zip")), "zip")
        self.assertEqual(kakao_report.detect_source_kind(Path("NTUSER.DAT")), "ntuser-dat")
        self.assertEqual(kakao_report.detect_source_kind(Path("phone.dmg")), "dmg")
        self.assertEqual(kakao_report.detect_source_kind(Path("evidence.7z")), "file:7z")

        self.assertIn("DMG", kakao_report.input_note_for_source(Path("phone.dmg"), "dmg"))
        self.assertIn("registry/device clues", kakao_report.input_note_for_source(Path("NTUSER.DAT"), "ntuser-dat"))
        self.assertIn("Extract it first", kakao_report.input_note_for_source(Path("data.7z"), "file:7z"))

    def test_summary_distinguishes_raw_rows_from_visible_rows_and_unopened_dbs(self) -> None:
        payload = {
            "summary": {
                "status": "no-match",
                "chat_database_count": 1019,
                "opened_database_count": 0,
            }
        }
        legacy_payload = {
            "summary": {
                "sqlite_open_count": 40,
                "message_row_count": 9719,
            },
            "entries": [
                {"sqlite_status": "opened", "message_row_count": 120},
                {"sqlite_status": "sqlite-header-not-found", "message_row_count": 0},
            ],
        }
        visible_messages = [
            {"analysis_method": "legacy-edb-decrypt", "message": "hello"},
            {"analysis_method": "legacy-edb-decrypt", "message": "world"},
        ]

        summary = kakao_report.build_summary_payload(
            source=Path("data.zip"),
            payload=payload,
            legacy_payload=legacy_payload,
            rooms=[],
            messages=visible_messages,
            media=[],
            temporary_extraction=True,
            source_kind="zip",
            input_note="ZIP was safely extracted and analyzed.",
        )

        self.assertEqual(summary["source_type"], "zip")
        self.assertEqual(summary["legacy_sqlite_open_count"], 40)
        self.assertEqual(summary["raw_recovered_message_row_count"], 9719)
        self.assertEqual(summary["visible_message_count"], 2)
        self.assertEqual(summary["message_count"], 2)
        self.assertEqual(summary["unopened_database_count"], 979)
        self.assertEqual(summary["legacy_database_status_counts"]["opened"], 1)
        self.assertIn("database_counts_csv", summary["outputs"])
        self.assertIn("raw_recovered_message_row_count", summary["message_count_note"])

    def test_database_count_rows_preserve_per_database_status(self) -> None:
        rows = kakao_report.build_database_count_rows(
            {},
            {
                "entries": [
                    {
                        "chat_id": "42",
                        "source_path": "/case/chatLogs_42.edb",
                        "sqlite_status": "opened",
                        "decrypt_status": "decrypted",
                        "message_row_count": 99,
                        "message_previews": [{"message_text": "sample"}],
                    }
                ]
            },
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["analysis_method"], "legacy-edb-decrypt")
        self.assertEqual(rows[0]["chat_id"], "42")
        self.assertEqual(rows[0]["sqlite_status"], "opened")
        self.assertEqual(rows[0]["message_row_count"], 99)
        self.assertEqual(rows[0]["message_preview_count"], 1)


class KakaoTalkZipSafetyTests(unittest.TestCase):
    def test_zip_extraction_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            archive = root / "evil.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../evil.txt", "nope")

            with self.assertRaises(KakaoTalkDecryptError):
                extract_zip_archive_safely(archive, root / "out")

    def test_zip_extraction_rejects_symlink_members(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            archive = root / "symlink.zip"
            info = zipfile.ZipInfo("link")
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(info, "target")

            with self.assertRaises(KakaoTalkDecryptError):
                extract_zip_archive_safely(archive, root / "out")


if __name__ == "__main__":
    unittest.main()
