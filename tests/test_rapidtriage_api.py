from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import tempfile
import unittest
import wave
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import (
        build_email_conversation_trusted_diff,
        build_run_validation_diff_inventory,
        build_run_validation_package,
        build_hex_viewer_trusted_diff,
        build_large_sqlite_fts_trusted_diff,
        build_media_transcript_trusted_diff,
        build_pagination_cursor_manifest,
        build_pagination_trusted_diff,
        build_preview_sandbox_trusted_diff,
        build_source_preview,
        build_source_search,
        encode_source_search_file_resume_token,
        encode_source_search_resume_token,
        sqlite_wal_sidecar_info,
        build_sqlite_viewer_trusted_diff,
        build_ui_virtualization_trusted_diff,
        build_ui_virtualization_manifest,
        email_viewer_core_accuracy_gates,
        create_app,
        hex_viewer_core_accuracy_gates,
        large_sqlite_fts_core_accuracy_gates,
        media_viewer_core_accuracy_gates,
        pagination_core_accuracy_gates,
        preview_sandbox_core_accuracy_gates,
        sqlite_viewer_core_accuracy_gates,
        ui_virtualization_core_accuracy_gates,
    )
from rapidtriage.cli import build_web_parser
from rapidtriage.core.crash import write_crash_report
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.keyword_packs import build_keyword_pack_trusted_diff, keyword_pack_core_accuracy_gates
from rapidtriage.core.large_case_controls import build_large_case_resilience_contract
from tests.schema_validation import validate
from tests.test_rapidtriage_run import build_run_fixture
from tests.windows_artifact_fixtures import build_windows_artifact_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent


def hash_file(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class RapidTriageApiTests(unittest.TestCase):
    def test_source_search_finds_sqlite_hits_after_legacy_5000_row_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "large.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
                connection.executemany(
                    "INSERT INTO notes(body) VALUES (?)",
                    [(f"ordinary row {index}",) for index in range(6000)] + [("needle after legacy boundary",)],
                )
                connection.commit()
            finally:
                connection.close()

            payload = build_source_search(db_path, ["needle"], limit=10, context=40)

        self.assertEqual(payload["summary"]["match_count"], 1)
        self.assertEqual(payload["matches"][0]["row_number"], 6001)
        self.assertEqual(payload["summary"]["sqlite_scanned_row_count"], 6001)
        self.assertEqual(payload["summary"]["sqlite_row_scan_limit"], 100_000)
        self.assertTrue(payload["summary"]["sqlite_full_cursor_scan"])
        self.assertFalse(payload["summary"]["sqlite_scan_truncated"])
        self.assertEqual(payload["source_search_profile"]["qc_prep_item_number"], 56)
        self.assertEqual(
            payload["source_search_full_cursor_contract"]["profile_version"],
            "source-search-full-cursor-scan-contract-v1",
        )

    def test_source_search_sqlite_result_limit_discloses_resume_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "many-hits.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
                connection.executemany("INSERT INTO notes(body) VALUES (?)", [("needle",) for _ in range(5)])
                connection.commit()
            finally:
                connection.close()

            payload = build_source_search(db_path, ["needle"], limit=2, context=10)
            resume_token = payload["summary"]["sqlite_resume_token"]
            resumed = build_source_search(db_path, ["needle"], limit=2, context=10, sqlite_resume_token=resume_token)

        self.assertEqual(payload["summary"]["match_count"], 2)
        self.assertTrue(payload["summary"]["sqlite_result_limit_reached"])
        self.assertEqual(payload["summary"]["sqlite_resume_state"]["reason"], "result-limit")
        self.assertTrue(payload["summary"]["sqlite_resume_token"])
        self.assertEqual(len(payload["summary"]["sqlite_resume_token_hash"]), 64)
        self.assertFalse(payload["summary"]["sqlite_full_cursor_scan"])
        self.assertTrue(payload["truncated"])
        self.assertEqual(resumed["summary"]["match_count"], 2)
        self.assertTrue(resumed["summary"]["sqlite_resume_requested"])
        self.assertEqual([match["row_number"] for match in resumed["matches"]], [3, 4])

    def test_source_search_sqlite_resume_token_requires_next_row_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "bad-resume.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO notes(body) VALUES (?)", ("needle",))
                connection.commit()
            finally:
                connection.close()
            token = encode_source_search_resume_token(
                source_path=db_path,
                keywords=["needle"],
                state={"table": "notes", "reason": "bad-test-token"},
            )

            with self.assertRaises(Exception) as raised:
                build_source_search(db_path, ["needle"], sqlite_resume_token=token)

        self.assertEqual(getattr(raised.exception, "status_code", None), 400)
        self.assertEqual(getattr(raised.exception, "detail", ""), "sqlite_resume_token is missing resume state")

    def test_source_search_sqlite_default_row_scan_limit_prevents_full_db_sweep(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "bounded.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
                connection.executemany("INSERT INTO notes(body) VALUES (?)", [(f"ordinary row {index}",) for index in range(25)])
                connection.commit()
            finally:
                connection.close()

            payload = build_source_search(db_path, ["needle"], limit=10, context=10, sqlite_row_scan_limit=12)

        self.assertEqual(payload["summary"]["match_count"], 0)
        self.assertEqual(payload["summary"]["sqlite_row_scan_limit"], 12)
        self.assertEqual(payload["summary"]["sqlite_scanned_row_count"], 12)
        self.assertTrue(payload["summary"]["sqlite_scan_truncated"])
        self.assertFalse(payload["summary"]["sqlite_full_cursor_scan"])
        self.assertEqual(payload["summary"]["sqlite_resume_state"]["reason"], "sqlite-row-scan-limit")
        self.assertTrue(payload["summary"]["sqlite_resume_token"])
        self.assertTrue(payload["source_search_profile"]["large_data_controls"]["sqlite_resume_token"])
        self.assertTrue(payload["source_search_profile"]["large_data_controls"]["sqlite_scan_truncated"])

    def test_source_search_api_preserves_sqlite_scan_limit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            run_dir = Path(temp) / "run"
            root.mkdir()
            run_dir.mkdir()
            db_path = root / "bounded-api.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
                connection.executemany("INSERT INTO notes(body) VALUES (?)", [(f"ordinary row {index}",) for index in range(100_000)])
                connection.execute("INSERT INTO notes(body) VALUES (?)", ("needle after row cap",))
                connection.commit()
            finally:
                connection.close()
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "fraud",
                        "root": str(root),
                        "output_dir": str(run_dir),
                        "outputs": {"summary": str(summary_path)},
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            job = store.import_completed_run(run_dir)
            client = TestClient(create_app(store))

            response = client.get(
                f"/api/runs/{job.run_id}/source-search",
                params={"path": str(db_path), "keyword": "needle", "limit": 10, "context": 40},
            )
            resume_token = response.json()["summary"]["sqlite_resume_token"]
            resumed_response = client.get(
                f"/api/runs/{job.run_id}/source-search",
                params={
                    "path": str(db_path),
                    "keyword": "needle",
                    "limit": 10,
                    "context": 40,
                    "sqlite_resume_token": resume_token,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["summary"]["match_count"], 0)
        self.assertEqual(payload["summary"]["sqlite_row_scan_limit"], 100_000)
        self.assertEqual(payload["summary"]["sqlite_scanned_row_count"], 100_000)
        self.assertTrue(payload["summary"]["sqlite_scan_truncated"])
        self.assertFalse(payload["summary"]["sqlite_full_cursor_scan"])
        self.assertEqual(payload["summary"]["sqlite_resume_state"]["reason"], "sqlite-row-scan-limit")
        self.assertEqual(
            payload["source_search_full_cursor_contract"]["profile_version"],
            "source-search-full-cursor-scan-contract-v1",
        )
        self.assertEqual(
            payload["source_search_profile"]["large_data_controls"]["sqlite_resume_state"]["reason"],
            "sqlite-row-scan-limit",
        )
        self.assertTrue(payload["summary"]["sqlite_resume_token"])
        self.assertEqual(payload["source_search_profile"]["large_data_controls"]["sqlite_resume_token"], payload["summary"]["sqlite_resume_token"])
        self.assertEqual(resumed_response.status_code, 200, resumed_response.text)
        resumed_payload = resumed_response.json()
        self.assertEqual(resumed_payload["summary"]["match_count"], 1)
        self.assertTrue(resumed_payload["summary"]["sqlite_resume_requested"])
        self.assertEqual(resumed_payload["matches"][0]["row_number"], 100_001)
        self.assertEqual(resumed_payload["matches"][0]["source_viewer_locator"]["offset"], 100_000)

    def test_source_preview_opens_zip_entry_locator_without_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            run_dir = Path(temp) / "run"
            export_dir = root / "Users" / "alice" / "Documents"
            export_dir.mkdir(parents=True)
            run_dir.mkdir()
            archive_path = export_dir / "ChatGPT-export.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "conversations.json",
                    json.dumps(
                        [
                            {
                                "title": "Forensic review",
                                "mapping": {
                                    "1": {"message": {"author": {"role": "user"}, "content": {"parts": ["find evtx"]}}},
                                    "2": {
                                        "message": {
                                            "author": {"role": "assistant"},
                                            "content": {"parts": ["open source viewer"]},
                                        }
                                    },
                                },
                            }
                        ],
                        ensure_ascii=False,
                    ),
                )
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "fraud",
                        "root": str(root),
                        "output_dir": str(run_dir),
                        "source": {"type": "folder", "source_path": str(root), "analysis_root": str(root)},
                        "outputs": {"summary": str(summary_path)},
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            job = store.import_completed_run(run_dir)
            client = TestClient(create_app(store))

            response = client.get(
                f"/api/runs/{job.run_id}/source-preview",
                params={"path": "Users/alice/Documents/ChatGPT-export.zip::conversations.json"},
            )
            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["preview_type"], "json")
            self.assertEqual(payload["archive_entry"]["archive_entry_name"], "conversations.json")
            self.assertEqual(payload["viewer_metadata"]["container_type"], "zip")
            self.assertEqual(payload["viewer_metadata"]["parser"], "rapidtriage.source-viewer.zip-entry-json")
            self.assertEqual(payload["zip_entry"]["core_accuracy_gates"]["component"], "source-read-zip-entry-locator")
            self.assertEqual(payload["source_locator"]["locator_type"], "zip-entry-text-preview")
            self.assertIn("find evtx", payload["text"])
            self.assertIn("hash=true", payload["metadata_url"])
            self.assertIn("source-search", payload["search_url"])
            self.assertIn(str(archive_path), payload["download_url"])
            self.assertIn("Archive completeness", " ".join(payload["viewer_limitations"]))
            self.assertEqual(
                {action["id"] for action in payload["viewer_actions"]},
                {"download-container", "hash-container", "search-current-entry", "pin-compare", "save-review"},
            )
            search_response = client.get(
                f"/api/runs/{job.run_id}/source-search",
                params={"path": "Users/alice/Documents/ChatGPT-export.zip::conversations.json", "keyword": "evtx"},
            )
            self.assertEqual(search_response.status_code, 200, search_response.text)
            search_payload = search_response.json()
            self.assertTrue(search_payload["path"].endswith("ChatGPT-export.zip::conversations.json"))
            self.assertEqual(search_payload["summary"]["zip_entry_search"], True)
            self.assertEqual(search_payload["summary"]["match_count"], 1)
            self.assertEqual(search_payload["matches"][0]["source_name"], "conversations.json")
            self.assertEqual(search_payload["matches"][0]["archive_entry"]["archive_entry_name"], "conversations.json")
            self.assertIn("ChatGPT-export.zip::conversations.json", search_payload["matches"][0]["citation"])

            traversal_response = client.get(
                f"/api/runs/{job.run_id}/source-preview",
                params={"path": "Users/alice/Documents/ChatGPT-export.zip::../secret.json"},
            )
            self.assertEqual(traversal_response.status_code, 400)
            self.assertIn("must not contain parent traversal", traversal_response.json()["detail"])

    def test_source_search_large_file_emits_resume_token_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "huge.log"
            log_path.write_bytes(b"header\n" + (b"x" * 44) + b"needle-after-window\n")

            payload = build_source_search(log_path, ["needle"], limit=10, context=10, max_plain_text_bytes=32)
            resume_token = payload["summary"]["file_resume_token"]
            resumed = build_source_search(
                log_path,
                ["needle"],
                limit=10,
                context=10,
                max_plain_text_bytes=32,
                file_resume_token=resume_token,
            )

        self.assertEqual(payload["summary"]["match_count"], 0)
        self.assertEqual(payload["summary"]["file_resume_state"]["reason"], "byte-scan-limit")
        self.assertTrue(payload["summary"]["file_resume_token"])
        self.assertEqual(len(payload["summary"]["file_resume_token_hash"]), 64)
        self.assertTrue(payload["truncated"])
        self.assertEqual(resumed["summary"]["match_count"], 1)
        self.assertTrue(resumed["summary"]["file_resume_requested"])
        self.assertEqual(resumed["matches"][0]["offset_hex"], "0x00000033")
        self.assertIn("needle-after", resumed["matches"][0]["snippet"])

    def test_source_search_file_resume_token_requires_next_offset_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_path = Path(temp) / "huge.log"
            log_path.write_bytes(b"header\nneedle\n")
            token = encode_source_search_file_resume_token(
                source_path=log_path,
                keywords=["needle"],
                state={"reason": "bad-test-token"},
            )

            with self.assertRaises(Exception) as raised:
                build_source_search(log_path, ["needle"], max_plain_text_bytes=4, file_resume_token=token)

        self.assertEqual(getattr(raised.exception, "status_code", None), 400)
        self.assertEqual(getattr(raised.exception, "detail", ""), "file_resume_token is missing resume state")

    def test_source_preview_mbox_discloses_bounded_parse_window(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            mbox_path = Path(temp) / "mailbox.mbox"
            first = (
                b"From first@example.test Mon Jan 01 00:00:00 2026\n"
                b"From: first@example.test\n"
                b"To: analyst@example.test\n"
                b"Subject: First bounded message\n"
                b"\n"
                b"needle in first body\n"
            )
            second = (
                b"From second@example.test Mon Jan 01 00:01:00 2026\n"
                b"From: second@example.test\n"
                b"To: analyst@example.test\n"
                b"Subject: Second outside cap\n"
                b"\n"
                + (b"x" * 256)
            )
            mbox_path.write_bytes(first + second)

            with patch("rapidtriage.api.app.EMAIL_PREVIEW_MAX_BYTES", len(first) + 16):
                payload = build_source_preview("run-1", mbox_path)

        self.assertEqual(payload["preview_type"], "email")
        self.assertTrue(payload["truncated"])
        self.assertIn("partial", payload["message"])
        diagnostics = payload["email"]["parse_diagnostics"]
        self.assertEqual(diagnostics["parse_mode"], "bounded-mbox")
        self.assertTrue(diagnostics["source_truncated"])
        self.assertLessEqual(diagnostics["bytes_read"], len(first) + 16)
        self.assertGreaterEqual(payload["email"]["message_count"], 1)
        self.assertEqual(payload["email"]["messages"][0]["subject"], "First bounded message")

    def test_source_preview_large_eml_limits_message_parse_size(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            eml_path = Path(temp) / "large.eml"
            eml_path.write_bytes(
                b"From: sender@example.test\n"
                b"To: analyst@example.test\n"
                b"Subject: Large bounded EML\n"
                b"\n"
                + (b"body " * 128)
            )

            with (
                patch("rapidtriage.api.app.EMAIL_PREVIEW_MAX_BYTES", 256),
                patch("rapidtriage.api.app.EMAIL_PREVIEW_MESSAGE_MAX_BYTES", 128),
            ):
                payload = build_source_preview("run-1", eml_path)

        self.assertEqual(payload["preview_type"], "email")
        self.assertTrue(payload["truncated"])
        diagnostics = payload["email"]["parse_diagnostics"]
        self.assertEqual(diagnostics["parse_mode"], "bounded-eml")
        self.assertTrue(diagnostics["source_truncated"])
        self.assertEqual(diagnostics["message_size_truncated_count"], 1)
        self.assertEqual(payload["email"]["messages"][0]["subject"], "Large bounded EML")

    def test_source_preview_sqlite_discloses_sidecar_review_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "chat.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO messages(body) VALUES ('sidecar visible')")
                connection.commit()
            finally:
                connection.close()
            db_path.with_name(db_path.name + "-shm").write_bytes(b"rapidtriage-shm-present")

            payload = build_source_preview("run-1", db_path)

        self.assertEqual(payload["preview_type"], "sqlite")
        profile = payload["sqlite"]["sidecar_state_profile"]
        self.assertTrue(profile["shm_detected"])
        self.assertTrue(profile["requires_wal_review"])
        self.assertFalse(profile["wal_detected"])
        self.assertIn("sqlite-wal-preview", profile["recommended_cli"])
        self.assertIn("sidecar", profile["source_viewer_warning"].lower())
        self.assertEqual(
            payload["sqlite"]["sqlite_preview_manifest"]["database"]["sidecar_state_profile_hash"],
            profile["profile_hash"],
        )
        self.assertIn("wal-shm-journal-sidecar-status", payload["sqlite"]["review_features"])
        controls = payload["sqlite"]["commercial_uplift_evidence"]["reportability_decision"]["control_snapshot"]
        self.assertTrue(controls["sqlite_sidecar_review_required"])

    def test_source_sqlite_wal_preview_endpoint_links_sidecar_review_to_gui(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "chat.db"
            connection = sqlite3.connect(db_path)
            try:
                connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO messages(body) VALUES ('wal endpoint')")
                connection.commit()
            finally:
                connection.close()
            db_path.with_name(db_path.name + "-wal").write_bytes(
                struct.pack(">IIIIIIII", 0x377F0683, 3007000, 1024, 7, 1, 2, 3, 4)
                + struct.pack(">IIIIII", 1, 1, 1, 2, 3, 4)
                + (b"\0" * 1024)
            )
            run_dir = root / "run"
            run_dir.mkdir()
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "fraud",
                        "root": str(root),
                        "output_dir": str(run_dir),
                        "outputs": {"summary": str(summary_path)},
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            job = store.import_completed_run(run_dir)
            client = TestClient(create_app(store))

            response = client.get(
                f"/api/runs/{job.run_id}/source-sqlite-wal-preview",
                params={"path": str(db_path), "max_frames": 5},
            )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["command"], "sqlite-wal-preview")
        self.assertEqual(payload["api_profile"]["profile_version"], "source-sqlite-wal-preview-api-v1")
        self.assertEqual(payload["api_profile"]["gui_binding"], "sqlite-sidecar-preview")
        self.assertTrue(payload["recovery_scope"]["wal_detected"])
        self.assertEqual(payload["recovery_scope"]["frame_preview_count"], 1)
        self.assertEqual(payload["wal"]["frames"][0]["page_number"], 1)
        self.assertIn("trusted SQLite recovery tool", payload["api_profile"]["reportability_warning"])

    def test_sqlite_wal_sidecar_header_profile_counts_frames(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            wal_path = Path(temp) / "chat.db-wal"
            wal_path.write_bytes(
                struct.pack(">IIIIIIII", 0x377F0683, 3007000, 1024, 7, 1, 2, 3, 4)
                + struct.pack(">IIIIII", 1, 0, 1, 2, 3, 4)
                + (b"\0" * 1024)
            )

            info = sqlite_wal_sidecar_info(wal_path)

        self.assertTrue(info["exists"])
        self.assertEqual(info["header"]["status"], "parsed")
        self.assertEqual(info["header"]["magic_hex"], "0x377f0683")
        self.assertEqual(info["header"]["page_size"], 1024)
        self.assertEqual(info["header"]["estimated_frame_count"], 1)

    def test_source_search_rejects_oversized_docx_member_before_expanding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            docx_path = Path(temp) / "oversized.docx"
            with zipfile.ZipFile(docx_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("word/document.xml", "<w:t>" + ("A" * 2048) + "</w:t>")

            payload = build_source_search(docx_path, ["needle"], max_plain_text_bytes=1024)

        self.assertFalse(payload["searchable"])
        self.assertEqual(payload["summary"]["match_count"], 0)
        self.assertIn("size limit", payload["message"])
        limits = payload["source_search_profile"]["large_data_controls"]["document_extraction_limits"]
        self.assertEqual(limits["max_archive_member_bytes"], 1024)
        self.assertEqual(limits["max_archive_total_bytes"], 1024)
        self.assertTrue(limits["limits_visible_to_gui"])

    def test_source_search_rejects_pdf_stream_that_expands_past_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            pdf_path = Path(temp) / "compressed-stream.pdf"
            expanded = b"(" + (b"A" * 2048) + b"needle" + b")"
            compressed = zlib.compress(expanded)
            pdf_path.write_bytes(
                b"%PDF-1.4\n"
                + b"1 0 obj << /Length "
                + str(len(compressed)).encode("ascii")
                + b" /Filter /FlateDecode >> stream\n"
                + compressed
                + b"\nendstream endobj\n%%EOF\n"
            )

            payload = build_source_search(pdf_path, ["needle"], max_plain_text_bytes=1024)

        self.assertFalse(payload["searchable"])
        self.assertEqual(payload["summary"]["match_count"], 0)
        self.assertIn("pdf stream expands beyond text extraction size limit", payload["message"])

    def test_large_case_resilience_contract_covers_items_56_to_60(self) -> None:
        contract = build_large_case_resilience_contract(requested_cap_bytes=512 * 1024 * 1024)

        self.assertEqual(contract["qc_prep_item_numbers"], [56, 57, 58, 59, 60])
        self.assertEqual(contract["source_search_full_cursor_contract"]["qc_prep_item_number"], 56)
        self.assertTrue(
            contract["source_search_full_cursor_contract"]["result_limit_policy"]["must_emit_resume_state_when_limit_reached"]
        )
        self.assertEqual(contract["hash_cache_persistence_contract"]["qc_prep_item_number"], 57)
        self.assertTrue(contract["hash_cache_persistence_contract"]["required_behaviors"]["invalidate_on_mtime_change"])
        self.assertEqual(contract["duplicate_grouping_contract"]["qc_prep_item_number"], 58)
        self.assertIn("perceptual-image-hash", contract["duplicate_grouping_contract"]["grouping_modes"])
        self.assertEqual(contract["parser_isolation_contract"]["qc_prep_item_number"], 59)
        self.assertTrue(contract["parser_isolation_contract"]["required_behaviors"]["partial_output_quarantine"])
        self.assertEqual(contract["memory_cap_contract"]["qc_prep_item_number"], 60)
        self.assertEqual(contract["memory_cap_contract"]["requested_cap_bytes"], 512 * 1024 * 1024)

    def test_web_entrypoint_parser_supports_direct_launch_options(self) -> None:
        args = build_web_parser().parse_args(["--host", "0.0.0.0", "--port", "9000"])

        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 9000)
        self.assertEqual(args.reload, False)
        self.assertIsNone(args.crash_log_dir)

    def test_health_and_index_are_available(self) -> None:
        client = TestClient(create_app(RunJobStore()))

        self.assertEqual(client.get("/api/health").json(), {"status": "ok"})
        self.assertFalse(client.get("/api/enterprise/policy").json()["telemetry"]["enabled"])
        keyword_packs = client.get("/api/keyword-packs").json()
        self.assertIn("#62", keyword_packs["keyword_pack_library_assessment"]["commercial_gap_ids"])
        self.assertEqual(keyword_packs["keyword_pack_library_assessment"]["core_accuracy_gates"][0]["gap_id"], "#62")
        library_manifest = keyword_packs["keyword_pack_library_assessment"]["keyword_pack_library_manifest"]
        self.assertEqual(library_manifest["manifest_version"], "keyword-pack-library-manifest-v1")

        self.assertEqual(
            keyword_packs["keyword_pack_library_assessment"]["keyword_pack_library_manifest_hash"],
            library_manifest["manifest_hash"],
        )
        self.assertGreaterEqual(library_manifest["keyword_row_hash_count"], 1)
        self.assertIn(
            "keyword-pack manifest hash",
            keyword_packs["keyword_pack_library_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn(
            "keyword row hashes",
            keyword_packs["keyword_pack_library_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertEqual(keyword_packs["keyword_pack_library_assessment"]["commercial_uplift_evidence"]["item_numbers"], [62])
        self.assertEqual(
            keyword_packs["keyword_pack_library_assessment"]["commercial_uplift_evidence"]["large_data_controls"]["keyword_pack_manifest_hash"],
            library_manifest["manifest_hash"],
        )
        self.assertEqual(
            keyword_packs["keyword_pack_library_assessment"]["commercial_uplift_evidence"]["reportability_decision"]["allowed_use"],
            "keyword-pack-expansion-triage-pivot",
        )
        self.assertIn(
            "trusted-keyword-pack-expansion-diff-missing",
            keyword_packs["keyword_pack_library_assessment"]["commercial_uplift_evidence"]["failed_validation_check_ids"],
        )
        self.assertIn("#62", keyword_packs["packs"][0]["commercial_gap_ids"])
        self.assertEqual(keyword_packs["packs"][0]["core_accuracy_gates"][0]["gap_id"], "#62")
        self.assertEqual(
            keyword_packs["packs"][0]["keyword_pack_manifest"]["manifest_version"],
            "keyword-pack-manifest-v1",
        )
        self.assertEqual(
            keyword_packs["packs"][0]["keyword_pack_manifest_hash"],
            keyword_packs["packs"][0]["keyword_pack_manifest"]["manifest_hash"],
        )
        self.assertGreaterEqual(keyword_packs["packs"][0]["keyword_pack_manifest"]["keyword_row_hash_count"], 1)
        self.assertEqual(keyword_packs["packs"][0]["commercial_uplift_evidence"]["batch_id"], "commercial-uplift-061-065")
        trusted_pack = build_keyword_pack_trusted_diff(["Password", "token"], ["password", "TOKEN"])
        pack_gates = keyword_pack_core_accuracy_gates(
            pack_count=1,
            keyword_count=2,
            custom_file_count=1,
            provenance_refs=["unit-pack"],
            trusted_diff=trusted_pack,
        )
        self.assertEqual(trusted_pack["status"], "pass")
        self.assertIn("trusted keyword-pack expansion diff pass", pack_gates[0]["satisfied_checks"])
        index_response = client.get("/")

        self.assertEqual(index_response.status_code, 200)
        self.assertIn("rapidtriage", index_response.text)
        favicon_response = client.get("/favicon.ico")
        self.assertEqual(favicon_response.status_code, 200)
        self.assertEqual(favicon_response.headers["content-type"].split(";")[0], "image/svg+xml")
        for asset_name in ("app_workbench_config.js", "app_state.js", "app.js"):
            asset_response = client.get(f"/assets/{asset_name}")
            self.assertEqual(asset_response.status_code, 200)
            self.assertIn("javascript", asset_response.headers["content-type"])

    def test_visible_forensic_capabilities_api_exposes_hidden_feature_status_and_run_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "run-out"
            run_dir.mkdir()
            artifacts_path = run_dir / "artifacts_browser.json"
            artifacts_path.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "artifact_type": "browser-history",
                                "url": "https://chatgpt.com/c/example",
                                "provider": "Chrome",
                            },
                            {
                                "artifact_type": "kakaotalk-message",
                                "path": "users/123/chatLogs_1.edb",
                                "details": {"service": "KakaoTalk"},
                            },
                            {
                                "artifact_type": "remote-control-log",
                                "path": "ProgramData/AnyDesk/service.trace",
                                "details": {"tool": "AnyDesk", "remote_id": "redacted"},
                            },
                            {
                                "artifact_type": "usb-device",
                                "path": "Windows/inf/setupapi.dev.log",
                                "details": {"registry": "USBSTOR", "serial": "redacted"},
                            },
                            {
                                "artifact_type": "print-spooler",
                                "path": "Windows/System32/spool/PRINTERS/job.SHD",
                                "details": {"printer": "Office Printer"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "fraud",
                        "root": str(run_dir),
                        "output_dir": str(run_dir),
                        "summary": {"browser_history_count": 1},
                        "outputs": {
                            "summary": str(summary_path),
                            "artifacts_browser": str(artifacts_path),
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            job = store.import_completed_run(run_dir)
            client = TestClient(create_app(store))

            static_response = client.get("/api/forensic-capabilities")
            run_response = client.get(f"/api/runs/{job.run_id}/capabilities")

        self.assertEqual(static_response.status_code, 200, static_response.text)
        static_payload = static_response.json()
        self.assertEqual(static_payload["profile_version"], "visible-forensic-capabilities-v1")
        self.assertIn("validation-required", static_payload["status_labels"])
        self.assertGreaterEqual(static_payload["summary"]["capability_count"], 80)
        self.assertTrue(static_payload["summary"]["gui_contract_pass"])
        self.assertEqual(static_payload["gui_contract"]["issue_count"], 0)
        first_capability = static_payload["groups"][0]["capabilities"][0]
        self.assertIn("tab", first_capability)
        self.assertIn("viewer", first_capability)
        self.assertIn("artifact_types", first_capability)
        self.assertIn("workflow_stage", first_capability)
        self.assertIn("next_action", first_capability)
        self.assertIn("gui_surfaces", first_capability)

        self.assertEqual(run_response.status_code, 200, run_response.text)
        run_payload = run_response.json()
        self.assertTrue(run_payload["summary"]["gui_contract_pass"])
        capabilities = {
            capability["id"]: capability
            for group in run_payload["groups"]
            for capability in group["capabilities"]
        }
        self.assertGreater(capabilities["browser-ai-usage"]["signal_count"], 0)
        self.assertGreater(capabilities["kakaotalk-windows-app-database"]["signal_count"], 0)
        self.assertGreater(capabilities["remote-control-anydesk-teamviewer-rustdesk"]["signal_count"], 0)
        self.assertGreater(capabilities["usb-external-device-history"]["signal_count"], 0)
        self.assertGreater(capabilities["print-spooler-spl-shd"]["signal_count"], 0)
        self.assertIn("windows-copilot-recall", capabilities)
        self.assertIn("super-timeline-plaso-style", capabilities)
        self.assertIn("yara-ioc-scanner", capabilities)
        self.assertTrue(capabilities["browser-ai-usage"]["has_signals"])
        self.assertTrue(run_payload["summary"]["run_bound"])

    def test_web_console_exposes_maestro_style_artifact_workbench(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        state_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_state.js").read_text(encoding="utf-8")
        index_html = (REPO_ROOT / "rapidtriage" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('/assets/app_workbench_config.js', index_html)
        self.assertIn('/assets/app_state.js', index_html)
        self.assertLess(index_html.index('/assets/app_workbench_config.js'), index_html.index('/assets/app.js'))
        self.assertLess(index_html.index('/assets/app_workbench_config.js'), index_html.index('/assets/app_state.js'))
        self.assertLess(index_html.index('/assets/app_state.js'), index_html.index('/assets/app.js'))
        self.assertIn("FORENSIC_RIBBON_GROUPS", config_js)
        self.assertIn("FORENSIC_ARTIFACT_TAXONOMY", config_js)
        self.assertIn("renderForensicRibbon(run)", app_js)
        self.assertIn("renderCaseHero(run)", app_js)
        self.assertIn("renderCaseReadinessDashboard(payload)", app_js)
        self.assertIn("case-readiness-dashboard", app_js)
        self.assertIn("loadCommercialReadinessSummary", app_js)
        self.assertIn("new URLSearchParams", app_js)
        self.assertIn("next_gate: \"commercial_grade\"", app_js)
        self.assertIn("include_internal_validation: \"true\"", app_js)
        self.assertIn("MAC_FIRST_EVIDENCE_STORAGE_KEY", app_js)
        self.assertIn("mac_first_evidence", app_js)
        self.assertIn("bindMacFirstEvidenceControls", app_js)
        self.assertIn("Validation package", app_js)
        self.assertIn("Mapped evidence", app_js)
        self.assertIn("Mac evidence", app_js)
        self.assertIn("Mac-first evidence is attached as preparatory proof only", app_js)
        self.assertIn("renderMacFirstEvidenceRows", app_js)
        self.assertIn("data-testid=\"mac-first-evidence-rows\"", app_js)
        self.assertIn("Attached Mac evidence", app_js)
        self.assertIn("trusted diff", app_js)
        self.assertIn("commercial-readiness-panel", app_js)
        self.assertIn("Commercial readiness gate", app_js)
        self.assertIn("globalCaseSearchForm", app_js)
        self.assertIn("runGlobalCommandSearch", app_js)
        self.assertIn("bindCaseDbCursorButtons", app_js)
        self.assertIn("data-testid=\"case-db-cursor-pagination\"", app_js)
        self.assertIn("Next results", app_js)
        self.assertIn("renderE01IngestWorkflow", app_js)
        self.assertIn("renderE01HandoffContract", app_js)
        self.assertIn("renderE01PartitionBrowser", app_js)
        self.assertIn("renderVscWorkflowHandoff", app_js)
        self.assertIn("renderImageStageControlStatus", app_js)
        self.assertIn("bindE01PartitionControls", app_js)
        self.assertIn("renderE01RunWorkflowStatus", app_js)
        self.assertIn("renderRunPlanE01Readiness", app_js)
        self.assertIn("applyEvidenceCheckRecommendation", app_js)
        self.assertIn("bindEvidenceCheckActions", app_js)
        self.assertIn("E01_PRE_RUN_STEPS", app_js)
        self.assertIn("updateRunSubmissionCta", app_js)
        self.assertIn("Starting E01 workflow", app_js)
        self.assertIn("e01-workflow-panel", app_js)
        self.assertIn("data-testid=\"e01-end-to-end-handoff\"", app_js)
        self.assertIn("data-testid=\"e01-partition-browser\"", app_js)
        self.assertIn("data-testid=\"vsc-workflow-handoff\"", app_js)
        self.assertIn("data-testid=\"image-stage-control-contract\"", app_js)
        self.assertIn("data-start-configured-e01-run", app_js)
        self.assertIn("data-e01-partition-sector", app_js)
        self.assertIn("renderViewerEvidenceTrail", app_js)
        self.assertIn("source-verification", app_js)
        self.assertIn("renderCompareCitationBundle", app_js)
        self.assertIn("report-citation-bundle", app_js)
        self.assertIn("renderEvtxReadinessArtifactCard", app_js)
        self.assertIn("evtx_commercial_readiness_profile", app_js)
        self.assertIn("renderNtfsDepthArtifactCard", app_js)
        self.assertIn("ntfs_native_depth_readiness_profile", app_js)
        self.assertIn("ntfsArtifactPreviewText", app_js)
        self.assertIn("renderNtfsReplayPreviewArtifactCard", app_js)
        self.assertIn("bounded_mft_replay_preview", app_js)
        self.assertIn("rename_pair_preview", app_js)
        self.assertIn("delete_lifecycle_preview", app_js)
        self.assertIn("Delete lifecycle", app_js)
        self.assertIn("bounded MFT path correlation", app_js)
        self.assertIn("renderNtfsSourceLocatorLinks", app_js)
        self.assertIn("Source locators", app_js)
        self.assertIn("source-hex-range", app_js)
        self.assertIn("renderSourceResolutionDiagnostics", app_js)
        self.assertIn("Source path resolution diagnostics", app_js)
        self.assertIn("renderRegistryDepthArtifactCard", app_js)
        self.assertIn("registryArtifactPreviewText", app_js)
        self.assertIn("registry_native_depth_readiness_profile", app_js)
        self.assertIn("renderWindowsCoreReadinessArtifactCard", app_js)
        self.assertIn("windowsCoreReadinessProfile", app_js)
        self.assertIn("account_privilege_deep_parse_profile", app_js)
        self.assertIn("execution_artifact_validation_profile", app_js)
        self.assertIn("srum_ese_validation_profile", app_js)
        self.assertIn("renderCoreAccuracyGateCard", app_js)
        self.assertIn("core_accuracy_gates", app_js)
        self.assertIn("missing_required_checks", app_js)
        self.assertIn("renderArtifactValidationBadges", app_js)
        self.assertIn("artifact-validation-badges", app_js)
        self.assertIn("renderArtifactValidationSummary", app_js)
        self.assertIn("summarizeArtifactValidation", app_js)
        self.assertIn("artifactCommercialBlockers", app_js)
        self.assertIn("renderVirtualWindowJumpControl", state_js)
        self.assertIn("VIRTUAL_WINDOW_STORAGE_PREFIX", app_js)
        self.assertIn("renderForensicArtifactNavigator(payload)", app_js)
        self.assertIn("virtualWindowOffsets", app_js)
        self.assertIn("data-virtual-window-key", app_js)
        self.assertIn("function bindVirtualWindowButtons", state_js)
        self.assertIn("WORKBENCH_SMOKE_CHECKPOINTS", config_js)
        self.assertIn("START_CHOICE_CONTRACT", config_js)
        self.assertIn("applyStartChoice", app_js)
        self.assertIn("WORKBENCH_LAYOUT_CONTRACT", config_js)
        self.assertIn("WORKBENCH_ARTIFACT_TREE_GROUPS", config_js)
        self.assertIn("TABLE_CONTROL_CONTRACT", config_js)
        self.assertIn("PREVIEW_DETAIL_CONTRACT", config_js)
        self.assertIn("VIEWER_NAVIGATION_CONTRACT", config_js)
        self.assertIn("WORKBENCH_SESSION_CONTRACT", config_js)
        self.assertIn("SEARCH_SOURCE_VERIFICATION_CONTRACT", config_js)
        self.assertIn("SEARCH_RESULT_SOURCE_ACTION_CONTRACT", config_js)
        self.assertIn("CURRENT_FILE_SEARCH_CONTRACT", config_js)
        self.assertIn("renderWorkbenchLayoutFrame", app_js)
        self.assertIn("renderTableControlBar", app_js)
        self.assertIn("renderPreviewRail", app_js)
        self.assertIn("renderPreviewDetailCard", app_js)
        self.assertIn("recordViewerNavigation", app_js)
        self.assertIn("renderViewerNavigationControls", app_js)
        self.assertIn("goViewerNavigation", app_js)
        self.assertIn("function persistWorkbenchSession", state_js)
        self.assertIn("function restoreWorkbenchSession", state_js)
        self.assertIn("function restoreWorkbenchControls", state_js)
        self.assertIn("renderSearchSourceVerification", app_js)
        self.assertIn("renderSearchResultLocator", app_js)
        self.assertIn("renderSearchResultSourceActionStrip", app_js)
        self.assertIn("renderCurrentFileSearchProfile", app_js)
        self.assertIn("applyWorkbenchFilters", app_js)
        self.assertIn("applyColumnPreset", app_js)
        self.assertIn("data-testid=\"case-workbench-layout\"", app_js)
        self.assertIn("data-testid=\"table-control-bar\"", app_js)
        self.assertIn("data-testid=\"workbench-artifact-tree\"", app_js)
        self.assertIn("data-testid=\"workbench-result-table\"", app_js)
        self.assertIn("data-testid=\"workbench-preview-detail\"", app_js)
        self.assertIn("data-testid=\"preview-analyst-summary\"", app_js)
        self.assertIn("data-testid=\"preview-source-locator\"", app_js)
        self.assertIn("data-testid=\"preview-metadata-disclosure\"", app_js)
        self.assertIn("data-testid=\"preview-hash-card\"", app_js)
        self.assertIn("data-testid=\"preview-limitation-warning\"", app_js)
        self.assertIn("data-testid=\"preview-review-actions\"", app_js)
        self.assertIn("data-testid=\"viewer-navigation-bar\"", app_js)
        self.assertIn("data-viewer-history-delta", app_js)
        self.assertIn("data-testid=\"search-source-verification\"", app_js)
        self.assertIn("data-testid=\"search-result-locator\"", app_js)
        self.assertIn("data-testid=\"search-result-source-actions\"", app_js)
        self.assertIn("data-testid=\"current-file-search-profile\"", app_js)
        self.assertIn("data-testid=\"evidence-tray\"", app_js)
        self.assertIn("data-testid=\"report-tray\"", app_js)
        self.assertIn("Browser / AI", app_js)
        self.assertIn("Messenger", app_js)
        self.assertIn("Validation", app_js)
        self.assertIn("data-testid=\"start-choice-grid\"", index_html)
        self.assertIn("data-testid=\"start-choice-e01\"", index_html)
        self.assertIn("data-testid=\"start-choice-folder\"", index_html)
        self.assertIn("data-testid=\"start-choice-recent\"", index_html)
        self.assertIn("data-testid=\"start-choice-sample\"", index_html)
        self.assertIn("data-testid=\"start-choice-qc\"", index_html)
        self.assertIn("intake-choice-card", styles)
        self.assertIn("case-workbench-layout", styles)
        self.assertIn("table-control-bar", styles)
        self.assertIn("table-columns-compact", styles)
        self.assertIn("table-columns-source", styles)
        self.assertIn("workbench-artifact-tree", styles)
        self.assertIn("workbench-preview-rail", styles)
        self.assertIn("analyst-preview-card", styles)
        self.assertIn("preview-metadata-list", styles)
        self.assertIn("limitation-warning-card.warning", styles)
        self.assertIn("viewer-navigation-bar", styles)
        self.assertIn("search-verification-card", styles)
        self.assertIn("search-result-locator", styles)
        self.assertIn("search-result-source-actions", styles)
        self.assertIn("current-file-search-profile", styles)
        self.assertIn("renderWorkbenchSmokePanel(run)", app_js)
        self.assertIn("renderRunValidationPackageSummary", app_js)
        self.assertIn("run-validation-diff-panel", app_js)
        self.assertIn("usn_state_replay_diff_attached", app_js)
        self.assertIn("renderCrashReportsPanel", app_js)
        self.assertIn("crash-dashboard", app_js)
        self.assertIn("data-testid=\"case-hero\"", app_js)
        self.assertIn("data-testid=\"global-case-search\"", app_js)
        self.assertIn("data-testid=\"source-viewer\"", app_js)
        self.assertIn("data-testid=\"source-verification-trail\"", app_js)
        self.assertIn("data-testid=\"viewer-review-form\"", app_js)
        self.assertIn("data-testid=\"artifact-validation-summary\"", app_js)
        self.assertIn("/api/workbench/smoke-contract", app_js)
        self.assertIn("/api/workbench/large-result-evidence?record_count=100000", app_js)
        self.assertIn("e2e performance contract", app_js)
        self.assertIn("/validation-package", app_js)
        self.assertIn("Crash reports", index_html)
        self.assertIn("forensic-ribbon", styles)
        self.assertIn("case-hero", styles)
        self.assertIn("crash-dashboard", styles)
        self.assertIn("workbench-smoke-panel", styles)
        self.assertIn("smoke-checkpoint-row", styles)
        self.assertIn("smoke-link-row", styles)
        self.assertIn("validation-diff-card", styles)
        self.assertIn("validation-diff-list", styles)
        self.assertIn("case-readiness-dashboard", styles)
        self.assertIn("readiness-grid", styles)
        self.assertIn("case-command-search", styles)
        self.assertIn("e01-workflow-panel", styles)
        self.assertIn("e01-handoff-card", styles)
        self.assertIn("e01-partition-browser", styles)
        self.assertIn("e01-partition-table", styles)
        self.assertIn("vsc-handoff-card", styles)
        self.assertIn("vsc-step-grid", styles)
        self.assertIn("image-stage-control-card", styles)
        self.assertIn("stage-control-grid", styles)
        self.assertIn("e01-stage-grid", styles)
        self.assertIn("run-plan-e01-readiness", styles)
        self.assertIn("e01-pre-run-grid", styles)
        self.assertIn("commercial-readiness-card", styles)
        self.assertIn("not-commercial-ready", styles)

    def test_commercial_readiness_api_returns_compact_gui_gate(self) -> None:
        client = TestClient(create_app(RunJobStore()))

        response = client.get("/api/commercial-readiness?next_gate=validated&limit=3")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["command"], "commercial-readiness")
        self.assertEqual(payload["api_profile"]["profile_version"], "commercial-readiness-gui-gate-v1")
        self.assertEqual(payload["api_profile"]["gui_binding"], "commercial-readiness-gate")
        self.assertFalse(payload["commercial_claim_allowed"])
        self.assertIn("validated", payload["gate_counts"])
        self.assertIn("commercial_grade", payload["gate_counts"])
        self.assertLessEqual(len(payload["focused_items"]), 3)
        self.assertTrue(payload["focused_items"])
        self.assertEqual(payload["focused_next_gate"], "validated")
        self.assertIn("workbench_actions", payload)
        self.assertFalse(payload["validation_package"]["attached"])

    def test_commercial_readiness_api_can_attach_internal_validation_package(self) -> None:
        client = TestClient(create_app(RunJobStore()))

        response = client.get(
            "/api/commercial-readiness?next_gate=commercial_grade&limit=4&include_internal_validation=true"
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertFalse(payload["commercial_claim_allowed"])
        self.assertEqual(payload["api_profile"]["validation_package_mode"], "internal-known-answer")
        self.assertTrue(payload["validation_package"]["attached"])
        self.assertEqual(payload["validation_package"]["mode"], "internal-known-answer")
        self.assertEqual(payload["validation_evidence_summary"]["items_with_passed_validation_evidence"], 120)
        self.assertEqual(payload["gate_counts"]["validated"]["passed"], 120)
        self.assertEqual(payload["gate_counts"]["commercial_grade"]["passed"], 0)
        self.assertEqual(payload["focused_next_gate"], "commercial_grade")
        self.assertTrue(payload["focused_items"])

    def test_commercial_readiness_api_can_attach_mac_first_evidence(self) -> None:
        client = TestClient(create_app(RunJobStore()))
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence_path = Path(tmp_dir) / "macos-live-smoke.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "command": "macos-live-smoke",
                        "profile_version": "macos-live-smoke-v1",
                        "summary": {
                            "local_smoke_score": 85.71,
                            "passed_count": 6,
                            "failed_count": 1,
                            "failed_check_ids": ["forensic-cross-tool-ready"],
                        },
                        "commercial_grade_blockers": ["trusted-forensic-cross-tool-output-missing"],
                        "outputs": {"json": str(evidence_path)},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            response = client.get(f"/api/commercial-readiness?mac_first_evidence={evidence_path}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        mac_first = payload["mac_first_evidence_summary"]
        self.assertTrue(mac_first["attached"])
        self.assertEqual(mac_first["evidence_count"], 1)
        self.assertFalse(payload["commercial_claim_allowed"])
        self.assertEqual(payload["gate_counts"]["commercial_grade"]["passed"], 0)

    def test_commercial_readiness_api_reports_bad_mac_first_evidence_as_operator_input_error(self) -> None:
        client = TestClient(create_app(RunJobStore()))
        with tempfile.TemporaryDirectory() as tmp_dir:
            missing_path = Path(tmp_dir) / "missing-qc"

            response = client.get(f"/api/commercial-readiness?mac_first_evidence={missing_path}")

        self.assertEqual(response.status_code, 400)
        self.assertIn("Mac-first evidence path not found", response.json()["detail"])

    def test_crash_report_api_lists_details_and_exports_local_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch.dict("os.environ", {"RAPIDTRIAGE_CRASH_LOG_DIR": tmp_dir}, clear=False):
                report = write_crash_report(
                    RuntimeError("api boom"),
                    context={
                        "component": "unit-test",
                        "path": "/api/example",
                        "auth_token": "secret-token",
                    },
                )
                client = TestClient(create_app(RunJobStore()))

                listing_response = client.get("/api/crash-reports")
                self.assertEqual(listing_response.status_code, 200)
                listing = listing_response.json()
                self.assertEqual(listing["command"], "crash-reports")
                self.assertIn("#105", listing["commercial_gap_ids"])
                self.assertTrue(listing["local_only"])
                self.assertFalse(listing["upload_enabled"])
                self.assertEqual(listing["summary"]["report_count"], 1)
                self.assertEqual(listing["crash_trend_dashboard"]["report_count"], 1)
                self.assertTrue(listing["crash_trend_dashboard"]["export_ui_available"])
                self.assertEqual(listing["reports"][0]["crash_id"], report["crash_id"])
                self.assertGreaterEqual(listing["reports"][0]["redacted_key_count"], 1)
                self.assertGreaterEqual(listing["crash_trend_dashboard"]["redacted_key_total"], 1)

                detail_response = client.get(f"/api/crash-reports/{report['crash_id']}")
                self.assertEqual(detail_response.status_code, 200)
                detail = detail_response.json()
                self.assertEqual(detail["summary"]["crash_id"], report["crash_id"])
                self.assertEqual(detail["payload"]["crash_id"], report["crash_id"])
                self.assertNotIn("secret-token", json.dumps(detail, ensure_ascii=False))

                export_response = client.post(f"/api/crash-reports/{report['crash_id']}/export")
                self.assertEqual(export_response.status_code, 200)
                exported = export_response.json()
                self.assertEqual(exported["profile_version"], "crash-export-ui-bundle-manifest-v1")
                self.assertTrue(exported["local_only"])
                self.assertFalse(exported["automatic_upload_enabled"])
                bundle_path = Path(exported["bundle_path"])
                self.assertTrue(bundle_path.exists())
                self.assertEqual(hash_file(bundle_path, "sha256"), exported["bundle_sha256"])
                with zipfile.ZipFile(bundle_path) as bundle:
                    names = set(bundle.namelist())
                    self.assertIn("crash-export-manifest.json", names)
                    self.assertIn(f"{report['crash_id']}.json", names)

    def test_workbench_smoke_contract_exposes_browser_test_flow(self) -> None:
        client = TestClient(create_app(RunJobStore()))
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        index_html = (REPO_ROOT / "rapidtriage" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        response = client.get("/api/workbench/smoke-contract")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["profile_version"], "single-case-workbench-smoke-v1")
        self.assertEqual(payload["qc_prep_item"], 5)
        self.assertEqual(len(payload["manifest_sha256"]), 64)
        self.assertEqual(payload["immediate_queue_item"], 7)
        self.assertTrue(payload["browser_test_ready"])
        self.assertFalse(payload["commercial_grade_ready"])
        self.assertIn("fresh_gui_launch_evidence", payload)
        self.assertEqual(payload["fresh_gui_launch_evidence"]["required_platforms"], ["windows", "macos"])
        self.assertTrue(payload["implemented_controls"]["platform_smoke_scripts"])
        self.assertEqual(payload["functional_priority_profile"]["queue_item_number"], 7)
        self.assertIn("playwright-browser-smoke-log-not-attached", payload["functional_priority_profile"]["failed_validation_check_ids"])
        self.assertIn("fresh-macos-browser-run-not-attached", payload["functional_priority_profile"]["failed_validation_check_ids"])
        platforms = {row["platform"]: row for row in payload["platform_evidence"]}
        self.assertIn("windows", platforms)
        self.assertIn("macos", platforms)
        self.assertIn("smoke-test-rapidtriage.ps1", platforms["windows"]["script"])
        self.assertIn("smoke-test-rapidtriage.sh", platforms["macos"]["script"])
        self.assertIn("source_viewer", payload["selectors"])
        self.assertIn("viewer_review", payload["selectors"])
        static_markup = index_html + app_js
        for selector in payload["selectors"].values():
            if selector.startswith("[data-testid='"):
                test_id = selector.removeprefix("[data-testid='").removesuffix("']")
                if f'data-testid="{test_id}"' in static_markup:
                    continue
                if test_id.startswith("tab-"):
                    self.assertIn('data-testid="tab-${escapeHtml(item)}"', app_js)
                    self.assertIn(test_id.removeprefix("tab-"), app_js)
                    continue
                self.fail(f"Smoke selector {selector} is not present in static markup")
            elif "data-tab='" in selector:
                tab = selector.split("data-tab='", 1)[1].split("'", 1)[0]
                self.assertIn(f'data-tab="${{escapeHtml(mode.tab)}}"', app_js)
                self.assertIn(f'tab: "{tab}"', (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8"))
        self.assertIn("case_report", payload["api_routes"])
        step_ids = {step["id"] for step in payload["required_steps"]}
        self.assertEqual(
            step_ids,
            {
                "open-workbench",
                "create-or-import-run",
                "select-run",
                "search-case",
                "open-source-viewer",
                "mark-evidence",
                "export-report",
            },
        )
        for step_id in step_ids:
            self.assertIn(f'id: "{step_id}"', (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8"))
        self.assertIn("viewer-evidence-trail", styles)
        self.assertIn("viewer-evidence-card", styles)
        self.assertIn("compare-citation-bundle", styles)
        self.assertIn("evtx-readiness-card", styles)
        self.assertIn("ntfs-depth-card", styles)
        self.assertIn("registry-depth-card", styles)
        self.assertIn("windows-core-readiness-card", styles)
        self.assertIn("core-accuracy-card", styles)
        self.assertIn("accuracy-gate-row", styles)
        self.assertIn("artifact-validation-badges", styles)
        self.assertIn("artifact-validation-summary", styles)
        self.assertIn("artifact-validation-summary-grid", styles)
        self.assertIn("forensic-artifact-navigator", styles)
        self.assertIn("virtual-window-card", styles)
        self.assertIn("virtual-window-jump", styles)

    def test_workbench_large_result_evidence_profiles_100k_ui_windowing(self) -> None:
        client = TestClient(create_app(RunJobStore()))

        response = client.get("/api/workbench/large-result-evidence", params={"record_count": 100_000})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["profile_version"], "large-result-ui-evidence-v1")
        self.assertEqual(payload["immediate_queue_item"], 8)
        self.assertEqual(payload["record_count"], 100_000)
        self.assertLessEqual(payload["visible_rows"], 300)
        self.assertTrue(payload["dom_budget"]["dom_budget_pass"])
        self.assertGreaterEqual(payload["window_count"], 2)
        self.assertTrue(all(len(item["manifest"]["manifest_hash"]) == 64 for item in payload["window_manifests"]))
        self.assertEqual(payload["performance_contract"]["profile_version"], "browser-e2e-performance-contract-v1")
        self.assertEqual(payload["performance_contract"]["item_number"], 25)
        self.assertEqual(len(payload["performance_contract"]["contract_hash"]), 64)
        self.assertIn("virtual_window_card", payload["performance_contract"]["selectors"])
        self.assertGreaterEqual(len(payload["performance_contract"]["required_steps"]), 6)
        self.assertIn("playwright-trace.zip", payload["performance_contract"]["required_artifacts"])
        self.assertEqual(payload["performance_contract"]["performance_budgets"]["dom_node_budget"], payload["dom_budget"]["dom_node_budget"])
        self.assertEqual(payload["evidence_manifest"]["profile_version"], "large-result-ui-evidence-manifest-v1")
        self.assertEqual(payload["evidence_manifest"]["performance_contract_hash"], payload["performance_contract"]["contract_hash"])
        self.assertEqual(len(payload["evidence_manifest_hash"]), 64)
        self.assertEqual(payload["evidence_manifest_hash"], payload["evidence_manifest"]["manifest_hash"])
        self.assertEqual(payload["functional_priority_profile"]["queue_item_number"], 8)
        self.assertEqual(
            payload["functional_priority_profile"]["controls"]["performance_contract_hash"],
            payload["performance_contract"]["contract_hash"],
        )
        self.assertEqual(
            payload["functional_priority_profile"]["controls"]["evidence_manifest_hash"],
            payload["evidence_manifest_hash"],
        )
        self.assertIn("playwright-100k-browser-trace-not-attached", payload["functional_priority_profile"]["failed_validation_check_ids"])
        self.assertFalse(payload["commercial_grade_ready"])

    def test_sample_case_api_creates_and_imports_practice_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = TestClient(create_app(RunJobStore()))
            response = client.post(
                "/api/sample-case/run",
                json={
                    "output_dir": str(Path(tmp_dir) / "sample"),
                    "mode": "fraud",
                    "overwrite": True,
                    "read_only": True,
                },
            )

            self.assertEqual(response.status_code, 201, response.text)
            payload = response.json()
            self.assertEqual(payload["command"], "sample-case.run")
            self.assertEqual(payload["run"]["status"], "completed")
            self.assertEqual(payload["run"]["origin"], "imported")
            self.assertTrue((Path(tmp_dir) / "sample" / "run-output" / "rapidtriage-run-summary.json").is_file())

    def test_run_validation_package_exports_hashes_review_status_and_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = TestClient(create_app(RunJobStore()))
            response = client.post(
                "/api/sample-case/run",
                json={
                    "output_dir": str(Path(tmp_dir) / "sample"),
                    "mode": "fraud",
                    "overwrite": True,
                    "read_only": True,
                },
            )
            self.assertEqual(response.status_code, 201, response.text)
            run_payload = response.json()["run"]
            run_id = run_payload["run_id"]
            output_dir = Path(run_payload["summary"]["output_dir"])

            bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "files",
                    "pointer": "/candidates/0",
                    "tag": "validation",
                    "note": "Include this source in validation-package review status.",
                    "review_status": "relevant",
                    "include_in_report": True,
                },
            )
            self.assertEqual(bookmark_response.status_code, 200, bookmark_response.text)

            package_response = client.get(f"/api/runs/{run_id}/validation-package")

            self.assertEqual(package_response.status_code, 200, package_response.text)
            package = package_response.json()
            self.assertEqual(package["command"], "run.validation-package")
            self.assertEqual(package["profile_version"], "run-validation-package-v1")
            self.assertEqual(package["immediate_queue_item"], 9)
            self.assertEqual(package["functional_priority_profile"]["queue_item_number"], 9)
            self.assertFalse(package["commercial_grade_ready"])
            self.assertIn("trusted-tool-diffs-not-attached", package["commercial_grade_blockers"])
            self.assertEqual(package["review_status"]["bookmark_count"], 1)
            self.assertEqual(package["review_status"]["report_item_count"], 1)
            self.assertEqual(package["review_status"]["review_status_counts"]["relevant"], 1)
            self.assertGreater(package["output_hashes"]["item_count"], 0)
            self.assertTrue(all(len(item["hashes"]["sha256"]) == 64 for item in package["output_hashes"]["items"]))
            self.assertEqual(len(package["package_manifest_hash"]), 64)
            self.assertTrue((output_dir / "rapidforensic-run-validation-package.json").is_file())
            self.assertTrue((output_dir / "rapidforensic-run-validation-package.audit.json").is_file())
            self.assertTrue(any(item["area"] == "trusted-diff" for item in package["limitation_inventory"]))

            file_response = client.get(f"/api/runs/{run_id}/validation-package/file")
            self.assertEqual(file_response.status_code, 200)
            self.assertIn("run.validation-package", file_response.text)

    def test_run_validation_diff_inventory_summarizes_usn_state_replay_cross_tool_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            cross_tool = root / "usn-state-replay-cross-tool.json"
            cross_tool.write_text(
                json.dumps(
                    {
                        "command": "cross-tool-validate",
                        "status": "pass",
                        "comparisons": [
                            {
                                "reference_name": "known-answer-state-replay",
                                "status": "pass",
                                "usn_state_replay_field_comparison": {
                                    "mode": "usn-state-replay-field-diff",
                                    "common_record_count": 1,
                                    "mismatch_count": 0,
                                    "missing_common_field_count": 0,
                                    "field_match_ratio": 1.0,
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            inventory = build_run_validation_diff_inventory(
                {"outputs": {"usn_state_replay_cross_tool": str(cross_tool)}}
            )

            self.assertTrue(inventory["attached"])
            self.assertEqual(inventory["cross_tool_output_count"], 1)
            self.assertTrue(inventory["usn_state_replay_diff_attached"])
            self.assertEqual(inventory["usn_state_replay_diff_pass_count"], 1)
            summary = inventory["outputs"][0]["diff_summary"]
            self.assertEqual(summary["command"], "cross-tool-validate")
            self.assertEqual(summary["usn_state_replay_status"], "pass")
            self.assertEqual(summary["usn_state_replay_common_record_count"], 1)
            self.assertIn("usn-state-replay-field-diff", summary["field_diff_modes"])

    def test_run_validation_package_uses_attached_trusted_diff_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            run_dir = root / "run"
            run_dir.mkdir()
            cross_tool = run_dir / "validation-diffs" / "usn-state-replay-cross-tool.json"
            cross_tool.parent.mkdir()
            cross_tool.write_text(
                json.dumps(
                    {
                        "command": "cross-tool-validate",
                        "status": "pass",
                        "comparisons": [
                            {
                                "reference_name": "known-answer-state-replay",
                                "status": "pass",
                                "usn_state_replay_field_comparison": {
                                    "mode": "usn-state-replay-field-diff",
                                    "common_record_count": 3,
                                    "mismatch_count": 0,
                                    "missing_common_field_count": 0,
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            summary_path = run_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "profile_version": "rapidtriage-run-summary-v1",
                        "mode": "fraud",
                        "root": str(root / "evidence.E01"),
                        "output_dir": str(run_dir),
                        "outputs": {
                            "summary": str(summary_path),
                            "validation_diff_usn_state": str(cross_tool),
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = RunJobStore()
            job = store.import_completed_run(run_dir)

            package = build_run_validation_package(store, job.run_id)

            profile = package["functional_priority_profile"]
            self.assertIn("trusted-tool-diff-output-attached", profile["passed_validation_check_ids"])
            self.assertIn("trusted-tool-diff-pass-recorded", profile["passed_validation_check_ids"])
            self.assertNotIn("trusted-tool-diffs-not-attached", profile["failed_validation_check_ids"])
            self.assertNotIn("trusted-tool-diffs-not-attached", package["commercial_grade_blockers"])
            self.assertIn("independent-review-not-attached", package["commercial_grade_blockers"])
            self.assertTrue(package["implemented_controls"]["trusted_diff_attached"])
            self.assertTrue(package["implemented_controls"]["trusted_diff_pass_recorded"])
            self.assertEqual(package["diff_inventory"]["usn_state_replay_diff_pass_count"], 1)

    def test_evidence_identify_api_reports_extended_container_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "phone-export.ad1"
            source.write_bytes(b"fixture")
            client = TestClient(create_app(RunJobStore()))

            response = client.post("/api/evidence/identify", json={"path": str(source)})

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["command"], "evidence.identify")
            self.assertEqual(payload["result"]["adapter"], "forensic-container")
            self.assertEqual(payload["result"]["detected_format"], "ad1")
            self.assertEqual(payload["result"]["supported"], True)
            self.assertEqual(payload["result"]["can_extract"], False)
            self.assertTrue(any(".ad1" in item["suffixes"] for item in payload["formats"]))

    def test_collect_plan_api_previews_profile_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            build_windows_artifact_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            profiles_response = client.get("/api/collect/profiles")
            plan_response = client.post(
                "/api/collect/plan",
                json={"root": str(root), "profile": "intrusion", "input_kind": "mounted-image"},
            )

            self.assertEqual(profiles_response.status_code, 200)
            self.assertIn("intrusion", profiles_response.json()["profiles"])
            self.assertEqual(plan_response.status_code, 200, plan_response.text)
            payload = plan_response.json()
            self.assertEqual(payload["command"], "collect-plan")
            self.assertEqual(payload["profile"], "intrusion")
            self.assertGreater(payload["summary"]["present_count"], 0)
            self.assertIn("EventLogs", payload["summary"]["category_counts"])

    def test_create_run_waits_and_exposes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            sqlite_path = root / "viewer.sqlite"
            connection = sqlite3.connect(sqlite_path)
            try:
                connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO notes (body) VALUES (?)", ("password in sqlite viewer",))
                connection.commit()
            finally:
                connection.close()
            json_path = root / "structured.json"
            json_path.write_text(json.dumps({"case": "CASE-001", "hit": {"keyword": "password"}}), encoding="utf-8")
            xml_path = root / "structured.xml"
            xml_path.write_text("<root><event id='1'>password xml hit</event></root>", encoding="utf-8")
            eml_path = root / "message.eml"
            eml_path.write_text(
                "From: alice@example.com\n"
                "To: bob@example.com\n"
                "Subject: Password review\n"
                "Date: Mon, 27 Apr 2026 12:00:00 +0900\n"
                "MIME-Version: 1.0\n"
                "Content-Type: multipart/mixed; boundary=\"rapid-boundary\"\n"
                "\n"
                "--rapid-boundary\n"
                "Content-Type: text/plain; charset=\"utf-8\"\n"
                "\n"
                "password email body\n"
                "--rapid-boundary\n"
                "Content-Type: text/plain; name=\"note.txt\"\n"
                "Content-Disposition: attachment; filename=\"note.txt\"\n"
                "\n"
                "attached password note\n"
                "--rapid-boundary--\n",
                encoding="utf-8",
            )
            binary_path = root / "binary.bin"
            binary_path.write_bytes(b"\x00\x01RapidTriage\xff" * 300)
            image_path = root / "screen.png"
            from PIL import Image

            Image.new("RGB", (16, 12), "white").save(image_path)
            similar_image_path = root / "screen-copy.png"
            Image.new("RGB", (16, 12), "white").save(similar_image_path)
            image_path.with_name("screen.ocr.txt").write_text("이미지 OCR password", encoding="utf-8")
            image_path.with_name("screen.translation.txt").write_text("translated OCR password", encoding="utf-8")
            media_path = root / "call.wav"
            with wave.open(str(media_path), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(8000)
                wav_file.writeframes(b"\x00\x00" * 8000)
            media_path.with_suffix(".wav.srt").write_text("1\n00:00:00,000 --> 00:00:01,000\npassword spoken\n", encoding="utf-8")
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 202, response.text)
            run_payload = response.json()
            self.assertEqual(run_payload["status"], "completed")
            self.assertEqual(run_payload["summary"]["mode"], "fraud")

            run_id = run_payload["run_id"]
            summary_response = client.get(f"/api/runs/{run_id}/summary")
            files_response = client.get(f"/api/runs/{run_id}/files")
            timeline_response = client.get(f"/api/runs/{run_id}/timeline")
            indicators_response = client.get(f"/api/runs/{run_id}/indicators", params={"offset": 0, "limit": 5})
            search_response = client.get(
                f"/api/runs/{run_id}/search",
                params={"keyword": "password", "ocr": "false", "keyword_pack": "credentials"},
            )
            docs_index_search_response = client.get(
                f"/api/runs/{run_id}/docs-index-search",
                params={"keyword": "password", "limit": 5},
            )

            self.assertEqual(summary_response.status_code, 200)
            self.assertEqual(files_response.status_code, 200)
            self.assertEqual(timeline_response.status_code, 200)
            self.assertEqual(indicators_response.status_code, 200)
            self.assertEqual(search_response.status_code, 200)
            self.assertEqual(docs_index_search_response.status_code, 200, docs_index_search_response.text)
            docs_index_payload = docs_index_search_response.json()
            self.assertEqual(docs_index_payload["command"], "docs-index-search")
            self.assertEqual(docs_index_payload["api_profile"]["gui_binding"], "docs-index-sidecar-search")
            self.assertGreaterEqual(docs_index_payload["summary"]["matched_document_count"], 1)
            self.assertFalse(docs_index_payload["summary"]["stores_full_text"])
            self.assertIn("source_viewer_url", docs_index_payload["results"][0])
            self.assertIn("keyword=password", docs_index_payload["results"][0]["source_search_url"])
            self.assertEqual(docs_index_payload["results"][0]["source"], "docs-index")
            self.assertTrue(docs_index_payload["results"][0]["pointer"].startswith("docs-index://document/"))
            self.assertEqual(
                docs_index_payload["results"][0]["source_viewer_action_profile"]["profile_version"],
                "search-result-source-viewer-actions-v1",
            )
            self.assertEqual(
                docs_index_payload["results"][0]["review_note_citation"]["profile_version"],
                "docs-index-review-note-citation-v1",
            )
            self.assertIn("Docs-index hit:", docs_index_payload["results"][0]["review_note_citation"]["text"])
            self.assertIn("Result hash:", docs_index_payload["results"][0]["review_note_citation"]["text"])
            docs_index_actions = {
                action["id"]: action
                for action in docs_index_payload["results"][0]["source_viewer_action_profile"]["actions"]
            }
            self.assertIn("keyword=password", docs_index_actions["search-inside-source"]["url"])
            self.assertEqual(docs_index_actions["search-inside-source"]["keywords"], ["password"])
            self.assertFalse(docs_index_actions["save-review"]["enabled"])
            self.assertIn(
                "bookmark-source-mapping-required",
                docs_index_payload["results"][0]["source_viewer_action_profile"]["blockers"],
            )
            output_preview_response = client.get(f"/api/runs/{run_id}/outputs/report/preview")
            self.assertEqual(output_preview_response.status_code, 200, output_preview_response.text)
            output_preview = output_preview_response.json()
            self.assertEqual(output_preview["command"], "run-output-preview")
            self.assertEqual(output_preview["output_name"], "report")
            self.assertEqual(output_preview["preview_type"], "text")
            self.assertIn("rapidtriage-run-report", output_preview["path"])
            self.assertIn("/outputs/report/file", output_preview["download_url"])
            self.assertEqual(output_preview["output_preview_profile"]["profile_version"], "run-output-preview-v1")
            self.assertTrue(output_preview["output_preview_profile"]["bounded"])
            self.assertEqual(
                output_preview["output_preview_profile"]["reportability_decision"]["allowed_use"],
                "analyst-output-verification-and-workflow-handoff",
            )
            self.assertEqual(files_response.json()["command"], "files")
            self.assertEqual(timeline_response.json()["command"], "timeline")
            self.assertEqual(indicators_response.json()["command"], "indicators")
            self.assertEqual(indicators_response.json()["pagination"]["collection"], "indicators")
            self.assertGreaterEqual(indicators_response.json()["summary"]["indicator_count"], 1)
            ti_feed_path = Path(tmp_dir) / "local-ti-feed.json"
            ti_feed_path.write_text(
                json.dumps(
                    {
                        "plugin": {"name": "api-local-feed", "version": "2026.05"},
                        "indicators": [
                            {
                                "type": "domain",
                                "value": "download.example",
                                "severity": "medium",
                                "source": "api-fixture",
                                "note": "Known download pivot for API review.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            ti_response = client.get(
                f"/api/runs/{run_id}/indicators/ti-enrichment",
                params={"ti_feed": str(ti_feed_path), "limit": 10},
            )
            self.assertEqual(ti_response.status_code, 200, ti_response.text)
            ti_payload = ti_response.json()
            self.assertEqual(ti_payload["command"], "indicator-ti-enrichment")
            self.assertEqual(ti_payload["profile_version"], "ioc-ti-enrichment-review-package-v1")
            self.assertTrue(ti_payload["local_only"])
            self.assertTrue(ti_payload["no_external_calls"])
            self.assertEqual(ti_payload["summary"]["ti_feed_count"], 1)
            self.assertGreaterEqual(ti_payload["summary"]["matched_indicator_count"], 1)
            self.assertEqual(ti_payload["ti_feed_sources"][0]["name"], "api-local-feed")
            self.assertEqual(ti_payload["ti_feed_sources"][0]["version"], "2026.05")
            self.assertEqual(len(ti_payload["ti_feed_sources"][0]["sha256"]), 64)
            self.assertEqual(ti_payload["core_accuracy_gates"][0]["gap_id"], "#63")
            self.assertIn("offline feed provenance", ti_payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("ioc-ti enrichment manifest", ti_payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(
                ti_payload["ioc_ti_enrichment_manifest_hash"],
                ti_payload["ioc_ti_enrichment_manifest"]["manifest_hash"],
            )
            self.assertGreaterEqual(ti_payload["ioc_ti_enrichment_manifest"]["indicator_row_hash_count"], 1)
            self.assertEqual(
                ti_payload["ti_feed_sources"][0]["ti_feed_manifest_hash"],
                ti_payload["ti_feed_sources"][0]["ti_feed_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                ti_payload["reportability_decision"]["allowed_use"],
                "offline-ioc-ti-triage-pivot",
            )
            self.assertTrue(any(item.get("ti_review_status") == "feed-match-review-required" for item in ti_payload["indicators"]))
            indicator_bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "indicators",
                    "pointer": "/indicators/0",
                    "tag": "ioc",
                    "review_status": "needs-review",
                },
            )
            self.assertEqual(indicator_bookmark_response.status_code, 200, indicator_bookmark_response.text)
            self.assertEqual(
                indicator_bookmark_response.json()["case"]["bookmarks"][0]["reference"]["command"],
                "indicators",
            )
            self.assertEqual(search_response.json()["command"], "search")
            self.assertGreaterEqual(search_response.json()["summary"]["match_count"], 1)
            self.assertEqual(
                search_response.json()["keyword_pack_selection_profile"]["profile_version"],
                "keyword-pack-selection-profile-v1",
            )
            self.assertIn("credentials", search_response.json()["keyword_pack_selection_profile"]["selected_pack_names"])
            self.assertIn("#62", search_response.json()["keyword_pack_selection_profile"]["commercial_gap_ids"])
            selection_manifest = search_response.json()["keyword_pack_selection_profile"]["keyword_pack_selection_manifest"]
            self.assertEqual(selection_manifest["manifest_version"], "keyword-pack-selection-manifest-v1")
            self.assertEqual(
                search_response.json()["keyword_pack_selection_profile"]["keyword_pack_selection_manifest_hash"],
                selection_manifest["manifest_hash"],
            )
            self.assertGreaterEqual(selection_manifest["keyword_row_hash_count"], 1)
            self.assertGreaterEqual(len(selection_manifest["keyword_rows"]), 1)
            self.assertIn(
                "keyword row hashes",
                search_response.json()["keyword_pack_selection_profile"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                search_response.json()["keyword_pack_selection_profile"]["commercial_uplift_evidence"]["item_numbers"],
                [62],
            )
            self.assertEqual(
                search_response.json()["keyword_pack_selection_profile"]["commercial_uplift_evidence"]["large_data_controls"]["keyword_pack_manifest_hash"],
                selection_manifest["manifest_hash"],
            )
            self.assertEqual(search_response.json()["workbench_search_profile"]["item_number"], 16)
            self.assertIn("documents", search_response.json()["workbench_search_profile"]["target_sources"])
            self.assertEqual(
                search_response.json()["workbench_search_profile"]["reportability_decision"]["allowed_use"],
                "case-wide-triage-and-review-routing",
            )
            document_match = next(
                item
                for item in search_response.json()["matches"]
                if item["source"] == "documents" and item["path"].endswith(".txt")
            )
            self.assertIn("metadata", document_match)
            self.assertEqual(document_match["source_verification_profile"]["profile_version"], "unified-search-source-verification-v1")
            self.assertTrue(document_match["source_verification_profile"]["viewer_supported"])
            self.assertEqual(
                search_response.json()["search_result_source_action_profile"]["profile_version"],
                "search-result-source-viewer-actions-summary-v1",
            )
            self.assertEqual(search_response.json()["search_result_source_action_profile"]["qc_prep_item"], 6)
            self.assertGreaterEqual(search_response.json()["search_result_source_action_profile"]["actionable_viewer_count"], 1)
            action_profile = document_match["source_viewer_action_profile"]
            self.assertEqual(action_profile["profile_version"], "search-result-source-viewer-actions-v1")
            self.assertEqual(action_profile["qc_prep_item"], 6)
            self.assertTrue(action_profile["viewer_supported"])
            self.assertEqual(action_profile["review_context"]["source"], "docs")
            self.assertEqual(
                {action["id"] for action in action_profile["actions"]},
                {"open-source-viewer", "open-source-file", "search-inside-source", "pin-compare", "save-review"},
            )
            self.assertIn("/source-preview", next(action["url"] for action in action_profile["actions"] if action["id"] == "open-source-viewer"))
            self.assertEqual(
                search_response.json()["workbench_search_profile"]["source_verification_summary"]["profile_version"],
                "unified-search-source-verification-summary-v1",
            )
            source_response = client.get(f"/api/runs/{run_id}/source-file", params={"path": document_match["path"]})
            self.assertEqual(source_response.status_code, 200)
            self.assertIn("password", source_response.text)
            preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": document_match["path"]})
            self.assertEqual(preview_response.status_code, 200)
            preview_payload = preview_response.json()
            self.assertEqual(preview_payload["preview_type"], "text")
            self.assertIn("password", preview_payload["text"])
            self.assertEqual(preview_payload["viewer_metadata"]["parser_version"], "2")
            self.assertIn("source-search", preview_payload["search_url"])
            self.assertIn("Preview is read-only", preview_payload["viewer_limitations"][0])
            self.assertEqual(
                preview_payload["source_viewer_specialization_profile"]["profile_version"],
                "source-viewer-specialization-v1",
            )
            self.assertEqual(preview_payload["source_viewer_specialization_profile"]["item_number"], 18)
            self.assertEqual(
                preview_payload["source_viewer_specialization_profile"]["viewer_family"],
                "document-text-preview",
            )
            self.assertTrue(
                preview_payload["source_viewer_specialization_profile"]["default_layout"]["metadata_collapsed_by_default"]
            )
            self.assertTrue(
                preview_payload["source_viewer_specialization_profile"]["supported_viewer_features"]["text_preview"]
            )
            self.assertIn(
                "source-search",
                preview_payload["source_viewer_specialization_profile"]["citation_contract"]["search_inside_file_url"],
            )
            self.assertEqual(
                preview_payload["review_evidence_tray_profile"]["profile_version"],
                "review-evidence-tray-profile-v1",
            )
            self.assertEqual(preview_payload["review_evidence_tray_profile"]["item_number"], 19)
            self.assertTrue(preview_payload["review_evidence_tray_profile"]["tray_item_contract"]["include_in_report"])
            self.assertIn("relevant", preview_payload["review_evidence_tray_profile"]["default_review_states"])
            self.assertIn(
                "hash=true",
                preview_payload["review_evidence_tray_profile"]["source_actions"]["hash_source"],
            )
            self.assertIn("#73", preview_payload["viewer_sandbox"]["commercial_gap_ids"])
            self.assertFalse(preview_payload["viewer_sandbox"]["executes_content"])
            self.assertEqual(
                preview_payload["viewer_sandbox"]["preview_sandbox_policy_profile"]["profile_version"],
                "preview-sandbox-policy-profile-v1",
            )
            self.assertEqual(
                preview_payload["viewer_sandbox"]["preview_sandbox_policy_profile"]["renderer_strategy"],
                "escaped-bounded-data-rendering",
            )
            self.assertFalse(preview_payload["viewer_sandbox"]["preview_sandbox_policy_profile"]["external_network_access"])
            source_sandbox_manifest = preview_payload["viewer_sandbox"]["source_preview_sandbox_manifest"]
            self.assertEqual(source_sandbox_manifest["profile_version"], "source-preview-sandbox-manifest-v1")
            self.assertEqual(source_sandbox_manifest["item_number"], 73)
            self.assertRegex(source_sandbox_manifest["source_policy_row"]["row_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(source_sandbox_manifest["row_head_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                preview_payload["viewer_sandbox"]["source_preview_sandbox_manifest_hash"],
                source_sandbox_manifest["manifest_hash"],
            )
            self.assertEqual(preview_payload["viewer_sandbox"]["core_accuracy_gates"][0]["gap_id"], "#73")
            self.assertIn("read-only bounded preview", preview_payload["viewer_sandbox"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "preview sandbox policy profile emitted",
                preview_payload["viewer_sandbox"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "preview policy row hashes emitted",
                preview_payload["viewer_sandbox"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            active_html = root / "Users" / "alice" / "Desktop" / "active.html"
            active_html.write_text("<script>fetch('https://example.invalid')</script>", encoding="utf-8")
            html_preview = build_source_preview("run-1", active_html)
            self.assertTrue(html_preview["viewer_sandbox"]["active_content_blocked"])
            self.assertFalse(html_preview["viewer_sandbox"]["executes_content"])
            self.assertFalse(html_preview["viewer_sandbox"]["external_network_access"])
            self.assertTrue(
                html_preview["viewer_sandbox"]["source_preview_sandbox_manifest"][
                    "active_content_blocking_required"
                ]
            )
            self.assertEqual(preview_payload["viewer_sandbox"]["trusted_preview_sandbox_diff"]["status"], "missing")
            sandbox_diff = build_preview_sandbox_trusted_diff(
                preview_payload["viewer_sandbox"],
                preview_payload["viewer_sandbox"],
            )
            sandbox_gates = preview_sandbox_core_accuracy_gates(
                source_path=Path(document_match["path"]),
                active_content_blocked=preview_payload["viewer_sandbox"]["active_content_blocked"],
                max_chars=preview_payload["viewer_sandbox"]["max_inline_text_chars"],
                policy_profile=preview_payload["viewer_sandbox"]["preview_sandbox_policy_profile"],
                trusted_diff=sandbox_diff,
            )
            self.assertEqual(sandbox_diff["status"], "pass")
            self.assertIn("trusted preview sandbox/no-exec diff pass", sandbox_gates[0]["satisfied_checks"])
            self.assertIn("#51", preview_payload["review_workflow"]["commercial_gap_ids"])
            self.assertIn("#52", preview_payload["compare_workflow"]["commercial_gap_ids"])
            self.assertEqual(preview_payload["analyst_workbench_profile"]["commercial_batch_id"], "commercial-uplift-051-060")
            self.assertEqual(preview_payload["analyst_workbench_profile"]["item_numbers"], list(range(51, 61)))
            self.assertTrue(
                preview_payload["analyst_workbench_profile"]["workflow_contract"]["current_file_search"]["implemented"]
            )
            self.assertEqual(
                preview_payload["analyst_workbench_profile"]["workflow_contract"]["specialized_viewer"]["viewer_family"],
                "document-text-preview",
            )
            self.assertEqual(
                preview_payload["analyst_workbench_profile"]["workflow_contract"]["specialized_viewer"][
                    "specialization_profile"
                ],
                "source-viewer-specialization-v1",
            )
            stage10_matrix = preview_payload["analyst_workbench_profile"]["stage10_capability_matrix"]
            self.assertEqual(stage10_matrix["profile_version"], "stage10-review-viewer-capability-matrix-v1")
            self.assertEqual(stage10_matrix["implemented_count"], 10)
            self.assertEqual(stage10_matrix["capability_count"], 10)
            self.assertEqual(len(preview_payload["analyst_workbench_profile"]["stage10_capability_matrix_hash"]), 64)
            by_item = {entry["item_number"]: entry for entry in stage10_matrix["entries"]}
            self.assertTrue(by_item[51]["implemented"])
            self.assertTrue(by_item[52]["implemented"])
            self.assertTrue(by_item[53]["implemented"])
            self.assertTrue(by_item[54]["implemented"])
            self.assertTrue(by_item[55]["implemented"])
            self.assertTrue(by_item[56]["implemented"])
            self.assertTrue(by_item[57]["implemented"])
            self.assertTrue(by_item[58]["implemented"])
            self.assertTrue(by_item[59]["implemented"])
            self.assertTrue(by_item[60]["implemented"])
            self.assertIn("trusted-duplicate-manifest-required", by_item[60]["commercial_blockers"])
            self.assertEqual(
                stage10_matrix["reportability_decision"]["decision"],
                "do-not-claim-stage10-commercial-grade-without-trusted-viewer-corpora",
            )
            self.assertEqual(preview_payload["review_workflow"]["core_accuracy_gates"][0]["gap_id"], "#51")
            self.assertEqual(preview_payload["compare_workflow"]["core_accuracy_gates"][0]["gap_id"], "#52")
            self.assertEqual(preview_payload["review_workflow"]["commercial_uplift_evidence"]["item_numbers"], [51])
            self.assertIn(
                "review status fields persisted",
                preview_payload["review_workflow"]["commercial_uplift_evidence"]["passed_validation_check_ids"],
            )
            self.assertEqual(
                preview_payload["review_workflow"]["commercial_uplift_evidence"]["reportability_decision"]["allowed_use"],
                "single-user-review-status-triage-pivot",
            )
            self.assertEqual(preview_payload["compare_workflow"]["commercial_uplift_evidence"]["item_numbers"], [52])
            self.assertEqual(
                preview_payload["compare_workflow"]["commercial_uplift_evidence"]["reportability_decision"]["decision"],
                "do-not-report-compare-output-as-semantic-diff-complete",
            )
            self.assertEqual(preview_payload["compare_pin_profile"]["profile_version"], "source-compare-pin-profile-v1")
            self.assertEqual(preview_payload["compare_pin_profile"]["item_number"], 20)
            self.assertEqual(preview_payload["compare_pin_profile"]["max_pinned_items"], 3)
            self.assertIn("bounded-text-diff", preview_payload["compare_pin_profile"]["supported_comparison_modes"])
            self.assertIn(
                "persistent-compare-notes-not-yet-implemented",
                preview_payload["compare_pin_profile"]["commercial_grade_blockers"],
            )
            self.assertEqual(
                {action["id"] for action in preview_payload["viewer_actions"]},
                {"download", "hash", "search-current-file", "pin-compare", "save-review"},
            )
            compare_action = next(action for action in preview_payload["viewer_actions"] if action["id"] == "pin-compare")
            review_action = next(action for action in preview_payload["viewer_actions"] if action["id"] == "save-review")
            self.assertEqual(compare_action["max_pinned_items"], 3)
            self.assertIn("#51", review_action["commercial_gap_ids"])
            metadata_response = client.get(
                f"/api/runs/{run_id}/source-metadata",
                params={"path": document_match["path"], "hash": "true"},
            )
            self.assertEqual(metadata_response.status_code, 200)
            metadata_payload = metadata_response.json()
            self.assertEqual(metadata_payload["command"], "source-metadata")
            self.assertEqual(metadata_payload["hash_status"], "computed")
            self.assertEqual(metadata_payload["hashes"]["sha256"], hash_file(Path(document_match["path"]), "sha256"))
            self.assertIn("#76", metadata_payload["hash_cache_assessment"]["commercial_gap_ids"])
            self.assertEqual(metadata_payload["hash_cache_assessment"]["core_accuracy_gates"][0]["gap_id"], "#76")
            file_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": document_match["path"], "keyword": "password"},
            )
            self.assertEqual(file_search_response.status_code, 200)
            file_search_payload = file_search_response.json()
            self.assertEqual(file_search_payload["command"], "source-search")
            self.assertEqual(file_search_payload["summary"]["match_count"], 1)
            self.assertEqual(file_search_payload["source_search_profile"]["item_number"], 17)
            self.assertEqual(
                file_search_payload["source_search_profile"]["reportability_decision"]["allowed_use"],
                "current-file-verification-pivot",
            )
            self.assertEqual(file_search_payload["matches"][0]["keyword"], "password")
            self.assertEqual(
                file_search_payload["matches"][0]["citation_profile"]["profile_version"],
                "current-file-search-citation-v1",
            )
            self.assertEqual(file_search_payload["matches"][0]["citation_profile"]["locator_type"], "text-line-offset")
            self.assertTrue(file_search_payload["matches"][0]["citation_profile"]["ready_for_review_note"])
            self.assertEqual(
                file_search_payload["matches"][0]["citation_profile"]["report_draft_profile"]["profile_version"],
                "current-file-search-report-draft-profile-v1",
            )
            self.assertEqual(file_search_payload["matches"][0]["citation_profile"]["report_draft_profile"]["qc_prep_item"], 14)
            self.assertTrue(file_search_payload["matches"][0]["citation_profile"]["report_draft_profile"]["ready_for_report_draft"])
            self.assertIn("password", file_search_payload["matches"][0]["snippet"].lower())
            self.assertEqual(len(file_search_payload["matches"][0]["match_id"]), 16)
            self.assertEqual(file_search_payload["matches"][0]["pointer"], "source-search:/matches/0")
            self.assertIn("line", file_search_payload["matches"][0]["citation"])
            self.assertEqual(file_search_payload["matches"][0]["locator"]["keyword"], "password")
            self.assertIn("verify source hashes", file_search_payload["matches"][0]["review_hint"])
            sqlite_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(sqlite_path)})
            self.assertEqual(sqlite_preview_response.status_code, 200, sqlite_preview_response.text)
            sqlite_preview = sqlite_preview_response.json()
            self.assertEqual(sqlite_preview["preview_type"], "sqlite")
            self.assertEqual(sqlite_preview["sqlite"]["tables"][0]["name"], "notes")
            self.assertEqual(sqlite_preview["sqlite"]["tables"][0]["rows"][0]["values"]["body"], "password in sqlite viewer")
            preview_row = sqlite_preview["sqlite"]["tables"][0]["rows"][0]
            self.assertEqual(preview_row["source_viewer_locator"]["profile_version"], "sqlite-row-source-viewer-locator-v1")
            self.assertEqual(preview_row["source_viewer_locator"]["qc_prep_item"], 11)
            self.assertEqual(preview_row["source_viewer_locator"]["viewer"], "source-sqlite-table")
            self.assertEqual(preview_row["source_viewer_locator"]["table"], "notes")
            self.assertEqual(preview_row["source_viewer_locator"]["rowid"], 1)
            self.assertEqual(preview_row["source_viewer_locator"]["primary_key_values"], {"id": 1})
            self.assertTrue(preview_row["source_viewer_locator"]["review_note_ready"])
            self.assertEqual(preview_row["review_note_citation"]["profile_version"], "sqlite-row-review-note-citation-v1")
            self.assertIn("locator=", preview_row["review_note_citation"]["text"])
            self.assertIn("database_metadata", sqlite_preview["sqlite"])
            self.assertTrue(
                any(column["name"] == "body" for column in sqlite_preview["sqlite"]["tables"][0]["column_details"])
            )
            self.assertIn("CREATE TABLE notes", sqlite_preview["sqlite"]["tables"][0]["schema_sql"])
            self.assertIn("schema-sql", sqlite_preview["sqlite"]["review_features"])
            self.assertIn("#54", sqlite_preview["sqlite"]["sqlite_viewer_assessment"]["commercial_gap_ids"])
            self.assertEqual(sqlite_preview["sqlite"]["core_accuracy_gates"][0]["gap_id"], "#54")
            sqlite_uplift = sqlite_preview["sqlite"]["commercial_uplift_evidence"]
            self.assertEqual(sqlite_uplift["item_numbers"], [54])
            self.assertIn("read-only SQLite open", sqlite_uplift["passed_validation_check_ids"])
            self.assertIn("SQLite viewer report-grade validation plan", sqlite_uplift["passed_validation_check_ids"])
            self.assertFalse(sqlite_uplift["large_data_controls"]["deleted_row_recovery"])
            self.assertTrue(sqlite_uplift["large_data_controls"]["table_pagination_api"])
            self.assertTrue(sqlite_uplift["large_data_controls"]["where_builder_api"])
            self.assertTrue(sqlite_uplift["large_data_controls"]["sqlite_viewer_report_grade_validation_plan_present"])
            self.assertEqual(sqlite_uplift["large_data_controls"]["sqlite_viewer_report_grade_ready_slot_count"], 6)
            self.assertEqual(sqlite_uplift["large_data_controls"]["sqlite_viewer_report_grade_blocking_slot_count"], 6)
            self.assertEqual(sqlite_preview["sqlite"]["table_page_profile"]["profile_version"], "sqlite-table-page-profile-v1")
            self.assertTrue(sqlite_preview["sqlite"]["table_page_profile"]["supports_offset_pagination"])
            self.assertFalse(sqlite_preview["sqlite"]["table_page_profile"]["executes_arbitrary_sql"])
            self.assertIn("source-sqlite-table", sqlite_preview["sqlite"]["table_page_profile"]["table_links"][0]["first_page_url"])
            self.assertEqual(
                sqlite_preview["sqlite"]["sqlite_preview_manifest"]["manifest_version"],
                "sqlite-preview-source-manifest-v1",
            )
            self.assertEqual(sqlite_preview["sqlite"]["sqlite_preview_manifest_hash"], sqlite_preview["sqlite"]["sqlite_preview_manifest"]["manifest_hash"])
            self.assertEqual(sqlite_preview["sqlite"]["sqlite_preview_manifest"]["source_viewer_locator"]["viewer"], "source-sqlite")
            self.assertGreaterEqual(sqlite_preview["sqlite"]["sqlite_preview_manifest"]["table_hash_count"], 1)
            self.assertGreaterEqual(sqlite_preview["sqlite"]["sqlite_preview_manifest"]["row_hash_count"], 1)
            sqlite_plan = sqlite_preview["sqlite"]["sqlite_viewer_report_grade_validation_plan"]
            self.assertEqual(sqlite_plan["profile_version"], "sqlite-viewer-report-grade-validation-plan-v1")
            self.assertEqual(sqlite_plan["item_number"], 54)
            self.assertEqual(sqlite_plan["gap_id"], "#54")
            self.assertEqual(sqlite_preview["sqlite"]["sqlite_viewer_report_grade_validation_plan_hash"], sqlite_plan["validation_plan_sha256"])
            self.assertEqual(sqlite_plan["ready_slot_count"], 6)
            self.assertEqual(sqlite_plan["blocking_slot_count"], 6)
            self.assertIn("sqlite-deleted-row-and-wal-recovery-required", sqlite_plan["blockers"])
            manifest_row = sqlite_preview["sqlite"]["sqlite_preview_manifest"]["tables"][0]["row_hashes"][0]
            self.assertEqual(manifest_row["source_viewer_locator"]["profile_version"], "sqlite-row-source-viewer-locator-v1")
            self.assertEqual(manifest_row["review_note_citation"]["qc_prep_item"], 11)
            self.assertIn(
                "SQLite preview source manifest",
                sqlite_preview["sqlite"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("SQLite row hashes", sqlite_preview["sqlite"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "SQLite viewer report-grade validation plan",
                sqlite_preview["sqlite"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                sqlite_uplift["reportability_decision"]["allowed_use"],
                "read-only-sqlite-preview-triage-pivot",
            )
            self.assertIn(
                "deleted-row-and-wal-recovery-not-implemented-in-viewer",
                sqlite_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(sqlite_preview["sqlite"]["trusted_sqlite_viewer_diff"]["status"], "missing")
            self.assertIn(
                "sqlite-viewer-trusted-query-schema-diff-required",
                sqlite_uplift["reportability_decision"]["blockers"],
            )
            self.assertIn("read-only SQLite open", sqlite_preview["sqlite"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("#74", sqlite_preview["sqlite"]["sqlite_fts_optimization_assessment"]["commercial_gap_ids"])
            self.assertIn("#74", sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["commercial_gap_ids"])
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["functional_priority_profile"]["item_number"],
                32,
            )
            self.assertTrue(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["functional_priority_profile"]["controls"]["bounded_row_preview"]
            )
            self.assertEqual(sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["gap_id"], "#74")
            self.assertGreaterEqual(sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["searchable_text_column_count"], 1)
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"]["profile_version"],
                "sqlite-preview-query-plan-profile-v1",
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"]["profile_version"],
                "sqlite-fts-optimization-manifest-v1",
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"]["item_number"],
                32,
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"]["gap_id"],
                "#32",
            )
            self.assertRegex(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"]["plan_hash"],
                r"^[0-9a-f]{64}$",
            )
            self.assertGreaterEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"]["plan_row_hash_count"],
                1,
            )
            self.assertRegex(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"]["plan_row_head_hash"],
                r"^[0-9a-f]{64}$",
            )
            self.assertRegex(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"]["plans"][0]["row_hash"],
                r"^[0-9a-f]{64}$",
            )
            self.assertRegex(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"]["manifest_hash"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"][
                    "query_plan_row_head_hash"
                ],
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"][
                    "plan_row_head_hash"
                ],
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest_hash"],
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["functional_priority_profile"]["controls"]["optimization_manifest_hash"],
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["sqlite_fts_optimization_manifest"]["manifest_hash"],
            )
            self.assertIn(
                "bounded query plan profile emitted",
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "SQLite/FTS optimization manifest hash emitted",
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "query plan row hashes emitted",
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["trusted_large_sqlite_fts_diff"]["status"],
                "missing",
            )
            fts_diff = build_large_sqlite_fts_trusted_diff(
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"],
                sqlite_preview["sqlite"]["large_sqlite_fts_optimization"],
            )
            fts_gates = large_sqlite_fts_core_accuracy_gates(
                database_metadata=sqlite_preview["sqlite"]["database_metadata"],
                previews=sqlite_preview["sqlite"]["tables"],
                searchable_text_column_count=sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["searchable_text_column_count"],
                preview_row_count=sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["preview_row_count"],
                query_plan_profile=sqlite_preview["sqlite"]["large_sqlite_fts_optimization"]["query_plan_profile"],
                trusted_diff=fts_diff,
            )
            self.assertEqual(fts_diff["status"], "pass")
            self.assertIn("trusted large SQLite/FTS query-plan diff pass", fts_gates[0]["satisfied_checks"])
            self.assertEqual(sqlite_preview["sqlite"]["table_profiles"][0]["name"], "notes")
            self.assertGreaterEqual(sqlite_preview["sqlite"]["table_profiles"][0]["searchable_text_column_count"], 1)
            self.assertTrue(any("SQLite previews show bounded" in item for item in sqlite_preview["viewer_limitations"]))
            sqlite_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": str(sqlite_path), "keyword": "password"},
            )
            self.assertEqual(sqlite_search_response.status_code, 200, sqlite_search_response.text)
            sqlite_search = sqlite_search_response.json()
            self.assertEqual(sqlite_search["summary"]["match_count"], 1)
            self.assertEqual(sqlite_search["matches"][0]["table"], "notes")
            self.assertEqual(sqlite_search["matches"][0]["locator"]["table"], "notes")
            self.assertEqual(
                sqlite_search["matches"][0]["source_viewer_locator"]["profile_version"],
                "sqlite-row-source-viewer-locator-v1",
            )
            self.assertEqual(sqlite_search["matches"][0]["source_viewer_locator"]["column"], "body")
            self.assertEqual(sqlite_search["matches"][0]["source_viewer_locator"]["primary_key_values"], {"id": 1})
            self.assertEqual(
                sqlite_search["matches"][0]["citation_profile"]["review_note_citation"]["profile_version"],
                "sqlite-row-review-note-citation-v1",
            )
            self.assertEqual(sqlite_search["matches"][0]["citation_profile"]["qc_prep_item"], 11)
            self.assertIn("table notes", sqlite_search["matches"][0]["citation"])
            sqlite_page_response = client.get(
                f"/api/runs/{run_id}/source-sqlite-table",
                params={
                    "path": str(sqlite_path),
                    "table": "notes",
                    "offset": 0,
                    "limit": 2,
                    "where_column": "body",
                    "where_contains": "password",
                    "order_by": "id",
                },
            )
            self.assertEqual(sqlite_page_response.status_code, 200, sqlite_page_response.text)
            sqlite_page = sqlite_page_response.json()
            self.assertEqual(sqlite_page["command"], "source-sqlite-table")
            self.assertEqual(sqlite_page["profile_version"], "sqlite-table-page-v1")
            self.assertEqual(sqlite_page["table"], "notes")
            self.assertEqual(sqlite_page["pagination"]["returned"], 1)
            self.assertEqual(sqlite_page["where"]["mode"], "contains")
            self.assertFalse(sqlite_page["where"]["arbitrary_sql_allowed"])
            self.assertEqual(
                sqlite_page["sqlite_table_page_manifest"]["manifest_version"],
                "sqlite-table-page-proof-manifest-v1",
            )
            self.assertEqual(sqlite_page["sqlite_table_page_manifest_hash"], sqlite_page["sqlite_table_page_manifest"]["manifest_hash"])
            self.assertEqual(sqlite_page["sqlite_table_page_manifest"]["source_viewer_locator"]["viewer"], "source-sqlite-table")
            self.assertGreaterEqual(sqlite_page["sqlite_table_page_manifest"]["row_hash_count"], 1)
            self.assertEqual(
                sqlite_page["sqlite_viewer_report_grade_validation_plan_hash"],
                sqlite_page["sqlite_viewer_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(sqlite_page["sqlite_viewer_report_grade_validation_plan"]["ready_slot_count"], 6)
            self.assertEqual(sqlite_page["sqlite_viewer_report_grade_validation_plan"]["blocking_slot_count"], 6)
            self.assertEqual(sqlite_page["rows"][0]["source_viewer_locator"]["profile_version"], "sqlite-row-source-viewer-locator-v1")
            self.assertEqual(sqlite_page["rows"][0]["source_viewer_locator"]["query_hash"], sqlite_page["sqlite_table_page_manifest"]["query_hash"])
            self.assertEqual(sqlite_page["rows"][0]["review_note_citation"]["qc_prep_item"], 11)
            self.assertEqual(
                sqlite_page["sqlite_table_page_manifest"]["rows"][0]["source_viewer_locator"]["locator_sha256"],
                sqlite_page["rows"][0]["source_viewer_locator"]["locator_sha256"],
            )
            self.assertIn("SQLite table page proof manifest", sqlite_page["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("SQLite viewer report-grade validation plan", sqlite_page["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("password", sqlite_page["rows"][0]["values"]["body"])
            self.assertIn("sqlite_table=notes", sqlite_page["copy_safe_citation"]["text"])
            json_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(json_path)})
            self.assertEqual(json_preview_response.status_code, 200, json_preview_response.text)
            json_preview = json_preview_response.json()
            self.assertEqual(json_preview["preview_type"], "json")
            self.assertEqual(json_preview["viewer_metadata"]["strategy"], "bounded-json-parse")
            self.assertEqual(json_preview["json"]["summary"]["type"], "object")
            xml_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(xml_path)})
            self.assertEqual(xml_preview_response.status_code, 200, xml_preview_response.text)
            xml_preview = xml_preview_response.json()
            self.assertEqual(xml_preview["preview_type"], "xml")
            self.assertEqual(xml_preview["xml"]["root_tag"], "root")
            self.assertTrue(any(node["tag"] == "event" for node in xml_preview["xml"]["nodes"]))
            eml_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(eml_path)})
            self.assertEqual(eml_preview_response.status_code, 200, eml_preview_response.text)
            eml_preview = eml_preview_response.json()
            self.assertEqual(eml_preview["preview_type"], "email")
            self.assertEqual(eml_preview["email"]["messages"][0]["subject"], "Password review")
            self.assertIn("password email body", eml_preview["email"]["messages"][0]["body_preview"])
            self.assertEqual(eml_preview["email"]["thread_count"], 1)
            self.assertEqual(eml_preview["email"]["threads"][0]["message_count"], 1)
            self.assertEqual(eml_preview["email"]["messages"][0]["attachment_count"], 1)
            self.assertEqual(eml_preview["email"]["messages"][0]["attachments"][0]["filename"], "note.txt")
            self.assertEqual(len(eml_preview["email"]["messages"][0]["attachments"][0]["sha256"]), 64)
            self.assertEqual(
                eml_preview["email"]["attachment_package_profile"]["profile_version"],
                "email-attachment-package-profile-v1",
            )
            self.assertEqual(eml_preview["email"]["attachment_package_profile"]["attachment_count"], 1)
            self.assertIn(
                "source-email-attachment",
                eml_preview["email"]["attachment_package_profile"]["links"][0]["package_url"],
            )
            self.assertEqual(
                eml_preview["email"]["email_conversation_manifest"]["manifest_version"],
                "email-conversation-source-manifest-v1",
            )
            self.assertEqual(
                eml_preview["email"]["email_conversation_manifest_hash"],
                eml_preview["email"]["email_conversation_manifest"]["manifest_hash"],
            )
            email_plan = eml_preview["email"]["email_viewer_report_grade_validation_plan"]
            self.assertEqual(email_plan["profile_version"], "email-viewer-report-grade-validation-plan-v1")
            self.assertEqual(email_plan["item_number"], 55)
            self.assertEqual(email_plan["gap_id"], "#55")
            self.assertEqual(
                eml_preview["email"]["email_viewer_report_grade_validation_plan_hash"],
                email_plan["validation_plan_sha256"],
            )
            self.assertEqual(email_plan["ready_slot_count"], 6)
            self.assertEqual(email_plan["blocking_slot_count"], 6)
            self.assertIn("native-pst-ost-msg-conversation-view-required", email_plan["blockers"])
            self.assertEqual(
                eml_preview["email"]["email_conversation_manifest"]["source_viewer_locator"]["viewer"],
                "source-email-conversation",
            )
            self.assertGreaterEqual(eml_preview["email"]["email_conversation_manifest"]["message_hash_count"], 1)
            self.assertGreaterEqual(eml_preview["email"]["email_conversation_manifest"]["thread_hash_count"], 1)
            self.assertIn("#55", eml_preview["email"]["email_conversation_viewer_assessment"]["commercial_gap_ids"])
            self.assertEqual(eml_preview["email"]["core_accuracy_gates"][0]["gap_id"], "#55")
            self.assertIn(
                "email conversation source manifest",
                eml_preview["email"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn("email message hashes", eml_preview["email"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("email thread hashes", eml_preview["email"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "email viewer report-grade validation plan",
                eml_preview["email"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            eml_uplift = eml_preview["email"]["commercial_uplift_evidence"]
            self.assertEqual(eml_uplift["item_numbers"], [55])
            self.assertIn("thread grouping", eml_uplift["passed_validation_check_ids"])
            self.assertIn("email viewer report-grade validation plan", eml_uplift["passed_validation_check_ids"])
            self.assertFalse(eml_uplift["large_data_controls"]["native_pst_ost_msg"])
            self.assertTrue(eml_uplift["large_data_controls"]["attachment_package_endpoint"])
            self.assertTrue(eml_uplift["large_data_controls"]["email_viewer_report_grade_validation_plan_present"])
            self.assertEqual(eml_uplift["large_data_controls"]["email_viewer_report_grade_ready_slot_count"], 6)
            self.assertEqual(eml_uplift["large_data_controls"]["email_viewer_report_grade_blocking_slot_count"], 6)
            self.assertEqual(
                eml_uplift["reportability_decision"]["decision"],
                "do-not-report-email-preview-as-native-mailbox-thread-complete",
            )
            self.assertIn(
                "native-pst-ost-msg-conversation-view-not-implemented",
                eml_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(eml_preview["email"]["trusted_email_conversation_diff"]["status"], "missing")
            self.assertIn(
                "email-viewer-trusted-thread-export-required",
                eml_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(eml_preview["email"]["conversation_view"]["thread_count"], 1)
            self.assertEqual(
                eml_preview["email"]["conversation_view"]["threads"][0]["message_order"][0]["subject"],
                "Password review",
            )
            attachment_response = client.get(
                f"/api/runs/{run_id}/source-email-attachment",
                params={"path": str(eml_path), "message_index": 1, "attachment_index": 1, "include_content": "true"},
            )
            self.assertEqual(attachment_response.status_code, 200, attachment_response.text)
            attachment_payload = attachment_response.json()
            self.assertEqual(attachment_payload["command"], "source-email-attachment")
            self.assertEqual(attachment_payload["filename"], "note.txt")
            self.assertEqual(attachment_payload["content_status"], "included-base64")
            self.assertEqual(
                attachment_payload["email_attachment_proof_manifest"]["manifest_version"],
                "email-attachment-proof-manifest-v1",
            )
            self.assertEqual(
                attachment_payload["email_attachment_proof_manifest_hash"],
                attachment_payload["email_attachment_proof_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                attachment_payload["email_viewer_report_grade_validation_plan_hash"],
                attachment_payload["email_viewer_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(attachment_payload["email_viewer_report_grade_validation_plan"]["ready_slot_count"], 6)
            self.assertEqual(attachment_payload["email_viewer_report_grade_validation_plan"]["blocking_slot_count"], 6)
            self.assertEqual(
                attachment_payload["email_attachment_proof_manifest"]["source_viewer_locator"]["viewer"],
                "source-email-attachment",
            )
            self.assertIn("sha256", attachment_payload["copy_safe_citation"]["text"])
            self.assertIn("email attachment proof manifest", attachment_payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("email viewer report-grade validation plan", attachment_payload["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(attachment_payload["reportability_decision"]["allowed_use"], "bounded-email-conversation-triage-pivot")
            binary_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(binary_path)})
            self.assertEqual(binary_preview_response.status_code, 200, binary_preview_response.text)
            binary_preview = binary_preview_response.json()
            self.assertEqual(binary_preview["preview_type"], "hex")
            self.assertEqual(binary_preview["hex"]["rows"][0]["offset_hex"], "0x00000000")
            self.assertIn("52 61 70 69 64", binary_preview["hex"]["rows"][0]["hex"])
            self.assertTrue(binary_preview["hex"]["truncated"])
            self.assertEqual(len(binary_preview["hex"]["preview_sha256"]), 64)
            self.assertIn("#53", binary_preview["hex"]["hex_viewer_assessment"]["commercial_gap_ids"])
            self.assertEqual(binary_preview["hex"]["core_accuracy_gates"][0]["gap_id"], "#53")
            hex_uplift = binary_preview["hex"]["commercial_uplift_evidence"]
            self.assertEqual(hex_uplift["item_numbers"], [53])
            self.assertIn("bounded hex rows", hex_uplift["passed_validation_check_ids"])
            self.assertIn("hex viewer report-grade validation plan", hex_uplift["passed_validation_check_ids"])
            self.assertTrue(hex_uplift["large_data_controls"]["export_range_citation"])
            self.assertTrue(hex_uplift["large_data_controls"]["hex_viewer_report_grade_validation_plan_present"])
            self.assertEqual(hex_uplift["large_data_controls"]["hex_viewer_report_grade_ready_slot_count"], 6)
            self.assertEqual(hex_uplift["large_data_controls"]["hex_viewer_report_grade_blocking_slot_count"], 6)
            self.assertEqual(
                hex_uplift["reportability_decision"]["allowed_use"],
                "bounded-hex-preview-triage-pivot",
            )
            self.assertIn(
                "export-range-citation-package-needs-trusted-offset-validation",
                hex_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(binary_preview["hex"]["trusted_hex_viewer_diff"]["status"], "missing")
            self.assertIn(
                "hex-viewer-trusted-offset-manifest-required",
                hex_uplift["reportability_decision"]["blockers"],
            )
            self.assertTrue(binary_preview["hex"]["offset_navigation"]["supports_keyword_byte_hits"])
            self.assertTrue(binary_preview["hex"]["offset_navigation"]["supports_range_citation_export"])
            hex_plan = binary_preview["hex"]["hex_viewer_report_grade_validation_plan"]
            self.assertEqual(hex_plan["profile_version"], "hex-viewer-report-grade-validation-plan-v1")
            self.assertEqual(hex_plan["item_number"], 53)
            self.assertEqual(hex_plan["gap_id"], "#53")
            self.assertEqual(
                binary_preview["hex"]["hex_viewer_report_grade_validation_plan_hash"],
                hex_plan["validation_plan_sha256"],
            )
            self.assertEqual(hex_plan["ready_slot_count"], 6)
            self.assertEqual(hex_plan["blocking_slot_count"], 6)
            self.assertIn("interactive-jump-to-offset-ui-not-implemented", hex_plan["blockers"])
            self.assertEqual(binary_preview["hex"]["range_citation_profile"]["profile_version"], "hex-range-citation-v1")
            self.assertEqual(binary_preview["hex"]["range_citation_profile"]["qc_prep_item"], 12)
            self.assertTrue(binary_preview["hex"]["range_citation_profile"]["supports_report_candidate_payload"])
            self.assertTrue(binary_preview["hex"]["range_citation_profile"]["supports_compare_pin_payload"])
            self.assertEqual(binary_preview["hex"]["range_citation_profile"]["default_offset_hex"], "0x00000000")
            self.assertIn("source-hex-range", binary_preview["hex"]["range_citation_profile"]["default_export_url"])
            self.assertEqual(
                binary_preview["hex"]["hex_preview_manifest"]["manifest_version"],
                "hex-preview-source-locator-manifest-v1",
            )
            self.assertEqual(binary_preview["hex"]["hex_preview_manifest"]["source_viewer_locator"]["viewer"], "source-hex")
            self.assertTrue(binary_preview["hex"]["hex_preview_manifest"]["manifest_hash"])
            self.assertGreaterEqual(binary_preview["hex"]["hex_preview_manifest"]["row_hash_count"], 1)
            self.assertIn(
                "hex preview source locator manifest",
                binary_preview["hex"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "hex viewer report-grade validation plan",
                binary_preview["hex"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            hex_range_response = client.get(
                f"/api/runs/{run_id}/source-hex-range",
                params={"path": str(binary_path), "offset": 2, "length": 12, "include_hashes": "true"},
            )
            self.assertEqual(hex_range_response.status_code, 200, hex_range_response.text)
            hex_range = hex_range_response.json()
            self.assertEqual(hex_range["command"], "source-hex-range")
            self.assertEqual(hex_range["profile_version"], "hex-range-citation-package-v1")
            self.assertEqual(hex_range["qc_prep_item"], 12)
            self.assertEqual(hex_range["offset_hex"], "0x00000002")
            self.assertEqual(hex_range["length_returned"], 12)
            self.assertEqual(len(hex_range["range_hashes"]["sha256"]), 64)
            self.assertEqual(hex_range["source_hash_status"], "computed")
            self.assertEqual(
                hex_range["hex_range_review_link_profile"]["profile_version"],
                "hex-range-review-link-profile-v1",
            )
            self.assertEqual(hex_range["review_note_citation"]["profile_version"], "hex-range-review-note-citation-v1")
            self.assertTrue(hex_range["report_candidate_payload"]["ready_for_report_draft"])
            self.assertEqual(hex_range["compare_pin_payload"]["source"], "hex-range")
            self.assertEqual(hex_range["hex_range_proof_manifest"]["manifest_version"], "hex-range-proof-manifest-v1")
            self.assertEqual(hex_range["hex_range_proof_manifest"]["source_viewer_locator"]["viewer"], "source-hex-range")
            self.assertEqual(hex_range["hex_range_proof_manifest_hash"], hex_range["hex_range_proof_manifest"]["manifest_hash"])
            self.assertEqual(
                hex_range["hex_viewer_report_grade_validation_plan_hash"],
                hex_range["hex_viewer_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(hex_range["hex_viewer_report_grade_validation_plan"]["ready_slot_count"], 6)
            self.assertEqual(hex_range["hex_viewer_report_grade_validation_plan"]["blocking_slot_count"], 6)
            self.assertGreaterEqual(hex_range["hex_range_proof_manifest"]["row_hash_count"], 1)
            self.assertIn("RapidTriage", hex_range["rows"][0]["ascii"])
            self.assertIn("range_sha256", hex_range["copy_safe_citation"]["text"])
            self.assertEqual(hex_range["core_accuracy_gates"][0]["gap_id"], "#53")
            self.assertIn("bounded hex rows", hex_range["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("hex range proof manifest", hex_range["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("hex viewer report-grade validation plan", hex_range["core_accuracy_gates"][0]["satisfied_checks"])
            binary_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": str(binary_path), "keyword": "RapidTriage"},
            )
            self.assertEqual(binary_search_response.status_code, 200, binary_search_response.text)
            binary_search = binary_search_response.json()
            self.assertEqual(binary_search["message"], "Binary/hex byte search completed.")
            self.assertEqual(binary_search["matches"][0]["offset_hex"], "0x00000002")
            self.assertIn("byte offset", binary_search["matches"][0]["citation"])
            image_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(image_path)})
            self.assertEqual(image_preview_response.status_code, 200, image_preview_response.text)
            image_preview = image_preview_response.json()
            self.assertEqual(image_preview["preview_type"], "image")
            self.assertEqual(
                image_preview["review_evidence_tray_profile"]["sidecar_viewer_contract"]["profile_version"],
                "evidence-tray-sidecar-viewer-contract-v1",
            )
            self.assertEqual(image_preview["review_evidence_tray_profile"]["sidecar_viewer_contract"]["qc_prep_item"], 13)
            self.assertGreaterEqual(
                image_preview["review_evidence_tray_profile"]["sidecar_viewer_contract"]["sidecar_link_count"],
                3,
            )
            self.assertTrue(image_preview["review_evidence_tray_profile"]["sidecar_viewer_contract_hash"])
            self.assertEqual(image_preview["image"]["width"], 16)
            self.assertEqual(len(image_preview["image"]["perceptual_hash"]), 16)
            self.assertIn("#56", image_preview["image"]["gallery_review"]["commercial_gap_ids"])
            self.assertIn("#56", image_preview["image"]["gallery_review_assessment"]["commercial_gap_ids"])
            self.assertEqual(image_preview["image"]["core_accuracy_gates"][0]["gap_id"], "#56")
            self.assertEqual(
                image_preview["image"]["image_gallery_manifest"]["manifest_version"],
                "image-gallery-source-manifest-v1",
            )
            self.assertEqual(
                image_preview["image"]["image_gallery_manifest_hash"],
                image_preview["image"]["image_gallery_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                image_preview["image"]["image_gallery_manifest"]["source_viewer_locator"]["viewer"],
                "source-image-gallery",
            )
            self.assertTrue(image_preview["image"]["image_gallery_manifest"]["image_row_hash"])
            image_plan = image_preview["image"]["image_gallery_report_grade_validation_plan"]
            self.assertEqual(image_plan["profile_version"], "image-gallery-report-grade-validation-plan-v1")
            self.assertEqual(image_plan["item_number"], 56)
            self.assertEqual(image_plan["gap_id"], "#56")
            self.assertEqual(
                image_preview["image"]["image_gallery_report_grade_validation_plan_hash"],
                image_plan["validation_plan_sha256"],
            )
            self.assertEqual(image_plan["ready_slot_count"], 6)
            self.assertEqual(image_plan["blocking_slot_count"], 6)
            self.assertIn("ml-visual-similarity-clustering-required", image_plan["blockers"])
            self.assertIn("image gallery source manifest", image_preview["image"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn(
                "image gallery report-grade validation plan",
                image_preview["image"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            image_uplift = image_preview["image"]["commercial_uplift_evidence"]
            self.assertEqual(image_uplift["item_numbers"], [56])
            self.assertIn("perceptual similarity bucket", image_uplift["passed_validation_check_ids"])
            self.assertIn("image gallery report-grade validation plan", image_uplift["passed_validation_check_ids"])
            self.assertFalse(image_uplift["large_data_controls"]["dedicated_virtualized_gallery"])
            self.assertTrue(image_uplift["large_data_controls"]["image_gallery_report_grade_validation_plan_present"])
            self.assertEqual(image_uplift["large_data_controls"]["image_gallery_report_grade_ready_slot_count"], 6)
            self.assertEqual(
                image_uplift["reportability_decision"]["allowed_use"],
                "image-gallery-metadata-triage-pivot",
            )
            self.assertIn("#58", image_preview["image"]["ocr_queue_assessment"]["commercial_gap_ids"])
            self.assertIn("#59", image_preview["image"]["korean_ocr_translation_workflow"]["commercial_gap_ids"])
            self.assertIn("similarity-bucketed", image_preview["image"]["gallery_review"]["tag_suggestions"])
            self.assertEqual(image_preview["image"]["ocr_queue_profile"]["profile_version"], "source-ocr-queue-profile-v1")
            self.assertIn("source-ocr-queue", image_preview["image"]["ocr_queue_profile"]["default_queue_url"])
            self.assertFalse(image_preview["image"]["ocr_queue_profile"]["native_ocr_execution"])
            self.assertEqual(
                image_preview["image"]["korean_ocr_translation_profile"]["profile_version"],
                "source-ocr-translation-profile-v1",
            )
            self.assertIn(
                "source-ocr-translation",
                image_preview["image"]["korean_ocr_translation_profile"]["default_review_url"],
            )
            self.assertTrue(image_preview["image"]["korean_ocr_translation_profile"]["supports_side_by_side_review"])
            self.assertFalse(image_preview["image"]["korean_ocr_translation_profile"]["certified_translation"])
            self.assertEqual(image_preview["image"]["gallery_page_profile"]["profile_version"], "image-gallery-page-profile-v1")
            self.assertTrue(image_preview["image"]["gallery_page_profile"]["supports_folder_gallery_page"])
            self.assertIn("source-image-gallery", image_preview["image"]["gallery_page_profile"]["default_page_url"])
            self.assertTrue(image_uplift["large_data_controls"]["bounded_gallery_page"])
            self.assertEqual(image_preview["image"]["ocr_plan"]["status"], "sidecar-imported")
            self.assertEqual(image_preview["image"]["translation_plan"]["status"], "sidecar-imported")
            self.assertTrue(image_preview["image"]["korean_ocr_translation_workflow"]["korean_detected_or_expected"])
            self.assertIn("translated OCR", image_preview["image"]["translation_sidecar"]["text"])
            image_gallery_response = client.get(
                f"/api/runs/{run_id}/source-image-gallery",
                params={"path": str(image_path), "limit": 10},
            )
            self.assertEqual(image_gallery_response.status_code, 200, image_gallery_response.text)
            image_gallery = image_gallery_response.json()
            self.assertEqual(image_gallery["command"], "source-image-gallery")
            self.assertEqual(image_gallery["profile_version"], "image-gallery-page-v1")
            self.assertGreaterEqual(image_gallery["total"], 2)
            self.assertTrue(any(item["is_anchor"] for item in image_gallery["items"]))
            self.assertTrue(all(len(item["sha256"]) == 64 for item in image_gallery["items"]))
            self.assertEqual(
                image_gallery["image_gallery_page_manifest"]["manifest_version"],
                "image-gallery-page-manifest-v1",
            )
            self.assertEqual(
                image_gallery["image_gallery_page_manifest_hash"],
                image_gallery["image_gallery_page_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                image_gallery["image_gallery_page_manifest"]["source_viewer_locator"]["viewer"],
                "source-image-gallery-page",
            )
            self.assertEqual(
                image_gallery["image_gallery_report_grade_validation_plan_hash"],
                image_gallery["image_gallery_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(image_gallery["image_gallery_report_grade_validation_plan"]["ready_slot_count"], 6)
            self.assertEqual(image_gallery["image_gallery_report_grade_validation_plan"]["blocking_slot_count"], 6)
            self.assertGreaterEqual(image_gallery["image_gallery_page_manifest"]["image_row_hash_count"], 1)
            self.assertIn("image gallery report-grade validation plan", image_gallery["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("keyboard_triage", image_gallery)
            self.assertFalse(image_gallery["large_data_controls"]["persistent_tags"])
            self.assertEqual(image_gallery["large_data_controls"]["image_gallery_report_grade_ready_slot_count"], 6)
            self.assertEqual(image_gallery["reportability_decision"]["allowed_use"], "image-gallery-metadata-triage-pivot")
            ocr_queue_response = client.get(
                f"/api/runs/{run_id}/source-ocr-queue",
                params={"path": str(image_path), "max_items": 10},
            )
            self.assertEqual(ocr_queue_response.status_code, 200, ocr_queue_response.text)
            ocr_queue = ocr_queue_response.json()
            self.assertEqual(ocr_queue["command"], "ocr-queue")
            self.assertEqual(ocr_queue["profile_version"], "source-ocr-queue-page-v1")
            self.assertEqual(ocr_queue["anchor_name"], "screen.png")
            self.assertIn("viewer_context", ocr_queue)
            self.assertFalse(ocr_queue["viewer_context"]["native_ocr_execution"])
            self.assertGreaterEqual(ocr_queue["summary"]["candidate_count"], 2)
            self.assertIn("#58", ocr_queue["summary"]["commercial_gap_ids"])
            self.assertEqual(ocr_queue["ocr_queue_manifest"]["manifest_version"], "ocr-queue-source-manifest-v1")
            self.assertEqual(ocr_queue["ocr_queue_manifest_hash"], ocr_queue["ocr_queue_manifest"]["manifest_hash"])
            self.assertEqual(
                ocr_queue["source_ocr_queue_page_manifest"]["manifest_version"],
                "source-ocr-queue-page-manifest-v1",
            )
            self.assertEqual(
                ocr_queue["source_ocr_queue_page_manifest_hash"],
                ocr_queue["source_ocr_queue_page_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                ocr_queue["source_ocr_queue_page_manifest"]["source_viewer_locator"]["viewer"],
                "source-ocr-queue-page",
            )
            self.assertGreaterEqual(ocr_queue["source_ocr_queue_page_manifest"]["page_row_hash_count"], 1)
            self.assertIn("sidecar_imported", json.dumps(ocr_queue, ensure_ascii=False).replace("-", "_"))
            self.assertIn("anchor_queue_id", ocr_queue["copy_safe_citation"]["text"])
            translation_response = client.get(
                f"/api/runs/{run_id}/source-ocr-translation",
                params={"path": str(image_path), "include_text": "true"},
            )
            self.assertEqual(translation_response.status_code, 200, translation_response.text)
            translation_review = translation_response.json()
            self.assertEqual(translation_review["command"], "source-ocr-translation")
            self.assertEqual(translation_review["profile_version"], "source-ocr-translation-review-v1")
            self.assertTrue(translation_review["summary"]["ocr_sidecar_present"])
            self.assertTrue(translation_review["summary"]["translation_sidecar_present"])
            self.assertTrue(translation_review["summary"]["korean_detected_or_expected"])
            self.assertEqual(translation_review["side_by_side_review"][0]["role"], "ocr-source")
            self.assertIn("이미지 OCR", translation_review["side_by_side_review"][0]["text"])
            self.assertEqual(translation_review["side_by_side_review"][1]["role"], "translation-target")
            self.assertIn("translated OCR", translation_review["side_by_side_review"][1]["text"])
            self.assertEqual(translation_review["core_accuracy_gates"][0]["gap_id"], "#59")
            self.assertIn("translation sidecar import", translation_review["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("OCR/translation review manifest", translation_review["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("side-by-side review row hashes", translation_review["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(
                translation_review["source_ocr_translation_review_manifest"]["manifest_version"],
                "source-ocr-translation-review-manifest-v1",
            )
            self.assertEqual(
                translation_review["source_ocr_translation_review_manifest_hash"],
                translation_review["source_ocr_translation_review_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                translation_review["source_ocr_translation_review_manifest"]["source_viewer_locator"]["viewer"],
                "source-ocr-translation-review",
            )
            self.assertEqual(translation_review["source_ocr_translation_review_manifest"]["review_side_hash_count"], 2)
            self.assertTrue(translation_review["review_profile"]["supports_side_by_side_review"])
            self.assertFalse(translation_review["review_profile"]["certified_translation"])
            self.assertEqual(
                translation_review["reportability_decision"]["control_snapshot"]["review_manifest_hash"],
                translation_review["source_ocr_translation_review_manifest_hash"],
            )
            self.assertIn("ocr_sha256", translation_review["copy_safe_citation"]["text"])
            media_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(media_path)})
            self.assertEqual(media_preview_response.status_code, 200, media_preview_response.text)
            media_preview = media_preview_response.json()
            self.assertEqual(media_preview["preview_type"], "media")
            self.assertEqual(
                media_preview["review_evidence_tray_profile"]["sidecar_viewer_contract"]["sidecar_links"][0]["viewer"],
                "source-media-cue",
            )
            self.assertEqual(len(media_preview["media"]["source_hashes"]["sha256"]), 64)
            self.assertEqual(media_preview["media"]["review"]["transcript_alignment"], "sidecar-cue-based")
            self.assertIn("#57", media_preview["media"]["review"]["commercial_gap_ids"])
            self.assertTrue(media_preview["media"]["review"]["cue_navigation_available"])
            self.assertIn("#57", media_preview["media"]["media_transcript_assessment"]["commercial_gap_ids"])
            self.assertEqual(media_preview["media"]["core_accuracy_gates"][0]["gap_id"], "#57")
            self.assertIn("media transcript source manifest", media_preview["media"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("transcript cue hashes", media_preview["media"]["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertEqual(
                media_preview["media"]["media_transcript_manifest"]["manifest_version"],
                "media-transcript-source-manifest-v1",
            )
            self.assertEqual(
                media_preview["media"]["media_transcript_manifest_hash"],
                media_preview["media"]["media_transcript_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                media_preview["media"]["media_transcript_manifest"]["source_viewer_locator"]["viewer"],
                "source-media-transcript",
            )
            self.assertEqual(media_preview["media"]["media_transcript_manifest"]["cue_hash_count"], 1)
            media_plan = media_preview["media"]["media_transcript_report_grade_validation_plan"]
            self.assertEqual(media_plan["profile_version"], "media-transcript-report-grade-validation-plan-v1")
            self.assertEqual(media_plan["item_number"], 57)
            self.assertEqual(media_plan["gap_id"], "#57")
            self.assertEqual(
                media_preview["media"]["media_transcript_report_grade_validation_plan_hash"],
                media_plan["validation_plan_sha256"],
            )
            self.assertEqual(media_plan["ready_slot_count"], 6)
            self.assertEqual(media_plan["blocking_slot_count"], 6)
            self.assertIn("media-transcript-trusted-cue-diff-required", media_plan["blockers"])
            self.assertEqual(
                len(media_preview["media"]["media_transcript_manifest"]["sidecars"][0]["sidecar_row_hash"]),
                64,
            )
            media_uplift = media_preview["media"]["commercial_uplift_evidence"]
            self.assertEqual(media_uplift["item_numbers"], [57])
            self.assertIn("transcript sidecars imported", media_uplift["passed_validation_check_ids"])
            self.assertIn("media transcript report-grade validation plan", media_uplift["passed_validation_check_ids"])
            self.assertFalse(media_uplift["large_data_controls"]["playback_executed_inline"])
            self.assertEqual(
                media_uplift["large_data_controls"]["media_transcript_manifest_hash"],
                media_preview["media"]["media_transcript_manifest_hash"],
            )
            self.assertTrue(media_uplift["large_data_controls"]["media_transcript_report_grade_validation_plan_present"])
            self.assertEqual(media_uplift["large_data_controls"]["media_transcript_report_grade_ready_slot_count"], 6)
            self.assertEqual(media_uplift["large_data_controls"]["transcript_cue_hash_count"], 1)
            self.assertEqual(media_preview["media"]["trusted_media_transcript_diff"]["status"], "missing")
            self.assertIn(
                "media-transcript-trusted-cue-diff-required",
                media_uplift["reportability_decision"]["blockers"],
            )
            self.assertEqual(
                media_uplift["reportability_decision"]["decision"],
                "do-not-report-media-preview-as-playback-or-asr-validated",
            )
            self.assertEqual(media_preview["media"]["cue_package_profile"]["profile_version"], "media-cue-package-profile-v1")
            self.assertEqual(media_preview["media"]["cue_package_profile"]["cue_count"], 1)
            self.assertIn("source-media-cue", media_preview["media"]["cue_package_profile"]["links"][0]["package_url"])
            self.assertTrue(media_uplift["large_data_controls"]["selected_cue_export"])
            self.assertEqual(media_preview["media"]["media_transcript_assessment"]["cue_count"], 1)
            self.assertEqual(media_preview["media"]["transcript_sidecars"][0]["cues"][0]["start"], "00:00:00,000")
            self.assertEqual(len(media_preview["media"]["transcript_sidecars"][0]["cues"][0]["cue_hash"]), 64)
            self.assertIn("#57", media_preview["media"]["transcript_sidecars"][0]["commercial_gap_ids"])
            self.assertEqual(media_preview["media"]["transcript_sidecars"][0]["cue_count"], 1)
            self.assertEqual(media_preview["media"]["transcript_sidecars"][0]["validation_status"], "sidecar-review-required")
            self.assertEqual(media_preview["media"]["metadata"]["duration_seconds"], 1.0)
            self.assertEqual(media_preview["media"]["transcript_sidecar_count"], 1)
            self.assertIn("password spoken", media_preview["media"]["transcript_sidecars"][0]["preview"])
            media_cue_response = client.get(
                f"/api/runs/{run_id}/source-media-cue",
                params={"path": str(media_path), "sidecar_index": 1, "cue_index": 1, "include_source_hashes": "true"},
            )
            self.assertEqual(media_cue_response.status_code, 200, media_cue_response.text)
            media_cue = media_cue_response.json()
            self.assertEqual(media_cue["command"], "source-media-cue")
            self.assertEqual(media_cue["profile_version"], "media-cue-citation-package-v1")
            self.assertEqual(media_cue["start"], "00:00:00,000")
            self.assertIn("password spoken", media_cue["text"])
            self.assertEqual(len(media_cue["text_sha256"]), 64)
            self.assertEqual(len(media_cue["source_hashes"]["sha256"]), 64)
            self.assertEqual(media_cue["media_cue_proof_manifest"]["manifest_version"], "media-cue-proof-manifest-v1")
            self.assertEqual(
                media_cue["media_cue_proof_manifest_hash"],
                media_cue["media_cue_proof_manifest"]["manifest_hash"],
            )
            self.assertEqual(media_cue["media_cue_proof_manifest"]["source_viewer_locator"]["viewer"], "source-media-cue")
            self.assertEqual(media_cue["media_cue_proof_manifest"]["cue"]["cue_index"], 1)
            self.assertEqual(len(media_cue["media_cue_proof_manifest"]["cue"]["cue_hash"]), 64)
            self.assertEqual(
                media_cue["media_transcript_report_grade_validation_plan_hash"],
                media_cue["media_transcript_report_grade_validation_plan"]["validation_plan_sha256"],
            )
            self.assertEqual(media_cue["media_transcript_report_grade_validation_plan"]["ready_slot_count"], 6)
            self.assertEqual(media_cue["media_transcript_report_grade_validation_plan"]["blocking_slot_count"], 6)
            self.assertIn("media transcript report-grade validation plan", media_cue["core_accuracy_gates"][0]["satisfied_checks"])
            self.assertIn("text_sha256", media_cue["copy_safe_citation"]["text"])
            filtered_search_response = client.get(
                f"/api/runs/{run_id}/search",
                params={
                    "keyword": "password",
                    "ocr": "false",
                    "source": "documents",
                    "extension": ".txt",
                    "path_contains": "case-root",
                },
            )
            self.assertEqual(filtered_search_response.status_code, 200)
            filtered_search_payload = filtered_search_response.json()
            self.assertGreaterEqual(filtered_search_payload["summary"]["match_count"], 1)
            self.assertEqual(filtered_search_payload["options"]["sources"], ["documents"])
            self.assertEqual(filtered_search_payload["options"]["extensions"], [".txt"])
            self.assertTrue(all(item["source"] == "documents" for item in filtered_search_payload["matches"]))
            self.assertTrue(all(Path(item["path"]).suffix == ".txt" for item in filtered_search_payload["matches"]))
            paged_files_response = client.get(f"/api/runs/{run_id}/files", params={"offset": 1, "limit": 2})
            self.assertEqual(paged_files_response.status_code, 200)
            paged_files = paged_files_response.json()
            self.assertEqual(paged_files["pagination"]["collection"], "candidates")
            self.assertEqual(paged_files["pagination"]["offset"], 1)
            self.assertEqual(paged_files["pagination"]["limit"], 2)
            self.assertEqual(len(paged_files["candidates"]), 2)
            self.assertGreaterEqual(paged_files["pagination"]["total"], 2)
            self.assertIn("next_cursor", paged_files["pagination"])
            self.assertEqual(paged_files["pagination"]["pagination_manifest"]["profile"], "pagination-cursor-manifest-v1")
            self.assertEqual(
                paged_files["pagination"]["pagination_manifest"]["profile_version"],
                "pagination-cursor-manifest-v1",
            )
            self.assertEqual(paged_files["pagination"]["pagination_manifest"]["item_number"], 78)
            self.assertRegex(paged_files["pagination"]["pagination_manifest"]["endpoint_id"], r"^[0-9a-f]{64}$")
            self.assertRegex(
                paged_files["pagination"]["pagination_manifest"]["cursor_token_hashes"]["cursor"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                paged_files["pagination"]["cursor_endpoint_coverage_manifest"]["profile"],
                "cursor-api-coverage-manifest-v1",
            )
            self.assertEqual(paged_files["pagination"]["cursor_endpoint_coverage_manifest"]["item_number"], 31)
            self.assertEqual(paged_files["pagination"]["cursor_endpoint_coverage_manifest"]["gap_id"], "#31")
            self.assertEqual(
                paged_files["pagination"]["cursor_endpoint_coverage_manifest"]["pagination_manifest_hash"],
                paged_files["pagination"]["pagination_manifest"]["manifest_hash"],
            )
            self.assertEqual(len(paged_files["pagination"]["cursor_endpoint_coverage_manifest"]["manifest_hash"]), 64)
            self.assertEqual(
                paged_files["pagination"]["page_window_id"],
                paged_files["pagination"]["pagination_manifest"]["page_window_id"],
            )
            self.assertEqual(len(paged_files["pagination"]["pagination_manifest"]["manifest_hash"]), 64)
            self.assertFalse(paged_files["pagination"]["snapshot_policy"]["snapshot_isolated"])
            self.assertIn("#78", paged_files["pagination"]["commercial_gap_ids"])
            self.assertEqual(paged_files["pagination"]["functional_priority_profile"]["item_number"], 31)
            self.assertEqual(paged_files["pagination"]["functional_priority_profile"]["batch_id"], "commercial-uplift-031-035")
            self.assertTrue(paged_files["pagination"]["functional_priority_profile"]["controls"]["cursor_tokens"])
            self.assertFalse(paged_files["pagination"]["functional_priority_profile"]["controls"]["snapshot_isolation"])
            self.assertEqual(
                paged_files["pagination"]["functional_priority_profile"]["controls"]["coverage_manifest_hash"],
                paged_files["pagination"]["cursor_endpoint_coverage_manifest"]["manifest_hash"],
            )
            self.assertIn(
                "case-db-review-candidates",
                paged_files["pagination"]["functional_priority_profile"]["controls"]["missing_endpoint_families"],
            )
            self.assertIn("#78", paged_files["pagination"]["pagination_assessment"]["commercial_gap_ids"])
            self.assertEqual(
                paged_files["pagination"]["pagination_assessment"]["pagination_manifest"]["manifest_hash"],
                paged_files["pagination"]["pagination_manifest"]["manifest_hash"],
            )
            self.assertEqual(
                paged_files["pagination"]["pagination_assessment"]["has_more"],
                paged_files["pagination"]["has_more"],
            )
            self.assertEqual(paged_files["pagination"]["core_accuracy_gates"][0]["gap_id"], "#78")
            self.assertIn(
                "pagination cursor manifest hash emitted",
                paged_files["pagination"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(paged_files["pagination"]["core_accuracy_gates"][1]["gap_id"], "#79")
            self.assertEqual(paged_files["pagination"]["ui_virtualization"]["core_accuracy_gates"][0]["gap_id"], "#79")
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["profile"],
                "ui-virtualization-manifest-v1",
            )
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["profile_version"],
                "ui-virtualization-manifest-v1",
            )
            self.assertEqual(paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["item_number"], 79)
            self.assertTrue(
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["viewport_state_policy"][
                    "keyboard_navigation"
                ]
            )
            self.assertFalse(
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["viewport_state_policy"][
                    "persisted_viewport_restoration"
                ]
            )
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["row_window_id"],
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["row_window_id"],
            )
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["manifest_hash"],
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["manifest_hash"],
            )
            self.assertEqual(len(paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["manifest_hash"]), 64)
            self.assertIn(
                "UI row-window manifest hash emitted",
                paged_files["pagination"]["ui_virtualization"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["functional_priority_profile"]["item_number"],
                25,
            )
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["functional_priority_profile"]["batch_id"],
                "commercial-uplift-021-025",
            )
            self.assertTrue(
                paged_files["pagination"]["ui_virtualization"]["functional_priority_profile"]["controls"]["api_pagination"]
            )
            self.assertIn(
                "browser-e2e-100k-record-run-not-attached",
                paged_files["pagination"]["ui_virtualization"]["functional_priority_profile"]["blockers"],
            )
            self.assertEqual(
                paged_files["pagination"]["pagination_assessment"]["trusted_pagination_diff"]["status"],
                "missing",
            )
            self.assertEqual(
                paged_files["pagination"]["ui_virtualization"]["trusted_ui_virtualization_diff"]["status"],
                "missing",
            )
            pagination_diff = build_pagination_trusted_diff(paged_files["pagination"], paged_files["pagination"])
            pagination_gates = pagination_core_accuracy_gates(
                "candidates",
                total=paged_files["pagination"]["total"],
                returned=paged_files["pagination"]["returned"],
                has_more=paged_files["pagination"]["has_more"],
                trusted_diff=pagination_diff,
            )
            ui_diff = build_ui_virtualization_trusted_diff(
                paged_files["pagination"]["ui_virtualization"],
                paged_files["pagination"]["ui_virtualization"],
            )
            ui_gates = ui_virtualization_core_accuracy_gates(
                label="candidates",
                total=paged_files["pagination"]["ui_virtualization"]["total_rows"],
                visible=paged_files["pagination"]["ui_virtualization"]["visible_rows"],
                api_pagination=True,
                row_window_manifest=paged_files["pagination"]["ui_virtualization"]["row_window_manifest"],
                trusted_diff=ui_diff,
            )
            manual_ui_manifest = build_ui_virtualization_manifest(
                label="candidates",
                total=paged_files["pagination"]["ui_virtualization"]["total_rows"],
                visible=paged_files["pagination"]["ui_virtualization"]["visible_rows"],
                api_pagination=True,
            )
            self.assertEqual(
                manual_ui_manifest["manifest_hash"],
                paged_files["pagination"]["ui_virtualization"]["row_window_manifest"]["manifest_hash"],
            )
            self.assertEqual(pagination_diff["status"], "pass")
            self.assertIn("trusted pagination cursor manifest diff pass", pagination_gates[0]["satisfied_checks"])
            self.assertEqual(ui_diff["status"], "pass")
            self.assertIn("trusted UI virtualization manifest diff pass", ui_gates[0]["satisfied_checks"])
            cursor_files_response = client.get(
                f"/api/runs/{run_id}/files",
                params={"cursor": paged_files["pagination"]["cursor"], "limit": 2},
            )
            self.assertEqual(cursor_files_response.status_code, 200)
            self.assertEqual(cursor_files_response.json()["pagination"]["offset"], 1)
            last_page_offset = max(0, paged_files["pagination"]["total"] - 1)
            last_page_response = client.get(
                f"/api/runs/{run_id}/files",
                params={"offset": last_page_offset, "limit": 1},
            )
            self.assertEqual(last_page_response.status_code, 200)
            last_page = last_page_response.json()
            self.assertFalse(last_page["pagination"]["has_more"])
            self.assertFalse(last_page["pagination"]["pagination_assessment"]["has_more"])
            manual_manifest = build_pagination_cursor_manifest(
                collection_name="candidates",
                offset=last_page_offset,
                limit=1,
                returned=last_page["pagination"]["returned"],
                total=last_page["pagination"]["total"],
                cursor=last_page["pagination"]["cursor"],
                next_cursor=last_page["pagination"]["next_cursor"],
                previous_cursor=last_page["pagination"]["previous_cursor"],
                has_more=False,
            )
            self.assertEqual(manual_manifest["manifest_hash"], last_page["pagination"]["pagination_manifest"]["manifest_hash"])
            paged_docs_response = client.get(f"/api/runs/{run_id}/docs", params={"offset": 0, "limit": 1})
            self.assertEqual(paged_docs_response.status_code, 200)
            paged_docs = paged_docs_response.json()
            self.assertEqual(paged_docs["pagination"]["collection"], "results")
            self.assertLessEqual(len(paged_docs["results"]), 1)
            self.assertIn("candidates", paged_docs["omitted_fields"])
            self.assertTrue((output_dir / "rapidtriage-run-summary.json").is_file())

            persisted = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["mode"], "fraud")

            report_response = client.get(f"/api/runs/{run_id}/report")
            artifacts_response = client.get(f"/api/runs/{run_id}/artifacts")
            paged_artifacts_response = client.get(f"/api/runs/{run_id}/artifacts", params={"offset": 0, "limit": 1})

            self.assertEqual(report_response.status_code, 200)
            self.assertIn("rapidtriage run report", report_response.text)
            self.assertEqual(artifacts_response.status_code, 200)
            self.assertIn("artifacts", artifacts_response.json())
            self.assertEqual(paged_artifacts_response.status_code, 200)
            paged_artifacts = paged_artifacts_response.json()["artifacts"]
            first_artifact_group = next(iter(paged_artifacts.values()))
            self.assertEqual(first_artifact_group["pagination"]["collection"], "artifacts")
            self.assertLessEqual(len(first_artifact_group["artifacts"]), 1)

    def test_viewer_trusted_diffs_control_core_accuracy_gates(self) -> None:
        hex_rows = [{"offset": 0, "offset_hex": "0x00000000", "hex": "52 61 70 69 64", "ascii": "Rapid"}]
        hex_diff = build_hex_viewer_trusted_diff(hex_rows, list(hex_rows), trusted_tool="known-byte-offset-manifest")
        self.assertEqual(hex_diff["status"], "pass")
        hex_gate = hex_viewer_core_accuracy_gates(
            source_path=Path("fixture.bin"),
            rows=hex_rows,
            preview_hashes={"sha256": "preview-hash"},
            truncated=False,
            trusted_diff=hex_diff,
        )[0]
        self.assertIn("trusted hex offset manifest diff pass", hex_gate["satisfied_checks"])

        sqlite_tables = [
            {
                "name": "notes",
                "columns": ["id", "body"],
                "row_count": 1,
                "schema_sql": "CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)",
                "rows": [{"row_number": 1, "values": {"id": 1, "body": "password"}}],
            }
        ]
        sqlite_diff = build_sqlite_viewer_trusted_diff(sqlite_tables, list(sqlite_tables), trusted_tool="sqlite3-cli-oracle")
        self.assertEqual(sqlite_diff["status"], "pass")
        sqlite_gate = sqlite_viewer_core_accuracy_gates(
            source_path=Path("fixture.sqlite"),
            database_metadata={"page_size": 4096, "page_count": 1},
            tables=sqlite_tables,
            trusted_diff=sqlite_diff,
        )[0]
        self.assertIn("trusted sqlite query/schema diff pass", sqlite_gate["satisfied_checks"])

        email_threads = [
            {
                "thread_id": "thread-1",
                "subject": "Password review",
                "message_count": 1,
                "participants": ["alice@example.test", "bob@example.test"],
                "attachment_count": 1,
                "message_order": [{"index": 1, "message_id": "<m1@example.test>"}],
            }
        ]
        email_diff = build_email_conversation_trusted_diff(email_threads, list(email_threads), trusted_tool="mail-client-thread-export")
        self.assertEqual(email_diff["status"], "pass")
        email_gate = email_viewer_core_accuracy_gates(
            source_path=Path("fixture.eml"),
            messages=[{"from": "alice@example.test", "subject": "Password review", "attachment_count": 1}],
            conversation={"threads": email_threads},
            trusted_diff=email_diff,
        )[0]
        self.assertIn("trusted email thread/export diff pass", email_gate["satisfied_checks"])

        mismatch = build_hex_viewer_trusted_diff(
            hex_rows,
            [{**hex_rows[0], "ascii": "Wrong"}],
            trusted_tool="known-byte-offset-manifest",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["blocker_id"], "hex-viewer-trusted-offset-manifest-required")

        sidecars = [
            {
                "path": "/case/audio.wav.srt",
                "sha256": "sidecar-hash",
                "cue_count": 1,
                "preview": "password spoken",
                "cues": [{"start": "00:00:00,000", "end": "00:00:01,000", "text": "password spoken"}],
            }
        ]
        media_diff = build_media_transcript_trusted_diff(sidecars, list(sidecars), trusted_tool="transcript-cue-manifest")
        self.assertEqual(media_diff["status"], "pass")
        media_gate = media_viewer_core_accuracy_gates(
            source_path=Path("/case/audio.wav"),
            metadata={"duration_seconds": 1.0},
            sidecars=sidecars,
            trusted_diff=media_diff,
        )[0]
        self.assertIn("trusted transcript cue/alignment diff pass", media_gate["satisfied_checks"])

    def test_create_run_rejects_detected_image_that_cannot_be_scanned_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "case.ad1"
            source.write_bytes(b"fixture")
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(source),
                    "mode": "fraud",
                    "read_only": True,
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 400)
            self.assertIn("Mount or export the evidence first", response.json()["detail"])

    def test_bookmark_api_writes_run_case_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            run_id = run_response.json()["run_id"]

            bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "files",
                    "pointer": "/candidates/0",
                    "tag": "review",
                    "tags": ["credential", "report"],
                    "note": (
                        "Check this file.\n\n"
                        "Current-file hit: credentials.txt line 3 offset 12 keyword password\n"
                        "Structured citation: SQLite row citation: viewer.sqlite table=notes row=1 rowid=1 locator=abc123\n"
                        "Source locator: abc123\n"
                        "Snippet: admin password found\n"
                        "Review hint: verify source hashes before report inclusion\n\n"
                        "Docs-index hit: docs-index://document/7 path=/evidence/docs/report.txt\n"
                        "Matched terms: password:2, admin:1\n"
                        "Result hash: deadbeef1234\n"
                        "Review hint: open source viewer and current-file source-search before report inclusion"
                    ),
                    "review_status": "relevant",
                    "include_in_report": True,
                },
            )

            self.assertEqual(bookmark_response.status_code, 200, bookmark_response.text)
            indicator_bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "indicators",
                    "pointer": "/indicators/0",
                    "tag": "ioc",
                    "note": "Review this indicator pivot.",
                    "review_status": "needs-review",
                    "include_in_report": False,
                },
            )
            self.assertEqual(indicator_bookmark_response.status_code, 200, indicator_bookmark_response.text)
            case_path = output_dir / "rapidtriage-case.json"
            self.assertTrue(case_path.is_file())

            case_response = client.get(f"/api/runs/{run_id}/case")
            self.assertEqual(case_response.status_code, 200)
            payload = case_response.json()
            self.assertEqual(payload["exists"], True)
            self.assertEqual(payload["case"]["summary"]["bookmark_count"], 2)
            self.assertEqual(payload["case"]["summary"]["report_item_count"], 1)
            self.assertEqual(payload["case"]["summary"]["review_status_counts"]["relevant"], 1)
            self.assertEqual(payload["case"]["summary"]["review_status_counts"]["needs-review"], 1)
            self.assertEqual(payload["case"]["summary"]["review_revision_count"], 2)
            self.assertEqual(payload["case"]["bookmarks"][0]["tags"], ["review", "credential", "report"])
            self.assertEqual(payload["case"]["bookmarks"][0]["review"]["status"], "relevant")
            self.assertEqual(payload["case"]["bookmarks"][0]["review"]["include_in_report"], True)
            self.assertEqual(payload["case"]["bookmarks"][0]["review_history"][0]["action"], "created")

            manifest_response = client.get(f"/api/runs/{run_id}/submission-manifest")
            self.assertEqual(manifest_response.status_code, 200, manifest_response.text)
            manifest = manifest_response.json()
            self.assertEqual(manifest["command"], "submission-manifest")
            validate(
                manifest,
                json.loads((REPO_ROOT / "rapidtriage" / "schemas" / "submission-manifest.schema.json").read_text(encoding="utf-8")),
            )
            self.assertEqual(manifest["summary"]["hashed_item_count"], 1)
            self.assertEqual(manifest["hash_algorithms"], ["md5", "sha1", "sha256"])
            evidence = manifest["items"][0]["evidence"]
            evidence_path = Path(evidence["path"])
            self.assertEqual(evidence["hashes"]["md5"], hash_file(evidence_path, "md5"))
            self.assertEqual(evidence["hashes"]["sha1"], hash_file(evidence_path, "sha1"))
            self.assertEqual(evidence["hashes"]["sha256"], hash_file(evidence_path, "sha256"))
            self.assertTrue((output_dir / "rapidtriage-submission-manifest.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-submission-manifest.audit.json").is_file())

            manifest_file_response = client.get(f"/api/runs/{run_id}/submission-manifest/file")
            self.assertEqual(manifest_file_response.status_code, 200)
            self.assertIn("submission-manifest", manifest_file_response.text)

            report_response = client.post(
                f"/api/runs/{run_id}/case-report",
                json={
                    "template": "technical-appendix",
                    "title": "Incident report",
                    "case_number": "CASE-001",
                    "investigator": "Analyst A",
                    "organization": "Forensic Lab",
                    "requester": "Legal Team",
                    "scope": "Review report-candidate evidence and hashes.",
                    "conclusion": "The listed evidence was reviewed and hashed.",
                },
            )
            self.assertEqual(report_response.status_code, 200, report_response.text)
            report_payload = report_response.json()
            self.assertIn("디지털 포렌식 분석 보고서", report_payload["markdown"])
            self.assertIn("Report template: `technical-appendix`", report_payload["markdown"])
            self.assertIn("Noise policy:", report_payload["markdown"])
            self.assertIn("Technical appendix", report_payload["markdown"])
            self.assertIn("Max extract bytes", report_payload["markdown"])
            self.assertIn("Source path", report_payload["markdown"])
            self.assertIn("IOC/Indicator review pivots", report_payload["markdown"])
            self.assertIn("Review this indicator pivot.", report_payload["markdown"])
            self.assertIn("Source-search cited hits", report_payload["markdown"])
            self.assertIn("credentials.txt line 3 offset 12 keyword password", report_payload["markdown"])
            self.assertIn("Source type: `source-search`", report_payload["markdown"])
            self.assertIn("Structured citation: SQLite row citation", report_payload["markdown"])
            self.assertIn("Source locator: `abc123`", report_payload["markdown"])
            self.assertIn("Snippet: admin password found", report_payload["markdown"])
            self.assertIn("Review hint: verify source hashes before report inclusion", report_payload["markdown"])
            self.assertIn("docs-index://document/7", report_payload["markdown"])
            self.assertIn("Source type: `docs-index`", report_payload["markdown"])
            self.assertIn("Matched terms: password:2, admin:1", report_payload["markdown"])
            self.assertIn("Result hash: `deadbeef1234`", report_payload["markdown"])
            self.assertIn("CASE-001", report_payload["markdown"])
            self.assertIn(evidence["hashes"]["sha256"], report_payload["markdown"])
            self.assertIn("html", report_payload["exports"])
            self.assertIn("docx", report_payload["exports"])
            self.assertIn("pdf", report_payload["exports"])
            self.assertIn("manifest", report_payload["exports"])
            self.assertTrue((output_dir / "rapidtriage-case-report.md").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.html").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.docx").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.pdf").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.exports.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.audit.md").is_file())
            self.assertIn("case-report-docx", (output_dir / "rapidtriage-case-report.audit.md").read_text(encoding="utf-8"))
            self.assertIn("case-report-pdf", (output_dir / "rapidtriage-case-report.audit.md").read_text(encoding="utf-8"))
            export_manifest = json.loads((output_dir / "rapidtriage-case-report.exports.json").read_text(encoding="utf-8"))
            self.assertIn("sha256", export_manifest["files"]["pdf"])
            self.assertEqual(export_manifest["files"]["pdf"]["filename"], "rapidtriage-case-report.pdf")
            with zipfile.ZipFile(output_dir / "rapidtriage-case-report.docx") as report_docx:
                self.assertIn("word/document.xml", report_docx.namelist())
            self.assertEqual((output_dir / "rapidtriage-case-report.pdf").read_bytes()[:5], b"%PDF-")

            report_file_response = client.get(f"/api/runs/{run_id}/case-report/file")
            self.assertEqual(report_file_response.status_code, 200)
            self.assertIn("디지털 포렌식 분석 보고서", report_file_response.text)
            html_report_response = client.get(f"/api/runs/{run_id}/case-report/file/html")
            self.assertEqual(html_report_response.status_code, 200)
            self.assertIn("<h1>디지털 포렌식 분석 보고서</h1>", html_report_response.text)
            docx_report_response = client.get(f"/api/runs/{run_id}/case-report/file/docx")
            self.assertEqual(docx_report_response.status_code, 200)
            self.assertGreater(len(docx_report_response.content), 500)
            pdf_report_response = client.get(f"/api/runs/{run_id}/case-report/file/pdf")
            self.assertEqual(pdf_report_response.status_code, 200)
            self.assertEqual(pdf_report_response.content[:5], b"%PDF-")
            export_manifest_response = client.get(f"/api/runs/{run_id}/case-report/file/manifest")
            self.assertEqual(export_manifest_response.status_code, 200)
            self.assertIn("case-report.exports", export_manifest_response.text)

            bundle_response = client.post(
                f"/api/runs/{run_id}/reviewer-bundle",
                json={"title": "Reviewer handoff", "max_items": 50},
            )
            self.assertEqual(bundle_response.status_code, 200, bundle_response.text)
            bundle_payload = bundle_response.json()
            self.assertEqual(bundle_payload["command"], "bundle")
            self.assertTrue((output_dir / "rapidtriage-reviewer-bundle" / "rapidtriage-reviewer.html").is_file())
            self.assertTrue((output_dir / "rapidtriage-reviewer-bundle.zip").is_file())
            self.assertIn("sha256", bundle_payload["archive_hashes"])
            with zipfile.ZipFile(output_dir / "rapidtriage-reviewer-bundle.zip") as reviewer_zip:
                self.assertIn("rapidtriage-reviewer.html", reviewer_zip.namelist())
                self.assertIn("rapidtriage-selected-evidence.json", reviewer_zip.namelist())
                self.assertIn("rapidtriage-bundle-manifest.json", reviewer_zip.namelist())

            bundle_file_response = client.get(f"/api/runs/{run_id}/reviewer-bundle/file")
            self.assertEqual(bundle_file_response.status_code, 200)
            self.assertEqual(bundle_file_response.content[:2], b"PK")

    def test_run_catalog_persists_and_imports_existing_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            root = tmp_path / "case-root"
            output_dir = tmp_path / "run-out"
            state_path = tmp_path / "state" / "runs.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            store = RunJobStore(state_path=state_path)
            client = TestClient(create_app(store))
            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            run_id = run_response.json()["run_id"]

            restored_client = TestClient(create_app(RunJobStore(state_path=state_path)))
            restored_response = restored_client.get(f"/api/runs/{run_id}")

            self.assertEqual(restored_response.status_code, 200)
            self.assertEqual(restored_response.json()["status"], "completed")
            job_profile = restored_response.json()["job_queue_assessment"]["functional_priority_profile"]
            self.assertEqual(job_profile["batch_id"], "commercial-uplift-026-030")
            self.assertEqual(job_profile["item_number"], 27)
            self.assertEqual(job_profile["component"], "persistent-job-queue")
            self.assertTrue(job_profile["controls"]["state_file_persistence"])
            self.assertEqual(len(job_profile["controls"]["persistence_manifest_hash"]), 64)
            self.assertEqual(len(job_profile["controls"]["execution_manifest_hash"]), 64)
            self.assertRegex(job_profile["controls"]["execution_transition_head_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(job_profile["controls"]["execution_step_head_hash"], r"^[0-9a-f]{64}$")
            self.assertGreaterEqual(job_profile["controls"]["progress_percent"], 0)
            self.assertGreaterEqual(job_profile["controls"]["completed_step_count"], 1)
            self.assertFalse(job_profile["ready_for_commercial_claim"])

            import_response = restored_client.post("/api/runs/import", json={"output_dir": str(output_dir)})
            self.assertEqual(import_response.status_code, 201, import_response.text)
            self.assertEqual(import_response.json()["status"], "completed")
            self.assertEqual(import_response.json()["origin"], "imported")

            output_files_response = restored_client.get(f"/api/runs/{run_id}/output-files")
            self.assertEqual(output_files_response.status_code, 200)
            names = {item["name"] for item in output_files_response.json()["files"]}
            self.assertIn("report", names)
            self.assertIn("summary", names)

            report_download = restored_client.get(f"/api/runs/{run_id}/outputs/report/file")
            self.assertEqual(report_download.status_code, 200)
            self.assertIn("rapidtriage run report", report_download.text)

            delete_response = restored_client.delete(f"/api/runs/{run_id}")
            self.assertEqual(delete_response.status_code, 204)
            self.assertEqual(restored_client.get(f"/api/runs/{run_id}").status_code, 404)

    def test_run_api_passes_file_triage_controls_to_gui_files_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            known_good = root / "known-good-note.txt"
            known_good.write_text("standard operating system help text\n", encoding="utf-8")
            suspicious = root / "suspicious-note.txt"
            suspicious.write_text("needle exfil staging note\n", encoding="utf-8")
            disguised = root / "holiday.jpg"
            disguised.write_bytes(b"MZ\x90\x00not actually a jpeg")
            feed = Path(tmp_dir) / "known-good.csv"
            feed.write_text(hashlib.sha256(known_good.read_bytes()).hexdigest() + "\n", encoding="utf-8")
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "known_good_hash_feeds": [str(feed)],
                    "hide_known_good": True,
                    "known_good_max_hash_bytes": 1024 * 1024,
                    "wait": True,
                },
            )
            self.assertEqual(run_response.status_code, 202, run_response.text)
            run_id = run_response.json()["run_id"]

            files_response = client.get(f"/api/runs/{run_id}/files")
            self.assertEqual(files_response.status_code, 200)
            payload = files_response.json()

        self.assertEqual(payload["filters"]["known_good_hash_feeds"], [str(feed.resolve())])
        self.assertTrue(payload["filters"]["hide_known_good"])
        self.assertEqual(payload["filters"]["known_good_max_hash_bytes"], 1024 * 1024)
        self.assertEqual(payload["summary"]["known_good_suppressed_count"], 1)
        self.assertEqual(payload["known_good_suppressed_candidates"][0]["name"], "known-good-note.txt")
        self.assertNotIn("known-good-note.txt", {item["name"] for item in payload["candidates"]})
        self.assertEqual(payload["summary"]["signature_mismatch_count"], 1)
        self.assertEqual(payload["signature_mismatch_candidates"][0]["name"], "holiday.jpg")

    def test_case_db_api_imports_searches_and_marks_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            db_path = Path(tmp_dir) / "case.db"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            self.assertEqual(run_response.status_code, 202, run_response.text)

            import_response = client.post(
                "/api/case-db/import-run",
                json={
                    "database": str(db_path),
                    "run_output": str(output_dir),
                    "case_id": "CASE-API-DB",
                    "name": "API Case DB",
                },
            )
            self.assertEqual(import_response.status_code, 200, import_response.text)
            self.assertGreaterEqual(import_response.json()["summary"]["indexed_document_count"], 1)

            search_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "save_as": "Password review",
                },
            )
            self.assertEqual(search_response.status_code, 200, search_response.text)
            search_payload = search_response.json()
            self.assertGreaterEqual(search_payload["summary"]["match_count"], 1)
            self.assertEqual(search_payload["saved_search"]["name"], "Password review")
            self.assertIn("#51", search_payload["review_workflow_summary"]["commercial_gap_ids"])
            self.assertEqual(
                search_payload["review_workflow_summary"]["profile_version"],
                "case-search-review-workflow-summary-v1",
            )
            self.assertGreaterEqual(search_payload["review_workflow_summary"]["review_queue_count"], 1)
            self.assertIn(
                "assignment queue metadata emitted",
                search_payload["review_workflow_summary"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            first_page_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "limit": 1,
                },
            )
            self.assertEqual(first_page_response.status_code, 200, first_page_response.text)
            first_page = first_page_response.json()
            self.assertEqual(first_page["summary"]["returned_count"], 1)
            self.assertTrue(first_page["summary"]["has_more"])
            first_manifest = first_page["case_search_result_window_manifest"]
            self.assertEqual(first_manifest["profile_version"], "case-search-result-window-manifest-v1")
            self.assertEqual(first_manifest["cursor"]["offset"], 0)
            self.assertEqual(first_manifest["cursor"]["page_size"], 1)
            self.assertEqual(first_manifest["counts"]["returned_count"], 1)
            self.assertEqual(first_manifest["query_scope_hash"], first_page["summary"]["cursor_api"]["scope_hash"])
            self.assertEqual(
                first_page["summary"]["case_search_result_window_manifest_hash"],
                first_manifest["manifest_hash"],
            )
            self.assertEqual(len(first_manifest["manifest_hash"]), 64)
            self.assertEqual(len(first_manifest["page_window_hash"]), 64)
            self.assertGreaterEqual(len(first_manifest["match_rows"]), 1)
            self.assertEqual(first_manifest["match_rows"][0]["window_position"], 1)
            self.assertEqual(first_manifest["match_rows"][0]["source_viewer_locator"]["viewer"], "case-review-source")
            second_page_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "limit": 1,
                    "cursor": first_page["summary"]["next_cursor"],
                },
            )
            self.assertEqual(second_page_response.status_code, 200, second_page_response.text)
            second_page = second_page_response.json()
            self.assertEqual(second_page["summary"]["cursor_api"]["offset"], 1)
            self.assertEqual(second_page["summary"]["returned_count"], 1)
            second_manifest = second_page["case_search_result_window_manifest"]
            self.assertEqual(second_manifest["cursor"]["offset"], 1)
            self.assertEqual(second_manifest["query_scope_hash"], first_manifest["query_scope_hash"])
            self.assertNotEqual(second_manifest["page_window_hash"], first_manifest["page_window_hash"])
            self.assertEqual(second_manifest["match_rows"][0]["window_position"], 2)
            self.assertNotEqual(
                first_page["matches"][0]["citation_id"],
                second_page["matches"][0]["citation_id"],
            )
            target = search_payload["matches"][0]
            metadata_filter = "fixture_marker=api-roundtrip"

            metadata_search_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "metadata_filters": [metadata_filter],
                    "save_as": "Password metadata review",
                },
            )
            self.assertEqual(metadata_search_response.status_code, 200, metadata_search_response.text)
            metadata_payload = metadata_search_response.json()
            filter_key, filter_value = metadata_filter.split("=", 1)
            self.assertEqual(metadata_payload["options"]["metadata"], {filter_key: filter_value})
            self.assertEqual(metadata_payload["saved_search"]["filters"]["metadata"], {filter_key: filter_value})
            self.assertEqual(metadata_payload["case_search_result_window_manifest"]["filters"]["metadata"], {filter_key: filter_value})
            self.assertTrue(metadata_payload["case_search_result_window_manifest"]["filters"]["post_retrieval_filtering"])

            review_response = client.post(
                "/api/case-db/review",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "target_type": target["target_type"],
                    "target_id": target["target_id"],
                    "status": "relevant",
                    "verification_status": "source_opened",
                    "tags": ["credential"],
                    "note": "Opened in viewer.",
                    "reviewer": "api-test",
                    "assignee": "analyst-a",
                    "priority": "high",
                    "due_at": "2026-04-30T09:00:00+09:00",
                    "include_in_report": True,
                },
            )
            self.assertEqual(review_response.status_code, 200, review_response.text)
            self.assertEqual(review_response.json()["verification_status"], "source_opened")
            self.assertEqual(review_response.json()["assignee"], "analyst-a")
            self.assertEqual(review_response.json()["priority"], "high")
            self.assertEqual(review_response.json()["due_at"], "2026-04-30T09:00:00+09:00")
            self.assertIn("#51", review_response.json()["review_workflow"]["commercial_gap_ids"])

            saved_searches_response = client.post(
                "/api/case-db/saved-searches/list",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                },
            )
            self.assertEqual(saved_searches_response.status_code, 200, saved_searches_response.text)
            saved_by_name = {item["name"]: item for item in saved_searches_response.json()["saved_searches"]}
            self.assertIn("Password review", saved_by_name)
            self.assertIn("Password metadata review", saved_by_name)
            self.assertEqual(saved_by_name["Password metadata review"]["filters"]["metadata"], {filter_key: filter_value})

            batch_response = client.post(
                "/api/case-db/review-batch",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "targets": [
                        {
                            "target_type": target["target_type"],
                            "target_id": target["target_id"],
                        }
                    ],
                    "status": "relevant",
                    "verification_status": "verified",
                    "tags": ["credential", "batch"],
                    "note": "Batch verified.",
                    "reviewer": "api-test",
                    "assignee": "lead-reviewer",
                    "priority": "urgent",
                    "include_in_report": True,
                },
            )
            self.assertEqual(batch_response.status_code, 200, batch_response.text)
            self.assertEqual(batch_response.json()["updated_count"], 1)
            self.assertEqual(batch_response.json()["marks"][0]["assignee"], "lead-reviewer")
            self.assertEqual(batch_response.json()["marks"][0]["priority"], "urgent")
            self.assertTrue(batch_response.json()["marks"][0]["review_workflow"]["assignment_present"])

            export_response = client.post(
                "/api/case-db/report-export",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                },
            )
            self.assertEqual(export_response.status_code, 200, export_response.text)
            export_payload = export_response.json()
            self.assertEqual(export_payload["command"], "case-db-report-export")
            self.assertGreaterEqual(export_payload["summary"]["exported_item_count"], 1)
            self.assertEqual(export_payload["items"][0]["review"]["include_in_report"], True)
            self.assertIn("target_citation_id", export_payload["items"][0])
            self.assertTrue(all(item.get("copy_safe_citation") for item in export_payload["citation_index"]))
            self.assertEqual(
                export_payload["report_citation_manager"]["coverage_profile"]["profile_version"],
                "report-citation-coverage-profile-v1",
            )
            self.assertGreaterEqual(
                export_payload["report_citation_manager"]["coverage_profile"]["citation_count"],
                1,
            )
            self.assertEqual(
                export_payload["evidence_selection_version_history"]["integrity_profile"]["profile_version"],
                "evidence-selection-history-integrity-profile-v1",
            )
            self.assertEqual(
                len(export_payload["evidence_selection_version_history"]["integrity_profile"]["head_hash"]),
                64,
            )

            filtered_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "review_status": "relevant",
                    "verification_status": "verified",
                },
            )
            self.assertEqual(filtered_response.status_code, 200, filtered_response.text)
            filtered_payload = filtered_response.json()
            self.assertGreaterEqual(filtered_payload["summary"]["match_count"], 1)
            self.assertEqual(filtered_payload["matches"][0]["review"]["status"], "relevant")

    def test_run_case_db_ensure_imports_once_for_default_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            db_path = Path(tmp_dir) / "case-default.db"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            self.assertEqual(run_response.status_code, 202, run_response.text)
            run_id = run_response.json()["run_id"]

            first_ensure = client.post(
                f"/api/runs/{run_id}/case-db/ensure",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-DEFAULT-WORKFLOW",
                    "name": "Default Case DB Workflow",
                },
            )
            self.assertEqual(first_ensure.status_code, 200, first_ensure.text)
            first_payload = first_ensure.json()
            self.assertEqual(first_payload["command"], "case-db.ensure-run")
            self.assertEqual(first_payload["case_id"], "CASE-DEFAULT-WORKFLOW")
            self.assertEqual(first_payload["database"], str(db_path.resolve()))
            self.assertEqual(first_payload["imported"], True)
            self.assertGreaterEqual(first_payload["storage"]["summary"]["indexed_document_count"], 1)

            second_ensure = client.post(
                f"/api/runs/{run_id}/case-db/ensure",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-DEFAULT-WORKFLOW",
                },
            )
            self.assertEqual(second_ensure.status_code, 200, second_ensure.text)
            second_payload = second_ensure.json()
            self.assertEqual(second_payload["imported"], False)
            self.assertEqual(
                second_payload["storage"]["summary"]["indexed_document_count"],
                first_payload["storage"]["summary"]["indexed_document_count"],
            )

            search_response = client.post(
                "/api/case-db/search",
                json={
                    "database": second_payload["database"],
                    "case_id": second_payload["case_id"],
                    "keywords": ["password"],
                    "sources": ["documents"],
                },
            )
            self.assertEqual(search_response.status_code, 200, search_response.text)
            self.assertGreaterEqual(search_response.json()["summary"]["match_count"], 1)

    def test_imported_summary_cannot_expose_files_outside_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_dir = tmp_path / "run-out"
            output_dir.mkdir()
            outside_file = tmp_path / "outside.txt"
            outside_file.write_text("do not expose", encoding="utf-8")
            summary_path = output_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "fraud",
                        "root": str(tmp_path / "case-root"),
                        "output_dir": str(output_dir),
                        "input_kind": "folder",
                        "summary": {},
                        "outputs": {
                            "summary": str(summary_path),
                            "report": str(outside_file),
                        },
                    }
                ),
                encoding="utf-8",
            )

            client = TestClient(create_app(RunJobStore()))
            import_response = client.post("/api/runs/import", json={"output_dir": str(output_dir)})
            self.assertEqual(import_response.status_code, 201, import_response.text)
            run_id = import_response.json()["run_id"]

            report_response = client.get(f"/api/runs/{run_id}/outputs/report/file")
            self.assertEqual(report_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
