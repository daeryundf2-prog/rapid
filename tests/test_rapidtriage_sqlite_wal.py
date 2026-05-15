from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.sqlite_wal import SqliteWalPreviewError, build_sqlite_wal_preview


class RapidTriageSqliteWalPreviewTests(unittest.TestCase):
    def test_sqlite_wal_preview_parses_frame_headers_and_hashes_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "browser-history.sqlite"
            db_path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
            wal_path = root / "browser-history.sqlite-wal"
            page_size = 1024
            header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, page_size, 1, 11, 22, 33, 44)
            frame_header = struct.pack(">IIIIII", 5, 9, 11, 22, 55, 66)
            page = bytearray(b"\x00" * page_size)
            page[0] = 0x0D
            page[1:3] = (100).to_bytes(2, "big")
            page[3:5] = (2).to_bytes(2, "big")
            page[5:7] = (900).to_bytes(2, "big")
            page[7] = 1
            page[100:102] = (0).to_bytes(2, "big")
            page[102:104] = (24).to_bytes(2, "big")
            wal_path.write_bytes(header + frame_header + bytes(page))

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out", max_frames=5)

            self.assertTrue(Path(payload["outputs"]["json"]).is_file())
            self.assertTrue(Path(payload["outputs"]["markdown"]).is_file())
            self.assertTrue(Path(payload["safe_copy"]["analysis_database_path"]).is_file())

        self.assertEqual(payload["profile_version"], "sqlite-wal-recovery-mvp-preview-v1")
        self.assertEqual(payload["wal"]["status"], "parsed")
        self.assertEqual(payload["wal"]["header"]["page_size"], 1024)
        self.assertEqual(payload["wal"]["estimated_frame_count"], 1)
        self.assertEqual(payload["wal"]["frames"][0]["page_number"], 5)
        self.assertTrue(payload["wal"]["frames"][0]["is_commit_frame"])
        self.assertTrue(payload["wal"]["frames"][0]["salt_matches_header"])
        self.assertEqual(payload["wal"]["frames"][0]["page_profile"]["page_type"], "leaf-table-btree-page")
        self.assertEqual(payload["wal"]["frames"][0]["page_profile"]["cell_count"], 2)
        freeblock_profile = payload["wal"]["frames"][0]["page_profile"]["freeblock_profile"]
        self.assertEqual(freeblock_profile["freeblock_count"], 1)
        self.assertEqual(freeblock_profile["total_freeblock_bytes"], 24)
        self.assertEqual(freeblock_profile["blocks"][0]["offset"], 100)
        self.assertEqual(payload["recovery_scope"]["freeblock_preview_count"], 1)
        self.assertEqual(payload["safe_copy"]["profile_version"], "sqlite-sidecar-safe-copy-v1")
        self.assertTrue(payload["safe_copy"]["database_copied"])
        self.assertTrue(payload["safe_copy"]["wal_copied"])
        self.assertIn("sqlite-wal-evidence-copy", payload["wal"]["path"])
        self.assertFalse(payload["recovery_scope"]["deleted_row_recovery_attempted"])
        self.assertRegex(payload["manifest_sha256"], r"^[0-9a-f]{64}$")

    def test_sqlite_wal_preview_cli_handles_missing_wal(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["sqlite-wal-preview", "case.db", "--output-dir", "out"])
        self.assertEqual(args.command, "sqlite-wal-preview")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            sqlite3.connect(db_path).close()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["sqlite-wal-preview", str(db_path), "--output-dir", str(root / "out"), "--json"])
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["wal"]["status"], "missing")
        self.assertFalse(payload["recovery_scope"]["wal_detected"])
        self.assertTrue(payload["safe_copy"]["database_copied"])
        self.assertFalse(payload["safe_copy"]["wal_copied"])
        self.assertEqual(payload["schema_profile"]["status"], "parsed")

    def test_sqlite_wal_preview_schema_profile_lists_tables_and_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, url TEXT NOT NULL, deleted INTEGER DEFAULT 0)")
                connection.execute("CREATE INDEX evidence_url_idx ON evidence(url)")
                connection.commit()

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out")

        self.assertEqual(payload["schema_profile"]["status"], "parsed")
        self.assertEqual(payload["schema_profile"]["table_count"], 1)
        table = payload["schema_profile"]["tables"][0]
        self.assertEqual(table["name"], "evidence")
        self.assertEqual([column["name"] for column in table["columns"]], ["id", "url", "deleted"])
        self.assertEqual(payload["schema_profile"]["index_count"], 1)
        self.assertTrue(payload["recovery_scope"]["schema_profile_available"])

    def test_sqlite_wal_preview_safe_copy_records_source_and_copy_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            db_path.write_bytes(b"SQLite format 3\x00" + b"\x01" * 128)
            shm_path = root / "case.db-shm"
            shm_path.write_bytes(b"shared-memory-placeholder")

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out")

        sidecars = {Path(row["source"]["path"]).name: row for row in payload["safe_copy"]["sidecars"]}
        self.assertTrue(sidecars["case.db"]["copied"])
        self.assertTrue(sidecars["case.db"]["copy_matches_source_after"])
        self.assertTrue(sidecars["case.db-shm"]["copied"])
        self.assertFalse(sidecars["case.db-wal"]["copied"])
        self.assertEqual(sidecars["case.db-wal"]["copy"]["sha256"], None)

    def test_sqlite_wal_preview_safe_copy_removes_stale_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            db_path.write_bytes(b"SQLite format 3\x00" + b"\x01" * 128)
            output_dir = root / "out"
            stale_copy_dir = output_dir / "sqlite-wal-evidence-copy"
            stale_copy_dir.mkdir(parents=True)
            stale_wal_copy = stale_copy_dir / "case.db-wal"
            stale_wal_copy.write_bytes(b"stale wal copy")

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=output_dir)

            self.assertFalse(stale_wal_copy.exists())

        self.assertFalse(payload["safe_copy"]["wal_copied"])
        self.assertEqual(payload["wal"]["status"], "missing")

    def test_sqlite_wal_preview_refuses_output_copy_dir_as_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output_dir = root / "out"
            db_path = output_dir / "sqlite-wal-evidence-copy" / "case.db"
            db_path.parent.mkdir(parents=True)
            db_path.write_bytes(b"SQLite format 3\x00" + b"\x01" * 128)

            with self.assertRaisesRegex(SqliteWalPreviewError, "must not contain the source database"):
                build_sqlite_wal_preview(database_path=db_path, output_dir=output_dir)

            self.assertTrue(db_path.exists())

    def test_sqlite_wal_preview_reads_database_header_freelist_trunk(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            page_size = 1024
            data = bytearray(b"\x00" * (page_size * 4))
            data[0:16] = b"SQLite format 3\x00"
            data[16:18] = page_size.to_bytes(2, "big")
            data[18] = 2
            data[19] = 2
            data[28:32] = (4).to_bytes(4, "big")
            data[32:36] = (3).to_bytes(4, "big")
            data[36:40] = (2).to_bytes(4, "big")
            trunk_offset = (3 - 1) * page_size
            data[trunk_offset : trunk_offset + 4] = (0).to_bytes(4, "big")
            data[trunk_offset + 4 : trunk_offset + 8] = (1).to_bytes(4, "big")
            data[trunk_offset + 8 : trunk_offset + 12] = (4).to_bytes(4, "big")
            db_path.write_bytes(bytes(data))

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out")

        self.assertEqual(payload["database_header_profile"]["status"], "parsed")
        self.assertEqual(payload["database_header_profile"]["first_freelist_trunk_page"], 3)
        self.assertEqual(payload["freelist_profile"]["status"], "parsed")
        self.assertEqual(payload["freelist_profile"]["total_freelist_pages"], 2)
        self.assertEqual(payload["freelist_profile"]["trunk_pages"][0]["leaf_pages_preview"], [4])
        self.assertTrue(payload["recovery_scope"]["freelist_profile_available"])

    def test_sqlite_wal_preview_decodes_leaf_table_cell_record_preview(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            db_path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
            wal_path = root / "case.db-wal"
            page_size = 1024
            header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, page_size, 1, 11, 22, 33, 44)
            frame_header = struct.pack(">IIIIII", 2, 2, 11, 22, 55, 66)
            page = bytearray(b"\x00" * page_size)
            cell_offset = 900
            record = bytes([4, 0, 23, 1]) + b"alpha" + bytes([7])
            cell = bytes([len(record), 42]) + record
            page[0] = 0x0D
            page[3:5] = (1).to_bytes(2, "big")
            page[5:7] = cell_offset.to_bytes(2, "big")
            page[8:10] = cell_offset.to_bytes(2, "big")
            page[cell_offset : cell_offset + len(cell)] = cell
            wal_path.write_bytes(header + frame_header + bytes(page))

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out", max_frames=5)

        cell_profile = payload["wal"]["frames"][0]["page_profile"]["cell_profile"]
        self.assertEqual(cell_profile["preview_cell_count"], 1)
        cell = cell_profile["cells"][0]
        self.assertEqual(cell["status"], "parsed")
        self.assertEqual(cell["rowid"], 42)
        record_profile = cell["record_profile"]
        self.assertEqual(record_profile["status"], "parsed")
        self.assertEqual([entry["type"] for entry in record_profile["serial_types"]], ["null", "text", "integer"])
        self.assertEqual(record_profile["values_preview"][1]["text_preview"], "alpha")
        self.assertEqual(record_profile["values_preview"][2]["value"], 7)

    def test_sqlite_wal_preview_maps_decoded_record_values_to_schema_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.execute("PRAGMA page_size = 1024")
                connection.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, url TEXT NOT NULL, visits INTEGER)")
                connection.commit()
            wal_path = root / "case.db-wal"
            page_size = 1024
            header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, page_size, 1, 11, 22, 33, 44)
            frame_header = struct.pack(">IIIIII", 2, 2, 11, 22, 55, 66)
            page = bytearray(b"\x00" * page_size)
            cell_offset = 900
            record = bytes([4, 0, 23, 1]) + b"alpha" + bytes([7])
            cell = bytes([len(record), 42]) + record
            page[0] = 0x0D
            page[3:5] = (1).to_bytes(2, "big")
            page[5:7] = cell_offset.to_bytes(2, "big")
            page[8:10] = cell_offset.to_bytes(2, "big")
            page[cell_offset : cell_offset + len(cell)] = cell
            wal_path.write_bytes(header + frame_header + bytes(page))

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out", max_frames=5)

        self.assertEqual(payload["schema_profile"]["status"], "parsed")
        self.assertEqual(payload["recovery_scope"]["schema_mapped_record_count"], 1)
        mapping = payload["wal"]["frames"][0]["page_profile"]["cell_profile"]["cells"][0]["schema_mapping"]
        self.assertEqual(mapping["status"], "mapped")
        self.assertEqual(mapping["table_name"], "evidence")
        self.assertEqual([column["name"] for column in mapping["columns"]], ["id", "url", "visits"])
        self.assertEqual(mapping["columns"][0]["rowid_alias_value"], 42)
        self.assertEqual(mapping["columns"][1]["value_preview"]["text_preview"], "alpha")
        self.assertEqual(mapping["columns"][2]["value_preview"]["value"], 7)

    def test_sqlite_wal_preview_carves_deleted_record_candidate_from_freeblock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.execute("PRAGMA page_size = 1024")
                connection.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, url TEXT NOT NULL, visits INTEGER)")
                connection.commit()
            wal_path = root / "case.db-wal"
            page_size = 1024
            header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, page_size, 1, 11, 22, 33, 44)
            frame_header = struct.pack(">IIIIII", 2, 2, 11, 22, 55, 66)
            page = bytearray(b"\x00" * page_size)
            freeblock_offset = 100
            candidate_offset = freeblock_offset + 4
            record = bytes([4, 0, 23, 1]) + b"ghost" + bytes([3])
            deleted_cell = bytes([len(record), 77]) + record
            page[0] = 0x0D
            page[1:3] = freeblock_offset.to_bytes(2, "big")
            page[3:5] = (0).to_bytes(2, "big")
            page[5:7] = (900).to_bytes(2, "big")
            page[freeblock_offset : freeblock_offset + 2] = (0).to_bytes(2, "big")
            page[freeblock_offset + 2 : freeblock_offset + 4] = (48).to_bytes(2, "big")
            page[candidate_offset : candidate_offset + len(deleted_cell)] = deleted_cell
            wal_path.write_bytes(header + frame_header + bytes(page))

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out", max_frames=5)

        candidate_profile = payload["wal"]["frames"][0]["page_profile"]["deleted_record_candidate_profile"]
        self.assertEqual(candidate_profile["candidate_count"], 1)
        candidate = candidate_profile["candidates"][0]
        self.assertEqual(candidate["status"], "candidate")
        self.assertEqual(candidate["rowid"], 77)
        self.assertEqual(candidate["record_profile"]["values_preview"][1]["text_preview"], "ghost")
        self.assertEqual(candidate["schema_mapping"]["status"], "mapped")
        self.assertEqual(candidate["schema_mapping"]["columns"][0]["rowid_alias_value"], 77)
        self.assertEqual(candidate["schema_mapping"]["columns"][1]["value_preview"]["text_preview"], "ghost")
        self.assertEqual(payload["recovery_scope"]["deleted_record_candidate_count"], 1)

    def test_sqlite_wal_preview_records_blocked_trusted_tool_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            sqlite3.connect(db_path).close()

            payload = build_sqlite_wal_preview(database_path=db_path, output_dir=root / "out", tool_resolver=lambda _tool: None)

        self.assertEqual(payload["trusted_tool_profile"]["status"], "blocked")
        self.assertFalse(payload["trusted_tool_profile"]["selected_tool"]["available"])
        self.assertFalse(payload["recovery_scope"]["trusted_tool_comparison_ready"])

    def test_sqlite_wal_preview_records_trusted_tool_exports_when_available(self) -> None:
        def fake_runner(command, **_kwargs):
            export_dir = Path(command[command.index("-d") + 1])
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "carved.csv").write_text("table,rowid,url\nevidence,77,ghost\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="trusted ok", stderr="")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, url TEXT)")
                connection.commit()

            payload = build_sqlite_wal_preview(
                database_path=db_path,
                output_dir=root / "out",
                preferred_trusted_tool="sqlite_dissect",
                tool_resolver=lambda tool: f"/usr/bin/{tool}" if tool == "sqlite_dissect" else None,
                command_runner=fake_runner,
            )

        trusted = payload["trusted_tool_profile"]
        self.assertEqual(trusted["status"], "complete")
        self.assertTrue(trusted["summary"]["ready_for_candidate_diff"])
        self.assertEqual(trusted["exports"][0]["name"], "carved.csv")
        self.assertIn("sha256", trusted["exports"][0])
        self.assertEqual(payload["candidate_false_positive_profile"]["status"], "passed-zero-candidates")

    def test_sqlite_wal_preview_semantically_matches_trusted_csv_to_deleted_candidate(self) -> None:
        def fake_runner(command, **_kwargs):
            export_dir = Path(command[command.index("-d") + 1])
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "carved.csv").write_text("table,rowid,url,visits\nevidence,77,ghost,3\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="trusted ok", stderr="")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            db_path = root / "case.db"
            with contextlib.closing(sqlite3.connect(db_path)) as connection:
                connection.execute("PRAGMA page_size = 1024")
                connection.execute("CREATE TABLE evidence(id INTEGER PRIMARY KEY, url TEXT NOT NULL, visits INTEGER)")
                connection.commit()
            wal_path = root / "case.db-wal"
            page_size = 1024
            header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, page_size, 1, 11, 22, 33, 44)
            frame_header = struct.pack(">IIIIII", 2, 2, 11, 22, 55, 66)
            page = bytearray(b"\x00" * page_size)
            freeblock_offset = 100
            candidate_offset = freeblock_offset + 4
            record = bytes([4, 0, 23, 1]) + b"ghost" + bytes([3])
            deleted_cell = bytes([len(record), 77]) + record
            page[0] = 0x0D
            page[1:3] = freeblock_offset.to_bytes(2, "big")
            page[3:5] = (0).to_bytes(2, "big")
            page[5:7] = (900).to_bytes(2, "big")
            page[freeblock_offset : freeblock_offset + 2] = (0).to_bytes(2, "big")
            page[freeblock_offset + 2 : freeblock_offset + 4] = (48).to_bytes(2, "big")
            page[candidate_offset : candidate_offset + len(deleted_cell)] = deleted_cell
            wal_path.write_bytes(header + frame_header + bytes(page))

            payload = build_sqlite_wal_preview(
                database_path=db_path,
                output_dir=root / "out",
                preferred_trusted_tool="sqlite_dissect",
                tool_resolver=lambda tool: f"/usr/bin/{tool}" if tool == "sqlite_dissect" else None,
                command_runner=fake_runner,
            )

        diff = payload["trusted_semantic_diff_profile"]
        self.assertEqual(diff["status"], "matched")
        self.assertEqual(diff["matched_candidate_count"], 1)
        self.assertTrue(diff["matches"][0]["rowid_match"])
        self.assertEqual(diff["matches"][0]["matched_columns"], ["url", "visits"])
        self.assertEqual(payload["recovery_scope"]["trusted_semantic_match_count"], 1)
        self.assertEqual(payload["candidate_false_positive_profile"]["candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()
