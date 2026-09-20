from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows.filesystem import (
    build_native_mft_record,
    build_native_usn_record,
    collect_recycle_bin_artifacts,
)
from rapidtriage.core.carving import run_bounded_carving
from rapidtriage.core.case_db import open_case_database
from rapidtriage.core.files import run_files_scan
from rapidtriage.core.recovery import (
    CANDIDATE_KINDS,
    build_recovery_record,
    count_candidate_kinds,
    is_deleted_candidate_kind,
    is_recovered_candidate_kind,
    normalize_candidate_kind,
    recovery_record_from_payload,
)


class RecoveryModelUnitTests(unittest.TestCase):
    def test_taxonomy_matches_prd_vocabulary(self) -> None:
        self.assertEqual(
            set(CANDIDATE_KINDS),
            {"existing", "deleted-entry", "orphan-record", "carved", "partial-corrupt"},
        )

    def test_build_recovery_record_normalizes_fields(self) -> None:
        record = build_recovery_record(
            "deleted-or-free-key-cell",
            subtype="deleted-or-free-key-cell",
            confidence="MEDIUM",
            validation_status="partial",
            source_offset=4096,
            limitation="requires hbin context",
        )
        self.assertEqual(record["schema"], "candidate-kind-v1")
        self.assertEqual(record["candidate_kind"], "deleted-entry")
        self.assertEqual(record["subtype"], "deleted-or-free-key-cell")
        self.assertEqual(record["confidence"], "medium")
        self.assertEqual(record["validation_status"], "partial")
        self.assertEqual(record["source_offset"], 4096)
        self.assertEqual(record["limitations"], ["requires hbin context"])
        self.assertFalse(record["commercial_claim_allowed"])

    def test_build_recovery_record_defaults_for_unknown_values(self) -> None:
        record = build_recovery_record("not-a-real-kind", confidence="bogus", validation_status="bogus")
        self.assertEqual(record["candidate_kind"], "existing")
        self.assertEqual(record["confidence"], "unknown")
        self.assertEqual(record["validation_status"], "unverified")

    def test_kind_predicates(self) -> None:
        self.assertTrue(is_deleted_candidate_kind("deleted-entry"))
        self.assertTrue(is_deleted_candidate_kind("orphan-record"))
        self.assertTrue(is_deleted_candidate_kind("partial-corrupt"))
        self.assertFalse(is_deleted_candidate_kind("existing"))
        self.assertTrue(is_recovered_candidate_kind("carved"))
        self.assertTrue(is_recovered_candidate_kind("deleted-entry"))
        self.assertFalse(is_recovered_candidate_kind("existing"))

    def test_normalize_candidate_kind_aliases(self) -> None:
        self.assertEqual(normalize_candidate_kind("deleted-or-free-value-cell"), "deleted-entry")
        self.assertEqual(normalize_candidate_kind("recycle-bin-entry"), "deleted-entry")
        self.assertEqual(normalize_candidate_kind("truncated"), "partial-corrupt")
        self.assertEqual(normalize_candidate_kind(None), "existing")

    def test_recovery_record_from_payload_defaults_missing(self) -> None:
        self.assertEqual(recovery_record_from_payload({})["candidate_kind"], "existing")
        row = {"recovery": {"candidate_kind": "deleted-or-free-key-cell"}}
        self.assertEqual(recovery_record_from_payload(row)["candidate_kind"], "deleted-entry")

    def test_count_candidate_kinds(self) -> None:
        rows = [
            {"recovery": build_recovery_record("existing")},
            {"recovery": build_recovery_record("carved")},
            {"recovery": build_recovery_record("carved")},
            {},
        ]
        counts = count_candidate_kinds(rows)
        self.assertEqual(counts["existing"], 2)
        self.assertEqual(counts["carved"], 2)


class FilesScanRecoveryTests(unittest.TestCase):
    def test_files_candidates_carry_existing_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "report.txt").write_text("hello", encoding="utf-8")

            payload = run_files_scan(root, categories=["documents"])

            candidates = payload["candidates"]
            self.assertEqual(len(candidates), 1)
            recovery = candidates[0]["recovery"]
            self.assertEqual(recovery["schema"], "candidate-kind-v1")
            self.assertEqual(recovery["candidate_kind"], "existing")
            self.assertEqual(recovery["deletion_state"], "allocated")
            self.assertEqual(recovery["confidence"], "high")
            self.assertEqual(recovery["source_path"], candidates[0]["path"])
            self.assertEqual(payload["summary"]["candidate_kind_counts"], {"existing": 1})

    def test_files_scan_does_not_mark_deleted_by_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "deleted-notes.txt").write_text("data", encoding="utf-8")

            payload = run_files_scan(root, categories=["documents"])

            recovery = payload["candidates"][0]["recovery"]
            self.assertEqual(recovery["candidate_kind"], "existing")
            self.assertEqual(recovery["deletion_state"], "allocated")


class CarvingRecoveryTests(unittest.TestCase):
    def test_footer_validated_candidate_is_carved_high_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            (root / "unallocated.bin").write_bytes(b"noise%PDF-1.7\nbody%%EOFtail")

            payload = run_bounded_carving(root, Path(tmp_dir) / "carve")

            entry = payload["entries"][0]
            recovery = entry["recovery"]
            self.assertEqual(recovery["candidate_kind"], "carved")
            self.assertEqual(recovery["confidence"], "high")
            self.assertEqual(recovery["validation_status"], "validated")
            self.assertEqual(recovery["boundary_method"], "signature-footer")
            self.assertEqual(recovery["signature_type"], "pdf")
            self.assertEqual(recovery["source_offset"], entry["offset"])
            self.assertEqual(payload["summary"]["candidate_kind_counts"], {"carved": 1})

    def test_missing_footer_is_partial_corrupt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            (root / "slack.bin").write_bytes(b"\xff\xd8\xff\xe0truncated-image-without-eoi")

            payload = run_bounded_carving(root, Path(tmp_dir) / "carve")

            recovery = payload["entries"][0]["recovery"]
            self.assertEqual(recovery["candidate_kind"], "partial-corrupt")
            self.assertEqual(recovery["confidence"], "low")
            self.assertEqual(recovery["validation_status"], "partial")
            self.assertTrue(recovery["limitations"])

    def test_header_only_signature_is_low_confidence_carved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            root.mkdir()
            (root / "frag.bin").write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00zip-fragment")

            payload = run_bounded_carving(root, Path(tmp_dir) / "carve")

            recovery = payload["entries"][0]["recovery"]
            self.assertEqual(recovery["candidate_kind"], "carved")
            self.assertEqual(recovery["confidence"], "low")
            self.assertEqual(recovery["boundary_method"], "header-only-bounded")


class FilesystemRecoveryTests(unittest.TestCase):
    def _write_recycle_bin(self, root: Path, *, with_payload: bool) -> Path:
        recycle_dir = root / "$Recycle.Bin" / "S-1-5-21-test"
        recycle_dir.mkdir(parents=True)
        i_file = recycle_dir / "$IABCDEF.txt"
        blob = (2).to_bytes(8, "little") + (100).to_bytes(8, "little") + (0).to_bytes(8, "little") + b"X" * 8
        i_file.write_bytes(blob)
        if with_payload:
            (recycle_dir / "$RABCDEF.txt").write_bytes(b"payload")
        return i_file

    def test_recycle_bin_entry_is_deleted_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            self._write_recycle_bin(root, with_payload=True)

            records = list(collect_recycle_bin_artifacts(root))

            self.assertEqual(len(records), 1)
            recovery = records[0].details["recovery"]
            self.assertEqual(recovery["candidate_kind"], "deleted-entry")
            self.assertEqual(recovery["deletion_state"], "recycled")
            self.assertEqual(recovery["confidence"], "high")
            self.assertEqual(recovery["source_record_id"], "ABCDEF.txt")

    def test_recycle_bin_without_payload_notes_limitation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            self._write_recycle_bin(root, with_payload=False)

            records = list(collect_recycle_bin_artifacts(root))

            recovery = records[0].details["recovery"]
            self.assertEqual(recovery["candidate_kind"], "deleted-entry")
            self.assertTrue(any("$R" in item for item in recovery["limitations"]))

    def test_mft_not_in_use_is_deleted_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            mft = Path(tmp_dir) / "$MFT"
            mft.write_bytes(b"\x00" * 64)
            record = {
                "record_number_candidate": 42,
                "record_offset": 43008,
                "in_use": False,
                "path_candidates": ["Users/a/deleted.txt"],
            }

            artifact = build_native_mft_record(mft, record, 0)

            recovery = artifact.details["recovery"]
            self.assertEqual(recovery["candidate_kind"], "deleted-entry")
            self.assertEqual(recovery["deletion_state"], "mft-record-not-in-use")
            self.assertEqual(recovery["source_record_id"], "42")
            self.assertEqual(recovery["source_offset"], 43008)

    def test_mft_in_use_without_path_is_orphan_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            mft = Path(tmp_dir) / "$MFT"
            mft.write_bytes(b"\x00" * 64)
            record = {"record_number_candidate": 7, "in_use": True, "path_candidates": []}

            artifact = build_native_mft_record(mft, record, 0)

            recovery = artifact.details["recovery"]
            self.assertEqual(recovery["candidate_kind"], "orphan-record")
            self.assertEqual(recovery["deletion_state"], "mft-parent-unresolved")

    def test_mft_in_use_with_path_is_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            mft = Path(tmp_dir) / "$MFT"
            mft.write_bytes(b"\x00" * 64)
            record = {"record_number_candidate": 5, "in_use": True, "path_candidates": ["Windows/a.txt"]}

            artifact = build_native_mft_record(mft, record, 0)

            self.assertEqual(artifact.details["recovery"]["candidate_kind"], "existing")

    def test_usn_delete_event_is_deleted_entry_with_limitation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            journal = Path(tmp_dir) / "$UsnJrnl"
            journal.write_bytes(b"\x00" * 64)
            record = {
                "file_reference_number": 99,
                "record_offset": 512,
                "deleted_hint": True,
                "file_name": "gone.txt",
            }

            artifact = build_native_usn_record(journal, record, 0)

            recovery = artifact.details["recovery"]
            self.assertEqual(recovery["candidate_kind"], "deleted-entry")
            self.assertEqual(recovery["deletion_state"], "journal-observed-delete")
            self.assertTrue(any("not establish" in item for item in recovery["limitations"]))


class CaseDbRecoveryImportTests(unittest.TestCase):
    def _import_files_payload(self, tmp_dir: str, candidates: list[dict[str, object]]) -> dict[str, object] | None:
        root = Path(tmp_dir)
        files_path = root / "rapidtriage-files.json"
        files_path.write_text(json.dumps({"command": "files", "candidates": candidates}), encoding="utf-8")
        database = open_case_database(root / "case.db")
        database.import_run_output(
            {"outputs": {"files": str(files_path)}, "source": {"source_path": str(root)}},
            case_id="CASE-RECOVERY",
        )
        connection = sqlite3.connect(root / "case.db")
        try:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM file_record WHERE case_id = 'CASE-RECOVERY'").fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()

    def test_import_marks_deleted_from_recovery_block_not_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence = Path(tmp_dir) / "deleted-notes.txt"
            evidence.write_text("data", encoding="utf-8")
            row = self._import_files_payload(
                tmp_dir,
                [
                    {
                        "path": str(evidence),
                        "extension": ".txt",
                        "size": 4,
                        "modified_at": "2026-01-01T00:00:00",
                        "recovery": build_recovery_record("existing", deletion_state="allocated"),
                    }
                ],
            )
            self.assertIsNotNone(row)
            self.assertEqual(row["is_deleted"], 0)
            self.assertEqual(row["is_recovered"], 0)

    def test_import_records_carved_kind_and_source_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence = Path(tmp_dir) / "carved.jpg"
            evidence.write_bytes(b"\xff\xd8\xff\xe0data\xff\xd9")
            row = self._import_files_payload(
                tmp_dir,
                [
                    {
                        "path": str(evidence),
                        "extension": ".jpg",
                        "size": 10,
                        "modified_at": "2026-01-01T00:00:00",
                        "recovery": build_recovery_record("carved", source_offset=8192),
                    }
                ],
            )
            self.assertIsNotNone(row)
            self.assertEqual(row["is_deleted"], 0)
            self.assertEqual(row["is_recovered"], 1)
            self.assertEqual(row["source_offset"], 8192)

    def test_import_legacy_row_without_recovery_defaults_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence = Path(tmp_dir) / "file.txt"
            evidence.write_text("data", encoding="utf-8")
            row = self._import_files_payload(
                tmp_dir,
                [{"path": str(evidence), "extension": ".txt", "size": 4, "modified_at": "2026-01-01T00:00:00"}],
            )
            self.assertIsNotNone(row)
            self.assertEqual(row["is_deleted"], 0)


if __name__ == "__main__":
    unittest.main()
