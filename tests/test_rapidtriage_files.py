from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.files import (
    build_duplicate_content_manifest,
    build_duplicate_content_trusted_diff,
    duplicate_content_core_accuracy_gates,
    duplicate_detection_assessment,
)
from rapidtriage.core.hash_cache import (
    build_hash_cache_manifest,
    build_hash_cache_trusted_diff,
    compute_hashes_cached,
    export_hash_cache_snapshot,
    hash_cache_assessment,
    import_hash_cache_snapshot,
    reset_hash_cache,
)


def candidate_categories(candidate: dict[str, object]) -> list[str]:
    if "categories" in candidate:
        return list(candidate["categories"])
    category = candidate.get("category")
    return [category] if category else []


class RapidTriageFilesTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_hash_cache()

    def test_files_command_scans_default_categories_and_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "notes.txt").write_text("incident notes", encoding="utf-8")
            with zipfile.ZipFile(root / "bundle.zip", "w") as archive:
                archive.writestr("evidence.txt", "archive payload")
            (root / "records.sqlite").write_text("SQLite format 3", encoding="utf-8")
            (root / "tool.exe").write_bytes(b"MZ\x90\x00")
            (root / "mailbox.pst").write_bytes(b"email archive")
            (root / "case.E01").write_bytes(b"EVF")
            (root / "phone.ufdx").write_bytes(b"cellebrite mobile image")
            (root / "memory.vmem").write_bytes(b"memory dump")
            (root / "route.ivo").write_bytes(b"vehicle export")
            (root / "split.7z001").write_bytes(b"segmented archive")
            (root / "photo.jpg").write_bytes(b"\xff\xd8\xff")
            output = root / "files.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["command"], "files")
            self.assertEqual(Path(payload["root"]), root.resolve())
            self.assertEqual(payload["summary"]["candidate_count"], 11)
            self.assertIn("duplicate_group_count", payload["summary"])
            self.assertIn("duplicate_content_groups", payload)
            self.assertIn("#76", payload["summary"]["commercial_gap_ids"])
            self.assertIn("#77", payload["summary"]["commercial_gap_ids"])
            self.assertEqual(payload["hash_cache_manifest"]["profile"], "hash-cache-manifest-v1")
            self.assertEqual(payload["hash_cache_manifest"]["profile_version"], "hash-cache-manifest-v1")
            self.assertIn("manifest_hash", payload["hash_cache_manifest"])
            self.assertIn("cache_session_id", payload["hash_cache_manifest"])
            self.assertIn("entries_head_hash", payload["hash_cache_manifest"])
            self.assertIn("events_head_hash", payload["hash_cache_manifest"])
            self.assertEqual(payload["hash_cache_manifest"]["policy"]["scope"], "process-local-with-explicit-snapshot")
            self.assertTrue(payload["hash_cache_manifest"]["policy"]["persistent_across_restarts"])
            self.assertEqual(
                payload["hash_cache_manifest"]["persistence_manifest"]["profile_version"],
                "hash-cache-persistence-manifest-v1",
            )
            self.assertRegex(payload["hash_cache_manifest"]["persistence_manifest_hash"], r"^[0-9a-f]{64}$")
            self.assertTrue(payload["hash_cache_manifest"]["policy"]["export_import_contract_declared"])
            self.assertIn("#76", payload["hash_cache_assessment"]["commercial_gap_ids"])
            self.assertIn("#77", payload["duplicate_detection_assessment"]["commercial_gap_ids"])
            self.assertEqual(payload["hash_cache_assessment"]["core_accuracy_gates"][0]["gap_id"], "#76")
            self.assertIn(
                "hash-cache manifest hash emitted",
                payload["hash_cache_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertEqual(payload["hash_cache_assessment"]["trusted_hash_cache_diff"]["status"], "missing")
            self.assertIn(
                "trusted-hash-cache-manifest-diff-missing",
                payload["hash_cache_assessment"]["blockers"],
            )
            self.assertEqual(payload["duplicate_detection_assessment"]["core_accuracy_gates"][0]["gap_id"], "#77")
            self.assertEqual(
                payload["duplicate_detection_assessment"]["trusted_duplicate_content_diff"]["status"],
                "missing",
            )
            self.assertIn(
                "trusted-duplicate-file-manifest-diff-missing",
                payload["duplicate_detection_assessment"]["blockers"],
            )
            self.assertEqual({gate["gap_id"] for gate in payload["core_accuracy_gates"]}, {"#76", "#77"})
            category_counts = payload["summary"]["category_counts"]
            self.assertGreaterEqual(category_counts["documents"], 1)
            self.assertGreaterEqual(category_counts["archives"], 1)
            self.assertGreaterEqual(category_counts["databases"], 1)
            self.assertGreaterEqual(category_counts["executables"], 1)
            self.assertGreaterEqual(category_counts["emails"], 1)
            self.assertGreaterEqual(category_counts["disk-images"], 1)
            self.assertGreaterEqual(category_counts["mobile-images"], 1)
            self.assertGreaterEqual(category_counts["memory-dumps"], 1)
            self.assertGreaterEqual(category_counts["vehicle-images"], 1)
            self.assertGreaterEqual(category_counts["images"], 1)

            candidates = {Path(item["path"]).name: item for item in payload["candidates"]}
            self.assertEqual(
                set(candidates),
                {
                    "notes.txt",
                    "bundle.zip",
                    "records.sqlite",
                    "tool.exe",
                    "mailbox.pst",
                    "case.E01",
                    "phone.ufdx",
                    "memory.vmem",
                    "route.ivo",
                    "split.7z001",
                    "photo.jpg",
                },
            )
            self.assertIn("documents", candidate_categories(candidates["notes.txt"]))
            self.assertIn("archives", candidate_categories(candidates["bundle.zip"]))
            self.assertIn("databases", candidate_categories(candidates["records.sqlite"]))
            self.assertIn("executables", candidate_categories(candidates["tool.exe"]))
            self.assertIn("emails", candidate_categories(candidates["mailbox.pst"]))
            self.assertIn("disk-images", candidate_categories(candidates["case.E01"]))
            self.assertIn("mobile-images", candidate_categories(candidates["phone.ufdx"]))
            self.assertIn("memory-dumps", candidate_categories(candidates["memory.vmem"]))
            self.assertIn("vehicle-images", candidate_categories(candidates["route.ivo"]))
            self.assertIn("archives", candidate_categories(candidates["split.7z001"]))
            self.assertIn("images", candidate_categories(candidates["photo.jpg"]))

            for name, candidate in candidates.items():
                self.assertEqual(candidate["name"], name)
                self.assertTrue(candidate["path"].startswith(str(root.resolve())))
                self.assertIn("modified_at", candidate)
                self.assertIn("size", candidate)
                self.assertIn("extension", candidate)

    def test_files_command_records_nested_paths_and_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            nested = root / "Users" / "alice" / "Desktop"
            nested.mkdir(parents=True)
            candidate_path = nested / "report.docx"
            candidate_path.write_text("placeholder", encoding="utf-8")
            mtime = datetime(2024, 1, 2, 3, 4, 5).timestamp()
            os.utime(candidate_path, (mtime, mtime))
            output = root / "nested.json"

            exit_code = main(["files", str(root), "--output", str(output)])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            candidate = payload["candidates"][0]
            self.assertIn("documents", candidate_categories(candidate))
            self.assertEqual(candidate["name"], "report.docx")
            self.assertEqual(candidate["extension"], ".docx")
            self.assertEqual(Path(candidate["path"]), candidate_path.resolve())
            self.assertEqual(candidate["modified_at"], datetime.fromtimestamp(mtime).isoformat())

    def test_files_command_groups_bounded_duplicate_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "copy-a.txt").write_text("same evidence content", encoding="utf-8")
            (root / "copy-b.txt").write_text("same evidence content", encoding="utf-8")
            output = root / "duplicates.json"

            self.assertEqual(main(["files", str(root), "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(payload["summary"]["duplicate_group_count"], 1)
            duplicate_group = payload["duplicate_content_groups"][0]
            self.assertEqual(duplicate_group["file_count"], 2)
            self.assertTrue(duplicate_group["group_id"].startswith("dup-"))
            self.assertIn("group_fingerprint", duplicate_group)
            self.assertEqual(duplicate_group["report_suppression_status"], "not-suppressed")
            self.assertFalse(duplicate_group["suppression_policy"]["safe_to_auto_suppress"])
            self.assertIn("#77", duplicate_group["commercial_gap_ids"])
            duplicate_manifest = payload["duplicate_content_manifest"]
            self.assertEqual(duplicate_manifest["profile"], "duplicate-content-manifest-v1")
            self.assertEqual(duplicate_manifest["profile_version"], "duplicate-content-manifest-v1")
            self.assertEqual(duplicate_manifest["group_count"], 1)
            self.assertIn("manifest_hash", duplicate_manifest)
            self.assertRegex(duplicate_manifest["group_head_hash"], r"^[0-9a-f]{64}$")
            self.assertFalse(duplicate_manifest["suppression_policy"]["auto_suppression_enabled"])
            suppression_manifest = payload["duplicate_detection_assessment"]["duplicate_suppression_manifest"]
            self.assertEqual(suppression_manifest["profile_version"], "duplicate-suppression-manifest-v1")
            self.assertEqual(suppression_manifest["item_number"], 33)
            self.assertEqual(suppression_manifest["gap_id"], "#33")
            self.assertEqual(suppression_manifest["duplicate_content_manifest_hash"], duplicate_manifest["manifest_hash"])
            self.assertEqual(len(suppression_manifest["manifest_hash"]), 64)
            self.assertEqual(len(suppression_manifest["review_matrix_hash"]), 64)
            self.assertTrue(suppression_manifest["review_decision_required_for_each_group"])
            self.assertEqual(suppression_manifest["review_matrix"][0]["required_decision"], "include-representative-or-keep-all-with-note")
            self.assertEqual(
                payload["duplicate_detection_assessment"]["duplicate_suppression_manifest_hash"],
                suppression_manifest["manifest_hash"],
            )
            duplicate_profile = payload["duplicate_detection_assessment"]["functional_priority_profile"]
            self.assertEqual(duplicate_profile["item_number"], 33)
            self.assertEqual(duplicate_profile["batch_id"], "commercial-uplift-031-035")
            self.assertEqual(duplicate_profile["controls"]["duplicate_group_count"], 1)
            self.assertEqual(
                duplicate_profile["controls"]["suppression_manifest_hash"],
                suppression_manifest["manifest_hash"],
            )
            self.assertEqual(
                duplicate_profile["controls"]["review_matrix_hash"],
                suppression_manifest["review_matrix_hash"],
            )
            self.assertFalse(duplicate_profile["controls"]["collapse_by_default_in_ui"])
            self.assertFalse(duplicate_profile["controls"]["auto_suppression_enabled"])
            self.assertIn(
                "duplicate-content manifest hash emitted",
                payload["duplicate_detection_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "duplicate-suppression manifest hash emitted",
                payload["duplicate_detection_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )
            self.assertIn(
                "duplicate review matrix hash emitted",
                payload["duplicate_detection_assessment"]["core_accuracy_gates"][0]["satisfied_checks"],
            )

    def test_hash_cache_and_duplicate_trusted_diffs_promote_core_gates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "same.bin"
            path.write_bytes(b"hash me once")

            first = compute_hashes_cached(path)
            second = compute_hashes_cached(path)

            self.assertEqual(first, second)

            hash_manifest = build_hash_cache_manifest()
            self.assertEqual(hash_manifest["entry_count"], 1)
            self.assertEqual(hash_manifest["stats"]["misses"], 1)
            self.assertEqual(hash_manifest["stats"]["hits"], 1)
            self.assertEqual(hash_manifest["entries"][0]["name"], "same.bin")
            self.assertIn("path_hash", hash_manifest["entries"][0])
            self.assertRegex(hash_manifest["cache_session_id"], r"^[0-9a-f]{64}$")
            self.assertRegex(hash_manifest["entries_head_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(hash_manifest["events_head_hash"], r"^[0-9a-f]{64}$")
            self.assertRegex(hash_manifest["persistence_manifest_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual(hash_manifest["persistence_manifest"]["row_count"], 1)
            self.assertEqual(
                hash_manifest["persistence_manifest"]["rows"][0]["content_address_key"],
                first["sha256"],
            )
            snapshot = Path(tmp_dir) / "hash-cache-snapshot.json"
            export_report = export_hash_cache_snapshot(snapshot)
            self.assertTrue(snapshot.is_file())
            self.assertEqual(export_report["entry_count"], 1)
            self.assertRegex(export_report["snapshot_hash"], r"^[0-9a-f]{64}$")
            reset_hash_cache()
            import_report = import_hash_cache_snapshot(snapshot)
            self.assertEqual(import_report["imported_count"], 1)
            third = compute_hashes_cached(path)
            self.assertEqual(third, first)
            restored_manifest = build_hash_cache_manifest()
            self.assertEqual(restored_manifest["stats"]["hits"], 1)

        hash_assessment = hash_cache_assessment(cache_manifest=hash_manifest)
        hash_diff = build_hash_cache_trusted_diff(hash_assessment, hash_assessment)
        promoted_hash = hash_cache_assessment(trusted_diff=hash_diff)

        self.assertEqual(hash_diff["status"], "pass")
        self.assertIn(
            "trusted hash-cache manifest diff pass",
            promoted_hash["core_accuracy_gates"][0]["satisfied_checks"],
        )

    def test_hash_cache_invalidates_same_path_when_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "mutable.txt"
            path.write_text("before", encoding="utf-8")
            before = compute_hashes_cached(path)
            path.write_text("after", encoding="utf-8")
            after = compute_hashes_cached(path)
            manifest = build_hash_cache_manifest()

        self.assertNotEqual(before["sha256"], after["sha256"])
        self.assertEqual(manifest["stats"]["invalidations"], 1)
        self.assertEqual(manifest["entry_count"], 1)
        self.assertEqual(manifest["invalidation_proof"]["invalidations"], 1)
        self.assertEqual(manifest["invalidation_proof"]["same_path_invalidation_events"], 1)
        self.assertEqual(manifest["invalidation_proof"]["latest_invalidation_event"]["action"], "invalidated")
        self.assertTrue(any(event["action"] == "invalidated" for event in manifest["recent_events"]))

        groups = [
            {
                "group_id": "dup-" + "a" * 16,
                "sha256": "a" * 64,
                "group_fingerprint": "b" * 64,
                "file_count": 2,
                "size": 12,
                "representative_path": "/case/a.txt",
                "representative_name": "a.txt",
                "paths": ["/case/a.txt", "/case/b.txt"],
                "report_suppression_status": "not-suppressed",
            }
        ]
        duplicate_manifest = build_duplicate_content_manifest(groups)
        duplicate_diff = build_duplicate_content_trusted_diff(groups, groups)
        promoted_duplicate = duplicate_detection_assessment(
            groups,
            duplicate_manifest=duplicate_manifest,
            trusted_diff=duplicate_diff,
        )
        promoted_gates = duplicate_content_core_accuracy_gates(
            groups,
            duplicate_manifest=duplicate_manifest,
            trusted_diff=duplicate_diff,
        )

        self.assertEqual(duplicate_diff["status"], "pass")
        self.assertEqual(duplicate_manifest["profile"], "duplicate-content-manifest-v1")
        self.assertIn(
            "trusted duplicate file manifest diff pass",
            promoted_duplicate["core_accuracy_gates"][0]["satisfied_checks"],
        )
        self.assertIn("trusted duplicate file manifest diff pass", promoted_gates[0]["satisfied_checks"])


if __name__ == "__main__":
    unittest.main()
