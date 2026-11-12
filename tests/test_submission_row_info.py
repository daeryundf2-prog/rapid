"""R8 T-178: submission manifest items carry the cited artifact row and a relative evidence path."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.submission import (
    SKIP_REASON_KO,
    build_submission_manifest,
    evidence_relative_roots,
)
from tests.schema_validation import validate

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "rapidtriage" / "schemas" / "submission-manifest.schema.json"

# Key sets before T-178 (snapshot): every existing key stays, T-178 only adds.
ITEM_KEYS_BEFORE = {"bookmark_id", "summary", "tags", "note", "review", "reference", "evidence"}
EVIDENCE_KEYS_BEFORE = {"path", "name", "size", "modified_at", "hashes", "hash_source"}
SKIP_KEYS_BEFORE = {"bookmark_id", "summary", "path", "reason"}
SUMMARY_KEYS_BEFORE = {
    "case_bookmark_count",
    "report_candidate_count",
    "hashed_item_count",
    "skipped_count",
    "max_items_skipped_count",
    "truncated",
    "total_size",
}
ROW_KEYS = {"timestamp", "preview", "citation_id", "collection", "kind", "locator"}


def case_db_mark(index: int, path: Path) -> dict[str, object]:
    """A bookmark shaped like ``review_payload.read_case_db_marks`` output (a case DB mark)."""
    return {
        "bookmark_id": f"case-db:CIT-{index:04d}",
        "summary": f"artifact row {index}",
        "tags": ["tag"],
        "note": "",
        "review": {"status": "relevant", "include_in_report": True},
        "reference": {
            "source_command": "case-db",
            "citation_id": f"CIT-{index:04d}",
            "target_type": "artifact",
            "target_id": str(index),
            "collection": "browser_history",
            "kind": "url_visit",
            "locator": f"artifacts/browser_history.jsonl#L{index}",
        },
        "snapshot": {"path": str(path), "timestamp": f"2026-01-0{index}T00:00:00Z", "summary": f"row preview {index}"},
    }


def json_bookmark(index: int, path: Path) -> dict[str, object]:
    return {
        "bookmark_id": f"bm-{index}",
        "summary": f"bookmark {index}",
        "tags": [],
        "note": "",
        "review": {"status": "relevant", "include_in_report": True},
        "reference": {"command": "files", "file": str(path), "pointer": f"/items/{index}", "root": None, "stable_key": f"k{index}"},
        "snapshot": {"path": str(path), "timestamp": None, "artifact_key": "file", "summary": f"bookmark {index}"},
    }


class SubmissionRowInfoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        (self.root / "nested").mkdir()
        self.addCleanup(self._tmp.cleanup)

    def make_file(self, name: str) -> Path:
        path = self.root / "nested" / name
        path.write_bytes(f"synthetic {name}".encode())
        return path

    def test_six_artifact_rows_carry_row_info_and_relative_path(self) -> None:
        bookmarks = [case_db_mark(index, self.make_file(f"row{index}.txt")) for index in range(1, 7)]
        manifest = build_submission_manifest({"case_id": "c", "bookmarks": bookmarks}, allowed_roots=[self.root])
        items = manifest["items"]
        self.assertEqual(len(items), 6)
        with_row = [item for item in items if all(item["row"][key] for key in ROW_KEYS)]
        self.assertEqual(len(with_row), 6)
        first = items[0]
        self.assertEqual(
            first["row"],
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "preview": "row preview 1",
                "preview_truncated": False,
                "preview_total": 13,
                "citation_id": "CIT-0001",
                "collection": "browser_history",
                "kind": "url_visit",
                "locator": "artifacts/browser_history.jsonl#L1",
            },
        )
        self.assertEqual(first["evidence"]["relative_path"], "nested/row1.txt")
        # The 200-character preview cap is disclosed, never silent (collector caps inventory).
        from rapidtriage.core import submission

        long_row = submission.build_row_info({"summary": "가" * 450})
        self.assertTrue(long_row["preview_truncated"])
        self.assertEqual(long_row["preview_total"], 450)
        self.assertEqual(len(long_row["preview"]), submission.PREVIEW_MAX_CHARS)
        validate(manifest, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))

    def test_existing_keys_unchanged_snapshot(self) -> None:
        bookmarks = [json_bookmark(1, self.make_file("a.txt")), json_bookmark(2, self.root / "missing.txt")]
        manifest = build_submission_manifest({"bookmarks": bookmarks}, allowed_roots=[self.root])
        item = manifest["items"][0]
        self.assertEqual(set(item), ITEM_KEYS_BEFORE | {"row"})
        self.assertEqual(set(item["evidence"]), EVIDENCE_KEYS_BEFORE | {"relative_path", "relative_to"})
        self.assertEqual(set(manifest["summary"]), SUMMARY_KEYS_BEFORE)
        skip = manifest["skipped"][0]
        self.assertEqual(set(skip), SKIP_KEYS_BEFORE | {"reason_ko"})
        self.assertEqual(skip["reason"], "missing-or-not-file")
        self.assertEqual(skip["reason_ko"], SKIP_REASON_KO["missing-or-not-file"])
        # Bookmark-JSON items fall back to their own reference fields.
        self.assertEqual(item["row"]["collection"], "files")
        self.assertEqual(item["row"]["kind"], "file")
        self.assertEqual(item["row"]["locator"], "/items/1")
        self.assertEqual(item["row"]["citation_id"], "")
        validate(manifest, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))

    def test_501_items_report_one_max_items_skip(self) -> None:
        path = self.make_file("shared.txt")
        bookmarks = [case_db_mark(index, path) for index in range(1, 502)]
        manifest = build_submission_manifest({"bookmarks": bookmarks}, allowed_roots=[self.root])
        summary = manifest["summary"]
        self.assertEqual(summary["hashed_item_count"], 500)
        self.assertEqual(summary["max_items_skipped_count"], 1)
        self.assertTrue(summary["truncated"])
        self.assertNotIn("over_limit_count", summary)
        self.assertEqual([skip["reason"] for skip in manifest["skipped"]], ["max-items"])
        self.assertEqual(manifest["skipped"][0]["reason_ko"], SKIP_REASON_KO["max-items"])

    def test_every_skip_reason_has_korean_text(self) -> None:
        outside = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: outside.rmdir())
        bookmarks = [
            {"bookmark_id": "no-path", "review": {"include_in_report": True}},
            json_bookmark(2, outside / "x.txt"),
        ]
        manifest = build_submission_manifest({"bookmarks": bookmarks}, allowed_roots=[self.root])
        reasons = {skip["reason"]: skip["reason_ko"] for skip in manifest["skipped"]}
        self.assertEqual(
            reasons,
            {
                "no-source-path": SKIP_REASON_KO["no-source-path"],
                "outside-allowed-roots": SKIP_REASON_KO["outside-allowed-roots"],
            },
        )

    def test_relative_path_is_relative_to_the_analysed_root_only(self) -> None:
        # An E01 run's roots: output folder (allowed, holds carved/recovered output), the
        # extracted file system under it (the analysed root) and the image stage folder.
        output_dir = self.root / "out"
        analysis_root = output_dir / "_e01" / "fs"
        (analysis_root / "Users" / "u").mkdir(parents=True)
        (output_dir / "carved").mkdir()
        inside = analysis_root / "Users" / "u" / "a.docx"
        inside.write_bytes(b"synthetic doc")
        carved = output_dir / "carved" / "00001.jpg"
        carved.write_bytes(b"synthetic carve")
        summary = {"root": str(analysis_root), "output_dir": str(output_dir), "source": {"analysis_root": str(analysis_root)}}
        bookmarks = [case_db_mark(1, inside), case_db_mark(2, carved)]
        # Allowed roots in the order the API lists them: output folder first.
        manifest = build_submission_manifest(
            {"bookmarks": bookmarks},
            allowed_roots=[output_dir, analysis_root],
            evidence_roots=evidence_relative_roots(summary),
        )
        evidence = {item["bookmark_id"]: item["evidence"] for item in manifest["items"]}
        self.assertEqual(evidence["case-db:CIT-0001"]["relative_path"], "Users/u/a.docx")
        self.assertEqual(evidence["case-db:CIT-0001"]["relative_to"], "evidence-root")
        self.assertEqual(evidence["case-db:CIT-0002"]["relative_path"], "")
        self.assertEqual(evidence["case-db:CIT-0002"]["relative_to"], "")
        self.assertEqual(evidence["case-db:CIT-0002"]["path"], str(carved))
        self.assertEqual(manifest["summary"]["hashed_item_count"], 2)
        validate(manifest, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
        self.assertEqual(evidence_relative_roots(summary), [analysis_root.resolve()])

    def test_long_preview_is_capped(self) -> None:
        bookmark = case_db_mark(1, self.make_file("long.txt"))
        bookmark["snapshot"]["summary"] = "가" * 500  # type: ignore[index]
        manifest = build_submission_manifest({"bookmarks": [bookmark]}, allowed_roots=[self.root])
        preview = manifest["items"][0]["row"]["preview"]
        self.assertEqual(len(preview), 200)
        self.assertTrue(preview.endswith("…"))


if __name__ == "__main__":
    unittest.main()
