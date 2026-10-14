"""Parser-quality r1 integration: API contracts the core changes rely on.

* ``/files`` NTFS join: ``$SI``/``$FN`` times, ``is_deleted``, attributes;
  ``apply_listing_times`` accepts the join entry; rows keep
  ``modified_at_origin``/``fs_modified_at``.
* ``/docs`` pages ``candidates`` with a ``matched`` filter
  (``matched=1`` = the previous ``results`` contract) and reports
  ``candidate_count``/``matched_count``.
* ``run_review.canonical_run_case`` finds a case DB persisted under the
  older ``run-run-<slug>`` id.
* ``/tree`` kind nodes forward ``collection_status`` (also "completed"),
  ``skip_reasons`` and ``skipped_row_count``. (Docs ``/candidates/<n>``
  review locators: ``tests/test_rapidtriage_api.py``
  ``test_review_batch_resolves_run_locators_and_review_map_round_trips``.)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from rapidtriage.core.files import TIME_ORIGIN_LISTING, apply_listing_times
from rapidtriage.core.models import FileCandidate
from rapidtriage.core.run.persist import (
    CASE_DB_FILE_NAME,
    legacy_run_case_ids,
    run_case_id,
)

try:
    from rapidtriage.api.app import files_ntfs
    from rapidtriage.api.app.pagination import docs_page
    from rapidtriage.api.app.run_review import canonical_run_case
    from rapidtriage.api.app.tree import build_artifact_domain_groups

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

FULL = "reconstructed-bounded-parent-cache"


def mft_row(path: str, entry: int, **details: object) -> dict[str, object]:
    return {"artifact_type": "ntfs-meta-row", "details": {"source": "mft", "path": path, "path_status": FULL, "entry_number": entry, **details}}


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class NtfsJoinContractTests(unittest.TestCase):
    def setUp(self) -> None:
        files_ntfs.clear_ntfs_index_cache()
        self.addCleanup(files_ntfs.clear_ntfs_index_cache)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def write_rows(self, rows: list[dict[str, object]], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def test_index_keeps_si_fn_times_attributes_and_deleted_flag(self) -> None:
        rows = [
            mft_row(
                "\\Users\\alice.txt",
                65,
                in_use=False,
                created_at="2024-01-01T00:00:00+00:00",
                modified_at="2024-01-02T00:00:00+00:00",
                accessed_at="2024-01-03T00:00:00+00:00",
                mft_modified_at="2024-01-04T00:00:00+00:00",
                si_created_at="2024-01-01T00:00:00+00:00",
                si_modified_at="2024-01-02T00:00:00+00:00",
                si_accessed_at="2024-01-03T00:00:00+00:00",
                si_mft_modified_at="2024-01-04T00:00:00+00:00",
                fn_created_at="2023-12-01T00:00:00+00:00",
                fn_modified_at="2023-12-02T00:00:00+00:00",
                fn_accessed_at="2023-12-03T00:00:00+00:00",
                fn_mft_modified_at="2023-12-04T00:00:00.123456+00:00",
                file_attributes=0x22,
            ),
            # Written before the $SI/$FN split: merged times only (+ the two fn_ fields it had).
            mft_row(
                "\\Users\\legacy.txt",
                66,
                in_use=True,
                created_at="2022-01-01T00:00:00+00:00",
                fn_created_at="2021-01-01T00:00:00+00:00",
            ),
        ]
        index = files_ntfs.build_ntfs_index(("r", "a", 0, 0), self.write_rows(rows, self.base / "rows.jsonl"))
        alice = index.lookup("users/alice.txt")
        self.assertEqual(set(alice), set(files_ntfs.NTFS_ENTRY_KEYS))
        self.assertEqual(alice["entry_number"], 65)
        self.assertFalse(alice["in_use"])
        self.assertTrue(alice["is_deleted"])
        self.assertEqual(alice["si_modified_at"], "2024-01-02T00:00:00+00:00")
        self.assertEqual(alice["si_created_at"], "2024-01-01T00:00:00+00:00")
        self.assertEqual(alice["si_accessed_at"], "2024-01-03T00:00:00+00:00")
        self.assertEqual(alice["fn_created_at"], "2023-12-01T00:00:00+00:00")
        self.assertEqual(alice["fn_mft_modified_at"], "2023-12-04T00:00:00.123456+00:00")
        self.assertEqual(alice["attributes"], ["HIDDEN", "ARCHIVE"])
        legacy = index.lookup("users/legacy.txt")
        self.assertFalse(legacy["is_deleted"])
        self.assertEqual(legacy["created_at"], "2022-01-01T00:00:00+00:00")
        self.assertIsNone(legacy["si_created_at"])  # a merged time is never relabelled as $SI
        self.assertEqual(legacy["fn_created_at"], "2021-01-01T00:00:00+00:00")
        self.assertIsNone(legacy["attributes"])

    def test_join_page_fills_unknown_is_deleted_and_keeps_time_origin(self) -> None:
        evidence = self.base / "evidence"
        (evidence / "Users").mkdir(parents=True)
        output_dir = self.base / "run"
        analysis_id = "20261013T000000-ntfs"
        self.write_rows(
            [
                mft_row("\\Users", 63, in_use=True),
                mft_row("\\Users\\alice.txt", 65, in_use=False, si_modified_at="2024-01-02T00:00:00+00:00", file_attributes=0x20),
                mft_row("\\Users\\bob.txt", 66, in_use=False),
            ],
            output_dir / "analyses" / analysis_id / "rows.jsonl",
        )
        scope = SimpleNamespace(
            run_id="run-1",
            output_dir=output_dir,
            summary={"scan_scope_root": str(evidence), "outputs": {}},
            source={"type": "folder"},
        )
        state = {"analysis_id": analysis_id, "summary": {"mft_record_count": 3}, "options": {}, "row_count": 3}
        rows = [
            {
                "path": str(evidence / "Users" / "alice.txt"),
                "modified_at_origin": "acquisition-copy",
                "fs_modified_at": None,
                "source_file_mtime": "2026-10-07T00:00:00+00:00",
                "is_deleted": None,
            },
            # A row whose deletion state is already known keeps it.
            {"path": str(evidence / "Users" / "bob.txt"), "modified_at_origin": "listing", "fs_modified_at": "2020-01-01T00:00:00+00:00", "is_deleted": False},
        ]
        with mock.patch.object(files_ntfs, "latest_parsed_ntfs_analysis", return_value=state):
            page = files_ntfs.join_files_page(scope, {"candidates": rows}, rows)
        self.assertEqual(page["ntfs_join"]["status"], "joined", page["ntfs_join"])
        alice, bob = page["candidates"]
        self.assertEqual(alice["ntfs"]["si_modified_at"], "2024-01-02T00:00:00+00:00")
        self.assertEqual(alice["ntfs"]["attributes"], ["ARCHIVE"])
        self.assertTrue(alice["is_deleted"])
        self.assertEqual(alice["modified_at_origin"], "acquisition-copy")
        self.assertIsNone(alice["fs_modified_at"])
        self.assertEqual(alice["source_file_mtime"], "2026-10-07T00:00:00+00:00")
        self.assertFalse(bob["is_deleted"])
        self.assertEqual(bob["modified_at_origin"], "listing")
        self.assertEqual(bob["fs_modified_at"], "2020-01-01T00:00:00+00:00")
        self.assertTrue(bob["ntfs"]["is_deleted"])

    def test_apply_listing_times_accepts_ntfs_join_entry(self) -> None:
        candidate = FileCandidate(path="x", name="x", extension="", size=1, modified_at="2026-10-07T00:00:00+00:00", modified_epoch=0.0, categories=[], reasons={})
        apply_listing_times(
            candidate,
            {
                "modified_at": "2024-01-02T09:00:00+00:00",  # merged
                "si_modified_at": "2024-01-02T00:00:00+00:00",
                "si_created_at": "2024-01-01T00:00:00+00:00",
                "fn_accessed_at": "2023-12-03T00:00:00+00:00",
                "si_mft_modified_at": "2024-01-04T00:00:00+00:00",
                "in_use": False,
                "attributes": ["HIDDEN"],
            },
        )
        self.assertEqual(candidate.fs_modified_at, "2024-01-02T00:00:00+00:00")  # $SI before merged
        self.assertEqual(candidate.fs_created_at, "2024-01-01T00:00:00+00:00")
        self.assertEqual(candidate.fs_accessed_at, "2023-12-03T00:00:00+00:00")  # $FN as last fallback
        self.assertEqual(candidate.fs_changed_at, "2024-01-04T00:00:00+00:00")
        self.assertEqual(candidate.modified_at, "2024-01-02T00:00:00+00:00")
        self.assertEqual(candidate.modified_at_origin, TIME_ORIGIN_LISTING)
        self.assertTrue(candidate.is_deleted)
        self.assertEqual(candidate.attributes, ["HIDDEN"])
        self.assertEqual(candidate.attributes_origin, TIME_ORIGIN_LISTING)

        explicit = FileCandidate(path="y", name="y", extension="", size=1, modified_at="", modified_epoch=0.0, categories=[], reasons={})
        apply_listing_times(explicit, {"mtime": "2024-02-01T00:00:00+00:00", "deleted": False, "in_use": False})
        self.assertFalse(explicit.is_deleted)  # an explicit ``deleted`` wins over ``in_use``


DOCS_PAYLOAD: dict[str, object] = {
    "command": "docs",
    "summary": {"candidate_count": 3, "match_count": 1},
    "manifest": {"providers": []},
    "candidates": [
        {"path": "/e/a.txt", "matched": True, "matched_keywords": ["k"]},
        {"path": "/e/b.hwp", "matched": False, "matched_keywords": []},
        {"path": "/e/c.pdf", "matched": False, "matched_keywords": []},
    ],
    "results": [{"path": "/e/a.txt", "kind": "txt", "matched_keywords": ["k"], "preview": "k", "size": 1}],
}


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class DocsPageContractTests(unittest.TestCase):
    def test_default_pages_every_candidate_with_counts(self) -> None:
        page = docs_page(DOCS_PAYLOAD, matched=None, offset=1, limit=1)
        self.assertEqual(page["pagination"]["collection"], "candidates")
        self.assertEqual(page["pagination"]["total"], 3)
        self.assertEqual([row["path"] for row in page["candidates"]], ["/e/b.hwp"])
        self.assertEqual(page["candidates"][0]["record_index"], 1)
        self.assertEqual((page["candidate_count"], page["matched_count"]), (3, 1))
        self.assertIn("results", page["omitted_fields"])

    def test_matched_filters_and_matched_one_keeps_previous_contract(self) -> None:
        unmatched = docs_page(DOCS_PAYLOAD, matched=False, offset=0, limit=10)
        self.assertEqual([row["record_index"] for row in unmatched["candidates"]], [1, 2])
        self.assertEqual(unmatched["pagination"]["total"], 2)
        previous = docs_page(DOCS_PAYLOAD, matched=True, offset=0, limit=10)
        self.assertEqual(previous["pagination"]["collection"], "results")
        self.assertEqual(previous["results"], DOCS_PAYLOAD["results"])
        self.assertIn("candidates", previous["omitted_fields"])
        self.assertEqual((previous["candidate_count"], previous["matched_count"]), (3, 1))
        whole = docs_page(DOCS_PAYLOAD, matched=None, offset=0, limit=0)
        self.assertEqual(len(whole["candidates"]), 3)
        self.assertEqual(whole["results"], DOCS_PAYLOAD["results"])

    def test_pre_r1_candidates_without_matched_use_results_membership(self) -> None:
        legacy = {
            "candidates": [{"path": "/e/a.txt"}, {"path": "/e/b.txt"}],
            "results": [{"path": "/e/a.txt"}],
        }
        page = docs_page(legacy, matched=True, offset=0, limit=5)
        self.assertEqual(page["results"], [{"path": "/e/a.txt"}])
        unmatched = docs_page(legacy, matched=False, offset=0, limit=5)
        self.assertEqual([row["path"] for row in unmatched["candidates"]], ["/e/b.txt"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class TreeSkipDisclosureTests(unittest.TestCase):
    def test_kind_nodes_forward_collection_status_and_skip_reasons(self) -> None:
        groups = build_artifact_domain_groups(
            {
                "synthetic-media": {
                    "artifact_count": 1,
                    "artifact_type_counts": {"synthetic-media-scan-skipped": 1},
                    "collection_status": "skipped",
                    "skipped_row_count": 1,
                    "skip_reasons": {"선택 의존성 deepfake_lens 없음": 1},
                },
                "eventlog": {"artifact_count": 2, "artifact_type_counts": {"eventlog-event": 2}, "collection_status": "completed"},
            }
        )
        kinds = {kind["kind"]: kind for group in groups for kind in group["children"] if "@" not in kind["id"]}
        media = kinds["synthetic-media"]
        self.assertEqual(media["collection_status"], "skipped")
        self.assertEqual(media["skipped_row_count"], 1)
        self.assertEqual(media["skip_reasons"], {"선택 의존성 deepfake_lens 없음": 1})
        eventlog = kinds["eventlog"]
        self.assertEqual(eventlog["collection_status"], "completed")  # forwarded even when completed
        self.assertNotIn("skip_reasons", eventlog)
        self.assertNotIn("skipped_row_count", eventlog)


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class CanonicalRunCaseTests(unittest.TestCase):
    def test_finds_case_persisted_under_legacy_run_case_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "run-subset7"
            output_dir.mkdir()
            legacy_id = legacy_run_case_ids(output_dir)[0]
            self.assertEqual(legacy_id, "run-run-subset7")
            self.assertEqual(run_case_id(output_dir), "run-subset7")
            database = output_dir / CASE_DB_FILE_NAME
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE case_record (case_id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO case_record VALUES (?)", (legacy_id,))
            connection.commit()
            connection.close()
            path, case_id = canonical_run_case({"output_dir": str(output_dir)}, "abc123")
            self.assertEqual(case_id, legacy_id)
            self.assertEqual(path, database.resolve())
            # A case under the current id wins over the legacy form.
            connection = sqlite3.connect(database)
            connection.execute("INSERT INTO case_record VALUES (?)", ("run-subset7",))
            connection.commit()
            connection.close()
            self.assertEqual(canonical_run_case({"output_dir": str(output_dir)}, "abc123")[1], "run-subset7")


if __name__ == "__main__":
    unittest.main()
