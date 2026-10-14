"""Parser-quality r1 integration: API contracts the core changes rely on.

* ``/files`` NTFS join: ``$SI``/``$FN`` times, ``is_deleted``, attributes;
  ``apply_listing_times`` accepts the join entry; rows keep
  ``modified_at_origin``/``fs_modified_at``.
* ``/docs`` keeps the previous contract by default (pages ``results``);
  ``all=1`` pages ``candidates`` with an optional ``matched`` filter;
  ``matched=0`` without ``all=1`` is a 400; every view reports
  ``candidate_count``/``matched_count``.
* ``run_review.canonical_run_case`` finds a case DB persisted under the
  older ``run-run-<slug>`` id.
* ``/files?scope=inventory`` (parser-quality r2) pages the files output's
  ``inventory`` (every non-candidate scanned file, incl. ``other``) with the
  same ``category`` filter; both scopes report ``candidate_count``/
  ``inventory_count``; the NTFS join keeps ``recovery.deletion_state`` /
  inventory ``deletion_state`` in step with ``is_deleted``; ``/tree`` "기타"
  comes from ``inventory_category_counts`` with ``scope="inventory"``.
* ``/tree`` kind nodes forward ``collection_status`` (also "completed"),
  ``skip_reasons`` and ``skipped_row_count``; the eventlog kind node carries
  ``stale_below_first_record_count``.
* ``/files`` rows carry ``match_method`` (``path-fold`` / ``none`` / null).
* Review locators ``/inventory/<n>`` resolve by path (the candidate's
  ``file_record`` when that path is also a candidate) and round-trip.
  (Docs ``/candidates/<n>``
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
from rapidtriage.core.jobs import RunJobStore
from rapidtriage.core.models import FileCandidate
from rapidtriage.core.run.persist import (
    CASE_DB_FILE_NAME,
    legacy_run_case_ids,
    run_case_id,
)

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, files_ntfs
    from rapidtriage.api.app.artifact_filter import filter_files_by_category
    from rapidtriage.api.app.pagination import docs_page
    from rapidtriage.api.app.run_review import RunLocatorIndex, canonical_run_case
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
        self.assertEqual([alice["match_method"], bob["match_method"]], ["path-fold", "path-fold"])

    def test_join_keeps_deletion_state_in_step_with_is_deleted(self) -> None:
        evidence = self.base / "evidence"
        (evidence / "Users").mkdir(parents=True)
        output_dir = self.base / "run"
        analysis_id = "20261014T000000-ntfs"
        self.write_rows(
            [
                mft_row("\\Users", 63, in_use=True),
                mft_row("\\Users\\gone.txt", 70, in_use=False),
                mft_row("\\Users\\live.txt", 71, in_use=True),
                mft_row("\\Users\\other.bin", 72, in_use=False),
            ],
            output_dir / "analyses" / analysis_id / "rows.jsonl",
        )
        scope = SimpleNamespace(run_id="run-del", output_dir=output_dir, summary={"scan_scope_root": str(evidence), "outputs": {}}, source={"type": "folder"})
        state = {"analysis_id": analysis_id, "summary": {"mft_record_count": 4}, "options": {}, "row_count": 4}

        def candidate(name: str, deletion_state: str, is_deleted: object = None) -> dict[str, object]:
            return {"path": str(evidence / "Users" / name), "is_deleted": is_deleted, "recovery": {"candidate_kind": "existing", "deletion_state": deletion_state}}

        shared_recovery = {"candidate_kind": "existing", "deletion_state": "unknown"}
        rows = [
            {"path": str(evidence / "Users" / "gone.txt"), "is_deleted": None, "recovery": shared_recovery},
            candidate("live.txt", "unknown"),
            candidate("missing.txt", "allocated"),  # not in the MFT, unknown: a pre-r2 "allocated" claim is dropped
            candidate("missing2.txt", "deleted"),  # recorded deleted with unknown is_deleted stays deleted
            candidate("missing3.txt", "unallocated-candidate", True),  # specific recovery state kept
        ]
        with mock.patch.object(files_ntfs, "latest_parsed_ntfs_analysis", return_value=state):
            page = files_ntfs.join_files_page(scope, {"candidates": rows}, rows)
            inventory_rows = [{"path": str(evidence / "Users" / "other.bin"), "is_deleted": None, "inventory_only": True, "deletion_state": "unknown"}]
            inventory = files_ntfs.join_files_page(scope, {"inventory": inventory_rows}, inventory_rows, collection="inventory")
        states = [(row["is_deleted"], row["recovery"]["deletion_state"]) for row in page["candidates"]]
        self.assertEqual(
            states,
            [(True, "deleted"), (False, "allocated"), (None, "unknown"), (None, "deleted"), (True, "unallocated-candidate")],
        )
        self.assertEqual(shared_recovery["deletion_state"], "unknown")  # cached payload rows are never mutated
        self.assertEqual(inventory["ntfs_join"]["matched"], 1)
        self.assertNotIn("candidates", inventory)
        (other,) = inventory["inventory"]
        self.assertEqual((other["is_deleted"], other["deletion_state"], other["filesystem"]), (True, "deleted", "NTFS"))
        self.assertEqual([row["match_method"] for row in page["candidates"]], ["path-fold", "path-fold", "none", "none", "none"])
        self.assertEqual(other["match_method"], "path-fold")

    def test_match_method_is_null_when_no_join_ran(self) -> None:
        rows = [{"path": "/e/a.txt", "is_deleted": None}]
        skipped = files_ntfs.join_files_page(None, {"candidates": rows}, rows)
        self.assertEqual(skipped["ntfs_join"]["status"], "skipped")
        self.assertIsNone(skipped["candidates"][0]["match_method"])
        scope = SimpleNamespace(run_id="run-none", output_dir=self.base, summary={"outputs": {}}, source={"type": "folder"})
        with mock.patch.object(files_ntfs, "latest_parsed_ntfs_analysis", return_value=None):
            page = files_ntfs.join_files_page(scope, {"candidates": rows}, rows)
        self.assertEqual(page["ntfs_join"]["status"], "no_analysis")
        self.assertIsNone(page["candidates"][0]["match_method"])

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
    def test_default_keeps_previous_results_contract_with_counts(self) -> None:
        page = docs_page(DOCS_PAYLOAD, offset=0, limit=10)
        self.assertEqual(page["pagination"]["collection"], "results")
        self.assertEqual(page["results"], DOCS_PAYLOAD["results"])
        self.assertEqual(page["candidates"], [])  # omitted, as before r1
        self.assertIn("candidates", page["omitted_fields"])
        self.assertEqual((page["candidate_count"], page["matched_count"]), (3, 1))
        self.assertEqual(docs_page(DOCS_PAYLOAD, matched=True, offset=0, limit=10), page)
        whole = docs_page(DOCS_PAYLOAD, offset=0, limit=0)
        self.assertEqual(whole["results"], DOCS_PAYLOAD["results"])
        self.assertEqual((whole["candidate_count"], whole["matched_count"]), (3, 1))
        self.assertNotIn("candidate_count", DOCS_PAYLOAD)  # the cached payload is not mutated

    def test_matched_zero_requires_all(self) -> None:
        with self.assertRaisesRegex(ValueError, "all=1이 필요합니다"):
            docs_page(DOCS_PAYLOAD, matched=False, offset=0, limit=10)

    def test_all_pages_every_candidate_with_record_index(self) -> None:
        page = docs_page(DOCS_PAYLOAD, all_candidates=True, offset=1, limit=1)
        self.assertEqual(page["pagination"]["collection"], "candidates")
        self.assertEqual(page["pagination"]["total"], 3)
        self.assertEqual([row["path"] for row in page["candidates"]], ["/e/b.hwp"])
        self.assertEqual(page["candidates"][0]["record_index"], 1)
        self.assertEqual((page["candidate_count"], page["matched_count"]), (3, 1))
        self.assertIn("results", page["omitted_fields"])
        unmatched = docs_page(DOCS_PAYLOAD, all_candidates=True, matched=False, offset=0, limit=10)
        self.assertEqual([row["record_index"] for row in unmatched["candidates"]], [1, 2])
        self.assertEqual(unmatched["pagination"]["total"], 2)
        hits = docs_page(DOCS_PAYLOAD, all_candidates=True, matched=True, offset=0, limit=10)
        self.assertEqual([row["record_index"] for row in hits["candidates"]], [0])
        whole = docs_page(DOCS_PAYLOAD, all_candidates=True, offset=0, limit=0)
        self.assertEqual(len(whole["candidates"]), 3)
        self.assertEqual(whole["results"], DOCS_PAYLOAD["results"])

    def test_pre_r1_candidates_without_matched_use_results_membership(self) -> None:
        legacy = {
            "candidates": [{"path": "/e/a.txt"}, {"path": "/e/b.txt"}],
            "results": [{"path": "/e/a.txt"}],
        }
        page = docs_page(legacy, offset=0, limit=5)
        self.assertEqual(page["results"], [{"path": "/e/a.txt"}])
        unmatched = docs_page(legacy, all_candidates=True, matched=False, offset=0, limit=5)
        self.assertEqual([row["path"] for row in unmatched["candidates"]], ["/e/b.txt"])


TOKEN = "parser-quality-integration-token"


def write_files_run(base: Path, files: dict[str, object]) -> Path:
    """Minimal completed run whose only output is ``files``."""
    run_dir = base / "run"
    run_dir.mkdir()
    files_path = run_dir / "rapidtriage-files.json"
    files_path.write_text(json.dumps(files), encoding="utf-8")
    summary_path = run_dir / "rapidtriage-run-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "profile_version": "rapidtriage-run-summary-v1",
                "mode": "hacking",
                "root": str(base / "evidence"),
                "scan_scope_root": str(base / "evidence"),
                "output_dir": str(run_dir),
                "source": {"type": "folder"},
                "outputs": {"files": str(files_path), "summary": str(summary_path)},
            }
        ),
        encoding="utf-8",
    )
    return run_dir


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class FilesInventoryScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        files_ntfs.clear_ntfs_index_cache()
        self.addCleanup(files_ntfs.clear_ntfs_index_cache)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        evidence = self.base / "evidence"

        def inventory_row(name: str, categories: list[str] | None) -> dict[str, object]:
            row: dict[str, object] = {"path": str(evidence / name), "name": name, "inventory_only": True, "is_deleted": None, "deletion_state": "unknown"}
            if categories is not None:
                row["categories"] = categories
            return row

        self.files = {
            "summary": {"category_counts": {"documents": 2}, "inventory_count": 4, "inventory_category_counts": {"other": 3, "images": 1}},
            "candidates": [
                {"path": str(evidence / "a.docx"), "name": "a.docx", "categories": ["documents"], "recovery": {"deletion_state": "unknown"}},
                {"path": str(evidence / "b.hwp"), "name": "b.hwp", "categories": ["documents"], "recovery": {"deletion_state": "unknown"}},
            ],
            "inventory": [
                inventory_row("x.dll", ["other"]),
                inventory_row("photo.jpg", ["images"]),
                inventory_row("y.dat", ["other"]),
                inventory_row("legacy.bin", None),  # no categories: counted as "other"
            ],
        }
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(write_files_run(self.base, self.files)).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        self.url = f"/api/runs/{self.run_id}/files"

    def get(self, *params: tuple[str, str], status: int = 200) -> dict[str, object]:
        response = self.client.get(self.url, params=list(params))
        self.assertEqual(response.status_code, status, response.text)
        return response.json()

    def test_default_scope_stays_candidates_without_inventory_rows(self) -> None:
        page = self.get(("limit", "10"))
        self.assertEqual(page["scope"], "candidates")
        self.assertEqual([row["name"] for row in page["candidates"]], ["a.docx", "b.hwp"])
        self.assertNotIn("inventory", page)  # never ships the inventory list with candidate pages
        self.assertEqual((page["candidate_count"], page["inventory_count"]), (2, 4))
        self.assertNotIn("inventory_note", page)
        self.assertEqual(page["pagination"]["total"], 2)
        whole = self.get()  # limit=0: every candidate, still without inventory
        self.assertNotIn("inventory", whole)
        self.assertEqual(len(whole["candidates"]), 2)

    def test_inventory_scope_pages_every_row_with_own_record_index(self) -> None:
        first = self.get(("scope", "inventory"), ("limit", "2"))
        self.assertEqual(first["scope"], "inventory")
        self.assertNotIn("candidates", first)
        self.assertEqual([(row["name"], row["record_index"]) for row in first["inventory"]], [("x.dll", 0), ("photo.jpg", 1)])
        self.assertEqual(first["pagination"]["collection"], "inventory")
        self.assertEqual((first["pagination"]["total"], first["pagination"]["has_more"]), (4, True))
        self.assertEqual((first["candidate_count"], first["inventory_count"]), (2, 4))
        self.assertEqual(first["ntfs_join"]["total"], 2)
        self.assertTrue(all(row["deletion_state"] == "unknown" for row in first["inventory"]))
        rest = self.get(("scope", "inventory"), ("limit", "5"), ("offset", "2"))
        self.assertEqual([row["record_index"] for row in rest["inventory"]], [2, 3])

    def test_category_filter_works_on_both_scopes(self) -> None:
        other = self.get(("scope", "inventory"), ("category", "other"), ("limit", "5"))
        self.assertEqual([(row["name"], row["record_index"]) for row in other["inventory"]], [("x.dll", 0), ("y.dat", 2), ("legacy.bin", 3)])
        self.assertEqual((other["matched"], other["record_count"]), (3, 4))
        self.assertEqual(other["pagination"]["collection"], "inventory")
        self.assertEqual(other["matched"], self.files["summary"]["inventory_category_counts"]["other"])  # agrees with the tree count
        images = self.get(("scope", "inventory"), ("category", "images"), ("limit", "5"))
        self.assertEqual([row["name"] for row in images["inventory"]], ["photo.jpg"])
        docs = self.get(("category", "documents"), ("limit", "5"))
        self.assertEqual((docs["scope"], docs["matched"], docs["inventory_count"]), ("candidates", 2, 4))
        self.assertNotIn("inventory", docs)
        self.assertEqual(self.get(("category", "other"), ("limit", "5"))["matched"], 0)  # other lives in inventory only
        self.get(("scope", "inventory"), ("category", "other"), status=400)  # filters need limit>0
        self.get(("scope", "everything"), status=422)

    def test_output_without_inventory_reports_null_count_and_note(self) -> None:
        legacy = {"candidates": self.files["candidates"]}
        legacy_base = self.base / "legacy"
        legacy_base.mkdir()
        run_id = self.store.import_completed_run(write_files_run(legacy_base, legacy)).run_id
        page = self.client.get(f"/api/runs/{run_id}/files", params={"scope": "inventory", "limit": 5}).json()
        self.assertEqual((page["inventory"], page["inventory_count"], page["candidate_count"]), ([], None, 2))
        self.assertIn("inventory", page["inventory_note"])

    def test_tree_other_node_counts_inventory_and_points_at_inventory_scope(self) -> None:
        tree = self.client.get(f"/api/runs/{self.run_id}/tree").json()
        files = next(node for node in tree["nodes"] if node["id"] == "files")
        self.assertEqual(files["inventory_count"], 4)
        children = {child["id"]: child for child in files["children"]}
        other = children["files:other"]
        self.assertEqual((other["label"], other["count"], other["scope"], other["category"]), ("기타", 3, "inventory", "other"))
        self.assertNotIn("scope", children["files:documents"])  # candidate nodes keep the default scope

    def test_filter_helper_drops_the_other_list(self) -> None:
        page = filter_files_by_category(self.files, {"documents"}, offset=0, limit=0)
        self.assertEqual(len(page["candidates"]), 2)
        self.assertNotIn("inventory", page)


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
        self.assertNotIn("stale_below_first_record_count", eventlog)  # old output: not sent

    def test_eventlog_kind_node_carries_stale_below_first_count(self) -> None:
        groups = build_artifact_domain_groups(
            {
                "eventlog": {
                    "artifact_count": 3,
                    "artifact_type_counts": {"eventlog-event": 2, "eventlog-record-candidate": 1},
                    "stale_below_first_record_count": 1,
                },
            }
        )
        (eventlog,) = [kind for group in groups for kind in group["children"] if kind["kind"] == "eventlog"]
        self.assertEqual(eventlog["id"], "artifacts:eventlog")
        self.assertEqual(eventlog["stale_below_first_record_count"], 1)
        zero = build_artifact_domain_groups({"eventlog": {"artifact_count": 0, "stale_below_first_record_count": 0}})
        self.assertEqual(zero[0]["children"][0]["stale_below_first_record_count"], 0)  # 0 is sent (known none)


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


@unittest.skipUnless(HAS_FASTAPI, "fastapi not installed")
class InventoryReviewLocatorTests(unittest.TestCase):
    """``/inventory/<n>`` review locators resolve by path against the real case-DB import."""

    def test_inventory_locators_resolve_by_path_and_round_trip(self) -> None:
        from rapidtriage.core.case_db import CaseDatabase

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            evidence = base / "evidence"
            evidence.mkdir()
            output_dir = base / "run"
            output_dir.mkdir()
            a, b, c = (str(evidence / name) for name in ("a.docx", "b.dll", "c.dat"))
            files_path = output_dir / "rapidtriage-files.json"
            files_path.write_text(
                json.dumps(
                    {
                        "summary": {"candidate_count": 1, "inventory_count": 3},
                        "candidates": [{"path": a, "name": "a.docx", "size": 1}],
                        # a.docx is also a candidate: the import skips its inventory row.
                        "inventory": [
                            {"path": b, "name": "b.dll", "inventory_only": True},
                            {"path": a, "name": "a.docx", "inventory_only": True},
                            {"path": c, "name": "c.dat", "inventory_only": True},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            outputs = {"files": str(files_path)}
            database_path = output_dir / CASE_DB_FILE_NAME
            CaseDatabase(database_path).import_run_output(
                {"outputs": outputs, "root": str(evidence), "source": {"type": "folder", "source_path": str(evidence)}},
                case_id="run-x",
                hash_files=False,
            )
            connection = sqlite3.connect(database_path)
            try:
                ids = {str(path): int(row_id) for row_id, path in connection.execute("SELECT id, path FROM file_record ORDER BY id")}
                self.assertEqual(list(ids), [a, b, c])  # candidate, then inventory without the duplicate
                index = RunLocatorIndex(connection, "run-x", outputs, output_dir=output_dir)
                self.assertEqual(index.resolve("files", "/candidates/0"), ("file_record", str(ids[a])))
                self.assertEqual(index.resolve("files", "/inventory/0"), ("file_record", str(ids[b])))
                # Same path as a candidate: the candidate's row, not an id offset.
                self.assertEqual(index.resolve("files", "/inventory/1"), ("file_record", str(ids[a])))
                self.assertEqual(index.resolve("files", "/inventory/2"), ("file_record", str(ids[c])))
                self.assertIsNone(index.resolve("files", "/inventory/3"))
                self.assertIsNone(index.resolve("files", "/inventory/x"))
                # Back to the locator the grid shows: inventory-only rows by their inventory position.
                self.assertEqual(index.locate("file_record", str(ids[a]))["locator"], "/candidates/0")
                self.assertEqual(index.locate("file_record", str(ids[b]))["locator"], "/inventory/0")
                self.assertEqual(index.locate("file_record", str(ids[c]))["locator"], "/inventory/2")
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
