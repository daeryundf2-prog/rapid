"""``GET /files`` non-row sections (R6 S3 follow-up): paged responses no longer repeat the large
non-row sections of ``rapidtriage-files.json``; ``sections=`` and ``GET /files/sections`` serve them
on request and ``limit=0`` (full export) is unchanged."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.api.app.files_sections import (
    clear_sections_cache,
    parse_sections,
    section_names,
)
from rapidtriage.core.jobs import RunJobStore

TOKEN = "r6-files-sections-token"
SECTIONS = (
    "signature_mismatch_candidates",
    "hash_cache_manifest",
    "hash_cache_assessment",
    "duplicate_content_manifest",
    "duplicate_detection_assessment",
    "duplicate_content_groups",
    "fuzzy_text_duplicate_groups",
    "known_good_suppressed_candidates",
)


def files_payload(root: Path) -> dict[str, object]:
    groups = [
        {"group_id": f"g{index}", "sha256": f"{index:064x}", "file_count": 2, "paths": [str(root / f"a{index}.doc"), str(root / f"b{index}.doc")]}
        for index in range(25)
    ]
    rows = [
        {"path": str(root / f"f{index}.docx"), "name": f"f{index}.docx", "extension": ".docx", "size": index, "categories": ["documents"]}
        for index in range(30)
    ]
    return {
        "command": "files",
        "root": str(root),
        "generated_at": "2026-10-21T00:00:00",
        "filters": {"categories": ["documents"]},
        "summary": {"candidate_count": len(rows), "duplicate_group_count": len(groups)},
        "time_provenance": {"profile": "t"},
        "file_exclusions": {"count": 0},
        "known_good_suppression_profile": {"profile": "kg"},
        "known_good_suppressed_candidates": [],
        "file_signature_profile": {"checked_count": 30},
        "signature_mismatch_candidates": [{"name": "holiday.jpg", "detected": "zip"}],
        "hash_cache_manifest": {"profile": "hc", "entries": [{"sha256": "0" * 64}]},
        "hash_cache_assessment": {"component": "hash-cache", "status": "engineering"},
        "duplicate_content_manifest": {"group_count": len(groups), "groups": groups[:5]},
        "duplicate_detection_assessment": {"component": "duplicates", "groups": groups[:3]},
        "core_accuracy_gates": [{"gap_id": "#1"}],
        "duplicate_content_groups": groups,
        "fuzzy_text_duplicate_groups": [{"group_id": "fz0", "paths": []}],
        "candidates": rows,
        "inventory": [],
        "scan_scope_root": str(root),
    }


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FilesSectionsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_sections_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        self.payload = files_payload(base / "evidence")
        self.files_path = self.run_dir / "rapidtriage-files.json"
        self.files_path.write_text(json.dumps(self.payload), encoding="utf-8")
        summary_path = self.run_dir / "rapidtriage-run-summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(self.run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": {"files": str(self.files_path), "summary": str(summary_path)},
                    "summary": {"counts": {}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, path: str = "", **params: object):
        return self.client.get(f"/api/runs/{self.run_id}/files{path}", params=params)

    def page(self, **params: object) -> dict[str, object]:
        response = self.get(**params)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_default_page_carries_rows_and_header_but_no_sections(self) -> None:
        page = self.page(limit=10)
        for name in SECTIONS:
            self.assertNotIn(name, page)
        self.assertEqual(len(page["candidates"]), 10)
        self.assertEqual(page["pagination"]["total"], 30)
        for key in ("summary", "filters", "time_provenance", "file_signature_profile", "core_accuracy_gates", "command", "root"):
            self.assertIn(key, page)
        self.assertEqual(page["summary"]["duplicate_group_count"], 25)
        self.assertNotIn("sections_missing", page)

    def test_sections_available_lists_every_section_with_accurate_size_and_count(self) -> None:
        page = self.page(limit=5)
        available = {entry["name"]: entry for entry in page["sections_available"]}
        self.assertEqual(set(available), set(SECTIONS))
        for name in SECTIONS:
            value = self.payload[name]
            encoded = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            self.assertEqual(available[name]["approx_bytes"], encoded, name)
            self.assertEqual(available[name]["item_count"], len(value), name)  # type: ignore[arg-type]

    def test_sections_param_includes_only_the_requested_sections(self) -> None:
        page = self.page(limit=5, sections="duplicate_content_groups,hash_cache_manifest")
        self.assertEqual(page["duplicate_content_groups"], self.payload["duplicate_content_groups"])
        self.assertEqual(page["hash_cache_manifest"], self.payload["hash_cache_manifest"])
        for name in set(SECTIONS) - {"duplicate_content_groups", "hash_cache_manifest"}:
            self.assertNotIn(name, page)
        repeated = self.page(limit=5, sections=["duplicate_content_groups", "fuzzy_text_duplicate_groups"])
        self.assertIn("fuzzy_text_duplicate_groups", repeated)
        self.assertIn("duplicate_content_groups", repeated)

    def test_sections_all_is_the_old_page(self) -> None:
        page = self.page(limit=5, sections="all")
        for name in SECTIONS:
            self.assertEqual(page[name], self.payload[name])
        self.assertIn("sections_available", page)

    def test_unknown_section_is_reported_and_malformed_is_a_korean_422(self) -> None:
        page = self.page(limit=5, sections="nope,duplicate_content_groups")
        self.assertEqual(page["sections_missing"], ["nope"])
        self.assertIn("duplicate_content_groups", page)
        response = self.get(limit=5, sections="../etc")
        self.assertEqual(response.status_code, 422)
        self.assertIn("sections 값이 올바르지 않습니다", response.json()["detail"])

    def test_filtered_pages_exclude_sections_too(self) -> None:
        for params in ({"category": "documents"}, {"sort": "flags"}, {"from": "2020-01-01"}, {"path_prefix": ""}):
            response = self.get(limit=5, **params)
            self.assertEqual(response.status_code, 200, (params, response.text))
            page = response.json()
            for name in SECTIONS:
                self.assertNotIn(name, page, params)
            self.assertIn("sections_available", page)

    def test_limit_zero_full_export_is_unchanged(self) -> None:
        page = self.page()
        for name in SECTIONS:
            self.assertEqual(page[name], self.payload[name])
        self.assertNotIn("sections_available", page)
        self.assertEqual(len(page["candidates"]), 30)

    def test_section_endpoint_returns_one_section_and_pages_lists(self) -> None:
        response = self.get("/sections", name="duplicate_content_groups")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["kind"], "list")
        self.assertEqual(body["item_count"], 25)
        self.assertEqual(body["value"], self.payload["duplicate_content_groups"])
        self.assertNotIn("pagination", body)
        paged = self.get("/sections", name="duplicate_content_groups", offset=20, limit=10).json()
        self.assertEqual([group["group_id"] for group in paged["value"]], [f"g{index}" for index in range(20, 25)])
        self.assertEqual(paged["pagination"], {"offset": 20, "limit": 10, "returned": 5, "total": 25, "has_more": False})
        obj = self.get("/sections", name="hash_cache_assessment", limit=1).json()
        self.assertEqual(obj["kind"], "object")
        self.assertEqual(obj["value"], self.payload["hash_cache_assessment"])
        page = self.page(limit=1)
        size = next(entry["approx_bytes"] for entry in page["sections_available"] if entry["name"] == "duplicate_content_groups")
        self.assertEqual(body["approx_bytes"], size)

    def test_section_endpoint_errors(self) -> None:
        missing = self.get("/sections", name="candidates")
        self.assertEqual(missing.status_code, 404)
        self.assertIn("섹션이 없습니다", missing.json()["detail"])
        self.assertEqual(self.get("/sections", name="summary").status_code, 404)
        self.assertEqual(self.get("/sections", name="a/b").status_code, 422)
        self.assertEqual(self.get("/sections").status_code, 422)

    def test_sizes_follow_a_rewritten_output(self) -> None:
        self.page(limit=1)
        self.payload["duplicate_content_groups"] = self.payload["duplicate_content_groups"][:2]  # type: ignore[index]
        self.files_path.write_text(json.dumps(self.payload) + " " * 7, encoding="utf-8")
        page = self.page(limit=1)
        entry = next(item for item in page["sections_available"] if item["name"] == "duplicate_content_groups")
        self.assertEqual(entry["item_count"], 2)


class FilesSectionsUnitTests(unittest.TestCase):
    def test_section_names_skip_rows_header_and_scalars(self) -> None:
        payload = {"candidates": [], "inventory": [], "summary": {}, "command": "files", "big": [1], "obj": {"a": 1}}
        self.assertEqual(section_names(payload), ["big", "obj"])

    def test_parse_sections(self) -> None:
        self.assertEqual(parse_sections(["a,b", " c ", ""]), (False, frozenset({"a", "b", "c"})))
        self.assertEqual(parse_sections(["all,a"]), (True, frozenset({"a"})))


if __name__ == "__main__":
    unittest.main()
