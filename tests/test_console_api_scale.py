"""Console API scale (cases with about a million artifacts): ``view=list`` listing pages, the row index of
large ``files`` / ``timeline`` outputs and the ``/tree`` summary head scan."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import artifact_filter, create_app, fs_tree, json_rows, tree
    from rapidtriage.api.app.json_rows import JsonLayoutError, JsonRowIndex, LazyRows, large_output_index
    from rapidtriage.api.app.list_view import project_details

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.jobs import RunJobStore

TOKEN = "console-api-scale-token"

PROFILE = {"stages": [{"name": "mft", "checks": [{"id": i, "ok": True} for i in range(5)]}], "version": 3}


def artifact(index: int) -> dict[str, object]:
    return {
        "artifact_type": "mft-entry",
        "path": rf"C:\Evidence\$MFT#{index}",
        "details": {
            "file_name": f"file{index}.txt",
            "entry_number": index,
            "risk_flags": ["deleted"],
            "mft_full_parser_profile": PROFILE,
            "record_header_samples": [{"offset": 0, "bytes": "46494c45"}],
            "raw": {"sender": "kim", "nested": {"a": 1}, "ids": [1, 2]},
            "event_data": {"TargetUserName": "admin"},
            "commercial_uplift_evidence": {"source_refs": ["service:Slack"], "matrix": {"x": 1}, "grade": "B"},
        },
    }


ARTIFACTS = [artifact(i) for i in range(3)]
FILES = {
    "command": "files",
    "root": "C:\\Users",
    "summary": {"category_counts": {"documents": 3}},
    "candidates": [{"path": rf"C:\Users\a\doc{i}.docx", "name": f"doc{i}.docx", "categories": ["documents"]} for i in range(3)],
    "duplicate_content_groups": [{"sha256": "ab", "paths": ["a", "b"], "file_count": 2}],
    "inventory": [{"path": rf"C:\Windows\x{i}.exe", "name": f"x{i}.exe", "categories": ["executables"]} for i in range(4)],
    "hash_cache_manifest": {"entries": 7},
}
TIMELINE = {
    "command": "timeline",
    # Record order is not time order; e5 has no time.
    "events": [
        {"timestamp": f"2025-05-2{day}T01:00:00Z", "event_type": f"e{i}", "details": {"n": i}}
        for i, day in enumerate((2, 0, 4, 1, 3))
    ]
    + [{"timestamp": None, "event_type": "e5", "details": {}}],
    "summary": {"event_count": 5},
}


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class ConsoleApiScaleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        run_dir = base / "run"
        run_dir.mkdir()
        records = run_dir / "windows-filesystem.jsonl"
        records.write_text("".join(json.dumps(row) + "\n" for row in ARTIFACTS), encoding="utf-8")
        outputs: dict[str, object] = {
            "artifacts_windows-filesystem": {
                "record_count": len(ARTIFACTS),
                "summary": {"artifact_count": len(ARTIFACTS), "artifact_type_counts": {"mft-entry": len(ARTIFACTS)}},
                "artifact_type_profiles": {"mft-entry": {"provider": "ntfs"}},
                "records_path": str(records),
                "artifacts": [],
            },
            "files": FILES,
            "timeline": TIMELINE,
        }
        summary_outputs: dict[str, str] = {}
        self.paths: dict[str, Path] = {}
        for name, payload in outputs.items():
            path = run_dir / f"{name}.json"
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            summary_outputs[name] = str(path)
            self.paths[name] = path
        summary_path = run_dir / "rapidtriage-run-summary.json"
        summary_outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(base / "evidence"),
                    "output_dir": str(run_dir),
                    "source": {"type": "directory", "analysis_root": str(base / "evidence")},
                    "outputs": summary_outputs,
                    "summary": {"counts": {"artifacts": len(ARTIFACTS), "files": 3, "timeline_events": 6}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def call(self, endpoint: str, query: str = "", expect: int = 200) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/{endpoint}?{query}")
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    # --- view=list ---------------------------------------------------------------------

    def test_artifacts_list_view_drops_nested_details_and_keeps_grid_fields(self) -> None:
        full = self.call("artifacts", "kind=windows-filesystem&limit=10")["artifacts"]["windows-filesystem"]
        page = self.call("artifacts", "kind=windows-filesystem&limit=10&view=list")["artifacts"]["windows-filesystem"]
        self.assertIn("mft_full_parser_profile", full["artifacts"][0]["details"])
        row = page["artifacts"][1]
        self.assertEqual(row["record_index"], 1)
        self.assertEqual(row["details_omitted"], ["mft_full_parser_profile", "record_header_samples"])
        self.assertEqual(row["details"]["file_name"], "file1.txt")
        self.assertEqual(row["details"]["risk_flags"], ["deleted"])
        self.assertEqual(row["details"]["raw"], {"sender": "kim", "ids": [1, 2]})
        self.assertEqual(row["details"]["event_data"], {"TargetUserName": "admin"})
        self.assertEqual(row["details"]["commercial_uplift_evidence"], {"source_refs": ["service:Slack"]})
        self.assertEqual(page["view"], "list")
        self.assertEqual(page["view_omitted"], ["artifact_type_profiles", "summary"])
        self.assertNotIn("pagination_manifest", page["pagination"])
        self.assertEqual(page["pagination"]["total"], len(ARTIFACTS))
        self.assertEqual(page["record_count"], len(ARTIFACTS))
        # The viewer's full row: the plain request at the record's offset.
        record = self.call("artifacts", "kind=windows-filesystem&offset=1&limit=1")["artifacts"]["windows-filesystem"]
        self.assertEqual(record["artifacts"][0]["details"], ARTIFACTS[1]["details"])

    def test_list_view_composes_with_cross_kind_filters(self) -> None:
        payload = self.call("artifacts", "limit=10&artifact_type=mft-entry&view=list")
        self.assertEqual(len(payload["cross_kind"]["order"]), len(ARTIFACTS))
        rows = payload["artifacts"]["windows-filesystem"]["artifacts"]
        self.assertTrue(all("mft_full_parser_profile" not in row["details"] for row in rows))

    def test_unknown_view_is_a_korean_422(self) -> None:
        for endpoint in ("artifacts", "files", "timeline"):
            detail = self.call(endpoint, "limit=1&view=full", expect=422)["detail"]
            self.assertIn("list", detail)

    def test_files_and_timeline_list_view_drop_page_blocks(self) -> None:
        files = self.call("files", "limit=2&view=list")
        self.assertEqual([row["record_index"] for row in files["candidates"]], [0, 1])
        self.assertEqual(files["candidate_count"], 3)
        self.assertEqual(files["inventory_count"], 4)
        self.assertIn("ntfs_join", files)
        self.assertIn("flags_join", files)
        self.assertEqual(files["pagination"]["total"], 3)
        self.assertEqual(files["view_omitted"], ["duplicate_content_groups", "hash_cache_manifest", "summary"])
        self.assertIn("duplicate_content_groups", self.call("files", "limit=2"))
        timeline = self.call("timeline", "limit=2&view=list")
        self.assertEqual([event["event_type"] for event in timeline["events"]], ["e0", "e1"])
        self.assertNotIn("summary", timeline)
        self.assertNotIn("pagination_manifest", timeline["pagination"])

    def test_project_details_never_mutates_its_input(self) -> None:
        details = json.loads(json.dumps(ARTIFACTS[0]["details"]))
        projected, omitted = project_details(details)
        self.assertEqual(details, ARTIFACTS[0]["details"])
        self.assertIsNot(projected["raw"], details["raw"])
        self.assertEqual(omitted, ["mft_full_parser_profile", "record_header_samples"])

    # --- row index of large outputs ----------------------------------------------------

    def test_large_files_and_timeline_pages_come_from_the_row_index(self) -> None:
        queries = {
            "files": ["limit=2", "offset=2&limit=5", "scope=inventory&offset=1&limit=2", "limit=2&view=list"],
            "timeline": ["limit=2", "offset=3&limit=10", "cursor=offset:4&limit=1"],
        }
        expected = {(endpoint, query): self.call(endpoint, query) for endpoint, items in queries.items() for query in items}
        reads: list[str] = []
        original = self.store.read_output

        def tracked(run_id: str, name: str) -> dict[str, object]:
            reads.append(name)
            return original(run_id, name)

        with mock.patch.object(json_rows, "OUTPUT_JSON_CACHE_MAX_BYTES", 0), mock.patch.object(self.store, "read_output", tracked):
            for (endpoint, query), page in expected.items():
                self.assertEqual(self.call(endpoint, query), page, (endpoint, query))
            # Filtered pages still parse the whole output.
            self.assertEqual(len(self.call("files", "limit=5&category=documents")["candidates"]), 3)
        self.assertEqual(reads, ["files"])

    def test_index_matches_a_full_parse(self) -> None:
        path = self.paths["files"]
        index = JsonRowIndex.build(path)
        self.assertEqual(index.keys(), list(FILES))
        self.assertEqual(index.count("inventory"), 4)
        self.assertIsNone(index.count("summary"))
        self.assertEqual(index.rows("inventory", 1, 99), FILES["inventory"][1:])
        self.assertEqual(index.payload_with_placeholders(["candidates"])["candidates"], [])
        self.assertEqual(index.value("duplicate_content_groups"), FILES["duplicate_content_groups"])
        lazy = LazyRows(index, "candidates")
        self.assertEqual((len(lazy), lazy[-1], lazy[:2]), (3, FILES["candidates"][2], FILES["candidates"][:2]))

    def test_unindented_output_has_no_index(self) -> None:
        compact = Path(self.temp.name) / "compact.json"
        compact.write_text(json.dumps(FILES), encoding="utf-8")
        with self.assertRaises(JsonLayoutError):
            JsonRowIndex.build(compact)
        with mock.patch.object(json_rows, "OUTPUT_JSON_CACHE_MAX_BYTES", 0):
            self.assertIsNone(large_output_index(compact))
            self.assertIsNotNone(large_output_index(self.paths["files"]))
        self.assertIsNone(large_output_index(self.paths["files"]))  # small: the parsed-output cache serves it

    # --- whole-list timeline sort ---------------------------------------------------------

    def timeline_types(self, query: str) -> list[str]:
        return [event["event_type"] for event in self.call("timeline", query)["events"]]

    def test_timeline_sort_orders_the_whole_list_on_the_server(self) -> None:
        page = self.call("timeline", "sort=timestamp&order=desc&limit=3&view=list")
        self.assertEqual([event["record_index"] for event in page["events"]], [2, 4, 0])
        self.assertEqual((page["pagination"]["total"], page["pagination"]["has_more"]), (6, True))
        self.assertEqual(page["sort"], {"key": "timestamp", "order": "desc", "status": "ready", "progress": 1})
        self.assertEqual(self.timeline_types("sort=timestamp:desc&offset=3&limit=10"), ["e3", "e1", "e5"])
        ascending = self.call("timeline", "sort=timestamp&limit=10&locate=0")
        self.assertEqual([event["event_type"] for event in ascending["events"]], ["e1", "e3", "e0", "e4", "e2", "e5"])
        self.assertEqual(ascending["sort"]["position"], 2)
        window = "from=2025-05-21T00:00:00Z&to=2025-05-23T23:59:59Z"
        filtered = self.call("timeline", f"sort=timestamp&order=desc&limit=10&{window}")
        self.assertEqual([event["event_type"] for event in filtered["events"]], ["e4", "e0", "e3"])
        self.assertEqual(filtered["matched"], 3)
        self.assertIn("conditions", filtered["pagination"])
        queries = ["sort=timestamp&order=desc&limit=3", "sort=timestamp&limit=10&locate=0", f"sort=timestamp&order=desc&limit=10&{window}", f"limit=2&{window}"]
        expected = {query: self.call("timeline", query) for query in queries}
        with mock.patch.object(json_rows, "OUTPUT_JSON_CACHE_MAX_BYTES", 0):
            for query, page in expected.items():
                self.assertEqual(self.call("timeline", query), page, query)

    def test_timeline_sort_rejects_other_keys(self) -> None:
        self.call("timeline", "sort=event_type&limit=5", expect=422)
        self.call("timeline", "sort=timestamp&order=up&limit=5", expect=422)
        self.call("timeline", "sort=timestamp", expect=400)

    # --- filtered kind pages -------------------------------------------------------------

    def test_filtered_kind_pages_reuse_one_match_scan(self) -> None:
        queries = [
            "artifact_type=mft-entry&limit=2",
            "artifact_type=mft-entry&offset=1&limit=1",
            "artifact_type=mft-entry&offset=2&limit=5",
            "path_contains=MFT&limit=1&view=list",
        ]

        def pages() -> list[dict[str, object]]:
            return [self.call("artifacts", f"kind=windows-filesystem&{query}") for query in queries]

        with mock.patch.object(artifact_filter, "kind_matches", return_value=None):
            streamed = pages()  # the streaming scan, as before the cache
        artifact_filter._KIND_MATCHES.clear()
        self.assertEqual(pages(), streamed)
        with mock.patch.object(artifact_filter, "iter_jsonl_records", side_effect=AssertionError("rescanned")):
            self.assertEqual(pages(), streamed)

    def test_large_files_folder_pages_come_from_the_row_index(self) -> None:
        queries = ["path_prefix=a&limit=2", "path_prefix=a&offset=1&limit=5&view=list", "path_prefix=a&limit=5&category=documents"]
        expected = {query: self.call("files", query) for query in queries}
        self.assertEqual(len(expected["path_prefix=a&limit=2"]["candidates"]), 2)
        fs_tree.clear_fs_index_cache()
        reads: list[str] = []
        original = self.store.read_output

        def tracked(run_id: str, name: str) -> dict[str, object]:
            reads.append(name)
            return original(run_id, name)

        with mock.patch.object(json_rows, "OUTPUT_JSON_CACHE_MAX_BYTES", 0), mock.patch.object(self.store, "read_output", tracked):
            for query, page in expected.items():
                self.assertEqual(self.call("files", query), page, query)
        self.assertEqual(reads, [])  # the folder index too is built from the row index

    # --- /tree summary head scan ---------------------------------------------------------

    def test_indented_summary_is_read_without_a_full_parse(self) -> None:
        with mock.patch.object(tree, "read_output_json", side_effect=AssertionError("full parse")):
            self.assertEqual(tree.read_output_summary(self.paths["files"]), FILES["summary"])
            self.assertEqual(tree.read_output_key(self.paths["timeline"], "summary"), TIMELINE["summary"])

    def test_head_scan_grows_past_the_window_and_skips_nested_keys(self) -> None:
        path = Path(self.temp.name) / "nested.json"
        summary = {"counts": list(range(400))}
        path.write_text(json.dumps({"meta": {"summary": "x"}, "n": "\"summary\": 1", "summary": summary}, indent=2), encoding="utf-8")
        # The top-level key is inside the first 96 bytes, its value is not.
        with mock.patch.object(tree, "SUMMARY_SCAN_BYTES", 96), mock.patch.object(
            tree, "read_output_json", side_effect=AssertionError("full parse")
        ):
            self.assertEqual(tree.read_output_key(path, "summary"), summary)
        with mock.patch.object(tree, "_scan_output_key", side_effect=AssertionError("rescanned")):
            self.assertEqual(tree.read_output_key(path, "summary"), summary)  # cached per file revision


if __name__ == "__main__":
    unittest.main()
