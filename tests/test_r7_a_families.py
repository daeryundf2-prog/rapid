"""R7 갈래 A 계열 (Nuix R1): relations derived from the run outputs, the families API, ``family=``
on the listings, the selection expansion and the run-completion files (Q-A1, Q-A2, Q-A6)."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.families import (
        FAMILIES_SERVICE,
        collect_sources,
        derive,
        load_or_build,
        write_run_families,
    )
    from rapidtriage.api.app.row_conditions import MATCH_CACHE

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.core.families import (
    FAMILIES_FILE_NAME,
    FamilyIndex,
    base_ref,
    family_index_from_records,
    iter_family_records,
    make_ref,
    parse_ref,
)
from rapidtriage.core.jobs import RunJobStore
from tests import r7_a_fixtures as fx

TOKEN = "r7-a-families-token"
EMAIL = "artifacts:email:/artifacts/"


class RefTests(unittest.TestCase):
    def test_refs_round_trip_and_reject_malformed(self) -> None:
        for ref in (
            "artifacts:email:/artifacts/3",
            "files::/candidates/12",
            "files::/inventory/0",
            "analysis:20260101T000000-ab:/rows/0",
            "artifacts:generic-documents:/artifacts/5#entry:2",
            "artifacts:email:/artifacts/1#attachment:0",
            r"source::C:\ev\pagefile.sys",
        ):
            with self.subTest(ref=ref):
                parsed = parse_ref(ref)
                self.assertIsNotNone(parsed)
                assert parsed is not None
                self.assertEqual(make_ref(*parsed), ref)
        for bad in ("", "artifacts::/artifacts/1", "files:x:/candidates/1", "nope:k:/x", "artifacts:email:/rows/1", "artifacts:email:/artifacts/1#entry:x", "x" * 3000):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_ref(bad))
        self.assertEqual(base_ref("artifacts:k:/artifacts/5#entry:2"), "artifacts:k:/artifacts/5")

    def test_cycles_and_second_parents_are_refused(self) -> None:
        index = FamilyIndex()
        self.assertTrue(index.add("a:k:/artifacts/1", "artifacts:k:/artifacts/2", "attachment"))
        self.assertFalse(index.add("artifacts:k:/artifacts/3", "artifacts:k:/artifacts/2", "attachment"))
        self.assertFalse(index.add("artifacts:k:/artifacts/2", "a:k:/artifacts/1", "attachment"))


class DeriveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.outputs = fx.write_run(self.run_dir)

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
    def test_synthetic_run_relations_match_100_percent(self) -> None:
        derived = derive(collect_sources(self.outputs, self.run_dir))
        families = derived.families
        got = sorted((parent, child, relation) for child, (parent, relation) in families.parent.items())
        self.assertEqual(got, sorted(fx.EXPECTED_EDGES))
        self.assertEqual(families.edge_count, len(fx.EXPECTED_EDGES))
        # Directions: an attachment's top-level item is its message (never across the PST container).
        self.assertEqual(families.top(EMAIL + "2"), EMAIL + "1")
        self.assertEqual(families.ancestors(EMAIL + "2"), [EMAIL + "1", EMAIL + "0"])
        self.assertEqual(families.family(EMAIL + "2"), [EMAIL + "1", EMAIL + "2", EMAIL + "3"])
        self.assertEqual(families.top(EMAIL + "1"), EMAIL + "1")
        # Immaterial: the inline logo and the archive folder entry.
        self.assertFalse(families.info(EMAIL + "3").material)
        self.assertFalse(families.info("artifacts:generic-documents:/artifacts/0#entry:0").material)
        self.assertTrue(families.info("artifacts:generic-documents:/artifacts/0#entry:1").material)
        # Carved rows hang under the files row of their source; the extracted app row under its member.
        self.assertEqual(families.top(f"analysis:{fx.CARVE_ID}:/rows/1"), "files::/candidates/0")
        self.assertEqual(families.top("artifacts:mobile-export:/artifacts/3"), "artifacts:mobile-export:/artifacts/0")

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
    def test_relations_do_not_depend_on_row_order(self) -> None:
        reversed_rows = {kind: list(reversed(rows)) for kind, rows in fx.KINDS.items()}
        with mock.patch.dict(fx.KINDS, reversed_rows):
            outputs = fx.write_run(self.run_dir)
            derived = derive(collect_sources(outputs, self.run_dir))
        count = {kind: len(rows) for kind, rows in fx.KINDS.items()}

        def flip(ref: str) -> str:
            collection, kind, locator = parse_ref(ref) or ("", "", "")
            if collection != "artifacts":
                return ref
            head, mark, tail = locator.partition("#")
            number = int(head.rsplit("/", 1)[1])
            return make_ref(collection, kind, f"/artifacts/{count[kind] - 1 - number}{mark}{tail}")

        got = sorted((flip(parent), flip(child), relation) for child, (parent, relation) in derived.families.parent.items())
        self.assertEqual(got, sorted(fx.EXPECTED_EDGES))

    def test_records_round_trip(self) -> None:
        if not HAS_FASTAPI:
            self.skipTest("fastapi is required")
        families = derive(collect_sources(self.outputs, self.run_dir)).families
        records = list(iter_family_records(families))
        self.assertEqual(len(records), len(fx.EXPECTED_EDGES))
        rebuilt = family_index_from_records(json.loads(json.dumps(records)))
        self.assertEqual(rebuilt.parent, families.parent)
        self.assertEqual(rebuilt.children, families.children)
        with self.assertRaises(ValueError):
            family_index_from_records([{"parent_locator": "bad", "child_locator": EMAIL + "1", "relation": "x"}])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for API tests")
class FamiliesApiTests(unittest.TestCase):
    def setUp(self) -> None:
        FAMILIES_SERVICE.clear()
        MATCH_CACHE.clear()
        self.addCleanup(FAMILIES_SERVICE.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.outputs = fx.write_run(self.run_dir)
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, url: str, expect: int = 200) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}/{url}")
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    def family(self, ref: str, direction: str = "family", extra: str = "") -> dict[str, object]:
        return self.get(f"families/{quote(ref, safe='')}?direction={direction}{extra}")

    def test_q_a1_attachment_parent_and_siblings(self) -> None:
        body = self.family(EMAIL + "2")
        self.assertTrue(body["has_family"])
        self.assertEqual(body["parent"]["ref"], EMAIL + "1")
        self.assertEqual(body["parent"]["title"], "견적서 송부")
        self.assertEqual(body["top"]["ref"], EMAIL + "1")
        self.assertEqual([node["ref"] for node in body["siblings"]], [EMAIL + "3"])
        self.assertEqual([node["ref"] for node in body["tree"]["items"]], [EMAIL + "2", EMAIL + "3"])
        self.assertEqual(body["item"]["relation_label"], "첨부")
        self.assertEqual(body["counts"], {"members": 3, "descendants": 2, "material": 2, "rows": 3})
        up = self.family(EMAIL + "2", "up")
        self.assertEqual([node["ref"] for node in up["ancestors"]], [EMAIL + "1", EMAIL + "0"])
        self.assertNotIn("tree", up)
        # "상위 항목으로" lands on one mail row whose family lists every attachment.
        listing = self.get(f"artifacts?limit=50&family={quote(EMAIL + '1', safe='')}")
        order = [tuple(item) for item in listing["cross_kind"]["order"]]
        self.assertEqual(order, [("email", 1), ("email", 2), ("email", 3)])

    def test_q_a2_zip_members_are_virtual_children_with_preview_paths(self) -> None:
        ref = "artifacts:generic-documents:/artifacts/0"
        body = self.family(ref, "down", f"&source_path={quote(fx.ZIP, safe='')}")
        items = body["tree"]["items"]
        self.assertEqual(len(items), 4)
        self.assertTrue(all(item["virtual"] and not item["navigable"] for item in items))
        self.assertEqual([item["title"] for item in items], ["보고서/", "보고서/1분기.xlsx", "보고서/2분기.xlsx", "readme.txt"])
        self.assertNotIn("source_path", items[0])  # a folder entry has no preview
        self.assertEqual(items[1]["source_path"], f"{fx.ZIP}::보고서/1분기.xlsx")
        self.assertEqual(items[1]["row_ref"], ref)
        self.assertEqual(body["counts"]["material"], 4)  # the archive row + 3 file entries
        # A member's own family view: the archive row is its parent.
        member = self.family(ref + "#entry:3")
        self.assertEqual(member["parent"]["ref"], ref)
        self.assertEqual(len(member["siblings"]), 3)

    def test_unrelated_row_and_bad_requests(self) -> None:
        body = self.family("artifacts:generic-documents:/artifacts/3")
        self.assertFalse(body["has_family"])
        self.assertIsNone(body["parent"])
        self.assertEqual(body["tree"]["items"], [])
        self.assertTrue(body["is_top"])
        self.assertIn("항목 참조", self.get("families/not-a-ref", 422)["detail"])
        self.assertIn("direction", self.get(f"families/{quote(EMAIL + '1', safe='')}?direction=sideways", 422)["detail"])
        self.assertIn("family", self.get("artifacts?limit=10&family=bogus", 422)["detail"])

    def test_family_condition_on_files_artifacts_and_timeline(self) -> None:
        carve_family = self.get(f"files?limit=50&family={quote(f'analysis:{fx.CARVE_ID}:/rows/1', safe='')}")
        self.assertEqual([row["record_index"] for row in carve_family["candidates"]], [0])
        self.assertEqual(carve_family["pagination"]["conditions"]["family"], [f"analysis:{fx.CARVE_ID}:/rows/1"])
        # Repeated family=: the union of the families (the selection expansion uses it).
        union = self.get(f"artifacts?limit=50&kind=email&family={quote(EMAIL + '2', safe='')}&family={quote(EMAIL + '8', safe='')}")
        self.assertEqual([row["record_index"] for row in union["artifacts"]["email"]["artifacts"]], [1, 2, 3, 7, 8])
        backup = self.get(f"artifacts?limit=50&kind=mobile-export&family={quote('artifacts:mobile-export:/artifacts/3', safe='')}")
        self.assertEqual([row["record_index"] for row in backup["artifacts"]["mobile-export"]["artifacts"]], [0, 1, 2, 3])
        timeline = self.get(f"timeline?limit=50&family={quote(EMAIL + '1', safe='')}")
        self.assertEqual([row["record_index"] for row in timeline["events"]], [0, 1])
        # AND with another condition: the time window keeps the first event only.
        narrowed = self.get(f"timeline?limit=50&family={quote(EMAIL + '1', safe='')}&to=2025-05-26T01:15:42Z")
        self.assertEqual([row["record_index"] for row in narrowed["events"]], [0])

    def test_family_condition_through_sort_path_and_flag_free_paths(self) -> None:
        ref = quote(EMAIL + "4", safe="")
        deadline = time.monotonic() + 20
        while True:  # the sort index builds in the background on the first request
            sorted_page = self.get(f"artifacts?limit=50&kind=email&sort=details.filename&family={ref}")
            if sorted_page["artifacts"]["email"].get("sort", {}).get("status") != "building" or time.monotonic() > deadline:
                break
            time.sleep(0.05)
        self.assertEqual(sorted(row["record_index"] for row in sorted_page["artifacts"]["email"]["artifacts"]), [4, 5, 6])
        single = self.get(f"artifacts?limit=50&kind=email&family={ref}")
        self.assertEqual([row["record_index"] for row in single["artifacts"]["email"]["artifacts"]], [4, 5, 6])
        self.assertEqual(single["artifacts"]["email"]["pagination"]["total"], 3)
        with_path = self.get(f"artifacts?limit=50&kind=email&path_contains=box.pst&family={ref}")
        self.assertEqual([row["record_index"] for row in with_path["artifacts"]["email"]["artifacts"]], [4, 5, 6])
        typed = self.get(f"artifacts?limit=50&artifact_type=email-attachment&family={ref}")
        self.assertEqual([tuple(item) for item in typed["cross_kind"]["order"]], [("email", 5), ("email", 6)])

    def test_listing_rows_carry_family_and_dedup_fields_once_ready(self) -> None:
        FAMILIES_SERVICE.get(self.run_id, self.outputs, self.run_dir)
        rows = self.get("artifacts?limit=50&kind=email")["artifacts"]["email"]["artifacts"]
        by_index = {row["record_index"]: row for row in rows}
        self.assertEqual(by_index[2]["family"]["parent"], EMAIL + "1")
        self.assertEqual(by_index[2]["family"]["parent_title"], "견적서 송부")
        self.assertEqual(by_index[1]["family"]["children"], 2)
        self.assertEqual(by_index[2]["dedup"], {"status": "duplicate", "count": 6})
        files = self.get("files?limit=50")["candidates"]
        self.assertEqual(files[2]["dedup"], {"status": "original", "count": 6})
        self.assertEqual(files[0]["family"]["children"], 2)
        self.assertNotIn("family", files[3])

    def test_q_a6_selection_expansion(self) -> None:
        body = self.get(
            "family-expansion?"
            + "&".join(f"ref={quote(ref, safe='')}" for ref in (EMAIL + "5", "artifacts:generic-documents:/artifacts/0#entry:2", "files::/candidates/6"))
        )
        refs = [item["ref"] for item in body["items"]]
        self.assertEqual(
            refs,
            [EMAIL + "5", EMAIL + "4", EMAIL + "6", "artifacts:generic-documents:/artifacts/0", "files::/candidates/6"],
        )
        self.assertEqual(body["requested"], 3)
        self.assertEqual(body["added"], 2)
        self.get("family-expansion", 422)
        self.assertIn("항목 참조", self.get("family-expansion?ref=bad", 422)["detail"])


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class FilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.outputs = fx.write_run(self.run_dir)

    def test_run_completion_files_are_read_back_and_go_stale(self) -> None:
        record = write_run_families(self.run_dir, self.outputs)
        self.assertEqual(record["status"], "completed", record)
        self.assertEqual(record["edges"], len(fx.EXPECTED_EDGES))
        for name in (FAMILIES_FILE_NAME, "rapidtriage-dedup.json", "rapidtriage-irregular.json"):
            self.assertTrue((self.run_dir / name).is_file(), name)
        header = json.loads((self.run_dir / FAMILIES_FILE_NAME).read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(header["format"], "rapidtriage-families-v1")
        sources = collect_sources(self.outputs, self.run_dir)
        stored = load_or_build(sources, self.run_dir)
        self.assertEqual(stored.source, "file")
        built = derive(sources)
        self.assertEqual(stored.families.parent, built.families.parent)
        self.assertEqual(stored.dedup.mode("family").status, built.dedup.mode("family").status)
        self.assertEqual(stored.irregular.summary(), built.irregular.summary())
        # A changed source (one more carve row) is a new stamp: rebuilt, not read.
        rows = self.run_dir / "analyses" / fx.CARVE_ID / "rows.jsonl"
        rows.write_text(rows.read_text(encoding="utf-8") + json.dumps(fx.CARVE_ROWS[0]) + "\n", encoding="utf-8", newline="\n")
        again = load_or_build(collect_sources(self.outputs, self.run_dir), self.run_dir)
        self.assertEqual(again.source, "built")
        self.assertEqual(len(again.families.children["files::/candidates/0"]), 3)

    def test_corrupt_file_is_rebuilt(self) -> None:
        write_run_families(self.run_dir, self.outputs)
        path = self.run_dir / "rapidtriage-dedup.json"
        path.write_text(path.read_text(encoding="utf-8")[:-40], encoding="utf-8")
        derived = load_or_build(collect_sources(self.outputs, self.run_dir), self.run_dir)
        self.assertEqual(derived.source, "built")

    def test_persist_off_keeps_memory_only(self) -> None:
        with mock.patch.dict(os.environ, {"RAPIDTRIAGE_INDEX_PERSIST": "0"}):
            derived = load_or_build(collect_sources(self.outputs, self.run_dir), self.run_dir)
        self.assertEqual(derived.source, "memory")
        self.assertFalse((self.run_dir / FAMILIES_FILE_NAME).exists())

    def test_persist_step_record_never_raises(self) -> None:
        from rapidtriage.core.run.persist import build_run_families

        record = build_run_families(self.run_dir / "missing", {"files": str(self.run_dir / "nope.json")})
        self.assertIn(record["status"], ("completed", "failed"))


if __name__ == "__main__":
    unittest.main()
