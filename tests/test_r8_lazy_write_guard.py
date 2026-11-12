"""R8 T-133 (D37): read-only results — the index / cache lazy writes stay in memory.

* AST: every file-system write in the nine explorer / index modules is reached only through a
  persist guard (``may_persist`` / ``index_persist_enabled``), a state-changing route the read-only
  gate refuses, or the run-completion step (``tests/lazy_write_ast.py``).
* the six screens (timeline, map, families, folder explorer, registry explorer, sort) answer on a
  read-only run whose saved index files are missing, without calling the index writers, and leave
  the evidence folder (the run folder inside it) byte-identical.
* a normal run whose index files are missing writes back exactly the files the run step wrote
  (same names; the cache file list is unchanged).
"""

from __future__ import annotations

import ast
import unittest
from unittest import mock

from rapidtriage.api.app import families, geo_index, timeline_index
from tests.lazy_write_ast import API_APP, ROOT, Package, is_write, units_of
from tests.test_r8_import_readonly import Base, snapshot

#: T-133 targets (plan appendix F row T-133, v2 file list).
INDEX_MODULES = (
    "timeline_index.py",
    "geo_index.py",
    "families.py",
    "fs_tree.py",
    "files_ntfs.py",
    "registry_tree.py",
    "artifact_sort.py",
    "timeline_hist.py",
    "files_index.py",
)
#: Index / cache files the run step writes next to the outputs and the API rebuilds on demand.
LAZY_INDEX_FILES = (
    "rapidtriage-timeline-index.bin",
    "rapidtriage-geo-index.json",
    "rapidtriage-families.jsonl",
    "rapidtriage-dedup.json",
    "rapidtriage-irregular.json",
)
#: Screen -> requests ``(path after /api/runs/{run_id}/, query, expected status)``.
SCREENS: dict[str, tuple[tuple[str, dict[str, str], int], ...]] = {
    "timeline": (
        ("timeline", {"limit": "50"}, 200),
        ("timeline", {"limit": "50", "q": "wallet", "group": "1"}, 200),
        ("timeline", {"limit": "50", "offhours": "1", "tz": "+09:00"}, 200),
        ("timeline-histogram", {}, 200),
    ),
    "map": (
        ("geo-clusters", {}, 200),
        ("artifacts", {"kind": "media-image", "geo": "-90,-180,90,180", "limit": "20"}, 200),
    ),
    "families": (
        ("dedup/summary", {}, 200),
        ("irregular/summary", {}, 200),
        ("family-expansion", {"ref": "files::/candidates/0"}, 200),
        ("families/files%3A%3A%2Fcandidates%2F0", {}, 200),
        ("timeline", {"limit": "20", "dup": "any"}, 200),
    ),
    "folders": (
        ("fs-tree", {}, 200),
        ("fs-tree", {"path": "Users"}, 200),
        ("fs-tree", {"scope": "inventory"}, 200),
        ("files", {"limit": "20"}, 200),
    ),
    "registry": (
        ("registry-tree", {}, 200),
        ("registry-values", {}, 404),  # the sample evidence has no hive: answered, nothing built
    ),
    "sort": (
        ("artifacts", {"kind": "recent-files", "sort": "modified_at", "order": "desc", "limit": "20"}, 200),
        ("artifacts", {"kind": "recent-files", "sort": "modified_at", "order": "asc", "limit": "20"}, 200),
    ),
}


class IndexWriteAstTests(unittest.TestCase):
    package: Package

    @classmethod
    def setUpClass(cls) -> None:
        cls.package = Package()

    def test_every_index_module_write_asks_a_persist_guard(self) -> None:
        checked = 0
        writers = 0
        for name in INDEX_MODULES:
            with self.subTest(name):
                sites, problems = self.package.unguarded(API_APP / name)
                checked += 1
                writers += len(sites)
                self.assertEqual(problems, [])
        self.assertEqual(checked, 9)
        self.assertGreaterEqual(writers, 9)  # timeline / geo / families each write (temp, replace, cleanup)

    def test_the_walk_sees_writes_and_guards(self) -> None:
        source = (
            "import os, sqlite3\n"
            "from pathlib import Path\n"
            "def r8_probe_unguarded_writer(p):\n    Path(p).write_text('x')\n"
            "def guarded(p):\n    if may_persist(p):\n        open(p, 'w').close()\n"
            "def reader(p):\n    open(p, 'rb').close()\n    sqlite3.connect(f'{p}?mode=ro', uri=True)\n"
        )
        tree = ast.parse(source)
        calls = [is_write(node) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertEqual(sorted(call for call in calls if call), ["open(write)", "write_text"])
        units = {unit.name: unit for unit in units_of(ROOT / "probe.py", tree)}
        self.assertIsNotNone(self.package.unsafe_reason(units["r8_probe_unguarded_writer"]))  # nothing guarded calls it
        self.assertIsNone(self.package.unsafe_reason(units["guarded"]))


class ScreenFixture(Base):
    """A read-only run (output folder inside the evidence) whose saved index files are gone."""

    def setUp(self) -> None:
        super().setUp()
        self.legacy = self.copy_output(self.evidence / "legacy-out")
        for name in LAZY_INDEX_FILES:
            (self.legacy / name).unlink()
        response = self.import_folder(self.legacy)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["readonly_reason"], "OUTPUT_INSIDE_EVIDENCE")
        self.run_id = response.json()["run_id"]

    def open_screen(self, run_id: str, requests) -> list[dict]:  # type: ignore[no-untyped-def]
        bodies = []
        for path, params, expected in requests:
            response = self.client.get(f"/api/runs/{run_id}/{path}", params=params)
            self.assertEqual(response.status_code, expected, f"{path} {params}: {response.text[:300]}")
            bodies.append(response.json())
        timeline_index.wait_for_background()
        return bodies


class ReadOnlyIndexScreenTests(ScreenFixture):
    def setUp(self) -> None:
        super().setUp()
        self.writers = {
            "save_index": mock.patch.object(timeline_index, "save_index", wraps=timeline_index.save_index),
            "write_geo_index_file": mock.patch.object(geo_index, "write_geo_index_file", wraps=geo_index.write_geo_index_file),
            "write_derived_files": mock.patch.object(families, "write_derived_files", wraps=families.write_derived_files),
        }
        self.spies = {name: patcher.start() for name, patcher in self.writers.items()}
        for patcher in self.writers.values():
            self.addCleanup(patcher.stop)

    def assert_screen_writes_nothing(self, screen: str) -> list[dict]:
        before = snapshot(self.evidence)
        bodies = self.open_screen(self.run_id, SCREENS[screen])
        self.assertEqual(snapshot(self.evidence), before, screen)
        for name, spy in self.spies.items():
            self.assertEqual(spy.call_count, 0, f"{screen}: {name} reached on a read-only run")
        for name in LAZY_INDEX_FILES:
            self.assertFalse((self.legacy / name).exists(), name)
        return bodies

    def test_timeline(self) -> None:
        first = self.assert_screen_writes_nothing("timeline")[0]
        self.assertGreater(first["pagination"]["total"], 0)

    def test_map(self) -> None:
        clusters = self.assert_screen_writes_nothing("map")[0]
        self.assertEqual(clusters["run_id"], self.run_id)

    def test_families(self) -> None:
        bodies = self.assert_screen_writes_nothing("families")
        self.assertEqual(bodies[0]["source"], "memory")  # built, kept in memory

    def test_folder_explorer(self) -> None:
        tree = self.assert_screen_writes_nothing("folders")[0]
        self.assertGreater(tree["node"]["file_count"], 0)

    def test_registry_explorer(self) -> None:
        self.assert_screen_writes_nothing("registry")

    def test_sort(self) -> None:
        self.assert_screen_writes_nothing("sort")


class NormalRunCacheFilesTests(ScreenFixture):
    def test_normal_run_writes_back_the_same_cache_files(self) -> None:
        normal = self.copy_output(self.base / "normal-out")
        expected = sorted(str(path.relative_to(normal)) for path in normal.rglob("*"))
        for name in LAZY_INDEX_FILES:
            (normal / name).unlink()
        response = self.import_folder(normal)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIsNone(response.json()["readonly_reason"])
        normal_id = response.json()["run_id"]
        for requests in SCREENS.values():
            self.open_screen(normal_id, requests)
        self.assertEqual(sorted(str(path.relative_to(normal)) for path in normal.rglob("*")), expected)


if __name__ == "__main__":
    unittest.main()
