from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

HAS_FASTAPI = True
try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

if HAS_FASTAPI:
    from rapidtriage.api.app import create_app
    from rapidtriage.api.app.routes_browse import BROWSE_ENTRY_LIMIT
from rapidtriage.core.jobs import (
    RunJobStore,
    invalidate_output_json_cache,
    read_output_json,
)

TEST_API_TOKEN = "rapidtriage-test-token"


def _write_run_output(output_dir: Path, name: str, payload: dict) -> Path:
    path = output_dir / f"rapidtriage-{name}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _import_fixture_run(store: RunJobStore, tmp_dir: Path, *, outputs: dict[str, Path]) -> str:
    output_dir = tmp_dir / "run-out"
    output_dir.mkdir(exist_ok=True)
    summary_path = output_dir / "rapidtriage-run-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "mode": "hacking",
                "root": str(tmp_dir / "case-root"),
                "output_dir": str(output_dir),
                "input_kind": "folder",
                "summary": {},
                "outputs": {name: str(path) for name, path in outputs.items()},
            }
        ),
        encoding="utf-8",
    )
    return store.import_completed_run(output_dir).run_id


class RunOutputCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        invalidate_output_json_cache()

    def tearDown(self) -> None:
        invalidate_output_json_cache()

    def test_read_output_caches_parsed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "run-out"
            output_dir.mkdir()
            files_path = _write_run_output(output_dir, "files", {"candidates": [{"path": "a"}], "n": 1})
            store = RunJobStore()
            run_id = _import_fixture_run(store, tmp_dir, outputs={"files": files_path})

            first = store.read_output(run_id, "files")
            second = store.read_output(run_id, "files")

            self.assertIs(first, second)
            self.assertEqual(first["n"], 1)

    def test_read_output_reload_when_file_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "run-out"
            output_dir.mkdir()
            files_path = _write_run_output(output_dir, "files", {"candidates": [], "n": 1})
            store = RunJobStore()
            run_id = _import_fixture_run(store, tmp_dir, outputs={"files": files_path})
            first = store.read_output(run_id, "files")

            # mtime_ns + size are part of the cache key; bump both so a rewrite
            # on filesystems with coarse timestamp granularity still misses.
            time.sleep(0.01)
            files_path.write_text(json.dumps({"candidates": [{"path": "b"}], "n": 2}), encoding="utf-8")

            second = store.read_output(run_id, "files")

            self.assertIsNot(first, second)
            self.assertEqual(second["n"], 2)

    def test_invalidate_output_cache_drops_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "run-out"
            output_dir.mkdir()
            files_path = _write_run_output(output_dir, "files", {"candidates": [], "n": 1})
            store = RunJobStore()
            run_id = _import_fixture_run(store, tmp_dir, outputs={"files": files_path})

            first = store.read_output(run_id, "files")
            store.invalidate_output_cache(run_id)
            second = store.read_output(run_id, "files")

            self.assertIsNot(first, second)
            self.assertEqual(second["n"], 1)

            third = store.read_output(run_id, "files")
            invalidate_output_json_cache(files_path)
            fourth = store.read_output(run_id, "files")

            self.assertIsNot(third, fourth)

    def test_read_output_json_missing_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                read_output_json(Path(tmp) / "missing.json")

    def test_remove_run_drops_cached_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            output_dir = tmp_dir / "run-out"
            output_dir.mkdir()
            files_path = _write_run_output(output_dir, "files", {"candidates": [], "n": 1})
            store = RunJobStore()
            run_id = _import_fixture_run(store, tmp_dir, outputs={"files": files_path})

            first = store.read_output(run_id, "files")
            store.remove(run_id)

            self.assertIsNot(first, read_output_json(files_path))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API tests")
class BrowseApiTests(unittest.TestCase):
    def _client(self):
        return TestClient(
            create_app(RunJobStore(), auth_token=TEST_API_TOKEN),
            headers={"X-RapidTriage-Token": TEST_API_TOKEN},
        )

    def test_browse_requires_auth_token(self) -> None:
        client = TestClient(create_app(RunJobStore(), auth_token=TEST_API_TOKEN))
        self.assertEqual(client.get("/api/browse").status_code, 401)

    def test_browse_roots_without_path(self) -> None:
        client = self._client()
        response = client.get("/api/browse")

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertIsNone(payload["path"])
        self.assertGreaterEqual(len(payload["entries"]), 1)
        for entry in payload["entries"]:
            self.assertTrue(entry["is_dir"])
            self.assertTrue(entry["path"])

    def test_browse_directory_lists_directories_first_and_skips_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "zzz_dir").mkdir()
            (root / "aaa_dir").mkdir()
            (root / "b.txt").write_text("hello", encoding="utf-8")
            (root / "a.txt").write_text("hi", encoding="utf-8")
            (root / ".hidden").write_text("secret", encoding="utf-8")
            (root / ".hidden_dir").mkdir()

            response = self._client().get("/api/browse", params={"path": str(root)})

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["path"], str(root.resolve()))
            self.assertFalse(payload["truncated"])
            names = [entry["name"] for entry in payload["entries"]]
            self.assertEqual(names, ["aaa_dir", "zzz_dir", "a.txt", "b.txt"])
            by_name = {entry["name"]: entry for entry in payload["entries"]}
            self.assertTrue(by_name["aaa_dir"]["is_dir"])
            self.assertIsNone(by_name["aaa_dir"]["size"])
            self.assertFalse(by_name["a.txt"]["is_dir"])
            self.assertEqual(by_name["a.txt"]["size"], 2)

    def test_browse_file_path_returns_single_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "evidence.txt"
            target.write_text("bytes", encoding="utf-8")

            response = self._client().get("/api/browse", params={"path": str(target)})

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["path"], str(target.resolve()))
            self.assertEqual(len(payload["entries"]), 1)
            self.assertEqual(payload["entries"][0]["name"], "evidence.txt")
            self.assertFalse(payload["entries"][0]["is_dir"])
            self.assertEqual(payload["entries"][0]["size"], 5)

    def test_browse_missing_path_returns_404(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            response = self._client().get("/api/browse", params={"path": str(missing)})

            self.assertEqual(response.status_code, 404)
            self.assertIn("detail", response.json())

    def test_browse_caps_entries_at_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index in range(BROWSE_ENTRY_LIMIT + 5):
                (root / f"file-{index:04d}.txt").write_text("x", encoding="utf-8")

            response = self._client().get("/api/browse", params={"path": str(root)})

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertTrue(payload["truncated"])
            self.assertEqual(len(payload["entries"]), BROWSE_ENTRY_LIMIT)


if __name__ == "__main__":
    unittest.main()
