from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path

HAS_FASTAPI = True
try:
    import fastapi  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "tests" / "fixtures" / "api_openapi_snapshot.json"
SNAPSHOT_TOOL_PATH = REPO_ROOT / "scripts" / "update-api-snapshot.py"
UPDATE_SNAPSHOT_ENV = "RAPIDTRIAGE_UPDATE_API_SNAPSHOT"


def load_snapshot_tool():
    """Load scripts/update-api-snapshot.py as a module (file name uses dashes)."""
    spec = importlib.util.spec_from_file_location("update_api_snapshot", SNAPSHOT_TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def diff_snapshots(expected: dict, actual: dict) -> list[str]:
    """Return human-readable differences between two API snapshots."""
    problems: list[str] = []
    expected_paths = expected.get("paths", {})
    actual_paths = actual.get("paths", {})
    for path in sorted(set(actual_paths) - set(expected_paths)):
        problems.append(f"added path not in snapshot: {path} {sorted(actual_paths[path])}")
    for path in sorted(set(expected_paths) - set(actual_paths)):
        problems.append(f"removed path still in snapshot: {path}")
    for path in sorted(set(expected_paths) & set(actual_paths)):
        expected_ops = expected_paths[path]
        actual_ops = actual_paths[path]
        for method in sorted(set(actual_ops) - set(expected_ops)):
            problems.append(f"added method not in snapshot: {method.upper()} {path}")
        for method in sorted(set(expected_ops) - set(actual_ops)):
            problems.append(f"removed method still in snapshot: {method.upper()} {path}")
        for method in sorted(set(expected_ops) & set(actual_ops)):
            if expected_ops[method] != actual_ops[method]:
                problems.append(
                    f"operationId changed: {method.upper()} {path} "
                    f"{expected_ops[method]!r} -> {actual_ops[method]!r}"
                )
    return problems


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for RapidTriage API contract tests")
class RapidTriageApiContractTests(unittest.TestCase):
    def test_openapi_surface_matches_checked_in_snapshot(self) -> None:
        tool = load_snapshot_tool()
        actual = tool.build_api_snapshot()

        if os.environ.get(UPDATE_SNAPSHOT_ENV) == "1":
            tool.write_snapshot(SNAPSHOT_PATH)

        expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        problems = diff_snapshots(expected, actual)
        self.assertEqual(
            [],
            problems,
            "API surface drifted from tests/fixtures/api_openapi_snapshot.json. "
            "If this change is intentional, regenerate the fixture with "
            "`python scripts/update-api-snapshot.py` or "
            f"`{UPDATE_SNAPSHOT_ENV}=1 python -m unittest tests.test_rapidtriage_api_contract`:\n"
            + "\n".join(problems),
        )

    def test_snapshot_fixture_is_well_formed(self) -> None:
        snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        paths = snapshot.get("paths")
        self.assertIsInstance(paths, dict)
        self.assertGreater(len(paths), 0)
        for path, operations in paths.items():
            self.assertTrue(path.startswith("/"), path)
            self.assertIsInstance(operations, dict)
            for method, operation_id in operations.items():
                self.assertIn(
                    method,
                    {"get", "put", "post", "delete", "options", "head", "patch", "trace"},
                )
                self.assertIsInstance(operation_id, str)
                self.assertTrue(operation_id, f"{method.upper()} {path} has no operationId")


if __name__ == "__main__":
    unittest.main()
