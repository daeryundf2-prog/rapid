"""scripts/compare-runs.py on small synthetic run folders (R6 S1 Q-S1-5)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "compare-runs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("rapidtriage_compare_runs_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compare_runs = _load_module()

BASE_KINDS: dict[str, dict[str, list[str]]] = {
    # kind -> artifact_type -> row paths
    "browser": {
        "browser-history": ["C:/Users/u/AppData/Local/Chrome/User Data/Default/History"] * 3,
        "browser-cookie": ["C:/Users/u/AppData/Local/Chrome/User Data/Default/Network/Cookies"] * 2,
    },
    "eventlog": {
        "eventlog-event": ["C:/Windows/System32/winevt/Logs/Security.evtx"] * 4,
        "eventlog-detection": ["C:/Windows/System32/winevt/Logs/System.evtx"],
    },
}


def write_run(
    root: Path,
    kinds: dict[str, dict[str, list[str]]],
    *,
    jsonl: bool = False,
    seconds: dict[str, int] | None = None,
    parser_errors: dict[str, int] | None = None,
    stage_offsets: tuple[int, ...] = (10, 100, 160),
) -> Path:
    artifacts_dir = root / "artifacts"
    artifacts_dir.mkdir(parents=True)
    events = []
    for kind, types in kinds.items():
        rows = [
            {"provider": kind, "artifact_type": name, "path": path, "supported": True, "details": {"secret": "x"}}
            for name, paths in types.items()
            for path in paths
        ]
        errors = [{"error_type": "ValueError", "message": "m", "path": ""}] * (parser_errors or {}).get(kind, 0)
        payload: dict[str, object] = {
            "kind": kind,
            "summary": {
                "artifact_count": len(rows),
                "artifact_type_counts": {name: len(paths) for name, paths in types.items()},
                "parser_error_count": len(errors),
                "collection_status": "completed",
            },
            "parser_errors": errors,
        }
        if jsonl:
            records = artifacts_dir / f"rapidtriage-artifacts-{kind}.jsonl"
            records.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            payload.update({"artifacts": rows[:1], "record_count": len(rows), "records_file": records.name})
        else:
            payload["artifacts"] = rows
        (artifacts_dir / f"rapidtriage-artifacts-{kind}.json").write_text(json.dumps(payload), encoding="utf-8")
        events.append({"kind": kind, "status": "completed", "duration_ms": (seconds or {}).get(kind, 1000)})
    total_rows = sum(len(paths) for types in kinds.values() for paths in types.values())
    summary = {
        "mode": "hacking",
        "summary": {"counts": {"artifacts": total_rows, "timeline_events": 7, "files": 3, "indicators": 2}},
    }
    (root / "rapidtriage-run-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (root / "rapidtriage-parser-scheduler.json").write_text(json.dumps({"events": events}), encoding="utf-8")
    stamps = [f"2026-10-15T12:00:{0:02d}+00:00"]
    completed = []
    for name, offset in zip(("prepare", "artifacts", "timeline"), stage_offsets):
        completed.append({"stage": name, "completed_at": f"2026-10-15T12:{offset // 60:02d}:{offset % 60:02d}+00:00"})
    last = stage_offsets[-1] + 5
    progress = {
        "started_at": stamps[0],
        "completed_at": f"2026-10-15T12:{last // 60:02d}:{last % 60:02d}+00:00",
        "completed_stages": completed,
        "providers": {},
    }
    (root / "rapidtriage-run-progress.json").write_text(json.dumps(progress), encoding="utf-8")
    return root


def run_script(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = compare_runs.main(list(args))
    return code, out.getvalue()


class CompareRunsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.baseline = write_run(self.tmp / "base", BASE_KINDS)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def compare(self, candidate: Path, *extra: str) -> tuple[int, dict]:
        code, text = run_script("--baseline", str(self.baseline), "--candidate", str(candidate), "--json", *extra)
        return code, json.loads(text)

    def kind(self, report: dict, name: str) -> dict:
        return next(item for item in report["kinds"] if item["kind"] == name)

    def type_row(self, report: dict, kind: str, artifact_type: str) -> dict:
        return next(row for row in self.kind(report, kind)["artifact_types"] if row["artifact_type"] == artifact_type)

    def test_identical_runs_pass(self) -> None:
        candidate = write_run(self.tmp / "cand", BASE_KINDS, jsonl=True)
        code, report = self.compare(candidate)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["schema"], "rapidtriage-compare-runs-v1")
        self.assertEqual([item["verdict"] for item in report["kinds"]], ["pass", "pass"])
        self.assertEqual(report["new_kinds"], [])
        self.assertEqual(report["run_counts"]["artifacts"], {"baseline": 10, "candidate": 10, "delta": 0})
        self.assertEqual([s["stage"] for s in report["stages"]], ["prepare", "artifacts", "timeline"])
        self.assertEqual(report["total_seconds"]["ratio"], 1.0)
        self.assertEqual(
            sorted(report),
            sorted(
                [
                    "schema", "baseline", "candidate", "allowed_types", "verdict", "regression_kinds", "move_kinds",
                    "kinds", "new_kinds", "new_kinds_total_seconds", "run_counts", "stages", "total_seconds",
                    "timing_flags",
                ]
            ),
        )

    def test_row_change_is_regression_with_path_tails(self) -> None:
        kinds = json.loads(json.dumps(BASE_KINDS))
        kinds["browser"]["browser-history"] = kinds["browser"]["browser-history"][:1]
        candidate = write_run(self.tmp / "cand", kinds, jsonl=True)
        code, report = self.compare(candidate)
        self.assertEqual(code, 1)
        self.assertEqual(report["regression_kinds"], ["browser"])
        row = self.type_row(report, "browser", "browser-history")
        self.assertEqual((row["baseline"], row["candidate"], row["delta"], row["verdict"]), (3, 1, -2, "regression"))
        self.assertEqual(row["path_tails"], ["User Data/Default/History"])
        self.assertIn("artifact-type-count-changed", self.kind(report, "browser")["reasons"])
        # Row content never reaches the report.
        self.assertNotIn('"secret"', json.dumps(report))

    def test_allow_type_accepts_change(self) -> None:
        kinds = json.loads(json.dumps(BASE_KINDS))
        kinds["browser"]["browser-cookie"] = kinds["browser"]["browser-cookie"] * 3
        candidate = write_run(self.tmp / "cand", kinds)
        code, report = self.compare(candidate, "--allow-type", "browser-cookie")
        self.assertEqual(code, 0)
        self.assertEqual(self.type_row(report, "browser", "browser-cookie")["verdict"], "allowed")
        self.assertEqual(report["allowed_types"], ["browser-cookie"])

    def test_new_type_is_allowed(self) -> None:
        kinds = json.loads(json.dumps(BASE_KINDS))
        kinds["browser"]["browser-cache-entry"] = ["C:/x/Cache/data_1"] * 2
        candidate = write_run(self.tmp / "cand", kinds)
        code, report = self.compare(candidate)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "pass")
        row = self.type_row(report, "browser", "browser-cache-entry")
        self.assertEqual((row["baseline"], row["candidate"], row["verdict"]), (0, 2, "new-type"))
        self.assertEqual(self.kind(report, "browser")["delta"], 2)

    def test_moved_type_with_same_kind_total_is_move(self) -> None:
        kinds = json.loads(json.dumps(BASE_KINDS))
        moved = kinds["eventlog"]["eventlog-event"].pop()
        kinds["eventlog"]["eventlog-detection"].append(moved)
        candidate = write_run(self.tmp / "cand", kinds, jsonl=True)
        code, report = self.compare(candidate)
        self.assertEqual(code, 0)
        self.assertEqual(report["move_kinds"], ["eventlog"])
        eventlog = self.kind(report, "eventlog")
        self.assertEqual((eventlog["verdict"], eventlog["delta"]), ("move", 0))
        self.assertEqual(self.type_row(report, "eventlog", "eventlog-event")["verdict"], "move")
        self.assertEqual(self.type_row(report, "eventlog", "eventlog-detection")["verdict"], "move")

    def test_new_kind_listed_with_rows_time_errors(self) -> None:
        kinds = json.loads(json.dumps(BASE_KINDS))
        kinds["p2p"] = {"p2p-torrent-file": ["C:/Users/u/Downloads/a.torrent"]}
        candidate = write_run(self.tmp / "cand", kinds, seconds={"p2p": 70_000}, parser_errors={"p2p": 1})
        code, report = self.compare(candidate)
        self.assertEqual(code, 0)
        self.assertEqual(
            {k: report["new_kinds"][0][k] for k in ("kind", "rows", "seconds", "parser_errors")},
            {"kind": "p2p", "rows": 1, "seconds": 70.0, "parser_errors": 1},
        )
        self.assertIn("new-kinds-over-budget", report["timing_flags"])
        code, _ = self.compare(candidate, "--fail-on-slow")
        self.assertEqual(code, 1)

    def test_missing_kind_and_parser_errors_regress(self) -> None:
        kinds = {"eventlog": BASE_KINDS["eventlog"]}
        candidate = write_run(self.tmp / "cand", kinds, parser_errors={"eventlog": 2})
        code, report = self.compare(candidate)
        self.assertEqual(code, 1)
        self.assertIn("kind-missing-in-candidate", self.kind(report, "browser")["reasons"])
        self.assertIn("parser-errors-increased", self.kind(report, "eventlog")["reasons"])

    def test_slow_stage_flagged(self) -> None:
        candidate = write_run(self.tmp / "cand", BASE_KINDS, stage_offsets=(10, 300, 360))
        code, report = self.compare(candidate)
        self.assertEqual(code, 0)
        self.assertIn("stage-slow:artifacts", report["timing_flags"])
        self.assertIn("total-slow", report["timing_flags"])

    def test_input_errors_exit_2_and_output_file(self) -> None:
        code, _ = run_script("--baseline", str(self.tmp / "missing"), "--candidate", str(self.baseline))
        self.assertEqual(code, 2)
        empty = self.tmp / "empty"
        empty.mkdir()
        code, _ = run_script("--baseline", str(self.baseline), "--candidate", str(empty))
        self.assertEqual(code, 2)
        out = self.tmp / "report" / "r.json"
        code, text = run_script("--baseline", str(self.baseline), "--candidate", str(self.baseline), "--output", str(out))
        self.assertEqual(code, 0)
        self.assertIn("compare-runs: PASS", text)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["verdict"], "pass")

    def test_read_only(self) -> None:
        candidate = write_run(self.tmp / "cand", BASE_KINDS, jsonl=True)
        before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in self.tmp.rglob("*") if p.is_file()}
        self.compare(candidate)
        after = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in self.tmp.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertTrue(os.path.isdir(candidate))


if __name__ == "__main__":
    unittest.main()
