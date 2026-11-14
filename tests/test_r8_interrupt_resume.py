"""R8 T-354 interrupt / resume / cancel / retry measurement script (synthetic data only)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import socket
import sqlite3
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "r8-interrupt-resume.py"


def _load():
    spec = importlib.util.spec_from_file_location("r8_interrupt_resume_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load()


def _plan(*tasks: tuple[str, str, str, bool]) -> dict:
    """``(id, type, status, reused)`` rows in one group."""
    return {
        "groups": [
            {
                "id": "g",
                "tasks": [{"id": tid, "type": kind, "status": status, "reused": reused} for tid, kind, status, reused in tasks],
            }
        ]
    }


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class PointTests(unittest.TestCase):
    PLAN = _plan(
        ("image-extract", "stage", "skipped", False),
        ("fingerprint", "stage", "completed", False),
        ("browser", "provider", "running", False),
        ("eventlog", "provider", "completed", False),
        ("docs", "stage", "queued", False),
        ("persist", "stage", "queued", False),
        ("docs-extract", "stage", "queued", False),
        ("files-extract", "stage", "skipped", False),
    )

    def test_point_tasks(self) -> None:
        self.assertEqual(mod.point_task_ids(self.PLAN, "collection"), ["browser", "eventlog"])
        self.assertEqual(mod.point_task_ids(self.PLAN, "indexing"), ["docs", "persist"])
        # folder evidence: the optional extraction stage; skipped tasks never count
        self.assertEqual(mod.point_task_ids(self.PLAN, "extraction"), ["docs-extract"])
        # image evidence: image-extract only, and only while it is not skipped
        self.assertEqual(mod.point_task_ids(self.PLAN, "extraction", image=True), [])
        live = _plan(("image-extract", "stage", "running", False), ("docs-extract", "stage", "queued", False))
        self.assertEqual(mod.point_task_ids(live, "extraction", image=True), ["image-extract"])
        with self.assertRaises(ValueError):
            mod.point_task_ids(self.PLAN, "nowhere")

    def test_running_and_finished(self) -> None:
        self.assertEqual(mod.running_in(self.PLAN, mod.point_task_ids(self.PLAN, "collection")), ["browser"])
        self.assertEqual(mod.running_in(self.PLAN, ["docs"]), [])
        self.assertEqual(mod.finished_task_ids(self.PLAN), ["eventlog", "fingerprint"])
        self.assertEqual(mod.finished_task_ids(None), [])

    def test_reexecuted_ignores_reused_and_reverify(self) -> None:
        resumed = _plan(
            ("fingerprint", "stage", "completed", False),
            ("eventlog", "provider", "completed", True),
            ("manifest", "stage", "completed", False),
            ("docs", "stage", "partial", False),
            ("browser", "provider", "completed", False),
        )
        before = ["fingerprint", "eventlog", "manifest", "docs"]
        self.assertEqual(mod.reexecuted_tasks(before, resumed), ["docs", "manifest"])
        self.assertEqual(mod.reexecuted_tasks(before, resumed, ignore=()), ["docs", "fingerprint", "manifest"])


class CountTests(unittest.TestCase):
    def test_summary_counts_flatten(self) -> None:
        summary = {
            "summary": {
                "artifact_type_counts": {"mft-record": 3, "media-image": 1},
                "provider_artifact_counts": {"windows-filesystem": 4, "bad": "x"},
                "scanned_file_count": 10,
                "timeline_event_count": 7,
                "silent_failure_risk": True,
            }
        }
        self.assertEqual(
            mod.summary_counts(summary),
            {
                "artifact_type_counts:mft-record": 3,
                "artifact_type_counts:media-image": 1,
                "provider_artifact_counts:windows-filesystem": 4,
                "summary:scanned_file_count": 10,
                "summary:timeline_event_count": 7,
            },
        )
        self.assertEqual(mod.summary_counts(None), {})

    def test_case_db_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "case.db"
            con = sqlite3.connect(db)
            con.executescript(
                "CREATE TABLE artifact (artifact_type TEXT); CREATE TABLE event (event_type TEXT);"
                "CREATE TABLE file_record (id INTEGER); "
                "INSERT INTO artifact VALUES ('a'),('a'),('b'); INSERT INTO event VALUES ('e');"
                "INSERT INTO file_record VALUES (1),(2);"
            )
            con.commit()
            con.close()
            self.assertEqual(
                mod.case_db_counts(db),
                {"case_db:file_record": 2, "case_db:artifact:a": 2, "case_db:artifact:b": 1, "case_db:event:e": 1},
            )
            self.assertEqual(mod.case_db_counts(Path(tmp) / "missing.db"), {})
            self.assertEqual(mod.case_db_counts(None), {})

    def test_compare_counts(self) -> None:
        base = {"a": 1, "b": 2, "c": 3}
        self.assertEqual(mod.compare_counts(base, dict(base)), [])
        diffs = mod.compare_counts(base, {"a": 1, "b": 5, "d": 4})
        self.assertEqual(
            diffs,
            [
                {"key": "b", "baseline": 2, "value": 5, "delta": 3},
                {"key": "c", "baseline": 3, "value": 0, "delta": -3},
                {"key": "d", "baseline": 0, "value": 4, "delta": 4},
            ],
        )


class EvaluateTests(unittest.TestCase):
    @staticmethod
    def _good() -> dict:
        interrupts = [
            {"point": p, "hit": True, "interrupted_status": "interrupted", "resumed_status": "completed", "count_diffs": [], "reexecuted": []}
            for p in mod.POINTS
        ]
        return {
            "points": list(mod.POINTS),
            "interrupts": interrupts,
            "cancel": {"final_status": "cancelled", "seconds_to_cancelled": 2.5},
            "retry": {"failed_status": "failed", "resumed_status": "completed", "reexecuted": [], "count_diffs": []},
            "evidence_snapshot": {"identical": True},
        }

    def test_all_met(self) -> None:
        self.assertEqual(mod.evaluate(self._good()), [])

    def test_each_shortfall_is_one_gap(self) -> None:
        report = self._good()
        report["interrupts"][0]["hit"] = False
        report["interrupts"][1]["count_diffs"] = [{"key": "x", "baseline": 1, "value": 0, "delta": -1}]
        report["interrupts"][2]["reexecuted"] = ["manifest"]
        report["interrupts"][2]["interrupted_status"] = "failed"
        report["cancel"]["seconds_to_cancelled"] = 12.0
        report["retry"]["reexecuted"] = ["docs", "files"]
        report["retry"]["count_diffs"] = [{"key": "y"}]
        report["evidence_snapshot"]["identical"] = False
        areas = [gap["area"] for gap in mod.evaluate(report)]
        self.assertEqual(
            areas,
            ["interrupt-resume", "interrupt-status", "interrupt-rerun", "cancel", "retry-rerun", "retry-counts", "evidence-snapshot"],
        )
        detail = mod.evaluate(report)[0]["detail"]
        self.assertIn("1/3", detail)
        self.assertIn("not reached: extraction", detail)
        self.assertIn("differing or not completed: collection", detail)

    def test_cancel_and_retry_failures(self) -> None:
        report = self._good()
        report["cancel"] = {"final_status": "completed", "seconds_to_cancelled": None}
        report["retry"] = {"failed_status": "completed", "resumed_status": None}
        areas = [gap["area"] for gap in mod.evaluate(report)]
        self.assertEqual(areas, ["cancel", "retry-injection", "retry"])
        report["cancel"] = {"skipped": True}
        report["retry"] = {"skipped": True}
        self.assertEqual(mod.evaluate(report), [])


class HelperTests(unittest.TestCase):
    def test_synthetic_evidence_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            one = mod.write_synthetic_evidence(Path(tmp) / "one", files=16)
            two = mod.write_synthetic_evidence(Path(tmp) / "two", files=16)
            files_one = sorted(p.relative_to(one).as_posix() for p in one.rglob("*") if p.is_file())
            files_two = sorted(p.relative_to(two).as_posix() for p in two.rglob("*") if p.is_file())
            self.assertEqual(files_one, files_two)
            self.assertEqual(len(files_one), 16 + 2 * 2)
            for rel in files_one:
                self.assertEqual((one / rel).read_bytes(), (two / rel).read_bytes())

    def test_read_dev_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp) / ".rt-dev.env"
            env.write_text("# c\nRT_WT_NAME=x\nRAPIDTRIAGE_API_PORT=8745\n", encoding="utf-8")
            self.assertEqual(mod.read_dev_port(env), 8745)
            self.assertIsNone(mod.read_dev_port(Path(tmp) / "missing"))

    def test_read_plan_prefers_live_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertIsNone(mod.read_plan(out))
            (out / mod.PLAN_FILE).write_text(json.dumps({"groups": [], "outcome": "complete"}), encoding="utf-8")
            self.assertEqual(mod.read_plan(out)["outcome"], "complete")
            (out / mod.PROGRESS_FILE).write_text(json.dumps({"plan": {"groups": [], "outcome": "running"}}), encoding="utf-8")
            self.assertEqual(mod.read_plan(out)["outcome"], "running")

    def test_protected_port_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(mod.HarnessError):
                mod.Server(Path(tmp), 8710, budget_s=10)

    def test_missing_evidence_is_a_harness_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = mod.main(["--corpus", "C1", "--evidence", str(Path(tmp) / "none.E01"), "--work-dir", tmp])
            self.assertEqual(code, 2)
            self.assertIn("evidence not found", err.getvalue())


class QuickRunTests(unittest.TestCase):
    """The whole script against a small synthetic sample with a private server (--quick)."""

    def test_quick_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = mod.main(
                    [
                        "--quick",
                        "--quick-files", "60",
                        "--points", "collection",
                        "--work-dir", str(Path(tmp) / "work"),
                        "--output", str(output),
                        "--port", str(_free_port()),
                        "--run-timeout", "300",
                    ]
                )  # fmt: skip
            self.assertIn(code, (0, 1), err.getvalue()[-2000:])
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["schema"], mod.SCHEMA)
        self.assertEqual(report["baseline"]["status"], "completed")
        self.assertGreater(report["baseline"]["count_keys"], 0)
        self.assertEqual([item["point"] for item in report["interrupts"]], ["collection"])
        item = report["interrupts"][0]
        if item["hit"]:  # timing-dependent on a tiny sample; the fields must be there when it hit
            self.assertIn("interrupted_status", item)
            self.assertIn("count_diffs", item)
        cancel = report["cancel"]
        self.assertIn(cancel["final_status"], ("cancelled", "completed"))
        self.assertIn("seconds_to_cancelled", cancel)
        retry = report["retry"]
        self.assertEqual(retry["failed_status"], "failed")  # the input-side injection works
        self.assertIn("timeline", retry["failed_tasks"])
        self.assertIn("reexecuted", retry)
        self.assertTrue(report["evidence_snapshot"]["identical"])
        self.assertEqual(report["verdict"], "pass" if not report["gaps"] else "gaps")


if __name__ == "__main__":
    unittest.main()
