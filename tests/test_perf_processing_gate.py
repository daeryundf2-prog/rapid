"""scripts/perf-processing-gate.py on synthetic run summaries (T-214)."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path

from tests.reference_diff_helpers import REPO_ROOT, load_script

BASELINE = REPO_ROOT / "docs" / "validation" / "perf-processing-baseline.json"
T0 = dt.datetime(2026, 11, 1, 0, 0, 0, tzinfo=dt.timezone.utc)


def at(seconds: float) -> str:
    return (T0 + dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def task(task_id: str, kind: str, start: float | None, end: float | None, status: str = "completed") -> dict[str, object]:
    return {"id": task_id, "type": kind, "status": status,
            "started_at": at(start) if start is not None else None,
            "finished_at": at(end) if end is not None else None}


def group(group_id: str, tasks: list[dict[str, object]], start: float | None, end: float | None) -> dict[str, object]:
    duration = int((end - start) * 1000) if start is not None and end is not None else None
    return {"id": group_id, "started_at": at(start) if start is not None else None,
            "finished_at": at(end) if end is not None else None, "duration_ms": duration, "tasks": tasks}


def plan(prepare_s: float, collection_s: float) -> dict[str, object]:
    """prepare 0..prepare_s, then two provider groups covering ``collection_s``, then a report stage."""
    c0, c1 = prepare_s, prepare_s + collection_s
    return {
        "command": "run-plan",
        "outcome": "complete",
        "groups": [
            group("prepare", [task("image-extract", "stage", 0, prepare_s)], 0, prepare_s),
            group("os-account", [task("windows-registry", "provider", c0, c0 + collection_s / 2)], c0, c0 + collection_s / 2),
            group("web", [task("browser", "provider", c0 + 1, c1), task("p2p", "provider", None, None, "skipped")], c0 + 1, c1),
            group("carve", [task("carve", "stage", None, None)], None, None),
            group("report", [task("report", "stage", c1, c1 + 10)], c1, c1 + 10),
        ],
    }


class PerfProcessingGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.module = load_script("perf-processing-gate")

    def write(self, name: str, payload: object) -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def gate(self, *argv: str) -> tuple[int, dict[str, object], str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        corpus = [] if "--corpus" in argv or "--no-corpus" in argv else ["--corpus", "IMG-B"]
        argv = tuple(item for item in argv if item != "--no-corpus")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.module.main([*argv, *corpus, "--json"])
        text = stdout.getvalue()
        return code, (json.loads(text) if text.strip().startswith("{") else {}), stderr.getvalue()

    def statuses(self, report: dict[str, object]) -> dict[str, str]:
        return {row["step"]: row["status"] for row in report["steps"]}  # type: ignore[union-attr]

    def test_committed_baseline_records_img_b_numbers_only(self) -> None:
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertEqual(data["tolerance"], 0.2)
        self.assertEqual(
            data["corpora"]["IMG-B"]["metrics"],
            {"prepare_s": 3719, "collection_s": 3511, "output_bytes": 71_600_000_000},
        )
        self.assertNotRegex(BASELINE.read_text(encoding="utf-8"), r"[A-Za-z]:[\\/]|\.(E01|e01|dd|raw)\b")

    def test_twenty_percent_worse_summary_exits_1_with_steps(self) -> None:
        # Run summary carrying the plan: prepare +25%, collection +21%, output size measured +0%.
        current = self.write("summary.json", {"command": "run-summary", "plan": plan(3719 * 1.25, 3511 * 1.21)})
        out = self.tmp / "report.json"
        code, report, _ = self.gate("--current", str(current), "--output", str(out))
        self.assertEqual(code, 1)
        self.assertEqual(report["verdict"], "worsened")
        self.assertEqual(report["worsened"], ["prepare_s", "collection_s"])
        self.assertEqual(report["unmeasured"], ["output_bytes"])
        rows = {row["step"]: row for row in report["steps"]}
        self.assertAlmostEqual(rows["prepare_s"]["change_pct"], 25.0, places=1)
        self.assertEqual(rows["group.os-account_s"]["status"], "no_baseline")
        self.assertNotIn("group.carve_s", rows)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["worsened"], ["prepare_s", "collection_s"])

    def test_text_output_lists_worsened_steps(self) -> None:
        current = self.write("flat.json", {"metrics": {"prepare_s": 3719, "collection_s": 3511, "output_bytes": 71.6e9 * 1.3}})
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = self.module.main(["--current", str(current), "--corpus", "IMG-B"])
        self.assertEqual(code, 1)
        self.assertIn("나빠진 단계(20% 초과): output_bytes", stdout.getvalue())

    def test_within_tolerance_and_improvement_pass(self) -> None:
        current = self.write("plan.json", plan(3719 * 1.2, 1000))  # exactly +20% is not "more than 20%"
        code, report, _ = self.gate("--current", str(current), "--allow-unmeasured", "output_bytes")
        self.assertEqual(code, 0)
        self.assertEqual(report["allowed_unmeasured"], ["output_bytes"])
        self.assertEqual(report["verdict"], "ok")
        statuses = self.statuses(report)
        self.assertEqual((statuses["prepare_s"], statuses["collection_s"], statuses["output_bytes"]), ("ok", "ok", "unmeasured"))
        flat = self.write("flat.json", {"metrics": {"prepare_s": 3719 * 1.2, "collection_s": 3511 * 1.2, "output_bytes": 71.6e9 * 1.2}})
        code, report, _ = self.gate("--current", str(flat))
        self.assertEqual((code, report["worsened"]), (0, []))

    def test_missing_timings_are_insufficient_not_ok(self) -> None:
        # WB-13 P1-3: nothing compared is "비교 불충분" (exit 3), never verdict ok / exit 0.
        bare = plan(100, 100)
        for item in bare["groups"]:  # type: ignore[union-attr]
            item["duration_ms"] = None
            for entry in item["tasks"]:
                entry["started_at"] = entry["finished_at"] = None
        code, report, _ = self.gate("--current", str(self.write("bare.json", bare)))
        self.assertEqual((code, report["verdict"], report["verdict_label"]), (3, "insufficient", "비교 불충분"))
        self.assertEqual(report["unmeasured"], ["prepare_s", "collection_s", "output_bytes"])
        self.assertEqual(report["worsened"], [])

    def test_unmeasured_metric_needs_allow_unmeasured(self) -> None:
        flat = self.write("flat.json", {"metrics": {"prepare_s": 3719, "collection_s": 3511}})
        code, report, _ = self.gate("--current", str(flat))
        self.assertEqual((code, report["verdict"]), (3, "insufficient"))
        self.assertTrue(any("output_bytes" in reason for reason in report["insufficient_reasons"]))
        code, report, _ = self.gate("--current", str(flat), "--allow-unmeasured", "output_bytes")
        self.assertEqual((code, report["verdict"]), (0, "ok"))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.module.main(["--current", str(flat), "--corpus", "IMG-B"]), 3)
        self.assertIn("비교 불충분: 미측정 지표", stdout.getvalue())

    def test_failed_run_with_an_unfinished_provider_is_refused(self) -> None:
        # Review experiment: outcome failed, one provider finished in 5 s, one never finished.
        failed = {
            "command": "run-plan",
            "outcome": "failed",
            "groups": [
                group("os-account", [task("windows-registry", "provider", 0, 5)], 0, 5),
                group("web", [task("browser", "provider", 1, None, "running")], 1, None),
            ],
        }
        code, report, _ = self.gate("--current", str(self.write("failed.json", failed)), "--allow-unmeasured", "prepare_s,output_bytes")
        self.assertEqual((code, report["verdict"]), (3, "insufficient"))
        self.assertEqual(report["plan_problems"]["outcome"], "failed")
        self.assertEqual(report["plan_problems"]["unfinished_providers"], ["web/browser(running)"])
        rows = {row["step"]: row for row in report["steps"]}
        self.assertEqual(rows["collection_s"]["current"], 5.0)  # still shown, but not a pass

    def test_plan_without_outcome_or_with_reused_steps_is_refused(self) -> None:
        running = plan(3719, 3511)
        running.pop("outcome")
        code, report, _ = self.gate("--current", str(self.write("running.json", running)), "--allow-unmeasured", "output_bytes")
        self.assertEqual((code, report["plan_problems"]), (3, {"outcome": None}))
        resumed = plan(100, 100)
        resumed["groups"][0]["tasks"][0]["reused"] = True  # type: ignore[index]
        code, report, _ = self.gate("--current", str(self.write("resumed.json", {"plan": resumed})), "--allow-unmeasured", "output_bytes")
        self.assertEqual((code, report["plan_problems"]["reused_steps"]), (3, ["prepare/image-extract"]))
        self.assertTrue(any("재사용" in reason for reason in report["insufficient_reasons"]))

    def test_other_corpus_identity_is_refused(self) -> None:
        flat = self.write("flat.json", {"corpus": "C2", "metrics": {"prepare_s": 10, "collection_s": 10, "output_bytes": 10}})
        code, report, _ = self.gate("--current", str(flat))
        self.assertEqual((code, report["verdict"]), (3, "insufficient"))
        self.assertEqual(report["corpus_identity"]["mismatches"], [{"field": "corpus", "baseline": "IMG-B", "current": "C2"}])
        baseline = self.write("baseline.json", {
            "schema_version": "perf-processing-baseline-v1", "tolerance": 0.2,
            "corpora": {"S": {"identity": {"evidence_bytes": 1000}, "metrics": {"prepare_s": 10}}},
        })
        smaller = self.write("smaller.json", {"evidence_bytes": 10, "metrics": {"prepare_s": 1}})
        code, report, _ = self.gate("--baseline", str(baseline), "--current", str(smaller), "--corpus", "S")
        self.assertEqual(code, 3)
        same = self.write("same.json", {"evidence_bytes": 1000, "metrics": {"prepare_s": 10}})
        code, report, _ = self.gate("--baseline", str(baseline), "--current", str(same), "--corpus", "S")
        self.assertEqual((code, report["corpus_identity"]["mismatches"]), (0, []))

    def test_output_folder_size_and_tolerance_override(self) -> None:
        run_dir = self.tmp / "run"
        (run_dir / "sub").mkdir(parents=True)
        (run_dir / "a.bin").write_bytes(b"x" * 1300)
        (run_dir / "sub" / "b.bin").write_bytes(b"y" * 100)
        baseline = self.write("baseline.json", {
            "schema_version": "perf-processing-baseline-v1", "tolerance": 0.2,
            "corpora": {"S": {"metrics": {"output_bytes": 1000, "prepare_s": 10}}},
        })
        current = self.write("flat.json", {"metrics": {"prepare_s": 11.5}})
        code, report, _ = self.gate("--baseline", str(baseline), "--current", str(current), "--output-dir-size", str(run_dir), "--corpus", "S")
        self.assertEqual(code, 1)
        self.assertEqual(report["corpus"], "S")
        self.assertEqual(report["worsened"], ["output_bytes"])
        rows = {row["step"]: row for row in report["steps"]}
        self.assertEqual(rows["output_bytes"]["current"], 1400.0)
        code, report, _ = self.gate("--baseline", str(baseline), "--current", str(current), "--tolerance", "0.1",
                                    "--output-dir-size", str(run_dir), "--corpus", "S")
        self.assertEqual(report["worsened"], ["output_bytes", "prepare_s"])

    def test_input_errors_exit_2(self) -> None:
        flat = self.write("flat.json", {"metrics": {"prepare_s": 1}})
        cases = [
            (["--current", str(self.tmp / "none.json")], "현재 처리 요약 파일이 없습니다"),
            (["--current", str(self.write("odd.json", {"command": "x"}))], "단계 시간을 찾지 못했습니다"),
            (["--current", str(flat), "--corpus", "R8"], "기준선에 코퍼스 R8가 없습니다"),
            (["--current", str(self.write("bad.json", {"metrics": {"prepare_s": "slow"}}))], "숫자가 아닙니다"),
            (["--current", str(flat), "--output-dir-size", str(self.tmp / "no-dir")], "출력 폴더가 없습니다"),
            # WB-13 P1-3: non-finite numbers, a tolerance outside (0, 1], no corpus named.
            (["--current", str(self.write("nan.json", {"metrics": {"prepare_s": float("nan")}}))], "유한한 0 이상의 수가 아닙니다"),
            (["--current", str(self.write("neg.json", {"metrics": {"prepare_s": -1}}))], "유한한 0 이상의 수가 아닙니다"),
            (["--current", str(flat), "--tolerance", "nan"], "허용 폭은 0보다 크고 1 이하"),
            (["--current", str(flat), "--tolerance", "0"], "허용 폭은 0보다 크고 1 이하"),
            (["--current", str(flat), "--tolerance", "1.5"], "허용 폭은 0보다 크고 1 이하"),
            (["--current", str(flat), "--tolerance", "-0.1"], "허용 폭은 0보다 크고 1 이하"),
            (["--current", str(flat), "--no-corpus"], "--corpus로 현재 런이 처리한 코퍼스를 밝혀야 합니다"),
            (["--current", str(flat), "--allow-unmeasured", "speed"], "기준선에 없는 지표: speed"),
            (["--current", str(self.write("nanplan.json", {"groups": [{"id": "prepare", "duration_ms": float("nan")}]}))],
             "duration_ms가 유한한"),
        ]
        for tolerance in (True, -0.5, float("nan")):
            baseline = self.write("tol.json", {"schema_version": "perf-processing-baseline-v1", "tolerance": tolerance,
                                               "corpora": {"S": {"metrics": {"prepare_s": 1}}}})
            cases.append((["--baseline", str(baseline), "--current", str(flat), "--corpus", "S"], "기준선 허용 폭"))
        for argv, message in cases:
            code, report, stderr = self.gate(*argv)
            self.assertEqual((code, report), (2, {}), argv)
            self.assertIn(message, stderr)


if __name__ == "__main__":
    unittest.main()
