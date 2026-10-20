"""Run plan (처리 계획표, plan P2 / R4 V1): plan, heartbeat, control, cancel/skip/finish, resume, API, CLI."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from unittest import mock

import rapidtriage.core.artifacts as core_artifacts
import rapidtriage.core.run as run_module
from rapidtriage.cli import main as cli_main
from rapidtriage.core.jobs import RunJob, RunJobStore, RunRequest
from rapidtriage.core.models import ArtifactRecord
from rapidtriage.core.run import RUN_PROFILES, run_triage_mode
from rapidtriage.core.run.plan import (
    CONTROL_FILE_NAME,
    GROUP_CATALOG,
    PLAN_FILE_NAME,
    PROVIDER_GROUPS,
    PlanTargetError,
    RunControlWatcher,
    append_control_request,
    build_run_plan,
    builtin_provider_kinds,
    derive_group_status,
    evaluate_control,
    find_task,
    iter_tasks,
    plan_preview,
    validate_skip_targets,
)
from rapidtriage.core.run.progress import (
    RUN_PROGRESS_FILE_NAME,
    RunProgress,
    load_run_progress_view,
    read_run_progress,
)
from tests.test_rapidtriage_run import build_run_fixture

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_API_TOKEN = "rapidtriage-test-token"
DEAD_PID = 2_000_000_000


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class SlowCollector:
    """Fake provider that yields rows slowly so a run can be controlled while it runs."""

    name = "slow-eventlog"
    description = "slow test provider"
    target_platform = "windows"

    def __init__(self, kind: str, rows: int, delay: float = 0.002) -> None:
        self.collector_kind = kind
        self.rows = rows
        self.delay = delay

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterator[ArtifactRecord]:
        for index in range(self.rows):
            time.sleep(self.delay)
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="windows-event-log-record",
                path=str(Path(root) / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"),
                supported=True,
                details={"record_id": index, "event_id": 4624, "channel": "Security", "timestamp": "2026-01-01T00:00:00+00:00"},
            )


@contextlib.contextmanager
def slow_provider(kind: str = "eventlog", rows: int = 200_000, *, single_worker: bool = True) -> Iterator[None]:
    real = core_artifacts.get_artifact_collector

    def fake(name: str):
        if name.strip().lower() == kind:
            return SlowCollector(kind, rows)
        return real(name)

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(core_artifacts, "get_artifact_collector", side_effect=fake))
        if single_worker:
            stack.enter_context(mock.patch.object(run_module, "artifact_scheduler_workers", return_value=1))
        yield


def wait_for(predicate: Callable[[], bool], timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.05)
    return False


def plan_task(output_dir: Path, task_id: str) -> dict | None:
    progress = read_run_progress(output_dir)
    plan = progress.get("plan") if progress else None
    return find_task(plan, task_id) if plan else None


def control_when_running(output_dir: Path, task_id: str, action: str, targets=(), *, actor: str = "web") -> threading.Thread:
    """Background thread: once ``task_id`` runs with rows, append one control request."""

    def worker() -> None:
        def running() -> bool:
            task = plan_task(output_dir, task_id)
            return bool(task and task.get("status") == "running" and int(task.get("rows_so_far") or 0) > 0)

        if wait_for(running):
            append_control_request(output_dir, action, list(targets), actor=actor)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread


class PlanConstructionTests(unittest.TestCase):
    def test_every_builtin_provider_has_a_domain_group(self) -> None:
        for kind in builtin_provider_kinds():
            self.assertIn(kind, PROVIDER_GROUPS, kind)
        # R2/R3 providers are placed in their domain groups.
        self.assertEqual(PROVIDER_GROUPS["windows-messenger"], "messaging")
        self.assertEqual(PROVIDER_GROUPS["cloud-sync"], "cloud")
        self.assertEqual(PROVIDER_GROUPS["kakaotalk-windows"], "messaging")
        self.assertEqual(PROVIDER_GROUPS["email"], "messaging")
        self.assertEqual(PROVIDER_GROUPS["windows-execution"], "execution")
        self.assertEqual(PROVIDER_GROUPS["windows-registry"], "os-account")
        self.assertEqual([group_id for group_id, _label, _tasks in GROUP_CATALOG][-3:], ["triage-flags", "derived", "report"])

    def test_plan_per_mode(self) -> None:
        for mode, profile in RUN_PROFILES.items():
            plan = build_run_plan(mode=mode)
            task_ids = [task["id"] for task in iter_tasks(plan)]
            self.assertEqual(len(task_ids), len(set(task_ids)), mode)
            for kind in builtin_provider_kinds():
                self.assertIn(kind, task_ids, (mode, kind))
            for kind in profile.artifacts_kinds:
                self.assertEqual(find_task(plan, kind)["group"], PROVIDER_GROUPS[kind])
            self.assertEqual(plan["counts"]["groups"]["total"], len(GROUP_CATALOG))
            self.assertEqual(find_task(plan, "carve")["status"], "skipped")
            self.assertEqual(find_task(plan, "carve")["reason"], "옵션 꺼짐")
            self.assertEqual(find_task(plan, "docs-extract")["status"], "skipped")
            self.assertEqual(find_task(plan, "report")["skippable"], False)
        hacking = build_run_plan(mode="hacking")
        self.assertEqual(hacking["counts"]["tasks"]["total"], len(builtin_provider_kinds()) + 14)
        # R6 S1 Q-S1-4: p2p runs in the web group for investigative modes.
        for mode in ("seizure", "fraud", "hacking"):
            p2p_task = find_task(build_run_plan(mode=mode), "p2p")
            self.assertEqual(p2p_task["group"], "web", mode)
            self.assertEqual(p2p_task["status"], "queued", mode)
        recovery = build_run_plan(mode="recovery")
        for kind in ("browser", "p2p", "windows-execution", "windows-system"):
            self.assertEqual(find_task(recovery, kind)["group"], "manifest", kind)
        manifest_tasks = [task["id"] for task in recovery["groups"][[g["id"] for g in recovery["groups"]].index("manifest")]["tasks"]]
        self.assertEqual(manifest_tasks[-1], "manifest")
        on = build_run_plan(mode="fraud", carve=True, extract=True, case_db=False)
        self.assertEqual(find_task(on, "carve")["status"], "queued")
        self.assertEqual(find_task(on, "files-extract")["status"], "queued")
        self.assertEqual(find_task(on, "persist")["reason"], "케이스 DB 꺼짐")

    def test_skip_targets_validation_and_preview(self) -> None:
        plan = build_run_plan(mode="hacking", skip_groups=["messaging"], skip_tasks=["eventlog"], actor="web")
        messaging = [group for group in plan["groups"] if group["id"] == "messaging"][0]
        self.assertEqual(messaging["status"], "skipped")
        self.assertEqual(messaging["counts"]["skipped"], 6)  # R5 L1: + email-clients
        self.assertTrue(all(task["reason"] == "실행 전 제외" for task in messaging["tasks"]))
        self.assertEqual(find_task(plan, "eventlog")["requested_by"]["actor"], "web")
        with self.assertRaisesRegex(PlanTargetError, "알 수 없는 그룹입니다: nope"):
            validate_skip_targets("hacking", ["nope"])
        with self.assertRaisesRegex(PlanTargetError, "건너뛸 수 없는 그룹입니다: report"):
            validate_skip_targets("hacking", ["report"])
        with self.assertRaisesRegex(PlanTargetError, "알 수 없는 태스크입니다: zzz"):
            validate_skip_targets("hacking", [], ["zzz"])
        with self.assertRaisesRegex(PlanTargetError, "건너뛸 수 없는 태스크입니다: manifest"):
            validate_skip_targets("hacking", [], ["manifest"])
        preview = plan_preview("hacking")
        by_id = {group["id"]: group for group in preview["groups"]}
        self.assertFalse(by_id["carve"]["default_on"])
        self.assertTrue(by_id["eventlog"]["default_on"])
        self.assertFalse(by_id["report"]["skippable"])
        self.assertEqual(by_id["web"]["tasks"][0]["id"], "browser")

    def test_group_status_derivation(self) -> None:
        self.assertEqual(derive_group_status(["running", "queued"]), "running")
        self.assertEqual(derive_group_status(["queued", "queued"]), "queued")
        self.assertEqual(derive_group_status(["completed", "completed"]), "completed")
        self.assertEqual(derive_group_status(["skipped", "skipped"]), "skipped")
        self.assertEqual(derive_group_status(["cancelled", "skipped"]), "cancelled")
        self.assertEqual(derive_group_status(["failed"]), "failed")
        self.assertEqual(derive_group_status(["completed", "cancelled"]), "partial")
        self.assertEqual(derive_group_status(["completed", "queued"]), "running")

    def test_evaluate_control_semantics(self) -> None:
        plan = build_run_plan(mode="hacking")
        find_task(plan, "eventlog")["status"] = "running"
        find_task(plan, "windows-registry")["status"] = "completed"
        accepted, rejected, effects = evaluate_control(plan, "skip", [{"task": "eventlog"}, {"group": "messaging"}, {"task": "windows-registry"}])
        self.assertEqual(accepted, [{"group": "messaging"}])
        self.assertEqual(
            [item["reason"] for item in rejected],
            ["이미 시작된 태스크는 건너뛸 수 없습니다. 취소를 사용하세요", "이미 끝난 태스크입니다"],
        )
        self.assertEqual(set(effects.values()), {"skip"})
        _accepted, _rejected, effects = evaluate_control(plan, "cancel", [{"task": "eventlog"}, {"task": "browser"}])
        self.assertEqual(effects, {"eventlog": "cancel-running", "browser": "cancel-queued"})
        _accepted, rejected, _effects = evaluate_control(plan, "cancel", [{"task": "report"}, {"group": "zzz"}])
        self.assertEqual(len(rejected), 2)
        _a, _r, effects = evaluate_control(plan, "finish")
        self.assertNotIn("eventlog", effects)
        self.assertTrue(all(value == "cancel-queued" for value in effects.values()))
        self.assertNotIn("docs", effects)
        _a, _r, effects = evaluate_control(plan, "cancel_all")
        self.assertEqual(effects["eventlog"], "cancel-running")
        self.assertEqual(effects["docs"], "cancel-queued")
        self.assertNotIn("report", effects)


class HeartbeatAndViewTests(unittest.TestCase):
    def test_heartbeat_owner_and_interrupted_view(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            progress = RunProgress(output_dir, heartbeat_interval=0.05)
            progress.start(stage="prepare")
            progress.set_plan(build_run_plan(mode="hacking"))
            first = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual(first["version"], "run-progress-v2")
            self.assertEqual(first["_owner"]["pid"], os.getpid())
            self.assertTrue(wait_for(lambda: load_json(output_dir / RUN_PROGRESS_FILE_NAME)["heartbeat_at"] != first["heartbeat_at"], 5))
            view = load_run_progress_view(output_dir)
            self.assertTrue(view["live"])
            self.assertNotIn("_owner", view)
            self.assertEqual(find_task(view["plan"], "image-extract")["status"], "running")
            progress.provider_running("eventlog")
            progress.task_rows("eventlog", 12)
            progress.finish()
            done = load_json(output_dir / RUN_PROGRESS_FILE_NAME)
            self.assertEqual(done["status"], "completed")
            self.assertTrue((output_dir / PLAN_FILE_NAME).is_file())
            stamp = done["heartbeat_at"]
            time.sleep(0.2)
            self.assertEqual(load_json(output_dir / RUN_PROGRESS_FILE_NAME)["heartbeat_at"], stamp)

            # A running file whose owner process is gone is served interrupted.
            plan = build_run_plan(mode="hacking")
            find_task(plan, "eventlog").update(status="running", rows_so_far=40)
            find_task(plan, "browser").update(status="running", rows_so_far=0)
            orphan = {**done, "status": "running", "plan": plan, "_owner": {"pid": DEAD_PID, "boot_id": first["_owner"]["boot_id"], "heartbeat_at": time.time()}}
            (output_dir / RUN_PROGRESS_FILE_NAME).write_text(json.dumps(orphan), encoding="utf-8")
            before = (output_dir / RUN_PROGRESS_FILE_NAME).read_bytes()
            view = load_run_progress_view(output_dir)
            self.assertEqual(view["status"], "interrupted")
            self.assertEqual(view["plan"]["outcome"], "interrupted")
            self.assertEqual(find_task(view["plan"], "eventlog")["status"], "partial")
            self.assertEqual(find_task(view["plan"], "browser")["status"], "cancelled")
            self.assertEqual(find_task(view["plan"], "browser")["reason"], "서버 재시작으로 중단")
            self.assertEqual((output_dir / RUN_PROGRESS_FILE_NAME).read_bytes(), before)

    def test_control_file_watcher_applies_new_requests_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            append_control_request(output_dir, "skip", [{"group": "web"}], actor="cli")  # an earlier run's request
            progress = RunProgress(output_dir, heartbeat_interval=0)
            progress.start(stage="artifacts")
            progress.set_plan(build_run_plan(mode="hacking"))
            watcher = RunControlWatcher(output_dir, progress.apply_control, poll_seconds=0.05)
            watcher.start()
            try:
                append_control_request(output_dir, "skip", [{"group": "messaging"}], actor="cli")
                self.assertTrue(wait_for(lambda: progress.task_status("email") == "skipped", 5))
                self.assertEqual(progress.task_status("browser"), "queued")
                record = progress.task_record("email")
                self.assertEqual(record["reason"], "검사관 요청")
                self.assertEqual(record["requested_by"]["actor"], "cli")
                requests = load_json(output_dir / CONTROL_FILE_NAME)["requests"]
                self.assertEqual([item["seq"] for item in requests], [1, 2])
            finally:
                watcher.stop()
                progress.finish()


class RunControlPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "case-root"
        self.root.mkdir()
        build_run_fixture(self.root)
        self.output_dir = Path(self._tmp.name) / "run-out"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_skip_group_before_start(self) -> None:
        summary = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir, skip_groups=["messaging"], actor="web")
        plan = load_json(self.output_dir / PLAN_FILE_NAME)
        self.assertEqual(plan["outcome"], "complete")
        messaging = [group for group in plan["groups"] if group["id"] == "messaging"][0]
        self.assertEqual(messaging["status"], "skipped")
        self.assertEqual(messaging["counts"], {**messaging["counts"], "total": 6, "skipped": 6, "completed": 0})
        for kind in ("email", "kakaotalk-windows", "windows-messenger", "email-clients"):
            self.assertFalse((self.output_dir / "artifacts" / f"rapidtriage-artifacts-{kind}.json").exists())
            self.assertNotIn(f"artifacts_{kind}", summary["outputs"])
        scheduler = load_json(self.output_dir / "rapidtriage-parser-scheduler.json")
        self.assertNotIn("email", json.dumps(scheduler.get("events", [])))
        steps = {step["name"]: step for step in summary["steps"]}
        self.assertEqual(steps["artifacts-email"]["status"], "skipped")
        self.assertEqual(steps["artifacts-email"]["warning_level"], "warning")
        self.assertIn("실행 전 제외", steps["artifacts-email"]["warning_messages"][0])
        self.assertEqual(summary["safety"]["skip_groups"], ["messaging"])
        # Resolved spellings: CI temp dirs differ (macOS /var -> /private/var, Windows RUNNER~1).
        self.assertEqual(Path(summary["outputs"]["plan"]).resolve(), (self.output_dir / PLAN_FILE_NAME).resolve())
        audit = load_json(self.output_dir / "rapidtriage-run-audit.json")
        self.assertEqual(audit["provenance"]["options"]["skip_groups"], ["messaging"])
        self.assertTrue(any("부분 런" in note for note in audit.get("notes") or audit["provenance"].get("notes") or []))
        checkpoints = load_json(self.output_dir / "rapidtriage-run-checkpoints.json")
        rows = {row["stage"]: row for row in checkpoints["checkpoints"]}
        self.assertEqual(rows["artifacts-email"]["status"], "skipped")
        self.assertIn("건너뛴·취소된 처리", (self.output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8"))
        self.assertEqual(find_task(plan, "image-extract")["status"], "skipped")
        self.assertEqual(find_task(plan, "image-extract")["reason"], "폴더 입력")
        self.assertEqual(load_json(self.output_dir / RUN_PROGRESS_FILE_NAME)["status"], "completed")

    def test_cancel_running_provider_keeps_partial_rows_then_resume_recollects(self) -> None:
        with slow_provider():
            thread = control_when_running(self.output_dir, "eventlog", "cancel", [{"task": "eventlog"}])
            summary = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir)
            thread.join(5)
        plan = summary["plan"]
        task = find_task(plan, "eventlog")
        self.assertEqual(task["status"], "partial")
        self.assertEqual(task["reason"], "실행 중 취소")
        self.assertEqual(task["requested_by"]["actor"], "web")
        self.assertEqual(plan["outcome"], "partial")
        payload = load_json(self.output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.json")
        self.assertEqual(payload["summary"]["collection_status"], "cancelled-partial")
        rows = payload["summary"]["rows_before_cancel"]
        self.assertGreater(rows, 0)
        self.assertLess(rows, 200_000)
        self.assertEqual(payload["summary"]["parser_error_count"], 0)
        jsonl = self.output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.jsonl"
        self.assertEqual(len(jsonl.read_text(encoding="utf-8").splitlines()), rows)
        self.assertEqual(task["artifact_count"], rows)
        steps = {step["name"]: step for step in summary["steps"]}
        self.assertEqual(steps["artifacts-eventlog"]["status"], "partial")
        self.assertEqual(steps["artifacts-eventlog"]["warning_level"], "warning")
        events = load_json(self.output_dir / "rapidtriage-parser-scheduler.json")["events"]
        self.assertEqual([event["status"] for event in events if event["kind"] == "eventlog"], ["cancelled"])
        checkpoints = {row["stage"]: row for row in load_json(self.output_dir / "rapidtriage-run-checkpoints.json")["checkpoints"]}
        self.assertEqual(checkpoints["artifacts-eventlog"]["status"], "partial")
        audit = load_json(self.output_dir / "rapidtriage-run-audit.json")
        control = audit["provenance"]["options"]["plan_control"]
        self.assertEqual([(item["action"], item["actor"]) for item in control], [("cancel", "web")])
        timeline = load_json(self.output_dir / "rapidtriage-timeline.json")
        self.assertTrue(timeline["summary"]["inputs_partial"])
        self.assertIn("eventlog", timeline["summary"]["partial_kinds"])
        self.assertIn("eventlog", summary["case_db"].get("partial_kinds", []))
        other = self.output_dir / "artifacts" / "rapidtriage-artifacts-windows-registry.jsonl"
        other_bytes = other.read_bytes()

        # Resume: completed providers are reused, the partial one is collected again.
        with slow_provider(rows=50):
            resumed = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir, resume=True)
        self.assertEqual(resumed["plan"]["outcome"], "complete")
        self.assertEqual(resumed["plan"]["resumed_from"]["outcome"], "partial")
        self.assertEqual(
            [(item["action"], item["actor"]) for item in resumed["plan"]["resumed_from"]["control_requests"]],
            [("cancel", "web")],
        )
        self.assertTrue(find_task(resumed["plan"], "windows-registry")["reused"])
        self.assertFalse(find_task(resumed["plan"], "eventlog")["reused"])
        self.assertEqual(find_task(resumed["plan"], "eventlog")["status"], "completed")
        self.assertEqual(load_json(self.output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.json")["summary"]["artifact_count"], 50)
        self.assertEqual(other.read_bytes(), other_bytes)
        self.assertIn("artifacts-windows-registry", resumed["safety"]["reused_outputs"])
        self.assertNotIn("timeline", resumed["safety"]["reused_outputs"])

    def test_cancel_all_still_writes_summary_report_and_audit(self) -> None:
        with slow_provider():
            thread = control_when_running(self.output_dir, "eventlog", "cancel_all", actor="cli")
            summary = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir)
            thread.join(5)
        plan = summary["plan"]
        self.assertEqual(plan["outcome"], "cancelled")
        self.assertEqual(find_task(plan, "eventlog")["status"], "partial")
        self.assertEqual(find_task(plan, "browser")["status"], "cancelled")
        self.assertEqual(find_task(plan, "browser")["reason"], "모두 취소 요청")
        for stage in ("docs", "files", "timeline", "indicators", "persist", "triage-flags", "derived"):
            self.assertEqual(find_task(plan, stage)["status"], "cancelled", stage)
        self.assertEqual(find_task(plan, "report")["status"], "completed")
        progress = load_json(self.output_dir / RUN_PROGRESS_FILE_NAME)
        self.assertEqual(progress["status"], "cancelled")
        for name in ("rapidtriage-run-summary.json", "rapidtriage-run-report.md", "rapidtriage-run-audit.json", PLAN_FILE_NAME):
            self.assertTrue((self.output_dir / name).is_file(), name)
        steps = {step["name"]: step for step in summary["steps"]}
        self.assertEqual(steps["timeline"]["status"], "cancelled")
        self.assertEqual(steps["artifacts-browser"]["status"], "cancelled")
        self.assertEqual(load_json(self.output_dir / "rapidtriage-timeline.json")["plan_status"], "cancelled")
        self.assertFalse((self.output_dir / "rapidtriage-case.db").exists())
        report = (self.output_dir / "rapidtriage-run-report.md").read_text(encoding="utf-8")
        self.assertIn("모두 취소", report)

    def test_cancel_all_with_provider_stuck_in_a_call_closes_writers_and_reports_it(self) -> None:
        # The provider yields one row, then sits inside a long call (a parser
        # library that never yields). Cancel arrives through the control file
        # (web jobs.cancel / store.control path); the run must still end
        # promptly with every output file closed (Windows: renamable) and the
        # stuck provider thread reported, not joined forever.
        entered = threading.Event()
        release = threading.Event()

        class StuckCollector(SlowCollector):
            def collect(self, root: Path) -> Iterator[ArtifactRecord]:
                rows = super().collect(root)
                yield next(rows)
                entered.set()
                release.wait(120)
                yield from rows

        real = core_artifacts.get_artifact_collector

        def fake(name: str):
            return StuckCollector("eventlog", 5) if name.strip().lower() == "eventlog" else real(name)

        def cancel_when_stuck() -> None:
            if wait_for(lambda: entered.is_set() and (plan_task(self.output_dir, "eventlog") or {}).get("status") == "running"):
                append_control_request(self.output_dir, "cancel_all", (), actor="web")

        trigger = threading.Thread(target=cancel_when_stuck, daemon=True)
        try:
            with mock.patch.object(core_artifacts, "get_artifact_collector", side_effect=fake), mock.patch.object(
                run_module, "artifact_scheduler_workers", return_value=1
            ), mock.patch.object(core_artifacts, "PROVIDER_STOP_GRACE_SECONDS", 0.5):
                trigger.start()
                started = time.monotonic()
                summary = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir)
                elapsed = time.monotonic() - started
            trigger.join(5)
            self.assertLess(elapsed, 60.0)
            plan = summary["plan"]
            self.assertEqual(plan["outcome"], "cancelled")
            task = find_task(plan, "eventlog")
            self.assertEqual(task["status"], "partial")
            self.assertEqual(task["artifact_count"], 1)
            self.assertEqual(task["provider_thread_left_running"], "rapidtriage-provider-eventlog")
            self.assertEqual(plan["stuck_providers"], [{"task": "eventlog", "thread": "rapidtriage-provider-eventlog"}])
            payload = load_json(self.output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.json")
            self.assertTrue(payload["summary"]["provider_stop_timeout"])
            self.assertEqual(payload["summary"]["rows_before_cancel"], 1)
            # No run worker is left; only the reported stuck provider thread.
            names = [thread.name for thread in threading.enumerate()]
            self.assertFalse([name for name in names if name.startswith(("rapidtriage-artifact", "rapidtriage-manifest"))], names)
            self.assertEqual([name for name in names if name.startswith("rapidtriage-provider-")], ["rapidtriage-provider-eventlog"])
            # Every output file is closed: no temp leftovers, and each file can be
            # renamed (fails with WinError 32 while any handle is open on Windows).
            self.assertEqual(sorted(self.output_dir.rglob("*.tmp")), [])
            jsonl = self.output_dir / "artifacts" / "rapidtriage-artifacts-eventlog.jsonl"
            jsonl_bytes = jsonl.read_bytes()
            for path in [item for item in self.output_dir.rglob("*") if item.is_file()]:
                moved = path.with_name(path.name + ".moved")
                os.rename(path, moved)
                os.rename(moved, path)
        finally:
            release.set()
        stuck = [thread for thread in threading.enumerate() if thread.name == "rapidtriage-provider-eventlog"]
        for thread in stuck:
            thread.join(10)
            self.assertFalse(thread.is_alive())
        # The released provider's later rows are dropped; nothing is rewritten.
        self.assertEqual(jsonl.read_bytes(), jsonl_bytes)
        self.assertEqual(sorted(self.output_dir.rglob("*.tmp")), [])

    def test_finish_cancels_queued_providers_and_finishes_later_stages(self) -> None:
        with slow_provider(rows=2500):
            thread = control_when_running(self.output_dir, "eventlog", "finish", actor="web")
            summary = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir)
            thread.join(5)
        plan = summary["plan"]
        self.assertEqual(plan["outcome"], "partial")
        self.assertEqual(find_task(plan, "eventlog")["status"], "completed")
        self.assertEqual(find_task(plan, "browser")["status"], "cancelled")
        self.assertEqual(find_task(plan, "browser")["reason"], "마치기 요청")
        self.assertEqual(find_task(plan, "windows-registry")["status"], "completed")
        for stage in ("docs", "files", "timeline", "indicators", "persist"):
            self.assertEqual(find_task(plan, stage)["status"], "completed", stage)
        self.assertTrue((self.output_dir / "rapidtriage-case.db").is_file())
        self.assertTrue(load_json(self.output_dir / "rapidtriage-timeline.json")["summary"]["inputs_partial"])
        self.assertEqual(load_json(self.output_dir / RUN_PROGRESS_FILE_NAME)["status"], "completed")


class JobStoreTests(unittest.TestCase):
    def test_canceled_spelling_and_restart_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "runs.json"
            request = RunRequest(root=tmp, mode="hacking", output_dir=str(Path(tmp) / "out"))
            records = [
                {**RunJob(run_id="old1", request=request, status="canceled").to_record(), "status": "canceled"},
                {**RunJob(run_id="run1", request=request, status="running").to_record()},
            ]
            state.write_text(json.dumps({"version": 1, "runs": records}), encoding="utf-8")
            store = RunJobStore(state_path=state)
            self.assertEqual(store.get("old1").status, "cancelled")
            interrupted = store.get("run1")
            self.assertEqual(interrupted.status, "interrupted")
            self.assertEqual(interrupted.error, "서버 재시작으로 중단")
            saved = load_json(state)
            self.assertNotIn("canceled", [run["status"] for run in saved["runs"]])
            with mock.patch.object(store, "submit", side_effect=lambda req, **_kwargs: RunJob(run_id="new", request=req)) as submit:
                store.retry("run1", resume=True)
                resumed_request = submit.call_args.args[0]
                self.assertTrue(resumed_request.resume)
                self.assertEqual(resumed_request.output_dir, str((Path(tmp) / "out").resolve()))
                store.retry("old1")
                self.assertFalse(submit.call_args.args[0].resume)
            store._jobs["done"] = RunJob(run_id="done", request=request, status="completed")
            with self.assertRaisesRegex(ValueError, "실패·취소·중단된 런만"):
                store.retry("done")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class RunPlanApiTests(unittest.TestCase):
    def client(self, store: RunJobStore) -> TestClient:
        return TestClient(create_app(store, auth_token=TEST_API_TOKEN), headers={"X-RapidTriage-Token": TEST_API_TOKEN})

    def test_preview_create_validation_and_finished_control(self) -> None:
        store = RunJobStore()
        client = self.client(store)
        preview = client.get("/api/run-plan/preview", params={"mode": "hacking"})
        self.assertEqual(preview.status_code, 200)
        self.assertIn("messaging", [group["id"] for group in preview.json()["groups"]])
        self.assertEqual(client.get("/api/run-plan/preview", params={"mode": "nope"}).status_code, 400)
        with tempfile.TemporaryDirectory() as tmp:
            bad = client.post("/api/runs", json={"root": tmp, "mode": "hacking", "skip_groups": ["report"]})
            self.assertEqual(bad.status_code, 400)
            self.assertEqual(bad.json()["detail"], "건너뛸 수 없는 그룹입니다: report")
            bad = client.post("/api/runs", json={"root": tmp, "mode": "hacking", "skip_groups": ["zzz"]})
            self.assertEqual(bad.json()["detail"], "알 수 없는 그룹입니다: zzz")
            root = Path(tmp) / "root"
            root.mkdir()
            build_run_fixture(root)
            response = client.post(
                "/api/runs",
                json={"root": str(root), "mode": "hacking", "output_dir": str(Path(tmp) / "out"), "skip_groups": ["mobile", "cloud"], "wait": True},
            )
            self.assertEqual(response.status_code, 202)
            run_id = response.json()["run_id"]
            self.assertEqual(response.json()["status"], "completed")
            plan = client.get(f"/api/runs/{run_id}/plan")
            self.assertEqual(plan.status_code, 200)
            body = plan.json()
            self.assertEqual(body["run_status"], "completed")
            self.assertEqual([g["status"] for g in body["groups"] if g["id"] in {"mobile", "cloud"}], ["skipped", "skipped"])
            self.assertEqual(find_task(body, "android-apk")["requested_by"]["actor"], "web")
            again = client.get(f"/api/runs/{run_id}/plan", headers={"If-None-Match": plan.headers["etag"]})
            self.assertEqual(again.status_code, 304)
            control = client.post(f"/api/runs/{run_id}/plan/control", json={"action": "cancel", "targets": [{"task": "eventlog"}]})
            self.assertEqual(control.status_code, 409)
            self.assertEqual(control.json()["detail"], "실행 중인 런이 아닙니다")
            self.assertEqual(client.post("/api/runs/nope/plan/control", json={"action": "finish"}).status_code, 404)
            summary = client.get(f"/api/runs/{run_id}/summary").json()
            self.assertEqual(summary["safety"]["skip_groups"], ["mobile", "cloud"])
            retry = client.post(f"/api/runs/{run_id}/retry", json={"resume": True})
            self.assertEqual(retry.status_code, 409)
            self.assertEqual(retry.json()["detail"], "실패·취소·중단된 런만 다시 실행할 수 있습니다")

    def test_live_tree_artifacts_and_control_while_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            build_run_fixture(root)
            source_out = Path(tmp) / "done"
            run_triage_mode(root, mode="hacking", output_dir=source_out)
            output_dir = Path(tmp) / "live"
            (output_dir / "artifacts").mkdir(parents=True)
            for suffix in (".json", ".jsonl"):
                shutil.copy(source_out / "artifacts" / f"rapidtriage-artifacts-windows-registry{suffix}", output_dir / "artifacts")
            store = RunJobStore()
            job = RunJob(run_id="live1", request=RunRequest(root=str(root), mode="hacking", output_dir=str(output_dir)), status="running")
            store._jobs["live1"] = job
            progress = RunProgress(output_dir, heartbeat_interval=0)
            progress.start(stage="artifacts")
            progress.set_plan(build_run_plan(mode="hacking"))
            outside = Path(tmp) / "outside.json"
            shutil.copy(source_out / "artifacts" / "rapidtriage-artifacts-browser.json", outside)
            try:
                registry = output_dir / "artifacts" / "rapidtriage-artifacts-windows-registry.json"
                progress.provider_running("windows-registry")
                progress.provider_finished(
                    "windows-registry",
                    status="completed",
                    artifact_count=load_json(registry)["summary"]["artifact_count"],
                    output={"path": str(registry), "records_path": str(registry.with_suffix(".jsonl"))},
                )
                progress.provider_running("browser")
                progress.provider_finished("browser", status="completed", artifact_count=3, output={"path": str(outside)})
                progress.provider_running("eventlog")
                client = self.client(store)
                tree = client.get("/api/runs/live1/tree")
                self.assertEqual(tree.status_code, 200, tree.text)
                live = tree.json()["live"]
                self.assertEqual(live["available_kinds"], ["windows-registry"])
                self.assertIn("eventlog", live["pending_kinds"])
                self.assertIn("browser", live["pending_kinds"])  # its output path is outside the run dir
                kinds = {
                    node["kind"]: node
                    for group in [n for n in tree.json()["nodes"] if n["id"] == "artifacts"][0]["children"]
                    for node in group["children"]
                }
                self.assertNotIn("disabled", kinds["windows-registry"])
                self.assertGreater(kinds["windows-registry"]["count"], 0)
                self.assertTrue(kinds["eventlog"]["disabled"])
                self.assertIn("처리 중", kinds["eventlog"]["reason"])
                self.assertIn("대기 중", kinds["email"]["reason"])
                artifacts = client.get("/api/runs/live1/artifacts", params={"kind": "windows-registry", "limit": 5})
                self.assertEqual(artifacts.status_code, 200, artifacts.text)
                self.assertTrue(artifacts.json()["artifacts"]["windows-registry"]["artifacts"])
                self.assertTrue(artifacts.json()["live"]["partial"])
                self.assertEqual(client.get("/api/runs/live1/artifacts", params={"kind": "browser", "limit": 5}).json()["artifacts"], {})
                timeline = client.get("/api/runs/live1/timeline")
                self.assertEqual(timeline.status_code, 409)
                self.assertIn("런 마무리 후 사용할 수 있습니다", timeline.json()["detail"])
                runs = client.get("/api/runs").json()["runs"]
                row = [item for item in runs if item["run_id"] == "live1"][0]
                self.assertEqual(row["progress"]["plan_counts"]["completed"], 2)
                self.assertEqual(row["progress"]["current"][0]["task"], "eventlog")
                self.assertTrue(row["progress"]["live"])
                progress.control_watcher = RunControlWatcher(output_dir, progress.apply_control, poll_seconds=60)
                control = client.post(
                    "/api/runs/live1/plan/control",
                    json={"action": "skip", "targets": [{"group": "messaging"}, {"task": "eventlog"}, {"task": "windows-registry"}]},
                )
                self.assertEqual(control.status_code, 202, control.text)
                result = control.json()
                self.assertEqual(result["accepted"], [{"group": "messaging"}])
                self.assertEqual(len(result["rejected"]), 2)
                self.assertEqual(find_task(result["plan"], "email")["status"], "skipped")
                self.assertEqual(client.post("/api/runs/live1/plan/control", json={"action": "cancel"}).status_code, 400)
                cancel = client.post("/api/runs/live1/cancel")
                self.assertEqual(cancel.status_code, 200)
                self.assertTrue(progress.cancel_all_requested.is_set())
                self.assertEqual(find_task(cancel.json()["plan"], "docs")["status"], "cancelled")
            finally:
                progress.finish()


class RunPlanCliTests(unittest.TestCase):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
            try:
                code = cli_main(list(argv))
            except SystemExit as exc:
                code = int(exc.code or 0)
        return code, buffer.getvalue()

    def test_print_plan_run_plan_and_run_control(self) -> None:
        code, out = self.run_cli("run", ".", "--mode", "hacking", "--print-plan", "json", "--skip-group", "messaging")
        self.assertEqual(code, 0)
        plan = json.loads(out)
        self.assertEqual(find_task(plan, "email")["status"], "skipped")
        code, out = self.run_cli("run", ".", "--mode", "hacking", "--print-plan")
        self.assertIn("그룹 25 / 태스크", out)
        self.assertEqual(self.run_cli("run", ".", "--mode", "hacking", "--print-plan", "--skip-group", "report")[0], 2)
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            self.assertEqual(self.run_cli("run-control", tmp, "finish")[0], 2)  # no running run
            progress = RunProgress(output_dir, heartbeat_interval=0)
            progress.start(stage="artifacts")
            progress.set_plan(build_run_plan(mode="hacking"))
            try:
                code, out = self.run_cli("run-control", tmp, "cancel", "--target", "task:eventlog", "--target", "group:web")
                self.assertEqual(code, 0)
                request = json.loads(out)["request"]
                self.assertEqual(request["actor"], "cli")
                self.assertEqual(request["targets"], [{"task": "eventlog"}, {"group": "web"}])
                code, _out = self.run_cli("run-control", tmp, "cancel")
                self.assertEqual(load_json(output_dir / CONTROL_FILE_NAME)["requests"][-1]["action"], "cancel_all")
                self.assertEqual(self.run_cli("run-control", tmp, "skip", "--target", "bad")[0], 2)
                code, out = self.run_cli("run-plan", tmp)
                self.assertEqual(code, 0)
                self.assertIn("eventlog", out)
            finally:
                progress.finish()

    @unittest.skipUnless(sys.platform == "win32" or hasattr(signal, "SIGINT"), "signals required")
    def test_ctrl_c_cancels_all_with_summary_and_exit_130(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            build_run_fixture(root)
            plugins = Path(tmp) / "plugins"
            plugins.mkdir()
            (plugins / "slowtest_provider.py").write_text(
                "import time\n"
                "from rapidtriage.core.models import ArtifactRecord\n"
                "class SlowTestProvider:\n"
                "    collector_kind = 'slow-test'\n"
                "    name = 'slow-test'\n"
                "    description = 'slow test provider'\n"
                "    target_platform = 'any'\n"
                "    def supported(self):\n"
                "        return True\n"
                "    def collect(self, root):\n"
                "        for index in range(100000):\n"
                "            time.sleep(0.005)\n"
                "            yield ArtifactRecord(provider='slow-test', artifact_type='slow-row', path=str(root), supported=True, details={'n': index})\n",
                encoding="utf-8",
            )
            output_dir = Path(tmp) / "out"
            env = {**os.environ, "RAPIDTRIAGE_PLUGIN_DIRS": str(plugins), "PYTHONIOENCODING": "utf-8"}
            kwargs: dict = {}
            if sys.platform == "win32":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            # synthetic-media is skipped: with the optional deepfake_lens installed
            # its analysis of the fixture images takes minutes, and the plugin
            # provider (manifest stage) only starts after the artifacts stage.
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "rapidtriage", "run", str(root), "--mode", "hacking",
                    "--output-dir", str(output_dir), "--skip-task", "synthetic-media",
                ],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **kwargs,
            )
            try:
                running = wait_for(lambda: (plan_task(output_dir, "slow-test") or {}).get("status") == "running", 120)
                self.assertTrue(running, "slow provider never started")
                if sys.platform == "win32":
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=180)
            finally:
                if process.poll() is None:
                    process.kill()
                # Reap the process before the temp dir is removed: on Windows its
                # open handles block the cleanup until it has really exited.
                process.wait(60)
            self.assertEqual(process.returncode, 130, stderr.decode("utf-8", "replace")[-2000:])
            # Nothing of the run is left open or half-written once the CLI returned.
            self.assertEqual(sorted(output_dir.rglob("*.tmp")), [])
            for path in [item for item in output_dir.rglob("*") if item.is_file()]:
                moved = path.with_name(path.name + ".moved")
                os.rename(path, moved)
                os.rename(moved, path)
            plan = load_json(output_dir / PLAN_FILE_NAME)
            self.assertEqual(plan["outcome"], "cancelled")
            self.assertEqual(find_task(plan, "slow-test")["status"], "partial")
            self.assertEqual(plan["control"]["requests"][0]["actor"], "cli")
            self.assertTrue((output_dir / "rapidtriage-run-summary.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-run-audit.json").is_file())
            self.assertIn(b"Saved run summary JSON", stdout)
            self.assertNotIn("stuck_providers", plan)


if __name__ == "__main__":
    unittest.main()
