"""Adversarial-review regressions for the r4 run plan (resume, retry, control file, caches)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core.jobs import (
    PLAN_NOT_WRITTEN_MESSAGE,
    QUEUED_CONTROL_MESSAGE,
    RunControlConflict,
    RunJob,
    RunJobStore,
    RunOutputDirBusy,
    RunRequest,
)
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.run.incremental_indexing import load_reusable_json
from rapidtriage.core.run.plan import (
    CONTROL_FILE_NAME,
    ControlFileError,
    RunControlWatcher,
    append_control_request,
    build_run_plan,
    control_file_lock,
    control_path,
    evaluate_control,
    find_task,
    utc_now,
)
from rapidtriage.core.run.progress import (
    RUN_PROGRESS_FILE_NAME,
    RunProgress,
    active_run_progress,
    read_run_progress,
)
from tests.test_rapidtriage_run import build_run_fixture
from tests.test_rapidtriage_run_plan import (
    DEAD_PID,
    control_when_running,
    load_json,
    slow_provider,
)

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, fs_tree, media_similar, registry_tree

    HAS_FASTAPI = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

REPO_ROOT = Path(__file__).resolve().parent.parent
TOKEN = "run-plan-review-token"


class BlockingExecuteStore(RunJobStore):
    """Job store whose workers wait (jobs stay ``queued``) until ``release`` is set."""

    def __init__(self, **kwargs: object) -> None:
        self.release = threading.Event()
        super().__init__(**kwargs)

    def _execute(self, run_id: str) -> dict[str, object]:
        self.release.wait(10)
        return {}


def stage_task(summary: dict, task_id: str) -> dict:
    return find_task(summary["plan"], task_id)


class ChainedResumeTests(unittest.TestCase):
    """#1: a chain of resumes never reuses placeholder/partial stage outputs."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name) / "case-root"
        self.root.mkdir()
        build_run_fixture(self.root)
        self.output_dir = Path(self._tmp.name) / "run-out"

    def test_cancelled_then_interrupted_resume_then_resume_rebuilds_stage_outputs(self) -> None:
        with slow_provider():
            thread = control_when_running(self.output_dir, "eventlog", "cancel_all", actor="cli")
            first = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir)
            thread.join(5)
        self.assertEqual(first["plan"]["outcome"], "cancelled")
        self.assertEqual(load_json(self.output_dir / "rapidtriage-timeline.json")["plan_status"], "cancelled")
        self.assertTrue(load_json(self.output_dir / "rapidtriage-manifest.json")["inputs_partial"])
        # Run B: a resume that died before rebuilding anything (outcome still None, owner gone).
        progress = read_run_progress(self.output_dir)
        progress["status"] = "running"
        progress["plan"]["outcome"] = None
        progress["_owner"] = {"pid": DEAD_PID, "boot_id": 0, "heartbeat_at": 0}
        (self.output_dir / RUN_PROGRESS_FILE_NAME).write_text(json.dumps(progress), encoding="utf-8")
        # Run C: resume again.
        with slow_provider(rows=50):
            resumed = run_triage_mode(self.root, mode="hacking", output_dir=self.output_dir, resume=True)
        self.assertEqual(resumed["plan"]["outcome"], "complete")
        self.assertEqual(resumed["plan"]["resumed_from"]["outcome"], "interrupted")
        reused = set(resumed["safety"]["reused_outputs"])
        for stage in ("manifest", "docs", "files", "timeline", "indicators"):
            self.assertNotIn(stage, reused, stage)
        self.assertIn("did not end complete", resumed["safety"]["resume_disabled_reason"])
        timeline = load_json(self.output_dir / "rapidtriage-timeline.json")
        self.assertNotIn("plan_status", timeline)
        self.assertNotIn("inputs_partial", timeline)
        self.assertEqual(stage_task(resumed, "timeline")["status"], "completed")
        self.assertFalse(stage_task(resumed, "timeline")["reused"])
        self.assertGreater(timeline["summary"].get("event_count", len(timeline.get("events") or [])), 0)

    def test_placeholder_and_partial_payloads_are_never_reusable(self) -> None:
        directory = Path(self._tmp.name)
        cases = {
            "complete.json": ({"command": "timeline", "summary": {}, "events": []}, True),
            "placeholder.json": ({"command": "timeline", "summary": {}, "events": [], "plan_status": "cancelled"}, False),
            "skipped-summary.json": ({"command": "timeline", "summary": {"plan_status": "skipped"}, "events": []}, False),
            "partial.json": ({"command": "timeline", "summary": {}, "events": [], "inputs_partial": True}, False),
            "partial-summary.json": ({"command": "timeline", "summary": {"inputs_partial": True}, "events": []}, False),
        }
        for name, (payload, reusable) in cases.items():
            path = directory / name
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_reusable_json(path, expected_command="timeline", required_keys=("summary", "events"))
            self.assertEqual(loaded is not None, reusable, name)


class OutputDirGuardTests(unittest.TestCase):
    """#2 concurrent resume / submit into one folder, #4 fresh retry, #8 superseded runs."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.out = self.base / "out"
        self.store = BlockingExecuteStore()
        self.addCleanup(self.store.release.set)
        request = RunRequest(root=str(self.base), mode="hacking", output_dir=str(self.out))
        self.store._jobs["old"] = RunJob(run_id="old", request=request, status="interrupted")

    def test_second_resume_and_same_folder_submit_are_rejected(self) -> None:
        first = self.store.retry("old", resume=True)
        self.assertEqual(first.status, "queued")
        old = self.store.get("old")
        self.assertEqual((old.retried_by, old.superseded_by), (first.run_id, first.run_id))
        with self.assertRaises(RunOutputDirBusy) as caught:
            self.store.retry("old", resume=True)
        self.assertIn(first.run_id, str(caught.exception))
        self.assertIn("같은 출력 폴더", str(caught.exception))
        with self.assertRaises(RunOutputDirBusy):
            self.store.submit(RunRequest(root=str(self.base), mode="hacking", output_dir=str(self.out) + os.sep))
        # Another folder is fine.
        other = self.store.submit(RunRequest(root=str(self.base), mode="hacking", output_dir=str(self.base / "other")))
        self.assertEqual(other.status, "queued")

    def test_fresh_retry_of_a_resumed_run_does_not_resume_and_writes_a_new_folder(self) -> None:
        request = RunRequest(root=str(self.base), mode="hacking", output_dir=str(self.out), resume=True)
        self.store._jobs["resumed"] = RunJob(run_id="resumed", request=request, status="failed")
        retry = self.store.retry("resumed", resume=False)
        self.assertFalse(retry.request.resume)
        new_dir = Path(str(retry.request.output_dir))
        self.assertNotEqual(new_dir, self.out.resolve())
        self.assertEqual(new_dir.parent, self.out.resolve().parent)
        self.assertTrue(new_dir.name.startswith("out-retry-"))
        resumed = self.store.get("resumed")
        self.assertEqual(resumed.retried_by, retry.run_id)
        self.assertIsNone(resumed.superseded_by)
        # A run without an explicit folder keeps the per-run default folder.
        self.store._jobs["plain"] = RunJob(run_id="plain", request=RunRequest(root=str(self.base), mode="hacking"), status="failed")
        plain_retry = self.store.retry("plain")
        self.assertIsNone(plain_retry.request.output_dir)
        self.assertNotEqual(plain_retry.output_dir(), self.store.get("plain").output_dir())

    @unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
    def test_api_conflicts_and_superseded_plan(self) -> None:
        # The old run left a progress file whose owner died (interrupted).
        self.out.mkdir()
        progress = RunProgress(self.out, heartbeat_interval=0)
        progress.start(stage="artifacts")
        progress.set_plan(build_run_plan(mode="hacking"))
        payload = read_run_progress(self.out)
        payload["_owner"] = {"pid": DEAD_PID, "boot_id": 0, "heartbeat_at": 0}
        progress._deactivate()
        (self.out / RUN_PROGRESS_FILE_NAME).write_text(json.dumps(payload), encoding="utf-8")
        client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})
        before = client.get("/api/runs/old/plan").json()
        self.assertIsNone(before["superseded_by"])
        self.assertTrue(before["groups"])
        retry = client.post("/api/runs/old/retry", json={"resume": True})
        self.assertEqual(retry.status_code, 202, retry.text)
        new_id = retry.json()["run_id"]
        again = client.post("/api/runs/old/retry", json={"resume": True})
        self.assertEqual(again.status_code, 409)
        self.assertIn("같은 출력 폴더", again.json()["detail"])
        create = client.post("/api/runs", json={"root": str(self.base), "mode": "hacking", "output_dir": str(self.out)})
        self.assertEqual(create.status_code, 409)
        old_plan = client.get("/api/runs/old/plan").json()
        self.assertEqual(old_plan["superseded_by"], new_id)
        self.assertEqual(old_plan["groups"], [])
        self.assertFalse(old_plan["live"])
        self.assertIn(new_id, old_plan["message"])
        old_run = client.get("/api/runs/old").json()
        self.assertEqual(old_run["superseded_by"], new_id)
        self.assertEqual(old_run["progress"]["superseded_by"], new_id)
        # The queued resume's own plan is a skeleton (the folder still holds the old run's plan).
        new_plan = client.get(f"/api/runs/{new_id}/plan")
        self.assertEqual(new_plan.json()["run_status"], "queued")
        self.assertIsNone(new_plan.json()["started_at"])
        self.assertTrue(all(task["status"] in {"queued", "skipped"} for group in new_plan.json()["groups"] for task in group["tasks"]))
        # Stable ETag for a queued run's skeleton.
        cached = client.get(f"/api/runs/{new_id}/plan", headers={"If-None-Match": new_plan.headers["etag"]})
        self.assertEqual(cached.status_code, 304)
        # Control of a queued run is refused instead of judged against the old run's plan.
        control = client.post(f"/api/runs/{new_id}/plan/control", json={"action": "skip", "targets": [{"group": "web"}]})
        self.assertEqual(control.status_code, 409)
        self.assertEqual(control.json()["detail"], QUEUED_CONTROL_MESSAGE)
        self.assertFalse((self.out / CONTROL_FILE_NAME).exists())


class ControlTimingTests(unittest.TestCase):
    """#3 cancel_all before the watcher, stale plan of a running job; #5 late cancel_all."""

    def test_watcher_since_applies_requests_written_after_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            append_control_request(output_dir, "skip", [{"group": "web"}])  # an earlier run's request
            time.sleep(0.01)
            since = utc_now()
            append_control_request(output_dir, "cancel_all", (), actor="web")  # written before the watcher exists
            seen: list[dict] = []
            RunControlWatcher(output_dir, seen.append, since=since).poll()
            self.assertEqual([item["action"] for item in seen], ["cancel_all"])
            legacy: list[dict] = []
            RunControlWatcher(output_dir, legacy.append).poll()
            self.assertEqual(legacy, [])

    def test_run_applies_cancel_all_written_before_it_started(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case-root"
            root.mkdir()
            build_run_fixture(root)
            output_dir = Path(tmp) / "out"
            output_dir.mkdir()
            submitted = utc_now()
            append_control_request(output_dir, "cancel_all", (), actor="web")
            summary = run_triage_mode(root, mode="hacking", output_dir=output_dir, control_since=submitted)
            self.assertEqual(summary["plan"]["outcome"], "cancelled")
            self.assertEqual(load_json(output_dir / RUN_PROGRESS_FILE_NAME)["status"], "cancelled")

    def test_running_job_does_not_use_an_earlier_runs_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            progress = RunProgress(output_dir, heartbeat_interval=0)
            progress.start(stage="artifacts")
            progress.set_plan(build_run_plan(mode="hacking"))
            try:
                time.sleep(0.01)
                store = RunJobStore()
                request = RunRequest(root=tmp, mode="hacking", output_dir=str(output_dir), resume=True)
                store._jobs["new"] = RunJob(run_id="new", request=request, status="running")
                with self.assertRaises(RunControlConflict) as caught:
                    store.control("new", "skip", [{"group": "web"}])
                self.assertEqual(str(caught.exception), PLAN_NOT_WRITTEN_MESSAGE)
                self.assertFalse((output_dir / CONTROL_FILE_NAME).exists())
            finally:
                progress.finish()

    def test_cancel_all_after_report_started_is_rejected_and_files_agree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            store = RunJobStore()
            store._jobs["r"] = RunJob(run_id="r", request=RunRequest(root=tmp, mode="hacking", output_dir=str(output_dir)), status="running")
            progress = RunProgress(output_dir, heartbeat_interval=0)
            progress.start(stage="prepare")
            plan = build_run_plan(mode="hacking")
            for group in plan["groups"]:
                for task in group["tasks"]:
                    if task["status"] == "queued" and task["id"] != "report":
                        task["status"] = "completed"
            progress.set_plan(plan)
            progress.control_watcher = RunControlWatcher(output_dir, progress.apply_control, poll_seconds=60)
            progress.begin_stage("report")
            _accepted, rejected, effects = evaluate_control(progress.plan_snapshot(), "cancel_all")
            self.assertEqual(effects, {})
            self.assertIn("이미 끝난 태스크", rejected[0]["reason"])
            with self.assertRaises(RunControlConflict) as caught:
                store.cancel("r")
            self.assertIn("이미 끝난 태스크", str(caught.exception))
            self.assertFalse(store.get("r").cancellation_requested)
            result = store.control("r", "cancel_all")
            self.assertIn("이미 끝난 태스크", result["rejected"][0]["reason"])
            # Even a request written straight to the control file is rejected by the run.
            progress.apply_control({"action": "cancel_all", "targets": [], "actor": "cli", "at": utc_now(), "seq": 9})
            self.assertFalse(progress.cancel_all_requested.is_set())
            final = progress.finalize_plan()
            progress.finish()
            self.assertEqual(final["outcome"], "complete")
            self.assertIsNone(final["control"]["cancel_all_at"])
            self.assertEqual(load_json(output_dir / RUN_PROGRESS_FILE_NAME)["status"], "completed")
            self.assertEqual(load_json(output_dir / "rapidtriage-run-plan.json")["outcome"], "complete")

    def test_finish_writes_final_status_before_leaving_the_active_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            progress = RunProgress(output_dir, heartbeat_interval=0)
            progress.start(stage="prepare")
            progress.set_plan(build_run_plan(mode="hacking"))
            seen: list[object] = []
            real = progress._write_plan_file_locked

            def spy() -> None:
                seen.append(active_run_progress(output_dir))
                real()

            with mock.patch.object(progress, "_write_plan_file_locked", side_effect=spy):
                progress.finish()
            self.assertIs(seen[0], progress)
            self.assertIsNone(active_run_progress(output_dir))
            self.assertEqual(load_json(output_dir / RUN_PROGRESS_FILE_NAME)["status"], "completed")


class ControlFileTests(unittest.TestCase):
    """#6 control-file read-modify-write safety."""

    def test_unreadable_file_aborts_the_append_and_keeps_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            for _ in range(3):
                append_control_request(output_dir, "skip", [{"task": "browser"}])
            seen: list[dict] = []
            watcher = RunControlWatcher(output_dir, seen.append)
            control_path(output_dir).write_text("{garbage", encoding="utf-8")
            with self.assertRaises(ControlFileError) as caught:
                append_control_request(output_dir, "cancel_all", ())
            self.assertIn("읽을 수 없어", str(caught.exception))
            self.assertEqual(control_path(output_dir).read_text(encoding="utf-8"), "{garbage")
            watcher.poll()  # unreadable: nothing applied, stamp not recorded
            self.assertEqual(seen, [])
            requests = [{"seq": n, "action": "skip", "targets": [{"task": "browser"}], "actor": "cli", "at": utc_now()} for n in (1, 2, 3)]
            requests.append({"seq": 4, "action": "cancel_all", "targets": [], "actor": "web", "at": utc_now()})
            control_path(output_dir).write_text(json.dumps({"version": "run-control-v1", "requests": requests}), encoding="utf-8")
            watcher.poll()
            self.assertEqual([item["seq"] for item in seen], [4])
            self.assertEqual(append_control_request(output_dir, "finish")["seq"], 5)

    def test_lock_file_busy_and_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            lock = output_dir / (CONTROL_FILE_NAME + ".lock")
            lock.write_text("other", encoding="utf-8")
            with self.assertRaises(ControlFileError) as caught:
                with control_file_lock(output_dir, timeout=0.1):
                    pass
            self.assertIn("잠겨", str(caught.exception))
            old = time.time() - 3600
            os.utime(lock, (old, old))
            self.assertEqual(append_control_request(output_dir, "finish")["seq"], 1)
            self.assertFalse(lock.exists())

    def test_appends_from_two_processes_keep_unique_seq(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            script = (
                "import sys\n"
                "from pathlib import Path\n"
                "from rapidtriage.core.run.plan import append_control_request\n"
                "for _ in range(15):\n"
                "    append_control_request(Path(sys.argv[1]), 'skip', [{'task': 'browser'}])\n"
            )
            env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
            workers = [
                subprocess.Popen([sys.executable, "-c", script, tmp], cwd=str(REPO_ROOT), env=env)
                for _ in range(3)
            ]
            for worker in workers:
                self.assertEqual(worker.wait(60), 0)
            seqs = [item["seq"] for item in load_json(Path(tmp) / CONTROL_FILE_NAME)["requests"]]
            self.assertEqual(sorted(seqs), list(range(1, 46)))


class LegacySpellingTests(unittest.TestCase):
    """#7 ``canceled`` in steps and transition logs of older state files."""

    def test_steps_and_transitions_are_normalized(self) -> None:
        record = RunJob(run_id="x", request=RunRequest(root=".", mode="hacking"), status="cancelled").to_record()
        record["status"] = "canceled"
        record["steps"][0]["status"] = "canceled"
        record["transition_log"].append(
            {"sequence": 2, "event_type": "job-canceled", "status": "canceled", "step": "prepare", "step_status": "canceled", "message": "", "details": {}}
        )
        job = RunJob.from_record(record)
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(job.steps[0]["status"], "cancelled")
        last = job.transition_log[-1]
        self.assertEqual((last["event_type"], last["status"], last["step_status"]), ("job-cancelled", "cancelled", "cancelled"))


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class ExplorerCacheTests(unittest.TestCase):
    """Index caches: no leaked build locks, media builds outside the cache lock, folder positions cached."""

    def test_failed_builds_do_not_leak_locks(self) -> None:
        caches = [
            (fs_tree.FsIndexCache(), fs_tree, "build_fs_index", lambda cache: cache.get(("r", 1), {})),
            (registry_tree.RegistryIndexCache(), registry_tree, "build_registry_index", lambda cache: cache.get(("r", 1), [])),
            (media_similar.MediaIndexCache(), media_similar, "build_media_index", lambda cache: cache.get(("r", 1), {}, Path("x"))),
        ]
        for cache, module, name, call in caches:
            with mock.patch.object(module, name, side_effect=RuntimeError("boom")):
                for _ in range(3):
                    with self.assertRaises(RuntimeError):
                        call(cache)
            self.assertEqual(cache.pending_builds(), 0, name)

    def test_media_index_builds_outside_the_cache_lock_single_flight(self) -> None:
        cache = media_similar.MediaIndexCache()
        builds: list[bool] = []
        gate = threading.Event()

        def build(key, payload, payload_path):
            builds.append(cache._lock.locked())
            gate.wait(5)
            return media_similar.MediaIndex(key=key)

        with mock.patch.object(media_similar, "build_media_index", side_effect=build):
            results: list[object] = []
            threads = [threading.Thread(target=lambda: results.append(cache.get(("r", 1), {}, Path("x")))) for _ in range(4)]
            for thread in threads:
                thread.start()
            time.sleep(0.2)
            # Other keys are not blocked by the running build.
            other_done = threading.Event()
            with mock.patch.object(media_similar, "build_media_index", side_effect=lambda *a: other_done.set() or object()):
                cache.get(("other", 1), {}, Path("y"))
            self.assertTrue(other_done.is_set())
            gate.set()
            for thread in threads:
                thread.join(5)
        self.assertEqual(builds, [False])
        self.assertEqual(len({id(item) for item in results}), 1)

    def test_folder_positions_are_cached_per_index(self) -> None:
        root = "C:/ev"
        rows = [{"path": f"{root}/a/{n}.txt", "relative_path": f"a/{n}.txt", "size": 1} for n in range(5)]
        rows.append({"path": f"{root}/b/x.txt", "relative_path": "b/x.txt", "size": 1})
        index = fs_tree.build_fs_index(("r",), {"root": root, "candidates": rows, "inventory": []})
        first = fs_tree.files_restriction(index, "candidates", ["a"], recursive=False)
        self.assertEqual(list(first), [0, 1, 2, 3, 4])
        self.assertIs(fs_tree.files_restriction(index, "candidates", ["a"], recursive=False), first)
        self.assertEqual(list(fs_tree.files_restriction(index, "candidates", [], recursive=True)), [0, 1, 2, 3, 4, 5])
        with mock.patch.object(fs_tree, "FS_RESTRICTION_CACHE_ENTRIES", 1):
            fs_tree.files_restriction(index, "candidates", ["b"], recursive=False)
        self.assertEqual(len(index.restrictions), 1)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required")
class RegistryMountGuessTests(unittest.TestCase):
    """The hive root row arriving after a key whose mount was guessed re-mounts the hive."""

    @staticmethod
    def row(key_path: str, *, root: bool = False) -> dict[str, object]:
        return {
            "artifact_type": "registry-key-tree-node",
            "path": "C:/ev/NTUSER.DAT",
            "details": {"key_path": key_path, "is_root_key": root, "name": key_path.rsplit("\\", 1)[-1], "value_count": 0, "subkey_count": 0},
        }

    def build(self, rows: list[dict[str, object]]):
        payload = {"artifacts": rows}
        index = registry_tree.build_registry_index(("r",), [(registry_tree.REGISTRY_KIND, payload, Path("x.json"))])
        self.assertEqual(len(index.hives), 1)
        return index, next(iter(index.hives.values()))

    def test_real_root_deeper_than_the_guess(self) -> None:
        index, hive = self.build(
            [self.row(r"HKU\S-1\Classes\Software"), self.row(r"HKU\S-1\Classes", root=True), self.row(r"HKU\S-1\Classes\Software\Run")]
        )
        self.assertEqual(hive.mount, r"HKU\S-1\Classes")
        self.assertEqual(index.key_path(hive.root), r"HKU\S-1\Classes")
        run = index.find(hive, r"HKU\S-1\Classes\Software\Run")
        self.assertIsNotNone(run)
        self.assertEqual(index.key_path(run), r"HKU\S-1\Classes\Software\Run")
        self.assertEqual(hive.key_count, 3)
        self.assertEqual(index.outside_mount, 0)

    def test_real_root_shallower_than_the_guess(self) -> None:
        index, hive = self.build(
            [self.row(r"ROOT\ControlSet001\Control"), self.row("ROOT", root=True), self.row(r"ROOT\Select")]
        )
        self.assertEqual(hive.mount, "ROOT")
        self.assertEqual(index.outside_mount, 0)
        for key in (r"ROOT\Select", r"ROOT\ControlSet001\Control", r"ROOT\ControlSet001"):
            node = index.find(hive, key)
            self.assertIsNotNone(node, key)
            self.assertEqual(index.key_path(node), key)
        self.assertEqual(hive.key_count, 4)


if __name__ == "__main__":
    unittest.main()
