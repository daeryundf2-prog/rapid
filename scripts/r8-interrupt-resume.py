#!/usr/bin/env python3
"""Interrupt / resume / cancel / retry measurement on the current engine (R8 T-354, QA-204·090).

Drives a private RapidTriage web server (``python -m rapidtriage web`` under
``scripts/dev/run.py``, own state file, own port) through the run API and measures:

* **interrupt** — for each point (``extraction``, ``collection``, ``indexing``) a run is started,
  the server is stopped while a task of that point runs (CTRL_BREAK / SIGTERM to the run.py
  wrapper: it kills the server's process tree at once, like a crash), the server is started again,
  the run must read ``interrupted`` and is resumed with ``POST /retry {resume: true}`` ("이어서
  실행"). Per-kind row counts of the resumed run are compared with an uninterrupted run.
* **cancel** — ``POST /cancel`` ("모두 취소") during collection; seconds until the run reads
  ``cancelled`` ("취소됨"). Target: 10 s.
* **retry** — a step failure is injected **through the input, without product changes**: the
  output folder is given a directory named ``rapidtriage-timeline.json`` before the run, so the
  timeline stage cannot write its result and the run fails. The directory is removed and the run
  is resumed ("이어서 실행"); every task that had completed before the failure and runs again
  (not ``reused``) is a re-executed step (target 0). Row counts are compared with the baseline.
* **evidence snapshot** (T-003 ``scripts/r8-evidence-snapshot.py``) before and after: identical.

Points: ``extraction`` = ``image-extract`` (E01 evidence) or, for a folder, the optional
extraction stage (``docs-extract``/``files-extract``; every run of this script asks for
``extract: true`` so all runs are comparable); ``collection`` = any provider task; ``indexing`` =
``docs`` (문서 검색·색인) or ``persist`` (케이스 DB·전문 색인). A point a run passed between two
polls is reported ``hit: false`` and is not counted as measured.

Row counts per kind: summary ``artifact_type_counts`` / ``provider_artifact_counts`` / file,
document and timeline totals, and the case DB ``artifact`` rows per ``artifact_type``, ``event``
rows per ``event_type``, ``file_record`` and ``indexed_document`` rows.

Every shortfall becomes an entry in ``gaps`` (one per unmet acceptance line). Engineering
baseline only, not release evidence. Real-data output stays outside Git
(default ``D:/rapid-qa/derived/r8/T-354/<corpus>-<time>``).

  python scripts/r8-interrupt-resume.py --corpus C1 --evidence <C1 E01> --json
  python scripts/r8-interrupt-resume.py --corpus S --evidence <S folder> --mode hacking
  python scripts/r8-interrupt-resume.py --quick --json          # synthetic sample (CI / tests)

Exit code: 0 when every acceptance line holds, 1 when a gap was found, 2 on a harness error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import os
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

SCHEMA = "r8-interrupt-resume/1"
REPO = Path(__file__).resolve().parents[1]
RUN_WRAPPER = REPO / "scripts" / "dev" / "run.py"
SNAPSHOT_SCRIPT = REPO / "scripts" / "r8-evidence-snapshot.py"
PROTECTED_PORT = 8710
DEFAULT_REAL_ROOT = Path("D:/rapid-qa/derived/r8/T-354")
PLAN_FILE = "rapidtriage-run-plan.json"
PROGRESS_FILE = "rapidtriage-run-progress.json"  # carries the live plan (the plan file is written at the end)
SUMMARY_FILE = "rapidtriage-run-summary.json"
CASE_DB_FILE = "rapidtriage-case.db"
INJECT_NAME = "rapidtriage-timeline.json"  # a directory here makes the timeline stage fail
POINTS = ("extraction", "collection", "indexing")
INDEXING_TASKS = ("docs", "persist")
FOLDER_EXTRACT_TASKS = ("docs-extract", "files-extract")
TERMINAL = frozenset({"completed", "failed", "cancelled", "interrupted"})
DONE_TASK = frozenset({"completed", "partial"})
CANCEL_TARGET_S = 10.0
#: Re-run on every resume by design: the input fingerprint is how a resume proves the evidence is
#: unchanged (a check, not repeated work), so it is reported as ``reverified``, not re-executed.
REVERIFY_TASKS = frozenset({"fingerprint"})
SUMMARY_SCALARS = (
    "scanned_file_count",
    "file_candidate_count",
    "document_candidate_count",
    "document_match_count",
    "timeline_event_count",
)
CASE_DB_TABLES = ("file_record", "indexed_document")
CASE_DB_GROUPED = (("artifact", "artifact_type"), ("event", "event_type"))


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested)
# --------------------------------------------------------------------------- #


def iter_tasks(plan: Mapping[str, Any] | None) -> Iterable[Mapping[str, Any]]:
    for group in (plan or {}).get("groups") or []:
        if isinstance(group, Mapping):
            for task in group.get("tasks") or []:
                if isinstance(task, Mapping):
                    yield task


def task_statuses(plan: Mapping[str, Any] | None) -> dict[str, str]:
    return {str(t.get("id")): str(t.get("status") or "") for t in iter_tasks(plan)}


def point_task_ids(plan: Mapping[str, Any] | None, point: str, *, image: bool = False) -> list[str]:
    """Task ids that stand for ``point`` in this plan (skipped tasks never count).

    ``image``: the evidence is an image file, so extraction is ``image-extract`` (a folder run
    also lists that task, briefly ``running`` before it is skipped)."""
    live = {str(t.get("id")): t for t in iter_tasks(plan) if t.get("status") != "skipped"}
    if point == "extraction":
        if image:
            return ["image-extract"] if "image-extract" in live else []
        return [tid for tid in FOLDER_EXTRACT_TASKS if tid in live]
    if point == "collection":
        return [tid for tid, t in live.items() if t.get("type") == "provider"]
    if point == "indexing":
        return [tid for tid in INDEXING_TASKS if tid in live]
    raise ValueError(f"unknown point: {point}")


def running_in(plan: Mapping[str, Any] | None, task_ids: Iterable[str]) -> list[str]:
    wanted = set(task_ids)
    return sorted(str(t.get("id")) for t in iter_tasks(plan) if t.get("id") in wanted and t.get("status") == "running")


def finished_task_ids(plan: Mapping[str, Any] | None) -> list[str]:
    """Tasks done (completed / partial) in ``plan``: work a resume must not redo."""
    return sorted(tid for tid, status in task_statuses(plan).items() if status in DONE_TASK)


def reexecuted_tasks(
    done_before: Iterable[str], resumed_plan: Mapping[str, Any] | None, *, ignore: Iterable[str] = REVERIFY_TASKS
) -> list[str]:
    """Tasks done before the stop that the resumed run ran again (status done, ``reused`` false)."""
    before = set(done_before) - set(ignore)
    return sorted(
        str(t.get("id"))
        for t in iter_tasks(resumed_plan)
        if t.get("id") in before and t.get("status") in DONE_TASK and not t.get("reused")
    )


def _int_map(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): int(v) for k, v in value.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}


def summary_counts(summary: Mapping[str, Any] | None) -> dict[str, int]:
    """Flat ``section:key -> count`` from a run summary's ``summary`` block."""
    block = (summary or {}).get("summary")
    block = block if isinstance(block, Mapping) else {}
    counts: dict[str, int] = {}
    for section in ("artifact_type_counts", "provider_artifact_counts"):
        for key, value in _int_map(block.get(section)).items():
            counts[f"{section}:{key}"] = value
    for key in SUMMARY_SCALARS:
        value = block.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            counts[f"summary:{key}"] = value
    return counts


def case_db_counts(db_path: Path | None) -> dict[str, int]:
    """Row counts per kind in the run's case DB (opened read-only); ``{}`` when absent."""
    if db_path is None or not db_path.is_file():
        return {}
    uri = "file:" + db_path.resolve().as_posix() + "?mode=ro"
    counts: dict[str, int] = {}
    con = sqlite3.connect(uri, uri=True)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in CASE_DB_TABLES:
            if table in tables:
                counts[f"case_db:{table}"] = int(con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
        for table, column in CASE_DB_GROUPED:
            if table in tables:
                for key, value in con.execute(f'SELECT "{column}", count(*) FROM "{table}" GROUP BY 1'):
                    counts[f"case_db:{table}:{key}"] = int(value)
    finally:
        con.close()
    return counts


def compare_counts(baseline: Mapping[str, int], other: Mapping[str, int]) -> list[dict[str, Any]]:
    """Every key whose count differs (a key missing on one side counts as 0 there)."""
    diffs = []
    for key in sorted(set(baseline) | set(other)):
        left, right = int(baseline.get(key, 0)), int(other.get(key, 0))
        if left != right:
            diffs.append({"key": key, "baseline": left, "value": right, "delta": right - left})
    return diffs


def evaluate(report: Mapping[str, Any], *, cancel_target_s: float = CANCEL_TARGET_S) -> list[dict[str, str]]:
    """One gap per unmet acceptance line (T-354 수용)."""
    gaps: list[dict[str, str]] = []

    def gap(area: str, detail: str) -> None:
        gaps.append({"area": area, "detail": detail})

    interrupts = report.get("interrupts") or []
    hit = [item for item in interrupts if item.get("hit")]
    equal = [item for item in hit if item.get("resumed_status") == "completed" and not item.get("count_diffs")]
    wanted = len(report.get("points") or POINTS)
    if len(equal) < wanted:
        detail = f"{len(equal)}/{wanted} points resumed with zero row-count difference"
        missed = [str(item.get("point")) for item in interrupts if not item.get("hit")]
        bad = [str(item.get("point")) for item in hit if item not in equal]
        detail += f"; not reached: {', '.join(missed)}" if missed else ""
        detail += f"; differing or not completed: {', '.join(bad)}" if bad else ""
        gap("interrupt-resume", detail)
    for item in hit:
        if item.get("interrupted_status") != "interrupted":
            gap("interrupt-status", f"{item.get('point')}: after restart the run read {item.get('interrupted_status')!r}, not 'interrupted'")
        if item.get("reexecuted"):
            gap("interrupt-rerun", f"{item.get('point')}: resume re-ran {len(item['reexecuted'])} finished task(s): {', '.join(item['reexecuted'])}")
    cancel = report.get("cancel")
    if isinstance(cancel, Mapping) and not cancel.get("skipped"):
        seconds = cancel.get("seconds_to_cancelled")
        if cancel.get("final_status") != "cancelled" or seconds is None:
            gap("cancel", f"run did not reach 'cancelled' (final {cancel.get('final_status')!r})")
        elif float(seconds) > cancel_target_s:
            gap("cancel", f"'취소됨' after {seconds} s (target {cancel_target_s:g} s)")
    retry = report.get("retry")
    if isinstance(retry, Mapping) and not retry.get("skipped"):
        if retry.get("failed_status") != "failed":
            gap("retry-injection", f"injected failure gave {retry.get('failed_status')!r}, not 'failed'")
        if retry.get("resumed_status") != "completed":
            gap("retry", f"retry ended {retry.get('resumed_status')!r}")
        if retry.get("reexecuted"):
            gap("retry-rerun", f"retry re-ran {len(retry['reexecuted'])} finished task(s): {', '.join(retry['reexecuted'])}")
        if retry.get("count_diffs"):
            gap("retry-counts", f"{len(retry['count_diffs'])} row-count difference(s) vs baseline")
    snap = report.get("evidence_snapshot")
    if not isinstance(snap, Mapping) or not snap.get("identical"):
        gap("evidence-snapshot", "evidence changed (or not compared)")
    return gaps


def write_synthetic_evidence(folder: Path, *, files: int = 240) -> Path:
    """Deterministic invented evidence folder (fake user, example.* hosts, no real values)."""
    user = folder / "Users" / "synth-user01"
    docs, desktop, downloads = user / "Documents", user / "Desktop", user / "Downloads"
    for path in (docs, desktop, downloads):
        path.mkdir(parents=True, exist_ok=True)
    for index in range(files):
        body = "\n".join(
            f"synthetic memo {index:04d} line {line}: invoice INV-{index:04d} contract review https://example.com/p/{index}"
            for line in range(40)
        )
        (docs / f"memo-{index:04d}.txt").write_text(body + "\n", encoding="utf-8", newline="\n")
    for index in range(max(1, files // 8)):
        rows = "\n".join(f"{row},{index},{row * index}" for row in range(50))
        (desktop / f"ledger-{index:03d}.csv").write_text("row,sheet,value\n" + rows + "\n", encoding="utf-8", newline="\n")
        (downloads / f"page-{index:03d}.html").write_text(
            f"<html><body><a href='https://example.org/{index}'>example {index}</a></body></html>\n",
            encoding="utf-8",
            newline="\n",
        )
    return folder


def read_dev_port(env_file: Path) -> int | None:
    """``RAPIDTRIAGE_API_PORT`` from a worktree's ``.rt-dev.env`` (``None`` when absent)."""
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        key, _, value = line.strip().partition("=")
        if key == "RAPIDTRIAGE_API_PORT" and value.strip().isdigit():
            return int(value.strip())
    return None


def read_json(path: Path) -> dict[str, Any] | None:
    """A JSON file being replaced by another process: ``None`` instead of an error."""
    for _ in range(5):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            time.sleep(0.02)
    return None


def read_plan(output_dir: Path) -> dict[str, Any] | None:
    """The run plan: the live one in the progress file, else the plan file."""
    progress = read_json(output_dir / PROGRESS_FILE)
    plan = progress.get("plan") if progress else None
    return plan if isinstance(plan, dict) else read_json(output_dir / PLAN_FILE)


def _load_snapshot_module():
    spec = importlib.util.spec_from_file_location("r8_evidence_snapshot_t354", SNAPSHOT_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load scripts/r8-evidence-snapshot.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Server and run driving
# --------------------------------------------------------------------------- #


class HarnessError(RuntimeError):
    pass


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if os.name != "nt":
            # The killed server leaves the port in TIME_WAIT; uvicorn binds with SO_REUSEADDR, so the
            # probe must too or it reports "busy" for a minute (CI 703f840, ubuntu). On Windows the
            # option means "steal a live port", so it stays off there.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


class Server:
    """``python -m rapidtriage web`` under ``scripts/dev/run.py``: start, hard stop, restart."""

    def __init__(self, work: Path, port: int, *, budget_s: int) -> None:
        if port == PROTECTED_PORT:
            raise HarnessError("port 8710 is the operator's server")
        self.work = work
        self.port = port
        self.budget_s = budget_s
        self.token = secrets.token_hex(16)
        self.base = f"http://127.0.0.1:{port}"
        self.proc: subprocess.Popen | None = None
        self.starts = 0
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def start(self, timeout: float = 90.0) -> float:
        deadline = time.monotonic() + 30
        while not _port_free(self.port):
            if time.monotonic() > deadline:
                raise HarnessError(f"port {self.port} stays busy")
            time.sleep(0.25)
        state = self.work / "state"
        state.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.update(
            RAPIDTRIAGE_STATE_PATH=str(state / "runs.json"),
            RAPIDTRIAGE_CASES_DB=str(state / "rapidtriage-cases.db"),
            RAPIDTRIAGE_AUTH_TOKEN=self.token,
            RAPIDTRIAGE_NO_BROWSER="1",
            PYTHONPATH=str(REPO) + os.pathsep + env.get("PYTHONPATH", ""),
            PYTHONIOENCODING="utf-8",
        )
        env.pop("RAPIDTRIAGE_TOKEN", None)
        command = [
            sys.executable, str(RUN_WRAPPER), "--timeout", str(self.budget_s), "--port", str(self.port), "--",
            sys.executable, "-m", "rapidtriage", "web", "--host", "127.0.0.1", "--port", str(self.port),
            "--no-browser", "--crash-log-dir", str(self.work / "crash"),
        ]  # fmt: skip
        self.starts += 1
        log = (self.work / f"server-{self.starts}.log").open("wb")
        kwargs: dict[str, Any] = {"cwd": str(REPO), "env": env, "stdout": log, "stderr": subprocess.STDOUT}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        began = time.monotonic()
        self.proc = subprocess.Popen(command, **kwargs)
        log.close()
        while time.monotonic() - began < timeout:
            if self.proc.poll() is not None:
                raise HarnessError(f"server exited early (code {self.proc.returncode}); see server-{self.starts}.log")
            try:
                status, _ = self.call("GET", "/api/health", timeout=5)
                if status == 200:
                    return round(time.monotonic() - began, 3)
            except OSError:
                pass
            time.sleep(0.25)
        raise HarnessError("server did not answer /api/health in time")

    def stop(self) -> float:
        """Stop at once: the wrapper kills the server's whole tree (job object / process group)."""
        if self.proc is None or self.proc.poll() is not None:
            self.proc = None
            return 0.0
        began = time.monotonic()
        if os.name == "nt":
            self.proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()  # our own wrapper, by PID; its job object closes with it
            self.proc.wait(timeout=30)
        self.proc = None
        return round(time.monotonic() - began, 3)

    def call(self, method: str, path: str, body: Any = None, *, timeout: float = 120) -> tuple[int, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            self.base + path,
            method=method,
            data=data,
            headers={"X-RapidTriage-Token": self.token, "Content-Type": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw) if raw else None
            except ValueError:
                return exc.code, raw.decode("utf-8", "replace")[:500]

    def must(self, method: str, path: str, body: Any = None, *, ok: Iterable[int] = (200, 201, 202)) -> Any:
        status, payload = self.call(method, path, body)
        if status not in set(ok):
            raise HarnessError(f"{method} {path} -> {status}: {str(payload)[:300]}")
        return payload


class Driver:
    def __init__(self, server: Server, evidence: Path, *, mode: str, extract: bool, run_timeout: float, poll_s: float) -> None:
        self.server = server
        self.evidence = evidence
        self.mode = mode
        self.extract = extract
        self.run_timeout = run_timeout
        self.poll_s = poll_s
        self.image = evidence.is_file()

    def submit(self, output_dir: Path) -> str:
        body = {"root": str(self.evidence), "mode": self.mode, "output_dir": str(output_dir), "extract": self.extract}
        payload = self.server.must("POST", "/api/runs", body)
        return str(payload["run_id"])

    def status(self, run_id: str) -> str:
        status, payload = self.server.call("GET", f"/api/runs/{run_id}")
        if status != 200 or not isinstance(payload, Mapping):
            raise HarnessError(f"GET /api/runs/{run_id} -> {status}")
        return str(payload.get("status") or "")

    def wait_terminal(self, run_id: str, *, interval: float = 1.0) -> tuple[str, float]:
        began = time.monotonic()
        while time.monotonic() - began < self.run_timeout:
            current = self.status(run_id)
            if current in TERMINAL:
                return current, round(time.monotonic() - began, 3)
            time.sleep(interval)
        raise HarnessError(f"run {run_id} did not finish in {self.run_timeout} s")

    def wait_point(self, run_id: str, output_dir: Path, point: str) -> tuple[bool, dict[str, Any] | None, list[str]]:
        """Poll the live plan until a task of ``point`` runs; ``(hit, plan, running)``.

        Not hit when the run ended, or every task of the point finished, before a poll saw one running."""
        began = time.monotonic()
        last_status_check = 0.0
        while time.monotonic() - began < self.run_timeout:
            plan = read_plan(output_dir)
            if plan is not None:
                ids = point_task_ids(plan, point, image=self.image)
                running = running_in(plan, ids)
                if running:
                    return True, plan, running
                statuses = task_statuses(plan)
                if ids and all(statuses.get(tid) in DONE_TASK | {"failed", "cancelled", "skipped"} for tid in ids):
                    return False, plan, []
                if plan.get("outcome") not in (None, "", "running"):
                    return False, plan, []
            if time.monotonic() - last_status_check > 2.0:
                last_status_check = time.monotonic()
                if self.status(run_id) in TERMINAL:
                    return False, read_plan(output_dir), []
            time.sleep(self.poll_s)
        raise HarnessError(f"run {run_id} never reached {point}")

    def counts(self, output_dir: Path) -> dict[str, int]:
        summary = read_json(output_dir / SUMMARY_FILE)
        if summary is None:
            return {}
        case_db = summary.get("case_db") if isinstance(summary.get("case_db"), Mapping) else {}
        raw = case_db.get("path") if isinstance(case_db, Mapping) else None
        db_path = Path(str(raw)) if raw else output_dir / CASE_DB_FILE
        return {**summary_counts(summary), **case_db_counts(db_path)}

    def resume(self, run_id: str) -> str:
        payload = self.server.must("POST", f"/api/runs/{run_id}/retry", {"resume": True})
        return str(payload["run_id"])


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def measure_interrupt(driver: Driver, work: Path, point: str, baseline: Mapping[str, int], log: Callable[[str], None]) -> dict[str, Any]:
    out = work / f"interrupt-{point}"
    run_id = driver.submit(out)
    hit, plan, running = driver.wait_point(run_id, out, point)
    item: dict[str, Any] = {"point": point, "run_id": run_id, "hit": hit, "running_at_stop": running}
    if not hit:
        item["note"] = "run passed the point between polls; not measured"
        driver.wait_terminal(run_id)
        log(f"interrupt {point}: not reached")
        return item
    item["stop_seconds"] = driver.server.stop()
    after = read_plan(out)
    item["done_before_stop"] = finished_task_ids(after)
    item["still_running_at_stop"] = running_in(after, point_task_ids(after, point, image=driver.image))
    item["restart_seconds"] = driver.server.start()
    status, payload = driver.server.call("GET", f"/api/runs/{run_id}")
    item["interrupted_status"] = payload.get("status") if isinstance(payload, Mapping) else None
    item["interrupted_message"] = payload.get("error") if isinstance(payload, Mapping) else None
    if item["interrupted_status"] not in ("interrupted", "failed", "cancelled"):
        driver.wait_terminal(run_id)
        item["resumed_status"] = None
        return item
    new_id = driver.resume(run_id)
    item["resumed_run_id"] = new_id
    item["resumed_status"], item["resume_seconds"] = driver.wait_terminal(new_id)
    resumed_plan = read_plan(out)
    item["reexecuted"] = reexecuted_tasks(item["done_before_stop"], resumed_plan)
    item["reverified"] = sorted(set(reexecuted_tasks(item["done_before_stop"], resumed_plan, ignore=())) - set(item["reexecuted"]))
    item["reused"] = sorted(str(t.get("id")) for t in iter_tasks(resumed_plan) if t.get("reused"))
    counts = driver.counts(out)
    item["count_keys"] = len(counts)
    item["count_diffs"] = compare_counts(baseline, counts)
    log(
        f"interrupt {point}: resumed {item['resumed_status']}, diffs {len(item['count_diffs'])}, "
        f"re-executed {len(item['reexecuted'])}"
    )
    return item


def measure_cancel(driver: Driver, work: Path, log: Callable[[str], None]) -> dict[str, Any]:
    out = work / "cancel"
    run_id = driver.submit(out)
    hit, _plan, running = driver.wait_point(run_id, out, "collection")
    item: dict[str, Any] = {"run_id": run_id, "requested_during": "collection" if hit else "after collection", "running_at_request": running}
    began = time.monotonic()
    status, payload = driver.server.call("POST", f"/api/runs/{run_id}/cancel")
    item["cancel_http_status"] = status
    item["cancel_response_status"] = payload.get("status") if isinstance(payload, Mapping) else str(payload)[:200]
    final = ""
    seconds = None
    while time.monotonic() - began < driver.run_timeout:
        final = driver.status(run_id)
        if final in TERMINAL:
            if final == "cancelled":
                seconds = round(time.monotonic() - began, 3)
            break
        time.sleep(0.1)
    item["final_status"] = final
    item["seconds_to_cancelled"] = seconds
    item["target_seconds"] = CANCEL_TARGET_S
    plan = read_plan(out)
    item["plan_outcome"] = plan.get("outcome") if plan else None
    log(f"cancel: {final} after {seconds} s")
    return item


def measure_retry(driver: Driver, work: Path, baseline: Mapping[str, int], log: Callable[[str], None]) -> dict[str, Any]:
    out = work / "retry"
    blocker = out / INJECT_NAME
    blocker.mkdir(parents=True, exist_ok=True)
    item: dict[str, Any] = {
        "injection": f"directory '{INJECT_NAME}' in the output folder (timeline stage cannot write; no product change)",
    }
    run_id = driver.submit(out)
    item["run_id"] = run_id
    item["failed_status"], item["failed_seconds"] = driver.wait_terminal(run_id)
    failed_plan = read_plan(out)
    item["failed_tasks"] = sorted(tid for tid, s in task_statuses(failed_plan).items() if s == "failed")
    item["done_before_retry"] = finished_task_ids(failed_plan)
    shutil.rmtree(blocker, ignore_errors=True)
    if item["failed_status"] not in ("failed", "cancelled", "interrupted"):
        item["resumed_status"] = None
        log(f"retry: injection gave {item['failed_status']}")
        return item
    new_id = driver.resume(run_id)
    item["resumed_run_id"] = new_id
    item["resumed_status"], item["resume_seconds"] = driver.wait_terminal(new_id)
    resumed_plan = read_plan(out)
    item["reexecuted"] = reexecuted_tasks(item["done_before_retry"], resumed_plan)
    item["reverified"] = sorted(set(reexecuted_tasks(item["done_before_retry"], resumed_plan, ignore=())) - set(item["reexecuted"]))
    item["reused"] = sorted(str(t.get("id")) for t in iter_tasks(resumed_plan) if t.get("reused"))
    item["count_diffs"] = compare_counts(baseline, driver.counts(out))
    log(f"retry: failed {item['failed_tasks']}, resumed {item['resumed_status']}, re-executed {len(item['reexecuted'])}")
    return item


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="", help="corpus label for the report (C1, S, ...)")
    ap.add_argument("--evidence", type=Path, help="evidence folder or E01 (default $R8_EVIDENCE_<CORPUS>)")
    ap.add_argument("--snapshot-root", type=Path, action="append", help="snapshot these roots (default: the evidence folder, or the E01's folder)")
    ap.add_argument("--mode", default="fraud", choices=("fraud", "hacking", "recovery", "seizure"))
    ap.add_argument("--no-extract", action="store_true", help="runs without the optional extraction stage")
    ap.add_argument("--points", default=",".join(POINTS), help="comma list of extraction,collection,indexing")
    ap.add_argument("--skip-cancel", action="store_true")
    ap.add_argument("--skip-retry", action="store_true")
    ap.add_argument("--quick", action="store_true", help="synthetic sample in a temp folder (CI / tests)")
    ap.add_argument("--quick-files", type=int, default=240, help=argparse.SUPPRESS)
    ap.add_argument("--work-dir", type=Path, help=f"output folder (default {DEFAULT_REAL_ROOT}/<corpus>-<time>; --quick: temp)")
    ap.add_argument("--port", type=int, help="server port (default RAPIDTRIAGE_API_PORT of .rt-dev.env)")
    ap.add_argument("--run-timeout", type=float, default=4 * 3600.0, help="seconds per run")
    ap.add_argument("--poll", type=float, default=0.05, help="plan poll interval (seconds)")
    ap.add_argument("--output", type=Path, help="result JSON (default <work-dir>/result.json)")
    ap.add_argument("--keep", action="store_true", help="--quick: keep the temp folder")
    ap.add_argument("--json", action="store_true", help="print the result JSON")
    return ap.parse_args(argv)


def _resolve_port(args: argparse.Namespace) -> int:
    port = args.port or read_dev_port(REPO / ".rt-dev.env")
    if port is None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
    if port == PROTECTED_PORT:
        raise HarnessError("port 8710 is the operator's server")
    return port


def run(args: argparse.Namespace, log: Callable[[str], None]) -> dict[str, Any]:
    points = [p.strip() for p in args.points.split(",") if p.strip()]
    for point in points:
        if point not in POINTS:
            raise HarnessError(f"unknown point: {point}")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    temp_root: Path | None = None
    if args.quick:
        temp_root = Path(tempfile.mkdtemp(prefix="r8-interrupt-"))
        work = args.work_dir or temp_root / "work"
        evidence = write_synthetic_evidence(temp_root / "evidence", files=args.quick_files)
        corpus = args.corpus or "SYN-quick"
    else:
        corpus = args.corpus or "custom"
        raw = args.evidence or (Path(os.environ[f"R8_EVIDENCE_{corpus}"]) if os.environ.get(f"R8_EVIDENCE_{corpus}") else None)
        if raw is None:
            raise HarnessError(f"--evidence (or $R8_EVIDENCE_{corpus}) is required")
        evidence = raw
        if not evidence.exists():
            raise HarnessError(f"evidence not found: {evidence}")
        work = args.work_dir or DEFAULT_REAL_ROOT / f"{corpus}-{stamp}"
    evidence = evidence.resolve()
    work = work.resolve()
    roots = [p.resolve() for p in (args.snapshot_root or [evidence if evidence.is_dir() else evidence.parent])]
    for root in roots:
        if work == root or root in work.parents:
            raise HarnessError("the work folder must be outside the evidence")
    work.mkdir(parents=True, exist_ok=True)

    snap_mod = _load_snapshot_module()
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "corpus": corpus,
        "evidence": str(evidence),
        "evidence_kind": "folder" if evidence.is_dir() else "file",
        "mode": args.mode,
        "extract": not args.no_extract,
        "points": points,
        "work_dir": str(work),
        "started_at": _now(),
        "engineering_baseline_only": True,
    }
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, capture_output=True, text=True, check=False)
        report["commit"] = commit.stdout.strip() or None
    except OSError:
        report["commit"] = None

    log(f"snapshot before ({len(roots)} root(s))")
    before = snap_mod.snapshot(roots, redact_names=True)
    (work / "evid_before.json").write_text(json.dumps(before, indent=1) + "\n", encoding="utf-8")

    server = Server(work, _resolve_port(args), budget_s=int(args.run_timeout * (len(points) + 4)) + 600)
    report["port"] = server.port
    driver = Driver(server, evidence, mode=args.mode, extract=not args.no_extract, run_timeout=args.run_timeout, poll_s=args.poll)
    try:
        report["server_start_seconds"] = server.start()
        log("baseline run")
        base_dir = work / "baseline"
        base_id = driver.submit(base_dir)
        base_status, base_seconds = driver.wait_terminal(base_id)
        baseline = driver.counts(base_dir)
        report["baseline"] = {"run_id": base_id, "status": base_status, "seconds": base_seconds, "count_keys": len(baseline), "counts": baseline}
        if base_status != "completed" or not baseline:
            raise HarnessError(f"baseline run ended {base_status!r} with {len(baseline)} counts")
        base_plan = read_plan(base_dir)
        report["point_tasks"] = {point: point_task_ids(base_plan, point, image=driver.image) for point in points}
        log(f"baseline: {base_seconds} s, {len(baseline)} count keys")
        report["interrupts"] = [measure_interrupt(driver, work, point, baseline, log) for point in points]
        report["cancel"] = {"skipped": True} if args.skip_cancel else measure_cancel(driver, work, log)
        report["retry"] = {"skipped": True} if args.skip_retry else measure_retry(driver, work, baseline, log)
    finally:
        server.stop()
        report["server_starts"] = server.starts

    log("snapshot after")
    after = snap_mod.snapshot(roots, redact_names=True)
    (work / "evid_after.json").write_text(json.dumps(after, indent=1) + "\n", encoding="utf-8")
    diff = snap_mod.compare(before, after)
    report["evidence_snapshot"] = {
        "roots": len(roots),
        "files": before["file_count"],
        "bytes": before["total_bytes"],
        "identical": diff["identical"],
        "changed": len(diff["changed"]),
        "new": len(diff["new"]),
        "deleted": len(diff["deleted"]),
    }
    report["finished_at"] = _now()
    report["gaps"] = evaluate(report)
    report["verdict"] = "pass" if not report["gaps"] else "gaps"
    output = args.output or work / "result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    report["result_path"] = str(output)
    if temp_root is not None and not args.keep:
        # the synthetic evidence (and the work folder when it was the temp default) goes away
        shutil.rmtree(temp_root, ignore_errors=True)
        if args.work_dir is None and args.output is None:
            report["result_path"] = None
    return report


def _print_human(report: Mapping[str, Any]) -> None:
    base = report.get("baseline") or {}
    print(f"T-354 {report.get('corpus')}: baseline {base.get('status')} in {base.get('seconds')} s ({base.get('count_keys')} count keys)")
    for item in report.get("interrupts") or []:
        if not item.get("hit"):
            print(f"  interrupt {item['point']}: not reached")
            continue
        print(
            f"  interrupt {item['point']}: stopped during {','.join(item.get('running_at_stop') or [])} -> "
            f"{item.get('interrupted_status')} -> resumed {item.get('resumed_status')}; "
            f"row diffs {len(item.get('count_diffs') or [])}; re-executed {len(item.get('reexecuted') or [])}"
        )
    cancel = report.get("cancel") or {}
    if not cancel.get("skipped"):
        print(f"  cancel: {cancel.get('final_status')} after {cancel.get('seconds_to_cancelled')} s")
    retry = report.get("retry") or {}
    if not retry.get("skipped"):
        print(
            f"  retry: {retry.get('failed_status')} ({','.join(retry.get('failed_tasks') or [])}) -> {retry.get('resumed_status')}; "
            f"re-executed {len(retry.get('reexecuted') or [])}; row diffs {len(retry.get('count_diffs') or [])}"
        )
    snap = report.get("evidence_snapshot") or {}
    print(f"  evidence snapshot: {'identical' if snap.get('identical') else 'CHANGED'} ({snap.get('files')} files)")
    for gap in report.get("gaps") or []:
        print(f"  GAP {gap['area']}: {gap['detail']}")
    if report.get("result_path"):
        print(f"  -> {report['result_path']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    def log(message: str) -> None:
        print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)

    try:
        report = run(args, log)
    except HarnessError as exc:
        print(f"r8-interrupt-resume: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_human(report)
    return 0 if not report["gaps"] else 1


if __name__ == "__main__":
    sys.exit(main())
