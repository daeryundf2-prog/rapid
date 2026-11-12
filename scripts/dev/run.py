#!/usr/bin/env python3
"""Run one command with a time limit and kill only its own process tree (plan task T-151).

Agents used to leave vitest, vite and uvicorn processes running after a session,
and ``taskkill /IM`` by image name killed other sessions' browsers too.  This
wrapper starts the command in its own process group (Windows: also a job
object), records every process of that tree in a state file, and when the
command ends or runs past ``--timeout`` it kills that tree and nothing else.

Examples::

    python scripts/dev/run.py --timeout 300 -- npx vitest run
    python scripts/dev/run.py --timeout 600 --port 8765 -- python -m rapidtriage serve --port 8765
    python scripts/dev/run.py --timeout 60 --json -- python -m unittest tests.test_dev_run
    python scripts/dev/run.py --cleanup          # kill leftovers of dead wrappers

Rules:

* Port 8710 is the operator's server.  ``--port 8710`` (or ``8710`` in the
  command) is refused before any socket is opened.  A busy ``--port`` is refused.
* ``RAPIDTRIAGE_NO_BROWSER=1`` is set for the command.
* ``--cleanup`` only kills processes recorded by a wrapper that is no longer
  running, and only when the PID still has the recorded start time.  It never
  matches by name.

Exit code: the command's own exit code; 124 on timeout; 130 on Ctrl+C;
2 when the wrapper refuses to start.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTECTED_PORT = 8710
EXIT_TIMEOUT = 124
EXIT_INTERRUPT = 130
EXIT_REFUSED = 2
POLL_SECONDS = 0.2
IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# Process inspection (no psutil: ctypes on Windows, ps on POSIX)
# --------------------------------------------------------------------------- #

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _TH32CS_SNAPPROCESS = 0x00000002
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _STILL_ACTIVE = 259
    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    _kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    _kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    _kernel32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [ctypes.c_void_p, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL


def _process_table() -> dict[int, int]:
    """Return ``{pid: parent_pid}`` for every running process."""
    table: dict[int, int] = {}
    if IS_WINDOWS:
        snap = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if not snap or snap == _INVALID_HANDLE:
            return table
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            ok = _kernel32.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                table[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                ok = _kernel32.Process32NextW(snap, ctypes.byref(entry))
        finally:
            _kernel32.CloseHandle(snap)
        return table
    try:
        out = subprocess.run(
            ["ps", "-A", "-o", "pid=,ppid="],
            capture_output=True, text=True, check=False,
        ).stdout
    except OSError:
        return table
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = int(parts[1])
    return table


def process_start(pid: int) -> str | None:
    """Return an opaque start-time token for a running ``pid``, or ``None``.

    The token guards against PID reuse: a recorded PID is only treated as ours
    when its start time still matches.
    """
    if pid <= 0:
        return None
    if IS_WINDOWS:
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            code = wintypes.DWORD()
            if not _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            if code.value != _STILL_ACTIVE:
                return None
            times = [wintypes.FILETIME() for _ in range(4)]
            if not _kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                return None
            created = times[0]
            return str((created.dwHighDateTime << 32) | created.dwLowDateTime)
        finally:
            _kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        try:
            text = stat.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        fields = text.rsplit(")", 1)[-1].split()
        if fields and fields[0] == "Z":
            return None
        return fields[19] if len(fields) > 19 else None
    try:
        out = subprocess.run(
            ["ps", "-o", "stat=,lstart=", "-p", str(pid)],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
    except OSError:
        return None
    if not out or out.startswith("Z"):
        return None
    return out.split(None, 1)[-1]


def is_alive(pid: int, start: str | None = None) -> bool:
    """True when ``pid`` runs and (if given) still has start token ``start``."""
    current = process_start(pid)
    if current is None:
        return False
    return start is None or current == start


def _descendants(roots: set[int], table: dict[int, int]) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, ppid in table.items():
        if pid != ppid:
            children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [pid for pid in roots if pid in table]
    while stack:
        pid = stack.pop()
        for child in children.get(pid, ()):
            if child not in found and child not in roots:
                found.add(child)
                stack.append(child)
    return found


# --------------------------------------------------------------------------- #
# Tree tracking and killing
# --------------------------------------------------------------------------- #


class _Job:
    """Windows job object: every descendant joins it and dies with it."""

    def __init__(self) -> None:
        self.handle = None
        if not IS_WINDOWS:
            return
        handle = _kernel32.CreateJobObjectW(None, None)
        if not handle:
            return
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        _kernel32.SetInformationJobObject(
            handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info),
        )
        self.handle = handle

    def assign(self, proc: subprocess.Popen) -> bool:
        if not self.handle:
            return False
        proc_handle = getattr(proc, "_handle", None)
        if proc_handle is None:
            return False
        return bool(_kernel32.AssignProcessToJobObject(self.handle, int(proc_handle)))

    def terminate(self) -> None:
        if self.handle:
            _kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            _kernel32.CloseHandle(self.handle)
            self.handle = None


class Tree:
    """The processes started by this wrapper, keyed by PID with start tokens."""

    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self.members: dict[int, str] = {}
        start = process_start(root_pid)
        if start is not None:
            self.members[root_pid] = start

    def refresh(self) -> bool:
        """Add new descendants.  Returns True when the membership changed."""
        table = _process_table()
        live_roots = {pid for pid, start in self.members.items() if is_alive(pid, start)}
        live_roots.add(self.root_pid)
        changed = False
        for pid in _descendants(live_roots, table):
            if pid in self.members:
                continue
            start = process_start(pid)
            if start is not None:
                self.members[pid] = start
                changed = True
        return changed

    def alive(self) -> list[int]:
        return sorted(pid for pid, start in self.members.items() if is_alive(pid, start))


def _kill_pid_tree(pid: int, start: str) -> None:
    """Kill one recorded process (and, on Windows, its descendants) if it is still ours."""
    if not is_alive(pid, start):
        return
    if IS_WINDOWS:
        subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(pid)],
            capture_output=True, check=False,
        )
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def kill_tree(
    proc: subprocess.Popen, tree: Tree, job: _Job, grace: float,
) -> list[int]:
    """Kill everything in ``tree``; return the PIDs still alive afterwards."""
    tree.refresh()
    if IS_WINDOWS:
        job.terminate()
        if proc.poll() is None:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True, check=False,
            )
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + max(grace, 0.0)
        while time.monotonic() < deadline and (proc.poll() is None or tree.alive()):
            time.sleep(0.05)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    for pid, start in list(tree.members.items()):
        _kill_pid_tree(pid, start)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    deadline = time.monotonic() + 5
    remaining = tree.alive()
    while remaining and time.monotonic() < deadline:
        time.sleep(0.1)
        remaining = tree.alive()
    return remaining


# --------------------------------------------------------------------------- #
# State files
# --------------------------------------------------------------------------- #


def default_state_dir() -> Path:
    digest = hashlib.sha256(str(REPO_ROOT).lower().encode("utf-8")).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / "rapidtriage-dev-run" / digest


def _write_state(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _state_payload(command: list[str], proc: subprocess.Popen, tree: Tree, started: float) -> dict:
    return {
        "version": 1,
        "wrapper": {"pid": os.getpid(), "start": process_start(os.getpid())},
        "root": proc.pid,
        "pgid": None if IS_WINDOWS else proc.pid,
        "command": command,
        "started_at": started,
        "processes": [{"pid": pid, "start": start} for pid, start in sorted(tree.members.items())],
    }


def cleanup(state_dir: Path) -> dict:
    """Kill processes recorded by wrappers that are no longer running."""
    report: dict = {"state_dir": str(state_dir), "killed": [], "skipped_active": [], "remaining": []}
    if not state_dir.is_dir():
        return report
    for path in sorted(state_dir.glob("run-*.json")):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        wrapper = state.get("wrapper") or {}
        if wrapper.get("pid") and is_alive(int(wrapper["pid"]), wrapper.get("start")):
            report["skipped_active"].append(str(path))
            continue
        recorded = [
            (int(item["pid"]), str(item["start"]))
            for item in state.get("processes", [])
            if isinstance(item, dict) and item.get("pid") and item.get("start")
        ]
        ours = [(pid, start) for pid, start in recorded if is_alive(pid, start)]
        pgid = state.get("pgid")
        if not IS_WINDOWS and pgid:
            for pid, _start in ours:
                try:
                    if os.getpgid(pid) == int(pgid):
                        os.killpg(int(pgid), signal.SIGKILL)
                        break
                except (ProcessLookupError, PermissionError):
                    continue
        for pid, start in ours:
            _kill_pid_tree(pid, start)
        deadline = time.monotonic() + 5
        left = [pid for pid, start in ours if is_alive(pid, start)]
        while left and time.monotonic() < deadline:
            time.sleep(0.1)
            left = [pid for pid, start in ours if is_alive(pid, start)]
        report["killed"].extend(pid for pid, _start in ours if pid not in left)
        report["remaining"].extend(left)
        if not left:
            path.unlink(missing_ok=True)
    return report


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #


def _mentions_protected_port(command: list[str]) -> bool:
    needle = str(PROTECTED_PORT)
    for token in command:
        for part in token.replace("=", " ").replace(":", " ").split():
            if part == needle:
                return True
    return False


def port_problem(port: int | None, command: list[str]) -> str | None:
    if port == PROTECTED_PORT or _mentions_protected_port(command):
        return f"port {PROTECTED_PORT} is reserved for the operator's server; pick another port"
    if port is None:
        return None
    if not 0 < port < 65536:
        return f"port {port} is out of range"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            return f"port {port} is already in use"
    return None


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def _resolve(command: list[str]) -> list[str]:
    exe = shutil.which(command[0])
    return [exe, *command[1:]] if exe else list(command)


def run(args: argparse.Namespace, command: list[str]) -> tuple[int, dict]:
    result: dict = {"command": command, "timeout": args.timeout, "port": args.port}
    problem = port_problem(args.port, command)
    if problem:
        result.update(status="refused", reason=problem, exit_code=EXIT_REFUSED, seconds=0.0)
        return EXIT_REFUSED, result

    state_dir = Path(args.state_dir) if args.state_dir else default_state_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / f"run-{os.getpid()}-{uuid.uuid4().hex[:8]}.json"

    env = dict(os.environ)
    env["RAPIDTRIAGE_NO_BROWSER"] = "1"
    kwargs: dict = {"env": env}
    if IS_WINDOWS:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    job = _Job()
    started = time.time()
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(_resolve(command), **kwargs)
    except OSError as exc:
        job.close()
        result.update(status="error", reason=str(exc), exit_code=127, seconds=0.0)
        return 127, result
    job.assign(proc)
    tree = Tree(proc.pid)
    _write_state(state_path, _state_payload(command, proc, tree, started))

    status = "exited"
    exit_code: int | None = None
    try:
        while True:
            exit_code = proc.poll()
            if exit_code is not None:
                break
            if args.timeout and time.monotonic() - t0 >= args.timeout:
                status = "timeout"
                break
            if tree.refresh():
                _write_state(state_path, _state_payload(command, proc, tree, started))
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        status = "interrupted"

    remaining = kill_tree(proc, tree, job, args.grace)
    job.close()
    seconds = round(time.monotonic() - t0, 3)

    if status == "timeout":
        code = EXIT_TIMEOUT
    elif status == "interrupted":
        code = EXIT_INTERRUPT
    else:
        code = exit_code if exit_code is not None else 1
        if code < 0:
            code = 128 - code
    if remaining:
        _write_state(state_path, _state_payload(command, proc, tree, started))
    else:
        state_path.unlink(missing_ok=True)

    result.update(
        status=status,
        exit_code=code,
        child_exit_code=proc.returncode,
        seconds=seconds,
        pid=proc.pid,
        tree=sorted(tree.members),
        remaining=remaining,
        state_file=str(state_path) if remaining else None,
    )
    return code, result


def _emit(result: dict, args: argparse.Namespace) -> None:
    text = json.dumps(result, ensure_ascii=False)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n", encoding="utf-8", newline="\n")
    if args.json:
        sys.stdout.flush()
        print(text, flush=True)
    elif result.get("status") in ("refused", "error", "timeout") or result.get("remaining"):
        print(f"run.py: {result.get('status')}: {result.get('reason', '')}"
              f" remaining={result.get('remaining', [])}".rstrip(), file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a command with a time limit; kill only its own process tree.",
        usage="run.py --timeout N [--port P] [--json] -- <cmd...>\n       run.py --cleanup",
    )
    parser.add_argument("--timeout", type=float, default=0.0,
                        help="seconds before the tree is killed (exit 124); required unless --cleanup")
    parser.add_argument("--port", type=int, help="port the command will listen on; refused if busy or 8710")
    parser.add_argument("--grace", type=float, default=2.0, help="POSIX: seconds between SIGTERM and SIGKILL")
    parser.add_argument("--json", action="store_true", help="print the result JSON as the last stdout line")
    parser.add_argument("--json-out", help="also write the result JSON to this file")
    parser.add_argument("--state-dir", help="directory for state files (default: a per-repo temp dir)")
    parser.add_argument("--cleanup", action="store_true",
                        help="kill processes left by wrappers that are no longer running, then exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" in argv:
        split = argv.index("--")
        own, command = argv[:split], argv[split + 1:]
    else:
        own, command = argv, []
    parser = build_parser()
    args = parser.parse_args(own)

    if args.cleanup:
        state_dir = Path(args.state_dir) if args.state_dir else default_state_dir()
        report = cleanup(state_dir)
        print(json.dumps(report, ensure_ascii=False))
        return 1 if report["remaining"] else 0
    if not command:
        parser.error("missing command after --")
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")

    code, result = run(args, command)
    _emit(result, args)
    return code


if __name__ == "__main__":
    sys.exit(main())
