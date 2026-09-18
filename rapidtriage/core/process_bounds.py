from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence

CHILD_PROCESS_BOUNDARY_PROFILE_VERSION = "child-process-boundary-v1"
CHILD_TIMEOUT_EXIT_CODE = 124
CHILD_RLIMIT_EXIT_CODE = 125

DEFAULT_CHILD_TIMEOUT_SECONDS = 3600
DEFAULT_CHILD_CPU_LIMIT_SECONDS = 7200
DEFAULT_CHILD_FSIZE_BYTES = 512 * 1024 * 1024 * 1024
DEFAULT_CHILD_NOFILE_LIMIT = 4096


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        return default


def child_timeout_seconds() -> int:
    return _env_int("RAPIDTRIAGE_CHILD_TIMEOUT_SECONDS", DEFAULT_CHILD_TIMEOUT_SECONDS)


def _posix_limiter(cpu_seconds: int, fsize_bytes: int, nofile_limit: int):
    def apply_limits() -> None:
        import resource

        if cpu_seconds > 0:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        if fsize_bytes > 0:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
        if nofile_limit > 0:
            resource.setrlimit(resource.RLIMIT_NOFILE, (nofile_limit, nofile_limit))

    return apply_limits


def run_bounded_command(
    command: Sequence[str],
    *,
    timeout_seconds: int | None = None,
    encoding: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a forensic helper tool with bounded wall time and POSIX resource limits.

    Enforced: wall-clock timeout, RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NOFILE on
    POSIX. Not enforced: filesystem isolation, network isolation, address-space
    caps, and process-count caps — hostile-evidence handling must not be
    described as sandboxed on the strength of this runner alone.
    """
    timeout = timeout_seconds if timeout_seconds is not None else child_timeout_seconds()
    cpu_seconds = _env_int("RAPIDTRIAGE_CHILD_CPU_SECONDS", DEFAULT_CHILD_CPU_LIMIT_SECONDS)
    fsize_bytes = _env_int("RAPIDTRIAGE_CHILD_FSIZE_BYTES", DEFAULT_CHILD_FSIZE_BYTES)
    nofile_limit = _env_int("RAPIDTRIAGE_CHILD_NOFILE", DEFAULT_CHILD_NOFILE_LIMIT)
    kwargs: dict[str, object] = {"capture_output": True, "text": True}
    if encoding:
        kwargs["encoding"] = encoding
        kwargs["errors"] = "replace"
    if timeout and timeout > 0:
        kwargs["timeout"] = timeout
    if os.name == "posix":
        kwargs["preexec_fn"] = _posix_limiter(cpu_seconds, fsize_bytes, nofile_limit)
    try:
        return subprocess.run(list(command), **kwargs)  # type: ignore[arg-type]
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return subprocess.CompletedProcess(
            list(command),
            CHILD_TIMEOUT_EXIT_CODE,
            stdout,
            f"{stderr}\nchild process timed out after {timeout}s".strip(),
        )


def child_process_boundary_profile() -> dict[str, object]:
    posix = os.name == "posix"
    return {
        "profile_version": CHILD_PROCESS_BOUNDARY_PROFILE_VERSION,
        "platform_posix": posix,
        "enforced": {
            "wall_clock_timeout_seconds": child_timeout_seconds(),
            "timeout_exit_code": CHILD_TIMEOUT_EXIT_CODE,
            "rlimit_cpu_seconds": _env_int("RAPIDTRIAGE_CHILD_CPU_SECONDS", DEFAULT_CHILD_CPU_LIMIT_SECONDS) if posix else 0,
            "rlimit_fsize_bytes": _env_int("RAPIDTRIAGE_CHILD_FSIZE_BYTES", DEFAULT_CHILD_FSIZE_BYTES) if posix else 0,
            "rlimit_nofile": _env_int("RAPIDTRIAGE_CHILD_NOFILE", DEFAULT_CHILD_NOFILE_LIMIT) if posix else 0,
            "shell": False,
        },
        "not_enforced": {
            "filesystem_isolation": "no chroot/sandbox-exec/bwrap; child tools keep the caller's filesystem view",
            "network_isolation": "no network namespace or sandbox profile applied to child tools",
            "rlimit_as": "address-space caps are not set; forensic tools legitimately map large images",
            "rlimit_nproc": "process-count caps are not set; FUSE helpers spawn children",
            "windows_platform": not posix,
        },
        "hostile_evidence_sandboxed": False,
        "note": (
            "Bounded child execution limits runaway time/CPU/output size only. "
            "Treat evidence parsers as unsandboxed until OS-level isolation evidence exists."
        ),
        "commercial_claim_allowed": False,
    }


def run_bounded_paths() -> dict[str, object]:
    return {
        "runners": [
            "rapidtriage.core.e01.default_runner",
            "rapidtriage.core.disk_image.default_runner",
            "rapidtriage.core.virtual_disk.default_runner",
            "rapidtriage.core.archive_image.default_runner",
        ],
        "tools": ["ewfmount", "mmls", "tsk_recover", "ewfverify", "fsstat", "qemu-img", "umount", "fusermount"],
    }
