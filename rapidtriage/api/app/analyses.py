"""Analysis workbench jobs: CLI-only analyses run from the console (plan P1 §3.1).

An analysis is a bounded job over a completed run (carving, VSC, NTFS
metadata, OCR batch, memory import, cross-case correlation). Each one lives
in ``<run output_dir>/analyses/<analysis_id>/``:

* ``analysis.json`` -- the AnalysisState, rewritten atomically (temp file +
  ``os.replace``) on every status change, at most once per second while
  progress moves, and on a heartbeat while a unit runs long;
* ``rows.jsonl`` -- result rows ``{"artifact_type": "<kind>-row", "path"?,
  "details": {...}}`` appended as units finish, so a cancelled analysis keeps
  its partial rows; ``row_count`` only counts rows already flushed to disk;
* kind-specific files (manifests, extracted bytes).

There is no index file: the analyses of a run are the ``analyses/*/
analysis.json`` files on disk. Every active state records its owner
(``_owner = {pid, boot_id, heartbeat_at}``). A ``queued``/``running`` state
whose owner process is gone, rebooted, or silent past
``HEARTBEAT_STALE_SECONDS`` is *served* as ``failed`` with ``RESTART_MESSAGE``;
reads never rewrite state files.

Execution uses one process-wide pool of ``ANALYSIS_MAX_WORKERS`` daemon
threads. Cancellation sets a ``threading.Event`` that kind runners check at
every unit boundary; the state keeps its status (with ``cancel_requested_at``)
until the runner stops and ``cancelled`` is written; a still-queued analysis is
taken off the queue and written ``cancelled`` at once. An app's shutdown cancels
the analyses that app submitted and drops its queued ones, which end
``cancelled`` (``AnalysisRunner.shutdown(owner=...)``); other apps sharing the
process-wide pool are not touched. Kind
runners (``analysis_kinds``) only call existing core functions.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import ntpath
import os
import queue
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict

from fastapi import HTTPException, Query
from pydantic import BaseModel, ValidationError

from ...core.jobs import RunJob, RunJobStore, is_relative_to, run_output_dir
from ...core.json_safe import json_default
from .helpers import allowed_source_roots, get_job

LOGGER = logging.getLogger(__name__)

ANALYSES_DIR_NAME = "analyses"
STATE_FILE_NAME = "analysis.json"
ROWS_FILE_NAME = "rows.jsonl"
ANALYSIS_STATE_VERSION = "analysis-state-v1"
ANALYSIS_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})
RUN_READY_STATUSES = frozenset({"completed", "failed"})
RESTART_MESSAGE = "서버 재시작으로 중단"
ALREADY_RUNNING_MESSAGE = "이미 실행 중인 분석이 있습니다"
PROGRESS_WRITE_INTERVAL_SECONDS = 1.0
HEARTBEAT_INTERVAL_SECONDS = 15.0
HEARTBEAT_STALE_SECONDS = 90.0
BOOT_ID_TOLERANCE_SECONDS = 120
ANALYSIS_MAX_WORKERS = 2
REPLACE_ATTEMPTS = 5
TERMINAL_REPLACE_ATTEMPTS = 40
RUNNING_PERCENT_CAP = 99.9
# Extra roots an operator allows for analysis *inputs* (os.pathsep list). They are
# evidence: never an output target.
ANALYSIS_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_ROOTS"
# Extra roots an operator allows for analysis *outputs* (same parsing rules).
ANALYSIS_OUTPUT_ROOTS_ENV = "RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS"
_BACKSLASH = "\\"


class AnalysisCancelled(Exception):
    """Raised by ``AnalysisContext.check_cancel`` at a unit boundary."""


class AnalysisFailure(Exception):
    """A kind runner's expected failure; ``str(exc)`` is the Korean error shown to the examiner."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _state_text(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=json_default) + "\n"


def atomic_write_json(path: Path, payload: Mapping[str, object], *, attempts: int = REPLACE_ATTEMPTS) -> None:
    """Write ``payload`` as JSON via temp file + ``os.replace`` (retried on Windows sharing errors)."""
    tmp_path = path.with_name(f"{path.name}.{threading.get_ident()}.tmp")
    tmp_path.write_text(_state_text(payload), encoding="utf-8")
    for attempt in range(attempts):
        try:
            os.replace(tmp_path, path)
            return
        except PermissionError:
            # Windows refuses to replace a file another reader holds open.
            if attempt == attempts - 1:
                tmp_path.unlink(missing_ok=True)
                raise
            time.sleep(0.05)


def write_terminal_json(path: Path, payload: Mapping[str, object]) -> None:
    """Terminal state: retry the atomic replace longer, then fall back to a plain write."""
    try:
        atomic_write_json(path, payload, attempts=TERMINAL_REPLACE_ATTEMPTS)
    except OSError as exc:
        LOGGER.warning("atomic terminal write of %s failed (%s); writing in place", path, exc)
        path.write_text(_state_text(payload), encoding="utf-8")


def read_state_file(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


# --- process ownership ----------------------------------------------------------


def boot_id() -> int:
    """Approximate boot time (epoch seconds); changes across reboots."""
    return int(time.time() - time.monotonic())


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return kernel32.GetLastError() == 5  # access denied: the process exists
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def owner_record() -> dict[str, object]:
    return {"pid": os.getpid(), "boot_id": boot_id(), "heartbeat_at": time.time()}


def orphan_reason(owner: object, *, now: float | None = None) -> str | None:
    """Why an active state's owner can no longer finish it (``None``: still owned elsewhere)."""
    if not isinstance(owner, Mapping):
        return "owner-missing"
    now = time.time() if now is None else now
    try:
        pid = int(owner.get("pid") or 0)
        owner_boot = int(owner.get("boot_id") or 0)
        heartbeat = float(owner.get("heartbeat_at") or 0.0)
    except (TypeError, ValueError):
        return "owner-invalid"
    if abs(owner_boot - boot_id()) > BOOT_ID_TOLERANCE_SECONDS:
        return "rebooted"
    if pid == os.getpid():
        return "not-active-in-owner"  # this process owns it but no longer runs it
    if not pid_alive(pid):
        return "owner-dead"
    if now - heartbeat > HEARTBEAT_STALE_SECONDS:
        return "heartbeat-stale"
    return None


# --- path policy ----------------------------------------------------------------


def _forbidden(label: str, reason: str) -> HTTPException:
    return HTTPException(status_code=403, detail=f"{label} 경로를 허용하지 않습니다: {reason}")


def lexical_absolute_path(raw: str, *, label: str) -> str:
    """Reject UNC/device/relative/home paths without touching the filesystem; return ``abspath``."""
    text = str(raw or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail=f"{label} 경로가 비어 있습니다")
    if "\x00" in text:
        raise HTTPException(status_code=400, detail=f"{label} 경로에 NUL 문자가 있습니다")
    if text.startswith("~"):
        raise _forbidden(label, "홈 디렉터리(~) 표기는 쓸 수 없습니다")
    if os.name == "nt":
        normalized = text.replace("/", _BACKSLASH)
        if normalized.startswith(_BACKSLASH * 2):
            raise _forbidden(label, r"UNC·장치 경로(\\server, \\?\, \\.\)는 쓸 수 없습니다")
        drive, rest = ntpath.splitdrive(normalized)
        if not drive:
            raise _forbidden(label, "드라이브 문자를 포함한 절대 경로여야 합니다")
        if not rest.startswith(_BACKSLASH):
            raise _forbidden(label, "드라이브 상대 경로(C:foo)는 쓸 수 없습니다")
    else:
        if text.startswith("//"):
            raise _forbidden(label, "네트워크 경로는 쓸 수 없습니다")
        if not text.startswith("/"):
            raise _forbidden(label, "절대 경로여야 합니다")
    return os.path.abspath(text)


def _root_forms(values: Iterable[object]) -> list[Path]:
    """Lexical and resolved forms of local absolute root paths."""
    roots: list[Path] = []
    for value in values:
        candidates: list[Path] = []
        if isinstance(value, Path):
            candidates = [value]
        elif isinstance(value, str) and value.strip():
            text = value.strip()
            if os.name == "nt" and text.replace("/", _BACKSLASH).startswith(_BACKSLASH * 2):
                continue
            candidates = [Path(os.path.abspath(text))]
            try:
                candidates.append(Path(text).resolve())
            except (OSError, RuntimeError, ValueError):
                pass
        for candidate in candidates:
            if candidate not in roots:
                roots.append(candidate)
    return roots


def extra_analysis_roots(env: str = ANALYSIS_ROOTS_ENV) -> list[Path]:
    """Roots from ``env`` (an os.pathsep list): quotes stripped; relative/UNC/``~`` entries ignored with a warning.

    ``RAPIDTRIAGE_ANALYSIS_ROOTS`` (default) lists input roots,
    ``RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS`` output roots.
    """
    entries: list[str] = []
    for item in os.environ.get(env, "").split(os.pathsep):
        item = item.strip().strip("\"'").strip()
        if not item:
            continue
        try:
            lexical_absolute_path(item, label=env)
        except HTTPException as exc:
            LOGGER.warning("ignoring %s entry %r: %s", env, item, exc.detail)
            continue
        entries.append(item)
    return _root_forms(entries)


def _under_any(path: Path, roots: Iterable[Path]) -> bool:
    return any(path == root or is_relative_to(path, root) for root in roots)


MAX_LINK_HOPS = 40
_EXTENDED_PREFIXES = ("\\\\?\\", "\\??\\")


def _link_target(path: Path) -> str | None:
    """The stored target of ``path`` when it is a symlink/junction (``lstat``/``readlink``: never followed)."""
    from ...core.link_safe_walk import lstat_is_link

    try:
        if not lstat_is_link(path):
            return None
        return os.readlink(path)
    except (OSError, ValueError):
        return None  # missing, or a reparse point that is not a readable link


def _link_escape(label: str, scope: str, target: object) -> HTTPException:
    return HTTPException(status_code=403, detail=f"{label} 경로가 링크를 거쳐 허용 범위({scope}) 밖을 가리킵니다: {target}")


def _normalized_link_target(target: str, link: Path) -> str | None:
    """Absolute local form of a link target, or ``None`` when it names a network/device path."""
    text = target
    for prefix in _EXTENDED_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):]
            if text[:4].upper() == "UNC\\":
                return None  # \\?\UNC\server\share
            break
    if text.replace("/", _BACKSLASH).startswith(_BACKSLASH * 2) or text.startswith("//"):
        return None  # \\server\share, //server/share
    if not os.path.isabs(text) or (os.name == "nt" and not ntpath.splitdrive(text)[0]):
        text = os.path.join(os.path.dirname(link), text)
    return os.path.abspath(text)


def precheck_links(lexical: Path, roots: list[Path], *, label: str, scope: str) -> None:
    """Before ``resolve()``: follow link components lexically and refuse network or outside targets.

    Each component below the matching root is ``lstat``-ed (never followed);
    a symlink/junction's stored target is read with ``readlink`` and, when it
    names a UNC/device path or lands outside ``roots``, the request is refused
    without ever opening the target (``resolve`` could otherwise reach a
    remote share first). Targets inside ``roots`` are walked the same way.
    """
    current = Path(lexical)
    for _hop in range(MAX_LINK_HOPS):
        base = max((root for root in roots if current == root or is_relative_to(current, root)), key=lambda r: len(r.parts), default=None)
        if base is None:
            raise _link_escape(label, scope, current)
        parts = current.relative_to(base).parts
        probe = base
        for index, part in enumerate(parts):
            probe = probe / part
            target = _link_target(probe)
            if target is None:
                continue
            normalized = _normalized_link_target(target, probe)
            if normalized is None:
                raise _link_escape(label, scope, target)
            current = Path(normalized).joinpath(*parts[index + 1 :])
            break
        else:
            return
    raise _link_escape(label, scope, current)


def confine_path(raw: str, roots: list[Path], *, label: str, scope: str) -> Path:
    """Lexical form check, lexical root check, lexical link walk, then resolve and re-check."""
    lexical = Path(lexical_absolute_path(raw, label=label))
    if not _under_any(lexical, roots):
        raise HTTPException(status_code=403, detail=f"{label} 경로가 허용 범위({scope}) 밖에 있습니다: {lexical}")
    precheck_links(lexical, roots, label=label, scope=scope)
    try:
        resolved = lexical.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{label} 경로를 해석할 수 없습니다: {exc}") from exc
    if not _under_any(resolved, roots):
        raise HTTPException(
            status_code=403,
            detail=f"{label} 경로가 링크를 거쳐 허용 범위({scope}) 밖을 가리킵니다: {resolved}",
        )
    return resolved


# --- run scope -------------------------------------------------------------

INPUT_SCOPE = "런 소스/출력 디렉터리 또는 서버 허용 입력 루트"
OUTPUT_SCOPE = f"런 출력 디렉터리 또는 서버 허용 출력 루트({ANALYSIS_OUTPUT_ROOTS_ENV})"


@dataclass
class RunScope:
    """The completed run an analysis reads from, with its path policy."""

    store: RunJobStore
    run_id: str
    job: RunJob
    summary: dict[str, object]
    output_dir: Path

    @property
    def source(self) -> Mapping[str, object]:
        source = self.summary.get("source")
        return source if isinstance(source, Mapping) else {}

    def source_path(self) -> Path | None:
        value = self.source.get("source_path") or self.summary.get("root")
        return Path(str(value)).expanduser().resolve() if value else None

    def scan_root(self) -> Path:
        for value in (self.summary.get("scan_scope_root"), self.source.get("analysis_root"), self.summary.get("root")):
            if isinstance(value, str) and value:
                return Path(value).expanduser().resolve()
        raise AnalysisFailure("런 요약에 스캔 루트가 없습니다")

    def input_roots(self) -> list[Path]:
        raw = [self.summary.get(key) for key in ("root", "scan_scope_root", "output_dir")]
        raw += [self.source.get(key) for key in ("analysis_root", "stage_dir", "source_path")]
        roots = _root_forms([*raw, *allowed_source_roots(self.summary)])
        roots.extend(root for root in extra_analysis_roots() if root not in roots)
        return roots

    def output_roots(self) -> list[Path]:
        """Run output dir + ``RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS`` (input roots are never output targets)."""
        roots = _root_forms([self.summary.get("output_dir"), self.output_dir])
        roots.extend(root for root in extra_analysis_roots(ANALYSIS_OUTPUT_ROOTS_ENV) if root not in roots)
        return roots

    def resolve_input_path(self, raw: str, *, label: str) -> Path:
        """Resolve an input path option; 403 unless under the run's allowed roots."""
        return confine_path(raw, self.input_roots(), label=label, scope=INPUT_SCOPE)

    def resolve_output_path(self, raw: str, *, label: str) -> Path:
        """Resolve an output path option; 403 unless under the run output dir or server output roots."""
        return confine_path(raw, self.output_roots(), label=label, scope=OUTPUT_SCOPE)

    def allows_input(self, path: Path | str) -> bool:
        try:
            self.resolve_input_path(str(path), label="경로")
        except HTTPException:
            return False
        return True


def run_scope(store: RunJobStore, run_id: str, *, require_ready: bool = True) -> RunScope:
    job = get_job(store, run_id)
    if require_ready and job.status not in RUN_READY_STATUSES:
        raise HTTPException(status_code=409, detail="완료되거나 실패한 런에서만 분석을 실행할 수 있습니다")
    if job.summary is None:
        raise HTTPException(status_code=409, detail="런 요약이 없어 분석을 실행할 수 없습니다")
    try:
        output_dir = run_output_dir(job.summary)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail="런 요약에 출력 디렉터리가 없습니다") from exc
    return RunScope(store=store, run_id=run_id, job=job, summary=job.summary, output_dir=output_dir)


# --- kind registry ------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisSpec:
    """One analysis kind: option model, path preparation and runner."""

    kind: str
    label: str
    unit: str
    options_model: type[BaseModel]
    run: Callable[[AnalysisContext], None]
    # Validates/normalizes options against the run (403 for paths outside roots).
    prepare: Callable[[BaseModel, RunScope], dict[str, object]] | None = None
    field_labels: Mapping[str, str] = field(default_factory=dict)


def kind_registry() -> Mapping[str, AnalysisSpec]:
    from .analysis_kinds import KIND_RUNNERS

    return KIND_RUNNERS


def get_spec(kind: str) -> AnalysisSpec:
    registry = kind_registry()
    spec = registry.get(kind)
    if spec is None:
        raise HTTPException(
            status_code=400,
            detail=f"지원하지 않는 분석 종류입니다: {kind!r} (가능: {', '.join(sorted(registry))})",
        )
    return spec


_DIGIT_HAS_FINAL = {"0": True, "1": True, "2": False, "3": True, "4": False, "5": False, "6": True, "7": True, "8": True, "9": False}
_TRAILING_PARENS = re.compile(r"\s*\([^()]*\)\s*$")


def _has_final_consonant(word: str) -> bool | None:
    """Whether ``word`` (a trailing ``(…)`` is ignored) ends in a 받침; ``None`` when unknown (Latin etc.)."""
    text = _TRAILING_PARENS.sub("", word.strip()) or word.strip()
    text = text.rstrip(" .,:;!?\"'")
    if not text:
        return None
    last = text[-1]
    if "가" <= last <= "힣":
        return (ord(last) - 0xAC00) % 28 != 0
    return _DIGIT_HAS_FINAL.get(last)


def with_josa(word: str, final: str, open_: str) -> str:
    """``word`` + the particle matching its last syllable (``은``/``는``, ``이``/``가``); ``은(는)`` form when unknown."""
    has_final = _has_final_consonant(word)
    if has_final is None:
        return f"{word}{final}({open_})"
    return f"{word}{final if has_final else open_}"


_ERROR_TEMPLATES: dict[str, str] = {
    "missing": "{label} 값이 필요합니다",
    "extra_forbidden": "알 수 없는 옵션입니다: {label}",
    "int_parsing": "{topic} 정수여야 합니다",
    "int_type": "{topic} 정수여야 합니다",
    "int_from_float": "{topic} 정수여야 합니다",
    "bool_parsing": "{topic} true/false 여야 합니다",
    "bool_type": "{topic} true/false 여야 합니다",
    "string_type": "{topic} 문자열이어야 합니다",
    "list_type": "{topic} 목록이어야 합니다",
    "dict_type": "{topic} 객체여야 합니다",
    "model_type": "{topic} 객체여야 합니다",
    "greater_than_equal": "{topic} {ge} 이상이어야 합니다",
    "greater_than": "{topic} {gt}보다 커야 합니다",
    "less_than_equal": "{topic} {le} 이하여야 합니다",
    "less_than": "{topic} {lt}보다 작아야 합니다",
    "too_short": "{label} 항목이 너무 적습니다(최소 {min_length}개)",
    "too_long": "{label} 항목이 너무 많습니다(최대 {max_length}개)",
    "string_too_short": "{subject} 비어 있습니다",
    "string_too_long": "{subject} 너무 깁니다(최대 {max_length}자)",
    "literal_error": "{label} 값은 {expected} 중 하나여야 합니다",
    "enum": "{label} 값은 {expected} 중 하나여야 합니다",
}


_BYTE_BOUND_TEMPLATES: dict[str, tuple[str, str]] = {
    "greater_than_equal": ("ge", "{topic} {mb} 이상이어야 합니다"),
    "greater_than": ("gt", "{topic} {mb}보다 커야 합니다"),
    "less_than_equal": ("le", "{topic} {mb} 이하여야 합니다"),
    "less_than": ("lt", "{topic} {mb}보다 작아야 합니다"),
}
MIB = 1024 * 1024


def _format_mb(value: int) -> str:
    """Bytes -> ``"16,384 MB"`` (non-whole values with two decimals)."""
    if value % MIB == 0:
        return f"{value // MIB:,} MB"
    return f"{value / MIB:,.2f} MB"


def korean_validation_errors(exc: ValidationError, labels: Mapping[str, str]) -> list[dict[str, object]]:
    """Pydantic errors -> ``[{loc, msg, type}]`` with Korean messages for the dialog."""
    errors: list[dict[str, object]] = []
    for error in exc.errors():
        loc = [str(part) for part in error.get("loc", ())]
        key = loc[0] if loc else ""
        label = labels.get(".".join(loc)) or labels.get(key) or ".".join(loc) or "옵션"
        error_type = str(error.get("type") or "")
        context = dict(error.get("ctx") or {})
        template = _ERROR_TEMPLATES.get(error_type)
        particles = {"topic": with_josa(label, "은", "는"), "subject": with_josa(label, "이", "가")}
        if key.endswith("_bytes") and error_type in _BYTE_BOUND_TEMPLATES:
            # The dialog labels byte fields in MB: state the bound in MB too.
            bound = int(context.get(_BYTE_BOUND_TEMPLATES[error_type][0]) or 0)
            if error_type.startswith("greater") and 0 < bound < MIB:
                message = f"{particles['topic']} 0 MB보다 커야 합니다"
            else:
                message = _BYTE_BOUND_TEMPLATES[error_type][1].format(label=label, mb=_format_mb(bound), **particles)
        elif template is not None:
            try:
                extra = {k: v for k, v in context.items() if k not in {"label", "topic", "subject"}}
                message = template.format(label=label, **particles, **extra)
            except (KeyError, IndexError):
                message = f"{label} 값이 올바르지 않습니다"
        elif error_type == "value_error":
            message = str(context.get("error") or error.get("msg") or "").removeprefix("Value error, ")
        else:
            message = f"{label} 값이 올바르지 않습니다"
        errors.append({"loc": ["options", *loc], "msg": message, "type": error_type})
    return errors



# --- context ------------------------------------------------------------------


class AnalysisContext:
    """What a kind runner sees: options, run scope, progress, rows, cancellation."""

    def __init__(
        self,
        *,
        scope: RunScope,
        spec: AnalysisSpec,
        state: dict[str, object],
        directory: Path,
        options: BaseModel,
        owner: object | None = None,
    ) -> None:
        self.scope = scope
        self.spec = spec
        # The app (``create_app`` token) that submitted it; its shutdown cancels only these.
        self.owner = owner
        self.state = state
        self.directory = directory
        self.options = options
        self.cancel_event = threading.Event()
        self.lock = threading.RLock()
        self.summary: dict[str, object] = state.setdefault("summary", {})  # type: ignore[assignment]
        self._rows_handle = None
        self._pending_rows = 0
        self._last_write = 0.0

    # -- state persistence ---------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.directory / STATE_FILE_NAME

    @property
    def rows_path(self) -> Path:
        return self.directory / ROWS_FILE_NAME

    def _flush_rows_locked(self) -> None:
        if self._rows_handle is not None:
            self._rows_handle.flush()
        if self._pending_rows:
            self.state["row_count"] = int(self.state.get("row_count") or 0) + self._pending_rows
            self._pending_rows = 0

    def write_state(self, *, force: bool = True, terminal: bool = False) -> None:
        with self.lock:
            now = time.monotonic()
            if not force and now - self._last_write < PROGRESS_WRITE_INTERVAL_SECONDS:
                return
            self._flush_rows_locked()
            self._last_write = now
            if self.state.get("status") in ACTIVE_STATUSES:
                self.state["_owner"] = owner_record()
            else:
                self.state.pop("_owner", None)
            try:
                if terminal:
                    write_terminal_json(self.state_path, self.state)
                else:
                    atomic_write_json(self.state_path, self.state)
            except OSError as exc:  # state bookkeeping must not kill the analysis
                LOGGER.warning("analysis state write failed for %s: %s", self.state_path, exc)

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return json.loads(json.dumps(self.state, default=json_default))

    # -- runner API ----------------------------------------------------------

    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise AnalysisCancelled()

    def _progress(self) -> dict[str, object]:
        progress = self.state.get("progress")
        if not isinstance(progress, dict):
            progress = new_progress(self.spec.unit)
            self.state["progress"] = progress
        return progress

    def progress_done(self) -> int:
        with self.lock:
            return int(self._progress().get("done") or 0)

    def set_total(self, total: int | None, *, unit: str | None = None, message: str | None = None) -> None:
        """Set the unit total; it never drops below the units already done."""
        with self.lock:
            progress = self._progress()
            done = int(progress.get("done") or 0)
            progress["total"] = None if total is None else max(done, int(total))
            if unit:
                progress["unit"] = unit
            if message is not None:
                progress["message"] = message
            refresh_percent(progress)
        self.write_state(force=False)

    def advance(self, count: int = 1, *, message: str | None = None) -> None:
        with self.lock:
            progress = self._progress()
            done = int(progress.get("done") or 0) + max(0, count)
            progress["done"] = done
            total = progress.get("total")
            if isinstance(total, int) and total < done:
                progress["total"] = done
            if message is not None:
                progress["message"] = message
            refresh_percent(progress)
        self.write_state(force=False)

    def extend(self, count: int, *, message: str | None = None) -> None:
        """Grow total and done together (units found and finished in one step)."""
        with self.lock:
            progress = self._progress()
            done = int(progress.get("done") or 0) + max(0, count)
            total = progress.get("total")
            progress["done"] = done
            progress["total"] = max(done, (int(total) if isinstance(total, int) else 0) + max(0, count))
            if message is not None:
                progress["message"] = message
            refresh_percent(progress)
        self.write_state(force=False)

    def set_message(self, message: str) -> None:
        with self.lock:
            self._progress()["message"] = message
        self.write_state(force=False)

    def open_rows(self) -> None:
        with self.lock:
            if self._rows_handle is None:
                self._rows_handle = self.rows_path.open("ab")

    def write_row(self, row: Mapping[str, object]) -> None:
        line = json.dumps(row, ensure_ascii=False, default=json_default).encode("utf-8") + b"\n"
        with self.lock:
            self.open_rows()
            assert self._rows_handle is not None
            self._rows_handle.write(line)
            self._pending_rows += 1

    def close_rows(self) -> None:
        with self.lock:
            self._flush_rows_locked()
            if self._rows_handle is not None:
                self._rows_handle.close()
                self._rows_handle = None

    def row(self, details: Mapping[str, object], *, path: str | None = None) -> dict[str, object]:
        """Build a ``<kind>-row`` record."""
        record: dict[str, object] = {"artifact_type": f"{self.spec.kind}-row"}
        if path:
            record["path"] = path
        record["details"] = dict(details)
        return record


def new_progress(unit: str) -> dict[str, object]:
    return {"done": 0, "total": None, "unit": unit, "message": "", "percent": None}


def refresh_percent(progress: dict[str, object], *, finished: bool = False) -> None:
    """Percent of done/total, capped at ``RUNNING_PERCENT_CAP`` until the analysis completes."""
    if finished:
        progress["percent"] = 100.0
        return
    total = progress.get("total")
    done = int(progress.get("done") or 0)
    if isinstance(total, int) and total > 0:
        progress["percent"] = round(min(RUNNING_PERCENT_CAP, done * 100.0 / total), 1)
    elif total == 0:
        progress["percent"] = RUNNING_PERCENT_CAP
    else:
        progress["percent"] = None


# --- store --------------------------------------------------------------------


def analyses_root(output_dir: Path) -> Path:
    return Path(output_dir) / ANALYSES_DIR_NAME


def analysis_directory(output_dir: Path, analysis_id: str) -> Path:
    if not ANALYSIS_ID_PATTERN.fullmatch(analysis_id or ""):
        raise HTTPException(status_code=404, detail="분석을 찾을 수 없습니다")
    return analyses_root(output_dir) / analysis_id


def public_state(state: Mapping[str, object]) -> dict[str, object]:
    """AnalysisState as served by the API (internal keys dropped)."""
    return {key: value for key, value in state.items() if not str(key).startswith("_")}


class DaemonWorkerPool:
    """Minimal executor on daemon threads (interpreter exit never waits for an analysis)."""

    def __init__(self, max_workers: int, name: str) -> None:
        self._max_workers = max_workers
        self._name = name
        self._queue: queue.Queue[tuple[Callable[..., None], tuple[object, ...]] | None] = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._shutdown = False

    def submit(self, fn: Callable[..., None], *args: object) -> None:
        with self._lock:
            if self._shutdown:
                raise RuntimeError("analysis worker pool is shut down")
            self._queue.put((fn, args))
            if len(self._threads) < self._max_workers:
                thread = threading.Thread(target=self._work, name=f"{self._name}-{len(self._threads)}", daemon=True)
                self._threads.append(thread)
                thread.start()

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            fn, args = item
            try:
                fn(*args)
            except Exception:  # pragma: no cover - _execute handles its own errors
                LOGGER.exception("analysis worker task failed")

    def drop_queued(self, predicate: Callable[[tuple[object, ...]], bool]) -> list[tuple[object, ...]]:
        """Remove the queued (never started) tasks whose args match ``predicate``; return their args."""
        dropped: list[tuple[object, ...]] = []
        kept: list[tuple[Callable[..., None], tuple[object, ...]] | None] = []
        with self._lock:
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is not None and predicate(item[1]):
                    dropped.append(item[1])
                else:
                    kept.append(item)
            for item in kept:
                self._queue.put(item)
        return dropped

    def shutdown(self, *, wait: bool = False, cancel_futures: bool = False) -> list[tuple[object, ...]]:
        """Stop accepting work; with ``cancel_futures`` return the queued (never started) tasks' args."""
        dropped: list[tuple[object, ...]] = []
        with self._lock:
            self._shutdown = True
            if cancel_futures:
                while True:
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if item is not None:
                        dropped.append(item[1])
            for _thread in self._threads:
                self._queue.put(None)
            threads = list(self._threads)
        if wait:
            for thread in threads:
                thread.join()
        return dropped


class AnalysisRunner:
    """Process-wide worker pool and registry of the analyses this process runs."""

    def __init__(self, *, max_workers: int = ANALYSIS_MAX_WORKERS) -> None:
        self._max_workers = max_workers
        self._pool: DaemonWorkerPool | None = None
        self._lock = threading.Lock()
        self._active: dict[tuple[str, str], AnalysisContext] = {}
        self._heartbeat: threading.Thread | None = None

    def _get_pool(self) -> DaemonWorkerPool:
        if self._pool is None:
            self._pool = DaemonWorkerPool(self._max_workers, "rapidtriage-analysis")
        if self._heartbeat is None or not self._heartbeat.is_alive():
            self._heartbeat = threading.Thread(target=self._beat, name="rapidtriage-analysis-heartbeat", daemon=True)
            self._heartbeat.start()
        return self._pool

    def _beat(self) -> None:
        while True:
            time.sleep(HEARTBEAT_INTERVAL_SECONDS)
            with self._lock:
                contexts = list(self._active.values())
            for context in contexts:
                context.write_state()

    # -- read side ------------------------------------------------------------

    @staticmethod
    def _key(output_dir: Path, analysis_id: str) -> tuple[str, str]:
        return (str(Path(output_dir).resolve()), analysis_id)

    def _context(self, output_dir: Path, analysis_id: str) -> AnalysisContext | None:
        with self._lock:
            return self._active.get(self._key(output_dir, analysis_id))

    def load_state(self, output_dir: Path, analysis_id: str) -> dict[str, object] | None:
        """Current state (live when running here); orphaned active states are served as failed, never rewritten."""
        context = self._context(output_dir, analysis_id)
        if context is not None:
            return context.snapshot()
        state = read_state_file(analyses_root(output_dir) / analysis_id / STATE_FILE_NAME)
        if state is None or state.get("status") not in ACTIVE_STATUSES:
            return state
        context = self._context(output_dir, analysis_id)  # registered while we read
        if context is not None:
            return context.snapshot()
        reason = orphan_reason(state.get("_owner"))
        if reason is None:
            return state  # another live server process owns it
        owner = state.get("_owner") if isinstance(state.get("_owner"), Mapping) else {}
        heartbeat = owner.get("heartbeat_at") if isinstance(owner, Mapping) else None
        finished = (
            dt.datetime.fromtimestamp(float(heartbeat), dt.timezone.utc).isoformat()
            if isinstance(heartbeat, (int, float))
            else None
        )
        return {
            **state,
            "status": "failed",
            "error": RESTART_MESSAGE,
            "interrupted_reason": reason,
            "finished_at": finished,
            "elapsed_s": elapsed_seconds(state.get("started_at"), finished),
        }

    def list_states(self, output_dir: Path) -> list[dict[str, object]]:
        root = analyses_root(output_dir)
        states: list[dict[str, object]] = []
        try:
            children = [child for child in root.iterdir() if child.is_dir()]
        except OSError:
            return []
        for child in children:
            if not ANALYSIS_ID_PATTERN.fullmatch(child.name):
                continue
            state = self.load_state(output_dir, child.name)
            if state is not None:
                states.append(state)
        states.sort(key=lambda item: (str(item.get("created_at") or ""), str(item.get("analysis_id") or "")), reverse=True)
        return states

    def latest(self, output_dir: Path, kinds: Iterable[str], *, status: str | None = None) -> dict[str, object] | None:
        wanted = set(kinds)
        for state in self.list_states(output_dir):
            if state.get("kind") in wanted and (status is None or state.get("status") == status):
                return state
        return None

    # -- write side -----------------------------------------------------------

    def _busy(self, output_key: str, kind: str) -> bool:
        """Any registered context of this kind (incl. one whose cancel is still pending)."""
        return any(key[0] == output_key and ctx.spec.kind == kind for key, ctx in self._active.items())

    def submit(
        self,
        scope: RunScope,
        kind: str,
        raw_options: Mapping[str, object] | None,
        *,
        owner: object | None = None,
    ) -> dict[str, object]:
        """Queue one analysis; ``owner`` scopes it to that app's ``shutdown(owner=...)``."""
        spec = get_spec(kind)
        try:
            options = spec.options_model.model_validate(dict(raw_options or {}))
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=korean_validation_errors(exc, spec.field_labels)) from exc
        output_key = str(scope.output_dir.resolve())
        with self._lock:
            if self._busy(output_key, kind):
                raise HTTPException(status_code=409, detail=ALREADY_RUNNING_MESSAGE)
        stored_options = spec.prepare(options, scope) if spec.prepare is not None else options.model_dump()
        with self._lock:
            if self._busy(output_key, kind):
                raise HTTPException(status_code=409, detail=ALREADY_RUNNING_MESSAGE)
            analysis_id = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"
            directory = analyses_root(scope.output_dir) / analysis_id
            directory.mkdir(parents=True, exist_ok=False)
            state: dict[str, object] = {
                "version": ANALYSIS_STATE_VERSION,
                "analysis_id": analysis_id,
                "run_id": scope.run_id,
                "kind": kind,
                "label": spec.label,
                "status": "queued",
                "options": stored_options,
                "created_at": utc_now(),
                "started_at": None,
                "finished_at": None,
                "elapsed_s": None,
                "cancel_requested_at": None,
                "progress": new_progress(spec.unit),
                "row_count": 0,
                "output_dir": str(directory),
                "rows_path": str(directory / ROWS_FILE_NAME),
                "summary": {},
                "error": None,
            }
            context = AnalysisContext(
                scope=scope, spec=spec, state=state, directory=directory, options=options, owner=owner
            )
            # Stored (normalized) options win over the raw model for runners.
            context.options = spec.options_model.model_validate(stored_options)
            key = (output_key, analysis_id)
            self._active[key] = context  # registered before the file exists: readers never see an orphan
            failure: Exception | None = None
            try:
                context.rows_path.touch()
                context.write_state()
                snapshot = context.snapshot()
                pool = self._get_pool()
            except Exception as exc:  # never leave a registration nobody will run
                failure = exc
                self._active.pop(key, None)
        if failure is None:
            try:
                pool.submit(self._execute, key, context)
            except Exception as exc:  # pool shut down concurrently, thread start failed, ...
                failure = exc
                with self._lock:
                    self._active.pop(key, None)
        if failure is not None:
            LOGGER.warning("analysis %s could not be started: %s", analysis_id, failure)
            self._finish(context, error=f"분석 실행기를 시작할 수 없습니다: {failure}")
            return context.snapshot()
        return snapshot

    def cancel(self, output_dir: Path, analysis_id: str) -> dict[str, object] | None:
        """Request cancellation; the status turns ``cancelled`` once the runner has stopped."""
        context = self._context(output_dir, analysis_id)
        if context is None:
            return self.load_state(output_dir, analysis_id)
        context.cancel_event.set()
        with context.lock:
            if context.state.get("status") in ACTIVE_STATUSES and not context.state.get("cancel_requested_at"):
                context.state["cancel_requested_at"] = utc_now()
                context._progress()["message"] = "취소 요청됨 · 현재 단위가 끝나면 멈춥니다"
            queued = context.state.get("status") == "queued"
        if queued:
            # Never started: take it off the queue and end it now (no worker to wait for).
            with self._lock:
                pool = self._pool
            dropped = pool.drop_queued(lambda args: len(args) > 1 and args[1] is context) if pool is not None else []
            if dropped:
                self._finish(context, error=None)
                with self._lock:
                    self._active.pop(self._key(output_dir, analysis_id), None)
                return context.snapshot()
        context.write_state()
        return context.snapshot()

    def shutdown(self, *, owner: object | None = None) -> None:
        """App shutdown: cancel active analyses and drop queued ones, which end ``cancelled``.

        With ``owner`` only that app's analyses are touched and the shared pool
        keeps serving other apps; without it every analysis is cancelled and the
        pool stops (it restarts lazily on the next submit).
        """
        with self._lock:
            contexts = [ctx for ctx in self._active.values() if owner is None or ctx.owner is owner]
            pool = self._pool
            if owner is None:
                self._pool = None
        for context in contexts:
            context.cancel_event.set()
        if pool is None:
            dropped: list[tuple[object, ...]] = []
        elif owner is None:
            dropped = pool.shutdown(wait=False, cancel_futures=True)
        else:
            mine = {id(ctx) for ctx in contexts}
            dropped = pool.drop_queued(lambda args: len(args) > 1 and id(args[1]) in mine)
        for args in dropped:
            key, context = args[0], args[1]
            if isinstance(context, AnalysisContext):
                self._finish(context, error=None)
                with self._lock:
                    self._active.pop(key, None)  # type: ignore[arg-type]

    def _execute(self, key: tuple[str, str], context: AnalysisContext) -> None:
        error: str | None = None
        try:
            if context.cancel_event.is_set():
                raise AnalysisCancelled()
            with context.lock:
                context.state["status"] = "running"
                context.state["started_at"] = utc_now()
            context.write_state()
            context.open_rows()
            context.spec.run(context)
        except AnalysisCancelled:
            pass
        except AnalysisFailure as exc:
            error = str(exc)
        except HTTPException as exc:
            error = str(exc.detail)
        except Exception as exc:  # a runner bug must still end in a terminal state
            LOGGER.exception("analysis %s failed", key)
            error = f"분석 중 오류가 발생했습니다: {type(exc).__name__}: {exc}"
        finally:
            context.close_rows()
            self._finish(context, error=error)
            with self._lock:
                self._active.pop(key, None)

    @staticmethod
    def _finish(context: AnalysisContext, *, error: str | None) -> None:
        with context.lock:
            context._flush_rows_locked()
            state = context.state
            now = utc_now()
            progress = context._progress()
            if context.cancel_event.is_set():
                state["status"] = "cancelled"
                progress["message"] = "취소됨"
                refresh_percent(progress)
            elif error is not None:
                state["status"] = "failed"
                state["error"] = error
                refresh_percent(progress)
            else:
                state["status"] = "completed"
                if progress.get("total") is None:
                    progress["total"] = progress.get("done") or 0
                refresh_percent(progress, finished=True)
                if not progress.get("message"):
                    progress["message"] = "완료"
            state["finished_at"] = now
            state["elapsed_s"] = elapsed_seconds(state.get("started_at"), now)
            completed = state["status"] == "completed"
        context.write_state(terminal=True)
        if completed:
            run_completion_hooks(context)


# Called (best effort) after an analysis is written ``completed``; the search
# index registers its incremental update here (``search_index_service``).
COMPLETION_HOOKS: list[Callable[[AnalysisContext], None]] = []


def run_completion_hooks(context: AnalysisContext) -> None:
    for hook in COMPLETION_HOOKS:
        try:
            hook(context)
        except Exception:  # a hook never changes the analysis outcome
            LOGGER.exception("analysis completion hook failed for %s", context.state.get("analysis_id"))


def elapsed_seconds(started_at: object, finished_at: str | None) -> float | None:
    if not started_at or not finished_at:
        return None
    try:
        start = dt.datetime.fromisoformat(str(started_at))
        end = dt.datetime.fromisoformat(finished_at)
    except ValueError:
        return None
    return round(max(0.0, (end - start).total_seconds()), 3)


ANALYSIS_RUNNER = AnalysisRunner()


def analysis_payload(output_dir: Path, analysis_id: str) -> dict[str, Any]:
    state = ANALYSIS_RUNNER.load_state(output_dir, analysis_directory(output_dir, analysis_id).name)
    if state is None:
        raise HTTPException(status_code=404, detail="분석을 찾을 수 없습니다")
    return public_state(state)



def read_analysis_rows(
    output_dir: Path, analysis_id: str, record_indices: Iterable[int]
) -> tuple[dict[str, object] | None, dict[int, dict[str, object]]]:
    """``(state, {record_index: row})`` for an analysis of this run output (one forward pass).

    Only records before the flushed ``row_count`` are read (never a line a
    running analysis is still writing). ``state`` is ``None`` when the analysis
    does not exist under ``output_dir``.
    """
    from .jsonl_records import iter_jsonl_records

    if not ANALYSIS_ID_PATTERN.fullmatch(analysis_id or ""):
        return None, {}
    state = ANALYSIS_RUNNER.load_state(output_dir, analysis_id)
    if state is None:
        return None, {}
    row_count = int(state.get("row_count") or 0)
    wanted = sorted({index for index in record_indices if 0 <= index < row_count})
    rows: dict[int, dict[str, object]] = {}
    if not wanted:
        return state, rows
    targets = set(wanted)
    try:
        for index, _offset, row, _line in iter_jsonl_records(analyses_root(output_dir) / analysis_id / ROWS_FILE_NAME, start=wanted[0]):
            if index > wanted[-1]:
                break
            if index in targets and isinstance(row, dict):
                rows[index] = row
    except OSError:
        pass
    return state, rows


def read_analysis_row(
    output_dir: Path, analysis_id: str, record_index: int
) -> tuple[dict[str, object], dict[str, object]] | None:
    """``(state, row)`` of one record of an analysis of this run output, or ``None``."""
    state, rows = read_analysis_rows(output_dir, analysis_id, [record_index])
    row = rows.get(record_index)
    return (state, row) if state is not None and row is not None else None


# --- viewer access to analysis-row sources -------------------------------------------

# Path options a runner validated with ``RunScope.resolve_input_path`` at submit
# time whose files the result rows point into (vsc-compare/extract rows for
# deleted/modified files live inside the snapshot, outside the run roots).
ANALYSIS_SOURCE_ROOT_OPTIONS = ("snapshot_root", "volatility_output_dir")
ANALYSIS_SOURCE_SCOPE = "이 분석의 입력 루트"
ROW_LOCATOR_PATTERN = re.compile(r"^/rows/(\d{1,12})$")


class AnalysisRowRef(TypedDict):
    analysis_id: str | None
    locator: str | None


def analysis_row_ref(
    analysis_id: str | None = Query(
        default=None,
        max_length=64,
        description="분석 결과 행의 원본을 열 때: 분석 id (locator와 함께). 행 자신의 경로만 그 분석의 입력 루트 안에서 열린다.",
    ),
    locator: str | None = Query(default=None, max_length=32, description="분석 결과 행 로케이터 /rows/<record_index>"),
) -> AnalysisRowRef:
    """Optional ``analysis_id`` + ``locator`` query of the source viewer routes."""
    return {"analysis_id": analysis_id.strip() if analysis_id and analysis_id.strip() else None, "locator": locator}


def _row_path_forms(row: Mapping[str, object]) -> set[str]:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    forms: set[str] = set()
    for value in (row.get("path"), details.get("source_path"), details.get("destination")):
        if isinstance(value, str) and value.strip() and os.path.isabs(value.strip()):
            forms.add(os.path.normcase(os.path.abspath(value.strip())))
    return forms


def resolve_analysis_row_source(
    store: RunJobStore,
    run_id: str,
    raw_path: str,
    *,
    analysis_id: str,
    locator: str,
    allow_directory: bool = False,
) -> Path:
    """Read-only viewer access to the file an analysis result row names.

    Only the row's own path (``path``/``details.source_path``/``details.destination``)
    is served, and only inside the analysis's validated input roots
    (``ANALYSIS_SOURCE_ROOT_OPTIONS``, re-confined to the run's input roots now)
    with the same lexical/link checks as the analysis (``confine_path`` +
    ``precheck_links``: links are never followed out). Arbitrary paths get no
    wider access.
    """
    match = ROW_LOCATOR_PATTERN.fullmatch(str(locator or "").strip())
    if match is None:
        raise HTTPException(status_code=400, detail="분석 행 로케이터는 /rows/<번호> 형식이어야 합니다")
    scope = run_scope(store, run_id, require_ready=False)
    found = read_analysis_row(scope.output_dir, analysis_id, int(match.group(1)))
    if found is None:
        raise HTTPException(status_code=404, detail="분석 결과 행을 찾을 수 없습니다")
    state, row = found
    lexical = lexical_absolute_path(raw_path, label="원본 파일")
    if os.path.normcase(lexical) not in _row_path_forms(row):
        raise HTTPException(status_code=403, detail="요청한 경로가 이 분석 결과 행의 경로가 아닙니다")
    options = state.get("options") if isinstance(state.get("options"), Mapping) else {}
    roots: list[Path] = []
    for key in ANALYSIS_SOURCE_ROOT_OPTIONS:
        value = options.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            root = scope.resolve_input_path(value, label="분석 입력 루트")
        except HTTPException:
            continue  # no longer an allowed input root: never served
        # The option as stored (lexical) and as resolved now: a row path spelled like
        # the option (a temp dir behind a symlink, a Windows 8.3 short name) is then
        # still walked by ``precheck_links`` from its own root, so a link inside it is
        # reported as a link instead of as an unrelated outside path.
        roots.extend(form for form in _root_forms([value, root, str(root)]) if form not in roots)
    if not roots:
        raise HTTPException(status_code=403, detail=f"원본 파일이 허용된 증거 루트와 {ANALYSIS_SOURCE_SCOPE} 밖에 있습니다: {lexical}")
    resolved = confine_path(lexical, roots, label="원본 파일", scope=ANALYSIS_SOURCE_SCOPE)
    if resolved.is_file() or (allow_directory and resolved.is_dir()):
        return resolved
    raise HTTPException(
        status_code=404,
        detail={"message": f"{ANALYSIS_SOURCE_SCOPE}에서 원본 파일을 찾을 수 없습니다", "path": str(resolved)},
    )


# --- scoped file picker (GET /api/browse?scope=analysis-input|analysis-output) -----------

BROWSE_SCOPES = {"analysis-input": INPUT_SCOPE, "analysis-output": OUTPUT_SCOPE}


def _browse_root_entries(roots: list[Path]) -> list[dict[str, object]]:
    """One entry per distinct existing root (lexical and resolved forms collapse)."""
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for root in roots:
        try:
            resolved = root.resolve()
            is_dir = resolved.is_dir()
            is_file = resolved.is_file()
        except (OSError, RuntimeError, ValueError):
            continue
        key = os.path.normcase(str(resolved))
        if key in seen or not (is_dir or is_file):
            continue
        seen.add(key)
        entry: dict[str, object] = {"name": str(resolved), "path": str(resolved), "kind": "directory" if is_dir else "file", "evidence_candidate": True}
        if is_file:
            try:
                entry["size_bytes"] = resolved.stat().st_size
            except OSError:
                entry["size_bytes"] = None
        entries.append(entry)
    return entries


def browse_analysis_scope(
    store: RunJobStore, *, run_id: str | None, scope_name: str, path: str | None, show_hidden: bool
) -> dict[str, object]:
    """The analysis dialog's picker: only the run's allowed input (or output) roots.

    No ``path`` lists the roots themselves; a ``path`` must lie under a root
    (``confine_path``: lexical form, links never followed out) or the answer is
    403 in Korean. ``parent`` is ``None`` at a root (the console goes back to
    the root list by browsing without ``path``).
    """
    from ...core.browse import (
        BROWSE_ENTRY_LIMIT,
        BROWSE_PROFILE_VERSION,
        BrowseError,
        browse_directory,
    )

    label = BROWSE_SCOPES.get(scope_name)
    if label is None:
        raise HTTPException(status_code=400, detail=f"알 수 없는 찾아보기 범위(scope)입니다: {scope_name} (analysis-input 또는 analysis-output)")
    if not run_id:
        raise HTTPException(status_code=400, detail="분석 찾아보기(scope)에는 run_id가 필요합니다")
    scope = run_scope(store, run_id, require_ready=False)
    roots = scope.input_roots() if scope_name == "analysis-input" else scope.output_roots()
    root_entries = _browse_root_entries(roots)
    base: dict[str, object] = {
        "profile_version": BROWSE_PROFILE_VERSION,
        "scope": scope_name,
        "scope_label": label,
        "run_id": run_id,
        "home": "",
        "separator": os.sep,
        "roots": [{"name": entry["name"], "path": entry["path"], "kind": entry["kind"]} for entry in root_entries],
        "limit": BROWSE_ENTRY_LIMIT,
    }
    root_listing = {
        **base,
        "path": "",
        "parent": None,
        "at_roots": True,
        "entries": root_entries,
        "entry_count": len(root_entries),
        "truncated": False,
        "hidden_count": 0,
    }
    if not path or not path.strip():
        return root_listing
    resolved = confine_path(path, roots, label="찾아보기", scope=label)
    directory = resolved.parent if resolved.is_file() else resolved
    if directory != resolved and not _under_any(directory, roots):
        return root_listing  # a file root (e.g. the run's disk image): its folder is not browsable
    try:
        listing = browse_directory(directory, show_hidden=show_hidden)
    except BrowseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    root_keys = {os.path.normcase(str(entry["path"])) for entry in root_entries}
    parent = listing.get("parent")
    at_root = os.path.normcase(str(listing.get("path"))) in root_keys
    if at_root or not isinstance(parent, str) or not _under_any(Path(parent), roots):
        parent = None
    return {**listing, **base, "parent": parent, "at_roots": False}
