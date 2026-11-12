"""Read-only run folders (R8 plan decision D37).

A run whose output folder is inside its evidence — a result written before the
output guard (``core/output_guard.py``) existed, then imported or restored — is opened
*read-only*: it is browsed and searched, but nothing is written into its folder any more.

Three layers keep that promise:

* :func:`may_persist` — the question every lazy writer (thumbnail cache, timeline / geo / family
  indexes, search history …) asks before writing next to a run's outputs. ``False`` means "keep
  it in memory".
* the API refuses state-changing requests for such a run (``409 RUN_READ_ONLY``, in
  ``api/app/factory.py``).
* :func:`install_write_guard` — a process audit hook (installed by the web app) that refuses any
  file creation, write, rename or copy under a registered read-only folder with
  :class:`ReadOnlyRunWriteError`, so a writer that forgot to ask cannot write either. Deletes are
  not intercepted: no lazy writer deletes, and the operator must stay able to remove the folder.

The registry is process-wide (the API threads, background index builders and the search-history
writer all see it) and holds canonical folder paths only.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

from .output_guard import canonical_path

RUN_READ_ONLY = "RUN_READ_ONLY"
RUN_READ_ONLY_MESSAGE = (
    "읽기 전용으로 연 결과입니다(결과 폴더가 증거 안에 있음). 이 결과 폴더에는 아무것도 쓰지 않습니다. "
    "결과 폴더를 증거 밖으로 옮긴 뒤 다시 가져오세요"
)

_LOCK = threading.Lock()
# canonical folder -> reason code (``OUTPUT_INSIDE_EVIDENCE``)
_READONLY: dict[str, str] = {}
_PREFIXES: tuple[tuple[str, str], ...] = ()
_GUARD_INSTALLED = False

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
# Audit events that change the file system, with the indexes of their path arguments.
_PATH_EVENTS: dict[str, tuple[int, ...]] = {
    "os.mkdir": (0,),
    "os.rename": (0, 1),
    "os.truncate": (0,),
    "os.link": (0, 1),
    "os.symlink": (0, 1),
    "shutil.copyfile": (1,),
    "shutil.copytree": (1,),
    "shutil.move": (0, 1),
    "shutil.make_archive": (0,),
}


class ReadOnlyRunWriteError(PermissionError):
    """A write into a read-only run folder was refused (HTTP 409 ``RUN_READ_ONLY``)."""

    code = RUN_READ_ONLY

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"{RUN_READ_ONLY_MESSAGE}: {path}")

    def to_detail(self) -> dict[str, str]:
        return {"code": RUN_READ_ONLY, "message": RUN_READ_ONLY_MESSAGE, "readonly_reason": self.reason}


def _rebuild_prefixes_locked() -> None:
    global _PREFIXES
    _PREFIXES = tuple((folder, reason) for folder, reason in _READONLY.items())


def register_readonly_folder(folder: Path | str, reason: str) -> None:
    with _LOCK:
        _READONLY[canonical_path(folder)] = reason
        _rebuild_prefixes_locked()


def unregister_readonly_folder(folder: Path | str) -> None:
    with _LOCK:
        if _READONLY.pop(canonical_path(folder), None) is not None:
            _rebuild_prefixes_locked()


def _match(text: str) -> str | None:
    for folder, reason in _PREFIXES:
        if text == folder or text.startswith(folder if folder.endswith(os.sep) else folder + os.sep):
            return reason
    return None


def readonly_reason_for(path: Path | str | None) -> str | None:
    """Reason code when ``path`` is (inside) a registered read-only run folder, else ``None``."""
    if path is None or not _PREFIXES:
        return None
    try:
        return _match(canonical_path(path))
    except (OSError, ValueError):
        return None


def may_persist(path: Path | str | None) -> bool:
    """Whether a lazy writer may write at / under ``path`` (``False`` for read-only run folders)."""
    return readonly_reason_for(path) is None


def _path_text(value: object) -> str | None:
    if isinstance(value, int) or value is None:
        return None
    try:
        return os.fsdecode(os.fspath(value))  # type: ignore[arg-type]
    except TypeError:
        return None


def _is_write_open(mode: object, flags: object) -> bool:
    if isinstance(mode, str):
        return any(char in mode for char in "wax+")
    return isinstance(flags, int) and bool(flags & _WRITE_FLAGS)


def _refuse(raw: object) -> None:
    text = _path_text(raw)
    if not text:
        return
    reason = readonly_reason_for(text)
    if reason is not None:
        raise ReadOnlyRunWriteError(text, reason)


def _audit(event: str, args: tuple[object, ...]) -> None:
    if not _PREFIXES:
        return
    if event == "open":
        if len(args) >= 3 and _is_write_open(args[1], args[2]):
            _refuse(args[0])
        return
    if event == "sqlite3.connect":
        # Creating a database file (index, history) is a write; opening an existing one is left to
        # the API gate (state-changing requests are refused) so reads keep working.
        text = _path_text(args[0]) if args else None
        if text and not text.startswith("file:") and text != ":memory:" and not os.path.exists(text):
            _refuse(text)
        return
    indexes = _PATH_EVENTS.get(event)
    if indexes is None:
        return
    for index in indexes:
        if index < len(args):
            _refuse(args[index])


def install_write_guard() -> None:
    """Install the process audit hook once (web app start); cheap while no folder is registered."""
    global _GUARD_INSTALLED
    with _LOCK:
        if _GUARD_INSTALLED:
            return
        sys.addaudithook(_audit)
        _GUARD_INSTALLED = True


def readonly_folders() -> dict[str, str]:
    with _LOCK:
        return dict(_READONLY)
