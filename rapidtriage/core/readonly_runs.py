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
  :class:`ReadOnlyRunWriteError`, so a writer that forgot to ask cannot write either. Deleting an
  existing file or folder under it is refused the same way (the operator removes the folder outside
  the app, after removing the run from the list), and a SQLite database that already exists there is
  opened with ``PRAGMA query_only`` so no statement can change it (SQLite writes its file in C,
  where the ``open`` audit event never fires).

The registry is process-wide (the API threads, background index builders and the search-history
writer all see it) and holds canonical folder paths only. Registrations are owned: a run store holds
each read-only run's folder until the run is removed from the list or the store is closed (app
shutdown), and a folder held by several owners stays read-only until the last one releases it.
"""

from __future__ import annotations

import functools
import os
import sqlite3
import sys
import threading
from collections.abc import Hashable
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from .output_guard import canonical_path

RUN_READ_ONLY = "RUN_READ_ONLY"
RUN_READ_ONLY_MESSAGE = (
    "읽기 전용으로 연 결과입니다(결과 폴더가 증거 안에 있음). 이 결과 폴더에는 아무것도 쓰지 않습니다. "
    "결과 폴더를 증거 밖으로 옮긴 뒤 다시 가져오세요"
)

_LOCK = threading.Lock()
# canonical folder -> reason code (``OUTPUT_INSIDE_EVIDENCE``)
_READONLY: dict[str, str] = {}
# canonical folder -> owners holding it read-only (a run store holds one per run); the folder leaves
# ``_READONLY`` when its last owner releases it.
_HOLDERS: dict[str, set[Hashable]] = {}
# Owner of a registration made without one (direct calls, tests): released by an owner-less unregister.
_UNOWNED: Hashable = "unowned"
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
# Audit events that delete, with the index of their path argument: refused only when the target
# exists (a ``missing_ok`` clean-up of a file that was never written changes nothing).
_DELETE_EVENTS: dict[str, int] = {
    "os.remove": 0,  # also ``os.unlink`` / ``Path.unlink``
    "os.rmdir": 0,
    "shutil.rmtree": 0,
}
_ORIGINAL_SQLITE_CONNECT = sqlite3.connect


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
    _canonical_dir.cache_clear()


@functools.lru_cache(maxsize=4096)
def _canonical_dir(directory: str) -> str:
    return canonical_path(directory)


def _canonical(path: Path | str) -> str:
    """:func:`canonical_path` with the parent folder's resolution cached.

    ``realpath`` costs about a millisecond on Windows, and the guard asks for every write, delete and
    SQLite connection while a read-only run is open — mostly for files of a few folders. The parent
    folder is resolved in full (links, junctions, 8.3 names) and cached until
    the registry changes; the leaf is then resolved in full too, so a link or junction planted as
    the last component that points into a read-only folder is still refused (integrity over ~1 ms).
    """
    absolute = os.path.abspath(os.path.expanduser(os.fspath(path)))
    head, tail = os.path.split(absolute)
    if not tail or tail in {".", ".."} or "~" in tail or absolute.startswith("\\\\?\\"):
        return canonical_path(absolute)
    return canonical_path(os.path.join(_canonical_dir(head), tail))


def register_readonly_folder(folder: Path | str, reason: str, *, owner: Hashable = _UNOWNED) -> str:
    """Register ``folder`` read-only on behalf of ``owner``; returns the canonical folder.

    A folder stays registered while at least one owner holds it (a run store holds one per run,
    see ``RunJobStore``). Registering again with the same owner is a no-op hold (not counted twice).
    """
    canonical = canonical_path(folder)
    with _LOCK:
        _HOLDERS.setdefault(canonical, set()).add(owner)
        if _READONLY.get(canonical) != reason:
            _READONLY[canonical] = reason
            _rebuild_prefixes_locked()
    return canonical


def unregister_readonly_folder(folder: Path | str, *, owner: Hashable | None = None) -> bool:
    """Release ``owner``'s hold on ``folder``; the folder is writable again once nobody holds it.

    Without ``owner`` every hold is dropped at once (operator / test clean-up). Returns whether the
    folder left the registry."""
    canonical = canonical_path(folder)
    with _LOCK:
        holders = _HOLDERS.get(canonical)
        if holders is None:
            return False
        if owner is None:
            holders.clear()
        else:
            holders.discard(owner)
        if holders:
            return False
        del _HOLDERS[canonical]
        _READONLY.pop(canonical, None)
        _rebuild_prefixes_locked()
        return True


def readonly_holders(folder: Path | str) -> int:
    """How many owners hold ``folder`` read-only (0 when it is not registered)."""
    with _LOCK:
        return len(_HOLDERS.get(canonical_path(folder), ()))


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
        return _match(_canonical(path))
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


def _sqlite_file(text: str) -> str | None:
    """File path of a ``sqlite3.connect`` database argument (plain path or ``file:`` URI)."""
    if text == ":memory:" or not text:
        return None
    if not text.startswith("file:"):
        return text
    parts = urlsplit(text)
    path = unquote(parts.path)
    if not path or path == ":memory:" or "mode=memory" in parts.query:
        return None
    if os.name == "nt" and len(path) >= 3 and path[0] == "/" and path[2] == ":":
        path = path[1:]  # file:///C:/x -> C:/x
    return path


def _audit_sqlite_connect(args: tuple[object, ...]) -> None:
    # Creating a database file (index, history) is a write; an existing one is opened read-only by
    # :func:`_guarded_sqlite_connect`.
    text = _path_text(args[0]) if args else None
    path = _sqlite_file(text) if text else None
    if path and not os.path.exists(path):
        _refuse(path)


def _opened_read_only(text: str, uri: bool) -> bool:
    """A ``file:`` URI opened with ``mode=ro``: SQLite cannot write that file through the connection."""
    if not uri or not text.startswith("file:"):
        return False
    return parse_qs(urlsplit(text).query).get("mode", [""])[-1] == "ro"


# Authorizer actions that change a database (``CREATE TEMP …`` reports the ``temp`` database).
_SQLITE_WRITE_ACTIONS = frozenset(
    getattr(sqlite3, name)
    for name in (
        "SQLITE_INSERT", "SQLITE_UPDATE", "SQLITE_DELETE", "SQLITE_CREATE_INDEX", "SQLITE_CREATE_TABLE",
        "SQLITE_CREATE_TRIGGER", "SQLITE_CREATE_VIEW", "SQLITE_DROP_INDEX", "SQLITE_DROP_TABLE",
        "SQLITE_DROP_TRIGGER", "SQLITE_DROP_VIEW", "SQLITE_ALTER_TABLE", "SQLITE_REINDEX", "SQLITE_ANALYZE",
        "SQLITE_CREATE_VTABLE", "SQLITE_DROP_VTABLE",
    )
    if hasattr(sqlite3, name)
)


def _temp_only_writes(action: int, arg1: str | None, _arg2: str | None, database: str | None, _trigger: str | None) -> int:
    """Authorizer of a ``mode=ro`` connection to a read-only folder: writes only into ``temp``.

    ``mode=ro`` does not reach an ``ATTACH``ed file (it opens read-write), so a change to any
    database but ``temp`` is refused, and so is attaching a file of a read-only folder by a literal
    path that is not ``mode=ro`` (a bound filename is not visible to the authorizer)."""
    if action in _SQLITE_WRITE_ACTIONS:
        return sqlite3.SQLITE_OK if database == "temp" else sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_ATTACH and arg1:
        path = _sqlite_file(arg1)
        if path and not _opened_read_only(arg1, True) and readonly_reason_for(path) is not None:
            return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _guarded_sqlite_connect(database, *args, **kwargs):  # type: ignore[no-untyped-def]
    """``sqlite3.connect`` that turns on ``PRAGMA query_only`` for a database under a read-only folder.

    SQLite writes its file in C, where no ``open`` audit event fires, and the connection is not usable
    yet inside the ``sqlite3.connect/handle`` audit event, so the switch is made right after connecting:
    reads keep working, every statement that would change the database fails
    ("attempt to write a readonly database").

    A ``file:…?mode=ro`` connection (the search index reader) is left without ``query_only``: SQLite
    already opened the file read-only, and the switch would also refuse the ``TEMP`` tables a query
    builds (T-134: searching a read-only run). Its authorizer allows changes to ``temp`` only.
    """
    connection = _ORIGINAL_SQLITE_CONNECT(database, *args, **kwargs)
    if _PREFIXES:
        text = _path_text(database)
        path = _sqlite_file(text) if text else None
        if path and readonly_reason_for(path) is not None:
            if text and _opened_read_only(text, bool(kwargs.get("uri"))):  # positional ``uri``: strict path
                connection.set_authorizer(_temp_only_writes)
            else:
                connection.execute("PRAGMA query_only = ON")
    return connection


def _audit(event: str, args: tuple[object, ...]) -> None:
    if not _PREFIXES:
        return
    if event == "open":
        if len(args) >= 3 and _is_write_open(args[1], args[2]):
            _refuse(args[0])
        return
    if event == "sqlite3.connect":
        _audit_sqlite_connect(args)
        return
    delete_index = _DELETE_EVENTS.get(event)
    if delete_index is not None:
        if delete_index < len(args):
            text = _path_text(args[delete_index])
            if text and os.path.lexists(text):
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
        sqlite3.connect = _guarded_sqlite_connect  # type: ignore[assignment]
        _GUARD_INSTALLED = True


def readonly_folders() -> dict[str, str]:
    with _LOCK:
        return dict(_READONLY)
