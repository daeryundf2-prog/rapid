"""Shared helpers of the R7 AI session adapters (lane B).

Read-only rules every adapter follows:

* SQLite is opened through :func:`open_sqlite_ro` only: ``mode=ro&immutable=1`` when the
  database has no ``-wal`` sidecar; with a ``-wal`` the database + WAL are read into a private
  scratch copy that is opened instead (plain ``mode=ro`` was measured to rewrite the ``-shm``
  read-marks, and ``immutable=1`` ignores the WAL). The WAL test checks that the database,
  ``-wal`` and ``-shm`` bytes and mtimes are unchanged and that WAL-only rows are read.
* Credential files are never opened: :func:`credential_row` uses ``stat`` only.
* Every text value goes through ``redact.py`` before it lands in a row.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path

from ..redact import cap_text, redact_str
from ._iface import (
    AiAgentAdapter,
    AiLimits,
    AiRow,
    EvidenceProfile,
    Found,
    profile_account_key,
)

PARSER_VERSION = "r7-ai-b-1"
HEAD_TEXT_CHARS = 512
MAX_LIST_ITEMS = 50
MAX_WALK_FILES = 20_000

COVERAGE_LOCAL_VERIFIED = "local-verified"
COVERAGE_NOT_VALIDATED = "schema-not-validated"

_SYSTEM_PROFILES = frozenset({"public", "default", "default user", "all users", "defaultapppool", "wdagutilityaccount"})


# --- paths -----------------------------------------------------------------------------------


def profile_homes(roots: Sequence[Path]) -> list[tuple[Path, str]]:
    """``(home, account_key)`` for every user profile below the evidence roots.

    A root that is itself a home (has dot folders such as ``.claude``) counts as one profile;
    ``Users/<u>``, ``Documents and Settings/<u>`` and ``home/<u>`` children are enumerated (image
    inputs keep every profile, plan §3.2 OS rule)."""
    seen: set[str] = set()
    out: list[tuple[Path, str]] = []

    def add(home: Path, account: str) -> None:
        key = os.path.normcase(str(home))
        if key in seen or not home.is_dir():
            return
        seen.add(key)
        out.append((home, account))

    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        add(root, root.name)
        for container in ("Users", "users", "Documents and Settings", "home"):
            base = root / container
            if not base.is_dir():
                continue
            try:
                children = sorted(base.iterdir())
            except OSError:
                continue
            for child in children:
                if child.is_dir() and child.name.lower() not in _SYSTEM_PROFILES:
                    add(child, child.name)
    return out


def app_dirs(home: Path, os_hint: str = "auto") -> dict[str, list[Path]]:
    """Per-user application data folders (``roaming`` / ``local``) for ``os_hint``."""
    hint = (os_hint or "auto").lower()
    roaming: list[Path] = []
    local: list[Path] = []
    if hint in ("auto", "windows"):
        roaming.append(home / "AppData" / "Roaming")
        local.append(home / "AppData" / "Local")
    if hint in ("auto", "macos", "darwin"):
        roaming.append(home / "Library" / "Application Support")
        local.append(home / "Library" / "Application Support")
    if hint in ("auto", "linux"):
        roaming.append(home / ".config")
        local.append(home / ".local" / "share")
    return {"roaming": [p for p in roaming if p.is_dir()], "local": [p for p in local if p.is_dir()]}


def safe_stat(path: Path) -> tuple[int | None, str]:
    """``(size, mtime ISO)`` without opening the file."""
    try:
        st = path.stat()
    except OSError:
        return None, ""
    return st.st_size, iso_from_epoch(st.st_mtime)


def walk_files(root: Path, *, limit: int = MAX_WALK_FILES, pattern: str = "*") -> Iterator[Path]:
    """Files below ``root`` (no symlink following), at most ``limit``."""
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    stack.append(entry)
                    continue
            except OSError:
                continue
            if pattern != "*" and not entry.match(pattern):
                continue
            yield entry
            count += 1
            if count >= limit:
                return


# --- time ------------------------------------------------------------------------------------

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$")


def iso_from_epoch(seconds: float) -> str:
    try:
        value = dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    text = value.isoformat(timespec="milliseconds" if value.microsecond else "seconds")
    return text.replace("+00:00", "Z")


def to_iso(value: object) -> str:
    """ISO 8601 UTC text from an ISO string or an epoch in s / ms / µs (``""`` when not a time)."""
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        number = float(value)
        if number <= 0:
            return ""
        if number > 1e17:  # ns
            number /= 1e9
        elif number > 1e14:  # µs
            number /= 1e6
        elif number > 1e11:  # ms
            number /= 1e3
        return iso_from_epoch(number)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        if text.isdigit():
            return to_iso(int(text))
        if _ISO_RE.match(text):
            try:
                parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00").replace(" ", "T"))
            except ValueError:
                return ""
            if parsed.tzinfo is None:
                return parsed.isoformat()  # wall clock without zone: kept as written
            return iso_from_epoch(parsed.timestamp())
    return ""


def has_zone(text: str) -> bool:
    return text.endswith("Z") or bool(re.search(r"[+-]\d{2}:\d{2}$", text))


# --- read budget -----------------------------------------------------------------------------


class ReadBudget:
    """Bytes an adapter may read (``AiLimits.max_adapter_read_bytes``); exhaustion is recorded."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.exhausted = False
        self.skipped: list[str] = []

    def take(self, size: int, label: str = "") -> bool:
        if self.used + size > self.limit:
            self.exhausted = True
            if label and len(self.skipped) < MAX_LIST_ITEMS:
                self.skipped.append(label)
            return False
        self.used += size
        return True


def read_small_json(path: Path, budget: ReadBudget, *, max_bytes: int = 8 * 1024 * 1024) -> object:
    """Parse a JSON (or JSONC) file of at most ``max_bytes``; ``None`` when unreadable/too big."""
    size, _ = safe_stat(path)
    if size is None or size > max_bytes or not budget.take(size, str(path)):
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return json.loads(_strip_jsonc(text))
    except ValueError:
        return None


def _strip_jsonc(text: str) -> str:
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def iter_jsonl(path: Path, budget: ReadBudget, stats: dict[str, int] | None = None) -> Iterator[dict]:
    """Records of a JSONL file (bad lines and non-objects counted, never fatal)."""
    size, _ = safe_stat(path)
    if size is None or not budget.take(size, str(path)):
        if stats is not None:
            stats["files_skipped_budget"] = stats.get("files_skipped_budget", 0) + 1
        return
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                if stats is not None:
                    stats["bad_lines"] = stats.get("bad_lines", 0) + 1
                continue
            if isinstance(record, dict):
                yield record
            elif stats is not None:
                stats["non_object_lines"] = stats.get("non_object_lines", 0) + 1


def iter_text_lines(path: Path, budget: ReadBudget) -> Iterator[str]:
    size, _ = safe_stat(path)
    if size is None or not budget.take(size, str(path)):
        return
    try:
        handle = path.open("r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        for line in handle:
            yield line.rstrip("\r\n")


# --- SQLite ----------------------------------------------------------------------------------


def immutable_uri(path: Path) -> str:
    """``file:…?mode=ro&immutable=1`` for ``path`` (never writes, never reads the WAL)."""
    posix = path.resolve().as_posix()
    if not posix.startswith("/"):
        posix = "/" + posix
    quoted = posix.replace("%", "%25").replace("?", "%3F").replace("#", "%23")
    return f"file:{quoted}?mode=ro&immutable=1"


def wal_size(path: Path) -> int:
    size, _ = safe_stat(Path(str(path) + "-wal"))
    return size or 0


class _ScratchConnection(sqlite3.Connection):
    """Connection on a private scratch copy; ``close()`` removes the copy."""

    scratch_dir: str = ""

    def close(self) -> None:
        try:
            super().close()
        finally:
            if self.scratch_dir:
                shutil.rmtree(self.scratch_dir, ignore_errors=True)
                self.scratch_dir = ""


def open_sqlite_ro(path: Path, limits: AiLimits | None = None) -> tuple[sqlite3.Connection, bool]:
    """Open an evidence SQLite database without writing to it: ``(connection, wal_included)``.

    * No (or empty) ``-wal``: the original is opened ``mode=ro&immutable=1``.
    * Non-empty ``-wal``: a reader in WAL mode writes read-marks into the ``-shm`` even with
      ``mode=ro`` (measured: the ``-shm`` bytes and mtime change), and ``immutable=1`` ignores the
      WAL. So the database and its ``-wal`` (never the ``-shm``) are copied into a private scratch
      folder, the copy is opened (SQLite rebuilds the WAL index there) and the copy is deleted on
      ``close()``. The originals are only read.
    * Database + WAL over ``AiLimits.max_sqlite_bytes``: no copy; the original is opened
      ``immutable=1`` and the WAL is reported as not read (``wal_included=False``)."""
    cap = (limits or AiLimits()).max_sqlite_bytes
    wal = wal_size(path)
    size, _ = safe_stat(path)
    if wal > 0 and (size or 0) + wal <= cap:
        scratch = tempfile.mkdtemp(prefix="rt-ai-sqlite-")
        try:
            copy = Path(scratch) / "db.sqlite"
            shutil.copyfile(path, copy)
            shutil.copyfile(str(path) + "-wal", str(copy) + "-wal")
            conn = sqlite3.connect(str(copy), check_same_thread=False, factory=_ScratchConnection)
        except (OSError, sqlite3.Error):
            shutil.rmtree(scratch, ignore_errors=True)
            raise
        conn.scratch_dir = scratch
        with_wal = True
    else:
        conn = sqlite3.connect(immutable_uri(path), uri=True, check_same_thread=False)
        with_wal = False
    conn.text_factory = lambda data: data.decode("utf-8", "replace")
    conn.execute("PRAGMA query_only = ON")
    return conn, with_wal


def table_columns(conn: sqlite3.Connection) -> dict[str, list[str]]:
    tables: dict[str, list[str]] = {}
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')"):
        try:
            cols = [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{name}")')]
        except sqlite3.DatabaseError:
            cols = []
        tables[str(name)] = cols
    return tables


def select_rows(conn: sqlite3.Connection, table: str, columns: Iterable[str], available: Sequence[str], *, where: str = "", order: str = "") -> Iterator[dict[str, object]]:
    """``SELECT`` only the requested columns that exist (missing ones read as ``None``)."""
    wanted = list(columns)
    present = [c for c in wanted if c in available]
    if not present:
        return
    sql = f'SELECT {", ".join(chr(34) + c + chr(34) for c in present)} FROM "{table}"'
    if where:
        sql += f" WHERE {where}"
    if order and all(part.strip().split(" ")[0] in available for part in order.split(",")):
        sql += f" ORDER BY {order}"
    try:
        cursor = conn.execute(sql)
    except sqlite3.DatabaseError:
        return
    for values in cursor:
        row = dict.fromkeys(wanted)
        row.update(zip(present, values))
        yield row


def sqlite_over_cap(path: Path, limits: AiLimits) -> bool:
    size, _ = safe_stat(path)
    return size is not None and size > limits.max_sqlite_bytes


def is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def decode_json_value(value: object) -> object:
    """A TEXT/BLOB cell holding JSON -> parsed value (``None`` when it is not JSON)."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text[0] not in "{[":
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def content_text(content: object) -> str:
    """Text of a message ``content`` value: a string, a list of ``{text}`` blocks or one block."""
    if isinstance(content, str):
        return content
    if isinstance(content, Mapping):
        text = content.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(content, list):
        return "\n".join(str(item["text"]) for item in content if isinstance(item, Mapping) and isinstance(item.get("text"), str))
    return ""


# --- rows ------------------------------------------------------------------------------------


_OS_NAMES = frozenset({"windows", "macos", "linux"})


def iter_profiles(roots: Sequence[object], os_hint: str = "") -> list[EvidenceProfile]:
    """Lane A passes :class:`EvidenceProfile` roots; a plain path (tests, ad-hoc runs) is expanded
    with :func:`profile_homes` into one profile per user home."""
    out: list[EvidenceProfile] = []
    hint = (os_hint or "").lower()
    for root in roots:
        if isinstance(root, EvidenceProfile):
            out.append(root)
        elif isinstance(root, (str, os.PathLike)):
            for home, user in profile_homes([Path(root)]):
                out.append(EvidenceProfile(home=home, user=user, os=hint if hint in _OS_NAMES else "unknown"))
    return out


def make_found(adapter: AiAgentAdapter, profile: EvidenceProfile, path: Path, **extra: object) -> Found:
    return Found(
        adapter=adapter.name,
        tool=adapter.tool,
        path=path,
        profile=profile,
        account_key=profile_account_key(profile),
        profile_label=profile.label,
        extra=dict(extra),
    )


def profile_os(found: Found) -> str:
    return found.profile.os if found.profile is not None and found.profile.os in _OS_NAMES else "auto"


class RowContext:
    """Per-(adapter, ``Found``) row defaults and counters. Rows are lane A :class:`AiRow`; the
    type-specific fields of plan §3.3 go into ``payload``."""

    def __init__(self, adapter: AiAgentAdapter, tool_label: str, found: Found, limits: AiLimits, coverage: str = COVERAGE_LOCAL_VERIFIED) -> None:
        self.adapter = adapter.name
        self.tool = adapter.tool
        self.tool_label = tool_label
        self.account_key = found.account_key or profile_account_key(found.profile)
        self.profile_label = found.profile_label or (found.profile.label if found.profile is not None else "")
        self.user = found.profile.user if found.profile is not None else ""
        self.limits = limits
        self.coverage = coverage
        self.budget = ReadBudget(limits.max_adapter_read_bytes)
        self.unknown_record_types: dict[str, int] = {}
        self.record_type_counts: dict[str, int] = {}

    def row(
        self,
        artifact_type: str,
        path: Path | str,
        *,
        timestamp: str = "",
        kind: str = "",
        coverage: str = "",
        truncated: bool = False,
        truncated_fields: Sequence[str] = (),
        started_at: str = "",
        ended_at: str = "",
        **fields: object,
    ) -> AiRow:
        """One row. A time without a zone (log wall clock) is never the row ``timestamp`` (lane A
        labels row times UTC); it stays in ``payload.timestamp_local``."""
        stamp = timestamp or ""
        payload: dict[str, object] = {"adapter": self.adapter, "adapter_version": PARSER_VERSION}
        if stamp and not has_zone(stamp):
            payload["timestamp_local"] = stamp
            payload["timestamp_local_kind"] = kind
            stamp = ""
        payload.update(fields)
        return AiRow(
            artifact_type=artifact_type,
            tool=self.tool,
            account_key=self.account_key,
            profile_label=self.profile_label,
            path=str(path),
            timestamp=stamp,
            timestamp_kind=kind if stamp else "",
            started_at=started_at if has_zone(started_at) else "",
            ended_at=ended_at if has_zone(ended_at) else "",
            payload=payload,
            coverage_status=coverage or self.coverage,
            truncated=bool(truncated),
            truncated_fields=tuple(truncated_fields),
            tool_label=self.tool_label,
            user=self.user,
            parser=f"ai-agents/{self.adapter}",
        )

    def text(self, value: object) -> tuple[str, bool, int]:
        return cap_text(value, self.limits.max_message_bytes)

    def count_type(self, record_type: str, known: frozenset[str]) -> None:
        self.record_type_counts[record_type] = self.record_type_counts.get(record_type, 0) + 1
        if record_type not in known:
            self.unknown_record_types[record_type] = self.unknown_record_types.get(record_type, 0) + 1


def credential_row(ctx: RowContext, path: Path, kind: str, *, key_name: str = "", value_bytes: int | None = None) -> AiRow:
    """``ai-credential-presence``: path, size, mtime, kind. The file is never opened and no hash
    is taken (plan §3.2: 경로·크기·mtime·해시 없음)."""
    size, mtime = safe_stat(path) if not key_name else (value_bytes, "")
    return ctx.row(
        "ai-credential-presence",
        path,
        credential_kind=kind,
        size=size,
        file_mtime=mtime,
        key_name=key_name,
        value_collected=False,
    )


def instruction_row(ctx: RowContext, path: Path, kind: str, *, hash_file: bool = True, extra: Mapping[str, object] | None = None) -> AiRow | None:
    size, mtime = safe_stat(path)
    if size is None:
        return None
    head = ""
    if size <= 4 * 1024 * 1024 and ctx.budget.take(min(size, 64 * 1024), str(path)):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                head = handle.read(HEAD_TEXT_CHARS * 4)
        except OSError:
            head = ""
    head_text, _, _ = cap_text(head[: HEAD_TEXT_CHARS * 2], HEAD_TEXT_CHARS)
    return ctx.row(
        "ai-instruction-file",
        path,
        instruction_kind=kind,
        size=size,
        file_mtime=mtime,
        sha256=file_sha256(path) if hash_file and size <= 64 * 1024 * 1024 else "",
        head_text=head_text,
        **dict(extra or {}),
    )


def presence_row(ctx: RowContext, path: Path, presence_kind: str, **fields: object) -> AiRow:
    size, mtime = safe_stat(path)
    return ctx.row("ai-tool-presence", path, presence_kind=presence_kind, size=size, file_mtime=mtime, **fields)


def retention_row(ctx: RowContext, path: Path, *, retention_days: object = None) -> AiRow:
    """``ai-retention-cleanup`` from a cleanup marker: its content time when it holds one."""
    size, mtime = safe_stat(path)
    stamp = ""
    if size is not None and size <= 256 and ctx.budget.take(size, str(path)):
        try:
            stamp = to_iso(path.read_text(encoding="utf-8", errors="replace").strip())
        except OSError:
            stamp = ""
    return ctx.row(
        "ai-retention-cleanup",
        path,
        timestamp=stamp,
        kind="cleanup",
        cleaned_at=stamp,
        cleanup_time_source="marker-content" if stamp else "none (file mtime is a row field only)",
        file_mtime=mtime,
        retention_days=retention_days,
    )


# --- tool calls ------------------------------------------------------------------------------

SHELL_TOOLS = frozenset({"bash", "shell", "powershell", "run_terminal_cmd", "run_command", "terminal", "exec", "local_shell", "local_shell_call", "execute_command", "cmd"})
READ_TOOLS = frozenset({"read", "read_file", "view_file", "view", "cat", "notebookread", "open_file"})
WRITE_TOOLS = frozenset({"write", "write_file", "write_to_file", "create_file"})
EDIT_TOOLS = frozenset({"edit", "multiedit", "notebookedit", "edit_file", "search_replace", "replace_file_content", "multi_replace_file_content", "str_replace", "apply_patch", "patch"})
DELETE_TOOLS = frozenset({"delete_file", "remove_file"})
SEARCH_TOOLS = frozenset({"glob", "grep", "ls", "list_dir", "grep_search", "file_search", "codebase_search", "find_by_name", "search", "websearch", "web_search", "toolsearch"})
BROWSER_TOOLS = frozenset({"webfetch", "web_fetch", "read_url_content", "browser", "browser_action", "fetch"})

PATH_KEYS = ("file_path", "path", "notebook_path", "target_file", "targetfile", "absolutepath", "absolute_path", "filepath", "directorypath", "relative_workspace_path", "target_directory", "file", "filename", "searchpath", "cwd")
COMMAND_KEYS = ("command", "commandline", "cmd", "script")
PATTERN_KEYS = ("pattern", "query", "regex", "url")

_DESTRUCTIVE_RE = re.compile(
    r"(?ix)(?:^|[\s;&|(`])(?:rm\s+-[a-z]*[rf]|rm\s|rmdir\b|del\s|erase\s|rd\s+/s|remove-item\b|format(?:\.com)?\s+[a-z]:|"
    r"git\s+(?:reset\s+--hard|clean\s+-[a-z]*f|push\s+(?:-f|--force))|shred\b|cipher\s+/w|sdelete\b|diskpart\b|mkfs\b|dd\s+if=|wevtutil\s+cl|clear-eventlog\b|vssadmin\s+delete)"
)
_DELETE_VERB_RE = re.compile(r"(?i)(?:^|[\s;&|(])(?:rm|del|erase|rmdir|rd|remove-item|ri|shred|sdelete)\b")
_COPY_VERB_RE = re.compile(r"(?i)(?:^|[\s;&|(])(?:cp|copy|copy-item|xcopy|robocopy|mv|move|move-item|rsync|scp)\b")
_REDIRECT_RE = re.compile(r">>?\s*(\"[^\"]+\"|'[^']+'|[^\s;&|]+)")
_WIN_PATH_RE = re.compile(r"(?:\"([A-Za-z]:[\\/][^\"]*)\"|'([A-Za-z]:[\\/][^']*)'|(?<![\w/])([A-Za-z]:[\\/][^\s\"'|<>;&,)]*)|(\\\\[^\s\"'|<>;&,)]+))")
_POSIX_PATH_RE = re.compile(r"(?:(?<=\s)|^)((?:~|/(?:home|Users|mnt|media|Volumes|tmp|var|etc|opt|srv|data|root))/[^\s\"'|<>;&,)]*)")


def tool_kind(name: str) -> str:
    lowered = (name or "").strip().lower()
    if lowered.startswith("mcp__") or lowered.startswith("mcp_") or lowered.startswith("mcp:"):
        return "mcp"
    if lowered in SHELL_TOOLS:
        return "shell"
    if lowered in READ_TOOLS:
        return "read"
    if lowered in WRITE_TOOLS:
        return "write"
    if lowered in EDIT_TOOLS:
        return "edit"
    if lowered in DELETE_TOOLS:
        return "delete"
    if lowered in SEARCH_TOOLS:
        return "search"
    if lowered in BROWSER_TOOLS or lowered.startswith("browser"):
        return "browser"
    return "other"


def mcp_server_of(name: str) -> tuple[str, str]:
    """``mcp__server__tool`` -> ``(server, tool)``."""
    lowered = name or ""
    if lowered.startswith("mcp__"):
        parts = lowered[5:].split("__", 1)
        return parts[0], parts[1] if len(parts) > 1 else ""
    return "", ""


def _lower_keys(data: Mapping[str, object]) -> dict[str, object]:
    return {str(k).lower(): v for k, v in data.items()}


def tool_input_fields(input_value: object) -> dict[str, str]:
    """``command`` / ``target_path`` / ``pattern`` of a tool input (raw; caller redacts)."""
    if isinstance(input_value, str):
        parsed = decode_json_value(input_value)
        input_value = parsed if isinstance(parsed, dict) else {"command": input_value}
    if not isinstance(input_value, Mapping):
        return {}
    data = _lower_keys(input_value)
    out: dict[str, str] = {}
    for key in COMMAND_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            value = " ".join(str(item) for item in value)
        if isinstance(value, str) and value:
            out["command"] = value
            break
    for key in PATH_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value:
            out["target_path"] = value
            break
    for key in PATTERN_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value:
            out["pattern"] = value
            break
    return out


def command_is_destructive(command: str) -> bool:
    return bool(command) and bool(_DESTRUCTIVE_RE.search(command))


def command_paths(command: str) -> list[tuple[str, str]]:
    """``(op, path)`` pairs named in a shell command (heuristic, plan §3.2 file-touch from Bash).

    Delete verbs -> ``delete``; copy/move verbs -> last path ``write``, others ``read``; a
    redirect target -> ``write``; anything else -> ``read``."""
    if not command:
        return []
    paths: list[str] = []
    for match in _WIN_PATH_RE.finditer(command):
        value = next((g for g in match.groups() if g), "")
        if value:
            paths.append(value.rstrip(".,"))
    for match in _POSIX_PATH_RE.finditer(command):
        paths.append(match.group(1).rstrip(".,"))
    redirects = {m.group(1).strip("\"'") for m in _REDIRECT_RE.finditer(command)}
    deleting = bool(_DELETE_VERB_RE.search(command))
    copying = bool(_COPY_VERB_RE.search(command))
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, path in enumerate(paths):
        if path in seen:
            continue
        seen.add(path)
        if path in redirects:
            op = "write"
        elif deleting:
            op = "delete"
        elif copying and index == len(paths) - 1 and len(paths) > 1:
            op = "write"
        else:
            op = "read"
        out.append((op, path))
    return out[:MAX_LIST_ITEMS]


def file_op_for_kind(kind: str) -> str:
    return {"read": "read", "write": "write", "edit": "edit", "delete": "delete"}.get(kind, "")


FILE_OP_TIME_KIND = {"read": "accessed", "write": "modified", "edit": "modified", "delete": "deleted", "create": "created", "workspace": "observed"}


class SessionAccumulator:
    """Builds the rows of one session: caps (messages / tool calls), counters, time range."""

    def __init__(self, ctx: RowContext, session_id: str, path: Path | str, *, parent_session_id: str = "") -> None:
        self.ctx = ctx
        self.session_id = session_id
        self.path = path
        self.parent_session_id = parent_session_id
        self.rows: list[AiRow] = []
        self.meta: dict[str, object] = {}
        self.messages = 0
        self.tool_calls = 0
        self.file_touches = 0
        self.messages_emitted = 0
        self.tool_calls_emitted = 0
        self.messages_truncated = 0
        self.first_ts = ""
        self.last_ts = ""
        self.tokens_in = 0
        self.tokens_out = 0
        self.models: list[str] = []
        self.versions: list[str] = []
        self.pending_calls: dict[str, AiRow] = {}

    def see_time(self, stamp: str) -> None:
        if not stamp:
            return
        if not self.first_ts or stamp < self.first_ts:
            self.first_ts = stamp
        if not self.last_ts or stamp > self.last_ts:
            self.last_ts = stamp

    def note(self, values: list[str], value: object) -> None:
        if isinstance(value, str) and value and value not in values and len(values) < MAX_LIST_ITEMS:
            values.append(value)

    def message(self, role: str, stamp: str, text: object, *, source_path: Path | str | None = None, **fields: object) -> AiRow | None:
        self.messages += 1
        self.see_time(stamp)
        if self.messages > self.ctx.limits.max_messages_per_session:
            return None
        body, truncated, original = self.ctx.text(text) if self.ctx.limits.include_bodies else ("", False, len(str(text or "")))
        if truncated:
            self.messages_truncated += 1
        row = self.ctx.row(
            "ai-agent-message",
            source_path or self.path,
            timestamp=stamp,
            kind="message",
            session_id=self.session_id,
            seq=self.messages,
            role=role,
            ts=stamp,
            text=body,
            text_bytes=original,
            truncated=truncated,
            truncated_fields=("text",) if truncated else (),
            **fields,
        )
        self.messages_emitted += 1
        self.rows.append(row)
        return row

    def tool_call(self, name: str, stamp: str, input_value: object, *, call_id: str = "", source_path: Path | str | None = None, **fields: object) -> AiRow | None:
        self.tool_calls += 1
        self.see_time(stamp)
        if self.tool_calls > self.ctx.limits.max_tool_calls_per_session:
            return None
        parsed = tool_input_fields(input_value)
        kind = str(fields.pop("kind", "") or tool_kind(name))
        command_raw = parsed.get("command", "")
        command, command_truncated, _ = cap_text(command_raw, self.ctx.limits.max_message_bytes) if command_raw else ("", False, 0)
        destructive = fields.pop("destructive", None)
        destructive_source = "tool-record" if destructive is not None else ""
        if destructive is None and command_raw:
            destructive = command_is_destructive(command_raw)
            destructive_source = "command-pattern"
        server, mcp_tool = mcp_server_of(name)
        row = self.ctx.row(
            "ai-agent-tool-call",
            source_path or self.path,
            timestamp=stamp,
            kind="run",
            session_id=self.session_id,
            ts=stamp,
            tool_name=redact_str(name),
            tool_kind=kind,
            call_id=call_id,
            command=command,
            command_truncated=command_truncated,
            truncated=command_truncated,
            truncated_fields=("command",) if command_truncated else (),
            target_path=redact_str(parsed.get("target_path", "")),
            pattern=redact_str(parsed.get("pattern", ""))[:512],
            mcp_server=server,
            mcp_tool=mcp_tool,
            destructive=bool(destructive) if destructive is not None else None,
            destructive_source=destructive_source,
            **fields,
        )
        self.tool_calls_emitted += 1
        self.rows.append(row)
        if call_id:
            self.pending_calls[call_id] = row
        # file touches from the input
        op = file_op_for_kind(kind)
        if op and parsed.get("target_path"):
            self.file_touch(op, parsed["target_path"], stamp, tool_name=name, op_source="tool-input", source_path=source_path)
        if command_raw and kind == "shell":
            for cmd_op, path in command_paths(command_raw):
                self.file_touch(cmd_op, path, stamp, tool_name=name, op_source="command-heuristic", source_path=source_path)
        return row

    def tool_result(self, call_id: str, *, result_bytes: int | None = None, exit_code: object = None, is_error: object = None) -> None:
        row = self.pending_calls.get(call_id)
        if row is None:
            return
        if result_bytes is not None:
            row.payload["result_bytes"] = result_bytes
        if isinstance(exit_code, int) and not isinstance(exit_code, bool):
            row.payload["exit_code"] = exit_code
        if isinstance(is_error, bool):
            row.payload["is_error"] = is_error

    def file_touch(
        self,
        op: str,
        path: str,
        stamp: str,
        *,
        tool_name: str = "",
        op_source: str = "",
        source_path: Path | str | None = None,
        exists_in_evidence: bool | None = None,
        file_locator: str = "",
        **fields: object,
    ) -> AiRow:
        self.file_touches += 1
        row = self.ctx.row(
            "ai-agent-file-touch",
            source_path or self.path,
            timestamp=stamp,
            kind=FILE_OP_TIME_KIND.get(op, "observed"),
            session_id=self.session_id,
            ts=stamp,
            op=op,
            touched_path=redact_str(path),
            tool_name=redact_str(tool_name),
            op_source=op_source,
            exists_in_evidence=exists_in_evidence,
            file_locator=file_locator,
            **fields,
        )
        self.rows.append(row)
        return row

    def session_row(self, **fields: object) -> AiRow:
        started = str(fields.pop("started_at", "") or self.first_ts)
        ended = str(fields.pop("ended_at", "") or self.last_ts)
        capped = tuple(name for name, over in (("messages", self.messages > self.ctx.limits.max_messages_per_session), ("tool_calls", self.tool_calls > self.ctx.limits.max_tool_calls_per_session)) if over)
        row = self.ctx.row(
            "ai-agent-session",
            self.path,
            timestamp=started,
            kind="started",
            session_id=self.session_id,
            parent_session_id=self.parent_session_id,
            started_at=started,
            ended_at=ended,
            truncated=bool(capped),
            truncated_fields=capped,
            messages=self.messages,
            messages_emitted=self.messages_emitted,
            messages_capped=self.messages > self.ctx.limits.max_messages_per_session,
            messages_truncated=self.messages_truncated,
            tool_calls=self.tool_calls,
            tool_calls_emitted=self.tool_calls_emitted,
            tool_calls_capped=self.tool_calls > self.ctx.limits.max_tool_calls_per_session,
            file_touches=self.file_touches,
            tokens_in=self.tokens_in or None,
            tokens_out=self.tokens_out or None,
            models=list(self.models),
            model=self.models[0] if self.models else "",
            client_versions=list(self.versions),
            **{**self.meta, **fields},
        )
        return row

    def finish(self, **fields: object) -> list[AiRow]:
        return [self.session_row(**fields), *self.rows]


def mcp_row(ctx: RowContext, path: Path | str, server: str, *, status: str, stamp: str = "", tools: Sequence[str] = (), transport: str = "", endpoint: str = "", session_id: str = "", **fields: object) -> AiRow:
    return ctx.row(
        "ai-mcp-server",
        path,
        timestamp=stamp,
        kind="observed",
        server=redact_str(server),
        status=status,
        transport=transport,
        endpoint=redact_str(endpoint)[:512],
        tools=[redact_str(t) for t in list(tools)[:200]],
        tool_count=len(tools),
        session_id=session_id,
        ts=stamp,
        **fields,
    )


def mcp_rows_from_config(ctx: RowContext, path: Path, config: object, *, scope: str = "") -> list[AiRow]:
    """``mcpServers`` style mapping -> ``ai-mcp-server`` rows (status ``configured``). Only the
    command / URL (masked) and env variable *names* are kept."""
    rows: list[AiRow] = []
    if not isinstance(config, Mapping):
        return rows
    for name, spec in config.items():
        if not isinstance(spec, Mapping):
            continue
        data = _lower_keys(spec)
        url = data.get("url") or data.get("serverurl") or data.get("httpurl") or ""
        command = data.get("command") or ""
        args = data.get("args")
        if isinstance(args, list):
            command = " ".join([str(command), *[str(a) for a in args]]).strip()
        transport = str(data.get("type") or data.get("transport") or ("http" if url else "stdio" if command else ""))
        env = data.get("env")
        rows.append(
            mcp_row(
                ctx,
                path,
                str(name),
                status="configured",
                transport=transport,
                endpoint=str(url or command),
                remote=bool(url) and not str(url).startswith(("http://localhost", "http://127.0.0.1")),
                env_var_names=sorted(str(k) for k in env)[:MAX_LIST_ITEMS] if isinstance(env, Mapping) else [],
                config_scope=scope,
            )
        )
    return rows


_LOG_TS_RE = re.compile(r"^\s*\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]?")
_LOG_BRACKETS_RE = re.compile(r"\[([^\]\s]{1,80})\]")
_LOG_SERVER_WORD_RE = re.compile(r"(?i)\bmcp\s+server\s+[\"'`]?([A-Za-z0-9_.@/\-]{1,80})[\"'`]?")
_LOG_LEVELS = frozenset({"info", "warn", "warning", "error", "debug", "trace", "fatal", "mcp", "main", "log"})
_LOG_STATUS = (
    ("failed", re.compile(r"(?i)\b(fail(?:ed|ure)?|error|crash(?:ed)?)\b")),
    ("connected", re.compile(r"(?i)\b(connected|started|ready|initialized)\b")),
    ("disconnected", re.compile(r"(?i)\b(disconnect(?:ed)?|stopped|closed|shut ?down)\b")),
    ("needs-auth", re.compile(r"(?i)\b(needs?\s*auth|unauthori[sz]ed|401)\b")),
)


def log_line_time(line: str) -> str:
    match = _LOG_TS_RE.match(line)
    if not match:
        return ""
    return to_iso(match.group(1).replace(",", "."))


def parse_mcp_log(ctx: RowContext, path: Path) -> list[AiRow]:
    """Server names and last status from an MCP log (``[server]`` after the time/level, or
    ``MCP server "x"``). Heuristic over unvalidated formats; every line is counted, unparsed
    lines included."""
    servers: dict[str, dict[str, object]] = {}
    lines = 0
    for line in iter_text_lines(path, ctx.budget):
        lines += 1
        stamp = log_line_time(line)
        name = ""
        word = _LOG_SERVER_WORD_RE.search(line)
        if word:
            name = word.group(1)
        else:
            for candidate in _LOG_BRACKETS_RE.findall(line):
                if candidate.lower() in _LOG_LEVELS or _LOG_TS_RE.match(candidate) or candidate[:1].isdigit():
                    continue
                name = candidate
                break
        if not name:
            continue
        entry = servers.setdefault(name, {"first": "", "last": "", "status": "seen", "lines": 0})
        entry["lines"] = int(entry["lines"]) + 1  # type: ignore[call-overload]
        if stamp:
            if not entry["first"]:
                entry["first"] = stamp
            entry["last"] = stamp
        # the status words come after the server name (``[error]`` level tags do not count)
        tail = line[line.find(name) + len(name) :]
        for status, pattern in _LOG_STATUS:
            if pattern.search(tail):
                entry["status"] = status
                break
    rows = [
        mcp_row(
            ctx,
            path,
            name,
            status=str(entry["status"]),
            stamp=str(entry["first"]),
            first_seen=entry["first"],
            last_seen=entry["last"],
            log_lines=entry["lines"],
            source="mcp-log",
        )
        for name, entry in sorted(servers.items())
    ]
    return rows


def summary_row(ctx: RowContext, path: Path | str, **fields: object) -> AiRow:
    """Adapter run summary (``ai-tool-presence`` with ``presence_kind=adapter-summary``): read
    budget, unknown record types, skips."""
    return ctx.row(
        "ai-tool-presence",
        path,
        presence_kind="adapter-summary",
        read_bytes=ctx.budget.used,
        read_budget_bytes=ctx.budget.limit,
        read_budget_exhausted=ctx.budget.exhausted,
        skipped_for_budget=list(ctx.budget.skipped),
        unknown_record_types=dict(sorted(ctx.unknown_record_types.items())),
        unknown_record_count=sum(ctx.unknown_record_types.values()),
        record_type_counts=dict(sorted(ctx.record_type_counts.items())),
        **fields,
    )

