"""File-system explorer index over the files output (plan r4 §2.2 V2).

``GET /api/runs/{id}/fs-tree`` serves one folder level of the run's scanned
files; ``GET /api/runs/{id}/files?path_prefix=&recursive=`` lists the rows of
the selected folder. Both read the same index, so a folder's counts always
equal the grid's totals for that folder.

* **Folder of a row.** ``relative_path`` (relative to the scan root, the files
  step's own field) when it is a clean relative path; else ``path`` relative to
  one of the files output's roots (``scan_scope_root``, ``root``). A row that
  is neither (absolute path outside every root, ``..`` segments) is outside the
  evidence root: it is never placed in the tree and counted in
  ``index.outside_root``. Folders group case-insensitively (NTFS semantics);
  the first spelling seen is displayed.
* **Counts.** Per scope (``candidates`` | ``inventory``): direct files and
  their size sum, and recursive totals (the folder and every subfolder).
* **Bounds.** At most ``FS_TREE_MAX_ROWS`` rows per scope and
  ``FS_TREE_MAX_DIRS`` folders are indexed; past that the index reports
  ``truncated`` with a Korean reason and unindexed rows count as outside.
* **Cache.** One index per (run, files output path, size, mtime) -- a rewritten
  files output builds a new one; ``FS_TREE_CACHE_RUNS`` runs are kept.
* **Paths.** API paths are folder paths relative to the volume root with ``/``
  separators (``""`` = root). ``..``/``.`` segments and control characters are
  a Korean 422; an absolute path is accepted only inside the run's evidence
  roots (made relative), otherwise a Korean 403.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import threading
from array import array
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

FS_TREE_MAX_ROWS = 3_000_000
FS_TREE_MAX_DIRS = 1_000_000
FS_TREE_CACHE_RUNS = 4
FS_TREE_DEFAULT_LIMIT = 200
FS_TREE_MAX_LIMIT = 1000
FS_PATH_MAX_CHARS = 4096
SCOPES = ("candidates", "inventory")
SPECIAL_IDS = ("orphan", "unallocated", "slack")
SPECIAL_LABELS = {"orphan": "고아 파일", "unallocated": "미할당 공간", "slack": "슬랙"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
OUTSIDE_ROOT_MESSAGE = "런의 증거 루트 밖 경로입니다"


def _fold(text: str) -> str:
    return text.casefold()


def _clean_parts(text: str) -> tuple[str, ...] | None:
    """Relative path segments, or ``None`` when ``..`` (escape) appears."""
    parts: list[str] = []
    for part in text.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    return tuple(parts)


def _norm_root(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return os.path.abspath(value).replace("\\", "/").rstrip("/")


def files_roots(payload: Mapping[str, object]) -> list[str]:
    roots: list[str] = []
    for key in ("scan_scope_root", "root"):
        root = _norm_root(payload.get(key))
        if root and root not in roots:
            roots.append(root)
    return roots


def _relative_to_roots(raw: str, roots: Sequence[str]) -> tuple[str, ...] | None:
    text = raw.replace("\\", "/")
    folded = _fold(text)
    for root in roots:
        prefix = _fold(root) + "/"
        if folded.startswith(prefix):
            return _clean_parts(text[len(prefix) :])
    return None


def row_parts(row: Mapping[str, object], roots: Sequence[str]) -> tuple[str, ...] | None:
    """Path segments of a files row relative to the volume root; ``None`` = outside the root."""
    relative = row.get("relative_path")
    if isinstance(relative, str) and relative.strip() and not _DRIVE.match(relative) and not relative.startswith(("/", "\\")):
        parts = _clean_parts(relative)
        if parts:
            return parts
    path = row.get("path")
    if isinstance(path, str) and path:
        parts = _relative_to_roots(os.path.abspath(path), roots)
        if parts:
            return parts
    return None


def _row_size(row: Mapping[str, object]) -> int:
    value = row.get("size")
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


@dataclass
class FsIndex:
    """Folders (ids; 0 = volume root) with per-scope direct/recursive counts and sizes."""

    key: tuple[object, ...]
    roots: list[str]
    names: list[str] = field(default_factory=lambda: [""])
    parents: array = field(default_factory=lambda: array("i", [-1]))
    children: dict[int, list[int]] = field(default_factory=dict)
    lookup: dict[tuple[int, str], int] = field(default_factory=dict)
    # [scope] -> per folder: direct count/size, recursive count/size
    direct_n: dict[str, array] = field(default_factory=dict)
    direct_size: dict[str, array] = field(default_factory=dict)
    total_n: dict[str, array] = field(default_factory=dict)
    total_size: dict[str, array] = field(default_factory=dict)
    # [scope] -> folder id per row (-1 = outside the root / not indexed)
    row_dirs: dict[str, array] = field(default_factory=dict)
    outside: dict[str, int] = field(default_factory=dict)
    row_counts: dict[str, int] = field(default_factory=dict)
    # DFS order: folder f's subtree = folders with pre[f] <= pre[x] < post[f]
    pre: array = field(default_factory=lambda: array("i"))
    post: array = field(default_factory=lambda: array("i"))
    truncated: bool = False
    truncated_reason: str | None = None

    def child(self, parent: int, name: str) -> int | None:
        return self.lookup.get((parent, _fold(name)))

    def ensure_dir(self, parent: int, name: str) -> int | None:
        key = (parent, _fold(name))
        found = self.lookup.get(key)
        if found is not None:
            return found
        if len(self.names) >= FS_TREE_MAX_DIRS:
            return None
        node = len(self.names)
        self.names.append(name)
        self.parents.append(parent)
        self.lookup[key] = node
        self.children.setdefault(parent, []).append(node)
        return node

    def path_of(self, node: int) -> str:
        parts: list[str] = []
        while node > 0:
            parts.append(self.names[node])
            node = self.parents[node]
        return "/".join(reversed(parts))

    def find(self, parts: Sequence[str]) -> int | None:
        node = 0
        for part in parts:
            found = self.child(node, part)
            if found is None:
                return None
            node = found
        return node

    def breadcrumb(self, node: int) -> list[dict[str, str]]:
        chain: list[int] = []
        while node > 0:
            chain.append(node)
            node = self.parents[node]
        return [{"name": self.names[item], "path": self.path_of(item)} for item in reversed(chain)]


def build_fs_index(key: tuple[object, ...], payload: Mapping[str, object]) -> FsIndex:
    roots = files_roots(payload)
    index = FsIndex(key=key, roots=roots)
    folder_rows: dict[str, list[tuple[int, int]]] = {}
    for scope in SCOPES:
        rows = payload.get(scope)
        rows = rows if isinstance(rows, list) else []
        dirs = array("i", [-1]) * len(rows)
        placed: list[tuple[int, int]] = []
        outside = 0
        for position, row in enumerate(rows):
            if position >= FS_TREE_MAX_ROWS:
                index.truncated = True
                index.truncated_reason = f"파일 행이 {FS_TREE_MAX_ROWS:,}개를 넘어 앞부분만 폴더 색인에 넣었습니다"
                outside += len(rows) - position
                break
            parts = row_parts(row, roots) if isinstance(row, Mapping) else None
            if not parts:
                outside += 1
                continue
            node = 0
            for part in parts[:-1]:
                next_node = index.ensure_dir(node, part)
                if next_node is None:
                    index.truncated = True
                    index.truncated_reason = f"폴더가 {FS_TREE_MAX_DIRS:,}개를 넘어 일부 폴더를 색인하지 못했습니다"
                    node = -1
                    break
                node = next_node
            if node < 0:
                outside += 1
                continue
            dirs[position] = node
            placed.append((node, _row_size(row)))
        index.row_dirs[scope] = dirs
        index.outside[scope] = outside
        index.row_counts[scope] = len(rows)
        folder_rows[scope] = placed
    count = len(index.names)
    for scope in SCOPES:
        direct_n = array("q", [0]) * count
        direct_size = array("q", [0]) * count
        for node, size in folder_rows[scope]:
            direct_n[node] += 1
            direct_size[node] += size
        total_n = array("q", direct_n)
        total_size = array("q", direct_size)
        # Children always have larger ids than their parent: fold sums bottom-up.
        for node in range(count - 1, 0, -1):
            parent = index.parents[node]
            total_n[parent] += total_n[node]
            total_size[parent] += total_size[node]
        index.direct_n[scope] = direct_n
        index.direct_size[scope] = direct_size
        index.total_n[scope] = total_n
        index.total_size[scope] = total_size
    for siblings in index.children.values():
        siblings.sort(key=lambda node: (_fold(index.names[node]), index.names[node]))
    pre = array("i", [0]) * count
    post = array("i", [0]) * count
    clock = 0
    stack: list[tuple[int, bool]] = [(0, False)]
    while stack:
        node, done = stack.pop()
        if done:
            post[node] = clock
            continue
        pre[node] = clock
        clock += 1
        stack.append((node, True))
        for child in reversed(index.children.get(node, ())):
            stack.append((child, False))
    index.pre = pre
    index.post = post
    return index


class FsIndexCache:
    """Per-run LRU of :class:`FsIndex`, single-flight per key."""

    def __init__(self, max_runs: int = FS_TREE_CACHE_RUNS) -> None:
        self.max_runs = max_runs
        self._lock = threading.Lock()
        self._build_locks: dict[tuple[object, ...], threading.Lock] = {}
        self._items: OrderedDict[tuple[object, ...], FsIndex] = OrderedDict()

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def get(self, key: tuple[object, ...], payload: Mapping[str, object]) -> FsIndex:
        with self._lock:
            found = self._items.get(key)
            if found is not None:
                self._items.move_to_end(key)
                return found
            build_lock = self._build_locks.setdefault(key, threading.Lock())
        with build_lock:
            with self._lock:
                found = self._items.get(key)
                if found is not None:
                    return found
            index = build_fs_index(key, payload)
            with self._lock:
                # One index per run: a rewritten files output replaces the old one.
                for stale in [item for item in self._items if item[0] == key[0]]:
                    self._items.pop(stale, None)
                self._items[key] = index
                while len(self._items) > self.max_runs:
                    self._items.popitem(last=False)
                self._build_locks.pop(key, None)
            return index


FS_INDEX_CACHE = FsIndexCache()


def clear_fs_index_cache() -> None:
    FS_INDEX_CACHE.clear()


def files_output_key(run_id: str, files_path: Path | None) -> tuple[object, ...]:
    try:
        stat = files_path.stat() if files_path is not None else None
    except OSError:
        stat = None
    return (run_id, str(files_path), stat.st_size if stat else -1, stat.st_mtime_ns if stat else -1)


# --- request parsing -------------------------------------------------------------------


def parse_scope(value: str | None) -> str:
    text = (value or "candidates").strip() or "candidates"
    if text not in SCOPES:
        raise HTTPException(status_code=422, detail="scope는 candidates(후보) 또는 inventory(기타 파일)여야 합니다")
    return text


def parse_limit(value: str | None, *, default: int = FS_TREE_DEFAULT_LIMIT, maximum: int = FS_TREE_MAX_LIMIT) -> int:
    if value is None or not value.strip():
        return default
    try:
        number = int(value.strip())
    except ValueError:
        raise HTTPException(status_code=422, detail=f"limit은 1~{maximum} 사이의 정수여야 합니다") from None
    if not 1 <= number <= maximum:
        raise HTTPException(status_code=422, detail=f"limit은 1~{maximum} 사이의 정수여야 합니다")
    return number


def parse_bool(value: str | None, name: str) -> bool:
    if value is None or not value.strip():
        return False
    text = value.strip().lower()
    if text in ("1", "true", "yes"):
        return True
    if text in ("0", "false", "no"):
        return False
    raise HTTPException(status_code=422, detail=f"{name} 값은 true 또는 false여야 합니다")


def encode_cursor(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    if len(text) > FS_PATH_MAX_CHARS * 2:
        raise HTTPException(status_code=422, detail="after(이어보기 커서)가 올바르지 않습니다")
    try:
        name = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        name = ""
    if not name:
        raise HTTPException(status_code=422, detail="after(이어보기 커서)가 올바르지 않습니다")
    return name


def parse_folder_path(value: str | None, roots: Sequence[str]) -> tuple[str, ...]:
    """Folder segments relative to the volume root (see module doc for the rules)."""
    text = (value or "").strip()
    if len(text) > FS_PATH_MAX_CHARS:
        raise HTTPException(status_code=422, detail=f"경로는 {FS_PATH_MAX_CHARS:,}자 이하여야 합니다")
    if _CONTROL.search(text):
        raise HTTPException(status_code=422, detail="경로에 제어 문자를 쓸 수 없습니다")
    if _DRIVE.match(text) or text.startswith(("\\\\", "//")):
        parts = _relative_to_roots(os.path.abspath(text), roots)
        if parts is None:
            if _fold(os.path.abspath(text).replace("\\", "/").rstrip("/")) in {_fold(root) for root in roots}:
                return ()
            raise HTTPException(status_code=403, detail=OUTSIDE_ROOT_MESSAGE)
        return parts
    parts = _clean_parts(text)
    if parts is None:
        raise HTTPException(status_code=422, detail="경로에 '..'(상위 폴더)를 쓸 수 없습니다")
    return parts


def require_folder(index: FsIndex, parts: Sequence[str]) -> int:
    node = index.find(parts)
    if node is None:
        raise HTTPException(status_code=404, detail="폴더를 찾을 수 없습니다: " + "/".join(parts)[:200])
    return node


# --- responses --------------------------------------------------------------------------


def scope_children(index: FsIndex, node: int, scope: str) -> list[int]:
    """Child folders holding at least one file of ``scope`` (a folder only another scope fills is hidden)."""
    totals = index.total_n[scope]
    return [child for child in index.children.get(node, ()) if totals[child] > 0]


def folder_summary(index: FsIndex, node: int, scope: str) -> dict[str, object]:
    children = scope_children(index, node, scope)
    return {
        "name": index.names[node] if node else "",
        "path": index.path_of(node),
        "direct_file_count": int(index.direct_n[scope][node]),
        "direct_size": int(index.direct_size[scope][node]),
        "file_count": int(index.total_n[scope][node]),
        "size": int(index.total_size[scope][node]),
        "folder_count": len(children),
        "has_children": bool(children),
    }


def folder_children(
    index: FsIndex, node: int, scope: str, *, limit: int, after: str | None
) -> tuple[list[dict[str, object]], str | None, int]:
    siblings = scope_children(index, node, scope)
    start = 0
    if after is not None:
        marker = (_fold(after), after)
        # Children are sorted by (casefold, name): resume behind the cursor name.
        low, high = 0, len(siblings)
        while low < high:
            middle = (low + high) // 2
            name = index.names[siblings[middle]]
            if (_fold(name), name) <= marker:
                low = middle + 1
            else:
                high = middle
        start = low
    window = siblings[start : start + limit]
    rows = [folder_summary(index, child, scope) for child in window]
    next_after = encode_cursor(index.names[window[-1]]) if window and start + limit < len(siblings) else None
    return rows, next_after, len(siblings)


def index_info(index: FsIndex, scope: str) -> dict[str, object]:
    info: dict[str, object] = {
        "rows": index.row_counts.get(scope, 0),
        "indexed": index.row_counts.get(scope, 0) - index.outside.get(scope, 0),
        "outside_root": index.outside.get(scope, 0),
        "folders": len(index.names),
        "truncated": index.truncated,
    }
    if index.truncated_reason:
        info["reason"] = index.truncated_reason
    if index.outside.get(scope):
        info["outside_root_reason"] = "증거 루트 밖이거나 상대 경로를 알 수 없는 행은 폴더 트리에 넣지 않습니다"
    return info


def files_restriction(index: FsIndex, scope: str, parts: Sequence[str], *, recursive: bool) -> list[int]:
    """Row positions of ``scope`` in the folder (direct files, or the whole subtree)."""
    folder = require_folder(index, parts)
    dirs = index.row_dirs.get(scope, array("i"))
    if not recursive:
        return [position for position, node in enumerate(dirs) if node == folder]
    low, high = index.pre[folder], index.post[folder]
    pre = index.pre
    return [position for position, node in enumerate(dirs) if node >= 0 and low <= pre[node] < high]


# --- special nodes ----------------------------------------------------------------------


def _recovery(row: Mapping[str, object]) -> Mapping[str, object]:
    value = row.get("recovery")
    return value if isinstance(value, Mapping) else {}


def special_kind(row: Mapping[str, object]) -> str | None:
    """``orphan`` | ``unallocated`` | ``slack`` for a files row, else ``None``."""
    recovery = _recovery(row)
    kind = str(recovery.get("candidate_kind") or "").lower()
    state = str(recovery.get("deletion_state") or row.get("deletion_state") or "").lower()
    markers = " ".join(
        str(value).lower()
        for value in (recovery.get("subtype"), recovery.get("source_id"), row.get("inventory_reason"))
        if value
    )
    if "slack" in markers:
        return "slack"
    if kind == "orphan-record" or "orphan" in markers:
        return "orphan"
    if kind == "carved" or state == "unallocated-candidate" or "unallocated" in markers:
        return "unallocated"
    return None


def parse_special(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    text = value.strip()
    if text not in SPECIAL_IDS:
        raise HTTPException(status_code=422, detail="special은 orphan(고아 파일)·unallocated(미할당 공간)·slack(슬랙) 중 하나여야 합니다")
    return text


def special_restriction(rows: Sequence[object], special: str) -> list[int]:
    return [position for position, row in enumerate(rows) if isinstance(row, Mapping) and special_kind(row) == special]


def special_counts(payload: Mapping[str, object]) -> dict[str, dict[str, int]]:
    counts = {special: {scope: 0 for scope in SCOPES} for special in SPECIAL_IDS}
    for scope in SCOPES:
        rows = payload.get(scope)
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, Mapping):
                kind = special_kind(row)
                if kind:
                    counts[kind][scope] += 1
    return counts


ORPHAN_STATUSES = ("partial-parent-reference-missing", "partial-parent-sequence-mismatch", "partial-parent-outside-bounded-scan")


def special_nodes(
    counts: Mapping[str, Mapping[str, int]],
    ntfs_state: Mapping[str, object] | None,
    carve_state: Mapping[str, object] | None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """``(shown, hidden)`` special nodes: files rows first, else an analysis that has them."""
    shown: list[dict[str, object]] = []
    hidden: list[dict[str, object]] = []
    for special in SPECIAL_IDS:
        per_scope = counts.get(special, {})
        total = sum(int(per_scope.get(scope, 0)) for scope in SCOPES)
        label = SPECIAL_LABELS[special]
        if total:
            shown.append(
                {
                    "id": special,
                    "label": label,
                    "count": total,
                    "counts": {scope: int(per_scope.get(scope, 0)) for scope in SCOPES},
                    "source": "files",
                    "files_query": {"special": special},
                }
            )
            continue
        if special == "orphan" and ntfs_state is not None:
            summary = ntfs_state.get("summary") if isinstance(ntfs_state.get("summary"), Mapping) else {}
            statuses = summary.get("path_status_counts") if isinstance(summary.get("path_status_counts"), Mapping) else {}
            orphans = sum(int(statuses.get(status) or 0) for status in ORPHAN_STATUSES)
            if orphans:
                shown.append(
                    {
                        "id": special,
                        "label": label,
                        "count": orphans,
                        "source": "ntfs-meta",
                        "analysis": {"analysis_id": ntfs_state.get("analysis_id"), "kind": "ntfs-meta"},
                        "note": "부모 폴더를 재구성하지 못한 MFT 레코드 수(NTFS 메타 분석 경로 상태)",
                    }
                )
                continue
        if special == "unallocated" and carve_state is not None and int(carve_state.get("row_count") or 0) > 0:
            shown.append(
                {
                    "id": special,
                    "label": label,
                    "count": int(carve_state.get("row_count") or 0),
                    "source": "carve",
                    "analysis": {"analysis_id": carve_state.get("analysis_id"), "kind": "carve"},
                    "note": "카빙 분석이 시그니처로 찾은 후보 행 수",
                }
            )
            continue
        hidden.append({"id": special, "label": label, "reason": _hidden_reason(special, ntfs_state, carve_state)})
    return shown, hidden


def _hidden_reason(special: str, ntfs_state: Mapping[str, object] | None, carve_state: Mapping[str, object] | None) -> str:
    if special == "orphan":
        if ntfs_state is None:
            return "파일 목록에 고아 레코드 행이 없고 NTFS 메타 분석도 없습니다"
        return "파일 목록과 NTFS 메타 분석에 부모를 잃은(고아) 레코드가 없습니다"
    if special == "unallocated":
        if carve_state is None:
            return "파일 목록에 미할당 영역 후보가 없고 완료된 카빙 분석도 없습니다"
        return "카빙 분석이 미할당 영역 후보를 찾지 못했습니다"
    return "파일 목록·NTFS 메타 분석에 파일 슬랙 데이터가 없습니다(처리 단계가 슬랙 영역을 행으로 만들지 않음)"
