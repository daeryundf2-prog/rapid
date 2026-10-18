"""Registry explorer index (plan r4 §2.2 V2): hive -> key hierarchy from collected rows.

``GET /api/runs/{id}/registry-tree`` and ``/registry-values`` read one index
built from the run's ``windows-registry`` output:

* **Keys.** Every ``registry-key-tree-node`` row (``details.key_path``,
  ``name``, ``last_written_filetime``, ``value_count``, ``subkey_count``,
  ``cell_offset``) of one hive file (the row's ``path``) becomes a node; a
  parent key the collector did not emit becomes a ``synthetic`` node so the
  path stays navigable. The hive's root is its ``is_root_key`` row (mount
  path such as ``HKLM\\SYSTEM`` or ``HKU\\<SID>``).
* **Linked rows.** Other rows of ``REGISTRY_LINK_KINDS`` that name a key
  (``details.key_path`` or ``details.key``) of the same hive file are linked to
  that key (at most ``REGISTRY_LINKS_PER_KEY`` per key, ``REGISTRY_LINKS_MAX``
  in all): the console jumps from a key to those artifact rows.
* **Bounds / cache.** At most ``REGISTRY_TREE_MAX_NODES`` key rows are indexed
  (``truncated`` with a Korean reason past that). The index is cached per run
  output signature (output JSON + JSONL path, size, mtime of every scanned
  kind), single-flight, ``REGISTRY_TREE_CACHE_RUNS`` runs.
* **Values.** ``/registry-values`` reads the key's value list from the hive
  file itself through ``NativeRegistryHive`` (``cell_offset`` of the node,
  verified by name, else the root-relative path) -- only when the hive file
  resolves inside the run's evidence roots. Otherwise the answer is the
  collected value names with ``values_status = names-only`` and a reason.
"""

from __future__ import annotations

import hashlib
from array import array
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

from ...artifacts.windows.registry import (
    NativeRegistryHive,
    decode_registry_value_data,
    filetime_to_iso_ticks,
    registry_value_type_name,
)
from ...core.jobs import RunJobStore
from .index_cache import SingleFlightIndexCache
from .jsonl_records import iter_artifact_records, iter_records_at, jsonl_records_path
from .tree import _file_signature

REGISTRY_KIND = "windows-registry"
REGISTRY_LINK_KINDS = ("windows-registry", "windows-shellbags", "windows-os-account")
KEY_TREE_TYPE = "registry-key-tree-node"
REGISTRY_TREE_MAX_NODES = 600_000
REGISTRY_LINKS_PER_KEY = 50
REGISTRY_LINKS_MAX = 200_000
REGISTRY_TREE_CACHE_RUNS = 2
REGISTRY_TREE_DEFAULT_LIMIT = 200
REGISTRY_TREE_MAX_LIMIT = 1000
REGISTRY_VALUES_DEFAULT_LIMIT = 500
REGISTRY_VALUES_MAX_LIMIT = 2000
VALUE_READ_MAX_BYTES = 1024 * 1024
VALUE_HEX_PREVIEW_BYTES = 64
VALUE_TEXT_MAX_CHARS = 4000
KEY_PATH_MAX_CHARS = 2048
NO_REGISTRY_REASON = "이 런에는 레지스트리 키 트리 행(registry-key-tree-node)이 없습니다"


def hive_id(path: str) -> str:
    return hashlib.sha1(path.casefold().encode("utf-8")).hexdigest()[:12]


def _fold(text: str) -> str:
    return text.casefold()


@dataclass
class HiveInfo:
    id: str
    path: str
    root: int
    mount: str
    key_count: int = 0

    def describe(self, index: RegistryIndex) -> dict[str, object]:
        name = self.path.replace("\\", "/").rsplit("/", 1)[-1]
        return {
            "id": self.id,
            "name": name,
            "path": self.path,
            "mount": self.mount,
            "label": f"{name} ({self.mount})" if self.mount else name,
            "key_count": self.key_count,
            "root_last_written_at": filetime_to_iso_ticks(index.filetimes[self.root]) or None,
        }


@dataclass
class RegistryIndex:
    key: tuple[object, ...]
    hives: dict[str, HiveInfo] = field(default_factory=dict)
    names: list[str] = field(default_factory=list)
    parents: array = field(default_factory=lambda: array("i"))
    filetimes: array = field(default_factory=lambda: array("q"))
    value_counts: array = field(default_factory=lambda: array("i"))
    subkey_counts: array = field(default_factory=lambda: array("i"))
    cell_offsets: array = field(default_factory=lambda: array("q"))
    record_indices: array = field(default_factory=lambda: array("q"))
    children: dict[int, list[int]] = field(default_factory=dict)
    links: dict[int, list[tuple[str, int, str, str]]] = field(default_factory=dict)
    link_totals: Counter[int] = field(default_factory=Counter)
    link_types: dict[int, Counter[str]] = field(default_factory=dict)
    unresolved_links: int = 0
    outside_mount: int = 0
    truncated: bool = False
    truncated_reason: str | None = None
    node_rows: int = 0
    kinds: list[str] = field(default_factory=list)

    def add_node(self, name: str, parent: int, *, filetime: int = 0, value_count: int = -1, subkey_count: int = -1,
                 cell_offset: int = -1, record_index: int = -1) -> int:
        node = len(self.names)
        self.names.append(name)
        self.parents.append(parent)
        self.filetimes.append(filetime)
        self.value_counts.append(value_count)
        self.subkey_counts.append(subkey_count)
        self.cell_offsets.append(cell_offset)
        self.record_indices.append(record_index)
        if parent >= 0:
            self.children.setdefault(parent, []).append(node)
        return node

    def key_path(self, node: int) -> str:
        parts: list[str] = []
        while node >= 0:
            parts.append(self.names[node])
            node = self.parents[node]
        return "\\".join(reversed(parts))

    def child(self, node: int, name: str) -> int | None:
        wanted = _fold(name)
        for item in self.children.get(node, ()):
            if _fold(self.names[item]) == wanted:
                return item
        return None

    def find(self, hive: HiveInfo, key: str) -> int | None:
        """Node of ``key`` (full key path, mount included; ``""`` = the hive root)."""
        text = key.strip().strip("\\")
        if not text:
            return hive.root
        mount = hive.mount.strip("\\")
        folded = _fold(text)
        if folded == _fold(mount):
            return hive.root
        if not folded.startswith(_fold(mount) + "\\"):
            return None
        node = hive.root
        for part in text[len(mount) + 1 :].split("\\"):
            if not part:
                continue
            found = self.child(node, part)
            if found is None:
                return None
            node = found
        return node

    def relative_path(self, hive: HiveInfo, node: int) -> str:
        parts: list[str] = []
        while node >= 0 and node != hive.root:
            parts.append(self.names[node])
            node = self.parents[node]
        return "\\".join(reversed(parts))

    def breadcrumb(self, hive: HiveInfo, node: int) -> list[dict[str, str]]:
        chain: list[int] = []
        while node >= 0:
            chain.append(node)
            if node == hive.root:
                break
            node = self.parents[node]
        return [{"name": self.names[item] if item != hive.root else hive.mount, "key": self.key_path(item)} for item in reversed(chain)]


def _int(value: object, default: int = -1) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def build_registry_index(
    key: tuple[object, ...],
    sources: Sequence[tuple[str, Mapping[str, object], Path]],
) -> RegistryIndex:
    """Index over ``sources`` = ``[(kind, payload, payload_path)]`` (the registry kind first)."""
    index = RegistryIndex(key=key, kinds=[kind for kind, _payload, _path in sources])
    by_path: dict[tuple[str, str], int] = {}
    pending_links: list[tuple[str, str, str, int, str, str]] = []
    for kind, payload, payload_path in sources:
        for record_index, row in iter_artifact_records(payload, payload_path=payload_path):
            details = row.get("details")
            if not isinstance(details, Mapping):
                continue
            hive_path = str(row.get("path") or "")
            artifact_type = str(row.get("artifact_type") or "")
            if kind == REGISTRY_KIND and artifact_type == KEY_TREE_TYPE:
                key_path = str(details.get("key_path") or "").strip("\\")
                if not hive_path or not key_path:
                    continue
                index.node_rows += 1
                if len(index.names) >= REGISTRY_TREE_MAX_NODES:
                    index.truncated = True
                    index.truncated_reason = f"레지스트리 키가 {REGISTRY_TREE_MAX_NODES:,}개를 넘어 앞부분만 색인했습니다"
                    continue
                _add_key(index, by_path, hive_path, key_path, details, record_index)
                continue
            if kind == REGISTRY_KIND and artifact_type in {"registry-hive", "registry-hive-strings", "registry-summary"}:
                continue
            link_key = details.get("key_path") or details.get("key")
            if not hive_path or not isinstance(link_key, str) or not link_key.strip("\\"):
                continue
            if len(pending_links) >= REGISTRY_LINKS_MAX:
                index.unresolved_links += 1
                continue
            label = _link_label(details, artifact_type)
            pending_links.append((hive_path, link_key.strip("\\"), kind, record_index, artifact_type, label))
    for hive_path, link_key, kind, record_index, artifact_type, label in pending_links:
        node = by_path.get((_fold(hive_path), _fold(link_key)))
        if node is None:
            index.unresolved_links += 1
            continue
        index.link_totals[node] += 1
        index.link_types.setdefault(node, Counter())[artifact_type] += 1
        bucket = index.links.setdefault(node, [])
        if len(bucket) < REGISTRY_LINKS_PER_KEY:
            bucket.append((kind, record_index, artifact_type, label))
    for siblings in index.children.values():
        siblings.sort(key=lambda node: (_fold(index.names[node]), index.names[node]))
    return index


def _add_key(
    index: RegistryIndex,
    by_path: dict[tuple[str, str], int],
    hive_path: str,
    key_path: str,
    details: Mapping[str, object],
    record_index: int,
) -> None:
    folded_hive = _fold(hive_path)
    hive = index.hives.get(hive_id(hive_path))
    fields = {
        "filetime": max(0, _int(details.get("last_written_filetime"), 0)),
        "value_count": _int(details.get("value_count")),
        "subkey_count": _int(details.get("subkey_count")),
        "cell_offset": _int(details.get("cell_offset")),
        "record_index": record_index,
    }
    if hive is not None and details.get("is_root_key") is True and _fold(key_path) != _fold(hive.mount):
        # The hive's root row came after a key whose mount was guessed: re-mount.
        _remount(index, by_path, hive, key_path, fields)
        return
    existing = by_path.get((folded_hive, _fold(key_path)))
    if existing is not None:
        # A synthetic parent created earlier: fill in the collected facts.
        if index.record_indices[existing] < 0:
            index.filetimes[existing] = fields["filetime"]
            index.value_counts[existing] = fields["value_count"]
            index.subkey_counts[existing] = fields["subkey_count"]
            index.cell_offsets[existing] = fields["cell_offset"]
            index.record_indices[existing] = record_index
        return
    if hive is None:
        if details.get("is_root_key") is True:
            mount = key_path
        else:
            # A key before its hive's root row: mount = HKLM\<hive> / HKU\<sid> (filled in later).
            segments = key_path.split("\\")
            mount = "\\".join(segments[:2]) if len(segments) > 2 else segments[0]
        is_root = _fold(mount) == _fold(key_path)
        root = index.add_node(mount, -1, **(fields if is_root else {}))
        hive = HiveInfo(id=hive_id(hive_path), path=hive_path, root=root, mount=mount)
        index.hives[hive.id] = hive
        by_path[(folded_hive, _fold(mount))] = root
        hive.key_count += 1
        if is_root:
            return
    mount = hive.mount
    if not _fold(key_path).startswith(_fold(mount) + "\\"):
        index.outside_mount += 1
        return
    parts = key_path[len(mount) + 1 :].split("\\")
    parent = hive.root
    prefix = mount
    for part in parts[:-1]:
        prefix = f"{prefix}\\{part}"
        found = by_path.get((folded_hive, _fold(prefix)))
        if found is None:
            found = index.add_node(part, parent)
            by_path[(folded_hive, _fold(prefix))] = found
            hive.key_count += 1
        parent = found
    node = index.add_node(parts[-1], parent, **fields)
    by_path[(folded_hive, _fold(key_path))] = node
    hive.key_count += 1


def _subtree_size(index: RegistryIndex, node: int) -> int:
    size = 0
    stack = [node]
    while stack:
        current = stack.pop()
        size += 1
        stack.extend(index.children.get(current, ()))
    return size


def _remount(
    index: RegistryIndex,
    by_path: dict[tuple[str, str], int],
    hive: HiveInfo,
    root_path: str,
    fields: Mapping[str, int],
) -> None:
    """Make ``root_path`` (the ``is_root_key`` row) the hive root when the mount was guessed wrong.

    The guess (``HKLM\\<hive>`` from the first, non-root row) can be deeper or
    shallower than the real root. Deeper real root: its node (under the guess)
    becomes the root and the guessed ancestors drop out of the hive. Shallower
    real root: a new root node is created and the guessed root is re-attached
    beneath it. An unrelated root path counts as ``outside_mount``.
    """
    folded_hive = _fold(hive.path)
    folded_root = _fold(root_path)
    folded_mount = _fold(hive.mount)
    if folded_root.startswith(folded_mount + "\\"):
        node = by_path.get((folded_hive, folded_root))
        if node is None:
            _add_key(index, by_path, hive.path, root_path, {}, int(fields.get("record_index", -1)))
            node = by_path[(folded_hive, folded_root)]
        index.filetimes[node] = fields["filetime"]
        index.value_counts[node] = fields["value_count"]
        index.subkey_counts[node] = fields["subkey_count"]
        index.cell_offsets[node] = fields["cell_offset"]
        index.record_indices[node] = fields["record_index"]
        parent = index.parents[node]
        if parent >= 0:
            siblings = index.children.get(parent, [])
            if node in siblings:
                siblings.remove(node)
        index.parents[node] = -1
        index.names[node] = root_path
        hive.root = node
        hive.mount = root_path
        hive.key_count = _subtree_size(index, node)
        return
    if folded_mount.startswith(folded_root + "\\"):
        new_root = index.add_node(root_path, -1, **fields)
        by_path[(folded_hive, folded_root)] = new_root
        relative = hive.mount[len(root_path) + 1 :].split("\\")
        parent = new_root
        prefix = root_path
        for part in relative[:-1]:
            prefix = f"{prefix}\\{part}"
            found = by_path.get((folded_hive, _fold(prefix)))
            if found is None:
                found = index.add_node(part, parent)
                by_path[(folded_hive, _fold(prefix))] = found
            parent = found
        old_root = hive.root
        index.names[old_root] = relative[-1]
        index.parents[old_root] = parent
        index.children.setdefault(parent, []).append(old_root)
        hive.root = new_root
        hive.mount = root_path
        hive.key_count = _subtree_size(index, new_root)
        return
    index.outside_mount += 1


def _link_label(details: Mapping[str, object], artifact_type: str) -> str:
    for name in ("value_name", "activity_value", "service_name", "display_name", "user_name", "group_name", "label", "persistence_category"):
        value = details.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()[:200]
    return artifact_type


class RegistryIndexCache(SingleFlightIndexCache[RegistryIndex]):
    def __init__(self, max_runs: int = REGISTRY_TREE_CACHE_RUNS) -> None:
        super().__init__(max_runs)

    def get(self, key: tuple[object, ...], sources: Sequence[tuple[str, Mapping[str, object], Path]]) -> RegistryIndex:
        return self.get_or_build(key, lambda: build_registry_index(key, sources))


REGISTRY_INDEX_CACHE = RegistryIndexCache()


def clear_registry_index_cache() -> None:
    REGISTRY_INDEX_CACHE.clear()


def registry_sources(store: RunJobStore, run_id: str) -> list[tuple[str, Mapping[str, object], Path]]:
    sources: list[tuple[str, Mapping[str, object], Path]] = []
    for kind in REGISTRY_LINK_KINDS:
        name = f"artifacts_{kind}"
        try:
            path = store.output_path(run_id, name)
            payload = store.read_output(run_id, name)
        except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError, ValueError):
            continue
        if isinstance(payload, Mapping):
            sources.append((kind, payload, path))
    return sources


def load_registry_index(store: RunJobStore, run_id: str) -> RegistryIndex | None:
    sources = registry_sources(store, run_id)
    if not sources or sources[0][0] != REGISTRY_KIND:
        return None
    signature: list[object] = [run_id]
    for kind, payload, path in sources:
        signature.extend((kind, *_file_signature(path), *_file_signature(jsonl_records_path(payload, path))))
    index = REGISTRY_INDEX_CACHE.get(tuple(signature), sources)
    return index if index.hives else None


# --- request parsing --------------------------------------------------------------------


def require_hive(index: RegistryIndex, value: str | None) -> HiveInfo:
    text = (value or "").strip()
    if not text:
        raise HTTPException(status_code=422, detail="hive(하이브 id)를 지정하세요")
    hive = index.hives.get(text)
    if hive is None:
        raise HTTPException(status_code=404, detail="하이브를 찾을 수 없습니다: " + text[:64])
    return hive


def require_key(index: RegistryIndex, hive: HiveInfo, value: str | None) -> int:
    text = (value or "").strip()
    if len(text) > KEY_PATH_MAX_CHARS:
        raise HTTPException(status_code=422, detail=f"key(키 경로)는 {KEY_PATH_MAX_CHARS:,}자 이하여야 합니다")
    if any(ord(char) < 0x20 for char in text):
        raise HTTPException(status_code=422, detail="key(키 경로)에 제어 문자를 쓸 수 없습니다")
    node = index.find(hive, text)
    if node is None:
        raise HTTPException(status_code=404, detail="키를 찾을 수 없습니다: " + text[:200])
    return node


# --- responses ---------------------------------------------------------------------------


def key_summary(index: RegistryIndex, hive: HiveInfo, node: int) -> dict[str, object]:
    children = index.children.get(node, ())
    value_count = int(index.value_counts[node])
    subkey_count = int(index.subkey_counts[node])
    record_index = int(index.record_indices[node])
    return {
        "name": index.names[node] if node != hive.root else hive.mount,
        "key_path": index.key_path(node),
        "last_written_at": filetime_to_iso_ticks(index.filetimes[node]) or None,
        "value_count": value_count if value_count >= 0 else None,
        "subkey_count": subkey_count if subkey_count >= 0 else len(children),
        "child_count": len(children),
        "has_children": bool(children),
        "record_index": record_index if record_index >= 0 else None,
        "synthetic": record_index < 0,
        "linked_row_count": int(index.link_totals.get(node, 0)),
    }


def key_children(
    index: RegistryIndex, hive: HiveInfo, node: int, *, limit: int, after: str | None
) -> tuple[list[dict[str, object]], str | None, int]:
    from .fs_tree import encode_cursor

    siblings = index.children.get(node, [])
    start = 0
    if after is not None:
        marker = (_fold(after), after)
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
    rows = [key_summary(index, hive, child) for child in window]
    next_after = encode_cursor(index.names[window[-1]]) if window and start + limit < len(siblings) else None
    return rows, next_after, len(siblings)


def index_info(index: RegistryIndex) -> dict[str, object]:
    info: dict[str, object] = {
        "key_rows": index.node_rows,
        "keys": len(index.names),
        "hives": len(index.hives),
        "kinds": list(index.kinds),
        "linked_rows": sum(index.link_totals.values()),
        "unresolved_links": index.unresolved_links,
        "outside_mount": index.outside_mount,
        "truncated": index.truncated,
    }
    if index.truncated_reason:
        info["reason"] = index.truncated_reason
    return info


def linked_rows(index: RegistryIndex, node: int) -> dict[str, object]:
    rows = [
        {"kind": kind, "record_index": record_index, "artifact_type": artifact_type, "label": label, "locator": f"/artifacts/{record_index}"}
        for kind, record_index, artifact_type, label in index.links.get(node, ())
    ]
    return {
        "artifact_rows": rows,
        "artifact_row_total": int(index.link_totals.get(node, 0)),
        "artifact_types": dict(sorted(index.link_types.get(node, Counter()).items())),
    }


def _value_entry(hive: NativeRegistryHive, value: object) -> dict[str, object]:
    value_type = int(getattr(value, "value_type", 0) or 0)
    size = int(getattr(value, "data_size", 0) or 0)
    name = str(getattr(value, "name", "") or "")
    entry: dict[str, object] = {
        "name": name,
        "display_name": name or "(기본값)",
        "type": registry_value_type_name(value_type),
        "type_code": value_type,
        "data_size": size,
    }
    if size > VALUE_READ_MAX_BYTES:
        entry.update(data_hex=None, data_truncated=True, decoded=None, decoded_kind="too-large")
        return entry
    raw = hive.value_bytes(value)  # type: ignore[arg-type]
    entry["data_hex"] = raw[:VALUE_HEX_PREVIEW_BYTES].hex(" ")
    entry["data_truncated"] = len(raw) > VALUE_HEX_PREVIEW_BYTES
    if not raw:
        entry.update(decoded=None, decoded_kind="empty")
        return entry
    decoded = decode_registry_value_data(value_type, raw)
    if isinstance(decoded, bytes):
        entry.update(decoded=None, decoded_kind="binary")
    elif isinstance(decoded, list):
        items = [str(item)[:VALUE_TEXT_MAX_CHARS] for item in decoded[:200]]
        entry.update(decoded=items, decoded_kind="list")
    elif isinstance(decoded, int):
        entry.update(decoded=decoded, decoded_kind="number", decoded_hex=f"0x{decoded:X}")
    else:
        text = str(decoded)
        entry.update(decoded=text[:VALUE_TEXT_MAX_CHARS], decoded_kind="text", decoded_truncated=len(text) > VALUE_TEXT_MAX_CHARS)
    return entry


def read_key_values(
    index: RegistryIndex, hive_info: HiveInfo, node: int, hive_file: Path, *, limit: int
) -> tuple[list[dict[str, object]], int, str | None]:
    """``(values, value_total, problem)`` read from the hive file; ``problem`` = Korean reason when it failed."""
    hive = NativeRegistryHive.open(hive_file)
    if hive is None:
        return [], 0, "하이브 파일을 regf 형식으로 열 수 없습니다"
    with hive:
        key = None
        offset = int(index.cell_offsets[node])
        name = index.names[node]
        if offset >= 0:
            candidate = hive.key_at(offset)
            if candidate is not None and (node == hive_info.root or _fold(str(candidate.name)) == _fold(name)):
                key = candidate
        if key is None:
            key = hive.open_key(index.relative_path(hive_info, node))
        if key is None:
            return [], 0, "하이브 파일에서 이 키를 다시 찾지 못했습니다(셀 오프셋·경로 불일치)"
        values = hive.values(key)
        return [_value_entry(hive, value) for value in values[:limit]], len(values), None


def collected_value_names(
    store: RunJobStore, run_id: str, index: RegistryIndex, node: int
) -> list[str]:
    record_index = int(index.record_indices[node])
    if record_index < 0:
        return []
    sources = registry_sources(store, run_id)
    if not sources or sources[0][0] != REGISTRY_KIND:
        return []
    _kind, payload, path = sources[0]
    for _index, row in iter_records_at(payload, path, [record_index]):
        details = row.get("details")
        names = details.get("value_names") if isinstance(details, Mapping) else None
        if isinstance(names, list):
            return [str(item) for item in names]
    return []
