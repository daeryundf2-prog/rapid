"""통합 보기 tables of a run (plan axiom-adoption §3.2), read from the newest completed ``derived`` set.

Source: the newest *completed* ``derived`` analysis of the run (the run step
``analyses/run-derived-<time>`` or a manual run of the kind) whose ``summary.json``
says ``completed`` or ``partial``, by ``finished_at``. The directory comes from the
validated analysis id, never from a request or a path stored in a state file; the
table name is one of :data:`TABLES`, so a request can never name a file.

One table is indexed once per (run, analysis id, table, size, mtime) -- single-flight,
at most ``INDEX_CACHE_MAX`` tables and ``INDEX_CACHE_MAX_ROWS`` rows in all cached (the
newest table is always kept; search texts are cut to ``SEARCH_TEXT_CHARS``) -- into a :class:`TableIndex`: the fields paging
needs (normalised value, a casefolded search text, kinds, count, first/last seen), the byte
offset and length of every row's line, and one row order per sort. The index comes from the
``<table>.index.json`` sidecar the engine writes (a set without one, or with one that does
not fit its table, is indexed by reading every row); a page reads only its own rows by offset.
Pages are keyset pages: the
cursor names the analysis id, the sort and the last row's normalised value, so a cursor
from another generation or sort is refused (Korean 422) instead of skipping rows.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import threading
from array import array
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

from ...core.derived.engine import (
    INDEX_SUFFIX,
    INDEX_VERSION,
    SEARCH_TEXT_CHARS,
    SUMMARY_FILE_NAME,
    TABLE_LABELS,
    TABLES,
    search_text,
)
from ...core.derived.stage import DERIVED_ANALYSIS_KIND
from .analyses import ANALYSIS_ID_PATTERN, ANALYSIS_RUNNER, analyses_root

INDEX_CACHE_MAX = 8
# Rows over all cached table indices (each row costs a few hundred bytes: value, search text, offsets).
INDEX_CACHE_MAX_ROWS = 1_000_000
TABLE_MAX_BYTES = 512 * 1024 * 1024
SORTS = ("count", "first_seen", "last_seen")
DEFAULT_LIMIT = 100
MAX_LIMIT = 500
MAX_QUERY_CHARS = 200
MAX_VALUE_CHARS = 4096
KIND_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,95}$")
JOINABLE_STATUSES = frozenset({"completed", "partial"})
NO_SOURCE_REASON = "통합 보기 결과가 없습니다. 처리 단계에서 '통합 보기(derived)' 분석을 실행하세요."
SORT_ERROR = "sort는 count, first_seen, last_seen 중 하나여야 합니다"
LIMIT_ERROR = f"limit는 1~{MAX_LIMIT} 사이의 정수여야 합니다"
CURSOR_ERROR = "after 커서가 올바르지 않습니다. 첫 페이지부터 다시 요청하세요"
STALE_CURSOR_ERROR = "after 커서가 이 정렬·결과와 맞지 않습니다(결과가 새로 만들어졌거나 정렬이 바뀜). 첫 페이지부터 다시 요청하세요"


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def derived_sources(output_dir: Path) -> list[dict[str, object]]:
    """``{analysis_id, source, directory, generated_at, summary}`` per completed ``derived`` set, newest first."""
    found: list[dict[str, object]] = []
    root = analyses_root(Path(output_dir))
    for state in ANALYSIS_RUNNER.list_states(Path(output_dir)):
        analysis_id = str(state.get("analysis_id") or "")
        if state.get("kind") != DERIVED_ANALYSIS_KIND or state.get("status") != "completed":
            continue
        if not ANALYSIS_ID_PATTERN.fullmatch(analysis_id):
            continue
        directory = root / analysis_id
        summary = _read_json(directory / SUMMARY_FILE_NAME)
        if summary is None or summary.get("status") not in JOINABLE_STATUSES:
            continue
        options = state.get("options") if isinstance(state.get("options"), Mapping) else {}
        found.append(
            {
                "analysis_id": analysis_id,
                "source": "run-stage" if options.get("source") == "run-stage" else "analysis",
                "directory": directory,
                "generated_at": state.get("finished_at") or summary.get("generated_at"),
                "summary": summary,
            }
        )
    found.sort(key=lambda item: str(item.get("generated_at") or ""), reverse=True)
    return found


def source_info(source: Mapping[str, object]) -> dict[str, object]:
    summary = source["summary"] if isinstance(source.get("summary"), Mapping) else {}
    coverage = summary.get("coverage") if isinstance(summary.get("coverage"), Mapping) else {}
    info: dict[str, object] = {
        "status": "ready",
        "analysis_id": source.get("analysis_id"),
        "source": source.get("source"),
        "generated_at": source.get("generated_at"),
        "coverage": "partial" if summary.get("status") == "partial" else "complete",
        "catalog_version": summary.get("catalog_version"),
    }
    if summary.get("status") == "partial":
        incomplete = [str(kind) for kind in coverage.get("incomplete") or []]
        info["incomplete_sources"] = incomplete
        info["reason"] = f"통합 보기가 일부만 계산되었습니다: 끝까지 읽지 못한 소스({', '.join(incomplete) or '?'})의 나머지 행은 빠졌습니다"
    return info


def table_summaries(summary: Mapping[str, object]) -> dict[str, dict[str, object]]:
    tables = summary.get("tables") if isinstance(summary.get("tables"), Mapping) else {}
    out: dict[str, dict[str, object]] = {}
    for table in TABLES:
        entry = tables.get(table) if isinstance(tables.get(table), Mapping) else {}
        out[table] = {
            "table": table,
            "label": TABLE_LABELS[table],
            "rows": int(entry.get("rows") or 0),
            "occurrences": int(entry.get("occurrences") or 0),
            "capped": bool(entry.get("capped")),
            "cap_reason": entry.get("cap_reason"),
            "dropped_values": int(entry.get("dropped_values") or 0),
            "by_kind": dict(entry.get("by_kind") or {}) if isinstance(entry.get("by_kind"), Mapping) else {},
            "by_semantic": dict(entry.get("by_semantic") or {}) if isinstance(entry.get("by_semantic"), Mapping) else {},
        }
        if isinstance(entry.get("by_class"), Mapping):
            out[table]["by_class"] = dict(entry["by_class"])
        if isinstance(entry.get("by_class_carved"), Mapping):
            out[table]["by_class_carved"] = dict(entry["by_class_carved"])
    return out


def tree_derived_node(output_dir: Path | None) -> dict[str, object] | None:
    """The ``/tree`` ``derived`` node (통합 보기) with one child per table, or ``None`` without a set."""
    if output_dir is None:
        return None
    sources = derived_sources(Path(output_dir))
    if not sources:
        return None
    source = sources[0]
    summaries = table_summaries(source["summary"])  # type: ignore[arg-type]
    children = [
        {
            "id": f"derived:{table}",
            "label": entry["label"],
            "count": entry["rows"],
            "collection": "derived",
            "kind": table,
            "occurrences": entry["occurrences"],
            "capped": entry["capped"],
        }
        for table, entry in summaries.items()
    ]
    return {
        "id": "derived",
        "label": "통합 보기",
        "count": sum(int(child["count"]) for child in children),  # type: ignore[call-overload]
        "collection": "derived",
        "children": children,
        "source": source_info(source),
    }


# --- table index ------------------------------------------------------------------


@dataclass
class TableIndex:
    key: tuple[object, ...]
    path: Path
    normalized: list[str]
    search: list[str]
    kinds: list[frozenset[str]]
    counts: list[int]
    first: list[str | None]
    last: list[str | None]
    # Byte offset / length of each row's line in the table file (rows are read on demand).
    offsets: array = field(default_factory=lambda: array("q"))
    lengths: array = field(default_factory=lambda: array("q"))
    position: dict[str, int] = field(default_factory=dict)
    orders: dict[str, list[int]] = field(default_factory=dict)
    # sort -> row position -> place in that order (cursor resume), built on the first cursor.
    places: dict[str, dict[int, int]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __len__(self) -> int:
        return len(self.normalized)

    def rows_at(self, positions: Sequence[int]) -> list[dict[str, object]]:
        """The full rows at ``positions`` (one seek + read each, in the given order)."""
        rows: list[dict[str, object]] = []
        with self.path.open("rb") as handle:
            for position in positions:
                handle.seek(self.offsets[position])
                row = json.loads(handle.read(self.lengths[position]))
                rows.append(row if isinstance(row, dict) else {})
        return rows

    def order(self, sort: str) -> list[int]:
        with self.lock:
            cached = self.orders.get(sort)
            if cached is not None:
                return cached
            indices = range(len(self.normalized))
            if sort == "count":
                ordered = list(indices)  # the file is written count desc, normalised asc
            elif sort == "first_seen":
                ordered = sorted(indices, key=lambda i: (self.first[i] is None, self.first[i] or "", self.normalized[i]))
            else:
                # last_seen: newest first; rows without a time last; ties by normalised value.
                with_time = sorted((i for i in indices if self.last[i] is not None), key=lambda i: self.normalized[i])
                with_time.sort(key=lambda i: self.last[i] or "", reverse=True)
                ordered = with_time + sorted((i for i in indices if self.last[i] is None), key=lambda i: self.normalized[i])
            self.orders[sort] = ordered
            return ordered


def _add(index: TableIndex, normalized: str, value: object, count: object, first: object, last: object, kinds: object) -> None:
    index.normalized.append(normalized)
    index.search.append(search_text(value, normalized))
    index.kinds.append(frozenset(str(kind) for kind in kinds) if isinstance(kinds, (list, Mapping)) else frozenset())
    index.counts.append(int(count) if isinstance(count, int) and not isinstance(count, bool) else 0)
    index.first.append(str(first) if first else None)
    index.last.append(str(last) if last else None)


def _str_list(value: object, rows: int, *, optional: bool = False) -> bool:
    return isinstance(value, list) and len(value) == rows and all(
        isinstance(item, str) or (optional and item is None) for item in value
    )


def _int_list(value: object, rows: int) -> bool:
    return isinstance(value, list) and len(value) == rows and all(isinstance(item, int) and not isinstance(item, bool) for item in value)


def _from_sidecar(key: tuple[object, ...], path: Path, sidecar: Path, size: int) -> TableIndex | None:
    """The index from the columnar ``<table>.index.json``; ``None`` when it is missing or does not fit the table."""
    try:
        payload = json.loads(sidecar.read_bytes())
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("version") != INDEX_VERSION or not isinstance(payload.get("rows"), int):
        return None
    rows = int(payload["rows"])
    kind_sets = payload.get("kind_sets")
    offsets, lengths, kinds = payload.get("offsets"), payload.get("lengths"), payload.get("kinds")
    valid = (
        _str_list(payload.get("normalized"), rows)
        and _str_list(payload.get("search"), rows)
        and _str_list(payload.get("first"), rows, optional=True)
        and _str_list(payload.get("last"), rows, optional=True)
        and _int_list(payload.get("count"), rows)
        and _int_list(offsets, rows)
        and _int_list(lengths, rows)
        and _int_list(kinds, rows)
        and isinstance(kind_sets, list)
        and all(isinstance(entry, list) for entry in kind_sets)
    )
    if not valid:
        return None
    assert isinstance(offsets, list) and isinstance(lengths, list) and isinstance(kinds, list) and isinstance(kind_sets, list)
    if any(offset < 0 or length <= 0 or offset + length > size for offset, length in zip(offsets, lengths)):
        return None
    if any(not 0 <= item < len(kind_sets) for item in kinds):
        return None
    frozen = [frozenset(str(kind) for kind in entry) for entry in kind_sets]
    return TableIndex(
        key,
        path,
        payload["normalized"],
        # A sidecar of an older engine may hold uncut search texts.
        [text if len(text) <= SEARCH_TEXT_CHARS else text[:SEARCH_TEXT_CHARS] for text in payload["search"]],
        [frozen[item] for item in kinds],
        payload["count"],
        payload["first"],
        payload["last"],
        offsets=array("q", offsets),
        lengths=array("q", lengths),
    )


def build_table_index(key: tuple[object, ...], path: Path) -> TableIndex:
    """Index of one table: from its ``.index.json`` sidecar, else by reading every row (older sets)."""
    size = path.stat().st_size
    index = _from_sidecar(key, path, path.with_name(f"{path.stem}{INDEX_SUFFIX}"), size)
    if index is None:
        index = TableIndex(key, path, [], [], [], [], [], [])
        offset = 0
        with path.open("rb") as handle:
            for line in handle:
                start, offset = offset, offset + len(line)
                stripped = line.strip()
                if not stripped.startswith(b"{"):
                    continue
                try:
                    row = json.loads(stripped)
                except ValueError:
                    continue
                if not isinstance(row, dict) or not isinstance(row.get("normalized"), str):
                    continue
                _add(index, row["normalized"], row.get("value"), row.get("count"), row.get("first_seen"), row.get("last_seen"), row.get("kinds"))
                index.offsets.append(start)
                index.lengths.append(len(line))
    index.position = {value: position for position, value in enumerate(index.normalized)}
    return index


class TableIndexCache:
    """Table indices built single-flight per key; at most ``max_tables`` kept (LRU)."""

    def __init__(self, *, max_tables: int = INDEX_CACHE_MAX, max_rows: int = INDEX_CACHE_MAX_ROWS) -> None:
        self._max = max_tables
        self._max_rows = max_rows
        self._lock = threading.Lock()
        self._cache: OrderedDict[tuple[str, str], TableIndex] = OrderedDict()
        self._building: dict[tuple[object, ...], threading.Event] = {}
        self.builds = 0

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def get(self, run_key: str, analysis_id: str, table: str, path: Path) -> TableIndex:
        stat = path.stat()
        key = (run_key, analysis_id, table, stat.st_size, stat.st_mtime_ns)
        slot = (run_key, table)
        while True:
            with self._lock:
                cached = self._cache.get(slot)
                if cached is not None and cached.key == key:
                    self._cache.move_to_end(slot)
                    return cached
                waiting = self._building.get(key)
                if waiting is None:
                    done = threading.Event()
                    self._building[key] = done
                    break
            waiting.wait()
        try:
            index = build_table_index(key, path)
            with self._lock:
                self.builds += 1
                self._cache[slot] = index
                self._cache.move_to_end(slot)
                while len(self._cache) > 1 and (
                    len(self._cache) > self._max or sum(len(item) for item in self._cache.values()) > self._max_rows
                ):
                    self._cache.popitem(last=False)
            return index
        finally:
            with self._lock:
                self._building.pop(key, None)
            done.set()


TABLE_INDEX_CACHE = TableIndexCache()


def clear_derived_cache() -> None:
    TABLE_INDEX_CACHE.clear()


# --- requests -------------------------------------------------------------------------


def require_table(table: str) -> str:
    if table not in TABLES:
        raise HTTPException(status_code=404, detail=f"알 수 없는 통합 보기 표입니다: {table[:40]!r} (가능: {', '.join(TABLES)})")
    return table


def parse_limit(raw: str | None) -> int:
    text = (raw or "").strip()
    if not text:
        return DEFAULT_LIMIT
    if not text.isdigit() or len(text) > 6 or not 1 <= int(text) <= MAX_LIMIT:
        raise HTTPException(status_code=422, detail=LIMIT_ERROR)
    return int(text)


def parse_sort(raw: str | None) -> str:
    text = (raw or "").strip() or "count"
    if text not in SORTS:
        raise HTTPException(status_code=422, detail=SORT_ERROR)
    return text


def encode_cursor(analysis_id: str, sort: str, normalized: str) -> str:
    payload = json.dumps({"a": analysis_id, "s": sort, "v": normalized}, ensure_ascii=False, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(raw: str) -> dict[str, str]:
    text = raw.strip()
    if not text or len(text) > 12_000 or not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise HTTPException(status_code=422, detail=CURSOR_ERROR)
    try:
        payload = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail=CURSOR_ERROR) from exc
    if not isinstance(payload, dict) or not all(isinstance(payload.get(name), str) for name in ("a", "s", "v")):
        raise HTTPException(status_code=422, detail=CURSOR_ERROR)
    return {"a": payload["a"], "s": payload["s"], "v": payload["v"]}


@dataclass(frozen=True)
class DerivedQuery:
    q: str
    kind: str | None
    sort: str
    limit: int
    after: str | None


def parse_query(q: str | None, kind: str | None, sort: str | None, limit: str | None, after: str | None) -> DerivedQuery:
    text = (q or "").strip()
    if len(text) > MAX_QUERY_CHARS:
        raise HTTPException(status_code=422, detail=f"검색어는 {MAX_QUERY_CHARS}자까지입니다")
    kind_text = (kind or "").strip() or None
    if kind_text is not None and not KIND_PATTERN.fullmatch(kind_text):
        raise HTTPException(status_code=422, detail="kind 형식이 아닙니다 (아티팩트 kind, files:candidates, files:inventory, analysis:<id>)")
    return DerivedQuery(
        q=text.casefold(), kind=kind_text, sort=parse_sort(sort), limit=parse_limit(limit), after=(after or "").strip() or None
    )


def _list_row(row: dict[str, object]) -> dict[str, object]:
    samples = row.pop("samples", None)
    row["sample_count"] = len(samples) if isinstance(samples, list) else 0
    return row


def page_rows(
    index: TableIndex, query: DerivedQuery, *, analysis_id: str
) -> tuple[list[dict[str, object]], int, str | None]:
    """``(rows, matched, next_cursor)`` of one keyset page (``matched`` = rows passing the filters)."""
    order = index.order(query.sort)
    start = 0
    if query.after:
        cursor = decode_cursor(query.after)
        if cursor["a"] != analysis_id or cursor["s"] != query.sort or cursor["v"] not in index.position:
            raise HTTPException(status_code=422, detail=STALE_CURSOR_ERROR)
        target = index.position[cursor["v"]]
        # Position of the cursor row in this order (orders are permutations; built once per sort).
        start = _order_position(index, query.sort, order, target) + 1
    needle = query.q
    kind = query.kind

    def passes(position: int) -> bool:
        if kind is not None and kind not in index.kinds[position]:
            return False
        return not needle or needle in index.search[position]

    filtered = bool(needle or kind)
    matched = sum(1 for position in order if passes(position)) if filtered else len(order)
    picked: list[int] = []
    more = False
    for cursor_index in range(start, len(order)):
        position = order[cursor_index]
        if filtered and not passes(position):
            continue
        if len(picked) >= query.limit:
            more = True
            break
        picked.append(position)
    rows = [_list_row(row) for row in index.rows_at(picked)]
    next_cursor = encode_cursor(analysis_id, query.sort, index.normalized[picked[-1]]) if more and picked else None
    return rows, matched, next_cursor


def _order_position(index: TableIndex, sort: str, order: Sequence[int], target: int) -> int:
    if sort == "count":
        return target
    with index.lock:
        places = index.places.get(sort)
        if places is None:
            places = {row: place for place, row in enumerate(order)}
            index.places[sort] = places
    return places[target]


def locate_sample(sample: Mapping[str, object], analysis_kinds: Mapping[str, object] | None = None) -> dict[str, object]:
    """Grid address of a sample row: ``{collection, locator, kind? | scope? | analysis_id + analysis_kind?}``."""
    kind = str(sample.get("kind") or "")
    index = sample.get("record_index")
    position = int(index) if isinstance(index, int) and not isinstance(index, bool) else 0
    if kind.startswith("files:"):
        listing = kind.removeprefix("files:")
        return {"collection": "files", "scope": listing, "locator": f"/{listing}/{position}"}
    if kind.startswith("analysis:"):
        analysis_id = kind.removeprefix("analysis:")
        located: dict[str, object] = {"collection": "analysis", "analysis_id": analysis_id, "locator": f"/rows/{position}"}
        analysis_kind = (analysis_kinds or {}).get(kind)
        if isinstance(analysis_kind, str) and analysis_kind:
            located["analysis_kind"] = analysis_kind
        return located
    return {"collection": "artifacts", "kind": kind, "locator": f"/artifacts/{position}"}


def value_rows(index: TableIndex, value: str, analysis_kinds: Mapping[str, object] | None = None) -> dict[str, object]:
    position = index.position.get(value)
    if position is None:
        raise HTTPException(status_code=404, detail="이 통합 보기 표에 없는 값입니다 (정규화 값으로 요청하세요)")
    row = index.rows_at([position])[0]
    samples = row.get("samples") if isinstance(row.get("samples"), list) else []
    row["samples"] = [{**sample, **locate_sample(sample, analysis_kinds)} for sample in samples if isinstance(sample, Mapping)]
    return row
