"""Located-row index of a run (plan r6 §3.3 갈래 C): every artifact row with coordinates, in one file.

``rapidtriage-geo-index.json`` in the run output folder lists ``(kind, record_index, byte offset,
lat, lon, time text, epoch seconds)`` for each row whose :func:`row_conditions.row_coordinates`
finds a coordinate pair -- one pass over every kind's ``.jsonl`` (inline payloads too), at most
:data:`GEO_INDEX_MAX_ROWS` located rows (``truncated`` beyond). The run pipeline writes it in the
``persist`` stage (:func:`write_run_geo_index`); a run without the file (older runs, a changed
output) builds it on the first map request in a background thread (:class:`GeoIndexService`, one
build per key through :class:`SingleFlightIndexCache`). An output folder that cannot be written
-- or ``RAPIDTRIAGE_INDEX_PERSIST=0`` (``index_cache.index_persist_enabled``) -- keeps the index in
memory only (``source: memory``) -- never an error.

The file's ``stamp`` lists ``(kind, file name, size, mtime_ns)`` of every kind's payload JSON and
JSONL stream; any change rebuilds the index (a stale file is ignored).

Consumers:

* ``GET /api/runs/{id}/artifacts?geo=…`` across kinds (:func:`page_located`): the box's rows come
  from the index and only those records are read (by byte offset); other filters (path, type,
  channel, field, flag, row conditions) are applied to those rows only.
* ``GET /api/runs/{id}/geo-clusters`` (:func:`build_clusters`): grid clusters (default 0.01°)
  with count, first / last time and one representative row -- the same cell rule as the
  console's ``geo.ts`` ``clusterRows`` (floor with a 1e-9 epsilon, the last cell clamped at
  90° / 180°, boxes half-open like ``row_conditions.in_geo_box``).

Rows with coordinates hold one of the exact keys ``gps_latitude`` / ``latitude`` / ``lat``
(:data:`row_conditions.COORDINATE_KEYS`), so the build parses only JSONL lines whose raw bytes
contain such a key (:data:`_COORDINATE_KEY`); a kind whose shared profiles carry one parses
every line. Stdlib only.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import math
import os
import re
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from ...core.artifact_profiles import payload_record_count
from .artifact_sort import TIME_KEYS
from .index_cache import SingleFlightIndexCache, index_persist_enabled
from .jsonl_records import (
    expand_row,
    iter_artifact_records,
    jsonl_records_path,
    parse_record_line,
    payload_profiles,
)
from .row_conditions import in_geo_box, parse_moment, row_coordinates

LOGGER = logging.getLogger(__name__)

GEO_INDEX_FILE_NAME = "rapidtriage-geo-index.json"
GEO_INDEX_FORMAT = "rapidtriage-geo-index-v1"
# Located rows kept per run; a run with more is ``truncated`` and the listing falls back to the scan.
GEO_INDEX_MAX_ROWS = 500_000
# Seconds a request waits for a background build before answering ``building``.
GEO_INDEX_WAIT_SECONDS = 1.0
GEO_INDEX_CACHE_RUNS = 8
DEFAULT_CELL_DEGREES = 0.01
MIN_CELL_DEGREES = 0.001
MAX_CELL_DEGREES = 1.0
# Clusters returned per request (most rows first); ``clusters_truncated`` beyond.
MAX_CLUSTERS = 10_000
# Candidate rows read per cluster / page request when other filters need the full records.
FILTER_READ_CAP = 200_000

# Any of the coordinate keys as a JSON object key (``"gps_latitude"``, ``"latitude"``, ``"lat"``).
_COORDINATE_KEY = re.compile(rb'"(?:gps_)?lat(?:itude)?"')

# (kind, payload, payload path) of one artifacts output.
Source = tuple[str, Mapping[str, object], Path]


@dataclass(frozen=True)
class GeoEntry:
    record_index: int
    offset: int  # byte offset of the JSONL line; -1 for inline payloads
    lat: float
    lon: float
    time: str | None
    epoch: float | None


@dataclass
class GeoIndex:
    stamp: tuple[tuple[object, ...], ...]
    kinds: tuple[str, ...]
    by_kind: dict[str, list[GeoEntry]]
    truncated: bool = False
    scanned: int = 0
    source: str = "built"  # file | built | memory
    elapsed_seconds: float = 0.0
    located: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self.located = sum(len(rows) for rows in self.by_kind.values())


# --- stamp / row values ------------------------------------------------------------------------


def _file_stamp(path: Path | None) -> tuple[object, ...]:
    if path is None:
        return ("", -1, -1)
    try:
        stat = path.stat()
    except OSError:
        return (path.name, -1, -1)
    return (path.name, stat.st_size, stat.st_mtime_ns)


def sources_stamp(sources: Sequence[Source]) -> tuple[tuple[object, ...], ...]:
    """``(kind, payload name/size/mtime, records name/size/mtime)`` per kind, kind order."""
    stamp: list[tuple[object, ...]] = []
    for kind, payload, payload_path in sorted(sources, key=lambda item: item[0]):
        records = jsonl_records_path(payload, payload_path)
        stamp.append((kind, *_file_stamp(Path(payload_path)), *_file_stamp(records)))
    return tuple(stamp)


def row_geo_time(row: Mapping[str, object]) -> tuple[str | None, float | None]:
    """The GPS time of a row (``gps_timestamp``, ``exif_gps_profile.gps_datetime_utc_candidate``),
    else its row time (first parseable ``details`` time key) -- like ``geo.ts`` ``rowGeoTime``.
    Returns the text the console shows and its epoch seconds (``None`` when there is none)."""
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    gps = details.get("exif_gps_profile") if isinstance(details.get("exif_gps_profile"), Mapping) else {}
    candidates: list[object] = [details.get("gps_timestamp"), gps.get("gps_datetime_utc_candidate")]
    candidates.extend(details.get(key) for key in TIME_KEYS)
    for value in candidates:
        if value is None or isinstance(value, (bool, Mapping, list)):
            continue
        if isinstance(value, str) and not value.strip():
            continue
        moment = parse_moment(value)
        if moment is None:
            continue
        try:
            epoch = moment.timestamp()
        except (OverflowError, ValueError, OSError):
            epoch = None
        return (value if isinstance(value, str) else moment.isoformat()), epoch
    return None, None


def _entry(record_index: int, offset: int, row: Mapping[str, object]) -> GeoEntry | None:
    point = row_coordinates(row)
    if point is None:
        return None
    text, epoch = row_geo_time(row)
    return GeoEntry(record_index, offset, point[0], point[1], text, epoch)


def _profiles_have_coordinates(profiles: Mapping[str, object] | None) -> bool:
    if not profiles:
        return False
    try:
        blob = json.dumps(profiles, ensure_ascii=True, default=str).encode("ascii")
    except (TypeError, ValueError):
        return True
    return _COORDINATE_KEY.search(blob) is not None


def _scan_kind(payload: Mapping[str, object], payload_path: Path, budget: int) -> tuple[list[GeoEntry], int, bool]:
    """Located rows of one kind (record order), rows scanned, and whether ``budget`` cut it short."""
    records_path = jsonl_records_path(payload, payload_path)
    profiles = payload_profiles(payload)
    if records_path is None:
        found: list[GeoEntry] = []
        scanned = 0
        for record_index, row in iter_artifact_records(payload, payload_path=payload_path):
            scanned += 1
            entry = _entry(record_index, -1, row)
            if entry is not None:
                if len(found) >= budget:
                    return found, scanned, True
                found.append(entry)
        return found, scanned, False
    return _scan_jsonl(records_path, profiles, budget, prefilter=not _profiles_have_coordinates(profiles))


# Bytes read per block by the JSONL scan.
SCAN_BLOCK_BYTES = 8 << 20
# Raw-bytes probes of :data:`_COORDINATE_KEY` (``"lat"``, ``"latitude"``, ``"gps_lat…"``): a block
# holding neither cannot hold a located row.
_KEY_PROBES = (b'"lat', b'"gps_lat')


def _blocks(handle: BinaryIO) -> Iterator[bytes]:
    """The file in blocks of whole lines (the last one may lack its newline)."""
    tail = b""
    while True:
        block = handle.read(SCAN_BLOCK_BYTES)
        if not block:
            if tail:
                yield tail
            return
        data = tail + block if tail else block
        cut = data.rfind(b"\n") + 1
        if cut == 0:
            tail = data
            continue
        tail = data[cut:]
        yield data[:cut] if tail else data


def _scan_jsonl(
    records_path: Path, profiles: Mapping[str, object] | None, budget: int, *, prefilter: bool
) -> tuple[list[GeoEntry], int, bool]:
    """:func:`_scan_kind` over a JSONL stream, block by block (R6 S3 real-run fix).

    Records are the ``{``-lines (as in ``jsonl_records.iter_jsonl_records``). With ``prefilter``
    a block without any coordinate key is only counted; in a block where every line is a record
    only the lines holding a key are parsed (found by one regex pass over the block). Otherwise
    the block goes line by line. The per-line regex over every line cost ~2 s for the 294k long
    event-log lines of a real run."""
    found: list[GeoEntry] = []
    index = 0  # record index of the block's first record
    lines_before = 0  # lines before the block (1-based line numbers for warnings)
    base = 0  # byte offset of the block

    def take(record_index: int, offset: int, line_number: int, line: bytes) -> bool:
        row = parse_record_line(line, path=records_path, line_number=line_number)
        if row is None:
            return False
        entry = _entry(record_index, offset, expand_row(row, profiles))
        if entry is None:
            return False
        if len(found) >= budget:
            return True
        found.append(entry)
        return False

    with open(records_path, "rb") as handle:
        for block in _blocks(handle):
            lines = block.count(b"\n") + (0 if block.endswith(b"\n") else 1)
            uniform = block.count(b"\n{") + (1 if block.startswith(b"{") else 0) == lines
            if prefilter and uniform:
                # Every line is a record: record index = line index; parse the key lines only.
                if any(probe in block for probe in _KEY_PROBES):
                    counted, counted_at, last_start = 0, 0, -1
                    for match in _COORDINATE_KEY.finditer(block):
                        start = block.rfind(b"\n", 0, match.start()) + 1
                        if start == last_start:
                            continue
                        last_start = start
                        counted += block.count(b"\n", counted_at, start)
                        counted_at = start
                        end = block.find(b"\n", start)
                        line = block[start : len(block) if end < 0 else end].strip()
                        if take(index + counted, base + start, lines_before + counted + 1, line):
                            return found, index + counted + 1, True
                index += lines
            else:
                position = 0
                for number, line in enumerate(block.split(b"\n")[:lines], start=lines_before + 1):
                    offset = base + position
                    position += len(line) + 1
                    stripped = line.strip()
                    if not stripped.startswith(b"{"):
                        continue
                    record_index = index
                    index += 1
                    if prefilter and _COORDINATE_KEY.search(stripped) is None:
                        continue
                    if take(record_index, offset, number, stripped):
                        return found, index, True
            lines_before += lines
            base += len(block)
    return found, index, False


def scan_geo_index(sources: Sequence[Source], *, max_rows: int | None = None) -> GeoIndex:
    """Build the index with one pass over every kind (kind order: alphabetical)."""
    max_rows = GEO_INDEX_MAX_ROWS if max_rows is None else max_rows
    started = time.perf_counter()
    by_kind: dict[str, list[GeoEntry]] = {}
    scanned = 0
    truncated = False
    ordered = sorted(sources, key=lambda item: item[0])
    for kind, payload, payload_path in ordered:
        if truncated:
            break
        rows, kind_scanned, cut = _scan_kind(payload, Path(payload_path), max_rows - sum(len(v) for v in by_kind.values()))
        scanned += kind_scanned
        if rows:
            by_kind[kind] = rows
        truncated = cut
    return GeoIndex(
        stamp=sources_stamp(sources),
        kinds=tuple(kind for kind, _payload, _path in ordered),
        by_kind=by_kind,
        truncated=truncated,
        scanned=scanned,
        elapsed_seconds=round(time.perf_counter() - started, 3),
    )


# --- file ---------------------------------------------------------------------------------------


def _jsonable_stamp(stamp: tuple[tuple[object, ...], ...]) -> list[list[object]]:
    return [list(item) for item in stamp]


def write_geo_index_file(index: GeoIndex, output_dir: Path) -> Path:
    """Atomically write ``rapidtriage-geo-index.json`` (``OSError`` when the folder is read-only)."""
    kinds = list(index.kinds)
    position = {kind: number for number, kind in enumerate(kinds)}
    rows = [
        [position[kind], entry.record_index, entry.offset, entry.lat, entry.lon, entry.time, entry.epoch]
        for kind in kinds
        for entry in index.by_kind.get(kind, ())
    ]
    document = {
        "format": GEO_INDEX_FORMAT,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "stamp": _jsonable_stamp(index.stamp),
        "kinds": kinds,
        "max_rows": GEO_INDEX_MAX_ROWS,
        "truncated": index.truncated,
        "scanned": index.scanned,
        "located": len(rows),
        "columns": ["kind", "record_index", "offset", "lat", "lon", "time", "epoch"],
        "rows": rows,
    }
    target = Path(output_dir) / GEO_INDEX_FILE_NAME
    temp = target.with_name(f"{target.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with open(temp, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(temp, target)
    except OSError:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return target


def read_geo_index_file(output_dir: Path, stamp: tuple[tuple[object, ...], ...]) -> GeoIndex | None:
    """The stored index when its stamp matches ``stamp`` (``None``: missing, unreadable or stale)."""
    path = Path(output_dir) / GEO_INDEX_FILE_NAME
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(document, dict) or document.get("format") != GEO_INDEX_FORMAT:
        return None
    if document.get("stamp") != _jsonable_stamp(stamp):
        return None
    kinds = document.get("kinds")
    rows = document.get("rows")
    if not isinstance(kinds, list) or not isinstance(rows, list):
        return None
    by_kind: dict[str, list[GeoEntry]] = {}
    try:
        for item in rows:
            kind = str(kinds[int(item[0])])
            by_kind.setdefault(kind, []).append(
                GeoEntry(
                    int(item[1]),
                    int(item[2]),
                    float(item[3]),
                    float(item[4]),
                    None if item[5] is None else str(item[5]),
                    None if item[6] is None else float(item[6]),
                )
            )
    except (IndexError, TypeError, ValueError):
        return None
    return GeoIndex(
        stamp=stamp,
        kinds=tuple(str(kind) for kind in kinds),
        by_kind=by_kind,
        truncated=bool(document.get("truncated")),
        scanned=int(document.get("scanned") or 0),
        source="file",
    )


def load_or_build(sources: Sequence[Source], output_dir: Path | None) -> GeoIndex:
    """The stored index when current, else a new one (written next to the outputs when possible)."""
    stamp = sources_stamp(sources)
    if output_dir is not None:
        stored = read_geo_index_file(output_dir, stamp)
        if stored is not None:
            return stored
    index = scan_geo_index(sources)
    if output_dir is None or not index_persist_enabled():
        index.source = "memory"
        return index
    try:
        write_geo_index_file(index, output_dir)
    except OSError as exc:
        LOGGER.info("geo index kept in memory (output folder not writable): %s", exc)
        index.source = "memory"
    return index


def write_run_geo_index(output_dir: Path, sources: Sequence[Source]) -> dict[str, object]:
    """Run-completion step (``persist``): build and store the index. Never raises."""
    started = time.perf_counter()
    try:
        index = scan_geo_index(sources)
        path = write_geo_index_file(index, output_dir)
    except Exception as exc:  # the run stays usable: the API builds the index on demand
        return {
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    return {
        "status": "completed",
        "path": str(path),
        "located": index.located,
        "scanned": index.scanned,
        "truncated": index.truncated,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
    }


# --- per-run service ---------------------------------------------------------------------------


class _GeoCache(SingleFlightIndexCache[GeoIndex]):
    def peek(self, key: tuple[object, ...]) -> GeoIndex | None:
        with self._lock:
            found = self._items.get(key)
            if found is not None:
                self._items.move_to_end(key)
            return found


class GeoIndexService:
    """Per-run indexes: ready from the cache, else built in a background thread (``building``)."""

    def __init__(self, max_runs: int = GEO_INDEX_CACHE_RUNS) -> None:
        self.cache = _GeoCache(max_runs)
        self._lock = threading.Lock()
        self._threads: dict[tuple[object, ...], threading.Thread] = {}
        self._failed: dict[tuple[object, ...], str] = {}

    def clear(self) -> None:
        self.cache.clear()
        with self._lock:
            self._failed.clear()

    def lookup(
        self,
        run_id: str,
        sources: Sequence[Source],
        output_dir: Path | None,
        *,
        wait: float | None = None,
    ) -> tuple[GeoIndex | None, str]:
        """``(index, "ready")``, ``(None, "building")`` or ``(None, "unavailable")`` (the build failed)."""
        key = (run_id, sources_stamp(sources))
        found = self.cache.peek(key)
        if found is not None:
            return found, "ready"
        with self._lock:
            if key in self._failed:
                return None, "unavailable"
            thread = self._threads.get(key)
            if thread is None:
                thread = threading.Thread(
                    target=self._build, args=(key, list(sources), output_dir), name="rapidtriage-geo-index", daemon=True
                )
                self._threads[key] = thread
                thread.start()
        thread.join(GEO_INDEX_WAIT_SECONDS if wait is None else max(0.0, wait))
        found = self.cache.peek(key)
        if found is not None:
            return found, "ready"
        with self._lock:
            return None, "unavailable" if key in self._failed else "building"

    def _build(self, key: tuple[object, ...], sources: list[Source], output_dir: Path | None) -> None:
        try:
            self.cache.get_or_build(key, lambda: load_or_build(sources, output_dir))
        except Exception as exc:  # reported as ``unavailable``; the listing falls back to the scan
            LOGGER.warning("geo index build failed for run %s: %s", key[0], exc)
            with self._lock:
                if len(self._failed) > 64:
                    self._failed.clear()
                self._failed[key] = f"{type(exc).__name__}: {exc}"
        finally:
            with self._lock:
                self._threads.pop(key, None)


GEO_INDEX_SERVICE = GeoIndexService()


# --- reading candidate rows --------------------------------------------------------------------


def read_entries(
    payload: Mapping[str, object], payload_path: Path, entries: Sequence[GeoEntry]
) -> Iterator[tuple[GeoEntry, dict[str, object]]]:
    """``(entry, expanded row)`` for ``entries`` (one seek per row; a line that no longer parses is skipped)."""
    if not entries:
        return
    profiles = payload_profiles(payload)
    records_path = jsonl_records_path(payload, payload_path)
    if records_path is None:
        inline = payload.get("artifacts")
        inline = inline if isinstance(inline, list) else []
        for entry in entries:
            if 0 <= entry.record_index < len(inline) and isinstance(inline[entry.record_index], dict):
                yield entry, expand_row(inline[entry.record_index], profiles)
        return
    with open(records_path, "rb") as handle:
        for entry in entries:
            if entry.offset < 0:
                continue
            handle.seek(entry.offset)
            stripped = handle.readline().strip()
            if not stripped.startswith(b"{"):
                continue
            row = parse_record_line(stripped, path=records_path, line_number=0)
            if row is not None:
                yield entry, expand_row(row, profiles)


def candidates(
    index: GeoIndex,
    kinds: Sequence[str],
    box: tuple[float, float, float, float] | None,
    allowed_for: Callable[[str], set[int]] | None = None,
) -> list[tuple[str, GeoEntry]]:
    """Index rows of ``kinds`` (in that order, record order inside a kind) inside ``box``."""
    out: list[tuple[str, GeoEntry]] = []
    for kind in kinds:
        allowed = allowed_for(kind) if allowed_for is not None else None
        for entry in index.by_kind.get(kind, ()):
            if box is not None and not in_geo_box((entry.lat, entry.lon), box):
                continue
            if allowed is not None and entry.record_index not in allowed:
                continue
            out.append((kind, entry))
    return out


def _iter_rows(
    items: Sequence[tuple[str, GeoEntry]], sources: Mapping[str, tuple[Mapping[str, object], Path]], batch: int = 256
) -> Iterator[tuple[str, GeoEntry, dict[str, object]]]:
    """Rows of ``items`` in their order, read in batches per kind."""
    start = 0
    while start < len(items):
        kind = items[start][0]
        end = start
        while end < len(items) and end - start < batch and items[end][0] == kind:
            end += 1
        payload, payload_path = sources[kind]
        for entry, row in read_entries(payload, payload_path, [entry for _kind, entry in items[start:end]]):
            yield kind, entry, row
        start = end


def page_located(
    index: GeoIndex,
    sources: Sequence[Source],
    *,
    box: tuple[float, float, float, float],
    offset: int,
    limit: int,
    after: tuple[str, int, int] | None,
    matches: Callable[[Mapping[str, object]], bool] | None,
    allowed_for: Callable[[str], set[int]] | None,
    describe: Mapping[str, object],
) -> dict[str, object]:
    """``/artifacts?geo=…`` across kinds from the index: same response as
    ``artifact_filter.filter_across_kinds`` (rows in kind order, then record order) plus
    ``cross_kind.geo_index = true`` and ``located_total`` (located rows of the kinds, any box).

    ``matches`` (path / type / channel / field / row conditions) runs on the box's rows only;
    without it the page is read straight from the index and ``matched`` is the box's row count."""
    kinds = [kind for kind, _payload, _path in sources]
    by_name = {kind: (payload, Path(path)) for kind, payload, path in sources}
    items = candidates(index, kinds, box, allowed_for)
    start_pos, skip_until = 0, offset
    if after is not None:
        if after[0] not in kinds:
            raise ValueError(f"after 값이 이 요청에 없는 종류를 가리킵니다: {after[0]}")
        anchor = (kinds.index(after[0]), after[1])
        position = {kind: number for number, kind in enumerate(kinds)}
        start_pos = next(
            (number for number, (kind, entry) in enumerate(items) if (position[kind], entry.record_index) > anchor),
            len(items),
        )
        skip_until = after[2]
    base = skip_until
    rows_by_kind: dict[str, list[object]] = {kind: [] for kind in kinds}
    order: list[list[object]] = []
    has_more = False
    scanned = 0
    last: tuple[str, int] | None = None
    if matches is None:
        # The index alone answers: the box's rows are the matches, so ``matched`` is exact.
        window_start = start_pos if after is not None else min(offset, len(items))
        window = items[window_start : window_start + limit]
        for kind, entry, row in _iter_rows(window, by_name):
            rows_by_kind[kind].append({**row, "record_index": entry.record_index})
            order.append([kind, entry.record_index])
        scanned = len(window)
        has_more = window_start + len(window) < len(items)
        exhausted = not has_more
        if window:
            last = (window[-1][0], window[-1][1].record_index)
        matched = base + (len(items) - start_pos) if after is not None else len(items)
        cursor_matched = base + len(window)
    else:
        matched = skip_until if after is not None else 0
        exhausted = True
        capped = items[start_pos : start_pos + FILTER_READ_CAP]
        for kind, entry, row in _iter_rows(capped, by_name):
            scanned += 1
            if matches(row):
                if len(order) >= limit:
                    has_more, exhausted = True, False
                    break
                if matched >= skip_until:
                    rows_by_kind[kind].append({**row, "record_index": entry.record_index})
                    order.append([kind, entry.record_index])
                matched += 1
            last = (kind, entry.record_index)
        if exhausted and start_pos + len(capped) < len(items):
            exhausted = False  # read cap: continue behind ``last``
        cursor_matched = matched
    truncated = not exhausted and not has_more
    next_after = f"{last[0]}:{last[1]}:{cursor_matched}" if not exhausted and last is not None else None
    record_count = sum(payload_record_count(payload) for _kind, payload, _path in sources)
    return {
        "artifacts": {
            kind: {"artifacts": rows_by_kind[kind], "record_count": payload_record_count(payload)}
            for kind, payload, _path in sources
        },
        "cross_kind": {
            "collection": "artifacts",
            "kinds": kinds,
            "offset": base,
            "limit": limit,
            "returned": len(order),
            "order": order,
            "record_count": record_count,
            "matched": matched if exhausted or matches is None else None,
            "has_more": has_more or not exhausted,
            "next_offset": base + len(order) if not exhausted else None,
            "next_after": next_after,
            "scanned": scanned,
            "truncated": truncated,
            **dict(describe),
            "geo_index": True,
            "located_total": sum(len(index.by_kind.get(kind, ())) for kind in kinds),
        },
    }


# --- clusters ------------------------------------------------------------------------------------


def parse_cell(raw: str | float | None) -> float:
    """``cell`` degrees (default 0.01); Korean ``ValueError`` outside 0.001-1."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return DEFAULT_CELL_DEGREES
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError("cell 값은 격자 크기(도)를 나타내는 숫자여야 합니다 — 예: 0.01") from None
    if not math.isfinite(value) or not MIN_CELL_DEGREES <= value <= MAX_CELL_DEGREES:
        raise ValueError(f"cell 값은 {MIN_CELL_DEGREES}~{MAX_CELL_DEGREES}도 사이여야 합니다 — 예: 0.01")
    return value


def _js_round6(value: float) -> float:
    """``Math.round(value * 1e6) / 1e6`` of the console."""
    return math.floor(value * 1e6 + 0.5) / 1e6


def _number_text(value: float) -> str:
    """A number as JavaScript prints it (``37``, ``37.48``, ``-0.01``)."""
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def cell_of(value: float, limit: float, cell: float) -> int:
    """Grid cell index (``geo.ts`` ``cell``): floor with a 1e-9 epsilon, clamped to the last cell."""
    last = round(limit / cell) - 1
    return max(-last - 1, min(last, math.floor(value / cell + 1e-9)))


def build_clusters(
    rows: Sequence[tuple[str, GeoEntry]], cell: float, *, max_clusters: int = MAX_CLUSTERS
) -> tuple[list[dict[str, object]], int]:
    """Grid clusters of located rows (most rows first, then id) and the total cluster count."""
    groups: dict[tuple[int, int], dict[str, object]] = {}
    for kind, entry in rows:
        lat_cell, lon_cell = cell_of(entry.lat, 90, cell), cell_of(entry.lon, 180, cell)
        group = groups.get((lat_cell, lon_cell))
        if group is None:
            group = groups[(lat_cell, lon_cell)] = {
                "count": 0,
                "first": None,
                "last": None,
                "sample": (kind, entry),
            }
        group["count"] = int(group["count"]) + 1  # type: ignore[call-overload]
        if entry.epoch is not None:
            first, last = group["first"], group["last"]
            if first is None or entry.epoch < first.epoch:  # type: ignore[attr-defined]
                group["first"] = entry
            if last is None or entry.epoch > last.epoch:  # type: ignore[attr-defined]
                group["last"] = entry
    out: list[dict[str, object]] = []
    for (lat_cell, lon_cell), group in groups.items():
        lat0, lon0 = _js_round6(lat_cell * cell), _js_round6(lon_cell * cell)
        lat1, lon1 = _js_round6(lat0 + cell), _js_round6(lon0 + cell)
        sample_kind, sample = group["sample"]  # type: ignore[misc]
        first, last = group["first"], group["last"]
        out.append(
            {
                "id": f"{lat_cell}:{lon_cell}",
                "box": ",".join(_number_text(value) for value in (lat0, lon0, lat1, lon1)),
                "lat": _js_round6(lat0 + cell / 2),
                "lon": _js_round6(lon0 + cell / 2),
                "count": group["count"],
                "first_time": first.time if first is not None else None,  # type: ignore[attr-defined]
                "last_time": last.time if last is not None else None,  # type: ignore[attr-defined]
                "sample": {
                    "kind": sample_kind,
                    "record_index": sample.record_index,
                    "lat": sample.lat,
                    "lon": sample.lon,
                    "time": sample.time,
                },
            }
        )
    out.sort(key=lambda item: (-int(item["count"]), str(item["id"])))  # type: ignore[call-overload]
    return out[:max_clusters], len(out)


def filtered_candidates(
    items: Sequence[tuple[str, GeoEntry]],
    sources: Sequence[Source],
    matches: Callable[[Mapping[str, object]], bool],
) -> tuple[list[tuple[str, GeoEntry]], int, bool]:
    """``items`` whose records pass ``matches`` (at most :data:`FILTER_READ_CAP` read; ``truncated`` beyond)."""
    by_name = {kind: (payload, Path(path)) for kind, payload, path in sources}
    kept: list[tuple[str, GeoEntry]] = []
    scanned = 0
    for kind, entry, row in _iter_rows(items[:FILTER_READ_CAP], by_name):
        scanned += 1
        if matches(row):
            kept.append((kind, entry))
    return kept, scanned, len(items) > FILTER_READ_CAP
