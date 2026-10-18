"""Files-row provenance from the newest NTFS metadata analysis (plan P1 §3.3).

``GET /api/runs/{id}/files`` rows gain ``ntfs`` (MFT entry + timestamps),
``filesystem`` and ``source_image``; a joined row whose own ``is_deleted``
is unknown (``null``) takes ``not ntfs.in_use``. The page serves either the
``candidates`` or the ``inventory`` list (``?scope=``); both are joined alike.

* **Deletion state.** After the join every row's deletion state agrees with
  its final ``is_deleted`` (``True`` -> ``deleted``, ``False`` ->
  ``allocated``, ``null`` -> ``unknown``): ``recovery.deletion_state`` on
  candidates, top-level ``deletion_state`` on inventory rows. Only the three
  plain states are rewritten -- a specific recovery state (e.g.
  ``unallocated-candidate``) is kept, and with ``is_deleted`` unknown a
  ``deleted`` already recorded by the scan is kept, never downgraded.

* **Times.** ``ntfs`` keeps ``$STANDARD_INFORMATION`` (``si_*``) and
  ``$FILE_NAME`` (``fn_*``) times apart; ``created_at``/``modified_at``/
  ``accessed_at``/``mft_modified_at`` are the merged values the analysis
  wrote (``$SI``, falling back to ``$FN``). Rows of an analysis written
  before the split carry ``si_*``/``fn_*`` ``null`` (except ``fn_created_at``/
  ``fn_modified_at``, which older rows already had) -- a merged time is never
  relabelled as ``$SI``. ``attributes`` = ``$SI`` file-attribute names
  (``null`` when the analysis row has none).

* **Index.** The newest completed ``ntfs-meta`` analysis's ``rows.jsonl`` is
  read once per (run, analysis, file size/mtime) -- single-flight: concurrent
  requests wait for the one build -- into a compact map
  ``blake2b-64(casefold NFC volume path) -> packed (entry_number, merged /
  $SI / $FN times, file attributes, in_use)``. One index per run is kept (a newer
  analysis evicts the older one). USN lines are skipped by a byte check
  before ``json.loads``. When the estimated size exceeds ``INDEX_MAX_BYTES``
  the join answers ``status="too_large"`` instead of building.
* **Only full paths, never ambiguous ones.** Only MFT rows whose path was
  fully reconstructed (``path_status == FULL_PATH_STATUS``) are indexed: a
  partial path (parent outside the scan, cycle, sequence mismatch) is a bare
  name or a truncated chain that could collide with an unrelated file. When
  several rows share a path key, exactly one in-use row wins over deleted
  ones; two or more in-use rows (or only deleted rows, two or more) make the
  key ambiguous and it never joins.
* **Analysis choice.** The newest completed ``ntfs-meta`` analysis that
  parsed MFT records (``summary.mft_record_count > 0``) -- an extraction-only
  (``parse=false``) or unparsed run never hides an older parsed one.
* **Volume prefix.** Determined once per (run, analysis, files output): the
  run's scan root / stage dir when file paths directly under it start with an
  NTFS sentinel (``Windows``, ``Users``, ``$MFT``) present in the index, else
  the shallowest directory (depth ≤ ``MAX_PREFIX_DEPTH``) under those roots
  at which the sentinels match. Rows join only by their path relative to that
  prefix -- never by stripping components per row -- so
  ``Backup/Old/Windows/...`` never matches ``\\Windows\\...``.

Pages are joined, never the cached files payload (shared through the
output-JSON LRU).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import struct
import threading
import unicodedata
from collections import Counter, OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ...core.files import deletion_state_for
from .analyses import ANALYSIS_RUNNER, ROWS_FILE_NAME, RunScope, analyses_root
from .jsonl_records import parse_record_line

# Time fields packed per entry: merged (as written by the analysis), $SI, $FN.
TIME_FIELDS = (
    "created_at",
    "modified_at",
    "accessed_at",
    "mft_modified_at",
    "si_created_at",
    "si_modified_at",
    "si_accessed_at",
    "si_mft_modified_at",
    "fn_created_at",
    "fn_modified_at",
    "fn_accessed_at",
    "fn_mft_modified_at",
)
NTFS_ENTRY_KEYS = ("entry_number", *TIME_FIELDS, "in_use", "is_deleted", "attributes")
SENTINELS = frozenset({"windows", "users", "$mft"})
MAX_PREFIX_DEPTH = 3
PREFIX_SAMPLE_ROWS = 200_000
INDEX_CACHE_MAX_RUNS = 4
INDEX_MAX_BYTES = 512 * 1024 * 1024
# dict slot + int key + bytes value (113-byte payload): ~234 bytes measured on CPython 3.12.
INDEX_BYTES_PER_ENTRY = 240
USN_LINE_MARKER = b'"source": "usn"'
# entry_number, TIME_FIELDS..., file attributes (-1 = unknown), in_use
_PACK = struct.Struct("<q" + "q" * len(TIME_FIELDS) + "q?")
# Placeholders for keys shared by several rows of the same class.
_AMBIGUOUS_IN_USE = b"\x01"
_AMBIGUOUS_DELETED = b"\x00"
FULL_PATH_STATUS = "reconstructed-bounded-parent-cache"
_NONE_TIME = -(2**63)
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


# Per-row ``match_method`` of the join: the index holds only NFC + casefolded
# volume-relative path keys (:func:`ntfs_path_key`), so every hit is a folded
# path match; "none" = joined page, no MFT record at that path; ``None`` = no
# join ran (no analysis / no volume prefix / too large / skipped). There is no
# case-exact comparison, so "path-exact" is never emitted. The volume-prefix
# detection method stays page-level in ``ntfs_join.prefix_method``.
MATCH_METHOD_PATH_FOLD = "path-fold"
MATCH_METHOD_NONE = "none"


def ntfs_path_key(value: object) -> str:
    text = unicodedata.normalize("NFC", str(value or "")).replace("\\", "/").casefold()
    return text.strip("/")


def _hash_key(key: str) -> int:
    return int.from_bytes(hashlib.blake2b(key.encode("utf-8"), digest_size=8).digest(), "little")


def _time_to_us(value: object) -> int:
    if not value:
        return _NONE_TIME
    try:
        moment = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return _NONE_TIME
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return (moment - _EPOCH) // dt.timedelta(microseconds=1)


def _us_to_time(value: int) -> str | None:
    return None if value == _NONE_TIME else (_EPOCH + dt.timedelta(microseconds=value)).isoformat()


def _attribute_names(value: int) -> list[str] | None:
    if value < 0:
        return None
    from ...artifacts.windows.filesystem import NTFS_FILE_ATTRIBUTE_NAMES

    return [name for flag, name in NTFS_FILE_ATTRIBUTE_NAMES.items() if value & flag]


def _attribute_flags(details: Mapping[str, object]) -> int:
    value = details.get("file_attributes")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return -1
    return value


@dataclass
class NtfsIndex:
    key: tuple[str, str, int, int]
    entries: dict[int, bytes]
    top_level: frozenset[str]
    ambiguous: int = 0

    def lookup(self, path_key: str) -> dict[str, object] | None:
        packed = self.entries.get(_hash_key(path_key))
        if packed is None or len(packed) != _PACK.size:
            return None  # absent or ambiguous
        values = _PACK.unpack(packed)
        in_use = bool(values[-1])
        entry: dict[str, object] = {"entry_number": values[0]}
        for name, value in zip(TIME_FIELDS, values[1:-2]):
            entry[name] = _us_to_time(value)
        entry.update({"in_use": in_use, "is_deleted": not in_use, "attributes": _attribute_names(values[-2])})
        return entry


def _merge_entry(existing: bytes | None, packed: bytes, in_use: bool) -> bytes:
    """Value for a key seen again: one in-use row beats deleted rows; ties of a class are ambiguous."""
    if existing is None:
        return packed
    if existing == _AMBIGUOUS_IN_USE:
        return existing
    if existing == _AMBIGUOUS_DELETED:
        return packed if in_use else existing
    existing_in_use = bool(_PACK.unpack(existing)[-1])
    if in_use and existing_in_use:
        return _AMBIGUOUS_IN_USE
    if in_use:
        return packed
    if existing_in_use:
        return existing
    return _AMBIGUOUS_DELETED


def build_ntfs_index(key: tuple[str, str, int, int], rows_path: Path) -> NtfsIndex:
    """Compact index of fully reconstructed MFT paths (ambiguous keys never join)."""
    entries: dict[int, bytes] = {}
    top_level: set[str] = set()
    with rows_path.open("rb") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped.startswith(b"{") or USN_LINE_MARKER in stripped:
                continue
            row = parse_record_line(stripped, path=rows_path, line_number=line_number)
            details = row.get("details") if isinstance(row, Mapping) else None
            if not isinstance(details, Mapping) or details.get("source") != "mft" or not details.get("path"):
                continue
            if details.get("path_status") != FULL_PATH_STATUS:
                continue  # partial paths could collide with unrelated files
            path_key = ntfs_path_key(details["path"])
            hashed = _hash_key(path_key)
            in_use = bool(details.get("in_use"))
            packed = _PACK.pack(
                int(details.get("entry_number") or 0),
                *(_time_to_us(details.get(name)) for name in TIME_FIELDS),
                _attribute_flags(details),
                in_use,
            )
            entries[hashed] = _merge_entry(entries.get(hashed), packed, in_use)
            if "/" not in path_key and path_key in SENTINELS:
                top_level.add(path_key)
    ambiguous = sum(1 for value in entries.values() if len(value) != _PACK.size)
    return NtfsIndex(key=key, entries=entries, top_level=frozenset(top_level), ambiguous=ambiguous)


class NtfsIndexCache:
    """One index per run, built single-flight per key."""

    def __init__(self, *, max_runs: int = INDEX_CACHE_MAX_RUNS) -> None:
        self._max_runs = max_runs
        self._lock = threading.Lock()
        self._by_run: OrderedDict[str, NtfsIndex] = OrderedDict()
        self._building: dict[tuple[str, str, int, int], threading.Event] = {}
        self.builds = 0  # observable for tests

    def clear(self) -> None:
        with self._lock:
            self._by_run.clear()

    def get(self, run_id: str, analysis_id: str, rows_path: Path) -> NtfsIndex:
        stat = rows_path.stat()
        key = (run_id, analysis_id, stat.st_size, stat.st_mtime_ns)
        while True:
            with self._lock:
                cached = self._by_run.get(run_id)
                if cached is not None and cached.key == key:
                    self._by_run.move_to_end(run_id)
                    return cached
                waiting = self._building.get(key)
                if waiting is None:
                    done = threading.Event()
                    self._building[key] = done
                    break
            waiting.wait()
        try:
            index = build_ntfs_index(key, rows_path)
            with self._lock:
                self.builds += 1
                self._by_run[run_id] = index  # replaces (evicts) an older analysis of the run
                self._by_run.move_to_end(run_id)
                while len(self._by_run) > self._max_runs:
                    self._by_run.popitem(last=False)
            return index
        finally:
            with self._lock:
                self._building.pop(key, None)
            done.set()

    def cached_keys(self) -> list[tuple[str, str, int, int]]:
        with self._lock:
            return [index.key for index in self._by_run.values()]


NTFS_INDEX_CACHE = NtfsIndexCache()
_PREFIX_LOCK = threading.Lock()
_PREFIX_CACHE: OrderedDict[tuple[object, ...], tuple[str | None, str]] = OrderedDict()


def clear_ntfs_index_cache() -> None:
    NTFS_INDEX_CACHE.clear()
    with _PREFIX_LOCK:
        _PREFIX_CACHE.clear()


def _scan_roots(scope: RunScope) -> list[Path]:
    roots: list[Path] = []
    for value in (
        scope.summary.get("scan_scope_root"),
        scope.source.get("analysis_root"),
        scope.source.get("stage_dir"),
        scope.summary.get("root"),
    ):
        if isinstance(value, str) and value:
            path = Path(os.path.abspath(value))
            if path not in roots:
                roots.append(path)
    return roots


def _relative_parts(raw_path: object, root: Path) -> tuple[str, ...] | None:
    text = str(raw_path or "")
    if not text:
        return None
    try:
        return Path(os.path.abspath(text)).relative_to(root).parts
    except ValueError:
        return None


def detect_volume_prefix(roots: Sequence[Path], candidates: Sequence[object], top_level: frozenset[str]) -> tuple[str | None, str]:
    """``(prefix, method)``: the directory the volume's root maps to, or ``(None, reason)``."""
    if not top_level:
        return None, "no-sentinel-in-index"
    sample = [row for row in candidates[:PREFIX_SAMPLE_ROWS] if isinstance(row, Mapping)]
    for root in roots:
        if any((parts := _relative_parts(row.get("path"), root)) and parts[0].casefold() in top_level for row in sample):
            return str(root), "scan-root"
    for depth in range(1, MAX_PREFIX_DEPTH + 1):
        counts: Counter[str] = Counter()
        for root in roots:
            for row in sample:
                parts = _relative_parts(row.get("path"), root)
                if parts and len(parts) > depth and parts[depth].casefold() in top_level:
                    counts[str(root.joinpath(*parts[:depth]))] += 1
        if counts:
            return counts.most_common(1)[0][0], f"sentinel-depth-{depth}"
    return None, "no-sentinel-match"


def _files_stamp(scope: RunScope) -> tuple[object, ...]:
    outputs = scope.summary.get("outputs") if isinstance(scope.summary.get("outputs"), Mapping) else {}
    raw = outputs.get("files") if isinstance(outputs, Mapping) else None
    try:
        stat = Path(str(raw)).stat() if raw else None
    except OSError:
        stat = None
    return (str(raw), stat.st_size if stat else -1, stat.st_mtime_ns if stat else -1)


def _volume_prefix(scope: RunScope, index: NtfsIndex, candidates: Sequence[object]) -> tuple[str | None, str]:
    key = (scope.run_id, index.key, _files_stamp(scope))
    with _PREFIX_LOCK:
        cached = _PREFIX_CACHE.get(key)
        if cached is not None:
            return cached
    result = detect_volume_prefix(_scan_roots(scope), candidates, index.top_level)
    with _PREFIX_LOCK:
        _PREFIX_CACHE[key] = result
        while len(_PREFIX_CACHE) > INDEX_CACHE_MAX_RUNS * 2:
            _PREFIX_CACHE.popitem(last=False)
    return result


def latest_parsed_ntfs_analysis(scope: RunScope) -> Mapping[str, object] | None:
    """Newest completed ``ntfs-meta`` analysis with parsed MFT records (``mft_record_count > 0``)."""
    for state in ANALYSIS_RUNNER.list_states(scope.output_dir):
        if state.get("kind") != "ntfs-meta" or state.get("status") != "completed":
            continue
        summary = state.get("summary") if isinstance(state.get("summary"), Mapping) else {}
        try:
            if int(summary.get("mft_record_count") or 0) > 0:
                return state
        except (TypeError, ValueError):
            continue
    return None


PLAIN_DELETION_STATES = frozenset({"allocated", "deleted", "unknown"})


def _deletion_state(current: object, is_deleted: object) -> object:
    """Deletion state agreeing with ``is_deleted`` (see module doc); ``current`` when it must stay."""
    if current not in (None, "") and current not in PLAIN_DELETION_STATES:
        return current  # specific recovery state
    if not isinstance(is_deleted, bool):
        return current if current == "deleted" else deletion_state_for(None)
    return deletion_state_for(is_deleted)


def sync_row_deletion_state(row: dict[str, object]) -> dict[str, object]:
    """``row`` (an owned copy) with its deletion state following ``is_deleted``."""
    is_deleted = row.get("is_deleted")
    recovery = row.get("recovery")
    if isinstance(recovery, Mapping):
        state = _deletion_state(recovery.get("deletion_state"), is_deleted)
        if recovery.get("deletion_state") != state:
            row["recovery"] = {**recovery, "deletion_state": state}  # recovery may be shared with the cache
    if "deletion_state" in row or row.get("inventory_only"):
        row["deletion_state"] = _deletion_state(row.get("deletion_state"), is_deleted)
    return row


def _null_fields(row: Mapping[str, object], source_image: str | None) -> dict[str, object]:
    return sync_row_deletion_state({**row, "ntfs": None, "filesystem": None, "source_image": source_image})


def _join_context(
    scope: RunScope | None, prefix_rows: Sequence[object]
) -> tuple[dict[str, object], str | None, NtfsIndex | None, str | None]:
    """``(ntfs_join info, source_image, index | None, volume prefix | None)`` of a run: the index
    and prefix are set only when the join status is ``joined``."""
    join: dict[str, object] = {
        "analysis_id": None,
        "status": "no_analysis",
        "matched": 0,
        "total": 0,
        "analysis_total": None,
        "volume_prefix": None,
        "prefix_method": None,
        "partition": None,
    }
    source_image: str | None = None
    index: NtfsIndex | None = None
    prefix: str | None = None
    if scope is None:
        join["status"] = "skipped"
        join["reason"] = "런 출력 디렉터리를 확인할 수 없어 NTFS 조인을 건너뜁니다"
    else:
        if str(scope.source.get("type") or "") not in {"", "folder", "directory"}:
            value = scope.source.get("source_path")
            source_image = str(value) if value else None
        state = latest_parsed_ntfs_analysis(scope)
        if state is not None:
            analysis_id = str(state.get("analysis_id"))
            summary = state.get("summary") if isinstance(state.get("summary"), Mapping) else {}
            options = state.get("options") if isinstance(state.get("options"), Mapping) else {}
            partition = summary.get("partition") if isinstance(summary.get("partition"), Mapping) else {}
            source_image = str(summary.get("image") or options.get("image_path") or "") or source_image
            mft_records = int(summary.get("mft_record_count") or 0)
            join.update(
                {
                    "analysis_id": analysis_id,
                    "analysis_total": int(state.get("row_count") or 0),
                    "partition": partition.get("start_sector", options.get("partition_start_sector")),
                }
            )
            rows_path = analyses_root(scope.output_dir) / analysis_id / ROWS_FILE_NAME
            estimated = mft_records * INDEX_BYTES_PER_ENTRY
            if estimated > INDEX_MAX_BYTES:
                join["status"] = "too_large"
                join["reason"] = (
                    f"NTFS 조인 색인 예상 크기({estimated // (1024 * 1024):,} MB)가 "
                    f"한도({INDEX_MAX_BYTES // (1024 * 1024):,} MB)를 넘어 조인하지 않습니다"
                )
            elif rows_path.is_file():
                index = NTFS_INDEX_CACHE.get(scope.run_id, analysis_id, rows_path)
                prefix, method = _volume_prefix(scope, index, prefix_rows)
                join["volume_prefix"] = prefix
                join["prefix_method"] = method
                if prefix is None:
                    join["status"] = "no_volume_prefix"
                    join["reason"] = "파일 경로에서 NTFS 볼륨 루트(Windows·Users·$MFT)를 찾지 못했습니다"
                    index = None
                else:
                    join["status"] = "joined"
    return join, source_image, index, prefix


def ntfs_entry_for(row: Mapping[str, object], index: NtfsIndex, prefix: str) -> dict[str, object] | None:
    """The NTFS entry of a files row under the volume ``prefix`` (None when not indexed)."""
    parts = _relative_parts(row.get("path"), Path(prefix))
    return index.lookup(ntfs_path_key("/".join(parts))) if parts else None


def ntfs_si_modified_resolver(
    scope: RunScope | None, all_rows: Sequence[object]
) -> Callable[[Mapping[str, object]], object] | None:
    """Per-row ``$SI`` modified time of the NTFS join (row conditions of ``GET /files`` resolve an
    acquisition copy's time lazily instead of joining the whole list); None unless ``joined``."""
    _join, _source_image, index, prefix = _join_context(scope, all_rows)
    if index is None or prefix is None:
        return None

    def resolve(row: Mapping[str, object]) -> object:
        entry = ntfs_entry_for(row, index, prefix)
        return entry.get("si_modified_at") if entry is not None else None

    return resolve


def join_files_page(
    scope: RunScope | None,
    page: dict[str, object],
    all_candidates: Sequence[object] = (),
    *,
    collection: str = "candidates",
) -> dict[str, object]:
    """Return ``page`` (a copy) with ``ntfs``/``filesystem``/``source_image`` per row of
    ``page[collection]`` (``candidates`` or ``inventory``) and ``ntfs_join``.

    ``ntfs_join = {analysis_id, status, matched, total, analysis_total,
    volume_prefix, prefix_method, partition, reason?}``; ``matched``/``total``
    count this page's rows only. ``scope=None`` (no usable run output dir)
    skips the join. ``all_candidates`` = the collection's full list (volume
    prefix detection). Deletion states follow ``is_deleted`` (module doc).
    """
    rows = page.get(collection)
    rows = rows if isinstance(rows, list) else []
    join, source_image, index, prefix = _join_context(scope, all_candidates or rows)
    join["total"] = len(rows)
    matched = 0
    joined: list[object] = []
    for row in rows:
        if not isinstance(row, Mapping):
            joined.append(row)
            continue
        entry = ntfs_entry_for(row, index, prefix) if index is not None and prefix is not None else None
        if entry is None:
            nulled = _null_fields(row, source_image)
            nulled["match_method"] = MATCH_METHOD_NONE if index is not None else None
            joined.append(nulled)
            continue
        matched += 1
        merged = {**row, "ntfs": entry, "filesystem": "NTFS", "source_image": source_image, "match_method": MATCH_METHOD_PATH_FOLD}
        if merged.get("is_deleted") is None:
            merged["is_deleted"] = entry["is_deleted"]
        joined.append(sync_row_deletion_state(merged))
    join["matched"] = matched
    result = dict(page)
    result[collection] = joined
    result["ntfs_join"] = join
    return result
