"""Triage flags joined onto grid rows (plan viewer-families §3.1 "조인").

Source: the newest *completed* ``triage-flags`` analysis of the run --
the run step (``analyses/run-triage-flags-<time>``) or a manual run of the
kind -- by ``finished_at``; a ``partial`` set (a source was not read to its
end) is joined with ``flags_join.coverage = "partial"`` and a Korean reason.
The list of sources is cached per run for ``SOURCE_CACHE_TTL_SECONDS`` (and
dropped when an analysis of the run completes), so grid requests do not read
every ``analysis.json`` each time. Its ``flags.jsonl`` is read once per (run, source, file
size, mtime) -- single-flight, at most ``INDEX_CACHE_MAX_RUNS`` runs cached --
into per-kind maps ``record_index -> encoded flags`` plus sorted index arrays
per strongest grade and per rule, so the ``flag``/``flag_grade`` filters and
the ``flags`` sort never parse rows they do not return. A ``flags.jsonl``
larger than ``INDEX_MAX_BYTES`` is not indexed (``status="too_large"``; rows
then carry ``flags: []``).

Row kinds: artifact kind, ``files:candidates`` / ``files:inventory``,
``analysis:<analysis_id>``. Every joined flag is
``{id, grade, label, evidence, note?, version, citation: "<id>@<version>",
status, provenance}`` (``version`` = the rule version the flag set was computed with).
Flags with a grade other than A/B/C are skipped and counted (``flags_join.skipped_flags``).
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
from array import array
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import HTTPException

from ...core.triage_rules import GRADE_RANK, GRADES, load_catalog
from ...core.triage_rules.engine import FLAGS_FILE_NAME, SUMMARY_FILE_NAME
from ...core.triage_rules.stage import TRIAGE_ANALYSIS_KIND
from .analyses import (
    ANALYSIS_ID_PATTERN,
    ANALYSIS_RUNNER,
    COMPLETION_HOOKS,
    analyses_root,
)
from .jsonl_records import iter_artifact_records, iter_records_at

INDEX_CACHE_MAX_RUNS = 4
INDEX_MAX_BYTES = 256 * 1024 * 1024
FLAGS_SORT_KEY = "flags"
GRADE_ERROR = "flag_grade는 A, B, C 중 하나여야 합니다"
NO_SOURCE_REASON = "특이사항 결과가 없습니다. 분석 작업에서 '특이사항(triage-flags)'을 실행하세요."
FLAG_ID_MAX = 64
FLAG_FILTER_MAX = 50
JOINABLE_STATUSES = frozenset({"completed", "partial"})
PARTIAL_REASON = "특이사항이 일부만 계산되었습니다: 끝까지 읽지 못한 소스({sources})의 나머지 행에는 특이사항이 표시되지 않습니다"


@dataclass
class KindFlags:
    rows: dict[int, bytes] = field(default_factory=dict)
    best: dict[int, int] = field(default_factory=dict)
    by_grade: dict[str, array] = field(default_factory=dict)
    by_rule: dict[str, array] = field(default_factory=dict)


@dataclass
class FlagsIndex:
    key: tuple[object, ...]
    kinds: dict[str, KindFlags]
    skipped_flags: int = 0

    def flags_of(self, kind: str, record_index: int) -> list[dict[str, object]]:
        data = self.kinds.get(kind)
        raw = data.rows.get(record_index) if data is not None else None
        return json.loads(raw) if raw else []

    def matching(self, kind: str, rule_ids: frozenset[str] | None, grade: str | None) -> list[int]:
        """Sorted record indices of ``kind`` with any of ``rule_ids`` and a strongest grade at least ``grade``."""
        data = self.kinds.get(kind)
        if data is None:
            return []
        selected: set[int] | None = None
        if rule_ids:
            selected = set()
            for rule_id in rule_ids:
                selected.update(data.by_rule.get(rule_id, ()))
        if grade:
            allowed: set[int] = set()
            for name in GRADES[: GRADE_RANK[grade] + 1]:
                allowed.update(data.by_grade.get(name, ()))
            selected = allowed if selected is None else selected & allowed
        return sorted(selected if selected is not None else data.rows)

    def grade_lists(self, kind: str) -> list[list[int]]:
        """Flagged record indices of ``kind`` per strongest grade (A, B, C), each in record order."""
        data = self.kinds.get(kind)
        return [list(data.by_grade.get(grade, ())) if data is not None else [] for grade in GRADES]

    def best_rank(self, kind: str, record_index: int) -> int:
        """0/1/2 for a row whose strongest flag is A/B/C; 3 for an unflagged row."""
        data = self.kinds.get(kind)
        return data.best.get(record_index, len(GRADES)) if data is not None else len(GRADES)


def build_flags_index(key: tuple[object, ...], path: Path) -> FlagsIndex:
    kinds: dict[str, KindFlags] = {}
    grade_lists: dict[str, dict[str, list[int]]] = {}
    rule_lists: dict[str, dict[str, list[int]]] = {}
    skipped = 0
    with path.open("rb") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped.startswith(b"{"):
                continue
            try:
                row = json.loads(stripped)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            kind = str(row.get("kind") or "")
            index = row.get("record_index")
            listed = row.get("flags") if isinstance(row.get("flags"), list) else []
            flags = [flag for flag in listed if isinstance(flag, Mapping) and flag.get("id") and flag.get("grade") in GRADE_RANK]
            skipped += len(listed) - len(flags)
            if not kind or not isinstance(index, int) or isinstance(index, bool) or index < 0 or not flags:
                continue
            data = kinds.setdefault(kind, KindFlags())
            best = min(GRADE_RANK[str(flag["grade"])] for flag in flags)
            data.rows[index] = json.dumps(flags, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            data.best[index] = best
            grade_lists.setdefault(kind, {}).setdefault(GRADES[best], []).append(index)
            for flag in flags:
                rule_lists.setdefault(kind, {}).setdefault(str(flag["id"]), []).append(index)
    for kind, data in kinds.items():
        data.by_grade = {grade: array("q", sorted(set(items))) for grade, items in grade_lists.get(kind, {}).items()}
        data.by_rule = {rule_id: array("q", sorted(set(items))) for rule_id, items in rule_lists.get(kind, {}).items()}
    return FlagsIndex(key=key, kinds=kinds, skipped_flags=skipped)


class FlagsIndexCache:
    """One index per run output dir, built single-flight per key (concurrent requests wait for one build)."""

    def __init__(self, *, max_runs: int = INDEX_CACHE_MAX_RUNS) -> None:
        self._max_runs = max_runs
        self._lock = threading.Lock()
        self._by_run: OrderedDict[str, FlagsIndex] = OrderedDict()
        self._building: dict[tuple[object, ...], threading.Event] = {}
        self.builds = 0

    def clear(self) -> None:
        with self._lock:
            self._by_run.clear()

    def get(self, run_key: str, source_id: str, path: Path) -> FlagsIndex:
        stat = path.stat()
        key = (run_key, source_id, stat.st_size, stat.st_mtime_ns)
        while True:
            with self._lock:
                cached = self._by_run.get(run_key)
                if cached is not None and cached.key == key:
                    self._by_run.move_to_end(run_key)
                    return cached
                waiting = self._building.get(key)
                if waiting is None:
                    done = threading.Event()
                    self._building[key] = done
                    break
            waiting.wait()
        try:
            index = build_flags_index(key, path)
            with self._lock:
                self.builds += 1
                self._by_run[run_key] = index
                self._by_run.move_to_end(run_key)
                while len(self._by_run) > self._max_runs:
                    self._by_run.popitem(last=False)
            return index
        finally:
            with self._lock:
                self._building.pop(key, None)
            done.set()


FLAGS_INDEX_CACHE = FlagsIndexCache()


def clear_flags_index_cache() -> None:
    FLAGS_INDEX_CACHE.clear()


# --- source -------------------------------------------------------------------


def _read_json(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _moment(value: object) -> dt.datetime:
    try:
        moment = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


SOURCE_CACHE_TTL_SECONDS = 2.0
_SOURCE_CACHE_LOCK = threading.Lock()
_SOURCE_CACHE: dict[str, tuple[float, int, list[dict[str, object]]]] = {}
SOURCE_CACHE_MAX_RUNS = 32


def _analyses_mtime(output_dir: Path) -> int:
    try:
        return analyses_root(output_dir).stat().st_mtime_ns
    except OSError:
        return -1


def invalidate_flag_sources(output_dir: Path | None = None) -> None:
    """Drop the cached source list of one run (all runs without ``output_dir``)."""
    with _SOURCE_CACHE_LOCK:
        if output_dir is None:
            _SOURCE_CACHE.clear()
        else:
            _SOURCE_CACHE.pop(str(Path(output_dir).resolve()), None)


def flag_sources(output_dir: Path) -> list[dict[str, object]]:
    """Completed ``triage-flags`` analyses of a run output, newest first (cached briefly, see module doc)."""
    key = str(Path(output_dir).resolve())
    stamp = _analyses_mtime(Path(output_dir))
    now = time.monotonic()
    with _SOURCE_CACHE_LOCK:
        cached = _SOURCE_CACHE.get(key)
        if cached is not None and cached[0] > now and cached[1] == stamp:
            return list(cached[2])
    found = _scan_flag_sources(Path(output_dir))
    with _SOURCE_CACHE_LOCK:
        if len(_SOURCE_CACHE) >= SOURCE_CACHE_MAX_RUNS:
            _SOURCE_CACHE.pop(next(iter(_SOURCE_CACHE)))
        _SOURCE_CACHE[key] = (now + SOURCE_CACHE_TTL_SECONDS, stamp, found)
    return list(found)


def _scan_flag_sources(output_dir: Path) -> list[dict[str, object]]:
    """``{analysis_id, source, directory, generated_at, summary}`` per completed set, newest first.

    The directory comes from the validated analysis id (never from a path in a state file).
    """
    found: list[dict[str, object]] = []
    root = analyses_root(Path(output_dir))
    for state in ANALYSIS_RUNNER.list_states(Path(output_dir)):
        analysis_id = str(state.get("analysis_id") or "")
        if state.get("kind") != TRIAGE_ANALYSIS_KIND or state.get("status") != "completed":
            continue
        if not ANALYSIS_ID_PATTERN.fullmatch(analysis_id):
            continue
        directory = root / analysis_id
        summary = _read_json(directory / SUMMARY_FILE_NAME)
        if summary is None or summary.get("status") not in JOINABLE_STATUSES or not (directory / FLAGS_FILE_NAME).is_file():
            continue
        found.append(
            {
                "analysis_id": analysis_id,
                "source": "run-stage" if (state.get("options") or {}).get("source") == "run-stage" else "analysis",
                "directory": directory,
                "generated_at": state.get("finished_at") or summary.get("generated_at"),
                "summary": summary,
            }
        )
    found.sort(key=lambda item: _moment(item.get("generated_at")), reverse=True)
    return found


@dataclass
class FlagsJoin:
    """The flag index of one run (or the reason there is none) for one request."""

    index: FlagsIndex | None
    info: dict[str, object]
    summary: Mapping[str, object] | None = None
    _specs: Mapping[str, object] | None = field(default=None, repr=False)

    def _versions(self) -> Mapping[str, object]:
        versions = self.summary.get("rule_versions") if isinstance(self.summary, Mapping) else None
        return versions if isinstance(versions, Mapping) else {}

    def flags_for(self, kind: str, record_index: object) -> list[dict[str, object]]:
        """The row's flags with ``version``/``citation``/``status`` (``[]`` when unflagged or not joined)."""
        if self.index is None or not isinstance(record_index, int) or isinstance(record_index, bool):
            return []
        flags = self.index.flags_of(kind, record_index)
        if not flags:
            return flags
        versions = self._versions()
        if self._specs is None:
            self._specs = load_catalog().specs
        specs = self._specs
        for flag in flags:
            rule_id = str(flag.get("id") or "")
            spec = specs.get(rule_id)
            version = versions.get(rule_id) or (spec.version if spec else 1)
            flag["version"] = version
            flag["citation"] = f"{rule_id}@{version}"
            flag["status"] = spec.status if spec else None
        return flags

    def attach(self, rows: Iterable[object], kind: str) -> list[object]:
        """Copies of ``rows`` with ``flags`` (by ``record_index``); rows without one get ``[]``."""
        joined: list[object] = []
        for row in rows:
            if isinstance(row, dict):
                flags = self.flags_for(kind, row.get("record_index"))
                if flags:
                    provenance = row_provenance(row, kind)
                    for flag in flags:
                        flag["provenance"] = provenance
                joined.append({**row, "flags": flags})
            else:
                joined.append(row)
        return joined

    def require_index(self) -> FlagsIndex:
        if self.index is None:
            raise HTTPException(status_code=409, detail=str(self.info.get("reason") or NO_SOURCE_REASON))
        return self.index


def flags_join(output_dir: Path | None, *, build_index: bool = True) -> FlagsJoin:
    """The newest completed flag set of ``output_dir`` (``info.status``: joined | no_source | too_large | skipped).

    ``build_index=False`` only resolves the source and its summary (the tree needs no row index).
    """
    if output_dir is None:
        return FlagsJoin(None, {"status": "skipped", "reason": "런 출력 디렉터리를 확인할 수 없어 특이사항을 붙이지 않습니다"})
    sources = flag_sources(Path(output_dir))
    if not sources:
        return FlagsJoin(None, {"status": "no_source", "reason": NO_SOURCE_REASON})
    source = sources[0]
    summary = source["summary"] if isinstance(source["summary"], Mapping) else {}
    info: dict[str, object] = {
        "status": "joined",
        "source": source["source"],
        "analysis_id": source["analysis_id"],
        "generated_at": source["generated_at"],
        "catalog_version": summary.get("catalog_version"),
        "coverage": "complete",
    }
    if summary.get("status") == "partial":
        coverage = summary.get("coverage") if isinstance(summary.get("coverage"), Mapping) else {}
        incomplete = [str(kind) for kind in coverage.get("incomplete") or []]
        info.update(
            {"coverage": "partial", "incomplete_sources": incomplete, "reason": PARTIAL_REASON.format(sources=", ".join(incomplete) or "?")}
        )
    path = Path(str(source["directory"])) / FLAGS_FILE_NAME
    try:
        size = path.stat().st_size
    except OSError:
        return FlagsJoin(None, {**info, "status": "no_source", "reason": "특이사항 파일을 읽을 수 없습니다"})
    if size > INDEX_MAX_BYTES:
        reason = (
            f"특이사항 파일({size // (1024 * 1024):,} MB)이 색인 한도({INDEX_MAX_BYTES // (1024 * 1024):,} MB)를 넘어 "
            "행에 붙이지 않습니다"
        )
        return FlagsJoin(None, {**info, "status": "too_large", "reason": reason}, summary)
    if not build_index:
        return FlagsJoin(None, info, summary)
    try:
        index = FLAGS_INDEX_CACHE.get(str(Path(output_dir).resolve()), str(source["analysis_id"]), path)
    except OSError:
        return FlagsJoin(None, {**info, "status": "no_source", "reason": "특이사항 파일을 읽을 수 없습니다"}, summary)
    if index.skipped_flags:
        info["skipped_flags"] = index.skipped_flags
    return FlagsJoin(index, info, summary)


# --- request parsing ------------------------------------------------------------


@dataclass(frozen=True)
class FlagQuery:
    """Validated ``flag`` / ``flag_grade`` / ``sort=flags`` of one request."""

    rule_ids: frozenset[str] | None = None
    grade: str | None = None
    sort: bool = False

    @property
    def filtered(self) -> bool:
        return bool(self.rule_ids or self.grade)

    @property
    def active(self) -> bool:
        return self.filtered or self.sort

    def descriptor(self) -> dict[str, object] | None:
        if not self.filtered:
            return None
        return {"flag": sorted(self.rule_ids) if self.rule_ids else None, "flag_grade": self.grade}


def parse_flag_query(flag: Sequence[str], flag_grade: str | None, *, sort_flags: bool = False) -> FlagQuery:
    """Validated filters: unknown rule ids, too many ids or a grade other than A/B/C are a 422 (Korean)."""
    rule_ids = frozenset(item.strip() for item in flag if item and item.strip()) or None
    grade = flag_grade.strip().upper() if flag_grade and flag_grade.strip() else None
    if grade is not None and grade not in GRADES:
        raise HTTPException(status_code=422, detail=GRADE_ERROR)
    if rule_ids:
        if len(rule_ids) > FLAG_FILTER_MAX:
            raise HTTPException(status_code=422, detail=f"특이사항 지표는 한 번에 {FLAG_FILTER_MAX}개까지 지정할 수 있습니다")
        known = load_catalog().specs
        unknown = sorted(rule_id[:FLAG_ID_MAX] for rule_id in rule_ids if rule_id not in known)
        if unknown:
            raise HTTPException(status_code=422, detail=f"알 수 없는 특이사항 지표입니다: {', '.join(unknown[:5])}")
    return FlagQuery(rule_ids=rule_ids, grade=grade, sort=sort_flags)


def is_flags_sort(sort: str | None) -> bool:
    """``sort=flags`` (an ``:asc``/``:desc`` suffix is accepted and ignored: the order is always A, B, C, unflagged)."""
    if not sort:
        return False
    head, _, suffix = sort.strip().rpartition(":")
    key = head if head and suffix.lower() in {"asc", "desc"} else sort.strip()
    return key == FLAGS_SORT_KEY


FLAGS_SORT_DESCRIPTOR = {"key": FLAGS_SORT_KEY, "order": "asc", "status": "ready", "progress": 1.0}


def mark_flag_page(
    page: dict[str, object], query: FlagQuery, *, record_count: int | None = None, other_filters: bool = False
) -> dict[str, object]:
    """Record the flag filter on a page's ``pagination`` and, for ``sort=flags``, its ``sort`` descriptor.

    A ``sort=flags`` page without any filter is a reordering, not a filter: ``filtered`` is false and
    ``total`` is the whole ``record_count`` (the streaming pager only knows it at the end).
    """
    pagination = page.get("pagination")
    if isinstance(pagination, dict):
        pagination["flags"] = query.descriptor()
        if query.sort and not query.filtered and not other_filters:
            pagination["filtered"] = False
            if record_count is not None:
                pagination["total"] = record_count
    if query.sort:
        page["sort"] = dict(FLAGS_SORT_DESCRIPTOR)
    return page


# --- row sources -----------------------------------------------------------------


def flag_rows_source(
    payload: Mapping[str, object],
    payload_path: Path | None,
    *,
    kind: str,
    join: FlagsJoin,
    query: FlagQuery,
    record_limit: int | None = None,
) -> Iterator[tuple[int, dict[str, object]]]:
    """Rows of one kind for ``query``: the matching flagged rows (record order), or with ``sort`` every
    flagged row by strongest grade (A, B, C; record order inside each) followed -- only without a flag
    filter -- by the unflagged rows in record order."""
    index = join.require_index() if query.filtered else join.index
    if not query.sort:
        assert index is not None
        yield from iter_records_at(payload, payload_path, index.matching(kind, query.rule_ids, query.grade), record_limit=record_limit)
        return
    flagged: set[int] = set()
    if index is not None:
        eligible = set(index.matching(kind, query.rule_ids, query.grade)) if query.filtered else None
        for indices in index.grade_lists(kind):
            chosen = [item for item in indices if eligible is None or item in eligible]
            flagged.update(chosen)
            yield from iter_records_at(payload, payload_path, chosen, record_limit=record_limit)
    if query.filtered:
        return
    for record_index, row in iter_artifact_records(payload, payload_path=payload_path, limit=record_limit):
        if record_index not in flagged:
            yield record_index, row


def kind_rows_for_flags(join: FlagsJoin, query: FlagQuery):
    """``rows_for(kind, payload, path, start)`` for :func:`artifact_filter.filter_across_kinds` (flag filter only)."""

    def rows_for(kind: str, payload: Mapping[str, object], payload_path: Path, start: int) -> Iterator[tuple[int, dict[str, object]]]:
        indices = [item for item in join.require_index().matching(kind, query.rule_ids, query.grade) if item >= start]
        return iter_records_at(payload, payload_path, indices)

    return rows_for


def filter_files_rows(
    rows: Sequence[object],
    *,
    collection: str,
    join: FlagsJoin,
    query: FlagQuery,
    categories: frozenset[str] | None,
    offset: int,
    limit: int,
    row_filter: Callable[[Mapping[str, object]], bool] | None = None,
) -> tuple[list[object], dict[str, object]]:
    """Files rows of ``collection`` after category/flag filters and ``row_filter`` (row conditions)
    (and the ``flags`` order): ``(page rows, pagination)``."""
    from .artifact_filter import file_row_categories

    kind = f"files:{collection}"
    eligible: set[int] | None = None
    if query.filtered:
        eligible = set(join.require_index().matching(kind, query.rule_ids, query.grade))
    order: list[int] = []
    for record_index, row in enumerate(rows):
        if eligible is not None and record_index not in eligible:
            continue
        if categories:
            values = file_row_categories(row, collection)
            if not values or categories.isdisjoint(values):
                continue
        if row_filter is not None and not (isinstance(row, Mapping) and row_filter(row)):
            continue
        order.append(record_index)
    if query.sort and join.index is not None:
        index = join.index
        order.sort(key=lambda item: (index.best_rank(kind, item), item))
    window = order[offset : offset + limit] if limit > 0 else order[offset:]
    page_rows = [{**rows[item], "record_index": item} for item in window if isinstance(rows[item], dict)]
    has_more = limit > 0 and offset + len(window) < len(order)
    pagination: dict[str, object] = {
        "collection": collection,
        "offset": offset,
        "limit": limit,
        "returned": len(page_rows),
        "total": len(order),
        "matched": len(order),
        "next_offset": offset + len(window) if has_more else None,
        "previous_offset": max(0, offset - limit) if offset > 0 and limit > 0 else None,
        "has_more": has_more,
        "filtered": bool(eligible is not None or categories or row_filter is not None),
        "categories": sorted(categories) if categories else None,
        "flags": query.descriptor(),
        "scanned": len(rows),
        "truncated": False,
    }
    if query.sort:
        pagination["sort"] = FLAGS_SORT_KEY
    return page_rows, pagination


# --- tree / meta ---------------------------------------------------------------------


def _grade_counts(value: object) -> dict[str, int]:
    return {grade: int(value.get(grade) or 0) if isinstance(value, Mapping) else 0 for grade in GRADES}


def kind_flag_counts(summary: Mapping[str, object] | None, kind: str, artifact_types: Iterable[str] | None = None) -> dict[str, int]:
    """Flagged rows of ``kind`` by strongest grade; with ``artifact_types`` only rows of those types."""
    if not isinstance(summary, Mapping):
        return _grade_counts(None)
    if artifact_types is None:
        by_kind = summary.get("by_kind")
        return _grade_counts(by_kind.get(kind) if isinstance(by_kind, Mapping) else None)
    by_type = summary.get("by_kind_type")
    types = by_type.get(kind) if isinstance(by_type, Mapping) else None
    totals = _grade_counts(None)
    if isinstance(types, Mapping):
        for artifact_type in artifact_types:
            counts = _grade_counts(types.get(artifact_type))
            for grade in GRADES:
                totals[grade] += counts[grade]
    return totals


def tree_flags_section(output_dir: Path | None) -> tuple[dict[str, object] | None, Mapping[str, object] | None]:
    """``/tree`` ``flags`` section and the summary it came from (``(None, None)`` when the run has no flag set).

    ``{total, by_grade, by_rule: [{id, label, grade, status, count}], policy: [{id, label, count, note}],
    versions: {rule id: version}, catalog_version, source: {status, analysis_id, generated_at, …}}``;
    ``total``/``by_grade`` count rows by their strongest flag, ``by_rule`` rows per rule.
    """
    join = flags_join(output_dir, build_index=False)
    summary = join.summary
    if summary is None:
        return None, None
    catalog = load_catalog()
    rules: list[dict[str, object]] = []
    by_rule = summary.get("by_rule")
    if isinstance(by_rule, Mapping):
        for rule_id, count in by_rule.items():
            spec = catalog.specs.get(str(rule_id))
            rules.append(
                {
                    "id": str(rule_id),
                    "label": spec.label_ko if spec else str(rule_id),
                    "grade": spec.grade if spec else None,
                    "status": spec.status if spec else None,
                    "count": int(count or 0),
                }
            )
    rules.sort(key=lambda item: (GRADE_RANK.get(str(item["grade"]), len(GRADES)), -int(item["count"]), str(item["id"])))
    policy = summary.get("policy_sources")
    section: dict[str, object] = {
        "total": int(summary.get("flagged_rows") or 0),
        "by_grade": _grade_counts(summary.get("rows_by_best_grade")),
        "by_rule": rules,
        "policy": [dict(item) for item in policy if isinstance(item, Mapping)] if isinstance(policy, list) else [],
        "versions": dict(summary.get("rule_versions") or {}) if isinstance(summary.get("rule_versions"), Mapping) else {},
        "catalog_version": summary.get("catalog_version"),
        "source": {
            key: join.info.get(key)
            for key in ("status", "source", "analysis_id", "generated_at", "coverage", "incomplete_sources", "reason")
            if join.info.get(key) is not None
        },
    }
    return section, summary


CARVED_TERMS = ("carv", "slack", "string-scan")
RECOVERED_TERMS = ("recovered", "unallocated", "deleted", "orphan")


def _first_text(*values: object) -> str | None:
    for value in values:
        if value not in (None, "") and not isinstance(value, (Mapping, list)):
            return str(value)
    return None


def row_provenance(row: Mapping[str, object], kind: str) -> dict[str, object]:
    """Where a flagged row came from, from fields the row already carries (no parsing):
    ``{kind, record_index, recovery_method: parsed|carved|recovered|unknown, recovery_detail?, parser?,
    parser_version?, source_path?, source_offset?, deleted?}``."""
    details = row.get("details") if isinstance(row.get("details"), Mapping) else row
    record = row.get("artifact_record") if isinstance(row.get("artifact_record"), Mapping) else {}
    source = record.get("source") if isinstance(record.get("source"), Mapping) else {}
    recovery = row.get("recovery") if isinstance(row.get("recovery"), Mapping) else {}
    detail = _first_text(
        details.get("recovery_method"),
        details.get("evtx_record_state"),
        details.get("evtx_recovery_status"),
        details.get("recovery_status"),
        recovery.get("deletion_state"),
        details.get("deletion_state"),
    )
    if kind.startswith("analysis:") and str(row.get("artifact_type") or "").startswith("carve-"):
        method = "carved"
    elif detail is None:
        method = "parsed" if (record or details.get("parser") or kind.startswith("files:")) else "unknown"
    else:
        lowered = detail.lower()
        if any(term in lowered for term in CARVED_TERMS):
            method = "carved"
        elif any(term in lowered for term in RECOVERED_TERMS):
            method = "recovered"
        else:
            method = "parsed"
    provenance: dict[str, object] = {"kind": kind, "record_index": row.get("record_index"), "recovery_method": method}
    optional = {
        "recovery_detail": detail,
        "parser": _first_text(record.get("parser"), details.get("parser"), row.get("provider")),
        "parser_version": _first_text(record.get("parser_version"), details.get("parser_version")),
        "source_path": _first_text(source.get("source_path"), details.get("source_path"), row.get("path")),
        "source_offset": source.get("offset") if isinstance(source.get("offset"), int) else None,
        "deleted": details.get("is_deleted") if isinstance(details.get("is_deleted"), bool) else None,
    }
    provenance.update({key: value for key, value in optional.items() if value is not None})
    return provenance


def row_citations(
    join: FlagsJoin, kind: str, record_index: int, row: Mapping[str, object] | None = None
) -> list[dict[str, object]]:
    """``[{id, version, citation: "<id>@<version>", grade, label, status, evidence, note?, provenance?, text}]`` of one row.

    ``text`` = ``"<id>@<version> (<field>=<value>, …) [<recovery method>, <parser>@<parser version>, #<record_index>]"``
    for a report citation; the bracket comes from ``row`` (the row as the grid serves it) when given.
    """
    provenance = row_provenance({**row, "record_index": record_index}, kind) if row is not None else None
    cited: list[dict[str, object]] = []
    for flag in join.flags_for(kind, record_index):
        evidence = flag.get("evidence") if isinstance(flag.get("evidence"), Mapping) else {}
        fields = ", ".join(f"{key}={value}" for key, value in evidence.items())
        entry = {key: flag.get(key) for key in ("id", "version", "citation", "grade", "label", "status", "evidence")}
        if flag.get("note"):
            entry["note"] = flag["note"]
        entry["text"] = f"{flag.get('citation')} ({fields})" if fields else str(flag.get("citation"))
        if provenance is not None:
            entry["provenance"] = provenance
            parser = provenance.get("parser")
            version = provenance.get("parser_version")
            origin = [str(provenance["recovery_method"])]
            if parser:
                origin.append(f"{parser}@{version}" if version else str(parser))
            origin.append(f"#{record_index}")
            entry["text"] += f" [{', '.join(origin)}]"
        cited.append(entry)
    return cited


def _invalidate_after_analysis(context) -> None:
    """Completion hook: a finished ``triage-flags`` analysis is joined at once (not after the source-cache TTL)."""
    if context.spec.kind == TRIAGE_ANALYSIS_KIND:
        invalidate_flag_sources(context.scope.output_dir)


if _invalidate_after_analysis not in COMPLETION_HOOKS:
    COMPLETION_HOOKS.append(_invalidate_after_analysis)
