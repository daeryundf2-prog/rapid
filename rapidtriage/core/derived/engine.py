"""통합 보기 (derived cross-artifact tables), one pass over a run output (plan axiom-adoption §3.2).

``run_derived`` streams every row source of a run once -- the per-kind artifact
outputs, the files output (``candidates`` / ``inventory``) and completed analyses --
and gathers the values of every catalogue column that carries a ``semantic`` tag
(``core/triage_rules/catalog/*.yaml``) into six tables:

========== =========================================== ======================
table      semantic tags                               normalised by
========== =========================================== ======================
people     person, person_sender, person_recipient,     e-mail / E.164 / SID /
           account                                      casefold
devices    device                                       MAC / IP / GUID / casefold
paths      path                                         separators + casefold
attachments attachment                                  file name casefold
credentials credential                                  SHA-256 (masked display)
urls       url                                          host (+ URL class)
========== =========================================== ======================

(``hash``, ``geo`` and ``search_term`` tags feed no table yet; they are counted in the summary.)

A column value is read exactly like the console reads the column (``key`` then
``aliases``; ``event_data.X`` looks into every EVTX EventData container), so a count
is a count of what the grids show. Lists give one value per item; a mapping item gives
its ``filename`` / ``name`` / ``value``. A column with ``semantic_when: {field: [v…]}``
only counts on rows whose ``field`` is one of the values.

Each table is written to ``out_dir/<table>.jsonl``, one line per distinct normalised
value, sorted by count (desc) then value::

    {value, normalized, semantic, semantics: {tag: n}, count, kinds: {kind: n},
     families: {family: n}, first_seen, last_seen,
     samples: [{kind, record_index, field, family, artifact_type, time}] (≤ 20)}

plus ``url_class`` / ``url_class_label`` / ``examples`` (≤ 3 URLs) for ``urls`` and
``length`` / ``sha256`` for ``credentials``. **A credential's clear value is never
written**: ``value`` is the masked form, ``normalized`` is ``sha256:<hex>``.
``kind`` = artifact kind, ``files:candidates`` / ``files:inventory`` or
``analysis:<analysis_id>``; ``record_index`` numbers rows like the grid readers.
Next to each table, ``<table>.index.json`` is a columnar paging index (normalised values,
casefolded search texts, counts, first/last seen, kind sets, byte offset + length of each
row's line) so the API pages a table without parsing every row's samples.
``first_seen`` / ``last_seen`` come from the row's first catalogue time column that
has a value (else its ``timestamp``). Samples are spread round-robin over the (row source,
family) groups a value was seen in, so a value seen in several families links to each of them.

Caps: at most ``MAX_VALUES_PER_TABLE`` distinct values per table and an estimated
``MEMORY_CAP_BYTES`` for all tables together; past a cap new values are not added
(known values still count) and the table records ``capped`` + ``cap_reason`` +
``dropped_values``. ``summary.json`` (written last) holds per-table counts, the
coverage (a source not read to its end makes the set ``partial``), rows scanned per
source, the catalogue and URL-class versions and the elapsed time. Files are written to
a temp name and ``os.replace``-d.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..json_safe import json_default
from ..triage_rules.base import EVENT_DATA_KEYS, parse_time
from ..triage_rules.catalog import Catalog, load_catalog
from ..triage_rules.engine import (
    FilesOutput,
    Progress,
    RowSource,
    TriageInputs,
    _row_sources,
    _write_atomic,
    coverage_block,
)
from .normalize import clean, credential_record, normalize
from .url_classes import UrlClasses, load_url_classes

SUMMARY_FILE_NAME = "summary.json"
INDEX_SUFFIX = ".index.json"
SUMMARY_VERSION = "derived-summary-v1"
TABLES: tuple[str, ...] = ("people", "devices", "paths", "attachments", "credentials", "urls")
TABLE_LABELS: dict[str, str] = {
    "people": "사람 식별자",
    "devices": "장치 식별자",
    "paths": "접근 경로",
    "attachments": "첨부",
    "credentials": "자격 증명/토큰",
    "urls": "URL 분류",
}
TABLE_OF_SEMANTIC: dict[str, str] = {
    "person": "people",
    "person_sender": "people",
    "person_recipient": "people",
    "account": "people",
    "device": "devices",
    "path": "paths",
    "attachment": "attachments",
    "credential": "credentials",
    "url": "urls",
}
MAX_VALUES_PER_TABLE = 200_000
MAX_SAMPLES = 20
# Samples kept per (value, kind) while reading; the written row keeps MAX_SAMPLES round-robin.
MAX_SAMPLES_PER_KIND = 20
MAX_SAMPLES_STORED = 60
MAX_URL_EXAMPLES = 3
URL_EXAMPLE_CHARS = 300
MEMORY_CAP_BYTES = 320 * 1024 * 1024
# Rough per-entry / per-sample cost of the in-memory tables (CPython objects), for the memory cap.
ENTRY_OVERHEAD_BYTES = 900
SAMPLE_BYTES = 160
CANCEL_CHECK_EVERY = 2_000
ITEM_KEYS = ("filename", "file_name", "name", "value", "address", "email", "path", "url")
# Kinds whose rows the pass never reads (their own outputs, or copies of other rows).
SKIPPED_ANALYSIS_KINDS = frozenset({"triage-flags", "derived", "search-index"})
RECIPIENT_SPLIT = (",", ";")


@dataclass(frozen=True)
class TaggedColumn:
    semantic: str
    table: str
    key: str
    candidates: tuple[str, ...]
    when: tuple[tuple[str, frozenset[str]], ...] = ()


@dataclass(frozen=True)
class FamilyPlan:
    family: str
    columns: tuple[TaggedColumn, ...]
    time_keys: tuple[tuple[str, ...], ...]


def family_plans(catalog: Catalog) -> dict[str, FamilyPlan]:
    """Tagged columns and time columns of every catalogue family."""
    plans: dict[str, FamilyPlan] = {}
    for family in catalog.families:
        columns: list[TaggedColumn] = []
        times: list[tuple[str, ...]] = []
        seen: set[str] = set()
        for column in [*(family.get("core_columns") or []), *(family.get("aux_columns") or [])]:
            key = str(column.get("key") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            candidates = (key, *(str(alias) for alias in column.get("aliases") or ()))
            if column.get("format") == "time" and not column.get("derive"):
                times.append(candidates)
            semantic = column.get("semantic")
            if not semantic:
                continue
            when = column.get("semantic_when") if isinstance(column.get("semantic_when"), Mapping) else {}
            columns.append(
                TaggedColumn(
                    semantic=str(semantic),
                    table=TABLE_OF_SEMANTIC.get(str(semantic), ""),
                    key=key,
                    candidates=candidates,
                    when=tuple((str(name), frozenset(str(item) for item in values)) for name, values in when.items()),
                )
            )
        plans[str(family["id"])] = FamilyPlan(str(family["id"]), tuple(columns), tuple(times))
    return plans


def _present(value: object) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def read_key(details: Mapping[str, object], key: str) -> object:
    """A top-level key, ``event_data.X`` (any EVTX EventData container) or a dotted path (console ``readKey``)."""
    if "." not in key:
        return details.get(key)
    head, *rest = key.split(".")
    for name in EVENT_DATA_KEYS if head == "event_data" else (head,):
        value: object = details.get(name)
        for part in rest:
            value = value.get(part) if isinstance(value, Mapping) else None
        if _present(value):
            return value
    return None


def read_column(details: Mapping[str, object], candidates: Sequence[str]) -> tuple[object, str] | None:
    """First present value among a column's key and aliases, with the key it came from."""
    for key in candidates:
        value = read_key(details, key)
        if _present(value):
            return value, key
    return None


def iter_items(value: object, semantic: str) -> Iterable[object]:
    """The single values of a column value: list items, a mapping item's file name / name / value,
    and for sender/recipient columns a ``,``/``;`` separated list of addresses."""
    items = value if isinstance(value, (list, tuple)) else [value]
    for item in items:
        if isinstance(item, Mapping):
            item = next((item[key] for key in ITEM_KEYS if _present(item.get(key)) and not isinstance(item.get(key), (Mapping, list))), None)
            if item is None:
                continue
        if isinstance(item, (list, tuple, Mapping)):
            continue
        if semantic in ("person_sender", "person_recipient") and isinstance(item, str):
            parts = [part.strip() for part in item.replace(";", ",").split(",")]
            if len(parts) > 1 and all("@" in part for part in parts if part):
                yield from (part for part in parts if part)
                continue
        yield item


class _Entry:
    __slots__ = ("count", "examples", "extra", "families", "first", "kinds", "last", "samples", "semantics", "value")

    def __init__(self, value: str) -> None:
        self.value = value
        self.count = 0
        self.semantics: dict[str, int] = {}
        self.kinds: dict[str, int] = {}
        self.families: dict[str, int] = {}
        self.first: dt.datetime | None = None
        self.last: dt.datetime | None = None
        self.samples: dict[str, list[tuple[int, str, str, str, str | None]]] = {}
        self.examples: list[str] | None = None
        self.extra: dict[str, object] | None = None


@dataclass
class _TableState:
    entries: dict[str, _Entry]
    capped: bool = False
    cap_reason: str | None = None
    dropped_values: int = 0
    occurrences: int = 0


class DerivedCollector:
    """The six tables while the pass runs (caps on distinct values and estimated memory)."""

    def __init__(
        self,
        url_classes: UrlClasses,
        *,
        max_values: int = MAX_VALUES_PER_TABLE,
        memory_cap: int = MEMORY_CAP_BYTES,
    ) -> None:
        self.url_classes = url_classes
        self.max_values = max_values
        self.memory_cap = memory_cap
        self.tables: dict[str, _TableState] = {table: _TableState({}) for table in TABLES}
        self.estimated_bytes = 0

    def add(
        self,
        table: str,
        semantic: str,
        raw: object,
        *,
        kind: str,
        family: str,
        record_index: int,
        field: str,
        artifact_type: str,
        moment: dt.datetime | None,
        details: Mapping[str, object],
    ) -> bool:
        text = clean(raw)
        if text is None:
            return False
        extra: dict[str, object] | None = None
        if table == "credentials":
            record = credential_record(
                text,
                sha256=_sibling(details, field, "sha256"),
                length=_sibling(details, field, "length"),
            )
            key = f"sha256:{record['sha256']}"
            shown = str(record["masked"])
            extra = {"length": record["length"], "sha256": record["sha256"]}
        else:
            normalized = normalize(table, text)
            if not normalized:
                return False
            key = normalized
            shown = normalized if table == "urls" else text
        state = self.tables[table]
        entry = state.entries.get(key)
        if entry is None:
            reason = None
            if len(state.entries) >= self.max_values:
                reason = "values"
            elif self.estimated_bytes >= self.memory_cap:
                reason = "memory"
            if reason is not None:
                if not state.capped:
                    state.capped, state.cap_reason = True, reason
                state.dropped_values += 1
                return False
            entry = _Entry(shown)
            entry.extra = extra
            state.entries[key] = entry
            self.estimated_bytes += ENTRY_OVERHEAD_BYTES + 2 * (len(shown) + len(key))
        entry.count += 1
        state.occurrences += 1
        entry.semantics[semantic] = entry.semantics.get(semantic, 0) + 1
        entry.kinds[kind] = entry.kinds.get(kind, 0) + 1
        entry.families[family] = entry.families.get(family, 0) + 1
        if moment is not None:
            if entry.first is None or moment < entry.first:
                entry.first = moment
            if entry.last is None or moment > entry.last:
                entry.last = moment
        # Samples are kept per (row source, family): each family a value was seen in stays reachable.
        group = entry.samples.setdefault(f"{kind}\0{family}", [])
        stored = sum(len(items) for items in entry.samples.values())
        if (len(group) < MAX_SAMPLES_PER_KIND and stored < MAX_SAMPLES_STORED) or not group:
            group.append((record_index, field, family, artifact_type, moment.isoformat() if moment else None))
            self.estimated_bytes += SAMPLE_BYTES
        if table == "urls" and isinstance(raw, str) and "://" in raw:
            examples = entry.examples if entry.examples is not None else []
            clipped = raw.strip()[:URL_EXAMPLE_CHARS]
            if len(examples) < MAX_URL_EXAMPLES and clipped not in examples:
                examples.append(clipped)
                entry.examples = examples
                self.estimated_bytes += 2 * len(clipped)
        return True

    def rows(self, table: str) -> list[dict[str, object]]:
        """The table's rows, count desc then normalised value."""
        state = self.tables[table]
        ordered = sorted(state.entries.items(), key=lambda item: (-item[1].count, item[0]))
        return [self._row(table, key, entry) for key, entry in ordered]

    def _row(self, table: str, key: str, entry: _Entry) -> dict[str, object]:
        semantic = max(entry.semantics.items(), key=lambda item: (item[1], item[0]))[0]
        row: dict[str, object] = {
            "value": entry.value,
            "normalized": key,
            "semantic": semantic,
            "semantics": dict(sorted(entry.semantics.items())),
            "count": entry.count,
            "kinds": dict(sorted(entry.kinds.items(), key=lambda item: (-item[1], item[0]))),
            "families": dict(sorted(entry.families.items(), key=lambda item: (-item[1], item[0]))),
            "first_seen": entry.first.isoformat() if entry.first else None,
            "last_seen": entry.last.isoformat() if entry.last else None,
            "samples": _round_robin(entry.samples),
        }
        if table == "urls":
            url_class = self.url_classes.classify(key)
            row["url_class"] = url_class
            row["url_class_label"] = self.url_classes.labels.get(url_class) if url_class else None
            row["examples"] = list(entry.examples or [])
        if table == "credentials" and entry.extra:
            row.update(entry.extra)
        return row


def _sibling(details: Mapping[str, object], field: str, suffix: str) -> Any:
    """A parser's own digest/length of a secret column: ``<field>_<suffix>`` or ``value_<suffix>``."""
    for name in (f"{field}_{suffix}", f"value_{suffix}"):
        value = details.get(name)
        if value not in (None, ""):
            return value
    return None


def _round_robin(samples: Mapping[str, list[tuple[int, str, str, str, str | None]]]) -> list[dict[str, object]]:
    """Up to MAX_SAMPLES samples taken in turn from each (row source, family) group."""
    queues = [(group.split("\0", 1)[0], list(items)) for group, items in samples.items()]
    picked: list[dict[str, object]] = []
    position = 0
    while len(picked) < MAX_SAMPLES and any(items for _kind, items in queues):
        kind, items = queues[position % len(queues)]
        if items:
            record_index, field, family, artifact_type, moment = items.pop(0)
            picked.append(
                {
                    "kind": kind,
                    "record_index": record_index,
                    "field": field,
                    "family": family,
                    "artifact_type": artifact_type,
                    "time": moment,
                }
            )
        position += 1
    return picked


def _row_time(details: Mapping[str, object], plan: FamilyPlan) -> dt.datetime | None:
    for candidates in plan.time_keys:
        hit = read_column(details, candidates)
        if hit is not None:
            moment = parse_time(hit[0])
            if moment is not None:
                return moment
    return parse_time(details.get("timestamp"))


def _matches(details: Mapping[str, object], column: TaggedColumn) -> bool:
    for name, allowed in column.when:
        if str(details.get(name) or "") not in allowed:
            return False
    return True


def _sources(inputs: TriageInputs, files: FilesOutput, load_errors: dict[str, str]) -> list[RowSource]:
    analyses = tuple(item for item in inputs.analyses if item[1] not in SKIPPED_ANALYSIS_KINDS)
    scoped = TriageInputs(
        output_dir=inputs.output_dir,
        artifact_payloads=inputs.artifact_payloads,
        files_path=inputs.files_path,
        analyses=analyses,
        artifact_payload_objects=inputs.artifact_payload_objects,
        files_payload=inputs.files_payload,
    )
    return _row_sources(scoped, files, load_errors)


def run_derived(
    inputs: TriageInputs,
    out_dir: Path,
    *,
    source_label: str,
    progress: Progress | None = None,
    catalog: Catalog | None = None,
    url_classes: UrlClasses | None = None,
    max_values: int = MAX_VALUES_PER_TABLE,
    memory_cap: int = MEMORY_CAP_BYTES,
) -> dict[str, object]:
    """Build the six tables of ``inputs`` into ``out_dir`` (see module doc); returns the summary."""
    started = time.monotonic()
    progress = progress or Progress()
    catalog = catalog or load_catalog()
    url_classes = url_classes or load_url_classes()
    plans = family_plans(catalog)
    collector = DerivedCollector(url_classes, max_values=max_values, memory_cap=memory_cap)
    files = FilesOutput(inputs.files_payload, inputs.files_path)
    load_errors: dict[str, str] = {}
    sources = _sources(inputs, files, load_errors)
    if files.load_error is not None:
        load_errors["files"] = files.load_error
    coverage: dict[str, dict[str, object]] = {kind: {"expected": None, "reached": 0, "error": True} for kind in load_errors}
    errors: dict[str, dict[str, object]] = {
        f"source:{kind}": {"count": 1, "message": f"읽기 실패: {message}"[:300]} for kind, message in load_errors.items()
    }
    scanned: dict[str, int] = {}
    tagged_rows: dict[str, int] = {}
    untabled: dict[str, int] = {}
    for position, source in enumerate(sources):
        progress.check_cancel()
        progress.begin(source.kind, position, len(sources))
        family_cache: dict[str, FamilyPlan | None] = {}
        count = 0
        reached = 0
        hits = 0
        failed = False
        try:
            for index, row in source.rows():
                count += 1
                reached = max(reached, index + 1)
                if count % CANCEL_CHECK_EVERY == 0:
                    progress.check_cancel()
                    progress.rows(source.kind, count)
                if not isinstance(row, Mapping):
                    continue
                if source.collection == "files":
                    details: Mapping[str, object] = row
                    artifact_type = "file"
                else:
                    raw_details = row.get("details")
                    details = raw_details if isinstance(raw_details, Mapping) else {}
                    artifact_type = str(row.get("artifact_type") or "")
                if artifact_type in family_cache:
                    plan = family_cache[artifact_type]
                else:
                    family_id = "file" if source.collection == "files" else catalog.family_for(artifact_type, source.source_kind)
                    plan = plans.get(family_id) if family_id else None
                    family_cache[artifact_type] = plan
                if plan is None or not plan.columns:
                    continue
                moment: dt.datetime | None = None
                timed = False
                row_hit = False
                for column in plan.columns:
                    if column.when and not _matches(details, column):
                        continue
                    hit = read_column(details, column.candidates)
                    if hit is None:
                        continue
                    if not column.table:
                        untabled[column.semantic] = untabled.get(column.semantic, 0) + 1
                        continue
                    if not timed:
                        moment, timed = _row_time(details, plan), True
                    for item in iter_items(hit[0], column.semantic):
                        if collector.add(
                            column.table,
                            column.semantic,
                            item,
                            kind=source.kind,
                            family=plan.family,
                            record_index=index,
                            field=column.key,
                            artifact_type=artifact_type,
                            moment=moment,
                            details=details,
                        ):
                            row_hit = True
                if row_hit:
                    hits += 1
        except (OSError, ValueError) as exc:  # unreadable / truncated stream: the tail of this source is unread
            failed = True
            errors.setdefault(f"source:{source.kind}", {"count": 1, "message": f"읽기 실패: {exc}"[:300]})
        scanned[source.kind] = count
        tagged_rows[source.kind] = hits
        coverage[source.kind] = {"expected": source.total, "reached": reached, "error": failed}
        progress.rows(source.kind, count)
    progress.check_cancel()
    return _write_outputs(
        out_dir,
        collector=collector,
        catalog=catalog,
        url_classes=url_classes,
        source_label=source_label,
        scanned=scanned,
        tagged_rows=tagged_rows,
        untabled=untabled,
        coverage=coverage,
        errors=errors,
        elapsed=time.monotonic() - started,
        analysis_kinds={source.kind: source.source_kind for source in sources if source.collection == "analysis"},
    )


INDEX_VERSION = "derived-index-v1"


def search_text(value: object, normalized: str) -> str:
    """Casefolded text a table search matches: the value, plus the normalised form when it differs."""
    shown = str(value or "").casefold()
    key = normalized.casefold()
    return shown if shown == key else f"{shown}\n{key}"


def paging_index(rows: Sequence[Mapping[str, object]]) -> dict[str, Any]:
    """Columnar paging index of a table (``<table>.index.json``); ``offsets`` / ``lengths`` are filled
    while the rows are written. ``kinds`` holds an index into ``kind_sets`` per row."""
    kind_sets: list[list[str]] = []
    set_ids: dict[tuple[str, ...], int] = {}
    kinds: list[int] = []
    for row in rows:
        key = tuple(dict(row["kinds"]))  # type: ignore[call-overload]
        if key not in set_ids:
            set_ids[key] = len(kind_sets)
            kind_sets.append(list(key))
        kinds.append(set_ids[key])
    return {
        "version": INDEX_VERSION,
        "rows": len(rows),
        "normalized": [row["normalized"] for row in rows],
        "search": [search_text(row["value"], str(row["normalized"])) for row in rows],
        "count": [row["count"] for row in rows],
        "first": [row["first_seen"] for row in rows],
        "last": [row["last_seen"] for row in rows],
        "kind_sets": kind_sets,
        "kinds": kinds,
        "offsets": [],
        "lengths": [],
    }


def _write_outputs(
    out_dir: Path,
    *,
    collector: DerivedCollector,
    catalog: Catalog,
    url_classes: UrlClasses,
    source_label: str,
    scanned: Mapping[str, int],
    tagged_rows: Mapping[str, int],
    untabled: Mapping[str, int],
    coverage: Mapping[str, Mapping[str, object]],
    errors: Mapping[str, object],
    elapsed: float,
    analysis_kinds: Mapping[str, str] | None = None,
) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    tables: dict[str, dict[str, object]] = {}
    for table in TABLES:
        rows = collector.rows(table)
        by_kind: dict[str, int] = {}
        by_semantic: dict[str, int] = {}
        for row in rows:
            for kind, count in dict(row["kinds"]).items():  # type: ignore[call-overload]
                by_kind[kind] = by_kind.get(kind, 0) + int(count)
            for semantic, count in dict(row["semantics"]).items():  # type: ignore[call-overload]
                by_semantic[semantic] = by_semantic.get(semantic, 0) + int(count)

        index = paging_index(rows)

        def write_rows(handle, rows: list[dict[str, object]] = rows, index: dict[str, Any] = index) -> None:
            offset = 0
            for row in rows:
                line = json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=json_default) + "\n"
                size = len(line.encode("utf-8"))
                handle.write(line)
                index["offsets"].append(offset)
                index["lengths"].append(size)
                offset += size

        def write_index(handle, index: dict[str, Any] = index) -> None:
            handle.write(json.dumps(index, ensure_ascii=False, separators=(",", ":"), default=json_default))

        _write_atomic(out_dir / f"{table}.jsonl", write_rows)
        _write_atomic(out_dir / f"{table}{INDEX_SUFFIX}", write_index)
        state = collector.tables[table]
        tables[table] = {
            "label": TABLE_LABELS[table],
            "rows": len(rows),
            "occurrences": state.occurrences,
            "capped": state.capped,
            "cap_reason": state.cap_reason,
            "dropped_values": state.dropped_values,
            "by_kind": dict(sorted(by_kind.items(), key=lambda item: (-item[1], item[0]))),
            "by_semantic": dict(sorted(by_semantic.items())),
        }
        if table == "urls":
            classes: dict[str, int] = {}
            for row in rows:
                if row.get("url_class"):
                    classes[str(row["url_class"])] = classes.get(str(row["url_class"]), 0) + 1
            tables[table]["by_class"] = dict(sorted(classes.items()))
        # The written table is no longer needed in memory (lowers the peak for the larger tables after it).
        state.entries.clear()
        del rows, index
    coverage_summary = coverage_block(coverage)
    summary: dict[str, object] = {
        "version": SUMMARY_VERSION,
        "status": "completed" if coverage_summary["complete"] else "partial",
        "coverage": coverage_summary,
        "source": source_label,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "catalog_version": catalog.version,
        "url_classes": {
            "version": url_classes.version,
            "labels": dict(url_classes.labels),
            "sources": {key: list(value) for key, value in url_classes.sources.items()},
        },
        "tables": tables,
        "untabled_semantics": dict(sorted(untabled.items())),
        # ``analysis:<id>`` row source -> its analysis kind (the console opens that analysis node).
        "analysis_kinds": dict(sorted((analysis_kinds or {}).items())),
        "rows_scanned": dict(scanned),
        "rows_with_values": dict(tagged_rows),
        "errors": dict(errors),
        "caps": {
            "max_values_per_table": collector.max_values,
            "memory_cap_bytes": collector.memory_cap,
            "estimated_bytes": collector.estimated_bytes,
            "max_samples": MAX_SAMPLES,
        },
        "elapsed_s": round(elapsed, 3),
        "limitation": (
            "통합 보기는 카탈로그 의미 태그가 붙은 열의 값을 모은 표입니다. 같은 값이 같은 사람·장치라는 뜻은 아니며, "
            "자격 증명은 가린 값·길이·SHA-256만 저장합니다. 표본은 값마다 최대 20행입니다."
        ),
    }

    def write_summary(handle) -> None:
        handle.write(json.dumps(summary, ensure_ascii=False, indent=2, default=json_default) + "\n")

    _write_atomic(out_dir / SUMMARY_FILE_NAME, write_summary)
    return summary
