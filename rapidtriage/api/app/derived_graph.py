"""연결 그래프 라이트 (plan r4 §2.3): one 통합 보기 value -> its original rows -> the other
identifier values on those rows, two hops, bounded.

The value's stored samples (at most ``derived.MAX_SAMPLES`` rows, spread over the families it was
seen in) are the first hop. Each sample row is read back from its output (one forward pass per
artifact kind, the files list in memory, an analysis' ``rows.jsonl``) and its tagged columns are
read with the very routine the derived pass uses (``core.derived.engine.collect_row``), so a
second-hop value is normalised exactly like the table it belongs to. Credentials stay masked
(the collector keeps only the masked value and its SHA-256 key).

The graph never holds more than ``max_nodes`` nodes (default and ceiling 200): value nodes are
kept by the number of rows they share with the centre, then by their table count; the rest are
dropped and reported (``truncated``, ``dropped_values``).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException

from ...core.derived.engine import (
    DerivedCollector,
    FamilyPlan,
    collect_row,
    family_plans,
)
from ...core.derived.url_classes import load_url_classes
from ...core.triage_rules.catalog import load_catalog
from .analyses import ANALYSIS_ID_PATTERN, ROWS_FILE_NAME, analyses_root
from .derived import TABLE_LABELS, TableIndex, locate_sample
from .jsonl_records import iter_jsonl_records

GRAPH_MAX_NODES = 200
GRAPH_MIN_NODES = 10
# Value nodes taken from one row (a row with hundreds of paths must not crowd out the others).
GRAPH_MAX_VALUES_PER_ROW = 40


@lru_cache(maxsize=1)
def _plans() -> dict[str, FamilyPlan]:
    return family_plans(load_catalog())


@lru_cache(maxsize=1)
def _url_classes():
    return load_url_classes()


def row_values(row: Mapping[str, object], sample: Mapping[str, object]) -> list[tuple[str, str, str, str]]:
    """``(table, normalized, shown value, semantic)`` of every tagged column value of one sample row."""
    family = str(sample.get("family") or "")
    plan = _plans().get(family)
    if plan is None or not plan.columns:
        return []
    kind = str(sample.get("kind") or "")
    if kind.startswith("files:"):
        details: Mapping[str, object] = row
        artifact_type = "file"
    else:
        raw = row.get("details")
        details = raw if isinstance(raw, Mapping) else {}
        artifact_type = str(row.get("artifact_type") or sample.get("artifact_type") or "")
    collector = DerivedCollector(_url_classes(), max_values=GRAPH_MAX_VALUES_PER_ROW * 6)
    record_index = sample.get("record_index")
    collect_row(
        collector,
        plan,
        details,
        kind=kind,
        record_index=int(record_index) if isinstance(record_index, int) else 0,
        artifact_type=artifact_type,
    )
    out: list[tuple[str, str, str, str]] = []
    for table, state in collector.tables.items():
        for key, entry in state.entries.items():
            semantic = max(entry.semantics, key=entry.semantics.__getitem__) if entry.semantics else ""
            out.append((table, key, entry.value, semantic))
    return out


RowReader = Callable[[str, Sequence[int]], Iterable[tuple[int, Mapping[str, object]]]]


def read_sample_rows(
    samples: Sequence[Mapping[str, object]],
    *,
    read_artifacts: RowReader,
    files_payload: Callable[[], Mapping[str, object]],
    output_dir: Path,
) -> dict[tuple[str, int], Mapping[str, object]]:
    """The sample rows keyed by ``(kind, record_index)`` (rows that cannot be read are absent)."""
    by_kind: dict[str, list[int]] = {}
    for sample in samples:
        index = sample.get("record_index")
        if isinstance(index, int) and not isinstance(index, bool) and index >= 0:
            by_kind.setdefault(str(sample.get("kind") or ""), []).append(index)
    found: dict[tuple[str, int], Mapping[str, object]] = {}
    for kind, indices in by_kind.items():
        wanted = set(indices)
        try:
            if kind.startswith("files:"):
                listing = files_payload().get(kind.removeprefix("files:"))
                rows = listing if isinstance(listing, list) else []
                for index in sorted(wanted):
                    if index < len(rows) and isinstance(rows[index], Mapping):
                        found[(kind, index)] = rows[index]
            elif kind.startswith("analysis:"):
                analysis_id = kind.removeprefix("analysis:")
                if not ANALYSIS_ID_PATTERN.fullmatch(analysis_id):
                    continue  # never a path outside the run's analyses folder
                path = analyses_root(output_dir) / analysis_id / ROWS_FILE_NAME
                last = max(wanted)
                for index, _offset, row, _line in iter_jsonl_records(path):
                    if index > last:
                        break
                    if index in wanted and isinstance(row, Mapping):
                        found[(kind, index)] = row
            elif kind:
                for index, row in read_artifacts(kind, sorted(wanted)):
                    found[(kind, index)] = row
        except (OSError, ValueError, KeyError, RuntimeError, HTTPException):
            continue  # an unreadable source just contributes no second hop
    return found


def _row_label(sample: Mapping[str, object]) -> str:
    return f"{sample.get('artifact_type') or sample.get('family') or sample.get('kind')} #{sample.get('record_index')}"


def build_graph(
    *,
    table: str,
    center: Mapping[str, object],
    rows: Mapping[tuple[str, int], Mapping[str, object]],
    indexes: Mapping[str, TableIndex | None],
    analysis_kinds: Mapping[str, object] | None = None,
    max_nodes: int = GRAPH_MAX_NODES,
) -> dict[str, object]:
    """Nodes / edges of the 2-hop graph around ``center`` (a ``value_rows`` row with raw samples)."""
    center_key = str(center.get("normalized") or "")
    center_id = f"v:{table}:{center_key}"
    nodes: list[dict[str, object]] = [
        {
            "id": center_id,
            "type": "value",
            "center": True,
            "table": table,
            "table_label": TABLE_LABELS.get(table, table),
            "normalized": center_key,
            "label": str(center.get("value") or center_key),
            "count": center.get("count"),
            "in_table": True,
        }
    ]
    edges: list[dict[str, str]] = []
    samples = [sample for sample in center.get("samples") or [] if isinstance(sample, Mapping)]
    row_ids: list[str] = []
    # value id -> (table, key, shown, semantic, linked row ids)
    values: dict[str, tuple[str, str, str, str, list[str]]] = {}
    rows_read = 0
    for sample in samples[: max(0, max_nodes - 1)]:
        kind = str(sample.get("kind") or "")
        index = sample.get("record_index")
        row_id = f"r:{kind}:{index}"
        if row_id in row_ids:
            continue
        row_ids.append(row_id)
        nodes.append(
            {
                "id": row_id,
                "type": "row",
                "kind": kind,
                "family": sample.get("family"),
                "field": sample.get("field"),
                "artifact_type": sample.get("artifact_type"),
                "record_index": index,
                "time": sample.get("time"),
                "label": _row_label(sample),
                **locate_sample(sample, analysis_kinds),
            }
        )
        edges.append({"source": center_id, "target": row_id})
        row = rows.get((kind, index)) if isinstance(index, int) else None
        if row is None:
            continue
        rows_read += 1
        taken = 0
        for value_table, key, shown, semantic in row_values(row, sample):
            if value_table == table and key == center_key:
                continue
            value_id = f"v:{value_table}:{key}"
            entry = values.get(value_id)
            if entry is None:
                if taken >= GRAPH_MAX_VALUES_PER_ROW:
                    continue
                entry = (value_table, key, shown, semantic, [])
                values[value_id] = entry
            if row_id not in entry[4]:
                entry[4].append(row_id)
                taken += 1

    def table_count(value_table: str, key: str) -> int | None:
        index = indexes.get(value_table)
        if index is None:
            return None
        position = index.position.get(key)
        return index.counts[position] if position is not None else None

    ranked = sorted(
        values.items(),
        key=lambda item: (-len(item[1][4]), -(table_count(item[1][0], item[1][1]) or 0), item[1][0], item[1][1]),
    )
    room = max(0, max_nodes - len(nodes))
    kept, dropped = ranked[:room], ranked[room:]
    for value_id, (value_table, key, shown, semantic, linked) in kept:
        count = table_count(value_table, key)
        nodes.append(
            {
                "id": value_id,
                "type": "value",
                "center": False,
                "table": value_table,
                "table_label": TABLE_LABELS.get(value_table, value_table),
                "normalized": key,
                "label": shown,
                "semantic": semantic,
                "count": count,
                # Only a value the table holds opens it (a capped table may have dropped it).
                "in_table": count is not None,
                "rows": len(linked),
            }
        )
        edges.extend({"source": row_id, "target": value_id} for row_id in linked)
    return {
        "center": center_id,
        "nodes": nodes,
        "edges": edges,
        "rows": len(row_ids),
        "rows_read": rows_read,
        "values": len(kept),
        "dropped_values": len(dropped),
        "truncated": bool(dropped),
        "max_nodes": max_nodes,
    }
