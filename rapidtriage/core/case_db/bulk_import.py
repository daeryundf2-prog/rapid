"""Batched run-output import into a fresh case DB (parser-quality r2).

The run persist step (``CaseDatabase(bulk_load=True)``) used to insert one
artifact per ``execute`` with the FTS insert trigger copying the full
``data_json`` into ``artifact_fts``'s own content table: 455 s and 5.5 GB on
run-subset8 (635k artifacts), half of it a second copy of the text.

For a DB created with the compressed artifact layout (see
``constants.ARTIFACT_FTS_COMPRESSED_SQL``) this module:

* assigns row ids itself (the ids AUTOINCREMENT would pick) so rows go in
  with ``executemany`` batches inside one transaction per table;
* stores ``data_json`` zlib-compressed (``schema.encode_artifact_data``);
* writes the NFC ``artifact_fts`` index rows directly (insert trigger dropped
  for the load, re-created afterwards), so nothing is decoded again;
* prepares rows (profile expansion, JSON, zlib) in a producer thread while
  the connection thread runs SQLite, which releases the GIL while stepping.

Row values, ids, citation ids and their order are the same as the per-row
path; only the artifact storage layout differs.
"""

from __future__ import annotations

import itertools
import json
import queue
import sqlite3
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path

from ..artifact_profiles import iter_artifact_output_row_views
from ..textnorm import normalize_nfc
from .base import now_iso
from .constants import ARTIFACT_FTS_COMPRESSED_INSERT_TRIGGER_SQL
from .fts import sync_fts_row_nfc
from .helpers import artifact_details, artifact_summary, artifact_title
from .schema import ARTIFACT_DATA_LOCATOR_KEY, encode_artifact_data

__all__ = [
    "BULK_IMPORT_BATCH_ROWS",
    "bulk_import_run_artifacts",
    "bulk_import_run_events",
    "next_autoincrement_id",
]

BULK_IMPORT_BATCH_ROWS = 2000
# Prepared batches buffered between the producer thread and the connection
# thread (bounded memory: a few batches of ~2.5 KB rows).
BULK_IMPORT_QUEUE_BATCHES = 4

_ARTIFACT_INSERT_SQL = """
    INSERT INTO artifact (
        id, citation_id, case_id, evidence_source_id, file_record_id, artifact_type, parser_name,
        parser_version, title, summary, data_json, confidence, created_at, data_blob, data_codec
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_ARTIFACT_FTS_INSERT_SQL = "INSERT INTO artifact_fts(rowid, title, summary, metadata) VALUES (?, ?, ?, ?)"
_EVENT_INSERT_SQL = """
    INSERT INTO event (
        id, citation_id, case_id, evidence_source_id, artifact_id, file_record_id, event_type, timestamp,
        timestamp_kind, timezone, action, target, description, source, confidence
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_DONE = object()


def next_autoincrement_id(connection: sqlite3.Connection, table: str) -> int:
    """The rowid AUTOINCREMENT assigns to the next insert into ``table``."""
    max_row = connection.execute(f"SELECT MAX(id) FROM {table}").fetchone()
    seq_row = connection.execute("SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)).fetchone()
    return max(int(max_row[0] or 0) if max_row else 0, int(seq_row[0] or 0) if seq_row else 0) + 1


def _threaded(items: Iterable[object], *, batch_rows: int) -> Iterator[list[object]]:
    """Yield ``items`` in batches produced by a background thread (order kept)."""
    channel: queue.Queue[object] = queue.Queue(maxsize=BULK_IMPORT_QUEUE_BATCHES)
    stop = threading.Event()

    def produce() -> None:
        try:
            batch: list[object] = []
            for item in items:
                if stop.is_set():
                    return
                batch.append(item)
                if len(batch) >= batch_rows:
                    channel.put(batch)
                    batch = []
            if batch:
                channel.put(batch)
            channel.put(_DONE)
        except BaseException as exc:  # handed to the connection thread
            channel.put(exc)

    worker = threading.Thread(target=produce, name="rapidtriage-case-db-bulk", daemon=True)
    worker.start()
    try:
        while True:
            item = channel.get()
            if item is _DONE:
                return
            if isinstance(item, BaseException):
                raise item
            yield item  # type: ignore[misc]
    finally:
        stop.set()
        # Unblock a producer waiting on a full queue, then let it finish.
        while worker.is_alive():
            try:
                channel.get_nowait()
            except queue.Empty:
                worker.join(timeout=0.05)


def _prepared_artifacts(
    outputs: Mapping[str, object],
    file_id_for: Callable[[str], int | None],
) -> Iterator[tuple[object, ...]]:
    """Per-row values of the run's artifact outputs, in import order."""
    for output_name, raw_path in sorted(outputs.items()):
        name = str(output_name)
        if not name.startswith("artifacts_"):
            continue
        try:
            views = iter_artifact_output_row_views(Path(str(raw_path)))
            first = next(views, None)
        except (OSError, ValueError):
            continue
        if first is None:
            continue
        for row_index, row, varying_row in itertools.chain((first,), views):
            artifact_type = str(row.get("artifact_type") or name.removeprefix("artifacts_"))
            details = artifact_details(row)
            title = artifact_title(row)
            summary = artifact_summary(row)
            stored = dict(varying_row)
            locator = {"output_name": name, "row_index": row_index}
            stored[ARTIFACT_DATA_LOCATOR_KEY] = locator
            data_json = json.dumps(stored, ensure_ascii=False, sort_keys=True, default=str)
            stub, blob, codec = encode_artifact_data(data_json, locator=locator)
            yield (
                name,
                int(row_index),
                file_id_for(str(row.get("path") or details.get("source_path") or "")),
                artifact_type,
                str(details.get("parser") or row.get("provider") or name),
                str(details.get("parser_version") or ""),
                title,
                summary,
                stub,
                now_iso(),
                blob,
                codec,
                normalize_nfc(title),
                normalize_nfc(summary),
                normalize_nfc(data_json),
            )


def bulk_import_run_artifacts(
    connection: sqlite3.Connection,
    citations: object,
    *,
    case_id: str,
    evidence_source_id: int,
    outputs: Mapping[str, object],
    file_id_for: Callable[[str], int | None],
    artifact_ids: dict[tuple[str, int], int],
    batch_rows: int = BULK_IMPORT_BATCH_ROWS,
) -> int:
    """Insert every ``artifacts_*`` output row (compressed layout only).

    ``citations`` is the caller's ``CitationAllocator`` (``next()``);
    ``artifact_ids`` receives ``(output_name, row_index) -> id`` for the
    timeline import.
    """
    next_id = next_autoincrement_id(connection, "artifact")
    count = 0
    connection.execute("DROP TRIGGER IF EXISTS artifact_fts_ai")
    for batch in _threaded(_prepared_artifacts(outputs, file_id_for), batch_rows=batch_rows):
        rows = []
        fts_rows = []
        for (
            name,
            row_index,
            file_record_id,
            artifact_type,
            parser_name,
            parser_version,
            title,
            summary,
            stub,
            created_at,
            blob,
            codec,
            fts_title,
            fts_summary,
            fts_metadata,
        ) in batch:  # type: ignore[misc]
            row_id = next_id
            next_id += 1
            rows.append(
                (
                    row_id,
                    citations.next(),  # type: ignore[attr-defined]
                    case_id,
                    evidence_source_id,
                    file_record_id,
                    artifact_type,
                    parser_name,
                    parser_version,
                    title,
                    summary,
                    stub,
                    None,
                    created_at,
                    blob,
                    codec,
                )
            )
            fts_rows.append((row_id, fts_title, fts_summary, fts_metadata))
            artifact_ids[(name, row_index)] = row_id
        connection.executemany(_ARTIFACT_INSERT_SQL, rows)
        connection.executemany(_ARTIFACT_FTS_INSERT_SQL, fts_rows)
        count += len(rows)
    connection.execute(ARTIFACT_FTS_COMPRESSED_INSERT_TRIGGER_SQL)
    return count


def bulk_import_run_events(
    connection: sqlite3.Connection,
    citations: object,
    *,
    case_id: str,
    evidence_source_id: int,
    rows: Iterable[object],
    file_id_for: Callable[[str], int | None],
    artifact_ids: Mapping[tuple[str, int], int],
    batch_rows: int = BULK_IMPORT_BATCH_ROWS,
) -> int:
    """Insert timeline events in ``executemany`` batches (same rows/ids as per-row)."""
    next_id = next_autoincrement_id(connection, "event")
    count = 0
    batch: list[tuple[object, ...]] = []
    nfc_fixups: list[tuple[int, dict[str, str]]] = []

    def flush() -> None:
        connection.executemany(_EVENT_INSERT_SQL, batch)
        for row_id, values in nfc_fixups:
            sync_fts_row_nfc(connection, "event_fts", row_id, values)
        batch.clear()
        nfc_fixups.clear()

    for row in rows:
        if not isinstance(row, Mapping):
            continue
        timestamp = str(row.get("timestamp") or "")
        if not timestamp:
            continue
        details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
        source_record = details.get("source_record") if isinstance(details.get("source_record"), Mapping) else {}
        artifact_id = None
        if source_record.get("output") and source_record.get("row_index") is not None:
            artifact_id = artifact_ids.get((str(source_record.get("output")), int(source_record.get("row_index") or 0)))
        event_path = str(row.get("path") or "")
        file_record_id = file_id_for(event_path) or file_id_for(
            str(details.get("target_path") or details.get("source_path") or "")
        )
        event_type = str(row.get("event_type") or "")
        summary = str(row.get("summary") or "")
        source = str(row.get("source") or "")
        row_id = next_id
        next_id += 1
        batch.append(
            (
                row_id,
                citations.next(),  # type: ignore[attr-defined]
                case_id,
                evidence_source_id,
                artifact_id,
                file_record_id,
                event_type,
                timestamp,
                str(row.get("timestamp_kind") or ""),
                str(row.get("timezone") or ""),
                event_type,
                event_path,
                summary,
                source,
                None,
            )
        )
        fts_values = {"event_type": event_type, "target": event_path, "description": summary, "source": source}
        if not all(value.isascii() for value in fts_values.values()):
            nfc_fixups.append((row_id, fts_values))
        count += 1
        if len(batch) >= batch_rows:
            flush()
    if batch:
        flush()
    return count
