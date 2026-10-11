"""Run-output locator <-> case-DB row resolution for console review marks.

The console grid addresses rows by the run-output locator the paged run APIs
emit (``/candidates/3``, ``/results/2``, ``/events/7``, ``/indicators/1``,
``artifacts_<kind>`` + ``/artifacts/12``). Review marks live in the run's
case DB (``review_mark``), keyed by ``target_type`` + ``target_id`` (the case
DB row id). The case DB import keeps the run-output order:

* ``file_record`` / ``event`` / ``indexed_document`` (``source_type =
  'document'``) rows are inserted in output order, so ``id - first_id`` is the
  output ordinal (the same convention ``core/search_fts.py`` uses);
* ``artifact`` rows from per-kind outputs carry ``source_locator``
  (``output_name`` + ``row_index``) in ``data_json``, inserted in
  ``(output_name, row_index)`` order;
* indicator rows carry ``details.source_index`` (+ ``coverage_status`` for
  IOC scanner hits).

Lookups are point queries (plus a bisection for artifacts); nothing here
scans the large tables per row.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path

from ...core.case_db.review import load_review_target_match
from ...core.json_stream import JsonStreamError, iter_array_items
from ...core.run.persist import CASE_DB_FILE_NAME, run_case_id

ARTIFACT_LOCATOR_KEY = "source_locator"
INDICATOR_PARSER_NAME = "rapidtriage-indicators"
SCANNER_COVERAGE = "local-rule-ioc-scanner"
LOCATOR_COLLECTIONS = ("files", "docs", "timeline", "indicators", "artifacts")
# Search-hit sources -> grid collection.
SOURCE_ALIASES = {
    "documents": "docs",
    "docs-index": "docs",
    "web": "artifacts",
    "files": "files",
    "docs": "docs",
    "timeline": "timeline",
    "indicators": "indicators",
    "artifacts": "artifacts",
}


def canonical_run_case(summary: Mapping[str, object], run_id: str) -> tuple[Path, str]:
    """The run's canonical case DB path and case id.

    The persist step builds ``<output_dir>/rapidtriage-case.db`` with case id
    ``run_case_id(output_dir)``; ``/case-db/ensure`` creates ``run-<run_id>``
    when no persisted case exists. Prefer an existing ``run-<run_id>`` case
    (older ensure calls), then the persisted case, else ``run-<run_id>``.
    """
    output_dir = Path(str(summary.get("output_dir") or "")).expanduser().resolve()
    database = output_dir / CASE_DB_FILE_NAME
    legacy = f"run-{run_id}"
    if not database.is_file():
        return database, legacy
    persisted = run_case_id(output_dir)
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return database, legacy
    try:
        rows = {
            str(row[0])
            for row in connection.execute(
                "SELECT case_id FROM case_record WHERE case_id IN (?, ?)", (legacy, persisted)
            )
        }
    except sqlite3.Error:
        rows = set()
    finally:
        connection.close()
    if legacy in rows:
        return database, legacy
    if persisted in rows:
        return database, persisted
    return database, legacy


def normalize_collection(collection: str, kind: str = "") -> tuple[str, str]:
    """``artifacts:<kind>`` / search sources -> (collection, kind)."""
    value = collection.strip()
    if value.startswith("artifacts:"):
        return "artifacts", value.split(":", 1)[1]
    if value == "web":
        return "artifacts", kind or "browser"
    return SOURCE_ALIASES.get(value, value), kind


def _ordinal(locator: str, prefix: str) -> int | None:
    if not locator.startswith(prefix):
        return None
    tail = locator[len(prefix) :]
    return int(tail) if tail.isdigit() else None


def _stream_rows(path: Path | None, member: str) -> Iterator[Mapping[str, object]]:
    if path is None or not path.is_file():
        return
    try:
        for row in iter_array_items(path, member):
            if isinstance(row, Mapping):
                yield row
    except (JsonStreamError, OSError):
        return


class RunLocatorIndex:
    """Resolves locators for one evidence source of one case (one request)."""

    def __init__(self, connection: sqlite3.Connection, case_id: str, outputs: Mapping[str, object]) -> None:
        self.connection = connection
        self.case_id = case_id
        self.outputs = outputs
        row = connection.execute(
            "SELECT id FROM evidence_source WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)
        ).fetchone()
        self.evidence_source_id = int(row[0]) if row is not None else None
        self._first: dict[str, int | None] = {}
        self._docs_results: list[str] | None = None
        self._docs_candidates: list[str] | None = None

    # -- helpers ------------------------------------------------------------

    def _output_path(self, name: str) -> Path | None:
        raw = self.outputs.get(name)
        return Path(str(raw)).expanduser() if raw else None

    def _first_id(self, table: str, extra: str = "", params: tuple[object, ...] = ()) -> int | None:
        key = f"{table}{extra}{params}"
        if key not in self._first:
            row = self.connection.execute(
                f"SELECT id FROM {table} WHERE evidence_source_id = ?{extra} ORDER BY id LIMIT 1",
                (self.evidence_source_id, *params),
            ).fetchone()
            self._first[key] = int(row[0]) if row is not None else None
        return self._first[key]

    def _exists(self, table: str, row_id: int, extra: str = "") -> bool:
        return (
            self.connection.execute(
                f"SELECT 1 FROM {table} WHERE id = ? AND evidence_source_id = ?{extra}",
                (row_id, self.evidence_source_id),
            ).fetchone()
            is not None
        )

    def _docs_lists(self) -> tuple[list[str], list[str]]:
        if self._docs_results is None or self._docs_candidates is None:
            docs = self._output_path("docs")
            self._docs_results = [str(row.get("path") or "") for row in _stream_rows(docs, "results")]
            self._docs_candidates = [str(row.get("path") or "") for row in _stream_rows(docs, "candidates")]
        return self._docs_results, self._docs_candidates

    def _artifact_key(self, row_id: int) -> tuple[str, int] | None:
        row = self.connection.execute(
            f"SELECT json_extract(data_json, '$.{ARTIFACT_LOCATOR_KEY}.output_name'), "
            f"json_extract(data_json, '$.{ARTIFACT_LOCATOR_KEY}.row_index') "
            "FROM artifact WHERE id = ? AND evidence_source_id = ?",
            (row_id, self.evidence_source_id),
        ).fetchone()
        if row is None or row[0] is None or row[1] is None:
            return None
        return str(row[0]), int(row[1])

    def _artifact_id(self, output_name: str, row_index: int) -> int | None:
        """Bisect the contiguous per-kind artifact block; scan as a fallback."""
        target = (output_name, row_index)
        lo = self._first_id("artifact", " AND parser_name != ?", (INDICATOR_PARSER_NAME,))
        last = self.connection.execute(
            "SELECT id FROM artifact WHERE evidence_source_id = ? AND parser_name != ? ORDER BY id DESC LIMIT 1",
            (self.evidence_source_id, INDICATOR_PARSER_NAME),
        ).fetchone()
        if lo is not None and last is not None:
            hi = int(last[0])
            while lo <= hi:
                mid = (lo + hi) // 2
                key = self._artifact_key(mid)
                if key is None:
                    break  # gap / foreign row: ordering assumption broken
                if key == target:
                    return mid
                if key < target:
                    lo = mid + 1
                else:
                    hi = mid - 1
            else:
                return None
        row = self.connection.execute(
            f"SELECT id FROM artifact WHERE evidence_source_id = ? "
            f"AND json_extract(data_json, '$.{ARTIFACT_LOCATOR_KEY}.output_name') = ? "
            f"AND json_extract(data_json, '$.{ARTIFACT_LOCATOR_KEY}.row_index') = ? LIMIT 1",
            (self.evidence_source_id, output_name, row_index),
        ).fetchone()
        return int(row[0]) if row is not None else None

    def _indicator_id(self, index: int, *, scanner: bool) -> int | None:
        first = self._first_id("artifact", " AND parser_name = ?", (INDICATOR_PARSER_NAME,))
        if first is None:
            return None
        operator = "=" if scanner else "!="
        row = self.connection.execute(
            "SELECT id FROM artifact WHERE id >= ? AND evidence_source_id = ? AND parser_name = ? "
            "AND json_extract(data_json, '$.details.source_index') = ? "
            f"AND COALESCE(json_extract(data_json, '$.details.coverage_status'), '') {operator} ? "
            "ORDER BY id LIMIT 1",
            (first, self.evidence_source_id, INDICATOR_PARSER_NAME, index, SCANNER_COVERAGE),
        ).fetchone()
        return int(row[0]) if row is not None else None

    # -- public -------------------------------------------------------------

    def resolve(self, collection: str, locator: str, kind: str = "") -> tuple[str, str] | None:
        """Run-output locator -> (target_type, target_id), or None."""
        if self.evidence_source_id is None:
            return None
        collection, kind = normalize_collection(collection, kind)
        if collection == "files":
            ordinal = _ordinal(locator, "/candidates/")
            first = self._first_id("file_record")
            if ordinal is None or first is None or not self._exists("file_record", first + ordinal):
                return None
            return "file_record", str(first + ordinal)
        if collection == "timeline":
            ordinal = _ordinal(locator, "/events/")
            first = self._first_id("event")
            if ordinal is None or first is None or not self._exists("event", first + ordinal):
                return None
            return "event", str(first + ordinal)
        if collection == "docs":
            index = _ordinal(locator, "/results/")
            if index is None:
                return None
            results, candidates = self._docs_lists()
            path = results[index] if index < len(results) else ""
            if not path or path not in candidates:
                return None
            first = self._first_id("indexed_document", " AND source_type = 'document'")
            row_id = None if first is None else first + candidates.index(path)
            if row_id is None or not self._exists("indexed_document", row_id, " AND source_type = 'document'"):
                return None
            return "indexed_document", str(row_id)
        if collection == "indicators":
            for prefix, scanner in (("/indicators/", False), ("/ioc_scanner_hits/", True)):
                index = _ordinal(locator, prefix)
                if index is not None:
                    row_id = self._indicator_id(index, scanner=scanner)
                    return ("artifact", str(row_id)) if row_id is not None else None
            return None
        if collection == "artifacts":
            row_index = _ordinal(locator, "/artifacts/")
            if row_index is None or not kind:
                return None
            row_id = self._artifact_id(f"artifacts_{kind}", row_index)
            return ("artifact", str(row_id)) if row_id is not None else None
        return None

    def locate(self, target_type: str, target_id: str) -> dict[str, str] | None:
        """(target_type, target_id) -> {collection, kind, locator}, or None."""
        if self.evidence_source_id is None or not target_id.isdigit():
            return None
        row_id = int(target_id)
        if target_type == "file_record":
            first = self._first_id("file_record")
            if first is None or not self._exists("file_record", row_id):
                return None
            return {"collection": "files", "kind": "", "locator": f"/candidates/{row_id - first}"}
        if target_type == "event":
            first = self._first_id("event")
            if first is None or not self._exists("event", row_id):
                return None
            return {"collection": "timeline", "kind": "", "locator": f"/events/{row_id - first}"}
        if target_type == "indexed_document":
            first = self._first_id("indexed_document", " AND source_type = 'document'")
            if first is None or not self._exists("indexed_document", row_id, " AND source_type = 'document'"):
                return None
            results, candidates = self._docs_lists()
            ordinal = row_id - first
            path = candidates[ordinal] if 0 <= ordinal < len(candidates) else ""
            if not path or path not in results:
                return None
            return {"collection": "docs", "kind": "", "locator": f"/results/{results.index(path)}"}
        if target_type == "artifact":
            row = self.connection.execute(
                "SELECT parser_name, data_json FROM artifact WHERE id = ? AND evidence_source_id = ?",
                (row_id, self.evidence_source_id),
            ).fetchone()
            if row is None:
                return None
            try:
                stored = json.loads(str(row[1] or "{}"))
            except json.JSONDecodeError:
                return None
            if not isinstance(stored, Mapping):
                return None
            locator = stored.get(ARTIFACT_LOCATOR_KEY)
            if isinstance(locator, Mapping) and locator.get("output_name"):
                kind = str(locator["output_name"]).removeprefix("artifacts_")
                return {"collection": "artifacts", "kind": kind, "locator": f"/artifacts/{int(locator.get('row_index') or 0)}"}
            details = stored.get("details")
            if str(row[0]) == INDICATOR_PARSER_NAME and isinstance(details, Mapping):
                index = int(details.get("source_index") or 0)
                if details.get("coverage_status") == SCANNER_COVERAGE:
                    return {"collection": "indicators", "kind": "", "locator": f"/ioc_scanner_hits/{index}"}
                return {"collection": "indicators", "kind": "", "locator": f"/indicators/{index}"}
        return None


def split_batch_targets(
    targets: Iterable[Mapping[str, object]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Separate ``{target_type, target_id}`` targets from run-locator targets."""
    direct: list[dict[str, str]] = []
    located: list[dict[str, str]] = []
    for target in targets:
        if target.get("target_type") and target.get("target_id"):
            direct.append({"target_type": str(target["target_type"]), "target_id": str(target["target_id"])})
        else:
            located.append({key: str(value) for key, value in target.items() if value is not None})
    return direct, located


def review_map_entries(
    connection: sqlite3.Connection,
    case_id: str,
    outputs: Mapping[str, object],
    *,
    limit: int,
) -> tuple[list[dict[str, object]], bool]:
    """Every review mark of the case with its run-output locator (when known)."""
    index = RunLocatorIndex(connection, case_id, outputs)
    rows = connection.execute(
        "SELECT citation_id, target_type, target_id, status, tags_json, note, include_in_report, updated_at "
        "FROM review_mark WHERE case_id = ? ORDER BY updated_at DESC, id DESC LIMIT ?",
        (case_id, limit + 1),
    ).fetchall()
    truncated = len(rows) > limit
    entries: list[dict[str, object]] = []
    for row in rows[:limit]:
        try:
            tags = json.loads(str(row[4] or "[]"))
        except json.JSONDecodeError:
            tags = []
        target_type, target_id = str(row[1]), str(row[2])
        entry: dict[str, object] = {
            "citation_id": str(row[0]),
            "target_type": target_type,
            "target_id": target_id,
            "status": str(row[3]),
            "tags": [str(tag) for tag in tags] if isinstance(tags, list) else [],
            "note": str(row[5] or ""),
            "include_in_report": bool(row[6]),
            "updated_at": str(row[7] or ""),
            "collection": "",
            "kind": "",
            "locator": "",
        }
        location = index.locate(target_type, target_id)
        if location is not None:
            entry.update(location)
        match = load_review_target_match(connection, case_id, target_type=target_type, target_id=target_id)
        if match is not None:
            entry["title"] = str(match.get("title") or "")
            entry["path"] = str(match.get("path") or "")
            entry["preview"] = str(match.get("preview") or "")
            entry["timestamp"] = str(match.get("timestamp") or "")
            entry["target_kind"] = str(match.get("kind") or "")
        entries.append(entry)
    return entries, truncated
