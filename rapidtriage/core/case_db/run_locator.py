"""Run-output locator <-> case-DB row resolution for review marks.

The console grid addresses rows by the run-output locator the paged run APIs
emit (``/candidates/3`` -- files and docs --, ``/results/2``, ``/events/7``, ``/indicators/1``,
``artifacts_<kind>`` + ``/artifacts/12``). Review marks live in the run's
case DB (``review_mark``), keyed by ``target_type`` + ``target_id`` (the case
DB row id). The case DB import keeps the run-output order:

* ``file_record`` / ``event`` / ``indexed_document`` (``source_type =
  'document'``) rows are inserted in output order, so ``id - first_id`` is the
  output ordinal (the same convention ``core/search_fts.py`` uses);
* files ``/inventory/<n>`` (parser-quality r2): the import appends inventory
  rows after the candidates but skips one whose path is already imported
  (also a candidate), so inventory ordinals do not map to ids. They resolve
  by PATH (``normalized_path``, indexed): the candidate's row when that path
  is a candidate, else the inventory's own row;
* ``artifact`` rows from per-kind outputs carry ``source_locator``
  (``output_name`` + ``row_index``) in ``data_json``, inserted in
  ``(output_name, row_index)`` order;
* indicator rows carry ``details.source_index`` (+ ``coverage_status`` for
  IOC scanner hits).

Lookups are point queries (plus a bisection for artifacts); nothing here
scans the large tables per row.

:func:`location_source` maps a located row back to the run output file and
JSON pointer a case bookmark cites, so review marks reach the submission
(report, manifest, bundle) and a replay (:mod:`core.review_carryover`).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path

from ..artifact_profiles import iter_artifact_output_row_views
from ..json_stream import JsonStreamError, iter_array_items
from ..run.persist import CASE_DB_FILE_NAME, legacy_run_case_ids, run_case_id
from .helpers import normalize_path_for_db

ARTIFACT_LOCATOR_KEY = "source_locator"
# Analysis-workbench result rows (plan P1 §3.3) are not imported into the case
# DB; review marks address them as ``analysis_row`` + ``<analysis_id>/<record_index>``.
ANALYSIS_ROW_TARGET = "analysis_row"
ANALYSIS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
INDICATOR_PARSER_NAME = "rapidtriage-indicators"
# A mark toggled back to its defaults (status ``unreviewed``, no note/tags,
# not in the report, unverified) is "cleared": the row stays in ``review_mark``
# (``review_mark_history`` keeps the audit trail) but the review board and the
# review tallies leave it out.
ACTIVE_MARK_SQL = (
    "NOT (status = 'unreviewed' AND include_in_report = 0 AND COALESCE(note, '') = '' "
    "AND COALESCE(tags_json, '[]') IN ('[]', '') "
    "AND COALESCE(verification_status, 'unverified') IN ('unverified', ''))"
)
SCANNER_COVERAGE = "local-rule-ioc-scanner"
LOCATOR_COLLECTIONS = ("files", "docs", "timeline", "indicators", "artifacts")
# Longest row ordinal a locator may carry (``/events/<n>``): far above any run's row count.
MAX_ORDINAL_DIGITS = 12
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
    (older ensure calls), then the persisted case, then a case persisted
    under an older id form (:func:`legacy_run_case_ids`, e.g.
    ``run-run-subset7``), else ``run-<run_id>``.
    """
    output_dir = Path(str(summary.get("output_dir") or "")).expanduser().resolve()
    database = output_dir / CASE_DB_FILE_NAME
    legacy = f"run-{run_id}"
    if not database.is_file():
        return database, legacy
    persisted = run_case_id(output_dir)
    older = legacy_run_case_ids(output_dir)
    wanted = (legacy, persisted, *older)
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return database, legacy
    try:
        rows = {
            str(row[0])
            for row in connection.execute(
                f"SELECT case_id FROM case_record WHERE case_id IN ({', '.join('?' for _ in wanted)})", wanted
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
    for case_id in older:
        if case_id in rows:
            return database, case_id
    return database, legacy


def normalize_collection(collection: str, kind: str = "") -> tuple[str, str]:
    """``artifacts:<kind>`` / search sources -> (collection, kind)."""
    value = collection.strip()
    if value.startswith("artifacts:"):
        return "artifacts", value.split(":", 1)[1]
    if value == "web":
        return "artifacts", kind or "browser"
    return SOURCE_ALIASES.get(value, value), kind


def parse_ordinal(text: str) -> int | None:
    """A row ordinal: ASCII decimal digits only, at most :data:`MAX_ORDINAL_DIGITS` of them.

    ``str.isdigit`` also accepts ``'²'`` (``int`` then raises) and ``'٣'`` (``int`` reads 3);
    an unbounded digit string can exceed ``int``'s conversion limit. Both are a malformed
    locator (``None``), never an exception.
    """
    if 0 < len(text) <= MAX_ORDINAL_DIGITS and text.isascii() and text.isdecimal():
        return int(text)
    return None


def _ordinal(locator: str, prefix: str) -> int | None:
    if not locator.startswith(prefix):
        return None
    return parse_ordinal(locator[len(prefix) :])


def _stream_rows(path: Path | None, member: str) -> Iterator[Mapping[str, object]]:
    if path is None or not path.is_file():
        return
    try:
        for row in iter_array_items(path, member):
            if isinstance(row, Mapping):
                yield row
    except (JsonStreamError, OSError):
        return


def _analysis_row_exists(output_dir: Path | None, analysis_id: str, record_index: int) -> bool:
    """The analysis exists under the run output dir and has that row (unchecked without output_dir)."""
    if not ANALYSIS_ID_RE.fullmatch(analysis_id) or record_index < 0:
        return False
    if output_dir is None:
        return False  # cannot prove the analysis belongs to this run
    state_path = output_dir / "analyses" / analysis_id / "analysis.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(state, Mapping) and record_index < int(state.get("row_count") or 0)


def _artifact_row_flags(path: Path | None) -> Iterator[bool]:
    """Per ``/artifacts/<n>`` position of a per-kind artifacts output: whether the import keeps it."""
    if path is None:
        return
    position = 0
    try:
        for row_index, _row, _varying in iter_artifact_output_row_views(path):
            while position < row_index:
                yield False
                position += 1
            yield True
            position += 1
    except (OSError, ValueError):
        return


class RunOutputRows:
    """Whether run-output locators name rows the case-DB import keeps -- without a case DB.

    The read-only counterpart of :meth:`RunLocatorIndex.resolve` for a run whose case DB is
    not built yet (a mark preview must not build it): the same locator forms, checked against
    the run output rows the import inserts (object rows; timeline rows with a timestamp).
    Each output list is read once per instance, however many locators are checked.
    """

    def __init__(self, outputs: Mapping[str, object], *, output_dir: Path | None = None) -> None:
        self.outputs = outputs
        self.output_dir = output_dir
        self._counts: dict[str, int] = {}
        self._flags: dict[str, bytearray] = {}
        self._docs: tuple[list[str], set[str]] | None = None

    def _path(self, name: str) -> Path | None:
        raw = self.outputs.get(name)
        return Path(str(raw)).expanduser() if raw else None

    def _items(self, name: str, member: str) -> Iterator[object]:
        path = self._path(name)
        if path is None or not path.is_file():
            return
        try:
            yield from iter_array_items(path, member)
        except (JsonStreamError, OSError):
            return

    def _count(self, key: str, rows: Callable[[], Iterable[object]]) -> int:
        if key not in self._counts:
            self._counts[key] = sum(1 for _ in rows())
        return self._counts[key]

    def _flag(self, key: str, flags: Callable[[], Iterable[bool]], index: int) -> bool:
        if key not in self._flags:
            self._flags[key] = bytearray(1 if flag else 0 for flag in flags())
        found = self._flags[key]
        return index < len(found) and found[index] == 1

    def exists(self, collection: str, locator: str, kind: str = "") -> bool:
        if collection.strip() == "analysis":
            record_index = _ordinal(locator, "/rows/")
            return record_index is not None and _analysis_row_exists(self.output_dir, kind, record_index)
        collection, kind = normalize_collection(collection, kind)
        if collection == "files":
            index = _ordinal(locator, "/inventory/")
            if index is not None:
                # Inventory positions count object rows (RunLocatorIndex._inventory_path); one with a path is kept.
                return self._flag(
                    "files/inventory",
                    lambda: (bool(row.get("path")) for row in _stream_rows(self._path("files"), "inventory")),
                    index,
                )
            ordinal = _ordinal(locator, "/candidates/")
            return ordinal is not None and ordinal < self._count(
                "files/candidates", lambda: _stream_rows(self._path("files"), "candidates")
            )
        if collection == "timeline":
            ordinal = _ordinal(locator, "/events/")
            return ordinal is not None and ordinal < self._count(
                "timeline/events",
                lambda: (row for row in _stream_rows(self._path("timeline"), "events") if row.get("timestamp")),
            )
        if collection == "docs":
            if self._docs is None:
                results = [str(row.get("path") or "") for row in _stream_rows(self._path("docs"), "results")]
                candidates = [str(row.get("path") or "") for row in _stream_rows(self._path("docs"), "candidates")]
                self._counts["docs/candidates"] = len(candidates)
                self._docs = (results, set(candidates))
            results, candidate_paths = self._docs
            ordinal = _ordinal(locator, "/candidates/")
            if ordinal is not None:
                return ordinal < self._counts["docs/candidates"]
            index = _ordinal(locator, "/results/")
            path = results[index] if index is not None and index < len(results) else ""
            return bool(path) and path in candidate_paths
        if collection == "indicators":
            for member in ("indicators", "ioc_scanner_hits"):
                index = _ordinal(locator, f"/{member}/")
                if index is not None:
                    # ``source_index`` counts every list item; the import keeps the objects.
                    return self._flag(
                        f"indicators/{member}",
                        lambda: (isinstance(item, Mapping) for item in self._items("indicators", member)),  # noqa: B023
                        index,
                    )
            return False
        if collection == "artifacts":
            row_index = _ordinal(locator, "/artifacts/")
            if row_index is None or not kind:
                return False
            name = f"artifacts_{kind}"
            return self._flag(name, lambda: _artifact_row_flags(self._path(name)), row_index)
        return False


class RunLocatorIndex:
    """Resolves locators for one evidence source of one case (one request)."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        case_id: str,
        outputs: Mapping[str, object],
        *,
        output_dir: Path | None = None,
    ) -> None:
        self.connection = connection
        self.case_id = case_id
        self.outputs = outputs
        self.output_dir = output_dir
        row = connection.execute(
            "SELECT id FROM evidence_source WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)
        ).fetchone()
        self.evidence_source_id = int(row[0]) if row is not None else None
        self._first: dict[str, int | None] = {}
        self._docs_results: list[str] | None = None
        self._docs_candidates: list[str] | None = None
        self._file_candidate_count: int | None = None

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

    def _inventory_path(self, index: int) -> str:
        """Path of files ``inventory[index]`` (streamed, stops at the row)."""
        if index < 0:
            return ""
        for position, row in enumerate(_stream_rows(self._output_path("files"), "inventory")):
            if position == index:
                return str(row.get("path") or "")
        return ""

    def _inventory_index(self, normalized_path: str) -> int | None:
        """First files ``inventory`` position whose path normalizes to ``normalized_path``."""
        for position, row in enumerate(_stream_rows(self._output_path("files"), "inventory")):
            if normalize_path_for_db(str(row.get("path") or "")) == normalized_path:
                return position
        return None

    def _candidate_count(self) -> int:
        """Files candidates imported before the inventory rows (the import skips non-objects)."""
        if self._file_candidate_count is None:
            self._file_candidate_count = sum(1 for _ in _stream_rows(self._output_path("files"), "candidates"))
        return self._file_candidate_count

    def _file_id_by_path(self, path: str) -> int | None:
        """Lowest ``file_record`` id with that path: the candidate's row before the inventory's."""
        if not path:
            return None
        row = self.connection.execute(
            "SELECT id FROM file_record WHERE case_id = ? AND normalized_path = ? AND evidence_source_id = ? "
            "ORDER BY id LIMIT 1",
            (self.case_id, normalize_path_for_db(path), self.evidence_source_id),
        ).fetchone()
        return int(row[0]) if row is not None else None

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

    def _analysis_row(self, analysis_id: str, record_index: int) -> bool:
        return _analysis_row_exists(self.output_dir, analysis_id, record_index)

    # -- public -------------------------------------------------------------

    def resolve(self, collection: str, locator: str, kind: str = "") -> tuple[str, str] | None:
        """Run-output locator -> (target_type, target_id), or None."""
        if collection.strip() == "analysis":
            record_index = _ordinal(locator, "/rows/")
            if record_index is None or not self._analysis_row(kind, record_index):
                return None
            return ANALYSIS_ROW_TARGET, f"{kind}/{record_index}"
        if self.evidence_source_id is None:
            return None
        collection, kind = normalize_collection(collection, kind)
        if collection == "files":
            inventory_index = _ordinal(locator, "/inventory/")
            if inventory_index is not None:
                row_id = self._file_id_by_path(self._inventory_path(inventory_index))
                return ("file_record", str(row_id)) if row_id is not None else None
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
            # ``/candidates/<n>``: the docs listing (every document, parser-quality r1);
            # ``/results/<n>``: the keyword hits (``/docs?matched=1``).
            results, candidates = self._docs_lists()
            ordinal = _ordinal(locator, "/candidates/")
            if ordinal is None:
                index = _ordinal(locator, "/results/")
                if index is None:
                    return None
                path = results[index] if index < len(results) else ""
                if not path or path not in candidates:
                    return None
                ordinal = candidates.index(path)
            elif ordinal >= len(candidates):
                return None
            first = self._first_id("indexed_document", " AND source_type = 'document'")
            row_id = None if first is None else first + ordinal
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
        if target_type == ANALYSIS_ROW_TARGET:
            analysis_id, _, index = target_id.partition("/")
            if not index.isdigit() or not ANALYSIS_ID_RE.fullmatch(analysis_id):
                return None
            return {"collection": "analysis", "kind": analysis_id, "locator": f"/rows/{index}"}
        if self.evidence_source_id is None or not target_id.isdigit():
            return None
        row_id = int(target_id)
        if target_type == "file_record":
            first = self._first_id("file_record")
            if first is None or not self._exists("file_record", row_id):
                return None
            ordinal = row_id - first
            if ordinal >= self._candidate_count():
                # An inventory-only row (appended after the candidates). A
                # row not found in the inventory (pre-r2 output, a DB built
                # without the files output) keeps the candidate ordinal.
                stored = self.connection.execute("SELECT normalized_path FROM file_record WHERE id = ?", (row_id,)).fetchone()
                index = self._inventory_index(str(stored[0] or "")) if stored is not None else None
                if index is not None:
                    return {"collection": "files", "kind": "", "locator": f"/inventory/{index}"}
            return {"collection": "files", "kind": "", "locator": f"/candidates/{ordinal}"}
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
            if not path:
                return None
            location = {"collection": "docs", "kind": "", "locator": f"/candidates/{ordinal}"}
            if path in results:
                location["results_locator"] = f"/results/{results.index(path)}"
            return location
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


def location_source(location: Mapping[str, object]) -> tuple[str, str] | None:
    """``{collection, kind, locator}`` -> (run output name, JSON pointer) of the cited row.

    The output name is the run summary ``outputs`` key (``artifacts_<kind>``
    for artifact rows); analysis-workbench rows have no run output JSON
    (``None``)."""
    collection = str(location.get("collection") or "")
    kind = str(location.get("kind") or "")
    locator = str(location.get("locator") or "")
    if not locator.startswith("/"):
        return None
    if collection == "artifacts":
        return (f"artifacts_{kind}", locator) if kind else None
    if collection in ("files", "docs", "timeline", "indicators"):
        return collection, locator
    return None
