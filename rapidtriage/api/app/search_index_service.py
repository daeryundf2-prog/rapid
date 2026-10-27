"""Run-level services of the search index API (plan search-2026-10-13 §3.2–3.3).

* index status (``none|building|ready|stale|corrupt|build-failed-swap``) for
  ``/search/index``, ``/runs``, ``/tree``;
* auto builds: full on run completion (``RunJobStore`` completion hook) and
  incremental after other analyses complete (``analyses`` completion hook);
* saved searches (case DB ``saved_search``, ``filters_json.search_v = 2``; their
  creation is also an ``audit_event`` ``search.saved.create``);
* history: ``<run>/search/history.sqlite`` table ``search_history`` (last
  ``HISTORY_KEEP`` searches), written off the event loop by one writer thread;
* review marks of the run (``review_map_entries``) for ``review:``/``tag:``
  filters and the rows' ``review`` overlay (``truncated`` past ``REVIEW_MARK_LIMIT``);
* the per-run concurrency limit (429); a slot is held until the worker
  thread really ends and is released in a ``finally``.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ...core.case_db.base import now_iso
from ...core.case_db.database import CaseDatabase, next_citation_id_for_connection
from ...core.jobs import RunJob, RunJobStore, run_output_dir
from ...core.search_hits import base_locator
from ...core.search_index.build import (
    SEARCH_INDEX_KIND,
    SWAP_FAILED_STATUS,
    read_index_meta,
    stale_reasons,
)
from ...core.search_index.schema import INDEX_FILE_NAME
from .analyses import ACTIVE_STATUSES, ANALYSIS_RUNNER, public_state, run_scope
from .helpers import get_job

LOGGER = logging.getLogger(__name__)

AUTO_INDEX_ENV = "RAPIDTRIAGE_SEARCH_AUTO_INDEX"
MAX_CONCURRENT_QUERIES = 4
SAVED_SEARCH_ACTION = "search.saved.create"
SAVED_SEARCH_VERSION = 2
REVIEW_MARK_LIMIT = 50_000
HISTORY_KEEP = 500
HISTORY_DIR = "search"
HISTORY_FILE = "history.sqlite"
CORRUPT_INDEX = "검색 색인을 읽을 수 없습니다({reason}). 처리 단계에서 색인을 다시 만드세요"
NOT_COMPLETED = "완료된 런이 아닙니다"
NO_INDEX = "검색 색인이 없습니다. 처리 단계에서 색인을 만드세요"
INDEX_BUSY = "이미 색인을 만드는 중입니다"
TOO_MANY = "검색이 너무 많이 실행 중입니다"
NO_CASE_DB = "케이스 DB가 없습니다. 먼저 케이스 DB를 만드세요(POST /api/runs/{run}/case-db/ensure)"
DUPLICATE_SAVED = "같은 이름의 저장 검색이 있습니다"
SAVED_NOT_FOUND = "저장 검색을 찾을 수 없습니다"


def auto_index_enabled() -> bool:
    return os.environ.get(AUTO_INDEX_ENV, "1").strip().lower() not in {"0", "false", "no", "off"}


# ---------------------------------------------------------------------------
# run scope / status
# ---------------------------------------------------------------------------


def completed_run(store: RunJobStore, run_id: str) -> tuple[RunJob, Path]:
    job = get_job(store, run_id)
    if job.summary is None or job.status not in {"completed", "failed"}:
        raise HTTPException(status_code=409, detail=NOT_COMPLETED)
    try:
        return job, run_output_dir(job.summary)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=NOT_COMPLETED) from exc


def index_path_of(job: RunJob) -> Path | None:
    if job.summary is None:
        return None
    try:
        return run_output_dir(job.summary) / INDEX_FILE_NAME
    except RuntimeError:
        return None


def search_index_available(job: RunJob) -> bool:
    """One ``stat`` (``GET /api/runs`` rows)."""
    path = index_path_of(job)
    return bool(path is not None and path.is_file())


def latest_build(output_dir: Path) -> dict[str, object] | None:
    return ANALYSIS_RUNNER.latest(output_dir, [SEARCH_INDEX_KIND])


def index_status(job: RunJob, *, include_reasons: bool = True) -> dict[str, Any]:
    """``GET …/search/index`` payload (also the tree's ``index_status``)."""
    payload: dict[str, Any] = {
        "status": "none",
        "build_id": None,
        "built_at": None,
        "index_version": None,
        "doc_count": 0,
        "by_domain": {},
        "db_bytes": 0,
        "analyses_indexed": [],
        "tokenizer": None,
        "index_tokenizer": None,
        "tz": None,
        "building": None,
    }
    if job.summary is None:
        return payload
    try:
        output_dir = run_output_dir(job.summary)
    except RuntimeError:
        return payload
    path = output_dir / INDEX_FILE_NAME
    meta, unreadable = read_index_meta(path)
    latest = latest_build(output_dir)
    if latest is not None:
        payload["last_build"] = public_state(latest)
        if latest.get("status") in ACTIVE_STATUSES:
            payload["building"] = public_state(latest)
    if meta is not None:
        summary = meta.get("summary") if isinstance(meta.get("summary"), Mapping) else {}
        payload.update(
            {
                "status": "ready",
                "build_id": meta.get("build_id"),
                "built_at": meta.get("built_at"),
                "updated_at": meta.get("updated_at"),
                "index_version": meta.get("index_version"),
                "doc_count": int(summary.get("doc_count") or 0),
                "row_count": int(summary.get("row_count") or 0),
                "by_domain": summary.get("by_domain") or {},
                "skipped": summary.get("skipped") or {},
                "db_bytes": path.stat().st_size if path.is_file() else 0,
                "analyses_indexed": meta.get("analyses_indexed") or [],
                "tokenizer": meta.get("tokenizer"),
                "index_tokenizer": meta.get("tokenizer"),
                "tz": meta.get("tz") or None,
            }
        )
        if include_reasons:
            reasons = stale_reasons(meta, job.summary, output_dir, ANALYSIS_RUNNER.load_state)
            if reasons:
                payload["status"] = "stale"
                payload["stale_reason"] = reasons[0]
                payload["stale_reasons"] = reasons
    swap = _failed_swap(latest, meta)
    if swap is not None:
        # The old index (if any) still answers queries; the newest build could not replace it.
        payload["status"] = SWAP_FAILED_STATUS
        payload["swap_error"] = swap
    if meta is None and unreadable is not None:
        payload["status"] = "corrupt"
        payload["corrupt_reason"] = unreadable
    if payload["building"] is not None:
        payload["status"] = "building"
    return payload


def _failed_swap(latest: Mapping[str, object] | None, meta: Mapping[str, object] | None) -> str | None:
    if latest is None or latest.get("status") != "failed":
        return None
    summary = latest.get("summary") if isinstance(latest.get("summary"), Mapping) else {}
    if summary.get("status") != SWAP_FAILED_STATUS:
        return None
    if meta is not None and str(meta.get("updated_at") or meta.get("built_at") or "") > str(latest.get("finished_at") or ""):
        return None  # a later build or update replaced it
    return str(summary.get("swap_error") or latest.get("error") or "")


# ---------------------------------------------------------------------------
# builds
# ---------------------------------------------------------------------------


def submit_build(store: RunJobStore, run_id: str, options: Mapping[str, object], *, owner: object | None) -> dict[str, object]:
    scope = run_scope(store, run_id)  # 409 unless completed/failed
    latest = latest_build(scope.output_dir)
    if latest is not None and latest.get("status") in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail=INDEX_BUSY)
    try:
        return ANALYSIS_RUNNER.submit(scope, SEARCH_INDEX_KIND, options, owner=owner)
    except HTTPException as exc:
        if exc.status_code == 409:
            raise HTTPException(status_code=409, detail=INDEX_BUSY) from exc
        raise


def auto_build_on_completion(store: RunJobStore, job: RunJob, *, owner: object | None) -> None:
    """RunJobStore completion hook: a full index build for every completed run (best effort)."""
    if not auto_index_enabled() or job.summary is None:
        return
    try:
        submit_build(store, job.run_id, {"mode": "full"}, owner=owner)
    except HTTPException as exc:
        LOGGER.info("search index auto build skipped for %s: %s", job.run_id, exc.detail)
    except Exception:  # never fail the run because of the index
        LOGGER.exception("search index auto build failed to start for %s", job.run_id)


def auto_incremental_after_analysis(context: Any) -> None:
    """Analysis completion hook: index the new rows when the run already has an index."""
    spec = getattr(context, "spec", None)
    if not auto_index_enabled() or spec is None or spec.kind == SEARCH_INDEX_KIND:
        return
    scope = context.scope
    if not (scope.output_dir / INDEX_FILE_NAME).is_file():
        return
    latest = latest_build(scope.output_dir)
    if latest is not None and latest.get("status") in ACTIVE_STATUSES:
        return  # the running build reads finished analyses itself; stale detection covers the rest
    analysis_id = str(context.state.get("analysis_id") or "")
    try:
        ANALYSIS_RUNNER.submit(scope, SEARCH_INDEX_KIND, {"mode": "incremental", "analysis_ids": [analysis_id]}, owner=context.owner)
    except HTTPException as exc:
        LOGGER.info("search index incremental update skipped for %s: %s", analysis_id, exc.detail)
    except Exception:
        LOGGER.exception("search index incremental update failed to start for %s", analysis_id)


# ---------------------------------------------------------------------------
# concurrency
# ---------------------------------------------------------------------------


class QuerySlot:
    """One of a run's query slots. ``release`` is idempotent; ``claim`` marks the worker as started."""

    def __init__(self, limiter: QueryLimiter, run_id: str) -> None:
        self.limiter = limiter
        self.run_id = run_id
        self._lock = threading.Lock()
        self.started = False
        self.released = False

    def claim(self) -> bool:
        """The worker thread starts (``False``: the slot was already given back, do not run)."""
        with self._lock:
            if self.released:
                return False
            self.started = True
            return True

    def release(self) -> None:
        with self._lock:
            if self.released:
                return
            self.released = True
        self.limiter._release(self.run_id)


class QueryLimiter:
    def __init__(self, limit: int = MAX_CONCURRENT_QUERIES) -> None:
        self.limit = limit
        self._lock = threading.Lock()
        self._active: dict[str, int] = {}

    def acquire(self, run_id: str) -> QuerySlot:
        """A slot or 429; the caller must ``release`` it in a ``finally``."""
        with self._lock:
            if self._active.get(run_id, 0) >= self.limit:
                raise HTTPException(status_code=429, detail=TOO_MANY)
            self._active[run_id] = self._active.get(run_id, 0) + 1
        return QuerySlot(self, run_id)

    def _release(self, run_id: str) -> None:
        with self._lock:
            remaining = self._active.get(run_id, 1) - 1
            if remaining <= 0:
                self._active.pop(run_id, None)
            else:
                self._active[run_id] = remaining

    def active(self, run_id: str) -> int:
        with self._lock:
            return self._active.get(run_id, 0)

    @contextmanager
    def slot(self, run_id: str) -> Iterator[QuerySlot]:
        held = self.acquire(run_id)
        try:
            yield held
        finally:
            held.release()


QUERY_LIMITER = QueryLimiter()


# ---------------------------------------------------------------------------
# case DB: review marks, saved searches, history
# ---------------------------------------------------------------------------


def run_case(job: RunJob, run_id: str) -> tuple[Path, str]:
    from .run_review import canonical_run_case

    assert job.summary is not None
    return canonical_run_case(job.summary, run_id)


def _case_exists(database: Path, case_id: str) -> bool:
    if not database.is_file():
        return False
    try:
        connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        return connection.execute("SELECT 1 FROM case_record WHERE case_id = ?", (case_id,)).fetchone() is not None
    except sqlite3.Error:
        return False
    finally:
        connection.close()


def artifact_summaries(job: RunJob, run_id: str, keys: Sequence[tuple[str, str]]) -> dict[tuple[str, str], str]:
    """The case DB's stored ``artifact_summary`` of one page of console-search artifact rows
    (``{(kind, locator): summary}``; empty without a case DB): v1's hit titles (R7 S2 confirmation #10)."""
    from .run_review import RunLocatorIndex

    if job.summary is None or not keys:
        return {}
    database, case_id = run_case(job, run_id)
    if not database.is_file():
        return {}
    outputs = job.summary.get("outputs")
    try:
        connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
        try:
            index = RunLocatorIndex(connection, case_id, outputs if isinstance(outputs, dict) else {}, output_dir=run_output_dir(job.summary))
            return index.artifact_summaries(keys)
        finally:
            connection.close()
    except sqlite3.Error as exc:
        LOGGER.warning("artifact summaries unavailable for %s: %s", run_id, exc)
        return {}


class ReviewMarks:
    """Review marks of the run's case DB, loaded at most once per request (``truncated`` past the limit)."""

    def __init__(self, job: RunJob, run_id: str) -> None:
        self.job = job
        self.run_id = run_id
        self._marks: list[dict[str, object]] | None = None
        self._loaded = False
        self.truncated = False

    def load(self) -> list[dict[str, object]] | None:
        if self._loaded:
            return self._marks
        self._loaded = True
        from .run_review import review_map_entries

        database, case_id = run_case(self.job, self.run_id)
        if not database.is_file() or self.job.summary is None:
            return None
        outputs = self.job.summary.get("outputs")
        try:
            connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            try:
                entries, truncated = review_map_entries(
                    connection,
                    case_id,
                    outputs if isinstance(outputs, dict) else {},
                    limit=REVIEW_MARK_LIMIT,
                    output_dir=run_output_dir(self.job.summary),
                )
            finally:
                connection.close()
        except sqlite3.Error as exc:
            LOGGER.warning("review marks unavailable for %s: %s", self.run_id, exc)
            return None
        self._marks = entries
        self.truncated = bool(truncated)
        return entries

    def apply_truncation(self, result: dict[str, object], *, uses_review: bool) -> None:
        """Never silently wrong: past ``REVIEW_MARK_LIMIT`` marks the response says so."""
        if not self.truncated:
            return
        message = f"리뷰 표시가 {REVIEW_MARK_LIMIT:,}건을 넘어 최근 {REVIEW_MARK_LIMIT:,}건만 반영했습니다"
        query = result.get("query") if isinstance(result.get("query"), dict) else {}
        parsed = query.get("parsed") if isinstance(query.get("parsed"), dict) else {}
        warnings = parsed.get("warnings")
        if isinstance(warnings, list) and message not in warnings:
            warnings.append(message)
        if uses_review:
            result["truncated"] = True
            result["truncated_reason"] = result.get("truncated_reason") or message

    def overlay(self, rows: list[dict[str, object]]) -> None:
        marks = self.load() or []
        if not marks:
            return
        by_key = {(str(mark.get("collection") or ""), str(mark.get("kind") or ""), str(mark.get("locator") or "")): mark for mark in marks}
        for row in rows:
            collection, kind, locator = str(row.get("collection") or ""), str(row.get("kind") or ""), str(row.get("locator") or "")
            # An archive entry row shows the mark of its archive record.
            mark = by_key.get((collection, kind, locator)) or by_key.get((collection, kind, base_locator(locator)))
            if mark is not None:
                row["review"] = {
                    "status": mark.get("status"),
                    "tags": mark.get("tags") or [],
                    "include_in_report": bool(mark.get("include_in_report")),
                    "citation_id": mark.get("citation_id"),
                }


# ---------------------------------------------------------------------------
# history (<run>/search/history.sqlite, written by one background thread)
# ---------------------------------------------------------------------------


class SearchHistory:
    """Search history of each run, written off the event loop and capped at ``HISTORY_KEEP`` rows.

    ``record`` only queues the entry; one writer thread drains the queue, one
    transaction per run directory, so a burst of searches costs one write.
    """

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="search-history")
        self._lock = threading.Lock()
        self._pending: dict[Path, list[tuple[str, str, str, str]]] = {}
        self._scheduled = False

    @staticmethod
    def path_for(output_dir: Path) -> Path:
        return Path(output_dir) / HISTORY_DIR / HISTORY_FILE

    def submit(self, task: Callable[[], None]) -> Future[None]:
        def guarded() -> None:
            try:
                task()
            except Exception:  # history is best effort: never fails a search
                LOGGER.exception("search history task failed")

        return self._executor.submit(guarded)

    def record(self, output_dir: Path, params: Mapping[str, object], *, truncated: bool) -> None:
        entry = (
            now_iso(),
            str(params.get("q") or ""),
            json.dumps(dict(params), ensure_ascii=False, sort_keys=True, default=str),
            "truncated" if truncated else "ok",
        )
        with self._lock:
            self._pending.setdefault(Path(output_dir), []).append(entry)
            if self._scheduled:
                return
            self._scheduled = True
        self.submit(self._drain)

    def flush(self, timeout: float = 30.0) -> None:
        """Wait for the writes queued so far (read-your-writes for ``GET …/history``)."""
        try:
            self._executor.submit(lambda: None).result(timeout=timeout)
        except Exception:
            LOGGER.warning("search history flush timed out")

    def _drain(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, {}
            self._scheduled = False
        for output_dir, entries in pending.items():
            self._write(output_dir, entries)

    def _write(self, output_dir: Path, entries: list[tuple[str, str, str, str]]) -> None:
        path = self.path_for(output_dir)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(str(path), timeout=10)
        except (OSError, sqlite3.Error) as exc:
            LOGGER.warning("search history not recorded in %s: %s", output_dir, exc)
            return
        try:
            with connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS search_history (id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, "
                    "q TEXT NOT NULL, params_json TEXT NOT NULL, result TEXT NOT NULL)"
                )
                connection.executemany(
                    "INSERT INTO search_history (at, actor, q, params_json, result) VALUES (?, 'local-user', ?, ?, ?)", entries
                )
                connection.execute(
                    "DELETE FROM search_history WHERE id <= (SELECT id FROM search_history ORDER BY id DESC LIMIT 1 OFFSET ?)",
                    (HISTORY_KEEP,),
                )
        except sqlite3.Error as exc:
            LOGGER.warning("search history not recorded in %s: %s", output_dir, exc)
        finally:
            connection.close()

    def read(self, output_dir: Path, limit: int) -> list[dict[str, object]]:
        path = self.path_for(output_dir)
        if not path.is_file():
            return []
        try:
            connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
        except sqlite3.Error:
            return []
        try:
            rows = connection.execute(
                "SELECT id, at, actor, params_json, result FROM search_history ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        except sqlite3.Error:
            return []
        finally:
            connection.close()
        history: list[dict[str, object]] = []
        for row_id, timestamp, actor, params_json, result in rows:
            try:
                params = json.loads(params_json or "{}")
            except ValueError:
                params = {}
            params = params if isinstance(params, dict) else {}
            history.append(
                {
                    "id": int(row_id),
                    "at": timestamp,
                    "actor": actor,
                    "q": params.get("q"),
                    "options": params.get("options") or {},
                    "sort": params.get("sort"),
                    "view": params.get("view"),
                    "total": params.get("total"),
                    "total_exact": params.get("total_exact"),
                    "elapsed_ms": params.get("elapsed_ms"),
                    "build_id": params.get("build_id"),
                    "saved_id": params.get("saved_id"),
                    "result": result,
                }
            )
        return history


SEARCH_HISTORY = SearchHistory()


def search_history(job: RunJob, limit: int) -> list[dict[str, object]]:
    if job.summary is None:
        return []
    try:
        output_dir = run_output_dir(job.summary)
    except RuntimeError:
        return []
    SEARCH_HISTORY.flush()
    return SEARCH_HISTORY.read(output_dir, limit)


def _saved_payload(row: sqlite3.Row) -> dict[str, object] | None:
    try:
        filters = json.loads(row["filters_json"] or "{}")
    except ValueError:
        return None
    if not isinstance(filters, dict) or filters.get("search_v") != SAVED_SEARCH_VERSION:
        return None
    return {
        "id": int(row["id"]),
        "citation_id": row["citation_id"],
        "name": row["name"],
        "q": filters.get("q") or "",
        "options": filters.get("options") or {},
        "sort": filters.get("sort") or "relevance",
        "view": filters.get("view") or "rows",
        "last_count": filters.get("last_count"),
        "last_count_exact": filters.get("last_count_exact"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_run_at": row["last_run_at"] or None,
    }


@contextmanager
def _case_connection(job: RunJob, run_id: str, *, write: bool) -> Iterator[tuple[sqlite3.Connection, str] | None]:
    database, case_id = run_case(job, run_id)
    if not _case_exists(database, case_id):
        if write:
            raise HTTPException(status_code=409, detail=NO_CASE_DB)
        yield None
        return
    if write:
        with CaseDatabase(database).connect() as connection:
            yield connection, case_id
        return
    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        yield connection, case_id
    finally:
        connection.close()


def list_saved(job: RunJob, run_id: str) -> list[dict[str, object]]:
    with _case_connection(job, run_id, write=False) as handle:
        if handle is None:
            return []
        connection, case_id = handle
        try:
            rows = connection.execute("SELECT * FROM saved_search WHERE case_id = ? ORDER BY updated_at DESC, id DESC", (case_id,)).fetchall()
        except sqlite3.Error:
            return []
    return [payload for payload in (_saved_payload(row) for row in rows) if payload is not None]


def get_saved(job: RunJob, run_id: str, saved_id: int) -> dict[str, object]:
    with _case_connection(job, run_id, write=False) as handle:
        row = None
        if handle is not None:
            connection, case_id = handle
            row = connection.execute("SELECT * FROM saved_search WHERE case_id = ? AND id = ?", (case_id, saved_id)).fetchone()
    payload = _saved_payload(row) if row is not None else None
    if payload is None:
        raise HTTPException(status_code=404, detail=SAVED_NOT_FOUND)
    return payload


def _filters(body: Mapping[str, object], previous: Mapping[str, object] | None = None) -> dict[str, object]:
    filters = {
        "q": body.get("q"),
        "options": body.get("options") or {},
        "sort": body.get("sort") or "relevance",
        "view": body.get("view") or "rows",
        "search_v": SAVED_SEARCH_VERSION,
    }
    if previous:
        for key in ("last_count", "last_count_exact"):
            if key in previous:
                filters[key] = previous[key]
    return filters


def create_saved(job: RunJob, run_id: str, body: Mapping[str, object]) -> dict[str, object]:
    name = str(body.get("name") or "").strip()
    with _case_connection(job, run_id, write=True) as handle:
        assert handle is not None
        connection, case_id = handle
        if connection.execute("SELECT 1 FROM saved_search WHERE case_id = ? AND name = ?", (case_id, name)).fetchone() is not None:
            raise HTTPException(status_code=400, detail=DUPLICATE_SAVED)
        timestamp = now_iso()
        citation_id = next_citation_id_for_connection(connection, case_id, "search")
        cursor = connection.execute(
            "INSERT INTO saved_search (citation_id, case_id, name, keywords_json, filters_json, created_by, created_at, updated_at, last_run_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                citation_id,
                case_id,
                name,
                json.dumps([body.get("q")], ensure_ascii=False),
                json.dumps(_filters(body), ensure_ascii=False, sort_keys=True),
                "web-ui",
                timestamp,
                timestamp,
                "",
            ),
        )
        saved_id = int(cursor.lastrowid or 0)
    try:
        CaseDatabase(database_path(job, run_id)).add_audit_event(
            case_id=case_id,
            action=SAVED_SEARCH_ACTION,
            target_type="saved_search",
            target_id=citation_id,
            actor="local-user",
            tool_name="rapidtriage-search",
            params_json=json.dumps(_filters(body), ensure_ascii=False, sort_keys=True, default=str),
            result="ok",
        )
    except (sqlite3.Error, OSError) as exc:
        LOGGER.warning("search.saved.create audit not recorded for %s: %s", run_id, exc)
    return get_saved(job, run_id, saved_id)


def database_path(job: RunJob, run_id: str) -> Path:
    database, _case_id = run_case(job, run_id)
    return database


def update_saved(job: RunJob, run_id: str, saved_id: int, body: Mapping[str, object]) -> dict[str, object]:
    current = get_saved(job, run_id, saved_id)
    name = str(body.get("name") or current["name"]).strip()
    with _case_connection(job, run_id, write=True) as handle:
        assert handle is not None
        connection, case_id = handle
        clash = connection.execute("SELECT id FROM saved_search WHERE case_id = ? AND name = ? AND id != ?", (case_id, name, saved_id)).fetchone()
        if clash is not None:
            raise HTTPException(status_code=400, detail=DUPLICATE_SAVED)
        merged = {"q": body.get("q") or current["q"], "options": body.get("options") if body.get("options") is not None else current["options"],
                  "sort": body.get("sort") or current["sort"], "view": body.get("view") or current["view"]}
        connection.execute(
            "UPDATE saved_search SET name = ?, keywords_json = ?, filters_json = ?, updated_at = ? WHERE case_id = ? AND id = ?",
            (
                name,
                json.dumps([merged["q"]], ensure_ascii=False),
                json.dumps(_filters(merged, current), ensure_ascii=False, sort_keys=True),
                now_iso(),
                case_id,
                saved_id,
            ),
        )
    return get_saved(job, run_id, saved_id)


def delete_saved(job: RunJob, run_id: str, saved_id: int) -> None:
    get_saved(job, run_id, saved_id)
    with _case_connection(job, run_id, write=True) as handle:
        assert handle is not None
        connection, case_id = handle
        connection.execute("DELETE FROM saved_search WHERE case_id = ? AND id = ?", (case_id, saved_id))


def record_saved_count(job: RunJob, run_id: str, saved_id: int, total: int, exact: bool) -> None:
    """After a query run from a saved search: remember its count (tree badge)."""
    try:
        current = get_saved(job, run_id, saved_id)
    except HTTPException:
        return
    try:
        with _case_connection(job, run_id, write=True) as handle:
            assert handle is not None
            connection, case_id = handle
            filters = _filters(current, {"last_count": total, "last_count_exact": exact})
            connection.execute(
                "UPDATE saved_search SET filters_json = ?, last_run_at = ? WHERE case_id = ? AND id = ?",
                (json.dumps(filters, ensure_ascii=False, sort_keys=True), now_iso(), case_id, saved_id),
            )
    except (HTTPException, sqlite3.Error) as exc:
        LOGGER.warning("saved search count not recorded: %s", exc)


def tree_search_node(job: RunJob, run_id: str) -> dict[str, Any]:
    """``/tree`` "검색 결과" node: index status + saved searches (with their last counts)."""
    status = index_status(job)
    SEARCH_HISTORY.flush()  # saved-search counts written by the background writer
    try:
        saved = list_saved(job, run_id)
    except HTTPException:
        saved = []
    return {
        "id": "search",
        "label": "검색 결과",
        "count": len(saved),
        "collection": "search",
        "index_status": {
            "status": status["status"],
            "build_id": status["build_id"],
            "doc_count": status["doc_count"],
            "stale_reason": status.get("stale_reason"),
        },
        "saved_searches": [{"id": item["id"], "name": item["name"], "q": item["q"], "last_count": item.get("last_count")} for item in saved],
    }
