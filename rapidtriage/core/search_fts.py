"""Indexed unified-search backend over the run-local case DB (SQLite FTS5).

The run pipeline's persist step builds ``<output_dir>/rapidtriage-case.db``
(see core/run/persist.py). When it exists, ``run_unified_search`` asks this
module for matches instead of rescanning every run output:

* candidates come from FTS5 ``MATCH`` over ``indexed_document_fts``,
  ``file_record_fts``, ``artifact_fts`` and ``event_fts`` in rowid order
  (= run output order), with ``sources``/``extension``/``path_contains``
  pushed into SQL where the table has the column;
* every candidate is re-verified with the scan matchers
  (``match_keywords``), so exact/stem/fuzzy/regex semantics stay the scan's;
  FTS only narrows candidates (token-prefix queries, P22 NFC on the query);
* rows map back to the scan's match schema (source, kind, path, title,
  preview, pointer, metadata) so the API and web UI render them unchanged.

Index limitation: FTS tokens are word-prefix based, so a keyword that only
occurs *inside* a word (``shell`` in ``powershell``) is not a candidate.
Regex patterns without a leading literal and keywords without word
characters fall back to a bounded rowid-order walk of the index tables.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path

from .case_db.schema import artifact_data_select_sql, artifact_row_data_json
from .docs import build_preview
from .json_stream import JsonStreamError, iter_array_items
from .run.persist import CASE_DB_FILE_NAME
from .search import (
    build_keyword_match_plan,
    build_search_match_metadata,
    is_known_good_search_match,
    is_simple_word,
    keyword_stems,
    match_keywords,
    normalize_document_extraction_error,
)
from .search_budget import SearchBudget, SourceScan
from .textnorm import normalize_nfc, normalize_search_text

ARTIFACT_SOURCE_LOCATOR_KEY = "source_locator"
INDICATOR_PARSER_NAME = "rapidtriage-indicators"
BROWSER_OUTPUT_NAME = "artifacts_browser"
FTS_SOURCE_ORDER = ("documents", "files", "artifacts", "indicators", "timeline")
# unicode61 (the case DB tokenizer) keeps letters and digits; ``_`` and
# punctuation separate tokens.
_FTS_TOKEN_RE = re.compile(r"[^\W_]+")
_REGEX_PREFIX_RE = re.compile(r"^(?:\^|\\b|\(\?[a-zA-Z]+\)|\(\?:|\()*")
_REGEX_QUANTIFIER_CHARS = "?*{"


class CaseIndexError(RuntimeError):
    """The run case DB cannot serve this query (caller falls back to scan)."""


def resolve_run_case_db(summary: Mapping[str, object]) -> Path | None:
    """The run-local case DB for ``summary`` when it exists on disk."""
    outputs = summary.get("outputs")
    candidates: list[Path] = []
    if isinstance(outputs, Mapping):
        if outputs.get("case_db"):
            candidates.append(Path(str(outputs["case_db"])))
        if outputs.get("summary"):
            candidates.append(Path(str(outputs["summary"])).parent / CASE_DB_FILE_NAME)
    if summary.get("output_dir"):
        candidates.append(Path(str(summary["output_dir"])) / CASE_DB_FILE_NAME)
    for candidate in candidates:
        try:
            if candidate.expanduser().is_file():
                return candidate.expanduser()
        except OSError:
            continue
    return None


# -- FTS query construction ---------------------------------------------------


def fts_tokens(text: str) -> list[str]:
    return _FTS_TOKEN_RE.findall(normalize_search_text(text))


def fts_prefix_term(tokens: Sequence[str]) -> str:
    """A phrase whose last token is a prefix: ``"c windows sys"*``."""
    return '"' + " ".join(token.replace('"', '""') for token in tokens) + '"*'


def keyword_candidate_term(keyword: str, *, mode: str, fuzzy_distance: int) -> str | None:
    """FTS expression that every row the scan matcher accepts must satisfy.

    ``None`` means the keyword cannot be narrowed by the index.
    """
    if mode == "regex":
        literal = regex_leading_literal(keyword)
        return fts_prefix_term([literal]) if literal else None
    tokens = fts_tokens(keyword)
    if not tokens:
        return None
    if is_simple_word(keyword):
        # Stems (``files`` -> ``file``) match whole tokens; the shortest stem
        # as a prefix covers every variant.
        stem = min(keyword_stems(keyword), key=len)
        stem_tokens = fts_tokens(stem) or tokens
        if mode == "fuzzy" and fuzzy_distance > 0:
            word = stem_tokens[0]
            keep = max(2, (len(word) + 1) // 2)
            return fts_prefix_term([word[:keep]])
        return fts_prefix_term(stem_tokens)
    return fts_prefix_term(tokens)


def regex_leading_literal(pattern: str) -> str | None:
    """The literal word a regex must start with (``\\bpowershell\\.exe`` ->
    ``powershell``), or None when the pattern has no fixed leading word."""
    if "|" in pattern:
        return None
    body = _REGEX_PREFIX_RE.sub("", normalize_nfc(pattern), count=1)
    match = re.match(r"[^\W_]{2,}", body)
    if not match:
        return None
    literal = match.group(0)
    following = body[match.end() : match.end() + 1]
    if following and following in _REGEX_QUANTIFIER_CHARS:
        literal = literal[:-1]
    tokens = fts_tokens(literal)
    return tokens[0] if tokens and len(tokens[0]) >= 2 else None


def regex_literal_prefix_problem(pattern: str) -> str | None:
    """Korean reason why ``pattern`` cannot run as an indexed regex search, or ``None``.

    The index narrows candidates by the word a regex starts with
    (:func:`regex_leading_literal`); a pattern without one would walk every
    indexed row and run the regex on each (minutes on a large case).
    """
    if regex_leading_literal(pattern) is not None:
        return None
    shown = pattern if len(pattern) <= 80 else pattern[:77] + "..."
    return (
        f"정규식 '{shown}'은(는) 고정된 단어로 시작하지 않아 검색할 수 없습니다. "
        "정규식 검색은 색인에서 정규식의 첫 단어(글자·숫자 2자 이상)로 후보 행을 먼저 좁힌 뒤 정규식을 확인합니다. "
        "첫 단어가 없는 정규식(예: '.*Update', '\\d{6}-\\d{7}', 'a|b')은 모든 행을 하나씩 확인해야 해 "
        "수 분이 걸릴 수 있으므로 허용하지 않습니다. 'Live.*Update'처럼 고정 단어로 시작하게 바꾸거나 "
        "정확히 일치(exact) 검색을 사용하세요."
    )


def build_candidate_query(keywords: Sequence[str], *, mode: str, fuzzy_distance: int) -> str | None:
    terms = []
    for keyword in keywords:
        term = keyword_candidate_term(keyword, mode=mode, fuzzy_distance=fuzzy_distance)
        if term is None:
            return None
        terms.append(term)
    return " OR ".join(dict.fromkeys(terms)) if terms else None


# -- result collection --------------------------------------------------------


class MatchCollector:
    """Applies extension/path filters and counts visible rows toward ``limit``."""

    def __init__(
        self,
        *,
        limit: int,
        extensions: set[str],
        path_fragment: str,
        hide_known_good: bool,
    ) -> None:
        self.limit = limit
        self.extensions = extensions
        self.path_fragment = path_fragment
        self.hide_known_good = hide_known_good
        self.matches: list[dict[str, object]] = []
        self.visible = 0

    @property
    def full(self) -> bool:
        return bool(self.limit) and self.visible >= self.limit

    def accepts_path(self, path: str) -> bool:
        if self.extensions and Path(path).suffix.lower() not in self.extensions:
            return False
        if self.path_fragment and self.path_fragment not in normalize_search_text(path):
            return False
        return True

    def add(self, match: dict[str, object]) -> bool:
        """Keep ``match``; True when it counts as a visible result."""
        if not self.accepts_path(str(match.get("path") or "")):
            return False
        self.matches.append(match)
        if self.hide_known_good and is_known_good_search_match(match):
            return False
        self.visible += 1
        return True


# Bytes of run-output rows kept in memory for ordinal lookups (all runs).
OUTPUT_ROW_CACHE_ENV = "RAPIDTRIAGE_SEARCH_ROW_CACHE_MB"
OUTPUT_ROW_CACHE_DEFAULT_MB = 256
OUTPUT_ROW_CACHE_MAX_ENTRIES = 16


def _output_row_cache_bytes() -> int:
    raw = os.environ.get(OUTPUT_ROW_CACHE_ENV, "").strip()
    try:
        megabytes = float(raw) if raw else OUTPUT_ROW_CACHE_DEFAULT_MB
    except ValueError:
        megabytes = OUTPUT_ROW_CACHE_DEFAULT_MB
    return max(0, int(megabytes * 1024 * 1024))


def output_stamp(path: Path) -> tuple[str, int, int] | None:
    """``(path, size, mtime_ns)``: the revision a cached lookup belongs to (``None`` when unreadable)."""
    try:
        stat = path.stat()
    except OSError:
        return None
    return (str(path), stat.st_size, stat.st_mtime_ns)


class OutputRowCache:
    """Bounded LRU of run-output lookups keyed by output revision (path, size, mtime).

    ``rows(path, member)`` keeps one array member (``files.json`` /
    ``docs.json`` ``candidates``) as compact JSON text per row, so an FTS
    hit's ordinal lookup no longer re-streams the output on every request;
    ``value(path, tag, build)`` keeps derived lookups (the docs result index,
    extraction errors). Entries are bounded by
    ``RAPIDTRIAGE_SEARCH_ROW_CACHE_MB`` (default 256; ``0`` disables) and
    :data:`OUTPUT_ROW_CACHE_MAX_ENTRIES`; an output larger than the byte
    budget is never cached (callers stream it). A rewritten output has
    another stamp, so its old entry only ages out.
    """

    def __init__(self, max_bytes: int | None = None, max_entries: int = OUTPUT_ROW_CACHE_MAX_ENTRIES) -> None:
        self._max_bytes = max_bytes
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._build_lock = threading.Lock()
        self._entries: OrderedDict[tuple[object, ...], tuple[object, int]] = OrderedDict()
        self.builds = 0

    @property
    def max_bytes(self) -> int:
        return _output_row_cache_bytes() if self._max_bytes is None else self._max_bytes

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def _get(self, key: tuple[object, ...]) -> object | None:
        with self._lock:
            found = self._entries.get(key)
            if found is None:
                return None
            self._entries.move_to_end(key)
            return found[0]

    def _put(self, key: tuple[object, ...], value: object, nbytes: int) -> None:
        budget = self.max_bytes
        if nbytes > budget:
            return
        with self._lock:
            self._entries[key] = (value, nbytes)
            self._entries.move_to_end(key)
            total = sum(size for _value, size in self._entries.values())
            while self._entries and (total > budget or len(self._entries) > self._max_entries):
                _key, (_value, size) = self._entries.popitem(last=False)
                total -= size

    def rows(self, path: Path, member: str) -> Sequence[str] | None:
        stamp = output_stamp(path)
        if stamp is None or stamp[1] > self.max_bytes:
            return None
        key = (*stamp, "rows", member)
        found = self._get(key)
        if found is not None:
            return found  # type: ignore[return-value]
        with self._build_lock:
            found = self._get(key)
            if found is not None:
                return found  # type: ignore[return-value]
            rows: list[str] = []
            nbytes = 0
            for row in OrdinalRows._stream(path, member):
                text = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                rows.append(text)
                nbytes += len(text) + 64
            self.builds += 1
            self._put(key, rows, nbytes)
            return rows

    def value(self, path: Path, tag: str, build: Callable[[], object], *, nbytes: Callable[[object], int]) -> object:
        stamp = output_stamp(path)
        if stamp is None:
            return build()
        key = (*stamp, "value", tag)
        found = self._get(key)
        if found is not None:
            return found
        value = build()
        self.builds += 1
        self._put(key, value, nbytes(value))
        return value


class OrdinalRows:
    """Forward-only lookup of run-output array rows by position.

    FTS hits arrive in rowid order (= output order), so one streaming pass
    over e.g. files.json ``candidates`` hydrates every hit's metadata.
    """

    def __init__(self, path: Path | None, member: str) -> None:
        self._rows: Iterator[object] = iter(())
        self._cached: Sequence[str] | None = None
        if path is not None and path.is_file():
            self._cached = OUTPUT_ROW_CACHE.rows(path, member)
            if self._cached is None:
                self._rows = self._stream(path, member)
        self._position = -1
        self._current: Mapping[str, object] | None = None

    @staticmethod
    def _stream(path: Path, member: str) -> Iterator[object]:
        try:
            for row in iter_array_items(path, member):
                if isinstance(row, Mapping):
                    yield row
        except (JsonStreamError, OSError):
            return

    def get(self, ordinal: int) -> Mapping[str, object] | None:
        if self._cached is not None:
            # Cached member: random access, one row parsed per lookup.
            if not 0 <= ordinal < len(self._cached):
                return None
            row = json.loads(self._cached[ordinal])
            return row if isinstance(row, Mapping) else None
        if ordinal < self._position:
            return None
        while self._position < ordinal:
            row = next(self._rows, None)
            if row is None:
                self._position = ordinal + 1
                self._current = None
                return None
            self._position += 1
            self._current = row
        return self._current


OUTPUT_ROW_CACHE = OutputRowCache()


def _output_path(outputs: Mapping[str, object], name: str) -> Path | None:
    raw = outputs.get(name)
    return Path(str(raw)).expanduser() if raw else None


def _ascii_fragment(path_fragment: str) -> str:
    return path_fragment if path_fragment and path_fragment.isascii() else ""


def _iter_rows(
    connection: sqlite3.Connection,
    sql: str,
    params: Sequence[object],
    scan: SourceScan,
) -> Iterator[sqlite3.Row]:
    try:
        cursor = connection.execute(sql, tuple(params))
    except sqlite3.OperationalError as exc:
        if not _interrupted(exc):
            raise
        scan.stopped = "budget"
        return
    try:
        for row in cursor:
            if not scan.tick():
                return
            yield row
    except sqlite3.OperationalError as exc:
        # The progress handler stopped SQLite itself at the budget (a long
        # FTS prefix merge, or a cold-disk walk between two rows).
        if not _interrupted(exc):
            raise
        scan.stopped = "budget"
    finally:
        cursor.close()


def _interrupted(exc: sqlite3.Error) -> bool:
    return "interrupt" in str(exc).lower()


# SQLite VM instructions between two budget checks (microseconds apart).
PROGRESS_HANDLER_STEPS = 4096


class _BudgetGuard:
    """SQLite progress handler: aborts the running statement once the current source's deadline passed."""

    def __init__(self) -> None:
        self.deadline: float | None = None

    def __call__(self) -> int:
        return 1 if self.deadline is not None and time.monotonic() >= self.deadline else 0


def _match_clause(fts_table: str, query: str | None) -> tuple[str, str, list[object]]:
    """FROM/WHERE pieces: FTS-driven when ``query`` is set, else a rowid walk."""
    if query is None:
        return "", "", []
    return f"{fts_table} f JOIN ", f"{fts_table} MATCH ? AND ", [query]


def fts_unified_matches(
    db_path: Path,
    outputs: Mapping[str, object],
    keywords: Sequence[str],
    *,
    search_options: Mapping[str, object],
    sources: set[str],
    extensions: set[str],
    path_fragment: str,
    hide_known_good: bool,
    include_ocr: bool,
    limit: int,
    budget: SearchBudget,
    ocr_search: Callable[[int, SourceScan], tuple[list[dict[str, object]], list[dict[str, str]]]] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, str]]]:
    """Unified-search matches from the case DB index.

    Returns ``(matches, document_errors, ocr_errors)``; ``matches`` holds at
    most ``limit`` visible rows (plus hidden known-good rows for the
    suppression profile), in scan source order.
    """
    mode = str(search_options.get("search_mode") or "exact")
    fuzzy_distance = int(search_options.get("fuzzy_distance") or 0)
    query = build_candidate_query(keywords, mode=mode, fuzzy_distance=fuzzy_distance)
    plan = build_keyword_match_plan(keywords, search_options=search_options)
    collector = MatchCollector(
        limit=limit,
        extensions=extensions,
        path_fragment=path_fragment,
        hide_known_good=hide_known_good,
    )
    context = _SearchContext(
        outputs=outputs,
        keywords=keywords,
        plan=plan,
        search_options=search_options,
        query=query,
        collector=collector,
    )
    wanted = [
        source
        for source in FTS_SOURCE_ORDER
        if not sources or source in sources or (source == "artifacts" and "web" in sources)
    ]
    want_ocr = include_ocr and ocr_search is not None and (not sources or "ocr" in sources)
    document_errors: list[dict[str, object]] = []
    ocr_errors: list[dict[str, str]] = []
    try:
        connection = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise CaseIndexError(f"case DB unavailable: {exc}") from exc
    connection.row_factory = sqlite3.Row
    guard = _BudgetGuard()
    connection.set_progress_handler(guard, PROGRESS_HANDLER_STEPS)
    try:
        evidence = connection.execute("SELECT MAX(id) AS id FROM evidence_source").fetchone()
        if evidence is None or evidence["id"] is None:
            raise CaseIndexError("case DB has no imported run")
        context.evidence_source_id = int(evidence["id"])
        handlers = {
            "documents": _documents,
            "files": _files,
            "artifacts": _artifacts,
            "indicators": _indicators,
            "timeline": _timeline,
        }
        total_sources = len(wanted) + (1 if want_ocr else 0)
        for position, source in enumerate(wanted):
            if collector.full:
                budget.skip_source(source, "limit")
                continue
            scan = budget.start_source(source, sources_left=total_sources - position)
            guard.deadline = scan.deadline
            before = len(collector.matches)
            try:
                handlers[source](connection, context, scan, sources)
            except sqlite3.OperationalError as exc:
                if not _interrupted(exc):
                    raise
                scan.stopped = "budget"
            guard.deadline = None
            scan.finish(matches=len(collector.matches) - before, limit_reached=collector.full)
        if "documents" in wanted:
            document_errors = _document_errors(outputs)
    except sqlite3.Error as exc:
        raise CaseIndexError(f"case DB query failed: {exc}") from exc
    finally:
        connection.close()
    if want_ocr:
        if collector.full:
            budget.skip_source("ocr", "limit")
        else:
            scan = budget.start_source("ocr", sources_left=1)
            remaining = (limit - collector.visible) if limit else 0
            ocr_matches, ocr_errors = ocr_search(remaining, scan)
            for match in ocr_matches:
                if collector.full:
                    break
                collector.add(match)
            scan.finish(matches=len(ocr_matches), limit_reached=collector.full)
    return collector.matches, document_errors, ocr_errors


class _SearchContext:
    def __init__(
        self,
        *,
        outputs: Mapping[str, object],
        keywords: Sequence[str],
        plan: Sequence[Mapping[str, object]],
        search_options: Mapping[str, object],
        query: str | None,
        collector: MatchCollector,
    ) -> None:
        self.outputs = outputs
        self.keywords = keywords
        self.plan = plan
        self.search_options = search_options
        self.query = query
        self.collector = collector
        self.evidence_source_id = 0

    def matched(self, haystack: str) -> list[str]:
        return match_keywords(haystack, self.keywords, search_options=self.search_options, plan=self.plan)

    def match_metadata(self, haystack: str) -> dict[str, object]:
        return build_search_match_metadata(haystack, self.keywords, search_options=self.search_options)

    def base_id(self, connection: sqlite3.Connection, table: str, extra: str = "") -> int:
        row = connection.execute(
            f"SELECT MIN(id) AS id FROM {table} WHERE evidence_source_id = ?{extra}",
            (self.evidence_source_id,),
        ).fetchone()
        return int(row["id"]) if row is not None and row["id"] is not None else 0


def _documents(connection: sqlite3.Connection, context: _SearchContext, scan: SourceScan, _sources: set[str]) -> None:
    collector = context.collector
    base = context.base_id(connection, "indexed_document", " AND source_type = 'document'")
    fts_from, fts_where, params = _match_clause("indexed_document_fts", context.query)
    sql = (
        f"SELECT d.id, d.field_name, d.title, d.body FROM {fts_from}indexed_document d"
        f"{' ON d.id = f.rowid' if fts_from else ''} "
        f"WHERE {fts_where}d.evidence_source_id = ? AND d.source_type = 'document' "
        f"ORDER BY {'f.rowid' if fts_from else 'd.id'}"
    )
    docs_path = _output_path(context.outputs, "docs")
    candidates = OrdinalRows(docs_path, "candidates")
    result_index_by_path: dict[str, int] | None = None
    for row in _iter_rows(connection, sql, [*params, context.evidence_source_id], scan):
        ordinal = int(row["id"]) - base
        candidate = candidates.get(ordinal)
        if candidate is None:
            continue
        path = str(candidate.get("path", ""))
        if not collector.accepts_path(path):
            continue
        body = str(row["body"] or "")
        haystack = f"{row['title'] or ''}\n{body}"
        matched = context.matched(haystack)
        if not matched:
            continue
        if result_index_by_path is None:
            result_index_by_path = docs_result_index(docs_path)
        collector.add(
            {
                "source": "documents",
                "kind": str(candidate.get("kind", "") or row["field_name"] or ""),
                "path": path,
                "title": Path(path).name,
                "matched_keywords": matched,
                "preview": build_preview(body or haystack, matched[0]),
                "search_match": context.match_metadata(haystack),
                "pointer": f"/results/{result_index_by_path[path]}" if path in result_index_by_path else "",
                "candidate_index": ordinal,
                "metadata": dict(candidate),
            }
        )
        if collector.full:
            return


def docs_result_index(docs_path: Path | None) -> dict[str, int]:
    if docs_path is None or not docs_path.is_file():
        return {}

    def build() -> dict[str, int]:
        index: dict[str, int] = {}
        for position, item in enumerate(OrdinalRows._stream(docs_path, "results")):
            if item.get("path"):
                index.setdefault(str(item.get("path")), position)
        return index

    return OUTPUT_ROW_CACHE.value(  # type: ignore[return-value]
        docs_path,
        "docs-result-index",
        build,
        nbytes=lambda value: sum(len(key) + 80 for key in value),  # type: ignore[attr-defined]
    )


def _document_errors(outputs: Mapping[str, object]) -> list[dict[str, object]]:
    docs_path = _output_path(outputs, "docs")
    if docs_path is None or not docs_path.is_file():
        return []

    def build() -> list[dict[str, object]]:
        errors = []
        for item in OrdinalRows._stream(docs_path, "extraction_errors"):
            normalized = normalize_document_extraction_error(item)
            if normalized:
                errors.append(normalized)
        return errors

    cached = OUTPUT_ROW_CACHE.value(
        docs_path,
        "docs-extraction-errors",
        build,
        nbytes=lambda value: len(json.dumps(value, ensure_ascii=False)) + 64,
    )
    return [dict(item) for item in cached]  # type: ignore[attr-defined]


def _files(connection: sqlite3.Connection, context: _SearchContext, scan: SourceScan, _sources: set[str]) -> None:
    collector = context.collector
    base = context.base_id(connection, "file_record")
    fts_from, fts_where, params = _match_clause("file_record_fts", context.query)
    filters = ""
    filter_params: list[object] = []
    if collector.extensions:
        filters += f" AND lower(r.extension) IN ({', '.join('?' for _ in collector.extensions)})"
        filter_params.extend(sorted(collector.extensions))
    fragment = _ascii_fragment(collector.path_fragment)
    if fragment:
        filters += " AND instr(r.normalized_path, ?) > 0"
        filter_params.append(fragment.replace("\\", "/"))
    sql = (
        f"SELECT r.id FROM {fts_from}file_record r{' ON r.id = f.rowid' if fts_from else ''} "
        f"WHERE {fts_where}r.evidence_source_id = ?{filters} "
        f"ORDER BY {'f.rowid' if fts_from else 'r.id'}"
    )
    candidates = OrdinalRows(_output_path(context.outputs, "files"), "candidates")
    for row in _iter_rows(connection, sql, [*params, context.evidence_source_id, *filter_params], scan):
        ordinal = int(row["id"]) - base
        candidate = candidates.get(ordinal)
        if candidate is None:
            continue
        haystack = json.dumps(candidate, ensure_ascii=False)
        matched = context.matched(haystack)
        if not matched:
            continue
        path = str(candidate.get("path", ""))
        collector.add(
            {
                "source": "files",
                "kind": ",".join(str(item) for item in candidate.get("categories", []) or []),
                "path": path,
                "title": str(candidate.get("name") or Path(path).name),
                "matched_keywords": matched,
                "preview": path,
                "search_match": context.match_metadata(haystack),
                "pointer": f"/candidates/{ordinal}",
                "metadata": dict(candidate),
            }
        )
        if collector.full:
            return


def _artifacts(connection: sqlite3.Connection, context: _SearchContext, scan: SourceScan, sources: set[str]) -> None:
    collector = context.collector
    fts_from, fts_where, params = _match_clause("artifact_fts", context.query)
    filters = ""
    want_web = not sources or "web" in sources
    want_other = not sources or "artifacts" in sources
    if want_web != want_other:
        operator = "=" if want_web else "!="
        filters = f" AND json_extract(a.data_json, '$.{ARTIFACT_SOURCE_LOCATOR_KEY}.output_name') {operator} ?"
    sql = (
        f"SELECT a.id, a.artifact_type, {artifact_data_select_sql(connection, 'a')} FROM {fts_from}artifact a"
        f"{' ON a.id = f.rowid' if fts_from else ''} "
        f"WHERE {fts_where}a.evidence_source_id = ? AND a.parser_name != ?{filters} "
        f"ORDER BY {'f.rowid' if fts_from else 'a.id'}"
    )
    sql_params: list[object] = [*params, context.evidence_source_id, INDICATOR_PARSER_NAME]
    if filters:
        sql_params.append(BROWSER_OUTPUT_NAME)
    for row in _iter_rows(connection, sql, sql_params, scan):
        try:
            stored = json.loads(artifact_row_data_json(row))
        except (TypeError, ValueError):
            continue
        if not isinstance(stored, dict):
            continue
        locator = stored.pop(ARTIFACT_SOURCE_LOCATOR_KEY, None)
        if not isinstance(locator, Mapping):
            continue
        path = str(stored.get("path", ""))
        if not collector.accepts_path(path):
            continue
        haystack = json.dumps(stored, ensure_ascii=False)
        matched = context.matched(haystack)
        if not matched:
            continue
        output_name = str(locator.get("output_name") or "")
        artifact_kind = output_name.removeprefix("artifacts_")
        collector.add(
            {
                "source": "web" if output_name == BROWSER_OUTPUT_NAME else "artifacts",
                "kind": artifact_kind,
                "path": path,
                "title": str(stored.get("artifact_type") or row["artifact_type"] or artifact_kind),
                "matched_keywords": matched,
                "preview": "",  # finalize_search_hit sets the snippet (record JSON preview was discarded)
                "search_match": context.match_metadata(haystack),
                "pointer": f"/artifacts/{int(locator.get('row_index') or 0)}",
                "metadata": stored,
            }
        )
        if collector.full:
            return


def _indicators(connection: sqlite3.Connection, context: _SearchContext, scan: SourceScan, _sources: set[str]) -> None:
    collector = context.collector
    fts_from, fts_where, params = _match_clause("artifact_fts", context.query)
    sql = (
        f"SELECT a.id, {artifact_data_select_sql(connection, 'a')} FROM {fts_from}artifact a"
        f"{' ON a.id = f.rowid' if fts_from else ''} "
        f"WHERE {fts_where}a.evidence_source_id = ? AND a.parser_name = ? "
        f"ORDER BY {'f.rowid' if fts_from else 'a.id'}"
    )
    for row in _iter_rows(connection, sql, [*params, context.evidence_source_id, INDICATOR_PARSER_NAME], scan):
        try:
            stored = json.loads(artifact_row_data_json(row))
        except (TypeError, ValueError):
            continue
        details = stored.get("details") if isinstance(stored, Mapping) else None
        if not isinstance(details, Mapping) or not isinstance(details.get("raw"), Mapping):
            continue
        raw = dict(details["raw"])
        haystack = json.dumps(raw, ensure_ascii=False)
        matched = context.matched(haystack)
        if not matched:
            continue
        sources = raw.get("sources")
        first_source = sources[0] if isinstance(sources, list) and sources and isinstance(sources[0], Mapping) else {}
        path = str(first_source.get("path") or first_source.get("source_path") or "")
        index = int(details.get("source_index") or 0)
        if details.get("coverage_status") == "local-rule-ioc-scanner":
            hit_type = str(raw.get("type") or "ioc")
            title = f"IOC scanner: {raw.get('rule_id') or ''} {hit_type}:{raw.get('value') or ''}".strip()
            kind, pointer = "ioc-scanner-hit", f"/ioc_scanner_hits/{index}"
        else:
            indicator_type = str(raw.get("type") or "indicator")
            value = str(raw.get("value") or "")
            title = f"{indicator_type}: {value}" if value else indicator_type
            kind, pointer = indicator_type, f"/indicators/{index}"
        collector.add(
            {
                "source": "indicators",
                "kind": kind,
                "path": path,
                "title": title,
                "matched_keywords": matched,
                "preview": "",  # finalize_search_hit sets the snippet
                "search_match": context.match_metadata(haystack),
                "pointer": pointer,
                "metadata": raw,
            }
        )
        if collector.full:
            return


def _timeline(connection: sqlite3.Connection, context: _SearchContext, scan: SourceScan, _sources: set[str]) -> None:
    collector = context.collector
    base = context.base_id(connection, "event")
    fts_from, fts_where, params = _match_clause("event_fts", context.query)
    sql = (
        "SELECT e.id, e.event_type, e.timestamp, e.timestamp_kind, e.target, e.description, e.source "
        f"FROM {fts_from}event e{' ON e.id = f.rowid' if fts_from else ''} "
        f"WHERE {fts_where}e.evidence_source_id = ? "
        f"ORDER BY {'f.rowid' if fts_from else 'e.id'}"
    )
    for row in _iter_rows(connection, sql, [*params, context.evidence_source_id], scan):
        path = str(row["target"] or "")
        if not collector.accepts_path(path):
            continue
        event = {
            "timestamp": row["timestamp"],
            "timestamp_kind": row["timestamp_kind"],
            "event_type": row["event_type"],
            "source": row["source"],
            "path": path,
            "summary": row["description"],
        }
        haystack = json.dumps(event, ensure_ascii=False)
        matched = context.matched(haystack)
        if not matched:
            continue
        collector.add(
            {
                "source": "timeline",
                "kind": str(row["event_type"] or ""),
                "path": path,
                "title": str(row["description"] or "timeline event"),
                "matched_keywords": matched,
                "preview": "",  # finalize_search_hit sets the snippet
                "search_match": context.match_metadata(haystack),
                "pointer": f"/events/{int(row['id']) - base}",
                "metadata": event,
            }
        )
        if collector.full:
            return
