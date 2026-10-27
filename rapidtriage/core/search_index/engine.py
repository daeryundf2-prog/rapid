"""Query execution over ``rapidtriage-search.db`` (plan §3.2 ``search/query``).

The parsed query compiles to one parameterised SQL predicate over
``search_doc d`` in two shapes:

* **set mode** (whole index): keyword terms are ``d.group_id IN (<FTS LIKE
  candidates>)`` (the trigram index serves them; 2-character non-ASCII terms
  use ``search_bigram MATCH`` instead -- index v3), field terms are
  ``IN``-subqueries on ``search_field``/``search_hash``, time windows use the
  ``ts`` index and never touch FTS;
* **row mode** (a known small candidate set): the same terms as correlated
  ``EXISTS`` checks on the row, so no subquery is materialised.

Regular expressions never run inside SQLite: a cooperative pre-pass matches
the FTS (or scan) candidates in Python with :class:`.regex_guard.GuardedRegex`
(64 KB per row, bounded slices, a per-row time limit, a budget check every
``REGEX_CHECK_ROWS`` rows) into ``temp.rx_<n>`` tables that the predicate
reads; the match spans are reused for the snippet.

Execution:

* **first page** (``sort=relevance`` without ``aggregates``): keyset over the
  full-text index's own order (``rowid > :after ORDER BY rowid LIMIT n``) of
  the most useful top-level keyword, each chunk checked with the row-mode
  predicate; queries without such a keyword stream the set-mode predicate in
  ``doc_id`` order. Either stops as soon as ``limit + 1`` rows are found.
* **aggregates** (``aggregates=true`` -- the default -- or a time/path sort):
  the predicate runs **once** (``INSERT INTO temp.m SELECT …``); total,
  facets, histogram, gaps and the page all read ``temp.m``.

A progress handler stops any statement when the wall-clock budget runs out or
the client went away (``cancel_event``); the response then carries
``truncated`` + ``truncated_reason``. SQLite/limit errors become 400s with a
Korean message, never 500s.
"""

from __future__ import annotations

import base64
import bisect
import datetime as dt
import functools
import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..files import CATEGORY_RULES
from ..search_hits import ENTRY_MARK
from ..textnorm import locate_normalized
from .query import (
    MAX_LIST_ITEMS,
    Group,
    Node,
    Not,
    ParsedQuery,
    QueryError,
    Term,
    Value,
    parse_query,
    validate_regex,
)
from .regex_guard import GuardedRegex, RowTimeout
from .schema import (
    BIGRAM_RULE,
    FOLD_RULE,
    QUERY_BUDGET_SECONDS,
    QUERY_GRACE_SECONDS,
    READABLE_INDEX_VERSIONS,
    TOKENIZER_TRIGRAM,
    open_read_only,
)
from .textutil import (
    ascii_lower,
    fold,
    format_offset,
    is_bigram_term,
    ms_to_iso,
    nfc,
    normalize_hash,
    parse_offset,
    path_key,
)

# The aggregate pass materialises at most this many matching rows (memory guard).
TOTAL_CAP = 1_000_000
SORT_TS_CAP = 50_000
DEFAULT_BUDGET_SECONDS = QUERY_BUDGET_SECONDS
GRACE_SECONDS = QUERY_GRACE_SECONDS
PAGE_MAX = 1000
PROGRESS_OPCODES = 20_000
SNIPPET_BEFORE = 80
SNIPPET_AFTER = 200
MAX_MARKS = 20
MAX_GAPS = 500
MAX_BUCKETS = 2000
MAX_HASHSETS = 8
AFTER_HOURS_START = 22
AFTER_HOURS_END = 6
CURSOR_VERSION = 3
SQL_INT_MAX = 2**63 - 1
TS_NULL_HIGH = 253_402_300_800_000
TS_LAST_MS = 253_402_300_799_999  # 9999-12-31T23:59:59.999Z
TS_NULL_LOW = -62_135_596_800_001
DRIVER_CHUNK = 2000
DRIVER_MAX_CHUNKS = 10
STREAM_FETCH = 512
REGEX_FETCH = 256
REGEX_CHECK_ROWS = 64
FACET_LIMITS = (("domain", 50), ("collection", 10), ("artifact_type", 30), ("actor", 20), ("computer", 20))
AROUND_REF_RE = re.compile(
    r"^(?:(?P<collection>[a-z]+)(?::(?P<kind>[A-Za-z0-9_.-]{1,64}))?)?(?P<locator>/(?:artifacts|candidates|inventory|events|indicators|results|rows|entries)/\d{1,12})$"
)
HASHSET_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ANALYSIS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DURATION_RE = re.compile(r"^(\d{1,6})\s*([smhdw])$", re.IGNORECASE)
RELATIVE_RE = re.compile(r"^([+-])(\d{1,6})([smhdw])$", re.IGNORECASE)
TIME_RE = re.compile(
    r"^(?P<y>\d{4})(?:-(?P<mo>\d{2})(?:-(?P<d>\d{2})(?:[T ](?P<h>\d{2}):(?P<mi>\d{2})(?::(?P<s>\d{2})(?:\.(?P<f>\d{1,9}))?)?)?)?)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)
SIZE_RE = re.compile(r"^(\d{1,20}(?:\.\d{1,6})?)\s*(b|kb|mb|gb|tb|k|m|g|t)?$", re.IGNORECASE)
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
SIZE_UNITS = {"b": 1, "": 1, "k": 1024, "kb": 1024, "m": 1024**2, "mb": 1024**2, "g": 1024**3, "gb": 1024**3, "t": 1024**4, "tb": 1024**4}
BUCKETS = {"1m": 60, "5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "1d": 86400, "1w": 604800}
AUTO_BUCKETS = (60, 300, 900, 1800, 3600, 21600, 86400, 604800, 2592000)
AUTO_MAX_BUCKETS = 240

DOMAINS = frozenset(
    {"os", "execution", "filesystem", "registry", "eventlog", "web", "messaging", "cloud", "media", "mobile", "devices",
     "anti-forensics", "incident", "memory", "location", "other"}
)
COLLECTIONS = frozenset({"files", "docs", "artifacts", "indicators", "analysis"})
EXTSETS: dict[str, tuple[str, ...]] = {
    "documents": CATEGORY_RULES["documents"]["extensions"],
    "executables": CATEGORY_RULES["executables"]["extensions"],
    "archives": CATEGORY_RULES["archives"]["extensions"],
    "images": CATEGORY_RULES.get("images", {}).get("extensions", (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".webp")),
    "scripts": (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".sh", ".pl", ".rb"),
    "config": (".ini", ".cfg", ".conf", ".xml", ".json", ".yaml", ".yml", ".reg", ".inf", ".plist", ".config"),
    "db": CATEGORY_RULES["databases"]["extensions"],
    "email": CATEGORY_RULES["emails"]["extensions"],
}
REVIEW_FIELDS = frozenset({"review", "tag", "note", "bookmark"})
BOOKMARK_TAG = "북마크"
SORTS = ("relevance", "ts", "-ts", "path")
TEXT_SQL_FIELDS = frozenset({"kw", "word", "near"})


class Interrupted(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Budget:
    """Wall-clock budget + client cancellation, polled by the SQLite progress handler and Python loops."""

    def __init__(self, seconds: float, cancel_event: threading.Event | None = None) -> None:
        self.started = time.monotonic()
        self.deadline = self.started + max(0.0, seconds)
        self.seconds = seconds
        self.cancel_event = cancel_event
        self.reason: str | None = None

    def expired(self) -> bool:
        if self.reason is not None:
            return True
        if self.cancel_event is not None and self.cancel_event.is_set():
            self.reason = "클라이언트 연결이 끊겨 검색을 중단했습니다"
        elif time.monotonic() >= self.deadline:
            self.reason = f"시간 예산({self.seconds:g}초)을 넘어 검색을 중단했습니다"
        return self.reason is not None

    def check(self) -> None:
        if self.expired():
            raise Interrupted(self.reason or "")

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started) * 1000)

    @property
    def cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()


@dataclass
class SearchOptions:
    tz: str | None = None
    reference_ts: str | None = None
    case_sensitive: bool = False
    whole_word: bool = False
    hide_hashsets: list[str] = field(default_factory=list)

    def cache_key(self) -> dict[str, object]:
        return {
            "tz": self.tz or "",
            "reference_ts": self.reference_ts or "",
            "case_sensitive": self.case_sensitive,
            "whole_word": self.whole_word,
            "hide_hashsets": sorted(self.hide_hashsets),
        }


ReviewProvider = Callable[[], list[Mapping[str, object]] | None]
HashsetResolver = Callable[[str], Path | None]


# ---------------------------------------------------------------------------
# SQL functions (row-level predicates; linear time -- regexes never run in SQLite)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=256)
def _word_regex(term: str) -> re.Pattern[str]:
    return re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE)


@functools.lru_cache(maxsize=256)
def _literal_regex(term: str) -> re.Pattern[str]:
    return re.compile(re.escape(term), re.IGNORECASE)


def sx_word(text: object, term: object) -> int:
    if not isinstance(text, str) or not isinstance(term, str):
        return 0
    return 1 if _word_regex(nfc(term)).search(text) else 0


_WORD_RE = re.compile(r"\w+")


def sx_near(text: object, left: object, right: object, distance: object) -> int:
    """Both phrases occur within ``distance`` words of each other (case-insensitive)."""
    if not isinstance(text, str) or not isinstance(left, str) or not isinstance(right, str):
        return 0
    folded = fold(text)
    starts = [match.start() for match in _WORD_RE.finditer(folded)]
    if not starts:
        return 0

    def word_positions(needle: str) -> list[int]:
        positions: list[int] = []
        index = folded.find(needle)
        while index >= 0 and len(positions) < 1000:
            positions.append(max(0, bisect.bisect_right(starts, index) - 1))
            index = folded.find(needle, index + 1)
        return positions

    a = word_positions(fold(left))
    b = word_positions(fold(right))
    limit = int(distance or 0)
    if not a or not b:
        return 0
    b_sorted = sorted(b)
    for position in a:
        index = bisect.bisect_left(b_sorted, position - limit)
        if index < len(b_sorted) and b_sorted[index] <= position + limit:
            return 1
    return 0


def sx_data(text: object, name: object, value: object, prefix: object) -> int:
    """An EventData ``Name=Value`` line of the row text equals (or, with ``prefix``, starts with) the value."""
    if not isinstance(text, str) or not isinstance(name, str):
        return 0
    wanted_name = fold(name)
    wanted = fold(value)
    for line in text.split("\n"):
        key, sep, rest = line.partition("=")
        if not sep or fold(key) != wanted_name:
            continue
        candidate = fold(rest)
        if (prefix and candidate.startswith(wanted)) or candidate == wanted:
            return 1
    return 0


def register_functions(connection: sqlite3.Connection) -> None:
    connection.create_function("sx_word", 2, sx_word, deterministic=True)
    connection.create_function("sx_near", 4, sx_near, deterministic=True)
    connection.create_function("sx_data", 4, sx_data, deterministic=True)


# ---------------------------------------------------------------------------
# value helpers
# ---------------------------------------------------------------------------


def bigram_match(literal: str) -> str:
    """FTS5 query of one ``search_bigram`` token (both characters are non-ASCII, so never a ``"``)."""
    return f'"{literal}"'


def contains_sql(column: str, literal: str) -> tuple[str, str]:
    """``instr`` test of ``column`` containing ``literal`` ignoring ASCII case: ``(sql, param)``.

    SQLite ``lower`` only folds A-Z, so a literal without ASCII letters (a Korean word) matches
    the raw text exactly where it matches the lowered text -- and skips copying every row's text
    through ``lower`` (about 20 % of a short-term scan, R7 P2).
    """
    if any("a" <= char <= "z" or "A" <= char <= "Z" for char in literal):
        return f"instr(lower({column}), ?) > 0", ascii_lower(literal)
    return f"instr({column}, ?) > 0", literal


def like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def glob_to_like(text: str) -> str:
    """User glob (``*``/``?``) -> LIKE pattern with ``\\`` escape."""
    return like_escape(text).replace("*", "%").replace("?", "_")


def glob_escape(text: str) -> str:
    """Literal text for SQLite GLOB (metacharacters bracketed); ``*``/``?`` kept as wildcards."""
    return text.replace("[", "[[]")


def _items(value: Value) -> list[Value]:
    return value.items if value.kind == "list" else [value]


def _scalar(value: Value, field_name: str) -> str:
    if value.kind in {"token", "phrase"}:
        return value.text.strip()
    raise QueryError(f"{field_name}: 값 형식이 맞지 않습니다", value.pos)


def _bool(value: Value, field_name: str) -> bool:
    text = _scalar(value, field_name).lower()
    if text in {"true", "yes", "1"}:
        return True
    if text in {"false", "no", "0"}:
        return False
    raise QueryError(f"{field_name}: 값은 true 또는 false여야 합니다", value.pos)


def parse_duration(text: str, position: int, *, label: str) -> int:
    match = DURATION_RE.match(text.strip())
    if match is None:
        raise QueryError(f"{label} 기간은 5m·6h·2d 같은 형식이어야 합니다", position)
    return int(match.group(1)) * UNIT_SECONDS[match.group(2).lower()]


def parse_size(text: str, position: int) -> int:
    match = SIZE_RE.match(text.strip())
    if match is None:
        raise QueryError("크기는 100KB·5MB 같은 형식이어야 합니다", position)
    value = float(match.group(1)) * SIZE_UNITS[(match.group(2) or "").lower()]
    if not math.isfinite(value) or value > 2**62:
        raise QueryError("크기가 너무 큽니다", position)
    return int(value)


def resolve_time(text: str, position: int, *, end: bool, tz: dt.timedelta, ref_ms: int | None) -> int | None:
    """Bound of ``time:[a .. b]`` -> epoch ms; the end bound is inclusive to its precision."""
    value = text.strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered in {"ref", "now"}:
        if ref_ms is None:
            raise QueryError("기준 시각(ref)을 정할 수 없습니다. options.reference_ts를 주세요", position)
        return ref_ms
    relative = RELATIVE_RE.match(lowered)
    if relative is not None:
        if ref_ms is None:
            raise QueryError("상대 시각에는 기준 시각(options.reference_ts)이 필요합니다", position)
        sign = -1 if relative.group(1) == "-" else 1
        return ref_ms + sign * int(relative.group(2)) * UNIT_SECONDS[relative.group(3)] * 1000
    match = TIME_RE.match(value)
    if match is None:
        raise QueryError(f"시각 형식을 알 수 없습니다: {value} (예: 2025-05-28, 2025-05-28T19:00+09:00, -7d, ref)", position)
    parts = match.groupdict()
    zone = tz
    if parts["tz"]:
        parsed_zone = dt.timedelta(0) if parts["tz"] == "Z" else parse_offset(parts["tz"])
        if parsed_zone is None:
            raise QueryError(f"시간대 오프셋이 올바르지 않습니다: {parts['tz']} (예: +09:00, -05:30, Z)", position)
        zone = parsed_zone
    try:
        year = int(parts["y"])
        month = int(parts["mo"] or 1)
        day = int(parts["d"] or 1)
        hour = int(parts["h"] or 0)
        minute = int(parts["mi"] or 0)
        second = int(parts["s"] or 0)
        micro = int((parts["f"] or "0")[:6].ljust(6, "0"))
        moment = dt.datetime(year, month, day, hour, minute, second, micro, tzinfo=dt.timezone(zone))
        start_ms = int(moment.timestamp() * 1000)
    except (ValueError, OverflowError) as exc:
        raise QueryError(f"없거나 다룰 수 없는 날짜·시각입니다: {value}", position) from exc
    if not end or parts["f"]:
        return start_ms
    try:
        if parts["s"]:
            step = dt.timedelta(seconds=1)
        elif parts["mi"]:
            step = dt.timedelta(minutes=1)
        elif parts["d"]:
            step = dt.timedelta(days=1)
        elif parts["mo"]:
            nxt = moment.replace(year=year + (month == 12), month=1 if month == 12 else month + 1)
            return int(nxt.timestamp() * 1000) - 1
        else:
            return int(moment.replace(year=year + 1).timestamp() * 1000) - 1
        return int((moment + step).timestamp() * 1000) - 1
    except (ValueError, OverflowError):
        return TS_LAST_MS  # the end of year 9999: one step later is past datetime's range


# ---------------------------------------------------------------------------
# compiler
# ---------------------------------------------------------------------------


@dataclass
class RegexJob:
    """One ``re:`` term: matched in Python into ``temp.<table>`` before the predicate runs."""

    table: str
    pattern: str
    flags: str
    literal: str
    matcher: GuardedRegex
    positive: bool
    position: int


@dataclass
class Driver:
    """A top-level positive keyword whose FTS order drives the first page."""

    literal: str
    bigram: bool = False  # served by ``search_bigram`` (a 2-character non-ASCII term)


@dataclass
class CompileContext:
    connection: sqlite3.Connection
    tokenizer: str
    tz: dt.timedelta
    ref_ms: int | None
    options: SearchOptions
    review_provider: ReviewProvider | None = None
    hashset_resolver: HashsetResolver | None = None
    warnings: list[str] = field(default_factory=list)
    gap_seconds: int | None = None
    time_range: tuple[int | None, int | None] | None = None
    text_terms: list[tuple[str, str]] = field(default_factory=list)  # (field, literal)
    regex_jobs: list[RegexJob] = field(default_factory=list)
    drivers: list[Driver] = field(default_factory=list)
    attached: dict[str, str] = field(default_factory=dict)
    temp_tables: int = 0
    uses_review: bool = False
    bigram: bool = False  # the index has ``search_bigram`` (v3)
    folded: bool = False  # the index has ``text_fold`` and folded full-text content (v4)
    _marks: list[Mapping[str, object]] | None = None

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


class Compiler:
    """``mode="set"`` for the whole index, ``mode="row"`` for checking known candidates."""

    def __init__(self, ctx: CompileContext, *, mode: str = "set") -> None:
        self.ctx = ctx
        self.mode = mode
        self._regex_tables: dict[int, str] = {}

    def compile(self, node: Node, *, negated: bool = False, top: bool = True) -> tuple[str, list[object]]:
        if isinstance(node, Term):
            return self.term(node, negated, top)
        if isinstance(node, Not):
            sql, params = self.compile(node.child, negated=not negated, top=False)
            return f"NOT COALESCE(({sql}), 0)", params
        assert isinstance(node, Group)
        parts: list[str] = []
        params: list[object] = []
        for child in node.children:
            sql, child_params = self.compile(child, negated=negated, top=top and node.op == "AND")
            parts.append(f"({sql})")
            params.extend(child_params)
        return f" {node.op} ".join(parts), params

    # -- helpers -------------------------------------------------------------

    def group_in(self, column: str, source: str, where: str) -> str:
        """Rows whose group has a matching row in ``source`` (``column`` = its doc id)."""
        if self.mode == "row":
            return f"EXISTS (SELECT 1 FROM {source} WHERE {column} = d.group_id AND ({where}))"
        return f"d.group_id IN (SELECT {column} FROM {source} WHERE {where})"

    def match_literal(self, literal: str) -> str:
        """The form a keyword is compared in: NFC + casefold on a v4 index (its full-text content
        and bigram pairs are folded the same way), else as typed (SQLite folds ASCII only)."""
        return fold(literal) if self.ctx.folded else literal

    def fold_column(self, prefix: str = "") -> str:
        """The folded row text (``text_fold`` where the row has one) -- raw ``text`` before v4."""
        return f"COALESCE({prefix}text_fold, {prefix}text)" if self.ctx.folded else f"{prefix}text"

    def _fts_ok(self, literal: str) -> bool:
        return self.ctx.tokenizer == TOKENIZER_TRIGRAM and len(literal) >= 3 and "%" not in literal and "_" not in literal

    def _bigram_ok(self, literal: str) -> bool:
        """A 2-character non-ASCII term on an index with ``search_bigram`` (exact: no re-check needed)."""
        if not is_bigram_term(literal):
            return False
        if not self.ctx.bigram:
            self.ctx.warn("이전 형식 색인이라 2자 한글 검색어가 전체 본문을 훑습니다(느릴 수 있음). 색인을 다시 만드세요")
            return False
        return True

    def text_check(self, literal: str, extra: str = "", extra_params: Sequence[object] = ()) -> tuple[str, list[object]]:
        """Rows whose primary text contains ``literal`` (+ ``extra`` on ``{text}`` = the raw text,
        ``{fold}`` = the folded text).

        ``literal`` is compared in :meth:`match_literal` form; ``extra`` always reads
        ``search_doc`` itself (the full-text content of a v4 index is the folded text).
        """
        literal = self.match_literal(literal)
        if self.mode == "row":
            if not extra and self._bigram_ok(literal):
                # Exact without reading the text: the term's (small) row set, computed once.
                return "d.group_id IN (SELECT rowid FROM search_bigram WHERE search_bigram MATCH ?)", [bigram_match(literal)]
            test, param = contains_sql(self.fold_column("p."), literal)
            sql = f"p.text IS NOT NULL AND {test}"
            params: list[object] = [param]
            if extra:
                sql += " AND " + extra.format(text="p.text", fold=self.fold_column("p."))
                params.extend(extra_params)
            return f"EXISTS (SELECT 1 FROM search_doc p WHERE p.doc_id = d.group_id AND {sql})", params
        if self._fts_ok(literal):
            sql = "SELECT rowid FROM search_text WHERE text LIKE ?"
            params = [f"%{literal}%"]
            if extra:
                sql = f"SELECT doc_id FROM search_doc WHERE doc_id IN ({sql})"
        elif self._bigram_ok(literal):
            sql = "SELECT rowid FROM search_bigram WHERE search_bigram MATCH ?"
            params = [bigram_match(literal)]
            if extra:  # contentless: the extra checks read the row's text
                sql = f"SELECT doc_id FROM search_doc WHERE doc_id IN ({sql})"
        else:
            test, param = contains_sql(self.fold_column(), literal)
            sql = f"SELECT doc_id FROM search_doc WHERE text IS NOT NULL AND {test}"
            params = [param]
        if extra:
            sql += " AND " + extra.format(text="text", fold=self.fold_column())
            params.extend(extra_params)
        return f"d.group_id IN ({sql})", params

    def add_driver(self, literal: str, negated: bool, top: bool) -> None:
        literal = self.match_literal(literal)
        if self.mode == "set" and top and not negated:
            if self._fts_ok(literal):
                self.ctx.drivers.append(Driver(literal))
            elif self.ctx.bigram and is_bigram_term(literal):
                self.ctx.drivers.append(Driver(literal, bigram=True))

    # -- text --------------------------------------------------------------

    def regex_term(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        key = id(term)
        table = self._regex_tables.get(key)
        if table is None:
            flags = value.flags if value.kind == "regex" else ""
            info = validate_regex(value.text, value.pos or term.pos, flags)
            self.ctx.temp_tables += 1
            table = f"rx_{self.ctx.temp_tables}"
            self._regex_tables[key] = table
            literal = info.literal if len(info.literal) >= 3 else ""
            if not literal:
                self.ctx.warn("정규식에 3자 이상 고정 문자열이 없어 전체 본문을 훑습니다(느릴 수 있음)")
            self.ctx.regex_jobs.append(
                RegexJob(table, value.text, flags, literal, GuardedRegex(info.compiled), not negated, value.pos or term.pos)
            )
        return f"d.group_id IN (SELECT doc_id FROM temp.{table})", []

    def text_term(self, term: Term, value: Value, negated: bool, top: bool) -> tuple[str, list[object]]:
        name = term.field
        if self.ctx.options.whole_word and name == "kw":
            name = "word"
        if name == "re" or value.kind == "regex":
            if self.mode == "row":
                raise QueryError("정규식은 행 검사 모드에서 쓸 수 없습니다")  # callers never compile regexes in row mode
            return self.regex_term(term, value, negated)
        if name == "near":
            items = _items(value)
            if len(items) != 3 or any(item.kind not in {"token", "phrase"} for item in items):
                raise QueryError("near:(단어1, 단어2, 거리) 형식이어야 합니다", value.pos or term.pos)
            left, right = nfc(items[0].text.strip()), nfc(items[1].text.strip())
            try:
                distance = int(items[2].text.strip())
            except ValueError as exc:
                raise QueryError("near: 거리는 단어 수(정수)여야 합니다", items[2].pos) from exc
            if not 0 <= distance <= 100:
                raise QueryError("near: 거리는 0~100 단어여야 합니다", items[2].pos)
            if not left or not right:
                raise QueryError("빈 검색어입니다", value.pos or term.pos)
            if not negated and self.mode == "set":
                self.ctx.text_terms.extend([("near", left), ("near", right)])
            self.add_driver(left, negated, top)
            extra = "sx_near({text}, ?, ?, ?)"
            params: list[object] = [left, right, distance]
            folded_right = self.match_literal(right)
            if self.mode == "set" and self._fts_ok(folded_right):
                extra += " AND {fold} LIKE ?"
                params.append(f"%{folded_right}%")
            return self.text_check(left, extra, params)
        parts: list[str] = []
        params = []
        items = _items(value)
        for item in items:
            literal = nfc(_scalar(item, name))
            if not literal:
                raise QueryError("빈 검색어입니다", item.pos or term.pos)
            if not negated and self.mode == "set":
                self.ctx.text_terms.append((name, literal))
            if len(items) == 1:
                self.add_driver(literal, negated, top)
            extra = ""
            extra_params: list[object] = []
            if name == "word":
                extra, extra_params = "sx_word({text}, ?)", [literal]
            if self.ctx.options.case_sensitive:
                extra = f"{extra} AND instr({{text}}, ?) > 0" if extra else "instr({text}, ?) > 0"
                extra_params.append(literal)
            sql, sql_params = self.text_check(literal, extra, extra_params)
            parts.append(sql)
            params.extend(sql_params)
        return " OR ".join(parts), params

    # -- fields ------------------------------------------------------------

    def term(self, term: Term, negated: bool, top: bool) -> tuple[str, list[object]]:
        name = term.field
        value = term.value
        if name in {"kw", "word", "re", "near"}:
            return self.text_term(term, value, negated, top)
        if name.startswith("data."):
            return self.data_field(term, negated, top)
        if name in REVIEW_FIELDS:
            self.ctx.uses_review = True
        handler = getattr(self, "field_" + name, None)
        if handler is None:
            raise QueryError(f"알 수 없는 필드입니다: {name}", term.pos)
        if name in {"time", "around"}:
            return handler(term, value, negated, top)
        return handler(term, value, negated)

    def data_field(self, term: Term, negated: bool, top: bool) -> tuple[str, list[object]]:
        data_name = term.field[5:]
        if not data_name:
            raise QueryError("data. 뒤에 EventData 필드 이름이 필요합니다", term.pos)
        parts: list[str] = []
        params: list[object] = []
        items = _items(term.value)
        for item in items:
            raw = _scalar(item, term.field)
            prefix = raw.endswith("*")
            wanted = raw[:-1] if prefix else raw
            literal = nfc(f"{data_name}={wanted}")
            if len(items) == 1:
                self.add_driver(literal, negated, top)
            sql, sql_params = self.text_check(literal, "sx_data({text}, ?, ?, ?)", (data_name, wanted, 1 if prefix else 0))
            parts.append(sql)
            params.extend(sql_params)
        return " OR ".join(parts), params

    def field_time(self, term: Term, value: Value, negated: bool, top: bool) -> tuple[str, list[object]]:
        if value.kind == "range":
            low = resolve_time(value.low, value.pos, end=False, tz=self.ctx.tz, ref_ms=self.ctx.ref_ms)
            high = resolve_time(value.high, value.pos, end=True, tz=self.ctx.tz, ref_ms=self.ctx.ref_ms)
        elif value.kind in {"token", "phrase"}:
            low = resolve_time(value.text, value.pos, end=False, tz=self.ctx.tz, ref_ms=self.ctx.ref_ms)
            high = resolve_time(value.text, value.pos, end=True, tz=self.ctx.tz, ref_ms=self.ctx.ref_ms)
        else:
            raise QueryError("time: 값은 [시작 .. 끝] 또는 날짜여야 합니다", value.pos or term.pos)
        if low is not None and high is not None:
            if low > high:
                raise QueryError("시간 범위의 시작이 끝보다 늦습니다", value.pos or term.pos)
            if low == high:
                self.ctx.warn("시간 범위의 길이가 0입니다(그 한 순간만 찾습니다)")
        if not negated and top and self.ctx.time_range is None:
            self.ctx.time_range = (low, high)
        clauses = ["d.ts IS NOT NULL"]
        params: list[object] = []
        if low is not None:
            clauses.append("d.ts >= ?")
            params.append(low)
        if high is not None:
            clauses.append("d.ts <= ?")
            params.append(high)
        return " AND ".join(clauses), params

    def field_around(self, term: Term, value: Value, negated: bool, top: bool) -> tuple[str, list[object]]:
        items = _items(value)
        if not 1 <= len(items) <= 2:
            raise QueryError("around:(<로케이터>, 5m) 형식이어야 합니다", value.pos or term.pos)
        reference = _scalar(items[0], "around")
        window = parse_duration(items[1].text, items[1].pos, label="around:") if len(items) == 2 else 300
        if window > 7 * 86400:
            raise QueryError("around: 기간은 최대 7d입니다", items[-1].pos)
        if window == 0:
            self.ctx.warn("around: 기간이 0이라 기준 행과 같은 시각만 찾습니다")
        times = self.reference_times(reference, items[0].pos or term.pos)
        clauses = []
        params: list[object] = []
        for millis in times[:16]:
            clauses.append("(d.ts BETWEEN ? AND ?)")
            params.extend([millis - window * 1000, millis + window * 1000])
        if not negated and top and self.ctx.time_range is None:
            self.ctx.time_range = (min(times) - window * 1000, max(times) + window * 1000)
        return " OR ".join(clauses), params

    def reference_times(self, reference: str, position: int) -> list[int]:
        connection = self.ctx.connection
        if reference.isdigit():
            if len(reference) > 12:
                raise QueryError("around: doc_id가 너무 큽니다(최대 12자리)", position)
            rows = connection.execute(
                "SELECT ts FROM search_doc WHERE group_id = (SELECT group_id FROM search_doc WHERE doc_id = ?) AND ts IS NOT NULL",
                (int(reference),),
            ).fetchall()
        else:
            match = AROUND_REF_RE.match(reference)
            if match is None:
                raise QueryError("around: 기준은 doc_id 또는 <컬렉션>[:<종류>]/<로케이터> 형식이어야 합니다(예: artifacts:eventlog/artifacts/12)", position)
            sql = "SELECT ts, collection, kind FROM search_doc WHERE locator = ? AND ts IS NOT NULL"
            params: list[object] = [match.group("locator")]
            if match.group("collection"):
                sql += " AND collection = ?"
                params.append(match.group("collection"))
            if match.group("kind"):
                sql += " AND kind = ?"
                params.append(match.group("kind"))
            rows = connection.execute(sql + " LIMIT 64", params).fetchall()
            owners = {(row[1], row[2]) for row in rows}
            if len(owners) > 1:
                raise QueryError("around: 기준 로케이터가 여러 컬렉션에 있습니다. <컬렉션>:<종류>를 붙이세요", position)
        times = sorted({int(row[0]) for row in rows})
        if not times:
            raise QueryError("around: 기준 행을 찾을 수 없거나 시각이 없습니다", position)
        return times

    def field_tskind(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        clauses: list[str] = []
        params: list[object] = []
        for item in _items(value):
            kind = fold(_scalar(item, "tskind"))
            label = kind.replace("_", "-")
            family = kind.replace("-", "_")
            clauses.append("d.ts_family = ? OR d.ts_kind = ? OR (',' || d.ts_labels || ',') LIKE ?")
            params.extend([family, label, f"%,{like_escape(label)},%"])
        return " OR ".join(f"({clause})" for clause in clauses), params

    def field_in(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        names: list[str] = []
        for item in _items(value):
            name = fold(_scalar(item, "in"))
            name = {"documents": "docs", "doc": "docs", "file": "files", "indicator": "indicators", "analyses": "analysis"}.get(name, name)
            if name not in DOMAINS and name not in COLLECTIONS:
                raise QueryError(f"알 수 없는 도메인입니다: {name}", item.pos or term.pos)
            names.append(name)
        marks = ", ".join("?" for _ in names)
        return f"d.domain IN ({marks}) OR d.collection IN ({marks})", [*names, *names]

    def field_type(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        exact: list[str] = []
        clauses: list[str] = []
        params: list[object] = []
        for item in _items(value):
            text = fold(_scalar(item, "type"))
            if "*" in text or "?" in text:
                clauses.append("d.artifact_type GLOB ?")
                params.append(glob_escape(text))
            else:
                exact.append(text)
        if exact:
            clauses.insert(0, f"d.artifact_type IN ({', '.join('?' for _ in exact)})")
            params[0:0] = exact
        return " OR ".join(clauses), params

    def _like_column(self, column: str, term: Term, value: Value) -> tuple[str, list[object]]:
        clauses: list[str] = []
        params: list[object] = []
        for item in _items(value):
            text = nfc(_scalar(item, term.field))
            clauses.append(f"{column} LIKE ? ESCAPE '\\'")
            params.append(glob_to_like(text))
        return " OR ".join(clauses), params

    def field_actor(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._like_column("d.actor", term, value)

    def field_sid(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._like_column("d.actor_sid", term, value)

    def field_computer(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._like_column("d.computer", term, value)

    def field_afterhours(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        wanted = _bool(value, "afterhours")
        offset = int(self.ctx.tz.total_seconds())
        expression = "(((d.ts / 1000 + ?) % 86400) + 86400) % 86400"
        inside = f"({expression} >= ? OR {expression} < ?)"
        params: list[object] = [offset, AFTER_HOURS_START * 3600, offset, AFTER_HOURS_END * 3600]
        if wanted:
            return f"d.ts IS NOT NULL AND {inside}", params
        return f"d.ts IS NOT NULL AND NOT {inside}", params

    def field_gap(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        text = _scalar(value, "gap").lstrip(">=").strip()
        seconds = parse_duration(text, value.pos or term.pos, label="gap:")
        if seconds < 60:
            raise QueryError("gap: 기간은 1m 이상이어야 합니다", value.pos or term.pos)
        self.ctx.gap_seconds = seconds
        return "d.ts IS NOT NULL", []

    def _hash_clause(self, pairs: list[tuple[str, str]]) -> tuple[str, list[object]]:
        values = ", ".join("(?, ?)" for _ in pairs)
        params: list[object] = [part for pair in pairs for part in pair]
        return f"d.group_id IN (SELECT doc_id FROM search_hash WHERE (algorithm, value) IN (VALUES {values}))", params

    def field_hash(self, term: Term, value: Value, negated: bool, *, algorithm: str | None = None) -> tuple[str, list[object]]:
        pairs: list[tuple[str, str]] = []
        for item in _items(value):
            normalized = normalize_hash(_scalar(item, term.field))
            if normalized is None:
                raise QueryError("해시 형식이 아닙니다(MD5 32자·SHA-1 40자·SHA-256 64자 16진수)", item.pos or term.pos)
            if algorithm is not None and normalized[0] != algorithm:
                raise QueryError(f"{algorithm.upper()} 해시 길이가 아닙니다", item.pos or term.pos)
            pairs.append(normalized)
        return self._hash_clause(pairs)

    def field_md5(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self.field_hash(term, value, negated, algorithm="md5")

    def field_sha1(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self.field_hash(term, value, negated, algorithm="sha1")

    def field_sha256(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self.field_hash(term, value, negated, algorithm="sha256")

    def hashset_alias(self, hashset_id: str, position: int, *, missing_ok: bool = False) -> str | None:
        if not HASHSET_ID_RE.fullmatch(hashset_id):
            raise QueryError(f"해시 세트 id 형식이 아닙니다: {hashset_id}", position)
        if hashset_id in self.ctx.attached:
            return self.ctx.attached[hashset_id]
        path = self.ctx.hashset_resolver(hashset_id) if self.ctx.hashset_resolver is not None else None
        if path is None or not path.is_file():
            if missing_ok:
                self.ctx.warn(f"숨길 해시 세트를 찾을 수 없어 무시했습니다(삭제됨?): {hashset_id}")
                return None
            raise QueryError(f"해시 세트를 찾을 수 없습니다: {hashset_id}", position, status=404)
        if len(self.ctx.attached) >= MAX_HASHSETS:
            raise QueryError(f"해시 세트는 한 질의에 최대 {MAX_HASHSETS}개까지 쓸 수 있습니다", position)
        alias = f"hs{len(self.ctx.attached)}"
        self.ctx.connection.execute(f"ATTACH DATABASE ? AS {alias}", (f"{path.resolve().as_uri()}?mode=ro",))
        self.ctx.attached[hashset_id] = alias
        return alias

    def hashset_clause(self, hashset_id: str, position: int, *, missing_ok: bool = False) -> str | None:
        alias = self.hashset_alias(hashset_id, position, missing_ok=missing_ok)
        if alias is None:
            return None
        return self.group_in("h.doc_id", f"search_hash h JOIN {alias}.hash_entry s ON s.algorithm = h.algorithm AND s.value = h.value", "1")

    def field_hashset(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        parts: list[str] = []
        for item in _items(value):
            sql = self.hashset_clause(_scalar(item, "hashset"), item.pos or term.pos)
            assert sql is not None
            parts.append(sql)
        return " OR ".join(parts), []

    def _path_pattern(self, raw: str) -> str:
        text = path_key(nfc(raw))
        if len(text) >= 2 and text[1] == ":" and text[0].isalpha():
            text = text[2:]
        return text

    def field_path(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        clauses: list[str] = []
        params: list[object] = []
        for item in _items(value):
            pattern = self._path_pattern(_scalar(item, "path"))
            if "*" not in pattern and "?" not in pattern:
                pattern = f"*{pattern}*"
            clauses.append("d.path_fold GLOB ? OR d.path2_fold GLOB ?")
            params.extend([glob_escape(pattern)] * 2)
        return " OR ".join(clauses), params

    def field_under(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        clauses: list[str] = []
        params: list[object] = []
        for item in _items(value):
            prefix = self._path_pattern(_scalar(item, "under")).replace("*", "").replace("?", "")
            if not prefix.startswith("/"):
                prefix = "/" + prefix
            prefix = prefix.rstrip("/") + "/"
            clauses.append("d.path_fold GLOB ? OR d.path2_fold GLOB ?")
            params.extend([glob_escape(prefix) + "*"] * 2)
        return " OR ".join(clauses), params

    def field_ext(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        names = [fold(_scalar(item, "ext")).lstrip(".") for item in _items(value)]
        return f"d.ext IN ({', '.join('?' for _ in names)})", names

    def field_extset(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        names: list[str] = []
        for item in _items(value):
            key = fold(_scalar(item, "extset"))
            if key not in EXTSETS:
                raise QueryError(f"알 수 없는 확장자 묶음입니다: {key} (가능: {', '.join(EXTSETS)})", item.pos or term.pos)
            names.extend(ext.lstrip(".") for ext in EXTSETS[key])
        names = sorted(set(names))
        return f"d.ext IN ({', '.join('?' for _ in names)})", names

    def field_size(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        position = value.pos or term.pos
        if value.kind == "range":
            clauses = ["d.size IS NOT NULL"]
            params: list[object] = []
            if value.low:
                clauses.append("d.size >= ?")
                params.append(parse_size(value.low, position))
            if value.high:
                clauses.append("d.size <= ?")
                params.append(parse_size(value.high, position))
            return " AND ".join(clauses), params
        text = _scalar(value, "size")
        for operator in (">=", "<=", ">", "<", "="):
            if text.startswith(operator):
                return f"d.size {operator} ?", [parse_size(text[len(operator):], position)]
        return "d.size = ?", [parse_size(text, position)]

    def _flag(self, column: str, value: Value, name: str) -> tuple[str, list[object]]:
        return f"d.{column} = ?", [1 if _bool(value, name) else 0]

    def field_deleted(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._flag("deleted", value, "deleted")

    def field_mismatch(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._flag("sig_mismatch", value, "mismatch")

    def field_archive(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._flag("in_archive", value, "archive")

    def _search_field(self, name: str, term: Term, value: Value) -> tuple[str, list[object]]:
        clauses: list[str] = []
        params: list[object] = []
        for item in _items(value):
            text = fold(_scalar(item, term.field))
            pattern = glob_to_like(text) if ("*" in text or "?" in text) else f"%{like_escape(text)}%"
            clauses.append("f.value_fold LIKE ? ESCAPE '\\'")
            params.append(pattern)
        return self.group_in("f.doc_id", "search_field f", f"f.name = ? AND ({' OR '.join(clauses)})"), [name, *params]

    def field_author(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._search_field("author", term, value)

    def field_savedby(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._search_field("last_saved_by", term, value)

    def field_template(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._search_field("template", term, value)

    def field_provider(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._search_field("provider", term, value)

    def field_channel(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        return self._search_field("channel", term, value)

    def field_eventid(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        exact: list[int] = []
        ranges: list[tuple[int, int]] = []
        for item in _items(value):
            text = _scalar(item, "eventid")
            match = re.fullmatch(r"(\d{1,6})\s*-\s*(\d{1,6})", text)
            if match is not None:
                low, high = int(match.group(1)), int(match.group(2))
                if low > high:
                    raise QueryError("이벤트 ID 범위의 시작이 끝보다 큽니다", item.pos or term.pos)
                ranges.append((low, high))
            elif text.isdigit() and len(text) <= 6:
                exact.append(int(text))
            else:
                raise QueryError("eventid: 값은 숫자·범위(7045-7050)·목록이어야 합니다", item.pos or term.pos)
        clauses: list[str] = []
        params: list[object] = []
        if exact:
            clauses.append(f"f.value_int IN ({', '.join('?' for _ in exact)})")
            params.extend(exact)
        for low, high in ranges:
            clauses.append("f.value_int BETWEEN ? AND ?")
            params.extend([low, high])
        return self.group_in("f.doc_id", "search_field f", f"f.name = 'eventid' AND ({' OR '.join(clauses)})"), params

    def field_analysis(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        ids = []
        for item in _items(value):
            text = _scalar(item, "analysis")
            if not ANALYSIS_ID_RE.fullmatch(text):
                raise QueryError(f"분석 id 형식이 아닙니다: {text}", item.pos or term.pos)
            ids.append(text)
        return f"d.analysis_id IN ({', '.join('?' for _ in ids)})", ids

    # -- review --------------------------------------------------------------

    def marks(self) -> list[Mapping[str, object]]:
        if self.ctx._marks is None:
            marks = self.ctx.review_provider() if self.ctx.review_provider is not None else None
            if marks is None:
                self.ctx.warn("케이스 DB가 없어 리뷰 조건과 일치하는 행이 없습니다")
                marks = []
            self.ctx._marks = [mark for mark in marks if mark.get("locator")]
        return self.ctx._marks

    def review_table(self, predicate: Callable[[Mapping[str, object]], bool]) -> str:
        self.ctx.temp_tables += 1
        name = f"rv_{self.ctx.temp_tables}"
        connection = self.ctx.connection
        connection.execute(f"CREATE TEMP TABLE {name} (collection TEXT, kind TEXT, locator TEXT, PRIMARY KEY (collection, kind, locator)) WITHOUT ROWID")
        connection.executemany(
            f"INSERT OR IGNORE INTO temp.{name} VALUES (?, ?, ?)",
            [(str(mark.get("collection") or ""), str(mark.get("kind") or ""), str(mark.get("locator") or "")) for mark in self.marks() if predicate(mark)],
        )
        # An archive entry (``<locator>#entry:<n>``) carries the mark of its archive record.
        return (
            f"((d.collection, d.kind, d.locator) IN (SELECT collection, kind, locator FROM temp.{name}) OR "
            f"(d.artifact_type = 'archive-entry' AND instr(d.locator, '{ENTRY_MARK}') > 0 AND "
            f"(d.collection, d.kind, substr(d.locator, 1, instr(d.locator, '{ENTRY_MARK}') - 1)) IN "
            f"(SELECT collection, kind, locator FROM temp.{name})))"
        )

    def field_review(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        statuses = {fold(_scalar(item, "review")) for item in _items(value)}
        clauses: list[str] = []
        if "unreviewed" in statuses:
            clauses.append("NOT " + self.review_table(lambda mark: True))
            statuses.discard("unreviewed")
        if "include-in-report" in statuses:
            clauses.append(self.review_table(lambda mark: bool(mark.get("include_in_report"))))
            statuses.discard("include-in-report")
        if statuses:
            clauses.append(self.review_table(lambda mark: fold(mark.get("status")) in statuses))
        return " OR ".join(f"({clause})" for clause in clauses), []

    def field_tag(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        wanted = {fold(_scalar(item, "tag")) for item in _items(value)}
        return self.review_table(lambda mark: bool(wanted & {fold(tag) for tag in (mark.get("tags") or [])})), []

    def field_note(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        needles = [fold(_scalar(item, "note")) for item in _items(value)]
        return self.review_table(lambda mark: any(needle in fold(mark.get("note")) for needle in needles)), []

    def field_bookmark(self, term: Term, value: Value, negated: bool) -> tuple[str, list[object]]:
        sql = self.review_table(lambda mark: BOOKMARK_TAG in (mark.get("tags") or []))
        return (sql if _bool(value, "bookmark") else f"NOT {sql}"), []


# ---------------------------------------------------------------------------
# cursors
# ---------------------------------------------------------------------------


def query_hash(q: str, options: SearchOptions, collapse: bool, build_id: str) -> str:
    payload = json.dumps({"q": q.strip(), "options": options.cache_key(), "collapse": collapse, "build": build_id}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def encode_cursor(qhash: str, sort: str, effective: str, key: object, row_id: int, direction: str) -> str:
    payload = json.dumps(
        {"v": CURSOR_VERSION, "qhash": qhash, "sort": sort, "es": effective, "last": [key, row_id], "dir": direction},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _sql_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and -SQL_INT_MAX - 1 <= value <= SQL_INT_MAX


def decode_cursor(cursor: str, qhash: str, sort: str) -> tuple[object, int, str, str]:
    """``(key, row_id, direction, effective sort)``; 400 for anything that is not this query's cursor."""
    message = "커서가 이 질의에 맞지 않습니다"
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise QueryError(message) from exc
    if not isinstance(payload, dict) or payload.get("v") != CURSOR_VERSION or payload.get("qhash") != qhash or payload.get("sort") != sort:
        raise QueryError(message)
    effective = payload.get("es")
    last = payload.get("last")
    direction = payload.get("dir") or "next"
    if effective not in SORTS or not isinstance(last, list) or len(last) != 2 or direction not in {"next", "prev"}:
        raise QueryError(message)
    key, row_id = last
    if not _sql_int(row_id) or row_id < 0:
        raise QueryError(message)
    if not (_sql_int(key) or (isinstance(key, str) and len(key) <= 4096)):
        raise QueryError(message)
    return key, row_id, direction, str(effective)


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------


@dataclass
class QueryRequest:
    q: str
    options: SearchOptions = field(default_factory=SearchOptions)
    cursor: str | None = None
    limit: int = 100
    sort: str = "relevance"
    collapse: bool = True
    facets: bool = True
    histogram: str | None = None
    highlight: bool = True
    view: str = "rows"
    aggregates: bool = True


@dataclass
class Prepared:
    """A compiled query: set-mode predicate, optional row-mode predicate, regex jobs done."""

    where: str
    params: list[object]
    ctx: CompileContext
    row_where: str | None = None
    row_params: list[object] = field(default_factory=list)
    regex_spans: dict[str, dict[int, tuple[int, int]]] = field(default_factory=dict)
    regex_unchecked: int = 0


class SearchIndex:
    """One read-only index connection with its meta, opened per request and closed promptly."""

    def __init__(self, index_path: Path, meta: Mapping[str, object], *, budget: Budget) -> None:
        self.path = index_path
        self.meta = meta
        self.budget = budget
        self.connection = open_read_only(index_path)
        try:
            register_functions(self.connection)
            self.connection.set_progress_handler(self._progress, PROGRESS_OPCODES)
        except BaseException:
            self.connection.close()
            raise

    def _progress(self) -> int:
        return 1 if self.budget.expired() else 0

    def close(self) -> None:
        try:
            self.connection.set_progress_handler(None, 0)
            self.connection.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> SearchIndex:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def grace(self) -> None:
        """After a budget cut: a short grace budget to page/aggregate what was found (not after a disconnect)."""
        if not self.budget.cancelled:
            self.budget = Budget(GRACE_SECONDS, self.budget.cancel_event)

    @property
    def tokenizer(self) -> str:
        return str(self.meta.get("tokenizer") or TOKENIZER_TRIGRAM)

    @property
    def build_id(self) -> str:
        return str(self.meta.get("build_id") or "")

    def tz(self, override: str | None) -> dt.timedelta:
        if override:
            offset = parse_offset(override)
            if offset is None:
                raise QueryError("options.tz는 +09:00 같은 UTC 오프셋이어야 합니다")
            return offset
        return parse_offset(self.meta.get("tz")) or dt.timedelta(0)

    def reference_ms(self, override: str | None, tz: dt.timedelta) -> int | None:
        if override:
            return resolve_time(override, 0, end=False, tz=tz, ref_ms=None)
        row = self.connection.execute("SELECT MAX(ts) FROM search_doc").fetchone()
        return int(row[0]) if row and row[0] is not None else None

    def prepare(
        self,
        parsed: ParsedQuery,
        options: SearchOptions,
        *,
        review_provider: ReviewProvider | None,
        hashset_resolver: HashsetResolver | None,
        row_mode: bool,
    ) -> Prepared:
        tz = self.tz(options.tz)
        ctx = CompileContext(
            connection=self.connection,
            tokenizer=self.tokenizer,
            bigram=self.meta.get("bigram") == BIGRAM_RULE,
            folded=self.meta.get("fold") == FOLD_RULE,
            tz=tz,
            ref_ms=self.reference_ms(options.reference_ts, tz),
            options=options,
            review_provider=review_provider,
            hashset_resolver=hashset_resolver,
        )
        ctx.warnings.extend(parsed.warnings)
        compiler = Compiler(ctx)
        assert parsed.root is not None
        where, params = compiler.compile(parsed.root)
        hidden: list[str] = []
        for hashset_id in options.hide_hashsets[:MAX_LIST_ITEMS]:
            sql = compiler.hashset_clause(str(hashset_id), 0, missing_ok=True)
            if sql is not None:
                hidden.append(sql)
        for sql in hidden:
            where = f"({where}) AND NOT ({sql})"
        prepared = Prepared(where=where, params=params, ctx=ctx)
        if row_mode and not ctx.regex_jobs:
            row_compiler = Compiler(ctx, mode="row")
            row_where, row_params = row_compiler.compile(parsed.root)
            for hashset_id in options.hide_hashsets[:MAX_LIST_ITEMS]:
                if hashset_id in ctx.attached:
                    sql = row_compiler.hashset_clause(str(hashset_id), 0, missing_ok=True)
                    row_where = f"({row_where}) AND NOT ({sql})"
            prepared.row_where, prepared.row_params = row_where, row_params
        return prepared

    def run_regex_jobs(self, prepared: Prepared) -> None:
        """Match every ``re:`` term's candidates in Python (cooperative; raises :class:`Interrupted`)."""
        for job in prepared.ctx.regex_jobs:
            self.connection.execute(f"CREATE TEMP TABLE IF NOT EXISTS {job.table} (doc_id INTEGER PRIMARY KEY, s INTEGER, e INTEGER)")
        for job in prepared.ctx.regex_jobs:
            spans = prepared.regex_spans.setdefault(job.table, {})
            if job.literal and self.tokenizer == TOKENIZER_TRIGRAM and "%" not in job.literal and "_" not in job.literal:
                sql = "SELECT d.doc_id, d.text FROM search_doc d WHERE d.doc_id IN (SELECT rowid FROM search_text WHERE text LIKE ?) ORDER BY d.doc_id"
                # A v4 index's full-text content is folded: the (prefilter) literal is folded too.
                literal = fold(job.literal) if prepared.ctx.folded else job.literal
                params: list[object] = [f"%{literal}%"]
            elif job.literal:
                sql = "SELECT doc_id, text FROM search_doc WHERE text IS NOT NULL AND instr(lower(text), ?) > 0 ORDER BY doc_id"
                params = [ascii_lower(job.literal)]
            else:
                sql = "SELECT doc_id, text FROM search_doc WHERE text IS NOT NULL ORDER BY doc_id"
                params = []
            cursor = self.connection.execute(sql, params)
            found: list[tuple[int, int, int]] = []
            checked = 0
            try:
                while True:
                    chunk = cursor.fetchmany(REGEX_FETCH)
                    if not chunk:
                        break
                    for doc_id, text in chunk:
                        checked += 1
                        if checked % REGEX_CHECK_ROWS == 0:
                            self.budget.check()
                        try:
                            span = job.matcher.search(str(text or ""))
                        except RowTimeout:
                            prepared.regex_unchecked += 1
                            continue
                        if span is not None:
                            found.append((int(doc_id), span[0], span[1]))
                            spans[int(doc_id)] = span
                    if found:
                        self.connection.executemany(f"INSERT OR IGNORE INTO temp.{job.table} VALUES (?, ?, ?)", found)
                        found.clear()
                    self.budget.check()
            except sqlite3.OperationalError as exc:
                if self.budget.expired():
                    raise Interrupted(self.budget.reason or "") from exc
                raise
            finally:
                cursor.close()
                if found:
                    self.connection.executemany(f"INSERT OR IGNORE INTO temp.{job.table} VALUES (?, ?, ?)", found)

    def materialize(self, where: str, params: list[object], *, table: str = "m") -> tuple[int, bool]:
        """One pass of the predicate -> ``temp.<table>`` (at most ``TOTAL_CAP + 1`` rows); ``(rows, capped)``."""
        connection = self.connection
        connection.execute(f"DROP TABLE IF EXISTS temp.{table}")
        connection.execute(
            f"CREATE TEMP TABLE {table} (doc_id INTEGER PRIMARY KEY, group_id INTEGER, ts INTEGER, domain TEXT, "
            "collection TEXT, artifact_type TEXT, ts_kind TEXT, actor TEXT, computer TEXT, first INTEGER)"
        )
        try:
            # ``first``: the group's representative row in this result (the primary row when it matched).
            connection.execute(
                f"INSERT INTO temp.{table} (doc_id, group_id, ts, domain, collection, artifact_type, ts_kind, actor, computer, first) "
                "SELECT d.doc_id, d.group_id, d.ts, d.domain, d.collection, d.artifact_type, d.ts_kind, d.actor, d.computer, d.doc_id = d.group_id "
                f"FROM search_doc d WHERE {where} LIMIT ?",
                [*params, TOTAL_CAP + 1],
            )
            count = int(connection.execute(f"SELECT COUNT(*) FROM temp.{table}").fetchone()[0])
            capped = count > TOTAL_CAP
            connection.execute(f"CREATE INDEX temp.{table}_group ON {table}(group_id)")
            # Groups whose primary row did not match (a time window hit only a repeated row): their smallest row.
            connection.execute(
                f"UPDATE temp.{table} SET first = 1 WHERE doc_id IN (SELECT MIN(doc_id) FROM temp.{table} "
                f"WHERE doc_id != group_id AND group_id NOT IN (SELECT doc_id FROM temp.{table}) GROUP BY group_id)"
            )
        except sqlite3.OperationalError as exc:
            if self.budget.expired():
                raise Interrupted(self.budget.reason or "") from exc
            raise
        return count, capped


# ---------------------------------------------------------------------------
# pages
# ---------------------------------------------------------------------------


def _key_sql(sort: str, collapse: bool) -> tuple[str, str]:
    """(key expression, ORDER direction)."""
    if sort == "ts":
        key = f"COALESCE(ts, {TS_NULL_HIGH})"
        return (f"MIN({key})" if collapse else key), "ASC"
    if sort == "-ts":
        key = f"COALESCE(ts, {TS_NULL_LOW})"
        return (f"MAX({key})" if collapse else key), "DESC"
    if sort == "path":
        return ("MIN(path_fold)" if collapse else "path_fold"), "ASC"
    return ("MIN(doc_id)" if collapse else "doc_id"), "ASC"


def page_ids(
    connection: sqlite3.Connection,
    source: str,
    source_params: list[object],
    *,
    sort: str,
    collapse: bool,
    limit: int,
    after: tuple[object, int] | None,
    direction: str,
) -> list[tuple[int, int, object]]:
    """Keyset page over ``source`` -> ``[(row_id, representative doc_id, key)]`` in display order."""
    key, order = _key_sql(sort, collapse)
    forward = direction == "next"
    effective = order if forward else ("DESC" if order == "ASC" else "ASC")
    comparator = ">" if effective == "ASC" else "<"
    rid = "group_id" if collapse else "doc_id"
    params = list(source_params)
    keyset = ""
    if after is not None:
        keyset = f"({key}, {rid}) {comparator} (?, ?)"
        params.extend([after[0], after[1]])
    if collapse:
        sql = (
            f"SELECT group_id AS rid, MIN(doc_id) AS rep, {key} AS k FROM {source} GROUP BY group_id "
            + (f"HAVING {keyset} " if keyset else "")
            + f"ORDER BY k {effective}, rid {effective} LIMIT ?"
        )
    else:
        sql = (
            f"SELECT doc_id AS rid, doc_id AS rep, {key} AS k FROM {source} "
            + (f"WHERE {keyset} " if keyset else "")
            + f"ORDER BY k {effective}, rid {effective} LIMIT ?"
        )
    params.append(limit)
    rows = [(int(row[0]), int(row[1]), row[2]) for row in connection.execute(sql, params)]
    return rows if forward else list(reversed(rows))


def _collect_groups(rows: Iterable[tuple[int, int]], *, collapse: bool, want: int) -> tuple[list[tuple[int, int, object]], bool]:
    """``(doc_id, group_id)`` rows in scan order -> page entries ``(rid, rep, key)`` (``want`` at most) and whether more exist."""
    entries: list[tuple[int, int, object]] = []
    if not collapse:
        for doc_id, _group_id in rows:
            if len(entries) == want:
                return entries, True
            entries.append((doc_id, doc_id, doc_id))
        return entries, False
    current: int | None = None
    rep = 0
    for doc_id, group_id in rows:
        if group_id != current:
            if current is not None:
                entries.append((current, rep, rep))
                if len(entries) == want:
                    return entries, True
            current, rep = group_id, doc_id
        else:
            rep = min(rep, doc_id)
    if current is not None:
        entries.append((current, rep, rep))
    return entries[:want], len(entries) > want


def stream_page(
    connection: sqlite3.Connection,
    where: str,
    params: list[object],
    *,
    collapse: bool,
    limit: int,
    after: int | None,
    direction: str,
    budget: Budget,
) -> tuple[list[tuple[int, int, object]], bool]:
    """Relevance page streaming the set-mode predicate in ``doc_id`` order (stops at ``limit + 1``)."""
    forward = direction == "next"
    order = "ASC" if forward else "DESC"
    column = "d.group_id" if collapse else "d.doc_id"
    sql = f"SELECT d.doc_id, d.group_id FROM search_doc d WHERE ({where})"
    sql_params = list(params)
    if after is not None:
        sql += f" AND {column} {'>' if forward else '<'} ?"
        sql_params.append(after)
    sql += f" ORDER BY d.doc_id {order}"
    cursor = connection.execute(sql, sql_params)

    def rows() -> Iterator[tuple[int, int]]:
        while True:
            chunk = cursor.fetchmany(STREAM_FETCH)
            if not chunk:
                return
            for doc_id, group_id in chunk:
                yield int(doc_id), int(group_id)
            budget.check()

    try:
        entries, more = _collect_groups(rows(), collapse=collapse, want=limit)
    finally:
        cursor.close()
    return (entries if forward else list(reversed(entries))), more


def driver_page(
    connection: sqlite3.Connection,
    driver: Driver,
    row_where: str,
    row_params: list[object],
    *,
    collapse: bool,
    limit: int,
    after: int | None,
    direction: str,
    budget: Budget,
) -> tuple[list[tuple[int, int, object]], bool] | None:
    """Relevance page in the FTS index's own order (``rowid > :after LIMIT n``), each chunk checked in row mode.

    ``None`` when ``DRIVER_MAX_CHUNKS`` chunks did not fill the page (a dense keyword with a
    selective rest): the caller falls back to the set-mode plan.
    """
    forward = direction == "next"
    if driver.bigram:
        source, pattern = "search_bigram WHERE search_bigram MATCH ?", bigram_match(driver.literal)
    else:
        source, pattern = "search_text WHERE text LIKE ?", f"%{driver.literal}%"
    after_doc: int | None = None
    bound: int | None = None
    if after is not None:
        if collapse:
            bound = after
        else:
            after_doc = after
            row = connection.execute("SELECT group_id FROM search_doc WHERE doc_id = ?", (after,)).fetchone()
            group = int(row[0]) if row is not None else after
            bound = group - 1 if forward else group + 1  # the after-row's own group may still hold rows
    entries: list[tuple[int, int, object]] = []
    for _round in range(DRIVER_MAX_CHUNKS):
        if forward:
            sql = f"SELECT rowid FROM {source}" + (" AND rowid > ?" if bound is not None else "") + " ORDER BY rowid LIMIT ?"
        else:
            sql = f"SELECT rowid FROM {source}" + (" AND rowid < ?" if bound is not None else "") + " ORDER BY rowid DESC LIMIT ?"
        ids = [int(row[0]) for row in connection.execute(sql, [pattern, *([bound] if bound is not None else []), DRIVER_CHUNK])]
        if not ids:
            return (entries if forward else list(reversed(entries))), False
        bound = ids[-1]
        marks = ", ".join("?" for _ in ids)
        check = f"SELECT d.doc_id, d.group_id FROM search_doc d WHERE d.group_id IN ({marks}) AND ({row_where})"
        check_params: list[object] = [*ids, *row_params]
        if after_doc is not None:
            check += f" AND d.doc_id {'>' if forward else '<'} ?"
            check_params.append(after_doc)
        check += f" ORDER BY d.doc_id {'ASC' if forward else 'DESC'}"
        found = [(int(row[0]), int(row[1])) for row in connection.execute(check, check_params)]
        chunk_entries, _more = _collect_groups(found, collapse=collapse, want=len(found) + 1)
        for entry in chunk_entries:
            if len(entries) == limit:
                return (entries if forward else list(reversed(entries))), True
            entries.append(entry)
        budget.check()
        if len(ids) < DRIVER_CHUNK:
            return (entries if forward else list(reversed(entries))), False
    return None


# ---------------------------------------------------------------------------
# snippets
# ---------------------------------------------------------------------------


def build_snippet(
    text: str,
    terms: list[tuple[str, str]],
    regexes: list[tuple[GuardedRegex, tuple[int, int] | None]],
    *,
    highlight: bool,
) -> tuple[dict[str, object], list[dict[str, str]]]:
    """``{text, marks:[[start,end]…]}`` around the first match, and the terms that matched.

    Regex spans come from the pre-pass (the same guarded matcher); highlighting inside the
    window re-runs the guarded matcher on that short window only.
    """
    matched: list[dict[str, str]] = []
    spans: list[tuple[int, int]] = []
    for field_name, literal in terms:
        pattern = _word_regex(literal) if field_name == "word" else _literal_regex(literal)
        found = pattern.search(text)
        if found is not None:
            matched.append({"term": literal, "field": field_name})
            spans.append((found.start(), found.end()))
        elif field_name != "word":
            # Full case folding (``straße`` ~ ``STRASSE``) that ``re.IGNORECASE`` does not do.
            located = locate_normalized(text, literal)
            if located is not None and located[0] == text:
                matched.append({"term": literal, "field": field_name})
                spans.append((located[1], located[2]))
    for matcher, span in regexes:
        if span is not None and span[1] > span[0]:
            matched.append({"term": matcher.pattern, "field": "re"})
            spans.append(span)
    if not spans:
        body = text.split("\n", 1)
        excerpt = (body[1] if len(body) > 1 else body[0])[: SNIPPET_AFTER + SNIPPET_BEFORE]
        return {"text": " ".join(excerpt.split()), "marks": []}, matched
    first = min(spans)[0]
    start = max(0, first - SNIPPET_BEFORE)
    end = min(len(text), first + SNIPPET_AFTER)
    window = text[start:end]
    marks: list[list[int]] = []
    if highlight:
        for field_name, literal in terms:
            pattern = _word_regex(literal) if field_name == "word" else _literal_regex(literal)
            before = len(marks)
            for found in pattern.finditer(window):
                if found.end() > found.start():
                    marks.append([found.start(), found.end()])
                if len(marks) >= MAX_MARKS:
                    break
            if len(marks) == before and field_name != "word":
                located = locate_normalized(window, literal)
                if located is not None and located[0] == window and located[2] > located[1]:
                    marks.append([located[1], located[2]])
        for matcher, _span in regexes:
            if len(marks) >= MAX_MARKS:
                break
            marks.extend([a, b] for a, b in matcher.spans(window, MAX_MARKS - len(marks)))
        marks.sort()
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    shift = len(prefix)
    return {"text": prefix + window.replace("\n", " ") + suffix, "marks": [[a + shift, b + shift] for a, b in marks]}, matched


# ---------------------------------------------------------------------------
# aggregates (all from temp.m, one predicate pass)
# ---------------------------------------------------------------------------


def choose_bucket(span_ms: int, requested: str) -> tuple[int, str | None]:
    """Bucket seconds for ``span_ms``; never more than ``MAX_BUCKETS`` buckets (widened with a warning)."""
    span = max(1, span_ms) / 1000
    if requested == "auto":
        for candidate in AUTO_BUCKETS:
            if span / candidate <= AUTO_MAX_BUCKETS:
                return candidate, None
        return math.ceil(span / AUTO_MAX_BUCKETS), None
    seconds = BUCKETS.get(requested)
    if seconds is None:
        raise QueryError(f"히스토그램 구간은 auto 또는 {', '.join(BUCKETS)} 중 하나여야 합니다")
    if span / seconds > MAX_BUCKETS - 2:
        # Two buckets of slack: the first bucket starts at an aligned boundary before the data.
        widened = max(seconds, math.ceil(span / (MAX_BUCKETS - 2)))
        return widened, f"히스토그램 구간이 {MAX_BUCKETS:,}개를 넘어 구간을 {widened:,}초로 넓혔습니다"
    return seconds, None


def _after_hours_sql(column: str) -> str:
    expression = f"((({column} / 1000 + ?) % 86400) + 86400) % 86400"
    return f"({column} IS NOT NULL AND ({expression} >= ? OR {expression} < ?))"


def build_aggregates(
    connection: sqlite3.Connection,
    *,
    collapse: bool,
    facets: bool,
    bucket: str | None,
    tz: dt.timedelta,
    time_range: tuple[int | None, int | None] | None,
    gap_seconds: int | None,
    warnings: list[str],
    exact: bool,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Facets (one GROUP BY) and histogram (one GROUP BY) from ``temp.m`` -- never the live predicate.

    With ``collapse`` every count is of distinct groups: group-invariant facets count the
    groups' ``first`` rows; ``ts_kind``, histogram buckets and the after-hours count subtract
    the repeated rows of a group that fall in the same key (only ``doc_id != group_id`` rows
    can be such repeats, so the correction reads few rows).
    """
    tz_seconds = int(tz.total_seconds())
    after_params = [tz_seconds, AFTER_HOURS_START * 3600, tz_seconds, AFTER_HOURS_END * 3600]
    histogram_spec: tuple[int, int, int, int, int] | None = None  # (start, step, high, low, seconds)
    if bucket:
        row = connection.execute("SELECT MIN(ts), MAX(ts) FROM temp.m WHERE ts IS NOT NULL").fetchone()
        if row is not None and row[0] is not None:
            low, high = int(row[0]), int(row[1])
            if time_range is not None:
                # Only a top-level AND time window bounds the axis (under OR/NOT it does not bound the rows).
                low = time_range[0] if time_range[0] is not None else low
                high = time_range[1] if time_range[1] is not None else high
            seconds, warning = choose_bucket(max(1, high - low), bucket)
            if warning:
                warnings.append(warning)
            step = seconds * 1000
            offset = int(tz.total_seconds() * 1000)
            start = ((low + offset) // step) * step - offset
            histogram_spec = (start, step, high, low, seconds)
    if not facets and histogram_spec is None:
        return None, None
    bucket_sql = "NULL"
    bucket_params: list[object] = []
    if histogram_spec is not None:
        start, step, high, _low, _seconds = histogram_spec
        bucket_sql = "CASE WHEN {ts} IS NOT NULL AND {ts} >= ? AND {ts} <= ? THEN ({ts} - ?) / ? END"
        bucket_params = [start, high, start, step]
    counters: dict[str, Counter[str]] = {name: Counter() for name, _limit in FACET_LIMITS}
    ts_kinds: Counter[str] = Counter()
    buckets: dict[int, Counter[str]] = {}
    after_hours = 0
    if facets:
        for domain, collection, artifact_type, actor, computer, ts_kind, number, firsts in connection.execute(
            "SELECT domain, collection, artifact_type, actor, computer, ts_kind, COUNT(*), SUM(first) FROM temp.m GROUP BY 1, 2, 3, 4, 5, 6"
        ):
            weight = int(firsts or 0) if collapse else int(number)
            for name, value in (("domain", domain), ("collection", collection), ("artifact_type", artifact_type), ("actor", actor), ("computer", computer)):
                if value:
                    counters[name][str(value)] += weight
            if ts_kind:
                ts_kinds[str(ts_kind)] += int(number)
    if histogram_spec is not None:
        start, step, high, _low, _seconds = histogram_spec
        for bucket_index, domain, number in connection.execute(
            "SELECT (ts - ?) / ?, domain, COUNT(*) FROM temp.m WHERE ts IS NOT NULL AND ts >= ? AND ts <= ? GROUP BY 1, 2", [start, step, start, high]
        ):
            buckets.setdefault(int(bucket_index), Counter())[str(domain)] += int(number)
        row = connection.execute(f"SELECT COUNT(*) FROM temp.m WHERE {_after_hours_sql('ts')}", after_params).fetchone()
        after_hours = int(row[0]) if row else 0
    if collapse:
        # Repeated rows of one group with the same key count once.
        repeat = "x.doc_id != x.group_id AND EXISTS (SELECT 1 FROM temp.m y WHERE y.group_id = x.group_id AND y.doc_id < x.doc_id AND {same})"
        if facets:
            for ts_kind, number in connection.execute(
                "SELECT x.ts_kind, COUNT(*) FROM temp.m x WHERE x.ts_kind != '' AND " + repeat.format(same="y.ts_kind = x.ts_kind") + " GROUP BY 1"
            ):
                ts_kinds[str(ts_kind)] -= int(number)
        if histogram_spec is not None:
            x_bucket = bucket_sql.format(ts="x.ts")
            y_bucket = bucket_sql.format(ts="y.ts")
            for bucket_index, domain, number in connection.execute(
                f"SELECT {x_bucket} AS b, x.domain, COUNT(*) FROM temp.m x WHERE " + repeat.format(same=f"{y_bucket} = {x_bucket}") + " GROUP BY 1, 2",
                [*bucket_params, *bucket_params, *bucket_params],
            ):
                if bucket_index is not None:
                    buckets.setdefault(int(bucket_index), Counter())[str(domain)] -= int(number)
            dup_after = connection.execute(
                f"SELECT COUNT(*) FROM temp.m x WHERE {_after_hours_sql('x.ts')} AND " + repeat.format(same=_after_hours_sql("y.ts")),
                [*after_params, *after_params],
            ).fetchone()
            after_hours -= int(dup_after[0]) if dup_after else 0
    facet_payload: dict[str, object] | None = None
    if facets:
        facet_payload = {"exact": exact}
        for name, limit in FACET_LIMITS:
            ordered = sorted(counters[name].items(), key=lambda item: (-item[1], item[0]))[:limit]
            facet_payload[name] = [{"key": key, "count": count} for key, count in ordered]
        ordered_kinds = sorted(((key, count) for key, count in ts_kinds.items() if count > 0), key=lambda item: (-item[1], item[0]))[:30]
        facet_payload["ts_kind"] = [{"key": key, "count": count} for key, count in ordered_kinds]
        order = ["exact", "domain", "collection", "artifact_type", "ts_kind", "actor", "computer"]
        facet_payload = {key: facet_payload[key] for key in order}
    histogram: dict[str, object] | None = None
    if histogram_spec is not None:
        start, step, high, low, seconds = histogram_spec
        count = min(MAX_BUCKETS, int((high - start) // step) + 1)  # choose_bucket keeps two buckets of slack
        series = []
        for index in range(count):
            by_domain = {key: value for key, value in sorted(buckets.get(index, Counter()).items()) if value > 0}
            series.append({"start": ms_to_iso(start + index * step, tz), "count": sum(by_domain.values()), "by_domain": by_domain})
        histogram = {
            "bucket_seconds": seconds,
            "range_start": ms_to_iso(low, tz),
            "range_end": ms_to_iso(high, tz),
            "tz": format_offset(tz),
            "buckets": series,
            "counts": "groups" if collapse else "rows",
            "exact": exact,
            "after_hours_count": after_hours,
            "after_hours": {"start_hour": AFTER_HOURS_START, "end_hour": AFTER_HOURS_END},
        }
        if gap_seconds is not None:
            histogram["gaps"] = find_gaps(connection, gap_seconds, tz)
    return facet_payload, histogram


def find_gaps(connection: sqlite3.Connection, gap_seconds: int, tz: dt.timedelta) -> list[dict[str, object]]:
    """Silent stretches of at least ``gap_seconds`` between consecutive times of ``temp.m`` (SQL window)."""
    rows = connection.execute(
        "SELECT previous, ts FROM (SELECT ts, LAG(ts) OVER (ORDER BY ts) AS previous FROM (SELECT DISTINCT ts FROM temp.m WHERE ts IS NOT NULL)) "
        "WHERE previous IS NOT NULL AND ts - previous >= ? ORDER BY ts LIMIT ?",
        (gap_seconds * 1000, MAX_GAPS),
    ).fetchall()
    return [{"start": ms_to_iso(int(a), tz), "end": ms_to_iso(int(b), tz), "seconds": (int(b) - int(a)) // 1000} for a, b in rows]


EMPTY_FACETS = {"domain": [], "collection": [], "artifact_type": [], "ts_kind": [], "actor": [], "computer": []}


def _row_payload(
    row: sqlite3.Row,
    *,
    tz: dt.timedelta,
    terms: list[tuple[str, str]],
    regexes: list[tuple[GuardedRegex, tuple[int, int] | None]],
    highlight: bool,
    ts_kinds: list[str] | None,
) -> dict[str, object]:
    text = str(row["ptext"] or "")
    snippet, matched = build_snippet(text, terms, regexes, highlight=highlight)
    try:
        fields = json.loads(row["pfields"] or "{}")
    except ValueError:
        fields = {}
    fields = dict(list(fields.items())[:20]) if isinstance(fields, dict) else {}
    ts = row["ts"]
    record_ts = row["pts_text"] if "pts_text" in row.keys() else ""
    return {
        "doc_id": int(row["doc_id"]),
        "group_id": int(row["group_id"]),
        "collection": row["collection"],
        "kind": row["kind"],
        "locator": row["locator"],
        "analysis_id": row["analysis_id"],
        "domain": row["domain"],
        "artifact_type": row["artifact_type"],
        "title": row["title"],
        "path": row["path"],
        "target_path": row["path2"] or None,
        "size": row["size"],
        "ts": ms_to_iso(ts, dt.timedelta(0)) if ts is not None else None,
        "ts_local": ms_to_iso(ts, tz) if ts is not None else None,
        "ts_kind": row["ts_kind"] or None,
        # The record's own time as its source spells it (v4; what a v1 hit shows as ``timestamp``).
        "record_ts": record_ts or None,
        "ts_kinds": ts_kinds if ts_kinds is not None else ([row["ts_kind"]] if row["ts_kind"] else []),
        "actor": row["actor"],
        "computer": row["computer"],
        "hashes": {"md5": row["md5"] or None, "sha1": row["sha1"] or None, "sha256": row["sha256"] or None},
        "flags": {"deleted": bool(row["deleted"]), "sig_mismatch": bool(row["sig_mismatch"]), "in_archive": bool(row["in_archive"])},
        "truncated": bool(row["truncated"]),
        "snippet": snippet,
        "matched": matched,
        "fields": fields,
        "review": None,
        "pii": None,
        "masked_preview": [],
    }


def _has_ts_text(connection: sqlite3.Connection) -> bool:
    """Index v4 rows carry ``ts_text`` (v2/v3 indexes stay readable without it)."""
    return any(row[1] == "ts_text" for row in connection.execute("PRAGMA table_info(search_doc)"))


def fetch_rows(connection: sqlite3.Connection, doc_ids: list[int]) -> dict[int, sqlite3.Row]:
    if not doc_ids:
        return {}
    marks = ", ".join("?" for _ in doc_ids)
    record_ts = ", p.ts_text AS pts_text" if _has_ts_text(connection) else ""
    rows = connection.execute(
        f"SELECT d.*, p.text AS ptext, p.fields_json AS pfields{record_ts} FROM search_doc d JOIN search_doc p ON p.doc_id = d.group_id "
        f"WHERE d.doc_id IN ({marks})",
        doc_ids,
    ).fetchall()
    return {int(row["doc_id"]): row for row in rows}


def _check_index(meta: Mapping[str, object]) -> None:
    if meta.get("index_version") not in READABLE_INDEX_VERSIONS:
        raise QueryError("검색 색인 형식이 오래되었습니다. 처리 단계에서 색인을 다시 만드세요", status=409)


def _sql_error(exc: Exception) -> QueryError:
    """SQLite/limit errors of a query (never a 500)."""
    text = str(exc)
    lowered = text.lower()
    if "too many sql variables" in lowered or "too many terms" in lowered or "expression tree is too large" in lowered:
        return QueryError("질의가 너무 복잡합니다(조건·목록 값을 줄이세요)")
    if "parser stack overflow" in lowered or "too many attached" in lowered:
        return QueryError("질의가 너무 복잡합니다(괄호·NOT·해시 세트를 줄이세요)")
    if "locked" in lowered or "busy" in lowered:
        return QueryError("색인이 잠겨 있습니다(색인을 고치는 중). 잠시 뒤 다시 검색하세요", status=503)
    if isinstance(exc, OverflowError):
        return QueryError("질의의 숫자 값이 너무 큽니다")
    return QueryError(f"검색을 실행할 수 없습니다: {text}")


# Search sources a truncated-rows warning names (collection -> Korean label).
SOURCE_LABELS = {"docs": "문서", "files": "파일", "artifacts": "아티팩트", "indicators": "지표", "analysis": "분석 결과"}


def truncated_warning(meta: Mapping[str, object], collections: Iterable[str], domains: Iterable[str] = ()) -> str | None:
    """The matched sources (all when nothing matched) that hold rows cut at an index cap, with the
    number of cut rows per source (``문서 8건, 아티팩트 45건``); indexes before v4 name domains."""
    summary = meta.get("summary") if isinstance(meta.get("summary"), Mapping) else {}
    by_collection = summary.get("truncated_by_collection")
    if isinstance(by_collection, Mapping):
        counts, wanted, labels = by_collection, set(collections), SOURCE_LABELS
    else:
        by_domain = summary.get("truncated_by_domain")
        counts, wanted, labels = (by_domain if isinstance(by_domain, Mapping) else {}), set(domains), {}
    wanted = wanted or {str(name) for name in counts}
    hits = {str(name): int(count) for name, count in counts.items() if name in wanted and isinstance(count, int) and count > 0}
    if not hits:
        return None
    detail = ", ".join(f"{labels.get(name, name)} {count:,}건" for name, count in sorted(hits.items(), key=lambda item: (-item[1], item[0]))[:6])
    return f"색인 상한에서 본문 일부가 잘린 행이 있어 잘린 뒷부분은 검색되지 않습니다(본문이 잘린 행: {detail})"


def run_query(
    index_path: Path,
    meta: Mapping[str, object],
    request: QueryRequest,
    *,
    budget: Budget,
    review_provider: ReviewProvider | None = None,
    review_lookup: Callable[[list[dict[str, object]]], None] | None = None,
    hashset_resolver: HashsetResolver | None = None,
    stale: bool = False,
) -> dict[str, object]:
    """Execute one ``search/query`` request (plan §3.2 response shape). Raises :class:`QueryError` for 4xx."""
    parsed = parse_query(request.q)
    if request.sort not in SORTS:
        raise QueryError(f"정렬은 {', '.join(SORTS)} 중 하나여야 합니다")
    if request.histogram is not None and request.histogram != "auto" and request.histogram not in BUCKETS:
        raise QueryError(f"히스토그램 구간은 auto 또는 {', '.join(BUCKETS)} 중 하나여야 합니다")
    _check_index(meta)
    limit = max(1, min(PAGE_MAX, int(request.limit)))
    sort = "ts" if request.view == "timeline" and request.sort == "relevance" else request.sort
    try:
        with SearchIndex(index_path, meta, budget=budget) as index:
            return _run_query(index, parsed, request, sort, limit, budget, review_provider, review_lookup, hashset_resolver, stale)
    except (sqlite3.OperationalError, sqlite3.IntegrityError, OverflowError) as exc:
        raise _sql_error(exc) from exc
    except sqlite3.DatabaseError as exc:
        raise QueryError(f"검색 색인을 읽을 수 없습니다(손상): {exc}. 색인을 다시 만드세요", status=409) from exc


def _run_query(
    index: SearchIndex,
    parsed: ParsedQuery,
    request: QueryRequest,
    sort: str,
    limit: int,
    budget: Budget,
    review_provider: ReviewProvider | None,
    review_lookup: Callable[[list[dict[str, object]]], None] | None,
    hashset_resolver: HashsetResolver | None,
    stale: bool,
) -> dict[str, object]:
    meta = index.meta
    qhash = query_hash(request.q, request.options, request.collapse, index.build_id)
    after: tuple[object, int] | None = None
    direction = "next"
    cursor_sort: str | None = None
    if request.cursor:
        key, row_id, direction, cursor_sort = decode_cursor(request.cursor, qhash, sort)
        after = (key, row_id)
    wants_full = request.aggregates or sort != "relevance" or (cursor_sort is not None and cursor_sort != "relevance")
    prepared = index.prepare(
        parsed, request.options, review_provider=review_provider, hashset_resolver=hashset_resolver, row_mode=not wants_full
    )
    ctx = prepared.ctx
    warnings = ctx.warnings
    if stale:
        warnings.append("색인이 런 출력보다 오래되었습니다. 결과가 최신이 아닐 수 있습니다")
    truncated_reason: str | None = None
    try:
        index.run_regex_jobs(prepared)
    except Interrupted as exc:
        truncated_reason = exc.reason
        warnings.append("시간 예산이 끝나 정규식 후보를 모두 확인하지 못했습니다(일부 결과)")
        index.grace()
    if prepared.regex_unchecked:
        warnings.append(f"정규식 확인이 행당 시간 한도를 넘어 {prepared.regex_unchecked:,}개 행은 확인하지 못했습니다")
        truncated_reason = truncated_reason or "정규식 확인이 오래 걸리는 행이 있어 일부 행을 확인하지 못했습니다"
    connection = index.connection
    total: int | None = None
    complete = False
    capped = False
    materialized = False
    effective = cursor_sort or sort
    page_rows: list[tuple[int, int, object]] = []
    more = False
    page_done = False
    fast_cut = False
    if not wants_full and truncated_reason is None:
        try:
            page = _fast_page(index, prepared, request, limit, after, direction)
        except Interrupted as exc:
            page, fast_cut = None, True
            truncated_reason = exc.reason
            index.grace()
        if page is not None:
            page_rows, more = page
            page_done = True
            effective = "relevance"
    if not page_done:
        if index.budget.expired():
            truncated_reason = truncated_reason or index.budget.reason
            index.grace()
        if not fast_cut and not index.budget.expired():
            try:
                count, capped = index.materialize(prepared.where, prepared.params)
                materialized = True
            except Interrupted as exc:
                truncated_reason = truncated_reason or exc.reason
                index.grace()
        if materialized:
            groups, docs = connection.execute("SELECT COALESCE(SUM(first), 0), COUNT(*) FROM temp.m").fetchone()
            total = int(groups if request.collapse else docs)
            complete = truncated_reason is None and not capped
            if cursor_sort is None:
                effective = sort
                if sort in {"ts", "-ts"} and total > SORT_TS_CAP:
                    warnings.append(f"결과가 {SORT_TS_CAP:,}건을 넘어 시간순 대신 색인 순서로 정렬합니다")
                    effective = "relevance"
            if not index.budget.expired():
                source, source_params = ("temp.m", [])
                if effective == "path":
                    source = "(SELECT m.doc_id, m.group_id, m.ts, d.path_fold FROM temp.m m JOIN search_doc d ON d.doc_id = m.doc_id)"
                if capped:
                    # Past the cap temp.m holds only the first rows: the live predicate pages.
                    source = f"(SELECT d.doc_id, d.group_id, d.ts, d.path_fold FROM search_doc d WHERE {prepared.where})"
                    source_params = list(prepared.params)
                try:
                    fetched = page_ids(connection, source, source_params, sort=effective, collapse=request.collapse, limit=limit + 1, after=after, direction=direction)
                    more = len(fetched) > limit
                    page_rows = fetched[:limit] if direction == "next" else (fetched[-limit:] if more else fetched)
                except sqlite3.OperationalError:
                    if not index.budget.expired():
                        raise
                    truncated_reason = truncated_reason or index.budget.reason
        elif effective == "relevance" and not index.budget.expired():
            # The aggregate pass was cut: still show the first rows (streamed) within the grace budget.
            try:
                anchor = int(after[1]) if after is not None else None
                page_rows, more = stream_page(
                    connection, prepared.where, prepared.params, collapse=request.collapse, limit=limit, after=anchor, direction=direction, budget=index.budget
                )
            except (Interrupted, sqlite3.OperationalError) as exc:
                if isinstance(exc, sqlite3.OperationalError) and not index.budget.expired():
                    raise
                truncated_reason = truncated_reason or index.budget.reason
    rows_payload = _page_payload(index, prepared, request, page_rows, review_lookup, materialized=materialized)
    next_cursor = previous_cursor = None
    if page_rows:
        first, last = page_rows[0], page_rows[-1]
        if direction == "next":
            if more:
                next_cursor = encode_cursor(qhash, sort, effective, last[2], last[0], "next")
            if after is not None:
                previous_cursor = encode_cursor(qhash, sort, effective, first[2], first[0], "prev")
        else:
            next_cursor = encode_cursor(qhash, sort, effective, last[2], last[0], "next")
            if more:
                previous_cursor = encode_cursor(qhash, sort, effective, first[2], first[0], "prev")
    facets: dict[str, object] | None = None
    histogram: dict[str, object] | None = None
    matched_domains: set[str] = {str(row.get("domain") or "") for row in rows_payload}
    matched_collections: set[str] = {str(row.get("collection") or "") for row in rows_payload}
    if materialized and request.aggregates:
        try:
            facets, histogram = build_aggregates(
                connection,
                collapse=request.collapse,
                facets=request.facets,
                bucket=request.histogram,
                tz=ctx.tz,
                time_range=ctx.time_range,
                gap_seconds=ctx.gap_seconds,
                warnings=warnings,
                exact=complete,
            )
            if facets is not None:
                matched_domains |= {str(item["key"]) for item in facets["domain"]}  # type: ignore[index, union-attr]
                matched_collections |= {str(item["key"]) for item in facets["collection"]}  # type: ignore[index, union-attr]
        except sqlite3.OperationalError:
            if not index.budget.expired():
                raise
            warnings.append("시간 예산이 끝나 집계(패싯·히스토그램)를 만들지 못했습니다")
            truncated_reason = truncated_reason or index.budget.reason
    if request.aggregates and request.facets and facets is None:
        facets = {"exact": False, **EMPTY_FACETS}
    if capped:
        warnings.append(f"결과가 {TOTAL_CAP:,}건을 넘어 건수·집계는 처음 {TOTAL_CAP:,}건 기준입니다")
    if ctx.text_terms or ctx.regex_jobs:
        message = truncated_warning(
            meta, {name for name in matched_collections if name}, {domain for domain in matched_domains if domain}
        )
        if message:
            warnings.append(message)
    return {
        "query": {"raw": request.q, "parsed": {"clauses": parsed.clauses(), "warnings": warnings}},
        "rows": rows_payload,
        "page": {
            "cursor": request.cursor,
            "next_cursor": next_cursor,
            "previous_cursor": previous_cursor,
            "returned": len(rows_payload),
            "limit": limit,
            "total": total,
            "total_exact": complete,
            "total_cap": TOTAL_CAP,
            "sort": effective,
            "collapse": request.collapse,
            "aggregates": bool(request.aggregates and materialized),
        },
        "facets": facets,
        "histogram": histogram,
        "index": {"build_id": index.build_id, "built_at": meta.get("built_at"), "stale": stale, "tokenizer": index.tokenizer, "index_tokenizer": index.tokenizer},
        "elapsed_ms": budget.elapsed_ms(),
        "truncated": truncated_reason is not None,
        "truncated_reason": truncated_reason,
        "uses_review": ctx.uses_review,
    }


def _fast_page(
    index: SearchIndex,
    prepared: Prepared,
    request: QueryRequest,
    limit: int,
    after: tuple[object, int] | None,
    direction: str,
) -> tuple[list[tuple[int, int, object]], bool] | None:
    """Relevance page without the aggregate pass (``None``: use the full plan)."""
    anchor = int(after[1]) if after is not None else None
    connection = index.connection
    try:
        if prepared.ctx.drivers and prepared.row_where is not None:
            driver = max(prepared.ctx.drivers, key=lambda item: len(item.literal))
            return driver_page(
                connection, driver, prepared.row_where, prepared.row_params, collapse=request.collapse, limit=limit,
                after=anchor, direction=direction, budget=index.budget,
            )
        return stream_page(connection, prepared.where, prepared.params, collapse=request.collapse, limit=limit, after=anchor, direction=direction, budget=index.budget)
    except sqlite3.OperationalError as exc:
        if index.budget.expired():
            raise Interrupted(index.budget.reason or "") from exc
        raise


def _page_payload(
    index: SearchIndex,
    prepared: Prepared,
    request: QueryRequest,
    page_rows: list[tuple[int, int, object]],
    review_lookup: Callable[[list[dict[str, object]]], None] | None,
    *,
    materialized: bool,
) -> list[dict[str, object]]:
    if not page_rows:
        return []
    connection = index.connection
    ctx = prepared.ctx
    details = fetch_rows(connection, [rep for _rid, rep, _key in page_rows])
    kinds: dict[int, list[str]] = {}
    if request.collapse:
        group_ids = [rid for rid, _rep, _key in page_rows]
        marks = ", ".join("?" for _ in group_ids)
        if materialized:
            sql = f"SELECT group_id, ts_kind FROM temp.m WHERE group_id IN ({marks}) AND ts_kind != '' ORDER BY ts"
            params: list[object] = list(group_ids)
        else:
            # The page's groups only: the row-mode predicate never materialises a subquery.
            where, where_params = (prepared.row_where, prepared.row_params) if prepared.row_where is not None else (prepared.where, prepared.params)
            sql = f"SELECT d.group_id, d.ts_kind FROM search_doc d WHERE d.group_id IN ({marks}) AND d.ts_kind != '' AND ({where}) ORDER BY d.ts"
            params = [*group_ids, *where_params]
        for group_id, ts_kind in connection.execute(sql, params):
            bucket = kinds.setdefault(int(group_id), [])
            if ts_kind not in bucket:
                bucket.append(str(ts_kind))
    positive = [job for job in ctx.regex_jobs if job.positive]
    rows_payload: list[dict[str, object]] = []
    for rid, rep, _key in page_rows:
        row = details.get(rep)
        if row is None:
            continue
        group_id = int(row["group_id"])
        regexes = [(job.matcher, prepared.regex_spans.get(job.table, {}).get(group_id)) for job in positive]
        rows_payload.append(
            _row_payload(
                row,
                tz=ctx.tz,
                terms=ctx.text_terms,
                regexes=regexes,
                highlight=request.highlight,
                ts_kinds=kinds.get(rid) if request.collapse else None,
            )
        )
    if review_lookup is not None:
        review_lookup(rows_payload)
    return rows_payload


def run_count(
    index_path: Path,
    meta: Mapping[str, object],
    terms: list[Mapping[str, object]],
    options: SearchOptions,
    *,
    offset: int,
    budget: Budget,
    review_provider: ReviewProvider | None = None,
    hashset_resolver: HashsetResolver | None = None,
) -> dict[str, object]:
    """``search/count``: per-term totals (collapsed), domains and first/last time until the budget ends."""
    _check_index(meta)
    items: list[dict[str, object]] = []
    done = offset
    truncated = False
    try:
        with SearchIndex(index_path, meta, budget=budget) as index:
            tz = index.tz(options.tz)
            for position in range(offset, len(terms)):
                term = terms[position]
                item: dict[str, object] = {"label": term.get("label"), "q": term.get("q"), "count": None, "by_domain": {}, "first_ts": None, "last_ts": None}
                if truncated or budget.expired():
                    truncated = True
                    items.append(item)
                    continue
                try:
                    parsed = parse_query(str(term.get("q") or ""))
                    prepared = index.prepare(parsed, options, review_provider=review_provider, hashset_resolver=hashset_resolver, row_mode=False)
                    index.run_regex_jobs(prepared)
                    _rows, capped = index.materialize(prepared.where, prepared.params)
                    total, first, last = index.connection.execute("SELECT COALESCE(SUM(first), 0), MIN(ts), MAX(ts) FROM temp.m").fetchone()
                    item["count"] = int(total)
                    item["count_exact"] = not capped and not prepared.regex_unchecked
                    item["first_ts"] = ms_to_iso(first, tz) if first is not None else None
                    item["last_ts"] = ms_to_iso(last, tz) if last is not None else None
                    item["by_domain"] = {
                        str(domain): int(number)
                        for domain, number in index.connection.execute("SELECT domain, SUM(first) FROM temp.m GROUP BY domain ORDER BY 2 DESC")
                    }
                    done = position + 1
                except QueryError as exc:
                    item["error"] = exc.detail
                    item["position"] = exc.position
                    done = position + 1
                except Interrupted:
                    truncated = True
                except (sqlite3.OperationalError, OverflowError) as exc:
                    if budget.expired():
                        truncated = True
                    else:
                        error = _sql_error(exc)
                        item["error"] = error.detail
                        item["position"] = 0
                        done = position + 1
                items.append(item)
    except (sqlite3.OperationalError, OverflowError) as exc:
        raise _sql_error(exc) from exc
    return {"items": items, "offset": offset, "done": done, "total_terms": len(terms), "elapsed_ms": budget.elapsed_ms(), "truncated": truncated}


def run_hashes(
    index_path: Path,
    meta: Mapping[str, object],
    hashes: list[tuple[str, str]],
    *,
    budget: Budget,
    docs_per_hash: int = 50,
) -> dict[str, object]:
    """Hash list lookup: ``hashes`` are normalized ``(algorithm, value)`` pairs."""
    _check_index(meta)
    matched: list[dict[str, object]] = []
    with SearchIndex(index_path, meta, budget=budget) as index:
        connection = index.connection
        connection.execute("DROP TABLE IF EXISTS temp.wanted")
        connection.execute("CREATE TEMP TABLE wanted (algorithm TEXT, value TEXT, PRIMARY KEY (algorithm, value)) WITHOUT ROWID")
        connection.executemany("INSERT OR IGNORE INTO temp.wanted VALUES (?, ?)", hashes)
        hits: dict[tuple[str, str], list[int]] = {}
        for algorithm, value, doc_id in connection.execute(
            "SELECT h.algorithm, h.value, h.doc_id FROM temp.wanted w JOIN search_hash h ON h.algorithm = w.algorithm AND h.value = w.value ORDER BY h.doc_id"
        ):
            bucket = hits.setdefault((str(algorithm), str(value)), [])
            if len(bucket) < docs_per_hash:
                bucket.append(int(doc_id))
        tz = index.tz(None)
        wanted_ids = sorted({doc_id for ids in hits.values() for doc_id in ids})
        details: dict[int, sqlite3.Row] = {}
        for start in range(0, len(wanted_ids), 500):
            details.update(fetch_rows(connection, wanted_ids[start : start + 500]))
            budget.check()
        for (algorithm, value), ids in sorted(hits.items()):
            docs = [_row_payload(details[doc_id], tz=tz, terms=[], regexes=[], highlight=False, ts_kinds=None) for doc_id in ids if doc_id in details]
            matched.append({"hash": value, "algorithm": algorithm, "docs": docs, "doc_count": len(docs)})
        unique = int(connection.execute("SELECT COUNT(*) FROM temp.wanted").fetchone()[0])
    return {"matched": matched, "matched_count": len(matched), "unmatched_count": unique - len(matched), "elapsed_ms": budget.elapsed_ms()}
