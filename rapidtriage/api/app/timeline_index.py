"""Column index of the timeline events for row conditions (plan R6 §3.3 갈래 A).

``GET /timeline`` with ``from``/``to``/``weekday``/``hours``/``offhours``/``partial``/``content``
used to run :meth:`RowConditions.matches` on every event (ISO parsing, ``details`` walks) -- about
5 s for 500k events. This module keeps one small column index per timeline revision instead:

* ``epoch_us`` (``array('q')``) -- the row time (``row_conditions.row_time``: ``timestamp``) as
  microseconds since 1970-01-01T00:00Z; :data:`MISSING` (INT64_MIN) when absent / unparseable.
  Naive text is UTC (as in ``row_time``), so a condition's ``tz`` never changes a stored value.
* ``has_offset`` (``bytearray``) -- 1 when the timestamp carried an offset (``Z`` / ``±HH:MM``).
* ``content_mask`` (``array('H')``) -- 콘텐츠 유형 bits in ``row_conditions.CONTENT_TYPES`` order.
* ``partial`` (``bytearray``) -- ``row_conditions.row_is_partial``.

Weekday / hour are not stored (they depend on ``tz``): they come from the epoch plus a fixed
offset, or for an IANA zone from a per-UTC-hour offset cache (an hour with a transition inside, or
one the zone cannot represent, is converted event by event). Evaluation yields exactly the
positions of the predicate scan (tests compare both on random events, year 1 / 9999 edges
included) and goes into ``row_conditions.MATCH_CACHE`` as before, so later pages are unchanged.

One index per timeline revision (key ``row_conditions.output_stamp``, single-flight per run),
saved next to the timeline as :data:`INDEX_FILE_NAME` with a header carrying the timeline size /
mtime, a digest of its first / last 64 KB (``index_cache.head_tail_digest``: a rewrite keeping size
and mtime is noticed too), the event count and a fingerprint of the content / partial / time
rules. The request stamps the timeline *before* reading it and carries that stamp into the index
(``timeline_positions``): a timeline rewritten after the stamp keeps the index in memory under the
old stamp -- never loaded from or saved to a file of the new revision. A run writes it when its
timeline stage completes (:func:`write_timeline_index`). An older run gets it on its first
conditioned request: the columns that request needs are built first (a time condition only parses
the timestamps), the rest -- and the file -- follow (in the background for a large timeline;
slices of :data:`BACKGROUND_CHUNK_ROWS` rows with a short sleep between them, dropped while a
request waits for a column -- a request never waits behind the throttle). A
header that does not match is ignored and the index rebuilt; a folder that cannot be written -- or
``RAPIDTRIAGE_INDEX_PERSIST=0`` (``index_cache.index_persist_enabled``) -- keeps the index in
memory only. Any index failure falls back to the predicate scan -- never a 500.

Display grouping (``group=1``, timeline/grid readability C1 rule 2) adds a fourth saved column,
``group`` (``array('i')``): the display-group id of each event (index format version 3). The
search text of ``q=`` (C3, :class:`SearchColumn`, the same text :func:`event_matches_search`
scans) lives in memory only, built on the first search. Grouping runs after the position
selection: the matched positions of the conditions and ``q`` are reduced to one leader per group
(``MATCH_CACHE`` keeps the leaders, so later pages are a slice), and each page row lists its
members among those matched positions. A large timeline without the ``group`` column (an older
run) builds it in the background like the other columns; until then a grouped request groups its
matched positions itself (:func:`request_group_column`: only the events with a target key, their
own timestamps -- no time column over every event), with the same leaders and members. A page
row's ``group_id`` is a digest of the group key (:func:`group_label`), not the column's number.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import struct
import sys
import threading
import time
import unicodedata
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from itertools import accumulate
from pathlib import Path

from .index_cache import SingleFlightIndexCache, head_tail_digest, index_persist_enabled
from .row_conditions import (
    _FRACTION,
    _NEGATIONS,
    CONTENT_TYPES,
    DECRYPT_OK,
    DEFAULT_OFFHOURS,
    DEFAULT_WEEKEND,
    PARTIAL_STATUS_PHRASES,
    PARTIAL_STATUS_WORDS,
    PARTIAL_TRUNCATION_KEYS,
    PARTIAL_TYPE_TOKENS,
    TARGET_PATH_KEYS,
    RowConditions,
    _partial_status,
    in_hours,
    parse_moment,
)

LOGGER = logging.getLogger(__name__)

INDEX_FILE_NAME = "rapidtriage-timeline-index.bin"
INDEX_MAGIC = b"RTTLIDX1"
INDEX_VERSION = 3  # 2: header carries the timeline digest (adversarial review of R6 S3); 3: + group ids
MISSING = -(2**63)  # INT64_MIN: no parseable row time
US = dt.timedelta(microseconds=1)
HOUR_US = 3_600_000_000
DAY_US = 24 * HOUR_US
_EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_NAIVE_EPOCH = dt.datetime(1970, 1, 1)
MIN_US = (dt.datetime(1, 1, 1) - _NAIVE_EPOCH) // US
MAX_US = (dt.datetime(9999, 12, 31, 23, 59, 59, 999999) - _NAIVE_EPOCH) // US
_WEEK_SHIFT = 72  # hour 0 since the epoch (1970-01-01) is a Thursday: weekday 3 * 24
CONTENT_IDS: tuple[str, ...] = tuple(CONTENT_TYPES)
CONTENT_BITS: dict[str, int] = {content_id: 1 << bit for bit, content_id in enumerate(CONTENT_IDS)}
# Keys that can make a container 부분 결과 (row_conditions._partial_container): a container with
# none of them is never partial.
_PARTIAL_KEYS = frozenset({"parser_error", "parse_status", "decrypt_status", "coverage", *PARTIAL_TRUNCATION_KEYS})
_TARGET_KEYS = frozenset(TARGET_PATH_KEYS)
_HEADER_LEN = struct.Struct("<I")
TIME, CONTENT, PARTIAL, GROUP = "time", "content", "partial", "group"
COLUMNS: tuple[str, ...] = (TIME, CONTENT, PARTIAL, GROUP)
# ``group=1`` (timeline/grid readability C1 rule 2): events about the same thing at the same second
# with the same kind of time -- one file's creation time read from a Jump List, a shortcut and a
# ShimCache entry -- are one display row (``source_count`` / ``sources``), the events themselves
# stay listed under it (``group_members``). Key: (UTC second, offset/naive, folded target path /
# executable / URL, time-kind family); an event without a target or a time is its own row. Kinds
# of a different family never group (a file's creation is not its modification). The group id
# per event is the ``group`` column (saved in the index file with the others).
GROUP_TARGET_KEYS: tuple[str, ...] = ("target_path", "executable_path", "url")
_KIND_FAMILIES: dict[str, str] = {
    **dict.fromkeys(("created", "target-created", "item-created", "fs-created", "file-created", "creation"), "created"),
    **dict.fromkeys(
        ("modified", "target-modified", "item-modified", "fs-modified", "file-modified", "file-last-modified", "last-modified"),
        "modified",
    ),
    **dict.fromkeys(("accessed", "target-accessed", "item-accessed", "fs-accessed", "file-accessed", "last-accessed"), "accessed"),
}
NO_GROUP = -1
# Request-local group sets kept per index until its ``group`` column is built (UX-round review).
REQUEST_GROUPS_MAX = 8
# Timelines up to this many events complete their index (and file) inside the first request;
# larger ones finish the remaining columns and the file in a background thread.
SYNC_COMPLETE_MAX_EVENTS = 50_000
BACKGROUND_PAUSE_S = 0.001


def _rules_fingerprint() -> str:
    """Identity of the rules the stored columns were computed with (a change rebuilds the index)."""
    rules = repr(
        (
            INDEX_VERSION,
            [(key, spec.types, sorted(spec.extensions)) for key, spec in CONTENT_TYPES.items()],
            TARGET_PATH_KEYS,
            sorted(PARTIAL_STATUS_WORDS),
            PARTIAL_STATUS_PHRASES,
            sorted(PARTIAL_TRUNCATION_KEYS),
            PARTIAL_TYPE_TOKENS,
            sorted(DECRYPT_OK),
            sorted(_NEGATIONS),
            sorted(_PARTIAL_KEYS),
            _FRACTION.pattern,
            GROUP_TARGET_KEYS,
            sorted(_KIND_FAMILIES.items()),
        )
    )
    return hashlib.sha256(rules.encode("utf-8")).hexdigest()[:16]


RULES_FINGERPRINT = _rules_fingerprint()


# --- column values (exactly row_conditions.row_time / row_content_types / row_is_partial) ---------


def event_epoch(value: object) -> tuple[int, int]:
    """``(epoch_us, has_offset)`` of a ``timestamp`` value; ``(MISSING, 0)`` when it has no time.

    The reading of ``row_time(row, "timeline")`` (``parse_moment``) with a quicker path for text."""
    if isinstance(value, str):
        text = value.strip()
        if len(text) < 10 or not text[:4].isdigit():
            return MISSING, 0
        if len(text) > 10 and text[10] == " ":
            text = f"{text[:10]}T{text[11:]}"
        if text[-1] in "Zz":
            text = text[:-1] + "+00:00"
        if "." in text:
            text = _FRACTION.sub(r"\1", text)
        try:
            moment = dt.datetime.fromisoformat(text)
        except ValueError:
            return MISSING, 0
        if moment.tzinfo is None:
            return (moment - _NAIVE_EPOCH) // US, 0
        return (moment - _EPOCH) // US, 1
    if value is None or isinstance(value, (Mapping, list)):
        return MISSING, 0
    moment = parse_moment(value)
    return (MISSING, 0) if moment is None else ((moment - _EPOCH) // US, 1)


def _extension(value: str) -> str:
    """``row_conditions.path_extension`` of a string (without the regex split)."""
    text = value.strip()
    name = text[max(text.rfind("/"), text.rfind("\\")) + 1 :]
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem or not ext or len(ext) > 12 or not ext.replace("-", "").isalnum():
        return ""
    return ext.lower()


def _is_mapping(row: object) -> bool:
    return type(row) is dict or isinstance(row, Mapping)


def _artifact_type(row: Mapping[str, object], details: Mapping[str, object] | None) -> str:
    raw = row.get("artifact_type") or (details.get("artifact_type") if details else None) or ""
    return (raw if type(raw) is str else str(raw)).lower()


def _details_of(row: Mapping[str, object]) -> Mapping[str, object] | None:
    details = row.get("details")
    return details if type(details) is dict or isinstance(details, Mapping) else None


Pause = Callable[[], None] | None
CHUNK_ROWS = 4096
# Background slices are small: a request thread waits for the GIL until the build pauses, so a
# 4096-row slice (~6 ms) made the next page right after a first page cost ~45 ms on a real
# 330k-event timeline; 512-row slices keep it at ~15-20 ms (the build itself takes ~2x longer).
BACKGROUND_CHUNK_ROWS = 512


def _chunks(events: Sequence[object], pause: Pause) -> Iterator[tuple[int, Sequence[object]]]:
    """``events`` in slices; ``pause`` between slices lets request threads run (background build)."""
    step = CHUNK_ROWS if pause is None else BACKGROUND_CHUNK_ROWS
    for start in range(0, len(events), step):
        if pause is not None and start:
            pause()
        yield start, events[start : start + step]


def time_column(events: Sequence[object], pause: Pause = None) -> tuple[array, bytearray]:
    """``epoch_us`` / ``has_offset``: :func:`event_epoch` with its common text path inlined."""
    epoch = array("q", [MISSING]) * len(events)
    offsets = bytearray(len(events))
    fromisoformat = dt.datetime.fromisoformat
    utc_epoch, naive_epoch, micro = _EPOCH, _NAIVE_EPOCH, US
    previous: object = None
    previous_epoch, previous_offset = MISSING, 0
    for start, chunk in _chunks(events, pause):
        for position, row in enumerate(chunk, start):
            if type(row) is not dict and not isinstance(row, Mapping):
                continue
            value = row.get("timestamp")
            if type(value) is not str:
                if value is not None:
                    epoch[position], offsets[position] = event_epoch(value)
                continue
            if value == previous:  # sorted timelines repeat a timestamp often
                epoch[position], offsets[position] = previous_epoch, previous_offset
                continue
            previous, previous_epoch, previous_offset = value, MISSING, 0
            text = value.strip()
            # parse_moment also rejects a text whose first 4 characters are not digits; so does
            # fromisoformat (an ISO year is 4 ASCII digits), so that check is left to it.
            if len(text) < 10:
                continue
            if text[10:11] == " ":
                text = f"{text[:10]}T{text[11:]}"
            last = text[-1]
            if last == "Z" or last == "z":
                text = text[:-1] + "+00:00"
            if "." in text:
                dot = text.find(".")
                # _FRACTION (a 7th fraction digit) can only match with one there or a second dot.
                if text[dot + 7 : dot + 8].isdigit() or text.count(".") > 1:
                    text = _FRACTION.sub(r"\1", text)
            try:
                moment = fromisoformat(text)
            except ValueError:
                continue
            if moment.tzinfo is None:
                previous_epoch = epoch[position] = (moment - naive_epoch) // micro
            else:
                previous_epoch = epoch[position] = (moment - utc_epoch) // micro
                previous_offset = offsets[position] = 1
    return epoch, offsets


def content_column(events: Sequence[object], pause: Pause = None) -> array:
    """``content_mask``: ``row_content_types(row, "timeline")`` as bits, memoised per (type, ext)."""
    masks = array("H", bytes(2 * len(events)))
    memo: dict[tuple[str, str], int] = {}
    for start, chunk in _chunks(events, pause):
        for position, row in enumerate(chunk, start):
            if not _is_mapping(row):
                continue
            details = _details_of(row)  # type: ignore[arg-type]
            artifact_type = _artifact_type(row, details)  # type: ignore[arg-type]
            target = ""
            if details and not _TARGET_KEYS.isdisjoint(details):
                for key in TARGET_PATH_KEYS:
                    path = details.get(key)
                    if isinstance(path, str):
                        target = _extension(path)
                        if target:
                            break
            key = (artifact_type, target)
            mask = memo.get(key)
            if mask is None:
                mask = 0
                for content_id, spec in CONTENT_TYPES.items():
                    typed = artifact_type and any(artifact_type == p or artifact_type.startswith(p) for p in spec.types)
                    if typed or (target and target in spec.extensions):
                        mask |= CONTENT_BITS[content_id]
                memo[key] = mask
            masks[position] = mask
    return masks


def _container_partial(container: Mapping[str, object], statuses: dict[str, bool]) -> bool:
    """``row_conditions._partial_container`` with the parse-status words memoised."""
    if _PARTIAL_KEYS.isdisjoint(container):
        return False
    if container.get("parser_error") is True:
        return True
    status = container.get("parse_status")
    if isinstance(status, str) and status:
        failing = statuses.get(status)
        if failing is None:
            failing = statuses[status] = _partial_status(status)
        if failing:
            return True
    decrypt = container.get("decrypt_status")
    if isinstance(decrypt, str) and decrypt.lower() not in DECRYPT_OK:
        return True
    coverage = container.get("coverage")
    if coverage == "partial" or (isinstance(coverage, Mapping) and coverage.get("status") == "partial"):
        return True
    return any(container.get(key) is True for key in PARTIAL_TRUNCATION_KEYS)


def partial_column(events: Sequence[object], pause: Pause = None) -> bytearray:
    """``partial``: ``row_is_partial`` with type tokens and parse statuses memoised."""
    flags = bytearray(len(events))
    types: dict[str, bool] = {}
    statuses: dict[str, bool] = {}
    for start, chunk in _chunks(events, pause):
        for position, row in enumerate(chunk, start):
            if not _is_mapping(row):
                continue
            details = _details_of(row)  # type: ignore[arg-type]
            artifact_type = _artifact_type(row, details)  # type: ignore[arg-type]
            typed = types.get(artifact_type)
            if typed is None:
                typed = types[artifact_type] = any(token in artifact_type for token in PARTIAL_TYPE_TOKENS)
            if (
                typed
                or _container_partial(row, statuses)  # type: ignore[arg-type]
                or (details is not None and _container_partial(details, statuses))
            ):
                flags[position] = 1
    return flags


# --- search text (q=) and display groups (group=1) ---------------------------------------------------
#
# ``q`` (timeline/grid readability C3) is a case-insensitive "contains" over what an examiner reads
# of an event: its summary, the thing it is about (target path / executable / URL / key), its source
# path, event type and Korean event name. Per event the column keeps the folded summary + targets
# ("own" text); the path / type / label -- shared by many events -- are folded once per distinct
# value ("shared" text, by id). :func:`event_search_parts` defines both, for the column and the
# predicate scan alike, so the index answers exactly what the scan answers.

SEARCH_TARGET_KEYS: tuple[str, ...] = tuple(dict.fromkeys((*TARGET_PATH_KEYS, "url", "key_path")))
SEARCH_MAX_LENGTH = 200  # q is a substring, not a document
_EVENT_SEPARATOR = "\x00"  # between events in the search text; never part of a needle
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def fold_text(value: str) -> str:
    """Case-insensitive, NFC-normalised text (``artifact_filter.nfc_fold``); ASCII just lower-cased."""
    if value.isascii():
        return value.lower()
    return unicodedata.normalize("NFC", value).casefold()


def search_needle(q: str | None) -> str:
    """The canonical ``q``: whitespace runs -> one space, control characters dropped, NFC,
    lower-cased (``""`` = no search). The cache key of a search."""
    if not q:
        return ""
    text = " ".join(_CONTROL_RE.sub(" ", q).split())[:SEARCH_MAX_LENGTH]
    return unicodedata.normalize("NFC", text).lower()


def needle_forms(needle: str) -> tuple[str, ...]:
    """The needle as written (NFC) and decomposed (NFD): event text is lower-cased but not
    re-normalised (normalising ~25 M characters costs minutes), so a macOS-style NFD file name is
    found by the NFD form."""
    decomposed = unicodedata.normalize("NFD", needle)
    return (needle,) if decomposed == needle else (needle, decomposed)


def event_search_parts(row: object) -> tuple[str, str]:
    """``(own, shared)`` raw texts of one event (not lower-cased); ``("", "")`` for a non-object.

    Own: the summary and the target keys (path / executable / URL / key); shared: the source path,
    event type and Korean event name. Parts are joined by "\\n" (a needle never holds one)."""
    if not _is_mapping(row):
        return "", ""
    details = _details_of(row)  # type: ignore[arg-type]
    own: list[str] = []
    summary = row.get("summary")  # type: ignore[union-attr]
    if type(summary) is str and summary:
        own.append(summary)
    if details:
        for key in SEARCH_TARGET_KEYS:
            value = details.get(key)
            if type(value) is str and value and value not in own:
                own.append(value)
    shared: list[str] = []
    for value in (
        row.get("path"),  # type: ignore[union-attr]
        row.get("event_type"),  # type: ignore[union-attr]
        details.get("event_label_ko") if details else None,
    ):
        if type(value) is str and value:
            shared.append(value)
    return "\n".join(own), "\n".join(shared)


def event_matches_search(row: object, needle: str) -> bool:
    """Predicate form of ``q`` (the scan the search column replaces): a form of the needle is in
    the lower-cased own or shared text."""
    if not needle:
        return True
    own, shared = event_search_parts(row)
    own, shared = own.replace(_EVENT_SEPARATOR, " ").lower(), shared.lower()
    return any(form in own or form in shared for form in needle_forms(needle))


class SharedField:
    """One shared field (source path, event type or Korean event name): an id per event and the
    lower-cased distinct values (a few thousand at most in a real run)."""

    __slots__ = ("ids", "values")

    def __init__(self, raw: Iterable[object]) -> None:
        by_value: dict[str, int] = {}
        setdefault = by_value.setdefault
        self.ids = array("i", [setdefault(value, len(by_value)) for value in _str_or_empty(raw)])
        self.values = [value.lower() for value in by_value]


class SearchColumn:
    """The lower-cased own texts of every event in one string (events separated by
    :data:`_EVENT_SEPARATOR`, ``starts[i]`` = where event ``i`` begins) and the shared fields. A
    search is ``str.find`` over that string, jumping to the next event after each hit, plus the
    events whose shared value holds the needle (a needle never holds the "\\n" between parts, so
    matching a part is matching :func:`event_search_parts`' joined shared text)."""

    __slots__ = ("shared", "starts", "text")

    def __init__(self, text: str, starts: array, shared: tuple[SharedField, ...]) -> None:
        self.text = text
        self.starts = starts
        self.shared = shared

    def mask(self, needle: str) -> bytearray:
        """1 per event whose own or shared text holds a form of ``needle``."""
        starts, find = self.starts, self.text.find
        count = len(starts) - 1
        found = bytearray(count)
        forms = needle_forms(needle)
        for form in forms:
            at = find(form)
            while at >= 0:
                event = bisect_right(starts, at) - 1
                found[event] = 1
                if event + 1 >= count:
                    break
                at = find(form, starts[event + 1])
        for field in self.shared:
            hits = bytes(1 if any(form in value for form in forms) else 0 for value in field.values)
            if any(hits):
                for event in [i for i, value_id in enumerate(field.ids) if hits[value_id]]:
                    found[event] = 1
        return found

    def positions(self, needle: str, candidates: Iterable[int] | None = None) -> list[int]:
        """Positions (of ``candidates``, default all) whose text contains ``needle``."""
        found = self.mask(needle)
        if candidates is None:
            return [i for i, flag in enumerate(found) if flag]
        return [i for i in candidates if found[i]]


_SEARCH_TARGET_SET = frozenset(SEARCH_TARGET_KEYS)


def _as_dict(value: object) -> Mapping[str, object] | None:
    if type(value) is dict:
        return value  # type: ignore[return-value]
    return value if isinstance(value, Mapping) else None


def _str_or_empty(values: Iterable[object]) -> list[str]:
    return [value if type(value) is str else "" for value in values]


def search_column(events: Sequence[object]) -> SearchColumn:
    """:func:`event_search_parts` of every event. Built with list comprehensions and whole-string
    operations (a per-event Python loop costs ~4 us an event; lower-casing one string per event
    ~2 us for Korean text): the own texts are joined, then lower-cased once."""
    empty: dict[str, object] = {}
    rows = [found if found is not None else empty for found in map(_as_dict, events)]
    details = [_as_dict(row.get("details")) for row in rows]
    texts = _str_or_empty(row.get("summary") for row in rows)
    target_set = _SEARCH_TARGET_SET
    for i, found in enumerate(details):
        if found is None or target_set.isdisjoint(found):
            continue
        # The target values present (any order: a needle never spans the "\n" between parts).
        values = [value for value in map(found.get, target_set.intersection(found)) if type(value) is str and value]
        if values:
            text = texts[i]
            texts[i] = "\n".join([text, *values] if text else values)
    # A separator inside an event's text would split it: replace it (a needle never holds one).
    texts = [text.replace(_EVENT_SEPARATOR, " ") if _EVENT_SEPARATOR in text else text for text in texts]
    joined = _EVENT_SEPARATOR.join(texts)
    lowered = joined.lower()
    if len(lowered) != len(joined):  # a character lower-cases to two ("İ"): offsets per event
        texts = [text.lower() for text in texts]
        lowered = _EVENT_SEPARATOR.join(texts)
    starts = array("q", [0])
    starts.extend(accumulate(len(text) + 1 for text in texts))
    shared = (
        SharedField(row.get("path") for row in rows),
        SharedField(row.get("event_type") for row in rows),
        SharedField(found.get("event_label_ko") if found is not None else None for found in details),
    )
    return SearchColumn(lowered, starts, shared)


def kind_family(kind: object) -> str:
    """The family of a ``timestamp_kind`` (created / modified / accessed, else the kind itself)."""
    text = str(kind or "").strip().lower()
    return _KIND_FAMILIES.get(text, text)


class GroupColumn:
    """Group id per event (:data:`NO_GROUP` = never grouped) and the positions of every group
    with two or more events. ``ids`` is the index's ``group`` column, or for a request-local
    computation (:func:`request_group_column`) a :class:`SparseGroupIds` with ``members`` given."""

    __slots__ = ("ids", "members")

    def __init__(self, ids: Sequence[int], members: dict[int, list[int]] | None = None) -> None:
        self.ids = ids
        if members is None:
            grouped = [position for position, group in enumerate(ids) if group != NO_GROUP]
            by_group: dict[int, list[int]] = {}
            for position in grouped:
                by_group.setdefault(ids[position], []).append(position)
            members = {group: positions for group, positions in by_group.items() if len(positions) > 1}
        self.members = members

    def leaders(self, positions: Iterable[int]) -> list[int]:
        """``positions`` (ascending) with every group reduced to its first position."""
        ids, members = self.ids, self.members
        seen: set[int] = set()
        out: list[int] = []
        append = out.append
        for position in positions:
            group = ids[position]
            if group == NO_GROUP or group not in members:
                append(position)
            elif group not in seen:
                seen.add(group)
                append(position)
        return out


class SparseGroupIds:
    """``ids`` of a request-local :class:`GroupColumn`: the group of the computed positions,
    :data:`NO_GROUP` for every other one (``len`` = the event count)."""

    __slots__ = ("count", "groups")

    def __init__(self, count: int, groups: dict[int, int]) -> None:
        self.count = count
        self.groups = groups

    def __len__(self) -> int:
        return self.count

    def __getitem__(self, position: int) -> int:
        return self.groups.get(position, NO_GROUP)


def event_group_key(row: object) -> tuple[object, ...] | None:
    """The display-group key of one event -- ``(UTC second, has offset, folded target, time-kind
    family)`` -- exactly as :func:`group_column` keys it (``None``: never grouped)."""
    if not _is_mapping(row):
        return None
    details = _details_of(row)  # type: ignore[arg-type]
    if details is None or _GROUP_TARGET_SET.isdisjoint(details):
        return None
    epoch, offset = event_epoch(row.get("timestamp"))  # type: ignore[union-attr]
    if epoch == MISSING:
        return None
    target = ""
    for name in GROUP_TARGET_KEYS:
        candidate = details.get(name)
        if isinstance(candidate, str):
            candidate = candidate.strip()
            if candidate:
                target = candidate.lower() if candidate.isascii() else fold_text(candidate)
                break
    if not target:
        return None
    return (epoch // 1_000_000, offset, target, kind_family(row.get("timestamp_kind")))  # type: ignore[union-attr]


def group_label(key: tuple[object, ...] | None) -> str:
    """``group_id`` of a page row: a digest of the group key, so it is the same whichever way the
    groups were computed (index column or request-local) and across index rebuilds."""
    return "g" + hashlib.blake2b(repr(key).encode("utf-8"), digest_size=6).hexdigest()


def target_positions(events: Sequence[object]) -> array:
    """Positions of the events whose details hold a group target key (the only ones that group)."""
    target_set = _GROUP_TARGET_SET
    details = [row.get("details") if type(row) is dict else _details_of(row) if _is_mapping(row) else None for row in events]  # type: ignore[arg-type]
    return array(
        "l",
        [
            position
            for position, found in enumerate(details)
            if (type(found) is dict or isinstance(found, Mapping)) and not target_set.isdisjoint(found)  # type: ignore[arg-type]
        ],
    )


def request_group_column(events: Sequence[object], matched: Sequence[int] | None, targets: Sequence[int] | None = None) -> GroupColumn:
    """The display groups of the ``matched`` positions alone (``None`` = every event), computed
    from the events' own timestamps: no ``time`` / ``group`` column over the whole timeline. The
    leaders and members (members are always limited to the matched positions) equal those of the
    index's column; only the internal group numbers differ (``group_id`` is :func:`group_label`)."""
    if targets is None:
        targets = target_positions(events)
    if matched is None:
        candidates: Iterable[int] = targets
    elif len(matched) <= len(targets):
        is_target = bytearray(len(events))
        for position in targets:
            is_target[position] = 1
        candidates = [position for position in matched if is_target[position]]
    else:
        wanted = bytearray(len(events))
        for position in matched:
            wanted[position] = 1
        candidates = [position for position in targets if wanted[position]]
    by_key: dict[tuple[object, ...], int] = {}
    groups: dict[int, int] = {}
    positions_of: dict[int, list[int]] = {}
    for position in candidates:
        key = event_group_key(events[position])
        if key is None:
            continue
        group = by_key.get(key)
        if group is None:
            group = by_key[key] = len(by_key)
        groups[position] = group
        positions_of.setdefault(group, []).append(position)
    members = {group: positions for group, positions in positions_of.items() if len(positions) > 1}
    return GroupColumn(SparseGroupIds(len(events), groups), members)


def event_group_target(row: Mapping[str, object]) -> str:
    """The folded target an event groups on (``""``: none, never grouped)."""
    details = _details_of(row)
    if not details:
        return ""
    for key in GROUP_TARGET_KEYS:
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return fold_text(value.strip())
    return ""


_GROUP_TARGET_SET = frozenset(GROUP_TARGET_KEYS)


def group_column(events: Sequence[object], epoch_us: array, has_offset: bytearray, pause: Pause = None) -> array:
    """Group id per event by :func:`event_group_target` / :func:`kind_family`. Per chunk, list
    comprehensions pick the events whose details hold a target key (most events -- event logs --
    have none); only those run the per-event code."""
    ids = array("i", [NO_GROUP]) * len(events)
    by_key: dict[tuple[object, ...], int] = {}
    families: dict[object, str] = {}
    target_set, target_keys = _GROUP_TARGET_SET, GROUP_TARGET_KEYS
    empty: dict[str, object] = {}
    for start, chunk in _chunks(events, pause):
        details_of = [_as_dict((_as_dict(row) or empty).get("details")) for row in chunk]
        for offset, details in enumerate(details_of):
            if details is None or target_set.isdisjoint(details):
                continue
            position = start + offset
            value = epoch_us[position]
            if value == MISSING:
                continue
            target = ""
            for name in target_keys:
                candidate = details.get(name)
                if isinstance(candidate, str):
                    candidate = candidate.strip()
                    if candidate:
                        target = candidate.lower() if candidate.isascii() else fold_text(candidate)
                        break
            if not target:
                continue
            kind = chunk[offset].get("timestamp_kind")  # type: ignore[union-attr]
            family = families.get(kind) if isinstance(kind, str) else None
            if family is None:
                family = kind_family(kind)
                if isinstance(kind, str):
                    families[kind] = family
            key = (value // 1_000_000, has_offset[position], target, family)
            group = by_key.get(key)
            if group is None:
                group = by_key[key] = len(by_key)
            ids[position] = group
    return ids


# --- the index ---------------------------------------------------------------------------------------


class TimelineIndex:
    """Columns of one timeline revision; a column is ``None`` until something needs it."""

    def __init__(
        self,
        count: int,
        *,
        stamp: tuple[int, int] | None = None,
        timeline_path: Path | None = None,
        source: str = "built",
    ) -> None:
        self.count = count
        self.stamp = stamp  # timeline (size, mtime_ns) the columns describe
        self.timeline_path = timeline_path
        self.source = source  # built | file
        self.epoch_us: array | None = None
        self.has_offset: bytearray | None = None
        self.content_mask: array | None = None
        self.partial: bytearray | None = None
        self.group_ids: array | None = None
        self.saved = False
        # Memory only (timeline/grid readability C1/C3): the folded search text of ``q=`` and the
        # members of each display group (from ``group_ids``).
        self.search: SearchColumn | None = None
        self.groups: GroupColumn | None = None
        # Until the ``group`` column exists (a large timeline builds it in the background, UX-round
        # review): the target positions and the request-local groups per matched set (small LRU).
        self.targets: array | None = None
        self.request_groups: dict[tuple[object, ...], GroupColumn] = {}
        self._extra_lock = threading.Lock()
        self._lock = threading.Lock()  # saved / completing flags
        # One lock per column: a request never waits for a column it does not need.
        self._column_locks = {column: threading.Lock() for column in COLUMNS}
        self._completing = False
        # Request threads waiting per column: the background build of a column a request waits
        # for runs without its pauses (the other columns keep yielding the GIL to requests).
        self._waiting = dict.fromkeys(COLUMNS, 0)

    def requests_waiting(self, column: str | None = None) -> bool:
        if column is None:
            return any(self._waiting.values())
        return self._waiting[column] > 0

    def has(self, column: str) -> bool:
        if column == TIME:
            return self.epoch_us is not None
        if column == CONTENT:
            return self.content_mask is not None
        if column == GROUP:
            return self.group_ids is not None
        return self.partial is not None

    def complete(self) -> bool:
        return all(self.has(column) for column in COLUMNS)

    def ensure(self, events: Sequence[object], columns: Iterable[str], pause: Pause = None) -> None:
        """Build the missing ``columns`` from ``events`` (one pass per column). A request
        (``pause is None``) waiting for a column the background build holds makes that build drop
        its pauses until the column is done (it never waits behind the throttle)."""
        missing = [column for column in columns if not self.has(column)]
        if not missing:
            return
        if pause is not None:
            self._build(events, missing, pause)
            return
        with self._lock:
            for column in missing:
                self._waiting[column] += 1
        try:
            self._build(events, missing, None)
        finally:
            with self._lock:
                for column in missing:
                    self._waiting[column] -= 1

    def _paced(self, column: str, pause: Pause) -> Pause:
        """``pause`` unless a request waits for ``column``."""
        if pause is None:
            return None
        waiting = self._waiting

        def paced() -> None:
            if not waiting[column]:
                pause()

        return paced

    def _build(self, events: Sequence[object], columns: Iterable[str], pause: Pause) -> None:
        for column in columns:
            if self.has(column):
                continue
            with self._column_locks[column]:
                if self.has(column):
                    continue
                if column == TIME:
                    epoch, offsets = time_column(events, self._paced(column, pause))
                    self.has_offset, self.epoch_us = offsets, epoch
                elif column == CONTENT:
                    self.content_mask = content_column(events, self._paced(column, pause))
                elif column == GROUP:
                    if not self.has(TIME):  # the group key's second comes from the time column
                        self._build(events, (TIME,), pause)
                    assert self.epoch_us is not None and self.has_offset is not None
                    self.group_ids = group_column(events, self.epoch_us, self.has_offset, self._paced(column, pause))
                else:
                    self.partial = partial_column(events, self._paced(column, pause))

    def ensure_search(self, events: Sequence[object]) -> SearchColumn:
        """The ``q=`` text column (built on the first search, memory only)."""
        found = self.search
        if found is None:
            with self._extra_lock:
                found = self.search
                if found is None:
                    found = self.search = search_column(events)
        return found

    def ensure_groups(self, events: Sequence[object]) -> GroupColumn:
        """The display groups of ``group=1``: the ``group`` column (from the index file, else built
        now) and its members (computed once per index, memory only)."""
        found = self.groups
        if found is None:
            self.ensure(events, (GROUP,))
            with self._extra_lock:
                found = self.groups
                if found is None:
                    assert self.group_ids is not None
                    found = self.groups = GroupColumn(self.group_ids)
        return found

    def groups_for(
        self, events: Sequence[object], key: tuple[object, ...], matched: Callable[[], Sequence[int]] | None
    ) -> GroupColumn:
        """Display groups of one matched set without the ``group`` column (request-local, cached
        per ``key`` so later pages reuse them; the full column replaces them once built)."""
        if self.groups is not None:
            return self.groups
        with self._extra_lock:
            found = self.request_groups.get(key)
            if found is not None:
                return found
            if self.targets is None:
                self.targets = target_positions(events)
            targets = self.targets
        found = request_group_column(events, matched() if matched is not None else None, targets)
        with self._extra_lock:
            self.request_groups[key] = found
            while len(self.request_groups) > REQUEST_GROUPS_MAX:
                self.request_groups.pop(next(iter(self.request_groups)))
        return found

    def complete_and_save(self, events: Sequence[object], pause: Pause = None) -> None:
        """All columns, then the index file when the timeline is still the indexed revision."""
        self.ensure(events, COLUMNS, pause)
        with self._lock:
            if self.saved or self.timeline_path is None or self.stamp is None or not index_persist_enabled():
                return
            if _file_stamp(self.timeline_path) != self.stamp:
                return
            digest = head_tail_digest(self.timeline_path)
            if digest is None or _file_stamp(self.timeline_path) != self.stamp:
                return
            self.saved = save_index(self, index_path_for(self.timeline_path), self.stamp, digest)


def build_timeline_index(events: Sequence[object]) -> TimelineIndex:
    """All columns of ``events`` (no file)."""
    index = TimelineIndex(len(events))
    index.ensure(events, COLUMNS)
    return index


def _file_stamp(timeline_path: Path) -> tuple[int, int] | None:
    try:
        stat = timeline_path.stat()
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns


def index_path_for(timeline_path: Path) -> Path:
    return timeline_path.with_name(INDEX_FILE_NAME)


def _header(count: int, stamp: tuple[int, int], digest: str | None) -> dict[str, object]:
    return {
        "version": INDEX_VERSION,
        "timeline_size": stamp[0],
        "timeline_mtime_ns": stamp[1],
        "timeline_digest": digest,
        "count": count,
        "rules": RULES_FINGERPRINT,
        "content_ids": list(CONTENT_IDS),
        "byteorder": sys.byteorder,
    }


def save_index(index: TimelineIndex, index_path: Path, stamp: tuple[int, int], digest: str | None) -> bool:
    """Write a complete index atomically; ``False`` (memory only) when the folder is not writable
    or writing fails in any other way (the temporary file is removed then)."""
    if (
        index.epoch_us is None
        or index.has_offset is None
        or index.content_mask is None
        or index.partial is None
        or index.group_ids is None
    ):
        return False
    header = json.dumps(_header(index.count, stamp, digest), separators=(",", ":")).encode("utf-8")
    temp = index_path.with_name(f"{index_path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with temp.open("wb") as handle:
            handle.write(INDEX_MAGIC)
            handle.write(_HEADER_LEN.pack(len(header)))
            handle.write(header)
            index.epoch_us.tofile(handle)
            handle.write(index.has_offset)
            index.content_mask.tofile(handle)
            handle.write(index.partial)
            index.group_ids.tofile(handle)
        os.replace(temp, index_path)
        return True
    except Exception as exc:
        LOGGER.info("timeline index not saved to %s (memory only): %s", index_path, exc)
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def load_index(
    index_path: Path, stamp: tuple[int, int] | None, count: int | None = None, digest: str | None = None
) -> TimelineIndex | None:
    """The saved index when its header matches ``stamp``, ``digest`` (and ``count``), else ``None``."""
    if stamp is None or digest is None:
        return None
    try:
        with index_path.open("rb") as handle:
            if handle.read(len(INDEX_MAGIC)) != INDEX_MAGIC:
                return None
            (length,) = _HEADER_LEN.unpack(handle.read(_HEADER_LEN.size))
            if length > 65536:
                return None
            header = json.loads(handle.read(length).decode("utf-8"))
            if not isinstance(header, dict) or not isinstance(header.get("count"), int):
                return None
            total = header["count"]
            if header != _header(total, stamp, digest) or (count is not None and total != count) or total < 0:
                return None
            epoch = array("q")
            epoch.fromfile(handle, total)
            offsets = bytearray(handle.read(total))
            masks = array("H")
            masks.fromfile(handle, total)
            partial = bytearray(handle.read(total))
            groups = array("i")
            groups.fromfile(handle, total)
            if len(offsets) != total or len(partial) != total or handle.read(1):
                return None
    except (OSError, ValueError, EOFError, struct.error, UnicodeDecodeError):
        return None
    index = TimelineIndex(total, stamp=stamp, timeline_path=None, source="file")
    index.epoch_us, index.has_offset, index.content_mask, index.partial = epoch, offsets, masks, partial
    index.group_ids = groups
    index.saved = True
    return index


def write_timeline_index(events: Sequence[object], timeline_path: Path) -> Path | None:
    """Run completion (timeline stage): build and save the index of a just-written timeline."""
    stamp = _file_stamp(timeline_path)
    if stamp is None:
        return None
    target = index_path_for(timeline_path)
    digest = head_tail_digest(timeline_path)
    return target if save_index(build_timeline_index(events), target, stamp, digest) else None


def open_index(timeline_path: Path, count: int, stamp: tuple[int, int] | None = None) -> TimelineIndex:
    """The saved index when it matches the timeline revision, else an empty one to fill (with no
    ``timeline_path`` -- nothing to save -- when index files must not be written).

    ``stamp`` is the ``(size, mtime_ns)`` taken before the events were read (default: now). When
    the file no longer has it the events may be of another revision: the index stays in memory."""
    current = _file_stamp(timeline_path)
    stamp = current if stamp is None else stamp
    if stamp is None or current != stamp:
        return TimelineIndex(count, stamp=stamp, timeline_path=None)
    found = load_index(index_path_for(timeline_path), stamp, count, head_tail_digest(timeline_path))
    if found is not None:
        return found
    return TimelineIndex(count, stamp=stamp, timeline_path=timeline_path if index_persist_enabled() else None)


# --- evaluation ----------------------------------------------------------------------------------


def needed_columns(conditions: RowConditions) -> tuple[str, ...]:
    columns: list[str] = []
    if conditions.uses_time:
        columns.append(TIME)
    if conditions.content is not None:
        columns.append(CONTENT)
    if conditions.partial:
        columns.append(PARTIAL)
    return tuple(columns)


def _bound_us(moment: dt.datetime | None) -> int | None:
    return None if moment is None else (moment - _EPOCH) // US


def hour_of_week_table(conditions: RowConditions) -> bytes:
    """168 flags (``weekday * 24 + hour``) of the local clocks ``_clock_matches`` accepts."""
    table = bytearray(168)
    for weekday in range(7):
        for hour in range(24):
            if conditions.offhours:
                days = conditions.weekdays if conditions.weekdays is not None else DEFAULT_WEEKEND
                ok = weekday in days or in_hours(hour, conditions.hours or DEFAULT_OFFHOURS)
            else:
                ok = (conditions.weekdays is None or weekday in conditions.weekdays) and (
                    conditions.hours is None or in_hours(hour, conditions.hours)
                )
            table[weekday * 24 + hour] = 1 if ok else 0
    return bytes(table)


class _ZoneClock:
    """Local hour-of-week of UTC instants in an IANA zone with the zone's UTC offset cached per
    UTC day (plan: 날짜별 오프셋 캐시). A day is cached when the offset is the same at 00, 06, 12,
    18 h and its last microsecond (zones do not change offset and back within six hours); a day
    with a transition goes per UTC hour (same offset at the hour's first and last microsecond),
    and an hour with a transition inside -- or an edge the zone cannot represent -- converts its
    instants one by one, exactly like ``astimezone``."""

    _MIXED = object()

    def __init__(self, zone: dt.tzinfo) -> None:
        self.zone = zone
        self.days: dict[int, object] = {}
        self._hours: dict[int, int | None] = {}

    def _local(self, utc_us: int) -> dt.datetime | None:
        if not MIN_US <= utc_us <= MAX_US:
            return None
        try:
            return (_EPOCH + dt.timedelta(microseconds=utc_us)).astimezone(self.zone)
        except (OverflowError, ValueError):
            return None

    def _offset(self, utc_us: int) -> int | None:
        local = self._local(utc_us)
        return None if local is None else (local.replace(tzinfo=None) - _NAIVE_EPOCH) // US - utc_us

    def _same_offset(self, points: Iterable[int]) -> int | None:
        found: int | None = None
        for index, point in enumerate(points):
            offset = self._offset(point)
            if offset is None or (index and offset != found):
                return None
            found = offset
        return found

    def day_offset(self, day: int) -> object:
        found = self.days.get(day)
        if found is None:
            start = day * DAY_US
            offset = self._same_offset((start, start + 6 * HOUR_US, start + 12 * HOUR_US, start + 18 * HOUR_US, start + DAY_US - 1))
            found = self._MIXED if offset is None else offset
            self.days[day] = found
        return found

    def _hour_offset(self, hour: int) -> int | None:
        if hour in self._hours:
            return self._hours[hour]
        offset = self._same_offset((hour * HOUR_US, hour * HOUR_US + HOUR_US - 1))
        self._hours[hour] = offset
        return offset

    def hour_of_week(self, utc_us: int) -> int | None:
        offset = self.day_offset(utc_us // DAY_US)
        if offset is self._MIXED:
            offset = self._hour_offset(utc_us // HOUR_US)
        if offset is not None:
            return ((utc_us + offset) // HOUR_US + _WEEK_SHIFT) % 168  # type: ignore[operator]
        local = self._local(utc_us)
        return None if local is None else local.weekday() * 24 + local.hour


def _zone_positions(epoch: array, low: int, high: int, table: bytes, clock: _ZoneClock) -> list[int]:
    """IANA clock condition: per-UTC-day offsets inline (the per-event call only off that path)."""
    days = clock.days
    day_offset = clock.day_offset
    hour_of_week = clock.hour_of_week
    positions: list[int] = []
    append = positions.append
    for i, value in enumerate(epoch):
        if low <= value < high:
            offset = days.get(value // DAY_US)
            if offset is None:
                offset = day_offset(value // DAY_US)
            if type(offset) is int:
                if table[((value + offset) // HOUR_US + _WEEK_SHIFT) % 168]:
                    append(i)
            else:
                how = hour_of_week(value)
                if how is not None and table[how]:
                    append(i)
    return positions


def evaluate(index: TimelineIndex, conditions: RowConditions) -> list[int]:
    """Positions of the events passing ``conditions`` (the set ``conditions.predicate`` passes).

    The index must hold :func:`needed_columns` of ``conditions``."""
    positions: list[int] | None = None
    if conditions.uses_time:
        epoch = index.epoch_us
        assert epoch is not None
        low = _bound_us(conditions.time_from)
        high = _bound_us(conditions.time_until)
        low = MISSING + 1 if low is None else max(low, MISSING + 1)
        high = 2**63 if high is None else high
        if not conditions.clock:
            positions = [i for i, value in enumerate(epoch) if low <= value < high]
        else:
            table = hour_of_week_table(conditions)
            zone = conditions.tz
            if isinstance(zone, dt.timezone):
                offset = zone.utcoffset(None) // US
                # astimezone: the UTC instant and the local wall clock must both be representable.
                low = max(low, MIN_US, MIN_US - offset)
                high = min(high, MAX_US + 1, MAX_US + 1 - offset)
                shift = offset + _WEEK_SHIFT * HOUR_US
                positions = [
                    i for i, value in enumerate(epoch) if low <= value < high and table[(value + shift) // HOUR_US % 168]
                ]
            else:
                positions = _zone_positions(epoch, low, high, table, _ZoneClock(zone))
    if conditions.partial:
        partial = index.partial
        assert partial is not None
        if positions is None:
            positions = [i for i, flag in enumerate(partial) if flag]
        else:
            positions = [i for i in positions if partial[i]]
    if conditions.content is not None:
        masks = index.content_mask
        assert masks is not None
        want = 0
        for content_id in conditions.content:
            want |= CONTENT_BITS[content_id]
        if positions is None:
            positions = [i for i, mask in enumerate(masks) if mask & want]
        else:
            positions = [i for i in positions if masks[i] & want]
    # No condition the index answers (``geo`` is a 422 on /timeline): nothing narrows the list.
    return list(range(index.count)) if positions is None else positions


_ONLY_FIELDS: dict[str, dict[str, object]] = {
    TIME: {"time_from": None, "time_to": None, "time_until": None, "weekdays": None, "hours": None, "offhours": False},
    CONTENT: {"content": None},
    PARTIAL: {"partial": False},
}
# Built first when a request needs several missing columns (the rest is checked on its matches).
FIRST_COLUMN_ORDER: tuple[str, ...] = (PARTIAL, CONTENT, TIME)


def only_columns(conditions: RowConditions, columns: Iterable[str]) -> RowConditions:
    """``conditions`` without the parts answered by other columns (``geo`` dropped too)."""
    keep = set(columns)
    changes: dict[str, object] = {"geo": None}
    for column, cleared in _ONLY_FIELDS.items():
        if column not in keep:
            changes.update(cleared)
    return dataclasses.replace(conditions, **changes)  # type: ignore[arg-type]


def evaluate_building(index: TimelineIndex, events: Sequence[object], conditions: RowConditions) -> list[int]:
    """:func:`evaluate`, building what is missing: with several needed columns missing only one is
    built over all events (:data:`FIRST_COLUMN_ORDER`); the others are computed for its matches
    only (an AND of per-row tests, so the set is the same), and complete later."""
    needed = needed_columns(conditions)
    missing = [column for column in needed if not index.has(column)]
    if len(missing) <= 1 or index.count <= SYNC_COMPLETE_MAX_EVENTS:
        index.ensure(events, needed)
        return evaluate(index, conditions)
    present = [column for column in needed if index.has(column)]
    if not present:
        first = next(column for column in FIRST_COLUMN_ORDER if column in missing)
        index.ensure(events, (first,))
        present, missing = [first], [column for column in missing if column != first]
    candidates = evaluate(index, only_columns(conditions, present))
    subset = TimelineIndex(len(candidates))
    subset.ensure([events[position] for position in candidates], missing)
    return [candidates[position] for position in evaluate(subset, only_columns(conditions, missing))]


def _search_first(index: TimelineIndex, conditions: RowConditions) -> bool:
    """``q`` with conditions on a large timeline whose index lacks a needed column (UX-round
    review: the search column is built anyway; parsing every timestamp for the time column first
    doubled the first page)."""
    return index.count > SYNC_COMPLETE_MAX_EVENTS and any(not index.has(column) for column in needed_columns(conditions))


def evaluate_on(events: Sequence[object], candidates: Sequence[int], conditions: RowConditions) -> list[int]:
    """The ``candidates`` (ascending positions) passing ``conditions``, from columns of those events only."""
    needed = needed_columns(conditions)
    subset = TimelineIndex(len(candidates))
    subset.ensure([events[position] for position in candidates], needed)
    return [candidates[position] for position in evaluate(subset, only_columns(conditions, needed))]


# --- API entry -----------------------------------------------------------------------------------

TIMELINE_INDEXES: SingleFlightIndexCache[TimelineIndex] = SingleFlightIndexCache(max_runs=4)
_BACKGROUND: set[threading.Thread] = set()
_BACKGROUND_LOCK = threading.Lock()


def _yield_to_requests() -> None:
    """Background build: give the GIL to request threads between slices (skipped while a request
    waits for the column being built: ``TimelineIndex._paced``)."""
    time.sleep(BACKGROUND_PAUSE_S)


def _complete_later(index: TimelineIndex, events: Sequence[object]) -> None:
    """Finish the remaining columns and the file (in a thread for a large timeline)."""
    with index._lock:
        if index._completing or (index.complete() and (index.saved or index.timeline_path is None)):
            return
        index._completing = True

    def run() -> None:
        try:
            index.complete_and_save(events, _yield_to_requests)
        except Exception as exc:  # a background build never takes the server down
            LOGGER.warning("timeline index completion failed: %s", exc)
        finally:
            with _BACKGROUND_LOCK:
                _BACKGROUND.discard(threading.current_thread())

    if index.count <= SYNC_COMPLETE_MAX_EVENTS:
        index.complete_and_save(events)
        return
    thread = threading.Thread(target=run, name="timeline-index", daemon=True)
    with _BACKGROUND_LOCK:
        _BACKGROUND.add(thread)
    thread.start()


def wait_for_background(timeout: float = 30.0) -> bool:
    """Join pending background completions (perf script / tests); ``True`` when none is left."""
    with _BACKGROUND_LOCK:
        threads = list(_BACKGROUND)
    for thread in threads:
        thread.join(timeout)
    with _BACKGROUND_LOCK:
        return not _BACKGROUND


def _output_file_stamp(stamp: tuple[object, ...], timeline_path: Path) -> tuple[int, int] | None:
    """``(size, mtime_ns)`` of ``timeline_path`` in an ``output_stamp`` (``None``: not there)."""
    if len(stamp) == 1 and isinstance(stamp[0], tuple) and len(stamp[0]) == 3:
        path, size, mtime = stamp[0]
        if path == str(timeline_path) and type(size) is int and type(mtime) is int and size >= 0:
            return size, mtime
    return None


def _run_index(run_id: str, timeline_path: Path, events: Sequence[object], stamp: tuple[object, ...]) -> TimelineIndex:
    file_stamp = _output_file_stamp(stamp, timeline_path)
    return TIMELINE_INDEXES.get_or_build((run_id, stamp), lambda: open_index(timeline_path, len(events), file_stamp))


def timeline_positions(
    run_id: str,
    timeline_path: Path,
    events: Sequence[object],
    conditions: RowConditions | None,
    stamp: tuple[object, ...],
    needle: str = "",
) -> Callable[[], Iterable[int]]:
    """``MATCH_CACHE`` compute of ``GET /timeline``: positions from the run's index, or the
    predicate scan when the index cannot be used (an index problem never fails the request).

    ``conditions`` (``None``: none) and ``needle`` (the folded ``q``, :func:`search_needle`; the
    search column narrows the condition matches) are AND-ed. ``stamp`` is
    ``row_conditions.output_stamp(timeline_path)`` taken *before* ``events`` were read (the route
    does so); its ``(size, mtime_ns)`` is the revision the index describes."""

    def compute() -> Iterable[int]:
        try:
            index = _run_index(run_id, timeline_path, events, stamp)
            if index.count == len(events):
                positions: list[int] | None = None
                if conditions is not None and needle and _search_first(index, conditions):
                    # A large timeline missing a condition column: the search narrows first and the
                    # conditions are checked on its hits only (an AND of per-row tests: same set);
                    # the columns complete in the background.
                    positions = evaluate_on(events, index.ensure_search(events).positions(needle), conditions)
                    _complete_later(index, events)
                    return positions
                if conditions is not None:
                    positions = evaluate_building(index, events, conditions)
                    if not index.complete() or not index.saved:
                        _complete_later(index, events)
                if needle:
                    return index.ensure_search(events).positions(needle, positions)
                return range(len(events)) if positions is None else positions
            LOGGER.warning("timeline index of %s has %d rows for %d events; scanning", run_id, index.count, len(events))
        except Exception as exc:  # the scan below answers instead of a 500
            LOGGER.warning("timeline index of %s failed (%s); scanning", run_id, exc)
        predicate = conditions.predicate("timeline") if conditions is not None else None
        return [
            i
            for i, row in enumerate(events)
            if isinstance(row, Mapping) and (predicate is None or predicate(row)) and event_matches_search(row, needle)
        ]

    return compute


def timeline_groups(
    run_id: str,
    timeline_path: Path,
    events: Sequence[object],
    stamp: tuple[object, ...],
    matched: Callable[[], Sequence[int]] | None = None,
    key: tuple[object, ...] = (),
) -> GroupColumn:
    """The run's display groups (``group=1``); built without the shared index when that fails.

    With the ``group`` column (index file, or a small timeline built in the request) the groups of
    every event; a large timeline without it (an older run) builds the column in the background
    and answers from the groups of the ``matched`` positions (``None`` = every event) under
    ``key`` (the request's match key) -- same leaders and members (UX-round review: the first
    grouped page no longer waits for the time + group columns of the whole timeline)."""
    try:
        index = _run_index(run_id, timeline_path, events, stamp)
        if index.count == len(events):
            local = index.request_groups.get(key) if index.groups is None else None
            if local is not None:  # later pages of a request answered before the column existed
                groups = local
            elif index.has(GROUP) or index.count <= SYNC_COMPLETE_MAX_EVENTS:
                groups = index.ensure_groups(events)
            else:
                groups = index.groups_for(events, key, matched)
            if not index.complete() or not index.saved:
                _complete_later(index, events)
            return groups
        LOGGER.warning("timeline index of %s has %d rows for %d events; grouping alone", run_id, index.count, len(events))
    except Exception as exc:  # grouping is computed on its own instead of a 500
        LOGGER.warning("timeline index of %s failed (%s); grouping alone", run_id, exc)
    return TimelineIndex(len(events)).ensure_groups(events)


MAX_GROUP_SOURCES = 20
MAX_GROUP_MEMBERS = 50


def group_page_fields(
    groups: GroupColumn, events: Sequence[object], leader: int, matched: Sequence[int] | None
) -> dict[str, object]:
    """``group_id`` / ``source_count`` / ``sources`` / ``group_members`` of a grouped page row.

    ``matched`` (ascending positions, ``None`` = every event) limits the members to the events the
    request's conditions / search kept. ``sources`` lists each (artifact type, path) once."""
    group = groups.ids[leader]
    members = groups.members.get(group) if group != NO_GROUP else None
    if members and matched is not None:
        members = [m for m in members if _contains(matched, m)]
    if not members or len(members) < 2:
        return {"source_count": 1}
    sources: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for position in members:
        row = events[position]
        if not _is_mapping(row):
            continue
        details = _details_of(row)  # type: ignore[arg-type]
        artifact_type = str((details or {}).get("artifact_type") or row.get("source") or "")  # type: ignore[union-attr]
        path = str(row.get("path") or "")  # type: ignore[union-attr]
        if (artifact_type, path) in seen:
            continue
        seen.add((artifact_type, path))
        if len(sources) < MAX_GROUP_SOURCES:
            sources.append(
                {
                    "artifact_type": artifact_type,
                    "event_type": row.get("event_type"),  # type: ignore[union-attr]
                    "path": path,
                    "record_index": position,
                }
            )
    return {
        "group_id": group_label(event_group_key(events[leader])),
        "source_count": len(seen),
        "event_count": len(members),
        "sources": sources,
        "sources_truncated": len(seen) > len(sources),
        "group_members": members[:MAX_GROUP_MEMBERS],
        "group_members_truncated": len(members) > MAX_GROUP_MEMBERS,
    }


def locate_position(
    shown: Sequence[int], record: int, groups: GroupColumn | None = None, matched: Sequence[int] | None = None
) -> int | None:
    """Row position of event ``record`` in a listing showing the ascending positions ``shown``
    (``locate=``: a deep link to one event). Grouped: the row of its group's first matched member
    (``matched`` = the positions the conditions / ``q`` kept, ``None`` = every event). ``None``
    when the event is not listed."""
    if matched is not None and not _contains(matched, record):
        return None  # the conditions / q leave the event out
    target = record
    if groups is not None and 0 <= record < len(groups.ids):
        group = groups.ids[record]
        for member in groups.members.get(group, ()) if group != NO_GROUP else ():
            if matched is None or _contains(matched, member):
                target = member
                break
    at = bisect_left(shown, target)
    return at if at < len(shown) and shown[at] == target else None


def _contains(sorted_positions: Sequence[int], position: int) -> bool:
    at = bisect_left(sorted_positions, position)
    return at < len(sorted_positions) and sorted_positions[at] == position
