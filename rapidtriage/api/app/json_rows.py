"""Row windows of large pretty-printed run-output JSON files, without parsing them whole per request.

``rapidtriage-files.json`` / ``rapidtriage-timeline.json`` of a large case are hundreds of
MB: bigger than the parsed-output LRU (``core.jobs.OUTPUT_JSON_CACHE_MAX_BYTES``), so every
``GET /files`` / ``GET /timeline`` page re-parsed the whole file (seconds per request).

Run outputs are written by ``json.dump(..., indent=2)``: every member of the top-level object
starts a line indented by exactly two spaces, every element of a top-level array a line
indented by exactly four, and JSON strings never hold a raw line break. One regex pass over
the file records those line offsets (:class:`JsonRowIndex`); a page then parses only its own
rows and the other top-level members are parsed once per file revision.

The index is exact or absent. Building it also parses every array element and every other
member once, and checks the bytes between them (commas, line breaks, brackets): the indexed
rows, their positions and counts are then exactly what ``json.load`` of the same file gives.
A file without this layout, or one ``json.load`` would reject (a corrupt or split line, a
missing comma), gets no index (:func:`large_output_index` returns ``None``) and callers keep
the full parse, so it fails the way it always did and no row is ever served at a shifted
position. Line breaks may be LF or CRLF; the last line needs no line break.

An index belongs to one file revision ``(st_dev, st_ino, st_size, st_mtime_ns)``. Every read
re-opens the file and checks that revision first: a file rewritten or appended to after it was
indexed raises :class:`StaleIndexError` (a :class:`JsonLayoutError`) instead of serving bytes
at stale offsets, and the next :func:`large_output_index` call indexes the new revision. The
file is read with plain reads, never memory-mapped (a file truncated by a concurrent writer
cannot fault the server).
"""

from __future__ import annotations

import json
import os
import re
import threading
from array import array
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, overload

from ...core.jobs import OUTPUT_JSON_CACHE_MAX_BYTES
from .index_cache import SingleFlightIndexCache

# A line break followed by exactly two or four spaces and the line's first character.
_MEMBER_OR_ELEMENT_LINE = re.compile(rb"\n( {2}| {4})(?=[^ \r\n])")
# What may follow the last member: its line break, the closing brace, trailing whitespace.
_OBJECT_END = re.compile(rb"\r?\n\}[ \t\r\n]*")
_OBJECT_START = (b"{\n", b"{\r\n")
_BREAKS = (b"\n", b"\r\n")
_ELEMENT_GAPS = (b",\n", b",\r\n")
_ARRAY_TAILS = (b"\n  ", b"\r\n  ")
INDEX_CACHE_SIZE = 4
# Bytes read per step of the layout scan and of the element check.
SCAN_CHUNK_BYTES = 16 * 1024 * 1024
# Raw JSON bytes of parsed top-level values one index keeps (larger values are parsed on use).
VALUE_CACHE_MAX_BYTES = 16 * 1024 * 1024
# Rows of a folder / special node read up front (a larger restriction parses the whole output).
PREFETCH_ROWS_MAX = 20_000

Revision = tuple[int, int, int, int]


class JsonLayoutError(ValueError):
    """The file is not an ``indent=2`` JSON object ``json.load`` accepts (no row index)."""


class StaleIndexError(JsonLayoutError):
    """The file changed after it was indexed (or while it was being indexed)."""


def file_revision(stat: os.stat_result) -> Revision:
    """``(st_dev, st_ino, st_size, st_mtime_ns)``: a rewrite in place or an atomic replace changes it."""
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _open_revision(path: Path, revision: Revision) -> IO[bytes]:
    """``path`` opened for reading, provided it is still ``revision`` (else :class:`StaleIndexError`)."""
    handle = path.open("rb")
    try:
        if file_revision(os.fstat(handle.fileno())) != revision:
            raise StaleIndexError(f"{path.name} changed after it was indexed")
    except BaseException:
        handle.close()
        raise
    return handle


def _read_at(handle: IO[bytes], start: int, end: int) -> bytes:
    handle.seek(start)
    data = handle.read(end - start)
    if len(data) != end - start:
        raise StaleIndexError("the file is shorter than its index")
    return data


@dataclass
class _Member:
    name: str
    line_start: int
    value_start: int
    value_end: int


class _LayoutScan:
    """Pass 1: line offsets of the top-level members and of the top-level array elements."""

    def __init__(self) -> None:
        self.members: list[_Member] = []
        self.rows: dict[str, tuple[array, array]] = {}
        self._decoder = json.JSONDecoder()
        self._open: _Member | None = None  # member whose multi-line value is open
        self._open_char = b""
        self._starts: array | None = None  # element starts / ends of the open array member
        self._ends: array | None = None
        self._element_open = False

    def feed(self, region: bytes, base: int) -> None:
        """Scan the complete lines of ``region`` (file offset ``base``; it starts at a line break)."""
        for match in _MEMBER_OR_ELEMENT_LINE.finditer(region):
            line_start = base + match.start() + 1
            text_start = base + match.end()
            eol = region.find(b"\n", match.end())
            line = region[match.end() : eol if eol >= 0 else len(region)]
            if line.endswith(b"\r"):
                line = line[:-1]
            if match.end() - match.start() == 5:
                self._element(line, line_start, text_start)
            else:
                self._member(line, line_start, text_start)

    def _element(self, line: bytes, line_start: int, text_start: int) -> None:
        if self._starts is None or self._ends is None:
            return  # a member of a top-level object value (that value is parsed whole) or a stray line
        if self._element_open:
            if line[:1] not in (b"}", b"]") or line[1:] not in (b"", b","):
                raise JsonLayoutError("array element starts inside another element")
            self._ends.append(text_start + 1)
            self._element_open = False
            return
        value = line[:-1] if line.endswith(b",") else line
        self._starts.append(line_start)
        if value in (b"{", b"["):
            self._element_open = True
        else:
            self._ends.append(text_start + len(value))

    def _member(self, line: bytes, line_start: int, text_start: int) -> None:
        if line[:1] in (b"}", b"]"):
            member = self._open
            if member is None or self._element_open or line[:1] != self._open_char or line[1:] not in (b"", b","):
                raise JsonLayoutError("unbalanced top-level member")
            member.value_end = text_start + 1
            if self._starts is not None and self._ends is not None:
                self.rows[member.name] = (self._starts, self._ends)
            self._open, self._starts, self._ends = None, None, None
            return
        if self._open is not None:
            raise JsonLayoutError("member starts inside another member")
        try:
            text = line.decode("utf-8")
            name, position = self._decoder.raw_decode(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JsonLayoutError("unreadable member name") from exc
        rest = text[position:]
        if not isinstance(name, str) or not rest.startswith(": "):
            raise JsonLayoutError("unreadable member line")
        value_text = rest[2:]
        end = text_start + len(line)
        if value_text.endswith(","):
            value_text = value_text[:-1]
            end -= 1
        if any(member.name == name for member in self.members):
            raise JsonLayoutError("repeated top-level member")  # json.dump never writes one
        if value_text in ("{", "["):
            self._open = _Member(name, line_start, end - 1, -1)
            self._open_char = b"}" if value_text == "{" else b"]"
            self.members.append(self._open)
            if value_text == "[":
                self._starts, self._ends = array("q"), array("q")
            return
        self.members.append(_Member(name, line_start, end - len(value_text.encode("utf-8")), end))
        if value_text == "[]":
            self.rows[name] = (array("q"), array("q"))

    def finish(self) -> None:
        if self._open is not None:
            raise JsonLayoutError("unterminated top-level member")
        if not self.members:
            raise JsonLayoutError("no top-level member")


def _scan(path: Path, expected: Revision | None) -> tuple[Revision, _LayoutScan]:
    scan = _LayoutScan()
    with path.open("rb") as handle:
        revision = file_revision(os.fstat(handle.fileno()))
        if expected is not None and revision != expected:
            raise StaleIndexError(f"{path.name} changed before it was indexed")
        base = 0
        carry = b""
        while True:
            chunk = handle.read(SCAN_CHUNK_BYTES)
            data = carry + chunk if carry else chunk
            if base == 0 and not data.startswith(_OBJECT_START):
                if chunk and len(data) < 3:
                    carry = data
                    continue
                raise JsonLayoutError("not an indented JSON object")
            if not chunk:
                scan.feed(data, base)
                base += len(data)
                break
            cut = data.rfind(b"\n")
            if cut <= 0:
                carry = data  # one long line: read on
                continue
            scan.feed(data[:cut], base)
            base += cut
            carry = data[cut:]
        if base != revision[2] or file_revision(os.fstat(handle.fileno())) != revision:
            raise StaleIndexError(f"{path.name} changed while it was indexed")
    scan.finish()
    return revision, scan


class JsonRowIndex:
    """Byte offsets of the top-level members and of the top-level array elements of one file revision."""

    def __init__(
        self,
        path: Path,
        revision: Revision,
        members: dict[str, tuple[int, int]],
        rows: dict[str, tuple[array, array]],
        values: dict[str, Any],
    ) -> None:
        self.path = path
        self.revision = revision
        self._members = members  # key -> (value start, value end), in file order
        self._rows = rows  # array key -> (element starts, element ends)
        self._values = values  # parsed top-level values kept (shared, read-only)
        self._value_bytes = sum(members[key][1] - members[key][0] for key in values)
        self._lock = threading.Lock()

    @property
    def stamp(self) -> tuple[object, ...]:
        """``(path, *revision)``: the file revision as part of a cache key."""
        return (str(self.path), *self.revision)

    @classmethod
    def build(cls, path: Path, expected: Revision | None = None) -> JsonRowIndex:
        """Index ``path`` (which must still be ``expected`` when given): the layout scan, then the
        check that ``json.load`` reads the same rows (module doc)."""
        revision, scan = _scan(path, expected)
        values: dict[str, Any] = {}
        budget = VALUE_CACHE_MAX_BYTES
        with _open_revision(path, revision) as handle:
            if _read_at(handle, 0, scan.members[0].line_start) not in _OBJECT_START:
                raise JsonLayoutError("unexpected bytes before the first member")
            for position, member in enumerate(scan.members):
                last = position + 1 == len(scan.members)
                gap = _read_at(handle, member.value_end, revision[2] if last else scan.members[position + 1].line_start)
                if not (_OBJECT_END.fullmatch(gap) if last else gap in _ELEMENT_GAPS):
                    raise JsonLayoutError(f"unexpected bytes after member {member.name!r}")
                size = member.value_end - member.value_start
                found = scan.rows.get(member.name)
                if found is not None and len(found[0]):
                    parsed = _check_elements(handle, member, found, keep=size <= budget)
                else:
                    try:
                        parsed = json.loads(_read_at(handle, member.value_start, member.value_end))
                    except ValueError as exc:
                        raise JsonLayoutError(f"unreadable member {member.name!r}") from exc
                if parsed is not _UNKEPT and size <= budget:
                    values[member.name] = parsed
                    budget -= size
        members = {member.name: (member.value_start, member.value_end) for member in scan.members}
        return cls(path, revision, members, scan.rows, values)

    def _open(self) -> IO[bytes]:
        return _open_revision(self.path, self.revision)

    def keys(self) -> list[str]:
        return list(self._members)

    def count(self, key: str) -> int | None:
        """Element count of top-level array ``key`` (``None`` = absent or not an array)."""
        found = self._rows.get(key)
        return len(found[0]) if found is not None else None

    def value(self, key: str) -> Any:
        """Parsed top-level member ``key`` (shared and read-only)."""
        with self._lock:
            if key in self._values:
                return self._values[key]
        start, end = self._members[key]
        with self._open() as handle:
            data = _read_at(handle, start, end)
        try:
            parsed = json.loads(data)
        except ValueError as exc:
            raise JsonLayoutError(f"unreadable member {key!r}") from exc
        with self._lock:
            if key not in self._values and self._value_bytes + (end - start) <= VALUE_CACHE_MAX_BYTES:
                self._values[key] = parsed
                self._value_bytes += end - start
        return parsed

    def payload_with_placeholders(self, row_keys: Iterable[str]) -> dict[str, object]:
        """The top-level object in file order; members in ``row_keys`` are empty lists (never parsed)."""
        placeholders = set(row_keys)
        return {key: [] if key in placeholders else self.value(key) for key in self._members}

    def rows(self, key: str, start: int, stop: int) -> list[object]:
        """Elements ``[start, stop)`` of top-level array ``key``, parsed from one read."""
        starts, ends = self._rows[key]
        stop = min(stop, len(starts))
        if start >= stop:
            return []
        base = starts[start]
        with self._open() as handle:
            chunk = _read_at(handle, base, ends[stop - 1])
        try:
            return [json.loads(chunk[starts[i] - base : ends[i] - base]) for i in range(start, stop)]
        except ValueError as exc:
            raise JsonLayoutError(f"unreadable element of {key}") from exc


_UNKEPT = object()


def _check_elements(handle: IO[bytes], member: _Member, found: tuple[array, array], *, keep: bool) -> object:
    """Parse every element of array ``member`` and check the bytes around them; the parsed list when
    ``keep`` (else :data:`_UNKEPT`)."""
    starts, ends = found
    count = len(starts)
    if _read_at(handle, member.value_start + 1, starts[0]) not in _BREAKS:
        raise JsonLayoutError(f"unexpected bytes after {member.name!r} opens")
    kept: list[object] = []
    position = 0
    while position < count:
        base = starts[position]
        stop = position + 1
        while stop < count and ends[stop] - base <= SCAN_CHUNK_BYTES:
            stop += 1
        # The chunk runs to the next element's start (or to the closing bracket): every gap is in it.
        limit = starts[stop] if stop < count else member.value_end - 1
        data = _read_at(handle, base, limit)
        for index in range(position, stop):
            try:
                row = json.loads(data[starts[index] - base : ends[index] - base])
            except ValueError as exc:
                raise JsonLayoutError(f"unreadable element {index} of {member.name!r}") from exc
            if keep:
                kept.append(row)
            gap = data[ends[index] - base : (starts[index + 1] if index + 1 < count else limit) - base]
            if gap not in (_ELEMENT_GAPS if index + 1 < count else _ARRAY_TAILS):
                raise JsonLayoutError(f"unexpected bytes after element {index} of {member.name!r}")
        position = stop
    return kept if keep else _UNKEPT


class LazyRows(Sequence[object]):
    """Read-only sequence view of one indexed top-level array (elements parsed on access;
    iteration reads the array in chunks)."""

    CHUNK = 4096

    def __iter__(self) -> Iterator[object]:
        for start in range(0, self._length, self.CHUNK):
            yield from self._index.rows(self._key, start, start + self.CHUNK)

    def __init__(self, index: JsonRowIndex, key: str) -> None:
        self._index = index
        self._key = key
        self._length = index.count(key) or 0

    def __len__(self) -> int:
        return self._length

    @overload
    def __getitem__(self, item: int) -> object: ...

    @overload
    def __getitem__(self, item: slice) -> list[object]: ...

    def __getitem__(self, item: int | slice) -> object | list[object]:
        if isinstance(item, slice):
            start, stop, step = item.indices(self._length)
            window = self._index.rows(self._key, start, stop) if start < stop else []
            return window[::step] if step != 1 else window
        position = item + self._length if item < 0 else item
        if not 0 <= position < self._length:
            raise IndexError(item)
        return self._index.rows(self._key, position, position + 1)[0]


class PrefetchedRows(LazyRows):
    """An indexed array whose rows at ``positions`` (ascending) are read up front, in contiguous
    runs; other positions are parsed on access."""

    MAX_GAP = 64

    def __init__(self, index: JsonRowIndex, key: str, positions: Sequence[int]) -> None:
        super().__init__(index, key)
        self._rows: dict[int, object] = {}
        run_start: int | None = None
        previous = -1
        for position in [*positions, -1]:
            if run_start is not None and (position < 0 or position - previous > self.MAX_GAP or position - run_start >= self.CHUNK):
                for offset, row in enumerate(index.rows(key, run_start, previous + 1)):
                    self._rows[run_start + offset] = row
                run_start = None
            if position >= 0:
                run_start = position if run_start is None else run_start
                previous = position

    def __getitem__(self, item):  # type: ignore[override]
        if isinstance(item, int) and item in self._rows:
            return self._rows[item]
        return super().__getitem__(item)


_NO_INDEX = object()
# Per file: one build at a time (concurrent pages of the same file wait for it, other files build
# in parallel); a new revision of a file replaces its older index.
INDEX_CACHE: SingleFlightIndexCache[object] = SingleFlightIndexCache(INDEX_CACHE_SIZE)


def large_output_index(path: Path) -> JsonRowIndex | None:
    """Row index of a run output too large for the parsed-output LRU, else ``None``.

    ``None`` too when the file has no exact index (module doc) or changed while it was being
    indexed. Indexes are cached per file revision; a rewritten output self-invalidates.
    """
    resolved = Path(path).expanduser().resolve()
    stat = resolved.stat()
    if stat.st_size <= OUTPUT_JSON_CACHE_MAX_BYTES:
        return None
    revision = file_revision(stat)

    def build() -> object:
        try:
            return JsonRowIndex.build(resolved, revision)
        except StaleIndexError:
            raise
        except JsonLayoutError:
            return _NO_INDEX

    try:
        found = INDEX_CACHE.get_or_build((str(resolved), *revision), build)
    except StaleIndexError:
        return None  # changed while being indexed: this request parses the whole output
    return found if isinstance(found, JsonRowIndex) else None


def clear_index_cache() -> None:
    INDEX_CACHE.clear()
