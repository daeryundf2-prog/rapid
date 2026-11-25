"""Row windows of large pretty-printed run-output JSON files, without parsing them whole.

``rapidtriage-files.json`` / ``rapidtriage-timeline.json`` of a large case are hundreds of
MB: bigger than the parsed-output LRU (``core.jobs.OUTPUT_JSON_CACHE_MAX_BYTES``), so every
``GET /files`` / ``GET /timeline`` page re-parsed the whole file (seconds per request).

Run outputs are written by ``json.dump(..., indent=2)``: every member of the top-level object
starts a line indented by exactly two spaces, every element of a top-level array a line
indented by exactly four, and JSON strings never hold a raw line break. One regex pass over
the file records those line offsets (:class:`JsonRowIndex`); a page then parses only its own
rows and the other top-level members are parsed once per file revision. A file that does not
have this layout gets no index (:func:`large_output_index` returns ``None``) and callers keep
the full parse.
"""

from __future__ import annotations

import json
import mmap
import re
import threading
from array import array
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, overload

from ...core.jobs import OUTPUT_JSON_CACHE_MAX_BYTES

# A line break followed by exactly two or four spaces and the line's first character.
_MEMBER_OR_ELEMENT_LINE = re.compile(rb"\n( {2}| {4})(?=[^ \r\n])")
INDEX_CACHE_SIZE = 4


class JsonLayoutError(ValueError):
    """The file is not an ``indent=2`` JSON object (no row index)."""


class JsonRowIndex:
    """Byte offsets of the top-level members and of the top-level array elements of one file."""

    def __init__(
        self,
        path: Path,
        members: dict[str, tuple[int, int]],
        rows: dict[str, tuple[array, array]],
    ) -> None:
        self.path = path
        self._members = members  # key -> (value start, value end), in file order
        self._rows = rows  # array key -> (element starts, element ends)
        self._values: dict[str, Any] = {}
        self._lock = threading.Lock()

    @classmethod
    def build(cls, path: Path) -> JsonRowIndex:
        members: dict[str, tuple[int, int]] = {}
        rows: dict[str, tuple[array, array]] = {}
        with path.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if not (data[:2] == b"{\n" or data[:3] == b"{\r\n"):
                raise JsonLayoutError("not an indented JSON object")
            key: str | None = None  # member whose multi-line value is open
            value_start = 0
            starts: array | None = None  # element starts of the open array member
            ends: array | None = None
            element_open = False
            decoder = json.JSONDecoder()
            for match in _MEMBER_OR_ELEMENT_LINE.finditer(data):
                line_start = match.start() + 1
                text_start = match.end()
                eol = data.find(b"\n", text_start)
                line = data[text_start : eol if eol >= 0 else len(data)].rstrip(b"\r")
                if text_start - line_start == 4:
                    if starts is None or ends is None:
                        continue  # a member of a top-level object value
                    if line[:1] in (b"}", b"]") and element_open:
                        ends.append(text_start + 1)
                        element_open = False
                        continue
                    if element_open:
                        raise JsonLayoutError("array element starts inside another element")
                    value = line[:-1] if line.endswith(b",") else line
                    starts.append(line_start)
                    if value in (b"{", b"["):
                        element_open = True
                    else:
                        ends.append(text_start + len(value))
                    continue
                if line[:1] in (b"}", b"]"):
                    if key is None or element_open:
                        raise JsonLayoutError("unbalanced top-level member")
                    members[key] = (value_start, text_start + 1)
                    if starts is not None and ends is not None:
                        rows[key] = (starts, ends)
                    key, starts, ends = None, None, None
                    continue
                if key is not None:
                    raise JsonLayoutError("member starts inside another member")
                try:
                    text = line.decode("utf-8")
                    name, position = decoder.raw_decode(text)
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
                if value_text in ("{", "["):
                    key, value_start = name, end - 1
                    if value_text == "[":
                        starts, ends = array("q"), array("q")
                    continue
                members[name] = (end - len(value_text.encode("utf-8")), end)
                if value_text == "[]":
                    rows[name] = (array("q"), array("q"))
            if key is not None:
                raise JsonLayoutError("unterminated top-level member")
            if data[max(0, len(data) - 64) :].rstrip()[-1:] != b"}":
                raise JsonLayoutError("unterminated top-level object")
        return cls(path, members, rows)

    def keys(self) -> list[str]:
        return list(self._members)

    def count(self, key: str) -> int | None:
        """Element count of top-level array ``key`` (``None`` = absent or not an array)."""
        found = self._rows.get(key)
        return len(found[0]) if found is not None else None

    def value(self, key: str) -> Any:
        """Parsed top-level member ``key`` (cached: shared and read-only)."""
        with self._lock:
            if key in self._values:
                return self._values[key]
        start, end = self._members[key]
        with self.path.open("rb") as handle:
            handle.seek(start)
            parsed = json.loads(handle.read(end - start))
        with self._lock:
            self._values[key] = parsed
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
        with self.path.open("rb") as handle:
            handle.seek(base)
            chunk = handle.read(ends[stop - 1] - base)
        try:
            return [json.loads(chunk[starts[i] - base : ends[i] - base]) for i in range(start, stop)]
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise JsonLayoutError(f"unreadable element of {key}") from exc


class LazyRows(Sequence[object]):
    """Read-only sequence view of one indexed top-level array (elements parsed on access)."""

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


_INDEX_CACHE: OrderedDict[tuple[str, int, int], JsonRowIndex | None] = OrderedDict()
_INDEX_LOCK = threading.Lock()


def large_output_index(path: Path) -> JsonRowIndex | None:
    """Row index of a run output too large for the parsed-output LRU, else ``None``.

    ``None`` too when the file does not have the ``indent=2`` layout. Indexes are cached per
    file revision ``(resolved path, mtime_ns, size)``; a rewritten output self-invalidates.
    """
    resolved = Path(path).expanduser().resolve()
    stat = resolved.stat()
    if stat.st_size <= OUTPUT_JSON_CACHE_MAX_BYTES:
        return None
    key = (str(resolved), stat.st_mtime_ns, stat.st_size)
    with _INDEX_LOCK:  # one build at a time: concurrent pages of the same file wait for it
        if key in _INDEX_CACHE:
            _INDEX_CACHE.move_to_end(key)
            return _INDEX_CACHE[key]
        try:
            index: JsonRowIndex | None = JsonRowIndex.build(resolved)
        except JsonLayoutError:
            index = None
        _INDEX_CACHE[key] = index
        while len(_INDEX_CACHE) > INDEX_CACHE_SIZE:
            _INDEX_CACHE.popitem(last=False)
    return index
