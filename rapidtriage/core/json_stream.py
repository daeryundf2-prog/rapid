"""Incremental JSON reader for run outputs that exceed comfortable RAM.

Run stage payloads (manifest/docs/files/artifacts) can reach tens of GB on
large evidence sets. ``json.loads(path.read_text())`` on those files raises
``MemoryError`` regardless of installed RAM.  This module exposes a small
lazy API so downstream stages can consume a top-level member at a time:

- ``open_json(path)`` returns a context manager whose ``root()`` is a
  ``LazyObject`` for the top-level JSON object.
- ``LazyObject.members()`` yields ``(key, node)`` pairs in document order.
- ``LazyArray.items(lazy=False)`` yields parsed items; with ``lazy=True``
  container items are yielded as ``LazyObject``/``LazyArray`` nodes.
- ``node.materialize()`` parses the entire node value into memory — callers
  decide which members are small enough to materialize.
- ``Scalar`` nodes wrap leaf values (``str``, ``int``, ``float``, ``bool``,
  ``None``); ``Scalar.value``/``materialize()`` return the value.

Lazy children must be consumed before the parent advances; when the caller
abandons a lazy child early the reader fast-skips the remainder of that
value without materializing it, so ``for key, node in obj.members(): if key
== "summary": node.materialize(); break`` skips a preceding multi-GB array
member at near I/O speed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

__all__ = [
    "JsonStreamError",
    "LazyArray",
    "LazyObject",
    "Scalar",
    "iter_array_items",
    "open_json",
    "read_member",
]

_WS = " \t\r\n"
_SPECIAL = re.compile(r'["{}\[\]\\]')
_NUMBER_TAIL = re.compile(r"[.eE][+-]?")


class JsonStreamError(ValueError):
    """Raised when a streamed JSON document is malformed or truncated."""


class Scalar:
    """Materialized leaf value inside a lazy stream."""

    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value

    def materialize(self) -> Any:
        return self.value


class _Reader:
    """Chunked reader over a JSON document with parse and skip primitives."""

    __slots__ = ("_buf", "_chunk", "_dec", "_eof", "_f", "_pos", "_stack")

    def __init__(self, path: Path, chunk_size: int = 1 << 22) -> None:
        self._f = open(path, "r", encoding="utf-8", buffering=chunk_size)
        self._chunk = chunk_size
        self._buf = ""
        self._pos = 0
        self._eof = False
        self._dec = json.JSONDecoder()
        self._stack: list[str] = []

    def close(self) -> None:
        self._f.close()

    # -- buffer -----------------------------------------------------------
    def _more(self) -> bool:
        if self._pos:
            self._buf = self._buf[self._pos :]
            self._pos = 0
        data = self._f.read(self._chunk)
        if not data:
            self._eof = True
            return False
        self._buf += data
        return True

    def _fail(self, message: str) -> JsonStreamError:
        return JsonStreamError(f"{message} (offset ~{self._pos})")

    # -- cursor -----------------------------------------------------------
    def peek(self) -> str:
        while True:
            buf = self._buf
            i = self._pos
            n = len(buf)
            while i < n and buf[i] in _WS:
                i += 1
            self._pos = i
            if i < n:
                return buf[i]
            if not self._more():
                return ""

    def get(self) -> str:
        ch = self.peek()
        if not ch:
            raise self._fail("unexpected end of JSON input")
        self._pos += 1
        return ch

    def expect(self, ch: str) -> None:
        got = self.get()
        if got != ch:
            raise self._fail(f"expected {ch!r}, got {got!r}")

    # -- values -----------------------------------------------------------
    def value(self) -> Any:
        """Parse a complete value starting at the cursor."""
        while True:
            self.peek()
            try:
                result, end = self._dec.raw_decode(self._buf, self._pos)
            except json.JSONDecodeError as exc:
                if self._eof or not self._more():
                    raise self._fail(f"invalid JSON value: {exc}") from exc
                continue
            if not self._eof and (
                end == len(self._buf)
                # A number whose parse stopped on a '.'/'e'/'e+'/... at the
                # buffer edge may be truncated mid-token ("-1." could really
                # be "-1.973" continuing into the next chunk).
                or (
                    isinstance(result, (int, float))
                    and not isinstance(result, bool)
                    and _NUMBER_TAIL.fullmatch(self._buf, end) is not None
                )
            ) and self._more():
                continue  # the token may extend into the next chunk
            self._pos = end
            return result

    def node(self, *, lazy: bool) -> Any:
        """Return the value at the cursor, lazily wrapping containers.

        Lazy containers consume their opening bracket immediately so every
        marker on ``_stack`` denotes a container whose contents (but not
        opener) remain unread — the invariant ``drain_to`` relies on.
        """
        if not lazy:
            return self.value()
        ch = self.peek()
        if ch == "{":
            self.get()
            self._stack.append("{")
            return LazyObject(self, len(self._stack))
        if ch == "[":
            self.get()
            self._stack.append("[")
            return LazyArray(self, len(self._stack))
        return Scalar(self.value())

    def skip_value(self) -> None:
        """Skip one complete value without materializing it."""
        ch = self.peek()
        if ch in "{[":
            self.get()
            self._skip_container()
            return
        if ch == '"':
            self.value()
            return
        # number / true / false / null — scan to the next delimiter
        while True:
            buf = self._buf
            i = self._pos
            n = len(buf)
            while i < n and buf[i] not in _WS + ",}]":
                i += 1
            self._pos = i
            if i < n or not self._more():
                return

    def _skip_container(self) -> None:
        """Skip a container whose opening bracket was already consumed."""
        depth = 1
        in_string = False
        skip_first = False
        while True:
            buf = self._buf
            pos = self._pos
            if skip_first:
                # A "\\" was the last char of the previous chunk; the escaped
                # char is the first char of this buffer and must not be
                # interpreted (e.g. '"' would wrongly toggle in_string).
                pos += 1
                skip_first = False
            while True:
                match = _SPECIAL.search(buf, pos)
                if match is None:
                    pos = len(buf)
                    break
                ch = buf[match.start()]
                pos = match.end()
                if in_string:
                    if ch == "\\":
                        pos += 1
                        if pos > len(buf):
                            skip_first = True
                            pos = len(buf)
                            break
                    elif ch == '"':
                        in_string = False
                elif ch == '"':
                    in_string = True
                elif ch in "{[":
                    depth += 1
                else:
                    depth -= 1
                    if depth == 0:
                        self._pos = pos
                        return
            self._pos = pos
            if not self._more():
                raise self._fail("truncated JSON container")

    # -- structural iteration --------------------------------------------
    def drain_to(self, level: int) -> None:
        """Discard open containers deeper than ``level`` (lazy abandonment).

        Each stacked marker denotes a container whose opener was already
        consumed, so scanning to the matching close consumes exactly that
        container's remainder — including any further member syntax.
        """
        while len(self._stack) > level:
            self._skip_container()
            self._stack.pop()

    def read_key(self) -> str | None:
        """Inside an object: return the next member key or ``None`` at ``}``."""
        ch = self.peek()
        if ch == "}":
            self.get()
            return None
        if ch != '"':
            raise self._fail(f"expected object key, got {ch!r}")
        key = self.value()
        self.expect(":")
        return key


class LazyValue:
    """Base handle for a container value inside a JSON stream."""

    __slots__ = ("_level", "_reader")

    def __init__(self, reader: _Reader, level: int) -> None:
        self._reader = reader
        self._level = level

    def materialize(self) -> Any:
        """Parse the entire node value. Bounded by the node's own size.

        Container openers are consumed eagerly, so materialization walks
        the node's own members rather than re-parsing the raw text.
        """
        if isinstance(self, LazyObject):
            return {key: node.materialize() for key, node in self.members()}
        return [item.materialize() for item in self.items(lazy=True)]

    def _pop_self(self) -> None:
        stack = self._reader._stack
        if stack and len(stack) >= self._level:
            del stack[self._level - 1 :]


class LazyObject(LazyValue):
    """A ``{...}`` value whose members are consumed lazily."""

    __slots__ = ()

    def members(self) -> Iterator[tuple[str, Any]]:
        """Yield ``(key, node)`` pairs in document order.

        ``node`` is a ``Scalar`` for leaf values and ``LazyObject``/
        ``LazyArray`` for containers. A lazy child must be consumed (or
        abandoned, which fast-skips it) before the next member is read.
        """
        reader = self._reader
        while True:
            reader.drain_to(self._level)
            ch = reader.peek()
            if ch == "}":
                reader.get()
                self._pop_self()
                return
            if ch == ",":
                reader.get()
            key = reader.read_key()
            if key is None:
                self._pop_self()
                return
            yield key, reader.node(lazy=True)


class LazyArray(LazyValue):
    """A ``[...]`` value whose items are consumed lazily."""

    __slots__ = ()

    def items(self, *, lazy: bool = False) -> Iterator[Any]:
        """Yield array items in order.

        With ``lazy=False`` each item is fully parsed (bounded by the item's
        own size). With ``lazy=True`` container items are yielded as
        ``LazyObject``/``LazyArray`` nodes.
        """
        reader = self._reader
        while True:
            reader.drain_to(self._level)
            ch = reader.peek()
            if ch == "]":
                reader.get()
                self._pop_self()
                return
            if ch == ",":
                reader.get()
            yield reader.node(lazy=lazy)


@contextmanager
def open_json(path: Path, *, chunk_size: int = 1 << 22) -> Iterator[LazyObject]:
    """Open ``path`` as a lazy JSON stream over the top-level object."""
    reader = _Reader(Path(path), chunk_size)
    try:
        if reader.peek() != "{":
            raise JsonStreamError("streamed JSON root must be an object")
        reader.get()
        reader._stack.append("{")
        yield LazyObject(reader, 1)
    finally:
        reader.close()


def iter_array_items(
    path: Path,
    member: str,
    *,
    lazy: bool = False,
    chunk_size: int = 1 << 22,
) -> Iterator[Any]:
    """Yield items of the top-level ``member`` array of a JSON object file."""
    with open_json(path, chunk_size=chunk_size) as root:
        for key, node in root.members():
            if key != member:
                continue
            if not isinstance(node, LazyArray):
                raise JsonStreamError(f"member {member!r} is not an array")
            yield from node.items(lazy=lazy)
            return


def read_member(path: Path, member: str, *, chunk_size: int = 1 << 22) -> Any:
    """Return the parsed value of one top-level object member."""
    with open_json(path, chunk_size=chunk_size) as root:
        for key, node in root.members():
            if key == member:
                return node.materialize()
    raise JsonStreamError(f"member {member!r} not found")
