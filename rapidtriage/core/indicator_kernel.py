"""Transport for the optional Rust indicator candidate scanner.

Two worker modes share one binary. A *batch* sends ASCII scalar fields and
receives candidate spans. A *JSONL scan* hands the worker an artifact record
stream: it decodes and walks the rows it can reproduce exactly, returns only
the scalar fields with candidates, and returns every other line verbatim for
Python to decode and scan. Python validates each reply before applying it and
falls back to its own matcher on any worker failure.
"""

from __future__ import annotations

import os
import queue
import shutil
import struct
import subprocess
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .json_stream import iter_jsonl_lines, parse_jsonl_line

_MAGIC = b"RIND2\n"
_JSONL_MAGIC = b"RINDJ1\n"
_U32 = struct.Struct("<I")
_HIT = struct.Struct("<IIII")
_MAX_SCALAR = 4096
_MAX_ROWS = 8192
_MAX_BATCH_BYTES = 1024 * 1024
_TIMEOUT = 30.0

# JSONL reply records (see engines/rust/crates/rapid-indicators/src/jsonl.rs).
_RECORD_HIT, _RECORD_LINE, _RECORD_CHECKPOINT, _RECORD_END, _RECORD_PYTHON_SCALAR = range(5)
_END_COMPLETE, _END_DELEGATED = 0, 1
_HIT_HEAD = struct.Struct("<QI")
_LINE_HEAD = struct.Struct("<QQII")
_CHECKPOINT = struct.Struct("<QQQQ")
_END = struct.Struct("<IQ")
_SPAN = struct.Struct("<III")
_CONTEXT_HEAD = struct.Struct("<II")

Span = tuple[int, int, int]
# (text, pointer, context, spans) of one scalar field the worker walked to:
# spans of a native match, or None when Python's regexes must match it.
JsonlHit = tuple[str, str, dict[str, str], list[Span] | None]
# (line_number, row_index or None, line) that Python decodes itself.
JsonlLine = tuple[int, int | None, str]

_WORKER_ERRORS = (OSError, subprocess.SubprocessError, ValueError)


def worker_path() -> Path | None:
    name = "rapid-indicators.exe" if os.name == "nt" else "rapid-indicators"
    local = Path(__file__).resolve().parents[2] / "engines" / "rust" / "target" / "release" / name
    if local.is_file():
        return local
    installed = shutil.which(name)
    return Path(installed) if installed else None


def failure_reason(error: BaseException) -> str:
    """Disclosed ``fallback_reason`` for a worker failure."""
    if isinstance(error, FileNotFoundError):
        return "worker-unavailable"
    if isinstance(error, OSError):
        return "worker-io-error"
    if isinstance(error, subprocess.TimeoutExpired):
        return "worker-timeout"
    if isinstance(error, subprocess.CalledProcessError):
        return "worker-exit-error"
    return "invalid-worker-response"


def scan_batch(texts: list[str]) -> dict[int, list[Span]]:
    """Return sparse (family, start, end) spans in Python string offsets."""
    worker = worker_path()
    if worker is None:
        raise FileNotFoundError("indicator worker unavailable")
    if any(len(text) > _MAX_SCALAR or not text.isascii() for text in texts):
        raise ValueError("unsupported indicator scalar")
    request = b"".join((
        _MAGIC,
        struct.pack(f"<I{len(texts)}I", len(texts), *map(len, texts)),
        "".join(texts).encode("ascii"),
    ))
    reply = subprocess.run(
        [str(worker)], input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=True, timeout=_TIMEOUT,
    ).stdout
    # The trailer proves the worker finished the entire batch, even when
    # there were no hits. Validate everything before exposing any spans.
    trailer = _HIT.pack(len(texts), 3, 0, 0)
    if len(reply) < len(_MAGIC) + len(trailer) or not reply.startswith(_MAGIC) or not reply.endswith(trailer):
        raise ValueError("invalid indicator response envelope")
    records = memoryview(reply)[len(_MAGIC):-_HIT.size]
    if len(records) % _HIT.size:
        raise ValueError("truncated indicator response")
    hits: dict[int, list[Span]] = {}
    previous_row, previous_family, previous_end = -1, -1, 0
    for row, family, start, end in _HIT.iter_unpack(records):
        if row >= len(texts) or family > 2 or not start < end <= len(texts[row]):
            raise ValueError("invalid indicator span")
        if (row, family) < (previous_row, previous_family):
            raise ValueError("unordered indicator spans")
        if (row, family) == (previous_row, previous_family) and start < previous_end:
            raise ValueError("overlapping indicator spans within a family")
        hits.setdefault(row, []).append((family, start, end))
        previous_row, previous_family, previous_end = row, family, end
    return hits


@dataclass(frozen=True)
class FieldPolicy:
    """Traversal policy the JSONL worker applies, owned by ``indicators.py``."""

    max_scalar: int
    excluded_types: Iterable[str]
    subtree_keys: Iterable[str]
    subtree_suffixes: Iterable[str]
    subtree_prefixes: Iterable[str]
    leaf_keys: Iterable[str]
    evidence_hash_keys: Iterable[str]
    leaf_suffixes: Iterable[str]
    context_keys: tuple[str, ...]

    def encode(self) -> bytes:
        parts = [_JSONL_MAGIC, _U32.pack(self.max_scalar)]
        for table in (
            self.excluded_types, self.subtree_keys, self.subtree_suffixes, self.subtree_prefixes,
            self.leaf_keys, self.evidence_hash_keys, self.leaf_suffixes, self.context_keys,
        ):
            items = [item.encode("ascii") for item in table]
            parts.append(_U32.pack(len(items)))
            for item in items:
                parts.extend((_U32.pack(len(item)), item))
        return b"".join(parts)


@dataclass(frozen=True)
class _Checkpoint:
    offset: int
    line_number: int
    index: int
    scalars: int = 0


class _Reader:
    """Read worker frames on a thread so a stalled worker cannot block the run."""

    _EOF = object()

    def __init__(self, process: subprocess.Popen[bytes]):
        self._process = process
        self._frames: queue.Queue[object] = queue.Queue(maxsize=8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._read, name="rapid-indicators-reader", daemon=True)
        self._thread.start()

    def _put(self, item: object) -> None:
        while not self._stop.is_set():
            try:
                self._frames.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def _read(self) -> None:
        stream = self._process.stdout
        assert stream is not None
        try:
            if stream.read(len(_JSONL_MAGIC)) != _JSONL_MAGIC:
                raise ValueError("invalid indicator scan header")
            while not self._stop.is_set():
                head = stream.read(_U32.size)
                if not head:
                    self._put(self._EOF)
                    return
                if len(head) != _U32.size:
                    raise ValueError("truncated indicator frame length")
                (size,) = _U32.unpack(head)
                body = stream.read(size)
                if len(body) != size:
                    raise ValueError("truncated indicator frame")
                self._put(body)
        except Exception as error:
            self._put(error)

    def frame(self) -> bytes | None:
        """Next frame, or ``None`` once the worker exited cleanly."""
        try:
            item = self._frames.get(timeout=_TIMEOUT)
        except queue.Empty:
            raise subprocess.TimeoutExpired(self._process.args, _TIMEOUT) from None
        if isinstance(item, Exception):
            raise item
        if item is self._EOF:
            code = self._process.wait(timeout=_TIMEOUT)
            if code:
                raise subprocess.CalledProcessError(code, self._process.args)
            return None
        assert isinstance(item, bytes)
        return item

    def close(self) -> None:
        self._stop.set()
        if self._process.poll() is None:
            self._process.kill()
        self._process.wait()
        self._thread.join(timeout=_TIMEOUT)
        if self._process.stdout is not None:
            self._process.stdout.close()


def _utf8(data: memoryview) -> str:
    return bytes(data).decode("utf-8")


def _decode_frame(
    frame: bytes, previous: _Checkpoint, policy: FieldPolicy, file_size: int,
) -> tuple[list[JsonlHit | JsonlLine], _Checkpoint]:
    """Validate a whole frame before any of it is applied."""
    view = memoryview(frame)
    events: list[JsonlHit | JsonlLine] = []
    pos = 0
    floor = previous.index  # lowest row index the next record may carry
    hit_row = -1  # row of the latest native hit; a Python row never repeats it
    last_line = previous.line_number

    def take(length: int) -> memoryview:
        nonlocal pos
        if length > len(view) - pos:
            raise ValueError("truncated indicator record")
        pos += length
        return view[pos - length:pos]

    def unpack(layout: struct.Struct) -> tuple[int, ...]:
        return layout.unpack(take(layout.size))

    while True:
        (tag,) = take(1)
        if tag in (_RECORD_HIT, _RECORD_PYTHON_SCALAR):
            index, pointer_length = unpack(_HIT_HEAD)
            pointer = _utf8(take(pointer_length))
            (text_length,) = unpack(_U32)
            text = _utf8(take(text_length))
            # Native hits are ASCII (byte offsets are character offsets);
            # Python matches every other scalar itself.
            if not 0 < len(text) <= policy.max_scalar or text.isascii() != (tag == _RECORD_HIT):
                raise ValueError("invalid indicator scalar")
            if index < floor or not pointer.startswith(f"/artifacts/{index}/"):
                raise ValueError("invalid indicator row")
            floor = hit_row = index
            context: dict[str, str] = {}
            previous_slot = -1
            (count,) = unpack(_U32)
            for _ in range(count):
                slot, length = unpack(_CONTEXT_HEAD)
                if not previous_slot < slot < len(policy.context_keys):
                    raise ValueError("invalid indicator context")
                context[policy.context_keys[slot]] = _utf8(take(length))
                previous_slot = slot
            if tag == _RECORD_PYTHON_SCALAR:
                events.append((text, pointer, context, None))
                continue
            spans: list[Span] = []
            previous_family, previous_end = -1, 0
            (count,) = unpack(_U32)
            if not count:
                raise ValueError("indicator hit without spans")
            for _ in range(count):
                family, start, end = unpack(_SPAN)
                if family > 2 or family < previous_family or not start < end <= len(text):
                    raise ValueError("invalid indicator span")
                if family == previous_family and start < previous_end:
                    raise ValueError("overlapping indicator spans within a family")
                spans.append((family, start, end))
                previous_family, previous_end = family, end
            events.append((text, pointer, context, spans))
        elif tag == _RECORD_LINE:
            line_number, index_plus_one, terminated, length = unpack(_LINE_HEAD)
            if line_number <= last_line or terminated > 1:
                raise ValueError("invalid indicator line")
            last_line = line_number
            index = index_plus_one - 1 if index_plus_one else None
            if index is not None:
                if index < floor or index == hit_row:
                    raise ValueError("invalid indicator row")
                floor = index + 1
            line = bytes(take(length)).decode("utf-8") + ("\n" if terminated else "")
            events.append((line_number, index, line))
        elif tag == _RECORD_CHECKPOINT:
            checkpoint = _Checkpoint(*unpack(_CHECKPOINT))
            if pos != len(view):
                raise ValueError("indicator records after checkpoint")
            if not (previous.offset <= checkpoint.offset <= file_size and last_line <= checkpoint.line_number
                    and floor <= checkpoint.index and hit_row < checkpoint.index):
                raise ValueError("invalid indicator checkpoint")
            if checkpoint.offset == previous.offset and checkpoint.line_number != previous.line_number:
                raise ValueError("invalid indicator checkpoint")
            return events, checkpoint
        else:
            raise ValueError("invalid indicator record")


def _decode_end(frame: bytes) -> tuple[int, int] | None:
    if len(frame) != 1 + _END.size or frame[0] != _RECORD_END:
        return None
    status, total = _END.unpack_from(frame, 1)
    return status, total


class IndicatorBatch:
    """Apply rows with native hits and Python fallback rows in traversal order."""

    def __init__(self, on_row: Callable[[str, Mapping[str, str], list[Span] | None], None]):
        self._on_row = on_row
        self._rows: list[tuple[str, Mapping[str, str]]] = []
        self._size = 0
        self._native_rows = 0
        self._python_rows = 0
        self._fallback_reason: str | None = None

    @property
    def metadata(self) -> dict[str, object]:
        return {
            "native_rows": self._native_rows,
            "python_rows": self._python_rows,
            "fallback_reason": self._fallback_reason,
        }

    def add(self, text: str, source: Mapping[str, str]) -> None:
        if self._fallback_reason is not None:
            self._on_row(text, source, None)
            self._python_rows += 1
            return
        self._rows.append((text, source))
        self._size += len(text) + _U32.size
        if len(self._rows) >= _MAX_ROWS or self._size >= _MAX_BATCH_BYTES:
            self.flush()

    def flush(self) -> None:
        if not self._rows:
            return
        rows, self._rows = self._rows, []
        self._size = 0
        # Count and match the same subset; never encode a surrogate or turn
        # Unicode character offsets into UTF-8 byte offsets.
        indexes = [i for i, (text, _) in enumerate(rows) if text.isascii() and len(text) <= _MAX_SCALAR]
        hits: dict[int, list[Span]] = {}
        if indexes:
            try:
                hits = scan_batch([rows[i][0] for i in indexes])
            except _WORKER_ERRORS as error:
                self._fallback_reason = failure_reason(error)
        # A failed response has no committed prefix. Replay the entire batch
        # with Python, then route future rows directly there for this run.
        native_cursor = 0
        for i, (text, source) in enumerate(rows):
            if self._fallback_reason is None and native_cursor < len(indexes) and indexes[native_cursor] == i:
                spans = hits.get(native_cursor)
                if spans:
                    self._on_row(text, source, spans)
                native_cursor += 1
                self._native_rows += 1
            else:
                self._on_row(text, source, None)
                self._python_rows += 1

    def scan_jsonl(
        self,
        path: Path,
        policy: FieldPolicy,
        on_hit: Callable[[str, str, dict[str, str], list[Span] | None], None],
        on_row: Callable[[int, dict[str, object]], int],
    ) -> None:
        """Scan a JSONL record stream, as ``iter_jsonl_items`` would read it.

        ``on_hit`` applies one natively matched scalar field; ``on_row``
        scans one decoded row with Python and returns its scalar count.
        Frames are applied whole, in file order. After a worker failure the
        remaining lines, from the last applied checkpoint, go to Python.
        """
        self.flush()  # earlier fields of this output come first
        resume: _Checkpoint | None = _Checkpoint(0, 0, 0)
        if self._fallback_reason is None:
            resume = self._scan_jsonl_native(path, policy, on_hit, on_row)
        if resume is None:
            return
        index = resume.index
        for line_number, line in iter_jsonl_lines(path, start=resume.offset, first_line_number=resume.line_number + 1):
            if not line.strip():
                continue
            row = parse_jsonl_line(line, line_number, path)
            if isinstance(row, dict):
                self._python_rows += on_row(index, row)
                index += 1

    def _scan_jsonl_native(
        self,
        path: Path,
        policy: FieldPolicy,
        on_hit: Callable[[str, str, dict[str, str], list[Span] | None], None],
        on_row: Callable[[int, dict[str, object]], int],
    ) -> _Checkpoint | None:
        """Return ``None`` when complete, else the checkpoint Python resumes from."""
        applied = _Checkpoint(0, 0, 0)
        reader: _Reader | None = None
        try:
            while True:
                # Only worker transport and validation failures fall back.
                # Python's own decode errors below propagate unchanged.
                try:
                    if reader is None:
                        reader = _start_jsonl_worker(path, policy)
                    frame = _next_jsonl_frame(reader, applied, policy, path.stat().st_size)
                except _WORKER_ERRORS as error:
                    self._fallback_reason = failure_reason(error)
                    return applied
                if frame is None:
                    return None
                if frame is _DELEGATED:
                    return applied  # not UTF-8: Python reads (and rejects) it
                events, checkpoint = frame
                rows = _decode_python_lines(events, path)
                if rows is None:
                    self._fallback_reason = "invalid-worker-response"
                    return applied
                for item in rows:
                    if len(item) == 4:
                        on_hit(*item)
                        self._python_rows += item[3] is None
                    else:
                        self._python_rows += on_row(*item)
                self._native_rows += checkpoint.scalars
                applied = checkpoint
        finally:
            if reader is not None:
                reader.close()


_DELEGATED = object()


def _start_jsonl_worker(path: Path, policy: FieldPolicy) -> _Reader:
    worker = worker_path()
    if worker is None:
        raise FileNotFoundError("indicator worker unavailable")
    process = subprocess.Popen(
        [str(worker), "jsonl", os.fspath(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    reader = _Reader(process)
    assert process.stdin is not None
    try:
        with process.stdin:
            process.stdin.write(policy.encode())
    except OSError:
        reader.close()
        raise
    return reader


def _next_jsonl_frame(
    reader: _Reader, applied: _Checkpoint, policy: FieldPolicy, file_size: int,
) -> tuple[list[JsonlHit | JsonlLine], _Checkpoint] | object | None:
    """Decoded frame, ``_DELEGATED``, or ``None`` after a complete trailer."""
    frame = reader.frame()
    if frame is None:
        raise ValueError("indicator scan ended without a trailer")
    end = _decode_end(frame)
    if end is None:
        return _decode_frame(frame, applied, policy, file_size)
    status, total = end
    if status == _END_DELEGATED and applied == _Checkpoint(0, 0, 0) and total == 0:
        return _DELEGATED
    if status != _END_COMPLETE or total != applied.offset or total != file_size:
        raise ValueError("invalid indicator scan trailer")
    if reader.frame() is not None:
        raise ValueError("indicator records after trailer")
    return None


def _decode_python_lines(
    events: list[JsonlHit | JsonlLine], path: Path,
) -> list[JsonlHit | tuple[int, dict[str, object]]] | None:
    """Decode a frame's returned lines exactly as ``iter_jsonl_items`` would.

    ``None`` when the worker's row numbering disagrees with Python.
    """
    rows: list[JsonlHit | tuple[int, dict[str, object]]] = []
    for event in events:
        if len(event) == 4:
            rows.append(event)
            continue
        line_number, index, line = event
        if not line.strip():
            if index is not None:
                return None
            continue
        row = parse_jsonl_line(line, line_number, path)
        if isinstance(row, dict) != (index is not None):
            return None
        if index is not None:
            rows.append((index, row))
    return rows
