"""Batched transport for the optional Rust indicator candidate scanner."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

_MAGIC = b"RIND1\n"
_ROW_LENGTH = struct.Struct("<I")
_HIT = struct.Struct("<IIII")
_MAX_SCALAR = 4096
_MAX_ROWS = 8192
_MAX_BATCH_BYTES = 1024 * 1024

Span = tuple[int, int, int]


def worker_path() -> Path | None:
    name = "rapid-indicators.exe" if os.name == "nt" else "rapid-indicators"
    local = Path(__file__).resolve().parents[2] / "engines" / "rust" / "target" / "release" / name
    if local.is_file():
        return local
    installed = shutil.which(name)
    return Path(installed) if installed else None


def scan_batch(texts: list[str]) -> dict[int, list[Span]]:
    """Return sparse (family, start, end) spans in Python string offsets."""
    worker = worker_path()
    if worker is None:
        raise FileNotFoundError("indicator worker unavailable")
    request = bytearray(_MAGIC)
    for text in texts:
        if len(text) > _MAX_SCALAR or not text.isascii():
            raise ValueError("unsupported indicator scalar")
        request.extend(_ROW_LENGTH.pack(len(text)))
        request.extend(text.encode("ascii"))
    reply = subprocess.run(
        [str(worker)], input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=True, timeout=30,
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
        self._size += len(text) + _ROW_LENGTH.size
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
            except FileNotFoundError:
                self._fallback_reason = "worker-unavailable"
            except OSError:
                self._fallback_reason = "worker-io-error"
            except subprocess.TimeoutExpired:
                self._fallback_reason = "worker-timeout"
            except subprocess.CalledProcessError:
                self._fallback_reason = "worker-exit-error"
            except ValueError:
                self._fallback_reason = "invalid-worker-response"
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
