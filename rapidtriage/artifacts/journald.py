"""Bounded, read-only reader for the published systemd Journal File Format."""
from __future__ import annotations

import base64
import datetime as dt
import lzma
import os
import re
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from ..core.models import ArtifactRecord
from ._walk import iter_evidence_paths

FORMAT_REFERENCE = "https://systemd.io/JOURNAL_FILE_FORMAT/"
MAX_FILES = 64
MAX_ENTRIES = 5000
MAX_BYTES = 64 * 1024 * 1024  # I/O plus inflated payloads, shared across the collection
MAX_PAYLOAD = 1024 * 1024  # compressed or decoded bytes per field
MAX_FIELDS = 256
MAX_DATA_REFS = 65536  # bounds aggregate per-field output, including damaged/empty references
MAX_ARRAYS = 4096
XZ_MEMORY = 64 * 1024 * 1024
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
FIELD_NAME = re.compile(rb"[A-Z_0-9]{1,64}")
STATE = ("offline", "online", "archived")
HEADER_SIZE = 208  # through tail_entry_monotonic, present in every format revision
OBJECT_HEADER = struct.Struct("<BB6xQ")


class JournalError(ValueError):
    def __init__(self, reason: str, offset: int, **details: object):
        super().__init__(reason)
        self.details = {"reason": reason, "source_offset": offset, **details}


class _Budget:
    def __init__(self):
        self.bytes_left = MAX_BYTES
        self.entries_left = MAX_ENTRIES
        self.fields_left = MAX_DATA_REFS

    def charge(self, size: int, offset: int) -> None:
        if size > self.bytes_left:
            raise JournalError("byte-limit", offset)
        self.bytes_left -= size


def _row(path: Path, kind: str, offset: int, **details: object) -> ArtifactRecord:
    return ArtifactRecord(
        provider=JournaldProvider.name, artifact_type="linux-journald-" + kind,
        path=str(path), supported=kind == "entry",
        details={
            "parser": "linux-journald", "parser_version": "journald-v1",
            "source_path": str(path), "source_offset": offset, "source_offset_unit": "byte",
            "reportability": "triage", "coverage_status": "partial", **details,
        },
    )


def _diagnostic(path: Path, issue: JournalError) -> ArtifactRecord:
    details = issue.details.copy()
    return _row(path, "diagnostic", details.pop("source_offset"), **details)


class _Reader:
    def __init__(self, stream: BinaryIO, budget: _Budget):
        self.stream = stream
        self.budget = budget
        self.end = os.fstat(stream.fileno()).st_size
        header = self.read(0, HEADER_SIZE)
        if header[:8] != b"LPKSHHRH":
            raise JournalError("invalid-signature", 0)
        self.flags = struct.unpack_from("<I", header, 12)[0]
        if self.flags & ~31:
            raise JournalError("unsupported-incompatible-flags", 12, incompatible_flags=self.flags)
        if header[16] >= len(STATE):
            raise JournalError("invalid-state", 16)
        self.state = STATE[header[16]]
        self.compact = bool(self.flags & 16)
        self.start, arena_size = struct.unpack_from("<QQ", header, 88)
        if self.start < HEADER_SIZE or self.start % 8 or self.start > self.end:
            raise JournalError("invalid-header-size", 88)
        self.truncated = self.end < self.start + arena_size
        self.end = min(self.end, self.start + arena_size)
        self.n_entries = struct.unpack_from("<Q", header, 152)[0]
        self.array_offset = struct.unpack_from("<Q", header, 176)[0]

    def read(self, offset: int, size: int) -> bytes:
        if offset + size > self.end:
            raise JournalError("truncated-read", offset)
        self.budget.charge(size, offset)
        self.stream.seek(offset)
        data = self.stream.read(size)
        if len(data) != size:
            raise JournalError("truncated-read", offset)
        return data

    def object(self, offset: int, expected: int, minimum: int) -> tuple[int, int, bool]:
        if offset < self.start or offset % 8 or offset > self.end - OBJECT_HEADER.size:
            raise JournalError("invalid-object-offset", offset)
        kind, flags, size = OBJECT_HEADER.unpack(self.read(offset, OBJECT_HEADER.size))
        if kind != expected:
            raise JournalError("unexpected-object-type", offset, object_type=kind)
        if size < minimum or (expected != 1 and flags):
            raise JournalError("invalid-object-header", offset)
        clipped = size > self.end - offset
        if clipped and expected != 6:
            raise JournalError("truncated-object", offset)
        return flags, min(size, self.end - offset), clipped

    def field(self, offset: int, expected_hash: int | None) -> tuple[str, object]:
        prefix = 72 if self.compact else 64
        flags, size, _ = self.object(offset, 1, prefix + 1)
        file_flag = {0: 0, 1: 1, 2: 2, 4: 8}.get(flags)
        if file_flag is None or self.flags & file_flag != file_flag:
            raise JournalError("invalid-compression-flags", offset)
        if flags in (2, 4):
            raise JournalError("compressed-unsupported", offset, codec="LZ4" if flags == 2 else "ZSTD",
                               format_reference=FORMAT_REFERENCE)
        if expected_hash is not None:
            data_hash, = struct.unpack("<Q", self.read(offset + 16, 8))
            if data_hash != expected_hash:
                raise JournalError("item-hash-mismatch", offset)
        if size - prefix > MAX_PAYLOAD:
            raise JournalError("field-size-limit", offset)
        payload = self.read(offset + prefix, size - prefix)
        if flags == 1:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY)
            try:
                payload = decoder.decompress(payload, max_length=min(self.budget.bytes_left, MAX_PAYLOAD) + 1)
            except lzma.LZMAError as error:
                raise JournalError("invalid-or-over-limit-xz", offset) from error
            self.budget.charge(len(payload), offset)
            if len(payload) > MAX_PAYLOAD:
                raise JournalError("field-size-limit", offset)
            if not decoder.eof or decoder.unused_data:
                raise JournalError("invalid-xz", offset)
        name, separator, value = payload.partition(b"=")
        if not separator or not FIELD_NAME.fullmatch(name):
            raise JournalError("invalid-field-name", offset)
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return name.decode("ascii"), {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
        return name.decode("ascii"), decoded

    def entry(self, path: Path, offset: int, array: int) -> ArtifactRecord:
        _, size, _ = self.object(offset, 3, 64)
        seq, realtime, monotonic, boot = struct.unpack("<QQQ16s8x", self.read(offset + 16, 48))
        item = struct.Struct("<I" if self.compact else "<QQ")
        count, remainder = divmod(size - 64, item.size)
        issues = []
        if not count or remainder:
            issues.append({"reason": "invalid-item-list", "source_offset": offset + 64})
        if count > MAX_FIELDS:
            issues.append({"reason": "field-count-limit", "source_offset": offset + 64 + MAX_FIELDS * item.size})
        count = min(count, MAX_FIELDS)
        if count > self.budget.fields_left:
            raise JournalError("data-reference-limit", offset + 64)
        self.budget.fields_left -= count
        raw_items = self.read(offset + 64, count * item.size)
        fields: dict[str, object] = {}
        data_offsets = []
        for index, reference in enumerate(item.iter_unpack(raw_items)):
            reference_offset = offset + 64 + index * item.size
            address = reference[0]
            data_offsets.append(address)
            try:
                key, value = self.field(address, None if self.compact else reference[1])
            except JournalError as error:
                if error.details["reason"] == "byte-limit":
                    raise
                issues.append({**error.details, "reference_offset": reference_offset})
                continue
            if key == "_BOOT_ID" and (not isinstance(value, str) or value.lower() != boot.hex()):
                issues.append({"reason": "boot-id-mismatch", "source_offset": address,
                               "reference_offset": reference_offset, "entry_boot_id_offset": offset + 40})
            if key in fields:
                prior = fields[key]
                if isinstance(prior, list):
                    prior.append(value)
                else:
                    fields[key] = [prior, value]
            else:
                fields[key] = value
        for key, value in (("__REALTIME_TIMESTAMP", realtime), ("__MONOTONIC_TIMESTAMP", monotonic)):
            if key in fields:
                issues.append({"reason": "reserved-timestamp-field", "source_offset": offset})
            fields[key] = value
        fields.setdefault("_BOOT_ID", boot.hex())
        try:
            timestamp = (EPOCH + dt.timedelta(microseconds=realtime)).isoformat()
        except OverflowError:
            timestamp = None
            issues.append({"reason": "timestamp-out-of-range", "source_offset": offset + 24})
        return _row(
            path, "entry", offset, length=size, entry_array_offset=array, data_offsets=data_offsets,
            sequence_number=seq, timestamp=timestamp, boot_id=boot.hex(), fields=fields,
            journal_state=self.state, compact=self.compact, keyed_hash=bool(self.flags & 4),
            limitations=issues, coverage_status="partial" if issues else "parsed",
        )

    def rows(self, path: Path) -> Iterator[ArtifactRecord]:
        if self.truncated:
            yield _diagnostic(path, JournalError("truncated-arena", self.end))
        if self.state == "online":
            yield _diagnostic(path, JournalError("online-state", 16))
        remaining = self.n_entries
        array = self.array_offset
        seen = set()
        last_entry = 0
        slot = struct.Struct("<I" if self.compact else "<Q")
        while array and remaining:
            if array in seen:
                raise JournalError("entry-array-cycle", array)
            if len(seen) == MAX_ARRAYS:
                raise JournalError("array-limit", array)
            seen.add(array)
            _, size, clipped = self.object(array, 6, 24)
            if size < 24:
                raise JournalError("truncated-array", array)
            next_array, = struct.unpack("<Q", self.read(array + 16, 8))
            capacity, remainder = divmod(size - 24, slot.size)
            if remainder or clipped:
                yield _diagnostic(path, JournalError("truncated-array", array))
            count = min(capacity, remaining, self.budget.entries_left)
            contents = self.read(array + 24, count * slot.size)
            for index, (offset,) in enumerate(slot.iter_unpack(contents)):
                self.budget.entries_left -= 1
                if offset <= last_entry:
                    yield _diagnostic(path, JournalError("invalid-entry-order", array + 24 + index * slot.size,
                                                         target_offset=offset))
                    continue
                try:
                    yield self.entry(path, offset, array)
                    last_entry = offset
                except JournalError as error:
                    if error.details["reason"] in ("byte-limit", "data-reference-limit"):
                        raise
                    error.details["reference_offset"] = array + 24 + index * slot.size
                    yield _diagnostic(path, error)
            remaining -= count
            if remaining and not self.budget.entries_left:
                raise JournalError("entry-limit", array + 24 + count * slot.size)
            array = next_array
        if remaining:
            raise JournalError("incomplete-entry-index", array or 176, missing_entries=remaining)


class JournaldProvider:
    name = "linux-journald"
    collector_kind = "linux-journald"
    target_platform = "linux"
    description = "Linux systemd journal entries"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterator[ArtifactRecord]:
        directory = root.resolve()
        for component in ("var", "log", "journal"):
            directory = directory / component
            if directory.is_symlink() or not directory.is_dir():
                return
        budget = _Budget()
        files = 0
        for path in iter_evidence_paths(directory):
            if not path.name.endswith((".journal", ".journal~")) or path.is_symlink() or not path.is_file():
                continue
            if not path.resolve().is_relative_to(directory):
                continue
            if files >= MAX_FILES:
                yield _diagnostic(path, JournalError("file-limit", 0))
                return
            files += 1
            try:
                with path.open("rb") as stream:
                    yield from _Reader(stream, budget).rows(path)
            except JournalError as error:
                yield _diagnostic(path, error)
                if error.details["reason"] in ("entry-limit", "byte-limit", "data-reference-limit"):
                    return
            except OSError as error:
                yield _diagnostic(path, JournalError("read-error", 0, errno=error.errno))
