"""Bounded pure-Python LevelDB reader (write-ahead ``.log`` + ``.ldb``/``.sst`` tables) and Snappy.

Chromium/Electron apps (Teams, Slack, Discord, WhatsApp Desktop, Skype for
Desktop) keep IndexedDB and Local Storage in LevelDB. This module reads the
on-disk structures without the C library so the stdlib-only runtime can
recover record *values*; interpreting those values (V8-serialized objects,
JSON text) is the caller's job (``messenger.py`` carves message candidates).

Formats (LevelDB ``doc/log_format.md`` and ``doc/table_format.md``):

* ``.log``: 32 KiB blocks of physical records ``crc32c(4) length(2) type(1)
  data``; types FULL=1, FIRST=2, MIDDLE=3, LAST=4 assemble a WriteBatch
  ``sequence(8) count(4)`` followed by ``tag(1)`` entries (1 = put with
  varint-prefixed key and value, 0 = deletion with key only).
* table: 48-byte footer (metaindex handle, index handle, magic
  ``0xdb4775248b80fb57``); the index block's values are data-block handles;
  every block carries a 5-byte trailer (compression type 0 = none, 1 =
  Snappy; masked CRC32C). Block entries are prefix-compressed
  ``shared, non_shared, value_length`` varints followed by a restart array;
  keys are internal keys ``user_key + (sequence << 8 | type)``.

Every reader is bounded (bytes, blocks, records, decompressed size) and
raises :class:`LevelDBError` on structural damage instead of looping or
allocating without limit; callers isolate those errors per file.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

LOG_BLOCK_SIZE = 32 * 1024
LOG_HEADER_SIZE = 7
TABLE_MAGIC = 0xDB4775248B80FB57
TABLE_FOOTER_SIZE = 48
BLOCK_TRAILER_SIZE = 5
MAX_BLOCK_OUTPUT = 32 * 1024 * 1024
MAX_TABLE_BLOCKS = 200_000
MAX_RECORDS_PER_FILE = 500_000
# Prefix compression lets a few bytes of block re-emit a long shared key per entry: keys are capped,
# entries per block are capped and every block has a budget of decoded (key + value) bytes.
MAX_KEY_BYTES = 64 * 1024
MAX_BLOCK_ENTRIES = 262_144
BLOCK_DECODE_FACTOR = 8
BLOCK_DECODE_FLOOR = 1024 * 1024
# Decompressed (Snappy) bytes one table may produce; callers pass a smaller per-app remainder.
MAX_TABLE_DECOMPRESSED = 256 * 1024 * 1024
# CRC32C in pure Python costs ~0.5 µs/byte: checksums are verified for the
# first bytes of a file only (informational in a carving context).
CRC_VERIFY_BUDGET = 1024 * 1024

LOG_FULL, LOG_FIRST, LOG_MIDDLE, LOG_LAST = 1, 2, 3, 4
VALUE_TYPE_DELETION, VALUE_TYPE_VALUE = 0, 1


class LevelDBError(ValueError):
    """Structural damage in a LevelDB file (isolated per file by callers)."""


class SnappyError(LevelDBError):
    """Malformed or over-limit Snappy stream."""


@dataclass
class LevelDBRecord:
    """One key/value (or deletion) recovered from a log batch or a table block."""

    origin: str  # "log" | "table"
    user_key: bytes
    value: bytes | None
    sequence: int | None
    deleted: bool
    # log: file offset of the first physical fragment; table: data-block offset.
    file_offset: int
    entry_offset: int | None = None  # table: entry offset inside the decompressed block
    checksum_ok: bool | None = None


@dataclass
class ReadStats:
    records: int = 0
    deletions: int = 0
    corrupt_fragments: int = 0
    checksum_mismatches: int = 0
    checksum_unverified: int = 0
    dropped_partial_batches: int = 0
    corrupt_blocks: int = 0
    snappy_blocks: int = 0
    decompressed_bytes: int = 0
    budget_exhausted: bool = False
    truncated: bool = False
    errors: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        if len(self.errors) < 20:
            self.errors.append(message)

    def as_dict(self) -> dict[str, object]:
        return {
            "records": self.records,
            "deletions": self.deletions,
            "corrupt_fragments": self.corrupt_fragments,
            "checksum_mismatches": self.checksum_mismatches,
            "checksum_unverified": self.checksum_unverified,
            "dropped_partial_batches": self.dropped_partial_batches,
            "corrupt_blocks": self.corrupt_blocks,
            "snappy_blocks": self.snappy_blocks,
            "decompressed_bytes": self.decompressed_bytes,
            "budget_exhausted": self.budget_exhausted,
            "truncated": self.truncated,
            "errors": list(self.errors),
        }


# --- varints / CRC32C ------------------------------------------------------------


def read_varint(buffer: bytes, position: int, limit: int | None = None) -> tuple[int, int]:
    """``(value, next position)`` of a little-endian base-128 varint (max 10 bytes)."""
    end = len(buffer) if limit is None else min(limit, len(buffer))
    result = 0
    shift = 0
    while position < end and shift <= 63:
        byte = buffer[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
    raise LevelDBError("truncated or overlong varint")


def _crc32c_table() -> tuple[int, ...]:
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return tuple(table)


_CRC32C_TABLE = _crc32c_table()


def crc32c(data: bytes, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    table = _CRC32C_TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def mask_crc(crc: int) -> int:
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


# --- Snappy ---------------------------------------------------------------------


def snappy_uncompressed_length(data: bytes) -> int:
    length, _ = read_varint(data, 0)
    return length


def snappy_decompress(data: bytes, *, max_output: int = MAX_BLOCK_OUTPUT) -> bytes:
    """Decompress a raw (unframed) Snappy block; ``SnappyError`` on damage or over ``max_output``."""
    try:
        expected, position = read_varint(data, 0)
    except LevelDBError as exc:
        raise SnappyError("snappy: bad length preamble") from exc
    if expected > max_output:
        raise SnappyError(f"snappy: declared length {expected} exceeds cap {max_output}")
    out = bytearray()
    size = len(data)
    while position < size:
        tag = data[position]
        position += 1
        kind = tag & 0x03
        if kind == 0:  # literal
            length = tag >> 2
            if length >= 60:
                extra = length - 59
                if position + extra > size:
                    raise SnappyError("snappy: truncated literal length")
                length = int.from_bytes(data[position : position + extra], "little")
                position += extra
            length += 1
            if position + length > size:
                raise SnappyError("snappy: literal runs past input")
            out += data[position : position + length]
            position += length
        else:
            if kind == 1:
                if position >= size:
                    raise SnappyError("snappy: truncated copy-1")
                length = ((tag >> 2) & 0x07) + 4
                offset = ((tag >> 5) << 8) | data[position]
                position += 1
            elif kind == 2:
                if position + 2 > size:
                    raise SnappyError("snappy: truncated copy-2")
                length = (tag >> 2) + 1
                offset = int.from_bytes(data[position : position + 2], "little")
                position += 2
            else:
                if position + 4 > size:
                    raise SnappyError("snappy: truncated copy-4")
                length = (tag >> 2) + 1
                offset = int.from_bytes(data[position : position + 4], "little")
                position += 4
            if offset == 0 or offset > len(out):
                raise SnappyError("snappy: copy offset outside output")
            start = len(out) - offset
            if offset >= length:
                out += out[start : start + length]
            else:  # overlapping run: repeat the period
                pattern = bytes(out[start:])
                repeat = (length // offset) + 1
                out += (pattern * repeat)[:length]
        if len(out) > expected:
            raise SnappyError("snappy: output exceeds declared length")
    if len(out) != expected:
        raise SnappyError(f"snappy: output length {len(out)} != declared {expected}")
    return bytes(out)


# --- write-ahead log ------------------------------------------------------------------


def iter_log_records(data: bytes, stats: ReadStats | None = None, *, max_records: int = MAX_RECORDS_PER_FILE) -> Iterator[LevelDBRecord]:
    """Records of a ``.log`` file. Damaged fragments are skipped (counted), not fatal."""
    stats = stats if stats is not None else ReadStats()
    pending = bytearray()
    pending_offset = -1
    pending_ok: bool | None = True
    verified_bytes = 0
    size = len(data)
    block_start = 0
    while block_start < size:
        block_end = min(block_start + LOG_BLOCK_SIZE, size)
        position = block_start
        while position + LOG_HEADER_SIZE <= block_end:
            header = data[position : position + LOG_HEADER_SIZE]
            stored_crc = int.from_bytes(header[0:4], "little")
            length = int.from_bytes(header[4:6], "little")
            record_type = header[6]
            if record_type == 0 and length == 0 and stored_crc == 0:
                break  # zero trailer / preallocated space: rest of block is padding
            fragment_start = position + LOG_HEADER_SIZE
            if record_type not in (LOG_FULL, LOG_FIRST, LOG_MIDDLE, LOG_LAST) or fragment_start + length > block_end:
                stats.corrupt_fragments += 1
                stats.note(f"log fragment at {position}: bad type {record_type} or length {length}")
                pending.clear()
                pending_offset = -1
                break
            fragment = data[fragment_start : fragment_start + length]
            checksum_ok: bool | None
            if verified_bytes + length <= CRC_VERIFY_BUDGET:
                verified_bytes += length + 1
                checksum_ok = mask_crc(crc32c(fragment, crc32c(bytes([record_type])))) == stored_crc
                if not checksum_ok:
                    stats.checksum_mismatches += 1
            else:
                checksum_ok = None
                stats.checksum_unverified += 1
            if record_type == LOG_FULL:
                if pending_offset >= 0:
                    stats.dropped_partial_batches += 1
                # A FULL record ends any open FIRST..LAST run: later MIDDLE/LAST fragments must not
                # be glued onto the dropped prefix (that would yield a ghost batch).
                pending = bytearray()
                pending_offset = -1
                yield from _parse_batch(fragment, position, checksum_ok, stats, max_records)
            elif record_type == LOG_FIRST:
                if pending_offset >= 0:
                    stats.dropped_partial_batches += 1
                pending = bytearray(fragment)
                pending_offset = position
                pending_ok = checksum_ok
            elif record_type == LOG_MIDDLE:
                if pending_offset < 0:
                    stats.dropped_partial_batches += 1
                else:
                    pending += fragment
                    pending_ok = _and_ok(pending_ok, checksum_ok)
            else:  # LAST
                if pending_offset < 0:
                    stats.dropped_partial_batches += 1
                else:
                    pending += fragment
                    yield from _parse_batch(bytes(pending), pending_offset, _and_ok(pending_ok, checksum_ok), stats, max_records)
                pending = bytearray()
                pending_offset = -1
            if stats.records >= max_records:
                stats.truncated = True
                return
            position = fragment_start + length
        block_start += LOG_BLOCK_SIZE
    if pending_offset >= 0:
        stats.dropped_partial_batches += 1


def _and_ok(left: bool | None, right: bool | None) -> bool | None:
    if left is False or right is False:
        return False
    if left is None or right is None:
        return None
    return True


def _parse_batch(batch: bytes, file_offset: int, checksum_ok: bool | None, stats: ReadStats, max_records: int) -> Iterator[LevelDBRecord]:
    if len(batch) < 12:
        stats.corrupt_fragments += 1
        stats.note(f"log batch at {file_offset}: shorter than its header")
        return
    sequence = int.from_bytes(batch[0:8], "little")
    count = int.from_bytes(batch[8:12], "little")
    position = 12
    for index in range(count):
        if position >= len(batch) or stats.records >= max_records:
            if position >= len(batch) and index < count:
                stats.corrupt_fragments += 1
                stats.note(f"log batch at {file_offset}: {count - index} declared entries missing")
            return
        tag = batch[position]
        position += 1
        try:
            key_length, position = read_varint(batch, position)
            key = batch[position : position + key_length]
            if len(key) != key_length:
                raise LevelDBError("key runs past batch")
            position += key_length
            value: bytes | None = None
            if tag == VALUE_TYPE_VALUE:
                value_length, position = read_varint(batch, position)
                value = batch[position : position + value_length]
                if len(value) != value_length:
                    raise LevelDBError("value runs past batch")
                position += value_length
            elif tag != VALUE_TYPE_DELETION:
                raise LevelDBError(f"unknown batch tag {tag}")
        except LevelDBError as exc:
            stats.corrupt_fragments += 1
            stats.note(f"log batch at {file_offset}: {exc}")
            return
        stats.records += 1
        if value is None:
            stats.deletions += 1
        yield LevelDBRecord(
            origin="log",
            user_key=bytes(key),
            value=bytes(value) if value is not None else None,
            sequence=sequence + index,
            deleted=value is None,
            file_offset=file_offset,
            checksum_ok=checksum_ok,
        )


# --- tables ---------------------------------------------------------------------------


class _DecompressionBudget(LevelDBError):
    """The table's decompressed-bytes budget is spent (not damage: the rest of the table is skipped)."""


def _read_block(data: bytes, offset: int, size: int, stats: ReadStats, budget: int | None = None) -> bytes:
    if offset < 0 or size < 0 or offset + size + BLOCK_TRAILER_SIZE > len(data):
        raise LevelDBError(f"block handle ({offset}, {size}) outside file")
    raw = data[offset : offset + size]
    compression = data[offset + size]
    if compression == 0:
        return raw
    if compression == 1:
        try:
            declared = snappy_uncompressed_length(raw)
        except LevelDBError as exc:
            raise SnappyError("snappy: bad length preamble") from exc
        if budget is not None and stats.decompressed_bytes + min(declared, MAX_BLOCK_OUTPUT) > budget:
            raise _DecompressionBudget(f"decompressed-bytes budget {budget} spent before block at {offset}")
        stats.snappy_blocks += 1
        block = snappy_decompress(raw)
        stats.decompressed_bytes += len(block)
        return block
    raise LevelDBError(f"unknown block compression {compression}")


def iter_block_entries(block: bytes) -> Iterator[tuple[int, bytes, bytes]]:
    """``(entry offset, key, value)`` of one decompressed block, lazily.

    Bounded against prefix-compression amplification: a key longer than
    ``MAX_KEY_BYTES``, more than ``MAX_BLOCK_ENTRIES`` entries, or decoded
    key + value bytes beyond ``BLOCK_DECODE_FACTOR`` x the block size (at least
    ``BLOCK_DECODE_FLOOR``) raise :class:`LevelDBError` (entries already
    yielded stay valid).
    """
    if len(block) < 4:
        raise LevelDBError("block shorter than its restart count")
    restarts = int.from_bytes(block[-4:], "little")
    limit = len(block) - 4 - 4 * restarts
    if restarts == 0 or limit < 0:
        raise LevelDBError(f"bad restart count {restarts}")
    decode_budget = max(len(block) * BLOCK_DECODE_FACTOR, BLOCK_DECODE_FLOOR)
    decoded = 0
    entries = 0
    position = 0
    last_key = b""
    while position < limit:
        entry_offset = position
        shared, position = read_varint(block, position, limit)
        non_shared, position = read_varint(block, position, limit)
        value_length, position = read_varint(block, position, limit)
        if shared > len(last_key) or position + non_shared + value_length > limit:
            raise LevelDBError(f"block entry at {entry_offset} runs past the block")
        if shared + non_shared > MAX_KEY_BYTES:
            raise LevelDBError(f"block entry at {entry_offset}: key of {shared + non_shared} bytes exceeds {MAX_KEY_BYTES}")
        entries += 1
        decoded += shared + non_shared + value_length
        if entries > MAX_BLOCK_ENTRIES:
            raise LevelDBError(f"block holds more than {MAX_BLOCK_ENTRIES} entries")
        if decoded > decode_budget:
            raise LevelDBError(f"block entry at {entry_offset}: decoded bytes exceed {decode_budget} (prefix amplification)")
        key = last_key[:shared] + block[position : position + non_shared]
        position += non_shared
        value = block[position : position + value_length]
        position += value_length
        last_key = key
        yield entry_offset, key, value


def table_footer(data: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    if len(data) < TABLE_FOOTER_SIZE:
        raise LevelDBError("file shorter than a table footer")
    footer = data[-TABLE_FOOTER_SIZE:]
    if int.from_bytes(footer[-8:], "little") != TABLE_MAGIC:
        raise LevelDBError("table magic missing (truncated or not a LevelDB table)")
    meta_offset, position = read_varint(footer, 0)
    meta_size, position = read_varint(footer, position)
    index_offset, position = read_varint(footer, position)
    index_size, position = read_varint(footer, position)
    return (meta_offset, meta_size), (index_offset, index_size)


def iter_table_records(
    data: bytes,
    stats: ReadStats | None = None,
    *,
    max_records: int = MAX_RECORDS_PER_FILE,
    max_decompressed: int = MAX_TABLE_DECOMPRESSED,
) -> Iterator[LevelDBRecord]:
    """Records of an ``.ldb``/``.sst`` table. A bad footer/index raises; a bad data block is skipped (counted).

    Data-block handles must be strictly increasing, non-overlapping and end
    before the index block (a hostile index cannot make one block decompress
    many times). Snappy output is charged to ``max_decompressed``; when it is
    spent the rest of the table is skipped (``budget_exhausted``/``truncated``).
    """
    stats = stats if stats is not None else ReadStats()
    _meta, (index_offset, index_size) = table_footer(data)
    try:
        index_block = _read_block(data, index_offset, index_size, stats, max_decompressed)
    except _DecompressionBudget:
        stats.budget_exhausted = stats.truncated = True
        return
    handles: list[tuple[int, int]] = []
    previous_end = 0
    for _entry, _key, value in iter_block_entries(index_block):
        block_offset, position = read_varint(value, 0)
        block_size, _ = read_varint(value, position)
        block_end = block_offset + block_size + BLOCK_TRAILER_SIZE
        if (handles and block_offset < previous_end) or block_end > index_offset:
            stats.corrupt_blocks += 1
            stats.note(f"index handle ({block_offset}, {block_size}) overlaps, repeats or runs past the index block")
            continue
        handles.append((block_offset, block_size))
        previous_end = block_end
        if len(handles) >= MAX_TABLE_BLOCKS:
            stats.truncated = True
            break
    for block_offset, block_size in handles:
        try:
            block = _read_block(data, block_offset, block_size, stats, max_decompressed)
        except _DecompressionBudget as exc:
            stats.budget_exhausted = stats.truncated = True
            stats.note(str(exc))
            return
        except LevelDBError as exc:
            stats.corrupt_blocks += 1
            stats.note(f"table block at {block_offset}: {exc}")
            continue
        short_key_seen = False
        try:
            for entry_offset, key, value in iter_block_entries(block):
                if len(key) < 8:
                    if not short_key_seen:  # one damaged block counts once, not once per entry
                        stats.corrupt_blocks += 1
                        short_key_seen = True
                    continue
                trailer = int.from_bytes(key[-8:], "little")
                value_type = trailer & 0xFF
                deleted = value_type == VALUE_TYPE_DELETION
                stats.records += 1
                if deleted:
                    stats.deletions += 1
                yield LevelDBRecord(
                    origin="table",
                    user_key=key[:-8],
                    value=None if deleted else value,
                    sequence=trailer >> 8,
                    deleted=deleted,
                    file_offset=block_offset,
                    entry_offset=entry_offset,
                )
                if stats.records >= max_records:
                    stats.truncated = True
                    return
        except LevelDBError as exc:
            if not short_key_seen:
                stats.corrupt_blocks += 1
            stats.note(f"table block at {block_offset}: {exc}")
