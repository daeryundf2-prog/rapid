"""Content state of a (recovered) file from its first bytes (T-185, pure function).

``content_state(head, length)`` classifies a file's content from its head bytes and its
declared length, e.g. for a deleted file recovered from an image whose clusters may have been
wiped or reused. Nothing is read from disk and collection is unchanged; callers (preview T-059,
NTFS deleted-content verdict T-269) pass the bytes they already have.

States and precedence (first match wins):

1. ``empty``           -- ``length == 0``: nothing to recover.
2. ``signature-valid`` -- the head starts with a known file signature (``MAGIC_TABLE``; a magic
   may sit at an offset, e.g. ``ftyp`` at +4). Checked before entropy so compressed formats
   with a valid header (JPEG, ZIP, MP4 ...) are not called high-entropy. Only magics of 3 or
   more bytes are listed (2-byte ``MZ`` / MP3 frame sync match random data too often).
3. ``zero-filled``     -- every head byte is ``0x00`` (wiped / never-written clusters).
4. ``high-entropy``    -- Shannon entropy of the head >= ``HIGH_ENTROPY_BITS`` (7.5 bits/byte)
   over at least ``ENTROPY_MIN_BYTES`` (256) bytes: encrypted, compressed without a known
   header, or reused by other compressed data. Shorter heads cannot reach 7.5 reliably
   (max entropy of n bytes is log2(n)), so they are never ``high-entropy``.
5. ``unclassified``    -- content present but none of the above (text, unknown binary). This
   fifth value is the residual the four named states need; it is not an error.

``head`` should be the first ``DEFAULT_HEAD_BYTES`` (4 KiB) of the content, or all of it when
shorter. A head longer than ``length`` is cut to ``length``. ``length > 0`` with an empty head
is a caller error (nothing was read) and raises ``ValueError``.
"""

from __future__ import annotations

import math
from collections import Counter

EMPTY = "empty"
SIGNATURE_VALID = "signature-valid"
ZERO_FILLED = "zero-filled"
HIGH_ENTROPY = "high-entropy"
UNCLASSIFIED = "unclassified"
CONTENT_STATES = (EMPTY, SIGNATURE_VALID, ZERO_FILLED, HIGH_ENTROPY, UNCLASSIFIED)

DEFAULT_HEAD_BYTES = 4096
HIGH_ENTROPY_BITS = 7.5
ENTROPY_MIN_BYTES = 256

#: (kind, offset, magic). Mirrors ``core/carving.SIGNATURES`` and ``core/files.CATEGORY_MAGICS``
#: (>= 3-byte magics) without importing them: those modules pull in the document stack.
MAGIC_TABLE: tuple[tuple[str, int, bytes], ...] = (
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("gif", 0, b"GIF8"),
    ("pdf", 0, b"%PDF-"),
    ("zip", 0, b"PK\x03\x04"),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("rar", 0, b"Rar!\x1a\x07"),
    ("gzip", 0, b"\x1f\x8b\x08"),
    ("bzip2", 0, b"BZh"),
    ("xz", 0, b"\xfd7zXZ\x00"),
    ("cab", 0, b"MSCF\x00\x00\x00\x00"),
    ("zstd", 0, b"\x28\xb5\x2f\xfd"),
    ("sqlite", 0, b"SQLite format 3\x00"),
    ("ole2", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("evtx", 0, b"ElfFile\x00"),
    ("ese-database", 4, b"\xef\xcd\xab\x89"),
    ("elf", 0, b"\x7fELF"),
    ("riff", 0, b"RIFF"),
    ("mp3-id3", 0, b"ID3"),
    ("iso-bmff", 4, b"ftyp"),
    ("ewf", 0, b"EVF\x09\x0d\x0a\xff\x00"),
    ("ewf2", 0, b"EVF2\r\n\x81\x00"),
    ("vhdx", 0, b"vhdxfile"),
    ("registry-hive", 0, b"regf"),
    ("lnk", 0, b"L\x00\x00\x00\x01\x14\x02\x00"),
    ("prefetch-compressed", 0, b"MAM\x04"),
)


def signature_kind(head: bytes) -> str:
    """Kind of the first matching magic in ``MAGIC_TABLE``, ``""`` when none matches."""
    for kind, offset, magic in MAGIC_TABLE:
        if head[offset : offset + len(magic)] == magic:
            return kind
    return ""


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 for empty input)."""
    total = len(data)
    if not total:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in Counter(data).values())


def describe_content_state(head: bytes, length: int) -> dict[str, object]:
    """``content_state`` plus the evidence for it: ``state``, ``signature``, ``entropy``, ``head_bytes``."""
    if length < 0:
        raise ValueError("length must be >= 0")
    head = bytes(head[:length])
    if length == 0:
        return {"state": EMPTY, "signature": "", "entropy": 0.0, "head_bytes": 0}
    if not head:
        raise ValueError("head is empty but length > 0: read the content head first")
    kind = signature_kind(head)
    entropy = round(shannon_entropy(head), 4)
    if kind:
        state = SIGNATURE_VALID
    elif head.count(0) == len(head):
        state = ZERO_FILLED
    elif len(head) >= ENTROPY_MIN_BYTES and entropy >= HIGH_ENTROPY_BITS:
        state = HIGH_ENTROPY
    else:
        state = UNCLASSIFIED
    return {"state": state, "signature": kind, "entropy": entropy, "head_bytes": len(head)}


def content_state(head: bytes, length: int) -> str:
    """One of ``CONTENT_STATES`` for content whose first bytes are ``head`` and size is ``length``."""
    return str(describe_content_state(head, length)["state"])
