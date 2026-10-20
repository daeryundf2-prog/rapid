"""URL carving from page files, unallocated-space dumps and image free clusters (R5 L3; R6 S2).

``scan_url_source`` reads one file in bounded windows (``CHUNK_BYTES`` with a
``OVERLAP_BYTES`` overlap so a URL across a window edge is found once) and finds
``http://`` / ``https://`` URLs written as ASCII / UTF-8 bytes or as UTF-16LE. Only the URL
itself is kept -- never the bytes around it (no page bodies). A candidate needs a plausible host
(``a.b`` with a 2+ letter last label, or an IP address); trailing punctuation is trimmed and the
URL is cut to ``MAX_URL_CHARS``. Token-bearing query values (``access_token``, ``sig`` …) are
replaced by ``[가림]`` and the raw URL's SHA-256 kept (``url_sha256``).

URLs are de-duplicated per (URL, encoding) across one run of the analysis: the first offset is
kept with the number of hits in that source. Each candidate carries the 통합 보기 URL class of
its host (``core.derived.url_classes``) and, for a map URL, its coordinates
(``core.derived.map_urls``).

Zero spans (R6 S3): runs of at least ``ZERO_SPAN_MIN`` zero bytes are not handed to the regex
scans (wiped free space is mostly zeros and the two scans cost about 10 ms per MiB of zeros). No
URL match can contain two consecutive zero bytes -- ASCII URLs hold no zero at all and a UTF-16LE
match alternates a printable byte with ``0x00`` and only ends on a ``0x00`` -- so cutting the
scan at any run of zeros (keeping the run's first zero byte for a UTF-16LE match that ends there)
finds exactly the matches of the whole window, at the same offsets. The skipped bytes are counted
in ``UrlCarveState.zero_bytes_skipped``; they were still read and count toward the read budget.

Results are *candidates*: a URL string in the page file or free space says the string was in
memory or on disk at some time, not that the page was visited (hiberfil.sys is compressed and is
not scanned).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from urllib.parse import urlsplit

from ..artifacts.url_redaction import redact_url, url_sha256
from .derived.map_urls import maybe_map_url, parse_map_url
from .derived.url_classes import UrlClasses

CHUNK_BYTES = 8 * 1024 * 1024
OVERLAP_BYTES = 8 * 1024
MAX_URL_CHARS = 2048
MIN_URL_TAIL = 4
ASCII_URL = re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,2048}", re.IGNORECASE)
UTF16_URL = re.compile(rb"h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00(?:[\x21-\x7e]\x00){4,2048}", re.IGNORECASE)
TRAILING = ".,;:!?)]}'\"*"
# A zero run this long is skipped (shorter runs -- the zero bytes of UTF-16LE text, padding -- are
# scanned as usual). ``_ZERO_BIG`` is the stride used to walk a long run.
ZERO_SPAN_MIN = 4 * 1024
_ZERO_SPAN = bytes(ZERO_SPAN_MIN)
_ZERO_BIG_BYTES = 1024 * 1024
_ZERO_BIG = bytes(_ZERO_BIG_BYTES)
HOST_LABEL = re.compile(r"^[a-z0-9-]{1,63}$")
TLD = re.compile(r"^[a-z]{2,24}$|^xn--[a-z0-9-]{2,59}$")
SOURCE_KINDS = ("pagefile", "unallocated", "memory-dump", "image-unallocated")
# ``image-unallocated`` is not a file kind: the unallocated clusters of the NTFS volume of a disk
# image, read through ``core.ntfs_unalloc`` (R6 S2) and scanned with ``scan_url_windows``.
IMAGE_UNALLOCATED = "image-unallocated"
SOURCE_LABELS = {
    "pagefile": "페이지 파일",
    "unallocated": "미할당 영역 덤프",
    "memory-dump": "메모리 덤프",
    IMAGE_UNALLOCATED: "이미지 미할당 영역",
}
PAGEFILE_NAMES = frozenset({"pagefile.sys", "swapfile.sys"})
UNALLOCATED_TOKENS = ("unalloc", "blkls", "freespace", "free-space")
MEMORY_DUMP_SUFFIXES = frozenset({".dmp", ".mem", ".vmem", ".raw", ".lime"})


def source_kind(path: Path) -> str | None:
    """Which URL-carving source a file is (``None``: not one; hiberfil.sys is never one)."""
    name = path.name.lower()
    if name in PAGEFILE_NAMES:
        return "pagefile"
    if name == "hiberfil.sys":
        return None
    if any(token in name for token in UNALLOCATED_TOKENS) or path.suffix.lower() == ".unalloc":
        return "unallocated"
    if path.suffix.lower() in MEMORY_DUMP_SUFFIXES:
        return "memory-dump"
    return None


def clean_url(text: str) -> str | None:
    """The URL with trailing punctuation trimmed, ``None`` when its host is not plausible."""
    url = text[:MAX_URL_CHARS].rstrip(TRAILING)
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return None
    if not host or len(url) < len(parts.scheme) + 3 + MIN_URL_TAIL:
        return None
    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or not all(HOST_LABEL.fullmatch(label) for label in labels) or not TLD.fullmatch(labels[-1]):
        return None
    return url


class UrlCarveState:
    """De-duplication across sources of one analysis run (bounded by ``max_candidates``)."""

    def __init__(self, url_classes: UrlClasses | None, max_candidates: int) -> None:
        self.url_classes = url_classes
        self.max_candidates = max_candidates
        self.seen: set[tuple[str, str]] = set()
        self.capped = False
        # Bytes of zero runs (>= ``ZERO_SPAN_MIN``) not handed to the regex scans (R6 S3); every
        # source byte is counted at most once (window overlaps are not double-counted).
        self.zero_bytes_skipped = 0

    def full(self) -> bool:
        return len(self.seen) >= self.max_candidates


def _patterns(ascii_urls: bool, utf16_urls: bool) -> list[tuple[re.Pattern[bytes], str]]:
    return [(pattern, encoding) for pattern, encoding, wanted in ((ASCII_URL, "ascii", ascii_urls), (UTF16_URL, "utf-16le", utf16_urls)) if wanted]


def _zero_run_end(window: bytes, start: int) -> int:
    """End of the zero run that begins at ``start`` (``window[start:start + ZERO_SPAN_MIN]`` is zero)."""
    size = len(window)
    position = start + ZERO_SPAN_MIN
    while position + _ZERO_BIG_BYTES <= size and window[position : position + _ZERO_BIG_BYTES] == _ZERO_BIG:
        position += _ZERO_BIG_BYTES
    while position + ZERO_SPAN_MIN <= size and window[position : position + ZERO_SPAN_MIN] == _ZERO_SPAN:
        position += ZERO_SPAN_MIN
    rest = window[position : position + ZERO_SPAN_MIN]
    return position + len(rest) - len(rest.lstrip(b"\x00"))


def nonzero_segments(window: bytes, cutoff: int) -> tuple[list[tuple[int, int]], int]:
    """``([(start, end), ...], zero bytes skipped before cutoff)``: the parts of ``window`` the regex
    scans must see. A zero run of ``ZERO_SPAN_MIN`` bytes or more is dropped except its first byte
    (the ``0x00`` a UTF-16LE match may end on). Segments starting at or after ``cutoff`` are left
    to the next window; the skipped count covers ``window[:cutoff]`` only so an overlap is never
    counted twice."""
    size = len(window)
    if not size:
        return [], 0
    if window[:ZERO_SPAN_MIN] == _ZERO_SPAN[: min(size, ZERO_SPAN_MIN)] and window.count(0) == size:
        # The common case on wiped free space: the whole window is zeros.
        return ([], min(cutoff, size)) if size >= ZERO_SPAN_MIN else ([(0, size)], 0)
    segments: list[tuple[int, int]] = []
    position = 0
    while position < size and position < cutoff:
        run = window.find(_ZERO_SPAN, position)
        if run < 0:
            segments.append((position, size))
            break
        if run > position:
            # Keep the run's first zero byte: a UTF-16LE match may end on it.
            segments.append((position, run + 1))
        position = _zero_run_end(window, run)
    limit = min(cutoff, size)
    scanned = sum(max(0, min(end, limit) - start) for start, end in segments)
    return segments, limit - scanned


def _scan_window(
    window: bytes,
    base: int,
    cutoff: int,
    patterns: list[tuple[re.Pattern[bytes], str]],
    found: dict[tuple[str, str], dict[str, object]],
    state: UrlCarveState,
) -> None:
    """Matches of ``window`` starting before ``cutoff`` (the rest belongs to the next window);
    ``base`` is the offset of ``window[0]`` in the source. Zero runs are skipped
    (``nonzero_segments``) without changing which matches are found or their offsets."""
    segments, skipped = nonzero_segments(window, cutoff)
    state.zero_bytes_skipped += skipped
    # Pattern-major order as before the zero skip, so de-duplication and the candidate cap see
    # the matches in the same order.
    for pattern, encoding in patterns:
        for start, end in segments:
            if start >= cutoff:
                break
            for match in pattern.finditer(window, start, end):
                if match.start() >= cutoff:
                    break
                text = match.group(0).decode("ascii" if encoding == "ascii" else "utf-16-le", errors="replace")
                _add(found, state, text, encoding, base + match.start())


def scan_url_source(
    path: Path,
    *,
    state: UrlCarveState,
    read_limit: int,
    ascii_urls: bool = True,
    utf16_urls: bool = True,
    check_cancel: Callable[[], None] | None = None,
) -> tuple[list[dict[str, object]], int]:
    """``(candidates, bytes scanned)`` of one file; candidates are new (URL, encoding) pairs."""
    found: dict[tuple[str, str], dict[str, object]] = {}
    scanned = 0
    offset = 0
    tail = b""
    patterns = _patterns(ascii_urls, utf16_urls)
    with path.open("rb") as handle:
        while offset < read_limit:
            if check_cancel is not None:
                check_cancel()
            chunk = handle.read(min(CHUNK_BYTES, read_limit - offset))
            if not chunk:
                break
            offset += len(chunk)
            scanned += len(chunk)
            final = offset >= read_limit or len(chunk) < CHUNK_BYTES
            window = tail + chunk
            base = offset - len(window)
            # ``tail`` holds the unprocessed end of the previous window. A match is handled by the
            # window where it starts before the overlap (URLs are shorter than the overlap, so it
            # ends inside the window); the last window takes everything.
            cutoff = len(window) if final else max(len(window) - OVERLAP_BYTES, 0)
            _scan_window(window, base, cutoff, patterns, found, state)
            tail = window[cutoff:]
            if state.capped:
                break
    return list(found.values()), scanned


def scan_url_windows(
    windows: Iterable[tuple[bytes, int, int]],
    *,
    state: UrlCarveState,
    ascii_urls: bool = True,
    utf16_urls: bool = True,
) -> list[dict[str, object]]:
    """Candidates of pre-cut ``(window, base offset, cutoff)`` windows (``core.ntfs_unalloc``:
    ``base`` is an absolute image byte offset, so is every candidate's ``offset``)."""
    found: dict[tuple[str, str], dict[str, object]] = {}
    patterns = _patterns(ascii_urls, utf16_urls)
    for window, base, cutoff in windows:
        _scan_window(window, base, cutoff, patterns, found, state)
        if state.capped:
            break
    return list(found.values())


def _add(found: dict[tuple[str, str], dict[str, object]], state: UrlCarveState, raw: str, encoding: str, offset: int) -> None:
    url = clean_url(raw)
    if url is None:
        return
    key = (url, encoding)
    entry = found.get(key)
    if entry is not None:
        entry["hit_count"] = int(entry["hit_count"]) + 1  # type: ignore[call-overload]
        return
    if key in state.seen:
        return
    if state.full():
        state.capped = True
        return
    state.seen.add(key)
    found[key] = candidate_fields(url, encoding, offset, state.url_classes)


def candidate_fields(url: str, encoding: str, offset: int, url_classes: UrlClasses | None) -> dict[str, object]:
    shown = redact_url(url)
    changed = shown != url
    host = (urlsplit(url).hostname or "").lower()
    url_class = None
    if url_classes is not None:
        url_class = url_classes.classify(host) or url_classes.classify_path(urlsplit(url).path)
    fields: dict[str, object] = {
        "url": shown,
        "url_sha256": url_sha256(url),
        "url_tokens_redacted": changed,
        "host": host,
        "encoding": encoding,
        "offset": offset,
        "offset_hex": f"0x{offset:x}",
        "hit_count": 1,
        "url_class": url_class,
        "url_class_label": url_classes.labels.get(url_class) if url_classes is not None and url_class else None,
        "url_truncated": len(url) >= MAX_URL_CHARS,
    }
    if maybe_map_url(url):
        location = parse_map_url(url)
        if location:
            fields.update({key: location[key] for key in ("map_provider", "latitude", "longitude", "query") if location.get(key) is not None})
    return fields
