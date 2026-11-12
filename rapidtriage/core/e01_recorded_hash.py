"""Read the acquisition hash an E01/Ex01 image records about itself (T-181, D34a).

Acquisition tools (FTK Imager, EnCase, ewfacquire) store the MD5 / SHA-1 of the acquired
*media* inside the image: EWF1 (``.E01``) keeps it in the ``hash`` section (MD5), the
``digest`` section (MD5 + SHA-1) and/or the zlib-compressed XML ``xhash`` section; EWF2
(``.Ex01``) keeps it in its own hash sections. This module only *reads* those recorded values.
It never recomputes the media hash (that is D34b / T-125) and never writes to evidence: every
segment is opened ``"rb"`` (or through pyewf's default read-only mode).

Sources, in order:

1. ``ewf1-sections`` -- a small built-in walker over the EWF1 section chain of each segment
   (76-byte section descriptors, ``next`` offsets). It reads only descriptors and the three
   hash sections, so it is cheap even for very large images and needs no optional module.
2. ``libewf`` -- ``pyewf.handle().get_hash_value("MD5" / "SHA1")`` through the project's
   existing read-only opener (:func:`rapidtriage.core.e01_native.open_ewf_segments`). Used for
   EWF2 (Ex01) and as a second opinion when the walker finds nothing in an EWF1 image.

When neither yields a value the result is empty with a Korean ``reason`` (no recorded hash,
pyewf missing for Ex01, unreadable segment ...). An all-zero digest field means "not set".
"""

from __future__ import annotations

import logging
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

LOGGER = logging.getLogger(__name__)

EWF1_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
EWF2_SIGNATURE = b"EVF2\r\n\x81\x00"
EWF1_FILE_HEADER_SIZE = 13
EWF1_SECTION_DESCRIPTOR_SIZE = 76
#: Sections walked per segment before giving up (a 2 GiB segment has a few dozen; a loop or a
#: corrupt chain would otherwise spin). Hitting it is reported in ``reason`` / ``sections_truncated``.
MAX_SECTIONS_PER_SEGMENT = 100_000
#: Bytes inflated from an ``xhash`` section (the XML is a few hundred bytes).
XHASH_INFLATE_LIMIT = 1024 * 1024
HEX_DIGEST = {"md5": re.compile(r"^[0-9a-f]{32}$"), "sha1": re.compile(r"^[0-9a-f]{40}$")}


@dataclass
class RecordedHash:
    """Acquisition hash recorded in an EWF image (empty strings when absent)."""

    md5: str = ""
    sha1: str = ""
    source: str = ""  # ewf1-sections | libewf | ""
    sections: list[str] = field(default_factory=list)  # e.g. ["hash", "digest"]
    reason: str = ""  # why the values are empty (Korean), "" when a value was read
    sections_truncated: bool = False
    #: The segment set is known to be incomplete (the last walked segment does not end in ``done``):
    #: the hash sections live in the last segment, so "no value" means "not read", never "none recorded".
    incomplete: bool = False
    #: Raw (often English, long) error text behind ``reason``: logged and audited, never shown.
    detail: str = ""

    def get(self, algorithm: str) -> str:
        return {"md5": self.md5, "sha1": self.sha1}.get(algorithm.lower(), "")

    def to_dict(self) -> dict[str, object]:
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "source": self.source,
            "sections": list(self.sections),
            "reason": self.reason,
            "sections_truncated": self.sections_truncated,
            "incomplete": self.incomplete,
            "claims_acquisition_media_hash": bool(self.md5 or self.sha1),
            "recomputed": False,
        }


def _digest_hex(raw: bytes) -> str:
    """Hex of a digest field; ``""`` when the field is all zero (never filled in)."""
    return raw.hex() if raw and any(raw) else ""


def _clean(algorithm: str, value: object) -> str:
    text = str(value or "").strip().lower()
    return text if HEX_DIGEST[algorithm].match(text) and set(text) != {"0"} else ""


def parse_hash_section(data: bytes) -> dict[str, str]:
    """EWF1 ``hash`` section data: MD5[16] + unknown[16] + adler32[4]."""
    md5 = _digest_hex(data[:16]) if len(data) >= 16 else ""
    return {"md5": md5} if md5 else {}


def parse_digest_section(data: bytes) -> dict[str, str]:
    """EWF1 ``digest`` section data: MD5[16] + SHA-1[20] + padding[40] + adler32[4]."""
    found: dict[str, str] = {}
    if len(data) >= 16 and (md5 := _digest_hex(data[:16])):
        found["md5"] = md5
    if len(data) >= 36 and (sha1 := _digest_hex(data[16:36])):
        found["sha1"] = sha1
    return found


def parse_xhash_section(data: bytes) -> dict[str, str]:
    """EWF1 ``xhash`` section data: zlib-compressed XML ``<xhash><md5>..</md5><sha1>..</sha1></xhash>``."""
    try:
        inflater = zlib.decompressobj()
        xml = inflater.decompress(data, XHASH_INFLATE_LIMIT)
    except zlib.error:
        return {}
    if inflater.unconsumed_tail:
        LOGGER.warning("xhash 섹션 압축 해제가 상한 %d바이트에 닿아 잘림(나머지는 읽지 않음)", XHASH_INFLATE_LIMIT)
    text = xml.decode("utf-8", errors="replace").replace("\x00", "")
    found: dict[str, str] = {}
    for algorithm in ("md5", "sha1"):
        match = re.search(rf"<{algorithm}>\s*([0-9a-fA-F]+)\s*</{algorithm}>", text, flags=re.IGNORECASE)
        if match and (value := _clean(algorithm, match.group(1))):
            found[algorithm] = value
    return found


SECTION_PARSERS = {"hash": parse_hash_section, "digest": parse_digest_section, "xhash": parse_xhash_section}
#: Bytes of section data covered by the trailing Adler-32 (``hash``: MD5 + unknown; ``digest``:
#: MD5 + SHA-1 + padding). ``xhash`` is a zlib stream with its own checksum.
SECTION_CHECKSUM_SPAN = {"hash": 32, "digest": 76}
INCOMPLETE_SEGMENT_SET_REASON = "세그먼트 집합이 불완전함(마지막 세그먼트 없음)"
#: Verdict wording for an incomplete set (R8 WB-9 P1-3): never "기록된 취득 해시 없음".
INCOMPLETE_RECORDED_NOTE = "기록된 취득 해시를 읽지 못함(세그먼트 집합 불완전)"

_SEGMENT_SUFFIX = re.compile(r"^\.(?:E(?P<en>\d{2})|(?P<x>Ex)(?P<xn>\d{2}))$", re.IGNORECASE)
_SEGMENT_LETTER_SUFFIX = re.compile(r"^\.[E-Z](?P<x>x?)[A-Z]{2}$", re.IGNORECASE)
#: E01..E99 (99), then EAA..ZZZ (``[E-Z]`` x 26 x 26) -- libewf's naming after ``.E99``.
MAX_SEGMENT_INDEX = 99 + 22 * 26 * 26


def ewf_segment_suffix(index: int, ex_family: bool) -> str:
    """Segment file suffix for 1-based ``index``: ``.E01``..``.E99``, ``.EAA``..``.ZZZ``
    (``.Ex01``..``.Ex99``, ``.ExAA``..``.ZxZZ`` for Ex01)."""
    if index < 100:
        return f".Ex{index:02d}" if ex_family else f".E{index:02d}"
    k = index - 100
    first = chr(ord("E") + k // 676)
    tail = chr(ord("A") + (k // 26) % 26) + chr(ord("A") + k % 26)
    return f".{first}x{tail}" if ex_family else f".{first}{tail}"


def discover_recorded_hash_segments(path: Path) -> list[Path]:
    """Read-only segment discovery for the recorded-hash reader (T-181, P1-2).

    Continues past ``.E99`` into ``.EAA``.. (and ``.Ex99`` into ``.ExAA``..), which the engine's
    :func:`rapidtriage.core.e01.discover_e01_segments` does not (that gap is the container hash's
    own task). Walks the sequence from segment 1 and stops at the first missing name, so a gap
    or a missing last segment leaves the chain short; the section walker then sees no ``done``.
    Only lists the folder; never opens or writes a file.
    """
    suffix = path.suffix
    match = _SEGMENT_SUFFIX.match(suffix)
    letter = _SEGMENT_LETTER_SUFFIX.match(suffix) if match is None else None
    if match is None and letter is None:
        return [path]
    ex_family = bool((match or letter).group("x"))
    names = {child.name.lower(): child for child in path.parent.iterdir()}
    segments: list[Path] = []
    for index in range(1, MAX_SEGMENT_INDEX + 1):
        candidate = names.get((path.stem + ewf_segment_suffix(index, ex_family)).lower())
        if candidate is None:
            break
        segments.append(candidate)
    else:
        LOGGER.warning("세그먼트 이름 상한 %d개에 닿아 잘림(그 뒤 세그먼트는 찾지 않음)", MAX_SEGMENT_INDEX)
    return segments or [path]


def ewf_segment_index(path: Path) -> int | None:
    """1-based segment index of ``.E01``..``.E99`` / ``.EAA``..``.ZZZ`` (and the Ex01 forms), else ``None``."""
    suffix = Path(path).suffix
    match = _SEGMENT_SUFFIX.match(suffix)
    if match is not None:
        return int(match.group("en") or match.group("xn"))
    letter = _SEGMENT_LETTER_SUFFIX.match(suffix)
    if letter is None:
        return None
    body = suffix[1:].upper().replace("X", "", 1) if letter.group("x") else suffix[1:].upper()
    return 100 + (ord(body[0]) - ord("E")) * 676 + (ord(body[1]) - ord("A")) * 26 + (ord(body[2]) - ord("A"))


def discover_segment_files(path: Path) -> tuple[list[Path], list[int]]:
    """``(segments, gaps)``: every segment file of the set in index order, and the missing indices.

    The container hash and the disk preflight use this (R8 WB-9 P1-4) instead of the engine's
    two-digit :func:`rapidtriage.core.e01.discover_e01_segments`, so a set past ``.E99`` is covered
    in full. The chain from segment 1 comes from :func:`discover_recorded_hash_segments`;
    two-digit segments present after a gap are appended (as the engine's discovery did) and the
    gap indices are returned so callers can disclose them. Read only (lists the folder).
    """
    path = Path(path)
    chain = discover_recorded_hash_segments(path)
    first = ewf_segment_index(chain[0])
    if first is None:
        return chain, []
    ex_family = bool(re.match(r"^\.[E-Z]x", chain[0].suffix, re.IGNORECASE))
    have = {ewf_segment_index(item) for item in chain}
    extra: list[tuple[int, Path]] = []
    for child in path.parent.iterdir():
        if child.stem.lower() != path.stem.lower() or child.name in {item.name for item in chain}:
            continue
        match = _SEGMENT_SUFFIX.match(child.suffix)
        if match is None or bool(match.group("x")) != ex_family:
            continue
        index = int(match.group("en") or match.group("xn"))
        if index not in have:
            extra.append((index, child))
    segments = sorted(chain + [child for _, child in extra], key=lambda item: ewf_segment_index(item) or 0)
    indices = {ewf_segment_index(item) or 0 for item in segments}
    gaps = [index for index in range(1, max(indices) + 1) if index not in indices]
    return segments, gaps


def _checksum_ok(section_type: str, descriptor: bytes, data: bytes) -> bool:
    """Adler-32 of the section descriptor and, for ``hash`` / ``digest``, of the section data."""
    if struct.unpack_from("<I", descriptor, 72)[0] != zlib.adler32(descriptor[:72]):
        return False
    span = SECTION_CHECKSUM_SPAN.get(section_type)
    if span is None:
        return True
    if len(data) < span + 4:
        return False
    return struct.unpack_from("<I", data, span)[0] == zlib.adler32(data[:span])


@dataclass
class SegmentWalk:
    """Hash-bearing sections of one EWF1 segment and how its chain ended."""

    sections: list[tuple[str, dict[str, str]]] = field(default_factory=list)
    truncated: bool = False
    terminal: str = ""  # "done" | "next" | "" (chain ended without either)
    checksum_failures: list[str] = field(default_factory=list)


def walk_ewf1_segment(handle, file_size: int) -> SegmentWalk:
    """Walk one EWF1 segment's section chain from an open binary handle (read only).

    Collects the hash-bearing sections whose Adler-32 checksums verify (failures are listed in
    ``checksum_failures`` and their values dropped). Stops at ``done`` / ``next`` (recorded in
    ``terminal``), at a chain that does not move forward, or past the file end.
    """
    walk = SegmentWalk()
    offset = EWF1_FILE_HEADER_SIZE
    for _ in range(MAX_SECTIONS_PER_SEGMENT):
        if offset + EWF1_SECTION_DESCRIPTOR_SIZE > file_size:
            return walk
        handle.seek(offset)
        descriptor = handle.read(EWF1_SECTION_DESCRIPTOR_SIZE)
        if len(descriptor) < EWF1_SECTION_DESCRIPTOR_SIZE:
            return walk
        section_type = descriptor[:16].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip().lower()
        next_offset, section_size = struct.unpack_from("<QQ", descriptor, 16)
        parser = SECTION_PARSERS.get(section_type)
        if parser is not None:
            data_size = max(0, min(section_size, file_size - offset) - EWF1_SECTION_DESCRIPTOR_SIZE)
            if section_type != "xhash":
                data_size = min(data_size, 80)
            data = handle.read(min(data_size, XHASH_INFLATE_LIMIT))
            if data_size > XHASH_INFLATE_LIMIT:
                LOGGER.warning("%s 섹션이 읽기 상한 %d바이트를 넘어 잘림", section_type, XHASH_INFLATE_LIMIT)
            if _checksum_ok(section_type, descriptor, data):
                digests = parser(data)
                if digests:
                    walk.sections.append((section_type, digests))
            else:
                walk.checksum_failures.append(section_type)
        if section_type in ("done", "next"):
            walk.terminal = section_type
            return walk
        if next_offset <= offset:
            return walk
        offset = next_offset
    walk.truncated = True
    return walk


def _read_ewf1_sections(segments: list[Path]) -> tuple[RecordedHash, bool, list[str]]:
    """``(result, complete, notes)``: ``complete`` is True when the last segment ends in ``done``.

    A value is used only when every hash-bearing section that records that algorithm agrees;
    disagreeing sections are listed in ``notes`` and leave the value empty (no first-wins).
    """
    result = RecordedHash()
    values: dict[str, dict[str, list[str]]] = {"md5": {}, "sha1": {}}
    checksum_failures: list[str] = []
    terminal = ""
    for segment in segments:
        with segment.open("rb") as handle:
            if handle.read(len(EWF1_SIGNATURE)) != EWF1_SIGNATURE:
                terminal = ""
                continue
            walk = walk_ewf1_segment(handle, segment.stat().st_size)
        terminal = walk.terminal
        result.sections_truncated = result.sections_truncated or walk.truncated
        checksum_failures += [f"{segment.name} {name}" for name in walk.checksum_failures]
        for section_type, digests in walk.sections:
            for algorithm, value in digests.items():
                values[algorithm].setdefault(value, []).append(section_type)
            if section_type not in result.sections:
                result.sections.append(section_type)
    notes: list[str] = []
    if checksum_failures:
        notes.append(f"Adler-32 검사합이 맞지 않는 해시 섹션({', '.join(checksum_failures)})의 값은 쓰지 않았습니다")
    for algorithm, by_value in values.items():
        if len(by_value) == 1:
            setattr(result, algorithm, next(iter(by_value)))
        elif len(by_value) > 1:
            listed = " / ".join(f"{'·'.join(dict.fromkeys(kinds))} {value}" for value, kinds in by_value.items())
            notes.append(f"섹션마다 기록된 {algorithm.upper()} 값이 서로 다름({listed}) — 어느 값도 기록값으로 쓰지 않음")
    if result.md5 or result.sha1:
        result.source = "ewf1-sections"
    return result, terminal == "done", notes


def _read_libewf(segments: list[Path]) -> RecordedHash:
    from .e01_native import open_ewf_segments, pyewf

    if pyewf is None:
        return RecordedHash(reason="pyewf(libewf-python)가 없어 Ex01에 기록된 취득 해시를 읽지 못했습니다")
    handle = open_ewf_segments(segments)
    try:
        values = {}
        for algorithm, name in (("md5", "MD5"), ("sha1", "SHA1")):
            try:
                values[algorithm] = _clean(algorithm, handle.get_hash_value(name))
            except Exception:  # pyewf raises IOError subclasses for unknown identifiers
                values[algorithm] = ""
    finally:
        handle.close()
    result = RecordedHash(md5=values["md5"], sha1=values["sha1"])
    if result.md5 or result.sha1:
        result.source = "libewf"
    return result


def read_recorded_acquisition_hash(path: Path) -> RecordedHash:
    """Recorded acquisition MD5 / SHA-1 of the EWF image at ``path`` (any segment of the set).

    Never raises for an unreadable or non-EWF file: the empty result carries the ``reason``.
    An EWF1 set whose last walked segment does not end in ``done`` is reported as incomplete,
    never as "no recorded hash" (the hash sections live in the last segment).
    """
    path = Path(path)
    try:
        segments = discover_recorded_hash_segments(path)
        with segments[0].open("rb") as handle:
            signature = handle.read(len(EWF1_SIGNATURE))
    except OSError as exc:
        return RecordedHash(reason="이미지 세그먼트를 읽지 못했습니다", detail=_error_detail(exc))
    notes: list[str] = []
    try:
        if signature == EWF1_SIGNATURE:
            result, complete, notes = _read_ewf1_sections(segments)
            if not complete:
                notes.insert(0, INCOMPLETE_SEGMENT_SET_REASON)
                result.incomplete = True
            elif not (result.md5 or result.sha1) and not notes:
                fallback = _read_libewf(segments)
                if fallback.md5 or fallback.sha1:
                    fallback.sections_truncated = result.sections_truncated
                    result = fallback
        elif signature == EWF2_SIGNATURE:
            result = _read_libewf(segments)
        else:
            return RecordedHash(reason="EWF(E01/Ex01) 서명이 없어 기록된 취득 해시를 읽지 않았습니다")
    except Exception as exc:  # corrupt image / pyewf C errors: report, never raise into the caller
        # libewf's error chain is English and ~700 chars (R8 WB-8 P2-10): short Korean reason only.
        return RecordedHash(
            reason="기록된 취득 해시를 읽는 중 오류가 나 읽지 못했습니다 (손상된 이미지 또는 libewf 오류)",
            detail=_error_detail(exc),
        )
    if result.reason:
        notes.insert(0, result.reason)
    if not (result.md5 or result.sha1) and not notes:
        notes.append("이미지에 기록된 취득 해시가 없습니다 (hash·digest·xhash 섹션 없음)")
    if result.sections_truncated:
        notes.append(f"세그먼트당 섹션 상한 {MAX_SECTIONS_PER_SEGMENT}개에 도달해 나머지 섹션은 읽지 않았습니다(잘림)")
    result.reason = " · ".join(notes)
    return result


#: Characters of the raw error kept in ``RecordedHash.detail`` (audit / log only).
ERROR_DETAIL_LIMIT = 2000


def _error_detail(exc: BaseException) -> str:
    """The raw error, cut to ``ERROR_DETAIL_LIMIT``; a cut is marked in the text itself
    (``detail_truncated`` / ``detail_total`` characters), never silent."""
    detail = f"{type(exc).__name__}: {exc}"
    detail_total = len(detail)
    detail_truncated = detail_total > ERROR_DETAIL_LIMIT
    if detail_truncated:
        return f"{detail[:ERROR_DETAIL_LIMIT]} … [detail_truncated: {detail_total} chars]"
    return detail


HASH_ALGORITHM_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256"}


def evidence_hash_verdict(
    expected: str, container_digests: dict[str, str], recorded: RecordedHash | None
) -> tuple[str, str]:
    """``(status, message)`` for an evidence row's hash check (case workspace ``_hash_worker``).

    ``expected`` is the examiner's input (lower-case hex, may be empty), ``container_digests`` the
    file / container-byte digests just computed, ``recorded`` the acquisition hash read from the
    image (``None`` for non-EWF evidence). Order:

    * input equals the recorded acquisition hash -> ``computed`` (the media was not re-hashed,
      so it is not ``matched``);
    * input equals the container / file-byte digest -> ``matched``;
    * EWF: a recorded value of the input's algorithm exists and differs (container differs too)
      -> ``mismatched``, the message names both comparisons;
    * EWF: no recorded value of that algorithm (SHA-256 input, no hash section, read error)
      -> ``computed`` with a "대조 불가" message: nothing was compared, so nothing mismatched;
    * non-EWF: otherwise -> ``mismatched``.

    Status strings are the existing ones (``computed`` / ``matched`` / ``mismatched``); for
    non-EWF evidence (``recorded is None``) the messages are the pre-T-181 ones.
    """
    recorded_note = ""
    if recorded is not None:
        parts = [f"{name.upper()} {value}" for name, value in (("md5", recorded.md5), ("sha1", recorded.sha1)) if value]
        if parts:
            recorded_note = f"이미지에 기록된 취득 해시 {' · '.join(parts)}"
        elif recorded.incomplete:
            recorded_note = f"{INCOMPLETE_RECORDED_NOTE}({recorded.reason or '사유 미상'})"
        else:
            recorded_note = f"이미지에 기록된 취득 해시 없음({recorded.reason or '사유 미상'})"
    if not expected:
        message = "기대 해시가 없어 계산값만 기록했습니다 (파일·컨테이너 바이트 기준)"
        return "computed", f"{message} · {recorded_note}" if recorded_note else message
    algorithm = HASH_ALGORITHM_BY_LENGTH.get(len(expected), "")
    actual = container_digests.get(algorithm, "")
    label = algorithm.upper() or "알 수 없는 길이"
    recorded_value = recorded.get(algorithm) if recorded is not None else ""
    if recorded_value and recorded_value == expected:
        return "computed", (
            f"입력값 = 이미지에 기록된 취득 해시(매체 재계산은 하지 않음) · {label} {expected}"
            f" · 컨테이너 파일 바이트 계산값 {actual or '없음'}"
        )
    if actual and actual.lower() == expected:
        if recorded is None:
            return "matched", f"파일 바이트 {label} 기대값 {expected} / 계산값 {actual}"
        return "matched", f"컨테이너 파일 바이트 {label} 기대값 {expected} = 계산값 {actual} · {recorded_note}"
    if recorded is None:
        return "mismatched", f"파일 바이트 {label} 기대값 {expected} / 계산값 {actual or '없음'}"
    if recorded_value:
        return "mismatched", (
            f"입력값 {label} {expected}: 이미지에 기록된 취득 해시({label} {recorded_value})와 다름 · "
            f"컨테이너 파일 바이트 계산값({actual or '없음'})과도 다름 — 매체 해시 재계산은 하지 않음"
        )
    # Nothing to compare against (R8 WB-8 P1-1): no recorded value of the input's algorithm (E01
    # records no SHA-256; MD5-only image; no hash section; unreadable image). A media hash never
    # equals the container digest, so that difference is normal: ``computed``, never ``mismatched``.
    if algorithm in ("md5", "sha1"):
        recorded_part = f"이미지에 기록된 취득 해시와 대조 불가({recorded_note})"
    else:
        recorded_part = f"이미지에 기록된 취득 해시와 대조 불가(E01은 {label}를 기록하지 않음)"
    return "computed", (
        f"입력값 {label} {expected}: {recorded_part} · 컨테이너 파일 바이트 계산값 {actual or '없음'}"
        " (매체 해시는 컨테이너 해시와 다른 것이 정상) — 매체 해시 재계산은 하지 않음"
    )
