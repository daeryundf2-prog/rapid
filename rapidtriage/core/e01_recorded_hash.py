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

import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .e01 import discover_e01_segments

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
    text = xml.decode("utf-8", errors="replace").replace("\x00", "")
    found: dict[str, str] = {}
    for algorithm in ("md5", "sha1"):
        match = re.search(rf"<{algorithm}>\s*([0-9a-fA-F]+)\s*</{algorithm}>", text, flags=re.IGNORECASE)
        if match and (value := _clean(algorithm, match.group(1))):
            found[algorithm] = value
    return found


SECTION_PARSERS = {"hash": parse_hash_section, "digest": parse_digest_section, "xhash": parse_xhash_section}


def walk_ewf1_segment(handle, file_size: int) -> tuple[list[tuple[str, dict[str, str]]], bool]:
    """Walk one EWF1 segment's section chain from an open binary handle (read only).

    Returns ``([(section_type, digests), ...], truncated)`` for the hash-bearing sections.
    Stops at ``done`` / ``next``, at a chain that does not move forward, or past the file end.
    """
    found: list[tuple[str, dict[str, str]]] = []
    offset = EWF1_FILE_HEADER_SIZE
    for _ in range(MAX_SECTIONS_PER_SEGMENT):
        if offset + EWF1_SECTION_DESCRIPTOR_SIZE > file_size:
            return found, False
        handle.seek(offset)
        descriptor = handle.read(EWF1_SECTION_DESCRIPTOR_SIZE)
        if len(descriptor) < EWF1_SECTION_DESCRIPTOR_SIZE:
            return found, False
        section_type = descriptor[:16].split(b"\x00", 1)[0].decode("ascii", errors="replace").strip().lower()
        next_offset, section_size = struct.unpack_from("<QQ", descriptor, 16)
        parser = SECTION_PARSERS.get(section_type)
        if parser is not None:
            data_size = max(0, min(section_size, file_size - offset) - EWF1_SECTION_DESCRIPTOR_SIZE)
            if section_type != "xhash":
                data_size = min(data_size, 80)
            data = handle.read(min(data_size, XHASH_INFLATE_LIMIT))
            digests = parser(data)
            if digests:
                found.append((section_type, digests))
        if section_type in ("done", "next") or next_offset <= offset:
            return found, False
        offset = next_offset
    return found, True


def _read_ewf1_sections(segments: list[Path]) -> RecordedHash:
    result = RecordedHash()
    for segment in segments:
        with segment.open("rb") as handle:
            if handle.read(len(EWF1_SIGNATURE)) != EWF1_SIGNATURE:
                continue
            sections, truncated = walk_ewf1_segment(handle, segment.stat().st_size)
        result.sections_truncated = result.sections_truncated or truncated
        for section_type, digests in sections:
            result.md5 = result.md5 or digests.get("md5", "")
            result.sha1 = result.sha1 or digests.get("sha1", "")
            if section_type not in result.sections:
                result.sections.append(section_type)
    if result.md5 or result.sha1:
        result.source = "ewf1-sections"
    return result


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
    """
    path = Path(path)
    try:
        segments = discover_e01_segments(path)
        with segments[0].open("rb") as handle:
            signature = handle.read(len(EWF1_SIGNATURE))
    except OSError as exc:
        return RecordedHash(reason="이미지 세그먼트를 읽지 못했습니다", detail=_error_detail(exc))
    try:
        if signature == EWF1_SIGNATURE:
            result = _read_ewf1_sections(segments)
            if not (result.md5 or result.sha1):
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
    if not (result.md5 or result.sha1) and not result.reason:
        result.reason = "이미지에 기록된 취득 해시가 없습니다 (hash·digest·xhash 섹션 없음)"
    if result.sections_truncated:
        result.reason = (
            result.reason + " · " if result.reason else ""
        ) + f"세그먼트당 섹션 상한 {MAX_SECTIONS_PER_SEGMENT}개에 도달해 나머지 섹션은 읽지 않았습니다(잘림)"
    return result


#: Characters of the raw error kept in ``RecordedHash.detail`` (audit / log only).
ERROR_DETAIL_LIMIT = 2000


def _error_detail(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:ERROR_DETAIL_LIMIT]


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
        recorded_note = (
            f"이미지에 기록된 취득 해시 {' · '.join(parts)}"
            if parts
            else f"이미지에 기록된 취득 해시 없음({recorded.reason or '사유 미상'})"
        )
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
