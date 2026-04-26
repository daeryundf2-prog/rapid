from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

ESE_HEADER_READ_SIZE = 8192
ESE_SCAN_READ_SIZE = 8 * 1024 * 1024
ESE_SIGNATURE = bytes.fromhex("efcdab89")
ESE_SUSPICIOUS_TERMS = (
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "wmic",
    "certutil",
    "bitsadmin",
    "schtasks",
    "vssadmin",
    "frombase64string",
    "downloadstring",
    "invoke-expression",
    "http://",
    "https://",
)
WINDOWS_PATH_RE = re.compile(
    r"(?i)(?:[a-z]:\\|\\\\)[^\x00\r\n\t\"'<>|]{4,260}"
)
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")


def probe_ese_database(path: Path) -> dict[str, object]:
    header = read_prefix(path, ESE_HEADER_READ_SIZE)
    if not header:
        return {
            "header_readable": False,
            "signature_valid": False,
            "signature_hex": "",
            "header_sha256": "",
            "format_version": 0,
            "file_type": 0,
            "page_size": 0,
        }
    page_size = int_from(header, 0xEC)
    return {
        "header_readable": True,
        "signature_valid": header[4:8] == ESE_SIGNATURE if len(header) >= 8 else False,
        "signature_hex": header[4:8].hex() if len(header) >= 8 else "",
        "header_sha256": hashlib.sha256(header).hexdigest(),
        "format_version": int_from(header, 8),
        "file_type": int_from(header, 12),
        "page_size": page_size if page_size in {2048, 4096, 8192, 16384, 32768} else 0,
    }


def build_ese_string_pivots(path: Path, *, max_strings: int = 250) -> dict[str, object]:
    blob = read_prefix(path, ESE_SCAN_READ_SIZE)
    strings = list(unique_preserve_order(iter_printable_strings(blob)))[:max_strings]
    path_candidates = list(unique_preserve_order(find_regex_candidates(strings, WINDOWS_PATH_RE)))[:50]
    url_candidates = list(unique_preserve_order(find_regex_candidates(strings, URL_RE)))[:50]
    suspicious_strings = [
        value
        for value in strings
        if any(term in value.lower() for term in ESE_SUSPICIOUS_TERMS)
    ][:50]
    risk_flags = [f"ese-string:{term}" for term in ESE_SUSPICIOUS_TERMS if any(term in value.lower() for value in strings)]
    return {
        "string_scan_bytes": len(blob),
        "extracted_string_count": len(strings),
        "extracted_strings": strings[:50],
        "path_candidates": path_candidates,
        "url_candidates": url_candidates,
        "suspicious_strings": suspicious_strings,
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 15),
    }


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def int_from(blob: bytes, offset: int) -> int:
    if len(blob) < offset + 4:
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little", signed=False)


def iter_printable_strings(blob: bytes) -> Iterable[str]:
    yield from iter_ascii_strings(blob)
    yield from iter_utf16le_strings(blob)


def iter_ascii_strings(blob: bytes, *, min_chars: int = 5) -> Iterable[str]:
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_chars:
            yield current.decode("ascii", errors="ignore")
        current.clear()
    if len(current) >= min_chars:
        yield current.decode("ascii", errors="ignore")


def iter_utf16le_strings(blob: bytes, *, min_chars: int = 4) -> Iterable[str]:
    current = bytearray()
    for index in range(0, len(blob) - 1, 2):
        code_unit = blob[index : index + 2]
        value = int.from_bytes(code_unit, "little", signed=False)
        if 32 <= value <= 126 or value in {9, 10, 13}:
            current.extend(code_unit)
            continue
        if len(current) >= min_chars * 2:
            yield current.decode("utf-16le", errors="ignore").strip()
        current.clear()
    if len(current) >= min_chars * 2:
        yield current.decode("utf-16le", errors="ignore").strip()


def unique_preserve_order(values: Iterable[str]) -> Iterable[str]:
    seen: set[str] = set()
    for value in values:
        cleaned = " ".join(value.split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        yield cleaned


def find_regex_candidates(strings: Iterable[str], pattern: re.Pattern[str]) -> Iterable[str]:
    for value in strings:
        for match in pattern.finditer(value):
            yield match.group(0).rstrip(".,);]")
