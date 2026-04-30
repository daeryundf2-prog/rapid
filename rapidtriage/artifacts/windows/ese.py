from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

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


def build_ese_page_map(
    path: Path,
    *,
    table_markers: Mapping[str, Sequence[str]] | None = None,
    max_pages: int = 512,
    max_strings_per_page: int = 30,
) -> dict[str, object]:
    header = probe_ese_database(path)
    page_size = int(header.get("page_size") or 0)
    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0
    if not page_size or not file_size:
        return {
            "page_map_available": False,
            "analysis_status": "missing-page-size-or-file-size",
            "page_size": page_size,
            "file_size": file_size,
            "page_count_total": 0,
            "page_count_scanned": 0,
            "page_samples": [],
            "page_marker_family_counts": [],
            "page_risk_flags": [],
            "limitations": ["ESE page map requires a readable file and a supported ESE page size."],
        }

    page_count_total = (file_size + page_size - 1) // page_size
    start_page = 1 if page_count_total > 1 else 0
    scan_count = min(max(0, page_count_total - start_page), max_pages)
    samples: list[dict[str, object]] = []
    marker_counts: dict[str, int] = {}
    risk_flags: set[str] = set()

    try:
        with path.open("rb") as handle:
            for page_index in range(start_page, start_page + scan_count):
                handle.seek(page_index * page_size)
                page = handle.read(page_size)
                if not page:
                    break
                sample = build_ese_page_sample(
                    page,
                    page_index=page_index,
                    page_size=page_size,
                    table_markers=table_markers,
                    max_strings=max_strings_per_page,
                )
                for family in sample["table_marker_hits"]:
                    marker_counts[str(family)] = marker_counts.get(str(family), 0) + 1
                for flag in sample["risk_flags"]:
                    risk_flags.add(str(flag))
                if sample["evidence_density"] > 0:
                    samples.append(sample)
    except OSError:
        return {
            "page_map_available": False,
            "analysis_status": "page-read-failed",
            "page_size": page_size,
            "file_size": file_size,
            "page_count_total": page_count_total,
            "page_count_scanned": 0,
            "page_samples": [],
            "page_marker_family_counts": [],
            "page_risk_flags": [],
            "limitations": ["ESE file could not be read for page-level correlation."],
        }

    return {
        "page_map_available": True,
        "analysis_status": "bounded-page-map-built",
        "method_id": "ese-page-map-string-correlation-v1",
        "page_size": page_size,
        "file_size": file_size,
        "page_count_total": page_count_total,
        "page_count_scanned": scan_count,
        "page_scan_limit": max_pages,
        "candidate_page_count": len(samples),
        "page_samples": samples[:100],
        "page_marker_family_counts": [
            {"value": value, "count": count}
            for value, count in sorted(marker_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        "page_risk_flags": sorted(risk_flags),
        "limitations": [
            "Page map correlates page-local strings and marker families; it does not decode ESE catalog, tagged columns, long values, or native rows.",
            "Row-level timestamps, deleted state, and property IDs still require a validated Windows Search ESE decoder.",
        ],
    }


def build_ese_page_sample(
    page: bytes,
    *,
    page_index: int,
    page_size: int,
    table_markers: Mapping[str, Sequence[str]] | None,
    max_strings: int,
) -> dict[str, object]:
    strings = list(unique_preserve_order(iter_printable_strings(page)))[:max_strings]
    lowered_blob = "\n".join(strings).lower()
    path_candidates = list(unique_preserve_order(find_regex_candidates(strings, WINDOWS_PATH_RE)))[:10]
    url_candidates = list(unique_preserve_order(find_regex_candidates(strings, URL_RE)))[:10]
    suspicious_strings = [
        value
        for value in strings
        if any(term in value.lower() for term in ESE_SUSPICIOUS_TERMS)
    ][:10]
    table_marker_hits = {
        family: sorted({marker for marker in markers if marker in lowered_blob})
        for family, markers in (table_markers or {}).items()
        if any(marker in lowered_blob for marker in markers)
    }
    content_candidates = [
        value[:500]
        for value in strings
        if is_page_content_candidate(value, path_candidates, url_candidates, table_markers)
    ][:10]
    risk_flags = [
        f"ese-page-string:{term}"
        for term in ESE_SUSPICIOUS_TERMS
        if any(term in value.lower() for value in strings)
    ]
    evidence_density = (
        len(path_candidates)
        + len(url_candidates)
        + len(content_candidates)
        + len(suspicious_strings)
        + sum(len(values) for values in table_marker_hits.values())
    )
    return {
        "page_index": page_index,
        "page_offset": page_index * page_size,
        "page_size": len(page),
        "page_sha256": hashlib.sha256(page).hexdigest(),
        "zero_page": not any(page),
        "printable_string_count": len(strings),
        "strings": strings[:20],
        "path_candidates": path_candidates,
        "url_candidates": url_candidates,
        "content_candidates": content_candidates,
        "suspicious_strings": suspicious_strings,
        "table_marker_hits": table_marker_hits,
        "risk_flags": risk_flags,
        "evidence_density": evidence_density,
    }


def is_page_content_candidate(
    value: str,
    path_candidates: Sequence[str],
    url_candidates: Sequence[str],
    table_markers: Mapping[str, Sequence[str]] | None,
) -> bool:
    text = value.strip()
    lowered = text.lower()
    if len(text) < 20 or " " not in text:
        return False
    if text in path_candidates or text in url_candidates:
        return False
    if first_regex_match(text, WINDOWS_PATH_RE) or first_regex_match(text, URL_RE):
        return False
    return not any(marker in lowered for markers in (table_markers or {}).values() for marker in markers)


def first_regex_match(value: str, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.search(value))


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
