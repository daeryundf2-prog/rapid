from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable, Mapping

from .ese import ESE_SCAN_READ_SIZE, read_prefix

ESE_PAGE_SIZES = {2048, 4096, 8192, 16384, 32768}
WINDOWS_PATH_RE = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\x00\r\n\t\"'<>|]{4,260}")
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")
SID_RE = re.compile(r"\bS-\d(?:-\d+){2,}\b")
ISO_TIMESTAMP_RE = re.compile(r"\b20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?\b")
KEY_VALUE_RE = re.compile(r"(?i)\b([a-z][a-z0-9_ -]{1,40})\s*[:=]\s*(.*?)(?=\s+[a-z][a-z0-9_ -]{1,40}\s*[:=]|[;,|]|$)")

SRUM_TABLE_FAMILY_MARKERS: dict[str, tuple[str, ...]] = {
    "network-usage": (
        "networkusage",
        "network usage",
        "network data",
        "bytesreceived",
        "bytes received",
        "bytessent",
        "bytes sent",
        "interfaceluid",
        "networkprofile",
    ),
    "app-resource": (
        "appresource",
        "app resource",
        "applicationresource",
        "application",
        "cputime",
        "cpu time",
    ),
    "energy": (
        "energyusage",
        "energy usage",
        "energy",
        "battery",
        "foregroundcycle",
    ),
    "user": (
        "usersid",
        "user sid",
        "username",
        "user name",
        "user",
    ),
}


def analyze_srudb_native(path: Path, *, ese_header: Mapping[str, object]) -> dict[str, object]:
    blob = read_prefix(path, ESE_SCAN_READ_SIZE)
    string_hits = list(unique_string_hits(iter_printable_string_hits(blob)))[:400]
    table_candidates = build_srum_table_candidates(string_hits)
    row_candidates = build_srum_row_candidates(string_hits)
    return {
        "native_srudb_validation": build_srudb_validation(path, ese_header, blob),
        "native_string_hit_count": len(string_hits),
        "native_srum_table_candidates": table_candidates,
        "native_srum_row_candidates": row_candidates,
    }


def build_srudb_validation(path: Path, ese_header: Mapping[str, object], blob: bytes) -> dict[str, object]:
    try:
        file_size = path.stat().st_size
    except OSError:
        file_size = 0
    page_size = int(ese_header.get("page_size") or 0)
    file_page_count = file_size // page_size if page_size else 0
    trailing_bytes = file_size % page_size if page_size else file_size
    page_size_plausible = page_size in ESE_PAGE_SIZES
    signature_valid = bool(ese_header.get("signature_valid"))
    header_readable = bool(ese_header.get("header_readable"))
    status = "not-validated"
    if header_readable and signature_valid and page_size_plausible and file_size >= page_size:
        status = "header-size-plausible"
    if status == "header-size-plausible" and trailing_bytes == 0:
        status = "header-size-page-aligned"
    return {
        "validation_scope": "ese-header-size-and-bounded-string-scan",
        "validation_status": status,
        "header_readable": header_readable,
        "ese_signature_valid": signature_valid,
        "signature_expected_hex": "efcdab89",
        "page_size": page_size,
        "page_size_plausible": page_size_plausible,
        "file_size": file_size,
        "file_page_count": file_page_count,
        "file_size_page_aligned": bool(page_size and trailing_bytes == 0),
        "trailing_bytes_after_pages": trailing_bytes,
        "has_at_least_header_page": bool(page_size and file_size >= page_size),
        "scan_bytes": len(blob),
        "scan_truncated": file_size > len(blob),
        "first_page_sha256": hashlib.sha256(blob[:page_size]).hexdigest() if page_size and len(blob) >= page_size else "",
        "catalog_decoded": False,
        "table_pages_decoded": False,
        "page_checksums_verified": False,
        "row_level_decoding_available": False,
        "requires_dedicated_ese_srum_parser": True,
    }


def build_srum_table_candidates(string_hits: list[dict[str, object]]) -> list[dict[str, object]]:
    table_candidates: list[dict[str, object]] = []
    for table_family, markers in SRUM_TABLE_FAMILY_MARKERS.items():
        matched_markers: set[str] = set()
        matched_strings: list[str] = []
        source_offsets: list[int] = []
        for hit in string_hits:
            value = str(hit.get("value") or "")
            normalized = normalize_marker_text(value)
            matched = [marker for marker in markers if normalize_marker_text(marker) in normalized]
            if not matched:
                continue
            matched_markers.update(matched)
            if len(matched_strings) < 6:
                matched_strings.append(value)
                source_offsets.append(int(hit.get("offset") or 0))
        if not matched_markers:
            continue
        table_candidates.append(
            {
                "table_family": table_family,
                "matched_markers": sorted(matched_markers),
                "matched_marker_count": len(matched_markers),
                "candidate_strings": matched_strings,
                "source_offsets": source_offsets,
                "candidate_basis": "bounded-native-string-marker-scan",
                "candidate_confidence": round(0.38 + min(0.28, len(matched_markers) * 0.04), 2),
            }
        )
    return table_candidates


def build_srum_row_candidates(string_hits: list[dict[str, object]]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, int]] = set()
    for hit in string_hits:
        value = str(hit.get("value") or "")
        if not looks_like_srum_row_string(value):
            continue
        fields = extract_candidate_fields(value)
        table_family = classify_row_table_family(value)
        key = (
            table_family,
            str(fields.get("app_id") or fields.get("executable_path") or ""),
            str(fields.get("timestamp") or ""),
            int(hit.get("offset") or 0),
        )
        if key in seen:
            continue
        seen.add(key)
        counters = {
            name: fields[name]
            for name in ("bytes_sent", "bytes_received", "energy_usage", "cpu_time")
            if fields.get(name) not in ("", 0)
        }
        candidates.append(
            {
                "table_family": table_family,
                "candidate_basis": "bounded-native-string-row-cluster",
                "source_offset": int(hit.get("offset") or 0),
                "source_encoding": str(hit.get("encoding") or ""),
                "app_id": str(fields.get("app_id") or ""),
                "executable_path": str(fields.get("executable_path") or ""),
                "user": str(fields.get("user") or ""),
                "user_sid": str(fields.get("user_sid") or ""),
                "timestamp": str(fields.get("timestamp") or ""),
                "url": str(fields.get("url") or ""),
                "counter_candidates": counters,
                "bytes_sent": fields.get("bytes_sent", 0),
                "bytes_received": fields.get("bytes_received", 0),
                "energy_usage": fields.get("energy_usage", 0),
                "cpu_time": fields.get("cpu_time", 0),
                "interface_luid": str(fields.get("interface_luid") or ""),
                "network_profile": str(fields.get("network_profile") or ""),
                "candidate_confidence": row_candidate_confidence(fields, table_family),
                "raw_candidate": value[:2000],
            }
        )
    return candidates[:100]


def looks_like_srum_row_string(value: str) -> bool:
    lowered = value.lower()
    has_subject = bool(WINDOWS_PATH_RE.search(value) or SID_RE.search(value) or "application" in lowered or "appid" in lowered)
    has_srum_marker = any(
        normalize_marker_text(marker) in normalize_marker_text(value)
        for markers in SRUM_TABLE_FAMILY_MARKERS.values()
        for marker in markers
    )
    has_counter_or_time = bool(ISO_TIMESTAMP_RE.search(value)) or any(
        token in lowered for token in ("bytes", "energy", "cpu", "interfaceluid", "networkprofile")
    )
    return has_subject and has_srum_marker and has_counter_or_time


def extract_candidate_fields(value: str) -> dict[str, object]:
    key_values = {normalize_key(match.group(1)): match.group(2).strip() for match in KEY_VALUE_RE.finditer(value)}
    executable_path = first_regex(WINDOWS_PATH_RE, value)
    url = first_regex(URL_RE, value)
    app_id = first_key_value(key_values, "application", "appid", "app", "executable", "executablepath") or executable_path
    return {
        "app_id": app_id,
        "executable_path": executable_path,
        "user": first_key_value(key_values, "user", "username", "useraccount") or "",
        "user_sid": first_regex(SID_RE, value),
        "timestamp": first_regex(ISO_TIMESTAMP_RE, value).replace("Z", "+00:00"),
        "url": url,
        "bytes_sent": int_key_value(key_values, "bytessent", "bytes sent", "sendbytes", "networkbytessent"),
        "bytes_received": int_key_value(key_values, "bytesreceived", "bytes received", "receivebytes", "networkbytesreceived"),
        "energy_usage": int_key_value(key_values, "energyusage", "energy usage", "energy"),
        "cpu_time": int_key_value(key_values, "cputime", "cpu time", "cpu"),
        "interface_luid": first_key_value(key_values, "interfaceluid", "interface luid") or "",
        "network_profile": first_key_value(key_values, "networkprofile", "network profile", "profile", "ssid") or "",
    }


def classify_row_table_family(value: str) -> str:
    normalized = normalize_marker_text(value)
    best_family = "unknown"
    best_count = 0
    for table_family, markers in SRUM_TABLE_FAMILY_MARKERS.items():
        count = sum(1 for marker in markers if normalize_marker_text(marker) in normalized)
        if count > best_count:
            best_family = table_family
            best_count = count
    return best_family


def row_candidate_confidence(fields: Mapping[str, object], table_family: str) -> float:
    score = 0.34
    if table_family != "unknown":
        score += 0.08
    if fields.get("app_id") or fields.get("executable_path"):
        score += 0.08
    if fields.get("timestamp"):
        score += 0.06
    if fields.get("user") or fields.get("user_sid"):
        score += 0.05
    if fields.get("bytes_sent") or fields.get("bytes_received") or fields.get("energy_usage") or fields.get("cpu_time"):
        score += 0.08
    return round(min(score, 0.62), 2)


def iter_printable_string_hits(blob: bytes) -> Iterable[dict[str, object]]:
    yield from iter_ascii_string_hits(blob)
    yield from iter_utf16le_string_hits(blob)


def iter_ascii_string_hits(blob: bytes, *, min_chars: int = 5) -> Iterable[dict[str, object]]:
    current = bytearray()
    start = 0
    for index, byte in enumerate(blob):
        if 32 <= byte <= 126:
            if not current:
                start = index
            current.append(byte)
            continue
        if len(current) >= min_chars:
            yield {"value": current.decode("ascii", errors="ignore"), "offset": start, "encoding": "ascii"}
        current.clear()
    if len(current) >= min_chars:
        yield {"value": current.decode("ascii", errors="ignore"), "offset": start, "encoding": "ascii"}


def iter_utf16le_string_hits(blob: bytes, *, min_chars: int = 4) -> Iterable[dict[str, object]]:
    current = bytearray()
    start = 0
    for index in range(0, len(blob) - 1, 2):
        code_unit = blob[index : index + 2]
        value = int.from_bytes(code_unit, "little", signed=False)
        if 32 <= value <= 126 or value in {9, 10, 13}:
            if not current:
                start = index
            current.extend(code_unit)
            continue
        if len(current) >= min_chars * 2:
            yield {"value": current.decode("utf-16le", errors="ignore").strip(), "offset": start, "encoding": "utf-16le"}
        current.clear()
    if len(current) >= min_chars * 2:
        yield {"value": current.decode("utf-16le", errors="ignore").strip(), "offset": start, "encoding": "utf-16le"}


def unique_string_hits(hits: Iterable[dict[str, object]]) -> Iterable[dict[str, object]]:
    seen: set[str] = set()
    for hit in hits:
        cleaned = " ".join(str(hit.get("value") or "").split()).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        yield {**hit, "value": cleaned}


def first_regex(pattern: re.Pattern[str], value: str) -> str:
    match = pattern.search(value)
    return match.group(0).rstrip(".,);]") if match else ""


def first_key_value(values: Mapping[str, str], *keys: str) -> str:
    for key in keys:
        value = values.get(normalize_key(key))
        if value:
            return value.strip().strip("\"'")
    return ""


def int_key_value(values: Mapping[str, str], *keys: str) -> int:
    raw_value = first_key_value(values, *keys).replace(",", "")
    match = re.search(r"\d+", raw_value)
    return int(match.group(0)) if match else 0


def normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def normalize_marker_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())
