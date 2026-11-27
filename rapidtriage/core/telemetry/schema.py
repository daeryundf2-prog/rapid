"""Per-event property whitelist of the local telemetry log (P0 events only).

Every property an event may carry is declared here with its shape; anything
else is dropped before a record is written. Strings are never free text: an
enum value outside its list becomes ``other``, identifiers must look like code
names, versions like versions. Sizes and counts that could fingerprint a case
are written as log-scale buckets. Paths, file names, search terms, evidence
content, evidence hashes, user/device names and exception messages have no
property to go into, so they cannot be recorded.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass

SCHEMA_VERSION = 1
OTHER = "other"
UNKNOWN = "unknown"

COUNT_BUCKETS = ("0", "1-9", "10-99", "100-999", "1k-9k", "10k-99k", "100k-999k", "1m+")
SIZE_BUCKETS = ("<100MB", "100MB-1GB", "1-10GB", "10-100GB", "100GB-1TB", "1TB+")
_SIZE_EDGES = (100 * 10**6, 10**9, 10 * 10**9, 100 * 10**9, 10**12)

IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{0,63}")
VERSION = re.compile(r"\d{1,4}(?:\.\d{1,4}){0,3}(?:[.+\-]?[A-Za-z0-9]{1,16})?")


def count_bucket(value: int | None) -> str:
    """Log-scale bucket of a row/artifact/hit count (``unknown`` when not known)."""
    if value is None or value < 0:
        return UNKNOWN
    if value == 0:
        return "0"
    return COUNT_BUCKETS[min(len(COUNT_BUCKETS) - 1, 1 + int(math.log10(value)))]


def size_bucket(size_bytes: int | None) -> str:
    """Bucket of an evidence size in bytes (``unknown`` for folders or unreadable files)."""
    if size_bytes is None or size_bytes < 0:
        return UNKNOWN
    return SIZE_BUCKETS[sum(1 for edge in _SIZE_EDGES if size_bytes >= edge)]


@dataclass(frozen=True, slots=True)
class Prop:
    """Shape of one property: ``int`` | ``bool`` | ``enum`` | ``ident`` | ``version`` | ``hid``."""

    kind: str
    values: frozenset[str] = frozenset()


INT = Prop("int")
BOOL = Prop("bool")
IDENT_PROP = Prop("ident")
VERSION_PROP = Prop("version")
# Filled by the recorder from a salted HMAC; a caller-supplied value is never accepted.
HID = Prop("hid")


def enum(*values: str) -> Prop:
    return Prop("enum", frozenset((*values, OTHER)))


COUNT = enum(*COUNT_BUCKETS, UNKNOWN)
SIZE = enum(*SIZE_BUCKETS, UNKNOWN)
SURFACE = enum("tree", "timeline", "search", "review")
RUN_STAGES = enum(
    "prepare", "fingerprint", "artifacts", "manifest", "docs", "files", "carve", "extract",
    "timeline", "indicators", "persist", "triage-flags", "derived", "report", "completed",
)
RUN_STATUS = enum("completed", "partial", "cancelled", "failed", "queued", "running")
INPUT_KIND = enum("folder", "e01", "raw", "vhd", "iso", "zip", "egg", "live", "export", "auto")

EVENTS: Mapping[str, Mapping[str, Prop]] = {
    "case_created": {"evidence_slots": INT, "source": enum("wizard", "import", "sample", "cli")},
    "evidence_added": {"input_kind": INPUT_KIND, "size_bucket": SIZE, "format_supported": BOOL},
    "app_session_started": {
        "app_version": VERSION_PROP,
        "viewport_bucket": enum("xs", "sm", "md", "lg", "xl"),
        "locale": enum("ko", "en"),
    },
    "run_started": {
        "profile": IDENT_PROP,
        "input_kind": INPUT_KIND,
        "resume": BOOL,
        "memory_cap_source": enum("argument", "environment", "default-physical-ram-fraction"),
        "provider_count": INT,
        "actor": enum("web", "cli"),
    },
    "run_stage_completed": {
        "stage": RUN_STAGES,
        "duration_ms": INT,
        "status": enum("completed", "failed", "skipped", "partial", "cancelled"),
        "rows_bucket": COUNT,
    },
    "provider_finished": {
        "provider_kind": IDENT_PROP,
        "status": enum("completed", "partial", "cancelled", "failed", "skipped"),
        "artifact_count_bucket": COUNT,
        "parser_error_count": INT,
        "duration_ms": INT,
    },
    "run_finished": {
        "status": RUN_STATUS,
        "duration_ms": INT,
        "partial_task_count": INT,
        "parser_error_total": INT,
        "artifact_total_bucket": COUNT,
    },
    "run_failed": {"stage": RUN_STAGES, "error_class": IDENT_PROP, "duration_ms": INT},
    "grid_loaded": {
        "surface": SURFACE,
        "artifact_type": IDENT_PROP,
        "row_count_bucket": COUNT,
        "latency_ms": INT,
        "server_ms": INT,
        "total_known": BOOL,
        "truncated": BOOL,
    },
    "grid_sorted": {
        "surface": SURFACE,
        "column_kind": enum("time", "text", "number"),
        "direction": enum("asc", "desc"),
        "scope": enum("server", "loaded"),
        "loaded_rows_bucket": COUNT,
        "total_rows_bucket": COUNT,
        "latency_ms": INT,
    },
    "review_stage_entered": {
        "stage": enum("intake", "process", "explore", "review", "report"),
        "run_status": RUN_STATUS,
        "ms_since_run_finished": INT,
    },
    "review_tag_applied": {
        "action": enum("tag", "untag", "bookmark", "relevant", "irrelevant"),
        "row_count": INT,
        "source_surface": enum("grid", "viewer", "search", "timeline", "palette", "shortcut"),
        "artifact_type": IDENT_PROP,
        "tag_hid": HID,
        "is_first_in_run": BOOL,
        "analysis_hid": HID,
    },
    "case_report_created": {
        "format": enum("md", "html", "docx", "pdf"),
        "tagged_row_count": INT,
        "duration_ms": INT,
        "status": enum("ok", "error"),
    },
    "search_submitted": {
        "term_count": INT,
        "term_len_bucket": COUNT,
        "script": enum("hangul", "latin", "digit", "mixed"),
        "category": enum("keyword", "regex", "hash", "email", "phone", "pack"),
        "scope": enum("all", "field"),
        "from_keyword_pack": BOOL,
    },
    "search_results_returned": {
        "hit_count_bucket": COUNT,
        "latency_ms": INT,
        "zero_result": BOOL,
        "backend": enum("fts", "scan"),
        "truncated": BOOL,
    },
    "timeline_entered": {
        "event_count_bucket": COUNT,
        "latency_ms": INT,
        "entry": enum("stage", "pivot", "palette"),
    },
    "crash_reported": {
        "error_class": IDENT_PROP,
        "component": enum("api", "run", "worker"),
        "app_version": VERSION_PROP,
    },
}

#: ``_``-separated words no property name may contain: the forbidden data classes of the proposal
#: (paths, file names, search text, evidence content, evidence hashes, people, devices, messages).
FORBIDDEN_NAME_WORDS = frozenset({
    "path", "paths", "file", "filename", "name", "names", "query", "text",
    "content", "preview", "sha1", "sha256", "md5", "hash", "hashes", "user", "username", "examiner",
    "reviewer", "author", "device", "host", "hostname", "computer", "ip", "message", "note", "title",
    "label", "email", "phone",
})


def clean_value(spec: Prop, value: object) -> object | None:
    """``value`` in the shape ``spec`` allows, ``other`` for an unlisted string, ``None`` to drop."""
    match spec.kind:
        case "int":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                return None
            return max(0, int(value))
        case "bool":
            return value if isinstance(value, bool) else None
        case "enum":
            return value if isinstance(value, str) and value in spec.values else OTHER
        case "ident":
            return value if isinstance(value, str) and IDENT.fullmatch(value) else OTHER
        case "version":
            return value if isinstance(value, str) and VERSION.fullmatch(value) else OTHER
        case "hid":
            return None
        case unreachable:
            raise AssertionError(f"unknown property kind {unreachable!r}")


def clean_props(event: str, props: Mapping[str, object]) -> dict[str, object]:
    """Whitelisted, shape-checked copy of ``props`` (``KeyError`` for an unknown event)."""
    specs = EVENTS[event]
    cleaned: dict[str, object] = {}
    for key, value in props.items():
        spec = specs.get(key)
        if spec is None:
            continue
        kept = clean_value(spec, value)
        if kept is not None:
            cleaned[key] = kept
    return cleaned
