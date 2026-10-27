"""Build ``rapidtriage-search.db`` from a run's outputs (plan §3.0 "무엇을 text에 넣는가").

Every source row becomes one primary ``search_doc`` row addressed like the
review map (``collection``/``kind``/``locator``):

* artifacts ``artifacts_<kind>`` -> ``artifacts``/``<kind>``/``/artifacts/<n>``
  (``n`` = the JSONL record index every API reader uses);
* files candidates/inventory -> ``files``/``/candidates/<n>``, ``/inventory/<n>``;
* documents -> ``docs``/``/candidates/<n>``;
* indicator candidates -> ``indicators``/``/indicators/<n>``;
* analysis result rows -> ``analysis``/``<analysis_id>``/``/rows/<n>``.

A row with several evidence times (the timeline output's events of that
``source_record``) gets one extra row per further time: same locator and
columns, ``text`` NULL, ``group_id`` = the primary row (results collapse by it).

Rows are streamed (JSONL ``{``-lines numbered like ``api/app/jsonl_records``,
profile-expanded with ``expand_profile``); a full build writes
``rapidtriage-search.db.building`` and atomically replaces the index, so the
old index stays readable during the build. ``mode="incremental"`` replaces
only the rows of the given analyses in place.

Caps never cut silently: every value, list and row-text cut is counted in
``summary.skipped`` (``value-truncated``, ``list-truncated``,
``text-truncated``) and per field in ``summary.skipped_fields``, the row gets
``truncated = 1`` and ``summary.truncated_by_domain`` feeds the query
warning. Forensic payload fields (``PAYLOAD_KEYS``: ScriptBlockText,
CommandLine, url, …) are exempt from ``VALUE_MAX_CHARS`` up to the row cap.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ..artifact_profiles import (
    PROFILE_REF_KEY,
    PROFILES_PAYLOAD_KEY,
    expand_profile,
    read_artifact_output_head,
    resolve_records_path,
)
from ..json_stream import JsonStreamError, iter_array_items
from ..search_hits import record_time
from .schema import (
    BIGRAM_RULE,
    BUILDING_SUFFIX,
    FLATTEN_VERSION,
    FOLD_RULE,
    INDEX_FILE_NAME,
    INDEX_VERSION,
    QUERY_BUDGET_SECONDS,
    QUERY_GRACE_SECONDS,
    create_indexes,
    create_schema,
    detect_tokenizer,
    open_read_only,
    open_writable,
    read_meta,
    write_meta,
)
from .textutil import (
    bigram_tokens,
    fold,
    format_offset,
    nfc,
    normalize_hash,
    parse_offset,
    parse_ts_ms,
    path_key,
    stored_fold,
    target_path_key,
)

LOGGER = logging.getLogger(__name__)

SEARCH_INDEX_KIND = "search-index"
CANCEL_EVERY_ROWS = 500
BATCH_ROWS = 4000
TEXT_MAX_CHARS = 64 * 1024
# Document bodies (R7 S2 review #3): 512 K characters cover 99.6 % of the documents of a real
# run (run-subset10: 1,998 bodies, p99.5 = 371 K); 64 K cut 3 % of them and their later text
# was not searchable. Artifact rows keep ARTIFACT_TEXT_MAX_CHARS.
DOC_TEXT_MAX_CHARS = 512 * 1024
ARTIFACT_TEXT_MAX_CHARS = 8 * 1024
EVENTLOG_TEXT_MAX_CHARS = 64 * 1024
VALUE_MAX_CHARS = 1024
# Forensic payload fields (compared without ``_`` and case): kept whole up to the row cap.
PAYLOAD_KEYS = frozenset(
    {
        "scriptblocktext", "payload", "contextinfo", "commandline", "processcommandline", "parentcommandline",
        "imagepath", "servicefilename", "url", "title", "path", "body",
    }
)
SKIPPED_FIELDS_MAX = 200
# Replacing the index waits for readers: a query holds the file at most budget + grace.
SWAP_WAIT_SECONDS = QUERY_BUDGET_SECONDS + QUERY_GRACE_SECONDS + 5.0
FIELDS_MAX_CHARS = 16 * 1024
FIELDS_MAX_ENTRIES = 20
LIST_MAX_ITEMS = 200
# Small artifact types (aggregates such as browser-history-downloads, jumplist
# automatic destinations) keep up to the plan's 64 KB / 1,000 list items.
SMALL_TYPE_TEXT_MAX_CHARS = 64 * 1024
SMALL_TYPE_LIST_MAX_ITEMS = 1000
DOC_BODY_MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TIMES_PER_ROW = 2000
ANALYSIS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

ANALYSIS_DOMAINS = {
    "carve": "filesystem",
    "vsc-discover": "filesystem",
    "vsc-compare": "filesystem",
    "vsc-extract": "filesystem",
    "ntfs-meta": "filesystem",
    "ocr-batch": "media",
    "memory-import": "memory",
    "cross-case": "incident",
    "url-carve": "web",
}

# Detail keys whose values are boilerplate (validation plans, readiness,
# provenance, per-record digests) or numbers without search value. Matching
# subtrees are never walked.
NOISE_KEY_RE = re.compile(
    r"(blocker|commercial|readiness|validation|assessment|report_grade|accuracy_gate|uplift|profile_version|"
    r"^parser|coverage_status|reportability|limitation|caveat|next_validation|analyst_|required_|qc_|matrix|"
    r"forensic_review|record_projection|data_uri|thumbnail|^evtx_|_sha256$|_sha1$|_md5$|hashes$|^hashes_|_offset|"
    r"_hex$|droid|_filetime|_100ns|transaction_log|_note$|disclosure|semantics|citation|manifest|confidence|"
    r"risk_score|^source_index$|^cell_|trusted_diff|_plan$|evidence_refs|source_refs|gap_ids|operator_action|"
    r"slot|workflow|classifier|deepfake|_raw$|raw_preview|preview|policy|contract|^schema|inventory_profile|"
    r"_profile$|_ids$|_tags$|^event_tags$|guidance|privacy_legal|^timestamp|_at$|_time$|_date$|mtime|ctime|atime|"
    r"_count$|_counts$|_size$|_bytes$|^size$|entropy|_ratio$|^source_path$|^path$|status$|^supported$|^label$|"
    r"_depth$|^depth$|sequence|chunk|^opcode$|^task$|^level$|^keywords$|^version$|_version$|^bias|_minutes$|_source$|"
    r"_encoding$|^source_format$|^hive_hint$)",
    re.IGNORECASE,
)
KEEP_KEYS = frozenset({"event_id", "record_id", "logon_type", "volume_label", "volume_serial_number", "serial_number"})
ISO_LIKE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
LONG_HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{24,}$")
EMPTY_VALUES = frozenset({"", "-", "0", "none", "null", "n/a", "{00000000-0000-0000-0000-000000000000}"})

HASH_DETAIL_KEYS = ("md5", "sha1", "sha256", "media_sha256", "file_sha1", "file_sha256", "file_md5", "file_id", "sha1_candidates")
# Kinds/types whose ``source_hashes`` describe the row's own subject file.
FILE_SUBJECT_KINDS = frozenset({"media-image", "synthetic-media", "generic-documents", "windows-filesystem", "android-apk", "email"})
FILE_SUBJECT_TYPE_SUFFIXES = ("-file", "-hive", "-database")
CONTAINER_KINDS = frozenset({"eventlog", "windows-registry", "windows-shellbags"})
CONTAINER_TYPES = frozenset({"prefetch-reference"})

ACTOR_KEYS = ("target_user_name", "user_name", "username", "user", "account_name", "subject_user_name", "owner")
SID_KEYS = ("target_user_sid", "user_sid", "sid", "subject_user_sid")
TITLE_KEYS = ("title", "name", "entry_name", "program_name", "executable_hint", "item_name", "label", "key_name")
PATH_DETAIL_KEYS = ("target_path", "executable_path", "local_base_path", "shell_path", "key_path", "source_path", "url")
# The row's target (``path2``): LNK/Jump List target, Amcache/ShimCache/BAM executable,
# Amcache shortcut target, download target, Prefetch reference.
TARGET_PATH_KEYS = (
    "target_path", "local_base_path", "shortcut_target_path", "executable_path", "current_path",
    "lower_case_long_path", "full_path", "referenced_path", "device_path", "destlist_path",
)
TARGET_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|\\|/|%[A-Za-z0-9_]+%[\\/])")

TS_FAMILIES = (
    ("run", re.compile(r"(^run(-\d+)?$|last-run|last-execution|execut|started)")),
    ("last_written", re.compile(r"last-written|written")),
    ("created", re.compile(r"creat|install|added|first")),
    ("modified", re.compile(r"modif|changed")),
    ("accessed", re.compile(r"access")),
    ("visit", re.compile(r"visit|navigat|typed")),
    ("download", re.compile(r"download")),
    ("taken", re.compile(r"exif|taken|datetime-original")),
    ("event", re.compile(r"^event$|notification|crash|logon|ended")),
)


def ts_family(label: str) -> str:
    text = str(label or "").lower()
    for family, pattern in TS_FAMILIES:
        if pattern.search(text):
            return family
    return "other"


# ---------------------------------------------------------------------------
# documents of the index
# ---------------------------------------------------------------------------


@dataclass
class Doc:
    collection: str
    locator: str
    kind: str = ""
    analysis_id: str = ""
    domain: str = ""
    artifact_type: str = ""
    title: str = ""
    path: str = ""
    size: int | None = None
    actor: str = ""
    actor_sid: str = ""
    computer: str = ""
    body: list[str] = field(default_factory=list)
    text_cap: int = ARTIFACT_TEXT_MAX_CHARS
    list_cap: int = LIST_MAX_ITEMS
    fields: dict[str, object] = field(default_factory=dict)
    search_fields: list[tuple[str, str, int | None]] = field(default_factory=list)
    hashes: list[tuple[str, str]] = field(default_factory=list)
    times: list[tuple[int, str, tuple[str, ...]]] = field(default_factory=list)
    deleted: int = 0
    sig_mismatch: int = 0
    in_archive: int = 0
    # False for rows whose path is only their container (an EVTX file, a hive):
    # the path stays searchable with ``path:``/``under:`` but is not repeated in the text.
    text_path: bool = True
    path2: str = ""
    # The record's own time as v1 hits show it (``search_hits.record_time``; ``search_doc.ts_text``).
    ts_text: str = ""
    # "<reason>:<field>" -> count of cuts on this row (value/list/text caps).
    cuts: Counter[str] = field(default_factory=Counter)


@dataclass
class BuildContext:
    output_dir: Path
    roots: list[str]
    domain_of: Callable[[str, str], str]
    timeline: dict[tuple[str, int], list[tuple[int, str, tuple[str, ...]]]]
    doc_meta: dict[str, dict[str, str]] = field(default_factory=dict)
    skipped: Counter[str] = field(default_factory=Counter)
    skipped_fields: dict[str, Counter[str]] = field(default_factory=dict)
    tz_offset: dt.timedelta | None = None
    # Text/list caps of the artifact row being flattened (``_write_kind`` sets them per row).
    row_text_cap: int = ARTIFACT_TEXT_MAX_CHARS
    row_list_cap: int = LIST_MAX_ITEMS

    def evidence_path(self, raw: str) -> str:
        """Path as the examiner reads it: the run root prefix stripped (``\\Users\\x``)."""
        text = str(raw or "")
        if not text:
            return ""
        lowered = text.lower()
        for root in self.roots:
            if root and lowered.startswith(root):
                rest = text[len(root):]
                return rest if rest.startswith(("\\", "/")) else "\\" + rest
        return text


def _evidence_roots(summary: Mapping[str, object]) -> list[str]:
    source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
    values = [summary.get("root"), summary.get("scan_scope_root"), source.get("analysis_root"), source.get("stage_dir"), source.get("source_path")]
    roots: list[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            root = value.strip().rstrip("\\/").lower()
            if root and root not in roots:
                roots.append(root)
    return sorted(roots, key=len, reverse=True)


# ---------------------------------------------------------------------------
# value walking
# ---------------------------------------------------------------------------


def _usable_text(value: str) -> str | None:
    """The value worth indexing (whole; callers apply the caps), ``None`` for noise."""
    text = value.strip()
    if not text or text.lower() in EMPTY_VALUES:
        return None
    if (len(text) <= 5 and text.isdigit()) or ISO_LIKE_RE.match(text) or LONG_HEX_RE.match(text):
        return None
    return text


_PAYLOAD_CACHE: dict[str, bool] = {}


def is_payload_key(key: str) -> bool:
    cached = _PAYLOAD_CACHE.get(key)
    if cached is None:
        cached = key.replace("_", "").replace("-", "").lower() in PAYLOAD_KEYS
        if len(_PAYLOAD_CACHE) < 100_000:
            _PAYLOAD_CACHE[key] = cached
    return cached


def capped_value(text: str, key: str, budget: int, cuts: Counter[str] | None) -> str:
    """``text`` cut to ``VALUE_MAX_CHARS`` (payload keys: whole) and to the row budget; every cut counted."""
    if not is_payload_key(key) and len(text) > VALUE_MAX_CHARS:
        text = text[:VALUE_MAX_CHARS]
        if cuts is not None:
            cuts[f"value-truncated:{key}"] += 1
    if len(text) > budget:
        text = text[: max(0, budget)]
        if cuts is not None:
            cuts[f"text-truncated:{key}"] += 1
    return text


_NOISE_CACHE: dict[str, bool] = {}


def is_noise_key(key: str) -> bool:
    cached = _NOISE_CACHE.get(key)
    if cached is None:
        cached = key not in KEEP_KEYS and NOISE_KEY_RE.search(key) is not None
        if len(_NOISE_CACHE) < 100_000:
            _NOISE_CACHE[key] = cached
    return cached


def walk_values(
    details: Mapping[str, object],
    out: list[str],
    seen: set[str],
    budget: int,
    *,
    skip: frozenset[str] = frozenset(),
    list_cap: int = LIST_MAX_ITEMS,
    cuts: Counter[str] | None = None,
) -> int:
    """Append searchable string values of ``details`` (noise keys pruned); return chars left.

    Cuts (value cap, list cap, row budget) are counted in ``cuts`` as ``<reason>:<field>``.
    """
    stack: list[tuple[str, object]] = [(key, value) for key, value in reversed(list(details.items())) if key not in skip]
    while stack:
        key, value = stack.pop()
        if key and is_noise_key(key):
            continue
        if budget <= 0:
            if cuts is not None and _has_text(value):
                cuts[f"text-truncated:{key}"] += 1
            continue
        if isinstance(value, str):
            text = _usable_text(value)
            if text is not None and text not in seen:
                seen.add(text)
                text = capped_value(text, key, budget - 1, cuts)
                if text:
                    out.append(text)
                    budget -= len(text) + 1
        elif isinstance(value, Mapping):
            stack.extend((str(k), v) for k, v in reversed(list(value.items())))
        elif isinstance(value, list):
            if len(value) > list_cap and cuts is not None:
                cuts[f"list-truncated:{key}"] += 1
            stack.extend((key, item) for item in reversed(value[:list_cap]))
        elif isinstance(value, int) and not isinstance(value, bool) and key in KEEP_KEYS and value:
            text = str(value)
            if text not in seen:
                seen.add(text)
                out.append(text)
                budget -= len(text) + 1
    return budget


def _has_text(value: object) -> bool:
    """A value that would have added text (cheap check for cut accounting)."""
    if isinstance(value, str):
        return _usable_text(value) is not None
    if isinstance(value, Mapping):
        return any(not is_noise_key(str(key)) and _has_text(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_has_text(item) for item in value[:50])
    return False


def target_path(details: Mapping[str, object]) -> str:
    """The row's target path (``path2``) from its details, ``""`` when it has none."""
    for key in TARGET_PATH_KEYS:
        value = details.get(key)
        if isinstance(value, str):
            text = value.strip()
            if text and "://" not in text and TARGET_PATH_RE.match(text):
                return text
    executable = _first_text(details, ("header_executable_name", "executable_hint", "filename_executable_hint"))
    references = details.get("referenced_paths")
    if executable and isinstance(references, list):
        suffix = "\\" + executable.lower()
        for item in references:
            if isinstance(item, str) and item.lower().endswith(suffix):
                return item
    return ""


def _first_text(details: Mapping[str, object], keys: Iterable[str]) -> str:
    for key in keys:
        value = details.get(key)
        if isinstance(value, str) and value.strip() and value.strip() not in ("-", "0"):
            return value.strip()
    return ""


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _collect_hashes(details: Mapping[str, object], doc: Doc, *, include_source: bool) -> None:
    seen = {(alg, value) for alg, value in doc.hashes}

    def add(raw: object) -> None:
        if isinstance(raw, str):
            normalized = normalize_hash(raw)
            if normalized is not None and normalized not in seen:
                seen.add(normalized)
                doc.hashes.append(normalized)

    for key in HASH_DETAIL_KEYS:
        value = details.get(key)
        if isinstance(value, list):
            if len(value) > LIST_MAX_ITEMS:
                doc.cuts[f"list-truncated:{key}"] += 1
            for item in value[:LIST_MAX_ITEMS]:
                add(item)
        else:
            add(value)
    hashes = details.get("hashes")
    if isinstance(hashes, Mapping):
        for value in hashes.values():
            add(value)
    if include_source:
        source = details.get("source_hashes")
        if isinstance(source, Mapping):
            for value in source.values():
                add(value)


def _compact_fields(details: Mapping[str, object], *, preferred: Iterable[str] = ()) -> dict[str, object]:
    fields: dict[str, object] = {}
    used = 0
    keys = [key for key in preferred if key in details] + [key for key in details if key not in preferred]
    for key in keys:
        if len(fields) >= FIELDS_MAX_ENTRIES:
            break
        if is_noise_key(key) and key not in preferred:
            continue
        value = details.get(key)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, (int, float)):
            shown: object = value
        elif isinstance(value, str):
            if not value.strip():
                continue
            shown = value[:256]
        else:
            continue
        used += len(key) + len(str(shown))
        if used > FIELDS_MAX_CHARS:
            break
        fields[key] = shown
    return fields


def _detail_times(details: Mapping[str, object], offset: dt.timedelta | None) -> list[tuple[int, str, tuple[str, ...]]]:
    """Evidence times of a row without a timeline event (analysis rows): ``*_at``/``timestamp`` keys."""
    times: list[tuple[int, str, tuple[str, ...]]] = []
    seen: set[int] = set()
    for key, value in details.items():
        if not isinstance(value, str) or not (key == "timestamp" or key.endswith(("_at", "_time"))):
            continue
        if key.startswith("source_file_") or key in {"generated_at", "indexed_at", "extracted_at"}:
            continue
        millis = parse_ts_ms(value, default_offset=offset)
        if millis is None or millis in seen:
            continue
        seen.add(millis)
        label = str(details.get("timestamp_kind") or key) if key == "timestamp" else key.removesuffix("_at").removesuffix("_time")
        times.append((millis, label.replace("_", "-"), ()))
        if len(times) >= 8:
            break
    return times


# ---------------------------------------------------------------------------
# flatten_<domain>
# ---------------------------------------------------------------------------


def _base_doc(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object]) -> tuple[Doc, Mapping[str, object]]:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    artifact_type = str(row.get("artifact_type") or "artifact")
    raw_path = str(row.get("path") or details.get("source_path") or "")
    doc = Doc(
        collection="artifacts",
        kind=kind,
        locator=f"/artifacts/{record_index}",
        domain=ctx.domain_of(kind, artifact_type),
        artifact_type=artifact_type,
        path=raw_path,
        text_cap=ctx.row_text_cap,
        list_cap=ctx.row_list_cap,
    )
    doc.actor = _first_text(details, ACTOR_KEYS)
    doc.actor_sid = _first_text(details, SID_KEYS)
    computer = details.get("computer") or details.get("computer_name") or details.get("workstation_name")
    doc.computer = str(computer).strip() if isinstance(computer, str) and computer.strip() not in ("", "-") else ""
    doc.size = _int_or_none(details.get("size") if details.get("size") is not None else details.get("source_size"))
    doc.title = _first_text(details, TITLE_KEYS) or Path(raw_path.replace("\\", "/")).name or artifact_type
    doc.path2 = target_path(details)
    lowered = artifact_type.lower()
    if "deleted" in lowered or details.get("deleted") is True or details.get("is_deleted") is True:
        doc.deleted = 1
    if "signature-mismatch" in lowered:
        doc.sig_mismatch = 1
    include_source = kind in FILE_SUBJECT_KINDS or lowered.endswith(FILE_SUBJECT_TYPE_SUFFIXES)
    _collect_hashes(details, doc, include_source=include_source)
    if not include_source and (kind in CONTAINER_KINDS or artifact_type in CONTAINER_TYPES):
        doc.text_path = False
    doc.times = list(ctx.timeline.get((f"artifacts_{kind}", record_index), ()))
    doc.ts_text = record_time("artifacts", row) or ""
    return doc, details


def flatten_eventlog(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """Rendered message + every EventData ``Name=Value`` + channel/provider/computer/user."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    doc.text_cap = EVENTLOG_TEXT_MAX_CHARS  # payload events (4104 script blocks) keep up to 64 KB
    event_id = _int_or_none(details.get("event_id"))
    provider = str(details.get("provider_name") or "")
    channel = str(details.get("channel") or "")
    label = str(details.get("event_label_ko") or details.get("event_description") or "")
    doc.title = " · ".join(part for part in (str(details.get("event_id") or ""), label or provider) if part) or doc.title
    parts: list[str] = []
    seen: set[str] = set()
    budget = doc.text_cap
    for key, value in (("event_message", details.get("event_message")), ("provider_name", provider), ("channel", channel),
                       ("computer", doc.computer), ("actor", doc.actor), ("user_name", details.get("user_name"))):
        usable = _usable_text(value) if isinstance(value, str) else None
        if usable and usable not in seen:
            seen.add(usable)
            usable = capped_value(usable, key, budget - 1, doc.cuts)
            if usable:
                parts.append(usable)
                budget -= len(usable) + 1
    event_data = details.get("event_data") if isinstance(details.get("event_data"), Mapping) else {}
    for name, value in event_data.items():
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            shown = str(value).strip()
            if not shown or shown.lower() in EMPTY_VALUES or shown.startswith("%%") or f"{name}={shown}" in seen:
                continue
            seen.add(f"{name}={shown}")
            seen.add(shown)  # the same value under details (script_block_text, command_line) is not repeated
            kept = capped_value(shown, str(name), budget - len(str(name)) - 2, doc.cuts)
            if kept:
                parts.append(f"{name}={kept}")
                budget -= len(name) + len(kept) + 2
    walk_values(text, parts, seen, budget, skip=frozenset({"event_data", "event_message", "provider_name", "channel"}), list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    if event_id is not None:
        doc.search_fields.append(("eventid", str(event_id), event_id))
    if provider:
        doc.search_fields.append(("provider", fold(provider), None))
    if channel:
        doc.search_fields.append(("channel", fold(channel), None))
    doc.fields = {
        "event_id": details.get("event_id"),
        "provider": provider,
        "channel": channel,
        "record_id": details.get("record_id"),
        "computer": doc.computer,
        "user": doc.actor,
    }
    return doc


def flatten_registry(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """Key path + value names + decoded values (typed rows add their decoded fields)."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    key_path = str(details.get("key_path") or details.get("key") or "")
    if key_path:
        doc.title = key_path.rsplit("\\", 1)[-1] or key_path
    parts: list[str] = [key_path] if key_path else []
    seen = set(parts)
    walk_values(text, parts, seen, doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text, preferred=("key_path", "value_names", "vendor", "product", "serial_number", "friendly_name"))
    return doc


def flatten_paths(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """ShellBags / RecentDocs / UserAssist / LNK / JumpList: restored path + target + volume serial."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    target = _first_text(details, ("shell_path", "target_path", "local_base_path", "destlist_path", "item_name", "entry_name"))
    if target:
        doc.title = target
    parts: list[str] = [target] if target else []
    walk_values(text, parts, set(parts), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text, preferred=("shell_path", "target_path", "key_path", "volume_serial_number", "volume_label", "user"))
    return doc


def flatten_execution(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """Prefetch / Amcache / ShimCache / BAM: executable path + referenced paths (<= 200) + hashes."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    executable = _first_text(details, ("executable_path", "executable_hint", "program_name", "referenced_path", "header_executable_name"))
    if executable:
        doc.title = executable
    parts: list[str] = [executable] if executable else []
    walk_values(text, parts, set(parts), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text, preferred=("executable_path", "program_name", "sha1", "run_count", "publisher", "product_name"))
    return doc


def flatten_browser(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """URL + title + download target path + referrer."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    url = _first_text(details, ("url", "source_url", "tab_url"))
    title = _first_text(details, ("title", "page_title"))
    doc.title = title or url or doc.title
    parts = [part for part in (url, title, _first_text(details, ("target_path", "current_path")), _first_text(details, ("referrer",))) if part]
    walk_values(text, parts, set(parts), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text, preferred=("url", "title", "target_path", "referrer", "browser", "profile", "user"))
    return doc


def flatten_documents(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> list[Doc]:
    """Document metadata (author / last saved by / template / company) and archive entries."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    parts: list[str] = []
    walk_values(text, parts, set(), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    meta = document_meta(details)
    for name, value in meta.items():
        doc.search_fields.append((name, fold(value), None))
    doc.fields = _compact_fields(text, preferred=("author", "last_modified_by", "template", "company", "application", "title"))
    docs = [doc]
    profile = details.get("archive_inventory_profile")
    entries = profile.get("sample_entries") if isinstance(profile, Mapping) else None
    if isinstance(entries, list):
        if len(entries) > LIST_MAX_ITEMS:
            doc.cuts["list-truncated:sample_entries"] += 1
        for entry in entries[:LIST_MAX_ITEMS]:
            if not isinstance(entry, Mapping) or not entry.get("name"):
                continue
            name = str(entry.get("name"))
            child = Doc(
                collection="artifacts",
                kind=kind,
                locator=doc.locator,
                domain=doc.domain,
                artifact_type="archive-entry",
                title=name,
                path=f"{doc.path}!{name}",
                size=_int_or_none(entry.get("uncompressed_size")),
                in_archive=1,
                body=[name],
                ts_text=doc.ts_text,
            )
            child.search_fields.append(("archive_entry", fold(name), None))
            child.fields = {"archive": doc.path, "name": name, "crc32": entry.get("crc32") or ""}
            docs.append(child)
    return docs


def document_meta(details: Mapping[str, object]) -> dict[str, str]:
    meta: dict[str, str] = {}
    for name, keys in (
        ("author", ("author", "creator")),
        ("last_saved_by", ("last_modified_by", "last_saved_by", "last_author")),
        ("template", ("template",)),
        ("company", ("company",)),
    ):
        value = _first_text(details, keys)
        if value:
            meta[name] = value
    return meta


def flatten_messenger(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """Message body + conversation partner (KakaoTalk, mobile/email exports)."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    body = _first_text(details, ("message", "message_text", "body", "text", "content", "candidate_value", "subject"))
    partner = _first_text(details, ("sender", "from", "to", "partner", "chat_name", "room_name"))
    parts = [part for part in (body, partner) if part]
    walk_values(text, parts, set(parts), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text, preferred=("sender", "from", "to", "subject", "chat_name"))
    return doc


def flatten_media(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    """Media: path + EXIF text fields (camera, software, description)."""
    doc, details = _base_doc(ctx, kind, record_index, row)
    parts: list[str] = []
    walk_values(text, parts, set(), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text, preferred=("entry_name", "source_format", "camera_make", "camera_model", "make", "model"))
    return doc


def flatten_generic(ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object]) -> Doc:
    doc, details = _base_doc(ctx, kind, record_index, row)
    parts: list[str] = []
    walk_values(text, parts, set(), doc.text_cap, list_cap=doc.list_cap, cuts=doc.cuts)
    doc.body = parts
    doc.fields = _compact_fields(text)
    return doc


KIND_FLATTENERS: dict[str, Callable[[BuildContext, str, int, Mapping[str, object], Mapping[str, object]], Doc | list[Doc]]] = {
    "eventlog": flatten_eventlog,
    "windows-registry": flatten_registry,
    "windows-shellbags": flatten_paths,
    "recent-files": flatten_paths,
    "windows-execution": flatten_execution,
    "windows-prefetch": flatten_execution,
    "browser": flatten_browser,
    "generic-documents": flatten_documents,
    "kakaotalk-windows": flatten_messenger,
    "kakaotalk-macos": flatten_messenger,
    "windows-messenger": flatten_messenger,
    "email": flatten_messenger,
    "mobile-export": flatten_messenger,
    "media-image": flatten_media,
    "synthetic-media": flatten_media,
}


def flatten_artifact_row(
    ctx: BuildContext, kind: str, record_index: int, row: Mapping[str, object], text: Mapping[str, object] | None = None
) -> list[Doc]:
    """``text``: the detail values that feed ``search_doc.text`` (default: the row's details)."""
    if text is None:
        text = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    flattener = KIND_FLATTENERS.get(kind, flatten_generic)
    result = flattener(ctx, kind, record_index, row, text)
    return result if isinstance(result, list) else [result]


def flatten_file(ctx: BuildContext, scope: str, index: int, row: Mapping[str, object]) -> Doc:
    """Files candidate/inventory: path + name + hashes + categories/MIME."""
    raw_path = str(row.get("path") or "")
    doc = Doc(collection="files", locator=f"/{scope}/{index}", domain="filesystem", artifact_type=f"file-{scope}", path=raw_path)
    doc.title = str(row.get("name") or Path(raw_path.replace("\\", "/")).name)
    doc.size = _int_or_none(row.get("size"))
    doc.ts_text = record_time("files", row) or ""
    hashes = row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {}
    _collect_hashes({"hashes": hashes}, doc, include_source=False)
    signature = row.get("file_signature") if isinstance(row.get("file_signature"), Mapping) else {}
    recovery = row.get("recovery") if isinstance(row.get("recovery"), Mapping) else {}
    if signature.get("mismatch") is True:
        doc.sig_mismatch = 1
    deletion = str(row.get("deletion_state") or recovery.get("deletion_state") or "")
    if row.get("is_deleted") is True or deletion == "deleted":
        doc.deleted = 1
    categories = row.get("categories") if isinstance(row.get("categories"), list) else []
    parts = [doc.title, *(str(category) for category in categories)]
    for value in (signature.get("detected"), row.get("mime_type"), row.get("mime")):
        if isinstance(value, str) and value:
            parts.append(value)
    parts.extend(value for _alg, value in doc.hashes)
    doc.body = parts
    for key, label in (("fs_created_at", "created"), ("fs_modified_at", "modified"), ("fs_accessed_at", "accessed"), ("fs_changed_at", "changed")):
        millis = parse_ts_ms(row.get(key))
        if millis is not None:
            doc.times.append((millis, label, ()))
    doc.fields = {
        key: row.get(key)
        for key in ("name", "extension", "size", "deletion_state", "known_good_status", "time_origin")
        if row.get(key) not in (None, "")
    }
    if categories:
        doc.fields["categories"] = ", ".join(str(item) for item in categories)
    return doc


def flatten_doc(ctx: BuildContext, index: int, row: Mapping[str, object], body: str | None, *, body_cut: bool = False) -> Doc:
    """Document candidate: title + body (<= ``DOC_TEXT_MAX_CHARS``) + metadata (author, last saved by, template, company)."""
    raw_path = str(row.get("path") or "")
    doc = Doc(collection="docs", locator=f"/candidates/{index}", domain="media", artifact_type=f"document-{row.get('kind') or 'file'}", path=raw_path)
    doc.title = Path(raw_path.replace("\\", "/")).name
    doc.size = _int_or_none(row.get("size"))
    doc.ts_text = record_time("documents", row) or ""
    doc.text_cap = DOC_TEXT_MAX_CHARS
    if body_cut:
        doc.cuts["text-truncated:body"] += 1
    meta = ctx.doc_meta.get(os.path.normcase(raw_path), {})
    doc.body = [*(value for value in meta.values()), body or ""]
    for name, value in meta.items():
        doc.search_fields.append((name, fold(value), None))
    doc.fields = {key: row.get(key) for key in ("kind", "size", "text_status", "extraction_method", "text_length", "encrypted") if row.get(key) not in (None, "")}
    doc.fields.update(meta)
    if row.get("text_status") not in (None, "ok"):
        doc.fields["text_reason"] = str(row.get("text_reason") or "")[:256]
    return doc


def flatten_indicator(ctx: BuildContext, index: int, row: Mapping[str, object]) -> Doc:
    kind = str(row.get("type") or "indicator")
    value = str(row.get("value") or "")
    doc = Doc(collection="indicators", locator=f"/indicators/{index}", domain="incident", artifact_type=f"indicator-{kind}", title=f"{kind}: {value}"[:512])
    doc.ts_text = record_time("indicators", row) or ""
    flags = row.get("risk_flags") if isinstance(row.get("risk_flags"), list) else []
    doc.body = [value, kind, str(row.get("classification") or ""), *(str(flag) for flag in flags[:20])]
    if kind in {"md5", "sha1", "sha256"}:
        normalized = normalize_hash(value)
        if normalized is not None:
            doc.hashes.append(normalized)
    doc.fields = {"type": kind, "value": value[:256], "count": row.get("count"), "severity": row.get("severity") or "", "classification": row.get("classification") or ""}
    return doc


def flatten_analysis_row(ctx: BuildContext, analysis_id: str, analysis_kind: str, index: int, row: Mapping[str, object]) -> Doc:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    raw_path = str(row.get("path") or details.get("source_path") or details.get("path") or "")
    doc = Doc(
        collection="analysis",
        kind=analysis_id,
        locator=f"/rows/{index}",
        analysis_id=analysis_id,
        domain=ANALYSIS_DOMAINS.get(analysis_kind, "incident"),
        artifact_type=str(row.get("artifact_type") or f"{analysis_kind}-row"),
        path=raw_path,
    )
    doc.title = _first_text(details, ("path", "name", "file_name", "signature_kind", "indicator")) or Path(raw_path.replace("\\", "/")).name or doc.artifact_type
    doc.size = _int_or_none(details.get("size") if details.get("size") is not None else details.get("length"))
    if details.get("in_use") is False or details.get("status") == "deleted" or details.get("deleted") is True:
        doc.deleted = 1
    _collect_hashes(details, doc, include_source=False)
    parts: list[str] = []
    text = details.get("text")
    if isinstance(text, str) and text.strip():
        if len(text) > TEXT_MAX_CHARS // 2:
            doc.cuts["text-truncated:text"] += 1
        parts.append(text[: TEXT_MAX_CHARS // 2])
    doc.path2 = target_path(details)
    walk_values(details, parts, set(parts), doc.text_cap, skip=frozenset({"text"}), cuts=doc.cuts)
    doc.body = parts
    doc.times = _detail_times(details, None)
    doc.fields = _compact_fields(details)
    return doc


# ---------------------------------------------------------------------------
# readers
# ---------------------------------------------------------------------------


def iter_jsonl_rows(path: Path, *, limit: int | None = None) -> Iterator[tuple[int, dict[str, object] | None]]:
    """``(record_index, row)``: every ``{``-line takes one index (invalid JSON -> ``None``), like the API readers."""
    index = 0
    with open(path, "rb") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped.startswith(b"{"):
                continue
            if limit is not None and index >= limit:
                return
            try:
                row = json.loads(stripped)
            except ValueError:
                row = None
            yield index, row if isinstance(row, dict) else None
            index += 1


SMALL_TYPE_ROWS = 2000


def _varying_details(raw: Mapping[str, object], profiles: Mapping[str, object]) -> Mapping[str, object]:
    """The row's own detail values with low-cardinality codes resolved (no per-file context, no per-type template)."""
    details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
    profile = profiles.get(str(raw.get(PROFILE_REF_KEY) or ""))
    codes = profile.get("codes") if isinstance(profile, Mapping) else None
    if not isinstance(codes, Mapping):
        return details
    resolved = dict(details)
    for key, values in codes.items():
        index = resolved.get(key)
        if isinstance(index, int) and not isinstance(index, bool) and isinstance(values, list) and 0 <= index < len(values):
            resolved[key] = values[index]
    return resolved


def large_types(head: Mapping[str, object]) -> set[str]:
    """Artifact types of a kind output with more than ``SMALL_TYPE_ROWS`` rows (from its summary)."""
    summary = head.get("summary") if isinstance(head.get("summary"), Mapping) else {}
    type_counts = summary.get("artifact_type_counts") if isinstance(summary.get("artifact_type_counts"), Mapping) else {}
    return {str(name) for name, count in type_counts.items() if isinstance(count, int) and count > SMALL_TYPE_ROWS}


def iter_kind_output(path: Path) -> Iterator[tuple[int, dict[str, object] | None, Mapping[str, object] | None]]:
    """``(record_index, expanded row, text details)`` of one ``artifacts_<kind>`` output.

    ``text details`` is the row's varying part for artifact types with more
    than ``SMALL_TYPE_ROWS`` rows: per-type templates and per-file context
    repeat in every row (hive mount, channel family, parser boilerplate) and
    would only bloat the trigram index. Small types keep every value (a value
    shared by all five USB rows is still searchable).
    """
    head = read_artifact_output_head(path)
    profiles = head.get(PROFILES_PAYLOAD_KEY)
    profiles = profiles if isinstance(profiles, Mapping) else None
    large = large_types(head)
    if head.get("records_path") or head.get("records_file"):
        records = resolve_records_path(head, path)
        if records is None or not records.is_file():
            return
        rows: Iterable[tuple[int, dict[str, object] | None]] = iter_jsonl_rows(records)
    else:
        rows = ((index, row if isinstance(row, dict) else None) for index, row in enumerate(iter_array_items(path, "artifacts")))
    for index, row in rows:
        if row is None:
            yield index, None, None
            continue
        if profiles and row.get(PROFILE_REF_KEY):
            expanded = expand_profile(row, profiles, copy_templates=False)
            if str(row.get("artifact_type") or "") in large:
                yield index, expanded, _varying_details(row, profiles)
                continue
            yield index, expanded, expanded.get("details") if isinstance(expanded.get("details"), Mapping) else {}
            continue
        yield index, row, row.get("details") if isinstance(row.get("details"), Mapping) else {}


def load_timeline_times(
    timeline_path: Path | None, check_cancel: Callable[[], None], skipped: Counter[str] | None = None
) -> dict[tuple[str, int], list[tuple[int, str, tuple[str, ...]]]]:
    """``(output, row_index) -> [(ts_ms, timestamp_kind, labels)]`` from the timeline output (streamed)."""
    times: dict[tuple[str, int], list[tuple[int, str, tuple[str, ...]]]] = {}
    if timeline_path is None or not timeline_path.is_file():
        return times
    for position, event in enumerate(iter_array_items(timeline_path, "events")):
        if position % (CANCEL_EVERY_ROWS * 20) == 0:
            check_cancel()
        if not isinstance(event, dict):
            continue
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        source = details.get("source_record") if isinstance(details.get("source_record"), dict) else None
        if source is None or not isinstance(source.get("row_index"), int):
            continue
        millis = parse_ts_ms(event.get("timestamp"))
        if millis is None:
            continue
        labels = event.get("labels")
        label_tuple = tuple(str(item) for item in labels) if isinstance(labels, list) else ()
        bucket = times.setdefault((str(source.get("output") or ""), int(source["row_index"])), [])
        if len(bucket) < MAX_TIMES_PER_ROW:
            bucket.append((millis, str(event.get("timestamp_kind") or "event"), label_tuple))
        elif skipped is not None:
            skipped["times-capped"] += 1
    return times


def load_document_bodies(case_db: Path | None) -> dict[str, tuple[str, bool]]:
    """``normcase(path) -> (body, cut)`` from the run case DB ``indexed_document`` (read-only)."""
    bodies: dict[str, tuple[str, bool]] = {}
    if case_db is None or not case_db.is_file():
        return bodies
    try:
        connection = sqlite3.connect(f"{case_db.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error:
        return bodies
    try:
        rows = connection.execute(
            "SELECT f.path, substr(d.body, 1, ?), length(d.body) > ? FROM indexed_document d JOIN file_record f ON f.id = d.file_record_id "
            "WHERE d.source_type = 'document'",
            (DOC_TEXT_MAX_CHARS, DOC_TEXT_MAX_CHARS),
        )
        for path, body, cut in rows:
            if path and body:
                bodies.setdefault(os.path.normcase(str(path)), (str(body), bool(cut)))
    except sqlite3.Error as exc:
        LOGGER.warning("search index: document bodies unavailable from %s: %s", case_db, exc)
    finally:
        connection.close()
    return bodies


def extract_document_body(path: str, kind: str) -> tuple[str, bool] | None:
    """Fallback without a case DB: re-extract the text (bounded); ``(body, cut)``."""
    try:
        source = Path(path)
        if not source.is_file() or source.stat().st_size > DOC_BODY_MAX_FILE_BYTES:
            return None
        from ..docs import extract_text

        text = extract_text(source, kind)
        return text[:DOC_TEXT_MAX_CHARS], len(text) > DOC_TEXT_MAX_CHARS
    except Exception:  # extraction failures never stop the build
        return None


# ---------------------------------------------------------------------------
# writer
# ---------------------------------------------------------------------------

DOC_COLUMNS = (
    "doc_id, group_id, collection, kind, locator, analysis_id, domain, artifact_type, title, path, path_fold, path2, path2_fold, "
    "ext, size, ts, ts_kind, ts_text, ts_family, ts_labels, actor, actor_sid, computer, md5, sha1, sha256, text, text_fold, fields_json, deleted, "
    "sig_mismatch, in_archive, pii_count, truncated"
)
DOC_INSERT = f"INSERT INTO search_doc ({DOC_COLUMNS}) VALUES ({', '.join('?' for _ in DOC_COLUMNS.split(','))})"


class IndexWriter:
    """Assigns doc ids, expands per-time rows and batches inserts."""

    def __init__(self, connection: sqlite3.Connection, ctx: BuildContext, *, next_id: int = 1, fts_inline: bool = False) -> None:
        self.connection = connection
        self.ctx = ctx
        self.next_id = next_id
        self.fts_inline = fts_inline
        self.docs: list[tuple[object, ...]] = []
        self.fields: list[tuple[object, ...]] = []
        self.hashes: list[tuple[object, ...]] = []
        self.fts: list[tuple[int, str]] = []
        self.bigrams: list[tuple[int, str]] = []
        self.doc_count = 0
        self.row_count = 0
        self.text_bytes = 0
        self.by_domain: Counter[str] = Counter()

    def add(self, doc: Doc) -> None:
        display_path = self.ctx.evidence_path(doc.path)
        body = "\n".join(part for part in doc.body if part)
        if len(body) > doc.text_cap:
            body = body[: doc.text_cap]
            doc.cuts["text-truncated:body"] += 1
        text = nfc("\n".join(part for part in (doc.title, display_path if doc.text_path else "", body) if part))
        if len(text) > doc.text_cap + 1024:
            text = text[: doc.text_cap + 1024]
            doc.cuts["text-truncated:title"] += 1
        truncated = 1 if doc.cuts else 0
        for key, count in doc.cuts.items():
            reason, _sep, name = key.partition(":")
            self.ctx.skipped[reason] += count
            self.ctx.skipped_fields.setdefault(reason, Counter())[name] += count
        path2 = doc.path2.strip()
        path2_fold = target_path_key(path2) if path2 else ""
        fold_path = path_key(display_path)
        name = fold_path.rsplit("/", 1)[-1]
        ext = name.rsplit(".", 1)[-1] if "." in name and not name.startswith("!") else ""
        hashes = {alg: value for alg, value in doc.hashes}
        text_fold = stored_fold(text)
        content = text_fold if text_fold is not None else text  # what search_text / search_bigram index
        times = sorted(set(doc.times), key=lambda item: (item[0], item[1])) or [(None, "", ())]
        primary = self.next_id
        fields_json = json.dumps(doc.fields, ensure_ascii=False, default=str)[:FIELDS_MAX_CHARS] if doc.fields else "{}"
        for position, (millis, label, labels) in enumerate(times):
            doc_id = self.next_id
            self.next_id += 1
            extra = [item for item in labels if item != label]
            self.docs.append(
                (
                    doc_id,
                    primary,
                    doc.collection,
                    doc.kind,
                    doc.locator,
                    doc.analysis_id,
                    doc.domain,
                    doc.artifact_type,
                    nfc(doc.title)[:512],
                    display_path,
                    fold_path,
                    path2[:2048],
                    path2_fold[:2048],
                    ext[:16],
                    doc.size,
                    millis,
                    label,
                    doc.ts_text[:64] if position == 0 else "",
                    ts_family(label) if label else "",
                    ",".join(extra),
                    nfc(doc.actor)[:256],
                    doc.actor_sid[:128],
                    nfc(doc.computer)[:256],
                    hashes.get("md5", ""),
                    hashes.get("sha1", ""),
                    hashes.get("sha256", ""),
                    text if position == 0 else None,
                    text_fold if position == 0 else None,
                    fields_json if position == 0 else "{}",
                    doc.deleted,
                    doc.sig_mismatch,
                    doc.in_archive,
                    0,
                    truncated,
                )
            )
            self.row_count += 1
        if self.fts_inline:
            self.fts.append((primary, content))
        pairs = bigram_tokens(content)
        if pairs:
            self.bigrams.append((primary, pairs))
        self.fields.extend((primary, name, value, value_int) for name, value, value_int in doc.search_fields)
        self.hashes.extend((alg, value, primary) for alg, value in doc.hashes)
        self.doc_count += 1
        self.text_bytes += len(text.encode("utf-8"))
        self.by_domain[doc.domain] += 1
        if len(self.docs) >= BATCH_ROWS:
            self.flush()

    def flush(self) -> None:
        if self.docs:
            self.connection.executemany(DOC_INSERT, self.docs)
            self.docs.clear()
        if self.fields:
            self.connection.executemany("INSERT INTO search_field(doc_id, name, value_fold, value_int) VALUES (?, ?, ?, ?)", self.fields)
            self.fields.clear()
        if self.hashes:
            self.connection.executemany("INSERT INTO search_hash(algorithm, value, doc_id) VALUES (?, ?, ?)", self.hashes)
            self.hashes.clear()
        if self.fts:
            self.connection.executemany("INSERT INTO search_text(rowid, text) VALUES (?, ?)", self.fts)
            self.fts.clear()
        if self.bigrams:
            self.connection.executemany("INSERT INTO search_bigram(rowid, g) VALUES (?, ?)", self.bigrams)
            self.bigrams.clear()


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


class BuildCancelled(Exception):
    pass


@dataclass
class BuildHooks:
    """Progress/cancel callbacks of a build (the analysis runner adapts its context)."""

    set_total: Callable[[int], None] = lambda total: None
    advance: Callable[[str], None] = lambda message: None
    check_cancel: Callable[[], None] = lambda: None


def default_domain_of(kind: str, artifact_type: str) -> str:
    from ..artifact_domains import artifact_type_domain

    return artifact_type_domain(kind, artifact_type)


def run_outputs(summary: Mapping[str, object]) -> dict[str, Path]:
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    return {str(name): Path(str(value)) for name, value in outputs.items() if isinstance(value, str) and value}


def source_signature(path: Path) -> list[int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return [int(stat.st_size), int(stat.st_mtime_ns)]


def summary_sha256(summary: Mapping[str, object]) -> str:
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    return hashlib.sha256(json.dumps(outputs, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def indexable_analyses(output_dir: Path, load_state: Callable[[Path, str], Mapping[str, object] | None] | None = None) -> list[dict[str, object]]:
    """Finished analyses with rows (not ``search-index`` itself), oldest first."""
    root = Path(output_dir) / "analyses"
    found: list[dict[str, object]] = []
    try:
        children = sorted(child for child in root.iterdir() if child.is_dir() and ANALYSIS_ID_RE.fullmatch(child.name))
    except OSError:
        return found
    for child in children:
        state: Mapping[str, object] | None
        if load_state is not None:
            state = load_state(Path(output_dir), child.name)
        else:
            try:
                state = json.loads((child / "analysis.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                state = None
        if not isinstance(state, Mapping) or state.get("kind") == SEARCH_INDEX_KIND:
            continue
        if state.get("status") not in ("completed", "cancelled", "failed"):
            continue
        row_count = int(state.get("row_count") or 0)
        found.append({"analysis_id": child.name, "kind": str(state.get("kind") or ""), "row_count": row_count, "status": state.get("status")})
    return found


def _registry_offset(row: Mapping[str, object]) -> dt.timedelta | None:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    minutes = details.get("utc_offset_minutes")
    if isinstance(minutes, int) and not isinstance(minutes, bool) and abs(minutes) <= 14 * 60:
        return dt.timedelta(minutes=minutes)
    return parse_offset(details.get("utc_offset"))


def _timeline_offset(path: Path | None) -> dt.timedelta | None:
    if path is None or not path.is_file():
        return None
    try:
        from ..json_stream import read_member

        summary = read_member(path, "summary")
    except (JsonStreamError, OSError, ValueError, KeyError):
        return None
    evidence = summary.get("timezone", {}).get("evidence_timezone") if isinstance(summary, Mapping) and isinstance(summary.get("timezone"), Mapping) else None
    if isinstance(evidence, Mapping) and isinstance(evidence.get("bias_minutes"), int):
        return dt.timedelta(minutes=-int(evidence["bias_minutes"]))
    return None


def _write_kind(writer: IndexWriter, ctx: BuildContext, kind: str, path: Path, hooks: BuildHooks, sources: dict[str, object]) -> None:
    head_signature = source_signature(path)
    if head_signature is None:
        ctx.skipped["missing-output"] += 1
        return
    sources[str(path)] = head_signature
    try:
        large = large_types(read_artifact_output_head(path))
    except (JsonStreamError, OSError, ValueError):
        large = set()
    count = 0
    for record_index, row, text in iter_kind_output(path):
        count += 1
        if count % CANCEL_EVERY_ROWS == 0:
            hooks.check_cancel()
        if row is None:
            ctx.skipped["invalid-record"] += 1
            continue
        if kind == "windows-registry" and ctx.tz_offset is None and row.get("artifact_type") == "windows-timezone":
            ctx.tz_offset = _registry_offset(row)
        if str(row.get("artifact_type") or "") in large:
            ctx.row_text_cap, ctx.row_list_cap = ARTIFACT_TEXT_MAX_CHARS, LIST_MAX_ITEMS
        else:
            ctx.row_text_cap, ctx.row_list_cap = SMALL_TYPE_TEXT_MAX_CHARS, SMALL_TYPE_LIST_MAX_ITEMS
        for doc in flatten_artifact_row(ctx, kind, record_index, row, text):
            writer.add(doc)
    try:
        head = read_artifact_output_head(path)
        records = resolve_records_path(head, path)
        if records is not None:
            signature = source_signature(records)
            if signature is not None:
                sources[str(records)] = signature
    except (JsonStreamError, OSError, ValueError):
        pass


def _write_analysis(writer: IndexWriter, ctx: BuildContext, analysis: Mapping[str, object], hooks: BuildHooks) -> int:
    analysis_id = str(analysis["analysis_id"])
    rows_path = ctx.output_dir / "analyses" / analysis_id / "rows.jsonl"
    if not rows_path.is_file():
        return 0
    written = 0
    for index, row in iter_jsonl_rows(rows_path, limit=int(analysis.get("row_count") or 0)):
        if index % CANCEL_EVERY_ROWS == 0:
            hooks.check_cancel()
        if row is None:
            ctx.skipped["invalid-record"] += 1
            continue
        writer.add(flatten_analysis_row(ctx, analysis_id, str(analysis.get("kind") or ""), index, row))
        written += 1
    return written


def _collect_doc_meta(ctx: BuildContext, path: Path | None, hooks: BuildHooks) -> None:
    if path is None or not path.is_file():
        return
    for position, (_index, row, _text) in enumerate(iter_kind_output(path)):
        if position % CANCEL_EVERY_ROWS == 0:
            hooks.check_cancel()
        if row is None or row.get("artifact_type") != "document-metadata-risk":
            continue
        details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
        meta = document_meta(details)
        source = str(details.get("source_path") or row.get("path") or "")
        if meta and source:
            ctx.doc_meta.setdefault(os.path.normcase(source), meta)


def build_search_index(
    output_dir: Path,
    summary: Mapping[str, object],
    *,
    run_id: str = "",
    index_path: Path | None = None,
    mode: str = "full",
    analysis_ids: Iterable[str] | None = None,
    hooks: BuildHooks | None = None,
    domain_of: Callable[[str, str], str] | None = None,
    case_db: Path | None = None,
    load_state: Callable[[Path, str], Mapping[str, object] | None] | None = None,
) -> dict[str, object]:
    """Build (``full``) or update (``incremental``) the index; return the build summary.

    ``summary`` is the run summary (its ``outputs`` name the files read).
    Raises :class:`BuildCancelled` when ``hooks.check_cancel`` raises it, and
    re-raises whatever else ``check_cancel`` raises (the analysis runner's
    ``AnalysisCancelled``); a cancelled full build removes its ``.building`` file.
    """
    hooks = hooks or BuildHooks()
    started = time.monotonic()
    output_dir = Path(output_dir)
    target = Path(index_path) if index_path is not None else output_dir / INDEX_FILE_NAME
    if mode == "incremental":
        if not target.is_file() or (index_meta(target) or {}).get("index_version") != INDEX_VERSION:
            mode = "full"  # nothing (or an older format) to update: build everything
        else:
            return _build_incremental(output_dir, summary, target, list(analysis_ids or []), hooks, domain_of or default_domain_of, started, load_state)
    if mode != "full":
        raise ValueError(f"unknown search index build mode: {mode}")
    outputs = run_outputs(summary)
    tokenizer = detect_tokenizer()
    building = target.with_name(target.name + BUILDING_SUFFIX)
    target.parent.mkdir(parents=True, exist_ok=True)
    building.unlink(missing_ok=True)
    kinds = sorted(name for name in outputs if name.startswith("artifacts_"))
    analyses = indexable_analyses(output_dir, load_state)
    units = 1 + 1 + 1 + len(kinds) + 1 + len(analyses)  # timeline, docs, files, kinds, indicators, analyses
    hooks.set_total(units)
    timeline_path = outputs.get("timeline")
    skipped: Counter[str] = Counter()
    timeline = load_timeline_times(timeline_path, hooks.check_cancel, skipped)
    hooks.advance("타임라인 시각을 읽었습니다")
    ctx = BuildContext(output_dir=output_dir, roots=_evidence_roots(summary), domain_of=domain_of or default_domain_of, timeline=timeline, skipped=skipped)
    sources: dict[str, object] = {}
    if timeline_path is not None and timeline_path.is_file():
        sources[str(timeline_path)] = source_signature(timeline_path)
    connection = open_writable(building, bulk=True)
    try:
        create_schema(connection, tokenizer, with_indexes=False)
        writer = IndexWriter(connection, ctx)
        connection.execute("BEGIN")
        # documents first (index order = relevance order): bodies from the case DB.
        _collect_doc_meta(ctx, outputs.get("artifacts_generic-documents"), hooks)
        docs_path = outputs.get("docs")
        if docs_path is not None and docs_path.is_file():
            sources[str(docs_path)] = source_signature(docs_path)
            bodies = load_document_bodies(case_db if case_db is not None else output_dir / "rapidtriage-case.db")
            for index, row in enumerate(iter_array_items(docs_path, "candidates")):
                if index % CANCEL_EVERY_ROWS == 0:
                    hooks.check_cancel()
                if not isinstance(row, dict):
                    ctx.skipped["invalid-record"] += 1
                    continue
                path = str(row.get("path") or "")
                loaded = bodies.get(os.path.normcase(path))
                if loaded is None and row.get("text_status") == "ok":
                    loaded = extract_document_body(path, str(row.get("kind") or ""))
                    if loaded is None:
                        ctx.skipped["doc-body-unavailable"] += 1
                body, body_cut = loaded if loaded is not None else (None, False)
                writer.add(flatten_doc(ctx, index, row, body, body_cut=body_cut))
        hooks.advance("문서를 색인했습니다")
        files_path = outputs.get("files")
        if files_path is not None and files_path.is_file():
            sources[str(files_path)] = source_signature(files_path)
            for scope, member in (("candidates", "candidates"), ("inventory", "inventory")):
                for index, row in enumerate(iter_array_items(files_path, member)):
                    if index % CANCEL_EVERY_ROWS == 0:
                        hooks.check_cancel()
                    if isinstance(row, dict):
                        writer.add(flatten_file(ctx, scope, index, row))
        hooks.advance("파일 목록을 색인했습니다")
        for name in kinds:
            kind = name.removeprefix("artifacts_")
            _write_kind(writer, ctx, kind, outputs[name], hooks, sources)
            writer.flush()
            hooks.advance(f"{kind} 아티팩트를 색인했습니다")
        indicators_path = outputs.get("indicators")
        if indicators_path is not None and indicators_path.is_file():
            sources[str(indicators_path)] = source_signature(indicators_path)
            for index, row in enumerate(iter_array_items(indicators_path, "indicators")):
                if index % CANCEL_EVERY_ROWS == 0:
                    hooks.check_cancel()
                if isinstance(row, dict):
                    writer.add(flatten_indicator(ctx, index, row))
        hooks.advance("지표 후보를 색인했습니다")
        indexed: list[dict[str, object]] = []
        for analysis in analyses:
            written = _write_analysis(writer, ctx, analysis, hooks)
            indexed.append({**analysis, "doc_count": written})
            hooks.advance(f"분석 {analysis['analysis_id']} 결과를 색인했습니다")
        writer.flush()
        hooks.check_cancel()
        create_indexes(connection)
        connection.execute("INSERT INTO search_text(search_text) VALUES ('rebuild')")
        tz = ctx.tz_offset if ctx.tz_offset is not None else _timeline_offset(timeline_path)
        build_id = uuid.uuid4().hex[:16]
        built_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        build_summary: dict[str, object] = {
            "doc_count": writer.doc_count,
            "row_count": writer.row_count,
            "by_domain": dict(sorted(writer.by_domain.items())),
            "text_bytes": writer.text_bytes,
            "skipped": dict(ctx.skipped),
            "skipped_fields": skipped_fields_payload(ctx.skipped_fields),
            "truncated_by_domain": truncated_by_domain(connection),
            "truncated_by_collection": truncated_by_collection(connection),
            "tokenizer": tokenizer,
        }
        write_meta(
            connection,
            {
                "index_version": INDEX_VERSION,
                "flatten_version": FLATTEN_VERSION,
                "build_id": build_id,
                "built_at": built_at,
                "run_id": run_id,
                "output_dir": str(output_dir),
                "source_summary_sha256": summary_sha256(summary),
                "sources": sources,
                "tz": format_offset(tz) if tz is not None else "",
                "tz_source": "registry" if ctx.tz_offset is not None else ("timeline" if tz is not None else ""),
                "tokenizer": tokenizer,
                "bigram": BIGRAM_RULE,
                "fold": FOLD_RULE,
                "analyses_indexed": indexed,
                "summary": build_summary,
            },
        )
        connection.commit()
        connection.execute("ANALYZE")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.commit()
    except BaseException:
        connection.close()
        building.unlink(missing_ok=True)
        raise
    connection.close()
    build_summary.update({"elapsed_s": round(time.monotonic() - started, 3), "build_id": build_id, "mode": "full"})
    try:
        replace_index(building, target)
    except OSError as exc:
        # The old index stays (readers keep working); the new one is dropped, never left half-swapped.
        building.unlink(missing_ok=True)
        reason = f"새 색인으로 바꾸지 못했습니다(읽는 중인 검색이 {SWAP_WAIT_SECONDS:g}초 넘게 색인을 붙잡고 있음: {exc.__class__.__name__}). 이전 색인을 그대로 씁니다"
        build_summary.update({"status": SWAP_FAILED_STATUS, "swap_error": reason})
        raise IndexSwapFailed(reason, build_summary) from exc
    build_summary.update({"db_bytes": target.stat().st_size, "status": "ready"})
    return build_summary


SWAP_FAILED_STATUS = "build-failed-swap"


class IndexSwapFailed(RuntimeError):
    """The new index could not replace the old one (readers held it past ``SWAP_WAIT_SECONDS``)."""

    def __init__(self, reason: str, summary: dict[str, object]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.summary = summary


def replace_index(building: Path, target: Path, *, wait_seconds: float | None = None) -> None:
    """``os.replace`` with retries and backoff (Windows refuses while a reader holds the old file).

    Waits up to ``wait_seconds`` (default ``SWAP_WAIT_SECONDS`` = query budget + grace + 5 s:
    a reader opens the index per query and lets go within that); the last error is raised.
    """
    limit = SWAP_WAIT_SECONDS if wait_seconds is None else wait_seconds
    deadline = time.monotonic() + limit
    delay = 0.05
    while True:
        try:
            os.replace(building, target)
            return
        except PermissionError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 1.0)


def skipped_fields_payload(fields: Mapping[str, Counter[str]]) -> dict[str, dict[str, int]]:
    """``{reason: {field: count}}`` (top ``SKIPPED_FIELDS_MAX`` fields per reason)."""
    return {reason: dict(counter.most_common(SKIPPED_FIELDS_MAX)) for reason, counter in sorted(fields.items())}


def merge_skipped_fields(previous: object, current: Mapping[str, Counter[str]]) -> dict[str, dict[str, int]]:
    merged: dict[str, Counter[str]] = {}
    if isinstance(previous, Mapping):
        for reason, fields in previous.items():
            if isinstance(fields, Mapping):
                merged[str(reason)] = Counter({str(name): int(count) for name, count in fields.items() if isinstance(count, int)})
    for reason, counter in current.items():
        merged.setdefault(reason, Counter()).update(counter)
    return skipped_fields_payload(merged)


def truncated_by_domain(connection: sqlite3.Connection) -> dict[str, int]:
    """Primary rows cut at a cap, per domain (the query warns when matched domains have some)."""
    return {
        str(domain): int(count)
        for domain, count in connection.execute(
            "SELECT domain, COUNT(*) FROM search_doc WHERE truncated = 1 AND doc_id = group_id GROUP BY domain ORDER BY domain"
        )
    }


def truncated_by_collection(connection: sqlite3.Connection) -> dict[str, int]:
    """Primary rows cut at a cap, per collection (``docs``/``files``/``artifacts``/...): the query
    warning names them per search source."""
    return {
        str(collection): int(count)
        for collection, count in connection.execute(
            "SELECT collection, COUNT(*) FROM search_doc WHERE truncated = 1 AND doc_id = group_id GROUP BY collection ORDER BY collection"
        )
    }


def _build_incremental(
    output_dir: Path,
    summary: Mapping[str, object],
    target: Path,
    analysis_ids: list[str],
    hooks: BuildHooks,
    domain_of: Callable[[str, str], str],
    started: float,
    load_state: Callable[[Path, str], Mapping[str, object] | None] | None,
) -> dict[str, object]:
    """Replace the rows of ``analysis_ids`` (all finished analyses when empty) in place."""
    available = {item["analysis_id"]: item for item in indexable_analyses(output_dir, load_state)}
    wanted = [analysis_id for analysis_id in (analysis_ids or list(available)) if ANALYSIS_ID_RE.fullmatch(str(analysis_id))]
    hooks.set_total(len(wanted))
    connection = open_writable(target, bulk=False)
    try:
        meta = read_meta(connection)
        ctx = BuildContext(output_dir=output_dir, roots=_evidence_roots(summary), domain_of=domain_of, timeline={})
        row = connection.execute("SELECT COALESCE(MAX(doc_id), 0) FROM search_doc").fetchone()
        writer = IndexWriter(connection, ctx, next_id=int(row[0]) + 1, fts_inline=True)
        try:
            indexed = json.loads(meta.get("analyses_indexed") or "[]")
        except ValueError:
            indexed = []
        indexed = [item for item in indexed if isinstance(item, dict) and item.get("analysis_id") not in wanted]
        connection.execute("BEGIN IMMEDIATE")
        for analysis_id in wanted:
            hooks.check_cancel()
            removed = connection.execute(
                "SELECT doc_id, COALESCE(text_fold, text) FROM search_doc WHERE analysis_id = ? AND text IS NOT NULL", (analysis_id,)
            ).fetchall()
            connection.executemany(
                "INSERT INTO search_text(search_text, rowid, text) VALUES ('delete', ?, ?)", [(item[0], item[1]) for item in removed]
            )
            # Contentless: a delete names the row's tokens again (the same pairs the writer added).
            connection.executemany(
                "INSERT INTO search_bigram(search_bigram, rowid, g) VALUES ('delete', ?, ?)",
                [(item[0], pairs) for item in removed if (pairs := bigram_tokens(str(item[1])))],
            )
            connection.execute("DELETE FROM search_field WHERE doc_id IN (SELECT doc_id FROM search_doc WHERE analysis_id = ?)", (analysis_id,))
            connection.execute("DELETE FROM search_hash WHERE doc_id IN (SELECT doc_id FROM search_doc WHERE analysis_id = ?)", (analysis_id,))
            connection.execute("DELETE FROM search_doc WHERE analysis_id = ?", (analysis_id,))
            analysis = available.get(analysis_id)
            if analysis is not None:
                written = _write_analysis(writer, ctx, analysis, hooks)
                writer.flush()
                indexed.append({**analysis, "doc_count": written})
            hooks.advance(f"분석 {analysis_id} 결과를 색인했습니다")
        counts = Counter({str(domain): int(count) for domain, count in connection.execute("SELECT domain, COUNT(*) FROM search_doc WHERE doc_id = group_id GROUP BY domain")})
        try:
            previous = json.loads(meta.get("summary") or "{}")
        except ValueError:
            previous = {}
        previous = previous if isinstance(previous, dict) else {}
        skipped = Counter({str(key): int(value) for key, value in (previous.get("skipped") or {}).items() if isinstance(value, int)})
        skipped.update(ctx.skipped)
        build_summary = {
            **previous,
            "doc_count": sum(counts.values()),
            "by_domain": dict(sorted(counts.items())),
            "skipped": dict(skipped),
            "skipped_fields": merge_skipped_fields(previous.get("skipped_fields"), ctx.skipped_fields),
            "truncated_by_domain": truncated_by_domain(connection),
            "truncated_by_collection": truncated_by_collection(connection),
            "tokenizer": meta.get("tokenizer") or "",
        }
        build_summary["row_count"] = int(connection.execute("SELECT COUNT(*) FROM search_doc").fetchone()[0])
        write_meta(
            connection,
            {
                "analyses_indexed": indexed,
                "summary": build_summary,
                "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            },
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        connection.close()
        raise
    connection.close()
    build_summary.update(
        {
            "db_bytes": target.stat().st_size,
            "elapsed_s": round(time.monotonic() - started, 3),
            "build_id": meta.get("build_id") or "",
            "mode": "incremental",
            "analysis_ids": wanted,
        }
    )
    return build_summary


# ---------------------------------------------------------------------------
# status / staleness
# ---------------------------------------------------------------------------


META_READ_ATTEMPTS = 3
META_RETRY_SECONDS = 0.2


def read_index_meta(index_path: Path, *, attempts: int = META_READ_ATTEMPTS) -> tuple[dict[str, object] | None, str | None]:
    """``(meta, None)``, ``(None, None)`` without an index, ``(None, reason)`` for an unreadable (corrupt) one.

    A short lock (an incremental commit, a swap in progress) is retried ``attempts`` times
    so readers never report "no index" for a moment.
    """
    reason: str | None = None
    for attempt in range(max(1, attempts)):
        if not index_path.is_file():
            if attempt == 0:
                return None, None
            reason = "색인 파일이 교체되는 중입니다"
        else:
            try:
                connection = open_read_only(index_path)
                try:
                    raw = {str(row[0]): str(row[1]) for row in connection.execute("SELECT key, value FROM search_meta")}
                finally:
                    connection.close()
            except sqlite3.OperationalError as exc:
                reason = _meta_error(exc)
            except sqlite3.DatabaseError as exc:
                return None, _meta_error(exc)
            else:
                if raw.get("build_id"):
                    return _decode_meta(raw), None
                reason = "색인 메타데이터가 없습니다(빌드가 끝나지 않은 파일)"
        if attempt + 1 < attempts:
            time.sleep(META_RETRY_SECONDS * (attempt + 1))
    return None, reason


def _meta_error(exc: sqlite3.Error) -> str:
    text = str(exc).lower()
    if "locked" in text or "busy" in text:
        return "색인이 잠겨 있습니다(다른 작업이 쓰는 중)"
    if "no such table" in text:
        return "검색 색인 파일이 아닙니다(search_meta 없음)"
    return f"색인 파일을 읽을 수 없습니다(손상): {exc}"


def index_meta(index_path: Path, *, attempts: int = META_READ_ATTEMPTS) -> dict[str, object] | None:
    """Decoded ``search_meta`` of an index, or ``None`` when there is none (or it is unreadable)."""
    meta, _reason = read_index_meta(index_path, attempts=attempts)
    return meta


def _decode_meta(raw: Mapping[str, str]) -> dict[str, object]:
    meta: dict[str, object] = {}
    for key, value in raw.items():
        if key in {"sources", "analyses_indexed", "summary"}:
            try:
                meta[key] = json.loads(value)
            except ValueError:
                meta[key] = None
        else:
            meta[key] = value
    return meta


def stale_reasons(meta: Mapping[str, object], summary: Mapping[str, object], output_dir: Path, load_state: Callable[[Path, str], Mapping[str, object] | None] | None = None) -> list[str]:
    """Korean reasons the index no longer matches the run outputs (empty: fresh)."""
    reasons: list[str] = []
    if meta.get("index_version") == "search-index-v2" and meta.get("flatten_version") == FLATTEN_VERSION:
        reasons.append("2자 한글 검색용 색인(bigram)이 없는 이전 형식입니다. 색인을 다시 만드세요")
    elif meta.get("index_version") == "search-index-v3" and meta.get("flatten_version") == FLATTEN_VERSION:
        reasons.append(
            "이전 형식 색인입니다: 영문 외 대소문자(É·Ａ·Σ·ß 등)를 구분 없이 찾지 못하고 파일·문서 적중 시각이 비어 있습니다. 색인을 다시 만드세요"
        )
    elif meta.get("index_version") != INDEX_VERSION or meta.get("flatten_version") != FLATTEN_VERSION:
        reasons.append("색인 형식이 바뀌었습니다. 다시 만드세요")
    if meta.get("source_summary_sha256") != summary_sha256(summary):
        reasons.append("런 출력 목록이 바뀌었습니다")
    sources = meta.get("sources") if isinstance(meta.get("sources"), Mapping) else {}
    changed = [name for name, signature in sources.items() if source_signature(Path(name)) != signature]
    if changed:
        reasons.append(f"색인한 뒤 바뀐 출력 파일이 있습니다({len(changed)}개)")
    indexed = {
        str(item.get("analysis_id")): int(item.get("row_count") or 0)
        for item in (meta.get("analyses_indexed") or [])
        if isinstance(item, Mapping)
    }
    missing = [item for item in indexable_analyses(output_dir, load_state) if indexed.get(str(item["analysis_id"])) != int(item["row_count"])]
    if missing:
        reasons.append(f"색인에 없는 분석 결과가 있습니다({len(missing)}개)")
    return reasons
