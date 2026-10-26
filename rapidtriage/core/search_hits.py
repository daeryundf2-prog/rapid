"""Display fields and review locator of one unified-search hit.

Both search backends (case-DB FTS and output scan) produce raw matches whose
``metadata`` is the whole source record. The console grid needs a readable row
instead: a title, the path without the acquisition root, the record's own time,
a short highlighted snippet (never the serialized record), and a locator the
case DB can resolve to the source row for review marks.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from pathlib import PureWindowsPath

from .textnorm import locate_normalized, normalize_nfc, normalize_search_text

SNIPPET_LIMIT = 200
SNIPPET_LEAD = 40
TITLE_LIMIT = 160
# Leaves walked per record when looking for the match context (a browser
# history summary row nests thousands of values).
SNIPPET_LEAF_BUDGET = 20_000

# Record members that are envelope/profile bookkeeping, not evidence text.
_SKIPPED_KEYS = frozenset(
    {
        "artifact_record",
        "source_locator",
        "commercial_grade_blockers",
        "commercial_grade_ready",
        "commercial_uplift_evidence",
        "core_accuracy_gates",
        "legal_limitations",
        "validation_required",
        "hashes",
        "source_hashes",
    }
)

# Evidence-time members, most specific first (details, then the record).
_TIME_KEYS = (
    "timestamp",
    "event_time",
    "time_created",
    "last_visited_at",
    "visit_time",
    "last_run_time",
    "last_run",
    "last_modified",
    "modified_at",
    "last_written_at",
    "created_at",
    "started_at",
    "last_accessed_at",
    "accessed_at",
    "last_updated_at",
    "last_seen_at",
    "first_seen_at",
    "date",
)

_ORDINAL_POINTER = re.compile(r"^/([a-z_]+)/(\d+)$")
_WHITESPACE = re.compile(r"\s+")


def scan_root_of(summary: Mapping[str, object]) -> str:
    """The run's acquisition root (what every evidence path starts with), or ""."""
    source = summary.get("source") if isinstance(summary.get("source"), Mapping) else {}
    for value in (
        summary.get("scan_scope_root"),
        source.get("analysis_root") if isinstance(source, Mapping) else None,
        summary.get("root"),
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def display_path(path: str, root: str) -> str:
    """``path`` without the acquisition ``root`` (case-insensitive, either slash)."""
    if not path:
        return ""
    base = root.rstrip("\\/")
    if base and path.rstrip("\\/").replace("/", "\\").casefold() == base.replace("/", "\\").casefold():
        # The acquisition root itself (a whole-source artifact): its folder name.
        return PureWindowsPath(base).name or path
    if base and len(path) > len(base):
        head = path[: len(base)].replace("/", "\\").casefold()
        if head == base.replace("/", "\\").casefold() and path[len(base)] in "\\/":
            return path[len(base) + 1 :]
    return path


def _clean(text: str) -> str:
    return _WHITESPACE.sub(" ", normalize_nfc(text)).strip()


def _compact(text: str, limit: int) -> str:
    text = _clean(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _iter_leaves(value: object, key: str = "", budget: list[int] | None = None) -> Iterator[tuple[str, str]]:
    budget = budget if budget is not None else [SNIPPET_LEAF_BUDGET]
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if budget[0] <= 0:
                return
            if str(child_key) in _SKIPPED_KEYS:
                continue
            yield from _iter_leaves(child, str(child_key), budget)
    elif isinstance(value, (list, tuple)):
        for child in value:
            if budget[0] <= 0:
                return
            yield from _iter_leaves(child, key, budget)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        budget[0] -= 1
        text = str(value)
        if text.strip():
            yield key, text


def _highlights(snippet: str, keywords: Sequence[str]) -> list[list[int]]:
    spans: list[list[int]] = []
    for keyword in keywords:
        offset = 0
        while offset < len(snippet):
            located = locate_normalized(snippet[offset:], keyword)
            if located is None:
                break
            _display, start, end = located
            if end <= start:
                break
            spans.append([offset + start, offset + end])
            offset += end
    spans.sort()
    merged: list[list[int]] = []
    for span in spans:
        if merged and span[0] <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], span[1])
        else:
            merged.append(span)
    return merged


def _window(text: str, start: int, end: int, limit: int) -> str:
    """At most ``limit`` characters of ``text`` from shortly before ``[start, end)``, with ellipses.

    The lead-in is at most ``SNIPPET_LEAD`` characters so the match stays visible in a
    narrow grid cell; the rest of the room goes to the text after the match.
    """
    if len(text) <= limit and start <= SNIPPET_LEAD:
        return text
    avail = limit - 2  # room for the two ellipses
    lo = max(0, start - SNIPPET_LEAD) if end - start < avail else start
    hi = min(len(text), lo + avail)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return prefix + text[lo:hi] + suffix


def search_snippet(source: object, keywords: Sequence[str], *, limit: int = SNIPPET_LIMIT) -> tuple[str, list[list[int]]]:
    """``(snippet, highlight spans)``: the first match in ``source`` (text or a record).

    A record is read leaf by leaf (``key: value``); the envelope and profile
    members are skipped, so the snippet is evidence text, never the JSON.
    Without a literal match (regex/fuzzy hits) the start of the text is used.
    """
    candidates: Iterator[str]
    folded_keywords = [normalize_search_text(keyword) for keyword in keywords]
    # Keywords without whitespace match a leaf's cleaned text iff they match its folded raw
    # text (cleaning only collapses whitespace): leaves without any are skipped before the
    # whitespace clean-up and the offset mapping (R7: a record walks thousands of leaves).
    prefilter = bool(folded_keywords) and all(word and not any(ch.isspace() for ch in word) for word in folded_keywords)
    if isinstance(source, str):
        candidates = iter((_clean(source),))
    else:
        candidates = (f"{key}: {text}" if key else text for key, text in _iter_leaves(source))
    first = ""
    for raw in candidates:
        if prefilter and not isinstance(source, str):
            if not any(word in normalize_search_text(raw) for word in folded_keywords):
                if not first:
                    first = _clean(raw)
                continue
        candidate = raw if isinstance(source, str) else _clean(raw)
        if not candidate:
            continue
        first = first or candidate
        for keyword in keywords:
            located = locate_normalized(candidate, keyword)
            if located is None:
                continue
            display, start, end = located
            snippet = _window(display, start, end, limit)
            return snippet, _highlights(snippet, keywords)
    snippet = _window(first, 0, 0, limit) if first else ""
    return snippet, _highlights(snippet, keywords)


def _first_time(record: Mapping[str, object]) -> str | None:
    for key in _TIME_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def hit_timestamp(match: Mapping[str, object]) -> str | None:
    """The record's own time: details first, then the record (event/file time)."""
    for value in (match.get("timestamp"),):
        if isinstance(value, str) and value.strip():
            return value.strip()
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    details = metadata.get("details") if isinstance(metadata.get("details"), Mapping) else {}
    return _first_time(details) or _first_time(metadata)


def _artifact_title(record: Mapping[str, object]) -> str:
    from .case_db.helpers import artifact_summary

    try:
        summary = artifact_summary(record)
    except Exception:  # title is best effort; the row keeps its fallback
        summary = ""
    path = str(record.get("path") or "")
    if summary and summary not in {path, str(record.get("artifact_type") or "")}:
        return summary
    return PureWindowsPath(path).name if path else ""


def _artifact_type(match: Mapping[str, object]) -> str:
    metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
    envelope = metadata.get("artifact_record") if isinstance(metadata.get("artifact_record"), Mapping) else {}
    for value in (metadata.get("artifact_type"), envelope.get("artifact_type")):
        if isinstance(value, str) and value:
            return value
    return ""


def hit_locator(match: Mapping[str, object]) -> dict[str, object] | None:
    """Case-DB review locator: ``{collection, kind, pointer, record_index, output_index, ...}``.

    ``collection``/``kind``/``pointer`` are what ``POST /api/case-db/review-batch``
    resolves (``RunLocatorIndex``); ``record_index`` (= ``output_index``) is the
    row's position in ``output_name``. ``None`` when the hit has no source row.
    """
    source = str(match.get("source") or "")
    kind = str(match.get("kind") or "")
    pointer = str(match.get("pointer") or "")
    candidate_index = match.get("candidate_index")
    if source == "documents" and isinstance(candidate_index, int) and candidate_index >= 0:
        # docs.json `candidates` lists every document (the review locator); `/results/<n>`
        # only exists for docs-index keyword hits.
        return {
            "collection": "docs",
            "kind": "",
            "pointer": f"/candidates/{candidate_index}",
            "record_index": candidate_index,
            "output_name": "docs",
            "output_index": candidate_index,
        }
    parsed = _ORDINAL_POINTER.match(pointer)
    if parsed is None:
        return None
    member, ordinal = parsed.group(1), int(parsed.group(2))
    locator: dict[str, object] = {"pointer": pointer, "record_index": ordinal, "output_index": ordinal}
    if member == "candidates" and source in {"files", "ocr"}:
        locator.update(collection="files", kind="", output_name="files")
    elif member == "results" and source == "documents":
        locator.update(collection="docs", kind="", output_name="docs")
    elif member == "events":
        locator.update(collection="timeline", kind="", output_name="timeline")
    elif member in {"indicators", "ioc_scanner_hits"}:
        locator.update(collection="indicators", kind="", output_name="indicators")
    elif member == "artifacts" and kind:
        locator.update(collection="artifacts", kind=kind, output_name=f"artifacts_{kind}")
        metadata = match.get("metadata") if isinstance(match.get("metadata"), Mapping) else {}
        envelope = metadata.get("artifact_record") if isinstance(metadata.get("artifact_record"), Mapping) else {}
        if isinstance(envelope.get("artifact_id"), str) and envelope.get("artifact_id"):
            locator["artifact_id"] = envelope["artifact_id"]
    else:
        return None
    return {"collection": locator.pop("collection"), "kind": locator.pop("kind"), **locator}


def finalize_search_hit(match: Mapping[str, object], *, root: str) -> dict[str, object]:
    """Add ``title``/``display_path``/``artifact_type``/``timestamp``/``snippet``/``locator``.

    ``path`` stays the full source path (viewer, extraction, citations); the
    grid shows ``display_path`` and keeps ``path`` for the tooltip. ``preview``
    becomes the snippet so no client ever shows a serialized record.
    """
    item = dict(match)
    source = str(item.get("source") or "")
    keywords = [str(word) for word in item.get("matched_keywords") or [] if str(word)]
    metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
    path = str(item.get("path") or "")
    if source in {"artifacts", "web"}:
        title = _artifact_title(metadata) or str(item.get("title") or "")
        snippet_source: object = {
            key: value for key, value in metadata.items() if key not in {"path", "provider", "supported"}
        }
    elif source in {"timeline", "indicators"}:
        title = str(item.get("title") or "")
        snippet_source = metadata
    else:
        title = str(item.get("title") or "")
        snippet_source = str(item.get("preview") or "")
    snippet, highlights = search_snippet(snippet_source, keywords)
    item["title"] = _compact(title, TITLE_LIMIT) if title else PureWindowsPath(path).name
    item["artifact_type"] = _artifact_type(item) if source in {"artifacts", "web"} else ""
    item["timestamp"] = hit_timestamp(item)
    item["display_path"] = display_path(path, root)
    item["snippet"] = snippet
    item["snippet_highlights"] = highlights
    item["preview"] = snippet
    item["locator"] = hit_locator(item)
    item.pop("candidate_index", None)
    return item
