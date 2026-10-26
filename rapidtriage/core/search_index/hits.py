"""Console global search over the v2 index, answered in the v1 ``GET /search`` hit shape (R7 P2).

The console's global search sends the analyst's keywords (any keyword matches, like v1
``exact`` mode). :func:`console_query` turns them into one index query over the
collections v1 searches, and :func:`index_hit` turns an index row into the same hit
``finalize_search_hit`` produces for v1 (``source``/``kind``/``pointer``/``path``/``title``/
``display_path``/``artifact_type``/``timestamp``/``snippet``/``snippet_highlights``/``locator``/
compact ``metadata``), so the grid, the viewer and the review marks read both alike.

What v2 does not cover (documented in docs/rapidtriage-known-limitations.md "R7 P2"):

* timeline events (``/events/<n>``) are not a collection of the index -- the artifact row
  each event came from is;
* OCR sidecars (``ocr=1``) and IOC-scanner hits (``/ioc_scanner_hits/<n>``) are not indexed;
* file inventory rows (``/inventory/<n>``) and analysis result rows are indexed but v1 never
  searched them: the console query leaves them out (``-type:file-inventory -in:analysis``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from ..search import (
    build_search_match_metadata,
    compact_search_metadata,
    normalize_keywords,
)
from ..search_fts import docs_result_index
from ..search_hits import finalize_search_hit, scan_root_of

# The artifact kind whose hits v1 calls "web" (search_fts.BROWSER_OUTPUT_NAME).
BROWSER_KIND = "browser"
CONSOLE_SCOPE = "-in:analysis -type:file-inventory"
MAX_CONSOLE_KEYWORDS = 32


def console_keywords(keywords: Sequence[str]) -> list[str]:
    """v1 ``exact``-mode keyword normalization (NFC + casefold, trimmed, deduplicated)."""
    return normalize_keywords(keywords, search_mode="exact")


def _phrase(keyword: str) -> str:
    return '"' + keyword.replace("\\", "\\\\").replace('"', '\\"') + '"'


def console_query(keywords: Sequence[str]) -> str:
    """Index query matching a row that contains any keyword, over the collections v1 searches."""
    terms = [_phrase(keyword) for keyword in keywords]
    if not terms:
        raise ValueError("at least one keyword is required")
    return f"({' OR '.join(terms)}) {CONSOLE_SCOPE}"


def _ordinal(locator: str) -> int | None:
    tail = locator.rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None


def source_path(stored: str, root: str) -> str:
    """The full source path of an index row: the index keeps evidence paths without the run's
    acquisition root (``\\Users\\x``, build ``evidence_path``); the viewer, extraction and
    citations need the path v1 hits carry (``<root>\\Users\\x``)."""
    base = root.rstrip("\\/")
    if base and stored[:1] in ("\\", "/") and not stored.startswith(("\\\\", "//")):
        # A whole-source row stored as "\" is the root itself.
        return base + stored if stored.strip("\\/") else base
    return stored


def _body_context(text: str, title: str, path: str, keywords: Sequence[str]) -> str:
    """The index row text is ``title\\npath\\nbody``: drop a leading title/path (the grid shows them
    in their own columns, v1's snippet is body text) when the keyword is still in what remains."""
    for head in (f"{title} {path} ", f"{title} "):
        if head.strip() and text.startswith(head):
            rest = text[len(head):]
            folded = rest.casefold()
            if any(keyword.casefold() in folded for keyword in keywords):
                return rest
    return text


def _metadata(row: Mapping[str, object]) -> dict[str, object]:
    fields = row.get("fields") if isinstance(row.get("fields"), Mapping) else {}
    hashes = row.get("hashes") if isinstance(row.get("hashes"), Mapping) else {}
    record: dict[str, object] = {key: value for key, value in fields.items() if isinstance(value, (str, int, float, bool))}
    if row.get("collection") == "artifacts":
        record["artifact_type"] = row.get("artifact_type") or ""
    if row.get("ts"):
        record["timestamp"] = row.get("ts")
        record["timestamp_kind"] = row.get("ts_kind") or ""
    for algorithm in ("md5", "sha1", "sha256"):
        if hashes.get(algorithm):
            record[algorithm] = hashes[algorithm]
    if isinstance(fields.get("categories"), str):
        record["categories"] = [part.strip() for part in str(fields["categories"]).split(",") if part.strip()]
    flags = row.get("flags") if isinstance(row.get("flags"), Mapping) else {}
    if flags.get("deleted"):
        record["is_deleted"] = True
    return compact_search_metadata(record)


def index_hit(
    row: Mapping[str, object],
    *,
    root: str,
    keywords: Sequence[str],
    docs_results: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """One ``search/query`` row -> the v1 unified-search hit (``finalize_search_hit`` applied)."""
    collection = str(row.get("collection") or "")
    kind = str(row.get("kind") or "")
    locator = str(row.get("locator") or "")
    stored_path = str(row.get("path") or "")
    path = source_path(stored_path, root)
    title = str(row.get("title") or "")
    snippet = row.get("snippet") if isinstance(row.get("snippet"), Mapping) else {}
    snippet_text = _body_context(str(snippet.get("text") or ""), title, stored_path, keywords)
    fields = row.get("fields") if isinstance(row.get("fields"), Mapping) else {}
    matched_terms = {
        str(item.get("term") or "").casefold()
        for item in row.get("matched") or []
        if isinstance(item, Mapping)
    }
    matched = [keyword for keyword in keywords if keyword.casefold() in matched_terms] or list(keywords)
    match: dict[str, object] = {
        "path": path,
        "title": title,
        "matched_keywords": matched,
        "metadata": _metadata(row),
        "timestamp": row.get("ts") or None,
        "search_match": build_search_match_metadata(snippet_text, keywords, search_options={"search_mode": "exact"}),
    }
    snippet_source: object = snippet_text
    if collection == "docs":
        ordinal = _ordinal(locator)
        match.update(
            source="documents",
            kind=str(fields.get("kind") or ""),
            pointer=f"/results/{docs_results[path]}" if docs_results and path in docs_results else "",
            candidate_index=ordinal if ordinal is not None else -1,
            preview=snippet_text,
        )
    elif collection == "files":
        categories = match["metadata"].get("categories") if isinstance(match["metadata"], Mapping) else None
        match.update(
            source="files",
            kind=",".join(str(item) for item in categories) if isinstance(categories, list) else "",
            pointer=locator,
            preview=path,
        )
        snippet_source = None  # v1: the snippet of a file hit is its path
    elif collection == "indicators":
        artifact_type = str(row.get("artifact_type") or "")
        match.update(source="indicators", kind=artifact_type.removeprefix("indicator-") or "indicator", pointer=locator)
    else:
        match.update(source="web" if kind == BROWSER_KIND else "artifacts", kind=kind, pointer=locator)
    return finalize_search_hit(match, root=root, snippet_source=snippet_source, record_title=False)


def index_hits(
    rows: Sequence[Mapping[str, object]],
    *,
    root: str,
    keywords: Sequence[str],
    run_id: str,
    offset: int = 0,
    docs_results: Mapping[str, int] | None = None,
) -> list[dict[str, object]]:
    """A page of index rows as v1 hits, numbered like v1 (``search-hit-<offset + n>``)."""
    hits: list[dict[str, object]] = []
    for position, row in enumerate(rows):
        hit = index_hit(row, root=root, keywords=keywords, docs_results=docs_results)
        hit["search_result_id"] = f"search-hit-{offset + position + 1:06d}"
        if isinstance(hit.get("locator"), dict):
            hit["locator"]["run_id"] = run_id
        hits.append(hit)
    return hits


def attach_console_hits(
    result: dict[str, object],
    keywords: Sequence[str],
    *,
    summary: Mapping[str, object],
    run_id: str,
    offset: int = 0,
) -> dict[str, object]:
    """Replace a ``run_query`` result's ``rows`` by v1 ``matches`` (in place; returns ``result``)."""
    rows = [row for row in result.pop("rows", None) or [] if isinstance(row, Mapping)]
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), Mapping) else {}
    docs_path = outputs.get("docs") if isinstance(outputs, Mapping) else None
    docs_results = (
        docs_result_index(Path(str(docs_path)))
        if docs_path and any(row.get("collection") == "docs" for row in rows)
        else None
    )
    result["matches"] = index_hits(
        rows, root=scan_root_of(summary), keywords=keywords, run_id=run_id, offset=offset, docs_results=docs_results
    )
    return result
