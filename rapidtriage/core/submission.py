from __future__ import annotations

import datetime as dt
import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path

from .artifact_profiles import iter_payload_records
from .filetime import unix_ns_to_iso
from .hash_cache import compute_hashes_cached, compute_hashes_fresh

HASH_ALGORITHMS = ("md5", "sha1", "sha256")


def build_submission_manifest(
    case_payload: Mapping[str, object],
    *,
    allowed_roots: Sequence[Path],
    include_all: bool = False,
    max_items: int = 500,
) -> dict[str, object]:
    bookmarks = case_payload.get("bookmarks")
    rows = [item for item in bookmarks if isinstance(item, Mapping)] if isinstance(bookmarks, list) else []
    allowed = [root.expanduser().resolve() for root in allowed_roots]
    items: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    source_cache: dict[str, object] = {}

    for bookmark in rows:
        review = bookmark.get("review")
        review_payload = dict(review) if isinstance(review, Mapping) else {}
        if not include_all and not bool(review_payload.get("include_in_report")):
            continue
        if max_items and len(items) >= max_items:
            skipped.append(build_skip(bookmark, reason="max-items"))
            continue

        snapshot = bookmark.get("snapshot")
        snapshot_payload = snapshot if isinstance(snapshot, Mapping) else {}
        raw_path = snapshot_payload.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            skipped.append(build_skip(bookmark, reason="no-source-path"))
            continue

        source_path = Path(raw_path).expanduser().resolve()
        if not any(is_relative_to(source_path, root) for root in allowed):
            skipped.append(build_skip(bookmark, path=source_path, reason="outside-allowed-roots"))
            continue
        if not source_path.is_file():
            skipped.append(build_skip(bookmark, path=source_path, reason="missing-or-not-file"))
            continue

        reference = bookmark.get("reference")
        reference_payload = dict(reference) if isinstance(reference, Mapping) else {}
        withheld = verify_reference_row(reference_payload, source_cache)
        if withheld:
            skipped.append(build_skip(bookmark, path=source_path, reason=withheld))
            continue

        stat_result = source_path.stat()
        hashes = compute_hashes_fresh(source_path)
        items.append(
            {
                "bookmark_id": str(bookmark.get("bookmark_id") or ""),
                "summary": str(bookmark.get("summary") or source_path.name),
                "tags": list(bookmark.get("tags") or []),
                "note": str(bookmark.get("note") or ""),
                "review": review_payload,
                "reference": reference_payload,
                "evidence": {
                    "path": str(source_path),
                    "name": source_path.name,
                    "size": stat_result.st_size,
                    # Integer nanoseconds, not the float: 100 ns apart stays apart.
                    "modified_at": unix_ns_to_iso(stat_result.st_mtime_ns),
                    "modified_at_source": "fresh-stat-st_mtime_ns",
                    "hashes": hashes,
                    "hash_source": "fresh-file-read",
                },
            }
        )

    return {
        "command": "submission-manifest",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": str(case_payload.get("case_id") or ""),
        "title": str(case_payload.get("title") or ""),
        "hash_algorithms": list(HASH_ALGORITHMS),
        "hash_verification": {
            "scope": "submission-manifest",
            "metadata_cache_bypassed": True,
            "hash_source": "fresh-file-read",
            "note": (
                "Submission manifest hashes are always re-read from disk so a same-size "
                "metadata-preserving modification still changes the reported digest. The "
                "metadata-keyed hash cache is reserved for performance paths that do not "
                "claim fresh verification."
            ),
        },
        "options": {
            "include_all": include_all,
            "max_items": max_items,
        },
        "summary": {
            "case_bookmark_count": len(rows),
            "hashed_item_count": len(items),
            "skipped_count": len(skipped),
            "total_size": sum(int(item["evidence"]["size"]) for item in items),
        },
        "items": items,
        "skipped": skipped,
    }


def verify_reference_row(reference: dict[str, object], cache: dict[str, object]) -> str | None:
    """Re-check the cited output row right before submission.

    A bookmark stores the pointer *and* the SHA-256 of the row it was made on.
    Regenerating the output (an earlier source added to the timeline) shifts
    rows, so the pointer alone may now cite another row. The saved digest is
    the identity: the pointer is kept when its row still matches, corrected
    when exactly one row of the document matches, and the bookmark is withheld
    (returned reason) when the row is gone or cannot be told apart.
    ``reference`` gains a ``row_verification`` record of what was checked.
    """
    # Function-local: ``case`` imports the collectors, which import this module.
    from . import case as case_rows

    expected = reference.get("row_sha256")
    pointer = reference.get("pointer")
    if not isinstance(expected, str) or not expected or not isinstance(pointer, str):
        reference["row_verification"] = {"status": "no-row-digest"}
        return None
    raw_file = reference.get("file")
    payload = load_reference_document(raw_file, cache) if isinstance(raw_file, str) and raw_file else None
    if payload is None:
        reference["row_verification"] = {"status": "reference-file-unavailable"}
        return "reference-file-unavailable"
    command = str(payload.get("command") or reference.get("command") or "")
    try:
        current = case_rows.resolve_case_source_row(payload, source_command=command, source_pointer=pointer)
    except case_rows.CaseBookmarkError:
        current = None
    if current is not None and case_rows.source_row_sha256(current) == expected:
        reference["row_verification"] = {"status": "verified", "row_sha256_matches": True}
        return None
    matches = matching_row_pointers(payload, command=command, pointer=pointer, expected=expected)
    if len(matches) == 1:
        reference["pointer"] = matches[0]
        reference["row_verification"] = {
            "status": "pointer-corrected",
            "row_sha256_matches": True,
            "saved_pointer": pointer,
        }
        return None
    status = "reference-row-ambiguous" if matches else "reference-row-not-found"
    reference["row_verification"] = {"status": status, "row_sha256_matches": False, "saved_pointer": pointer}
    return status


def load_reference_document(raw_file: str, cache: dict[str, object]) -> Mapping[str, object] | None:
    if raw_file not in cache:
        try:
            loaded = json.loads(Path(raw_file).expanduser().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            loaded = None
        cache[raw_file] = loaded if isinstance(loaded, Mapping) else None
    document = cache[raw_file]
    return document if isinstance(document, Mapping) else None


def matching_row_pointers(payload: Mapping[str, object], *, command: str, pointer: str, expected: str) -> list[str]:
    """Every pointer of the same shape (collection index, same nested path)
    whose row hashes to ``expected``."""
    from . import case as case_rows

    collection_name = case_rows.CASE_SOURCE_ROWS.get(command)
    parts = pointer.split("/")
    if collection_name is None or len(parts) < 3 or parts[1] != collection_name:
        return []
    nested = "/".join(parts[3:])
    if command == "artifacts" and payload.get("records_path"):
        rows: Sequence[object] | Iterator[dict[str, object]] = iter_payload_records(payload)
    else:
        collection = payload.get(collection_name)
        rows = collection if isinstance(collection, list) else []
    matches: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            continue
        candidate: object = row
        if nested:
            try:
                candidate = case_rows.resolve_json_pointer(row, "/" + nested)
            except case_rows.CaseBookmarkError:
                continue
        if isinstance(candidate, Mapping) and case_rows.source_row_sha256(candidate) == expected:
            matches.append("/".join([*parts[:2], str(index), *parts[3:]]))
    return matches


def compute_hashes(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    """Metadata-cache-backed hashing for performance paths only.

    Callers that claim fresh integrity or submission verification must use
    ``compute_hashes_fresh`` instead so metadata-preserving modifications are
    never masked by a cached digest.
    """
    return compute_hashes_cached(path, chunk_size=chunk_size)


def build_skip(bookmark: Mapping[str, object], *, reason: str, path: Path | None = None) -> dict[str, object]:
    snapshot = bookmark.get("snapshot")
    snapshot_payload = snapshot if isinstance(snapshot, Mapping) else {}
    raw_path = str(path) if path is not None else str(snapshot_payload.get("path") or "")
    return {
        "bookmark_id": str(bookmark.get("bookmark_id") or ""),
        "summary": str(bookmark.get("summary") or ""),
        "path": raw_path,
        "reason": reason,
    }


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
