from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Mapping, Sequence

from .hash_cache import compute_hashes_cached

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

        stat_result = source_path.stat()
        hashes = compute_hashes(source_path)
        reference = bookmark.get("reference")
        items.append(
            {
                "bookmark_id": str(bookmark.get("bookmark_id") or ""),
                "summary": str(bookmark.get("summary") or source_path.name),
                "tags": list(bookmark.get("tags") or []),
                "note": str(bookmark.get("note") or ""),
                "review": review_payload,
                "reference": dict(reference) if isinstance(reference, Mapping) else {},
                "evidence": {
                    "path": str(source_path),
                    "name": source_path.name,
                    "size": stat_result.st_size,
                    "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
                    "hashes": hashes,
                },
            }
        )

    return {
        "command": "submission-manifest",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": str(case_payload.get("case_id") or ""),
        "title": str(case_payload.get("title") or ""),
        "hash_algorithms": list(HASH_ALGORITHMS),
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


def compute_hashes(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
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
