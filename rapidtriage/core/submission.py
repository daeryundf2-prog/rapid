from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from pathlib import Path

from .hash_cache import compute_hashes_cached, compute_hashes_fresh
from .report_candidates import is_report_candidate

HASH_ALGORITHMS = ("md5", "sha1", "sha256")
PREVIEW_MAX_CHARS = 200

# Korean reason shown next to each ``skipped`` entry (R8 T-178); ``reason`` stays the stable code.
SKIP_REASON_KO = {
    "max-items": "최대 항목 수(max_items)를 넘어 해시하지 않았습니다",
    "no-source-path": "원본 파일 경로가 없어 해시할 수 없습니다",
    "outside-allowed-roots": "허용된 원본 폴더 밖의 경로라 해시하지 않았습니다",
    "missing-or-not-file": "원본 파일이 없거나 파일이 아닙니다",
}


def evidence_relative_roots(summary: Mapping[str, object]) -> list[Path]:
    """The analysed file-system roots of a run (``source.analysis_root``, ``root``,
    ``scan_scope_root``): what ``evidence.relative_path`` is relative to. Never the output folder
    or an image stage folder, which hold copies and recovered output, not the evidence tree."""
    values: list[object] = []
    source = summary.get("source")
    if isinstance(source, Mapping):
        values.append(source.get("analysis_root"))
    values.extend((summary.get("root"), summary.get("scan_scope_root")))
    roots: list[Path] = []
    for value in values:
        if isinstance(value, str) and value:
            root = Path(value).expanduser().resolve()
            if root not in roots:
                roots.append(root)
    return roots


def build_submission_manifest(
    case_payload: Mapping[str, object],
    *,
    allowed_roots: Sequence[Path],
    include_all: bool = False,
    max_items: int = 500,
    evidence_roots: Sequence[Path] | None = None,
) -> dict[str, object]:
    """``evidence_roots``: the analysed file-system roots ``evidence.relative_path`` is relative
    to (default: ``allowed_roots``). A file under none of them -- carved or recovered output,
    extracts in the result folder -- gets ``relative_path: ""`` and ``relative_to: ""`` instead of
    a path relative to the output folder (R8 T-178 review P2-6); ``relative_to`` is
    ``"evidence-root"`` when the path is relative to an analysed root."""
    bookmarks = case_payload.get("bookmarks")
    rows = [item for item in bookmarks if isinstance(item, Mapping)] if isinstance(bookmarks, list) else []
    allowed = [root.expanduser().resolve() for root in allowed_roots]
    relative_roots = (
        [root.expanduser().resolve() for root in evidence_roots] if evidence_roots is not None else allowed
    )
    items: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    candidate_count = 0
    max_items_skipped = 0

    for bookmark in rows:
        review = bookmark.get("review")
        review_payload = dict(review) if isinstance(review, Mapping) else {}
        if not include_all and not is_report_candidate(bookmark):
            continue
        candidate_count += 1
        if max_items and len(items) >= max_items:
            skipped.append(build_skip(bookmark, reason="max-items"))
            max_items_skipped += 1
            continue

        snapshot = bookmark.get("snapshot")
        snapshot_payload = snapshot if isinstance(snapshot, Mapping) else {}
        raw_path = snapshot_payload.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            skipped.append(build_skip(bookmark, reason="no-source-path"))
            continue

        source_path = Path(raw_path).expanduser().resolve()
        containing_root = next((root for root in allowed if is_relative_to(source_path, root)), None)
        if containing_root is None:
            skipped.append(build_skip(bookmark, path=source_path, reason="outside-allowed-roots"))
            continue
        if not source_path.is_file():
            skipped.append(build_skip(bookmark, path=source_path, reason="missing-or-not-file"))
            continue

        stat_result = source_path.stat()
        hashes = compute_hashes_fresh(source_path)
        relative_root = next((root for root in relative_roots if is_relative_to(source_path, root)), None)
        reference = bookmark.get("reference")
        items.append(
            {
                "bookmark_id": str(bookmark.get("bookmark_id") or ""),
                "summary": str(bookmark.get("summary") or source_path.name),
                "tags": list(bookmark.get("tags") or []),
                "note": str(bookmark.get("note") or ""),
                "review": review_payload,
                "reference": dict(reference) if isinstance(reference, Mapping) else {},
                "row": build_row_info(bookmark),
                "evidence": {
                    "path": str(source_path),
                    "relative_path": source_path.relative_to(relative_root).as_posix() if relative_root else "",
                    "relative_to": "evidence-root" if relative_root else "",
                    "name": source_path.name,
                    "size": stat_result.st_size,
                    "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat(),
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
            # Rows selected for the manifest (report candidates, or every row with include_all).
            "report_candidate_count": candidate_count,
            "hashed_item_count": len(items),
            "skipped_count": len(skipped),
            # Candidates left out by ``max_items`` (also listed in ``skipped`` as "max-items").
            "max_items_skipped_count": max_items_skipped,
            "truncated": max_items_skipped > 0,
            "total_size": sum(int(item["evidence"]["size"]) for item in items),
        },
        "items": items,
        "skipped": skipped,
    }


def compute_hashes(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    """Metadata-cache-backed hashing for performance paths only.

    Callers that claim fresh integrity or submission verification must use
    ``compute_hashes_fresh`` instead so metadata-preserving modifications are
    never masked by a cached digest.
    """
    return compute_hashes_cached(path, chunk_size=chunk_size)


def _first_text(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def build_row_info(bookmark: Mapping[str, object]) -> dict[str, object]:
    """The artifact row a manifest item cites (R8 T-178): time, preview and where it came from.

    Case DB marks carry ``reference.citation_id/collection/kind/locator`` and ``snapshot.timestamp``;
    bookmark-JSON items fall back to their own reference fields (``command`` / ``artifact_key`` /
    ``pointer``). Missing values are empty strings, never dropped keys."""
    reference = bookmark.get("reference")
    ref = reference if isinstance(reference, Mapping) else {}
    snapshot = bookmark.get("snapshot")
    snap = snapshot if isinstance(snapshot, Mapping) else {}
    preview = _first_text(snap.get("summary"), bookmark.get("summary"), bookmark.get("note"))
    preview_total = len(preview)
    preview_truncated = preview_total > PREVIEW_MAX_CHARS
    if preview_truncated:
        preview = preview[: PREVIEW_MAX_CHARS - 1] + "…"
    return {
        "preview_truncated": preview_truncated,
        "preview_total": preview_total,
        "timestamp": _first_text(snap.get("timestamp"), ref.get("timestamp")),
        "preview": preview,
        "citation_id": _first_text(ref.get("citation_id")),
        "collection": _first_text(ref.get("collection"), ref.get("source_command"), ref.get("command")),
        "kind": _first_text(ref.get("kind"), snap.get("artifact_key"), ref.get("target_type")),
        "locator": _first_text(ref.get("locator"), ref.get("pointer"), ref.get("stable_key")),
    }


def build_skip(bookmark: Mapping[str, object], *, reason: str, path: Path | None = None) -> dict[str, object]:
    snapshot = bookmark.get("snapshot")
    snapshot_payload = snapshot if isinstance(snapshot, Mapping) else {}
    raw_path = str(path) if path is not None else str(snapshot_payload.get("path") or "")
    return {
        "bookmark_id": str(bookmark.get("bookmark_id") or ""),
        "summary": str(bookmark.get("summary") or ""),
        "path": raw_path,
        "reason": reason,
        "reason_ko": SKIP_REASON_KO.get(reason, reason),
    }


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
