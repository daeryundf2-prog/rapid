from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .link_safe_walk import WalkStats, iter_files_no_links, lstat_is_link

# Optional cancellation hook of API callers: called every CANCEL_CHECK_EVERY
# walked entries (and before each hashed or copied file); it aborts by raising.
CancelCheck = Callable[[], None]
CANCEL_CHECK_EVERY = 500
# Run output folders (``rapidtriage-run*``) are never snapshot candidates.
RUN_OUTPUT_DIR_PREFIX = "rapidtriage-run"


class VscCompareError(ValueError):
    pass


@dataclass(frozen=True)
class FileEntry:
    relative_path: str
    absolute_path: str
    size: int
    modified_at: str
    modified_ns: int
    sha256: str = ""


def build_vsc_image_workflow_handoff(
    *,
    current_root: Path | str | None,
    source_kind: str,
    source_path: Path | str | None = None,
    stage_dir: Path | str | None = None,
    discovery: Mapping[str, object] | None = None,
    status: str | None = None,
) -> dict[str, object]:
    current_text = str(current_root) if current_root else "<analysis-root>"
    stage_text = str(stage_dir) if stage_dir else "./rapidtriage-run"
    source_text = str(source_path) if source_path else ""
    snapshot_rows = list(discovery.get("snapshots") or []) if isinstance(discovery, Mapping) else []
    snapshot_placeholders = " ".join(json.dumps(str(row.get("path"))) for row in snapshot_rows[:3] if isinstance(row, Mapping))
    snapshot_arg = snapshot_placeholders or "<snapshot-root> [<snapshot-root>...]"
    handoff_status = status or ("ready-after-extraction" if current_root else "pending-after-extraction")
    payload: dict[str, object] = {
        "profile_version": "vsc-image-workflow-handoff-v1",
        "qc_prep_item": 3,
        "goal": "Discover mounted/exported Volume Shadow Copy roots, compare them with the recovered current volume, and preserve deleted/modified candidates with hashes.",
        "source_kind": source_kind,
        "source_path": source_text,
        "current_root": current_text,
        "stage_dir": stage_text,
        "status": handoff_status,
        "snapshot_count": len(snapshot_rows),
        "direct_image_level_mount_supported": False,
        "operator_warning": "RapidForensic does not mount VSC directly from E01/RAW yet; mount/export VSC snapshots read-only with a trusted tool, then use these commands.",
        "commands": {
            "discover": f"rapidtriage vsc-discover {json.dumps(current_text)} --output {json.dumps(str(Path(stage_text) / 'vsc-discovery.json'))}",
            "compare": f"rapidtriage vsc-compare {json.dumps(current_text)} {snapshot_arg} --hash --output {json.dumps(str(Path(stage_text) / 'vsc-compare.json'))}",
            "extract": f"rapidtriage vsc-extract {json.dumps(current_text)} {snapshot_arg} --output-dir {json.dumps(str(Path(stage_text) / 'vsc-evidence'))} --status deleted --status modified",
            "case_db_import": f"rapidtriage case-db --import-vsc-compare {json.dumps(str(Path(stage_text) / 'vsc-compare.json'))} --case-id <case-id>",
        },
        "workflow_steps": [
            {
                "id": "discover-mounted-snapshots",
                "label": "Discover mounted/exported snapshots",
                "status": "complete" if snapshot_rows else handoff_status,
                "evidence": "vsc-discovery JSON lists candidate snapshot roots and reason scores.",
            },
            {
                "id": "compare-current-vs-snapshot",
                "label": "Compare current volume against snapshots",
                "status": "ready-after-discovery" if snapshot_rows else "pending-snapshot-root",
                "evidence": "vsc-compare JSON records deleted/added/modified rows with optional SHA256.",
            },
            {
                "id": "extract-vsc-candidates",
                "label": "Extract deleted/modified candidates",
                "status": "ready-after-compare",
                "evidence": "vsc-extract copies selected files and records source/destination SHA256.",
            },
            {
                "id": "review-and-report",
                "label": "Review VSC deltas in Case DB",
                "status": "ready-after-import",
                "evidence": "Case DB imports VSC status, snapshot path, hashes, and review state.",
            },
        ],
        "validation_evidence_required": [
            "trusted tool or OS transcript showing mounted/exported VSC snapshot roots",
            "vsc-discovery JSON with snapshot path/reason scores",
            "vsc-compare JSON with deleted/modified/added summary",
            "vsc-extract manifest with copied file hashes for preserved candidates",
        ],
        "commercial_blockers": [
            "direct-image-level-vsc-mount-not-implemented",
            "trusted-vsc-snapshot-export-transcript-required",
            "known-answer-vsc-deleted-file-corpus-required",
        ],
    }
    payload["manifest_sha256"] = stable_json_hash(payload)
    return payload


def _within_roots(path: Path, roots: Sequence[Path]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def path_within_roots(path: Path, roots: Sequence[Path]) -> bool:
    """Lexical check first (no filesystem call on a path outside ``roots``), then the resolved path."""
    if not _within_roots(Path(os.path.abspath(path)), roots):
        return False
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    return _within_roots(resolved, roots)


def _discovery_walk_plan(
    search_roots: Sequence[Path],
    *,
    max_depth: int,
    allowed_roots: Sequence[Path] | None,
) -> tuple[list[tuple[Path, int, bool]], int]:
    """``[(start, start_depth, start_is_candidate)]`` and the number of search roots outside ``allowed_roots``.

    Without ``allowed_roots`` every search root is walked. With them, a search
    root outside every allowed root is never touched; only the allowed roots
    lexically beneath it (within the walk depth) are walked instead, each as a
    candidate itself plus its own subtree.
    """
    if allowed_roots is None:
        return [(root, 0, False) for root in search_roots], 0
    plan: list[tuple[Path, int, bool]] = []
    excluded = 0
    for search_root in search_roots:
        if _within_roots(Path(os.path.abspath(search_root)), allowed_roots):
            plan.append((search_root, 0, False))
            continue
        excluded += 1
        for root in allowed_roots:
            if root == search_root or not root.is_relative_to(search_root):
                continue
            level = len(root.relative_to(search_root).parts)
            if level <= max_depth + 1:  # iter_candidate_snapshot_dirs yields max_depth + 1 levels
                plan.append((root, level, True))
    return plan, excluded


def discover_vsc_snapshot_roots(
    current_root: Path,
    *,
    max_depth: int = 3,
    allowed_roots: Sequence[Path] | None = None,
    check_cancel: CancelCheck | None = None,
    skip_links: bool = False,
    exclude_dirs: Sequence[Path] = (),
) -> dict[str, object]:
    """Score directories around ``current_root`` that look like mounted/exported snapshots.

    ``allowed_roots`` (API callers) confines filesystem calls to those roots:
    outside search roots and candidates are skipped before any stat, walk or
    file count, the payload lists only what was walked, and
    ``excluded_outside_roots`` counts the skipped search roots and candidates.
    ``skip_links`` (API callers) never descends into or counts through
    symlinks/junctions. Run output folders (``rapidtriage-run*``) and
    ``exclude_dirs`` (with their subtrees) are never candidates.
    """
    current = current_root.expanduser().resolve()
    if not current.is_dir():
        raise VscCompareError(f"Current root is not a directory: {current}")
    search_roots = [current.parent, current / "System Volume Information", current / "VSS", current / "vss"]
    plan, excluded = _discovery_walk_plan(search_roots, max_depth=max_depth, allowed_roots=allowed_roots)

    excluded_trees = [Path(os.path.abspath(path)) for path in exclude_dirs]

    def allowed(path: Path) -> bool:
        nonlocal excluded
        if allowed_roots is None or path_within_roots(path, allowed_roots):
            return True
        excluded += 1
        return False

    def allowed_child(path: Path) -> bool:
        # The tool's own outputs are never snapshots (nor walked for them).
        return not is_run_output_dir(path, excluded_trees) and allowed(path)

    seen: set[Path] = set()
    walked_roots: list[Path] = []
    candidates: list[dict[str, object]] = []
    for search_root, start_depth, start_is_candidate in plan:
        if start_is_candidate and (search_root == current or current in search_root.parents):
            continue  # the current root's own subtree is covered by its VSS search roots
        if start_is_candidate and is_run_output_dir(search_root, excluded_trees):
            continue  # e.g. the run output dir itself (an input root) is never a snapshot
        if search_root in seen or not allowed(search_root) or not search_root.is_dir():
            continue
        seen.add(search_root)
        walked_roots.append(search_root)
        paths = iter_candidate_snapshot_dirs(
            search_root,
            max_depth=max_depth,
            start_depth=start_depth,
            allow=allowed_child,
            check_cancel=check_cancel,
            skip_links=skip_links,
        )
        for path in [search_root, *paths] if start_is_candidate else paths:
            if path == current or current in path.parents:
                continue
            label = path.name
            score = vsc_snapshot_name_score(path)
            if score <= 0:
                continue
            candidates.append(
                {
                    "path": str(path.resolve()),
                    "label": label,
                    "score": score,
                    "exists": path.is_dir(),
                    "file_count_sample": count_files_bounded(
                        path, limit=250, check_cancel=check_cancel, skip_links=skip_links
                    ),
                    "reason": vsc_snapshot_reason(path),
                }
            )
    unique: dict[str, dict[str, object]] = {}
    for candidate in candidates:
        unique[str(candidate["path"])] = candidate
    rows = sorted(unique.values(), key=lambda row: (-int(row["score"]), str(row["path"])))
    payload: dict[str, object] = {
        "schema": "rapidforensic-vsc-discovery-v1",
        "profile_version": "vsc-snapshot-discovery-v1",
        "checklist_item": 8,
        "qc_gap_id": "#8",
        "current_root": str(current),
        "search_roots": [str(path) for path in (search_roots if allowed_roots is None else walked_roots) if path.is_dir()],
        "snapshot_count": len(rows),
        "snapshots": rows,
        "direct_image_level_mount_supported": False,
        "operator_note": "Discovery is for mounted/exported VSC folders. Direct VSC mounting from E01/RAW remains an external workflow.",
    }
    if allowed_roots is not None:
        payload["excluded_outside_roots"] = excluded
    payload["image_workflow_handoff"] = build_vsc_image_workflow_handoff(
        current_root=current,
        source_kind="mounted-or-exported-windows-root",
        stage_dir=current.parent,
        discovery=payload,
        status="ready-after-discovery" if rows else "pending-snapshot-root",
    )
    payload["manifest_sha256"] = stable_json_hash(payload)
    return payload


def iter_candidate_snapshot_dirs(
    root: Path,
    *,
    max_depth: int,
    start_depth: int = 0,
    allow: Callable[[Path], bool] | None = None,
    check_cancel: CancelCheck | None = None,
    skip_links: bool = False,
) -> Iterable[Path]:
    """Directories below ``root``; ``allow`` rejects a child before any filesystem call on it.

    ``skip_links`` neither yields nor descends into symlinked/junction directories.
    """
    pending: list[tuple[Path, int]] = [(root, start_depth)]
    walked = 0
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            continue
        try:
            children = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for child in children:
            walked += 1
            if check_cancel is not None and walked % CANCEL_CHECK_EVERY == 0:
                check_cancel()
            if allow is not None and not allow(child):
                continue
            if skip_links:
                try:
                    if lstat_is_link(child):
                        continue
                except OSError:
                    continue
            if not child.is_dir():
                continue
            yield child
            pending.append((child, depth + 1))


def vsc_snapshot_name_score(path: Path) -> int:
    text = "/".join(part.lower() for part in path.parts[-4:])
    score = 0
    for token in ("vss", "vsc", "shadow", "snapshot", "volume shadow", "restorepoint"):
        if token in text:
            score += 3
    if "system volume information" in text:
        score += 2
    if any(char.isdigit() for char in path.name):
        score += 1
    return score


def vsc_snapshot_reason(path: Path) -> str:
    text = "/".join(part.lower() for part in path.parts[-4:])
    if "system volume information" in text:
        return "system-volume-information-shadow-copy-candidate"
    if "shadow" in text:
        return "shadow-copy-name-candidate"
    if "vss" in text or "vsc" in text:
        return "vss-vsc-name-candidate"
    return "snapshot-name-candidate"


def is_run_output_dir(path: Path, excluded_trees: Sequence[Path] = ()) -> bool:
    """A ``rapidtriage-run*`` folder, or a path inside one of ``excluded_trees`` (lexical only)."""
    return path.name.lower().startswith(RUN_OUTPUT_DIR_PREFIX) or _within_roots(
        Path(os.path.abspath(path)), excluded_trees
    )


def count_files_bounded(
    root: Path, *, limit: int, check_cancel: CancelCheck | None = None, skip_links: bool = False
) -> int:
    count = 0
    for _path in iter_regular_files(root, check_cancel=check_cancel, skip_links=skip_links):
        count += 1
        if count >= limit:
            break
    return count


def compare_vsc_snapshots(
    current_root: Path,
    snapshot_roots: Iterable[Path],
    *,
    compute_hashes: bool = False,
    case_sensitive: bool = False,
    max_records: int = 10000,
    allowed_roots: Sequence[Path] | None = None,
    check_cancel: CancelCheck | None = None,
    skip_links: bool = False,
    exclude_dirs: Sequence[Path] = (),
    statuses: Iterable[str] | None = None,
) -> dict[str, object]:
    """Index both sides and diff them; ``allowed_roots`` confines the embedded snapshot discovery.

    ``skip_links`` (API callers) indexes no file reached through a symlink or
    junction; each comparison summary then reports ``link_skipped_count``.

    Status counts are exact over the whole change set; only the ``records``
    listing is capped by ``max_records`` (0 = unlimited), filled deleted ->
    modified -> added (path order within each), so additions never crowd
    out deletions. ``truncated`` is true only when changes were left out of
    the listing. ``statuses`` limits which changes are listed (counts stay
    complete).
    """
    listed_statuses = set(statuses) if statuses is not None else None
    current = current_root.expanduser().resolve()
    snapshots = [path.expanduser().resolve() for path in snapshot_roots]
    if not current.is_dir():
        raise VscCompareError(f"Current root is not a directory: {current}")
    if not snapshots:
        raise VscCompareError("At least one snapshot directory is required")
    for snapshot in snapshots:
        if not snapshot.is_dir():
            raise VscCompareError(f"Snapshot root is not a directory: {snapshot}")

    current_stats = WalkStats()
    current_index = build_file_index(
        current,
        compute_hashes=compute_hashes,
        case_sensitive=case_sensitive,
        check_cancel=check_cancel,
        skip_links=skip_links,
        stats=current_stats,
    )
    comparisons: list[dict[str, object]] = []
    totals = {"deleted": 0, "added": 0, "modified": 0, "unchanged": 0}

    for snapshot in snapshots:
        snapshot_stats = WalkStats()
        snapshot_index = build_file_index(
            snapshot,
            compute_hashes=compute_hashes,
            case_sensitive=case_sensitive,
            check_cancel=check_cancel,
            skip_links=skip_links,
            stats=snapshot_stats,
        )
        counts: dict[str, int] = {"deleted": 0, "added": 0, "modified": 0, "unchanged": 0}
        records = compare_indexes(
            current_index,
            snapshot_index,
            snapshot_label=snapshot.name,
            max_records=max_records,
            statuses=listed_statuses,
            counts=counts,
        )
        for key, value in counts.items():
            totals[key] = totals.get(key, 0) + value
        listable = sum(
            value
            for key, value in counts.items()
            if key != "unchanged" and (listed_statuses is None or key in listed_statuses)
        )
        comparisons.append(
            {
                "snapshot_root": str(snapshot),
                "snapshot_label": snapshot.name,
                "summary": {
                    "current_file_count": len(current_index),
                    "snapshot_file_count": len(snapshot_index),
                    **counts,
                    "record_count": len(records),
                    "change_count": listable,
                    "truncated": len(records) < listable,
                    **(
                        {"link_skipped_count": current_stats.skipped_links + snapshot_stats.skipped_links}
                        if skip_links
                        else {}
                    ),
                },
                "records": records,
            }
        )

    discovery = discover_vsc_snapshot_roots(
        current,
        allowed_roots=allowed_roots,
        check_cancel=check_cancel,
        skip_links=skip_links,
        exclude_dirs=exclude_dirs,
    )
    return {
        "generated_at": dt.datetime.now().isoformat(),
        "tool": "rapidtriage-vsc-compare",
        "current_root": str(current),
        "snapshot_roots": [str(snapshot) for snapshot in snapshots],
        "snapshot_discovery": discovery,
        "image_workflow_handoff": build_vsc_image_workflow_handoff(
            current_root=current,
            source_kind="mounted-or-exported-windows-root",
            stage_dir=current.parent,
            discovery=discovery,
            status="compare-complete",
        ),
        "options": {
            "compute_hashes": compute_hashes,
            "case_sensitive": case_sensitive,
            "max_records": max_records,
        },
        "summary": {
            "snapshot_count": len(snapshots),
            "current_file_count": len(current_index),
            **totals,
        },
        "comparisons": comparisons,
        "notes": [
            "deleted means present in the snapshot but absent from the current root.",
            "modified is based on size/mtime by default; use --hash when byte-level confirmation is required.",
            "Direct VSC mounting from E01/RAW is not implemented; use mounted/exported snapshot folders.",
        ],
    }


def extract_vsc_changes(
    current_root: Path,
    snapshot_roots: Iterable[Path],
    output_dir: Path,
    *,
    statuses: Iterable[str] = ("deleted", "modified"),
    compute_hashes: bool = True,
    case_sensitive: bool = False,
    max_records: int = 10000,
    max_file_count: int = 1000,
    max_total_bytes: int = 2 * 1024 * 1024 * 1024,
    overwrite: bool = False,
    allowed_roots: Sequence[Path] | None = None,
    check_cancel: CancelCheck | None = None,
    skip_links: bool = False,
    exclude_dirs: Sequence[Path] = (),
    max_skipped_records: int | None = None,
) -> dict[str, object]:
    """Copy the selected changes' files; selection comes from the selected statuses only.

    ``max_records`` (0 = unlimited) caps the *selected* changes per snapshot
    (deleted -> modified -> added), never a listing that unselected
    additions filled first; ``summary.selection_truncated`` reports a cap
    hit. ``max_skipped_records`` (API callers) bounds the ``skipped`` list
    while ``summary.skipped_count``/``skipped_reason_counts`` stay exact.
    """
    selected_statuses = {status.strip().lower() for status in statuses if status.strip()}
    allowed_statuses = {"deleted", "modified", "added"}
    if not selected_statuses or not selected_statuses.issubset(allowed_statuses):
        raise VscCompareError("statuses must be one or more of: deleted, modified, added")
    destination_root = output_dir.expanduser().resolve()
    evidence_root = destination_root / "evidence"
    comparison = compare_vsc_snapshots(
        current_root,
        snapshot_roots,
        compute_hashes=compute_hashes,
        case_sensitive=case_sensitive,
        max_records=max_records,
        allowed_roots=allowed_roots,
        check_cancel=check_cancel,
        skip_links=skip_links,
        exclude_dirs=exclude_dirs,
        statuses=selected_statuses,
    )
    copied: list[dict[str, object]] = []
    skipped = _BoundedSkips(max_skipped_records)
    copied_bytes = 0
    selected_count = 0
    for comparison_row in comparison["comparisons"]:
        snapshot_label = safe_path_part(str(comparison_row.get("snapshot_label") or "snapshot"))
        for record in comparison_row.get("records", []):
            if not isinstance(record, dict):
                continue
            status = str(record.get("status") or "")
            if status not in selected_statuses:
                continue
            if check_cancel is not None:
                check_cancel()
            source = source_entry_for_vsc_extract(record)
            relative_path = str(record.get("relative_path") or "")
            selected_count += 1
            if not source:
                skipped.append(skip_record(record, "missing-source-entry"))
                continue
            source_path = Path(str(source.get("path") or ""))
            if not source_path.is_file():
                skipped.append(skip_record(record, "source-not-readable"))
                continue
            try:
                size = source_path.stat().st_size
            except OSError:
                skipped.append(skip_record(record, "source-stat-failed"))
                continue
            if max_file_count > 0 and len(copied) >= max_file_count:
                skipped.append(skip_record(record, "max-file-count"))
                continue
            if max_total_bytes > 0 and copied_bytes + size > max_total_bytes:
                skipped.append(skip_record(record, "max-total-bytes"))
                continue
            destination = evidence_root / snapshot_label / status / safe_relative_path(relative_path)
            if destination.exists() and not overwrite:
                skipped.append(skip_record(record, "destination-exists", destination=destination))
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(source_path, destination)
            except OSError:
                skipped.append(skip_record(record, "copy-failed", destination=destination))
                continue
            copied_bytes += size
            copied.append(
                {
                    "status": status,
                    "snapshot_label": snapshot_label,
                    "relative_path": relative_path,
                    "source_path": str(source_path.resolve()),
                    "destination_path": str(destination.resolve()),
                    "size": size,
                    "source_sha256": str(source.get("sha256") or "") or file_sha256(source_path),
                    "destination_sha256": file_sha256(destination),
                    "modified_at": source.get("modified_at") or "",
                    "evidence_strength": "vsc-snapshot-file-copy",
                }
            )
    manifest = {
        "generated_at": dt.datetime.now().isoformat(),
        "tool": "rapidtriage-vsc-extract",
        "current_root": comparison["current_root"],
        "snapshot_roots": comparison["snapshot_roots"],
        "output_dir": str(destination_root),
        "evidence_root": str(evidence_root),
        "options": {
            "statuses": sorted(selected_statuses),
            "compute_hashes": compute_hashes,
            "case_sensitive": case_sensitive,
            "max_records": max_records,
            "max_file_count": max_file_count,
            "max_total_bytes": max_total_bytes,
            "overwrite": overwrite,
        },
        "summary": {
            "snapshot_count": comparison["summary"]["snapshot_count"],
            "selected_count": selected_count,
            "copied_count": len(copied),
            "skipped_count": skipped.count,
            "skipped_reason_counts": dict(skipped.reasons),
            "skipped_listed_count": len(skipped.items),
            "copied_bytes": copied_bytes,
            "selection_truncated": any(
                (row.get("summary") or {}).get("truncated") for row in comparison["comparisons"]
            ),
        },
        "comparison_summary": comparison["summary"],
        "image_workflow_handoff": build_vsc_image_workflow_handoff(
            current_root=current_root.expanduser().resolve(),
            source_kind="mounted-or-exported-windows-root",
            stage_dir=destination_root,
            discovery=comparison.get("snapshot_discovery") if isinstance(comparison.get("snapshot_discovery"), Mapping) else None,
            status="extract-complete",
        ),
        "copied": copied,
        "skipped": skipped.items,
        "notes": [
            "deleted and modified records copy the snapshot-side file by default; added records copy the current-side file when selected.",
            "The manifest records source and destination SHA256 values for preservation review.",
        ],
    }
    return manifest


def source_entry_for_vsc_extract(record: dict[str, object]) -> dict[str, object] | None:
    status = str(record.get("status") or "")
    if status in {"deleted", "modified"}:
        source = record.get("snapshot")
    elif status == "added":
        source = record.get("current")
    else:
        source = None
    return source if isinstance(source, dict) else None


def skip_record(record: dict[str, object], reason: str, *, destination: Path | None = None) -> dict[str, object]:
    payload = {
        "status": str(record.get("status") or ""),
        "snapshot_label": str(record.get("snapshot_label") or ""),
        "relative_path": str(record.get("relative_path") or ""),
        "reason": reason,
    }
    if destination is not None:
        payload["destination_path"] = str(destination)
    return payload


def safe_relative_path(value: str) -> Path:
    parts = [part for part in Path(value.replace("\\", "/")).parts if part not in {"", ".", ".."}]
    return Path(*parts) if parts else Path("unnamed")


def safe_path_part(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value.strip())
    return cleaned or "snapshot"


def build_file_index(
    root: Path,
    *,
    compute_hashes: bool,
    case_sensitive: bool,
    check_cancel: CancelCheck | None = None,
    skip_links: bool = False,
    stats: WalkStats | None = None,
) -> dict[str, FileEntry]:
    index: dict[str, FileEntry] = {}
    for path in iter_regular_files(root, check_cancel=check_cancel, skip_links=skip_links, stats=stats):
        if compute_hashes and check_cancel is not None:
            check_cancel()  # hashing one file can take long
        try:
            stat_result = path.stat()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        relative = path.relative_to(root).as_posix()
        key = relative if case_sensitive else relative.lower()
        index[key] = FileEntry(
            relative_path=relative,
            absolute_path=str(path.resolve()),
            size=stat_result.st_size,
            modified_at=dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat(),
            modified_ns=stat_result.st_mtime_ns,
            sha256=file_sha256(path) if compute_hashes else "",
        )
    return index


def compare_indexes(
    current_index: dict[str, FileEntry],
    snapshot_index: dict[str, FileEntry],
    *,
    snapshot_label: str,
    max_records: int,
    statuses: set[str] | None = None,
    counts: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    """Change records: deleted, then modified, then added (path order within each).

    Every key is classified (``counts`` receives exact per-status totals);
    only the returned listing is capped at ``max_records`` (0 = unlimited),
    so a cap never hides a deletion behind additions that sort earlier.
    ``statuses`` restricts which changes are listed.
    """
    buckets: dict[str, list[dict[str, object]]] = {"deleted": [], "modified": [], "added": []}
    for key in sorted(set(current_index) | set(snapshot_index)):
        current = current_index.get(key)
        snapshot = snapshot_index.get(key)
        if current is None and snapshot is not None:
            status = "deleted"
        elif snapshot is None and current is not None:
            status = "added"
        elif current is not None and snapshot is not None and entries_differ(current, snapshot):
            status = "modified"
        else:
            continue
        if counts is not None:
            counts[status] = counts.get(status, 0) + 1
        if statuses is not None and status not in statuses:
            continue
        bucket = buckets[status]
        if max_records > 0 and len(bucket) >= max_records:
            continue  # this bucket alone already fills the listing
        bucket.append(change_record(status, snapshot_label, snapshot=snapshot, current=current))
    records = [*buckets["deleted"], *buckets["modified"], *buckets["added"]]
    return records[:max_records] if max_records > 0 else records


class _BoundedSkips:
    """Skip rows of an extract: exact count and per-reason totals, listing bounded by ``limit``."""

    def __init__(self, limit: int | None) -> None:
        self.limit = limit
        self.items: list[dict[str, object]] = []
        self.count = 0
        self.reasons: dict[str, int] = {}

    def append(self, item: dict[str, object]) -> None:
        self.count += 1
        reason = str(item.get("reason") or "")
        self.reasons[reason] = self.reasons.get(reason, 0) + 1
        if self.limit is None or len(self.items) < self.limit:
            self.items.append(item)


def change_record(
    status: str,
    snapshot_label: str,
    *,
    snapshot: FileEntry | None,
    current: FileEntry | None,
) -> dict[str, object]:
    reference = snapshot or current
    return {
        "status": status,
        "snapshot_label": snapshot_label,
        "relative_path": reference.relative_path if reference else "",
        "snapshot": entry_payload(snapshot),
        "current": entry_payload(current),
    }


def entry_payload(entry: FileEntry | None) -> dict[str, object] | None:
    if entry is None:
        return None
    payload: dict[str, object] = {
        "path": entry.absolute_path,
        "size": entry.size,
        "modified_at": entry.modified_at,
    }
    if entry.sha256:
        payload["sha256"] = entry.sha256
    return payload


def entries_differ(current: FileEntry, snapshot: FileEntry) -> bool:
    if current.sha256 and snapshot.sha256:
        return current.sha256 != snapshot.sha256
    return current.size != snapshot.size or current.modified_ns != snapshot.modified_ns


def status_counts(records: Iterable[dict[str, object]]) -> dict[str, int]:
    counts = {"deleted": 0, "added": 0, "modified": 0, "unchanged": 0}
    for record in records:
        status = str(record.get("status") or "")
        counts[status] = counts.get(status, 0) + 1
    return counts


def iter_regular_files(
    root: Path,
    *,
    check_cancel: CancelCheck | None = None,
    skip_links: bool = False,
    stats: WalkStats | None = None,
) -> Iterable[Path]:
    """Regular files below ``root``.

    The default (CLI) walk follows directory links as it always has.
    ``skip_links`` (API callers) uses ``iter_files_no_links``: symlinked or
    junction directories are never entered and linked files never yielded
    (counted in ``stats.skipped_links``), so a link cannot leave ``root`` and
    a junction loop cannot hang the walk.
    """
    if skip_links:
        yield from iter_files_no_links(root, check_cancel=check_cancel, every=CANCEL_CHECK_EVERY, stats=stats)
        return
    pending = [root]
    walked = 0
    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            continue
        for entry in entries:
            walked += 1
            if check_cancel is not None and walked % CANCEL_CHECK_EVERY == 0:
                check_cancel()  # every N walked entries, files or not
            try:
                if entry.is_dir():
                    pending.append(entry)
                elif entry.is_file():
                    yield entry
            except (FileNotFoundError, PermissionError, OSError):
                continue


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def stable_json_hash(payload: dict[str, object]) -> str:
    redacted = {key: value for key, value in payload.items() if key != "manifest_sha256"}
    return hashlib.sha256(json.dumps(redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
