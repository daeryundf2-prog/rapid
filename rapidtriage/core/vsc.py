from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path


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


def discover_vsc_snapshot_roots(current_root: Path, *, max_depth: int = 3) -> dict[str, object]:
    current = current_root.expanduser().resolve()
    if not current.is_dir():
        raise VscCompareError(f"Current root is not a directory: {current}")
    search_roots = [current.parent, current / "System Volume Information", current / "VSS", current / "vss"]
    seen: set[Path] = set()
    candidates: list[dict[str, object]] = []
    for search_root in search_roots:
        if not search_root.is_dir() or search_root in seen:
            continue
        seen.add(search_root)
        for path in iter_candidate_snapshot_dirs(search_root, max_depth=max_depth):
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
                    "file_count_sample": count_files_bounded(path, limit=250),
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
        "search_roots": [str(path) for path in search_roots if path.is_dir()],
        "snapshot_count": len(rows),
        "snapshots": rows,
        "direct_image_level_mount_supported": False,
        "operator_note": "Discovery is for mounted/exported VSC folders. Direct VSC mounting from E01/RAW remains an external workflow.",
    }
    payload["image_workflow_handoff"] = build_vsc_image_workflow_handoff(
        current_root=current,
        source_kind="mounted-or-exported-windows-root",
        stage_dir=current.parent,
        discovery=payload,
        status="ready-after-discovery" if rows else "pending-snapshot-root",
    )
    payload["manifest_sha256"] = stable_json_hash(payload)
    return payload


def iter_candidate_snapshot_dirs(root: Path, *, max_depth: int) -> Iterable[Path]:
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            continue
        try:
            children = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        for child in children:
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


def count_files_bounded(root: Path, *, limit: int) -> int:
    count = 0
    for path in iter_regular_files(root):
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
) -> dict[str, object]:
    current = current_root.expanduser().resolve()
    snapshots = [path.expanduser().resolve() for path in snapshot_roots]
    if not current.is_dir():
        raise VscCompareError(f"Current root is not a directory: {current}")
    if not snapshots:
        raise VscCompareError("At least one snapshot directory is required")
    for snapshot in snapshots:
        if not snapshot.is_dir():
            raise VscCompareError(f"Snapshot root is not a directory: {snapshot}")

    current_index = build_file_index(current, compute_hashes=compute_hashes, case_sensitive=case_sensitive)
    comparisons: list[dict[str, object]] = []
    totals = {"deleted": 0, "added": 0, "modified": 0, "unchanged": 0}

    for snapshot in snapshots:
        snapshot_index = build_file_index(snapshot, compute_hashes=compute_hashes, case_sensitive=case_sensitive)
        records = compare_indexes(
            current_index,
            snapshot_index,
            snapshot_label=snapshot.name,
            max_records=max_records,
        )
        counts = status_counts(records)
        for key, value in counts.items():
            totals[key] = totals.get(key, 0) + value
        comparisons.append(
            {
                "snapshot_root": str(snapshot),
                "snapshot_label": snapshot.name,
                "summary": {
                    "current_file_count": len(current_index),
                    "snapshot_file_count": len(snapshot_index),
                    **counts,
                    "record_count": len(records),
                    "truncated": max_records > 0 and len(records) >= max_records,
                },
                "records": records,
            }
        )

    discovery = discover_vsc_snapshot_roots(current)
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
) -> dict[str, object]:
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
    )
    copied: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
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
            "skipped_count": len(skipped),
            "copied_bytes": copied_bytes,
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
        "skipped": skipped,
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


def build_file_index(root: Path, *, compute_hashes: bool, case_sensitive: bool) -> dict[str, FileEntry]:
    index: dict[str, FileEntry] = {}
    for path in iter_regular_files(root):
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
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    all_keys = sorted(set(current_index) | set(snapshot_index))
    for key in all_keys:
        current = current_index.get(key)
        snapshot = snapshot_index.get(key)
        if current is None and snapshot is not None:
            records.append(change_record("deleted", snapshot_label, snapshot=snapshot, current=None))
        elif snapshot is None and current is not None:
            records.append(change_record("added", snapshot_label, snapshot=None, current=current))
        elif current is not None and snapshot is not None and entries_differ(current, snapshot):
            records.append(change_record("modified", snapshot_label, snapshot=snapshot, current=current))
        else:
            continue
        if max_records > 0 and len(records) >= max_records:
            break
    return records


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


def iter_regular_files(root: Path) -> Iterable[Path]:
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            continue
        for entry in entries:
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
