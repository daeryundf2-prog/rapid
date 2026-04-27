from __future__ import annotations

import datetime as dt
import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


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

    return {
        "generated_at": dt.datetime.now().isoformat(),
        "tool": "rapidtriage-vsc-compare",
        "current_root": str(current),
        "snapshot_roots": [str(snapshot) for snapshot in snapshots],
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
            modified_at=dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
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
