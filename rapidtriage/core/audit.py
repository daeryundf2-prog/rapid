from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from .input_root import InputRoot, resolve_input_root


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_path_for(output_path: Path) -> Path:
    if output_path.suffix:
        return output_path.with_name(f"{output_path.stem}.audit{output_path.suffix}")
    return output_path.with_name(f"{output_path.name}.audit.json")


def build_input_root_record(root: InputRoot | Path) -> dict[str, object]:
    input_root = resolve_input_root(root)
    digest = hashlib.sha256()
    file_count = 0
    total_size = 0

    for path in sorted(iter_regular_files(input_root.root_path)):
        try:
            stat_result = path.stat()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        relative = path.relative_to(input_root.root_path).as_posix()
        digest.update(relative.encode("utf-8", errors="ignore"))
        digest.update(b"\0")
        digest.update(str(stat_result.st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(stat_result.st_mtime_ns).encode("ascii"))
        digest.update(b"\n")
        file_count += 1
        total_size += stat_result.st_size

    return {
        "source_path": input_root.source_path,
        "root_path": str(input_root.root_path),
        "kind": input_root.kind,
        "inventory_sha256": digest.hexdigest(),
        "file_count": file_count,
        "total_size": total_size,
    }


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
                    continue
                if entry.is_file():
                    yield entry
            except (FileNotFoundError, PermissionError, OSError):
                continue


def describe_file(path: Path, *, label: str | None = None) -> dict[str, object]:
    resolved = path.expanduser().resolve()
    stat_result = resolved.stat()
    return {
        "label": label or resolved.name,
        "path": str(resolved),
        "sha256": compute_sha256(resolved),
        "size": stat_result.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
    }


def write_audit_record(
    audit_path: Path,
    *,
    command: str,
    options: Mapping[str, object] | None = None,
    input_root: InputRoot | Path | None = None,
    input_files: Sequence[tuple[str, Path]] | None = None,
    output_files: Sequence[tuple[str, Path]] | None = None,
    notes: Sequence[str] | None = None,
) -> dict[str, object]:
    payload = {
        "command": command,
        "generated_at": dt.datetime.now().isoformat(),
        "provenance": {
            "options": dict(options or {}),
            "input_root": build_input_root_record(input_root) if input_root is not None else None,
            "input_files": [
                describe_file(path, label=label)
                for label, path in dedupe_records(input_files or [])
                if path.exists() and path.is_file()
            ],
            "notes": list(notes or []),
        },
        "integrity": {
            "generated_outputs": [
                describe_file(path, label=label)
                for label, path in dedupe_records(output_files or [])
                if path.exists() and path.is_file()
            ]
        },
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload


def dedupe_records(records: Sequence[tuple[str, Path]]) -> list[tuple[str, Path]]:
    seen: set[tuple[str, str]] = set()
    normalized: list[tuple[str, Path]] = []
    for label, path in records:
        resolved = path.expanduser().resolve()
        key = (label, str(resolved))
        if key in seen:
            continue
        seen.add(key)
        normalized.append((label, resolved))
    return normalized
