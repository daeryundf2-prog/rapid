from __future__ import annotations

import datetime as dt
import difflib
import hashlib
from pathlib import Path
from typing import Mapping


class CompareError(ValueError):
    """Raised when a compare request cannot be completed."""


HASH_ALGORITHMS = ("md5", "sha1", "sha256")
TEXT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".conf",
    ".csv",
    ".ini",
    ".json",
    ".log",
    ".md",
    ".ps1",
    ".py",
    ".reg",
    ".sh",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def compare_paths(
    left: Path,
    right: Path,
    *,
    left_label: str = "left",
    right_label: str = "right",
    hash_files: bool = True,
    include_text_diff: bool = True,
    max_text_bytes: int = 256 * 1024,
    diff_context: int = 3,
) -> dict[str, object]:
    left_path = left.expanduser().resolve()
    right_path = right.expanduser().resolve()
    left_record = describe_path(left_path, label=left_label, hash_files=hash_files)
    right_record = describe_path(right_path, label=right_label, hash_files=hash_files)

    fields = build_field_differences(left_record, right_record)
    status = compare_status(left_record, right_record)
    text_diff = (
        build_text_diff(left_path, right_path, left_label=left_label, right_label=right_label, max_text_bytes=max_text_bytes, context=diff_context)
        if include_text_diff and status == "different"
        else {}
    )
    result = {
        "comparison_id": "compare-0001",
        "status": status,
        "timestamp": comparison_timestamp(left_record, right_record),
        "path": str(left_path),
        "left_path": str(left_path),
        "right_path": str(right_path),
        "summary": build_summary(left_record, right_record, status),
        "fields": fields,
        "diff": text_diff,
        "left": left_record,
        "right": right_record,
    }
    return {
        "command": "compare",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "options": {
            "left_label": left_label,
            "right_label": right_label,
            "hash_files": hash_files,
            "include_text_diff": include_text_diff,
            "max_text_bytes": max_text_bytes,
            "diff_context": diff_context,
        },
        "inputs": {
            "left": left_record,
            "right": right_record,
        },
        "summary": {
            "result_count": 1,
            "status_counts": {status: 1},
            "different_field_count": sum(1 for item in fields if item.get("status") == "different"),
            "text_diff_included": bool(text_diff.get("included")) if isinstance(text_diff, Mapping) else False,
        },
        "results": [result],
    }


def describe_path(path: Path, *, label: str, hash_files: bool) -> dict[str, object]:
    exists = path.exists()
    record: dict[str, object] = {
        "label": label,
        "path": str(path),
        "name": path.name,
        "extension": path.suffix.lower(),
        "exists": exists,
        "is_file": path.is_file() if exists else False,
        "is_dir": path.is_dir() if exists else False,
        "size": None,
        "modified_at": None,
        "hashes": {},
    }
    if not exists:
        return record
    stat_result = path.stat()
    record["size"] = stat_result.st_size
    record["modified_at"] = dt.datetime.fromtimestamp(stat_result.st_mtime, tz=dt.timezone.utc).isoformat()
    if path.is_dir():
        raise CompareError("general compare accepts files only; use vsc-compare for directory tree comparisons")
    if not path.is_file():
        raise CompareError(f"compare input is not a regular file: {path}")
    if hash_files:
        record["hashes"] = compute_hashes(path)
    return record


def compute_hashes(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> dict[str, str]:
    hashers = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(usedforsecurity=False),
        "sha256": hashlib.sha256(),
    }
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def build_field_differences(left: Mapping[str, object], right: Mapping[str, object]) -> list[dict[str, object]]:
    fields = ["exists", "is_file", "size", "extension", "modified_at"]
    rows: list[dict[str, object]] = []
    for field in fields:
        left_value = left.get(field)
        right_value = right.get(field)
        rows.append(
            {
                "name": field,
                "left": left_value,
                "right": right_value,
                "status": "same" if left_value == right_value else "different",
            }
        )
    left_hashes = left.get("hashes") if isinstance(left.get("hashes"), Mapping) else {}
    right_hashes = right.get("hashes") if isinstance(right.get("hashes"), Mapping) else {}
    for algorithm in HASH_ALGORITHMS:
        left_hash = left_hashes.get(algorithm)
        right_hash = right_hashes.get(algorithm)
        if left_hash or right_hash:
            rows.append(
                {
                    "name": algorithm,
                    "left": left_hash,
                    "right": right_hash,
                    "status": "same" if left_hash == right_hash else "different",
                }
            )
    return rows


def compare_status(left: Mapping[str, object], right: Mapping[str, object]) -> str:
    if not left.get("exists") and not right.get("exists"):
        return "both-missing"
    if not left.get("exists"):
        return "only-in-right"
    if not right.get("exists"):
        return "only-in-left"
    left_hashes = left.get("hashes") if isinstance(left.get("hashes"), Mapping) else {}
    right_hashes = right.get("hashes") if isinstance(right.get("hashes"), Mapping) else {}
    left_sha256 = left_hashes.get("sha256")
    right_sha256 = right_hashes.get("sha256")
    if left_sha256 and right_sha256:
        return "same" if left_sha256 == right_sha256 else "different"
    return "same" if left.get("size") == right.get("size") else "different"


def comparison_timestamp(left: Mapping[str, object], right: Mapping[str, object]) -> str:
    timestamps = [str(value) for value in (left.get("modified_at"), right.get("modified_at")) if isinstance(value, str) and value]
    if timestamps:
        return max(timestamps)
    return dt.datetime.now(dt.timezone.utc).isoformat()


def build_summary(left: Mapping[str, object], right: Mapping[str, object], status: str) -> str:
    left_name = str(left.get("name") or left.get("path") or "left")
    right_name = str(right.get("name") or right.get("path") or "right")
    if status == "same":
        return f"{left_name} and {right_name} match"
    if status == "only-in-left":
        return f"{left_name} exists only on the left side"
    if status == "only-in-right":
        return f"{right_name} exists only on the right side"
    if status == "both-missing":
        return "Both compare inputs are missing"
    return f"{left_name} differs from {right_name}"


def build_text_diff(
    left: Path,
    right: Path,
    *,
    left_label: str,
    right_label: str,
    max_text_bytes: int,
    context: int,
) -> dict[str, object]:
    if not left.is_file() or not right.is_file():
        return {}
    if left.suffix.lower() not in TEXT_EXTENSIONS and right.suffix.lower() not in TEXT_EXTENSIONS:
        return {"included": False, "reason": "non-text-extension"}
    if left.stat().st_size > max_text_bytes or right.stat().st_size > max_text_bytes:
        return {"included": False, "reason": "text-byte-limit"}
    try:
        left_lines = left.read_text(encoding="utf-8").splitlines()
        right_lines = right.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return {"included": False, "reason": "utf8-decode-failed"}
    diff_lines = list(
        difflib.unified_diff(
            left_lines,
            right_lines,
            fromfile=left_label,
            tofile=right_label,
            n=max(0, context),
            lineterm="",
        )
    )
    return {
        "included": bool(diff_lines),
        "format": "unified",
        "line_count": len(diff_lines),
        "preview": diff_lines[:200],
    }
