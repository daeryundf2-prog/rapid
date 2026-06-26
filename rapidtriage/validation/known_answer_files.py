from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Final

from rapidtriage.validation.known_answer_types import FileCheckResult, JsonObject, JsonValue


HASH_CHUNK_SIZE_BYTES: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class FileCheckSummary:
    checks: list[FileCheckResult]
    skipped_count: int


def run_file_checks(manifest_object: JsonObject | None, fixture_root: Path) -> FileCheckSummary:
    if manifest_object is None:
        return FileCheckSummary(checks=[], skipped_count=0)

    expected_items = manifest_object.get("expected_items")
    if not isinstance(expected_items, list):
        return FileCheckSummary(checks=[], skipped_count=0)

    checks: list[FileCheckResult] = []
    skipped_count = 0
    root = fixture_root.resolve()
    for item_value in expected_items:
        item = _as_object(item_value)
        if item is None or not _is_check_target(item):
            skipped_count += 1
            continue
        checks.append(_check_item(item, root))

    return FileCheckSummary(checks=checks, skipped_count=skipped_count)


def _is_check_target(item: JsonObject) -> bool:
    return (
        _string_field(item, "expected_status") == "allocated"
        and _string_field(item, "expected_recovery") == "must_recover_byte_exact"
        and _string_field(item, "expected_recovery_mode") == "filesystem"
    )


def _check_item(item: JsonObject, fixture_root: Path) -> FileCheckResult:
    item_id = _string_field(item, "item_id") or "<unknown>"
    relative_path = _fixture_relative_path(item)
    expected_size = _int_field(item, "size_bytes")
    expected_sha256 = _string_field(item, "sha256")

    if relative_path is None:
        return _failed_check(
            item_id=item_id,
            relative_path="",
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            message="no fixture relative path found",
        )
    if not _is_safe_relative_path(relative_path):
        return _failed_check(
            item_id=item_id,
            relative_path=relative_path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            message="path is not a safe relative path",
        )
    if expected_size is None or expected_sha256 is None:
        return _failed_check(
            item_id=item_id,
            relative_path=relative_path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            message="expected size_bytes and sha256 are required",
        )

    file_path = _resolve_fixture_path(fixture_root, relative_path)
    if file_path is None:
        return _failed_check(
            item_id=item_id,
            relative_path=relative_path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            message="path escapes fixture root after resolution",
        )
    if not file_path.exists():
        return _failed_check(
            item_id=item_id,
            relative_path=relative_path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            message="file does not exist",
        )
    if not file_path.is_file():
        return _failed_check(
            item_id=item_id,
            relative_path=relative_path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            message="path is not a regular file",
        )

    actual_size = file_path.stat().st_size
    actual_sha256 = _sha256_file(file_path)
    messages: list[str] = []
    if actual_size != expected_size:
        messages.append(f"size mismatch expected {expected_size} actual {actual_size}")
    if actual_sha256 != expected_sha256:
        messages.append(f"sha256 mismatch expected {expected_sha256} actual {actual_sha256}")

    return FileCheckResult(
        item_id=item_id,
        relative_path=relative_path,
        status="PASS" if not messages else "FAIL",
        ok=not messages,
        expected_size=expected_size,
        actual_size=actual_size,
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        message="ok" if not messages else "; ".join(messages),
    )


def _failed_check(
    *,
    item_id: str,
    relative_path: str,
    expected_size: int | None,
    expected_sha256: str | None,
    message: str,
) -> FileCheckResult:
    return FileCheckResult(
        item_id=item_id,
        relative_path=relative_path,
        status="FAIL",
        ok=False,
        expected_size=expected_size,
        actual_size=None,
        expected_sha256=expected_sha256,
        actual_sha256=None,
        message=message,
    )


def _fixture_relative_path(item: JsonObject) -> str | None:
    metadata = _as_object(item.get("expected_metadata"))
    if metadata is not None:
        metadata_path = _string_field(metadata, "fixture_relative_path")
        if metadata_path:
            return metadata_path

    normalized_path = _string_field(item, "normalized_path")
    if normalized_path:
        return normalized_path
    return _string_field(item, "original_path")


def _is_safe_relative_path(raw_path: str) -> bool:
    posix_path = PurePosixPath(raw_path)
    windows_path = PureWindowsPath(raw_path)
    path_parts = (*posix_path.parts, *windows_path.parts)
    return (
        raw_path != ""
        and "\x00" not in raw_path
        and not posix_path.is_absolute()
        and not windows_path.is_absolute()
        and windows_path.drive == ""
        and ".." not in path_parts
    )


def _resolve_fixture_path(fixture_root: Path, relative_path: str) -> Path | None:
    relative_parts = PurePosixPath(relative_path).parts
    candidates = [_candidate_path(fixture_root, relative_parts)]
    if relative_parts and relative_parts[0] == fixture_root.name:
        candidates.append(_candidate_path(fixture_root, relative_parts[1:]))

    for candidate in candidates:
        if not _is_inside_root(candidate, fixture_root):
            return None
        if candidate.exists():
            return candidate
    return candidates[0] if _is_inside_root(candidates[0], fixture_root) else None


def _candidate_path(fixture_root: Path, relative_parts: tuple[str, ...]) -> Path:
    return (fixture_root / Path(*relative_parts)).resolve()


def _is_inside_root(candidate: Path, fixture_root: Path) -> bool:
    try:
        _ = candidate.relative_to(fixture_root)
    except ValueError:
        return False
    return True


def _sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as file_obj:
        while chunk := file_obj.read(HASH_CHUNK_SIZE_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _as_object(value: JsonValue | None) -> JsonObject | None:
    return value if isinstance(value, dict) else None


def _string_field(document: JsonObject, field_name: str) -> str | None:
    value = document.get(field_name)
    return value if isinstance(value, str) else None


def _int_field(document: JsonObject, field_name: str) -> int | None:
    value = document.get(field_name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
