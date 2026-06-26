from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias


JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ManifestValidationError:
    path: str
    message: str
    validator: str | None = None


@dataclass(frozen=True, slots=True)
class FileCheckResult:
    item_id: str
    relative_path: str
    status: str
    ok: bool
    expected_size: int | None
    actual_size: int | None
    expected_sha256: str | None
    actual_sha256: str | None
    message: str


@dataclass(frozen=True, slots=True)
class ManifestValidationResult:
    schema_version: str
    run_id: str
    status: str
    ok: bool
    release_evidence_status: str
    tool: JsonObject
    started_at_utc: str
    finished_at_utc: str
    manifest_path: str
    schema_path: str
    fixture_root: str | None
    check_files: bool
    corpus_id: str | None
    case_id: str | None
    image_id: str | None
    expected_item_count: int | None
    warning_count: int
    error_count: int
    errors: list[ManifestValidationError]
    file_check_enabled: bool = False
    file_checked_count: int = 0
    file_skipped_count: int = 0
    file_error_count: int = 0
    file_checks: list[FileCheckResult] = field(default_factory=list)
    summary: JsonObject = field(default_factory=dict)

    @property
    def file_check_count(self) -> int:
        return self.file_checked_count

    @property
    def file_check_passed_count(self) -> int:
        return self.file_checked_count - self.file_error_count

    @property
    def file_check_failed_count(self) -> int:
        return self.file_error_count

    @property
    def file_check_skipped_count(self) -> int:
        return self.file_skipped_count
