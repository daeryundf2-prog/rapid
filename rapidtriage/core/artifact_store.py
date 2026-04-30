from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Iterable, Mapping


ARTIFACT_RECORD_SCHEMA = "ArtifactRecordV1"
REQUIRED_ARTIFACT_RECORD_FIELDS = {
    "schema",
    "artifact_id",
    "artifact_family",
    "artifact_type",
    "parser",
    "parser_version",
    "source",
    "confidence",
    "validation_required",
    "commercial_grade_ready",
    "commercial_grade_blockers",
    "legal_limitations",
    "fields",
}
REQUIRED_SOURCE_FIELDS = {"case_id", "source_id", "source_path", "offset", "length", "hashes"}


class ArtifactStoreError(ValueError):
    """Raised when a normalized artifact record cannot be stored safely."""


@dataclass(frozen=True)
class JsonlArtifactWriteResult:
    path: str
    manifest_path: str
    record_count: int
    rejected_count: int
    size_bytes: int
    sha256: str
    errors: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "manifest_path": self.manifest_path,
            "record_count": self.record_count,
            "rejected_count": self.rejected_count,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "errors": self.errors,
        }


class JsonlArtifactStreamWriter:
    """Incrementally write normalized artifact records without buffering a full case in memory."""

    def __init__(
        self,
        *,
        output_path: Path,
        manifest_path: Path | None = None,
        reject_invalid: bool = True,
    ) -> None:
        self.output_path = output_path.expanduser().resolve()
        self.manifest_path = (
            manifest_path or self.output_path.with_suffix(self.output_path.suffix + ".manifest.json")
        ).expanduser().resolve()
        self.reject_invalid = reject_invalid
        self.record_count = 0
        self.rejected_count = 0
        self.errors: list[dict[str, object]] = []
        self._record_index = 0
        self._handle: IO[str] | None = None
        self._closed = False

    def __enter__(self) -> "JsonlArtifactStreamWriter":
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if not self._closed and self._handle is not None:
            self._handle.close()

    def open(self) -> None:
        if self._handle is not None:
            return
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.output_path.open("w", encoding="utf-8")

    def write(self, record: Mapping[str, object]) -> None:
        if self._closed:
            raise ArtifactStoreError("cannot write to a closed artifact stream")
        if self._handle is None:
            self.open()
        self._record_index += 1
        validation_errors = validate_artifact_record(record)
        if validation_errors:
            self.rejected_count += 1
            self.errors.append(
                {
                    "record_index": self._record_index,
                    "errors": validation_errors,
                    "artifact_id": str(record.get("artifact_id") or ""),
                }
            )
            if self.reject_invalid:
                return
        assert self._handle is not None
        self._handle.write(json.dumps(dict(record), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        self._handle.write("\n")
        self.record_count += 1

    def close(self) -> JsonlArtifactWriteResult:
        if self._closed:
            return build_jsonl_artifact_write_result(
                output_path=self.output_path,
                manifest_path=self.manifest_path,
                record_count=self.record_count,
                rejected_count=self.rejected_count,
                errors=self.errors,
            )
        if self._handle is None:
            self.open()
        assert self._handle is not None
        self._handle.close()
        self._closed = True
        return write_jsonl_artifact_manifest(
            output_path=self.output_path,
            manifest_path=self.manifest_path,
            record_count=self.record_count,
            rejected_count=self.rejected_count,
            errors=self.errors,
        )


def write_jsonl_artifacts(
    records: Iterable[Mapping[str, object]],
    *,
    output_path: Path,
    manifest_path: Path | None = None,
    reject_invalid: bool = True,
) -> JsonlArtifactWriteResult:
    with JsonlArtifactStreamWriter(
        output_path=output_path,
        manifest_path=manifest_path,
        reject_invalid=reject_invalid,
    ) as writer:
        for record in records:
            writer.write(record)
        return writer.close()


def build_jsonl_artifact_write_result(
    *,
    output_path: Path,
    manifest_path: Path,
    record_count: int,
    rejected_count: int,
    errors: list[dict[str, object]],
) -> JsonlArtifactWriteResult:
    digest = sha256_file(output_path)
    size = output_path.stat().st_size
    return JsonlArtifactWriteResult(
        path=str(output_path),
        manifest_path=str(manifest_path),
        record_count=record_count,
        rejected_count=rejected_count,
        size_bytes=size,
        sha256=digest,
        errors=errors,
    )


def write_jsonl_artifact_manifest(
    *,
    output_path: Path,
    manifest_path: Path,
    record_count: int,
    rejected_count: int,
    errors: list[dict[str, object]],
) -> JsonlArtifactWriteResult:
    result = build_jsonl_artifact_write_result(
        output_path=output_path,
        manifest_path=manifest_path,
        record_count=record_count,
        rejected_count=rejected_count,
        errors=errors,
    )
    manifest = {
        "command": "jsonl-artifact-store",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "schema": ARTIFACT_RECORD_SCHEMA,
        "path": str(output_path),
        "record_count": result.record_count,
        "rejected_count": result.rejected_count,
        "size_bytes": result.size_bytes,
        "sha256": result.sha256,
        "streaming_safe": True,
        "storage_role": "worker-jsonl-staging-before-parquet",
        "errors": errors[:100],
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def validate_artifact_record(record: Mapping[str, object]) -> list[str]:
    errors: list[str] = []
    missing = sorted(field for field in REQUIRED_ARTIFACT_RECORD_FIELDS if field not in record)
    errors.extend(f"missing-field:{field}" for field in missing)
    if record.get("schema") != ARTIFACT_RECORD_SCHEMA:
        errors.append("schema-must-be-ArtifactRecordV1")
    source = record.get("source")
    if not isinstance(source, Mapping):
        errors.append("source-must-be-object")
    else:
        source_missing = sorted(field for field in REQUIRED_SOURCE_FIELDS if field not in source)
        errors.extend(f"source-missing-field:{field}" for field in source_missing)
    confidence = record.get("confidence")
    if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
        errors.append("confidence-must-be-0-to-1")
    for boolean_field in ("validation_required", "commercial_grade_ready"):
        if boolean_field in record and not isinstance(record.get(boolean_field), bool):
            errors.append(f"{boolean_field}-must-be-boolean")
    for list_field in ("commercial_grade_blockers", "legal_limitations"):
        if list_field in record and not isinstance(record.get(list_field), list):
            errors.append(f"{list_field}-must-be-list")
    if "fields" in record and not isinstance(record.get("fields"), Mapping):
        errors.append("fields-must-be-object")
    return errors


def read_jsonl_artifacts(path: Path) -> Iterable[dict[str, object]]:
    with path.expanduser().resolve().open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ArtifactStoreError(f"line {line_number} is not a JSON object")
            yield payload


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
