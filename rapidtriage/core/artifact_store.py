from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, IO, Iterable, Mapping


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
LEGACY_ADAPTER_VERSION = "legacy-artifact-contract-adapter-v1"


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


def build_artifact_record_v1_from_legacy(
    row: Mapping[str, object],
    *,
    kind: str,
    provider_name: str,
    root: str | Path,
    index: int,
    case_id: str = "standalone-artifacts",
    source_id: str | None = None,
) -> dict[str, object]:
    """Adapt existing collector rows into the normalized ArtifactRecordV1 contract.

    Legacy collectors still return compact rows for backwards compatibility. This adapter
    gives search/review/report/columnar layers a stable contract without rewriting every
    parser at once.
    """
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    artifact_type = str(row.get("artifact_type") or kind or "artifact")
    path = str(row.get("path") or details.get("source_path") or details.get("path") or root)
    source = build_artifact_source(details, root=root, path=path, case_id=case_id, source_id=source_id or kind)
    parser = str(details.get("parser") or provider_name or kind or "rapidtriage")
    parser_version = str(details.get("parser_version") or details.get("profile_version") or LEGACY_ADAPTER_VERSION)
    confidence = normalized_contract_confidence(row, details)
    blockers = normalized_string_list(
        details.get("commercial_grade_blockers")
        or details.get("reportability_blockers")
        or details.get("validation_blockers")
        or []
    )
    legal_limitations = normalized_string_list(
        details.get("legal_limitations")
        or details.get("not_proof_of")
        or details.get("privacy_legal_warning")
        or details.get("limitation")
        or []
    )
    validation_required = normalized_bool(
        details.get("validation_required"),
        default=bool(blockers) or confidence < 0.99,
    )
    commercial_ready = normalized_bool(
        details.get("commercial_grade_ready"),
        default=False,
    )
    fields = {
        "legacy_provider": str(row.get("provider") or provider_name),
        "legacy_supported": bool(row.get("supported", True)),
        "legacy_path": path,
        "details": dict(details),
        "review_contract": {
            "default_status": "unreviewed",
            "source_viewer_required": True,
            "include_in_report_allowed": not validation_required,
        },
        "gui_contract": {
            "primary_tab": "artifacts",
            "source_viewer": artifact_source_viewer(artifact_type, details),
            "filter_terms": artifact_filter_terms(artifact_type, details),
        },
    }
    record_core = {
        "schema": ARTIFACT_RECORD_SCHEMA,
        "artifact_family": str(kind or artifact_type),
        "artifact_type": artifact_type,
        "parser": parser,
        "parser_version": parser_version,
        "source": source,
        "confidence": confidence,
        "validation_required": validation_required,
        "commercial_grade_ready": commercial_ready,
        "commercial_grade_blockers": blockers,
        "legal_limitations": legal_limitations,
        "fields": fields,
    }
    record_core["artifact_id"] = stable_artifact_id(record_core, index=index)
    return record_core


def attach_artifact_record_contracts(
    payload: Mapping[str, object],
    *,
    kind: str,
    root: str | Path,
    case_id: str = "standalone-artifacts",
) -> dict[str, object]:
    provider = payload.get("provider") if isinstance(payload.get("provider"), Mapping) else {}
    provider_name = str(provider.get("name") or kind)
    rows = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
    adapted_rows: list[object] = []
    valid_count = 0
    invalid_count = 0
    contract_errors: list[dict[str, object]] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, Mapping):
            adapted_rows.append(row)
            invalid_count += 1
            contract_errors.append({"index": index, "errors": ["artifact-row-must-be-object"]})
            continue
        artifact_record = build_artifact_record_v1_from_legacy(
            row,
            kind=kind,
            provider_name=provider_name,
            root=root,
            index=index,
            case_id=case_id,
            source_id=kind,
        )
        errors = validate_artifact_record(artifact_record)
        if errors:
            invalid_count += 1
            contract_errors.append({"index": index, "errors": errors, "artifact_type": row.get("artifact_type")})
        else:
            valid_count += 1
        adapted = dict(row)
        adapted["artifact_record"] = artifact_record
        adapted_rows.append(adapted)
    result = dict(payload)
    result["artifacts"] = adapted_rows
    result["artifact_record_contract"] = {
        "profile_version": "artifact-output-contract-v1",
        "schema": ARTIFACT_RECORD_SCHEMA,
        "adapter_version": LEGACY_ADAPTER_VERSION,
        "record_count": len(rows),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "gui_usable": invalid_count == 0,
        "errors": contract_errors[:100],
    }
    summary = dict(result.get("summary")) if isinstance(result.get("summary"), Mapping) else {}
    summary["artifact_record_contract_valid_count"] = valid_count
    summary["artifact_record_contract_invalid_count"] = invalid_count
    result["summary"] = summary
    return result


def build_artifact_source(
    details: Mapping[str, object],
    *,
    root: str | Path,
    path: str,
    case_id: str,
    source_id: str,
) -> dict[str, object]:
    return {
        "case_id": str(case_id),
        "source_id": str(source_id),
        "source_path": str(details.get("source_path") or path or root),
        "offset": normalized_optional_int(first_present(details, "offset", "source_offset")),
        "length": normalized_optional_int(first_present(details, "length", "size", "size_bytes")),
        "hashes": normalized_hashes(details),
    }


def normalized_contract_confidence(row: Mapping[str, object], details: Mapping[str, object]) -> float:
    for value in (
        row.get("confidence"),
        details.get("parser_confidence"),
        details.get("confidence"),
        details.get("reportability_score"),
    ):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return min(1.0, max(0.0, float(value)))
    return 1.0 if bool(row.get("supported", True)) else 0.4


def normalized_bool(value: object, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def normalized_optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value >= 0 and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def first_present(details: Mapping[str, object], *keys: str) -> object:
    for key in keys:
        if key in details and details[key] is not None:
            return details[key]
    return None


def normalized_hashes(details: Mapping[str, object]) -> dict[str, str]:
    hashes = details.get("hashes")
    if isinstance(hashes, Mapping):
        return {str(key): str(value) for key, value in hashes.items() if value}
    output: dict[str, str] = {}
    for key in ("md5", "sha1", "sha256", "source_sha256", "file_sha256"):
        value = details.get(key)
        if value:
            output[key.replace("source_", "").replace("file_", "")] = str(value)
    return output


def normalized_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, Mapping):
        return [json.dumps(dict(value), ensure_ascii=False, sort_keys=True)]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        return [str(item) for item in value if str(item)]
    return [str(value)] if str(value) else []


def artifact_source_viewer(artifact_type: str, details: Mapping[str, object]) -> str:
    haystack = " ".join([artifact_type, " ".join(str(key) for key in details.keys())]).lower()
    if any(token in haystack for token in ("sqlite", "database", "edb", "ese")):
        return "sqlite-db-viewer"
    if any(token in haystack for token in ("eventlog", "evtx", "etl")):
        return "eventlog-viewer"
    if any(token in haystack for token in ("registry", "shellbag", "sam", "ntuser", "usrclass")):
        return "registry-viewer"
    if any(token in haystack for token in ("image", "video", "audio", "media")):
        return "media-viewer"
    if any(token in haystack for token in ("email", "mail", "mbox", "eml")):
        return "email-viewer"
    return "source-viewer"


def artifact_filter_terms(artifact_type: str, details: Mapping[str, object]) -> list[str]:
    terms = {artifact_type}
    for key in ("parser", "service", "browser", "provider", "app", "tool"):
        value = details.get(key)
        if value:
            terms.add(str(value))
    return sorted(terms)


def stable_artifact_id(record_core: Mapping[str, Any], *, index: int) -> str:
    source = record_core.get("source") if isinstance(record_core.get("source"), Mapping) else {}
    material = {
        "family": record_core.get("artifact_family"),
        "type": record_core.get("artifact_type"),
        "parser": record_core.get("parser"),
        "source_path": source.get("source_path"),
        "offset": source.get("offset"),
        "index": index,
    }
    digest = hashlib.sha256(json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    return f"artifact-{digest[:24]}"


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
