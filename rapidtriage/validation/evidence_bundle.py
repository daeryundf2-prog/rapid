from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from rapidtriage.validation.known_answer_types import JsonObject, JsonValue


FORBIDDEN_EXTENSIONS: Final = frozenset({".e01", ".ex01", ".dd", ".raw", ".img", ".vhd", ".vhdx", ".aff", ".001"})
LARGE_FILE_THRESHOLD_BYTES: Final = 1_048_576
HASH_CHUNK_SIZE_BYTES: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BundleResult:
    exit_code: int
    document: JsonObject


def build_bundle_manifest(root: Path) -> BundleResult:
    resolved_root = root.resolve()
    artifacts: list[JsonValue] = []
    issues: list[JsonValue] = []
    total_size_bytes = 0
    for path in sorted(candidate for candidate in resolved_root.rglob("*") if candidate.is_file()):
        relative_path = _relative_path(resolved_root, path)
        if relative_path is None:
            issues.append(_issue("critical", str(path), "path escapes bundle root", True))
            continue
        artifacts.append(_artifact(path, relative_path))
        total_size_bytes += path.stat().st_size
        issues.extend(_policy_issues(path, relative_path))

    blocking_count = sum(1 for issue in issues if isinstance(issue, dict) and issue.get("release_blocking") is True)
    warning_count = sum(1 for issue in issues if isinstance(issue, dict) and issue.get("severity") == "warning")
    status = "release_blocked" if blocking_count else "engineering_check_only"
    document: JsonObject = {
        "schema_version": "rapidforensic-release-evidence-bundle-manifest-v1",
        "bundle_root": str(root),
        "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "release_evidence_status": status,
        "artifacts": artifacts,
        "policy_issues": issues,
        "summary": {
            "artifact_count": len(artifacts),
            "total_size_bytes": total_size_bytes,
            "warning_count": warning_count,
            "blocking_issue_count": blocking_count,
        },
    }
    return BundleResult(exit_code=1 if blocking_count else 0, document=document)


def format_text(result: BundleResult) -> str:
    summary = _object(result.document, "summary")
    return "\n".join(
        [
            f"{result.document['release_evidence_status']} evidence bundle manifest",
            f"artifacts: {_int(summary, 'artifact_count')}",
            f"blocking_issues: {_int(summary, 'blocking_issue_count')}",
        ],
    )


def write_summary(result: BundleResult, path: Path) -> None:
    summary = _object(result.document, "summary")
    lines = [
        "# Release Evidence Bundle Summary",
        "",
        f"- Status: {result.document['release_evidence_status']}",
        f"- Artifacts: {_int(summary, 'artifact_count')}",
        f"- Blocking issues: {_int(summary, 'blocking_issue_count')}",
        "",
        "This summary is an engineering inventory, not release approval.",
        "",
    ]
    for issue in _list(result.document, "policy_issues"):
        if isinstance(issue, dict):
            lines.append(f"- {issue.get('severity')}: {issue.get('relative_path')} - {issue.get('message')}")
    _ = path.write_text("\n".join(lines), encoding="utf-8")


def _artifact(path: Path, relative_path: str) -> JsonObject:
    return {
        "relative_path": relative_path,
        "artifact_type": _artifact_type(path),
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


def _policy_issues(path: Path, relative_path: str) -> list[JsonObject]:
    issues: list[JsonObject] = []
    if path.suffix.lower() in FORBIDDEN_EXTENSIONS:
        issues.append(_issue("critical", relative_path, "raw evidence binary extension is forbidden in Git/bundle fixtures", True))
    if path.stat().st_size > LARGE_FILE_THRESHOLD_BYTES:
        issues.append(_issue("warning", relative_path, "artifact exceeds 1MB engineering fixture threshold", False))
    return issues


def _issue(severity: str, relative_path: str, message: str, release_blocking: bool) -> JsonObject:
    return {
        "severity": severity,
        "relative_path": relative_path,
        "message": message,
        "release_blocking": release_blocking,
    }


def _artifact_type(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name == "manifest.json" or "manifest" in name:
        return "manifest"
    if suffix == ".schema.json":
        return "schema"
    if "trusted-diff" in name:
        return "trusted_diff_result"
    if "results" in name:
        return "observed_result"
    if suffix in {".log", ".txt"}:
        return "log" if suffix == ".log" else "fixture"
    if suffix in {".md", ".rst"}:
        return "documentation"
    if suffix in {".sha256", ".hash"}:
        return "hash"
    return "other"


def _relative_path(root: Path, path: Path) -> str | None:
    try:
        relative = path.resolve().relative_to(root)
    except ValueError:
        return None
    if relative.is_absolute() or ".." in relative.parts:
        return None
    return relative.as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        while chunk := file_obj.read(HASH_CHUNK_SIZE_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _object(document: JsonObject, field: str) -> JsonObject:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, dict) else {}


def _list(document: JsonObject, field: str) -> list[JsonValue]:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, list) else []


def _int(document: JsonObject, field: str) -> int:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
