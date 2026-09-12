"""Import a FrameTrace ``package-case`` directory into a CaseDatabase.

FrameTrace ``package-case`` produces ``reports/package_*/`` directories that
contain ``manifest.sha256`` (``<sha256>  <relative/path>`` lines) and
``package-manifest.json`` (``schema_version``/``package_type``/``files[]``).
The packaged ``db/video_index.json`` is a single JSON document with a
``videos[]`` array; ``db/videos.jsonl`` carries the same rows as JSONL.

This adapter verifies every manifest entry against the bytes on disk before
importing. Hash mismatches and missing files are recorded as case artifacts
and an audit event rather than silently accepted. Videos are imported as
``file_record`` rows under a ``frametrace-package`` evidence source via the
public ``CaseDatabase.import_run_output`` API.

CLI wiring intentionally lives in this module so it does not require changes
to ``rapidtriage/cli/``::

    python -m rapidtriage.core.frametrace_import PACKAGE_DIR \
        --db CASE.db --case-id CASE-001 [--case-name NAME] [--verify-only]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path

from .case_db import CaseDatabase, open_case_database

FRAMETRACE_IMPORT_VERSION = "frametrace-package-import-v1"
FRAMETRACE_PACKAGE_TYPE = "frametrace-case-package"
CHECKSUM_MANIFEST_NAME = "manifest.sha256"
PACKAGE_MANIFEST_NAME = "package-manifest.json"
VIDEO_INDEX_NAME = "db/video_index.json"
VIDEO_JSONL_NAME = "db/videos.jsonl"
CHECKSUM_LINE_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?(.+?)\s*$")
MANIFEST_HASH_LIMIT_BYTES = 4 * 1024 * 1024 * 1024
VIDEO_INDEX_LIMIT_BYTES = 64 * 1024 * 1024


class FrametraceImportError(ValueError):
    """Raised when a frametrace package directory is invalid or unsafe."""


def verify_frametrace_package(package_dir: Path) -> dict[str, object]:
    """Verify ``manifest.sha256`` and ``package-manifest.json`` against disk.

    Returns a machine-readable verification payload. ``status`` is one of
    ``verified``, ``mismatch`` (one or more listed files differ or are
    missing), or ``incomplete`` (manifest itself missing/unreadable).
    """
    package_dir = Path(package_dir).expanduser().resolve()
    if not package_dir.is_dir():
        raise FrametraceImportError(f"frametrace package directory not found: {package_dir}")
    checksum_path = package_dir / CHECKSUM_MANIFEST_NAME
    manifest_path = package_dir / PACKAGE_MANIFEST_NAME
    if not checksum_path.is_file():
        raise FrametraceImportError(f"frametrace package is missing {CHECKSUM_MANIFEST_NAME}: {checksum_path}")

    checksum_entries = parse_checksum_manifest(checksum_path)
    manifest = parse_package_manifest(manifest_path) if manifest_path.is_file() else {}
    manifest_files = manifest.get("files")
    manifest_by_rel = {
        str(row.get("relative_path") or ""): row
        for row in manifest_files
        if isinstance(row, Mapping)
    } if isinstance(manifest_files, list) else {}

    entries: list[dict[str, object]] = []
    for rel_path, expected_sha256 in checksum_entries:
        entry: dict[str, object] = {
            "relative_path": rel_path,
            "expected_sha256": expected_sha256,
        }
        target = safe_package_member(package_dir, rel_path)
        if target is None:
            entry["status"] = "unsafe-path"
        elif not target.is_file():
            entry["status"] = "missing"
        else:
            entry["size_bytes"] = target.stat().st_size
            actual = sha256_file(target)
            entry["actual_sha256"] = actual
            entry["status"] = "ok" if actual.lower() == expected_sha256.lower() else "mismatch"
        manifest_row = manifest_by_rel.get(rel_path)
        if isinstance(manifest_row, Mapping):
            entry["manifest_size_bytes"] = manifest_row.get("size_bytes")
            entry["manifest_sha256"] = manifest_row.get("sha256")
            if entry.get("status") == "ok" and str(manifest_row.get("sha256") or "").lower() != expected_sha256.lower():
                entry["status"] = "manifest-disagreement"
        entries.append(entry)

    listed = {rel for rel, _ in checksum_entries}
    extra_manifest_rows = sorted(rel for rel in manifest_by_rel if rel and rel not in listed)
    problem_count = sum(1 for entry in entries if entry["status"] != "ok")
    status = "verified" if problem_count == 0 and not extra_manifest_rows else "mismatch"
    return {
        "profile_version": FRAMETRACE_IMPORT_VERSION,
        "package_dir": str(package_dir),
        "package_manifest": manifest,
        "package_manifest_present": manifest_path.is_file(),
        "package_type": str(manifest.get("package_type") or ""),
        "package_type_ok": not manifest or manifest.get("package_type") == FRAMETRACE_PACKAGE_TYPE,
        "entries": entries,
        "manifest_only_entries": extra_manifest_rows,
        "status": status,
        "summary": {
            "listed_file_count": len(entries),
            "verified_count": sum(1 for entry in entries if entry["status"] == "ok"),
            "mismatch_count": sum(1 for entry in entries if entry["status"] == "mismatch"),
            "missing_count": sum(1 for entry in entries if entry["status"] == "missing"),
            "unsafe_path_count": sum(1 for entry in entries if entry["status"] == "unsafe-path"),
            "manifest_disagreement_count": sum(1 for entry in entries if entry["status"] == "manifest-disagreement"),
            "manifest_only_count": len(extra_manifest_rows),
        },
    }


def parse_checksum_manifest(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FrametraceImportError(f"could not read checksum manifest {path}: {exc}") from exc
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = CHECKSUM_LINE_RE.match(line)
        if not match:
            raise FrametraceImportError(
                f"invalid {CHECKSUM_MANIFEST_NAME} line {line_number}: {line[:120]!r}"
            )
        entries.append((match.group(2).strip(), match.group(1).lower()))
    return entries


def parse_package_manifest(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FrametraceImportError(f"could not parse {PACKAGE_MANIFEST_NAME}: {exc}") from exc
    if not isinstance(payload, dict):
        raise FrametraceImportError(f"{PACKAGE_MANIFEST_NAME} must be a JSON object")
    return payload


def safe_package_member(package_dir: Path, relative_path: str) -> Path | None:
    """Resolve a manifest-relative path, refusing escapes outside the package."""
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    resolved = (package_dir / candidate).resolve()
    try:
        resolved.relative_to(package_dir)
    except ValueError:
        return None
    return resolved


def sha256_file(path: Path, *, limit: int = MANIFEST_HASH_LIMIT_BYTES) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def read_video_index(package_dir: Path) -> list[dict[str, object]]:
    """Read ``db/video_index.json`` videos[], falling back to videos.jsonl."""
    index_path = package_dir / VIDEO_INDEX_NAME
    videos: list[dict[str, object]] = []
    if index_path.is_file():
        if index_path.stat().st_size > VIDEO_INDEX_LIMIT_BYTES:
            raise FrametraceImportError(f"{VIDEO_INDEX_NAME} exceeds bounded-read limit")
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise FrametraceImportError(f"could not parse {VIDEO_INDEX_NAME}: {exc}") from exc
        rows = payload.get("videos") if isinstance(payload, Mapping) else None
        if isinstance(rows, list):
            videos.extend(dict(row) for row in rows if isinstance(row, Mapping))
    if videos:
        return videos
    jsonl_path = package_dir / VIDEO_JSONL_NAME
    if jsonl_path.is_file():
        if jsonl_path.stat().st_size > VIDEO_INDEX_LIMIT_BYTES:
            raise FrametraceImportError(f"{VIDEO_JSONL_NAME} exceeds bounded-read limit")
        for line in jsonl_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, Mapping):
                videos.append(dict(row))
    return videos


def video_source_path(video: Mapping[str, object], package_dir: Path) -> str:
    for key in ("source_path", "path", "absolute_path"):
        value = str(video.get(key) or "").strip()
        if value:
            return value
    relative = str(video.get("relative_path") or "").strip()
    if relative:
        member = safe_package_member(package_dir, relative)
        if member is not None:
            return str(member)
    file_url = str(video.get("file_url") or "").strip()
    if file_url.startswith("file://"):
        return file_url.removeprefix("file://")
    return file_url


def video_file_candidate(video: Mapping[str, object], package_dir: Path) -> dict[str, object]:
    path = video_source_path(video, package_dir)
    size = video.get("size_bytes") or video.get("size")
    modified = (
        video.get("modified_at")
        or video.get("mtime_iso")
        or video.get("mtime")
        or video.get("last_write_time")
        or ""
    )
    return {
        "path": path,
        "extension": Path(path).suffix.lower().lstrip("."),
        "size": size,
        "modified_at": modified,
    }


def video_artifact_row(video: Mapping[str, object], package_dir: Path, index: int) -> dict[str, object]:
    source_path = video_source_path(video, package_dir)
    video_id = str(video.get("id") or video.get("video_id") or "")
    return {
        "provider": "frametrace-package-import",
        "artifact_type": "frametrace-video-record",
        "path": source_path,
        "supported": True,
        "details": {
            "parser": "frametrace-package-import",
            "parser_version": FRAMETRACE_IMPORT_VERSION,
            "coverage_status": "frametrace-video-index-row",
            "reportability": "triage",
            "source_format": "frametrace-video-index-json",
            "source_index": index,
            "source_path": source_path,
            "video_id": video_id,
            "relative_path": str(video.get("relative_path") or ""),
            "file_url": str(video.get("file_url") or ""),
            "size_bytes": video.get("size_bytes"),
            "ffprobe_ok": video.get("ffprobe_ok"),
            "source_profile": video.get("source_profile") if isinstance(video.get("source_profile"), Mapping) else {},
            "evidence_strength": "external-tool-index-row",
            "validation_required": True,
            "validation_guidance": (
                "Row imported from a FrameTrace package index; source_path refers to the "
                "originating host and may not exist on this machine."
            ),
            "raw": dict(video),
        },
    }


def integrity_artifact_row(entry: Mapping[str, object]) -> dict[str, object]:
    rel_path = str(entry.get("relative_path") or "")
    status = str(entry.get("status") or "unknown")
    return {
        "provider": "frametrace-package-import",
        "artifact_type": "frametrace-package-integrity",
        "path": rel_path,
        "supported": False,
        "details": {
            "parser": "frametrace-package-import",
            "parser_version": FRAMETRACE_IMPORT_VERSION,
            "coverage_status": "package-integrity-check",
            "reportability": "triage",
            "source_format": "frametrace-manifest-sha256",
            "relative_path": rel_path,
            "integrity_status": status,
            "expected_sha256": str(entry.get("expected_sha256") or ""),
            "actual_sha256": str(entry.get("actual_sha256") or ""),
            "manifest_sha256": str(entry.get("manifest_sha256") or ""),
            "size_bytes": entry.get("size_bytes"),
            "evidence_strength": "package-integrity-finding",
            "validation_required": True,
            "validation_guidance": (
                "Package file failed manifest.sha256 verification; treat packaged "
                "contents as altered-after-packaging until re-verified with FrameTrace."
            ),
            "raw": dict(entry),
        },
    }


def import_frametrace_package(
    package_dir: Path,
    *,
    case_id: str,
    case_name: str | None = None,
    db_path: Path | None = None,
    database: CaseDatabase | None = None,
) -> dict[str, object]:
    """Verify and import a frametrace package into a CaseDatabase.

    Exactly one of ``database`` or ``db_path`` must be provided. Hash
    mismatches do not abort the import; they are imported as
    ``frametrace-package-integrity`` findings and flagged in the audit event
    and return payload so they are never silently accepted.
    """
    if database is None:
        if db_path is None:
            raise FrametraceImportError("database or db_path is required")
        database = open_case_database(Path(db_path))
    package_dir = Path(package_dir).expanduser().resolve()
    verification = verify_frametrace_package(package_dir)
    videos = read_video_index(package_dir)

    with tempfile.TemporaryDirectory(prefix="rapidtriage-frametrace-") as staging:
        staging_dir = Path(staging)
        files_json = staging_dir / "frametrace-files.json"
        files_json.write_text(
            json.dumps(
                {"candidates": [video_file_candidate(video, package_dir) for video in videos]},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        artifact_rows: list[dict[str, object]] = [
            video_artifact_row(video, package_dir, index) for index, video in enumerate(videos)
        ]
        artifact_rows.extend(
            integrity_artifact_row(entry)
            for entry in verification["entries"]  # type: ignore[index]
            if isinstance(entry, Mapping) and entry.get("status") != "ok"
        )
        artifact_rows.extend(
            integrity_artifact_row({"relative_path": rel, "status": "manifest-only-not-in-checksum"})
            for rel in verification["manifest_only_entries"]  # type: ignore[index]
        )
        artifacts_json = staging_dir / "frametrace-artifacts.json"
        artifacts_json.write_text(
            json.dumps({"artifacts": artifact_rows}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        run_summary: dict[str, object] = {
            "source": {
                "source_path": str(package_dir),
                "analysis_root": str(package_dir),
                "type": "frametrace-package",
            },
            "mode": "frametrace-package-import",
            "root": str(package_dir),
            "outputs": {
                "files": str(files_json),
                "artifacts_frametrace": str(artifacts_json),
            },
        }
        imported = database.import_run_output(run_summary, case_id=case_id, case_name=case_name)

    verification_status = str(verification["status"])
    audit_id = database.add_audit_event(
        case_id=str(imported["case_id"]),
        action="frametrace.package-imported",
        target_type="frametrace-package",
        target_id=str(package_dir),
        params_json=json.dumps(
            {
                "verification": verification["summary"],
                "video_count": len(videos),
                "import_summary": imported["summary"],
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        result="ok" if verification_status == "verified" else "partial",
        error="" if verification_status == "verified" else f"package verification status: {verification_status}",
    )
    return {
        "profile_version": FRAMETRACE_IMPORT_VERSION,
        "command": "frametrace-import",
        "package_dir": str(package_dir),
        "case_id": imported["case_id"],
        "verification": verification,
        "video_count": len(videos),
        "import": imported,
        "audit_citation_id": audit_id,
        "status": "imported" if verification_status == "verified" else "imported-with-integrity-findings",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m rapidtriage.core.frametrace_import",
        description="Verify and import a FrameTrace package_* directory into a rapidtriage case database.",
    )
    parser.add_argument("package_dir", type=Path, help="Path to the frametrace package_* directory")
    parser.add_argument("--db", type=Path, help="Path to the rapidtriage SQLite case database")
    parser.add_argument("--case-id", default="", help="Case identifier for the import")
    parser.add_argument("--case-name", default=None, help="Case display name when creating a case")
    parser.add_argument("--verify-only", action="store_true", help="Verify manifest.sha256 without importing")
    args = parser.parse_args(argv)

    if args.verify_only:
        payload = verify_frametrace_package(args.package_dir)
    else:
        if args.db is None or not args.case_id:
            parser.error("--db and --case-id are required unless --verify-only is used")
        payload = import_frametrace_package(
            args.package_dir,
            case_id=args.case_id,
            case_name=args.case_name,
            db_path=args.db,
        )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
