from __future__ import annotations

import datetime as dt
import csv
import hashlib
import json
import shutil
import sqlite3
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .docs import write_result


SQLITE_WAL_PREVIEW_VERSION = "sqlite-wal-recovery-mvp-preview-v1"
SQLITE_WAL_HEADER_SIZE = 32
SQLITE_WAL_FRAME_HEADER_SIZE = 24
SQLITE_DATABASE_HEADER_SIZE = 100
SQLITE_WAL_MAGIC_VALUES = {0x377F0682: "big-endian", 0x377F0683: "little-endian"}
SQLITE_BTREE_PAGE_TYPES = {
    0x02: "interior-index-btree-page",
    0x05: "interior-table-btree-page",
    0x0A: "leaf-index-btree-page",
    0x0D: "leaf-table-btree-page",
}
SQLITE_MAX_FREEBLOCK_PREVIEW = 20
SQLITE_MAX_FREELIST_TRUNK_PREVIEW = 10
SQLITE_MAX_FREELIST_LEAF_PREVIEW = 100
SQLITE_MAX_CELL_PREVIEW = 20
SQLITE_MAX_RECORD_VALUE_PREVIEW_BYTES = 128
SQLITE_MAX_FREEBLOCK_CANDIDATES = 20
SQLITE_TRUSTED_TOOL_PROFILE_VERSION = "sqlite-trusted-tool-comparison-profile-v1"


class SqliteWalPreviewError(ValueError):
    """Raised when SQLite WAL preview input is invalid."""


@dataclass(frozen=True)
class SqliteVarint:
    value: int
    next_offset: int
    size_bytes: int


def build_sqlite_wal_preview(
    *,
    database_path: Path,
    output_dir: Path | None = None,
    max_frames: int = 20,
    preferred_trusted_tool: str | None = None,
    trusted_tool_timeout_seconds: int = 300,
    tool_resolver: Callable[[str], str | None] = shutil.which,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, object]:
    database_path = database_path.expanduser().resolve()
    if not database_path.is_file():
        raise SqliteWalPreviewError(f"SQLite database not found: {database_path}")
    if max_frames <= 0:
        raise SqliteWalPreviewError("max_frames must be greater than zero")
    if output_dir is not None:
        output_dir = output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
    safe_copy = build_sqlite_safe_copy(database_path, output_dir=output_dir) if output_dir is not None else missing_safe_copy(database_path)
    analysis_database_path = Path(safe_copy["analysis_database_path"]) if safe_copy.get("analysis_database_path") else database_path
    wal_path = analysis_database_path.with_name(analysis_database_path.name + "-wal")
    shm_path = analysis_database_path.with_name(analysis_database_path.name + "-shm")
    wal_info = parse_sqlite_wal_file(wal_path, max_frames=max_frames) if wal_path.is_file() else missing_wal_info(wal_path)
    schema_profile = sqlite_schema_profile(analysis_database_path)
    wal_info = annotate_wal_records_with_schema(wal_info, schema_profile)
    database_header_profile = sqlite_database_header_profile(analysis_database_path)
    freelist_profile = sqlite_freelist_profile(analysis_database_path, database_header_profile)
    trusted_tool_profile = sqlite_trusted_tool_profile(
        database_path=analysis_database_path,
        wal_path=wal_path,
        output_dir=output_dir,
        schema_profile=schema_profile,
        preferred_tool=preferred_trusted_tool,
        timeout_seconds=trusted_tool_timeout_seconds,
        tool_resolver=tool_resolver,
        command_runner=command_runner,
    )
    trusted_semantic_diff_profile = sqlite_trusted_semantic_diff_profile(wal_info, trusted_tool_profile)
    candidate_false_positive_profile = sqlite_deleted_candidate_false_positive_profile()
    payload_core: dict[str, object] = {
        "command": "sqlite-wal-preview",
        "profile_version": SQLITE_WAL_PREVIEW_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "database": file_row(database_path),
        "analysis_database": file_row(analysis_database_path),
        "safe_copy": safe_copy,
        "wal": wal_info,
        "shm": file_row(shm_path) if shm_path.is_file() else {"path": str(shm_path), "exists": False},
        "schema_profile": schema_profile,
        "database_header_profile": database_header_profile,
        "freelist_profile": freelist_profile,
        "trusted_tool_profile": trusted_tool_profile,
        "trusted_semantic_diff_profile": trusted_semantic_diff_profile,
        "candidate_false_positive_profile": candidate_false_positive_profile,
        "recovery_scope": {
            "wal_detected": bool(wal_info.get("exists")),
            "frame_preview_count": len(wal_info.get("frames", [])) if isinstance(wal_info.get("frames"), list) else 0,
            "deleted_row_recovery_attempted": False,
            "schema_aware_carving_attempted": False,
            "schema_profile_available": schema_profile.get("status") == "parsed",
            "schema_aware_record_mapping_attempted": schema_profile.get("status") == "parsed",
            "schema_mapped_record_count": sqlite_wal_schema_mapped_record_count(wal_info),
            "deleted_record_candidate_count": sqlite_wal_deleted_record_candidate_count(wal_info),
            "trusted_tool_comparison_status": trusted_tool_profile.get("status"),
            "trusted_tool_comparison_ready": trusted_tool_profile.get("summary", {}).get("ready_for_candidate_diff", False),
            "trusted_semantic_diff_status": trusted_semantic_diff_profile.get("status"),
            "trusted_semantic_match_count": trusted_semantic_diff_profile.get("matched_candidate_count", 0),
            "candidate_false_positive_status": candidate_false_positive_profile.get("status"),
            "freelist_profile_available": freelist_profile.get("status") in {"parsed", "empty"},
            "freeblock_preview_count": sqlite_wal_freeblock_preview_count(wal_info),
        },
        "limitations": [
            "MVP previews WAL frames, page hashes, freeblock chains, freelist trunk metadata, and conservative deleted-record candidates; candidates require trusted-tool validation before reporting as recovered rows.",
            "Report-grade recovery requires schema-aware carving and trusted tool comparison such as sqlite-dissect/xsqlite.",
            "Output-backed runs create a hashed working copy of the database with matching -wal/-shm files before preview.",
        ],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "schema-aware-wal-row-recovery-required",
            "freelist-freeblock-carving-required",
            "trusted-sqlite-dissect-xsqlite-diff-required",
        ],
    }
    payload = {**payload_core, "manifest_sha256": stable_sqlite_wal_hash(payload_core)}
    if output_dir is not None:
        json_path = output_dir / "sqlite-wal-preview.json"
        markdown_path = output_dir / "sqlite-wal-preview.md"
        write_result(payload, json_path)
        markdown_path.write_text(render_sqlite_wal_preview_markdown(payload), encoding="utf-8")
        payload["outputs"] = {"json": str(json_path), "markdown": str(markdown_path)}
    return payload


def build_sqlite_safe_copy(database_path: Path, *, output_dir: Path) -> dict[str, object]:
    copy_dir = output_dir / "sqlite-wal-evidence-copy"
    if path_is_relative_to(database_path, copy_dir):
        raise SqliteWalPreviewError("SQLite WAL output copy directory must not contain the source database")
    if copy_dir.exists():
        shutil.rmtree(copy_dir)
    copy_dir.mkdir(parents=True, exist_ok=True)
    copy_rows = []
    for source_path in sqlite_sidecar_paths(database_path):
        destination_path = copy_dir / source_path.name
        if not source_path.exists():
            copy_rows.append({"source": missing_file_row(source_path), "copy": missing_file_row(destination_path), "copied": False, "source_stable": None})
            continue
        source_before = file_row(source_path)
        shutil.copy2(source_path, destination_path)
        copy_row = file_row(destination_path)
        source_after = file_row(source_path)
        copy_rows.append(
            {
                "source": source_after,
                "source_before_sha256": source_before["sha256"],
                "copy": copy_row,
                "copied": True,
                "source_stable": source_before["sha256"] == source_after["sha256"],
                "copy_matches_source_after": copy_row["sha256"] == source_after["sha256"],
            }
        )
    analysis_database_path = copy_dir / database_path.name
    wal_copy = analysis_database_path.with_name(analysis_database_path.name + "-wal")
    return {
        "profile_version": "sqlite-sidecar-safe-copy-v1",
        "copy_directory": str(copy_dir),
        "analysis_database_path": str(analysis_database_path),
        "copied_count": sum(1 for row in copy_rows if row["copied"]),
        "source_stable": all(row["source_stable"] is not False for row in copy_rows),
        "database_copied": analysis_database_path.is_file(),
        "wal_copied": wal_copy.is_file(),
        "sidecars": copy_rows,
        "purpose": "Parse a working copy so recovery preview does not mutate the source SQLite evidence set.",
    }


def path_is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def sqlite_trusted_tool_profile(
    *,
    database_path: Path,
    wal_path: Path,
    output_dir: Path | None,
    schema_profile: dict[str, object],
    preferred_tool: str | None,
    timeout_seconds: int,
    tool_resolver: Callable[[str], str | None],
    command_runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, object]:
    selected = select_sqlite_trusted_tool(preferred_tool=preferred_tool, tool_resolver=tool_resolver)
    export_dir = output_dir / "trusted-tool-output" if output_dir is not None else None
    if export_dir is not None:
        export_dir.mkdir(parents=True, exist_ok=True)
    command: list[str] = []
    completed: subprocess.CompletedProcess[str] | None = None
    status = "blocked"
    error = ""
    if selected["available"] and export_dir is not None:
        command = build_sqlite_trusted_tool_command(str(selected["tool"]), database_path, wal_path, export_dir, schema_profile)
        try:
            completed = command_runner(command, text=True, capture_output=True, timeout=timeout_seconds, check=False)
            status = "complete" if completed.returncode == 0 else "failed"
        except Exception as exc:  # pragma: no cover - external runtime dependent
            status = "failed"
            error = str(exc)
    elif selected["available"]:
        status = "blocked"
        error = "output-dir-required-for-trusted-tool-execution"
    exports = inventory_sqlite_trusted_tool_exports(export_dir) if export_dir is not None else []
    return {
        "profile_version": SQLITE_TRUSTED_TOOL_PROFILE_VERSION,
        "status": status,
        "selected_tool": selected,
        "trusted_tool_families": ["sqlite-dissect", "xsqlite"],
        "source": {
            "database": file_row(database_path),
            "wal": file_row(wal_path) if wal_path.is_file() else missing_file_row(wal_path),
        },
        "execution": {
            "command": command,
            "timeout_seconds": timeout_seconds,
            "returncode": completed.returncode if completed is not None else None,
            "stdout_tail": tail_text(completed.stdout if completed is not None else ""),
            "stderr_tail": tail_text(completed.stderr if completed is not None else error),
        },
        "exports": exports,
        "summary": {
            "tool_run_attempted": bool(selected["available"] and export_dir is not None),
            "tool_run_completed": status == "complete",
            "export_file_count": len(exports),
            "ready_for_candidate_diff": status == "complete" and bool(exports),
        },
        "limitations": [
            "Trusted-tool output is recorded as comparison evidence; automated semantic diff is limited to export presence and hashes in this MVP.",
            "xsqlite requires a concrete table name, so the first parsed table is used when xsqlite is selected.",
        ],
    }


def select_sqlite_trusted_tool(*, preferred_tool: str | None, tool_resolver: Callable[[str], str | None]) -> dict[str, object]:
    candidates = [preferred_tool] if preferred_tool else []
    candidates.extend(["sqlite_dissect", "sqlite-dissect", "xsqlite"])
    seen: list[str] = []
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.append(candidate)
        resolved = tool_resolver(candidate)
        if resolved:
            return {"tool": candidate, "path": resolved, "available": True, "candidates": seen}
    return {"tool": preferred_tool or "", "path": "", "available": False, "candidates": seen}


def build_sqlite_trusted_tool_command(tool: str, database_path: Path, wal_path: Path, export_dir: Path, schema_profile: dict[str, object]) -> list[str]:
    if tool in {"sqlite_dissect", "sqlite-dissect"}:
        command = [tool, str(database_path), "--schema-history", "--carve", "-d", str(export_dir), "-e", "csv"]
        if wal_path.is_file():
            command.extend(["-w", str(wal_path)])
        return command
    if tool == "xsqlite":
        table_name = first_sqlite_table_name(schema_profile) or "sqlite_schema"
        command = [tool, "recover"]
        if wal_path.is_file():
            command.extend(["--wal", str(wal_path)])
        command.extend([str(database_path), table_name, str(export_dir / f"{table_name}-xsqlite.xlsx")])
        return command
    return [tool, str(database_path), str(export_dir)]


def first_sqlite_table_name(schema_profile: dict[str, object]) -> str | None:
    tables = schema_profile.get("tables")
    if not isinstance(tables, list):
        return None
    for table in tables:
        if isinstance(table, dict) and isinstance(table.get("name"), str):
            return str(table["name"])
    return None


def inventory_sqlite_trusted_tool_exports(export_dir: Path | None) -> list[dict[str, object]]:
    if export_dir is None or not export_dir.exists():
        return []
    rows = []
    for path in sorted(export_dir.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        stat = path.stat()
        rows.append({"path": str(path), "name": path.name, "size_bytes": stat.st_size, "sha256": file_sha256(path)})
    return rows


def tail_text(value: str, limit: int = 4000) -> str:
    return str(value or "")[-limit:]


def sqlite_trusted_semantic_diff_profile(wal_info: dict[str, object], trusted_tool_profile: dict[str, object]) -> dict[str, object]:
    candidates = sqlite_flatten_deleted_record_candidates(wal_info)
    profile: dict[str, object] = {
        "profile_version": "sqlite-trusted-semantic-diff-profile-v1",
        "status": "unavailable",
        "candidate_count": len(candidates),
        "trusted_csv_row_count": 0,
        "matched_candidate_count": 0,
        "matches": [],
        "unmatched_candidates": [],
        "exports_checked": [],
        "anomalies": [],
    }
    if not candidates:
        return {**profile, "status": "no-candidates"}
    if trusted_tool_profile.get("status") != "complete":
        return {**profile, "status": "trusted-tool-not-complete"}
    exports = trusted_tool_profile.get("exports")
    if not isinstance(exports, list) or not exports:
        return {**profile, "status": "no-trusted-exports"}
    rows: list[dict[str, str]] = []
    exports_checked = []
    anomalies = []
    for export in exports:
        if not isinstance(export, dict):
            continue
        path = Path(str(export.get("path", "")))
        if path.suffix.lower() != ".csv":
            continue
        try:
            export_rows = sqlite_read_trusted_csv_rows(path)
            rows.extend(export_rows)
            exports_checked.append({"path": str(path), "row_count": len(export_rows), "sha256": export.get("sha256")})
        except (OSError, UnicodeError, csv.Error) as exc:
            anomalies.append({"path": str(path), "error": str(exc)})
    if not exports_checked:
        return {**profile, "status": "no-csv-exports", "anomalies": anomalies}
    matches = []
    matched_ids: set[str] = set()
    for candidate in candidates:
        for row_index, row in enumerate(rows):
            match = sqlite_candidate_matches_trusted_row(candidate, row)
            if match["matched"]:
                candidate_id = str(candidate["candidate_id"])
                matched_ids.add(candidate_id)
                matches.append({"candidate_id": candidate_id, "trusted_row_index": row_index, **match})
                break
    unmatched = [candidate for candidate in candidates if str(candidate["candidate_id"]) not in matched_ids]
    return {
        **profile,
        "status": "matched" if matches and not unmatched else "partial-match" if matches else "no-match",
        "trusted_csv_row_count": len(rows),
        "matched_candidate_count": len(matched_ids),
        "matches": matches[:50],
        "unmatched_candidates": unmatched[:50],
        "exports_checked": exports_checked,
        "anomalies": anomalies,
    }


def sqlite_read_trusted_csv_rows(path: Path, *, max_rows: int = 10_000) -> list[dict[str, str]]:
    rows = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            if index >= max_rows:
                break
            normalized = {str(key or "").strip().lower(): str(value or "").strip() for key, value in row.items()}
            rows.append(normalized)
    return rows


def sqlite_flatten_deleted_record_candidates(wal_info: dict[str, object]) -> list[dict[str, object]]:
    rows = []
    frames = wal_info.get("frames")
    if not isinstance(frames, list):
        return rows
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        page_profile = frame.get("page_profile")
        if not isinstance(page_profile, dict):
            continue
        candidate_profile = page_profile.get("deleted_record_candidate_profile")
        if not isinstance(candidate_profile, dict):
            continue
        candidates = candidate_profile.get("candidates")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            mapping = candidate.get("schema_mapping") if isinstance(candidate.get("schema_mapping"), dict) else {}
            column_values = sqlite_schema_mapping_column_values(mapping if isinstance(mapping, dict) else {})
            candidate_id = f"frame-{frame.get('frame_index')}-page-{frame.get('page_number')}-candidate-{candidate.get('candidate_index')}"
            rows.append(
                {
                    "candidate_id": candidate_id,
                    "table_name": mapping.get("table_name") if isinstance(mapping, dict) else None,
                    "rowid": str(candidate.get("rowid")),
                    "column_values": column_values,
                    "payload_sha256": candidate.get("payload_sha256"),
                }
            )
    return rows


def sqlite_schema_mapping_column_values(mapping: dict[str, object]) -> dict[str, str]:
    values = {}
    columns = mapping.get("columns")
    if not isinstance(columns, list):
        return values
    for column in columns:
        if not isinstance(column, dict) or not isinstance(column.get("name"), str):
            continue
        preview = column.get("value_preview") if isinstance(column.get("value_preview"), dict) else {}
        rendered = sqlite_render_value_preview(preview if isinstance(preview, dict) else {})
        if rendered == "" and "rowid_alias_value" in column:
            rendered = str(column["rowid_alias_value"])
        if rendered != "":
            values[str(column["name"])] = rendered
    return values


def sqlite_render_value_preview(preview: dict[str, object]) -> str:
    value_type = preview.get("type")
    if value_type == "null":
        return ""
    if "text_preview" in preview:
        return str(preview["text_preview"])
    if "value" in preview and preview.get("value") is not None:
        return str(preview["value"])
    if "preview_hex" in preview:
        return str(preview["preview_hex"])
    return ""


def sqlite_candidate_matches_trusted_row(candidate: dict[str, object], trusted_row: dict[str, str]) -> dict[str, object]:
    table_name = str(candidate.get("table_name") or "").strip().lower()
    row_table = trusted_row.get("table") or trusted_row.get("table_name") or trusted_row.get("tbl_name") or ""
    if table_name and row_table and table_name != normalize_match_text(row_table):
        return {"matched": False, "reason": "table-mismatch"}
    rowid = normalize_match_text(str(candidate.get("rowid") or ""))
    rowid_match = any(normalize_match_text(trusted_row.get(key, "")) == rowid for key in ("rowid", "_rowid_", "oid", "id"))
    column_values = candidate.get("column_values") if isinstance(candidate.get("column_values"), dict) else {}
    matched_columns = []
    for name, value in column_values.items():
        normalized_name = str(name).strip().lower()
        if normalized_name in trusted_row and normalize_match_text(trusted_row[normalized_name]) == normalize_match_text(str(value)):
            matched_columns.append(normalized_name)
    non_empty_value_count = sum(1 for value in column_values.values() if str(value).strip())
    value_threshold = min(2, max(1, non_empty_value_count))
    matched = (rowid_match and bool(matched_columns)) or len(matched_columns) >= value_threshold
    return {"matched": matched, "rowid_match": rowid_match, "matched_columns": matched_columns}


def normalize_match_text(value: str) -> str:
    return str(value or "").strip().lower()


def sqlite_deleted_candidate_false_positive_profile(*, sample_count: int = 32, page_size: int = 1024) -> dict[str, object]:
    total_candidates = 0
    sample_rows = []
    for index in range(sample_count):
        page = bytearray(b"\x00" * page_size)
        freeblock_offset = 100
        block_size = 64
        page[0] = 0x0D
        page[1:3] = freeblock_offset.to_bytes(2, "big")
        page[5:7] = (900).to_bytes(2, "big")
        page[freeblock_offset : freeblock_offset + 2] = (0).to_bytes(2, "big")
        page[freeblock_offset + 2 : freeblock_offset + 4] = block_size.to_bytes(2, "big")
        page[freeblock_offset + 4 : freeblock_offset + block_size] = bytes([0x80]) * (block_size - 4)
        freeblock_profile = sqlite_freeblock_profile(page=bytes(page), page_size=page_size, first_freeblock_offset=freeblock_offset, header_offset=0)
        candidate_profile = sqlite_deleted_record_candidate_profile(
            page=bytes(page),
            page_size=page_size,
            freeblock_profile=freeblock_profile,
            header_offset=0,
            cell_count=0,
        )
        candidate_count = int(candidate_profile.get("candidate_count") or 0)
        total_candidates += candidate_count
        sample_rows.append({"sample_index": index, "candidate_count": candidate_count, "freeblock_sha256": freeblock_profile["blocks"][0]["content_sha256"]})
    return {
        "profile_version": "sqlite-deleted-candidate-false-positive-stress-v1",
        "status": "passed-zero-candidates" if total_candidates == 0 else "candidates-observed",
        "sample_count": sample_count,
        "deterministic_pattern": "0x80 repeated varint-continuation bytes inside valid freeblock bodies",
        "candidate_count": total_candidates,
        "false_positive_rate": total_candidates / sample_count if sample_count else None,
        "samples": sample_rows[:10],
    }


def missing_safe_copy(database_path: Path) -> dict[str, object]:
    return {
        "profile_version": "sqlite-sidecar-safe-copy-v1",
        "copy_directory": None,
        "analysis_database_path": None,
        "copied_count": 0,
        "source_stable": None,
        "database_copied": False,
        "wal_copied": database_path.with_name(database_path.name + "-wal").is_file(),
        "sidecars": [],
        "purpose": "No output directory was supplied, so no working copy was created.",
    }


def sqlite_sidecar_paths(database_path: Path) -> tuple[Path, Path, Path]:
    return (database_path, database_path.with_name(database_path.name + "-wal"), database_path.with_name(database_path.name + "-shm"))


def parse_sqlite_wal_file(wal_path: Path, *, max_frames: int) -> dict[str, object]:
    size = wal_path.stat().st_size
    with wal_path.open("rb") as handle:
        header = handle.read(SQLITE_WAL_HEADER_SIZE)
        if len(header) < SQLITE_WAL_HEADER_SIZE:
            return {**file_row(wal_path), "status": "invalid-short-header", "frames": []}
        magic, version, page_size, checkpoint_sequence, salt1, salt2, checksum1, checksum2 = struct.unpack(">IIIIIIII", header)
        endian = SQLITE_WAL_MAGIC_VALUES.get(magic, "unknown")
        if page_size == 0:
            page_size = 1024
        frames = []
        frame_index = 0
        while frame_index < max_frames:
            frame_header = handle.read(SQLITE_WAL_FRAME_HEADER_SIZE)
            if len(frame_header) < SQLITE_WAL_FRAME_HEADER_SIZE:
                break
            page = handle.read(page_size)
            if len(page) < page_size:
                break
            page_number, commit_db_size, frame_salt1, frame_salt2, frame_checksum1, frame_checksum2 = struct.unpack(
                ">IIIIII",
                frame_header,
            )
            frame_index += 1
            frames.append(
                {
                    "frame_index": frame_index,
                    "page_number": page_number,
                    "commit_db_size_pages": commit_db_size,
                    "is_commit_frame": commit_db_size > 0,
                    "salt_matches_header": frame_salt1 == salt1 and frame_salt2 == salt2,
                    "checksum1": frame_checksum1,
                    "checksum2": frame_checksum2,
                    "page_sha256": hashlib.sha256(page).hexdigest(),
                    "page_profile": sqlite_page_profile(page_number=page_number, page=page, page_size=page_size),
                }
            )
    frame_size = SQLITE_WAL_FRAME_HEADER_SIZE + page_size
    estimated_frame_count = max(0, (size - SQLITE_WAL_HEADER_SIZE) // frame_size)
    return {
        **file_row(wal_path),
        "status": "parsed" if endian != "unknown" else "unknown-magic",
        "header": {
            "magic": f"0x{magic:08x}",
            "endianness": endian,
            "version": version,
            "page_size": page_size,
            "checkpoint_sequence": checkpoint_sequence,
            "salt1": salt1,
            "salt2": salt2,
            "checksum1": checksum1,
            "checksum2": checksum2,
        },
        "estimated_frame_count": estimated_frame_count,
        "preview_frame_count": len(frames),
        "frames": frames,
    }


def missing_wal_info(wal_path: Path) -> dict[str, object]:
    return {"path": str(wal_path), "exists": False, "status": "missing", "frames": []}


def sqlite_wal_freeblock_preview_count(wal_info: dict[str, object]) -> int:
    frames = wal_info.get("frames")
    if not isinstance(frames, list):
        return 0
    total = 0
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        page_profile = frame.get("page_profile")
        if not isinstance(page_profile, dict):
            continue
        freeblock_profile = page_profile.get("freeblock_profile")
        if isinstance(freeblock_profile, dict):
            total += int(freeblock_profile.get("freeblock_count") or 0)
    return total


def sqlite_wal_schema_mapped_record_count(wal_info: dict[str, object]) -> int:
    frames = wal_info.get("frames")
    if not isinstance(frames, list):
        return 0
    total = 0
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        page_profile = frame.get("page_profile")
        if not isinstance(page_profile, dict):
            continue
        cell_profile = page_profile.get("cell_profile")
        if not isinstance(cell_profile, dict):
            continue
        cells = cell_profile.get("cells")
        if not isinstance(cells, list):
            continue
        total += sum(1 for cell in cells if isinstance(cell, dict) and cell.get("schema_mapping", {}).get("status") == "mapped")
    return total


def sqlite_wal_deleted_record_candidate_count(wal_info: dict[str, object]) -> int:
    frames = wal_info.get("frames")
    if not isinstance(frames, list):
        return 0
    total = 0
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        page_profile = frame.get("page_profile")
        if not isinstance(page_profile, dict):
            continue
        candidate_profile = page_profile.get("deleted_record_candidate_profile")
        if not isinstance(candidate_profile, dict):
            continue
        total += int(candidate_profile.get("candidate_count") or 0)
    return total


def annotate_wal_records_with_schema(wal_info: dict[str, object], schema_profile: dict[str, object]) -> dict[str, object]:
    rootpage_map = sqlite_schema_rootpage_map(schema_profile)
    if not rootpage_map:
        return wal_info
    frames = wal_info.get("frames")
    if not isinstance(frames, list):
        return wal_info
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        table = rootpage_map.get(int(frame.get("page_number") or 0))
        if not table:
            continue
        page_profile = frame.get("page_profile")
        if not isinstance(page_profile, dict):
            continue
        cell_profile = page_profile.get("cell_profile")
        if not isinstance(cell_profile, dict):
            continue
        cells = cell_profile.get("cells")
        if not isinstance(cells, list):
            continue
        page_profile["schema_mapping"] = {
            "status": "mapped-rootpage",
            "table_name": table.get("name"),
            "rootpage": table.get("rootpage"),
            "column_count": len(table.get("columns", [])) if isinstance(table.get("columns"), list) else 0,
        }
        for cell in cells:
            if isinstance(cell, dict):
                cell["schema_mapping"] = sqlite_cell_schema_mapping(cell, table)
        candidate_profile = page_profile.get("deleted_record_candidate_profile")
        if isinstance(candidate_profile, dict):
            candidates = candidate_profile.get("candidates")
            if isinstance(candidates, list):
                for candidate in candidates:
                    if isinstance(candidate, dict):
                        candidate["schema_mapping"] = sqlite_cell_schema_mapping(candidate, table)
    return wal_info


def sqlite_schema_rootpage_map(schema_profile: dict[str, object]) -> dict[int, dict[str, object]]:
    if schema_profile.get("status") != "parsed":
        return {}
    tables = schema_profile.get("tables")
    if not isinstance(tables, list):
        return {}
    rootpages = {}
    for table in tables:
        if not isinstance(table, dict):
            continue
        rootpage = table.get("rootpage")
        if isinstance(rootpage, int) and rootpage > 0:
            rootpages[rootpage] = table
    return rootpages


def sqlite_cell_schema_mapping(cell: dict[str, object], table: dict[str, object]) -> dict[str, object]:
    columns = table.get("columns")
    record_profile = cell.get("record_profile")
    if not isinstance(columns, list) or not isinstance(record_profile, dict):
        return {"status": "unavailable"}
    values = record_profile.get("values_preview")
    serial_types = record_profile.get("serial_types")
    if not isinstance(values, list) or not isinstance(serial_types, list):
        return {"status": "record-values-unavailable", "table_name": table.get("name")}
    mapped_columns = []
    for index, column in enumerate(columns):
        if not isinstance(column, dict):
            continue
        value_preview = values[index] if index < len(values) and isinstance(values[index], dict) else {"status": "missing"}
        serial_type = serial_types[index] if index < len(serial_types) and isinstance(serial_types[index], dict) else {"status": "missing"}
        mapped = {
            "column_index": index,
            "name": column.get("name"),
            "declared_type": column.get("type"),
            "primary_key": bool(column.get("primary_key")),
            "serial_type": serial_type,
            "value_preview": value_preview,
        }
        if mapped["primary_key"] and value_preview.get("type") == "null" and "rowid" in cell:
            mapped["rowid_alias_value"] = cell.get("rowid")
        mapped_columns.append(mapped)
    return {
        "status": "mapped",
        "table_name": table.get("name"),
        "table_rootpage": table.get("rootpage"),
        "column_count": len(columns),
        "record_value_count": len(values),
        "columns": mapped_columns,
        "anomalies": [] if len(values) == len(columns) else ["record-column-count-mismatch"],
    }


def sqlite_page_profile(*, page_number: int, page: bytes, page_size: int) -> dict[str, object]:
    header_offset = 100 if page_number == 1 else 0
    if len(page) <= header_offset:
        return {
            "profile_version": "sqlite-page-profile-v1",
            "page_number": page_number,
            "page_size": page_size,
            "header_offset": header_offset,
            "status": "short-page",
        }
    page_type = page[header_offset]
    cell_count = None
    first_freeblock_offset = None
    cell_content_area_offset = None
    fragmented_free_bytes = None
    if len(page) >= header_offset + 8:
        first_freeblock_offset = int.from_bytes(page[header_offset + 1 : header_offset + 3], "big")
        cell_count = int.from_bytes(page[header_offset + 3 : header_offset + 5], "big")
        cell_content_area_offset = int.from_bytes(page[header_offset + 5 : header_offset + 7], "big")
        fragmented_free_bytes = page[header_offset + 7]
    freeblock_profile = sqlite_freeblock_profile(
        page=page,
        page_size=page_size,
        first_freeblock_offset=first_freeblock_offset or 0,
        header_offset=header_offset,
    )
    page_anomalies = []
    if isinstance(fragmented_free_bytes, int) and fragmented_free_bytes > 60:
        page_anomalies.append("fragmented-free-bytes-exceeds-sqlite-limit")
    cell_profile = sqlite_leaf_table_cell_profile(
        page=page,
        page_size=page_size,
        header_offset=header_offset,
        cell_count=cell_count or 0,
    ) if page_type == 0x0D else None
    deleted_record_candidate_profile = sqlite_deleted_record_candidate_profile(
        page=page,
        page_size=page_size,
        freeblock_profile=freeblock_profile,
        header_offset=header_offset,
        cell_count=cell_count or 0,
    ) if page_type == 0x0D else None
    return {
        "profile_version": "sqlite-page-profile-v1",
        "page_number": page_number,
        "page_size": page_size,
        "header_offset": header_offset,
        "status": "classified" if page_type in SQLITE_BTREE_PAGE_TYPES else "unknown-page-type",
        "page_type_byte": f"0x{page_type:02x}",
        "page_type": SQLITE_BTREE_PAGE_TYPES.get(page_type, "unknown"),
        "cell_count": cell_count,
        "first_freeblock_offset": first_freeblock_offset,
        "cell_content_area_offset": cell_content_area_offset,
        "fragmented_free_bytes": fragmented_free_bytes,
        "freeblock_profile": freeblock_profile,
        "cell_profile": cell_profile,
        "deleted_record_candidate_profile": deleted_record_candidate_profile,
        "anomalies": page_anomalies,
    }


def sqlite_deleted_record_candidate_profile(
    *,
    page: bytes,
    page_size: int,
    freeblock_profile: dict[str, object],
    header_offset: int,
    cell_count: int,
) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "sqlite-deleted-record-candidate-profile-v1",
        "candidate_count": 0,
        "candidates": [],
        "anomalies": [],
        "method": "Scan leaf-table freeblock bodies for complete SQLite table-leaf cell payloads; results are candidates, not court-ready recovered rows.",
    }
    blocks = freeblock_profile.get("blocks") if isinstance(freeblock_profile, dict) else None
    if not isinstance(blocks, list):
        return profile
    pointer_array_start = header_offset + 8
    pointer_array_end = pointer_array_start + (cell_count * 2)
    candidates = []
    anomalies = []
    for block in blocks:
        if not isinstance(block, dict) or block.get("anomalies"):
            continue
        block_offset = int(block.get("offset") or 0)
        block_size = int(block.get("size_bytes") or 0)
        if block_size <= 4:
            continue
        body_offset = block_offset + 4
        body_end = min(block_offset + block_size, page_size, len(page))
        cursor = body_offset
        while cursor < body_end and len(candidates) < SQLITE_MAX_FREEBLOCK_CANDIDATES:
            if pointer_array_start <= cursor < pointer_array_end:
                cursor = pointer_array_end
                continue
            candidate = sqlite_deleted_record_candidate_at(page=page, page_size=page_size, cell_offset=cursor, block_offset=block_offset, block_end=body_end, candidate_index=len(candidates))
            if candidate is None:
                cursor += 1
                continue
            candidates.append(candidate)
            cursor = int(candidate["cell_end_offset"])
        if len(candidates) >= SQLITE_MAX_FREEBLOCK_CANDIDATES:
            anomalies.append("deleted-record-candidate-preview-limit-reached")
            break
    return {**profile, "candidate_count": len(candidates), "candidates": candidates, "anomalies": anomalies}


def sqlite_deleted_record_candidate_at(
    *,
    page: bytes,
    page_size: int,
    cell_offset: int,
    block_offset: int,
    block_end: int,
    candidate_index: int,
) -> dict[str, object] | None:
    page_limit = min(page_size, len(page), block_end)
    try:
        payload_length = read_sqlite_varint(page, cell_offset, page_limit)
        rowid = read_sqlite_varint(page, payload_length.next_offset, page_limit)
    except ValueError:
        return None
    payload_offset = rowid.next_offset
    payload_end = payload_offset + payload_length.value
    if payload_length.value <= 0 or payload_end > page_limit:
        return None
    payload = page[payload_offset:payload_end]
    record_profile = sqlite_record_preview(payload)
    if record_profile.get("status") != "parsed":
        return None
    serial_types = record_profile.get("serial_types")
    if not isinstance(serial_types, list) or not serial_types:
        return None
    if any(isinstance(entry, dict) and entry.get("type") == "reserved" for entry in serial_types):
        return None
    return {
        "candidate_index": candidate_index,
        "status": "candidate",
        "source": "leaf-table-freeblock-body",
        "freeblock_offset": block_offset,
        "cell_offset": cell_offset,
        "cell_end_offset": payload_end,
        "payload_length": payload_length.value,
        "rowid": rowid.value,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "record_profile": record_profile,
        "anomalies": [],
    }


def sqlite_leaf_table_cell_profile(
    *,
    page: bytes,
    page_size: int,
    header_offset: int,
    cell_count: int,
    max_cells: int = SQLITE_MAX_CELL_PREVIEW,
) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "sqlite-leaf-table-cell-profile-v1",
        "cell_count": cell_count,
        "preview_cell_count": 0,
        "cells": [],
        "anomalies": [],
    }
    if cell_count <= 0:
        return profile
    pointer_array_offset = header_offset + 8
    pointer_array_end = pointer_array_offset + (cell_count * 2)
    if pointer_array_end > min(page_size, len(page)):
        return {**profile, "anomalies": ["cell-pointer-array-out-of-range"]}
    cells = []
    anomalies = []
    for cell_index in range(min(cell_count, max_cells)):
        pointer_offset = pointer_array_offset + cell_index * 2
        cell_offset = int.from_bytes(page[pointer_offset : pointer_offset + 2], "big")
        cell = sqlite_leaf_table_cell_preview(page=page, page_size=page_size, cell_index=cell_index, cell_offset=cell_offset)
        cells.append(cell)
    if cell_count > max_cells:
        anomalies.append("cell-preview-limit-reached")
    return {**profile, "preview_cell_count": len(cells), "cells": cells, "anomalies": anomalies}


def sqlite_leaf_table_cell_preview(*, page: bytes, page_size: int, cell_index: int, cell_offset: int) -> dict[str, object]:
    cell: dict[str, object] = {
        "cell_index": cell_index,
        "cell_offset": cell_offset,
        "status": "unavailable",
        "anomalies": [],
    }
    page_limit = min(page_size, len(page))
    if cell_offset <= 0 or cell_offset >= page_limit:
        return {**cell, "status": "invalid-cell-offset", "anomalies": ["cell-offset-out-of-range"]}
    try:
        payload_length = read_sqlite_varint(page, cell_offset, page_limit)
        rowid = read_sqlite_varint(page, payload_length.next_offset, page_limit)
    except ValueError as exc:
        return {**cell, "status": "invalid-varint", "anomalies": [str(exc)]}
    payload_offset = rowid.next_offset
    payload_end = payload_offset + payload_length.value
    anomalies = []
    overflow_page = None
    local_payload_end = min(payload_end, page_limit)
    if payload_end > page_limit:
        anomalies.append("payload-truncated-at-page-boundary")
        if page_limit >= payload_offset + 4:
            overflow_page = int.from_bytes(page[page_limit - 4 : page_limit], "big")
    payload = page[payload_offset:local_payload_end]
    record_profile = sqlite_record_preview(payload)
    return {
        **cell,
        "status": "parsed" if record_profile.get("status") == "parsed" else "parsed-with-record-anomalies",
        "payload_length": payload_length.value,
        "payload_varint_size": payload_length.size_bytes,
        "rowid": rowid.value,
        "rowid_varint_size": rowid.size_bytes,
        "payload_offset": payload_offset,
        "local_payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "overflow_page": overflow_page,
        "record_profile": record_profile,
        "anomalies": anomalies,
    }


def read_sqlite_varint(data: bytes, offset: int, limit: int | None = None) -> SqliteVarint:
    if limit is None:
        limit = len(data)
    if offset < 0 or offset >= limit:
        raise ValueError("varint-offset-out-of-range")
    value = 0
    for index in range(9):
        current_offset = offset + index
        if current_offset >= limit:
            raise ValueError("varint-truncated")
        byte = data[current_offset]
        if index == 8:
            value = (value << 8) | byte
            return SqliteVarint(value=value, next_offset=current_offset + 1, size_bytes=9)
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return SqliteVarint(value=value, next_offset=current_offset + 1, size_bytes=index + 1)
    raise ValueError("varint-too-long")


def sqlite_record_preview(payload: bytes) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "sqlite-record-preview-v1",
        "status": "unavailable",
        "serial_types": [],
        "values_preview": [],
        "anomalies": [],
    }
    if not payload:
        return {**profile, "status": "empty-payload", "anomalies": ["empty-payload"]}
    try:
        header_size = read_sqlite_varint(payload, 0)
    except ValueError as exc:
        return {**profile, "status": "invalid-header-varint", "anomalies": [str(exc)]}
    if header_size.value > len(payload):
        return {**profile, "status": "truncated-record-header", "header_size": header_size.value, "anomalies": ["record-header-exceeds-payload"]}
    serial_types = []
    offset = header_size.next_offset
    while offset < header_size.value:
        try:
            serial_type = read_sqlite_varint(payload, offset, header_size.value)
        except ValueError as exc:
            return {**profile, "status": "invalid-serial-type-varint", "header_size": header_size.value, "serial_types": serial_types, "anomalies": [str(exc)]}
        serial_types.append(sqlite_serial_type_profile(serial_type.value))
        offset = serial_type.next_offset
    values = []
    body_offset = header_size.value
    anomalies = []
    for serial_type in serial_types:
        value_size = serial_type.get("size_bytes")
        if value_size is None:
            anomalies.append("reserved-or-unsupported-serial-type")
            values.append({"status": "unsupported", "serial_type": serial_type["serial_type"]})
            continue
        value_end = body_offset + int(value_size)
        if value_end > len(payload):
            anomalies.append("record-value-truncated")
            values.append({"status": "truncated", "serial_type": serial_type["serial_type"], "available_bytes": max(0, len(payload) - body_offset)})
            break
        values.append(sqlite_record_value_preview(payload[body_offset:value_end], serial_type))
        body_offset = value_end
    return {
        **profile,
        "status": "parsed" if not anomalies else "parsed-with-anomalies",
        "header_size": header_size.value,
        "header_varint_size": header_size.size_bytes,
        "serial_types": serial_types,
        "values_preview": values,
        "consumed_payload_bytes": body_offset,
        "anomalies": anomalies,
    }


def sqlite_serial_type_profile(serial_type: int) -> dict[str, object]:
    if serial_type == 0:
        return {"serial_type": serial_type, "type": "null", "size_bytes": 0}
    if serial_type == 1:
        return {"serial_type": serial_type, "type": "integer", "size_bytes": 1}
    if serial_type == 2:
        return {"serial_type": serial_type, "type": "integer", "size_bytes": 2}
    if serial_type == 3:
        return {"serial_type": serial_type, "type": "integer", "size_bytes": 3}
    if serial_type == 4:
        return {"serial_type": serial_type, "type": "integer", "size_bytes": 4}
    if serial_type == 5:
        return {"serial_type": serial_type, "type": "integer", "size_bytes": 6}
    if serial_type == 6:
        return {"serial_type": serial_type, "type": "integer", "size_bytes": 8}
    if serial_type == 7:
        return {"serial_type": serial_type, "type": "float", "size_bytes": 8}
    if serial_type == 8:
        return {"serial_type": serial_type, "type": "integer-constant", "size_bytes": 0, "constant": 0}
    if serial_type == 9:
        return {"serial_type": serial_type, "type": "integer-constant", "size_bytes": 0, "constant": 1}
    if serial_type in {10, 11}:
        return {"serial_type": serial_type, "type": "reserved", "size_bytes": None}
    if serial_type >= 12 and serial_type % 2 == 0:
        return {"serial_type": serial_type, "type": "blob", "size_bytes": (serial_type - 12) // 2}
    return {"serial_type": serial_type, "type": "text", "size_bytes": (serial_type - 13) // 2}


def sqlite_record_value_preview(value: bytes, serial_type: dict[str, object]) -> dict[str, object]:
    value_type = serial_type.get("type")
    if value_type == "null":
        return {"status": "parsed", "type": value_type, "value": None}
    if value_type == "integer-constant":
        return {"status": "parsed", "type": "integer", "value": serial_type.get("constant")}
    if value_type == "integer":
        return {"status": "parsed", "type": value_type, "value": int.from_bytes(value, "big", signed=True)}
    if value_type == "float" and len(value) == 8:
        return {"status": "parsed", "type": value_type, "value": struct.unpack(">d", value)[0]}
    if value_type == "text":
        preview_bytes = value[:SQLITE_MAX_RECORD_VALUE_PREVIEW_BYTES]
        return {
            "status": "parsed",
            "type": value_type,
            "text_preview": preview_bytes.decode("utf-8", errors="replace"),
            "size_bytes": len(value),
            "truncated": len(value) > len(preview_bytes),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if value_type == "blob":
        preview_bytes = value[:SQLITE_MAX_RECORD_VALUE_PREVIEW_BYTES]
        return {
            "status": "parsed",
            "type": value_type,
            "size_bytes": len(value),
            "preview_hex": preview_bytes.hex(),
            "truncated": len(value) > len(preview_bytes),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    return {"status": "unsupported", "type": value_type}


def sqlite_freeblock_profile(
    *,
    page: bytes,
    page_size: int,
    first_freeblock_offset: int,
    header_offset: int,
    max_freeblocks: int = SQLITE_MAX_FREEBLOCK_PREVIEW,
) -> dict[str, object]:
    blocks = []
    anomalies = []
    seen_offsets = set()
    current_offset = first_freeblock_offset
    previous_offset = 0
    while current_offset:
        if len(blocks) >= max_freeblocks:
            anomalies.append("freeblock-preview-limit-reached")
            break
        if current_offset in seen_offsets:
            anomalies.append("freeblock-loop-detected")
            break
        if current_offset < header_offset + 8 or current_offset + 4 > min(page_size, len(page)):
            anomalies.append("freeblock-offset-out-of-range")
            break
        seen_offsets.add(current_offset)
        if current_offset <= previous_offset:
            anomalies.append("freeblock-offset-not-increasing")
            break
        next_offset = int.from_bytes(page[current_offset : current_offset + 2], "big")
        block_size = int.from_bytes(page[current_offset + 2 : current_offset + 4], "big")
        block_end = current_offset + block_size
        block_anomalies = []
        if block_size < 4:
            block_anomalies.append("freeblock-size-too-small")
            anomalies.append("freeblock-size-too-small")
        if block_end > min(page_size, len(page)):
            block_anomalies.append("freeblock-extends-past-page")
            anomalies.append("freeblock-extends-past-page")
        blocks.append(
            {
                "offset": current_offset,
                "next_offset": next_offset,
                "size_bytes": block_size,
                "content_sha256": hashlib.sha256(page[current_offset:block_end]).hexdigest() if block_size >= 4 and block_end <= len(page) else None,
                "anomalies": block_anomalies,
            }
        )
        if block_anomalies:
            break
        previous_offset = current_offset
        current_offset = next_offset
    return {
        "profile_version": "sqlite-freeblock-profile-v1",
        "first_freeblock_offset": first_freeblock_offset,
        "freeblock_count": len(blocks),
        "total_freeblock_bytes": sum(int(block["size_bytes"]) for block in blocks if isinstance(block.get("size_bytes"), int)),
        "blocks": blocks,
        "anomalies": anomalies,
    }


def sqlite_database_header_profile(database_path: Path) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "sqlite-database-header-profile-v1",
        "database_path": str(database_path),
        "status": "unavailable",
    }
    try:
        header = database_path.read_bytes()[:SQLITE_DATABASE_HEADER_SIZE]
    except OSError as exc:
        return {**profile, "status": "io-error", "error": str(exc)}
    if len(header) < SQLITE_DATABASE_HEADER_SIZE:
        return {**profile, "status": "short-header", "header_size_bytes": len(header)}
    if header[:16] != b"SQLite format 3\x00":
        return {**profile, "status": "not-sqlite", "header_magic_sha256": hashlib.sha256(header[:16]).hexdigest()}
    page_size_raw = int.from_bytes(header[16:18], "big")
    page_size = 65536 if page_size_raw == 1 else page_size_raw
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        return {**profile, "status": "invalid-page-size", "page_size": page_size}
    return {
        **profile,
        "status": "parsed",
        "page_size": page_size,
        "write_version": header[18],
        "read_version": header[19],
        "reserved_space_bytes": header[20],
        "database_size_pages": int.from_bytes(header[28:32], "big"),
        "first_freelist_trunk_page": int.from_bytes(header[32:36], "big"),
        "total_freelist_pages": int.from_bytes(header[36:40], "big"),
        "schema_cookie": int.from_bytes(header[40:44], "big"),
        "schema_format_number": int.from_bytes(header[44:48], "big"),
        "text_encoding": int.from_bytes(header[56:60], "big"),
        "user_version": int.from_bytes(header[60:64], "big"),
        "application_id": int.from_bytes(header[68:72], "big"),
    }


def sqlite_freelist_profile(database_path: Path, header_profile: dict[str, object]) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "sqlite-freelist-profile-v1",
        "database_path": str(database_path),
        "status": "unavailable",
        "trunk_pages": [],
        "anomalies": [],
    }
    if header_profile.get("status") != "parsed":
        return {**profile, "status": "header-unavailable"}
    page_size = int(header_profile.get("page_size") or 0)
    first_trunk_page = int(header_profile.get("first_freelist_trunk_page") or 0)
    total_freelist_pages = int(header_profile.get("total_freelist_pages") or 0)
    if first_trunk_page == 0 or total_freelist_pages == 0:
        return {
            **profile,
            "status": "empty",
            "page_size": page_size,
            "first_trunk_page": first_trunk_page,
            "total_freelist_pages": total_freelist_pages,
        }
    if page_size <= 0:
        return {**profile, "status": "invalid-page-size", "page_size": page_size}
    try:
        data = database_path.read_bytes()
    except OSError as exc:
        return {**profile, "status": "io-error", "error": str(exc)}

    trunk_pages = []
    anomalies = []
    seen_pages = set()
    current_page = first_trunk_page
    while current_page:
        if len(trunk_pages) >= SQLITE_MAX_FREELIST_TRUNK_PREVIEW:
            anomalies.append("freelist-trunk-preview-limit-reached")
            break
        if current_page in seen_pages:
            anomalies.append("freelist-trunk-loop-detected")
            break
        page_offset = (current_page - 1) * page_size
        if current_page <= 0 or page_offset < 0 or page_offset + 8 > len(data):
            anomalies.append("freelist-trunk-page-out-of-range")
            break
        seen_pages.add(current_page)
        page = data[page_offset : page_offset + page_size]
        next_trunk_page = int.from_bytes(page[0:4], "big")
        leaf_pointer_count = int.from_bytes(page[4:8], "big")
        max_leaf_slots = max(0, (len(page) - 8) // 4)
        preview_count = min(leaf_pointer_count, max_leaf_slots, SQLITE_MAX_FREELIST_LEAF_PREVIEW)
        leaf_pages = [int.from_bytes(page[8 + index * 4 : 12 + index * 4], "big") for index in range(preview_count)]
        trunk_anomalies = []
        if leaf_pointer_count > max_leaf_slots:
            trunk_anomalies.append("freelist-leaf-count-exceeds-page")
            anomalies.append("freelist-leaf-count-exceeds-page")
        if leaf_pointer_count > SQLITE_MAX_FREELIST_LEAF_PREVIEW:
            trunk_anomalies.append("freelist-leaf-preview-truncated")
        trunk_pages.append(
            {
                "page_number": current_page,
                "next_trunk_page": next_trunk_page,
                "leaf_pointer_count": leaf_pointer_count,
                "leaf_pages_preview": leaf_pages,
                "page_sha256": hashlib.sha256(page).hexdigest(),
                "anomalies": trunk_anomalies,
            }
        )
        if "freelist-leaf-count-exceeds-page" in trunk_anomalies:
            break
        current_page = next_trunk_page
    return {
        **profile,
        "status": "parsed" if not anomalies else "parsed-with-anomalies",
        "page_size": page_size,
        "first_trunk_page": first_trunk_page,
        "total_freelist_pages": total_freelist_pages,
        "preview_trunk_page_count": len(trunk_pages),
        "trunk_pages": trunk_pages,
        "anomalies": anomalies,
    }


def sqlite_schema_profile(database_path: Path) -> dict[str, object]:
    profile: dict[str, object] = {
        "profile_version": "sqlite-schema-profile-v1",
        "database_path": str(database_path),
        "status": "unavailable",
        "tables": [],
        "indexes": [],
        "views": [],
        "triggers": [],
    }
    try:
        with sqlite3.connect(f"{database_path.as_uri()}?mode=ro&immutable=1", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT type, name, tbl_name, rootpage, sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
            tables = []
            indexes = []
            views = []
            triggers = []
            for row in rows:
                entry = {
                    "name": row["name"],
                    "table_name": row["tbl_name"],
                    "rootpage": row["rootpage"],
                    "sql_sha256": hashlib.sha256((row["sql"] or "").encode("utf-8")).hexdigest(),
                }
                if row["type"] == "table":
                    entry["columns"] = sqlite_table_columns(connection, row["name"])
                    tables.append(entry)
                elif row["type"] == "index":
                    indexes.append(entry)
                elif row["type"] == "view":
                    views.append(entry)
                elif row["type"] == "trigger":
                    triggers.append(entry)
            profile.update(
                {
                    "status": "parsed",
                    "table_count": len(tables),
                    "index_count": len(indexes),
                    "view_count": len(views),
                    "trigger_count": len(triggers),
                    "tables": tables,
                    "indexes": indexes,
                    "views": views,
                    "triggers": triggers,
                }
            )
    except sqlite3.Error as exc:
        profile.update({"status": "sqlite-error", "error": str(exc)})
    except OSError as exc:
        profile.update({"status": "io-error", "error": str(exc)})
    return profile


def sqlite_table_columns(connection: sqlite3.Connection, table_name: str) -> list[dict[str, object]]:
    quoted_name = '"' + table_name.replace('"', '""') + '"'
    rows = connection.execute(f"PRAGMA table_info({quoted_name})").fetchall()
    return [
        {
            "cid": row["cid"],
            "name": row["name"],
            "type": row["type"],
            "notnull": bool(row["notnull"]),
            "default_value": row["dflt_value"],
            "primary_key": bool(row["pk"]),
        }
        for row in rows
    ]


def missing_file_row(path: Path) -> dict[str, object]:
    return {"path": str(path), "exists": False, "size_bytes": 0, "sha256": None}


def file_row(path: Path) -> dict[str, object]:
    stat = path.stat()
    return {"path": str(path), "exists": True, "size_bytes": stat.st_size, "sha256": file_sha256(path)}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_sqlite_wal_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def render_sqlite_wal_preview_markdown(payload: dict[str, object]) -> str:
    wal = payload.get("wal") if isinstance(payload.get("wal"), dict) else {}
    return "\n".join(
        [
            "# SQLite WAL Recovery MVP Preview",
            "",
            f"- Database: `{payload['database']['path']}`",
            f"- WAL status: `{wal.get('status', '')}`",
            f"- Estimated frames: `{wal.get('estimated_frame_count', 0)}`",
            f"- Preview frames: `{wal.get('preview_frame_count', 0)}`",
            f"- Manifest SHA256: `{payload['manifest_sha256']}`",
            "",
            "This MVP preserves WAL evidence and previews frame/page hashes; deleted-row reconstruction is a later validation step.",
            "",
        ]
    )
