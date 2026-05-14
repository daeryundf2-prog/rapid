from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Mapping, Sequence

from .docs import SUPPORTED_DOC_EXTS, extract_text
from .search import SearchError, load_run_summary
from .source_paths import resolve_source_path_in_roots
from .submission import compute_hashes

SOURCE_READ_PROFILE_VERSION = "source-read-v1"
DEFAULT_MAX_TEXT_CHARS = 20_000
DEFAULT_MAX_HEX_BYTES = 1024
DEFAULT_SQLITE_ROW_LIMIT = 50
MAX_SOURCE_READ_TEXT_CHARS = 2_000_000
MAX_SOURCE_READ_HEX_BYTES = 1_048_576
MAX_SQLITE_ROW_LIMIT = 500


class SourceReadError(ValueError):
    """Raised when a source file cannot be safely read from a completed run."""


def run_source_read(
    run_summary: Mapping[str, object] | Path,
    raw_path: str,
    *,
    include_hashes: bool = False,
    max_chars: int = DEFAULT_MAX_TEXT_CHARS,
    hex_bytes: int = DEFAULT_MAX_HEX_BYTES,
    sqlite_table: str | None = None,
    sqlite_offset: int = 0,
    sqlite_limit: int = DEFAULT_SQLITE_ROW_LIMIT,
    sqlite_where_column: str | None = None,
    sqlite_where_contains: str | None = None,
) -> dict[str, object]:
    summary = load_summary_or_raise(run_summary)
    source = summary_source(summary)
    analysis_root = source_analysis_root(source)
    source_path = resolve_source_read_path(raw_path, analysis_root=analysis_root)

    if not source_path.is_file():
        raise SourceReadError(f"source file not found or not a regular file: {source_path}")
    if not is_relative_to(source_path, analysis_root):
        raise SourceReadError(f"source file is outside the run analysis root: {source_path}")

    stat = source_path.stat()
    max_chars = normalize_limit(max_chars, default=DEFAULT_MAX_TEXT_CHARS, maximum=MAX_SOURCE_READ_TEXT_CHARS)
    hex_bytes = normalize_limit(hex_bytes, default=DEFAULT_MAX_HEX_BYTES, maximum=MAX_SOURCE_READ_HEX_BYTES)
    if sqlite_table:
        if bool(sqlite_where_column) != bool(sqlite_where_contains):
            raise SourceReadError("--sqlite-where-column and --sqlite-where-contains must be used together")
        preview = build_sqlite_table_preview(
            source_path,
            table=sqlite_table,
            offset=sqlite_offset,
            limit=sqlite_limit,
            where_column=sqlite_where_column,
            where_contains=sqlite_where_contains,
        )
    else:
        preview = build_source_read_preview(source_path, max_chars=max_chars, hex_bytes=hex_bytes)
    hashes = compute_hashes(source_path) if include_hashes else {}

    return {
        "command": "source-read",
        "profile_version": SOURCE_READ_PROFILE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary") or ""),
        "source": source,
        "analysis_root": str(analysis_root),
        "path": str(source_path),
        "relative_path": str(source_path.relative_to(analysis_root)),
        "name": source_path.name,
        "extension": source_path.suffix.lower(),
        "size": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
        "hashes": hashes,
        "preview": preview,
        "source_locator": build_source_locator(preview),
        "forensic_read_profile": forensic_read_profile(
            source_path=source_path,
            analysis_root=analysis_root,
            preview=preview,
            hashes=hashes,
            include_hashes=include_hashes,
        ),
        "reportability_decision": {
            "decision": "source-preview-is-review-aid-not-standalone-proof",
            "allowed_use": "analyst-source-verification-and-review",
            "required_before_report": [
                "verify source file hash",
                "record review status and note",
                "cite path plus line/offset/table locator where applicable",
                "preserve original evidence image/container provenance",
            ],
        },
    }


def load_summary_or_raise(run_summary: Mapping[str, object] | Path) -> Mapping[str, object]:
    try:
        return load_run_summary(run_summary)
    except SearchError as exc:
        raise SourceReadError(str(exc)) from exc


def summary_source(summary: Mapping[str, object]) -> Mapping[str, object]:
    source = summary.get("source")
    if not isinstance(source, Mapping):
        raise SourceReadError("run summary does not include source.analysis_root")
    return source


def source_analysis_root(source: Mapping[str, object]) -> Path:
    raw = source.get("analysis_root") or source.get("root")
    if not isinstance(raw, str) or not raw:
        raise SourceReadError("run source does not include analysis_root")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise SourceReadError(f"run analysis root does not exist: {root}")
    return root


def resolve_source_read_path(raw_path: str, *, analysis_root: Path) -> Path:
    if not raw_path.strip():
        raise SourceReadError("--path is required")
    return resolve_source_path_in_roots(raw_path, [analysis_root])


def build_source_read_preview(source_path: Path, *, max_chars: int, hex_bytes: int) -> dict[str, object]:
    suffix = source_path.suffix.lower()
    if suffix in SUPPORTED_DOC_EXTS:
        try:
            text = extract_text(source_path, suffix.lstrip("."))
            return text_preview_payload(text, max_chars=max_chars, strategy="document-text-extract")
        except Exception as exc:
            return {
                "preview_type": "error",
                "strategy": "document-text-extract",
                "message": f"text extraction failed: {exc}",
                "truncated": False,
            }

    if source_path.stat().st_size <= max_chars and not is_probably_binary(source_path):
        try:
            text = source_path.read_text(encoding="utf-8", errors="replace")
            return text_preview_payload(text, max_chars=max_chars, strategy="bounded-plain-text")
        except OSError as exc:
            return {
                "preview_type": "error",
                "strategy": "bounded-plain-text",
                "message": f"text read failed: {exc}",
                "truncated": False,
            }

    return hex_preview_payload(source_path, hex_bytes=hex_bytes)


def build_sqlite_table_preview(
    source_path: Path,
    *,
    table: str,
    offset: int,
    limit: int,
    where_column: str | None = None,
    where_contains: str | None = None,
) -> dict[str, object]:
    limit = normalize_limit(limit, default=DEFAULT_SQLITE_ROW_LIMIT, maximum=MAX_SQLITE_ROW_LIMIT)
    offset = max(0, int(offset or 0))
    try:
        with contextlib.closing(sqlite3.connect(f"{source_path.as_uri()}?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            tables = list_sqlite_tables(connection)
            if table not in tables:
                raise SourceReadError(f"sqlite table not found: {table}")
            columns = sqlite_table_columns(connection, table)
            if not columns:
                raise SourceReadError(f"sqlite table has no readable columns: {table}")
            if where_column and where_column not in columns:
                raise SourceReadError(f"sqlite filter column not found in {table}: {where_column}")
            return sqlite_table_payload(
                connection,
                source_path=source_path,
                table=table,
                columns=columns,
                offset=offset,
                limit=limit,
                where_column=where_column,
                where_contains=where_contains,
            )
    except sqlite3.DatabaseError as exc:
        raise SourceReadError(f"sqlite read failed for {source_path}: {exc}") from exc


def sqlite_table_payload(
    connection: sqlite3.Connection,
    *,
    source_path: Path,
    table: str,
    columns: Sequence[str],
    offset: int,
    limit: int,
    where_column: str | None,
    where_contains: str | None,
) -> dict[str, object]:
    quoted_table = quote_sqlite_identifier(table)
    selected_columns = list(columns[:32])
    select_clause = ", ".join(quote_sqlite_identifier(column) for column in selected_columns)
    where_sql = ""
    params: list[object] = []
    if where_column and where_contains is not None:
        where_sql = f" WHERE CAST({quote_sqlite_identifier(where_column)} AS TEXT) LIKE ? ESCAPE '\\'"
        params.append(f"%{escape_sqlite_like(where_contains)}%")

    total_rows = int(connection.execute(f"SELECT COUNT(*) FROM {quoted_table}{where_sql}", params).fetchone()[0])
    has_rowid = sqlite_table_has_rowid(connection, table)
    rowid_select = "rowid AS __rapid_rowid__, " if has_rowid else ""
    order_sql = " ORDER BY rowid" if has_rowid else ""
    row_params = [*params, limit, offset]
    rows = connection.execute(
        f"SELECT {rowid_select}{select_clause} FROM {quoted_table}{where_sql}{order_sql} LIMIT ? OFFSET ?",
        row_params,
    ).fetchall()
    normalized_rows = [sqlite_row_payload(row, selected_columns, include_rowid=has_rowid) for row in rows]
    manifest = {
        "manifest_version": "source-read-sqlite-table-locator-v1",
        "source_path": str(source_path),
        "source_size": source_path.stat().st_size,
        "table": table,
        "columns": selected_columns,
        "rowid_supported": has_rowid,
        "offset": offset,
        "limit": limit,
        "returned_row_count": len(normalized_rows),
        "total_matching_rows": total_rows,
        "where_column": where_column or "",
        "where_contains_sha256": hashlib.sha256(where_contains.encode("utf-8")).hexdigest()
        if where_contains is not None
        else "",
        "row_hashes": [row["row_hash"] for row in normalized_rows],
        "truncated": offset + len(normalized_rows) < total_rows,
        "commercial_gap_ids": ["#54"],
        "report_use_warning": "Use source hash, table locator, and trusted SQLite/schema validation before report-grade use.",
    }
    manifest_hash = stable_json_hash(manifest)
    manifest["manifest_hash"] = manifest_hash
    return {
        "preview_type": "sqlite-table",
        "strategy": "bounded-sqlite-table-page",
        "message": "SQLite table page preview is available.",
        "table": table,
        "columns": selected_columns,
        "rowid_supported": has_rowid,
        "offset": offset,
        "limit": limit,
        "row_count": len(normalized_rows),
        "total_matching_rows": total_rows,
        "truncated": bool(manifest["truncated"]),
        "where_column": where_column or "",
        "where_contains_present": where_contains is not None,
        "rows": normalized_rows,
        "sqlite_table_locator_manifest": manifest,
        "sqlite_table_locator_manifest_hash": manifest_hash,
        "core_accuracy_gates": {
            "component": "source-read-sqlite-table-locator",
            "satisfied_checks": [
                "read-only sqlite connection",
                "identifier allowlist from sqlite_master and pragma_table_info",
                "bounded row limit enforced",
                "row-level locator hash emitted",
            ],
            "remaining_blockers": [
                "deleted-row and WAL replay are not implemented in source-read",
                "trusted sqlite query/schema diff is required before court use",
            ],
        },
    }


def list_sqlite_tables(connection: sqlite3.Connection) -> list[str]:
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return [str(row[0]) for row in rows]


def sqlite_table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    rows = connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table)})").fetchall()
    return [str(row["name"] if isinstance(row, sqlite3.Row) else row[1]) for row in rows]


def sqlite_table_has_rowid(connection: sqlite3.Connection, table: str) -> bool:
    try:
        connection.execute(f"SELECT rowid FROM {quote_sqlite_identifier(table)} LIMIT 1").fetchone()
        return True
    except sqlite3.DatabaseError:
        return False


def sqlite_row_payload(row: sqlite3.Row, columns: Sequence[str], *, include_rowid: bool) -> dict[str, object]:
    values = {column: sqlite_preview_value(row[column]) for column in columns}
    locator = {
        "locator_type": "sqlite-table-row",
        "rowid": row["__rapid_rowid__"] if include_rowid else None,
        "columns": list(columns),
    }
    row_core = {
        "rowid": row["__rapid_rowid__"] if include_rowid else None,
        "values": values,
    }
    row_hash = stable_json_hash(row_core)
    return {
        **row_core,
        "row_hash": row_hash,
        "locator": locator,
        "citation_text": f"SQLite row {row_core['rowid'] if include_rowid else row_hash[:12]}",
    }


def quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def escape_sqlite_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def sqlite_preview_value(value: object, *, max_length: int = 240) -> object:
    if isinstance(value, bytes):
        preview = value[:64].hex()
        return {"type": "blob", "size": len(value), "hex_preview": preview, "truncated": len(value) > 64}
    if value is None or isinstance(value, (int, float)):
        return value
    text = str(value)
    return text if len(text) <= max_length else text[:max_length] + "...[truncated]"


def stable_json_hash(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_source_locator(preview: Mapping[str, object]) -> dict[str, object]:
    if preview.get("preview_type") == "sqlite-table":
        return {
            "locator_type": "sqlite-table-page",
            "table": str(preview.get("table") or ""),
            "offset": int(preview.get("offset") or 0),
            "limit": int(preview.get("limit") or 0),
            "row_count": int(preview.get("row_count") or 0),
            "manifest_hash": str(preview.get("sqlite_table_locator_manifest_hash") or ""),
        }
    if preview.get("preview_type") == "hex":
        return {
            "locator_type": "byte-range",
            "offset": int(preview.get("offset") or 0),
            "byte_count": int(preview.get("byte_count") or 0),
            "preview_sha256": str(preview.get("preview_sha256") or ""),
        }
    if preview.get("preview_type") == "text":
        return {
            "locator_type": "text-preview",
            "preview_length": int(preview.get("preview_length") or 0),
            "text_sha256": str(preview.get("text_sha256") or ""),
        }
    return {"locator_type": "unavailable"}


def text_preview_payload(text: str, *, max_chars: int, strategy: str) -> dict[str, object]:
    preview = text[:max_chars]
    return {
        "preview_type": "text",
        "strategy": strategy,
        "text": preview,
        "text_length": len(text),
        "preview_length": len(preview),
        "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        "truncated": len(text) > len(preview),
        "line_count": text.count("\n") + (1 if text else 0),
        "message": "Text preview is available.",
    }


def hex_preview_payload(source_path: Path, *, hex_bytes: int) -> dict[str, object]:
    with source_path.open("rb") as handle:
        blob = handle.read(hex_bytes)
    ascii_preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in blob)
    return {
        "preview_type": "hex",
        "strategy": "bounded-hex",
        "offset": 0,
        "byte_count": len(blob),
        "hex": blob.hex(),
        "ascii": ascii_preview,
        "preview_sha256": hashlib.sha256(blob).hexdigest() if blob else "",
        "truncated": source_path.stat().st_size > len(blob),
        "message": "Binary/large-file hex preview is available.",
    }


def forensic_read_profile(
    *,
    source_path: Path,
    analysis_root: Path,
    preview: Mapping[str, object],
    hashes: Mapping[str, str],
    include_hashes: bool,
) -> dict[str, object]:
    return {
        "profile_version": SOURCE_READ_PROFILE_VERSION,
        "read_mode": "read-only-bounded-preview",
        "source_scope": "completed-run-analysis-root",
        "path_inside_analysis_root": is_relative_to(source_path, analysis_root),
        "preview_type": str(preview.get("preview_type") or ""),
        "source_locator_type": str(build_source_locator(preview).get("locator_type") or ""),
        "hashes_computed": bool(hashes),
        "hash_algorithms": sorted(hashes) if hashes else [],
        "hashes_requested": include_hashes,
        "safe_for_large_case": preview.get("preview_type") == "sqlite-table"
        or bool(preview.get("truncated"))
        or source_path.stat().st_size <= DEFAULT_MAX_TEXT_CHARS,
        "limitations": [
            "Preview may be truncated to keep analysis responsive.",
            "Source preview does not replace original evidence image/container provenance.",
            "Binary preview is a bounded hex sample unless a dedicated parser/viewer exists.",
        ],
    }


def normalize_limit(value: int, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed <= 0:
        parsed = default
    return min(parsed, maximum)


def is_probably_binary(source_path: Path, *, sample_size: int = 4096) -> bool:
    try:
        sample = source_path.read_bytes()[:sample_size]
    except OSError:
        return False
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / len(sample) > 0.08


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def render_source_read_text(payload: Mapping[str, object]) -> str:
    preview = payload.get("preview") if isinstance(payload.get("preview"), Mapping) else {}
    lines = [
        f"Source: {payload.get('relative_path') or payload.get('path')}",
        f"Type: {preview.get('preview_type')}  Size: {payload.get('size')} bytes",
    ]
    hashes = payload.get("hashes") if isinstance(payload.get("hashes"), Mapping) else {}
    if hashes:
        lines.extend(f"{name.upper()}: {value}" for name, value in sorted(hashes.items()))
    if preview.get("preview_type") == "text":
        lines.append("")
        lines.append(str(preview.get("text") or ""))
    elif preview.get("preview_type") == "sqlite-table":
        lines.append("")
        lines.append(
            f"SQLite table: {preview.get('table')}  Rows: {preview.get('row_count')}/{preview.get('total_matching_rows')}"
        )
        for row in preview.get("rows", []) if isinstance(preview.get("rows"), list) else []:
            if not isinstance(row, Mapping):
                continue
            lines.append(f"- {row.get('citation_text')}: {json.dumps(row.get('values', {}), ensure_ascii=False)}")
    elif preview.get("preview_type") == "hex":
        lines.append("")
        lines.append(str(preview.get("hex") or ""))
        lines.append("")
        lines.append(str(preview.get("ascii") or ""))
    else:
        lines.append(str(preview.get("message") or "No preview available."))
    return "\n".join(lines)
