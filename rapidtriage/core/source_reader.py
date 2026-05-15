from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import sqlite3
import zipfile
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
MAX_ARCHIVED_SOURCE_ENTRY_BYTES = 16 * 1024 * 1024
ARCHIVED_SOURCE_SEPARATOR = "::"


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
    archive_request = parse_archived_source_request(raw_path)
    source_path = resolve_source_read_path(
        archive_request["archive_path"] if archive_request else raw_path,
        analysis_root=analysis_root,
    )

    if not source_path.is_file():
        raise SourceReadError(f"source file not found or not a regular file: {source_path}")
    if not is_relative_to(source_path, analysis_root):
        raise SourceReadError(f"source file is outside the run analysis root: {source_path}")

    stat = source_path.stat()
    max_chars = normalize_limit(max_chars, default=DEFAULT_MAX_TEXT_CHARS, maximum=MAX_SOURCE_READ_TEXT_CHARS)
    hex_bytes = normalize_limit(hex_bytes, default=DEFAULT_MAX_HEX_BYTES, maximum=MAX_SOURCE_READ_HEX_BYTES)
    archive_entry: dict[str, object] | None = None
    if archive_request:
        if sqlite_table:
            raise SourceReadError("sqlite table preview is not supported for archived source entries")
        preview, archive_entry = build_archived_source_preview(
            source_path,
            entry_name=str(archive_request["entry_name"]),
            max_chars=max_chars,
            hex_bytes=hex_bytes,
        )
    elif sqlite_table:
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

    source_locator = build_source_locator(preview)
    relative_path = str(source_path.relative_to(analysis_root))
    display_relative_path = (
        f"{relative_path}{ARCHIVED_SOURCE_SEPARATOR}{archive_entry['archive_entry_name']}"
        if archive_entry
        else relative_path
    )
    return {
        "command": "source-read",
        "profile_version": SOURCE_READ_PROFILE_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_summary": str(summary.get("outputs", {}).get("summary") or ""),
        "source": source,
        "analysis_root": str(analysis_root),
        "path": str(source_path),
        "relative_path": display_relative_path,
        "container_relative_path": relative_path if archive_entry else "",
        "name": Path(str(archive_entry["archive_entry_name"])).name if archive_entry else source_path.name,
        "extension": Path(str(archive_entry["archive_entry_name"])).suffix.lower() if archive_entry else source_path.suffix.lower(),
        "size": int(archive_entry["archive_entry_size"]) if archive_entry else stat.st_size,
        "container_size": stat.st_size if archive_entry else 0,
        "modified_at": str(archive_entry["archive_entry_modified_at"])
        if archive_entry
        else dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat(),
        "container_modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).isoformat()
        if archive_entry
        else "",
        "archive_entry": archive_entry or {},
        "hashes": hashes,
        "preview": preview,
        "source_locator": source_locator,
        "source_citation_package": build_source_citation_package(
            relative_path=display_relative_path,
            source_path=source_path,
            preview=preview,
            source_locator=source_locator,
            hashes=hashes,
            include_hashes=include_hashes,
        ),
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


def run_source_search(
    run_summary: Mapping[str, object] | Path,
    raw_path: str,
    keywords: Sequence[str],
    *,
    limit: int = 100,
    context: int = 120,
    max_chars: int = MAX_SOURCE_READ_TEXT_CHARS,
) -> dict[str, object]:
    normalized = [item.strip().lower() for item in keywords if item.strip()]
    if not normalized:
        raise SourceReadError("at least one keyword is required")
    source_payload = run_source_read(
        run_summary,
        raw_path,
        include_hashes=False,
        max_chars=max_chars,
        hex_bytes=DEFAULT_MAX_HEX_BYTES,
    )
    preview = source_payload.get("preview")
    if not isinstance(preview, Mapping):
        raise SourceReadError("source-read preview is missing")
    source_path = Path(str(source_payload.get("path") or ""))
    is_archive_entry = bool(source_payload.get("archive_entry"))
    is_sqlite_candidate = (
        not is_archive_entry
        and source_path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}
        and source_path.is_file()
    )
    if is_sqlite_candidate:
        matches, sqlite_summary = search_sqlite_source(
            source_path,
            normalized,
            relative_path=str(source_payload.get("relative_path") or raw_path),
            limit=limit,
            context=context,
        )
        searchable = True
        search_mode = "bounded-sqlite-table-scan"
    else:
        searchable = preview.get("preview_type") == "text"
        text = str(preview.get("text") or "") if searchable else ""
        matches = search_preview_text(
            text,
            normalized,
            relative_path=str(source_payload.get("relative_path") or raw_path),
            limit=limit,
            context=context,
        ) if searchable else []
        sqlite_summary = {}
        search_mode = "bounded-source-read-preview"
    return {
        "command": "source-search",
        "profile_version": "source-search-cli-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_summary": source_payload.get("run_summary", ""),
        "path": source_payload.get("path", ""),
        "relative_path": source_payload.get("relative_path", raw_path),
        "container_relative_path": source_payload.get("container_relative_path", ""),
        "name": source_payload.get("name", ""),
        "extension": source_payload.get("extension", ""),
        "size": source_payload.get("size", 0),
        "archive_entry": source_payload.get("archive_entry", {}),
        "keywords": normalized,
        "searchable": searchable,
        "truncated": bool(preview.get("truncated")) or len(matches) >= normalize_limit(limit, default=100, maximum=10_000),
        "summary": {
            "match_count": len(matches),
            "limit": normalize_limit(limit, default=100, maximum=10_000),
            "context": normalize_limit(context, default=120, maximum=2_000),
            "search_mode": search_mode,
            "zip_entry_search": is_archive_entry,
            **sqlite_summary,
        },
        "matches": matches,
        "source_locator": source_payload.get("source_locator", {}),
        "source_citation_package": source_payload.get("source_citation_package", {}),
        "reportability_decision": {
            "decision": "source-search-hit-is-review-lead-not-standalone-proof",
            "allowed_use": "current-file-keyword-hit-context",
            "required_before_report": [
                "open source-read/source viewer for the same locator",
                "record review status and analyst note",
                "cite path plus line/offset and preserve container provenance",
            ],
        },
    }


def search_preview_text(
    text: str,
    keywords: Sequence[str],
    *,
    relative_path: str,
    limit: int,
    context: int,
) -> list[dict[str, object]]:
    normalized_limit = normalize_limit(limit, default=100, maximum=10_000)
    normalized_context = normalize_limit(context, default=120, maximum=2_000)
    lower_text = text.lower()
    matches: list[dict[str, object]] = []
    for keyword in keywords:
        start = 0
        while len(matches) < normalized_limit:
            offset = lower_text.find(keyword, start)
            if offset < 0:
                break
            line = text.count("\n", 0, offset) + 1
            line_start = text.rfind("\n", 0, offset) + 1
            snippet_start = max(0, offset - normalized_context)
            snippet_end = min(len(text), offset + len(keyword) + normalized_context)
            matches.append(
                {
                    "match_id": f"{hashlib.sha256(f'{relative_path}:{keyword}:{offset}'.encode('utf-8')).hexdigest()[:16]}",
                    "keyword": keyword,
                    "line": line,
                    "offset": offset,
                    "line_offset": offset - line_start,
                    "snippet": text[snippet_start:snippet_end].replace("\n", "\\n"),
                    "citation": f"{relative_path} line {line} offset {offset} keyword {keyword}",
                    "source_path": relative_path,
                }
            )
            start = offset + max(1, len(keyword))
        if len(matches) >= normalized_limit:
            break
    matches.sort(key=lambda item: int(item["offset"]))
    return matches[:normalized_limit]


def search_sqlite_source(
    source_path: Path,
    keywords: Sequence[str],
    *,
    relative_path: str,
    limit: int,
    context: int,
    row_scan_limit: int = 5_000,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    normalized_limit = normalize_limit(limit, default=100, maximum=10_000)
    normalized_context = normalize_limit(context, default=120, maximum=2_000)
    max_rows = normalize_limit(row_scan_limit, default=5_000, maximum=100_000)
    matches: list[dict[str, object]] = []
    scanned_tables = 0
    scanned_rows = 0
    searchable_columns = 0
    try:
        connection = sqlite3.connect(f"{source_path.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return [], {
            "sqlite_search": True,
            "sqlite_status": f"open-failed: {exc}",
            "sqlite_scanned_tables": 0,
            "sqlite_scanned_rows": 0,
            "sqlite_searchable_columns": 0,
        }
    with contextlib.closing(connection):
        connection.row_factory = sqlite3.Row
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        except sqlite3.Error as exc:
            return [], {
                "sqlite_search": True,
                "sqlite_status": f"schema-read-failed: {exc}",
                "sqlite_scanned_tables": 0,
                "sqlite_scanned_rows": 0,
                "sqlite_searchable_columns": 0,
            }
        for table_row in table_rows:
            if len(matches) >= normalized_limit or scanned_rows >= max_rows:
                break
            table = str(table_row["name"])
            columns = sqlite_searchable_columns(connection, table)
            if not columns:
                continue
            scanned_tables += 1
            searchable_columns += len(columns)
            quoted_columns = ", ".join(sqlite_quote_identifier(column) for column in columns)
            rowid_expr = "rowid"
            try:
                rows = connection.execute(
                    f"SELECT {rowid_expr} AS __rapid_rowid, {quoted_columns} "
                    f"FROM {sqlite_quote_identifier(table)} LIMIT ?",
                    (max_rows - scanned_rows,),
                )
            except sqlite3.Error:
                continue
            for row in rows:
                scanned_rows += 1
                rowid = row["__rapid_rowid"] if "__rapid_rowid" in row.keys() else ""
                for column in columns:
                    value = row[column]
                    if value is None:
                        continue
                    text = str(value)
                    for match in search_preview_text(
                        text,
                        keywords,
                        relative_path=relative_path,
                        limit=normalized_limit - len(matches),
                        context=normalized_context,
                    ):
                        match.update(
                            {
                                "table": table,
                                "column": column,
                                "rowid": rowid,
                                "citation": (
                                    f"{relative_path} table {table} rowid {rowid} "
                                    f"column {column} offset {match['offset']} keyword {match['keyword']}"
                                ),
                                "source_path": relative_path,
                            }
                        )
                        matches.append(match)
                        if len(matches) >= normalized_limit:
                            break
                    if len(matches) >= normalized_limit:
                        break
                if len(matches) >= normalized_limit or scanned_rows >= max_rows:
                    break
    return matches[:normalized_limit], {
        "sqlite_search": True,
        "sqlite_status": "searched",
        "sqlite_scanned_tables": scanned_tables,
        "sqlite_scanned_rows": scanned_rows,
        "sqlite_searchable_columns": searchable_columns,
        "sqlite_row_scan_limit": max_rows,
    }


def sqlite_searchable_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({sqlite_quote_identifier(table)})").fetchall()
    except sqlite3.Error:
        return []
    columns: list[str] = []
    for row in rows:
        name = str(row[1])
        declared_type = str(row[2] or "").upper()
        if not declared_type or any(token in declared_type for token in ("CHAR", "CLOB", "TEXT", "VARCHAR")):
            columns.append(name)
    return columns


def sqlite_quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


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


def parse_archived_source_request(raw_path: str) -> dict[str, str] | None:
    text = str(raw_path or "").strip()
    if ARCHIVED_SOURCE_SEPARATOR not in text:
        return None
    archive_path, entry_name = text.split(ARCHIVED_SOURCE_SEPARATOR, 1)
    archive_path = archive_path.strip()
    entry_name = entry_name.strip().replace("\\", "/")
    if not archive_path or not entry_name:
        raise SourceReadError("archived source path must be formatted as archive.zip::entry/path.json")
    if Path(entry_name).is_absolute() or ".." in Path(entry_name).parts:
        raise SourceReadError("archive entry path must be relative and must not contain parent traversal")
    if Path(archive_path).suffix.lower() != ".zip":
        raise SourceReadError("archived source-read currently supports .zip containers only")
    return {"archive_path": archive_path, "entry_name": entry_name}


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


def build_archived_source_preview(
    archive_path: Path,
    *,
    entry_name: str,
    max_chars: int,
    hex_bytes: int,
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            info = find_zip_entry(archive, entry_name)
            if info.is_dir():
                raise SourceReadError(f"archive entry is a directory: {entry_name}")
            if info.file_size > MAX_ARCHIVED_SOURCE_ENTRY_BYTES:
                raise SourceReadError(
                    f"archive entry is too large for source-read ({info.file_size} bytes > "
                    f"{MAX_ARCHIVED_SOURCE_ENTRY_BYTES} bytes): {entry_name}"
                )
            blob = archive.read(info)
    except zipfile.BadZipFile as exc:
        raise SourceReadError(f"invalid zip archive: {archive_path}") from exc
    except KeyError as exc:
        raise SourceReadError(f"archive entry not found: {entry_name}") from exc
    except OSError as exc:
        raise SourceReadError(f"failed to read archive entry {entry_name}: {exc}") from exc

    entry_hashes = {
        "sha256": hashlib.sha256(blob).hexdigest(),
        "md5": hashlib.md5(blob).hexdigest(),
        "sha1": hashlib.sha1(blob).hexdigest(),
    }
    entry_metadata = {
        "container_type": "zip",
        "archive_path": str(archive_path),
        "archive_entry_name": info.filename,
        "archive_entry_index": zip_entry_index(archive_path, info.filename),
        "archive_entry_size": info.file_size,
        "archive_entry_compressed_size": info.compress_size,
        "archive_entry_crc32": f"{info.CRC:08x}",
        "archive_entry_modified_at": zip_info_modified_at(info),
        "entry_hashes": entry_hashes,
        "source_path": f"{archive_path}{ARCHIVED_SOURCE_SEPARATOR}{info.filename}",
        "large_data_controls": {
            "max_entry_bytes": MAX_ARCHIVED_SOURCE_ENTRY_BYTES,
            "extraction_mode": "in-memory-bounded-single-entry",
            "writes_extracted_files": False,
        },
    }

    if len(blob) <= max_chars and not is_probably_binary_bytes(blob):
        text = blob.decode("utf-8", errors="replace")
        preview = text_preview_payload(text, max_chars=max_chars, strategy="bounded-zip-entry-text")
    else:
        preview = hex_preview_payload_from_bytes(blob, hex_bytes=hex_bytes, total_size=len(blob))
    preview.update(entry_metadata)
    preview["core_accuracy_gates"] = {
        "component": "source-read-zip-entry-locator",
        "satisfied_checks": [
            "zip entry read without extraction",
            "entry size cap enforced",
            "entry crc and hashes emitted",
            "container path and entry locator preserved",
        ],
        "remaining_blockers": [
            "archive completeness and original evidence container provenance must be validated separately",
            "nested archives and encrypted zip entries are not expanded by source-read",
        ],
    }
    return preview, entry_metadata


def find_zip_entry(archive: zipfile.ZipFile, entry_name: str) -> zipfile.ZipInfo:
    normalized = entry_name.strip().replace("\\", "/")
    try:
        return archive.getinfo(normalized)
    except KeyError:
        lower = normalized.lower()
        for info in archive.infolist():
            if info.filename.lower() == lower:
                return info
        raise


def zip_entry_index(archive_path: Path, entry_name: str) -> int:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for index, info in enumerate(archive.infolist()):
                if info.filename == entry_name:
                    return index
    except (OSError, zipfile.BadZipFile):
        return -1
    return -1


def zip_info_modified_at(info: zipfile.ZipInfo) -> str:
    try:
        return dt.datetime(*info.date_time, tzinfo=dt.timezone.utc).isoformat()
    except (TypeError, ValueError):
        return ""


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
    if preview.get("container_type") == "zip":
        locator_type = "zip-entry-text-preview" if preview.get("preview_type") == "text" else "zip-entry-byte-range"
        return {
            "locator_type": locator_type,
            "container_type": "zip",
            "archive_entry_name": str(preview.get("archive_entry_name") or ""),
            "archive_entry_index": int_or_default(preview.get("archive_entry_index"), -1),
            "archive_entry_crc32": str(preview.get("archive_entry_crc32") or ""),
            "archive_entry_size": int(preview.get("archive_entry_size") or 0),
            "preview_length": int(preview.get("preview_length") or 0),
            "byte_count": int(preview.get("byte_count") or 0),
            "entry_sha256": str(
                preview.get("entry_hashes", {}).get("sha256")
                if isinstance(preview.get("entry_hashes"), Mapping)
                else ""
            ),
            "text_sha256": str(preview.get("text_sha256") or ""),
            "preview_sha256": str(preview.get("preview_sha256") or ""),
        }
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


def build_source_citation_package(
    *,
    relative_path: str,
    source_path: Path,
    preview: Mapping[str, object],
    source_locator: Mapping[str, object],
    hashes: Mapping[str, str],
    include_hashes: bool,
) -> dict[str, object]:
    locator_text = copy_safe_locator_text(source_locator)
    snippet = source_citation_snippet(preview)
    sha256 = str(hashes.get("sha256") or "")
    hash_status = "present" if sha256 else "not-requested" if not include_hashes else "missing"
    citation_core = {
        "relative_path": relative_path,
        "locator": source_locator,
        "source_sha256": sha256,
        "preview_type": str(preview.get("preview_type") or ""),
        "snippet_sha256": hashlib.sha256(snippet.encode("utf-8", errors="replace")).hexdigest() if snippet else "",
    }
    citation_id = stable_json_hash(citation_core)[:16]
    citation_text = f"{relative_path} [{locator_text}]"
    if sha256:
        citation_text = f"{citation_text} sha256:{sha256}"
    review_note_lines = [
        f"Current-file hit: {citation_text}",
        f"Snippet: {snippet}",
        "Review hint: Verify source hash, locator, parser limitation, and review status before report inclusion.",
    ]
    package_core = {
        "profile_version": "source-read-citation-package-v1",
        "citation_id": citation_id,
        "citation_text": citation_text,
        "relative_path": relative_path,
        "source_path_hash": hashlib.sha256(str(source_path).encode("utf-8", errors="replace")).hexdigest(),
        "source_locator": dict(source_locator),
        "source_hash_status": hash_status,
        "source_sha256": sha256,
        "snippet": snippet,
        "snippet_sha256": citation_core["snippet_sha256"],
        "review_note_template": "\n".join(review_note_lines),
        "report_selection_guidance": [
            "Open and verify this source before selecting it for a report.",
            "Carry the citation text, source hash, and locator into the review mark or report item.",
            "Treat bounded previews as reviewer aids, not standalone proof.",
        ],
        "core_accuracy_gates": {
            "component": "source-read-citation-package",
            "satisfied_checks": [
                "copy-safe citation text emitted",
                "stable locator serialized",
                "snippet hash emitted",
                "report note template emitted",
            ],
            "remaining_blockers": source_citation_blockers(hash_status=hash_status, preview=preview),
        },
        "commercial_gap_ids": ["#52", "#64", "#65"],
        "ready_for_review_note": True,
        "ready_for_court_report": False,
    }
    package_core["package_hash"] = stable_json_hash(package_core)
    return package_core


def source_citation_blockers(*, hash_status: str, preview: Mapping[str, object]) -> list[str]:
    blockers = [
        "review mark and analyst sign-off required before report inclusion",
        "original evidence container provenance must be preserved outside source-read",
    ]
    if preview.get("container_type") == "zip":
        blockers.append("archive completeness and original ZIP container provenance must be validated separately")
    if hash_status != "present":
        blockers.append("source hash was not computed for this source-read run")
    if bool(preview.get("truncated")):
        blockers.append("preview was truncated; open the exact locator or continue pagination before final wording")
    return blockers


def copy_safe_locator_text(source_locator: Mapping[str, object]) -> str:
    locator_type = str(source_locator.get("locator_type") or "unavailable")
    if locator_type in {"zip-entry-text-preview", "zip-entry-byte-range"}:
        return (
            f"zip entry {source_locator.get('archive_entry_name', '')} "
            f"crc32 {source_locator.get('archive_entry_crc32', '')}"
        )
    if locator_type == "sqlite-table-page":
        return (
            f"sqlite table {source_locator.get('table', '')} "
            f"offset {source_locator.get('offset', 0)} limit {source_locator.get('limit', 0)}"
        )
    if locator_type == "byte-range":
        return f"byte offset {source_locator.get('offset', 0)} length {source_locator.get('byte_count', 0)}"
    if locator_type == "text-preview":
        return f"text preview length {source_locator.get('preview_length', 0)}"
    return locator_type


def source_citation_snippet(preview: Mapping[str, object], *, max_chars: int = 240) -> str:
    snippet = ""
    if preview.get("preview_type") == "text":
        snippet = str(preview.get("text") or "")
    elif preview.get("preview_type") == "sqlite-table":
        rows = preview.get("rows") if isinstance(preview.get("rows"), list) else []
        if rows and isinstance(rows[0], Mapping):
            snippet = json.dumps(rows[0].get("values", {}), ensure_ascii=False, sort_keys=True)
    elif preview.get("preview_type") == "hex":
        snippet = str(preview.get("ascii") or preview.get("hex") or "")
    else:
        snippet = str(preview.get("message") or "")
    snippet = " ".join(snippet.split())
    return snippet if len(snippet) <= max_chars else snippet[: max_chars - 14] + "...[truncated]"


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
    return hex_preview_payload_from_bytes(blob, hex_bytes=hex_bytes, total_size=source_path.stat().st_size)


def hex_preview_payload_from_bytes(blob: bytes, *, hex_bytes: int, total_size: int) -> dict[str, object]:
    blob = blob[:hex_bytes]
    ascii_preview = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in blob)
    return {
        "preview_type": "hex",
        "strategy": "bounded-hex",
        "offset": 0,
        "byte_count": len(blob),
        "hex": blob.hex(),
        "ascii": ascii_preview,
        "preview_sha256": hashlib.sha256(blob).hexdigest() if blob else "",
        "truncated": total_size > len(blob),
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
        "container_type": str(preview.get("container_type") or ""),
        "archive_entry_name": str(preview.get("archive_entry_name") or ""),
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


def int_or_default(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


def is_probably_binary_bytes(blob: bytes, *, sample_size: int = 4096) -> bool:
    sample = blob[:sample_size]
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
