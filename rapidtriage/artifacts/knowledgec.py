"""Read CoreDuet KnowledgeC events from a copied SQLite database and its WAL."""
from __future__ import annotations

import json
import math
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path

from ..core.models import ArtifactRecord
from ..core.sqlite_snapshot import open_sqlite_snapshot, sqlite_snapshot_reference
from .macos import isoformat_from_macos_absolute

SYSTEM_DB = Path("private/var/db/CoreDuet/Knowledge/knowledgeC.db")
USER_DB = Path("Library/Application Support/Knowledge/knowledgeC.db")
MAX_ROWS = 5_000
MAX_VALUE_BYTES = 4_096
MAX_METADATA_COLUMNS = 256
MAX_VALUE_COLUMNS = 32
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
KNOWN_STREAMS = frozenset({
    "/app/activity", "/app/inFocus", "/app/intents", "/app/mediaUsage", "/app/usage",
    "/app/webUsage", "/bluetooth/isConnected", "/device/batteryPercentage",
    "/device/isLocked", "/device/isPluggedIn", "/display/isBacklit", "/notification/usage",
    "/safari/history",
})
# Streams whose ZVALUESTRING is the subject app's bundle ID (APOLLO knowledge_app_* modules).
VALUE_BUNDLE_STREAMS = frozenset({"/app/activity", "/app/inFocus", "/app/mediaUsage", "/app/usage"})
VALUE_COLUMNS = ("ZVALUESTRING", "ZVALUEINTEGER", "ZVALUEDOUBLE", "ZVALUEBINARY", "ZVALUEDATE")
OBJECT_COLUMNS = ("ZSTREAMNAME", "ZSTARTDATE", "ZENDDATE", "ZBUNDLEID", "ZVALUETYPE",
                  "ZSOURCE", "ZSTRUCTUREDMETADATA")


class KnowledgeCProvider:
    name = "macos-knowledgec"
    collector_kind = "macos-knowledgec"
    description = "macOS CoreDuet KnowledgeC activity intervals"
    target_platform = "macos"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterator[ArtifactRecord]:
        root = root.absolute()
        if root.is_symlink():
            return
        yield from _collect_database(root, root / SYSTEM_DB, "system", "system")
        users = root / "Users"
        if not users.is_symlink() and users.is_dir():
            for home in sorted(users.iterdir()):
                if not home.is_symlink() and home.is_dir():
                    yield from _collect_database(root, home / USER_DB, "user", home.name)
        else:
            # The selected evidence may itself be an extracted home directory.
            yield from _collect_database(root, root / USER_DB, "user", root.name)


def _snapshot_size(path: Path) -> int:
    size = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        member = path.with_name(path.name + suffix)
        try:
            details = member.lstat()
        except FileNotFoundError:
            if not suffix:
                raise
            continue
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("non-regular-snapshot-member")
        size += details.st_size
    return size


def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
    # Core Data stores ordinary tables. Avoid executing views or virtual tables
    # from an untrusted schema; only constant table names reach the PRAGMA.
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name=? COLLATE NOCASE "
        "AND type='table' AND sql LIKE 'CREATE TABLE %'", (table,),
    ).fetchone()
    if not exists:
        return []
    return [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]


def _bounded_field(alias: str, column: str) -> str:
    # Apply the byte limit inside SQLite so an oversized BLOB never reaches Python.
    field = alias + '."' + column.replace('"', '""') + '"'
    count = MAX_VALUE_BYTES + 1
    return (f"CASE typeof({field}) WHEN 'text' THEN CAST(substr(CAST({field} AS BLOB),1,{count}) AS TEXT) "
            f"WHEN 'blob' THEN substr({field},1,{count}) ELSE {field} END")


def _read_events(connection: sqlite3.Connection, base: dict) -> Iterator[ArtifactRecord]:
    connection.execute("PRAGMA trusted_schema=OFF")
    obj = {col.upper() for col in _columns(connection, "ZOBJECT")}
    if "ZSTREAMNAME" not in obj:
        yield _diagnostic(base, "missing-stream-column")
        return

    row_id = "Z_PK" if "Z_PK" in obj else "rowid"
    # Prefer the standard payload columns but retain additional value columns
    # by name; opaque metadata or an unfamiliar value type can still be cited.
    value_columns = [col for col in VALUE_COLUMNS if col in obj]
    value_columns += sorted(col for col in obj if col.startswith("ZVALUE")
                            and col not in VALUE_COLUMNS and col != "ZVALUETYPE")
    if len(value_columns) > MAX_VALUE_COLUMNS:
        yield _diagnostic(base, "value-column-cap")
    fields = [("o", col) for col in (row_id, *OBJECT_COLUMNS, *value_columns[:MAX_VALUE_COLUMNS])
              if col in obj or col == row_id]
    joins = []
    meta = _columns(connection, "ZSTRUCTUREDMETADATA") if "ZSTRUCTUREDMETADATA" in obj else []
    source = {col.upper() for col in _columns(connection, "ZSOURCE")} if "ZSOURCE" in obj else set()
    if "Z_PK" in {col.upper() for col in meta}:
        joins.append("LEFT JOIN ZSTRUCTUREDMETADATA m ON m.Z_PK=o.ZSTRUCTUREDMETADATA")
        meta_fields = [col for col in meta if col.upper() not in {"Z_PK", "Z_ENT", "Z_OPT"}]
        if len(meta_fields) > MAX_METADATA_COLUMNS:
            yield _diagnostic(base, "metadata-column-cap")
        fields.extend(("m", col) for col in meta_fields[:MAX_METADATA_COLUMNS])
    if "Z_PK" in source:
        joins.append("LEFT JOIN ZSOURCE s ON s.Z_PK=o.ZSOURCE")
        fields.extend(("s", col) for col in ("ZBUNDLEID", "ZDEVICEID") if col in source)

    projections = ", ".join(_bounded_field(alias, col) for alias, col in fields)
    # Core Data may share ZOBJECT between several entities. A row without a
    # stream is not an activity event, and must not consume the event cap.
    query = (f"SELECT {projections} FROM ZOBJECT o {' '.join(joins)} "
             f"WHERE typeof(o.ZSTREAMNAME)='text' AND o.ZSTREAMNAME<>'' ORDER BY o.{row_id} LIMIT ?")
    # Preserve original bytes until clipping/decoding, including split UTF-8.
    connection.text_factory = lambda raw: raw.decode("utf-8", "surrogateescape")
    output_size = 0
    for index, row in enumerate(connection.execute(query, (MAX_ROWS + 1,))):
        if index == MAX_ROWS:
            yield _diagnostic(base, "row-cap")
            return
        groups = {"o": {}, "s": {}, "m": {}}
        warnings = []
        for (alias, col), value in zip(fields, row):
            if value is not None:
                groups[alias][col] = _normalize(value, col, warnings)
        details = _event_details(groups["o"], groups["s"], groups["m"], warnings)
        details.update(base, source_table="ZOBJECT", source_index=index, source_row_id=groups["o"].get(row_id))
        output_size += len(json.dumps(details, ensure_ascii=False).encode("utf-8"))
        if output_size > MAX_OUTPUT_BYTES:
            yield _diagnostic(base, "output-byte-cap")
            return
        yield ArtifactRecord(KnowledgeCProvider.name, "macos-knowledgec-event", base["source_path"], True, details)


def _normalize(value: object, column: str, warnings: list[str]) -> object:
    if isinstance(value, (str, bytes)):
        raw = value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value
        if len(raw) > MAX_VALUE_BYTES:
            warnings.append("value-truncated:" + column)
            raw = raw[:MAX_VALUE_BYTES]
        if isinstance(value, bytes):
            return {"hex": raw.hex()}
        return raw.decode("utf-8", "replace")
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def _event_details(obj: dict, source: dict, meta: dict, warnings: list[str]) -> dict:
    stream = obj["ZSTREAMNAME"]
    unknown = stream not in KNOWN_STREAMS
    if unknown:
        warnings.append("unknown-stream")
    start_raw, end_raw = obj.get("ZSTARTDATE"), obj.get("ZENDDATE")
    start, end = _absolute_time(start_raw), _absolute_time(end_raw)
    if start_raw is not None and not start:
        warnings.append("invalid-start-time")
    if end_raw is not None and not end:
        warnings.append("invalid-end-time")
    values = {k: v for k, v in obj.items() if k.startswith("ZVALUE") and k != "ZVALUETYPE"}
    # Only stored identifiers name the subject app. The producing source bundle
    # stays in source_bundle_id and is never substituted for it. An explicit
    # identifier wins; the string value names the app only on streams whose
    # payload is the bundle ID (not /app/webUsage's page or /app/intents' app name).
    bundle = obj.get("ZBUNDLEID")
    ambiguous = False
    if not bundle:
        metadata_bundles = {v for k, v in meta.items() if isinstance(v, str) and v and
                            (k.upper().endswith("__BUNDLEID") or k.upper() == "ZBUNDLEID")}
        ambiguous = len(metadata_bundles) > 1
        if ambiguous:
            warnings.append("ambiguous-metadata-bundle")
        else:
            bundle = next(iter(metadata_bundles), None)
    payload = obj.get("ZVALUESTRING") if stream in VALUE_BUNDLE_STREAMS else None
    if bundle and payload and payload != bundle:
        warnings.append("subject-bundle-conflict")
    elif not bundle and not ambiguous:
        bundle = payload
    return {
        "stream": stream, "unknown_stream": unknown,
        "timestamp": start, "start_at": start, "end_at": end,
        "start_raw": start_raw, "end_raw": end_raw,
        "value": next((values[col] for col in VALUE_COLUMNS if col in values), None), "values": values, "value_type": obj.get("ZVALUETYPE"),
        "bundle_id": bundle, "source_bundle_id": source.get("ZBUNDLEID"),
        "source_device": source.get("ZDEVICEID"), "source_id": obj.get("ZSOURCE"),
        "structured_metadata": meta, "structured_metadata_id": obj.get("ZSTRUCTUREDMETADATA"),
        "coverage_status": "partial" if any(w.startswith(("value-truncated:", "invalid-")) for w in warnings)
        else "parsed",
        "warnings": warnings,
    }


def _absolute_time(raw: object) -> str | None:
    # Core Data stores dates as numeric seconds since 2001-01-01 UTC. Text or
    # binary in a date column is kept raw and flagged rather than reinterpreted.
    if not isinstance(raw, (int, float)):
        return None
    return isoformat_from_macos_absolute(raw) or None


def _diagnostic(base: dict, reason: str) -> ArtifactRecord:
    return ArtifactRecord(KnowledgeCProvider.name, "macos-knowledgec-diagnostic", base["source_path"], True,
                          {**base, "coverage_status": "partial", "reason": reason})


def _collect_database(root: Path, path: Path, scope: str, owner: str) -> Iterator[ArtifactRecord]:
    base = {"parser": KnowledgeCProvider.name, "parser_version": "knowledgec-v1", "source_path": str(path),
            "reportability": "triage", "scope": scope, "owner": owner}
    try:
        # Stop at the first symlink without following it, even to check existence.
        current = root
        for part in path.relative_to(root).parts[:-1]:
            current /= part
            if current.is_symlink():
                return
        try:
            size = _snapshot_size(path)
        except FileNotFoundError:
            return
        if size > MAX_SNAPSHOT_BYTES:
            yield _diagnostic(base, "snapshot-byte-cap")
            return
        provenance = {}
        with open_sqlite_snapshot(path, provenance=provenance) as connection:
            base["source_snapshot"] = sqlite_snapshot_reference(provenance)
            yield from _read_events(connection, base)
    except ValueError as exc:
        yield _diagnostic(base, str(exc))
    except (OSError, sqlite3.Error) as exc:
        yield _diagnostic(base, f"snapshot-read-error: {exc}")
