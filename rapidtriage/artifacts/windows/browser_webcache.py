"""Legacy Edge / Internet Explorer ``WebCacheV01.dat`` container rows (plan r2-communication §3.3 M3).

``WebCacheV01.dat`` is an ESE database: the ``Containers`` table names every
``Container_<ContainerId>`` table (``History``, ``MSHist01…`` daily/weekly history,
``Content`` = the WinINet cache, ``Cookies``, ``iedownload``, ``DOMStore`` …). Rows are
decoded with the bounded native reader (``ese_native.EseDatabase``) and mapped onto the
existing browser row types:

=====================  ==========================  ========================================
container              artifact type               fields
=====================  ==========================  ========================================
History, MSHist*       ``browser-history``          url, user (``Visited: user@url``), visit_count,
                                                   last visited / created / modified / expires
Content                ``browser-cache-entry``      url, response headers, cached file (INetCache)
                                                   size + SHA-256 when the file is present
Cookies                ``browser-cookie``           host, path, created / last accessed / expires
iedownload             ``browser-download``         source URL and target path (UTF-16 strings of
                                                   the ``ResponseHeaders`` blob), size, times
=====================  ==========================  ========================================

Other containers (``DOMStore``, ``feedplat``, ``iecompat`` …) are only counted in the
decode summary. Times are FILETIME (100 ns since 1601-01-01 UTC). The reader does not
replay the transaction log: a dirty database (``WebCacheV01.jfm`` next to it, dirty
state in the header) may miss its newest rows; the summary carries that limitation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .browser_cache import BODY_POLICY, body_signature, header_fields, parse_raw_headers
from .ese_native import EseDatabase, EseTable

WEBCACHE_PARSER = "windows-webcachev01-rows"
WEBCACHE_PARSER_VERSION = "webcache-ese-rows-v1"
MAX_WEBCACHE_BYTES = 512 * 1024 * 1024
MAX_WEBCACHE_ROWS = 200_000
MAX_CONTENT_FILE_HASH_BYTES = 4 * 1024 * 1024
FILETIME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
FILETIME_MIN = 116_444_736_000_000_000  # 1970-01-01
FILETIME_MAX = 160_000_000_000_000_000  # ~2108
UTF16_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def filetime_iso(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int) or not FILETIME_MIN <= value <= FILETIME_MAX:
        return None
    try:
        return (FILETIME_EPOCH + dt.timedelta(microseconds=value // 10)).isoformat()
    except OverflowError:
        return None


def ese_text(value: object) -> str:
    """A text/binary ESE value as text (UTF-16LE when it looks like it, else Latin-1)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.rstrip("\x00")
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        return raw.decode("latin-1").rstrip("\x00")
    return str(value)


def container_mapping(name: str) -> str:
    lowered = name.lower()
    if lowered == "history" or lowered.startswith("mshist"):
        return "browser-history"
    if lowered == "content":
        return "browser-cache-entry"
    if lowered == "cookies":
        return "browser-cookie"
    if lowered == "iedownload":
        return "browser-download"
    return ""


def split_user_url(url: str) -> tuple[str, str]:
    """``Visited: alice@https://x/`` / ``:2024010120240108: alice@https://x/`` → (user, url)."""
    text = url
    if ":" in text and not re.match(r"^[a-z][a-z0-9+.-]*://", text, flags=re.IGNORECASE):
        head, _, tail = text.partition(": ")
        if tail:
            text = tail
        elif text.lower().startswith("cookie:"):
            text = text[7:]
    user, sep, rest = text.partition("@")
    if sep and "/" not in user and " " not in user:
        return user, rest
    return "", text


def host_of(url: str) -> str:
    try:
        return (urlsplit(url if "://" in url else f"http://{url}").hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def utf16_strings(blob: object, limit: int = 32) -> list[str]:
    if not isinstance(blob, (bytes, bytearray)):
        return []
    return [match.group(0).decode("utf-16-le", "replace") for match in UTF16_STRING.finditer(bytes(blob))][:limit]


def resolve_content_file(webcache_path: Path, secure_dirs: str, directory_index: object, file_name: str) -> Path | None:
    """INetCache file of a ``Content`` row: ``…\\INetCache\\IE\\<SecureDirectories[index]>\\<Filename>``."""
    if not file_name or not isinstance(directory_index, int) or directory_index < 0 or len(secure_dirs) < (directory_index + 1) * 8:
        return None
    name = secure_dirs[directory_index * 8 : (directory_index + 1) * 8]
    local = webcache_path.parent.parent  # …\AppData\Local\Microsoft\Windows
    for base in (local / "INetCache" / "IE", local / "Temporary Internet Files" / "Content.IE5"):
        candidate = base / name / file_name
        if candidate.is_file():
            return candidate
    return None


def hash_content_file(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    digest = hashlib.sha256()
    head = b""
    read = 0
    with path.open("rb") as handle:
        while read < min(size, MAX_CONTENT_FILE_HASH_BYTES):
            chunk = handle.read(min(1024 * 1024, MAX_CONTENT_FILE_HASH_BYTES - read))
            if not chunk:
                break
            if len(head) < 256:
                head += chunk[: 256 - len(head)]
            digest.update(chunk)
            read += len(chunk)
    complete = read >= size
    return {
        "body_size": size,
        "body_sha256": digest.hexdigest() if complete and size else None,
        "body_prefix_sha256": digest.hexdigest() if not complete else None,
        "body_hash_scope": "full" if complete else f"prefix-{read}-bytes",
        "body_head_sha256": hashlib.sha256(head).hexdigest() if head else None,
        "body_signature": body_signature(head),
        "body_status": "hashed",
        "body_file": str(path),
    }


class WebCacheDecode:
    __slots__ = ("containers", "errors", "limitations", "rows", "truncated")

    def __init__(self) -> None:
        # (artifact_type, timestamp, timestamp_kind, fields, source_table, source_row_id)
        self.rows: list[tuple[str, str | None, str, dict[str, object], str, object]] = []
        self.containers: list[dict[str, object]] = []
        self.errors: list[str] = []
        self.limitations: list[str] = []
        self.truncated = False

    def summary(self) -> dict[str, object]:
        counts: dict[str, int] = {}
        for artifact_type, *_rest in self.rows:
            counts[artifact_type] = counts.get(artifact_type, 0) + 1
        return {
            "parser": WEBCACHE_PARSER,
            "parser_version": WEBCACHE_PARSER_VERSION,
            "decode_status": "decoded" if self.rows or self.containers else "not-decoded",
            "containers": self.containers[:200],
            "container_count": len(self.containers),
            "rows_by_type": counts,
            "row_count": len(self.rows),
            "truncated": self.truncated,
            "errors": self.errors[:20],
            "limitations": self.limitations[:20],
        }


def decode_webcache(path: Path, *, max_rows: int = MAX_WEBCACHE_ROWS) -> WebCacheDecode:
    """Decode the mapped containers of one ``WebCacheV01.dat`` (bounded; failures recorded, never raised)."""
    result = WebCacheDecode()
    try:
        size = path.stat().st_size
        if size > MAX_WEBCACHE_BYTES:
            result.errors.append(f"file-over-cap:{size}>{MAX_WEBCACHE_BYTES}")
            return result
        blob = path.read_bytes()
    except OSError as exc:
        result.errors.append(f"unreadable:{type(exc).__name__}")
        return result
    try:
        database = EseDatabase(blob)
    except Exception as exc:  # a corrupt database must not stop the browser provider
        result.errors.append(f"ese-open-failed:{type(exc).__name__}:{exc}"[:200])
        return result
    result.errors.extend(database.errors)
    result.limitations.extend(database.limitations)
    tables = {table.name: table for table in database.tables}
    containers_table = tables.get("Containers")
    if containers_table is None:
        if database.tables:
            result.errors.append("containers-table-missing")
        return result
    containers: list[dict[str, Any]] = []
    try:
        for _node, row, _markers in database.iter_table_rows(containers_table):
            containers.append(row)
    except Exception as exc:
        result.errors.append(f"containers-table-unreadable:{type(exc).__name__}")
    for container in containers:
        container_id = container.get("ContainerId")
        name = ese_text(container.get("Name"))
        table = tables.get(f"Container_{container_id}")
        mapped = container_mapping(name)
        entry: dict[str, object] = {
            "container_id": container_id,
            "name": name,
            "directory": ese_text(container.get("Directory"))[:260],
            "mapped_type": mapped,
            "table_present": table is not None,
            "row_count": 0,
            "error_count": 0,
        }
        result.containers.append(entry)
        if table is None or not mapped:
            if table is not None:
                entry["row_count"] = sum(1 for _ in _safe_rows(database, table, entry))
            continue
        secure_dirs = ese_text(container.get("SecureDirectories"))
        row_count = 0
        error_count = 0
        for node, row, markers in _safe_rows(database, table, entry):
            row_count += 1
            if len(result.rows) >= max_rows:
                result.truncated = True
                continue
            try:
                mapped_row = map_container_row(path, mapped, name, row, secure_dirs=secure_dirs)
            except (ValueError, OSError, TypeError) as exc:
                error_count += 1
                if len(result.errors) < 20:
                    result.errors.append(f"{name}:{type(exc).__name__}")
                continue
            artifact_type, timestamp, timestamp_kind, fields = mapped_row
            fields.update(
                {
                    "webcache_container": name,
                    "webcache_container_id": container_id,
                    "source_offset": node.record_file_offset,
                    "record_deleted_flag": node.deleted,
                    "ese_markers": markers[:10],
                }
            )
            result.rows.append((artifact_type, timestamp, timestamp_kind, fields, f"Container_{container_id}", row.get("EntryId")))
        entry["row_count"] = row_count
        entry["error_count"] = int(entry.get("error_count") or 0) + error_count
    return result


def _safe_rows(database: EseDatabase, table: EseTable, entry: dict[str, object]):
    try:
        yield from database.iter_table_rows(table)
    except Exception as exc:  # isolate a corrupt container table
        entry["error_count"] = 1
        entry["error"] = f"{type(exc).__name__}"


def map_container_row(
    path: Path, mapped: str, container: str, row: Mapping[str, Any], *, secure_dirs: str
) -> tuple[str, str | None, str, dict[str, object]]:
    raw_url = ese_text(row.get("Url"))
    user, url = split_user_url(raw_url)
    accessed = filetime_iso(row.get("AccessedTime"))
    created = filetime_iso(row.get("CreationTime"))
    modified = filetime_iso(row.get("ModifiedTime"))
    expires = filetime_iso(row.get("ExpiryTime"))
    sync = filetime_iso(row.get("SyncTime"))
    common: dict[str, object] = {
        "parser": WEBCACHE_PARSER,
        "parser_version": WEBCACHE_PARSER_VERSION,
        "recovery_method": "parsed",
        "webcache_url_raw": raw_url[:2048],
        "webcache_user": user,
        "entry_id": row.get("EntryId"),
        "access_count": row.get("AccessCount"),
        "created_at": created,
        "modified_at": modified,
        "expires_at": expires,
        "synced_at": sync,
        "accessed_at": accessed,
    }
    if mapped == "browser-history":
        common.update(
            {
                "row_kind": "webcache-history" if container.lower() == "history" else "webcache-history-period",
                "url": url,
                "title": "",
                "domain": host_of(url),
                "visit_count": row.get("AccessCount") or 0,
                "typed_count": 0,
                "hidden": False,
            }
        )
        return mapped, accessed or modified, "last-visited" if accessed else "modified", common
    if mapped == "browser-cookie":
        host, _, cookie_path = url.partition("/")
        common.update(
            {
                "host": host,
                "path": f"/{cookie_path}",
                "name": "",
                "last_accessed_at": accessed,
                "session_cookie": not bool(expires),
                "value_present": False,
                "value_policy": "쿠키 값은 수집하지 않음(존재 여부만 기록)",
                "cookie_file_name": ese_text(row.get("Filename"))[:260],
            }
        )
        return mapped, created or accessed, "created" if created else "last-accessed", common
    if mapped == "browser-download":
        strings = utf16_strings(row.get("ResponseHeaders"))
        source = next((item for item in strings if re.match(r"^[a-z][a-z0-9+.-]*://", item, flags=re.IGNORECASE)), url)
        target = next((item for item in strings if re.match(r"^[A-Za-z]:\\|^\\\\", item)), "")
        common.update(
            {
                "source_url": source,
                "url": source,
                "target_path": target,
                "total_bytes": row.get("FileSize"),
                "started_at": accessed or created,
                "state_name": "",
                "download_strings": strings[:8],
            }
        )
        return mapped, accessed or created, "download-started", common
    # Content: WinINet cache entry.
    headers_text = ese_text(row.get("ResponseHeaders"))
    parsed = parse_raw_headers(headers_text) if "HTTP/" in headers_text.upper() else {}
    fields = header_fields(parsed) if parsed else {}
    file_name = ese_text(row.get("Filename"))[:260]
    common.update(fields)
    common.update(
        {
            "url": url,
            "host": host_of(url),
            "method": "GET",
            "method_basis": "webcache-content",
            "cache_format": "webcache-content",
            "cache_file_name": file_name,
            "headers_status": "parsed" if parsed else "no-headers",
            "body_stored": False,
            "body_policy": BODY_POLICY,
            "body_size": row.get("FileSize"),
            "body_sha256": None,
            "body_status": "cached-file-not-found",
        }
    )
    cached = resolve_content_file(path, secure_dirs, row.get("SecureDirectory"), file_name)
    if cached is not None:
        common.update(hash_content_file(cached))
    return mapped, accessed or created, "last-accessed" if accessed else "created", common
