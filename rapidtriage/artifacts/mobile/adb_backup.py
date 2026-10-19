"""Android ``adb backup`` (``.ab``) unpacking (R5 L3; 재감사 §3 item 24).

An ``.ab`` file is a text header -- ``ANDROID BACKUP``, format version, compression flag
(``0``/``1``), encryption (``none`` / ``AES-256``) and, when encrypted, the salts / rounds / IV /
master-key blob lines -- followed by a zlib stream (when compressed) of a tar archive whose
members are ``apps/<package>/<domain>/<path>`` (domains: ``_manifest``, ``a`` APK, ``f`` files,
``db`` databases, ``sp`` shared_prefs, ``r`` root, ``c`` cache, ``ef`` external) and
``shared/<n>/…`` (shared storage).

:func:`collect_adb_backup` streams the tar in memory (nothing is written next to the evidence)
and yields one ``android-backup`` row (header, member / package counts, status) and one
``android-backup-member`` row per member: package, domain, path, size, mtime, mode, and for
members up to ``MAX_HASH_BYTES`` the SHA-256. A SQLite database member up to
``MAX_SQLITE_BYTES`` is copied to a private temporary file and given the same schema inventory
the existing ``android-app-data`` rows use (``build_android_sqlite_schema_inventory``: tables,
columns, row counts; no values); category / risk flags come from the same helpers.

An encrypted backup gives the header row only, with the Korean reason: the backup password is
needed and is never guessed (no brute force). A corrupt or truncated stream keeps the members
read so far (``status`` = ``partial``). Caps: ``MAX_MEMBERS`` members, ``MAX_TOTAL_BYTES``
decompressed bytes and a ``MAX_RATIO`` decompression-ratio guard.

R6 S2 (inner databases handed to the app parsers): with ``inner_root`` set (the run output's
``mobile-inner/`` folder, never the evidence tree), each SQLite member (``SQLite format 3``
header) of an ``apps/<package>/{db,f,r,sp}/`` domain is streamed to
``<inner_root>/<backup sha256[:16]>/<sha256(package)[:16]>/<safe name>`` together with its
``-wal`` / ``-shm`` / ``-journal`` companions. File names come only from the member's basename
through :func:`safe_component`; only regular members are written (links / devices skipped) and
an existing file is never overwritten. Caps: ``MAX_SQLITE_BYTES`` per database,
``MAX_SQLITE_MEMBERS`` databases and ``MAX_INNER_EXTRACT_BYTES`` in total per backup; a member
over a cap keeps its member row (``inner_extract_skipped`` = ``cap``). Each copy is then handed
to the existing parser: a messenger database (``is_chat_app_database_candidate``) to
``collect_chat_app_database_inventory``, anything else to ``build_android_app_data_record``;
those rows carry ``container_backup_path``, ``container_member``, ``inner_path`` and
``recovery_method`` = ``adb-backup-extracted``. The copies are labelled "해제 사본, 증거 아님"
(marker file + ``rapidtriage-mobile-inner.json`` index) and pruned from evidence rescans.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import tarfile
import tempfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath

from ...core.files import MOBILE_INNER_INDEX_NAME, MOBILE_INNER_MARKER_NAME
from ...core.models import ArtifactRecord

ADB_MAGIC = b"ANDROID BACKUP\n"
PARSER = "android-adb-backup"
PARSER_VERSION = "android-adb-backup-v1"
MAX_HEADER_BYTES = 4096
MAX_MEMBERS = 50_000
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024
MAX_RATIO = 200
MAX_HASH_BYTES = 32 * 1024 * 1024
MAX_SQLITE_BYTES = 64 * 1024 * 1024
MAX_SQLITE_MEMBERS = 200
# R6 S2: inner-database extraction (copies under the run output, never the evidence tree).
MAX_INNER_EXTRACT_BYTES = 1024 * 1024 * 1024
MAX_SAFE_NAME = 120
INNER_DOMAINS = frozenset({"db", "f", "r", "sp"})
COMPANION_SUFFIXES = ("-wal", "-shm", "-journal")
SQLITE_MAGIC = b"SQLite format 3\x00"
INNER_INDEX_NAME = MOBILE_INNER_INDEX_NAME
INNER_COPY_LABEL = "해제 사본, 증거 아님"
INNER_MARKER_TEXT = (
    "해제 사본, 증거 아님\n"
    "이 폴더는 RapidTriage가 adb 백업(.ab) 안 SQLite 데이터베이스를 기존 앱 파서에 넘기려고 풀어 둔 사본입니다.\n"
    "원본 증거가 아니며 증거 재스캔에서 제외됩니다. 원본은 각 행의 container_backup_path·container_member를 보십시오.\n"
)
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{n}" for n in range(1, 10)), *(f"LPT{n}" for n in range(1, 10))}
)
CHUNK = 1024 * 1024
INFLATE_STEP = 64 * 1024
DOMAIN_LABELS = {
    "_manifest": "백업 매니페스트",
    "a": "APK",
    "f": "앱 파일(files)",
    "db": "데이터베이스(databases)",
    "sp": "설정(shared_prefs)",
    "r": "앱 루트",
    "c": "캐시",
    "ef": "외부 저장소(앱)",
    "k": "키-값 백업",
    "obb": "확장 파일(OBB)",
}
ENCRYPTED_REASON = "암호화된 adb 백업(AES-256): 백업 비밀번호 없이는 해제할 수 없어 존재·헤더만 기록함(비밀번호 대입은 하지 않음)"


class AdbBackupError(ValueError):
    """Not an adb backup / malformed header (Korean message)."""


def read_header(handle) -> dict[str, object]:
    """Header fields of an ``.ab`` (handle positioned at the payload afterwards)."""
    head = handle.read(MAX_HEADER_BYTES)
    if not head.startswith(ADB_MAGIC):
        raise AdbBackupError("adb 백업 서명(ANDROID BACKUP)이 아닙니다")
    lines = head.split(b"\n")
    if len(lines) < 5:
        raise AdbBackupError("adb 백업 헤더가 잘렸습니다")
    try:
        version = int(lines[1])
        compressed = int(lines[2]) == 1
    except ValueError as exc:
        raise AdbBackupError("adb 백업 헤더의 버전·압축 값이 숫자가 아닙니다") from exc
    encryption = lines[3].decode("ascii", errors="replace").strip()
    header_lines = 4 if encryption.lower() == "none" else 9
    if len(lines) <= header_lines:
        raise AdbBackupError("adb 백업 암호화 헤더가 잘렸습니다")
    offset = sum(len(line) + 1 for line in lines[:header_lines])
    handle.seek(offset)
    header: dict[str, object] = {
        "backup_version": version,
        "compressed": compressed,
        "encryption": encryption,
        "payload_offset": offset,
    }
    if encryption.lower() != "none":
        # Only the PBKDF2 round count is kept: salts, IV and the master-key blob are key material.
        try:
            header["pbkdf2_rounds"] = int(lines[6])
        except ValueError:
            header["pbkdf2_rounds"] = None
    return header


class _Inflate:
    """File-like reader of the (optionally zlib-compressed) payload with bomb guards.

    Decompression is incremental (``max_length`` + ``unconsumed_tail``): one call never
    produces more than the bytes asked for plus :data:`INFLATE_STEP`, so a 1 MiB chunk of a
    zlib bomb cannot balloon into gigabytes in memory before the size / ratio guards run."""

    def __init__(self, handle, compressed: bool) -> None:
        self.handle = handle
        self.decoder = zlib.decompressobj() if compressed else None
        self.buffer = bytearray()
        self.pending = b""
        self.read_in = 0
        self.produced = 0
        self.eof = False

    def _next_data(self, room: int) -> bytes:
        if self.decoder is None:
            chunk = self.handle.read(max(room, CHUNK))
            self.read_in += len(chunk)
            if not chunk:
                self.eof = True
            return chunk
        if not self.pending:
            if self.decoder.eof:
                self.eof = True
                return b""
            chunk = self.handle.read(CHUNK)
            self.read_in += len(chunk)
            if not chunk:
                self.eof = True
                return self.decoder.flush()
            self.pending = chunk
        data = self.decoder.decompress(self.pending, max(room, INFLATE_STEP))
        self.pending = b"" if self.decoder.eof else self.decoder.unconsumed_tail
        return data

    def read(self, size: int = -1) -> bytes:
        want = CHUNK * 4 if size is None or size < 0 else size
        while len(self.buffer) < want and not self.eof:
            data = self._next_data(want - len(self.buffer))
            self.produced += len(data)
            if self.produced > MAX_TOTAL_BYTES:
                raise AdbBackupError("해제 크기 상한을 넘었습니다(압축 폭탄 방지)")
            if self.decoder is not None and self.produced > 64 * 1024 * 1024 and self.produced > MAX_RATIO * max(self.read_in, 1):
                raise AdbBackupError("압축 비율이 비정상입니다(압축 폭탄 방지)")
            self.buffer += data
        out = bytes(self.buffer[:want])
        del self.buffer[:want]
        return out


def member_mtime(value: object) -> str | None:
    """ISO UTC of a tar member mtime; ``None`` for 0, negative, non-finite or out-of-range values
    (a PAX ``mtime=1e300`` header must not raise ``OverflowError``)."""
    try:
        seconds = float(value)  # type: ignore[arg-type]
        if not seconds > 0:
            return None
        return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def member_parts(name: str) -> tuple[str, str, str]:
    """``(package, domain, path)`` of a tar member name (``apps/<pkg>/<domain>/<path>``)."""
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if len(parts) >= 3 and parts[0] == "apps":
        return parts[1], parts[2], "/".join(parts[3:])
    if parts and parts[0] == "shared":
        return "", "shared", "/".join(parts[1:])
    return "", "", "/".join(parts)


def _base(path: Path, artifact_type: str, fields: dict[str, object], *, timestamp: str | None, kind: str) -> ArtifactRecord:
    details: dict[str, object] = {
        "parser": PARSER,
        "parser_version": PARSER_VERSION,
        "recovery_method": "adb-backup-unpacked",
        "source_path": str(path),
        "source_format": "android-adb-backup",
        "timestamp": timestamp,
        "timestamp_kind": kind if timestamp else "",
        "timestamp_timezone": "UTC" if timestamp else "",
        **fields,
    }
    return ArtifactRecord(provider="mobile-export-artifacts", artifact_type=artifact_type, path=str(path), supported=True, details=details)


def safe_component(name: str, *, fallback: str = "member.db") -> str:
    """Safe single file-name component from a tar member name (R6 S2 path rule).

    Only the basename is kept (``/`` and ``\\`` both split); characters other than ASCII letters,
    digits, ``.``, ``_`` and ``-`` become ``_`` (so ``:`` NTFS streams, drive letters, NUL and
    control characters never survive); leading dots are dropped (no ``.``/``..``/hidden names);
    Windows device names get a ``_`` prefix; the result is at most ``MAX_SAFE_NAME`` characters
    with a short extension kept."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else "_" for ch in base)
    cleaned = cleaned.lstrip(".").rstrip(". ")
    if not cleaned or set(cleaned) <= {"_", ".", "-"}:
        cleaned = fallback
    if cleaned.partition(".")[0].upper() in _WINDOWS_DEVICE_NAMES:
        cleaned = "_" + cleaned
    if len(cleaned) > MAX_SAFE_NAME:
        stem, dot, suffix = cleaned.rpartition(".")
        if dot and 0 < len(suffix) <= 16:
            cleaned = stem[: MAX_SAFE_NAME - len(suffix) - 1] + "." + suffix
        else:
            cleaned = cleaned[:MAX_SAFE_NAME]
    return cleaned


def _companion_split(relative: str) -> tuple[str, str]:
    """``(database member path, companion suffix)``; suffix ``""`` for a non-companion member."""
    lowered = relative.lower()
    for suffix in COMPANION_SUFFIXES:
        if lowered.endswith(suffix) and len(relative) > len(suffix):
            return relative[: -len(suffix)], suffix
    return relative, ""


def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]


def _within(root: Path, candidate: Path) -> bool:
    try:
        base = os.path.abspath(root)
        return os.path.commonpath([base, os.path.abspath(candidate)]) == base
    except ValueError:
        return False


def write_inner_marker(inner_root: Path) -> None:
    """Create ``inner_root`` and its "copies, not evidence" marker (pruned from evidence walks)."""
    inner_root.mkdir(parents=True, exist_ok=True)
    marker = inner_root / MOBILE_INNER_MARKER_NAME
    if not marker.exists():
        marker.write_text(INNER_MARKER_TEXT, encoding="utf-8")


def write_inner_index(inner_root: Path, copies: list[dict[str, object]]) -> Path | None:
    """``rapidtriage-mobile-inner.json``: every inner copy written by one collection."""
    if not copies:
        return None
    write_inner_marker(inner_root)
    index = inner_root / INNER_INDEX_NAME
    payload = {
        "label_ko": INNER_COPY_LABEL,
        "evidence": False,
        "description_ko": INNER_MARKER_TEXT.strip(),
        "copy_count": len(copies),
        "copies": copies,
    }
    index.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return index


class _InnerExtractor:
    """Bounded writer of one backup's SQLite members under ``<inner_root>/<backup sha16>/``."""

    def __init__(self, inner_root: Path, backup_sha256: str) -> None:
        self.inner_root = inner_root
        candidate, counter = inner_root / backup_sha256[:16], 0
        while candidate.exists():
            counter += 1
            candidate = inner_root / f"{backup_sha256[:16]}-{counter}"
        self.root = candidate
        self.created = False
        self.written_bytes = 0
        self.database_count = 0
        self.skipped = 0
        self.names: dict[tuple[str, str, str], str] = {}
        self.claimed: set[tuple[str, str, str]] = set()
        self.used: dict[str, set[str]] = {}
        self.databases: list[dict[str, object]] = []

    def _name_for(self, package: str, domain: str, db_relative: str, *, database: bool) -> str:
        """Safe name of a database (companions reuse it; a repeated database member gets ``-<n>``)."""
        key = (package, domain, db_relative)
        name = self.names.get(key)
        if name is not None and not (database and key in self.claimed):
            if database:
                self.claimed.add(key)
            return name
        if database:
            self.claimed.add(key)
        used = self.used.setdefault(package, set())
        base = safe_component(db_relative)
        stem, dot, suffix = base.rpartition(".")
        if not dot or not stem:
            stem, suffix = base, ""
        name, counter = base, 0
        while name.lower() in used:
            counter += 1
            name = f"{stem}-{counter}.{suffix}" if suffix else f"{stem}-{counter}"
        used.add(name.lower())
        for extra in COMPANION_SUFFIXES:
            used.add((name + extra).lower())
        self.names[key] = name
        return name

    def plan(self, package: str, domain: str, relative: str, size: int, is_sqlite: bool) -> tuple[Path | None, str]:
        """Target path of a member (``None`` and a reason when it is not extracted)."""
        db_relative, companion = (relative, "") if is_sqlite else _companion_split(relative)
        if not is_sqlite and not companion:
            return None, ""
        if size > MAX_SQLITE_BYTES:
            return None, "size"
        if is_sqlite and self.database_count >= MAX_SQLITE_MEMBERS:
            return None, "count"
        if self.written_bytes + size > MAX_INNER_EXTRACT_BYTES:
            return None, "total"
        target = self.root / _sha16(package) / (self._name_for(package, domain, db_relative, database=is_sqlite) + companion)
        if not _within(self.root, target):
            return None, "unsafe-name"
        return target, ""

    def open(self, target: Path):
        if not self.created:
            write_inner_marker(self.inner_root)
            self.created = True
        target.parent.mkdir(parents=True, exist_ok=True)
        return target.open("xb")  # never overwrite, never write through an existing link


def _stream_member(extracted, head: bytes, size: int, sinks: list[Callable[[bytes], object]]) -> None:
    """Copy one member (``head`` already read) into every sink (hasher / file), chunk by chunk."""
    for sink in sinks:
        sink(head)
    remaining = size - len(head)
    while remaining > 0:
        chunk = extracted.read(min(CHUNK, remaining))
        if not chunk:
            raise EOFError("tar 구성원이 잘렸습니다")
        remaining -= len(chunk)
        for sink in sinks:
            sink(chunk)


def _read_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    package: str,
    domain: str,
    relative: str,
    state: dict[str, int],
    extractor: _InnerExtractor | None,
) -> tuple[str | None, dict[str, object] | None, dict[str, object]]:
    """``(sha256, schema inventory, inner fields)`` of one regular member, streamed (never whole in memory)."""
    from ..android import build_android_sqlite_schema_inventory

    extracted = archive.extractfile(member)
    if extracted is None:
        return None, None, {}
    head = extracted.read(16)
    is_sqlite = head.startswith(SQLITE_MAGIC)
    hasher = hashlib.sha256() if member.size <= MAX_HASH_BYTES else None
    inner_fields: dict[str, object] = {}
    target: Path | None = None
    if extractor is not None and package and domain in INNER_DOMAINS:
        target, reason = extractor.plan(package, domain, relative, member.size, is_sqlite)
        if reason:
            extractor.skipped += 1
            inner_fields = {
                "inner_extract_skipped": "cap" if reason in {"size", "count", "total"} else reason,
                "inner_extract_skipped_reason": reason,
            }
    want_inventory = is_sqlite and member.size <= MAX_SQLITE_BYTES and state["sqlite_done"] < MAX_SQLITE_MEMBERS
    inventory = None
    with tempfile.TemporaryDirectory(prefix="rapidtriage-ab-") as directory:
        inventory_path = target if target is not None else (Path(directory) / "member.db" if want_inventory else None)
        sinks: list[Callable[[bytes], object]] = [hasher.update] if hasher is not None else []
        handle = None
        try:
            if inventory_path is not None:
                handle = extractor.open(inventory_path) if target is not None and extractor is not None else inventory_path.open("xb")
                sinks.append(handle.write)
            if sinks:
                _stream_member(extracted, head, member.size, sinks)
        except FileExistsError:
            inner_fields = {"inner_extract_skipped": "name-collision", "inner_extract_skipped_reason": "name-collision"}
            target = inventory_path = None
        finally:
            if handle is not None:
                handle.close()
        digest = hasher.hexdigest() if hasher is not None else None
        if target is not None and extractor is not None:
            extractor.written_bytes += member.size
            inner_fields = {"inner_path": str(target), "inner_copy_label": INNER_COPY_LABEL}
            if is_sqlite:
                extractor.database_count += 1
                extractor.databases.append(
                    {
                        "package": package,
                        "domain": domain,
                        "member_name": member.name[:1000],
                        "member_path": relative,
                        "inner_path": target,
                        "size": member.size,
                        "sha256": digest,
                    }
                )
            else:
                inner_fields["inner_companion_of"] = _companion_split(relative)[0][:1000]
        if want_inventory and inventory_path is not None:
            state["sqlite_done"] += 1
            inventory = build_android_sqlite_schema_inventory(inventory_path)
    return digest, inventory, inner_fields


def _member_record(
    path: Path,
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    packages: dict[str, int],
    state: dict[str, int],
    extractor: _InnerExtractor | None,
    android_app_data_category: Callable[[Path], str],
    android_app_data_risk_flags: Callable[[Path, str], list[str]],
) -> ArtifactRecord:
    """``android-backup-member`` row of one tar member (links, devices and directories are never read)."""
    package, domain, relative = member_parts(member.name)
    if package:
        packages[package] = packages.get(package, 0) + 1
    digest, inventory, inner_fields = None, None, {}
    if member.isreg():
        digest, inventory, inner_fields = _read_member(archive, member, package, domain, relative, state, extractor)
    pseudo = Path("apps", package, domain, relative) if package else Path(member.name)
    category = android_app_data_category(pseudo)
    mtime = member_mtime(member.mtime)
    fields: dict[str, object] = {
        "member_name": member.name[:1000],
        "package": package,
        "backup_domain": domain,
        "backup_domain_label": DOMAIN_LABELS.get(domain, domain),
        "member_path": relative[:1000],
        "member_type": "file" if member.isfile() else "directory" if member.isdir() else "other",
        "size": member.size,
        "mode": f"{member.mode:o}",
        "member_mtime": mtime,
        "sha256": digest,
        "data_category": category,
        "risk_flags": android_app_data_risk_flags(pseudo, category),
        **inner_fields,
    }
    if inventory is not None:
        fields["sqlite_schema_inventory"] = inventory
    return _base(path, "android-backup-member", fields, timestamp=mtime, kind="member-modified")


def _handed_records(path: Path, extractor: _InnerExtractor, errors: list[str]) -> Iterator[ArtifactRecord]:
    """Hand every extracted database to the existing chat-database / Android app-data parsers."""
    from ..android import (
        android_app_data_category,
        android_app_data_risk_flags,
        build_android_app_data_record,
    )
    from .collector import collect_chat_app_database_inventory
    from .detect import is_chat_app_database_candidate
    from .roots import adb_inner_hint

    for entry in extractor.databases:
        inner_path = Path(str(entry["inner_path"]))
        package = str(entry["package"])
        hint = adb_inner_hint(package, str(entry["domain"]), str(entry["member_path"]), safe=safe_component)
        try:
            if is_chat_app_database_candidate(hint):
                record = collect_chat_app_database_inventory(inner_path, hint=hint)
            else:
                record = build_android_app_data_record(inner_path, package)
                category = android_app_data_category(hint)
                record.details["data_category"] = category
                record.details["risk_flags"] = android_app_data_risk_flags(hint, category)
        except Exception as exc:  # one broken inner database never drops the backup
            errors.append(f"{entry['member_name']}: {type(exc).__name__}"[:300])
            continue
        record.provider = "mobile-export-artifacts"
        record.path = str(path)
        record.details.update(
            {
                "container_backup_path": str(path),
                "container_member": entry["member_name"],
                "container_member_sha256": entry["sha256"],
                "container_format": "android-adb-backup",
                "recovery_method": "adb-backup-extracted",
                "inner_path": str(inner_path),
                "inner_copy_label": INNER_COPY_LABEL,
                "inner_hint": hint.as_posix(),
                "package": package,
                "backup_domain": entry["domain"],
            }
        )
        yield record


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_adb_backup(
    path: Path, *, inner_root: Path | None = None, inner_copies: list[dict[str, object]] | None = None
) -> Iterator[ArtifactRecord]:
    """``android-backup`` + ``android-backup-member`` rows of one ``.ab`` (see module doc), then -- with
    ``inner_root`` (R6 S2) -- the app-parser rows of its extracted inner databases. ``inner_copies``
    (optional) receives one index entry per file written."""
    from ..android import android_app_data_category, android_app_data_risk_flags

    members: list[ArtifactRecord] = []
    packages: dict[str, int] = {}
    status = "completed"
    error = ""
    header: dict[str, object] = {}
    state = {"sqlite_done": 0}
    member_errors = 0
    last_member_error = ""
    extractor: _InnerExtractor | None = None
    try:
        with path.open("rb") as handle:
            header = read_header(handle)
            if str(header.get("encryption") or "").lower() != "none":
                status = "encrypted-not-unpacked"
            else:
                if inner_root is not None:
                    extractor = _InnerExtractor(Path(inner_root), _file_sha256(path))
                stream = _Inflate(handle, bool(header.get("compressed")))
                try:
                    with tarfile.open(fileobj=stream, mode="r|") as archive:  # type: ignore[call-overload]
                        for member in archive:
                            if len(members) >= MAX_MEMBERS:
                                status, error = "partial", "member-cap-reached"
                                break
                            try:
                                record = _member_record(
                                    path,
                                    archive,
                                    member,
                                    packages,
                                    state,
                                    extractor,
                                    android_app_data_category,
                                    android_app_data_risk_flags,
                                )
                            except (tarfile.TarError, zlib.error, EOFError, OSError, AdbBackupError):
                                raise
                            except Exception as exc:  # one malformed member never drops the backup
                                member_errors += 1
                                last_member_error = f"{type(exc).__name__}: {exc}"[:300]
                                continue
                            members.append(record)
                except (tarfile.TarError, zlib.error, EOFError, OSError, ValueError, OverflowError) as exc:
                    status, error = "partial", f"{type(exc).__name__}: {exc}"[:300]
    except (AdbBackupError, OSError) as exc:
        status, error = "unreadable", f"{type(exc).__name__}: {exc}"[:300]
    handed: list[ArtifactRecord] = []
    handoff_errors: list[str] = []
    if extractor is not None:
        handed = list(_handed_records(path, extractor, handoff_errors))
        if inner_copies is not None:
            inner_copies.extend(
                {
                    "inner_path": record.details["inner_path"],
                    "label_ko": INNER_COPY_LABEL,
                    "container_backup_path": str(path),
                    "container_member": record.details.get("member_name"),
                    "size": record.details.get("size"),
                    "sha256": record.details.get("sha256"),
                }
                for record in members
                if record.details.get("inner_path")
            )
    summary: dict[str, object] = {
        **header,
        "status": status,
        "status_reason": ENCRYPTED_REASON if status == "encrypted-not-unpacked" else error,
        "member_count": len(members),
        "package_count": len(packages),
        "packages": sorted(packages)[:200],
        "sqlite_inventoried": state["sqlite_done"],
        "member_error_count": member_errors,
        "member_error_last": last_member_error,
        "coverage_status": "parsed" if status == "completed" else status,
    }
    if extractor is not None:
        summary.update(
            {
                "inner_extract_dir": str(extractor.root) if extractor.created else "",
                "inner_copy_label": INNER_COPY_LABEL,
                "inner_databases_extracted": extractor.database_count,
                "inner_bytes_written": extractor.written_bytes,
                "inner_extract_skipped_count": extractor.skipped,
                "inner_records_handed": len(handed),
                "inner_handoff_errors": handoff_errors[:20],
            }
        )
    yield _base(path, "android-backup", summary, timestamp=None, kind="")
    yield from members
    yield from handed


def adb_backup_error_record(path: Path, exc: BaseException) -> ArtifactRecord:
    """``android-backup`` header row for a backup whose unpacking failed unexpectedly."""
    reason = f"adb 백업 해제 중 예기치 않은 오류로 건너뜀 — {type(exc).__name__}: {exc}"[:300]
    fields: dict[str, object] = {
        "status": "unreadable",
        "status_reason": reason,
        "member_count": 0,
        "package_count": 0,
        "packages": [],
        "sqlite_inventoried": 0,
        "coverage_status": "unreadable",
    }
    return _base(path, "android-backup", fields, timestamp=None, kind="")
