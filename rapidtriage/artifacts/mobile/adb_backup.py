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
"""

from __future__ import annotations

import datetime as dt
import hashlib
import tarfile
import tempfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath

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


def _sqlite_inventory(data: bytes) -> dict[str, object]:
    from ..android import build_android_sqlite_schema_inventory

    with tempfile.TemporaryDirectory(prefix="rapidtriage-ab-") as directory:
        target = Path(directory) / "member.db"
        target.write_bytes(data)
        return build_android_sqlite_schema_inventory(target)


def _member_record(
    path: Path,
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    packages: dict[str, int],
    sqlite_done: int,
    android_app_data_category: Callable[[Path], str],
    android_app_data_risk_flags: Callable[[Path, str], list[str]],
) -> tuple[ArtifactRecord, int]:
    """``android-backup-member`` row of one tar member (and the updated SQLite inventory count)."""
    package, domain, relative = member_parts(member.name)
    if package:
        packages[package] = packages.get(package, 0) + 1
    digest = None
    inventory = None
    if member.isfile() and member.size <= MAX_HASH_BYTES:
        extracted = archive.extractfile(member)
        data = extracted.read() if extracted is not None else b""
        digest = hashlib.sha256(data).hexdigest()
        if (
            data.startswith(b"SQLite format 3\x00")
            and member.size <= MAX_SQLITE_BYTES
            and sqlite_done < MAX_SQLITE_MEMBERS
        ):
            sqlite_done += 1
            inventory = _sqlite_inventory(data)
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
    }
    if inventory is not None:
        fields["sqlite_schema_inventory"] = inventory
    return _base(path, "android-backup-member", fields, timestamp=mtime, kind="member-modified"), sqlite_done


def collect_adb_backup(path: Path) -> Iterator[ArtifactRecord]:
    """``android-backup`` + ``android-backup-member`` rows of one ``.ab`` (see module doc)."""
    from ..android import android_app_data_category, android_app_data_risk_flags

    members: list[ArtifactRecord] = []
    packages: dict[str, int] = {}
    status = "completed"
    error = ""
    header: dict[str, object] = {}
    sqlite_done = 0
    member_errors = 0
    last_member_error = ""
    try:
        with path.open("rb") as handle:
            header = read_header(handle)
            if str(header.get("encryption") or "").lower() != "none":
                status = "encrypted-not-unpacked"
            else:
                stream = _Inflate(handle, bool(header.get("compressed")))
                try:
                    with tarfile.open(fileobj=stream, mode="r|") as archive:  # type: ignore[call-overload]
                        for member in archive:
                            if len(members) >= MAX_MEMBERS:
                                status, error = "partial", "member-cap-reached"
                                break
                            try:
                                record, sqlite_done = _member_record(
                                    path, archive, member, packages, sqlite_done, android_app_data_category, android_app_data_risk_flags
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
    summary: dict[str, object] = {
        **header,
        "status": status,
        "status_reason": ENCRYPTED_REASON if status == "encrypted-not-unpacked" else error,
        "member_count": len(members),
        "package_count": len(packages),
        "packages": sorted(packages)[:200],
        "sqlite_inventoried": sqlite_done,
        "member_error_count": member_errors,
        "member_error_last": last_member_error,
        "coverage_status": "parsed" if status == "completed" else status,
    }
    yield _base(path, "android-backup", summary, timestamp=None, kind="")
    yield from members


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
