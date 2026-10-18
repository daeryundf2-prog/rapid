"""Desktop cloud sync clients (R2 M4): OneDrive, Dropbox, Google Drive (DriveFS), Naver MYBOX, iCloud for Windows.

Plan ``docs/plans/r2-communication-2026-10-17.md`` §3.4. One provider, kind
``cloud-sync``, four row types:

``cloud-sync-account``   client, account (e-mail / CID / account id), tenant, sync root(s)
``cloud-sync-file``      item path, state, size, cloud modified time, shared flag, item id
``cloud-sync-event``     upload / download / delete / rename / share, time, path, size, actor
``cloud-sync-inventory`` per client instance: files, SQLite tables, encrypted stores, reasons

Sources (all read-only, bounded, each source isolated -- a corrupt file becomes a
``source_errors`` entry of its client's inventory row and the run continues):

* OneDrive ``AppData\\Local\\Microsoft\\OneDrive\\settings\\<Personal|BusinessN>``:
  ``*.ini`` (UTF-16 ``library`` lines, ``cid``, e-mail, tenant), ``SyncEngineDatabase.db``
  (``od_ClientFile_Records`` / ``od_ClientFolder_Records`` / ``od_ScopeInfo_Records``; any
  ``*.db``/``*.dat`` with a SQLite header is read the same way), legacy binary ``<cid>.dat``
  (inventory only). ``logs\\<account>\\*.odl|odlgz|odlsent|aodl``: gzip bodies are
  inflated (bounded), records are located by the ``CC DD EE FF 00 00 00 00`` block
  signature and only their length-prefixed strings are read (``recovery_method``
  ``log-record-carved``). ``ObfuscationStringMap.txt`` is applied when present; newer
  clients encrypt parameters with ``general.keystore`` -- not decrypted (policy).
* Dropbox ``AppData\\Local\\Dropbox\\info.json`` (account sections, sync root),
  ``host.db`` (base64 root path), ``AppData\\Roaming\\Dropbox\\instanceN\\*.dbx``
  (encrypted SQLite: inventory only), ``sync_history.db`` when it is plain SQLite.
* Google Drive for desktop ``AppData\\Local\\Google\\DriveFS\\<account id>``:
  ``metadata_sqlite_db`` (``items`` + ``stable_parents``), ``mirror_sqlite_db``
  (``mirror_item``), ``content_cache`` (count / bytes), ``root_preference_sqlite.db``
  (sync roots); legacy Backup and Sync ``Google\\Drive\\user_default``
  (``sync_config.db`` key/value, ``snapshot.db`` ``cloud_entry``).
* Naver MYBOX (``Naver\\MYBOX``, ``NaverMYBOX``, legacy ``NDrive``): path signature and
  SQLite table inventory only.
* iCloud for Windows (``AppleInc.iCloud_*`` package, ``Apple Inc``/``Apple Computer``
  iCloud folders, ``Users\\<u>\\iCloudDrive``): path signature inventory; an
  ``iCloudDrive`` folder is reported as the sync root.
* Google Docs stubs (R5 L3): ``.gdoc`` / ``.gsheet`` / ``.gslides`` / ``.gdraw`` / ``.gform`` …
  JSON files (Backup and Sync ``url`` / ``doc_id`` / ``email`` / ``resource_id``; Drive for
  desktop ``doc_id`` / ``email``) anywhere in the input -> ``cloud-sync-file`` rows with
  ``google_doc_type`` and the document URL (``resource_key`` is never copied); DriveFS items
  whose mime type is ``application/vnd.google-apps.*`` get the same ``google_doc_type`` / URL.
* ``Windows\\Prefetch\\<CLIENT>.EXE-*.pf`` without any client data: one inventory row
  ``executable-trace-only`` (the client ran, its data is not in the input).

Every row carries ``recovery_method``, ``parser_version``, ``source_path``,
``source_offset`` (byte offset for logs, ``None`` for SQLite rows) and
``source_locator`` (``table=… rowid=…`` / ``offset=…``). Schema semantics of the
sync databases are not vendor-documented: state values stay raw
(``sync_state_semantics = unvalidated``) and every row is ``validation_required``.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import math
import re
import sqlite3
import struct
import zlib
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..core.models import ArtifactRecord
from ..core.sqlite_snapshot import open_sqlite_snapshot
from ..core.submission import compute_hashes
from ._walk import iter_evidence_paths
from .url_redaction import redact_text_urls, redact_url_fields, url_sha256

PARSER = "cloud-sync-clients"
PARSER_VERSION = "cloud-sync-clients-v1"

CLIENT_LABELS: dict[str, str] = {
    "onedrive": "OneDrive",
    "dropbox": "Dropbox",
    "google-drive": "Google Drive",
    "naver-mybox": "네이버 MYBOX",
    "icloud": "iCloud",
}
OPERATION_LABELS: dict[str, str] = {
    "upload": "업로드",
    "download": "다운로드",
    "delete": "삭제",
    "rename": "이름 변경·이동",
    "share": "공유",
}

# --- caps -------------------------------------------------------------------------
MIB = 1024 * 1024
MAX_CLIENT_FILES = 20_000  # client files listed per instance (more are counted, not listed)
MAX_SQLITE_BYTES = 512 * MIB
MAX_CONFIG_BYTES = 1 * MIB
MAX_HASH_BYTES = 256 * MIB
MAX_LOG_FILES = 400  # per run
MAX_LOG_FILE_BYTES = 64 * MIB  # on disk
MAX_LOG_INFLATED_BYTES = 128 * MIB  # after gzip
MAX_LOG_TOTAL_BYTES = 512 * MIB  # all logs of a run, after gzip
MAX_LOG_RECORD_BYTES = 64 * 1024
MAX_LOG_RECORDS_SCANNED = 2_000_000  # record signatures walked per log file (no offset list is kept)
MAX_LOG_EVENTS_PER_FILE = 5_000
MAX_LOG_STRINGS_PER_RECORD = 32
MAX_FILE_ROWS_PER_SOURCE = 50_000
MAX_EVENT_ROWS_PER_SOURCE = 20_000
MAX_TREE_NODES = 400_000  # folder / parent map entries per database
MAX_PATH_DEPTH = 64
# Parent links walked per chain (empty-named nodes count too) and resolved prefixes memoised per database.
MAX_CHAIN_STEPS = 2 * MAX_PATH_DEPTH
MAX_CHAIN_CACHE = 100_000
MAX_ROWS_TOTAL = 250_000
MAX_OBFUSCATION_MAP_BYTES = 16 * MIB
MAX_OBFUSCATION_ENTRIES = 500_000
MAX_INVENTORY_SAMPLES = 20
MAX_SOURCE_ERRORS = 50
MAX_SQLITE_TABLES_LISTED = 40

SQLITE_MAGIC = b"SQLite format 3\x00"
GZIP_MAGIC = b"\x1f\x8b"
ODL_FILE_MAGIC = b"EBFGONED"
ODL_HEADER_SIZE = 0x100
ODL_RECORD_SIGNATURE = b"\xcc\xdd\xee\xff\x00\x00\x00\x00"
ODL_SUFFIXES = (".odl", ".odlgz", ".odlsent", ".aodl")
# Plausible log record times (2010-01-01 .. 2040-01-01) in Unix milliseconds.
ODL_MIN_MS = 1_262_304_000_000
ODL_MAX_MS = 2_208_988_800_000

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
QUOTED_WINDOWS_PATH_RE = re.compile(r'"((?:[A-Za-z]:\\|\\\\)[^"\r\n]{0,400})"')
WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\x00-\x1f\"<>|*?]{1,400}")
FILE_NAME_RE = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f]{1,200}\.[A-Za-z0-9]{1,6}$")
ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{3,1024}")
# UTF-16LE runs of ASCII and Hangul syllables (U+AC00-U+D7A3): Korean file names in log parameters.
UTF16_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00|[\x00-\xff][\xac-\xd7]){4,512}")
LOG_KEYWORD_RE = re.compile(rb"(?i)upload|download|hydrat|delete|recycle|rename|move|shar(?:e|ing)")
SOURCE_SUFFIX_EXCLUDED = ("-wal", "-shm", "-journal")
# URL-like row fields: credential query values are replaced, the raw value's sha256 kept in ``<field>_sha256``.
URL_FIELDS = ("site_url", "item_path", "url")
SOURCE_CODE_SUFFIXES = (".cpp", ".c", ".h", ".hpp", ".cxx")
# A bare drive (the DriveFS virtual drive G:\) is a mount point, not a sync folder.
BARE_DRIVE_RE = re.compile(r"^[A-Za-z]:\\?$")

# Operation keywords, matched against whole tokens (CamelCase / punctuation split, lower-cased) and
# checked in this order: a "DeleteUploadedFile" function is a delete; "SharedFolder" and "SharePoint"
# are not a share; "Dehydrate" (free local space) is not a download; "RemoveFromCache" is not a delete.
OPERATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("share", re.compile(r"(?:un)?shar(?:e|es|ing)")),
    ("delete", re.compile(r"delete[ds]?|deleting|deletion|recycle[ds]?|recycling|remove[ds]?|removing|removal")),
    ("rename", re.compile(r"rename[ds]?|renaming|move[ds]?|moving")),
    ("upload", re.compile(r"upload(?:s|ed|ing|er)?")),
    ("download", re.compile(r"download(?:s|ed|ing|er)?|hydrat(?:e|es|ed|ing|ion)")),
)
# Compound vendor words that would otherwise split into operation tokens.
OPERATION_COMPOUNDS = re.compile(r"(?i)sharepoint|onedrive")
# Tokens that turn a "remove" into a cache eviction rather than a delete of the item.
CACHE_TOKENS = frozenset({"cache", "cached", "dehydrate", "dehydrated", "dehydration", "dehydrating"})
OPERATION_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")

EXECUTABLE_TRACES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("onedrive", ("ONEDRIVE.EXE-",)),
    ("dropbox", ("DROPBOX.EXE-",)),
    ("google-drive", ("GOOGLEDRIVEFS.EXE-", "GOOGLEDRIVESYNC.EXE-")),
    ("icloud", ("ICLOUDDRIVE.EXE-", "ICLOUDSERVICES.EXE-", "ICLOUDHOME.EXE-", "ICLOUD.EXE-")),
    ("naver-mybox", ("NAVERMYBOX", "MYBOX", "NDRIVE", "NAVERNDRIVE")),
)
PATH_PREFILTER_TERMS = ("onedrive", "dropbox", "drivefs", "google", "mybox", "ndrive", "icloud", "apple", "prefetch")
NAVER_CLIENT_SEGMENTS = ("mybox", "naver mybox", "navermybox", "ndrive", "naver ndrive", "naverndrive")
BROWSER_SEGMENTS = ("indexeddb", "user data", "cache_data", "local storage", "service worker", "webcache")
INSTALL_ANCHORS = ("appdata", "program files", "program files (x86)", "programdata")
# R5 L3: Google Docs stubs and DriveFS google-apps mime types.
GOOGLE_STUB_TYPES: dict[str, str] = {
    ".gdoc": "document",
    ".gsheet": "spreadsheet",
    ".gslides": "presentation",
    ".gdraw": "drawing",
    ".gform": "form",
    ".gtable": "table",
    ".gsite": "site",
    ".gmap": "map",
    ".gjam": "jam",
    ".gscript": "script",
}
GOOGLE_DOC_LABELS: dict[str, str] = {
    "document": "Google 문서",
    "spreadsheet": "Google 스프레드시트",
    "presentation": "Google 프레젠테이션",
    "drawing": "Google 드로잉",
    "form": "Google 설문지",
    "table": "Google 표",
    "site": "Google 사이트",
    "map": "Google 내 지도",
    "jam": "Jamboard",
    "script": "Apps Script",
    "folder": "Google Drive 폴더",
    "shortcut": "Google Drive 바로가기",
}
GOOGLE_DOC_URL_PATHS = {
    "document": "document",
    "spreadsheet": "spreadsheets",
    "presentation": "presentation",
    "drawing": "drawings",
    "form": "forms",
}
GOOGLE_APPS_MIME_PREFIX = "application/vnd.google-apps."
GOOGLE_DOC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{10,200}$")
MAX_GOOGLE_STUBS = 20_000
MAX_GOOGLE_STUB_BYTES = 64 * 1024
NO_CLIENT_NOTICE = (
    "클라우드 동기화 클라이언트 흔적 없음: OneDrive·Dropbox·Google Drive·네이버 MYBOX·iCloud의 "
    "설정·DB·로그 경로 서명이 입력에 없음"
)


def google_doc_fields(mime_type: object = None, item_id: object = None, *, doc_type: str = "") -> dict[str, object]:
    """``google_doc_type`` / label / document URL of a Google-native item (R5 L3); empty for other items."""
    kind = doc_type
    if not kind and isinstance(mime_type, str) and mime_type.startswith(GOOGLE_APPS_MIME_PREFIX):
        kind = mime_type[len(GOOGLE_APPS_MIME_PREFIX) :].strip()
    if not kind:
        return {}
    fields: dict[str, object] = {"google_doc_type": kind, "google_doc_type_label": GOOGLE_DOC_LABELS.get(kind, kind)}
    path = GOOGLE_DOC_URL_PATHS.get(kind)
    if path and isinstance(item_id, str) and GOOGLE_DOC_ID_RE.fullmatch(item_id):
        fields["google_doc_url"] = f"https://docs.google.com/{path}/d/{item_id}"
    return fields


def parse_google_stub(data: bytes) -> dict[str, object]:
    """Fields of a Google Docs stub JSON (``url``, ``doc_id``, ``email``, ``resource_id``); never ``resource_key``."""
    try:
        payload = json.loads(decode_text(data))
    except ValueError as exc:
        raise CloudSyncParseError(f"Google 문서 바로가기 JSON이 아닙니다: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CloudSyncParseError("Google 문서 바로가기 JSON이 객체가 아닙니다")
    doc_id = payload.get("doc_id")
    resource_id = payload.get("resource_id")
    if not isinstance(doc_id, str) and isinstance(resource_id, str) and ":" in resource_id:
        doc_id = resource_id.split(":", 1)[1]
    url = payload.get("url")
    email = payload.get("email")
    return {
        "doc_id": doc_id if isinstance(doc_id, str) and GOOGLE_DOC_ID_RE.fullmatch(doc_id) else None,
        "stub_url": url if isinstance(url, str) and url.startswith("https://") else None,
        "email": email if isinstance(email, str) and EMAIL_RE.fullmatch(email) else None,
        "resource_key_present": bool(payload.get("resource_key")),
    }


class CloudSyncParseError(ValueError):
    """A source could not be read (isolated into the client's inventory row)."""


# --- walk / classification ---------------------------------------------------------


@dataclass
class ClientInstance:
    """One client installation scope (OneDrive account folder, DriveFS account, Dropbox data dir, …)."""

    client: str
    key: str
    root: str
    user_profile: str = ""
    account_folder: str = ""
    files: list[tuple[Path, str]] = field(default_factory=list)  # (path, role)
    file_count: int = 0
    total_bytes: int = 0
    files_truncated: bool = False
    role_counts: dict[str, int] = field(default_factory=dict)  # every discovered file, listed or not
    source_errors: list[dict[str, str]] = field(default_factory=list)
    unparsed: list[str] = field(default_factory=list)
    sqlite_inventory: list[dict[str, object]] = field(default_factory=list)
    encrypted: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    sync_roots: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, path: Path, role: str) -> None:
        self.file_count += 1
        self.role_counts[role] = self.role_counts.get(role, 0) + 1
        try:
            self.total_bytes += path.stat().st_size
        except OSError:
            pass
        if len(self.files) < MAX_CLIENT_FILES:
            self.files.append((path, role))
        else:
            self.files_truncated = True

    def error(self, path: Path, exc: BaseException | str) -> None:
        if len(self.source_errors) < MAX_SOURCE_ERRORS:
            self.source_errors.append({"source": str(path), "error": str(exc)[:300]})

    def bump(self, name: str, amount: int = 1) -> None:
        self.counts[name] = self.counts.get(name, 0) + amount

    @property
    def primary_account(self) -> str:
        return self.accounts[0] if self.accounts else ""


def _parts(path: Path) -> list[str]:
    return [part.lower() for part in path.parts]


def user_profile_of(parts: Sequence[str], original: Sequence[str]) -> str:
    for index, part in enumerate(parts[:-1]):
        if part in ("users", "documents and settings") and index + 1 < len(parts):
            return original[index + 1]
    return ""


def _index_of(parts: Sequence[str], name: str, previous: Sequence[str] | None = None) -> int:
    for index, part in enumerate(parts):
        if part == name and (previous is None or (index > 0 and parts[index - 1] in previous)):
            return index
    return -1


def profile_for(path: Path, root: Path | None) -> str:
    r"""The evidence user of ``path``: the ``Users\<name>`` segment below the evidence root, else the
    last one of the full path (a root that is itself a profile or ``AppData`` folder). The location of
    an evidence copy (``C:\Users\<examiner>\AppData\Local\Temp\case``) is never the profile when the
    copy holds its own ``Users`` folder."""
    if root is not None:
        try:
            relative = list(path.relative_to(root).parts)
        except ValueError:
            relative = []
        found = user_profile_of([part.lower() for part in relative], relative)
        if found:
            return found
    original = list(path.parts)
    parts = [part.lower() for part in original]
    for index in range(len(parts) - 2, -1, -1):
        if parts[index] in ("users", "documents and settings"):
            return original[index + 1]
    return ""


def classify_client_path(path: Path, root: Path | None = None) -> tuple[str, str, str, str] | None:
    """``(client, instance key, instance root, role)`` of a client file, else ``None``.

    Roles: ``sqlite`` (decided later by header), ``ini``, ``odl``, ``obfuscation-map``,
    ``keystore``, ``info-json``, ``host-db``, ``dbx``, ``content-cache``, ``sync-root``,
    ``other``.
    """
    prefix = Path()
    original = list(path.parts)
    parts = [part.lower() for part in original]
    if not parts:
        return None
    name = parts[-1]
    if any(part in BROWSER_SEGMENTS for part in parts):
        return None
    profile = profile_for(path, root)
    # --- OneDrive ---------------------------------------------------------------
    index = _index_of(parts, "onedrive", ("microsoft",))
    if index > 0 and "appdata" in parts[:index]:
        sub = parts[index + 1 : -1]
        base = prefix.joinpath(*original[: index + 1])
        if sub[:1] == ["settings"] and len(sub) >= 2:
            account = original[index + 2]
            scope_root = str(base / original[index + 1] / account)
            if name.endswith(".ini"):
                role = "ini"
            elif name.endswith((".db", ".dat", ".sqlite")) and not name.endswith(SOURCE_SUFFIX_EXCLUDED):
                role = "sqlite"
            else:
                role = "other"
            return "onedrive", f"onedrive|{profile}|{account.lower()}", scope_root, role
        if sub[:1] == ["logs"]:
            account = original[index + 2] if len(sub) >= 2 else "logs"
            if name == "obfuscationstringmap.txt":
                role = "obfuscation-map"
            elif name == "general.keystore":
                role = "keystore"
            elif name.endswith(ODL_SUFFIXES):
                role = "odl"
            else:
                role = "other"
            # Logs belong to the account folder of the same name (Personal / Business1);
            # Common / root logs go to the client's "logs" instance.
            key_account = account.lower() if len(sub) >= 2 and account.lower() not in ("common",) else "logs"
            scope_root = str(base / "logs" / account) if len(sub) >= 2 else str(base / "logs")
            return "onedrive", f"onedrive|{profile}|{key_account}", scope_root, role
        return "onedrive", f"onedrive|{profile}|client", str(base), "other"
    # --- Dropbox ----------------------------------------------------------------
    index = _index_of(parts, "dropbox", ("local", "roaming"))
    if index > 1 and parts[index - 2] == "appdata":
        base = prefix.joinpath(*original[: index + 1])
        if name == "info.json":
            role = "info-json"
        elif name == "host.db":
            role = "host-db"
        elif name.endswith(".dbx"):
            role = "dbx"
        elif name.endswith((".db", ".sqlite", ".sqlite3")) and not name.endswith(SOURCE_SUFFIX_EXCLUDED):
            role = "sqlite"
        else:
            role = "other"
        return "dropbox", f"dropbox|{profile}", str(base), role
    # --- Google Drive (DriveFS / Backup and Sync) ----------------------------------
    index = _index_of(parts, "drivefs", ("google",))
    if index > 0:
        base = prefix.joinpath(*original[: index + 1])
        sub = parts[index + 1 : -1]
        if not sub:
            role = "sqlite" if name.endswith((".db", "_db", ".sqlite")) else "other"
            return "google-drive", f"google-drive|{profile}|drivefs", str(base), role
        account = original[index + 1]
        if account.lower() in ("logs", "crashpad", "cef_cache"):
            return "google-drive", f"google-drive|{profile}|drivefs", str(base), "other"
        if "content_cache" in sub:
            role = "content-cache"
        elif name.endswith(("_sqlite_db", ".db", ".sqlite")) and not name.endswith(SOURCE_SUFFIX_EXCLUDED) and len(sub) == 1:
            role = "sqlite"
        else:
            role = "other"
        return "google-drive", f"google-drive|{profile}|{account.lower()}", str(base / account), role
    index = _index_of(parts, "drive", ("google",))
    if index > 0 and "appdata" in parts[:index] and index + 1 < len(parts) - 1 and parts[index + 1].startswith("user_default"):
        base = prefix.joinpath(*original[: index + 2])
        role = "sqlite" if name in ("sync_config.db", "snapshot.db") else "other"
        return "google-drive", f"google-drive|{profile}|backup-and-sync", str(base), role
    # --- Naver MYBOX ---------------------------------------------------------------
    for index, part in enumerate(parts[:-1]):
        if part in NAVER_CLIENT_SEGMENTS and (
            part.startswith("naver") or (index > 0 and parts[index - 1] in ("naver", "naver corp", "navercorp"))
        ):
            if not any(anchor in parts[:index] for anchor in INSTALL_ANCHORS):
                return None
            base = prefix.joinpath(*original[: index + 1])
            role = "sqlite" if not name.endswith(SOURCE_SUFFIX_EXCLUDED) else "other"
            return "naver-mybox", f"naver-mybox|{profile}|{str(base).lower()}", str(base), role
    # --- iCloud for Windows -------------------------------------------------------
    for index, part in enumerate(parts[:-1]):
        if part.startswith("appleinc.icloud"):
            base = prefix.joinpath(*original[: index + 1])
            return "icloud", f"icloud|{profile}", str(base), "sqlite"
        if part in ("iclouddrive", "icloud drive") and index > 0 and (
            parts[index - 1] == profile.lower() or (index > 1 and parts[index - 2] == "users")
        ):
            base = prefix.joinpath(*original[: index + 1])
            return "icloud", f"icloud|{profile}", str(base), "sync-root"
        if part in ("apple inc", "apple computer") and "mobilesync" not in parts:
            rest = parts[index + 1 : -1]
            if rest and any("icloud" in item or "clouddocs" in item or item == "cloudkit" for item in rest):
                base = prefix.joinpath(*original[: index + 2])
                return "icloud", f"icloud|{profile}", str(base), "sqlite"
    return None


def icloud_sync_root(folder: Path, root: Path | None) -> tuple[str, str]:
    r"""``(sync root, path_basis)`` of an ``iCloudDrive`` folder found in an evidence copy.

    The root is anchored at the ``Users\<name>`` segment (``\Users\bob\iCloudDrive``) so that the
    copy's own location (``C\Users\bob`` exported as a folder, the examiner's temp path) never
    becomes part of it. Without a ``Users`` segment (the evidence root *is* the profile) the
    machine location is unknown: the folder is reported relative to the evidence root with no
    leading separator, which ``within_user_profile`` treats as unknown, not as outside a profile.
    """
    try:
        relative = list(folder.relative_to(root).parts) if root is not None else list(folder.parts)
    except ValueError:
        relative = list(folder.parts[1:])  # never the drive / UNC anchor
    lowered = [part.lower() for part in relative]
    for index in range(len(lowered) - 2, -1, -1):
        if lowered[index] in ("users", "documents and settings"):
            return "\\" + "\\".join(relative[index:]), "evidence-root-relative"
    return "\\".join(relative) or folder.name, "evidence-root-relative-unanchored"


def executable_trace_client(path: Path) -> str | None:
    if path.parent.name.lower() != "prefetch" or not path.name.lower().endswith(".pf"):
        return None
    upper = path.name.upper()
    for client, prefixes in EXECUTABLE_TRACES:
        if upper.startswith(prefixes) and ".EXE-" in upper:
            return client
    return None


# --- small readers -----------------------------------------------------------------


def read_head(path: Path, size: int = 16) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return -1


def is_sqlite(path: Path) -> bool:
    return read_head(path) == SQLITE_MAGIC


def read_bounded(path: Path, limit: int) -> bytes:
    size = file_size(path)
    if size < 0:
        raise CloudSyncParseError("읽기 실패")
    if size > limit:
        raise CloudSyncParseError(f"크기 상한 초과({size} > {limit} bytes)")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CloudSyncParseError(f"읽기 실패: {exc}") from exc


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    head = data[:200]
    if head and head.count(b"\x00") * 3 >= len(head) and head[1:2] == b"\x00":
        return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8", errors="replace")


def epoch_to_iso(value: object) -> str | None:
    """Seconds / milliseconds / microseconds since 1970 or a FILETIME (100 ns since 1601) -> ISO UTC."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if re.fullmatch(r"-?\d+(\.\d+)?", text):
            value = float(text)
        else:
            try:
                moment = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=dt.timezone.utc)
            return moment.astimezone(dt.timezone.utc).isoformat()
    if not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number <= 0:
        return None
    if number > 1e16:  # FILETIME
        seconds = number / 1e7 - 11_644_473_600
    elif number > 1e14:
        seconds = number / 1e6
    elif number > 1e11:
        seconds = number / 1e3
    else:
        seconds = number
    if not 315_532_800 <= seconds <= 4_102_444_800:  # 1980 .. 2100
        return None
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat()


def as_int(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    try:
        return int(str(value).strip())
    except (ValueError, OverflowError):
        return None


def as_flag(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "y"):
        return True
    if text in ("0", "false", "no", "n", ""):
        return False
    return None


def scalar(value: object) -> object:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return raw[:64].hex() if raw else None
    return value


def find_column(columns: Sequence[str], *candidates: str) -> str | None:
    lowered = {column.lower(): column for column in columns}
    for candidate in candidates:
        found = lowered.get(candidate.lower())
        if found is not None:
            return found
    squashed = {column.lower().replace("_", ""): column for column in columns}
    for candidate in candidates:
        found = squashed.get(candidate.lower().replace("_", ""))
        if found is not None:
            return found
    return None


def quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sqlite_tables(connection: sqlite3.Connection) -> dict[str, list[str]]:
    tables: dict[str, list[str]] = {}
    names = [
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    ]
    for table in names[:200]:
        try:
            columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({quote_identifier(table)})").fetchall()]
        except sqlite3.Error:
            columns = []
        tables[table] = columns
    return tables


def find_table(tables: Mapping[str, Sequence[str]], *terms: str, exact: Sequence[str] = ()) -> str | None:
    lowered = {name.lower(): name for name in tables}
    for name in exact:
        if name.lower() in lowered:
            return lowered[name.lower()]
    for term in terms:
        for low, name in lowered.items():
            if term in low:
                return name
    return None


def table_inventory(connection: sqlite3.Connection, tables: Mapping[str, Sequence[str]]) -> list[dict[str, object]]:
    listed: list[dict[str, object]] = []
    for name, columns in list(tables.items())[:MAX_SQLITE_TABLES_LISTED]:
        try:
            count = connection.execute(f"SELECT COUNT(*) FROM {quote_identifier(name)}").fetchone()[0]
        except sqlite3.Error:
            count = None
        listed.append({"table": name, "row_count": count, "columns": list(columns)[:40]})
    return listed


ChainCache = dict  # folder id -> (segments top-down, top id, parent links walked); complete chains only


def chain_from_parent(
    parent: object,
    parents: Mapping[object, object],
    names: Mapping[object, str],
    cache: ChainCache | None = None,
) -> tuple[list[str], object, bool]:
    """Folder names from the top down to ``parent`` (inclusive), the first id above the known folders, and a cycle/depth cut flag.

    At most ``MAX_CHAIN_STEPS`` parent links are walked whatever the names (an empty-named chain
    of 200,000 folders is cut, not walked) and at most ``MAX_PATH_DEPTH`` names are kept. With a
    ``cache`` (one per database) every resolved uncut prefix is memoised, so the chains of N
    files cost O(N) walks in total instead of O(N * depth).
    """
    walked: list[object] = []
    seen: set[object] = set()
    current = parent
    cut = False
    base: tuple[tuple[str, ...], object, int] | None = None
    while current is not None and current in names:
        if cache is not None:
            cached = cache.get(current)
            if cached is not None and len(walked) + cached[2] <= MAX_CHAIN_STEPS:
                base = cached
                break
        if current in seen or len(walked) >= MAX_CHAIN_STEPS:
            cut = True
            break
        seen.add(current)
        walked.append(current)
        following = parents.get(current)
        if following is None:
            break
        current = following
    prefix: tuple[str, ...] = base[0] if base is not None else ()
    top = base[1] if base is not None else current
    steps = base[2] if base is not None else 0
    own = [names[item] for item in reversed(walked) if names[item]]
    segments = [*prefix, *own]
    if len(segments) > MAX_PATH_DEPTH:
        segments = segments[-MAX_PATH_DEPTH:]
        cut = True
    if cache is not None and not cut and len(cache) < MAX_CHAIN_CACHE:
        # Memoise every walked node top-down: node k's chain is the prefix plus the names above it.
        running = list(prefix)
        for depth, item in enumerate(reversed(walked), start=1):
            if names[item]:
                running.append(names[item])
            if len(cache) >= MAX_CHAIN_CACHE:
                break
            cache.setdefault(item, (tuple(running), top, steps + depth))
    return segments, top, cut


def redact_row_urls(details: dict[str, object]) -> dict[str, object]:
    """Token-bearing URLs (SharePoint ``tempauth``, signed links) in ``site_url`` / ``item_path`` / ``log_strings``.

    Values are redacted in place; ``<field>_sha256`` (``log_strings_sha256``: one entry per string,
    ``None`` when unchanged) keeps the raw value's sha256 so the same URL still matches across sources.
    """
    redact_url_fields(details, URL_FIELDS)
    strings = details.get("log_strings")
    if isinstance(strings, list) and strings:
        redacted, changed = redact_text_urls(strings)
        if changed:
            details["log_strings_sha256"] = [url_sha256(raw) if new != raw else None for raw, new in zip(strings, redacted)]
            details["log_strings"] = redacted
            details["url_tokens_redacted"] = True
    return details


# --- provider ----------------------------------------------------------------------


class RowBudget:
    def __init__(self, limit: int | None = None) -> None:
        self.limit = MAX_ROWS_TOTAL if limit is None else limit
        self.used = 0
        self.truncated = False

    def take(self) -> bool:
        if self.used >= self.limit:
            self.truncated = True
            return False
        self.used += 1
        return True


class CloudSyncClientsProvider:
    collector_kind = "cloud-sync"
    name = PARSER
    description = "Desktop cloud sync clients (OneDrive, Dropbox, Google Drive, Naver MYBOX, iCloud): accounts, synced items, upload/delete events"
    target_platform = "windows"

    def __init__(self) -> None:
        self.collection_notes: list[str] = []

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        collector = CloudSyncCollector(root)
        records = list(collector.run())
        self.collection_notes = collector.notes()
        return records


class CloudSyncCollector:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.instances: dict[str, ClientInstance] = {}
        self.traces: dict[str, list[str]] = {}
        self.budget = RowBudget()
        self.hash_cache: dict[str, dict[str, str]] = {}
        self.log_files = 0
        self.log_bytes = 0
        self.google_stubs: list[Path] = []
        self.google_stubs_truncated = False

    # -- walk --
    def discover(self) -> None:
        for path in iter_evidence_paths(self.root, "*"):
            if path.suffix.lower() in GOOGLE_STUB_TYPES:
                self.add_google_stub(path)
                continue
            lowered = str(path).lower()
            if not any(term in lowered for term in PATH_PREFILTER_TERMS):
                continue
            trace = executable_trace_client(path)
            classified = None if trace is not None else classify_client_path(path, self.root)
            if trace is None and classified is None:
                continue
            try:
                if not path.is_file():
                    continue
            except OSError:
                continue
            if trace is not None:
                self.traces.setdefault(trace, []).append(str(path))
                continue
            assert classified is not None
            client, key, instance_root, role = classified
            instance = self.instances.get(key)
            if instance is not None and "settings" in _parts(Path(instance_root)) and "settings" not in _parts(Path(instance.root)):
                instance.root = instance_root  # an account's settings folder names it, not its logs folder
            if instance is None:
                instance = ClientInstance(
                    client=client,
                    key=key,
                    root=instance_root,
                    user_profile=profile_for(path, self.root),
                    account_folder=key.rsplit("|", 1)[-1] if client in ("onedrive", "google-drive") else "",
                )
                self.instances[key] = instance
            instance.add(path, role)

    def run(self) -> Iterator[ArtifactRecord]:
        self.discover()
        handlers = {
            "onedrive": self.onedrive,
            "dropbox": self.dropbox,
            "google-drive": self.google_drive,
            "naver-mybox": self.inventory_only,
            "icloud": self.icloud,
        }
        # OneDrive accounts first so log instances can borrow the account e-mail.
        ordered = sorted(self.instances.values(), key=lambda item: (item.client, item.key.endswith("|logs"), item.key))
        for instance in ordered:
            rows: list[ArtifactRecord] = []
            try:
                rows.extend(handlers[instance.client](instance))
            except Exception as exc:  # isolation: one client never stops the others
                instance.error(Path(instance.root), f"클라이언트 처리 실패: {exc}")
            yield from rows
            yield self.inventory_row(instance)
        if self.google_stubs:
            yield from self.google_stub_rows()
        for client, paths in sorted(self.traces.items()):
            if any(instance.client == client for instance in self.instances.values()):
                continue
            yield self.trace_row(client, paths)

    # -- Google Docs stubs (R5 L3) --
    def add_google_stub(self, path: Path) -> None:
        try:
            if not path.is_file():
                return
        except OSError:
            return
        if len(self.google_stubs) >= MAX_GOOGLE_STUBS:
            self.google_stubs_truncated = True
            return
        self.google_stubs.append(path)

    def google_stub_rows(self) -> Iterator[ArtifactRecord]:
        stubs = sorted(self.google_stubs, key=lambda item: str(item).lower())
        first = stubs[0]
        instance = ClientInstance(
            client="google-drive",
            key="google-drive|doc-stubs",
            root=str(first.parent),
            user_profile=profile_for(first, self.root),
        )
        instance.notes.append("Google 문서 바로가기(.gdoc 등) 파일: 문서 내용은 클라우드에만 있음(바로가기의 문서 ID·계정·URL만)")
        if self.google_stubs_truncated:
            instance.notes.append(f"Google 문서 바로가기 상한 {MAX_GOOGLE_STUBS:,}개 초과: 이후 파일은 읽지 않음")
        for path in stubs:
            instance.add(path, "google-doc-stub")
            try:
                if file_size(path) > MAX_GOOGLE_STUB_BYTES:
                    raise CloudSyncParseError("Google 문서 바로가기가 크기 상한을 넘습니다")
                fields = parse_google_stub(read_bounded(path, MAX_GOOGLE_STUB_BYTES))
            except (CloudSyncParseError, OSError) as exc:
                instance.error(path, exc)
                continue
            doc_type = GOOGLE_STUB_TYPES[path.suffix.lower()]
            if fields["email"] and fields["email"] not in instance.accounts:
                instance.accounts.append(str(fields["email"]))
            google = google_doc_fields(item_id=fields["doc_id"], doc_type=doc_type)
            row = self.record(
                instance,
                path,
                artifact_type="cloud-sync-file",
                recovery_method="stub-json",
                source_format="google-docs-stub",
                locator="json",
                item_path=str(path),
                path_basis="local-stub-file",
                file_name=path.name,
                item_id=fields["doc_id"],
                actor=fields["email"],
                url=google.get("google_doc_url") or fields["stub_url"],
                resource_key_present=fields["resource_key_present"] or None,
                sync_state="metadata",
                sync_state_semantics="google-docs-stub",
                **google,
            )
            if row is None:
                break
            instance.bump("files")
            yield row
        yield self.inventory_row(instance)

    def notes(self) -> list[str]:
        notes: list[str] = []
        if not self.instances:
            notes.append(NO_CLIENT_NOTICE)
            traced = sorted(CLIENT_LABELS[client] for client in self.traces)
            if traced:
                notes.append(
                    "실행 흔적(Prefetch)만 있음: " + ", ".join(traced) + " — 클라이언트 설정·DB·로그가 입력에 없음"
                )
        if self.budget.truncated:
            notes.append(f"행 상한 {MAX_ROWS_TOTAL:,}건에 도달해 이후 클라우드 동기화 행을 만들지 않음")
        return notes

    # -- row helpers --
    def hashes(self, path: Path) -> dict[str, str]:
        key = str(path)
        cached = self.hash_cache.get(key)
        if cached is not None:
            return cached
        result: dict[str, str] = {}
        size = file_size(path)
        if 0 <= size <= MAX_HASH_BYTES:
            try:
                result = dict(compute_hashes(path))
            except OSError:
                result = {}
        self.hash_cache[key] = result
        return result

    def record(
        self,
        instance: ClientInstance,
        source: Path,
        *,
        artifact_type: str,
        recovery_method: str,
        source_format: str,
        locator: str,
        offset: int | None = None,
        confidence: str = "medium",
        **values: object,
    ) -> ArtifactRecord | None:
        if not self.budget.take():
            return None
        details: dict[str, object] = {
            "parser": PARSER,
            "parser_version": PARSER_VERSION,
            "client": instance.client,
            "client_label": CLIENT_LABELS[instance.client],
            "recovery_method": recovery_method,
            "source_path": str(source),
            "source_offset": offset,
            "source_locator": locator,
            "source_format": source_format,
            "source_hashes": self.hashes(source) if source.is_file() else {},
            "user_profile": instance.user_profile or None,
            "client_instance_root": instance.root,
            "coverage_status": f"{artifact_type}-bounded",
            "reportability": "triage",
            "parser_confidence": confidence,
            "validation_required": True,
            "validation_guidance": (
                "동기화 클라이언트 DB·로그의 열 의미는 공급사 문서가 없어 검증이 필요합니다. 클라이언트 버전, 계정 범위, "
                "삭제·공유 상태를 MFT/USN·브라우저·감사 로그와 대조한 뒤 보고하십시오."
            ),
        }
        for name, value in values.items():
            if value is not None and value != "" and value != []:
                details[name] = value
        redact_row_urls(details)
        return ArtifactRecord(provider=PARSER, artifact_type=artifact_type, path=str(source), supported=True, details=details)

    def account_row(self, instance: ClientInstance, source: Path, *, locator: str, recovery_method: str, source_format: str, **values: object) -> ArtifactRecord | None:
        account = values.get("account")
        if isinstance(account, str) and account and account not in instance.accounts:
            instance.accounts.append(account)
        for root in values.get("sync_roots") or []:
            if root not in instance.sync_roots:
                instance.sync_roots.append(str(root))
        roots = [str(item) for item in values.get("sync_roots") or []]
        row = self.record(
            instance,
            source,
            artifact_type="cloud-sync-account",
            recovery_method=recovery_method,
            source_format=source_format,
            locator=locator,
            actor=values.get("account"),
            sync_root=roots[0] if roots else None,
            **values,
        )
        if row is not None:
            instance.bump("accounts")
        return row

    # -- OneDrive --
    def onedrive(self, instance: ClientInstance) -> Iterator[ArtifactRecord]:
        if instance.key.endswith("|client"):
            instance.unparsed.append("OneDrive 설치·업데이트 파일: 경로 서명 인벤토리만")
            return
        if any(role in ("ini", "sqlite") for _path, role in instance.files):
            try:
                account_info = self.onedrive_account(instance)
            except Exception as exc:  # isolation: a broken settings folder never drops the DB / logs
                instance.error(Path(instance.root), f"설정 해석 실패: {exc}")
            else:
                row = self.account_row(instance, account_info.pop("_source"), **account_info)
                if row is not None:
                    yield row
        for path, role in instance.files:
            if role != "sqlite":
                continue
            if not is_sqlite(path):
                if path.suffix.lower() == ".dat":
                    instance.unparsed.append(f"{path.name}: 구형 OneDrive 바이너리 .dat — 해석하지 않음(인벤토리만)")
                continue
            try:
                yield from self.onedrive_sync_db(instance, path)
            except Exception as exc:  # isolation: one poisoned database never drops the other sources
                instance.error(path, exc)
        account, borrowed = instance.primary_account, False
        if not account and instance.key.endswith("|logs"):
            account = self.sibling_onedrive_account(instance)
            borrowed = bool(account)
        yield from self.onedrive_logs(instance, account, borrowed=borrowed)

    def sibling_onedrive_account(self, instance: ClientInstance) -> str:
        """The account e-mail of the same profile's OneDrive account folders when there is exactly one (Common logs name none)."""
        accounts = {
            other.primary_account
            for other in self.instances.values()
            if other.client == "onedrive" and other is not instance and other.user_profile == instance.user_profile and other.primary_account
        }
        if len(accounts) == 1:
            return accounts.pop()
        if accounts:
            instance.notes.append(f"공통 로그: 같은 프로필의 OneDrive 계정이 {len(accounts)}개라 이벤트 계정을 정하지 않음")
        return ""

    def onedrive_account(self, instance: ClientInstance) -> dict[str, object]:
        ini_files = [path for path, role in instance.files if role == "ini"]
        folder = instance.account_folder
        emails: list[str] = []
        preferred = 0
        roots: list[str] = []
        cid = tenant = tenant_name = site_url = ""
        source: Path | None = None
        locator = ""
        for path in ini_files:
            try:
                text = decode_text(read_bounded(path, MAX_CONFIG_BYTES))
            except CloudSyncParseError as exc:
                instance.error(path, exc)
                continue
            for line in text.splitlines():
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key_lower = key.strip().lower()
                value = value.strip()
                if key_lower.startswith("library") or any(term in key_lower for term in ("folder", "rootpath", "localpath", "mountpoint")):
                    for found in QUOTED_WINDOWS_PATH_RE.findall(line) or ([value] if re.match(r"^[A-Za-z]:\\", value) else []):
                        cleaned = found.rstrip("\\") or found
                        if cleaned not in roots:
                            roots.append(cleaned)
                            source, locator = path, f"{path.name}: {key.strip()}"
                if key_lower == "cid" and value and not cid:
                    cid = value.strip('"')
                    source = source or path
                if key_lower in ("tenantid", "configuredtenantid", "tenant_id") and value and not tenant:
                    tenant = value.strip('"')
                if key_lower in ("tenantname", "tenantdisplayname") and value and not tenant_name:
                    tenant_name = value.strip('"')
                if key_lower in ("siteurl", "weburl", "davurlnamespace", "spositeurl") and value.startswith(("http", '"http')) and not site_url:
                    site_url = value.strip('"')
                for email in EMAIL_RE.findall(line):
                    if email.lower() not in (item.lower() for item in emails):
                        # An e-mail under an e-mail / UPN key names the account; others (support
                        # addresses in policy files) only follow it.
                        if any(term in key_lower for term in ("email", "upn", "username")):
                            emails.insert(preferred, email)
                            preferred += 1
                        else:
                            emails.append(email)
            if not tenant:
                guid = GUID_RE.search(path.stem)
                if guid and folder.startswith("business"):
                    tenant = guid.group(0)
        anchor = source or (ini_files[0] if ini_files else next(path for path, role in instance.files if role == "sqlite"))
        account_type = "business" if folder.startswith("business") else "personal" if folder == "personal" else folder
        return {
            "_source": anchor,
            "locator": locator or (f"{anchor.name}" if ini_files else "settings folder"),
            "recovery_method": "config-file" if ini_files else "path-signature",
            "source_format": "onedrive-settings-ini" if ini_files else "onedrive-settings-folder",
            "account": emails[0] if emails else (cid or None),
            "account_email": emails[0] if emails else None,
            "account_emails": emails[1:6] or None,
            "account_id": cid or None,
            "account_type": account_type,
            "tenant": tenant_name or tenant or None,
            "tenant_id": tenant or None,
            "site_url": site_url or None,
            "sync_roots": roots,
        }

    def onedrive_sync_db(self, instance: ClientInstance, path: Path) -> Iterator[ArtifactRecord]:
        if file_size(path) > MAX_SQLITE_BYTES:
            raise CloudSyncParseError(f"SQLite 크기 상한 초과({file_size(path)} bytes)")
        with open_sqlite_snapshot(path) as connection:
            tables = sqlite_tables(connection)
            instance.sqlite_inventory.append({"source": str(path), "tables": table_inventory(connection, tables)})
            file_table = find_table(tables, "clientfile")
            folder_table = find_table(tables, "clientfolder")
            scope_table = find_table(tables, "scopeinfo")
            if file_table is None:
                instance.unparsed.append(f"{path.name}: 파일 레코드 표(od_ClientFile_Records) 없음 — 표 인벤토리만")
                return
            folders: dict[object, object] = {}
            folder_names: dict[object, str] = {}
            if folder_table is not None:
                columns = tables[folder_table]
                id_col = find_column(columns, "resourceID", "resource_id", "id")
                parent_col = find_column(columns, "parentResourceID", "parent_resource_id", "parentID")
                name_col = find_column(columns, "folderName", "name", "folder_name")
                if id_col and parent_col and name_col:
                    cursor = connection.execute(
                        f"SELECT {quote_identifier(id_col)}, {quote_identifier(parent_col)}, {quote_identifier(name_col)} "
                        f"FROM {quote_identifier(folder_table)} LIMIT ?",
                        (MAX_TREE_NODES,),
                    )
                    for resource, parent, name in cursor:
                        folders[resource] = parent
                        folder_names[resource] = str(name or "")
            scopes: dict[object, dict[str, object]] = {}
            if scope_table is not None:
                columns = tables[scope_table]
                scope_id = find_column(columns, "scopeID", "scope_id", "id")
                url_col = find_column(columns, "webURL", "siteURL", "web_url", "url")
                remote_col = find_column(columns, "remotePath", "remote_path")
                tenant_col = find_column(columns, "tenantID", "tenant_id")
                if scope_id:
                    selected = [col for col in (scope_id, url_col, remote_col, tenant_col) if col]
                    cursor = connection.execute(
                        f"SELECT {', '.join(quote_identifier(col) for col in selected)} FROM {quote_identifier(scope_table)} LIMIT 1000"
                    )
                    for row in cursor:
                        values = dict(zip(selected, row))
                        scopes[values[scope_id]] = {
                            "url": values.get(url_col) if url_col else None,
                            "remote_path": values.get(remote_col) if remote_col else None,
                            "tenant": values.get(tenant_col) if tenant_col else None,
                        }
            yield from self.onedrive_file_rows(instance, path, connection, file_table, tables[file_table], folders, folder_names, scopes)

    def onedrive_file_rows(
        self,
        instance: ClientInstance,
        path: Path,
        connection: sqlite3.Connection,
        table: str,
        columns: Sequence[str],
        folders: Mapping[object, object],
        folder_names: Mapping[object, str],
        scopes: Mapping[object, Mapping[str, object]],
    ) -> Iterator[ArtifactRecord]:
        col = {
            "id": find_column(columns, "resourceID", "resource_id"),
            "parent": find_column(columns, "parentResourceID", "parent_resource_id"),
            "name": find_column(columns, "fileName", "file_name", "name"),
            "size": find_column(columns, "size", "fileSize"),
            "modified": find_column(columns, "lastChange", "lastModified", "modifiedTime", "lastWriteTime"),
            "status": find_column(columns, "fileStatus", "status", "syncStatus"),
            "shared": find_column(columns, "sharedItem", "shared", "isShared"),
            "hash": find_column(columns, "localHashDigest", "hash", "quickXorHash", "sha1Hash"),
            "etag": find_column(columns, "eTag", "etag"),
            "perms": find_column(columns, "spoPermissions"),
            "created": find_column(columns, "diskCreationTime"),
            "accessed": find_column(columns, "diskLastAccessTime"),
        }
        if not col["name"]:
            instance.unparsed.append(f"{path.name}/{table}: 파일 이름 열 없음")
            return
        selected = [name for name in col.values() if name]
        selected = list(dict.fromkeys(selected))
        sql = f"SELECT rowid AS __rowid, {', '.join(quote_identifier(name) for name in selected)} FROM {quote_identifier(table)} LIMIT ?"
        root = instance.sync_roots[0] if len(instance.sync_roots) == 1 else ""
        chains: ChainCache = {}
        emitted = 0
        for row in connection.execute(sql, (MAX_FILE_ROWS_PER_SOURCE + 1,)):
            if emitted >= MAX_FILE_ROWS_PER_SOURCE:
                instance.unparsed.append(f"{path.name}/{table}: 파일 행 상한 {MAX_FILE_ROWS_PER_SOURCE:,}건에서 중단")
                break
            values = {name: row[index + 1] for index, name in enumerate(selected)}
            rowid = row[0]
            name = str(values.get(col["name"]) or "")
            parent = values.get(col["parent"]) if col["parent"] else None
            segments, top, cut = chain_from_parent(parent, folders, folder_names, chains)
            relative = "\\".join([*segments, name]) if name else "\\".join(segments)
            item_path = f"{root}\\{relative}" if root and relative and not cut else relative
            scope = scopes.get(top) if top is not None else None
            shared = as_flag(values.get(col["shared"])) if col["shared"] else None
            modified = epoch_to_iso(values.get(col["modified"])) if col["modified"] else None
            status = values.get(col["status"]) if col["status"] else None
            record = self.record(
                instance,
                path,
                artifact_type="cloud-sync-file",
                recovery_method="sqlite-row",
                source_format="onedrive-syncenginedatabase",
                locator=f"table={table} rowid={rowid}",
                actor=instance.primary_account or None,
                account=instance.primary_account or None,
                item_path=item_path or None,
                path_basis="sync-root" if root and relative and not cut else "relative-to-sync-root",
                path_truncated=cut or None,
                file_name=name or None,
                item_id=scalar(values.get(col["id"])) if col["id"] else None,
                parent_item_id=scalar(parent),
                size=as_int(values.get(col["size"])) if col["size"] else None,
                timestamp=modified,
                timestamp_kind="cloud-modified" if modified else None,
                modified_at=modified,
                sync_state=None if status is None else str(status),
                sync_state_semantics="unvalidated-raw-value" if status is not None else None,
                shared=shared,
                content_hash=scalar(values.get(col["hash"])) if col["hash"] else None,
                etag=scalar(values.get(col["etag"])) if col["etag"] else None,
                spo_permissions=scalar(values.get(col["perms"])) if col["perms"] else None,
                disk_created_at=epoch_to_iso(values.get(col["created"])) if col["created"] else None,
                disk_accessed_at=epoch_to_iso(values.get(col["accessed"])) if col["accessed"] else None,
                site_url=str(scope.get("url")) if scope and scope.get("url") else None,
                tenant=str(scope.get("tenant")) if scope and scope.get("tenant") else None,
                source_table=table,
                source_rowid=rowid,
                risk_flags=["cloud-sync-shared-item"] if shared else None,
            )
            if record is None:
                return
            emitted += 1
            instance.bump("files")
            yield record

    def load_obfuscation_map(self, instance: ClientInstance) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for path, role in instance.files:
            if role != "obfuscation-map":
                continue
            try:
                text = decode_text(read_bounded(path, MAX_OBFUSCATION_MAP_BYTES))
            except CloudSyncParseError as exc:
                instance.error(path, exc)
                continue
            for line in text.splitlines():
                key, sep, value = line.partition("\t")
                if sep and key and value:
                    mapping.setdefault(key.strip(), value.strip())
                    if len(mapping) >= MAX_OBFUSCATION_ENTRIES:
                        break
        return mapping

    def onedrive_logs(self, instance: ClientInstance, account: str, *, borrowed: bool = False) -> Iterator[ArtifactRecord]:
        logs = [path for path, role in instance.files if role == "odl"]
        if not logs:
            return
        if any(role == "keystore" for _path, role in instance.files):
            instance.notes.append(
                "general.keystore 있음: 최신 OneDrive 로그 매개변수는 이 키로 암호화되어 있으며 복호하지 않음(정책) — 경로·파일 이름이 비어 있을 수 있음"
            )
        mapping = self.load_obfuscation_map(instance)
        if mapping:
            instance.notes.append(f"ObfuscationStringMap.txt 적용({len(mapping):,}개 항목)")
        else:
            instance.notes.append("난독화 문자열 맵 없음: 로그 매개변수의 난독화 문자열은 해석하지 않음")
        if borrowed:
            instance.notes.append(f"공통 로그 이벤트 계정: 같은 프로필의 유일한 OneDrive 계정({account})을 차용 — account_basis=sibling-account-folder")
        for path in sorted(logs, key=lambda item: str(item).lower()):
            remaining = MAX_LOG_TOTAL_BYTES - self.log_bytes
            if self.log_files >= MAX_LOG_FILES or remaining <= 0:
                instance.unparsed.append(f"로그 상한(파일 {MAX_LOG_FILES}개 / {MAX_LOG_TOTAL_BYTES // MIB} MB) 도달: {path.name} 이후 미처리")
                break
            self.log_files += 1
            limit = min(MAX_LOG_INFLATED_BYTES, remaining)
            try:
                data = read_bounded(path, MAX_LOG_FILE_BYTES)
                # The run-wide budget bounds what this file may contribute (inflated or plain): no overshoot.
                version, body, base_offset, inflated, truncated = load_odl_body(data, limit)
            except Exception as exc:  # isolation: one unreadable log never drops the others
                instance.error(path, exc)
                continue
            if truncated:
                instance.unparsed.append(
                    f"{path.name}: 로그 읽기 상한 {limit:,} bytes 도달(파일당 {MAX_LOG_INFLATED_BYTES // MIB} MB·실행 전체 "
                    f"{MAX_LOG_TOTAL_BYTES // MIB} MB) — 이후 레코드 미처리"
                )
            self.log_bytes += len(body)
            instance.bump("log_files")
            try:
                yield from self.odl_events(instance, path, body, base_offset, inflated, version, account, mapping, borrowed=borrowed)
            except Exception as exc:  # corrupt record layout: isolate this file
                instance.error(path, f"ODL 레코드 해석 실패: {exc}")

    def odl_events(
        self,
        instance: ClientInstance,
        path: Path,
        body: bytes,
        base_offset: int,
        inflated: bool,
        version: int | None,
        account: str,
        mapping: Mapping[str, str],
        *,
        borrowed: bool = False,
    ) -> Iterator[ArtifactRecord]:
        emitted = 0
        scanned = 0
        seen: set[tuple[str, str, str]] = set()
        for start, end in odl_record_spans(body):
            scanned += 1
            if scanned > MAX_LOG_RECORDS_SCANNED:
                instance.unparsed.append(f"{path.name}: 로그 레코드 탐색 상한 {MAX_LOG_RECORDS_SCANNED:,}건에서 중단")
                break
            instance.bump("log_records")
            record = body[start : min(end, start + MAX_LOG_RECORD_BYTES)]
            if not LOG_KEYWORD_RE.search(record):
                continue
            parsed = parse_odl_record(record, mapping)
            if parsed is None:
                continue
            operation, basis, function, code_file, strings, item = parsed
            moment = parsed_time(record)
            dedupe = (operation, item or function, moment or "")
            if dedupe in seen:
                continue
            seen.add(dedupe)
            if emitted >= MAX_LOG_EVENTS_PER_FILE:
                instance.unparsed.append(f"{path.name}: 로그 이벤트 상한 {MAX_LOG_EVENTS_PER_FILE:,}건에서 중단")
                return
            row = self.record(
                instance,
                path,
                artifact_type="cloud-sync-event",
                recovery_method="log-record-carved",
                source_format=f"onedrive-odl-v{version}" if version else "onedrive-odl",
                locator=f"offset={base_offset + start:#x}" + (" (gzip 해제 후)" if inflated else ""),
                offset=base_offset + start,
                confidence="low",
                actor=account or None,
                account=account or None,
                account_basis="sibling-account-folder" if borrowed and account else None,
                operation=operation,
                operation_label=OPERATION_LABELS[operation],
                operation_basis=basis,
                timestamp=moment,
                timestamp_kind=f"cloud-{operation}" if moment else None,
                item_path=item,
                log_function=function or None,
                log_code_file=code_file or None,
                log_strings=strings[:MAX_LOG_STRINGS_PER_RECORD],
                source_offset_space="inflated-stream" if inflated else "file",
                bulk_rule_eligible=bool(item) and basis == "log-function-name",
                risk_flags=[f"cloud-sync-{operation}"],
            )
            if row is None:
                return
            emitted += 1
            instance.bump("events")
            yield row
        if not scanned:
            instance.unparsed.append(f"{path.name}: ODL 레코드 서명 없음 — 처리하지 않음")

    # -- Dropbox --
    def dropbox(self, instance: ClientInstance) -> Iterator[ArtifactRecord]:
        order = {"info-json": 0, "host-db": 1}
        for path, role in sorted(instance.files, key=lambda item: (order.get(item[1], 2), str(item[0]).lower())):
            try:
                if role == "info-json":
                    yield from self.dropbox_info(instance, path)
                elif role == "host-db":
                    root = dropbox_host_root(read_bounded(path, MAX_CONFIG_BYTES))
                    if root and root not in instance.sync_roots:
                        # Older clients without info.json: host.db is the only sync-root source.
                        row = self.account_row(
                            instance,
                            path,
                            locator=f"{path.name}: line 2 (base64)",
                            recovery_method="config-file",
                            source_format="dropbox-host-db",
                            account=None,
                            account_type="dropbox-host",
                            sync_roots=[root],
                        )
                        if row is not None:
                            yield row
                elif role == "dbx":
                    instance.encrypted.append(str(path))
                elif role == "sqlite":
                    if not is_sqlite(path):
                        instance.encrypted.append(str(path))
                        continue
                    yield from self.dropbox_sqlite(instance, path)
            except Exception as exc:  # isolation: one source never drops the others
                instance.error(path, exc)
        if instance.encrypted:
            instance.unparsed.append(
                f"암호화된 Dropbox 저장소 {len(instance.encrypted)}개(.dbx 등): 복호하지 않음 — 인벤토리만"
            )

    def dropbox_info(self, instance: ClientInstance, path: Path) -> Iterator[ArtifactRecord]:
        try:
            payload = json.loads(decode_text(read_bounded(path, MAX_CONFIG_BYTES)))
        except json.JSONDecodeError as exc:
            raise CloudSyncParseError(f"info.json JSON 오류: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise CloudSyncParseError("info.json 최상위가 객체가 아님")
        for section, value in payload.items():
            if not isinstance(value, Mapping):
                continue
            root = str(value.get("path") or "")
            row = self.account_row(
                instance,
                path,
                locator=f"info.json: {section}",
                recovery_method="config-file",
                source_format="dropbox-info-json",
                account=None,  # info.json names no e-mail; the host id is the account key
                account_id=str(value.get("host")) if value.get("host") is not None else None,
                account_type=str(section),
                tenant=str(value.get("team_name") or value.get("team") or "") or None,
                subscription_type=str(value.get("subscription_type") or "") or None,
                is_team=value.get("is_team") if isinstance(value.get("is_team"), bool) else None,
                sync_roots=[root] if root else [],
            )
            if row is not None:
                yield row

    def dropbox_sqlite(self, instance: ClientInstance, path: Path) -> Iterator[ArtifactRecord]:
        if file_size(path) > MAX_SQLITE_BYTES:
            raise CloudSyncParseError(f"SQLite 크기 상한 초과({file_size(path)} bytes)")
        with open_sqlite_snapshot(path) as connection:
            tables = sqlite_tables(connection)
            instance.sqlite_inventory.append({"source": str(path), "tables": table_inventory(connection, tables)})
            table = find_table(tables, "sync_history", exact=("sync_history",))
            if table is None:
                return
            columns = tables[table]
            col = {
                "event": find_column(columns, "file_event_type", "event_type", "type", "action"),
                "direction": find_column(columns, "direction"),
                "path": find_column(columns, "local_path", "path", "file_path", "relative_path"),
                "time": find_column(columns, "timestamp", "time", "event_time", "server_time"),
                "actor": find_column(columns, "other_user", "user", "actor"),
                "size": find_column(columns, "size", "bytes", "file_size"),
                "id": find_column(columns, "file_id", "id", "file_identifier"),
                "is_dir": find_column(columns, "is_dir", "is_folder"),
            }
            if not col["path"] or not (col["event"] or col["direction"]):
                instance.unparsed.append(f"{path.name}/{table}: 경로·이벤트 열을 찾지 못함")
                return
            selected = list(dict.fromkeys(name for name in col.values() if name))
            sql = f"SELECT rowid AS __rowid, {', '.join(quote_identifier(name) for name in selected)} FROM {quote_identifier(table)} LIMIT ?"
            account = instance.primary_account
            emitted = 0
            for row in connection.execute(sql, (MAX_EVENT_ROWS_PER_SOURCE + 1,)):
                if emitted >= MAX_EVENT_ROWS_PER_SOURCE:
                    instance.unparsed.append(f"{path.name}/{table}: 이벤트 행 상한 {MAX_EVENT_ROWS_PER_SOURCE:,}건에서 중단")
                    break
                values = {name: row[index + 1] for index, name in enumerate(selected)}
                event = str(values.get(col["event"]) or "") if col["event"] else ""
                direction = str(values.get(col["direction"]) or "") if col["direction"] else ""
                operation = dropbox_operation(event, direction)
                if operation is None:
                    continue
                moment = epoch_to_iso(values.get(col["time"])) if col["time"] else None
                item = str(values.get(col["path"]) or "") or None
                is_dir = as_flag(values.get(col["is_dir"])) if col["is_dir"] else None
                other = str(values.get(col["actor"]) or "") if col["actor"] else ""
                record = self.record(
                    instance,
                    path,
                    artifact_type="cloud-sync-event",
                    recovery_method="sqlite-row",
                    source_format="dropbox-sync-history",
                    locator=f"table={table} rowid={row[0]}",
                    actor=other or account or None,
                    account=account or None,
                    operation=operation,
                    operation_label=OPERATION_LABELS[operation],
                    operation_basis="sqlite-event-columns",
                    event_type_raw=event or None,
                    direction_raw=direction or None,
                    timestamp=moment,
                    timestamp_kind=f"cloud-{operation}" if moment else None,
                    item_path=item,
                    is_folder=is_dir,
                    size=as_int(values.get(col["size"])) if col["size"] else None,
                    item_id=scalar(values.get(col["id"])) if col["id"] else None,
                    other_user=other or None,
                    source_table=table,
                    source_rowid=row[0],
                    bulk_rule_eligible=bool(item) and not is_dir,
                    risk_flags=[f"cloud-sync-{operation}"],
                )
                if record is None:
                    return
                emitted += 1
                instance.bump("events")
                yield record

    # -- Google Drive --
    def google_drive(self, instance: ClientInstance) -> Iterator[ArtifactRecord]:
        content_cache = [path for path, role in instance.files if role == "content-cache"]
        if content_cache:
            instance.bump("content_cache_files", len(content_cache))
            total = 0
            for path in content_cache:
                size = file_size(path)
                total += max(size, 0)
            instance.counts["content_cache_bytes"] = total
            instance.unparsed.append(
                f"content_cache 파일 {len(content_cache):,}개: 캐시 본문은 읽지 않고 개수·크기만 기록"
            )
        sqlite_paths = [path for path, role in instance.files if role == "sqlite"]
        account_id = instance.account_folder if instance.account_folder not in ("drivefs", "backup-and-sync") else ""
        emails: list[str] = []
        roots: list[str] = []
        parsed_rows: list[ArtifactRecord] = []
        for path in sorted(sqlite_paths, key=lambda item: item.name.lower()):
            if not is_sqlite(path):
                instance.unparsed.append(f"{path.name}: SQLite 헤더 아님 — 인벤토리만")
                continue
            if file_size(path) > MAX_SQLITE_BYTES:
                instance.error(path, f"SQLite 크기 상한 초과({file_size(path)} bytes)")
                continue
            try:
                with open_sqlite_snapshot(path) as connection:
                    tables = sqlite_tables(connection)
                    instance.sqlite_inventory.append({"source": str(path), "tables": table_inventory(connection, tables)})
                    found_emails, found_roots = google_account_hints(connection, tables)
                    emails.extend(email for email in found_emails if email not in emails)
                    roots.extend(root for root in found_roots if root not in roots)
                    name = path.name.lower()
                    if name == "metadata_sqlite_db" or (find_table(tables, exact=("items",)) and find_table(tables, exact=("stable_parents",))):
                        parsed_rows.extend(self.drivefs_items(instance, path, connection, tables))
                    elif name == "mirror_sqlite_db" or find_table(tables, exact=("mirror_item",)):
                        parsed_rows.extend(self.drivefs_mirror(instance, path, connection, tables))
                    elif name == "snapshot.db" or find_table(tables, exact=("cloud_entry",)):
                        parsed_rows.extend(self.backup_sync_snapshot(instance, path, connection, tables))
            except Exception as exc:  # isolation: one source never drops the others
                instance.error(path, exc)
        if emails or roots or account_id:
            anchor = sqlite_paths[0] if sqlite_paths else Path(instance.root)
            row = self.account_row(
                instance,
                anchor,
                locator="DriveFS 계정 폴더 이름·SQLite 키/값" if account_id else "SQLite 키/값·roots 표",
                recovery_method="sqlite-row" if emails or roots else "path-signature",
                source_format="google-drivefs" if instance.account_folder != "backup-and-sync" else "google-backup-and-sync",
                account=emails[0] if emails else account_id or None,
                account_email=emails[0] if emails else None,
                account_emails=emails[1:6] or None,
                account_id=account_id or None,
                account_type="drivefs" if instance.account_folder != "backup-and-sync" else "backup-and-sync",
                sync_roots=roots,
            )
            if row is not None:
                yield row
        account = instance.primary_account
        for row in parsed_rows:
            if account and not row.details.get("account"):
                row.details["account"] = account
                row.details["actor"] = account
            yield row

    def drivefs_items(self, instance: ClientInstance, path: Path, connection: sqlite3.Connection, tables: Mapping[str, Sequence[str]]) -> list[ArtifactRecord]:
        table = find_table(tables, exact=("items",))
        if table is None:
            instance.unparsed.append(f"{path.name}: items 표 없음")
            return []
        columns = tables[table]
        col = {
            "stable": find_column(columns, "stable_id"),
            "id": find_column(columns, "id", "cloud_id"),
            "title": find_column(columns, "local_title", "title", "name"),
            "folder": find_column(columns, "is_folder"),
            "trashed": find_column(columns, "trashed", "is_trashed"),
            "size": find_column(columns, "file_size", "size"),
            "modified": find_column(columns, "modified_date", "modified_time", "mtime"),
            "viewed": find_column(columns, "viewed_by_me_date"),
            "shared_date": find_column(columns, "shared_with_me_date"),
            "shared": find_column(columns, "shared", "is_shared"),
            "owner": find_column(columns, "is_owner", "owned_by_me"),
            "mime": find_column(columns, "mime_type"),
        }
        if not col["stable"] or not col["title"]:
            instance.unparsed.append(f"{path.name}/items: stable_id·title 열 없음(구형 protobuf 스키마일 수 있음)")
            return []
        parents: dict[object, object] = {}
        relation = find_table(tables, exact=("stable_parents",))
        if relation is not None:
            rel_cols = tables[relation]
            child = find_column(rel_cols, "item_stable_id", "child_stable_id")
            parent = find_column(rel_cols, "parent_stable_id")
            if child and parent:
                for item, owner in connection.execute(
                    f"SELECT {quote_identifier(child)}, {quote_identifier(parent)} FROM {quote_identifier(relation)} LIMIT ?",
                    (MAX_TREE_NODES,),
                ):
                    parents.setdefault(item, owner)
        names: dict[object, str] = {}
        folder_filter = f" WHERE {quote_identifier(col['folder'])} = 1" if col["folder"] else ""
        for stable, title in connection.execute(
            f"SELECT {quote_identifier(col['stable'])}, {quote_identifier(col['title'])} FROM {quote_identifier(table)}{folder_filter} LIMIT ?",
            (MAX_TREE_NODES,),
        ):
            names[stable] = str(title or "")
        selected = list(dict.fromkeys(name for name in col.values() if name))
        where = f" WHERE {quote_identifier(col['folder'])} = 0 OR {quote_identifier(col['folder'])} IS NULL" if col["folder"] else ""
        sql = f"SELECT rowid AS __rowid, {', '.join(quote_identifier(name) for name in selected)} FROM {quote_identifier(table)}{where} LIMIT ?"
        rows: list[ArtifactRecord] = []
        chains: ChainCache = {}
        for row in connection.execute(sql, (MAX_FILE_ROWS_PER_SOURCE + 1,)):
            if len(rows) >= MAX_FILE_ROWS_PER_SOURCE:
                instance.unparsed.append(f"{path.name}/items: 파일 행 상한 {MAX_FILE_ROWS_PER_SOURCE:,}건에서 중단")
                break
            values = {name: row[index + 1] for index, name in enumerate(selected)}
            stable = values.get(col["stable"])
            title = str(values.get(col["title"]) or "")
            segments, _top, cut = chain_from_parent(parents.get(stable), parents, names, chains)
            trashed = as_flag(values.get(col["trashed"])) if col["trashed"] else None
            shared_date = epoch_to_iso(values.get(col["shared_date"])) if col["shared_date"] else None
            shared_flag = as_flag(values.get(col["shared"])) if col["shared"] else None
            owner = as_flag(values.get(col["owner"])) if col["owner"] else None
            shared = True if shared_flag or shared_date or owner is False else (False if shared_flag is False else None)
            modified = epoch_to_iso(values.get(col["modified"])) if col["modified"] else None
            record = self.record(
                instance,
                path,
                artifact_type="cloud-sync-file",
                recovery_method="sqlite-row",
                source_format="google-drivefs-metadata",
                locator=f"table={table} rowid={row[0]}",
                item_path="/".join([*segments, title]) if title else None,
                path_basis="cloud-relative",
                path_truncated=cut or None,
                file_name=title or None,
                item_id=scalar(values.get(col["id"])) if col["id"] else scalar(stable),
                stable_id=scalar(stable),
                size=as_int(values.get(col["size"])) if col["size"] else None,
                timestamp=modified,
                timestamp_kind="cloud-modified" if modified else None,
                modified_at=modified,
                viewed_at=epoch_to_iso(values.get(col["viewed"])) if col["viewed"] else None,
                shared_with_me_at=shared_date,
                shared=shared,
                is_owner=owner,
                mime_type=values.get(col["mime"]) if col["mime"] else None,
                **google_doc_fields(
                    values.get(col["mime"]) if col["mime"] else None,
                    scalar(values.get(col["id"])) if col["id"] else None,
                ),
                sync_state="trashed" if trashed else "metadata",
                sync_state_semantics="drivefs-items-trashed-flag",
                deleted=trashed,
                source_table=table,
                source_rowid=row[0],
                risk_flags=[flag for flag in ("cloud-sync-shared-item" if shared else "", "cloud-sync-deleted" if trashed else "") if flag] or None,
            )
            if record is None:
                break
            instance.bump("files")
            rows.append(record)
        return rows

    def drivefs_mirror(self, instance: ClientInstance, path: Path, connection: sqlite3.Connection, tables: Mapping[str, Sequence[str]]) -> list[ArtifactRecord]:
        table = find_table(tables, "mirror_item", exact=("mirror_item",))
        if table is None:
            return []
        columns = tables[table]
        col = {
            "name": find_column(columns, "local_filename", "filename", "local_title", "name", "title"),
            "id": find_column(columns, "cloud_id", "cloud_stable_id", "local_stable_id", "id"),
            "size": find_column(columns, "size", "file_size", "local_size"),
            "modified": find_column(columns, "local_mtime", "mtime", "modified_time", "cloud_mtime"),
            "folder": find_column(columns, "is_folder", "is_directory"),
        }
        if not col["name"]:
            instance.unparsed.append(f"{path.name}/{table}: 파일 이름 열 없음")
            return []
        selected = list(dict.fromkeys(name for name in col.values() if name))
        sql = f"SELECT rowid AS __rowid, {', '.join(quote_identifier(name) for name in selected)} FROM {quote_identifier(table)} LIMIT ?"
        rows: list[ArtifactRecord] = []
        for row in connection.execute(sql, (MAX_FILE_ROWS_PER_SOURCE + 1,)):
            if len(rows) >= MAX_FILE_ROWS_PER_SOURCE:
                instance.unparsed.append(f"{path.name}/{table}: 파일 행 상한 {MAX_FILE_ROWS_PER_SOURCE:,}건에서 중단")
                break
            values = {name: row[index + 1] for index, name in enumerate(selected)}
            if col["folder"] and as_flag(values.get(col["folder"])):
                continue
            name = str(values.get(col["name"]) or "")
            modified = epoch_to_iso(values.get(col["modified"])) if col["modified"] else None
            record = self.record(
                instance,
                path,
                artifact_type="cloud-sync-file",
                recovery_method="sqlite-row",
                source_format="google-drivefs-mirror",
                locator=f"table={table} rowid={row[0]}",
                item_path=name or None,
                path_basis="file-name-only",
                file_name=name or None,
                item_id=scalar(values.get(col["id"])) if col["id"] else None,
                size=as_int(values.get(col["size"])) if col["size"] else None,
                timestamp=modified,
                timestamp_kind="cloud-modified" if modified else None,
                modified_at=modified,
                sync_state="mirror",
                sync_state_semantics="drivefs-mirror-local-copy",
                source_table=table,
                source_rowid=row[0],
            )
            if record is None:
                break
            instance.bump("files")
            rows.append(record)
        return rows

    def backup_sync_snapshot(self, instance: ClientInstance, path: Path, connection: sqlite3.Connection, tables: Mapping[str, Sequence[str]]) -> list[ArtifactRecord]:
        table = find_table(tables, exact=("cloud_entry",))
        if table is None:
            return []
        columns = tables[table]
        col = {
            "id": find_column(columns, "doc_id"),
            "name": find_column(columns, "filename", "title"),
            "modified": find_column(columns, "modified"),
            "size": find_column(columns, "size"),
            "removed": find_column(columns, "removed"),
            "shared": find_column(columns, "shared"),
            "type": find_column(columns, "doc_type"),
            "checksum": find_column(columns, "checksum"),
        }
        if not col["name"]:
            return []
        parents: dict[object, object] = {}
        names: dict[object, str] = {}
        relation = find_table(tables, exact=("cloud_relations",))
        if relation is not None and col["id"]:
            rel_cols = tables[relation]
            child = find_column(rel_cols, "child_doc_id")
            parent = find_column(rel_cols, "parent_doc_id")
            if child and parent:
                for item, owner in connection.execute(
                    f"SELECT {quote_identifier(child)}, {quote_identifier(parent)} FROM {quote_identifier(relation)} LIMIT ?",
                    (MAX_TREE_NODES,),
                ):
                    parents.setdefault(item, owner)
            for doc, name in connection.execute(
                f"SELECT {quote_identifier(col['id'])}, {quote_identifier(col['name'])} FROM {quote_identifier(table)} LIMIT ?",
                (MAX_TREE_NODES,),
            ):
                names[doc] = str(name or "")
        selected = list(dict.fromkeys(name for name in col.values() if name))
        sql = f"SELECT rowid AS __rowid, {', '.join(quote_identifier(name) for name in selected)} FROM {quote_identifier(table)} LIMIT ?"
        rows: list[ArtifactRecord] = []
        chains: ChainCache = {}
        for row in connection.execute(sql, (MAX_FILE_ROWS_PER_SOURCE + 1,)):
            if len(rows) >= MAX_FILE_ROWS_PER_SOURCE:
                instance.unparsed.append(f"{path.name}/{table}: 파일 행 상한 {MAX_FILE_ROWS_PER_SOURCE:,}건에서 중단")
                break
            values = {name: row[index + 1] for index, name in enumerate(selected)}
            if col["type"] and as_int(values.get(col["type"])) == 0:
                continue  # doc_type 0 = folder in Backup and Sync snapshots
            name = str(values.get(col["name"]) or "")
            segments, _top, cut = chain_from_parent(parents.get(values.get(col["id"])) if col["id"] else None, parents, names, chains)
            removed = as_flag(values.get(col["removed"])) if col["removed"] else None
            shared = as_flag(values.get(col["shared"])) if col["shared"] else None
            modified = epoch_to_iso(values.get(col["modified"])) if col["modified"] else None
            record = self.record(
                instance,
                path,
                artifact_type="cloud-sync-file",
                recovery_method="sqlite-row",
                source_format="google-backup-and-sync-snapshot",
                locator=f"table={table} rowid={row[0]}",
                item_path="/".join([*segments, name]) if name else None,
                path_basis="cloud-relative",
                path_truncated=cut or None,
                file_name=name or None,
                item_id=scalar(values.get(col["id"])) if col["id"] else None,
                size=as_int(values.get(col["size"])) if col["size"] else None,
                timestamp=modified,
                timestamp_kind="cloud-modified" if modified else None,
                modified_at=modified,
                shared=shared,
                deleted=removed,
                content_hash=scalar(values.get(col["checksum"])) if col["checksum"] else None,
                sync_state="removed" if removed else "cloud-entry",
                sync_state_semantics="backup-and-sync-removed-flag",
                source_table=table,
                source_rowid=row[0],
            )
            if record is None:
                break
            instance.bump("files")
            rows.append(record)
        return rows

    # -- inventory-only clients --
    def inventory_only(self, instance: ClientInstance) -> Iterator[ArtifactRecord]:
        for path, role in instance.files:
            if role != "sqlite" or not is_sqlite(path):
                continue
            if file_size(path) > MAX_SQLITE_BYTES:
                instance.error(path, f"SQLite 크기 상한 초과({file_size(path)} bytes)")
                continue
            try:
                with open_sqlite_snapshot(path) as connection:
                    tables = sqlite_tables(connection)
                    instance.sqlite_inventory.append({"source": str(path), "tables": table_inventory(connection, tables)})
            except Exception as exc:  # isolation: one source never drops the others
                instance.error(path, exc)
        instance.unparsed.append(
            f"{CLIENT_LABELS[instance.client]}: 공개된 DB 스키마가 없어 경로 서명·SQLite 표 인벤토리만(행 해석 없음)"
        )
        return iter(())

    def icloud(self, instance: ClientInstance) -> Iterator[ArtifactRecord]:
        sync_root_files = [path for path, role in instance.files if role == "sync-root"]
        yield from self.inventory_only(instance)
        if sync_root_files:
            sample = sync_root_files[0]
            parts = _parts(sample)
            index = next(i for i, part in enumerate(parts) if part in ("iclouddrive", "icloud drive"))
            folder = Path(*sample.parts[: index + 1])
            root, basis = icloud_sync_root(folder, self.root)
            row = self.account_row(
                instance,
                sample,
                locator="iCloudDrive 폴더 경로 서명",
                recovery_method="path-signature",
                source_format="icloud-drive-folder",
                account=None,
                account_type="icloud-drive",
                sync_roots=[root],
                synced_file_count=instance.role_counts.get("sync-root", 0),
                synced_file_count_basis="files-under-iclouddrive-in-evidence",
                path_basis=basis,
            )
            if row is not None:
                yield row

    # -- summary rows --
    def inventory_row(self, instance: ClientInstance) -> ArtifactRecord:
        parsed = {name: instance.counts.get(name, 0) for name in ("accounts", "files", "events")}
        if instance.source_errors:
            status = "partial-errors"
        elif any(parsed.values()):
            status = "parsed"
        else:
            status = "inventory-only"
        reasons = list(dict.fromkeys([*instance.unparsed, *instance.notes]))
        if instance.files_truncated:
            reasons.append(f"클라이언트 파일 목록 상한 {MAX_CLIENT_FILES:,}개 초과: 이후 파일은 개수만 셈")
        if status == "inventory-only" and not reasons:
            reasons.append("해석 가능한 계정·파일·이벤트 원본이 없음(경로 서명 인벤토리만)")
        roles: dict[str, int] = {}
        for _path, role in instance.files:
            roles[role] = roles.get(role, 0) + 1
        instance_root = Path(instance.root)
        details: dict[str, object] = {
            "parser": PARSER,
            "parser_version": PARSER_VERSION,
            "client": instance.client,
            "client_label": CLIENT_LABELS[instance.client],
            "recovery_method": "path-signature",
            "source_path": instance.root,
            "source_offset": None,
            "source_locator": "client folder",
            "source_format": "cloud-sync-client-folder",
            "user_profile": instance.user_profile or None,
            "account_folder": instance.account_folder or None,
            "actor": instance.primary_account or None,
            "account": instance.primary_account or None,
            "sync_root": instance.sync_roots[0] if instance.sync_roots else None,
            "sync_roots": instance.sync_roots or None,
            "inventory_status": status,
            "sync_state": status,
            "inventory_reason": "; ".join(reasons) if reasons else None,
            "inventory_reasons": reasons or None,
            "file_count": instance.file_count,
            "total_bytes": instance.total_bytes,
            "size": instance.total_bytes,
            "file_roles": roles,
            "sample_files": [str(path) for path, _role in instance.files[:MAX_INVENTORY_SAMPLES]],
            "files_truncated": instance.files_truncated or None,
            "sqlite_databases": instance.sqlite_inventory[:MAX_SQLITE_TABLES_LISTED] or None,
            "encrypted_stores": instance.encrypted[:MAX_INVENTORY_SAMPLES] or None,
            "encrypted_store_count": len(instance.encrypted) or None,
            "source_errors": instance.source_errors or None,
            "parsed_counts": parsed,
            "extra_counts": {name: value for name, value in instance.counts.items() if name not in parsed} or None,
            "coverage_status": "cloud-sync-inventory",
            "reportability": "inventory-triage",
            "parser_confidence": "medium" if status == "parsed" else "low",
            "validation_required": True,
            "risk_flags": [f"cloud-sync-client:{instance.client}"] + (["cloud-sync-source-errors"] if instance.source_errors else []),
        }
        details = {key: value for key, value in details.items() if value is not None or key == "source_offset"}
        return ArtifactRecord(provider=PARSER, artifact_type="cloud-sync-inventory", path=str(instance_root), supported=True, details=details)

    def trace_row(self, client: str, paths: list[str]) -> ArtifactRecord:
        reason = f"{CLIENT_LABELS[client]} 실행 흔적(Prefetch)만 있음 — 클라이언트 설정·DB·로그가 입력에 없음"
        return ArtifactRecord(
            provider=PARSER,
            artifact_type="cloud-sync-inventory",
            path=paths[0],
            supported=True,
            details={
                "parser": PARSER,
                "parser_version": PARSER_VERSION,
                "client": client,
                "client_label": CLIENT_LABELS[client],
                "recovery_method": "path-signature",
                "source_path": paths[0],
                "source_offset": None,
                "source_locator": "Windows\\Prefetch file name",
                "source_format": "prefetch-file-name",
                "inventory_status": "executable-trace-only",
                "sync_state": "executable-trace-only",
                "inventory_reason": reason,
                "inventory_reasons": [reason],
                "file_count": len(paths),
                "sample_files": paths[:MAX_INVENTORY_SAMPLES],
                "parsed_counts": {"accounts": 0, "files": 0, "events": 0},
                "coverage_status": "cloud-sync-inventory",
                "reportability": "inventory-triage",
                "parser_confidence": "low",
                "validation_required": True,
                "risk_flags": [f"cloud-sync-client:{client}", "cloud-sync-executable-trace-only"],
            },
        )


# --- format helpers ---------------------------------------------------------------------


def bounded_gunzip(data: bytes, limit: int | None = None) -> tuple[bytes, bool]:
    """Inflate every member of a (multi-member) gzip stream to at most ``limit`` bytes in total; ``(data, truncated)``.

    ``truncated`` is set when the cap stopped inflation while compressed input remained. Bytes after
    the last member that do not start another gzip member (padding) are ignored.
    """
    cap = MAX_LOG_INFLATED_BYTES if limit is None else limit
    chunks: list[bytes] = []
    produced = 0
    pending = data
    while pending[:2] == GZIP_MAGIC:
        if produced >= cap:
            return b"".join(chunks), True  # another member waits beyond the cap
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out = inflater.decompress(pending, cap - produced)
        except zlib.error as exc:
            raise CloudSyncParseError(f"gzip 해제 실패: {exc}") from exc
        chunks.append(out)
        produced += len(out)
        if not inflater.eof:
            # Stopped by the cap with input left, or a member cut short (keep what inflated).
            return b"".join(chunks), bool(inflater.unconsumed_tail)
        pending = inflater.unused_data
    return b"".join(chunks), False


def load_odl_body(data: bytes, limit: int | None = None) -> tuple[int | None, bytes, int, bool, bool]:
    """``(format version, record body, body offset in the (inflated) stream, inflated?, cap hit?)`` of an ODL file.

    ``limit`` (default ``MAX_LOG_INFLATED_BYTES``) bounds the returned body whether it was inflated or stored plain.
    """
    cap = MAX_LOG_INFLATED_BYTES if limit is None else limit
    inflated = truncated = False
    if data[:2] == GZIP_MAGIC:
        data, truncated = bounded_gunzip(data, cap + ODL_HEADER_SIZE)
        inflated = True
    if data[:8] == ODL_FILE_MAGIC:
        version = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else None
        body = data[ODL_HEADER_SIZE:]
        if body[:2] == GZIP_MAGIC:
            body, body_truncated = bounded_gunzip(body, cap)
            return version, body, 0, True, truncated or body_truncated
        if len(body) > cap:
            body, truncated = body[:cap], True
        return version, body, ODL_HEADER_SIZE, inflated, truncated
    if ODL_RECORD_SIGNATURE in data[:4096]:
        if len(data) > cap:
            data, truncated = data[:cap], True
        return None, data, 0, inflated, truncated
    raise CloudSyncParseError("ODL 헤더(EBFGONED)·레코드 서명 없음")


def odl_record_spans(body: bytes) -> Iterator[tuple[int, int]]:
    """``(start, end)`` of each signature-delimited record, found lazily (no offset list of the whole body)."""
    start = body.find(ODL_RECORD_SIGNATURE)
    while start >= 0:
        following = body.find(ODL_RECORD_SIGNATURE, start + 1)
        yield start, following if following >= 0 else len(body)
        start = following


def parsed_time(record: bytes) -> str | None:
    """First plausible Unix-millisecond u64 in the record header (v2 at +8, v3 at +16/+12)."""
    for offset in (8, 16, 12, 24):
        if len(record) < offset + 8:
            continue
        value = struct.unpack_from("<Q", record, offset)[0]
        if ODL_MIN_MS <= value <= ODL_MAX_MS:
            return dt.datetime.fromtimestamp(value / 1000, dt.timezone.utc).isoformat()
    return None


def prefixed_strings(record: bytes) -> list[str]:
    """Length-prefixed (u32 LE) printable ASCII strings of a record, in order."""
    found: list[str] = []
    for match in ASCII_RUN_RE.finditer(record, 8):
        start = match.start()
        run = match.group(0)
        for back in range(min(4, len(run))):
            # The prefix may sit before the run, or the run may begin with prefix bytes that are printable.
            head = start + back
            if head < 4:
                continue
            length = struct.unpack_from("<I", record, head - 4)[0]
            if 3 <= length <= len(run) - back:
                found.append(run[back : back + length].decode("ascii"))
                break
        if len(found) >= MAX_LOG_STRINGS_PER_RECORD:
            break
    return found


def utf16_strings(record: bytes) -> list[str]:
    values: list[str] = []
    for match in UTF16_RUN_RE.finditer(record):
        values.append(match.group(0).decode("utf-16-le", errors="replace"))
        if len(values) >= MAX_LOG_STRINGS_PER_RECORD:
            break
    return values


def deobfuscate(value: str, mapping: Mapping[str, str]) -> str:
    if not mapping:
        return value
    if value in mapping:
        return mapping[value]
    pieces = re.split(r"([\\/.\s])", value)
    return "".join(mapping.get(piece, piece) for piece in pieces)


def operation_tokens(text: str) -> list[str]:
    """Lower-cased word tokens of a function name / log string (CamelCase and punctuation split)."""
    flattened = OPERATION_COMPOUNDS.sub(lambda match: " " + match.group(0).lower() + " ", text)
    return [token.lower() for token in OPERATION_TOKEN_RE.findall(flattened)]


def classify_operation(text: str) -> str | None:
    tokens = operation_tokens(text)
    cache_context = any(token in CACHE_TOKENS for token in tokens)
    for operation, pattern in OPERATION_PATTERNS:
        if operation == "delete" and cache_context:
            continue  # RemoveFromCache / dehydration frees local space; the cloud item stays
        if any(pattern.fullmatch(token) for token in tokens):
            return operation
    return None


def parse_odl_record(record: bytes, mapping: Mapping[str, str]) -> tuple[str, str, str, str, list[str], str | None] | None:
    """``(operation, basis, function, code file, strings, item path)`` of a log record that names an operation."""
    strings = prefixed_strings(record)
    code_file = ""
    function = ""
    for index, value in enumerate(strings):
        if value.lower().endswith(SOURCE_CODE_SUFFIXES):
            code_file = value
            function = strings[index + 1] if index + 1 < len(strings) else ""
            params = strings[index + 2 :]
            break
    else:
        params = strings
    operation = classify_operation(f"{code_file} {function}") if (code_file or function) else None
    basis = "log-function-name"
    if operation is None:
        if code_file or function:
            return None  # a structured record whose function names no operation (keyword only in a parameter)
        operation = classify_operation(" ".join(params[:8]))
        basis = "log-string-keyword"
    if operation is None:
        return None
    candidates = [deobfuscate(value, mapping) for value in params] + utf16_strings(record)
    item: str | None = None
    for value in candidates:
        path_match = WINDOWS_PATH_RE.search(value)
        if path_match and not path_match.group(0).lower().endswith(SOURCE_CODE_SUFFIXES):
            item = path_match.group(0).strip()
            break
    if item is None:
        item = next((value for value in candidates if FILE_NAME_RE.match(value.strip()) and not value.lower().endswith(SOURCE_CODE_SUFFIXES)), None)
    shown = [deobfuscate(value, mapping) for value in strings][:MAX_LOG_STRINGS_PER_RECORD]
    return operation, basis, function, code_file, shown, item


def dropbox_host_root(data: bytes) -> str | None:
    lines = [line.strip() for line in decode_text(data).splitlines() if line.strip()]
    for line in lines[1:3]:
        try:
            decoded = base64.b64decode(line, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if re.match(r"^(?:[A-Za-z]:\\|\\\\|/)", decoded):
            return decoded
    return None


def dropbox_operation(event: str, direction: str) -> str | None:
    text = f"{event} {direction}".lower()
    if "delete" in text or "remove" in text:
        return "delete"
    if "rename" in text or "move" in text:
        return "rename"
    if "share" in text:
        return "share"
    if "upload" in text:
        return "upload"
    if "download" in text:
        return "download"
    if event.lower() in ("add", "edit", "create", "modify") and direction:
        return "upload" if "up" in direction.lower() or direction.lower() in ("local", "out") else "download"
    return None


def google_account_hints(connection: sqlite3.Connection, tables: Mapping[str, Sequence[str]]) -> tuple[list[str], list[str]]:
    """E-mail addresses and sync-root paths from DriveFS / Backup and Sync key-value and root tables (bounded)."""
    emails: list[str] = []
    roots: list[str] = []
    for table, columns in tables.items():
        lowered = table.lower()
        # Backup and Sync ``data``: ``entry_key`` names the setting, ``data_key`` is the literal "value".
        key_col = find_column(columns, "entry_key", "data_key", "property", "key", "name")
        value_col = find_column(columns, "data_value", "value")
        if lowered in ("data", "properties", "property", "preferences", "settings") and key_col and value_col:
            for key, value in connection.execute(
                f"SELECT {quote_identifier(key_col)}, {quote_identifier(value_col)} FROM {quote_identifier(table)} LIMIT 2000"
            ):
                text = str(scalar(value) or "")
                key_text = str(key or "").lower()
                if "email" in key_text or "account" in key_text:
                    emails.extend(email for email in EMAIL_RE.findall(text) if email not in emails)
                if ("root" in key_text or "path" in key_text) and re.match(r"^(?:[A-Za-z]:\\|\\\\\?\\|/)", text):
                    cleaned = text.removeprefix("\\\\?\\")
                    if cleaned not in roots and not BARE_DRIVE_RE.match(cleaned):
                        roots.append(cleaned)
        if lowered == "roots":
            path_cols = [column for column in columns if "path" in column.lower()]
            account_cols = [column for column in columns if "account" in column.lower() or "email" in column.lower()]
            selected = path_cols + account_cols
            if selected:
                for row in connection.execute(
                    f"SELECT {', '.join(quote_identifier(name) for name in selected)} FROM {quote_identifier(table)} LIMIT 200"
                ):
                    for name, value in zip(selected, row):
                        text = str(scalar(value) or "")
                        if name in account_cols:
                            emails.extend(email for email in EMAIL_RE.findall(text) if email not in emails)
                        elif re.match(r"^(?:[A-Za-z]:\\|\\\\\?\\|/)", text):
                            cleaned = text.removeprefix("\\\\?\\")
                            if cleaned not in roots and not BARE_DRIVE_RE.match(cleaned):
                                roots.append(cleaned)
    return emails[:10], roots[:10]
