"""Desktop mail clients (plan r5-residual L1; re-audit §3 item 11): ``email-clients`` provider.

Per user profile (``iter_windows_user_homes``):

* **Thunderbird** — ``AppData\\Roaming\\Thunderbird\\Profiles\\<profile>``:
  ``Mail`` / ``ImapMail`` folders are extensionless mbox files paired with a
  ``<name>.msf`` summary (a file without the pair counts only when it starts
  with ``From ``); ``.sbd`` directories nest sub-folders. ``X-Mozilla-Status``
  gives the read and expunged (deleted, not yet compacted) flags.
  ``global-messages-db.sqlite`` (Gloda search index) adds messages that are in
  the index but not in any parsed mbox (``deleted_state: index-only``) and the
  people seen in mail; ``abook.sqlite`` / ``history.sqlite`` give contacts,
  ``calendar-data\\local.sqlite`` calendar events, and ``prefs.js`` the
  accounts, identities, servers and SMTP servers.
  ``logins.json`` / ``key4.db`` / ``key3.db`` / ``signons.sqlite`` are listed
  by name, size and time only — never opened (R5 policy: no credential reading).
* **Windows Mail** (Mail and Calendar app, support ended 2024-12) —
  ``AppData\\Local\\Packages\\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\\LocalState\\Indexed\\LiveComm\\<account>\\<ver>\\Mail\\*.eml``
  and ``Att``; ``store.vol`` (ESE) is read only through ``ese_native`` as a
  bounded table inventory plus e-mail address candidates.
* **Windows Live Mail** — ``AppData\\Local\\Microsoft\\Windows Live Mail\\<account>\\<folder>\\*.eml``,
  ``*.oeaccount`` account XML (server / address / user name tags only; any
  tag containing ``Password`` is skipped) and ``Mail.MSMessageStore`` (ESE,
  same bounded inventory).

Messages reuse the normalised ``email-message`` / ``email-attachment`` /
``contact`` / ``calendar-event`` rows of :mod:`.email_pst`, attributed with
``mail_client``, ``account`` and ``folder``. ``email-client-account`` (one per
account/identity), ``email-client-profile`` (one per client root: version,
folders, counts, credential-store presence, caps), ``email-client-store`` (ESE
stores) and ``email-client-parse-error`` (one unreadable source; the collect
continues) are the client-specific rows.

The generic ``email`` provider skips ``.eml`` files under the Windows Mail and
Live Mail roots and extensionless mbox files under Thunderbird profiles
(:func:`client_mail_path_filter`), so each message appears once.
"""

from __future__ import annotations

import datetime as dt
import email
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from email import policy
from pathlib import Path

from ..core.models import ArtifactRecord
from .email_pst import (
    base_details,
    calendar_record,
    contact_record,
    mbox_message,
    message_records,
)
from .windows.common import iter_windows_user_homes, open_sqlite_snapshot

PARSER = "email-clients"
PARSER_VERSION = "email-clients-v1"
SQLITE_HEADER = b"SQLite format 3\x00"
ESE_SIGNATURE = bytes.fromhex("efcdab89")

MAX_WALK_FILES = 100_000
MAX_MBOX_READ_BYTES = 512 * 1024 * 1024
MAX_PROFILE_MBOX_BYTES = 2 * 1024 * 1024 * 1024
MAX_MESSAGE_BYTES = 32 * 1024 * 1024
MAX_MESSAGES_PER_ROOT = 50_000
MAX_EML_BYTES = 64 * 1024 * 1024
MAX_SQLITE_BYTES = 1024 * 1024 * 1024
MAX_SQLITE_ROWS = 50_000
MAX_PREFS_BYTES = 8 * 1024 * 1024
MAX_ESE_BYTES = 256 * 1024 * 1024
MAX_ESE_ROWS_COUNTED = 200_000
MAX_ESE_SCAN_BYTES = 16 * 1024 * 1024
MAX_ADDRESS_CANDIDATES = 200

THUNDERBIRD = "Thunderbird"
WINDOWS_MAIL = "Windows Mail"
WINDOWS_LIVE_MAIL = "Windows Live Mail"
CLIENT_LABELS_KO = {THUNDERBIRD: "Thunderbird", WINDOWS_MAIL: "Windows 메일(메일 및 일정)", WINDOWS_LIVE_MAIL: "Windows Live Mail"}
CLIENT_IDS = {THUNDERBIRD: "thunderbird", WINDOWS_MAIL: "windows-mail", WINDOWS_LIVE_MAIL: "windows-live-mail"}

THUNDERBIRD_PROFILES = ("appdata", "roaming", "thunderbird", "profiles")
LIVECOMM = ("appdata", "local", "packages", "microsoft.windowscommunicationsapps_8wekyb3d8bbwe", "localstate", "indexed", "livecomm")
LIVECOMM_PARTS = ("AppData", "Local", "Packages", "microsoft.windowscommunicationsapps_8wekyb3d8bbwe", "LocalState", "Indexed", "LiveComm")
LIVE_MAIL = ("appdata", "local", "microsoft", "windows live mail")
CREDENTIAL_STORE_FILES = ("logins.json", "key4.db", "key3.db", "signons.sqlite", "logins-backup.json")
# ``News`` holds newsgroup folders (same mbox + .msf layout); the email provider skips the whole profile.
MAIL_STORE_DIRS = ("Mail", "ImapMail", "News")
NON_MBOX_SUFFIXES = frozenset({".msf", ".dat", ".json", ".js", ".html", ".htm", ".sqlite", ".db", ".txt", ".ini", ".xml", ".log", ".bak", ".eml"})
MOZ_READ = 0x0001
MOZ_REPLIED = 0x0002
MOZ_MARKED = 0x0004
MOZ_EXPUNGED = 0x0008
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
PREF_RE = re.compile(r'^\s*user_pref\(\s*"((?:[^"\\]|\\.)+)"\s*,\s*(.+?)\s*\)\s*;\s*$')
PREF_PREFIXES = ("mail.identity.", "mail.server.", "mail.account.", "mail.smtpserver.", "mail.accountmanager.")
_SECRET_MARKERS = ("password", "passwd", "token", "secret", "oauth", "credential", "cookie")
OEACCOUNT_TAG_RE = re.compile(r"<([A-Za-z0-9_]+)(?:\s[^>]*)?>([^<]{0,512})</\1>")
OEACCOUNT_TAG_ALLOW = re.compile(r"(email_address|server|user_name|account_name|display_name|port|secure_connection)", re.IGNORECASE)
PRTIME_DIVISOR = 1_000_000


# --- path ownership (shared with the generic email provider) ----------------------------------


def client_mail_path_filter(root: Path) -> Callable[[Path], str]:
    """``path → client`` for the ``email`` provider: which client root (if any) owns a file under ``root``.

    Mirrors :func:`iter_windows_user_homes`: ``root\\Users\\<user>\\…`` or a profile root
    holding ``AppData``. Returns ``""`` for files no client provider reads.
    """
    try:
        users = (root / "Users").is_dir()
        profile = not users and (root / "AppData").is_dir()
    except OSError:
        users = profile = False
    if not users and not profile:
        return lambda _path: ""
    root_parts = len(root.parts)

    def owner(path: Path) -> str:
        parts = [part.lower() for part in path.parts[root_parts:]]
        if users:
            if len(parts) < 3 or parts[0] != "users":
                return ""
            parts = parts[2:]
        if tuple(parts[: len(LIVECOMM)]) == LIVECOMM:
            return WINDOWS_MAIL
        if tuple(parts[: len(LIVE_MAIL)]) == LIVE_MAIL:
            return WINDOWS_LIVE_MAIL
        if tuple(parts[: len(THUNDERBIRD_PROFILES)]) == THUNDERBIRD_PROFILES:
            return THUNDERBIRD
        return ""

    return owner


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def windows_mail_eml_paths(livecomm: Path) -> list[Path]:
    """``.eml`` files of a Windows Mail ``LiveComm`` root in the order :meth:`EmailClientsProvider._windows_mail` reads them."""
    return [path for account_dir in _child_dirs(livecomm) for path in _walk(account_dir) if path.suffix.lower() == ".eml"]


def live_mail_eml_paths(live_mail: Path) -> list[Path]:
    """``.eml`` files of a Windows Live Mail root in the order :meth:`EmailClientsProvider._live_mail` reads them."""
    paths = sorted(live_mail.glob("*.eml"), key=lambda item: item.name.lower())
    paths.extend(path for account_dir in _child_dirs(live_mail) for path in _walk(account_dir) if path.suffix.lower() == ".eml")
    return paths


def client_consumed_eml_paths(root: Path) -> set[str]:
    """Normalised paths of the ``.eml`` files the email-clients provider parses (Windows Mail / Live Mail).

    Only the first :data:`MAX_MESSAGES_PER_ROOT` messages of a client root (and the files its bounded
    walk reaches) are read there, so the generic ``email`` provider skips exactly these and still parses
    the rest — no message is lost when a root hits its cap."""
    consumed: set[str] = set()
    for user_home in iter_windows_user_homes(root):
        roots = (
            (user_home.joinpath(*LIVECOMM_PARTS), windows_mail_eml_paths),
            (user_home / "AppData" / "Local" / "Microsoft" / "Windows Live Mail", live_mail_eml_paths),
        )
        for client_root, enumerate_paths in roots:
            try:
                if not client_root.is_dir():
                    continue
                consumed.update(_path_key(path) for path in enumerate_paths(client_root)[:MAX_MESSAGES_PER_ROOT])
            except OSError:
                continue
    return consumed


def is_extensionless_mbox(path: Path) -> bool:
    """A Thunderbird-style mbox: no ``.msf``/known suffix, and a ``<name>.msf`` pair or a ``From `` first line."""
    if path.suffix.lower() in NON_MBOX_SUFFIXES or path.name.lower().endswith(".msf"):
        return False
    try:
        if path.with_name(path.name + ".msf").is_file():
            return True
        with path.open("rb") as handle:
            return handle.read(5) == b"From "
    except OSError:
        return False


# --- small parsers ------------------------------------------------------------------------------


def parse_prefs_js(text: str) -> dict[str, object]:
    """Account-related ``user_pref`` values of ``prefs.js`` (secret-named prefs are dropped)."""
    prefs: dict[str, object] = {}
    for line in text.splitlines():
        match = PREF_RE.match(line)
        if match is None:
            continue
        name = match.group(1)
        if not name.startswith(PREF_PREFIXES) or any(marker in name.lower() for marker in _SECRET_MARKERS):
            continue
        raw = match.group(2)
        value: object
        if raw.startswith('"'):
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw.strip('"')
        elif raw in ("true", "false"):
            value = raw == "true"
        else:
            try:
                value = int(raw)
            except ValueError:
                value = raw
        prefs[name] = value
    return prefs


def thunderbird_accounts(prefs: Mapping[str, object]) -> list[dict[str, object]]:
    """Accounts (server + identities + SMTP) from parsed prefs; servers without an account entry are kept too."""

    def group(prefix: str) -> dict[str, dict[str, object]]:
        grouped: dict[str, dict[str, object]] = {}
        for name, value in prefs.items():
            if name.startswith(prefix):
                key, _, attribute = name[len(prefix):].partition(".")
                if key and attribute:
                    grouped.setdefault(key, {})[attribute] = value
        return grouped

    identities = group("mail.identity.")
    servers = group("mail.server.")
    smtp = group("mail.smtpserver.")
    accounts = group("mail.account.")
    rows: list[dict[str, object]] = []
    used_servers: set[str] = set()
    for account_key, account in sorted(accounts.items()):
        server_key = str(account.get("server") or "")
        used_servers.add(server_key)
        identity_keys = [item.strip() for item in str(account.get("identities") or "").split(",") if item.strip()]
        rows.append(_account_row(account_key, server_key, servers.get(server_key, {}), identity_keys, identities, smtp))
    for server_key, server in sorted(servers.items()):
        if server_key not in used_servers:
            rows.append(_account_row("", server_key, server, [], identities, smtp))
    return rows


def _account_row(account_key: str, server_key: str, server: Mapping[str, object], identity_keys: list[str],
                 identities: Mapping[str, Mapping[str, object]], smtp: Mapping[str, Mapping[str, object]]) -> dict[str, object]:
    found = [identities.get(key, {}) for key in identity_keys]
    emails = [str(item.get("useremail") or "") for item in found if item.get("useremail")]
    names = [str(item.get("fullName") or "") for item in found if item.get("fullName")]
    smtp_keys = [str(item.get("smtpServer") or "") for item in found if item.get("smtpServer")]
    smtp_hosts = [str(smtp.get(key, {}).get("hostname") or "") for key in smtp_keys if smtp.get(key, {}).get("hostname")]
    hostname = str(server.get("hostname") or "")
    username = str(server.get("userName") or "")
    directory = str(server.get("directory-rel") or server.get("directory") or "")
    return {
        "account_key": account_key,
        "server_key": server_key,
        "server_type": str(server.get("type") or ""),
        "server_hostname": hostname,
        "server_port": server.get("port"),
        "server_username": username,
        "server_directory": directory,
        "server_name": str(server.get("name") or ""),
        "identity_keys": identity_keys,
        "identity_emails": emails,
        "identity_names": names,
        "smtp_hosts": smtp_hosts,
        "account": emails[0] if emails else (f"{username}@{hostname}" if username and hostname and "@" not in username else username or hostname),
    }


def iter_mbox_messages(path: Path, *, read_limit: int, message_limit: int = MAX_MESSAGE_BYTES,
                       digest: hashlib._Hash | None = None) -> Iterator[tuple[int, bytes, bool]]:
    """``(offset, message bytes, truncated)`` of an mbox, streaming; ``From `` after a blank line starts a message."""
    offset = 0
    start = -1
    buffer = bytearray()
    truncated = False
    previous_blank = True
    with path.open("rb") as handle:
        for line in handle:
            if offset >= read_limit:
                break
            if digest is not None:
                digest.update(line)
            if line.startswith(b"From ") and previous_blank:
                if start >= 0:
                    yield start, bytes(buffer), truncated
                start, buffer, truncated = offset, bytearray(), False
            elif start >= 0:
                if len(buffer) + len(line) <= message_limit:
                    buffer += line
                else:
                    truncated = True
            previous_blank = line in (b"\n", b"\r\n")
            offset += len(line)
    if start >= 0:
        yield start, bytes(buffer), truncated


def mozilla_status(message: email.message.Message) -> int | None:
    raw = str(message.get("X-Mozilla-Status") or "").strip()
    try:
        return int(raw, 16) if raw else None
    except ValueError:
        return None


def prtime_iso(value: object) -> str:
    """PRTime (µs since 1970, Mozilla) → ISO UTC; seconds/ms tolerated by magnitude."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    if number <= 0:
        return ""
    if number > 1e14:
        number /= PRTIME_DIVISOR
    elif number > 1e11:
        number /= 1000
    if not 946_684_800 <= number <= 4_102_444_800:
        return ""
    return dt.datetime.fromtimestamp(number, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_message_id(value: object) -> str:
    return str(value or "").strip().strip("<>").strip().lower()


def address_candidates(blob: bytes, limit: int = MAX_ADDRESS_CANDIDATES) -> list[str]:
    """ASCII and UTF-16LE e-mail address strings in a bounded byte range."""
    found: dict[str, None] = {}
    for match in EMAIL_RE.finditer(blob):
        found.setdefault(match.group(0).decode("ascii", "ignore").lower(), None)
        if len(found) >= limit:
            return list(found)
    for shift in (0, 1):
        try:
            text = blob[shift: len(blob) - ((len(blob) - shift) % 2)].decode("utf-16-le", errors="ignore")
        except ValueError:  # pragma: no cover - errors=ignore never raises
            continue
        for match in EMAIL_RE.finditer(text.encode("ascii", "ignore")):
            found.setdefault(match.group(0).decode("ascii", "ignore").lower(), None)
            if len(found) >= limit:
                return list(found)
    return list(found)


# --- provider -----------------------------------------------------------------------------------


@dataclass
class _ClientRun:
    client: str
    user: str
    root: Path
    rows: list[ArtifactRecord] = field(default_factory=list)
    errors: list[ArtifactRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    folders: list[dict[str, object]] = field(default_factory=list)
    sources: list[dict[str, object]] = field(default_factory=list)
    capped: list[str] = field(default_factory=list)
    message_ids: set[str] = field(default_factory=set)
    mbox_bytes: int = 0
    messages: int = 0
    extra: dict[str, object] = field(default_factory=dict)

    def cap(self, reason: str) -> None:
        if reason not in self.capped:
            self.capped.append(reason)


class EmailClientsProvider:
    name = "email-clients"
    collector_kind = "email-clients"
    description = "Desktop mail clients: Thunderbird (mbox, Gloda, address book, calendar, prefs), Windows Mail and Windows Live Mail"
    target_platform = "windows"

    def __init__(self) -> None:
        self.collection_notes: list[str] = []

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        self.collection_notes = []
        found = False
        for user_home in iter_windows_user_homes(root):
            profiles_dir = user_home / "AppData" / "Roaming" / "Thunderbird" / "Profiles"
            for profile in _child_dirs(profiles_dir):
                found = True
                yield from self._finish(self._thunderbird(_ClientRun(THUNDERBIRD, user_home.name, profile)))
            livecomm = user_home.joinpath(*LIVECOMM_PARTS)
            if livecomm.is_dir():
                found = True
                yield from self._finish(self._windows_mail(_ClientRun(WINDOWS_MAIL, user_home.name, livecomm)))
            live_mail = user_home / "AppData" / "Local" / "Microsoft" / "Windows Live Mail"
            if live_mail.is_dir():
                found = True
                yield from self._finish(self._live_mail(_ClientRun(WINDOWS_LIVE_MAIL, user_home.name, live_mail)))
        if not found:
            self.collection_notes.append("메일 클라이언트(Thunderbird·Windows 메일·Windows Live Mail) 폴더가 사용자 프로필에서 발견되지 않았습니다.")

    def _finish(self, run: _ClientRun) -> Iterator[ArtifactRecord]:
        yield self._profile_row(run)
        yield from run.rows
        yield from run.errors
        if run.capped:
            self.collection_notes.append(f"{CLIENT_LABELS_KO[run.client]}({run.user}): 상한 도달 — {', '.join(run.capped)}")

    # -- shared ------------------------------------------------------------------------------

    def _attribution(self, run: _ClientRun, *, account: str, store: Path, recovery_method: str) -> dict[str, object]:
        return {
            "parser": PARSER,
            "parser_version": PARSER_VERSION,
            "mail_client": run.client,
            "mail_client_id": CLIENT_IDS[run.client],
            "mail_client_label_ko": CLIENT_LABELS_KO[run.client],
            "account": account,
            "mailbox_store": str(store),
            "client_root": str(run.root),
            "user": run.user,
            "recovery_method": recovery_method,
            "reportability": "triage",
        }

    def _guarded(self, run: _ClientRun, path: Path, source_format: str, action: Callable[[], None]) -> None:
        try:
            action()
        except Exception as exc:  # one unreadable source never stops the client
            run.sources.append({"path": str(path), "format": source_format, "status": "parse-error"})
            run.errors.append(
                ArtifactRecord(
                    provider=self.name,
                    artifact_type="email-client-parse-error",
                    path=str(path),
                    supported=True,
                    details={
                        **self._attribution(run, account="", store=path, recovery_method="none"),
                        "source_path": str(path),
                        "source_format": source_format,
                        "parser_error": True,
                        "coverage_status": "parser-error",
                        "error_type": type(exc).__name__,
                        "error": str(exc)[:500],
                        "reason_ko": f"{CLIENT_LABELS_KO[run.client]} 원본({path.name})을 읽지 못해 건너뜀({type(exc).__name__}); 나머지는 계속 처리",
                        "timestamp": "",
                        "timestamp_source": "none-parse-error",
                    },
                )
            )

    def _add(self, run: _ClientRun, record: ArtifactRecord) -> None:
        run.rows.append(ArtifactRecord(provider=self.name, artifact_type=record.artifact_type, path=record.path,
                                       supported=True, details=record.details))
        run.counts[record.artifact_type] = run.counts.get(record.artifact_type, 0) + 1

    def _message(self, run: _ClientRun, raw: bytes, *, store: Path, source_format: str, folder: str, account: str,
                 recovery_method: str, offset: int | None, index: int, truncated: bool, source_sha256: str) -> list[ArtifactRecord]:
        """Normalised rows of one RFC 5322 message (``email_pst.mbox_message`` + client attribution)."""
        from ..core.triage_rules.email import folder_is_deleted

        parsed = email.message_from_bytes(raw, policy=policy.default)
        status = mozilla_status(parsed)
        deleted = "deleted-folder" if folder_is_deleted(folder) else ""
        if status is not None:
            # Only Mozilla's status flags say whether a message is live; without them the state stays empty.
            deleted = "deleted-or-recovered-candidate" if status & MOZ_EXPUNGED else (deleted or "live")
        message = mbox_message(parsed, folder=folder, deleted=deleted)  # type: ignore[arg-type]
        if status is not None:
            message["read_state"] = "읽음" if status & MOZ_READ else "읽지 않음"
            message["x_mozilla_status"] = f"{status:04x}"
            message["mozilla_flags"] = [name for bit, name in ((MOZ_READ, "read"), (MOZ_REPLIED, "replied"),
                                                               (MOZ_MARKED, "flagged"), (MOZ_EXPUNGED, "expunged")) if status & bit]
        base = base_details(source_path=store, source_sha256=source_sha256, source_format=source_format,
                            recovery_method=recovery_method, parser_version=PARSER_VERSION)
        base.update(self._attribution(run, account=account, store=store, recovery_method=recovery_method))
        base.update({"source_offset": offset, "source_index": index, "message_truncated": truncated})
        records = message_records(message, base=base)
        message_id = normalize_message_id(message.get("message_id"))
        if message_id:
            run.message_ids.add(message_id)
        return records

    # -- Thunderbird ---------------------------------------------------------------------------

    def _thunderbird(self, run: _ClientRun) -> _ClientRun:
        profile = run.root
        version = ""
        compat = profile / "compatibility.ini"
        if compat.is_file():
            match = re.search(r"^LastVersion=([^\r\n_]+)", _read_text(compat, 64 * 1024), re.MULTILINE)
            version = match.group(1) if match else ""
        run.extra["client_version"] = version
        run.extra["credential_store_files"] = _presence(profile, CREDENTIAL_STORE_FILES)
        accounts: list[dict[str, object]] = []
        prefs = profile / "prefs.js"
        if prefs.is_file():
            def read_prefs() -> None:
                accounts.extend(thunderbird_accounts(parse_prefs_js(_read_text(prefs, MAX_PREFS_BYTES))))
                for account in accounts:
                    details = {
                        **self._attribution(run, account=str(account["account"]), store=prefs, recovery_method="prefs-js"),
                        **account,
                        "source_path": str(prefs),
                        "source_format": "prefs-js",
                        "validation_required": True,
                        "timestamp": "",
                        "timestamp_source": "none-account-row",
                    }
                    self._add(run, ArtifactRecord(self.name, "email-client-account", str(prefs), True, details))
                run.sources.append({"path": str(prefs), "format": "prefs-js", "status": "read", "accounts": len(accounts)})
            self._guarded(run, prefs, "prefs-js", read_prefs)
        directories = _server_directories(accounts)
        for store_dir in MAIL_STORE_DIRS:
            base_dir = profile / store_dir
            for server_dir in _child_dirs(base_dir):
                account = directories.get(f"{store_dir}/{server_dir.name}".lower(), server_dir.name)
                for mbox in _mbox_files(server_dir):
                    folder = _folder_name(server_dir, mbox)
                    self._guarded(run, mbox, "thunderbird-mbox",
                                  lambda p=mbox, f=folder, a=account: self._thunderbird_mbox(run, p, f, a))
        gloda = profile / "global-messages-db.sqlite"
        if gloda.is_file():
            self._guarded(run, gloda, "thunderbird-gloda", lambda: self._gloda(run, gloda))
        for name, label in (("abook.sqlite", "개인 주소록(abook)"), ("history.sqlite", "수집된 주소(history)")):
            book = profile / name
            if book.is_file():
                self._guarded(run, book, "thunderbird-addressbook", lambda p=book, lb=label: self._address_book(run, p, lb))
        for name in ("abook.mab", "history.mab"):
            if (profile / name).is_file():
                run.sources.append({"path": str(profile / name), "format": "mork-mab", "status": "not-parsed-legacy-mork"})
        calendar = profile / "calendar-data" / "local.sqlite"
        if calendar.is_file():
            self._guarded(run, calendar, "thunderbird-calendar", lambda: self._calendar(run, calendar))
        return run

    def _thunderbird_mbox(self, run: _ClientRun, path: Path, folder: str, account: str) -> None:
        size = path.stat().st_size
        budget = min(MAX_MBOX_READ_BYTES, max(0, MAX_PROFILE_MBOX_BYTES - run.mbox_bytes))
        if budget <= 0:
            run.cap("profile-mbox-byte-cap")
            run.folders.append({"folder": folder, "path": str(path), "bytes": size, "status": "skipped-byte-cap"})
            return
        digest = hashlib.sha256()
        produced: list[ArtifactRecord] = []
        parsed = 0
        for index, (offset, raw, truncated) in enumerate(iter_mbox_messages(path, read_limit=budget, digest=digest)):
            if run.messages >= MAX_MESSAGES_PER_ROOT:
                run.cap("message-cap")
                break
            run.messages += 1
            parsed += 1
            produced.extend(self._message(run, raw, store=path, source_format="thunderbird-mbox", folder=folder,
                                          account=account, recovery_method="mbox-parse", offset=offset, index=index,
                                          truncated=truncated, source_sha256=""))
        read = min(size, budget)
        run.mbox_bytes += read
        complete = read >= size and run.messages < MAX_MESSAGES_PER_ROOT
        sha256 = digest.hexdigest() if complete else ""
        if not complete:
            run.cap("mbox-read-cap")
        for record in produced:
            record.details["source_sha256"] = sha256
            record.details["source_sha256_status"] = "full-file" if sha256 else "not-computed-partial-read"
            self._add(run, record)
        run.folders.append({"folder": folder, "account": account, "path": str(path), "bytes": size, "messages": parsed,
                            "msf_present": path.with_name(path.name + ".msf").is_file(), "complete": complete})

    def _gloda(self, run: _ClientRun, path: Path) -> None:
        if not _sqlite_ok(path):
            run.sources.append({"path": str(path), "format": "thunderbird-gloda", "status": "not-sqlite-or-too-large"})
            return
        indexed = matched = emitted = 0
        with open_sqlite_snapshot(path) as connection:
            tables = _tables(connection)
            folders: dict[str, str] = {}
            if "folderlocations" in tables:
                for row in _rows(connection, tables["folderlocations"]):
                    folders[str(row.get("id"))] = str(row.get("name") or row.get("folderuri") or "")
            texts: dict[str, dict[str, object]] = {}
            if "messagestext_content" in tables:
                texts = _gloda_texts(connection, tables["messagestext_content"])
            if "messages" in tables:
                for index, row in enumerate(_rows(connection, tables["messages"])):
                    indexed += 1
                    header_id = normalize_message_id(row.get("headermessageid"))
                    if header_id and header_id in run.message_ids:
                        matched += 1
                        continue
                    text = texts.get(str(row.get("id")), {})
                    body = str(text.get("c0body") or "")
                    body_complete = int(text.get("body_length") or 0) <= len(body)
                    folder = folders.get(str(row.get("folderid")), "")
                    date = prtime_iso(row.get("date"))
                    attachment_names = [name for name in str(text.get("c2attachmentnames") or "").split("\n") if name][:50]
                    details = {
                        **base_details(source_path=path, source_sha256="", source_format="thunderbird-gloda",
                                       recovery_method="sqlite-index", parser_version=PARSER_VERSION),
                        **self._attribution(run, account="", store=path, recovery_method="sqlite-index"),
                        "source_table": tables["messages"],
                        "source_row": index,
                        "from": str(text.get("c3author") or ""),
                        "to": str(text.get("c4recipients") or ""),
                        "subject": str(text.get("c1subject") or ""),
                        "date": date,
                        "submit_time": date,
                        "folder": folder,
                        "message_id": str(row.get("headermessageid") or ""),
                        "thread_id": str(row.get("conversationid") or ""),
                        "body_preview": " ".join(body.split())[:500],
                        "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest() if body and body_complete else "",
                        "body_length": int(text.get("body_length") or 0),
                        "attachment_names": attachment_names,
                        "attachment_count": len(attachment_names),
                        "deleted_state": "deleted-or-recovered-candidate" if str(row.get("deleted") or "0") not in ("0", "", "None") else "index-only",
                        "index_only_reason_ko": "Gloda 색인에만 있고 파싱한 mbox에는 없는 메시지(삭제·압축됨·IMAP 본문 미다운로드 가능)",
                        "validation_required": True,
                    }
                    self._add(run, ArtifactRecord(self.name, "email-message", str(path), True, details))
                    emitted += 1
            people = 0
            if "identities" in tables and "contacts" in tables:
                names = {str(row.get("id")): str(row.get("name") or "") for row in _rows(connection, tables["contacts"])}
                for row in _rows(connection, tables["identities"]):
                    if str(row.get("kind") or "") != "email" or not row.get("value"):
                        continue
                    card = {"display_name": names.get(str(row.get("contactid")), ""), "emails": [str(row.get("value"))]}
                    base = base_details(source_path=path, source_sha256="", source_format="thunderbird-gloda",
                                        recovery_method="sqlite-index", parser_version=PARSER_VERSION)
                    base.update(self._attribution(run, account="", store=path, recovery_method="sqlite-index"))
                    self._add(run, contact_record(card, base=base, folder="메일에 등장한 사람(Gloda)"))
                    people += 1
        run.extra.update({"gloda_indexed_messages": indexed, "gloda_matched_mbox": matched, "gloda_index_only_rows": emitted})
        run.sources.append({"path": str(path), "format": "thunderbird-gloda", "status": "read", "indexed": indexed,
                            "matched": matched, "index_only": emitted, "people": people})

    def _address_book(self, run: _ClientRun, path: Path, label: str) -> None:
        if not _sqlite_ok(path):
            run.sources.append({"path": str(path), "format": "thunderbird-addressbook", "status": "not-sqlite-or-too-large"})
            return
        cards: dict[str, dict[str, str]] = {}
        with open_sqlite_snapshot(path) as connection:
            tables = _tables(connection)
            if "properties" in tables:
                for row in _rows(connection, tables["properties"]):
                    card = cards.setdefault(str(row.get("card")), {})
                    name = str(row.get("name") or "")
                    if name and len(card) < 64:
                        card[name] = str(row.get("value") or "")
        base = base_details(source_path=path, source_sha256="", source_format="thunderbird-addressbook",
                            recovery_method="sqlite-table", parser_version=PARSER_VERSION)
        base.update(self._attribution(run, account="", store=path, recovery_method="sqlite-table"))
        for card_id, values in cards.items():
            display = values.get("DisplayName") or " ".join(part for part in (values.get("FirstName"), values.get("LastName")) if part)
            emails = [values[key] for key in ("PrimaryEmail", "SecondEmail") if values.get(key)]
            phones = [values[key] for key in ("CellularNumber", "WorkPhone", "HomePhone", "FaxNumber", "PagerNumber") if values.get(key)]
            if not (display or emails or phones):
                continue
            record = contact_record({"display_name": display, "emails": emails, "phones": phones,
                                     "organization": values.get("Company", ""), "title": values.get("JobTitle", "")},
                                    base=base, folder=label)
            record.details["card_id"] = card_id
            record.details["nickname"] = values.get("NickName", "")
            self._add(run, record)
        run.sources.append({"path": str(path), "format": "thunderbird-addressbook", "status": "read", "cards": len(cards)})

    def _calendar(self, run: _ClientRun, path: Path) -> None:
        if not _sqlite_ok(path):
            run.sources.append({"path": str(path), "format": "thunderbird-calendar", "status": "not-sqlite-or-too-large"})
            return
        events = 0
        with open_sqlite_snapshot(path) as connection:
            tables = _tables(connection)
            properties: dict[str, dict[str, str]] = {}
            if "cal_properties" in tables:
                for row in _rows(connection, tables["cal_properties"]):
                    properties.setdefault(str(row.get("item_id")), {})[str(row.get("key") or "").upper()] = str(row.get("value") or "")
            attendees: dict[str, list[str]] = {}
            if "cal_attendees" in tables:
                for row in _rows(connection, tables["cal_attendees"]):
                    text = str(row.get("icalstring") or row.get("attendee_id") or "")
                    match = re.search(r"mailto:([^\s;:\r\n]+)", text, re.IGNORECASE)
                    attendees.setdefault(str(row.get("item_id")), []).append(match.group(1) if match else text[:200])
            base = base_details(source_path=path, source_sha256="", source_format="thunderbird-calendar",
                                recovery_method="sqlite-table", parser_version=PARSER_VERSION)
            base.update(self._attribution(run, account="", store=path, recovery_method="sqlite-table"))
            if "cal_events" in tables:
                for row in _rows(connection, tables["cal_events"]):
                    item = str(row.get("id") or "")
                    extra = properties.get(item, {})
                    zone = str(row.get("event_start_tz") or "")
                    event = {
                        "summary": str(row.get("title") or ""),
                        "dtstart": prtime_iso(row.get("event_start")),
                        "dtend": prtime_iso(row.get("event_end")),
                        "all_day": zone == "floating" and bool(row.get("event_start")) and int(row.get("event_start") or 0) % 86_400_000_000 == 0,
                        "timezone": zone,
                        "timezone_status": "floating-local" if zone == "floating" else ("zoned" if zone else ""),
                        "location": extra.get("LOCATION", ""),
                        "description": extra.get("DESCRIPTION", ""),
                        "organizer": extra.get("ORGANIZER", ""),
                        "attendees": attendees.get(item, [])[:100],
                        "uid": item,
                        "status": str(row.get("ical_status") or ""),
                        "created": prtime_iso(row.get("time_created")),
                        "last_modified": prtime_iso(row.get("last_modified")),
                    }
                    record = calendar_record(event, base=base, folder=str(row.get("cal_id") or ""))
                    self._add(run, record)
                    events += 1
        run.sources.append({"path": str(path), "format": "thunderbird-calendar", "status": "read", "events": events})

    # -- Windows Mail / Live Mail ------------------------------------------------------------------

    def _windows_mail(self, run: _ClientRun) -> _ClientRun:
        for account_dir in _child_dirs(run.root):
            emls: list[Path] = []
            attachments = 0
            stores: list[Path] = []
            for path in _walk(account_dir):
                lowered_parts = [part.lower() for part in path.relative_to(account_dir).parts]
                if path.suffix.lower() == ".eml":
                    emls.append(path)  # same order as windows_mail_eml_paths (the email provider skips the ones read here)
                elif path.name.lower() == "store.vol":
                    stores.append(path)
                elif "att" in lowered_parts[:-1]:
                    attachments += 1
            account = account_dir.name
            details = {
                **self._attribution(run, account=account, store=account_dir, recovery_method="filesystem-inventory"),
                "account_key": account,
                "source_path": str(account_dir),
                "source_format": "directory",
                "eml_file_count": len(emls),
                "attachment_file_count": attachments,
                "store_files": [str(item) for item in stores],
                "validation_required": True,
                "timestamp": "",
                "timestamp_source": "none-account-row",
            }
            self._add(run, ArtifactRecord(self.name, "email-client-account", str(account_dir), True, details))
            for path in emls:
                # LiveComm\<account>\<store version>\Mail\…: the folder starts at "Mail" (the version is kept apart).
                parents = list(path.relative_to(account_dir).parts[:-1])
                lowered = [part.lower() for part in parents]
                start = lowered.index("mail") if "mail" in lowered else 0
                folder = "/".join(parents[start:])
                self._guarded(run, path, "windows-mail-eml",
                              lambda p=path, f=folder, a=account: self._eml(run, p, f, a, "windows-mail-eml"))
            for store in stores:
                self._guarded(run, store, "ese-store", lambda s=store, a=account: self._ese_store(run, s, a))
        return run

    def _live_mail(self, run: _ClientRun) -> _ClientRun:
        for store in sorted(run.root.glob("*.MSMessageStore"), key=lambda item: item.name.lower()):
            self._guarded(run, store, "ese-store", lambda s=store: self._ese_store(run, s, ""))
        for path in sorted(run.root.glob("*.eml"), key=lambda item: item.name.lower()):
            self._guarded(run, path, "live-mail-eml", lambda p=path: self._eml(run, p, "", "", "live-mail-eml"))
        for account_dir in _child_dirs(run.root):
            for oeaccount in sorted(account_dir.glob("*.oeaccount"), key=lambda item: item.name.lower())[:20]:
                self._guarded(run, oeaccount, "oeaccount-xml", lambda p=oeaccount, a=account_dir.name: self._oeaccount(run, p, a))
            # The account's e-mail address (from its .oeaccount) labels its messages; else the folder name.
            account = str(run.extra.get("oeaccount_emails", {}).get(account_dir.name) or account_dir.name)  # type: ignore[union-attr]
            for path in _walk(account_dir):
                if path.suffix.lower() == ".eml":
                    folder = "/".join(path.relative_to(account_dir).parts[:-1])
                    self._guarded(run, path, "live-mail-eml", lambda p=path, f=folder, a=account: self._eml(run, p, f, a, "live-mail-eml"))
        return run

    def _eml(self, run: _ClientRun, path: Path, folder: str, account: str, source_format: str) -> None:
        if run.messages >= MAX_MESSAGES_PER_ROOT:
            run.cap("message-cap")
            return
        size = path.stat().st_size
        with path.open("rb") as handle:
            raw = handle.read(MAX_EML_BYTES + 1)
        truncated = len(raw) > MAX_EML_BYTES
        raw = raw[:MAX_EML_BYTES]
        sha256 = hashlib.sha256(raw).hexdigest() if not truncated else ""
        run.messages += 1
        for record in self._message(run, raw, store=path, source_format=source_format, folder=folder, account=account,
                                    recovery_method="eml-parse", offset=0, index=0, truncated=truncated, source_sha256=sha256):
            record.details["source_size"] = size
            self._add(run, record)

    def _oeaccount(self, run: _ClientRun, path: Path, account: str) -> None:
        text = _read_text(path, 1024 * 1024)
        fields: dict[str, str] = {}
        for tag, value in OEACCOUNT_TAG_RE.findall(text):
            if "password" in tag.lower() or any(marker in tag.lower() for marker in _SECRET_MARKERS):
                continue
            if OEACCOUNT_TAG_ALLOW.search(tag) and value.strip():
                fields.setdefault(tag, value.strip()[:256])
        email_value = next((value for tag, value in fields.items() if "email_address" in tag.lower()), "")
        if email_value:
            run.extra.setdefault("oeaccount_emails", {})[account] = email_value  # type: ignore[index]
        details = {
            **self._attribution(run, account=email_value or account, store=path, recovery_method="xml-tags"),
            "account_key": account,
            "account_fields": fields,
            "identity_emails": [email_value] if email_value else [],
            "server_hostname": next((value for tag, value in fields.items() if tag.lower().endswith("_server")), ""),
            "server_username": next((value for tag, value in fields.items() if "user_name" in tag.lower()), ""),
            "source_path": str(path),
            "source_format": "oeaccount-xml",
            "secret_tags_skipped": True,
            "validation_required": True,
            "timestamp": "",
            "timestamp_source": "none-account-row",
        }
        self._add(run, ArtifactRecord(self.name, "email-client-account", str(path), True, details))

    def _ese_store(self, run: _ClientRun, path: Path, account: str) -> None:
        from .windows.ese_native import EseDatabase

        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(MAX_ESE_SCAN_BYTES)
        signature_ok = head[4:8] == ESE_SIGNATURE
        tables: list[dict[str, object]] = []
        decode_status = "not-attempted"
        decode_error = ""
        if signature_ok and size <= MAX_ESE_BYTES:
            try:
                with path.open("rb") as handle:
                    database = EseDatabase(handle.read(MAX_ESE_BYTES))
                counted = 0
                for table in database.tables[:200]:
                    rows = 0
                    for _ in database.iter_table_rows(table):
                        rows += 1
                        counted += 1
                        if counted >= MAX_ESE_ROWS_COUNTED:
                            run.cap("ese-row-count-cap")
                            break
                    tables.append({"name": table.name, "columns": len(table.columns), "rows_counted": rows})
                    if counted >= MAX_ESE_ROWS_COUNTED:
                        break
                decode_status = "catalog-decoded" if database.tables else "no-tables"
                decode_error = "; ".join(str(item) for item in database.errors[:5])
            except Exception as exc:  # the ESE decoder is bounded but a crafted file may still fail
                decode_status = "decode-failed"
                decode_error = f"{type(exc).__name__}: {exc}"[:300]
        elif signature_ok:
            decode_status = "skipped-size-cap"
            run.cap("ese-size-cap")
        candidates = address_candidates(head)
        details = {
            **self._attribution(run, account=account, store=path, recovery_method="ese-bounded-candidates"),
            "source_path": str(path),
            "source_format": "ese",
            "store_name": path.name,
            "store_bytes": size,
            "ese_signature_valid": signature_ok,
            "ese_decode_status": decode_status,
            "ese_decode_error": decode_error,
            "ese_tables": tables,
            "ese_table_count": len(tables),
            "address_candidates": candidates,
            "address_candidate_count": len(candidates),
            "address_scan_bytes": len(head),
            "confidence": "low",
            "coverage_status": "inventory-and-candidates",
            "note_ko": "ESE 저장소는 표 목록·행 수와 앞부분의 메일 주소 문자열 후보만 냅니다(메시지 행으로 해석하지 않음, 로그 재생 없음).",
            "validation_required": True,
            "timestamp": "",
            "timestamp_source": "none-store-row",
        }
        self._add(run, ArtifactRecord(self.name, "email-client-store", str(path), True, details))
        run.sources.append({"path": str(path), "format": "ese-store", "status": decode_status})

    # -- profile row ----------------------------------------------------------------------------

    def _profile_row(self, run: _ClientRun) -> ArtifactRecord:
        messages = run.counts.get("email-message", 0)
        data_rows = sum(count for kind, count in run.counts.items() if kind != "email-client-account")
        details = {
            **self._attribution(run, account="", store=run.root, recovery_method="filesystem-inventory"),
            "source_path": str(run.root),
            "source_format": "directory",
            "profile_name": run.root.name,
            "client_version": run.extra.get("client_version", ""),
            "credential_store_files": run.extra.get("credential_store_files", []),
            "credential_store_note_ko": "자격 증명 저장소(logins.json·key4.db 등)는 열지 않고 존재·크기·시각만 적습니다(정책)."
            if run.client == THUNDERBIRD else "",
            "mail_folders": run.folders[:200],
            "mail_folder_count": len(run.folders),
            "sources": run.sources[:100],
            "message_rows": messages,
            "attachment_rows": run.counts.get("email-attachment", 0),
            "contact_rows": run.counts.get("contact", 0),
            "calendar_rows": run.counts.get("calendar-event", 0),
            "account_rows": run.counts.get("email-client-account", 0),
            "store_rows": run.counts.get("email-client-store", 0),
            "parse_error_count": len(run.errors),
            "mbox_bytes_read": run.mbox_bytes,
            "gloda_indexed_messages": run.extra.get("gloda_indexed_messages"),
            "gloda_matched_mbox": run.extra.get("gloda_matched_mbox"),
            "gloda_index_only_rows": run.extra.get("gloda_index_only_rows"),
            "caps_hit": list(run.capped),
            "reason_ko": "" if data_rows else f"{CLIENT_LABELS_KO[run.client]} 폴더는 있으나 메일·연락처·일정 행으로 해석된 원본이 없습니다.",
            "coverage_status": "rows-recovered" if data_rows else "inventory-only",
            "validation_required": True,
            "timestamp": "",
            "timestamp_source": "none-profile-row",
        }
        return ArtifactRecord(self.name, "email-client-profile", str(run.root), True, details)


# --- module helpers -------------------------------------------------------------------------------


def _child_dirs(directory: Path) -> list[Path]:
    try:
        return sorted((item for item in directory.iterdir() if item.is_dir()), key=lambda item: item.name.lower())
    except OSError:
        return []


def _walk(root: Path, limit: int = MAX_WALK_FILES) -> Iterator[Path]:
    count = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort(key=str.lower)
        for name in sorted(filenames, key=str.lower):
            yield Path(directory) / name
            count += 1
            if count >= limit:
                return


def _mbox_files(server_dir: Path) -> list[Path]:
    return [path for path in _walk(server_dir) if is_extensionless_mbox(path)]


def _folder_name(server_dir: Path, mbox: Path) -> str:
    parts = list(mbox.relative_to(server_dir).parts)
    return "/".join(part[:-4] if part.lower().endswith(".sbd") else part for part in parts)


def _server_directories(accounts: Iterable[Mapping[str, object]]) -> dict[str, str]:
    """``"imapmail/<dir>"`` → account label, from ``directory-rel`` (``[ProfD]ImapMail/host``) or ``directory``."""
    mapping: dict[str, str] = {}
    for account in accounts:
        directory = str(account.get("server_directory") or "").replace("\\", "/")
        if not directory:
            continue
        directory = directory.removeprefix("[ProfD]")
        parts = [part for part in directory.split("/") if part]
        if len(parts) >= 2:
            mapping[f"{parts[-2]}/{parts[-1]}".lower()] = str(account.get("account") or parts[-1])
    return mapping


def _presence(root: Path, names: Iterable[str]) -> list[dict[str, object]]:
    listed: list[dict[str, object]] = []
    for name in names:
        try:
            stat_result = (root / name).stat()
        except OSError:
            continue
        listed.append(
            {
                "name": name,
                "bytes": stat_result.st_size,
                "modified": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
                "content_read": False,
            }
        )
    return listed


def _read_text(path: Path, limit: int) -> str:
    with path.open("rb") as handle:
        data = handle.read(limit)
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def _sqlite_ok(path: Path) -> bool:
    try:
        if path.stat().st_size > MAX_SQLITE_BYTES:
            return False
        with path.open("rb") as handle:
            return handle.read(16) == SQLITE_HEADER
    except OSError:
        return False


def _tables(connection: sqlite3.Connection) -> dict[str, str]:
    connection.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
    names = [str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    return {name.lower(): name for name in names if re.fullmatch(r"[A-Za-z0-9_]+", name)}


def _gloda_texts(connection: sqlite3.Connection, table: str) -> dict[str, dict[str, object]]:
    """Gloda full-text rows keyed by docid; the body is read up to 4,000 characters (its length is kept)."""
    columns = {str(row[1]).lower() for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()}
    wanted = [name for name in ("c1subject", "c2attachmentnames", "c3author", "c4recipients") if name in columns]
    body = ", substr(c0body, 1, 4000) AS c0body, length(c0body) AS body_length" if "c0body" in columns else ""
    select = ", ".join(["docid", *wanted]) + body
    cursor = connection.execute(f'SELECT {select} FROM "{table}" LIMIT ?', (MAX_SQLITE_ROWS,))
    names = [str(item[0]).lower() for item in cursor.description or ()]
    return {str(row[0]): dict(zip(names, row, strict=False)) for row in cursor.fetchall()}


def _rows(connection: sqlite3.Connection, table: str, limit: int = MAX_SQLITE_ROWS) -> list[dict[str, object]]:
    cursor = connection.execute(f'SELECT * FROM "{table}" LIMIT ?', (limit,))
    names = [str(item[0]).lower() for item in cursor.description or ()]
    return [dict(zip(names, row, strict=False)) for row in cursor.fetchall()]
