"""R5 L2 file-based system rows (plan r5-residual-2026-10-18 §3 L2; re-audit §3 items 5-8, 17, 19, 22, 25, §5).

Rows of the ``windows-system`` kind (``collect_system_extras``) and, for
``ntfs-volume-information``, the ``windows-filesystem`` kind
(``collect_ntfs_volume_information``):

* ``startup-item`` -- files of the user / all-users Startup folders (LNK through the
  existing Shell Link parser; the StartupApproved state is a registry row).
* ``ssh-known-host`` / ``ssh-authorized-key`` / ``ssh-client-session`` / ``ssh-key-file`` /
  ``ssh-server-config`` -- OpenSSH ``.ssh`` files, ``ProgramData\\ssh``, ``WinSCP.ini`` and
  PuTTY ``.ppk`` files. Private keys: presence, format, encryption flag and the *public*
  fingerprint only; the private key body is never copied, hashed or previewed.
* ``office-backstage-item`` -- ``BackstageInAppNavCache`` JSON (folders / files / URLs).
* ``vm-config`` -- VMware ``.vmx``/``preferences.ini``/``inventory.vmls``, VirtualBox
  ``VirtualBox.xml``/``*.vbox``, Hyper-V ``.vmcx`` (presence).
* ``crypto-wallet-presence`` -- desktop wallets and browser-extension wallets: presence,
  location, size, format, encryption flag, and public addresses of plain Electrum JSON.
  Keys, seeds, xprv and keystore contents are never read into a row.
* ``credential-store-presence`` -- ``Microsoft\\Credentials``, ``Vault`` and ``Protect``
  files: presence, size, GUID, SID. No blob contents, no DPAPI.
* ``av-detection-log`` -- McAfee Endpoint Security / VirusScan detection log lines.
* ``desktop-wallpaper`` -- ``Themes\\TranscodedWallpaper`` and ``Themes\\CachedFiles``.
* ``ntfs-volume-information`` -- ``$Boot`` (VBR: OEM, geometry, MFT LCN, 8-byte VSN) and the
  ``$Volume`` record (#3) of a ``$MFT`` (``$VOLUME_NAME``, ``$VOLUME_INFORMATION`` version
  and dirty flag). ``volume_serial_number`` uses the LNK/Prefetch spelling (``%08X``).

Every collector is bounded (bytes, lines, rows per type) and isolated: one corrupt file
yields a row with ``parse_status=error`` (or nothing) and the run continues.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping
from pathlib import Path

from ...core.files import RUN_OUTPUT_DIR_PREFIX, is_active_run_output_dir
from ...core.models import ArtifactRecord
from ...core.ntfs_volume import (  # noqa: F401 - re-exported (moved to core in R6 S2)
    NTFS_VOLUME_FLAGS,
    VBR_OEM_NTFS,
    apply_fixups,
    parse_ntfs_vbr,
    parse_volume_record,
    read_volume_information,
)
from .._walk import iter_evidence_paths
from .common import isoformat_from_timestamp, iter_windows_user_homes

PARSER = "windows-system-extras"
PARSER_VERSION = "system-extras-v1"
MAX_ROWS_PER_TYPE = 20_000
MAX_KEY_FILE_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LOG_LINES = 500_000
MAX_HASH_BYTES = 256 * 1024 * 1024
MAX_JSON_ITEMS = 5_000
MAX_JSON_DEPTH = 32
MAX_DIR_FILES = 2_000
WALLET_MKEY_SCAN_BYTES = 16 * 1024 * 1024
MAX_PUBLIC_ADDRESSES = 20

R5_SYSTEM_EXTRAS_TYPES = (
    "startup-item",
    "ssh-known-host",
    "ssh-authorized-key",
    "ssh-client-session",
    "ssh-key-file",
    "ssh-server-config",
    "office-backstage-item",
    "vm-config",
    "crypto-wallet-presence",
    "credential-store-presence",
    "av-detection-log",
    "desktop-wallpaper",
)

APPDATA_ROAMING = ("AppData", "Roaming")
APPDATA_LOCAL = ("AppData", "Local")
USER_STARTUP = (*APPDATA_ROAMING, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
MACHINE_STARTUP = ("ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "StartUp")
STARTUP_SKIP_NAMES = frozenset({"desktop.ini"})
SCRIPT_SUFFIXES = frozenset({".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".hta"})
EXECUTABLE_SUFFIXES = frozenset({".exe", ".com", ".scr", ".pif", ".dll", ".cpl", ".msi"})
# Lower-cased path markers of locations a standard user can write (startup-item rule input).
USER_WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
    "\\desktop\\",
)
USER_WRITABLE_EXCLUDES = (
    "\\appdata\\local\\microsoft\\",
    "\\appdata\\local\\programs\\",
    "\\appdata\\local\\google\\",
    "\\appdata\\local\\packages\\",
    "\\programdata\\microsoft\\windows\\start menu\\",
)

SSH_PRIVATE_HEADERS = (
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh", ""),
    ("-----BEGIN RSA PRIVATE KEY-----", "pem-rsa", "ssh-rsa"),
    ("-----BEGIN DSA PRIVATE KEY-----", "pem-dsa", "ssh-dss"),
    ("-----BEGIN EC PRIVATE KEY-----", "pem-ec", "ecdsa"),
    ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "pkcs8-encrypted", ""),
    ("-----BEGIN PRIVATE KEY-----", "pkcs8", ""),
)
SSH_KEY_TYPES = ("ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-")
SSHD_DIRECTIVES = (
    "port",
    "listenaddress",
    "permitrootlogin",
    "passwordauthentication",
    "pubkeyauthentication",
    "permitemptypasswords",
    "authorizedkeysfile",
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
    "allowtcpforwarding",
    "gatewayports",
    "subsystem",
    "match",
    "loglevel",
)
SSH_CONFIG_KEYS = {
    "hostname": "host_name",
    "user": "user_name",
    "port": "port",
    "identityfile": "identity_file",
    "proxyjump": "proxy_jump",
    "proxycommand": "proxy_command",
    "localforward": "local_forward",
    "remoteforward": "remote_forward",
    "dynamicforward": "dynamic_forward",
}
WINSCP_PROTOCOLS = {"0": "SCP", "1": "SFTP(SCP 대체)", "2": "SFTP", "5": "FTP", "6": "WebDAV", "7": "S3"}
SECRET_INI_KEYS = frozenset({"password", "proxypassword", "tunnelpassword", "passphrase", "encryptedpassword"})

# Desktop wallets: (product id, Korean/English name, path under the user home, kind of entry).
DESKTOP_WALLETS: tuple[tuple[str, str, tuple[str, ...], str], ...] = (
    ("bitcoin-core", "Bitcoin Core", (*APPDATA_ROAMING, "Bitcoin", "wallets"), "dir"),
    ("electrum", "Electrum", (*APPDATA_ROAMING, "Electrum", "wallets"), "electrum-dir"),
    ("electrum-ltc", "Electrum-LTC", (*APPDATA_ROAMING, "Electrum-LTC", "wallets"), "electrum-dir"),
    ("exodus", "Exodus", (*APPDATA_ROAMING, "Exodus", "exodus.wallet"), "dir"),
    ("ledger-live", "Ledger Live", (*APPDATA_ROAMING, "Ledger Live", "app.json"), "file"),
    ("atomic", "Atomic Wallet", (*APPDATA_ROAMING, "atomic", "Local Storage", "leveldb"), "dir"),
    ("wasabi", "Wasabi Wallet", (*APPDATA_ROAMING, "WalletWasabi", "Client", "Wallets"), "dir"),
    ("ethereum-keystore", "Ethereum keystore(geth)", (*APPDATA_ROAMING, "Ethereum", "keystore"), "keystore-dir"),
    ("monero", "Monero GUI", ("Documents", "Monero", "wallets"), "dir"),
    ("coinomi", "Coinomi", (*APPDATA_LOCAL, "Coinomi", "Coinomi", "wallets"), "dir"),
    ("guarda", "Guarda", (*APPDATA_ROAMING, "Guarda", "Local Storage", "leveldb"), "dir"),
    ("jaxx-liberty", "Jaxx Liberty", (*APPDATA_ROAMING, "com.liberty.jaxx", "IndexedDB"), "dir"),
)
# Chromium extension IDs of wallet extensions (Chrome Web Store detail URLs, see the R5 L2
# known-limitations section). Firefox stores extensions under per-profile random UUIDs: not mapped.
WALLET_EXTENSIONS: dict[str, tuple[str, str]] = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": ("metamask", "MetaMask"),
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": ("phantom", "Phantom"),
    "jblndlipeogpafnldhgmapagcccfchpi": ("kaikas", "Kaikas(Klaytn/Kaia)"),
    "hnfanknocfeofbddgcijnmhnfnkdnaad": ("coinbase-wallet", "Coinbase Wallet"),
    "egjidjbpglichdcondbcbdnbeeppgdph": ("trust-wallet", "Trust Wallet"),
    "fhbohimaelbohpjbbldcngcnapndodjp": ("binance-wallet", "Binance Wallet"),
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": ("tronlink", "TronLink"),
    "fnjhmkhhmkbjkkabndcnnogagogbneec": ("ronin", "Ronin Wallet"),
    "dmkamcknogkgcdfhhbddcghachkejeap": ("keplr", "Keplr"),
    "mcohilncbfahbmgdjkbpemcciiolgcge": ("okx-wallet", "OKX Wallet"),
    "acmacodkjbdgmoleebolmdjonilkdbch": ("rabby", "Rabby"),
    "aholpfdialjgjfhomihkjbmgjidlcdno": ("exodus-web3", "Exodus Web3"),
}
WALLET_EXTENSION_CONTAINERS = {
    "local extension settings": "local-extension-settings",
    "sync extension settings": "sync-extension-settings",
    "extensions": "extension-package",
}
INDEXEDDB_EXTENSION = re.compile(r"^chrome-extension_(?P<id>[a-p]{32})_0\.indexeddb\.(?:leveldb|blob)$")
BDB_BTREE_MAGIC = 0x00053162
ETH_KEYSTORE_ADDRESS = re.compile(r"--(?P<address>[0-9a-fA-F]{40})$")

CREDENTIAL_ROOTS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    ((*APPDATA_ROAMING, "Microsoft", "Credentials"), "credential-file", "자격 증명 파일(Credentials)"),
    ((*APPDATA_LOCAL, "Microsoft", "Credentials"), "credential-file", "자격 증명 파일(Credentials)"),
    ((*APPDATA_ROAMING, "Microsoft", "Vault"), "vault", "자격 증명 보관소(Vault)"),
    ((*APPDATA_LOCAL, "Microsoft", "Vault"), "vault", "자격 증명 보관소(Vault)"),
    ((*APPDATA_ROAMING, "Microsoft", "Protect"), "protect", "DPAPI 마스터 키(Protect)"),
)
SYSTEM_PROFILE_HOMES = (
    ("Windows", "System32", "config", "systemprofile"),
    ("Windows", "ServiceProfiles", "LocalService"),
    ("Windows", "ServiceProfiles", "NetworkService"),
)
SYSTEM_CREDENTIAL_ROOTS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("ProgramData", "Microsoft", "Vault"), "vault", "자격 증명 보관소(Vault, 시스템)"),
    (("Windows", "System32", "Microsoft", "Protect"), "protect", "DPAPI 마스터 키(Protect, 시스템)"),
)
VAULT_SUFFIX_KINDS = {".vcrd": ("vault-credential", "보관소 자격 증명(.vcrd)"), ".vpol": ("vault-policy", "보관소 정책(.vpol)"), ".vsch": ("vault-schema", "보관소 스키마(.vsch)")}
SID_PATTERN = re.compile(r"^S-1-\d+(?:-\d+)+$", re.IGNORECASE)

MCAFEE_LOG_NAMES = frozenset(
    {
        "onaccessscanlog.txt",
        "ondemandscanlog.txt",
        "accessprotectionlog.txt",
        "bufferoverflowprotectionlog.txt",
        "emailondeliverylog.txt",
    }
)
AV_TIME = re.compile(
    r"^\s*(?P<date>\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})[ \tT]+(?P<time>\d{1,2}:\d{2}:\d{2})(?:[.,](?P<fraction>\d{1,6}))?"
    r"(?:[ \t]*(?P<ampm>AM|PM|am|pm|오전|오후))?"
)
AV_NEGATIVE = re.compile(r"(?i)\bno (?:threats?|detections?|infections?|viruses)\b|\b0 (?:threats?|detections?|infected)\b|not found|탐지되지 않")
AV_DETECTION_TERMS = (
    "detected",
    "quarantin",
    "deleted",
    "cleaned",
    "blocked",
    "would be blocked",
    "access denied",
    "infected",
    "trojan",
    "탐지",
    "격리",
    "차단",
    "삭제",
)
AV_ACTIONS = (
    ("would be blocked", "would-block", "차단 예정(보고 모드)"),
    ("quarantin", "quarantined", "격리"),
    ("cleaned", "cleaned", "치료"),
    ("deleted", "deleted", "삭제"),
    ("blocked", "blocked", "차단"),
    ("access denied", "blocked", "차단"),
    ("격리", "quarantined", "격리"),
    ("차단", "blocked", "차단"),
    ("삭제", "deleted", "삭제"),
    ("detected", "detected", "탐지"),
    ("탐지", "detected", "탐지"),
)
WINDOWS_PATH = re.compile(r"(?i)^[a-z]:\\")
# A path inside free text ends at its file extension (ENS lines continue with "contains ...").
TEXT_PATH = re.compile(r"(?i)\b[a-z]:\\[^\t\r\n\"<>|*?:]*?\.[a-z0-9]{1,8}(?=$|[\s,;)\]])")
AV_THREAT_PATTERNS = (
    re.compile(r"(?i)threat\s*name\s*[:=]\s*(?P<threat>[^\t,;]+)"),
    re.compile(r"(?i)\bthreat\s*[:=]\s*(?P<threat>[^\t,;]+)"),
    re.compile(r"(?i)\bcontains\s+(?:the\s+)?(?P<threat>[A-Za-z0-9!_./:-]+(?:\s+\([^)]{1,60}\))?)"),
    re.compile(r"(?i)\bdetected\s+(?:as\s+)?(?P<threat>[A-Za-z0-9!_./:-]{3,}(?:\s+\([^)]{1,60}\))?)"),
)
AV_USER = re.compile(r"(?i)(?:<(?P<angle>[^<>\\]{1,64}(?:\\[^<>]{1,64})?)>|\b(?P<domain>(?:NT AUTHORITY|[A-Z0-9][A-Z0-9_.-]{0,30})\\[^\s\t\\]{1,64}))")

THEMES = (*APPDATA_ROAMING, "Microsoft", "Windows", "Themes")
IMAGE_MAGIC = (("jpeg", b"\xff\xd8\xff"), ("png", b"\x89PNG\r\n\x1a\n"), ("bmp", b"BM"), ("webp", b"RIFF"))

BACKSTAGE_NAME_KEYS = ("displayname", "name", "title", "filename", "label")
BACKSTAGE_LOCATION_KEYS = ("url", "fullpath", "path", "fileurl", "weburl", "resourceurl", "location", "uri", "docurl")
BACKSTAGE_MODIFIED_BY_KEYS = ("lastmodifiedby", "modifiedby", "editor", "author", "lastmodifiedbyname")

VMX_DISK_KEY = re.compile(r"^(?:scsi|sata|ide|nvme)\d+:\d+\.filename$", re.IGNORECASE)
VMX_MAC_KEY = re.compile(r"^ethernet\d+\.(?:generatedaddress|address)$", re.IGNORECASE)
VMWARE_MRU_KEY = re.compile(r"^pref\.mruvm(?P<index>\d+)\.(?P<field>filename|displayname)$", re.IGNORECASE)
VMLS_KEY = re.compile(r"^vmlist(?P<index>\d+)\.(?P<field>config|displayname)$", re.IGNORECASE)

class _Counter:
    """Rows per type across one collector run (``MAX_ROWS_PER_TYPE``)."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()

    def allow(self, artifact_type: str) -> bool:
        if self.counts[artifact_type] >= MAX_ROWS_PER_TYPE:
            return False
        self.counts[artifact_type] += 1
        return True


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def file_mtime(path: Path) -> str:
    try:
        return isoformat_from_timestamp(path.stat().st_mtime) or ""
    except OSError:
        return ""


def sha256_of(path: Path) -> dict[str, str]:
    size = file_size(path)
    if size is None or size > MAX_HASH_BYTES:
        return {}
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}


def decode_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", errors="replace")
    if len(data) >= 4 and data[1] == 0 and data[3] == 0 and data[0] != 0:
        return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp949", errors="replace")


def read_text(path: Path, limit: int = MAX_CONFIG_BYTES) -> str:
    return decode_text(read_prefix(path, limit))


def user_of(path: Path, root: Path) -> str:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except (OSError, ValueError):
        parts = path.parts
    lowered = [part.lower() for part in parts]
    if "users" in lowered:
        index = lowered.index("users")
        if index + 1 < len(parts):
            return parts[index + 1]
    return ""


def is_user_writable(path_text: str) -> bool:
    lowered = "\\" + path_text.replace("/", "\\").strip().strip('"').lower()
    if not lowered.strip("\\"):
        return False
    if any(marker in lowered for marker in USER_WRITABLE_EXCLUDES):
        return False
    return any(marker in lowered for marker in USER_WRITABLE_MARKERS)


def base_details(path: Path, *, source_format: str, recovery_method: str = "parsed", hashes: bool = True) -> dict[str, object]:
    resolved = str(path.resolve())
    return {
        "parser": PARSER,
        "parser_version": PARSER_VERSION,
        "coverage_status": "mapped",
        "reportability": "triage",
        "recovery_method": recovery_method,
        "source_path": resolved,
        "source_format": source_format,
        "source_hashes": sha256_of(path) if hashes and path.is_file() else {},
    }


def make_record(provider: str, artifact_type: str, path: Path, details: dict[str, object]) -> ArtifactRecord:
    details.setdefault("timestamp", "")
    details.setdefault("risk_flags", [])
    return ArtifactRecord(provider=provider, artifact_type=artifact_type, path=str(path.resolve()), supported=True, details=details)


def openssh_fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=") if blob else ""


def b64_blob(text: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        return b""


def ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ValueError("truncated ssh string length")
    length = int.from_bytes(data[offset : offset + 4], "big")
    end = offset + 4 + length
    if length > len(data) or end > len(data):
        raise ValueError("truncated ssh string")
    return data[offset + 4 : end], end


def blob_key_type(blob: bytes) -> str:
    try:
        name, _ = ssh_string(blob, 0)
    except ValueError:
        return ""
    try:
        return name.decode("ascii") if len(name) <= 64 else ""
    except UnicodeDecodeError:
        return ""


def parse_public_key_line(line: str) -> dict[str, object]:
    """``[options] <type> <base64> [comment]`` -> type, fingerprint, comment (the key text itself is public)."""
    parts = line.split()
    index = next((position for position, part in enumerate(parts) if part.startswith(SSH_KEY_TYPES)), -1)
    if index < 0 or index + 1 >= len(parts):
        return {"key_type": "", "fingerprint_sha256": "", "key_comment": "", "options": "", "parse_status": "unrecognized"}
    blob = b64_blob(parts[index + 1])
    return {
        "key_type": parts[index],
        "fingerprint_sha256": openssh_fingerprint(blob),
        "key_type_matches_blob": blob_key_type(blob) == parts[index] if blob else False,
        "key_comment": " ".join(parts[index + 2 :])[:200],
        "options": " ".join(parts[:index])[:500],
        "parse_status": "parsed" if blob else "invalid-base64",
    }


def iter_lines(text: str, limit: int = 100_000) -> Iterator[tuple[int, str]]:
    yield from enumerate(text.splitlines()[:limit], start=1)


# ---------------------------------------------------------------------------
# Secret-bearing files: document text policy (docs output, docs index, case DB)
# ---------------------------------------------------------------------------

# Folder sequences (lower-cased path parts) whose files hold keys, seeds or credential blobs.
SECRET_STORE_SEQUENCES: tuple[tuple[str, ...], ...] = (
    ("bitcoin", "wallets"),
    ("electrum", "wallets"),
    ("electrum-ltc", "wallets"),
    ("exodus", "exodus.wallet"),
    ("ethereum", "keystore"),
    ("walletwasabi", "client", "wallets"),
    ("atomic", "local storage"),
    ("coinomi", "coinomi", "wallets"),
    ("monero", "wallets"),
    ("guarda", "local storage"),
    ("com.liberty.jaxx",),
    ("ledger live",),
    ("microsoft", "credentials"),
    ("microsoft", "vault"),
    ("microsoft", "protect"),
)
SECRET_INI_LINE = re.compile(r"(?im)^(\s*(?:password|proxypassword|tunnelpassword|encryptedpassword|passphrase)\s*=).*$")
# A .reg saved-password value, including ``hex(1):`` data continued over ``\``-terminated lines.
SECRET_REG_LINE = re.compile(
    r'(?im)^(\s*"(?:password|proxypassword|tunnelpassword|encryptedpassword|passphrase)"\s*=)(?:[^\r\n]*\\\r?\n)*[^\r\n]*'
)
# WinSCP session sections (``[Sessions\name]`` / ``[Sessions]``) mark a WinSCP INI whatever the file is called (portable copies).
WINSCP_SESSION_SECTION = re.compile(r"(?im)^\s*\[Sessions[\\\]]")
# FileZilla saved passwords (``<Pass encoding="base64">…</Pass>``) in site manager / recent-server exports.
FILEZILLA_PASS_ELEMENT = re.compile(r"(?is)(<Pass\b[^>]*>).*?(</Pass\s*>)")
# Any PEM/OpenSSH/PGP private key armour: RSA, EC, OPENSSH, ENCRYPTED, PGP … ``PRIVATE KEY( BLOCK)``.
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?P<kind>[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?)-----.*?(?:-----END (?P=kind)-----|\Z)", re.DOTALL
)
PPK_PRIVATE_LINES = re.compile(r"(?ims)^Private-Lines:\s*\d+\s*$.*?(?=^Private-MAC:|\Z)")
WITHHELD_TEXT = "(비밀 값이 든 파일 — 정책상 본문을 저장하지 않음)"
# OpenSSH default private key names (``id_rsa.pub`` etc. are public) and server host keys.
SSH_PRIVATE_KEY_NAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "identity"})
SSH_HOST_PRIVATE_KEY = re.compile(r"^ssh_host_[a-z0-9]+_key$")
# Browser / mail / FTP credential stores withheld whole: Firefox/Thunderbird ``logins*.json`` (+ ``key3.db`` /
# ``key4.db`` / legacy ``signons.sqlite``), Chromium ``Login Data`` and FileZilla site lists.
SECRET_STORE_NAMES = frozenset(
    {"key3.db", "key4.db", "signons.sqlite", "login data", "login data for account", "sitemanager.xml", "recentservers.xml"}
)
LOGINS_JSON_NAME = re.compile(r"^logins[\w.-]*\.json$")
# Signal Desktop ``config.json`` holds the SQLCipher database key.
SIGNAL_CONFIG_PARENTS = frozenset({"signal", "signal beta"})
SECRET_FILE_SCAN_BYTES = 1024 * 1024


def is_secret_store_path(path: Path) -> bool:
    """A wallet store, browser wallet-extension store, Credentials/Vault/Protect file or private key."""
    parts = [part.lower() for part in path.parts]
    name = parts[-1] if parts else ""
    if name in SSH_PRIVATE_KEY_NAMES or name == "wallet.dat" or name.endswith(".ppk") or SSH_HOST_PRIVATE_KEY.match(name):
        return True
    if name in SECRET_STORE_NAMES or LOGINS_JSON_NAME.match(name):
        return True
    if name == "config.json" and len(parts) > 1 and parts[-2] in SIGNAL_CONFIG_PARENTS:
        return True
    for index, part in enumerate(parts[:-1]):
        if part in WALLET_EXTENSION_CONTAINERS and index + 1 < len(parts) and parts[index + 1] in WALLET_EXTENSIONS:
            return True
        match = INDEXEDDB_EXTENSION.match(part)
        if match and match.group("id") in WALLET_EXTENSIONS:
            return True
    for sequence in SECRET_STORE_SEQUENCES:
        width = len(sequence)
        if any(tuple(parts[index : index + width]) == sequence for index in range(len(parts) - width)):
            return True
    return False


def redact_secret_store_text(path: Path, text: str) -> str:
    """Document text with secrets removed: secret-store files are withheld, saved-password lines of
    WinSCP ``.ini``/``.reg`` text, FileZilla ``<Pass>`` values and private-key blocks (PEM/OpenSSH/PGP/PuTTY)
    are masked."""
    if not text:
        return text
    if is_secret_store_path(path):
        return WITHHELD_TEXT
    redacted = text
    name = path.name.lower()
    # Saved-session INI files only (WinSCP.ini or any .ini with ``[Sessions\…]``): other documents keep their text.
    if name == "winscp.ini" or (name.endswith(".ini") and WINSCP_SESSION_SECTION.search(redacted)):
        redacted = SECRET_INI_LINE.sub(r"\1(비밀번호 값 — 저장하지 않음)", redacted)
    if name.endswith(".reg"):
        redacted = SECRET_REG_LINE.sub(r"\1(비밀번호 값 — 저장하지 않음)", redacted)
    redacted = FILEZILLA_PASS_ELEMENT.sub(r"\1(비밀번호 값 — 저장하지 않음)\2", redacted)
    redacted = PRIVATE_KEY_BLOCK.sub(lambda match: f"[{match.group('kind')} — 본문 저장하지 않음]", redacted)
    return PPK_PRIVATE_LINES.sub("Private-Lines: (본문 저장하지 않음)\n", redacted)


def file_holds_store_secret(path: Path) -> bool:
    """A secret store (:func:`is_secret_store_path`) or a small text file whose secrets
    :func:`redact_secret_store_text` would mask (WinSCP INI/.reg passwords, FileZilla ``<Pass>``,
    private-key blocks): ``extract`` never copies such files verbatim."""
    if is_secret_store_path(path):
        return True
    try:
        if path.stat().st_size > SECRET_FILE_SCAN_BYTES:
            return False
        data = path.read_bytes()
    except OSError:
        return False
    if data[:2] == b"\xfe\xff":
        text = data.decode("utf-16", errors="replace")
    elif data[:2] == b"\xff\xfe" or (len(data) > 1 and data[1:2] == b"\x00"):
        text = data.decode("utf-16-le", errors="replace")
    else:
        text = data.decode("utf-8", errors="replace")
    return redact_secret_store_text(path, text) != text


# ---------------------------------------------------------------------------
# Provider entry points
# ---------------------------------------------------------------------------


def collect_system_extras(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    """All ``windows-system`` R5 L2 rows of an evidence root (each collector isolated)."""
    # R6 S2 lane A (lazy: av_ahnlab imports this module).
    from .av_ahnlab import collect_ahnlab_v3

    counter = _Counter()
    collectors: tuple[Callable[[Path, str], Iterable[ArtifactRecord]], ...] = (
        collect_startup_folder_items,
        collect_ssh_files,
        collect_office_backstage,
        collect_credential_store_presence,
        collect_wallpaper_files,
        collect_walk_dispatched,
        collect_ahnlab_v3,
    )
    for collector in collectors:
        try:
            for record in collector(root, provider):
                if counter.allow(record.artifact_type):
                    yield record
        except Exception:  # pragma: no cover - one collector failing never stops the others
            continue


# ---------------------------------------------------------------------------
# Startup folders
# ---------------------------------------------------------------------------


def startup_folders(root: Path) -> Iterator[tuple[Path, str, str]]:
    for home in iter_windows_user_homes(root):
        yield home.joinpath(*USER_STARTUP), "user", home.name
    yield root.joinpath(*MACHINE_STARTUP), "machine", ""


def collect_startup_folder_items(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    from .recent_files import parse_lnk_metadata_from_bytes

    for folder, scope, user in startup_folders(root):
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
            if not path.is_file() or path.name.lower() in STARTUP_SKIP_NAMES:
                continue
            suffix = path.suffix.lower()
            details = base_details(path, source_format="startup-folder")
            fields: dict[str, object] = {
                "item_name": path.name,
                "startup_source": "startup-folder-file",
                "startup_source_label": "시작프로그램 폴더",
                "scope": scope,
                "scope_label": "사용자" if scope == "user" else "시스템(모든 사용자)",
                "user": user,
                "enabled": None,
                "state_label": "레지스트리 StartupApproved\\StartupFolder에서 확인",
                "file_size": file_size(path),
                "source_file_mtime": file_mtime(path),
            }
            timestamp = ""
            timestamp_kind = ""
            if suffix == ".lnk":
                try:
                    lnk = parse_lnk_metadata_from_bytes(read_prefix(path, MAX_KEY_FILE_BYTES))
                except (ValueError, IndexError, UnicodeError) as exc:
                    lnk = {"lnk_parse_status": f"error: {type(exc).__name__}"}
                target = str(lnk.get("target_path") or "")
                arguments = str(lnk.get("command_line_arguments") or "")
                fields.update(
                    {
                        "item_kind": "shortcut",
                        "item_kind_label": "바로 가기(LNK)",
                        "lnk_parse_status": lnk.get("lnk_parse_status", ""),
                        "target_path": target,
                        "command_line_arguments": arguments[:1000],
                        "command": f"{target} {arguments}".strip(),
                        "working_directory": str(lnk.get("working_dir") or ""),
                        "target_created_at": lnk.get("target_created_at", ""),
                        "target_modified_at": lnk.get("target_modified_at", ""),
                        "target_accessed_at": lnk.get("target_accessed_at", ""),
                        "volume_serial_number": lnk.get("volume_serial_number", ""),
                        "tracker_machine_id": lnk.get("tracker_machine_id", ""),
                    }
                )
                for key, kind in (("target_modified_at", "target-modified"), ("target_created_at", "target-created")):
                    if lnk.get(key):
                        timestamp, timestamp_kind = str(lnk[key]), kind
                        break
            else:
                kind, kind_label = (
                    ("script", "스크립트") if suffix in SCRIPT_SUFFIXES else ("executable", "실행 파일") if suffix in EXECUTABLE_SUFFIXES else ("other", "기타 파일")
                )
                fields.update({"item_kind": kind, "item_kind_label": kind_label, "target_path": str(path.resolve()), "command": path.name})
            target_text = str(fields.get("target_path") or "")
            writable = is_user_writable(target_text)
            flags = ["startup-target-user-writable"] if writable else []
            if fields.get("item_kind") == "script":
                flags.append("startup-script")
            fields["target_user_writable"] = writable
            details.update(fields)
            details.update(
                {
                    "label": "시작프로그램 폴더 항목",
                    "timestamp": timestamp,
                    "timestamp_kind": timestamp_kind,
                    "risk_flags": flags,
                    "evidence_note": "시작프로그램 폴더의 항목은 로그온할 때 실행됩니다. 시각은 LNK에 기록된 대상 파일 시각이며 폴더에 추가된 시각이 아닙니다.",
                    "raw_preview": f"{path.name} → {fields.get('command') or ''}"[:500],
                }
            )
            yield make_record(provider, "startup-item", path, details)


# ---------------------------------------------------------------------------
# SSH: OpenSSH, ProgramData\ssh, WinSCP.ini, PuTTY .ppk
# ---------------------------------------------------------------------------


def collect_ssh_files(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    for home in iter_windows_user_homes(root):
        ssh_dir = home / ".ssh"
        if ssh_dir.is_dir():
            yield from _ssh_directory(ssh_dir, provider, user=home.name, scope="user")
        for ini in (home.joinpath(*APPDATA_ROAMING, "WinSCP.ini"),):
            if ini.is_file():
                yield from parse_winscp_ini(ini, provider, user=home.name)
    program_ssh = root / "ProgramData" / "ssh"
    if program_ssh.is_dir():
        yield from _ssh_directory(program_ssh, provider, user="", scope="machine")


def _ssh_directory(directory: Path, provider: str, *, user: str, scope: str) -> Iterable[ArtifactRecord]:
    for path in sorted(directory.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
        if not path.is_file():
            continue
        name = path.name.lower()
        try:
            if name in {"known_hosts", "known_hosts2", "known_hosts.old"}:
                yield from parse_known_hosts(path, provider, user=user)
            elif name in {"authorized_keys", "authorized_keys2", "administrators_authorized_keys"}:
                yield from parse_authorized_keys(path, provider, user=user, scope=scope)
            elif name == "config" and scope == "user":
                yield from parse_ssh_config(path, provider, user=user)
            elif name == "sshd_config":
                yield from parse_sshd_config(path, provider)
            elif name.startswith(("id_", "ssh_host_")) or name.endswith((".pub", ".ppk", ".pem", ".key")):
                record = ssh_key_file_record(path, provider, user=user, scope=scope)
                if record is not None:
                    yield record
        except Exception as exc:  # one corrupt file never stops the directory
            details = base_details(path, source_format="ssh-file", hashes=False)
            details.update({"parse_status": "error", "parse_error": f"{type(exc).__name__}: {exc}"[:200], "user": user, "label": "SSH 파일(해석 오류)"})
            yield make_record(provider, "ssh-key-file", path, details)


def parse_known_hosts(path: Path, provider: str, *, user: str) -> Iterable[ArtifactRecord]:
    hashes = sha256_of(path)
    for number, raw in iter_lines(read_text(path)):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        marker = parts[0] if parts and parts[0].startswith("@") else ""
        if marker:
            parts = parts[1:]
        if len(parts) < 3:
            continue
        hosts, key_type, key_text = parts[0], parts[1], parts[2]
        blob = b64_blob(key_text)
        hashed = hosts.startswith("|1|")
        details = base_details(path, source_format="openssh-known-hosts", hashes=False)
        details.update(
            {
                "source_hashes": hashes,
                "source_offset": number,
                "source_offset_unit": "line",
                "client": "openssh",
                "client_label": "OpenSSH",
                "user": user,
                "host": "" if hashed else hosts.split(",")[0],
                "host_patterns": "" if hashed else hosts[:500],
                "host_hashed": hashed,
                "port": _bracket_port(hosts),
                "key_type": key_type,
                "fingerprint_sha256": openssh_fingerprint(blob),
                "key_sha256": hashlib.sha256(blob).hexdigest() if blob else "",
                "marker": marker,
                "label": "SSH 알려진 호스트(known_hosts)",
                "evidence_note": "이 계정이 SSH로 접속해 서버 키를 저장한 호스트입니다. 해시된 항목(|1|)은 호스트 이름을 복원하지 않습니다.",
                "raw_preview": f"{'(해시됨)' if hashed else hosts[:200]} {key_type} {openssh_fingerprint(blob)}",
            }
        )
        yield make_record(provider, "ssh-known-host", path, details)


def _bracket_port(hosts: str) -> int | None:
    match = re.match(r"^\[(?P<host>[^\]]+)\]:(?P<port>\d+)", hosts)
    return int(match.group("port")) if match else None


def parse_authorized_keys(path: Path, provider: str, *, user: str, scope: str) -> Iterable[ArtifactRecord]:
    hashes = sha256_of(path)
    for number, raw in iter_lines(read_text(path)):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = parse_public_key_line(line)
        options = str(parsed.get("options") or "").lower()
        flags = []
        if not options:
            flags.append("unrestricted-authorized-key")
        if "command=" in options:
            flags.append("forced-command-key")
        if path.name.lower() == "administrators_authorized_keys":
            flags.append("administrators-authorized-key")
        details = base_details(path, source_format="openssh-authorized-keys", hashes=False)
        details.update(
            {
                "source_hashes": hashes,
                "source_offset": number,
                "source_offset_unit": "line",
                "user": user,
                "scope": scope,
                "scope_label": "관리자 계정 공통(administrators_authorized_keys)" if path.name.lower() == "administrators_authorized_keys" else "사용자",
                **parsed,
                "label": "SSH 허용 공개키(authorized_keys)",
                "risk_flags": flags,
                "evidence_note": "이 키를 가진 사람은 비밀번호 없이 이 컴퓨터에 SSH로 로그온할 수 있습니다(서버 측).",
                "raw_preview": f"{parsed.get('options') or ''} {parsed.get('key_type') or ''} {parsed.get('fingerprint_sha256') or ''} {parsed.get('key_comment') or ''}".strip(),
            }
        )
        yield make_record(provider, "ssh-authorized-key", path, details)


def parse_ssh_config(path: Path, provider: str, *, user: str) -> Iterable[ArtifactRecord]:
    hashes = sha256_of(path)
    blocks: list[tuple[int, str, dict[str, str]]] = []
    current: tuple[int, str, dict[str, str]] | None = None
    for number, raw in iter_lines(read_text(path)):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(?P<key>[A-Za-z]+)\s*(?:=\s*|\s+)(?P<value>.*)$", line)
        if not match:
            continue
        key = match.group("key").lower()
        value = match.group("value").strip().strip('"')
        if key in {"host", "match"}:
            current = (number, f"{'Match ' if key == 'match' else ''}{value}", {})
            blocks.append(current)
        elif current is not None and key in SSH_CONFIG_KEYS:
            current[2].setdefault(SSH_CONFIG_KEYS[key], value[:500])
    for number, alias, values in blocks:
        port = values.get("port", "")
        details = base_details(path, source_format="openssh-config", hashes=False)
        details.update(
            {
                "source_hashes": hashes,
                "source_offset": number,
                "source_offset_unit": "line",
                "client": "openssh",
                "client_label": "OpenSSH",
                "user": user,
                "session_name": alias[:200],
                "host_name": values.get("host_name", "") or ("" if any(char in alias for char in "*?") else alias.split()[0]),
                "user_name": values.get("user_name", ""),
                "port": int(port) if port.isdigit() else None,
                "identity_file": values.get("identity_file", ""),
                "proxy_jump": values.get("proxy_jump", ""),
                "proxy_command": values.get("proxy_command", ""),
                "port_forwarding": ", ".join(values[key] for key in ("local_forward", "remote_forward", "dynamic_forward") if key in values),
                "protocol": "SSH",
                "password_saved": False,
                "secret_values_stored": False,
                "label": "SSH 클라이언트 설정(config)",
                "raw_preview": f"Host {alias} → {values.get('user_name', '')}@{values.get('host_name', '')}".strip(),
            }
        )
        yield make_record(provider, "ssh-client-session", path, details)


def parse_sshd_config(path: Path, provider: str) -> Iterable[ArtifactRecord]:
    settings: dict[str, list[str]] = {}
    for _number, raw in iter_lines(read_text(path)):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\s=]+", line, maxsplit=1)
        lowered = parts[0].lower()
        if lowered in SSHD_DIRECTIVES:
            settings.setdefault(lowered, []).append((parts[1] if len(parts) > 1 else "").strip()[:300])
    flags = []
    if any(value.lower() == "yes" for value in settings.get("permitemptypasswords", [])):
        flags.append("sshd-empty-passwords-permitted")
    details = base_details(path, source_format="openssh-sshd-config")
    details.update(
        {
            "scope": "machine",
            "settings": {key: values[:20] for key, values in sorted(settings.items())},
            "port": ", ".join(settings.get("port", [])) or "22(기본값)",
            "password_authentication": ", ".join(settings.get("passwordauthentication", [])),
            "permit_root_login": ", ".join(settings.get("permitrootlogin", [])),
            "allow_users": ", ".join(settings.get("allowusers", [])),
            "label": "OpenSSH 서버 설정(sshd_config)",
            "risk_flags": flags,
            "evidence_note": "Windows OpenSSH 서버 설정입니다. 기본값과 다른 지시어만 파일에 적혀 있습니다.",
            "raw_preview": "; ".join(f"{key}={','.join(values[:3])}" for key, values in sorted(settings.items()))[:500],
        }
    )
    yield make_record(provider, "ssh-server-config", path, details)


def classify_private_key(data: bytes) -> dict[str, object] | None:
    """Format / encryption / public half of a private key file; ``None`` = not a private key.

    Only headers and the *public* part are read: for OpenSSH keys the cipher name and the
    public key blob precede the (possibly encrypted) private section, which is never touched.
    """
    head = data[:200].decode("ascii", errors="replace")
    for header, key_format, key_type in SSH_PRIVATE_HEADERS:
        if header in head:
            info: dict[str, object] = {"key_role": "private", "key_format": key_format, "key_type": key_type, "fingerprint_sha256": ""}
            text_value = data.decode("ascii", errors="replace")
            if key_format == "openssh":
                body = "".join(line.strip() for line in text_value.splitlines() if line and not line.startswith("-----"))
                blob = b64_blob(body)
                info.update(_openssh_private_public_half(blob))
            elif key_format.startswith("pem"):
                info["encrypted"] = "Proc-Type: 4,ENCRYPTED" in text_value
            else:
                info["encrypted"] = key_format == "pkcs8-encrypted"
            return info
    if data.startswith(b"PuTTY-User-Key-File-"):
        return _ppk_info(data.decode("utf-8", errors="replace"))
    return None


def _openssh_private_public_half(blob: bytes) -> dict[str, object]:
    if not blob.startswith(b"openssh-key-v1\x00"):
        return {"encrypted": None, "parse_status": "invalid-openssh-body"}
    try:
        offset = len(b"openssh-key-v1\x00")
        cipher, offset = ssh_string(blob, offset)
        kdf, offset = ssh_string(blob, offset)
        _kdf_options, offset = ssh_string(blob, offset)
        if offset + 4 > len(blob):
            raise ValueError("truncated key count")
        count = int.from_bytes(blob[offset : offset + 4], "big")
        offset += 4
        public = b""
        if count >= 1:
            public, offset = ssh_string(blob, offset)
    except ValueError:
        return {"encrypted": None, "parse_status": "truncated-openssh-body"}
    cipher_name = cipher.decode("ascii", errors="replace")[:40]
    return {
        "encrypted": cipher_name != "none",
        "cipher": cipher_name,
        "kdf": kdf.decode("ascii", errors="replace")[:40],
        "key_type": blob_key_type(public),
        "fingerprint_sha256": openssh_fingerprint(public),
        "key_count": count,
    }


def _ppk_info(text_value: str) -> dict[str, object]:
    header: dict[str, str] = {}
    public_lines: list[str] = []
    lines = text_value.splitlines()
    index = 0
    while index < len(lines) and index < 400:
        key, _, value = lines[index].partition(":")
        key = key.strip().lower()
        if key == "public-lines":
            count = int(value.strip()) if value.strip().isdigit() else 0
            public_lines = [line.strip() for line in lines[index + 1 : index + 1 + min(count, 64)]]
            index += 1 + min(count, 64)
            continue
        if key == "private-lines":
            break  # the private part is never read
        if key.startswith("putty-user-key-file-") or key in {"encryption", "comment"}:
            header[key] = value.strip()
        index += 1
    version = next((name.rsplit("-", 1)[-1] for name in header if name.startswith("putty-user-key-file-")), "")
    blob = b64_blob("".join(public_lines))
    encryption = header.get("encryption", "")
    return {
        "key_role": "private",
        "key_format": f"putty-ppk-v{version}" if version else "putty-ppk",
        "key_type": header.get(f"putty-user-key-file-{version}", "") or blob_key_type(blob),
        "encrypted": encryption.lower() != "none" if encryption else None,
        "cipher": encryption,
        "key_comment": header.get("comment", "")[:200],
        "fingerprint_sha256": openssh_fingerprint(blob),
    }


def ssh_key_file_record(path: Path, provider: str, *, user: str, scope: str) -> ArtifactRecord | None:
    size = file_size(path)
    if size is None or size > MAX_KEY_FILE_BYTES:
        return None
    data = read_prefix(path, MAX_KEY_FILE_BYTES)
    info = classify_private_key(data)
    if info is None:
        line = data.decode("utf-8", errors="replace").strip().splitlines()[0] if data.strip() else ""
        if not line.startswith(SSH_KEY_TYPES):
            return None
        info = {"key_role": "public", "key_format": "openssh-public", **parse_public_key_line(line)}
    private = info.get("key_role") == "private"
    if private:
        pair = path.with_name(path.name + ".pub")
        if not info.get("fingerprint_sha256") and pair.is_file():
            pub_line = read_text(pair, MAX_KEY_FILE_BYTES).strip().splitlines()
            if pub_line:
                public = parse_public_key_line(pub_line[0])
                info["fingerprint_sha256"] = public.get("fingerprint_sha256", "")
                info["key_type"] = info.get("key_type") or public.get("key_type", "")
    host_key = path.name.lower().startswith("ssh_host_")
    role_label = ("서버 호스트 개인키" if host_key else "개인키") if private else ("서버 호스트 공개키" if host_key else "공개키")
    # Private key files: no content hash either (a hash of a key is a key oracle); presence and size only.
    details = base_details(path, source_format="ssh-key-file", recovery_method="inventory", hashes=not private)
    details.update(
        {
            "user": user,
            "scope": scope,
            "file_name": path.name,
            "file_size": size,
            "source_file_mtime": file_mtime(path),
            **info,
            "key_role_label": role_label,
            "private_key_present": private,
            "secret_values_stored": False,
            "label": f"SSH 키 파일({role_label})",
            "evidence_note": "개인키는 존재·형식·암호화 여부와 공개키 지문만 기록합니다(본문·해시 저장 안 함)." if private else "공개키 지문(SHA256)으로 서버 authorized_keys와 대조할 수 있습니다.",
            "raw_preview": f"{path.name} {info.get('key_format', '')} {info.get('key_type', '')} {info.get('fingerprint_sha256', '')}".strip(),
            "risk_flags": ["ssh-private-key-unencrypted"] if private and info.get("encrypted") is False else [],
        }
    )
    return make_record(provider, "ssh-key-file", path, details)


def parse_ini_sections(text_value: str) -> list[tuple[str, int, dict[str, str]]]:
    sections: list[tuple[str, int, dict[str, str]]] = []
    current: dict[str, str] | None = None
    for number, raw in iter_lines(text_value):
        line = raw.strip()
        if not line or line.startswith((";", "#")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = {}
            sections.append((line[1:-1], number, current))
        elif current is not None and "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    return sections


def parse_winscp_ini(path: Path, provider: str, *, user: str) -> Iterable[ArtifactRecord]:
    from urllib.parse import unquote

    hashes = sha256_of(path)
    for section, number, values in parse_ini_sections(read_text(path)):
        lowered = section.lower()
        folded = {key.lower(): value for key, value in values.items()}
        if lowered.startswith("sessions\\"):
            host = folded.get("hostname", "")
            if not host:
                continue
            port = folded.get("portnumber", "")
            saved = {key for key, value in folded.items() if key in SECRET_INI_KEYS and value}
            details = base_details(path, source_format="winscp-ini", hashes=False)
            details.update(
                {
                    "source_hashes": hashes,
                    "source_offset": number,
                    "source_offset_unit": "line",
                    "client": "winscp",
                    "client_label": "WinSCP(INI)",
                    "user": user,
                    "session_name": unquote(section.split("\\", 1)[1]),
                    "host_name": host,
                    "user_name": folded.get("username", ""),
                    "port": int(port) if port.isdigit() else None,
                    "protocol": WINSCP_PROTOCOLS.get(folded.get("fsprotocol", ""), folded.get("fsprotocol", "")),
                    "public_key_file": unquote(folded.get("publickeyfile", "")),
                    "proxy_host": folded.get("proxyhost", ""),
                    "password_saved": bool(saved & {"password", "encryptedpassword"}),
                    "proxy_password_saved": "proxypassword" in saved,
                    "secret_values_stored": False,
                    "label": "저장된 접속 세션(WinSCP.ini)",
                    "risk_flags": ["ssh-password-saved"] if saved & {"password", "encryptedpassword"} else [],
                    "raw_preview": f"WinSCP {folded.get('username', '')}@{host}:{port}".strip(":"),
                }
            )
            yield make_record(provider, "ssh-client-session", path, details)
        elif lowered == "sshhostkeys":
            for name, value in values.items():
                match = re.match(r"^(?P<type>[^@]+)@(?P<port>\d+):(?P<host>.+)$", name)
                details = base_details(path, source_format="winscp-ini", hashes=False)
                details.update(
                    {
                        "source_hashes": hashes,
                        "source_offset": number,
                        "source_offset_unit": "line",
                        "client": "winscp",
                        "client_label": "WinSCP(INI)",
                        "user": user,
                        "host": match.group("host") if match else name,
                        "port": int(match.group("port")) if match else None,
                        "key_type": match.group("type") if match else "",
                        "key_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest() if value else "",
                        "fingerprint_sha256": "",
                        "label": "SSH 호스트 키(WinSCP.ini)",
                        "raw_preview": f"WinSCP {name}",
                    }
                )
                yield make_record(provider, "ssh-known-host", path, details)


# ---------------------------------------------------------------------------
# Office Backstage
# ---------------------------------------------------------------------------


def collect_office_backstage(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    for home in iter_windows_user_homes(root):
        office = home.joinpath(*APPDATA_LOCAL, "Microsoft", "Office")
        if not office.is_dir():
            continue
        for version in sorted(office.iterdir(), key=lambda item: item.name):
            cache = version / "BackstageInAppNavCache"
            if not cache.is_dir():
                continue
            files = sorted((item for item in iter_evidence_paths(cache, "*.json") if item.is_file()), key=lambda item: str(item).lower())
            for path in files[:MAX_DIR_FILES]:
                yield from parse_backstage_json(path, provider, user=home.name, office_version=version.name)


def _first(mapping: Mapping[str, object], keys: tuple[str, ...]) -> str:
    folded = {str(key).casefold(): value for key, value in mapping.items()}
    for key in keys:
        value = folded.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool) and str(value).strip():
            return str(value).strip()
    return ""


def _modified(mapping: Mapping[str, object]) -> str:
    for key, value in mapping.items():
        lowered = str(key).casefold()
        if isinstance(value, str) and ("modified" in lowered or "lastaccess" in lowered or "lastused" in lowered) and "by" not in lowered:
            if re.match(r"^\d{4}-\d{2}-\d{2}", value.strip()):
                return value.strip()
    return ""


def iter_backstage_items(document: object) -> Iterator[tuple[str, Mapping[str, object]]]:
    """``(json path, object)`` of every object carrying a URL/path field (bounded depth and count)."""
    stack: list[tuple[object, str, int]] = [(document, "$", 0)]
    emitted = 0
    while stack and emitted < MAX_JSON_ITEMS:
        node, where, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            continue
        if isinstance(node, Mapping):
            if _first(node, BACKSTAGE_LOCATION_KEYS):
                emitted += 1
                yield where, node
            for key, value in reversed(list(node.items())):
                if isinstance(value, (Mapping, list)):
                    stack.append((value, f"{where}.{key}", depth + 1))
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                if isinstance(node[index], (Mapping, list)):
                    stack.append((node[index], f"{where}[{index}]", depth + 1))


def parse_backstage_json(path: Path, provider: str, *, user: str, office_version: str) -> Iterable[ArtifactRecord]:
    size = file_size(path) or 0
    details_base = base_details(path, source_format="office-backstage-json")
    if size > MAX_JSON_BYTES:
        return
    try:
        document = json.loads(read_text(path, MAX_JSON_BYTES))
    except (ValueError, RecursionError) as exc:
        details = dict(details_base)
        details.update(
            {
                "user": user,
                "office_version": office_version,
                "cache_file": path.name,
                "parse_status": "error",
                "parse_error": f"{type(exc).__name__}: {exc}"[:200],
                "label": "Office Backstage 캐시(해석 오류)",
            }
        )
        yield make_record(provider, "office-backstage-item", path, details)
        return
    for where, item in iter_backstage_items(document):
        location = _first(item, BACKSTAGE_LOCATION_KEYS)
        modified = _modified(item)
        kind = "url" if location.lower().startswith(("http://", "https://")) else "local-path"
        details = dict(details_base)
        details.update(
            {
                "user": user,
                "office_version": office_version,
                "cache_file": path.name,
                "cache_folder": path.parent.name,
                "json_path": where[:300],
                "item_name": _first(item, BACKSTAGE_NAME_KEYS)[:500],
                "location": location[:2000],
                "url": location[:2000] if kind == "url" else "",
                "local_path": location[:2000] if kind != "url" else "",
                "location_kind": kind,
                "location_kind_label": "웹 주소(SharePoint/OneDrive 등)" if kind == "url" else "로컬·네트워크 경로",
                "host": re.sub(r"^https?://([^/]+).*$", r"\1", location) if kind == "url" else "",
                "modified_at": modified,
                "modified_by": _first(item, BACKSTAGE_MODIFIED_BY_KEYS)[:200],
                "timestamp": modified,
                "timestamp_kind": "modified" if modified else "",
                "field_extraction": "heuristic-keys",
                "label": "Office Backstage 항목",
                "evidence_note": "Office 열기/저장 화면(Backstage)이 캐시한 폴더·파일 목록입니다. 필드 이름은 버전마다 다를 수 있어 키 이름으로 찾습니다.",
                "raw_preview": f"{_first(item, BACKSTAGE_NAME_KEYS)} {location}"[:500],
            }
        )
        yield make_record(provider, "office-backstage-item", path, details)


# ---------------------------------------------------------------------------
# Credentials / Vault / Protect presence
# ---------------------------------------------------------------------------


def _credential_entries(base: Path, family: str) -> Iterator[tuple[Path, str, str, str]]:
    """``(file, store kind, sid, container guid)`` under one Credentials/Vault/Protect root."""
    if family == "credential-file":
        for path in sorted(base.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
            if path.is_file():
                yield path, "credential-file", "", ""
    elif family == "vault":
        for container in sorted(base.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
            if not container.is_dir():
                continue
            for path in sorted(container.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
                if path.is_file():
                    yield path, VAULT_SUFFIX_KINDS.get(path.suffix.lower(), ("vault-other", ""))[0], "", container.name
    else:
        for entry in sorted(base.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
            if entry.is_file():
                yield entry, "dpapi-credhist" if entry.name.upper() == "CREDHIST" else "protect-other", "", ""
            elif entry.is_dir() and SID_PATTERN.match(entry.name):
                for path in sorted(entry.rglob("*"), key=lambda item: str(item).lower())[:MAX_DIR_FILES]:
                    if not path.is_file():
                        continue
                    kind = "dpapi-preferred" if path.name.lower() == "preferred" else "dpapi-master-key"
                    yield path, kind, entry.name, ""


CREDENTIAL_KIND_LABELS = {
    "credential-file": "자격 증명 파일",
    "vault-credential": "보관소 자격 증명(.vcrd)",
    "vault-policy": "보관소 정책(.vpol)",
    "vault-schema": "보관소 스키마(.vsch)",
    "vault-other": "보관소 기타 파일",
    "dpapi-master-key": "DPAPI 마스터 키",
    "dpapi-preferred": "DPAPI 기본 마스터 키 지정(Preferred)",
    "dpapi-credhist": "DPAPI 자격 증명 기록(CREDHIST)",
    "protect-other": "Protect 기타 파일",
}


def collect_credential_store_presence(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    homes: list[tuple[Path, str, tuple[tuple[tuple[str, ...], str, str], ...]]] = [
        (home, home.name, CREDENTIAL_ROOTS) for home in iter_windows_user_homes(root)
    ]
    homes.extend((root.joinpath(*parts), parts[-1], CREDENTIAL_ROOTS) for parts in SYSTEM_PROFILE_HOMES)
    homes.append((root, "(시스템)", SYSTEM_CREDENTIAL_ROOTS))
    for home, owner, roots in homes:
        for parts, family, family_label in roots:
            base = home.joinpath(*parts)
            if not base.is_dir():
                continue
            for path, kind, sid, container in _credential_entries(base, family):
                size = file_size(path)
                details = base_details(path, source_format="windows-credential-store", recovery_method="inventory")
                guid = path.name if _is_guid(path.name) or re.fullmatch(r"[0-9A-Fa-f]{32}", path.name) else ""
                details.update(
                    {
                        "user": owner,
                        "store_family": family,
                        "store_family_label": family_label,
                        "store_kind": kind,
                        "store_kind_label": CREDENTIAL_KIND_LABELS.get(kind, kind),
                        "file_name": path.name,
                        "file_guid": guid,
                        "vault_guid": container,
                        "user_sid": sid,
                        "file_size": size,
                        "source_file_mtime": file_mtime(path),
                        "contents_stored": False,
                        "dpapi_decrypted": False,
                        "label": "Windows 저장된 자격 증명(존재만)",
                        "evidence_note": "정책상 DPAPI 복호와 blob 내용 해석은 하지 않습니다. 존재·크기·위치·GUID만 기록합니다.",
                        "raw_preview": f"{owner} {CREDENTIAL_KIND_LABELS.get(kind, kind)} {path.name} ({size or 0} bytes)",
                    }
                )
                yield make_record(provider, "credential-store-presence", path, details)


def _is_guid(name: str) -> bool:
    try:
        uuid.UUID(name.strip("{}"))
    except ValueError:
        return False
    return len(name.strip("{}")) == 36


# ---------------------------------------------------------------------------
# Wallpaper files
# ---------------------------------------------------------------------------


def image_info(data: bytes) -> dict[str, object]:
    image_format = next((name for name, magic in IMAGE_MAGIC if data.startswith(magic)), "")
    if image_format == "webp" and data[8:12] != b"WEBP":
        image_format = ""
    width = height = None
    if image_format == "png" and len(data) >= 24:
        width, height = int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    elif image_format == "bmp" and len(data) >= 26:
        width, height = int.from_bytes(data[18:22], "little", signed=True), abs(int.from_bytes(data[22:26], "little", signed=True))
    elif image_format == "jpeg":
        width, height = _jpeg_size(data)
    return {"image_format": image_format, "image_width": width, "image_height": height}


def _jpeg_size(data: bytes) -> tuple[int | None, int | None]:
    offset = 2
    while offset + 9 < len(data):
        if data[offset] != 0xFF:
            return None, None
        marker = data[offset + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        if length < 2:
            return None, None
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            return int.from_bytes(data[offset + 7 : offset + 9], "big"), int.from_bytes(data[offset + 5 : offset + 7], "big")
        offset += 2 + length
    return None, None


def collect_wallpaper_files(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    for home in iter_windows_user_homes(root):
        themes = home.joinpath(*THEMES)
        if not themes.is_dir():
            continue
        candidates = [themes / "TranscodedWallpaper", themes / "TranscodedWallpaper.jpg"]
        cached = themes / "CachedFiles"
        if cached.is_dir():
            candidates.extend(sorted(cached.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES])
        for path in candidates:
            if not path.is_file():
                continue
            info = image_info(read_prefix(path, 256 * 1024))
            source = "transcoded" if path.name.lower().startswith("transcodedwallpaper") else "cached-file"
            details = base_details(path, source_format="wallpaper-image", recovery_method="inventory")
            details.update(
                {
                    "user": home.name,
                    "wallpaper_source": source,
                    "wallpaper_source_label": "TranscodedWallpaper(현재 배경 사본)" if source == "transcoded" else "Themes\\CachedFiles(배경 캐시)",
                    "wallpaper_path": str(path.resolve()),
                    "original_path": "",
                    "file_size": file_size(path),
                    "source_file_mtime": file_mtime(path),
                    **info,
                    "label": "바탕 화면 배경 이미지",
                    "evidence_note": "현재 바탕 화면 배경의 변환 사본입니다. 원본 경로는 레지스트리 TranscodedImageCache 행에서 확인하십시오.",
                    "raw_preview": f"{home.name} {path.name} {info.get('image_format') or '형식 미상'} {info.get('image_width') or '-'}x{info.get('image_height') or '-'}",
                }
            )
            yield make_record(provider, "desktop-wallpaper", path, details)


# ---------------------------------------------------------------------------
# One walk: VM configs, wallets, McAfee logs, .ppk and WinSCP.ini outside AppData
# ---------------------------------------------------------------------------


def collect_walk_dispatched(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    handled: set[str] = set()
    yield from collect_wallets_in_homes(root, provider, handled)
    seen_extension_dirs: set[str] = set()
    for path in sorted(iter_evidence_paths(root, "*"), key=lambda item: str(item).lower()):
        name = path.name.lower()
        suffix = path.suffix.lower()
        parent = path.parent.name.lower()
        try:
            if parent in WALLET_EXTENSION_CONTAINERS and name in WALLET_EXTENSIONS and path.is_dir():
                yield from wallet_extension_record(path, provider, root, WALLET_EXTENSION_CONTAINERS[parent], seen_extension_dirs)
            elif parent == "indexeddb" and INDEXEDDB_EXTENSION.match(name) and path.is_dir():
                match = INDEXEDDB_EXTENSION.match(name)
                if match and match.group("id") in WALLET_EXTENSIONS:
                    yield from wallet_extension_record(path, provider, root, "indexeddb", seen_extension_dirs, extension_id=match.group("id"))
            elif not path.is_file():
                continue
            elif suffix == ".vmx":
                yield from vmx_records(path, provider, root)
            elif suffix == ".vbox":
                yield from vbox_records(path, provider, root)
            elif suffix == ".vmcx":
                yield vmcx_record(path, provider, root)
            elif name == "virtualbox.xml":
                yield from virtualbox_registry_records(path, provider, root)
            elif name == "preferences.ini" and parent == "vmware":
                yield from vmware_mru_records(path, provider, root)
            elif name == "inventory.vmls":
                yield from vmware_inventory_records(path, provider, root)
            elif name == "wallet.dat" and str(path.resolve()).casefold() not in handled:
                record = wallet_dat_record(path, provider, root, product=("bitcoin-core-family", f"wallet.dat({path.parent.name})"))
                if record is not None:
                    yield record
            elif suffix == ".ppk" and ".ssh" not in {part.lower() for part in path.parts}:
                record = ssh_key_file_record(path, provider, user=user_of(path, root), scope="user")
                if record is not None:
                    yield record
            elif name == "winscp.ini" and not (parent == "roaming" and path.parent.parent.name.lower() == "appdata"):
                # %APPDATA%\WinSCP.ini is read per user home; portable/installed copies are read here.
                yield from parse_winscp_ini(path, provider, user=user_of(path, root))
            elif "mcafee" in str(path).lower() and (name.endswith("_activity.log") or name in MCAFEE_LOG_NAMES):
                yield from mcafee_log_records(path, provider)
        except Exception as exc:  # one corrupt file (XML ParseError is a SyntaxError) never stops the walk
            details = base_details(path, source_format="system-extras", hashes=False)
            details.update({"parse_status": "error", "parse_error": f"{type(exc).__name__}: {exc}"[:200], "label": "해석 오류"})
            yield make_record(provider, _type_for_error(name, suffix), path, details)


def _type_for_error(name: str, suffix: str) -> str:
    if suffix in {".vmx", ".vbox", ".vmcx"} or name in {"virtualbox.xml", "preferences.ini", "inventory.vmls"}:
        return "vm-config"
    if name == "wallet.dat":
        return "crypto-wallet-presence"
    if suffix == ".ppk" or name == "winscp.ini":
        return "ssh-key-file" if suffix == ".ppk" else "ssh-client-session"
    if name.endswith(".log") or name.endswith(".txt"):
        return "av-detection-log"
    return "crypto-wallet-presence"


# --- VM configs -------------------------------------------------------------------


def parse_vmx_text(text_value: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for _number, raw in iter_lines(text_value, 20_000):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip().lower()] = value.strip().strip('"')
    return values


def vm_details(path: Path, root: Path, *, product: str, product_label: str, source_kind: str, source_label: str) -> dict[str, object]:
    details = base_details(path, source_format=f"vm-{source_kind}")
    details.update(
        {
            "user": user_of(path, root),
            "vm_product": product,
            "vm_product_label": product_label,
            "config_source": source_kind,
            "config_source_label": source_label,
            "file_size": file_size(path),
            "source_file_mtime": file_mtime(path),
            "label": f"가상 머신 구성({product_label})",
        }
    )
    return details


def vmx_records(path: Path, provider: str, root: Path) -> Iterable[ArtifactRecord]:
    values = parse_vmx_text(read_text(path))
    disks = sorted({value for key, value in values.items() if VMX_DISK_KEY.match(key) and value})[:20]
    macs = sorted({value.lower() for key, value in values.items() if VMX_MAC_KEY.match(key) and value})[:20]
    details = vm_details(path, root, product="vmware", product_label="VMware", source_kind="vmx", source_label="VMware 구성(.vmx)")
    details.update(
        {
            "vm_name": values.get("displayname", ""),
            "guest_os": values.get("guestos", ""),
            "vm_config_path": str(path.resolve()),
            "disk_paths": disks,
            "mac_addresses": macs,
            "mac_address": macs[0] if macs else "",
            "hardware_version": values.get("virtualhw.version", ""),
            "vm_uuid": values.get("uuid.bios", ""),
            "encrypted": "encryption.keysafe" in values or "encryption.data" in values,
            "shared_folders": sorted({value for key, value in values.items() if key.startswith("sharedfolder") and key.endswith(".hostpath")})[:20],
            "raw_preview": f"{values.get('displayname', path.stem)} ({values.get('guestos', '-')})",
            "evidence_note": "가상 머신 구성 파일입니다. 디스크(.vmdk)·MAC·공유 폴더로 호스트와의 파일 교환 흔적을 확인하십시오.",
        }
    )
    yield make_record(provider, "vm-config", path, details)


def vmware_mru_records(path: Path, provider: str, root: Path) -> Iterable[ArtifactRecord]:
    grouped: dict[int, dict[str, str]] = {}
    for key, value in parse_vmx_text(read_text(path)).items():
        match = VMWARE_MRU_KEY.match(key)
        if match:
            grouped.setdefault(int(match.group("index")), {})[match.group("field").lower()] = value
    for index, item in sorted(grouped.items()):
        details = vm_details(path, root, product="vmware", product_label="VMware", source_kind="vmware-mru", source_label="VMware 최근 VM(preferences.ini)")
        details.update(
            {
                "vm_name": item.get("displayname", ""),
                "vm_config_path": item.get("filename", ""),
                "mru_position": index,
                "raw_preview": f"MRU {index}: {item.get('displayname', '')} {item.get('filename', '')}".strip(),
            }
        )
        yield make_record(provider, "vm-config", path, details)


def vmware_inventory_records(path: Path, provider: str, root: Path) -> Iterable[ArtifactRecord]:
    grouped: dict[int, dict[str, str]] = {}
    for key, value in parse_vmx_text(read_text(path)).items():
        match = VMLS_KEY.match(key)
        if match:
            grouped.setdefault(int(match.group("index")), {})[match.group("field").lower()] = value
    for index, item in sorted(grouped.items()):
        if not item.get("config"):
            continue
        details = vm_details(path, root, product="vmware", product_label="VMware", source_kind="vmware-inventory", source_label="VMware 라이브러리(inventory.vmls)")
        details.update(
            {
                "vm_name": item.get("displayname", ""),
                "vm_config_path": item.get("config", ""),
                "inventory_index": index,
                "raw_preview": f"{item.get('displayname', '')} {item.get('config', '')}".strip(),
            }
        )
        yield make_record(provider, "vm-config", path, details)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_root(path: Path) -> ET.Element:
    from ...core.safe_xml import safe_xml_fromstring

    return safe_xml_fromstring(read_prefix(path, MAX_CONFIG_BYTES))


def virtualbox_registry_records(path: Path, provider: str, root: Path) -> Iterable[ArtifactRecord]:
    document = _xml_root(path)
    for element in document.iter():
        if _local(element.tag) != "MachineEntry":
            continue
        details = vm_details(path, root, product="virtualbox", product_label="VirtualBox", source_kind="virtualbox-registry", source_label="VirtualBox 등록 VM(VirtualBox.xml)")
        source = element.get("src", "")
        details.update(
            {
                "vm_name": Path(source.replace("\\", "/")).stem if source else "",
                "vm_config_path": source,
                "vm_uuid": element.get("uuid", "").strip("{}"),
                "raw_preview": f"VirtualBox {source}",
            }
        )
        yield make_record(provider, "vm-config", path, details)


def vbox_records(path: Path, provider: str, root: Path) -> Iterable[ArtifactRecord]:
    document = _xml_root(path)
    machine = next((element for element in document.iter() if _local(element.tag) == "Machine"), None)
    if machine is None:
        return
    disks = sorted({element.get("location", "") for element in document.iter() if _local(element.tag) == "HardDisk" and element.get("location")})[:20]
    macs = sorted(
        {_format_mac(element.get("MACAddress", "")) for element in document.iter() if _local(element.tag) == "Adapter" and element.get("MACAddress")}
    )[:20]
    shared = sorted({element.get("hostPath", "") for element in document.iter() if _local(element.tag) == "SharedFolder" and element.get("hostPath")})[:20]
    last_change = machine.get("lastStateChange", "")
    details = vm_details(path, root, product="virtualbox", product_label="VirtualBox", source_kind="vbox", source_label="VirtualBox 구성(.vbox)")
    details.update(
        {
            "vm_name": machine.get("name", ""),
            "guest_os": machine.get("OSType", ""),
            "vm_uuid": machine.get("uuid", "").strip("{}"),
            "vm_config_path": str(path.resolve()),
            "disk_paths": disks,
            "mac_addresses": macs,
            "mac_address": macs[0] if macs else "",
            "shared_folders": shared,
            "snapshot_count": sum(1 for element in document.iter() if _local(element.tag) == "Snapshot"),
            "last_state_change_at": last_change,
            "timestamp": last_change,
            "timestamp_kind": "last-updated" if last_change else "",
            "raw_preview": f"{machine.get('name', '')} ({machine.get('OSType', '-')}) 마지막 상태 변경 {last_change or '-'}",
        }
    )
    yield make_record(provider, "vm-config", path, details)


def _format_mac(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    return ":".join(cleaned[index : index + 2] for index in range(0, 12, 2)).lower() if len(cleaned) == 12 else value


def vmcx_record(path: Path, provider: str, root: Path) -> ArtifactRecord:
    details = vm_details(path, root, product="hyper-v", product_label="Hyper-V", source_kind="vmcx", source_label="Hyper-V 구성(.vmcx, 존재만)")
    details.update(
        {
            "recovery_method": "inventory",
            "vm_uuid": path.stem if _is_guid(path.stem) else "",
            "vm_config_path": str(path.resolve()),
            "vm_name": "",
            "raw_preview": f"Hyper-V {path.name}",
            "evidence_note": "VMCX는 이진 형식이라 이름·디스크는 해석하지 않습니다(존재·GUID·크기만).",
        }
    )
    return make_record(provider, "vm-config", path, details)


# --- Crypto wallets ------------------------------------------------------------------


def _wallet_details(path: Path, root: Path, *, product: str, product_label: str, wallet_kind: str) -> dict[str, object]:
    details = base_details(path, source_format="crypto-wallet", recovery_method="inventory", hashes=False)
    details.update(
        {
            "user": user_of(path, root),
            "wallet_product": product,
            "wallet_product_label": product_label,
            "wallet_kind": wallet_kind,
            "wallet_kind_label": {"desktop": "데스크톱 지갑", "browser-extension": "브라우저 확장 지갑", "file": "지갑 파일"}.get(wallet_kind, wallet_kind),
            "wallet_path": str(path.resolve()),
            "secret_values_stored": False,
            "label": f"암호화폐 지갑 존재({product_label})",
            "evidence_note": "정책상 개인키·시드·xprv·키스토어 내용은 읽거나 저장하지 않습니다. 존재·위치·크기·형식·암호화 표시(평문 Electrum은 공개 주소)만 기록합니다.",
        }
    )
    return details


def _dir_summary(path: Path) -> dict[str, object]:
    files = []
    for index, item in enumerate(iter_evidence_paths(path, "*")):
        if index >= MAX_DIR_FILES:
            break
        if item.is_file():
            files.append(item)
    times = []
    for item in files:
        try:
            times.append(item.stat().st_mtime)
        except OSError:
            continue
    newest = max(times, default=None)
    return {
        "file_count": len(files),
        "total_size": sum(file_size(item) or 0 for item in files),
        "file_names": sorted(item.name for item in files)[:30],
        "source_file_mtime": isoformat_from_timestamp(newest) or "" if newest else "",
    }


def wallet_db_format(head: bytes) -> str:
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if len(head) >= 16 and int.from_bytes(head[12:16], "little") == BDB_BTREE_MAGIC:
        return "berkeley-db"
    return "unknown"


def wallet_dat_record(path: Path, provider: str, root: Path, *, product: tuple[str, str]) -> ArtifactRecord | None:
    head = read_prefix(path, 16)
    db_format = wallet_db_format(head)
    if db_format == "unknown" and path.name.lower() == "wallet.dat" and len(head) < 16:
        return None
    # ``mkey`` (master key record) present = wallet passphrase set; only the flag is kept.
    scan = read_prefix(path, WALLET_MKEY_SCAN_BYTES) if db_format != "unknown" else b""
    details = _wallet_details(path, root, product=product[0], product_label=product[1], wallet_kind="file")
    details.update(
        {
            "wallet_format": db_format,
            "encrypted": (b"mkey" in scan) if scan else None,
            "file_count": 1,
            "total_size": file_size(path),
            "source_file_mtime": file_mtime(path),
            "raw_preview": f"{product[1]} {path.name} {db_format} {file_size(path) or 0} bytes",
        }
    )
    return make_record(provider, "crypto-wallet-presence", path, details)


def electrum_wallet_record(path: Path, provider: str, root: Path, product: tuple[str, str]) -> ArtifactRecord:
    size = file_size(path) or 0
    head = read_prefix(path, min(size, MAX_JSON_BYTES)) if size <= MAX_JSON_BYTES else b""
    details = _wallet_details(path, root, product=product[0], product_label=product[1], wallet_kind="desktop")
    addresses: list[str] = []
    info: dict[str, object] = {"wallet_format": "unknown", "encrypted": None}
    stripped = head.lstrip()
    if stripped.startswith(b"{"):
        try:
            document = json.loads(stripped.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            document = None
            info = {"wallet_format": "electrum-json", "encrypted": None, "parse_status": "invalid-json"}
        if isinstance(document, Mapping):
            addresses = electrum_public_addresses(document)
            info = {
                "wallet_format": "electrum-json",
                "encrypted": bool(document.get("use_encryption")),
                "electrum_wallet_type": str(document.get("wallet_type") or "")[:40],
                "electrum_seed_version": document.get("seed_version") if isinstance(document.get("seed_version"), int) else None,
            }
    elif stripped.startswith(b"QklFMQ"):
        info = {"wallet_format": "electrum-encrypted", "encrypted": True}
    details.update(
        {
            **info,
            "public_address_count": len(addresses),
            "public_addresses": addresses[:MAX_PUBLIC_ADDRESSES],
            "file_count": 1,
            "total_size": size,
            "source_file_mtime": file_mtime(path),
            "raw_preview": f"{product[1]} {path.name} {info.get('wallet_format')} 공개 주소 {len(addresses)}개",
        }
    )
    return make_record(provider, "crypto-wallet-presence", path, details)


def electrum_public_addresses(document: Mapping[str, object]) -> list[str]:
    """Receiving/change addresses of an Electrum JSON wallet (``addresses`` only; ``keystore`` never read)."""
    found: list[str] = []
    addresses = document.get("addresses")
    if isinstance(addresses, Mapping):
        for key in ("receiving", "change"):
            value = addresses.get(key)
            if isinstance(value, list):
                found.extend(item for item in value if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9]{25,90}", item))
        if not found:  # imported-address wallets: {address: {...}}
            found.extend(key for key in addresses if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9]{25,90}", key))
    seen: list[str] = []
    for item in found:
        if item not in seen:
            seen.append(item)
    return seen


def collect_wallets_in_homes(root: Path, provider: str, handled: set[str]) -> Iterable[ArtifactRecord]:
    for home in iter_windows_user_homes(root):
        roaming_bitcoin = home.joinpath(*APPDATA_ROAMING, "Bitcoin", "wallet.dat")
        if roaming_bitcoin.is_file():
            handled.add(str(roaming_bitcoin.resolve()).casefold())
            record = wallet_dat_record(roaming_bitcoin, provider, root, product=("bitcoin-core", "Bitcoin Core"))
            if record is not None:
                yield record
        for product, label, parts, entry in DESKTOP_WALLETS:
            target = home.joinpath(*parts)
            if entry == "file":
                if target.is_file():
                    details = _wallet_details(target, root, product=product, product_label=label, wallet_kind="desktop")
                    details.update({"file_count": 1, "total_size": file_size(target), "source_file_mtime": file_mtime(target), "raw_preview": f"{label} {target.name}"})
                    yield make_record(provider, "crypto-wallet-presence", target, details)
                continue
            if not target.is_dir():
                continue
            if entry == "electrum-dir":
                for path in sorted(target.iterdir(), key=lambda item: item.name.lower())[:MAX_DIR_FILES]:
                    if path.is_file():
                        yield electrum_wallet_record(path, provider, root, (product, label))
            elif product == "bitcoin-core":
                for path in sorted(target.rglob("wallet.dat"), key=lambda item: str(item).lower())[:MAX_DIR_FILES]:
                    handled.add(str(path.resolve()).casefold())
                    record = wallet_dat_record(path, provider, root, product=(product, f"{label}({path.parent.name})"))
                    if record is not None:
                        yield record
            else:
                details = _wallet_details(target, root, product=product, product_label=label, wallet_kind="desktop")
                summary = _dir_summary(target)
                if entry == "keystore-dir":
                    details["public_addresses"] = sorted(
                        {"0x" + match.group("address").lower() for name in summary["file_names"] if (match := ETH_KEYSTORE_ADDRESS.search(str(name)))}  # type: ignore[union-attr]
                    )[:MAX_PUBLIC_ADDRESSES]
                    details["public_address_count"] = len(details["public_addresses"])  # type: ignore[arg-type]
                details.update({**summary, "raw_preview": f"{label} {target.name} 파일 {summary['file_count']}개"})
                yield make_record(provider, "crypto-wallet-presence", target, details)


def wallet_extension_record(
    path: Path, provider: str, root: Path, container: str, seen: set[str], *, extension_id: str = ""
) -> Iterable[ArtifactRecord]:
    ext_id = extension_id or path.name.lower()
    product, label = WALLET_EXTENSIONS[ext_id]
    profile_dir = path.parent.parent
    key = f"{str(profile_dir).lower()}|{ext_id}|{container}"
    if key in seen:
        return
    seen.add(key)
    details = _wallet_details(path, root, product=product, product_label=label, wallet_kind="browser-extension")
    summary = _dir_summary(path)
    details.update(
        {
            "extension_id": ext_id,
            "extension_store_url": f"https://chromewebstore.google.com/detail/{ext_id}",
            "extension_container": container,
            "browser_profile": profile_dir.name,
            "browser_user_data": str(profile_dir.parent),
            **summary,
            "raw_preview": f"{label} 확장 {ext_id} ({profile_dir.name}, {container})",
        }
    )
    yield make_record(provider, "crypto-wallet-presence", path, details)


# --- McAfee logs -------------------------------------------------------------------


def av_time_text(match: re.Match[str]) -> str:
    date = match.group("date")
    if "/" in date:
        month, day, year = (int(part) for part in date.split("/"))
        if month > 12 and day <= 12:  # DD/MM/YYYY
            month, day = day, month
    else:
        year, month, day = (int(part) for part in date.split("-"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    ampm = (match.group("ampm") or "").lower()
    if ampm in {"pm", "오후"} and hour < 12:
        hour += 12
    elif ampm in {"am", "오전"} and hour == 12:
        hour = 0
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 61):
        return ""
    stamp = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"
    fraction = match.group("fraction")
    return f"{stamp}.{fraction[:6]}" if fraction else stamp


def mcafee_log_records(path: Path, provider: str) -> Iterable[ArtifactRecord]:
    product = "mcafee-ens" if path.name.lower().endswith("_activity.log") else "mcafee-virusscan"
    product_label = "McAfee Endpoint Security" if product == "mcafee-ens" else "McAfee VirusScan Enterprise"
    hashes = sha256_of(path)
    log_name = path.name
    text_value = decode_text(read_prefix(path, MAX_LOG_BYTES))
    for number, raw in iter_lines(text_value, MAX_LOG_LINES):
        line = raw.strip()
        lowered = line.lower()
        if not line or not any(term in lowered for term in AV_DETECTION_TERMS) or AV_NEGATIVE.search(line):
            continue
        match = AV_TIME.match(line)
        if not match:
            continue
        stamp = av_time_text(match)
        rest = line[match.end() :].strip()
        fields = [field.strip() for field in rest.split("\t")] if "\t" in rest else []
        action, action_label = next(((code, label) for term, code, label in AV_ACTIONS if term in lowered), ("", ""))
        paths = [field for field in fields if WINDOWS_PATH.match(field)] if fields else TEXT_PATH.findall(rest)
        threat = ""
        for pattern in AV_THREAT_PATTERNS:
            found = pattern.search(rest)
            if found:
                threat = found.group("threat").strip()
                break
        if not threat and len(fields) >= 5:
            threat = next((field for field in reversed(fields) if field and not WINDOWS_PATH.match(field)), "")
        user_match = AV_USER.search(rest)
        user = (user_match.group("angle") or user_match.group("domain") or "") if user_match else ""
        details = base_details(path, source_format="mcafee-log", hashes=False)
        details.update(
            {
                "source_hashes": hashes,
                "source_offset": number,
                "source_offset_unit": "line",
                "av_product": product,
                "av_product_label": product_label,
                "log_name": log_name,
                "detected_at": stamp,
                "action": action,
                "action_label": action_label,
                "threat_name": threat[:200],
                "object_path": paths[-1] if paths else "",
                "process_path": paths[0] if len(paths) > 1 else "",
                "account": user[:130],
                "message": line[:1000],
                "field_extraction": "tab-separated" if fields else "heuristic",
                "timestamp": stamp,
                "timestamp_kind": "event" if stamp else "",
                "timestamp_timezone": "local-unknown" if stamp else "",
                "label": f"백신 탐지 로그({product_label})",
                "risk_flags": ["av-detection"],
                "evidence_note": "로그 시각은 현지 시각(시간대 표시 없음)입니다. 위협명·경로는 줄 텍스트에서 찾은 값이므로 원문(message)과 함께 확인하십시오.",
                "raw_preview": line[:500],
            }
        )
        yield make_record(provider, "av-detection-log", path, details)


# ---------------------------------------------------------------------------
# NTFS volume information ($Boot VBR + $MFT record 3 = $Volume)
# ---------------------------------------------------------------------------


# Run output folders whose ``ntfs-meta`` analyses extracted ``$Boot`` / ``$MFT`` (R6 S2):
# ``<root>/rapidtriage-run*/analyses/<id>/ntfs/`` (a folder run; the evidence walk itself prunes
# run outputs) and ``<run output>/analyses/<id>/ntfs/`` when ``root`` lies inside a run output
# folder (an E01 run's extraction root, e.g. ``<output>/<stage>/fs``). R6 S2 review: only the
# output folder of a run active in this process counts (``core.files.register_run_output_dir``);
# a ``rapidtriage-run*`` folder planted in the evidence is never read as the tool's own output.
ANALYSIS_NTFS_GLOB = ("analyses", "*", "ntfs")
ANALYSIS_BOOT_NAMES = ("$Boot", "Boot.bin", "$Boot.bin")
ANALYSIS_MFT_NAMES = ("MFT.bin", "$MFT")
MAX_ANALYSIS_NTFS_FOLDERS = 64
RUN_OUTPUT_MARKERS = ("rapidtriage-run-summary.json", "rapidtriage-run-plan.json")
RUN_OUTPUT_ANCESTOR_LEVELS = 3


def _run_output_folders(root: Path) -> list[Path]:
    runs: list[Path] = []
    try:
        runs.extend(
            sorted(
                (item for item in root.iterdir() if item.name.startswith(RUN_OUTPUT_DIR_PREFIX) and item.is_dir() and not item.is_symlink()),
                key=lambda item: item.name.lower(),
            )
        )
    except OSError:
        pass
    for ancestor in [root, *list(root.parents)[:RUN_OUTPUT_ANCESTOR_LEVELS]]:
        if ancestor not in runs and any((ancestor / marker).is_file() for marker in RUN_OUTPUT_MARKERS):
            runs.append(ancestor)
    return [run for run in runs if is_active_run_output_dir(run)]


def analysis_ntfs_folders(root: Path) -> list[tuple[Path, dict[str, Path]]]:
    """``ntfs-meta`` extraction folders of the run output folders inside or above ``root``."""
    found: list[tuple[Path, dict[str, Path]]] = []
    for run in _run_output_folders(root):
        for folder in sorted(run.glob("/".join(ANALYSIS_NTFS_GLOB)), key=lambda item: str(item).lower()):
            if len(found) >= MAX_ANALYSIS_NTFS_FOLDERS:
                return found
            if not folder.is_dir() or folder.is_symlink():
                continue
            members: dict[str, Path] = {}
            for key, names in (("$boot", ANALYSIS_BOOT_NAMES), ("$mft", ANALYSIS_MFT_NAMES)):
                match = next((folder / name for name in names if (folder / name).is_file()), None)
                if match is not None:
                    members[key] = match
            if members:
                found.append((folder, members))
    return found


def collect_ntfs_volume_information(root: Path, provider: str) -> Iterable[ArtifactRecord]:
    """One row per folder holding ``$Boot`` and/or ``$MFT`` (record 3 = ``$Volume``).

    Also reads the ``ntfs/`` folders of ``ntfs-meta`` analyses in this root's run output
    folders (``$Boot`` extracted from an image, R6 S2), so the volume serial of an E01 meets the
    LNK volume serials in 통합 보기 from the next run on; one row per distinct volume serial."""
    folders: dict[Path, dict[str, Path]] = {}
    for path in iter_evidence_paths(root, "*"):
        name = path.name.lower()
        if name in {"$boot", "$mft"} and path.is_file():
            folders.setdefault(path.parent, {})[name] = path
    analysis_folders = dict(analysis_ntfs_folders(root)) if root.is_dir() else {}
    seen_serials: set[str] = set()
    for folder in [
        *sorted(folders, key=lambda item: str(item).lower()),
        *(folder for folder in analysis_folders if folder not in folders),
    ]:
        from_analysis = folder in analysis_folders and folder not in folders
        members = analysis_folders[folder] if from_analysis else folders[folder]
        boot_path = members.get("$boot")
        mft_path = members.get("$mft")
        fields = read_volume_information(boot_path, mft_path)
        if fields.get("vbr_parse_status") not in (None, "parsed") and fields.get("volume_record_status") != "parsed":
            continue  # neither part decoded: not an NTFS metadata folder
        serial = str(fields.get("volume_serial_number_64") or "")
        if from_analysis and (not serial or serial in seen_serials):
            continue  # an analysis folder adds a volume serial the evidence tree has not shown
        if serial:
            seen_serials.add(serial)
        primary = boot_path or mft_path
        if primary is None:
            continue
        details = base_details(primary, source_format="ntfs-metadata", hashes=False)
        details.update(
            {
                "source_hashes": sha256_of(boot_path) if boot_path is not None else {},
                "boot_source_path": str(boot_path.resolve()) if boot_path is not None else "",
                "mft_source_path": str(mft_path.resolve()) if mft_path is not None else "",
                "volume_record_number": 3 if mft_path is not None else None,
                **fields,
                **({"volume_source": "ntfs-meta-analysis", "analysis_id": folder.parent.name} if from_analysis else {}),
                "source_offset": 0,
                "label": "NTFS 볼륨 정보",
                "evidence_note": "볼륨 일련번호(VSN)는 LNK·Prefetch·이벤트 1006의 볼륨 시리얼과 같은 값(하위 4바이트)입니다. 8바이트 전체는 volume_serial_number_64.",
                "raw_preview": f"{fields.get('volume_label') or '-'} VSN {fields.get('volume_serial_display') or '-'} NTFS {fields.get('ntfs_version') or '-'}",
            }
        )
        if fields.get("volume_dirty"):
            details["risk_flags"] = ["ntfs-volume-dirty"]
        yield make_record(provider, "ntfs-volume-information", primary, details)
