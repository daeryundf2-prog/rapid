from __future__ import annotations

import datetime as dt
import hashlib
import re
from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord

PARSER_VERSION = "windows-os-account-v2"
USER_PROFILE_ROOT = "Users"
REGISTRY_EXPORT_EXT = ".reg"
ACCOUNT_HINT_KEYS = (
    "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "ControlSet001\\Control\\ComputerName",
    "ControlSet001\\Control\\TimeZoneInformation",
    "ControlSet001\\Control\\Windows",
    "LastBootUpTime",
    "ShutdownTime",
    "SAM\\Domains\\Account\\Users",
)


class WindowsOsAccountProvider:
    name = "windows-os-account"
    collector_kind = "windows-os-account"
    description = "Windows OS and account summary artifacts"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield from collect_user_profiles(root)
        yield from collect_registry_export_hints(root)


def collect_user_profiles(root: Path) -> Iterable[ArtifactRecord]:
    users_root = root / USER_PROFILE_ROOT
    if not users_root.is_dir():
        return
    ignored = {"all users", "default", "default user", "public", "desktop.ini"}
    for path in sorted(users_root.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_dir() or path.name.lower() in ignored:
            continue
        stat_result = path.stat()
        ntuser = path / "NTUSER.DAT"
        usrclass = path / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
        details = {
            "parser": "windows-user-profile-inventory",
            "parser_version": PARSER_VERSION,
            "coverage_status": "parsed",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "user_name": path.name,
            "profile_path": str(path.resolve()),
            "profile_modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat(),
            "ntuser_dat_present": ntuser.is_file(),
            "usrclass_dat_present": usrclass.is_file(),
            "ntuser_dat_hashes": file_hashes(ntuser) if ntuser.is_file() else {},
            "usrclass_dat_hashes": file_hashes(usrclass) if usrclass.is_file() else {},
            "account_type_hint": account_type_hint(path.name),
        }
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-user-profile",
            path=str(path.resolve()),
            supported=True,
            details=details,
        )


def collect_registry_export_hints(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob(f"*{REGISTRY_EXPORT_EXT}"), key=lambda item: str(item).lower()):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        text = decode_reg_export(raw)
        if not any(hint.lower() in text.lower() for hint in ACCOUNT_HINT_KEYS):
            continue
        hints = parse_registry_hints(text)
        if not any(hints.values()):
            continue
        details = {
            "parser": "windows-os-account-reg-export",
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "source_hashes": file_hashes(path),
            "computer_names": sorted(hints["computer_names"]),
            "time_zones": sorted(hints["time_zones"]),
            "profile_sids": sorted(hints["profile_sids"]),
            "admin_group_hints": sorted(hints["admin_group_hints"]),
            "last_boot_times": sorted(hints["last_boot_times"]),
            "shutdown_times": sorted(hints["shutdown_times"]),
            "account_lifecycle_hints": sorted(
                hints["account_lifecycle_hints"].values(),
                key=lambda item: (str(item.get("user_name") or ""), str(item.get("rid") or "")),
            ),
            "raw_preview": text[:2000],
        }
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-os-account-summary",
            path=str(path.resolve()),
            supported=True,
            details=details,
        )


def parse_registry_hints(text: str) -> dict[str, object]:
    hints = {
        "computer_names": set(),
        "time_zones": set(),
        "profile_sids": set(),
        "admin_group_hints": set(),
        "last_boot_times": set(),
        "shutdown_times": set(),
        "account_lifecycle_hints": {},
    }
    current_key = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current_key = line.strip("[]")
            sid_match = re.search(r"ProfileList\\([^\\\]]+)$", current_key, flags=re.IGNORECASE)
            if sid_match:
                hints["profile_sids"].add(sid_match.group(1))
            if "Administrators" in current_key or current_key.endswith("\\00000220"):
                hints["admin_group_hints"].add(current_key)
            account_name = account_name_from_key(current_key)
            if account_name:
                account_hint_for_key(hints, current_key)["user_name"] = account_name
            continue
        name, value = parse_reg_value(line)
        if not name:
            continue
        lowered_key = current_key.lower()
        lowered_name = name.lower()
        if lowered_name in {"computername", "hostname"}:
            hints["computer_names"].add(value)
        elif lowered_name in {"timezonekeyname", "standardname", "daylightname"}:
            hints["time_zones"].add(value)
        elif "profilelist" in lowered_key and lowered_name == "profileimagepath":
            hints["profile_sids"].add(value)
        elif "administrators" in lowered_key:
            hints["admin_group_hints"].add(f"{name}={value}")
        elif lowered_name in {"lastbootuptime", "lastboottime", "systemboottime"}:
            parsed = parse_timestamp_value(value)
            if parsed:
                hints["last_boot_times"].add(parsed)
        elif lowered_name in {"shutdowntime", "lastshutdowntime"}:
            parsed = parse_timestamp_value(value)
            if parsed:
                hints["shutdown_times"].add(parsed)
        if is_account_lifecycle_key(current_key):
            add_account_lifecycle_value(hints, current_key, name, value)
    return hints


def account_name_from_key(key: str) -> str:
    match = re.search(r"\\Users\\Names\\([^\\\]]+)$", key, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def account_rid_from_key(key: str) -> str:
    match = re.search(r"\\Users\\([0-9a-fA-F]{8})$", key)
    return match.group(1).upper() if match else ""


def is_account_lifecycle_key(key: str) -> bool:
    lowered = key.lower()
    return "\\sam\\domains\\account\\users\\" in lowered or "\\microsoft\\windows nt\\currentversion\\profilelist\\" in lowered


def account_hint_for_key(hints: dict[str, object], key: str) -> dict[str, object]:
    account_hints = hints["account_lifecycle_hints"]
    if not isinstance(account_hints, dict):
        return {}
    account_key = account_name_from_key(key) or account_rid_from_key(key) or key
    hint = account_hints.setdefault(
        account_key,
        {
            "key": key,
            "rid": account_rid_from_key(key),
            "user_name": account_name_from_key(key),
            "profile_path": "",
            "created_at": "",
            "last_logon_at": "",
            "password_last_set_at": "",
            "account_disabled_hint": False,
            "admin_hint": False,
            "raw_fields": {},
        },
    )
    return hint if isinstance(hint, dict) else {}


def add_account_lifecycle_value(hints: dict[str, object], key: str, name: str, value: str) -> None:
    hint = account_hint_for_key(hints, key)
    if not hint:
        return
    raw_fields = hint.setdefault("raw_fields", {})
    if isinstance(raw_fields, dict):
        raw_fields[name] = value
    lowered_name = name.lower()
    if lowered_name in {"username", "name", "accountname"} and value:
        hint["user_name"] = value
    elif lowered_name == "profileimagepath":
        hint["profile_path"] = value
    elif "created" in lowered_name:
        hint["created_at"] = parse_timestamp_value(value)
    elif lowered_name in {"lastlogin", "lastlogon", "lastlogontimestamp"}:
        hint["last_logon_at"] = parse_timestamp_value(value)
    elif lowered_name in {"passwordlastset", "pwdlastset"}:
        hint["password_last_set_at"] = parse_timestamp_value(value)
    elif lowered_name in {"disabled", "accountdisabled"}:
        hint["account_disabled_hint"] = value.lower() in {"1", "true", "yes", "disabled"}
    elif lowered_name in {"admincount", "isadministrator", "administrator"}:
        hint["admin_hint"] = value.lower() not in {"", "0", "false", "no"}
    elif lowered_name in {"useraccountcontrol", "uac"}:
        number = parse_int(value)
        if number is not None:
            hint["account_disabled_hint"] = bool(number & 0x2)


def decode_reg_export(raw: bytes) -> str:
    for encoding in ("utf-16", "utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("latin-1", errors="ignore")


def parse_reg_value(line: str) -> tuple[str, str]:
    if "=" not in line:
        return "", ""
    raw_name, raw_value = line.split("=", 1)
    name = raw_name.strip().strip('"')
    value = raw_value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    elif value.lower().startswith("hex(2):"):
        value = decode_reg_expand_sz(value[7:])
    elif value.lower().startswith("dword:"):
        parsed = parse_int(value)
        value = str(parsed) if parsed is not None else value
    return name, value


def parse_timestamp_value(value: str) -> str:
    text = value.strip().strip('"')
    if not text:
        return ""
    if re.match(r"^\d{4}-\d\d-\d\d[T ]", text):
        return text.replace("Z", "+00:00")
    wmi_match = re.match(r"^(\d{14})\.", text)
    if wmi_match:
        try:
            parsed = dt.datetime.strptime(wmi_match.group(1), "%Y%m%d%H%M%S")
        except ValueError:
            return ""
        return parsed.replace(tzinfo=dt.timezone.utc).isoformat()
    if text.lower().startswith("hex(b):"):
        raw = parse_hex_bytes(text[7:])
        if len(raw) >= 8:
            return filetime_to_iso(int.from_bytes(raw[:8], "little", signed=False))
    number = parse_int(text)
    if number is None:
        return ""
    if number > 10_000_000_000_000_000:
        return filetime_to_iso(number)
    if number > 1_000_000_000:
        try:
            return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return ""
    return ""


def parse_int(value: str) -> int | None:
    text = value.strip().strip('"')
    if text.lower().startswith("dword:"):
        text = text.split(":", 1)[1]
        base = 16
    elif text.lower().startswith("0x"):
        base = 16
    else:
        base = 10
    try:
        return int(text, base)
    except ValueError:
        return None


def parse_hex_bytes(value: str) -> bytes:
    items = []
    for item in value.replace("\\", "").replace("\n", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            items.append(int(item, 16))
        except ValueError:
            return b""
    return bytes(items)


def filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        base = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        return (base + dt.timedelta(microseconds=value / 10)).isoformat()
    except (OverflowError, ValueError):
        return ""


def decode_reg_expand_sz(value: str) -> str:
    hex_bytes = []
    for item in value.replace("\\", "").replace("\n", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            hex_bytes.append(int(item, 16))
        except ValueError:
            return value
    try:
        return bytes(hex_bytes).decode("utf-16le", errors="ignore").rstrip("\x00")
    except UnicodeError:
        return value


def account_type_hint(user_name: str) -> str:
    lowered = user_name.lower()
    if lowered.endswith("$"):
        return "machine-account"
    if lowered in {"administrator", "admin"}:
        return "admin-name-hint"
    if lowered in {"defaultaccount", "guest", "wdagutilityaccount"}:
        return "built-in"
    return "user-profile"


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}
