from __future__ import annotations

import datetime as dt
import hashlib
import re
from pathlib import Path
from typing import Iterable

from ...core.models import ArtifactRecord

PARSER_VERSION = "windows-os-account-v1"
USER_PROFILE_ROOT = "Users"
REGISTRY_EXPORT_EXT = ".reg"
ACCOUNT_HINT_KEYS = (
    "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "ControlSet001\\Control\\ComputerName",
    "ControlSet001\\Control\\TimeZoneInformation",
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
            "raw_preview": text[:2000],
        }
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-os-account-summary",
            path=str(path.resolve()),
            supported=True,
            details=details,
        )


def parse_registry_hints(text: str) -> dict[str, set[str]]:
    hints = {
        "computer_names": set(),
        "time_zones": set(),
        "profile_sids": set(),
        "admin_group_hints": set(),
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
    return hints


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
    return name, value


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
