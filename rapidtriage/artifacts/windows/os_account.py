from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review
from .registry import MAX_HIVE_CELL_SCAN_BYTES, iter_registry_cell_candidates, parse_registry_hive_header

PARSER_VERSION = "windows-os-account-v9"
USER_PROFILE_ROOT = "Users"
REGISTRY_EXPORT_EXT = ".reg"
SAM_HIVE_NAME = "SAM"
SAM_V_DATA_BASE_OFFSET = 0xCC
SAM_V_STRING_LAYOUT = (
    ("user_name", 0x0C),
    ("full_name", 0x18),
    ("comment", 0x24),
    ("user_comment", 0x30),
    ("home_directory", 0x3C),
    ("home_drive", 0x48),
    ("logon_script", 0x54),
    ("profile_path", 0x60),
    ("workstations", 0x6C),
)
SAM_BUILTIN_KEY_NAMES = {"SAM", "Domains", "Account", "Users", "Names", "Builtin", "Aliases", "Groups"}
SAM_COMMON_GROUP_NAMES = {
    "account operators",
    "administrators",
    "backup operators",
    "domain admins",
    "enterprise admins",
    "event log readers",
    "guests",
    "power users",
    "remote desktop users",
    "users",
}
SAM_BUILTIN_GROUP_RIDS = {
    "00000220": "Administrators",
    "00000221": "Users",
    "00000222": "Guests",
    "00000223": "Power Users",
    "00000227": "Backup Operators",
    "0000022F": "Remote Desktop Users",
    "0000023D": "Event Log Readers",
}
SAM_BUILTIN_GROUP_SIDS = {
    "Administrators": "S-1-5-32-544",
    "Users": "S-1-5-32-545",
    "Guests": "S-1-5-32-546",
    "Power Users": "S-1-5-32-547",
    "Backup Operators": "S-1-5-32-551",
    "Remote Desktop Users": "S-1-5-32-555",
    "Event Log Readers": "S-1-5-32-573",
}
BUILTIN_SID_NAMES = {sid: name for name, sid in SAM_BUILTIN_GROUP_SIDS.items()}
ACCOUNT_HINT_KEYS = (
    "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "SYSTEM\\Select",
    "ControlSet001\\Control\\ComputerName",
    "ControlSet001\\Control\\TimeZoneInformation",
    "ControlSet001\\Control\\Windows",
    "CurrentControlSet\\Services",
    "CurrentControlSet\\Enum\\USBSTOR",
    "CurrentControlSet\\MountedDevices",
    "Policy\\Secrets",
    "Privilege Rights",
    "SAM\\Domains\\Builtin\\Aliases",
    "SAM\\Domains\\Builtin\\Aliases\\Names",
    "SAM\\Domains\\Account\\Groups\\Names",
    "LastBootUpTime",
    "ShutdownTime",
    "SAM\\Domains\\Account\\Users",
)
OS_ACCOUNT_NATIVE_CAPABILITIES = {
    "profile_inventory": True,
    "sam_key_candidate_scan": True,
    "sam_fv_export_field_decode": True,
    "account_lifecycle_export_mapping": True,
    "group_membership_export_mapping": True,
    "lsa_policy_location_inventory": True,
    "privilege_assignment_export_mapping": True,
    "security_secret_decryption": False,
    "native_sam_alias_member_binary_decode": False,
    "full_os_version_sam_fv_layout_validation": False,
    "domain_controller_context_resolution": False,
    "transaction_log_replay": False,
}
OS_ACCOUNT_REPORT_GRADE_BLOCKERS = [
    "sam-security-system-trusted-diff-required",
    "full-native-sam-fv-layout-validation-required",
    "native-sam-alias-member-binary-decoding-required",
    "security-secret-decryption-not-implemented",
    "domain-context-and-transaction-log-validation-required",
]
OS_ACCOUNT_TRUSTED_TOOL_HINTS = ("recmd", "registryexplorer", "regripper", "windowsapi", "samparser", "secretsdump")


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
        yield from collect_sam_hive_candidates(root)


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
        source_hashes = file_hashes(path)
        details = {
            "parser": "windows-os-account-reg-export",
            "parser_version": PARSER_VERSION,
            "coverage_status": "mapped",
            "reportability": "triage",
            "source_path": str(path.resolve()),
            "source_format": "reg",
            "source_hashes": source_hashes,
            "computer_names": sorted(hints["computer_names"]),
            "time_zones": sorted(hints["time_zones"]),
            "profile_sids": sorted(hints["profile_sids"]),
            "admin_group_hints": sorted(hints["admin_group_hints"]),
            "last_boot_times": sorted(hints["last_boot_times"]),
            "shutdown_times": sorted(hints["shutdown_times"]),
            "current_control_sets": sorted(hints["current_control_sets"]),
            "service_count": len(hints["services"]),
            "mounted_device_count": len(hints["mounted_devices"]),
            "lsa_secret_count": len(hints["lsa_policy_locations"]),
            "privilege_assignment_count": len(hints["privilege_assignments"]),
            "group_membership_hint_count": len(hints["group_memberships"]),
            "group_membership_hints": normalized_group_memberships(hints["group_memberships"]),
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
        for record in build_system_security_records(path, hints, source_hashes):
            yield record
        for record in build_account_lifecycle_records(path, hints, source_hashes):
            yield record


def collect_sam_hive_candidates(root: Path) -> Iterable[ArtifactRecord]:
    for path in candidate_sam_hive_paths(root):
        try:
            stat_result = path.stat()
            with path.open("rb") as handle:
                header = handle.read(4096)
                handle.seek(0)
                scan_blob = handle.read(min(stat_result.st_size, MAX_HIVE_CELL_SCAN_BYTES))
        except OSError:
            continue
        metadata = parse_registry_hive_header(header)
        if not metadata.get("regf_valid"):
            continue
        key_candidates = [item for item in iter_registry_cell_candidates(scan_blob) if item.get("cell_kind") == "key-node"]
        cell_candidates = [item for item in key_candidates if is_sam_account_key_name(str(item.get("name") or ""))]
        rid_candidates = [item for item in cell_candidates if is_rid_key_name(str(item.get("name") or ""))]
        group_candidates = [item for item in key_candidates if is_sam_group_key_name(str(item.get("name") or ""))]
        group_rid_candidates = [item for item in group_candidates if is_builtin_group_rid_key_name(str(item.get("name") or ""))]
        source_hashes = file_hashes(path)
        for candidate in cell_candidates:
            details = sam_account_candidate_details(path, candidate, rid_candidates, metadata, source_hashes)
            yield ArtifactRecord(
                provider=WindowsOsAccountProvider.name,
                artifact_type="windows-sam-account-candidate",
                path=str(path.resolve()),
                supported=True,
                details=details,
            )
        for candidate in group_candidates:
            details = sam_group_candidate_details(path, candidate, group_rid_candidates, metadata, source_hashes)
            yield ArtifactRecord(
                provider=WindowsOsAccountProvider.name,
                artifact_type="windows-sam-group-candidate",
                path=str(path.resolve()),
                supported=True,
                details=details,
            )


def candidate_sam_hive_paths(root: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.name.upper() != SAM_HIVE_NAME:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        yield path


def sam_account_candidate_details(
    path: Path,
    candidate: dict[str, object],
    rid_candidates: list[dict[str, object]],
    metadata: dict[str, object],
    source_hashes: dict[str, str],
) -> dict[str, object]:
    name = str(candidate.get("name") or "")
    rid_hex = name.upper() if is_rid_key_name(name) else ""
    nearby_rid = nearest_rid_candidate(candidate, rid_candidates) if not rid_hex else None
    if nearby_rid is not None:
        rid_hex = str(nearby_rid.get("name") or "").upper()
    user_name = "" if is_rid_key_name(name) else name
    risk_flags = sam_account_risk_flags(user_name, rid_hex, candidate)
    validation_checks = {
        "regf_header_valid": bool(metadata.get("regf_valid")),
        "has_user_name_candidate": bool(user_name),
        "has_rid_candidate": bool(rid_hex),
        "allocated_key_cell": candidate.get("allocation_status") == "allocated",
        "native_sam_fv_decoding_available": False,
        "requires_second_parser_validation": True,
    }
    report_grade = os_account_report_grade_assessment(
        os_account_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#6"],
        extra_blockers=["native-sam-account-fv-binary-decoding-required"],
    )
    core_accuracy_gates = os_account_core_accuracy_gates(
        {
            "source_path": str(path.resolve()),
            "source_hashes": dict(source_hashes),
            "cell_offset": candidate.get("cell_offset", 0),
            "user_name": user_name,
            "rid": rid_hex,
            "validation_checks": validation_checks,
            "uac_flags": [],
        }
    )
    return {
        "parser": "windows-sam-hive-native-account-scan",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-sam-key-candidate",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": "registry-hive-sam",
        "source_hashes": dict(source_hashes),
        "hive_name": path.name,
        "regf_valid": bool(metadata.get("regf_valid")),
        "hive_last_written_at": metadata.get("last_written_at", ""),
        "candidate_role": "rid-key" if is_rid_key_name(name) else "account-name-key",
        "user_name_candidate": user_name,
        "account_type_hint": account_type_hint(user_name) if user_name else "",
        "rid_hex": rid_hex,
        "rid_decimal": rid_decimal(rid_hex),
        "nearby_rid_cell_offset": nearby_rid.get("cell_offset", 0) if nearby_rid is not None else 0,
        "cell_offset": candidate.get("cell_offset", 0),
        "cell_size": candidate.get("cell_size", 0),
        "allocation_status": candidate.get("allocation_status", ""),
        "last_written_at": candidate.get("last_written_at", ""),
        "parser_confidence": 0.55 if user_name and rid_hex else 0.45,
        "evidence_strength": "sam-hive-key-candidate",
        "validation_required": True,
        "validation_checks": validation_checks,
        "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
        "os_account_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "os_account_native_capabilities": OS_ACCOUNT_NATIVE_CAPABILITIES,
        "account_privilege_deep_parse_profile": account_privilege_deep_parse_profile(
            artifact_scope="native-sam-account-key-candidate",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={
                "user_name_candidate": user_name,
                "rid_hex": rid_hex,
                "allocation_status": str(candidate.get("allocation_status") or ""),
            },
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "validation_guidance": "Native SAM rows identify account-name/RID key candidates only; validate full F/V account attributes with a dedicated SAM parser before final testimony.",
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 20 + (20 if user_name.lower() in {"administrator", "admin"} else 0)),
        "raw_preview": " ".join(part for part in [user_name, rid_hex] if part),
    }


def sam_group_candidate_details(
    path: Path,
    candidate: dict[str, object],
    group_rid_candidates: list[dict[str, object]],
    metadata: dict[str, object],
    source_hashes: dict[str, str],
) -> dict[str, object]:
    name = str(candidate.get("name") or "")
    alias_rid_hex = name.upper() if is_builtin_group_rid_key_name(name) else ""
    nearby_rid = nearest_rid_candidate(candidate, group_rid_candidates) if not alias_rid_hex else None
    if nearby_rid is not None:
        alias_rid_hex = str(nearby_rid.get("name") or "").upper()
    group_name = SAM_BUILTIN_GROUP_RIDS.get(alias_rid_hex, "") if is_builtin_group_rid_key_name(name) else name
    risk_flags = sam_group_risk_flags(group_name, alias_rid_hex, candidate)
    validation_checks = {
        "regf_header_valid": bool(metadata.get("regf_valid")),
        "has_group_name_candidate": bool(group_name),
        "has_builtin_alias_rid_candidate": bool(alias_rid_hex),
        "allocated_key_cell": candidate.get("allocation_status") == "allocated",
        "native_membership_reconstruction_available": False,
        "requires_sam_alias_member_binary_decoding": True,
    }
    report_grade = os_account_report_grade_assessment(
        os_account_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#6"],
        extra_blockers=["native-sam-alias-member-binary-decoding-required"],
    )
    core_accuracy_gates = os_account_core_accuracy_gates(
        {
            "source_path": str(path.resolve()),
            "source_hashes": dict(source_hashes),
            "cell_offset": candidate.get("cell_offset", 0),
            "group_name": group_name,
            "rid": alias_rid_hex,
            "validation_checks": validation_checks,
            "group_sid_candidates": [SAM_BUILTIN_GROUP_SIDS[group_name]]
            if group_name in SAM_BUILTIN_GROUP_SIDS
            else [],
        }
    )
    return {
        "parser": "windows-sam-hive-native-group-scan",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-sam-group-key-candidate",
        "reportability": "triage",
        "source_path": str(path.resolve()),
        "source_format": "registry-hive-sam",
        "source_hashes": dict(source_hashes),
        "hive_name": path.name,
        "regf_valid": bool(metadata.get("regf_valid")),
        "hive_last_written_at": metadata.get("last_written_at", ""),
        "candidate_role": "builtin-alias-rid-key" if is_builtin_group_rid_key_name(name) else "group-name-key",
        "group_name_candidate": group_name,
        "alias_rid_hex": alias_rid_hex,
        "alias_rid_decimal": rid_decimal(alias_rid_hex),
        "nearby_alias_rid_cell_offset": nearby_rid.get("cell_offset", 0) if nearby_rid is not None else 0,
        "cell_offset": candidate.get("cell_offset", 0),
        "cell_size": candidate.get("cell_size", 0),
        "allocation_status": candidate.get("allocation_status", ""),
        "last_written_at": candidate.get("last_written_at", ""),
        "parser_confidence": 0.54 if group_name and alias_rid_hex else 0.48,
        "evidence_strength": "sam-hive-group-key-candidate",
        "validation_required": True,
        "validation_checks": validation_checks,
        "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
        "os_account_report_grade_assessment": report_grade,
        "core_accuracy_gates": core_accuracy_gates,
        "os_account_native_capabilities": OS_ACCOUNT_NATIVE_CAPABILITIES,
        "account_privilege_deep_parse_profile": account_privilege_deep_parse_profile(
            artifact_scope="native-sam-group-alias-candidate",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={
                "group_name_candidate": group_name,
                "alias_rid_hex": alias_rid_hex,
                "allocation_status": str(candidate.get("allocation_status") or ""),
            },
        ),
        "validation_guidance": "Native SAM group rows identify group/alias key candidates only; validate membership from alias member binary attributes with a dedicated SAM parser before final testimony.",
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
        "risk_flags": risk_flags,
        "risk_score": min(100, len(risk_flags) * 20 + (20 if is_privileged_group_name(group_name) else 0)),
        "raw_preview": " ".join(part for part in [group_name, alias_rid_hex] if part),
    }


def is_sam_account_key_name(name: str) -> bool:
    if not name or name in SAM_BUILTIN_KEY_NAMES:
        return False
    if len(name) > 128:
        return False
    if is_builtin_group_rid_key_name(name):
        return False
    if is_rid_key_name(name):
        return True
    if name.lower() in SAM_COMMON_GROUP_NAMES:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._$ -]{1,128}", name))


def is_rid_key_name(name: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Fa-f]{8}", name))


def is_sam_group_key_name(name: str) -> bool:
    if not name or name in SAM_BUILTIN_KEY_NAMES:
        return False
    if is_builtin_group_rid_key_name(name):
        return True
    return name.lower() in SAM_COMMON_GROUP_NAMES


def is_builtin_group_rid_key_name(name: str) -> bool:
    return name.upper() in SAM_BUILTIN_GROUP_RIDS


def nearest_rid_candidate(candidate: dict[str, object], rid_candidates: list[dict[str, object]]) -> dict[str, object] | None:
    if not rid_candidates:
        return None
    candidate_offset = int(candidate.get("cell_offset") or 0)
    nearest = min(rid_candidates, key=lambda item: abs(int(item.get("cell_offset") or 0) - candidate_offset))
    if abs(int(nearest.get("cell_offset") or 0) - candidate_offset) <= 4096:
        return nearest
    return None


def rid_decimal(rid_hex: str) -> int:
    if not rid_hex:
        return 0
    try:
        return int(rid_hex, 16)
    except ValueError:
        return 0


def sam_account_risk_flags(user_name: str, rid_hex: str, candidate: dict[str, object]) -> list[str]:
    flags: list[str] = []
    lowered = user_name.lower()
    if lowered in {"administrator", "admin"} or rid_hex.upper() == "000001F4":
        flags.append("built-in-administrator-candidate")
    if lowered == "guest" or rid_hex.upper() == "000001F5":
        flags.append("guest-account-candidate")
    if user_name.endswith("$"):
        flags.append("machine-account-candidate")
    if candidate.get("allocation_status") == "free-or-deleted-candidate":
        flags.append("deleted-or-free-sam-key-candidate")
    return sorted(set(flags))


def parse_registry_hints(text: str) -> dict[str, object]:
    hints = {
        "computer_names": set(),
        "time_zones": set(),
        "profile_sids": set(),
        "admin_group_hints": set(),
        "last_boot_times": set(),
        "shutdown_times": set(),
        "current_control_sets": set(),
        "services": {},
        "mounted_devices": {},
        "lsa_policy_locations": {},
        "privilege_assignments": {},
        "group_memberships": {},
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
            register_structural_key_hint(hints, current_key)
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
        add_structural_value_hint(hints, current_key, name, value)
    return hints


def build_system_security_records(path: Path, hints: dict[str, object], source_hashes: dict[str, str]) -> Iterable[ArtifactRecord]:
    for index, service in enumerate(sorted(hints["services"].values(), key=lambda item: str(item.get("service_name") or ""))):
        risk_flags = service_risk_flags(service)
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-service-config",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-system-service-reg-export",
                "parser_version": PARSER_VERSION,
                "coverage_status": "mapped-reg-export",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "service_name": service.get("service_name", ""),
                "key": service.get("key", ""),
                "image_path": service.get("image_path", ""),
                "display_name": service.get("display_name", ""),
                "object_name": service.get("object_name", ""),
                "start_type": service.get("start_type", ""),
                "start_type_label": service_start_type_label(service.get("start_type", "")),
                "service_type": service.get("service_type", ""),
                "parser_confidence": 0.86,
                "evidence_strength": "system-service-configuration",
                "validation_required": False,
                "risk_flags": risk_flags,
                "risk_score": min(100, len(risk_flags) * 25),
                "raw_preview": str(service.get("key", "")),
            },
        )
    for index, device in enumerate(sorted(hints["mounted_devices"].values(), key=lambda item: str(item.get("key") or ""))):
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-mounted-device",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-mounted-device-reg-export",
                "parser_version": PARSER_VERSION,
                "coverage_status": "mapped-reg-export",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "key": device.get("key", ""),
                "device_id": device.get("device_id", ""),
                "volume_guid": device.get("volume_guid", ""),
                "drive_letter": device.get("drive_letter", ""),
                "friendly_name": device.get("friendly_name", ""),
                "parser_confidence": 0.78,
                "evidence_strength": "mounted-device-registry-key",
                "validation_required": False,
                "risk_flags": ["mounted-device-history"],
                "risk_score": 20,
                "raw_preview": str(device.get("key", "")),
            },
        )
    for index, item in enumerate(sorted(hints["lsa_policy_locations"].values(), key=lambda row: str(row.get("key") or ""))):
        validation_checks = security_policy_validation_checks(item)
        report_grade = os_account_report_grade_assessment(
            os_account_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#6"],
            extra_blockers=["security-secret-decryption-not-implemented", "lsa-policy-context-validation-required"],
        )
        core_accuracy_gates = os_account_core_accuracy_gates(
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "secret_name": item.get("secret_name", ""),
                "secret_value_metadata": item.get("values", {}),
                "validation_checks": validation_checks,
            }
        )
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-lsa-policy-location",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-security-lsa-reg-export",
                "parser_version": PARSER_VERSION,
                "coverage_status": "sensitive-location-present",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "key": item.get("key", ""),
                "secret_name": item.get("secret_name", ""),
                "value_names": sorted((item.get("values") or {}).keys()) if isinstance(item.get("values"), dict) else [],
                "secret_value_metadata": item.get("values", {}),
                "parser_confidence": 0.72,
                "evidence_strength": "security-policy-sensitive-location",
                "validation_required": True,
                "validation_checks": validation_checks,
                "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
                "os_account_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "commercial_uplift_evidence": os_account_commercial_uplift_evidence(
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "source_index": index,
                        "rid": "",
                        "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
                        "os_account_report_grade_assessment": report_grade,
                    }
                ),
                "os_account_native_capabilities": OS_ACCOUNT_NATIVE_CAPABILITIES,
                "validation_guidance": "This row identifies sensitive LSA/SECURITY policy locations only; secrets are not decrypted and must be handled under legal authorization.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "risk_flags": ["security-sensitive-registry-location"],
                "risk_score": 45,
                "raw_preview": str(item.get("key", "")),
            },
        )
    for index, item in enumerate(sorted(hints["privilege_assignments"].values(), key=lambda row: str(row.get("privilege") or ""))):
        validation_checks = {
            "has_privilege": bool(item.get("privilege")),
            "has_assigned_sid": bool(item.get("assigned_sids")),
            "has_principal_resolution_hint": bool(privilege_principal_hints(item)),
            "requires_lsa_policy_validation": True,
        }
        report_grade = os_account_report_grade_assessment(
            os_account_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#6"],
            extra_blockers=["lsa-policy-export-or-native-validation-required"],
        )
        core_accuracy_gates = os_account_core_accuracy_gates(
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "privilege": item.get("privilege", ""),
                "assigned_sids": list(item.get("assigned_sids") or []),
                "assigned_principal_hints": privilege_principal_hints(item),
                "validation_checks": validation_checks,
            }
        )
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-privilege-assignment",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-security-privilege-reg-export",
                "parser_version": PARSER_VERSION,
                "coverage_status": "mapped-reg-export",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "key": item.get("key", ""),
                "privilege": item.get("privilege", ""),
                "assigned_sids": list(item.get("assigned_sids") or []),
                "assigned_principal_hints": privilege_principal_hints(item),
                "parser_confidence": 0.74,
                "evidence_strength": "security-privilege-assignment",
                "validation_required": True,
                "validation_checks": validation_checks,
                "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
                "os_account_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "os_account_native_capabilities": OS_ACCOUNT_NATIVE_CAPABILITIES,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "validation_guidance": "Validate privilege assignments against secedit/LSA policy exports before final testimony.",
                "risk_flags": privilege_risk_flags(item),
                "risk_score": min(100, 30 + len(privilege_risk_flags(item)) * 25),
                "raw_preview": str(item.get("key", "")),
            },
        )
    for index, group in enumerate(normalized_group_memberships(hints["group_memberships"])):
        risk_flags = group_membership_risk_flags(group)
        validation_checks = {
            "has_group_name": bool(group.get("group_name")),
            "has_member_sid": bool(group.get("member_sids")),
            "has_member_name": bool(group.get("member_names")),
            "native_membership_reconstruction_available": False,
            "requires_native_sam_alias_validation": True,
        }
        report_grade = os_account_report_grade_assessment(
            os_account_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#6"],
            extra_blockers=["native-sam-alias-member-binary-decoding-required", "domain-context-validation-required"],
        )
        core_accuracy_gates = os_account_core_accuracy_gates(
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "group_name": group.get("group_name", ""),
                "member_sids": list(group.get("member_sids") or []),
                "member_names": list(group.get("member_names") or []),
                "group_sid_candidates": list(group.get("group_sid_candidates") or []),
                "validation_checks": validation_checks,
            }
        )
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-group-membership",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-sam-group-membership-reg-export",
                "parser_version": PARSER_VERSION,
                "coverage_status": "mapped-reg-export",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "key": group.get("key", ""),
                "group_name": group.get("group_name", ""),
                "member_sids": list(group.get("member_sids") or []),
                "member_names": list(group.get("member_names") or []),
                "member_count": group.get("member_count", 0),
                "member_identifier_count": group.get("member_identifier_count", 0),
                "member_count_semantics": group.get("member_count_semantics", ""),
                "membership_source_types": list(group.get("membership_source_types") or []),
                "group_sid_candidates": list(group.get("group_sid_candidates") or []),
                "privileged_group": bool(group.get("privileged_group")),
                "parser_confidence": 0.76,
                "evidence_strength": "exported-group-membership-hint",
                "validation_required": True,
                "validation_checks": validation_checks,
                "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
                "os_account_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "os_account_native_capabilities": OS_ACCOUNT_NATIVE_CAPABILITIES,
                "validation_guidance": "Registry exports can identify group membership hints, but validate against native SAM alias member attributes and domain context before final testimony.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "risk_flags": risk_flags,
                "risk_score": min(100, len(risk_flags) * 25 + (20 if group.get("privileged_group") else 0)),
                "raw_preview": str(group.get("key", "")),
            },
        )


def build_account_lifecycle_records(path: Path, hints: dict[str, object], source_hashes: dict[str, str]) -> Iterable[ArtifactRecord]:
    accounts = hints.get("account_lifecycle_hints") if isinstance(hints.get("account_lifecycle_hints"), dict) else {}
    groups = hints.get("group_memberships") if isinstance(hints.get("group_memberships"), dict) else {}
    for index, account in enumerate(
        sorted(consolidate_account_lifecycle_hints(accounts), key=lambda item: (str(item.get("user_name") or ""), str(item.get("rid") or "")))
    ):
        user_name = str(account.get("user_name") or "")
        rid = str(account.get("rid") or "")
        group_rows = group_memberships_for_account(groups, user_name, rid)
        security_context = account_security_context(account, group_rows, hints)
        security_context_rows = normalized_account_security_context_rows(
            account=account,
            group_rows=group_rows,
            security_context=security_context,
        )
        risk_flags = account_lifecycle_risk_flags(account, group_rows)
        validation_checks = account_lifecycle_validation_checks(account, group_rows)
        report_grade = os_account_report_grade_assessment(
            os_account_validation_matrix(validation_checks),
            validation_required=True,
            gap_ids=["#6"],
            extra_blockers=[
                "full-native-sam-fv-layout-validation-required",
                "security-policy-secret-decryption-not-implemented",
                "domain-context-and-transaction-log-validation-required",
            ],
        )
        core_accuracy_gates = os_account_core_accuracy_gates(
            {
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "user_name": user_name,
                "rid": rid,
                "uac_flags": list(account.get("uac_flags") or []),
                "sam_binary_fields": dict(account.get("sam_binary_fields") or {}),
                "group_membership_hints": group_rows,
                "account_security_context": security_context,
                "validation_checks": validation_checks,
            }
        )
        deep_parse_profile = account_privilege_deep_parse_profile(
            artifact_scope="account-lifecycle-security-context",
            validation_checks=validation_checks,
            report_grade=report_grade,
            evidence_fields={
                "user_name": user_name,
                "rid": rid,
                "group_count": len(group_rows),
                "inherited_privilege_count": security_context.get("inherited_privilege_count", 0),
                "security_context_row_count": len(security_context_rows),
            },
        )
        sam_security_system_profile = sam_security_system_deep_parser_profile(
            artifact_scope="account-lifecycle-security-context",
            validation_checks=validation_checks,
            report_grade=report_grade,
            security_context=security_context,
            evidence_fields={
                "user_name": user_name,
                "rid": rid,
                "profile_path": account.get("profile_path", ""),
                "sam_binary_field_names": sorted((account.get("sam_binary_fields") or {}).keys()),
                "group_count": len(group_rows),
                "inherited_privilege_count": security_context.get("inherited_privilege_count", 0),
                "security_context_row_count": len(security_context_rows),
            },
        )
        security_context_manifest = sam_security_context_manifest(
            source_path=str(path.resolve()),
            source_hashes=dict(source_hashes),
            account=account,
            security_context=security_context,
            security_context_rows=security_context_rows,
            validation_checks=validation_checks,
            report_grade=report_grade,
        )
        yield ArtifactRecord(
            provider=WindowsOsAccountProvider.name,
            artifact_type="windows-account-lifecycle",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-account-lifecycle-reg-export",
                "parser_version": PARSER_VERSION,
                "coverage_status": "mapped-reg-export",
                "reportability": "review",
                "source_path": str(path.resolve()),
                "source_format": "reg",
                "source_hashes": dict(source_hashes),
                "source_index": index,
                "key": account.get("key", ""),
                "user_name": user_name,
                "rid": rid,
                "rid_decimal": rid_decimal(rid),
                "profile_path": account.get("profile_path", ""),
                "created_at": account.get("created_at", ""),
                "last_logon_at": account.get("last_logon_at", ""),
                "password_last_set_at": account.get("password_last_set_at", ""),
                "account_disabled_hint": bool(account.get("account_disabled_hint")),
                "admin_hint": bool(account.get("admin_hint")),
                "uac_flags": list(account.get("uac_flags") or []),
                "sam_binary_fields": dict(account.get("sam_binary_fields") or {}),
                "group_membership_hints": group_rows,
                "account_security_context": security_context,
                "normalized_security_context_rows": security_context_rows,
                "normalized_security_context_row_count": len(security_context_rows),
                "sam_security_context_manifest": security_context_manifest,
                "sam_security_context_manifest_hash": security_context_manifest["manifest_sha256"],
                "parser_confidence": account_lifecycle_confidence(account, group_rows),
                "evidence_strength": "account-lifecycle-registry-export",
                "validation_required": True,
                "validation_checks": validation_checks,
                "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
                "os_account_report_grade_assessment": report_grade,
                "core_accuracy_gates": core_accuracy_gates,
                "commercial_uplift_evidence": os_account_commercial_uplift_evidence(
                    {
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "source_index": index,
                        "rid": rid,
                        "os_account_validation_matrix": os_account_validation_matrix(validation_checks),
                        "os_account_report_grade_assessment": report_grade,
                        "account_privilege_deep_parse_profile": deep_parse_profile,
                    }
                ),
                "os_account_native_capabilities": OS_ACCOUNT_NATIVE_CAPABILITIES,
                "account_privilege_deep_parse_profile": deep_parse_profile,
                "sam_security_system_deep_parser_profile": sam_security_system_profile,
                "account_reportability_decision": deep_parse_profile["reportability_decision"],
                "forensic_review": build_forensic_review(
                    gap_id="#6",
                    artifact_goal="SAM/SECURITY/SYSTEM account and privilege context",
                    primary_evidence=[
                        f"user={user_name}" if user_name else "",
                        f"rid={rid}" if rid else "",
                        f"groups={len(group_rows)}",
                        f"inherited_privileges={security_context.get('inherited_privilege_count', 0)}",
                    ],
                    validation_required=True,
                    report_grade_assessment=report_grade,
                    commercial_grade_ready=False,
                    caveats=[
                        "Native SAM F/V account structures are only partially decoded.",
                        "SECURITY secret decryption and transaction-log replay are not complete.",
                    ],
                ),
                "validation_guidance": "Validate account status, group membership, and timestamps against native SAM F/V records, SECURITY policy, and domain context before final testimony.",
                "commercial_grade_ready": False,
                "commercial_grade_blockers": report_grade["blockers"],
                "risk_flags": risk_flags,
                "risk_score": min(100, len(risk_flags) * 20 + (20 if account.get("admin_hint") else 0)),
                "raw_preview": f"{user_name} {rid}".strip(),
            },
        )


def consolidate_account_lifecycle_hints(accounts: object) -> list[dict[str, object]]:
    if not isinstance(accounts, dict):
        return []
    merged: dict[str, dict[str, object]] = {}
    for account in accounts.values():
        if not isinstance(account, dict):
            continue
        key = str(account.get("user_name") or account.get("rid") or account.get("key") or "")
        if not key:
            continue
        target = merged.setdefault(key, dict(account))
        for field in ("user_name", "rid", "profile_path", "created_at", "last_logon_at", "password_last_set_at"):
            if not target.get(field) and account.get(field):
                target[field] = account[field]
        target["account_disabled_hint"] = bool(target.get("account_disabled_hint") or account.get("account_disabled_hint"))
        target["admin_hint"] = bool(target.get("admin_hint") or account.get("admin_hint"))
        target["uac_flags"] = sorted(set([*list(target.get("uac_flags") or []), *list(account.get("uac_flags") or [])]))
        binary_fields = target.setdefault("sam_binary_fields", {})
        if isinstance(binary_fields, dict) and isinstance(account.get("sam_binary_fields"), dict):
            binary_fields.update(account["sam_binary_fields"])
        raw = target.setdefault("raw_fields", {})
        if isinstance(raw, dict) and isinstance(account.get("raw_fields"), dict):
            raw.update(account["raw_fields"])
    return list(merged.values())


def register_structural_key_hint(hints: dict[str, object], key: str) -> None:
    service_name = service_name_from_key(key)
    if service_name:
        service_hint_for_key(hints, key, service_name)
    mounted = mounted_device_from_key(key)
    if mounted:
        hints["mounted_devices"].setdefault(mounted["key"], mounted)
    secret_name = lsa_secret_name_from_key(key)
    if secret_name:
        hints["lsa_policy_locations"].setdefault(key, {"key": key, "secret_name": secret_name})
    group_name = group_name_from_key(key)
    if group_name:
        hints["group_memberships"].setdefault(
            key,
            {"key": key, "group_name": group_name, "member_sids": [], "member_names": []},
        )


def add_structural_value_hint(hints: dict[str, object], key: str, name: str, value: str) -> None:
    lowered_name = name.lower()
    service_name = service_name_from_key(key)
    if service_name:
        service = service_hint_for_key(hints, key, service_name)
        if lowered_name == "imagepath":
            service["image_path"] = value
        elif lowered_name == "displayname":
            service["display_name"] = value
        elif lowered_name == "objectname":
            service["object_name"] = value
        elif lowered_name == "start":
            service["start_type"] = value
        elif lowered_name == "type":
            service["service_type"] = value
    mounted = mounted_device_from_key(key)
    if mounted:
        device = hints["mounted_devices"].setdefault(mounted["key"], mounted)
        if lowered_name in {"friendlyname", "deviceDesc".lower(), "mfg"}:
            device["friendly_name"] = value
        if "\\mounteddevices" in key.lower() and name:
            value_device = mounted_device_from_value_name(key, name)
            hints["mounted_devices"].setdefault(value_device["key"], value_device)
    secret_name = lsa_secret_name_from_key(key)
    if secret_name:
        secret = hints["lsa_policy_locations"].setdefault(key, {"key": key, "secret_name": secret_name})
        values = secret.setdefault("values", {})
        if isinstance(values, dict) and name:
            values[name] = security_secret_value_metadata(name, value)
    if "privilege rights" in key.lower():
        privilege = name if name else key.rsplit("\\", 1)[-1]
        hints["privilege_assignments"][privilege] = {
            "key": key,
            "privilege": privilege,
            "assigned_sids": split_sid_list(value),
        }
    group_name = group_name_from_key(key)
    if group_name:
        group = hints["group_memberships"].setdefault(
            key,
            {"key": key, "group_name": group_name, "member_sids": [], "member_names": []},
        )
        if lowered_name in {"members", "member", "membersids", "sids"}:
            group["member_sids"] = split_sid_list(value)
        elif lowered_name in {"membernames", "names", "membername"}:
            group["member_names"] = split_name_list(value)
    if key.lower().endswith("\\select") and lowered_name in {"current", "default", "lastknowngood"}:
        parsed = parse_int(value)
        if parsed is not None:
            hints["current_control_sets"].add(f"ControlSet{parsed:03d}:{name}")


def service_hint_for_key(hints: dict[str, object], key: str, service_name: str) -> dict[str, object]:
    services = hints["services"]
    if not isinstance(services, dict):
        return {}
    return services.setdefault(
        service_name,
        {
            "key": key,
            "service_name": service_name,
            "image_path": "",
            "display_name": "",
            "object_name": "",
            "start_type": "",
            "service_type": "",
        },
    )


def service_name_from_key(key: str) -> str:
    match = re.search(r"\\CurrentControlSet\\Services\\([^\\\]]+)$", key, flags=re.IGNORECASE)
    if not match:
        match = re.search(r"\\ControlSet\d{3}\\Services\\([^\\\]]+)$", key, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def mounted_device_from_key(key: str) -> dict[str, object]:
    lowered = key.lower()
    if "\\mounteddevices" in lowered:
        tail = key.rsplit("\\", 1)[-1]
        drive_letter = tail if re.fullmatch(r"\\DosDevices\\[A-Z]:", tail, flags=re.IGNORECASE) else ""
        volume_guid = tail if "volume{" in tail.lower() else ""
        return {"key": key, "device_id": tail, "drive_letter": drive_letter, "volume_guid": volume_guid, "friendly_name": ""}
    if "\\enum\\usbstor\\" in lowered:
        return {"key": key, "device_id": key.split("\\Enum\\", 1)[-1] if "\\Enum\\" in key else key, "drive_letter": "", "volume_guid": "", "friendly_name": ""}
    return {}


def mounted_device_from_value_name(key: str, name: str) -> dict[str, object]:
    drive_letter = name if re.fullmatch(r"\\DosDevices\\[A-Z]:", name, flags=re.IGNORECASE) else ""
    volume_guid = name if "volume{" in name.lower() else ""
    return {
        "key": f"{key}\\{name}",
        "device_id": name,
        "drive_letter": drive_letter,
        "volume_guid": volume_guid,
        "friendly_name": "",
    }


def lsa_secret_name_from_key(key: str) -> str:
    match = re.search(r"\\Policy\\Secrets\\([^\\\]]+)", key, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def security_secret_value_metadata(name: str, value: str) -> dict[str, object]:
    raw = parse_reg_binary(value)
    metadata = {
        "value_name": name,
        "registry_value_type": registry_value_type_label(value),
        "byte_count": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else "",
        "entropy": byte_entropy(raw) if raw else 0.0,
        "contains_nonzero_bytes": any(byte != 0 for byte in raw),
        "timestamp_candidate": parse_timestamp_value(value) if name.lower() in {"cupdtime", "oupdtime", "updtime"} else "",
        "metadata_only": True,
        "decrypted": False,
        "decryption_status": "not-attempted",
        "secret_handling_decision": {
            "profile_version": "security-secret-handling-decision-v1",
            "decision": "do-not-decrypt-or-display-secret",
            "allowed_use": "metadata-inventory-only",
            "protected_value_redacted": True,
            "authority_gate": "explicit-legal-authority-and-audit-required-before-decryption",
            "reporting_constraint": (
                "Report value names, hashes, sizes, entropy, and timestamp candidates only; do not report "
                "secret contents unless a separate authority-gated decrypt workflow produced audited output."
            ),
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": ["security-secret-decryption-not-implemented"],
        "validation_note": "SECURITY Policy\\Secrets values are inventoried and hashed, but not decrypted.",
    }
    return metadata


def security_policy_validation_checks(item: dict[str, object]) -> dict[str, object]:
    values = item.get("values") if isinstance(item.get("values"), dict) else {}
    metadata_values = [value for value in values.values() if isinstance(value, dict)]
    return {
        "has_secret_name": bool(item.get("secret_name")),
        "has_exported_values": bool(values),
        "exported_value_count": len(values),
        "hashed_value_count": sum(1 for value in metadata_values if value.get("sha256")),
        "timestamp_candidate_count": sum(1 for value in metadata_values if value.get("timestamp_candidate")),
        "secret_decryption_attempted": False,
        "requires_legal_authorization": True,
    }


def account_privilege_deep_parse_profile(
    *,
    artifact_scope: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    evidence_fields: Mapping[str, object],
) -> dict[str, object]:
    reportability_decision = os_account_reportability_decision(
        artifact_scope=artifact_scope,
        report_grade=report_grade,
        validation_checks=validation_checks,
    )
    return {
        "profile_version": "account-privilege-deep-parser-v1",
        "commercial_gap_id": "#6",
        "artifact_scope": artifact_scope,
        "target_artifacts": ["SAM", "SECURITY", "SYSTEM"],
        "current_decode_level": "partial-native-and-reg-export-correlation",
        "decoded_components": {
            "sam_f_value_export_candidate": bool(validation_checks.get("has_sam_f_value")),
            "sam_v_value_export_candidate": bool(validation_checks.get("has_sam_v_value")),
            "sam_fv_candidate_fields": bool(validation_checks.get("native_sam_fv_candidate_decoding_available")),
            "sam_v_layout_string_candidates": bool(validation_checks.get("has_decoded_sam_v_layout_fields")),
            "sam_alias_key_candidates": bool(
                validation_checks.get("has_builtin_alias_rid_candidate")
                or validation_checks.get("has_group_name")
                or validation_checks.get("has_group_name_candidate")
            ),
            "privilege_rights_export_mapping": bool(validation_checks.get("has_privilege") or evidence_fields.get("inherited_privilege_count")),
            "security_secret_metadata_inventory": bool(
                validation_checks.get("has_secret_name") or validation_checks.get("has_exported_values")
            ),
        },
        "not_yet_report_grade": {
            "full_os_version_sam_fv_layout": not OS_ACCOUNT_NATIVE_CAPABILITIES["full_os_version_sam_fv_layout_validation"],
            "sam_alias_member_binary_decode": not OS_ACCOUNT_NATIVE_CAPABILITIES["native_sam_alias_member_binary_decode"],
            "security_secret_decryption": not OS_ACCOUNT_NATIVE_CAPABILITIES["security_secret_decryption"],
            "domain_context_resolution": not OS_ACCOUNT_NATIVE_CAPABILITIES["domain_controller_context_resolution"],
            "transaction_log_replay": not OS_ACCOUNT_NATIVE_CAPABILITIES["transaction_log_replay"],
        },
        "evidence_fields": dict(evidence_fields),
        "reportability_decision": reportability_decision,
        "required_independent_checks": [
            "validate SAM F/V offsets and field semantics by Windows build",
            "decode SAM alias/member binary values for actual group membership",
            "replay SAM/SECURITY/SYSTEM transaction logs before final state claims",
            "cross-check privilege assignments with LSA policy/secedit output",
            "correlate local/domain SID context before admin-right conclusions",
        ],
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": list(report_grade.get("blockers") or []),
        "legal_handling": "SECURITY secrets are inventoried as metadata only; decryption requires explicit lawful authority and audit logging.",
    }


def sam_security_system_deep_parser_profile(
    *,
    artifact_scope: str,
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
    security_context: Mapping[str, object],
    evidence_fields: Mapping[str, object],
) -> dict[str, object]:
    return {
        "profile_version": "sam-security-system-deep-parser-v1",
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 12,
        "artifact_scope": artifact_scope,
        "target_hives": ["SAM", "SECURITY", "SYSTEM"],
        "decoded_components": {
            "sam_f_value_metadata": bool(validation_checks.get("has_sam_f_value")),
            "sam_v_value_metadata": bool(validation_checks.get("has_sam_v_value")),
            "account_lifecycle_timestamps": bool(
                validation_checks.get("has_created_timestamp") or validation_checks.get("has_last_logon_timestamp")
            ),
            "group_membership_hints": bool(security_context.get("inherited_privilege_count")),
            "privilege_assignment_hints": bool(validation_checks.get("has_privilege")),
            "lsa_secret_metadata_inventory": bool(
                validation_checks.get("has_secret_name") or validation_checks.get("has_exported_values")
            ),
            "current_control_set_context": bool(validation_checks.get("has_current_control_set")),
            "native_sam_alias_member_decode": bool(OS_ACCOUNT_NATIVE_CAPABILITIES["native_sam_alias_member_binary_decode"]),
            "security_secret_decryption": bool(OS_ACCOUNT_NATIVE_CAPABILITIES["security_secret_decryption"]),
            "transaction_log_replay": bool(OS_ACCOUNT_NATIVE_CAPABILITIES["transaction_log_replay"]),
        },
        "evidence_fields": dict(evidence_fields),
        "normalized_security_context_schema": {
            "fields": [
                "context_type",
                "principal",
                "name",
                "sid",
                "privilege",
                "service_name",
                "risk_flags",
                "citation",
            ],
            "row_count": int(evidence_fields.get("security_context_row_count") or 0),
            "secret_value_policy": "metadata-only-redacted",
            "safe_for_case_db_indexing": True,
        },
        "security_context_manifest_expected": True,
        "security_context_manifest_version": "sam-security-context-manifest-v1",
        "reportability_decision": os_account_reportability_decision(
            artifact_scope=artifact_scope,
            report_grade=report_grade,
            validation_checks=validation_checks,
        ),
        "legal_handling": {
            "security_secret_values_redacted": True,
            "secret_decryption_allowed_by_default": False,
            "authority_gate": "explicit-legal-authority-and-audited-secret-workflow-required",
        },
        "required_before_report": [
            "validate SAM F/V binary layouts by Windows build and account RID",
            "decode SAM alias/member binary values instead of relying only on name hints",
            "replay SAM/SECURITY/SYSTEM transaction logs before final account-state claims",
            "resolve domain/local SID context and ControlSet attribution",
            "diff account/group/privilege rows against Eric Zimmerman's Registry Explorer/RECmd or equivalent trusted output",
        ],
        "large_data_controls": {
            "row_is_account_scoped": True,
            "secrets_are_metadata_only": True,
            "safe_for_case_db_indexing": True,
        },
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": sorted(
            set(report_grade.get("blockers") or [])
            | {
                "sam-security-system-trusted-diff-required",
                "native-sam-alias-member-decode-required",
                "transaction-log-replay-required",
            }
        ),
    }


def os_account_reportability_decision(
    *,
    artifact_scope: str,
    report_grade: Mapping[str, object],
    validation_checks: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    if validation_checks.get("requires_legal_authorization") or validation_checks.get("has_secret_name"):
        blockers.add("security-secret-authority-gate-required")
    if not OS_ACCOUNT_NATIVE_CAPABILITIES["transaction_log_replay"]:
        blockers.add("sam-security-system-transaction-log-replay-required")
    return {
        "profile_version": "os-account-reportability-decision-v1",
        "commercial_gap_id": "#6",
        "artifact_scope": artifact_scope,
        "decision": "do-not-report-as-final-account-state",
        "allowed_use": "account-security-triage-pivot",
        "blockers": sorted(blockers),
        "secret_values_redacted": True,
        "requires_domain_context_review": not OS_ACCOUNT_NATIVE_CAPABILITIES["domain_controller_context_resolution"],
        "requires_transaction_log_replay": not OS_ACCOUNT_NATIVE_CAPABILITIES["transaction_log_replay"],
        "analyst_wording": (
            "Describe SAM/SECURITY/SYSTEM rows as account, group, privilege, or secret metadata candidates "
            "until native SAM binary attributes, SECURITY authority gates, domain context, and transaction logs are validated."
        ),
    }


def os_account_core_accuracy_gates(details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"cell_offset:{details.get('cell_offset', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if (
        (details.get("user_name") and details.get("rid"))
        or checks.get("has_user_name_candidate")
        or checks.get("has_rid_candidate")
        or details.get("group_sid_candidates")
    ):
        satisfied.append("RID/name/SID consistency")
    if details.get("uac_flags") or checks.get("native_sam_fv_candidate_decoding_available"):
        satisfied.append("UAC flag decoding")
    if details.get("group_membership_hints") or details.get("member_sids") or details.get("group_sid_candidates"):
        satisfied.append("group alias membership reconstruction")
    security_context = (
        details.get("account_security_context") if isinstance(details.get("account_security_context"), Mapping) else {}
    )
    if details.get("privilege") or details.get("assigned_sids") or security_context.get("inherited_privilege_count"):
        satisfied.append("privilege assignment attribution")
    secret_metadata = details.get("secret_value_metadata") if isinstance(details.get("secret_value_metadata"), Mapping) else {}
    if secret_metadata or details.get("secret_name") or not OS_ACCOUNT_NATIVE_CAPABILITIES["security_secret_decryption"]:
        satisfied.append("secret-value redaction and authority gate")
    trusted_diff = (
        details.get("os_account_trusted_diff")
        if isinstance(details.get("os_account_trusted_diff"), Mapping)
        else {}
    )
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted SAM/SECURITY/SYSTEM diff pass")

    return [build_accuracy_gate(6, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def os_account_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("os_account_validation_matrix") if isinstance(details.get("os_account_validation_matrix"), list) else []
    report_grade = (
        details.get("os_account_report_grade_assessment")
        if isinstance(details.get("os_account_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    profile = (
        details.get("account_privilege_deep_parse_profile")
        if isinstance(details.get("account_privilege_deep_parse_profile"), Mapping)
        else {}
    )
    trusted_diff = (
        details.get("os_account_trusted_diff")
        if isinstance(details.get("os_account_trusted_diff"), Mapping)
        else {}
    )
    return {
        "batch_id": "commercial-uplift-006-010",
        "item_numbers": [6],
        "implementation_track": "native-parser-depth",
        "objective": "Expose SAM/SECURITY/SYSTEM account validation evidence and commercial blockers on account rows.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_index:{details.get('source_index', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"rid:{details.get('rid', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": dict(profile.get("reportability_decision") or {}),
        "trusted_diff": {
            "status": str(trusted_diff.get("status") or "not-attached"),
            "trusted_tool": str(trusted_diff.get("trusted_tool") or ""),
            "matched_count": int(trusted_diff.get("matched_count") or 0),
            "mismatch_count": int(trusted_diff.get("mismatch_count") or 0),
            "missing_in_trusted_count": int(trusted_diff.get("missing_in_trusted_count") or 0),
            "extra_in_trusted_count": int(trusted_diff.get("extra_in_trusted_count") or 0),
            "commercial_grade_evidence": bool(trusted_diff.get("commercial_grade_evidence")),
        },
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "row_scope": "account-lifecycle-row",
            "secret_values_redacted": True,
            "native_sam_binary_decode_partial": True,
            "transaction_log_replay_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish native SAM alias/member binary reconstruction and SECURITY secret authority-gated decrypt validation.",
        "external_evidence_required": True,
    }


def build_os_account_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    """Compare SAM/SECURITY/SYSTEM account rows against a trusted parser/export."""

    tool_name = str(trusted_tool or "").strip()
    rapid_by_key = {
        key: normalized
        for row in rapid_rows
        for key, normalized in [_normalize_os_account_row(row)]
        if key
    }
    trusted_by_key = {
        key: normalized
        for row in trusted_rows
        for key, normalized in [_normalize_os_account_row(row)]
        if key
    }
    missing_in_trusted = sorted(key for key in rapid_by_key if key not in trusted_by_key)
    extra_in_trusted = sorted(key for key in trusted_by_key if key not in rapid_by_key)
    mismatches: list[dict[str, object]] = []
    matched_count = 0
    for key in sorted(set(rapid_by_key) & set(trusted_by_key)):
        rapid = rapid_by_key[key]
        trusted = trusted_by_key[key]
        field_diffs = []
        for field in (
            "row_type",
            "user_name",
            "sid",
            "rid",
            "uac_flags",
            "group_names",
            "assigned_privileges",
            "group_name",
            "member_sids",
            "member_names",
            "privilege",
            "assigned_sids",
            "secret_name",
            "admin_hint",
            "account_disabled_hint",
        ):
            left = rapid.get(field, "")
            right = trusted.get(field, "")
            if left or right:
                if left != right:
                    field_diffs.append({"field": field, "rapid": left, "trusted": right})
        if field_diffs:
            mismatches.append({"row_key": key, "field_diffs": field_diffs})
        else:
            matched_count += 1

    status = "pass"
    if not tool_name or not rapid_by_key or not trusted_by_key:
        status = "not-enough-evidence"
    elif missing_in_trusted or extra_in_trusted or mismatches:
        status = "diffs-present"
    normalized_tool = re.sub(r"[^a-z0-9]+", "", tool_name.lower())
    trusted_tool_recognized = any(hint in normalized_tool for hint in OS_ACCOUNT_TRUSTED_TOOL_HINTS)
    uses_rapidtriage_artifact_rows = any(isinstance(row.get("details"), Mapping) for row in rapid_rows)
    passed_decision = "os-account-diff-passed" if uses_rapidtriage_artifact_rows else "account-diff-passed"
    return {
        "profile_version": "os-account-trusted-diff-v1",
        "trusted_tool": tool_name,
        "trusted_tool_recognized": trusted_tool_recognized,
        "compare_fields": [
            "row_type",
            "user_name",
            "sid",
            "rid",
            "uac_flags",
            "group_names",
            "assigned_privileges",
            "group_name",
            "member_sids",
            "member_names",
            "privilege",
            "assigned_sids",
            "secret_name",
            "admin_hint",
            "account_disabled_hint",
        ],
        "rapid_row_count": len(rapid_by_key),
        "trusted_row_count": len(trusted_by_key),
        "matched_count": matched_count,
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing_in_trusted),
        "extra_in_trusted_count": len(extra_in_trusted),
        "status": status,
        "commercial_grade_evidence": status == "pass" and trusted_tool_recognized,
        "missing_in_trusted": missing_in_trusted[:100],
        "extra_in_trusted": extra_in_trusted[:100],
        "mismatches": mismatches[:100],
        "reportability_decision": {
            "decision": passed_decision if status == "pass" else "do-not-use-os-account-row-as-final",
            "allowed_use": (
                "support report-grade account/group/privilege assertions with attached corpus/signoff"
                if status == "pass" and trusted_tool_recognized
                else "triage-only account pivot until SAM/SECURITY/SYSTEM trusted diff is clean"
            ),
            "blockers": [] if status == "pass" and trusted_tool_recognized else ["sam-security-system-trusted-diff-required"],
        },
    }


def _normalize_os_account_row(row: Mapping[str, object]) -> tuple[str, dict[str, str]]:
    payload = _os_account_row_payload(row)
    row_type = os_account_row_type(row, payload)
    normalized = {
        "row_type": row_type,
        "user_name": str(payload.get("user_name") or payload.get("account_name") or "").strip().lower(),
        "sid": str(payload.get("sid") or payload.get("user_sid") or payload.get("account_sid") or "").strip().lower(),
        "rid": _normalize_rid(
            payload.get("rid")
            or payload.get("rid_decimal")
            or payload.get("account_rid")
            or payload.get("rid_candidate")
            or ""
        ),
        "uac_flags": _normalize_string_list(
            payload.get("uac_flags")
            or payload.get("user_account_control_flags")
            or payload.get("account_control_flags")
            or []
        ),
        "group_names": _normalize_string_list(payload.get("group_names") or payload.get("groups") or []),
        "assigned_privileges": _normalize_string_list(
            payload.get("assigned_privileges") or payload.get("privileges") or []
        ),
        "group_name": str(payload.get("group_name") or payload.get("group_name_candidate") or "").strip().lower(),
        "member_sids": _normalize_string_list(payload.get("member_sids") or payload.get("assigned_member_sids") or []),
        "member_names": _normalize_string_list(payload.get("member_names") or payload.get("assigned_member_names") or []),
        "privilege": str(payload.get("privilege") or payload.get("right") or "").strip().lower(),
        "assigned_sids": _normalize_string_list(payload.get("assigned_sids") or payload.get("assigned_principal_sids") or []),
        "secret_name": str(payload.get("secret_name") or payload.get("lsa_secret_name") or "").strip().lower(),
        "admin_hint": _normalize_bool_text(payload.get("admin_hint") or payload.get("is_admin") or payload.get("privileged_group")),
        "account_disabled_hint": _normalize_bool_text(
            payload.get("account_disabled_hint") or payload.get("disabled") or payload.get("is_disabled")
        ),
    }
    key = os_account_row_key(normalized)
    return key, normalized


def _os_account_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    if not details:
        return row
    flattened = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        flattened.setdefault(key, value)
    return flattened


def os_account_row_type(row: Mapping[str, object], payload: Mapping[str, object]) -> str:
    artifact_type = str(row.get("artifact_type") or payload.get("artifact_type") or "").lower()
    if "privilege" in artifact_type or payload.get("privilege") or payload.get("right") or payload.get("assigned_principal_sids"):
        return "privilege"
    if "group" in artifact_type or payload.get("group_name") or payload.get("group_name_candidate"):
        return "group"
    if "secret" in artifact_type or payload.get("secret_name"):
        return "secret"
    return "account"


def os_account_row_key(normalized: Mapping[str, str]) -> str:
    row_type = str(normalized.get("row_type") or "account")
    if row_type == "privilege":
        return f"privilege:{normalized.get('privilege', '')}"
    if row_type == "group":
        return f"group:{normalized.get('group_name', '') or normalized.get('rid', '')}"
    if row_type == "secret":
        return f"secret:{normalized.get('secret_name', '')}"
    return f"account:{normalized.get('rid', '') or normalized.get('user_name', '')}"


def _normalize_rid(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{8}", text):
        return str(int(text, 16))
    return text.lower()


def _normalize_string_list(value: object) -> str:
    values: list[str] = []
    if isinstance(value, str):
        values = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence):
        values = [str(item).strip() for item in value if str(item).strip()]
    return "|".join(sorted({item.lower() for item in values}))


def _normalize_bool_text(value: object) -> str:
    if value in (None, ""):
        return ""
    return str(bool(value)).lower()


def os_account_validation_matrix(checks: Mapping[str, object]) -> list[dict[str, object]]:
    labels = {
        "regf_header_valid": ("SAM hive header", "critical"),
        "has_user_name_candidate": ("User-name candidate", "high"),
        "has_rid_candidate": ("RID candidate", "high"),
        "allocated_key_cell": ("Allocated key cell", "medium"),
        "has_group_name_candidate": ("Group-name candidate", "high"),
        "has_builtin_alias_rid_candidate": ("Builtin alias RID candidate", "high"),
        "has_group_name": ("Group name", "high"),
        "has_member_sid": ("Member SID", "high"),
        "has_member_name": ("Member name", "medium"),
        "has_privilege": ("Privilege name", "high"),
        "has_assigned_sid": ("Assigned SID", "high"),
        "has_secret_name": ("LSA secret name", "high"),
        "has_exported_values": ("LSA exported values", "medium"),
        "has_sam_f_value": ("SAM F value", "high"),
        "has_sam_v_value": ("SAM V value", "high"),
        "has_decoded_sam_f_timestamps": ("SAM F timestamp candidates", "medium"),
        "has_decoded_sam_f_uac": ("SAM F UAC candidate", "medium"),
        "has_decoded_sam_v_strings": ("SAM V string candidates", "medium"),
        "has_decoded_sam_v_layout_fields": ("SAM V layout string candidates", "medium"),
        "native_sam_fv_candidate_decoding_available": ("Native SAM F/V candidate decode", "medium"),
        "native_sam_fv_report_grade": ("Native SAM F/V report-grade decode", "critical"),
        "native_membership_reconstruction_available": ("Native membership reconstruction", "critical"),
        "security_secret_decryption_available": ("SECURITY secret decryption", "critical"),
        "secret_decryption_attempted": ("Secret decryption attempted", "critical"),
        "requires_second_parser_validation": ("Second parser validation", "high"),
        "requires_lsa_policy_validation": ("LSA policy validation", "high"),
        "requires_native_sam_alias_validation": ("Native SAM alias validation", "high"),
        "requires_sam_alias_member_binary_decoding": ("SAM alias member binary decode", "critical"),
        "requires_legal_authorization": ("Legal authorization required", "critical"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key.endswith("_count") or key in {"exported_value_count", "hashed_value_count", "timestamp_candidate_count"}:
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_")
        passed = bool(value)
        if negative_requirement:
            passed = not bool(value)
        matrix.append(
            {
                "id": key.replace("_", "-"),
                "label": label,
                "passed": passed,
                "severity": severity,
                "detail": value,
            }
        )
    return matrix


def os_account_report_grade_assessment(
    validation_matrix: list[dict[str, object]],
    *,
    validation_required: bool,
    gap_ids: list[str],
    extra_blockers: list[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if not item.get("passed")]
    blockers = set(OS_ACCOUNT_REPORT_GRADE_BLOCKERS)
    blockers.update(f"validation-check-failed:{item}" for item in failed)
    blockers.update(extra_blockers)
    if validation_required:
        blockers.add("os-account-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if item.get("passed")],
        "commercial_gap_ids": gap_ids,
        "next_validation_step": (
            "Validate account, group, privilege, and SECURITY findings with native SAM/SECURITY parsing, "
            "transaction logs, domain context, and a second trusted parser before final testimony."
        ),
    }


def registry_value_type_label(value: str) -> str:
    lowered = value.strip().lower()
    if lowered.startswith("hex(b):"):
        return "REG_QWORD"
    if lowered.startswith("hex(2):"):
        return "REG_EXPAND_SZ"
    if lowered.startswith("hex(7):"):
        return "REG_MULTI_SZ"
    if lowered.startswith("hex:"):
        return "REG_BINARY"
    if lowered.startswith("dword:"):
        return "REG_DWORD"
    if value.startswith('"') and value.endswith('"'):
        return "REG_SZ"
    return "unknown"


def byte_entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    entropy = 0.0
    for byte in set(raw):
        probability = raw.count(byte) / len(raw)
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def group_name_from_key(key: str) -> str:
    alias_match = re.search(r"\\Aliases\\Names\\([^\\\]]+)", key, flags=re.IGNORECASE)
    if alias_match:
        return alias_match.group(1)
    group_match = re.search(r"\\Groups\\Names\\([^\\\]]+)", key, flags=re.IGNORECASE)
    return group_match.group(1) if group_match else ""


def split_sid_list(value: str) -> list[str]:
    return sorted(set(re.findall(r"S-\d(?:-\d+)+", value)))


def split_name_list(value: str) -> list[str]:
    return sorted({item.strip() for item in re.split(r"[,;|]", value) if item.strip()})


def normalized_group_memberships(groups: object) -> list[dict[str, object]]:
    if not isinstance(groups, dict):
        return []
    rows: list[dict[str, object]] = []
    for group in groups.values():
        if not isinstance(group, dict):
            continue
        member_sids = sorted(set(str(item) for item in list(group.get("member_sids") or []) if str(item)))
        member_names = sorted(set(str(item) for item in list(group.get("member_names") or []) if str(item)))
        group_name = str(group.get("group_name") or "")
        rows.append(
            {
                "key": group.get("key", ""),
                "group_name": group_name,
                "member_sids": member_sids,
                "member_names": member_names,
                "member_count": max(len(member_sids), len(member_names)),
                "member_identifier_count": len(set(member_sids + [item.lower() for item in member_names])),
                "member_count_semantics": "estimated from exported SID/name lists; SID-to-name correlation is not proven without native SAM/domain validation",
                "membership_source_types": group_membership_source_types(member_sids, member_names),
                "group_sid_candidates": group_sid_candidates(group_name),
                "privileged_group": is_privileged_group_name(group_name),
            }
        )
    return sorted(rows, key=lambda item: (str(item.get("group_name") or "").lower(), str(item.get("key") or "").lower()))


def group_membership_source_types(member_sids: list[str], member_names: list[str]) -> list[str]:
    source_types: list[str] = []
    if member_sids:
        source_types.append("member-sid")
    if member_names:
        source_types.append("member-name")
    return source_types


def group_sid_candidates(group_name: str) -> list[str]:
    sid = SAM_BUILTIN_GROUP_SIDS.get(normalize_group_name(group_name), "")
    return [sid] if sid else []


def normalize_group_name(group_name: str) -> str:
    for candidate in SAM_BUILTIN_GROUP_SIDS:
        if candidate.lower() == group_name.lower():
            return candidate
    return group_name


def privilege_principal_hints(item: Mapping[str, object]) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    for sid in item.get("assigned_sids", []) if isinstance(item.get("assigned_sids"), list) else []:
        sid_text = str(sid)
        principal = BUILTIN_SID_NAMES.get(sid_text, "")
        hints.append(
            {
                "sid": sid_text,
                "principal": principal,
                "principal_type": "builtin-alias" if principal else "sid",
            }
        )
    return hints


def group_memberships_for_account(groups: object, user_name: str, rid: str) -> list[dict[str, object]]:
    if not isinstance(groups, dict):
        return []
    matches: list[dict[str, object]] = []
    sid_tail = f"-{rid_decimal(rid)}" if rid else ""
    for group in groups.values():
        if not isinstance(group, dict):
            continue
        member_sids = list(group.get("member_sids") or [])
        member_names = list(group.get("member_names") or [])
        name_match = user_name and any(str(item).lower() == user_name.lower() for item in member_names)
        rid_match = sid_tail != "-0" and any(str(item).endswith(sid_tail) for item in member_sids)
        match_types = []
        if name_match:
            match_types.append("name")
        if rid_match:
            match_types.append("rid-sid-tail")
        if name_match or rid_match:
            matches.append(
                {
                    "group_name": group.get("group_name", ""),
                    "key": group.get("key", ""),
                    "match_type": match_types[0],
                    "match_types": match_types,
                    "member_sids": member_sids,
                    "member_names": member_names,
                    "group_sid_candidates": group_sid_candidates(str(group.get("group_name") or "")),
                    "privileged_group": is_privileged_group_name(str(group.get("group_name") or "")),
                }
            )
    return sorted(matches, key=lambda item: str(item.get("group_name") or ""))


def account_security_context(
    account: Mapping[str, object],
    group_rows: list[dict[str, object]],
    hints: Mapping[str, object],
) -> dict[str, object]:
    privileges = hints.get("privilege_assignments") if isinstance(hints.get("privilege_assignments"), dict) else {}
    services = hints.get("services") if isinstance(hints.get("services"), dict) else {}
    lsa_locations = hints.get("lsa_policy_locations") if isinstance(hints.get("lsa_policy_locations"), dict) else {}
    group_sid_set = {
        str(sid)
        for group in group_rows
        for sid in group.get("group_sid_candidates", [])
        if str(sid)
    }
    inherited_privileges: list[dict[str, object]] = []
    for privilege in privileges.values():
        if not isinstance(privilege, Mapping):
            continue
        assigned_sids = [str(item) for item in privilege.get("assigned_sids", []) if str(item)]
        matched_sids = sorted(group_sid_set.intersection(assigned_sids))
        if not matched_sids:
            continue
        inherited_privileges.append(
            {
                "privilege": str(privilege.get("privilege") or ""),
                "via_group_sids": matched_sids,
                "via_groups": sorted(BUILTIN_SID_NAMES.get(sid, sid) for sid in matched_sids),
                "risk_flags": privilege_risk_flags(privilege),
            }
        )
    service_account_matches = [
        {
            "service_name": str(service.get("service_name") or ""),
            "object_name": str(service.get("object_name") or ""),
            "image_path": str(service.get("image_path") or ""),
        }
        for service in services.values()
        if isinstance(service, Mapping)
        and str(account.get("user_name") or "").lower()
        and str(account.get("user_name") or "").lower() in str(service.get("object_name") or "").lower()
    ]
    return {
        "privileged_group_count": sum(1 for group in group_rows if group.get("privileged_group")),
        "group_sid_candidates": sorted(group_sid_set),
        "inherited_privilege_count": len(inherited_privileges),
        "inherited_privileges": sorted(inherited_privileges, key=lambda item: str(item.get("privilege") or "")),
        "service_account_matches": service_account_matches[:25],
        "service_account_match_count": len(service_account_matches),
        "lsa_sensitive_location_count": len(lsa_locations),
        "requires_native_sam_alias_validation": bool(group_rows),
        "requires_lsa_policy_validation": bool(privileges or lsa_locations),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "native-sam-alias-member-binary-decoding-required",
            "lsa-policy-native-validation-required",
        ],
    }


def normalized_account_security_context_rows(
    *,
    account: Mapping[str, object],
    group_rows: Sequence[Mapping[str, object]],
    security_context: Mapping[str, object],
) -> list[dict[str, object]]:
    user_name = str(account.get("user_name") or "")
    rid = str(account.get("rid") or "")
    rows: list[dict[str, object]] = []
    for group in group_rows:
        group_name = str(group.get("group_name") or "")
        group_sids = group.get("group_sid_candidates") if isinstance(group.get("group_sid_candidates"), list) else [""]
        for sid in group_sids:
            rows.append(
                {
                    "context_type": "group-membership-hint",
                    "principal": user_name,
                    "rid": rid,
                    "name": group_name,
                    "sid": str(sid),
                    "privileged": bool(group.get("privileged_group")),
                    "risk_flags": group_membership_risk_flags(dict(group)),
                    "citation": {"source": "SAM/Builtin/Alias export hint", "group_name": group_name},
                    "reportability": "triage-pivot",
                }
            )
    inherited = security_context.get("inherited_privileges")
    if isinstance(inherited, Sequence):
        for privilege in inherited:
            if not isinstance(privilege, Mapping):
                continue
            rows.append(
                {
                    "context_type": "inherited-privilege-hint",
                    "principal": user_name,
                    "rid": rid,
                    "privilege": str(privilege.get("privilege") or ""),
                    "via_groups": list(privilege.get("via_groups") or []),
                    "via_group_sids": list(privilege.get("via_group_sids") or []),
                    "risk_flags": list(privilege.get("risk_flags") or []),
                    "citation": {"source": "SECURITY/Privilege Rights export hint"},
                    "reportability": "triage-pivot",
                }
            )
    services = security_context.get("service_account_matches")
    if isinstance(services, Sequence):
        for service in services:
            if not isinstance(service, Mapping):
                continue
            rows.append(
                {
                    "context_type": "service-account-match",
                    "principal": user_name,
                    "rid": rid,
                    "service_name": str(service.get("service_name") or ""),
                    "object_name": str(service.get("object_name") or ""),
                    "image_path": str(service.get("image_path") or ""),
                    "risk_flags": service_risk_flags(service),
                    "citation": {"source": "SYSTEM/Services ObjectName export hint"},
                    "reportability": "triage-pivot",
                }
            )
    if int(security_context.get("lsa_sensitive_location_count") or 0):
        rows.append(
            {
                "context_type": "lsa-sensitive-location-summary",
                "principal": user_name,
                "rid": rid,
                "count": int(security_context.get("lsa_sensitive_location_count") or 0),
                "secret_values_redacted": True,
                "risk_flags": ["lsa-sensitive-location"],
                "citation": {"source": "SECURITY/Policy/Secrets metadata inventory"},
                "reportability": "metadata-only",
            }
        )
    return rows


def sam_security_context_manifest(
    *,
    source_path: str,
    source_hashes: Mapping[str, str],
    account: Mapping[str, object],
    security_context: Mapping[str, object],
    security_context_rows: Sequence[Mapping[str, object]],
    validation_checks: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    row_hashes = [stable_os_account_json_sha256(dict(row)) for row in security_context_rows]
    context_counts = Counter(str(row.get("context_type") or "") for row in security_context_rows if row.get("context_type"))
    high_risk_privileges = sorted(
        {
            str(row.get("privilege") or "")
            for row in security_context_rows
            if "high-risk-privilege" in list(row.get("risk_flags") or [])
        }
    )
    manifest: dict[str, object] = {
        "manifest_version": "sam-security-context-manifest-v1",
        "parser_version": PARSER_VERSION,
        "source": {
            "path": source_path,
            "sha256": source_hashes.get("sha256", ""),
            "format": "registry-export-or-sam-security-system-hints",
        },
        "account_identity": {
            "user_name": str(account.get("user_name") or ""),
            "rid": str(account.get("rid") or ""),
            "rid_decimal": rid_decimal(str(account.get("rid") or "")),
            "profile_path": str(account.get("profile_path") or ""),
            "account_disabled_hint": bool(account.get("account_disabled_hint")),
            "admin_hint": bool(account.get("admin_hint")),
            "uac_flags": list(account.get("uac_flags") or []),
        },
        "context_summary": {
            "row_count": len(security_context_rows),
            "row_hashes": row_hashes,
            "row_hash_manifest_sha256": stable_os_account_json_sha256(row_hashes),
            "context_type_counts": dict(sorted(context_counts.items())),
            "privileged_group_count": int(security_context.get("privileged_group_count") or 0),
            "inherited_privilege_count": int(security_context.get("inherited_privilege_count") or 0),
            "service_account_match_count": int(security_context.get("service_account_match_count") or 0),
            "lsa_sensitive_location_count": int(security_context.get("lsa_sensitive_location_count") or 0),
            "high_risk_privileges": high_risk_privileges,
        },
        "citation_refs": [
            {
                "kind": "account-source",
                "ref_id": "account-source",
                "source_path": source_path,
                "source_sha256": source_hashes.get("sha256", ""),
                "source_viewer_locator": {
                    "viewer": "registry-or-os-account-source",
                    "user_name": str(account.get("user_name") or ""),
                    "rid": str(account.get("rid") or ""),
                },
            },
            {
                "kind": "normalized-security-context-rows",
                "ref_id": "normalized-security-context-rows",
                "row_count": len(security_context_rows),
                "row_hashes": row_hashes[:100],
                "source_viewer_locator": {
                    "viewer": "account-security-context",
                    "row_types": sorted(context_counts),
                },
            },
        ],
        "validation_summary": {
            "passed_check_ids": [
                key.replace("_", "-")
                for key, value in validation_checks.items()
                if bool(value) and not key.startswith("requires_")
            ],
            "required_validation_ids": [
                key.replace("_", "-")
                for key, value in validation_checks.items()
                if bool(value) and key.startswith("requires_")
            ],
            "report_grade_status": str(report_grade.get("status") or ""),
            "commercial_gap_ids": list(report_grade.get("commercial_gap_ids") or []),
        },
        "reportability": {
            "allowed_use": "account-security-triage-pivot",
            "ready_for_court_report": bool(report_grade.get("report_grade_ready")),
            "validation_required": not bool(report_grade.get("report_grade_ready")),
            "secret_values_redacted": True,
            "blockers": list(report_grade.get("blockers") or []),
        },
        "large_data_controls": {
            "row_hashes_are_bounded": True,
            "secret_values_are_not_indexed": True,
            "safe_for_case_db_indexing": True,
        },
    }
    manifest["manifest_sha256"] = stable_os_account_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def stable_os_account_json_sha256(value: Mapping[str, object] | Sequence[object]) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def account_lifecycle_confidence(account: dict[str, object], group_rows: list[dict[str, object]]) -> float:
    score = 0.58
    if account.get("user_name"):
        score += 0.08
    if account.get("rid"):
        score += 0.08
    if account.get("last_logon_at") or account.get("created_at"):
        score += 0.08
    if group_rows:
        score += 0.06
    return min(0.88, round(score, 2))


def account_lifecycle_risk_flags(account: dict[str, object], group_rows: list[dict[str, object]]) -> list[str]:
    flags: list[str] = ["account-lifecycle-hint"]
    if account.get("admin_hint"):
        flags.append("admin-account-hint")
    if account.get("account_disabled_hint"):
        flags.append("disabled-account-hint")
    for group in group_rows:
        if is_privileged_group_name(str(group.get("group_name") or "")):
            flags.append("privileged-group-membership-hint")
    return sorted(set(flags))


def group_membership_risk_flags(group: dict[str, object]) -> list[str]:
    flags = ["group-membership-hint"]
    if group.get("privileged_group"):
        flags.append("privileged-group-membership-hint")
    if group.get("member_sids"):
        flags.append("sid-membership-hint")
    if group.get("member_names"):
        flags.append("name-membership-hint")
    return sorted(set(flags))


def sam_group_risk_flags(group_name: str, alias_rid_hex: str, candidate: dict[str, object]) -> list[str]:
    flags = ["sam-group-key-candidate"]
    if is_privileged_group_name(group_name) or alias_rid_hex.upper() == "00000220":
        flags.append("privileged-group-candidate")
    if candidate.get("allocation_status") == "free-or-deleted-candidate":
        flags.append("deleted-or-free-sam-group-key-candidate")
    return sorted(set(flags))


def is_privileged_group_name(group_name: str) -> bool:
    return group_name.lower() in {"administrators", "domain admins", "enterprise admins", "account operators", "backup operators"}


def service_risk_flags(service: dict[str, object]) -> list[str]:
    image = str(service.get("image_path") or "").lower()
    flags: list[str] = []
    if any(term in image for term in ("appdata", "\\temp\\", "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta")):
        flags.append("suspicious-service-image-path")
    if str(service.get("start_type") or "") in {"2", "0x2"}:
        flags.append("service-auto-start")
    return sorted(set(flags))


def service_start_type_label(value: object) -> str:
    labels = {"0": "boot", "1": "system", "2": "automatic", "3": "manual", "4": "disabled"}
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        try:
            text = str(int(text, 16))
        except ValueError:
            pass
    return labels.get(text, "")


def privilege_risk_flags(item: dict[str, object]) -> list[str]:
    privilege = str(item.get("privilege") or "").lower()
    flags = ["privilege-assignment"]
    if privilege in {"sedebugprivilege", "setcbprivilege", "seimpersonateprivilege", "seloadriverprivilege"}:
        flags.append("high-risk-privilege")
    return flags


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
            "uac_flags": [],
            "sam_binary_fields": {},
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
    if lowered_name in {"f", "v"}:
        binary_fields = hint.setdefault("sam_binary_fields", {})
        if isinstance(binary_fields, dict):
            decoded = decode_sam_binary_field(lowered_name.upper(), value)
            binary_fields[lowered_name.upper()] = decoded
            apply_sam_binary_decoded_fields(hint, lowered_name.upper(), decoded)
    if lowered_name == "@" and account_name_from_key(key):
        parsed = parse_int(value)
        if parsed is not None:
            hint["rid"] = f"{parsed:08X}"
    elif lowered_name in {"username", "name", "accountname"} and value:
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
            hint["uac_flags"] = user_account_control_flags(number)


def account_lifecycle_validation_checks(account: dict[str, object], group_rows: list[dict[str, object]]) -> dict[str, object]:
    binary_fields = account.get("sam_binary_fields") if isinstance(account.get("sam_binary_fields"), dict) else {}
    f_field = binary_fields.get("F") if isinstance(binary_fields.get("F"), dict) else {}
    v_field = binary_fields.get("V") if isinstance(binary_fields.get("V"), dict) else {}
    return {
        "has_user_name": bool(account.get("user_name")),
        "has_rid": bool(account.get("rid")),
        "has_created_timestamp": bool(account.get("created_at")),
        "has_last_logon_timestamp": bool(account.get("last_logon_at")),
        "has_password_last_set_timestamp": bool(account.get("password_last_set_at")),
        "has_uac_flags": bool(account.get("uac_flags")),
        "has_group_membership_hint": bool(group_rows),
        "has_sam_f_value": "F" in binary_fields,
        "has_sam_v_value": "V" in binary_fields,
        "has_decoded_sam_f_timestamps": bool(f_field.get("decoded_timestamps")),
        "has_decoded_sam_f_uac": bool(f_field.get("user_account_control_flags")),
        "has_decoded_sam_v_strings": bool(v_field.get("string_candidates")),
        "has_decoded_sam_v_layout_fields": bool(v_field.get("layout_string_fields")),
        "native_sam_fv_candidate_decoding_available": bool(f_field.get("decoded") or v_field.get("decoded")),
        "native_sam_fv_report_grade": False,
        "requires_second_parser_validation": True,
    }


def decode_sam_binary_field(field_name: str, value: str) -> dict[str, object]:
    raw = parse_reg_binary(value)
    decoded: dict[str, object] = {
        "present": True,
        "byte_count": len(raw),
        "decoded": False,
        "decoder_scope": "sam-fv-triage-candidate",
        "validation_note": "SAM F/V binary field is partially decoded for triage only; validate offsets against OS version and a second parser before testimony.",
    }
    if field_name == "F":
        f_decoded = decode_sam_f_value(raw)
        decoded.update(f_decoded)
        decoded["decoded"] = bool(f_decoded)
    elif field_name == "V":
        v_decoded = decode_sam_v_value(raw)
        decoded.update(v_decoded)
        decoded["decoded"] = bool(v_decoded.get("string_candidates") or v_decoded.get("layout_string_fields"))
    return decoded


def decode_sam_f_value(raw: bytes) -> dict[str, object]:
    if len(raw) < 16:
        return {}
    timestamp_offsets = {
        "last_logon_at": 0x08,
        "password_last_set_at": 0x18,
        "account_expires_at": 0x20,
        "last_failed_logon_at": 0x28,
    }
    decoded_timestamps: dict[str, str] = {}
    for name, offset in timestamp_offsets.items():
        if offset + 8 > len(raw):
            continue
        parsed = filetime_to_iso(int.from_bytes(raw[offset : offset + 8], "little", signed=False))
        if parsed:
            decoded_timestamps[name] = parsed
    result: dict[str, object] = {}
    if decoded_timestamps:
        result["decoded_timestamps"] = decoded_timestamps
    if len(raw) >= 0x34:
        rid = int.from_bytes(raw[0x30:0x34], "little", signed=False)
        if 0 < rid < 0x10000000:
            result["rid_decimal_candidate"] = rid
            result["rid_hex_candidate"] = f"{rid:08X}"
    if len(raw) >= 0x38:
        primary_group = int.from_bytes(raw[0x34:0x38], "little", signed=False)
        if 0 < primary_group < 0x10000000:
            result["primary_group_rid_candidate"] = primary_group
    if len(raw) >= 0x3C:
        uac = int.from_bytes(raw[0x38:0x3C], "little", signed=False)
        if uac:
            result["user_account_control_candidate"] = uac
            result["user_account_control_flags"] = user_account_control_flags(uac)
    if len(raw) >= 0x44:
        result["country_code_candidate"] = int.from_bytes(raw[0x3C:0x3E], "little", signed=False)
        result["bad_password_count_candidate"] = int.from_bytes(raw[0x40:0x42], "little", signed=False)
        result["logon_count_candidate"] = int.from_bytes(raw[0x42:0x44], "little", signed=False)
    return result


def decode_sam_v_value(raw: bytes) -> dict[str, object]:
    """Extract conservative SAM V string metadata without claiming OS-version-complete decoding."""

    strings = extract_utf16le_strings(raw, min_chars=3, limit=20)
    result: dict[str, object] = {
        "string_candidates": strings,
        "layout_profile": "sam-v-offset-length-candidate-v1",
        "layout_base_offset": SAM_V_DATA_BASE_OFFSET,
        "layout_validation_status": "fallback-string-scan",
        "layout_string_fields": {},
        "layout_field_candidates": [],
    }
    if len(raw) < SAM_V_DATA_BASE_OFFSET:
        return result

    field_values: dict[str, str] = {}
    field_candidates: list[dict[str, object]] = []
    for field_name, descriptor_offset in SAM_V_STRING_LAYOUT:
        candidate = decode_sam_v_string_descriptor(raw, field_name, descriptor_offset)
        if not candidate:
            continue
        field_candidates.append(candidate)
        if candidate.get("decoded_text"):
            field_values[field_name] = str(candidate["decoded_text"])

    if field_candidates:
        result["layout_field_candidates"] = field_candidates
        result["layout_string_fields"] = field_values
        result["layout_validation_status"] = (
            "layout-string-candidates-present" if field_values else "layout-descriptors-present-no-text"
        )
        result["reportability_warning"] = (
            "SAM V offsets are treated as OS-version-sensitive candidates; validate field semantics "
            "with a trusted SAM parser before final account testimony."
        )
    return result


def decode_sam_v_string_descriptor(raw: bytes, field_name: str, descriptor_offset: int) -> dict[str, object]:
    if descriptor_offset + 8 > len(raw):
        return {}
    relative_offset = int.from_bytes(raw[descriptor_offset : descriptor_offset + 4], "little", signed=False)
    length = int.from_bytes(raw[descriptor_offset + 4 : descriptor_offset + 8], "little", signed=False)
    allocated_length = (
        int.from_bytes(raw[descriptor_offset + 8 : descriptor_offset + 12], "little", signed=False)
        if descriptor_offset + 12 <= len(raw)
        else 0
    )
    if length <= 0:
        return {}
    absolute_offset = SAM_V_DATA_BASE_OFFSET + relative_offset
    within_bounds = absolute_offset >= SAM_V_DATA_BASE_OFFSET and absolute_offset + length <= len(raw)
    candidate = {
        "field": field_name,
        "descriptor_offset": descriptor_offset,
        "relative_offset": relative_offset,
        "absolute_offset": absolute_offset,
        "byte_length": length,
        "allocated_length": allocated_length,
        "within_bounds": within_bounds,
        "decoded_text": "",
    }
    if not within_bounds:
        return candidate
    raw_text = raw[absolute_offset : absolute_offset + length]
    try:
        text = raw_text.decode("utf-16le", errors="ignore").rstrip("\x00")
    except UnicodeError:
        text = ""
    if text and is_printable_sam_text(text):
        candidate["decoded_text"] = text
    return candidate


def is_printable_sam_text(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    printable = sum(1 for char in stripped if char.isprintable())
    return printable / max(len(stripped), 1) >= 0.85


def apply_sam_binary_decoded_fields(hint: dict[str, object], field_name: str, decoded: dict[str, object]) -> None:
    if field_name == "F":
        timestamps = decoded.get("decoded_timestamps") if isinstance(decoded.get("decoded_timestamps"), dict) else {}
        if not hint.get("last_logon_at") and timestamps.get("last_logon_at"):
            hint["last_logon_at"] = timestamps["last_logon_at"]
        if not hint.get("password_last_set_at") and timestamps.get("password_last_set_at"):
            hint["password_last_set_at"] = timestamps["password_last_set_at"]
        if not hint.get("rid") and decoded.get("rid_hex_candidate"):
            hint["rid"] = decoded["rid_hex_candidate"]
        if decoded.get("user_account_control_flags"):
            hint["uac_flags"] = sorted(set([*list(hint.get("uac_flags") or []), *list(decoded.get("user_account_control_flags") or [])]))
            hint["account_disabled_hint"] = bool(hint.get("account_disabled_hint") or "ACCOUNTDISABLE" in hint["uac_flags"])
    elif field_name == "V":
        layout_fields = decoded.get("layout_string_fields") if isinstance(decoded.get("layout_string_fields"), dict) else {}
        if not hint.get("user_name") and layout_fields.get("user_name"):
            hint["user_name"] = layout_fields["user_name"]
        if not hint.get("profile_path") and layout_fields.get("profile_path"):
            hint["profile_path"] = layout_fields["profile_path"]
        strings = decoded.get("string_candidates") if isinstance(decoded.get("string_candidates"), list) else []
        if strings:
            if not hint.get("user_name"):
                hint["user_name"] = strings[0]


def user_account_control_flags(value: int) -> list[str]:
    flags = {
        0x0002: "ACCOUNTDISABLE",
        0x0010: "LOCKOUT",
        0x0020: "PASSWD_NOTREQD",
        0x0200: "NORMAL_ACCOUNT",
        0x10000: "DONT_EXPIRE_PASSWORD",
        0x40000: "SMARTCARD_REQUIRED",
        0x80000: "TRUSTED_FOR_DELEGATION",
        0x100000: "NOT_DELEGATED",
        0x400000: "DONT_REQ_PREAUTH",
        0x800000: "PASSWORD_EXPIRED",
    }
    return [label for bit, label in flags.items() if value & bit]


def reg_binary_byte_count(value: str) -> int:
    return len(parse_reg_binary(value))


def parse_reg_binary(value: str) -> bytes:
    text = value.strip()
    if ":" in text:
        text = text.split(":", 1)[1]
    items: list[int] = []
    for item in text.replace("\\", "").replace("\n", "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            items.append(int(item, 16))
        except ValueError:
            continue
    return bytes(items)


def extract_utf16le_strings(raw: bytes, *, min_chars: int, limit: int) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for index in range(0, len(raw) - 1, 2):
        code_unit = raw[index : index + 2]
        value = int.from_bytes(code_unit, "little", signed=False)
        if 32 <= value <= 0xD7FF or 0xE000 <= value <= 0xFFFD:
            current.extend(code_unit)
            continue
        if len(current) >= min_chars * 2:
            decoded = current.decode("utf-16le", errors="ignore").strip("\x00\r\n\t ")
            if decoded and decoded not in strings:
                strings.append(decoded)
                if len(strings) >= limit:
                    return strings
        current.clear()
    if len(current) >= min_chars * 2:
        decoded = current.decode("utf-16le", errors="ignore").strip("\x00\r\n\t ")
        if decoded and decoded not in strings:
            strings.append(decoded)
    return strings[:limit]


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
