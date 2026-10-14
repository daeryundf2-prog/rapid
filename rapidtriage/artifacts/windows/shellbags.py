from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .._walk import iter_evidence_paths
from .registry import (
    HIVE_BIN_BASE_OFFSET,
    candidate_registry_hive_paths,
    collect_reg_export,
    file_hashes,
    hive_hint_from_path,
    registry_transaction_log_evidence,
)

PARSER_VERSION = "windows-shellbags-native-v5"
SHELLBAG_USER_HIVES = {"NTUSER.DAT", "USRCLASS.DAT"}
SHELLBAG_BLOCKERS = [
    "binary shell item payload decoding is not report-grade yet",
    "bag/node relationships require validation against a dedicated ShellBags parser",
    "registry transaction logs are not replayed",
    "deleted or slack ShellBag testimony is not validated",
    "trusted ShellBags parser diff is required",
]
SHELLBAG_TRUSTED_TOOLS = {"shellbagsexplorer", "sbecmd", "recmd", "registryexplorer", "regripper"}
SHELLBAG_CAPABILITIES = {
    "reg_export_shellbag_key_mapping": True,
    "native_user_hive_key_tree_candidates": False,
    "native_string_pivot_candidates": False,
    "native_full_bagmru_walk": True,
    "bag_id_candidate_extraction": True,
    "node_id_candidate_extraction": True,
    "key_last_write_timestamp_hint": True,
    "binary_shell_item_decode": True,
    "bag_node_relationship_validation": False,
    "transaction_log_replay": False,
    "deleted_slack_shellbag_validation": False,
}


class WindowsShellbagsProvider:
    collector_kind = "windows-shellbags"
    name = "windows-shellbags"
    description = "Windows ShellBags from Registry exports and native user-hive candidates"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        from .registry import RegistryCollectionContext

        for path in sorted(iter_evidence_paths(root, "*.reg"), key=lambda item: str(item).lower()):
            if not path.is_file():
                continue
            for record in collect_reg_export(path):
                key = str(record.details.get("key") or "").lower()
                if "shell\\bagmru" not in key and "shellnoroam\\bagmru" not in key:
                    continue
                details = dict(record.details)
                details["parser"] = "windows-shellbags-reg-export"
                yield ArtifactRecord(
                    provider=self.name,
                    artifact_type="shellbag-key",
                    path=record.path,
                    supported=True,
                    details=details,
                )
        context = RegistryCollectionContext(root)
        for path in candidate_registry_hive_paths(root):
            if path.name.upper() not in SHELLBAG_USER_HIVES:
                continue
            yield from collect_native_shellbag_hive(path, context=context)


def shellbag_core_accuracy_gates(details: Mapping[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("shellbag_trusted_diff")
        if isinstance(details.get("shellbag_trusted_diff"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"cell_offset:{details.get('cell_offset', '')}",
        f"hbin_offset:{details.get('hbin_offset', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if details.get("bag_id_candidates") or details.get("node_id_candidates") or details.get("shellbag_section") in {"bagmru", "bags"}:
        satisfied.append("BagMRU/Bags relationship")
    relationship_profile = (
        details.get("shellbag_relationship_profile")
        if isinstance(details.get("shellbag_relationship_profile"), Mapping)
        else {}
    )
    if relationship_profile.get("relationship_hash"):
        satisfied.append("relationship lineage profile")
    if checks.get("binary_shell_item_decoding_available"):
        satisfied.append("shell item binary decoding")
    if details.get("timestamp_candidates"):
        satisfied.append("timestamp source labeling")
    if details.get("user_hive_scope") in {"ntuser", "usrclass"} or str(details.get("hive_name") or "").upper() in {"NTUSER.DAT", "USRCLASS.DAT"}:
        satisfied.append("UsrClass/NTUSER correlation")
    if checks.get("transaction_log_context_recorded") or details.get("registry_transaction_log_evidence"):
        satisfied.append("transaction log context recorded")
    if not SHELLBAG_CAPABILITIES["deleted_slack_shellbag_validation"]:
        satisfied.append("deleted/slack validation warning")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted ShellBags parser diff pass")
    return [build_accuracy_gate(15, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_shellbag_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_shellbag_diff_payload(
        index_shellbag_rows(rapid_rows),
        index_shellbag_rows(trusted_rows),
        trusted_tool=trusted_tool,
    )


def index_shellbag_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = shellbag_diff_row_payload(row)
        evidence = payload.get("shellbag_evidence") if isinstance(payload.get("shellbag_evidence"), Mapping) else {}
        key_evidence = evidence.get("key_evidence") if isinstance(evidence.get("key_evidence"), Mapping) else {}
        relationship = evidence.get("relationship_evidence") if isinstance(evidence.get("relationship_evidence"), Mapping) else {}
        activity = evidence.get("activity_evidence") if isinstance(evidence.get("activity_evidence"), Mapping) else {}

        source_key_path = normalized_diff_value(
            first_present(
                first_alias(payload, "source_key_path", "key_path", "registry_path", "keypath"),
                first_alias(key_evidence, "source_key_path", "key_path", "registry_path", "keypath"),
            )
        )
        folder_path = normalized_diff_list(
            first_present(
                first_alias(payload, "folder_path", "shellbag_path", "path", "target_path", "shellbag_path_candidates", "path_candidates"),
                first_alias(activity, "folder_path", "shellbag_path", "path", "target_path", "path_candidates"),
            )
        )
        bag_id = normalized_diff_list(
            first_present(
                first_alias(payload, "bag_id", "bag", "bag_id_candidates", "bagid"),
                first_alias(relationship, "bag_id", "bag", "bag_id_candidates", "bagid"),
            )
        )
        node_id = normalized_diff_list(
            first_present(
                first_alias(payload, "node_id", "node", "node_id_candidates", "nodeid"),
                first_alias(relationship, "node_id", "node", "node_id_candidates", "nodeid"),
            )
        )
        key = source_key_path or "|".join(item for item in (folder_path, bag_id, node_id) if item)
        if not key:
            continue
        indexed[key] = {
            "source_key_path": source_key_path,
            "folder_path": folder_path,
            "bag_id": bag_id,
            "node_id": node_id,
            "timestamp": normalized_diff_value(
                first_present(
                    first_alias(payload, "timestamp", "key_last_written_at", "last_write_time", "lastwritetime"),
                    first_alias(activity, "primary_timestamp", "timestamp", "key_last_written_at", "last_write_time"),
                )
            ),
            "hive": normalized_diff_value(first_alias(payload, "hive_name", "hive", "source_hive")),
            "section": normalized_diff_value(
                first_present(
                    first_alias(payload, "shellbag_section", "section"),
                    first_alias(key_evidence, "shellbag_section", "section"),
                )
            ),
            "cell_offset": normalized_int_text(
                first_present(
                    first_alias(payload, "cell_offset", "key_cell_offset", "source_offset"),
                    first_alias(key_evidence, "cell_offset", "key_cell_offset", "source_offset"),
                )
            ),
            "hbin_offset": normalized_int_text(
                first_present(
                    first_alias(payload, "hbin_offset", "hbin"),
                    first_alias(key_evidence, "hbin_offset", "hbin"),
                )
            ),
            "allocation_status": normalized_diff_value(
                first_present(
                    first_alias(payload, "allocation_status", "allocated", "cell_state"),
                    first_alias(key_evidence, "allocation_status", "allocated", "cell_state"),
                )
            ),
            "transaction_status": normalized_diff_value(
                first_present(
                    first_alias(payload, "transaction_log_status", "transaction_status"),
                    first_alias(key_evidence, "transaction_log_status", "transaction_status"),
                )
            ),
        }
    return indexed


def shellbag_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def build_shellbag_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in SHELLBAG_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append(
                    {
                        "shellbag_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "shellbags-trusted-diff-v1",
        "status": status,
        "trusted_tool": trusted_tool,
        "trusted_tool_recognized": recognized,
        "rapid_indexed_count": len(rapid_index),
        "trusted_indexed_count": len(trusted_index),
        "matched_count": len(common) - len(mismatches),
        "mismatch_count": len(mismatches),
        "missing_in_trusted_count": len(missing),
        "extra_in_trusted_count": len(extra),
        "mismatches": mismatches[:25],
        "missing_in_trusted_sample": missing[:25],
        "extra_in_trusted_sample": extra[:25],
        "commercial_grade_evidence": status == "pass",
        "reportability_decision": {
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-shellbags-output-as-final",
            "blockers": [] if status == "pass" else ["shellbags-trusted-diff-required"],
        },
    }


def first_alias(row: Mapping[str, object], *aliases: str) -> object:
    normalized = {normalize_key(key): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(normalize_key(alias))
        if value not in (None, ""):
            return value
    return ""


def normalize_key(value: object) -> str:
    return "".join(ch for ch in str(value).lower() if ch.isalnum())


def normalized_diff_value(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("\\", "/").split())


def first_present(*values: object) -> object:
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [normalize_shellbag_list_item(item) for item in value]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalize_shellbag_list_item(value: object) -> str:
    if isinstance(value, Mapping):
        return str(first_alias(value, "path", "folder_path", "timestamp", "value", "id", "name") or "").strip()
    return str(value).strip()


def normalized_int_text(value: object) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return normalized_diff_value(text)


# ---------------------------------------------------------------------------
# Native ShellBags: BagMRU walk over the full hive + shell item decoding.
# ---------------------------------------------------------------------------

SHELLBAG_BAGMRU_PARENT_NAMES = {"shell", "shellnoroam"}
SHELL_ITEM_BEEF0004 = b"\x04\x00\xef\xbe"
SHELL_ITEM_KNOWN_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
    "2227a280-3aea-1069-a2de-08002b30309d": "Printers",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "0762d272-c50a-4bb0-a382-697dcd729b80": "Users",
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "System32",
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": "Program Files",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "Program Files (x86)",
    "6d809377-6af0-444b-8957-a3773f02200e": "Program Files",
    "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97": "ProgramData",
    "a39193cc-55b8-4244-aa44-e9bc5db04762": "ProgramData",
    "b6ebfb86-6907-413c-9af7-4fc2abf07cc5": "Public",
    "9339a431-9b4a-432e-a46b-95d20c17ea11": "Common AppData",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "User Profile",
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": "Documents",
    "e88865ea-0e1c-4e20-9aa6-edcd0212c87c": "Gallery",
    "f874310e-b6b7-47dc-bc84-b9e6b38f5903": "Home",
    "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
    "a0953c92-50dc-43bf-be83-3742fed03c9c": "Videos",
    "7b0db17d-9cd2-4a93-9733-46cc89022e7c": "Documents Library",
    "2112ab0a-c86a-4ffe-a368-0de96e47012e": "Music Library",
    "a990ae9f-a03b-4e80-94bc-9912d7504104": "Pictures Library",
    "491e922f-5643-4af4-a7eb-4e7a138d8174": "Videos Library",
    "3080f90d-d7ad-11d9-bd98-0000947b0257": "Desktop",
    "35786d3c-b075-49b9-88dd-029876e11c01": "Portable Devices",
    "9113a02d-00a3-46b9-bc5f-9c04daddd5d7": "Device Center",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer",
    "e17d4fc0-5564-11d1-83f2-00a0c90dc849": "Search Results",
    "9343812e-1c37-4a49-a12e-4b2d810d956b": "Search Home",
    "04731b67-d933-450a-90e6-4acd2e9408fe": "Search Folder",
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music",
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": "Pictures",
    "a0c69a99-21c8-4671-8703-7934162fcf1d": "Music",
    "b3690e58-e961-423b-b687-386ebfd83239": "Pictures",
    "f3364ba0-65b9-11ce-a9ba-00aa004ae837": "Shell File System Folder",
}


def shell_item_guid_name(raw: bytes) -> tuple[str, str]:
    import uuid

    if len(raw) < 16:
        return "", ""
    try:
        guid = str(uuid.UUID(bytes_le=bytes(raw[:16]))).lower()
    except ValueError:
        return "", ""
    return guid, SHELL_ITEM_KNOWN_GUIDS.get(guid, "")


def shell_item_ansi(raw: bytes) -> str:
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    if not raw:
        return ""
    try:
        return raw.decode("cp949")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def shell_item_utf16(raw: bytes) -> str:
    cursor = 0
    while cursor + 1 < len(raw):
        if raw[cursor] == 0 and raw[cursor + 1] == 0:
            break
        cursor += 2
    return raw[:cursor].decode("utf-16-le", errors="replace")


def shell_item_dos_datetime(date_value: int, time_value: int) -> str:
    """FAT date/time from a shell item; Explorer stores these in UTC."""
    if not date_value:
        return ""
    try:
        moment = dt.datetime(
            1980 + (date_value >> 9),
            (date_value >> 5) & 0x0F,
            date_value & 0x1F,
            time_value >> 11,
            (time_value >> 5) & 0x3F,
            (time_value & 0x1F) * 2,
            tzinfo=dt.timezone.utc,
        )
    except ValueError:
        return ""
    return moment.isoformat()


def shell_item_longest_utf16(raw: bytes, *, min_chars: int = 2) -> str:
    best = ""
    for alignment in (0, 1):
        run: list[str] = []
        for index in range(alignment, len(raw) - 1, 2):
            code = raw[index] | (raw[index + 1] << 8)
            if 0x20 <= code < 0xD800 or 0xE000 <= code < 0xFFFE:
                run.append(chr(code))
                continue
            if len(run) >= min_chars and len(run) > len(best):
                best = "".join(run)
            run = []
        if len(run) >= min_chars and len(run) > len(best):
            best = "".join(run)
    return best.strip()


def split_shell_item_list(blob: bytes, *, limit: int = 4096) -> list[bytes]:
    items: list[bytes] = []
    cursor = 0
    while cursor + 2 <= len(blob) and len(items) < limit:
        size = int.from_bytes(blob[cursor : cursor + 2], "little")
        if size == 0:
            break
        if size < 3 or cursor + size > len(blob):
            items.append(blob[cursor:])
            break
        items.append(blob[cursor : cursor + size])
        cursor += size
    return items


def decode_beef0004_block(item: bytes) -> dict[str, object]:
    index = item.find(SHELL_ITEM_BEEF0004)
    if index < 4:
        return {}
    block = item[index - 4 :]
    if len(block) < 0x14:
        return {}
    version = int.from_bytes(block[2:4], "little")
    result: dict[str, object] = {
        "extension_version": version,
        "created_at": shell_item_dos_datetime(
            int.from_bytes(block[8:10], "little"), int.from_bytes(block[10:12], "little")
        ),
        "accessed_at": shell_item_dos_datetime(
            int.from_bytes(block[12:14], "little"), int.from_bytes(block[14:16], "little")
        ),
    }
    if version >= 7 and len(block) >= 0x1C:
        reference = int.from_bytes(block[0x14:0x1C], "little")
        result["mft_entry"] = reference & 0xFFFFFFFFFFFF
        result["mft_sequence"] = reference >> 48
    if version >= 9:
        name_offset = 0x2E
    elif version >= 8:
        name_offset = 0x2A
    elif version >= 7:
        name_offset = 0x26
    elif version >= 3:
        name_offset = 0x14
    else:
        name_offset = 0
    if name_offset and name_offset < len(block):
        long_name = shell_item_utf16(block[name_offset:])
        if long_name:
            result["long_name"] = long_name
    return result


def decode_shell_item_entry(item: bytes) -> dict[str, object]:
    """Decode one SHITEMID into kind/name/times; never raises."""
    if len(item) < 3:
        return {"item_kind": "truncated", "name": "", "item_type": 0, "decode_method": "truncated"}
    item_type = item[2]
    result: dict[str, object] = {"item_type": item_type, "item_type_hex": f"0x{item_type:02x}", "size": len(item)}
    signature = item[6:10] if len(item) >= 10 else b""
    if item_type == 0x1F and signature == b"\xd5\xdf\xa3\x23":
        name, method, embedded = shell_item_users_property_view_name(item)
        result.update(item_kind="users-property-view", decode_method=method if name else "unresolved")
        result["name"] = name or "<사용자 속성 보기>"
        if embedded:
            result["embedded_path"] = embedded
        return result
    if item_type == 0x01 and len(item) >= 12 and item[4:8] == b"\x84\x21\xde\x39":
        category = int.from_bytes(item[8:12], "little")
        result.update(
            item_kind="control-panel-category",
            category_id=category,
            name=CONTROL_PANEL_CATEGORIES.get(category, f"<제어판 범주 {category}>"),
            decode_method="control-panel-category",
        )
        return result
    if item_type == 0x1F and len(item) > 20:
        drive = re.search(rb"\x2f([A-Za-z]):\\", item)
        guid, known = shell_item_guid_name(item[4:20])
        if drive and not known:
            # Root item wrapping a drive (removable/portable volume): name the volume.
            letter = drive.group(1).decode("ascii").upper()
            result.update(item_kind="volume", name=f"{letter}:\\", decode_method="root-embedded-drive", guid=guid)
            return result
    if item_type == 0x1F:
        guid, known = shell_item_guid_name(item[4:20])
        result.update(item_kind="root", guid=guid, sort_index=item[3] if len(item) > 3 else 0)
        result["name"] = known or (f"{{{guid}}}" if guid else "<root>")
        result["decode_method"] = "known-folder-guid" if known else "guid"
        return result
    if 0x20 <= item_type <= 0x2F:
        text = shell_item_ansi(item[3:]) if len(item) > 3 else ""
        if len(text) >= 2 and text[1] == ":":
            result.update(item_kind="volume", name=text.rstrip("\\") + "\\", decode_method="drive-letter")
            return result
        guid, known = shell_item_guid_name(item[4:20]) if len(item) >= 20 else ("", "")
        result.update(item_kind="volume", guid=guid, decode_method="volume-guid" if guid else "unresolved")
        result["name"] = known or (f"{{{guid}}}" if guid else "<volume>")
        return result
    if 0x30 <= item_type <= 0x3F or item_type == 0xB1:
        return decode_shell_file_entry(item, result)
    if 0x40 <= item_type <= 0x4F or item_type == 0xC3:
        flags = item[3] if len(item) > 3 else 0
        name = shell_item_ansi(item[5:]) if len(item) > 5 else ""
        result.update(item_kind="network", name=name or "<네트워크>", network_flags=flags, decode_method="network-ansi")
        if name.startswith("\\\\"):
            result["network_path"] = name
        return result
    if item_type == 0x71:
        guid, known = shell_item_guid_name(item[14:30]) if len(item) >= 30 else ("", "")
        if not guid:
            guid, known = shell_item_guid_name(item[4:20])
        result.update(item_kind="control-panel", guid=guid, decode_method="control-panel-guid")
        result["name"] = known or (f"{{{guid}}}" if guid else "<제어판>")
        return result
    if item_type == 0x61:
        name = shell_item_longest_utf16(item[4:], min_chars=4) or shell_item_ansi(item[8:])
        result.update(item_kind="uri", name=name or "<URI>", decode_method="uri-string")
        return result
    if item_type == 0x74 or signature == b"CFSF" or item[4:8] == b"CFSF":
        result.update(item_kind="delegate")
        block = decode_beef0004_block(item)
        if block:
            result.update(block)
        name = str(block.get("long_name") or "") if block else ""
        if not name:
            name = shell_item_ansi(item[0x18:]) if len(item) > 0x18 else ""
        result["name"] = name or "<위임 항목>"
        result["decode_method"] = "delegate-beef0004" if block.get("long_name") else "delegate-ansi"
        return result
    block = decode_beef0004_block(item)
    if block.get("long_name"):
        result.update(block)
        result.update(item_kind="other", name=str(block["long_name"]), decode_method="beef0004")
        return result
    name = shell_item_property_store_name(item)
    if not name:
        fallback = shell_item_longest_utf16(item[3:], min_chars=3)
        name = fallback if is_plausible_shell_text(fallback) else ""
    result.update(
        item_kind="other",
        name=name or f"<셸 항목 0x{item_type:02x}>",
        decode_method="utf16-scan" if name else "unsupported-type",
    )
    return result


def decode_shell_file_entry(item: bytes, result: dict[str, object]) -> dict[str, object]:
    item_type = int(result.get("item_type") or 0)
    is_directory = bool(item_type & 0x01)
    unicode_name = bool(item_type & 0x04)
    file_size = int.from_bytes(item[4:8], "little") if len(item) >= 8 else 0
    modified = (
        shell_item_dos_datetime(int.from_bytes(item[8:10], "little"), int.from_bytes(item[10:12], "little"))
        if len(item) >= 12
        else ""
    )
    attributes = int.from_bytes(item[12:14], "little") if len(item) >= 14 else 0
    short_name = shell_item_utf16(item[14:]) if unicode_name else shell_item_ansi(item[14:])
    block = decode_beef0004_block(item)
    long_name = str(block.get("long_name") or "")
    result.update(
        item_kind="directory" if is_directory or attributes & 0x10 else "file",
        short_name=short_name,
        long_name=long_name,
        name=long_name or short_name or f"<파일 항목 0x{item_type:02x}>",
        file_size=file_size,
        file_attributes=attributes,
        modified_at=modified,
        decode_method="beef0004-long-name" if long_name else ("short-name" if short_name else "unresolved"),
    )
    for key in ("created_at", "accessed_at", "mft_entry", "mft_sequence", "extension_version"):
        if key in block:
            result[key] = block[key]
    return result


SHELL_PROPERTY_FMTID_ITEM = "b725f130-47ef-101a-a5f1-02608c9eebac"
SHELL_PROPERTY_FMTID_NAMED = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
SHELL_PROPERTY_JUNK_STRINGS = {"autolist", "item", "items"}
CONTROL_PANEL_CATEGORIES = {
    0: "모든 제어판 항목",
    1: "모양 및 개인 설정",
    2: "하드웨어 및 소리",
    3: "네트워크 및 인터넷",
    4: "소리, 음성 및 오디오 장치",
    5: "시스템 및 보안",
    6: "시계, 언어 및 국가별 옵션",
    7: "접근성",
    8: "프로그램",
    9: "사용자 계정",
    10: "보안 센터",
    11: "모바일 PC",
}


def shell_item_property_strings(item: bytes) -> list[tuple[str, int, str]]:
    """(fmtid, property id, text) for every VT_LPWSTR in embedded 1SPS stores."""
    found: list[tuple[str, int, str]] = []
    cursor = item.find(b"1SPS")
    while cursor >= 4:
        storage_size = int.from_bytes(item[cursor - 4 : cursor], "little")
        end = min(len(item), cursor - 4 + storage_size) if storage_size else len(item)
        fmtid, _known = shell_item_guid_name(item[cursor + 4 : cursor + 20])
        entry = cursor + 20
        while fmtid != SHELL_PROPERTY_FMTID_NAMED and entry + 13 <= end:
            value_size = int.from_bytes(item[entry : entry + 4], "little")
            if value_size < 13 or entry + value_size > end:
                break
            property_id = int.from_bytes(item[entry + 4 : entry + 8], "little")
            payload = entry + 9
            value_type = int.from_bytes(item[payload : payload + 2], "little")
            if value_type == 0x1F and payload + 8 <= entry + value_size:
                text = shell_item_utf16(item[payload + 8 : entry + value_size]).strip()
                if text:
                    found.append((fmtid, property_id, text))
            entry += value_size
        cursor = item.find(b"1SPS", cursor + 4)
    return found


def shell_item_property_store_name(item: bytes) -> str:
    """System.ItemNameDisplay ({B725F130-...},10) from embedded property stores, if any."""
    for fmtid, property_id, text in shell_item_property_strings(item):
        if fmtid == SHELL_PROPERTY_FMTID_ITEM and property_id == 10 and is_plausible_shell_text(text):
            return text
    return ""


def is_plausible_shell_text(text: str) -> bool:
    if not text or text.casefold() in SHELL_PROPERTY_JUNK_STRINGS:
        return False
    lowered = text.casefold()
    if lowered.startswith(("prop", "autolist")):
        return False
    good = sum(
        1
        for char in text
        if 0x20 <= ord(char) < 0x7F or 0xAC00 <= ord(char) <= 0xD7A3 or 0x3131 <= ord(char) <= 0x318E
    )
    return good / len(text) >= 0.9


def shell_item_embedded_path(item: bytes) -> str:
    """Path of an IDList embedded in a users-property-view item (e.g. a UNC share)."""
    cursor = item.find(b"\x14\x00\x1f", 8)
    while cursor >= 0:
        chain = split_shell_item_list(item[cursor:])
        if chain and all(len(part) >= 3 for part in chain):
            names = [str(decode_shell_item_entry(part).get("name") or "") for part in chain]
            path = join_shell_path(names)
            if path:
                return path
        cursor = item.find(b"\x14\x00\x1f", cursor + 1)
    return ""


def shell_item_users_property_view_name(item: bytes) -> tuple[str, str, str]:
    display = shell_item_property_store_name(item)
    if display:
        return display, "property-store-item-name", shell_item_embedded_path(item)
    candidates = []
    for alignment in (0, 1):
        run: list[str] = []
        for index in range(alignment, len(item) - 1, 2):
            code = item[index] | (item[index + 1] << 8)
            if 0x20 <= code < 0xD800 or 0xE000 <= code < 0xFFFE:
                run.append(chr(code))
                continue
            if len(run) >= 3:
                candidates.append("".join(run).strip())
            run = []
    candidates = [text for text in candidates if is_plausible_shell_text(text)]
    embedded = shell_item_embedded_path(item)
    if candidates:
        return max(candidates, key=len), "utf16-display-string", embedded
    return embedded, "embedded-idlist", embedded


def decode_shell_item_list(blob: bytes) -> tuple[str, list[dict[str, object]]]:
    """Decode an IDList (PIDL) into a joined path plus per-item decodes."""
    items = [decode_shell_item_entry(item) for item in split_shell_item_list(blob)]
    return join_shell_path([str(item.get("name") or "") for item in items]), items


def join_shell_path(names: Sequence[str]) -> str:
    path = ""
    for name in names:
        if not name:
            continue
        if name.startswith("\\\\") or not path:
            path = name
        elif path.endswith("\\"):
            path += name
        else:
            path += "\\" + name
    return path


def parse_mru_list_ex(raw: object) -> list[int]:
    if not isinstance(raw, (bytes, bytearray)):
        return []
    order: list[int] = []
    for index in range(0, len(raw) - 3, 4):
        value = int.from_bytes(raw[index : index + 4], "little")
        if value == 0xFFFFFFFF:
            break
        order.append(value)
    return order


def collect_native_shellbag_hive(path: Path, *, context: object = None) -> Iterable[ArtifactRecord]:
    """Walk every Shell/ShellNoRoam BagMRU tree of a user hive and decode each slot."""
    from .registry import (
        NativeRegistryHive,
        RegistryCollectionContext,
        registry_hive_mount,
        registry_transaction_disclosure,
    )

    hive = NativeRegistryHive.open(path)
    if hive is None:
        return
    try:
        source_hashes = file_hashes(path)
        transaction_log_evidence = registry_transaction_log_evidence(path, hive_metadata=hive.header)
        disclosure = registry_transaction_disclosure(transaction_log_evidence)
        mount = registry_hive_mount(
            path,
            hive,
            context if isinstance(context, RegistryCollectionContext) else RegistryCollectionContext(None),
        )
        roots: list[tuple[tuple[str, ...], object]] = []
        bags_key_count = 0
        for components, key in hive.iter_keys():
            name = str(key.name or "").casefold()
            parent_name = components[-2].casefold() if len(components) >= 2 else str(hive.root.name or "").casefold()
            if parent_name in SHELLBAG_BAGMRU_PARENT_NAMES:
                if name == "bagmru":
                    roots.append((components, key))
                elif name == "bags":
                    bags_key_count += sum(1 for _ in hive.iter_keys(key)) - 1
        entry_count = 0
        kind_counts: Counter[str] = Counter()
        for components, root_key in roots:
            for record in iter_bagmru_entries(
                path,
                hive,
                root_key,
                components,
                mount=mount,
                source_hashes=source_hashes,
                transaction_disclosure=disclosure,
            ):
                if not record.details.get("bagmru_root"):
                    entry_count += 1
                    kind_counts[str(record.details.get("item_kind") or "")] += 1
                yield record
        yield ArtifactRecord(
            provider="windows-shellbags",
            artifact_type="shellbag-hive-summary",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "windows-shellbags-native-hive",
                "parser_version": PARSER_VERSION,
                "coverage_status": "native-bagmru-full-walk",
                "reportability": "triage",
                "label": "ShellBags 하이브 요약",
                "source_path": str(path.resolve()),
                "source_format": "registry-hive",
                "source_hashes": dict(source_hashes),
                "hive_name": path.name,
                "hive_mount": mount["mount"],
                "user_sid": mount["user_sid"],
                "bagmru_roots": [mount["mount"] + "\\" + "\\".join(parts) for parts, _ in roots],
                "shellbag_entry_count": entry_count,
                "item_kind_counts": dict(sorted(kind_counts.items())),
                "bags_view_settings_key_count_excluded": bags_key_count,
                "bags_exclusion_note": "Bags\\* 하위 키는 폴더 보기 설정(창 크기·정렬)이라 증거 행에서 제외하고 개수만 기록합니다.",
                "row_cap": None,
                "transaction_log_status": disclosure["status"],
                "transaction_log_disclosure": disclosure["message_ko"],
                "walk_errors": dict(hive.errors),
                "raw_preview": f"{path.name}: BagMRU {entry_count}개",
            },
        )
    finally:
        hive.close()


def iter_bagmru_entries(
    path: Path,
    hive: object,
    root_key: object,
    root_components: tuple[str, ...],
    *,
    mount: Mapping[str, str],
    source_hashes: Mapping[str, str],
    transaction_disclosure: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    mount_prefix = str(mount.get("mount") or path.name)
    root_relative = "\\".join(root_components)
    source_key_path = root_relative
    yield _shellbag_entry_record(
        path,
        source_hashes,
        mount=mount,
        transaction_disclosure=transaction_disclosure,
        source_key_path=source_key_path,
        node_key_path=source_key_path,
        full_key_path=f"{mount_prefix}\\{root_relative}",
        key=root_key,
        node_slot=_node_slot(hive, root_key),
        shell_path="",
        slot_name="",
        depth=0,
        bagmru_root=True,
        decoded={},
        mru_position=None,
        item_value=None,
        parent_items=[],
    )
    stack: list[tuple[object, str, int, str, list[dict[str, object]]]] = [(root_key, "", 0, root_relative, [])]
    visited: set[int] = set()
    while stack:
        node, parent_shell_path, depth, node_relative, parent_items = stack.pop()
        offset = int(getattr(node, "offset", 0) or 0)
        if offset in visited:
            continue
        visited.add(offset)
        values = {str(value.name): value for value in hive.values(node)}  # type: ignore[attr-defined]
        mru_value = values.get("MRUListEx")
        order = parse_mru_list_ex(hive.value_bytes(mru_value)) if mru_value is not None else []  # type: ignore[attr-defined]
        positions = {slot: position for position, slot in enumerate(order)}
        children = []
        for child in hive.subkeys(node):  # type: ignore[attr-defined]
            slot_name = str(child.name)
            item_value = values.get(slot_name)
            raw = hive.value_bytes(item_value) if item_value is not None else b""  # type: ignore[attr-defined]
            items = split_shell_item_list(raw)
            decoded = decode_shell_item_entry(items[0]) if items else {}
            item_name = str(decoded.get("name") or "") or f"<슬롯 {slot_name}>"
            shell_path = join_shell_path([parent_shell_path, item_name])
            slot_number = int(slot_name) if slot_name.isdigit() else None
            child_relative = f"{node_relative}\\{slot_name}"
            yield _shellbag_entry_record(
                path,
                source_hashes,
                mount=mount,
                transaction_disclosure=transaction_disclosure,
                source_key_path=source_key_path,
                node_key_path=child_relative,
                full_key_path=f"{mount_prefix}\\{child_relative}",
                key=child,
                node_slot=_node_slot(hive, child),
                shell_path=shell_path,
                slot_name=slot_name,
                depth=depth + 1,
                bagmru_root=False,
                decoded=decoded,
                mru_position=positions.get(slot_number) if slot_number is not None else None,
                item_value=item_value,
                parent_items=parent_items,
            )
            children.append((child, shell_path, depth + 1, child_relative, [*parent_items, decoded]))
        stack.extend(reversed(children))


def _node_slot(hive: object, key: object) -> int | None:
    value = hive.value(key, "NodeSlot")  # type: ignore[attr-defined]
    if value is None:
        return None
    data = hive.value_data(value)  # type: ignore[attr-defined]
    return data if isinstance(data, int) else None


def _shellbag_entry_record(
    path: Path,
    source_hashes: Mapping[str, str],
    *,
    mount: Mapping[str, str],
    transaction_disclosure: Mapping[str, str],
    source_key_path: str,
    node_key_path: str,
    full_key_path: str,
    key: object,
    node_slot: int | None,
    shell_path: str,
    slot_name: str,
    depth: int,
    bagmru_root: bool,
    decoded: Mapping[str, object],
    mru_position: int | None,
    item_value: object,
    parent_items: Sequence[Mapping[str, object]],
) -> ArtifactRecord:
    key_last_written_at = str(getattr(key, "last_written_at", "") or "")
    volume = next(
        (str(item.get("name") or "") for item in [*parent_items, decoded] if item.get("item_kind") == "volume"),
        "",
    )
    network = next(
        (str(item.get("name") or "") for item in [*parent_items, decoded] if item.get("item_kind") == "network"),
        "",
    )
    decoded_ok = bagmru_root or (
        bool(decoded) and str(decoded.get("decode_method") or "") not in {"unresolved", "unsupported-type", "truncated"}
    )
    details: dict[str, object] = {
        "parser": "windows-shellbags-native-hive",
        "parser_version": PARSER_VERSION,
        "coverage_status": "native-bagmru-shellitem-decode",
        "reportability": "review",
        "label": "ShellBags 루트" if bagmru_root else "ShellBags 폴더 기록",
        "source_path": str(path.resolve()),
        "source_format": "registry-hive",
        "source_hashes": dict(source_hashes),
        "hive_name": path.name,
        "hive_hint": hive_hint_from_path(path),
        "hive_mount": str(mount.get("mount") or ""),
        "user_sid": str(mount.get("user_sid") or ""),
        "user_hive_scope": "ntuser" if path.name.upper() == "NTUSER.DAT" else "usrclass",
        "candidate_source": "native-bagmru-decode",
        "source_key_path": source_key_path,
        "node_key_path": node_key_path,
        "key_path": full_key_path,
        "shellbag_section": "bagmru",
        "shell_path": shell_path,
        "slot_name": slot_name,
        "node_slot": node_slot,
        "mru_position": mru_position,
        "mru_position_note": "MRUListEx 순서(0 = 해당 폴더에서 가장 최근)",
        "bagmru_root": bagmru_root,
        "depth": depth,
        "item_kind": str(decoded.get("item_kind") or ("root-key" if bagmru_root else "")),
        "item_name": str(decoded.get("name") or ""),
        "volume": volume,
        "network_location": network,
        "shellitem": dict(decoded),
        "shellitem_value_cell_offset": (HIVE_BIN_BASE_OFFSET + int(getattr(item_value, "offset", 0) or 0))
        if item_value is not None
        else 0,
        "key_cell_offset": HIVE_BIN_BASE_OFFSET + int(getattr(key, "offset", 0) or 0),
        "key_last_written_at": key_last_written_at,
        "timestamp": key_last_written_at,
        "timestamp_label": "last_written",
        "timestamp_semantics": "BagMRU 노드 키 최종 수정 시각(해당 폴더의 하위 목록·보기 기록 갱신)",
        "item_modified_at": str(decoded.get("modified_at") or ""),
        "item_created_at": str(decoded.get("created_at") or ""),
        "item_accessed_at": str(decoded.get("accessed_at") or ""),
        "item_time_note": "셸 항목 내부 FAT 시각(2초 단위, UTC) — 탐색 당시 폴더의 MAC 값",
        "transaction_log_status": transaction_disclosure.get("status", ""),
        "transaction_log_disclosure": transaction_disclosure.get("message_ko", ""),
        "validation_checks": {
            "key_cell_parsed": True,
            "shellitem_value_present": bagmru_root or item_value is not None,
            "shellitem_decoded": decoded_ok,
        },
        "commercial_grade_ready": False,
        "commercial_grade_blockers": list(SHELLBAG_BLOCKERS),
        "raw_preview": shell_path or full_key_path,
    }
    return ArtifactRecord(
        provider="windows-shellbags",
        artifact_type="shellbag-entry",
        path=str(path.resolve()),
        supported=True,
        details=details,
    )
