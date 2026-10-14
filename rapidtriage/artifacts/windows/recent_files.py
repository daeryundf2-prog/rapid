from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import (
    build_forensic_review,
    isoformat_from_timestamp,
    iter_windows_user_homes,
)
from .filesystem import CONTENT_KIND_LABELS_KO, sniff_content_kind

RECENT_ROOT = ("AppData", "Roaming", "Microsoft", "Windows", "Recent")
PARSER_VERSION = "windows-recent-files-v8"
MAX_JUMPLIST_INLINE_DESTINATIONS = 256
MAX_OLE_STREAMS = 128
MAX_OLE_STREAM_BYTES = 8 * 1024 * 1024
MAX_LNK_EXTRA_DATA_BLOCKS = 64
MAX_LNK_SHELL_ITEMS = 128
MAX_LNK_PROPERTY_STORE_STRING_CANDIDATES = 12
MAX_LNK_PROPERTY_STORE_GUID_CANDIDATES = 12
MAX_DESTLIST_ENTRIES = 128
MAX_DESTLIST_CANDIDATE_TIMES = 8
MAX_DESTLIST_NUMERIC_CANDIDATES = 12
DESTLIST_HEADER_SIZE = 32
DESTLIST_ENTRY_LAYOUTS: tuple[tuple[str, int], ...] = (
    ("win7-win8-fixed114", 114),
    ("win10-plus-fixed130", 130),
)
JUMPLIST_COMMERCIAL_BLOCKERS = [
    "destlist-os-version-specific-field-validation-required",
    "destlist-deleted-entry-recovery-not-implemented",
    "destlist-account-metadata-not-fully-decoded",
    "application-id-hash-to-application-name-map-not-bundled",
    "jumplist-destlist-trusted-diff-required",
]
JUMPLIST_TRUSTED_TOOLS = {"jlecmd", "lnkecmd", "lecmd", "jumplistexplorer", "velociraptor"}
LNK_TRUSTED_TOOLS = {"lecmd", "lnkecmd", "windows shell", "shell properties", "velociraptor"}
QC_PREP_JUMPLIST_ITEM = 29
QC_PREP_LNK_ITEM = 32
QC_PREP_LNK_GOAL = (
    "Deepen LNK ShellLinkHeader, LinkInfo, StringData, ExtraData, "
    "TrackerDataBlock, and target/source citation."
)
QC_PREP_LNK_CONTRACT = {
    "item_number": QC_PREP_LNK_ITEM,
    "goal": QC_PREP_LNK_GOAL,
    "implemented_outputs": [
        "ShellLinkHeader flags, attributes, timestamps, size, show command, and hotkey fields",
        "LinkInfo local/common path candidates and StringData target context",
        "ExtraData block inventory with TrackerDataBlock and property-store candidate preservation",
        "target context citation profile with source field offsets, block bounds, and stable identity hash",
        "depth manifest with source hash, target identity hash, citation refs, and report blockers",
    ],
    "commercial_blockers": [
        "complete shell item semantic decoding",
        "full property-store schema validation",
        "LinkInfo/network-provider OS-version validation",
        "LECmd/known-answer trusted diff evidence for critical shortcuts",
    ],
}
JUMPLIST_CAPABILITIES = {
    "lnk_header_decode": True,
    "lnk_linkinfo_decode": True,
    "lnk_tracker_block_candidate_decode": True,
    "lnk_property_store_block_candidate_decode": True,
    "ole_stream_inventory": True,
    "embedded_lnk_destination_extraction": True,
    "destlist_header_candidate_decode": True,
    "destlist_entry_candidate_decode": True,
    "full_shell_item_property_store_decode": False,
    "destlist_deleted_entry_recovery": False,
    "destlist_account_metadata_decode": False,
    "appid_hash_mapping": False,
}
RECENT_PATTERNS: tuple[tuple[str, str, Sequence[str]], ...] = (
    ("recent-shortcut", "*.lnk", ()),
    ("jumplist-automatic", "*.automaticDestinations-ms", ("AutomaticDestinations",)),
    ("jumplist-custom", "*.customDestinations-ms", ("CustomDestinations",)),
)
LNK_HEADER_SIZE = 0x4C
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
CFB_FREESECT = 0xFFFFFFFF
CFB_ENDOFCHAIN = 0xFFFFFFFE
CFB_FATSECT = 0xFFFFFFFD
CFB_DIFSECT = 0xFFFFFFFC
LNK_FLAG_NAMES = {
    0x00000001: "HasLinkTargetIDList",
    0x00000002: "HasLinkInfo",
    0x00000004: "HasName",
    0x00000008: "HasRelativePath",
    0x00000010: "HasWorkingDir",
    0x00000020: "HasArguments",
    0x00000040: "HasIconLocation",
    0x00000080: "IsUnicode",
}
LNK_FILE_ATTRIBUTE_NAMES = {
    0x00000001: "READONLY",
    0x00000002: "HIDDEN",
    0x00000004: "SYSTEM",
    0x00000010: "DIRECTORY",
    0x00000020: "ARCHIVE",
    0x00000040: "DEVICE",
    0x00000080: "NORMAL",
    0x00000100: "TEMPORARY",
    0x00000400: "REPARSE_POINT",
    0x00000800: "COMPRESSED",
    0x00001000: "OFFLINE",
    0x00004000: "ENCRYPTED",
}
LNK_EXTRA_DATA_SIGNATURES = {
    0xA0000001: "EnvironmentVariableDataBlock",
    0xA0000002: "ConsoleDataBlock",
    0xA0000003: "TrackerDataBlock",
    0xA0000004: "ConsoleFEDataBlock",
    0xA0000005: "SpecialFolderDataBlock",
    0xA0000006: "DarwinDataBlock",
    0xA0000007: "IconEnvironmentDataBlock",
    0xA0000008: "ShimDataBlock",
    0xA0000009: "PropertyStoreDataBlock",
    0xA000000B: "KnownFolderDataBlock",
    0xA000000C: "VistaAndAboveIDListDataBlock",
}
STRING_DATA_FIELDS = (
    (0x00000004, "description"),
    (0x00000008, "relative_path"),
    (0x00000010, "working_dir"),
    (0x00000020, "command_line_arguments"),
    (0x00000040, "icon_location"),
)
WINDOWS_PATH_RE = re.compile(
    rb"(?:[A-Za-z]:\\[^\x00\r\n\t\"<>|]{2,}|\\\\[A-Za-z0-9_. -]+\\[^\x00\r\n\t\"<>|]{2,})"
)
UTF16_WINDOWS_PATH_RE = re.compile(
    rb"(?:(?:[A-Za-z]\x00:\x00\\\x00)|(?:\\\x00\\\x00[A-Za-z0-9_. -]+(?:\x00[A-Za-z0-9_. -]+)*\x00\\\x00))(?:[^\x00]\x00){2,}"
)


class WindowsRecentFilesProvider:
    collector_kind = "recent-files"
    name = "windows-recent-files"
    description = "Windows Recent items and Jump Lists collected from per-user profile directories"
    target_platform = "windows"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for user_root in iter_windows_user_homes(root):
            recent_root = user_root.joinpath(*RECENT_ROOT)
            if recent_root.is_dir():
                for artifact_type, pattern, extra_parts in RECENT_PATTERNS:
                    scan_root = recent_root.joinpath(*extra_parts)
                    if not scan_root.is_dir():
                        continue
                    for candidate in sorted(scan_root.glob(pattern), key=lambda item: item.name.lower()):
                        if not candidate.is_file():
                            continue
                        yield from self._records_for(candidate, artifact_type, user_root, "recent")
            # Shortcuts outside Recent (Desktop, Start Menu, SendTo, Quick
            # Launch, WinX ...) are the same Shell Link format, scoped with a
            # ``location`` label so they are not mistaken for recent-file use.
            for candidate in iter_profile_shortcuts(user_root, recent_root):
                yield from self._records_for(candidate, "shell-shortcut", user_root, shortcut_location(candidate, user_root))
        program_data_start = root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu"
        if program_data_start.is_dir():
            for candidate in sorted(program_data_start.rglob("*.lnk"), key=lambda item: str(item).lower()):
                if candidate.is_file():
                    yield from self._records_for(candidate, "shell-shortcut", None, "all-users-start-menu")

    def _records_for(
        self, candidate: Path, artifact_type: str, user_root: Path | None, location: str
    ) -> Iterable[ArtifactRecord]:
        stat_result = candidate.stat()
        metadata = recent_file_metadata(candidate, artifact_type)
        entries = metadata.pop("_jumplist_entries", None)
        effective_type = artifact_type
        if artifact_type in {"recent-shortcut", "shell-shortcut"} and metadata.get("lnk_parse_status") == "unsupported-header":
            effective_type = f"{artifact_type}-invalid-content"
            metadata.update(lnk_invalid_content_details(candidate))
        user_name = user_root.name if user_root is not None else ""
        details: dict[str, object] = {
            "parser": "windows-recent-files",
            "parser_version": PARSER_VERSION,
            "user": user_name,
            "location": location,
            "profile_template": user_name.lower() in TEMPLATE_PROFILE_NAMES,
            "entry_name": candidate.name,
            "entry_hint": candidate.stem,
            "size": stat_result.st_size,
            # Host mtime of the acquired copy: provenance only, never an event.
            "source_file_mtime": isoformat_from_timestamp(stat_result.st_mtime),
            **metadata,
        }
        if effective_type != artifact_type:
            details["artifact_type"] = effective_type
        if effective_type in {"recent-shortcut", "shell-shortcut"}:
            details.update(lnk_row_timestamp(details))
        yield ArtifactRecord(
            provider=self.name,
            artifact_type=effective_type,
            path=str(candidate.resolve()),
            supported=self.supported(),
            details=details,
        )
        for index, entry in enumerate(entries or []):
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="jumplist-entry",
                path=str(candidate.resolve()),
                supported=self.supported(),
                details={
                    "parser": "windows-recent-files",
                    "parser_version": PARSER_VERSION,
                    "artifact_type": "jumplist-entry",
                    "user": user_name,
                    "location": location,
                    "jumplist_kind": "automatic" if artifact_type == "jumplist-automatic" else "custom",
                    "application_id_hash": candidate.stem.split(".", 1)[0],
                    "source_path": str(candidate.resolve()),
                    "source_hashes": metadata.get("source_hashes", {}),
                    "source_index": index,
                    "coverage_status": "decoded-destlist-entry" if entry.get("destlist_entry_present") else "embedded-lnk-stream",
                    "reportability": "triage",
                    **entry,
                },
            )


TEMPLATE_PROFILE_NAMES = {"default", "default user", "all users"}


def iter_profile_shortcuts(user_root: Path, recent_root: Path) -> Iterable[Path]:
    recent_prefix = str(recent_root).lower()
    for candidate in sorted(user_root.rglob("*.lnk"), key=lambda item: str(item).lower()):
        if str(candidate).lower().startswith(recent_prefix):
            continue
        if candidate.is_file():
            yield candidate


SHORTCUT_LOCATION_MARKERS = (
    ("\\microsoft\\windows\\sendto\\", "sendto"),
    ("\\microsoft\\windows\\start menu\\", "start-menu"),
    ("\\internet explorer\\quick launch\\user pinned\\taskbar\\", "taskbar-pinned"),
    ("\\internet explorer\\quick launch\\", "quick-launch"),
    ("\\microsoft\\windows\\winx\\", "winx-menu"),
    ("\\desktop\\", "desktop"),
    ("\\documents\\", "documents"),
    ("\\downloads\\", "downloads"),
    ("\\favorites\\", "favorites"),
    ("\\links\\", "links"),
)


def shortcut_location(path: Path, user_root: Path) -> str:
    relative = "\\" + str(path.relative_to(user_root)).replace("/", "\\").lower()
    for marker, label in SHORTCUT_LOCATION_MARKERS:
        if marker in relative:
            return label
    return "other-profile"


def lnk_row_timestamp(details: Mapping[str, object]) -> dict[str, object]:
    for key, kind in (
        ("target_accessed_at", "lnk-target-accessed"),
        ("target_modified_at", "lnk-target-modified"),
        ("target_created_at", "lnk-target-created"),
    ):
        if details.get(key):
            return {"timestamp": details[key], "timestamp_source": key, "timestamp_kind": kind}
    return {"timestamp": "", "timestamp_source": "missing_lnk_target_times", "timestamp_kind": ""}


def lnk_invalid_content_details(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            prefix = handle.read(4096)
    except OSError:
        prefix = b""
    content = sniff_content_kind(prefix)
    kind = str(content["kind"])
    label = CONTENT_KIND_LABELS_KO.get(kind, kind)
    return {
        "lnk_parse_status": "invalid-content",
        "detected_content_kind": kind,
        "detected_content_label": label,
        "detected_content_basis": content["basis"],
        "content_entropy": content["entropy"],
        "content_zero_ratio": content["zero_ratio"],
        "header_hex": prefix[:16].hex(),
        "target_path": "",
        "embedded_paths": [],
        "risk_flags": ["lnk-invalid-content", "signature-extension-mismatch"],
        "reportability": "excluded-from-recent-file-evidence",
        "note": (
            f"확장자는 바로가기(.lnk)이지만 내용이 Shell Link 구조가 아닙니다({label}). "
            "최근 사용 파일 근거로 쓰지 않으며, 클러스터 재할당 잔존물인지 MFT/USN으로 확인하십시오."
        ),
    }


def recent_file_metadata(path: Path, artifact_type: str) -> dict[str, object]:
    base = {"source_hashes": file_hashes(path)}
    if artifact_type in {"recent-shortcut", "shell-shortcut"}:
        return {**base, **parse_lnk_metadata(path, artifact_type)}
    return {**base, **jump_list_metadata(path, artifact_type)}


def parse_lnk_metadata(path: Path, artifact_type: str = "recent-shortcut") -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError:
        return {"lnk_parse_status": "read-error"}
    source_hashes = file_hashes(path)
    source_path = str(path.resolve())
    metadata = parse_lnk_metadata_from_bytes(data)
    metadata.update(
        {
            "source_path": source_path,
            "source_hashes": source_hashes,
            "artifact_type": artifact_type,
        }
    )
    if metadata.get("lnk_parse_status") == "parsed":
        citation_profile = lnk_target_context_citation_profile(metadata)
        metadata["lnk_target_context_citation_profile"] = citation_profile
        metadata["lnk_target_context_citation_profile_hash"] = citation_profile["profile_sha256"]
    metadata["core_accuracy_gates"] = lnk_core_accuracy_gates(
        {
            **metadata,
            "source_path": source_path,
            "source_hashes": source_hashes,
        }
    )
    if metadata.get("lnk_parse_status") == "parsed":
        metadata["commercial_uplift_evidence"] = lnk_commercial_uplift_evidence(
            {
                **metadata,
                "source_path": source_path,
                "source_hashes": source_hashes,
                "artifact_type": "recent-shortcut",
            }
        )
        metadata["lnk_analyst_review_profile"] = lnk_analyst_review_profile(metadata)
        metadata["lnk_metadata_depth_manifest"] = lnk_metadata_depth_manifest(metadata)
        metadata["lnk_metadata_depth_manifest_hash"] = metadata["lnk_metadata_depth_manifest"]["manifest_sha256"]
    return metadata


def parse_lnk_metadata_from_bytes(data: bytes) -> dict[str, object]:
    embedded_paths = extract_windows_paths(data)
    if len(data) < LNK_HEADER_SIZE or data[:4] != b"\x4c\x00\x00\x00" or data[4:20] != LNK_CLSID:
        return {
            "lnk_parse_status": "unsupported-header",
            "target_path": "",
            "embedded_paths": embedded_paths,
            "commercial_grade_ready": False,
            "commercial_grade_blockers": ["native Shell Link header validation failed"],
        }

    link_flags = read_u32(data, 0x14)
    file_attributes = read_u32(data, 0x18)
    shell_item_metadata = parse_lnk_shell_item_metadata(data, link_flags)
    string_data, string_offset = parse_lnk_string_data(data, link_flags)
    link_info = parse_lnk_link_info(data, link_flags)
    extra_data_blocks, tracker_data = parse_lnk_extra_data(data, string_offset)
    property_store_blocks = [
        block["property_store_data"]
        for block in extra_data_blocks
        if isinstance(block.get("property_store_data"), dict)
    ]
    target_path = first_non_empty(
        link_info.get("full_path"),
        string_data.get("relative_path"),
        next(iter(embedded_paths), ""),
    )
    if link_info.get("full_path"):
        target_path_source = f"link-info:{link_info.get('full_path_source', '')}"
    elif string_data.get("relative_path"):
        target_path_source = "string-data:relative-path"
    elif embedded_paths:
        target_path_source = "embedded-path-string-scan"
    else:
        target_path_source = ""
    paths = sorted({item for item in [target_path, *embedded_paths] if item})
    validation_checks = {
        "has_valid_header": True,
        "has_target_path": bool(target_path),
        "has_timestamps": any(
            windows_filetime_to_iso(read_u64(data, offset))
            for offset in (0x1C, 0x24, 0x2C)
        ),
        "has_link_info": bool(link_info),
        "has_shell_item_idlist": bool(shell_item_metadata.get("items")),
        "has_tracker_data": bool(tracker_data),
        "has_property_store_data_block": bool(property_store_blocks),
        "extra_data_block_count": len(extra_data_blocks),
        "full_property_store_decode_available": False,
    }
    report_grade = recent_report_grade_assessment(
        recent_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#17"],
        blockers=[
            "full-shell-item-property-store-decoding-required",
            "tracker-data-known-answer-corpus-validation-required",
        ],
    )
    return {
        "lnk_parse_status": "parsed",
        "lnk_header_size": read_u32(data, 0),
        "link_flags": link_flags,
        "link_flag_names": flag_names(link_flags, LNK_FLAG_NAMES),
        "file_attributes": file_attributes,
        "file_attribute_names": flag_names(file_attributes, LNK_FILE_ATTRIBUTE_NAMES),
        "target_created_at": windows_filetime_to_iso(read_u64(data, 0x1C)),
        "target_accessed_at": windows_filetime_to_iso(read_u64(data, 0x24)),
        "target_modified_at": windows_filetime_to_iso(read_u64(data, 0x2C)),
        "target_file_size": read_u32(data, 0x34),
        "show_command": read_u32(data, 0x3C),
        "hot_key": read_u16(data, 0x40),
        "target_path": target_path,
        "target_path_source": target_path_source,
        "volume_serial_number": link_info.get("volume_serial_number", ""),
        "drive_type": link_info.get("drive_type", ""),
        "drive_type_name": link_info.get("drive_type_name", ""),
        "volume_label": link_info.get("volume_label", ""),
        "local_base_path": link_info.get("local_base_path", ""),
        "common_path_suffix": link_info.get("common_path_suffix", ""),
        "net_name": link_info.get("net_name", ""),
        "device_name": link_info.get("device_name", ""),
        "tracker_machine_id": tracker_data.get("machine_id", ""),
        "tracker_droid_file_mac_address": tracker_data.get("droid_file_mac_address", ""),
        "known_folder_ids": [
            {"id": block.get("known_folder_id", ""), "name": block.get("known_folder_name", "")}
            for block in extra_data_blocks
            if block.get("known_folder_id")
        ],
        "environment_target": next(
            (str(block.get("environment_target")) for block in extra_data_blocks if block.get("environment_target")), ""
        ),
        "embedded_paths": paths,
        "description": string_data.get("description", ""),
        "relative_path": string_data.get("relative_path", ""),
        "working_dir": string_data.get("working_dir", ""),
        "command_line_arguments": string_data.get("command_line_arguments", ""),
        "icon_location": string_data.get("icon_location", ""),
        "link_info": link_info,
        "shell_item_metadata": shell_item_metadata,
        "extra_data_blocks": extra_data_blocks,
        "tracker_data": tracker_data,
        "property_store_blocks": property_store_blocks,
        "string_data_offset": string_offset,
        "validation_checks": validation_checks,
        "core_accuracy_gates": lnk_core_accuracy_gates(
            {
                "validation_checks": validation_checks,
                "target_path": target_path,
                "working_dir": string_data.get("working_dir", ""),
                "command_line_arguments": string_data.get("command_line_arguments", ""),
                "link_info": link_info,
                "tracker_data": tracker_data,
                "property_store_blocks": property_store_blocks,
                "target_created_at": windows_filetime_to_iso(read_u64(data, 0x1C)),
                "target_accessed_at": windows_filetime_to_iso(read_u64(data, 0x24)),
                "target_modified_at": windows_filetime_to_iso(read_u64(data, 0x2C)),
                "link_flag_names": flag_names(link_flags, LNK_FLAG_NAMES),
                "source_path": "",
                "source_hashes": {},
            }
        ),
        "recent_validation_matrix": recent_validation_matrix(validation_checks),
        "recent_report_grade_assessment": report_grade,
        "recent_native_capabilities": JUMPLIST_CAPABILITIES,
        "forensic_review": build_forensic_review(
            gap_id="#17",
            artifact_goal="Shell Link target, timestamps, LinkInfo, StringData, ExtraData and tracker evidence",
            primary_evidence=[
                f"target_path={target_path}",
                f"embedded_paths={len(paths)}",
                f"extra_data_blocks={len(extra_data_blocks)}",
                f"tracker_present={bool(tracker_data)}",
                f"property_store_blocks={len(property_store_blocks)}",
            ],
            validation_required=True,
            report_grade_assessment=report_grade,
            blockers=report_grade["blockers"],
            caveats=[
                "Full shell item property-store semantics and broad known-answer validation are still required.",
                "Use target timestamps as link metadata, not proof that the target file currently exists.",
            ],
        ),
        "commercial_grade_ready": False,
        "commercial_grade_blockers": report_grade["blockers"],
    }


def parse_lnk_shell_item_metadata(data: bytes, link_flags: int) -> dict[str, object]:
    if not (link_flags & 0x00000001):
        return {"parse_status": "not-present", "items": []}
    offset = LNK_HEADER_SIZE
    id_list_size = read_u16(data, offset)
    end = offset + 2 + id_list_size
    if id_list_size <= 0 or end > len(data):
        return {"parse_status": "invalid-idlist", "declared_size": id_list_size, "items": []}
    item_offset = offset + 2
    items: list[dict[str, object]] = []
    while item_offset + 2 <= end and len(items) < MAX_LNK_SHELL_ITEMS:
        item_size = read_u16(data, item_offset)
        if item_size == 0:
            break
        if item_size < 2 or item_offset + item_size > end:
            return {
                "parse_status": "truncated-item",
                "declared_size": id_list_size,
                "items": items,
            }
        item_data = data[item_offset : item_offset + item_size]
        items.append(
            {
                "index": len(items),
                "offset": item_offset,
                "size": item_size,
                "type_hint": shell_item_type_hint(item_data[2] if len(item_data) > 2 else 0),
                "embedded_paths": extract_windows_paths(item_data),
            }
        )
        item_offset += item_size
    return {
        "parse_status": "parsed",
        "declared_size": id_list_size,
        "item_count": len(items),
        "items": items,
    }


def lnk_core_accuracy_gates(details: dict[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    link_info = details.get("link_info") if isinstance(details.get("link_info"), dict) else {}
    tracker_data = details.get("tracker_data") if isinstance(details.get("tracker_data"), dict) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), dict) else {}
    trusted_diff = (
        details.get("lnk_trusted_diff")
        if isinstance(details.get("lnk_trusted_diff"), Mapping)
        else {}
    )
    evidence_refs = [f"source_path:{details.get('source_path', '')}"]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if checks.get("has_valid_header") and details.get("link_flag_names") is not None:
        satisfied.append("header flag consistency")
    if details.get("target_path") or details.get("working_dir") or details.get("command_line_arguments"):
        satisfied.append("target/working-dir/arguments extraction")
    if link_info.get("local_base_path") or link_info.get("common_path_suffix"):
        satisfied.append("drive/network metadata")
    if tracker_data:
        satisfied.append("tracker GUID validation")
    if details.get("property_store_blocks") or checks.get("has_property_store_data_block"):
        satisfied.append("property-store block provenance")
    if details.get("target_created_at") or details.get("target_accessed_at") or details.get("target_modified_at"):
        satisfied.append("timestamp/source field provenance")
    if details.get("lnk_target_context_citation_profile"):
        satisfied.append("target context citation profile")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted LNK parser diff pass")
    return [build_accuracy_gate(17, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def parse_lnk_extra_data(data: bytes, offset: int) -> tuple[list[dict[str, object]], dict[str, object]]:
    blocks: list[dict[str, object]] = []
    tracker_data: dict[str, object] = {}
    while offset + 4 <= len(data) and len(blocks) < MAX_LNK_EXTRA_DATA_BLOCKS:
        block_size = read_u32(data, offset)
        if block_size < 4:
            # TerminalBlock (size < 4) ends the ExtraData section.
            break
        if block_size < 8 or offset + block_size > len(data):
            blocks.append(
                {
                    "offset": offset,
                    "size": block_size,
                    "signature": "",
                    "type": "InvalidExtraDataBlock",
                    "parse_status": "truncated-or-invalid-size",
                }
            )
            break
        signature = read_u32(data, offset + 4)
        block_data = data[offset : offset + block_size]
        block_type = LNK_EXTRA_DATA_SIGNATURES.get(signature, "UnknownExtraDataBlock")
        block_summary: dict[str, object] = {
            "index": len(blocks),
            "offset": offset,
            "size": block_size,
            "signature": f"0x{signature:08X}",
            "type": block_type,
            "parse_status": "parsed-known" if signature in LNK_EXTRA_DATA_SIGNATURES else "parsed-unknown",
        }
        if signature == 0xA0000003:
            tracker_data = parse_lnk_tracker_data_block(block_data)
            block_summary["tracker_data"] = tracker_data
        elif signature == 0xA0000009:
            block_summary["property_store_data"] = parse_lnk_property_store_data_block(block_data)
        elif signature == 0xA000000B and block_size >= 0x1C:
            folder_id = format_guid_le(block_data[8:24])
            block_summary["known_folder_id"] = folder_id
            block_summary["known_folder_name"] = KNOWN_FOLDER_NAMES.get(folder_id.lower(), "")
            block_summary["known_folder_idlist_offset"] = read_u32(block_data, 24)
        elif signature == 0xA0000005 and block_size >= 0x10:
            block_summary["special_folder_id"] = read_u32(block_data, 8)
            block_summary["special_folder_idlist_offset"] = read_u32(block_data, 12)
        elif signature in (0xA0000001, 0xA0000007, 0xA0000006) and block_size >= 0x314:
            ansi_value = read_c_string(block_data, 8, "lnk-ansi")
            unicode_value = read_c_string(block_data, 268, "utf-16le")
            key = {0xA0000001: "environment_target", 0xA0000007: "icon_environment_target", 0xA0000006: "darwin_data"}[signature]
            block_summary[key] = unicode_value or ansi_value
        blocks.append(block_summary)
        offset += block_size
    return blocks, tracker_data


def parse_lnk_property_store_data_block(block_data: bytes) -> dict[str, object]:
    payload = block_data[8:]
    guid_candidates = []
    for offset in range(max(0, len(payload) - 15)):
        chunk = payload[offset : offset + 16]
        if chunk == b"\x00" * 16 or len(guid_candidates) >= MAX_LNK_PROPERTY_STORE_GUID_CANDIDATES:
            continue
        guid_text = format_guid_le(chunk)
        if guid_text and guid_text not in [item["guid"] for item in guid_candidates]:
            guid_candidates.append({"relative_offset": offset + 8, "guid": guid_text})
    properties, storage_count = decode_serialized_property_storage(payload)
    return {
        "parse_status": "parsed-candidate" if len(block_data) >= 12 else "truncated-candidate",
        "declared_block_size": read_u32(block_data, 0) if len(block_data) >= 4 else len(block_data),
        "payload_size": len(payload),
        "storage_count": storage_count,
        "properties": properties,
        "property_count": len(properties),
        "embedded_paths": extract_windows_paths(payload),
        "string_candidates": extract_property_store_string_candidates(payload),
        "guid_candidates": guid_candidates,
        "validation_status": "decoded-serialized-property-storage" if properties else "candidate-requires-property-store-schema-validation",
        "reportability": "review-only",
    }


PROPERTY_STORE_NAMED_FORMAT = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"
PROPERTY_STORE_MAX_VALUES = 256


def decode_serialized_property_storage(payload: bytes) -> tuple[list[dict[str, object]], int]:
    """MS-PROPSTORE serialized property storage (``1SPS``) with typed values."""
    properties: list[dict[str, object]] = []
    storages = 0
    offset = 0
    while offset + 24 <= len(payload) and len(properties) < PROPERTY_STORE_MAX_VALUES:
        storage_size = read_u32(payload, offset)
        if storage_size == 0:
            break
        if storage_size < 24 or offset + storage_size > len(payload) or payload[offset + 4 : offset + 8] != b"1SPS":
            break
        storages += 1
        format_id = format_guid_le(payload[offset + 8 : offset + 24])
        cursor = offset + 24
        end = offset + storage_size
        named = format_id.lower() == PROPERTY_STORE_NAMED_FORMAT
        while cursor + 4 <= end and len(properties) < PROPERTY_STORE_MAX_VALUES:
            value_size = read_u32(payload, cursor)
            if value_size == 0 or cursor + value_size > end:
                break
            value_blob = payload[cursor : cursor + value_size]
            if named:
                name_size = read_u32(value_blob, 4)
                name = value_blob[9 : 9 + name_size].decode("utf-16le", errors="replace").rstrip("\x00")
                typed = value_blob[9 + name_size :]
                key = f"{format_id}/{name}"
                property_id: object = name
            else:
                property_id = read_u32(value_blob, 4)
                typed = value_blob[9:]
                key = f"{format_id}/{property_id}"
            value_type, value = decode_typed_property_value(typed)
            properties.append(
                {
                    "format_id": format_id,
                    "property_id": property_id,
                    "key": key,
                    "name": PROPERTY_KEY_NAMES.get(key.lower(), ""),
                    "value_type": value_type,
                    "value": value,
                }
            )
            cursor += value_size
        offset += storage_size
    return properties, storages


def decode_typed_property_value(typed: bytes) -> tuple[str, object]:
    if len(typed) < 4:
        return "truncated", ""
    vt = read_u16(typed, 0)
    body = typed[4:]
    if vt == 0x1F:  # VT_LPWSTR
        chars = read_u32(body, 0)
        return "VT_LPWSTR", body[4 : 4 + chars * 2].decode("utf-16le", errors="replace").rstrip("\x00")
    if vt == 0x1E:  # VT_LPSTR
        size = read_u32(body, 0)
        return "VT_LPSTR", decode_lnk_ansi(body[4 : 4 + size])
    if vt == 0x08:  # VT_BSTR
        size = read_u32(body, 0)
        return "VT_BSTR", body[4 : 4 + size].decode("utf-16le", errors="replace").rstrip("\x00")
    if vt == 0x40:  # VT_FILETIME
        return "VT_FILETIME", windows_filetime_to_iso(read_u64(body, 0))
    if vt == 0x48:  # VT_CLSID
        return "VT_CLSID", format_guid_le(body[:16])
    if vt in (0x13, 0x17):
        return "VT_UI4", read_u32(body, 0)
    if vt in (0x03, 0x16):
        return "VT_I4", struct.unpack_from("<i", body, 0)[0] if len(body) >= 4 else 0
    if vt == 0x15:
        return "VT_UI8", read_u64(body, 0)
    if vt == 0x14:
        return "VT_I8", struct.unpack_from("<q", body, 0)[0] if len(body) >= 8 else 0
    if vt == 0x12:
        return "VT_UI2", read_u16(body, 0)
    if vt == 0x0B:
        return "VT_BOOL", read_u16(body, 0) != 0
    return f"VT_0x{vt:04X}", body[:32].hex()


PROPERTY_KEY_NAMES = {
    "b725f130-47ef-101a-a5f1-02608c9eebac/10": "System.ItemNameDisplay",
    "b725f130-47ef-101a-a5f1-02608c9eebac/12": "System.Size",
    "b725f130-47ef-101a-a5f1-02608c9eebac/14": "System.DateModified",
    "b725f130-47ef-101a-a5f1-02608c9eebac/15": "System.DateCreated",
    "b725f130-47ef-101a-a5f1-02608c9eebac/16": "System.DateAccessed",
    "b725f130-47ef-101a-a5f1-02608c9eebac/4": "System.ItemTypeText",
    "28636aa6-953d-11d2-b5d6-00c04fd918d0/30": "System.ParsingPath",
    "e3e0584c-b788-4a5a-bb20-7f5a44c9acdd/6": "System.ItemFolderPathDisplay",
    "9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3/5": "System.AppUserModel.ID",
    "446d16b1-8dad-4870-a748-402ea43d788c/100": "System.ThumbnailCacheId",
    "f29f85e0-4ff9-1068-ab91-08002b27b3d9/2": "System.Title",
    "f29f85e0-4ff9-1068-ab91-08002b27b3d9/4": "System.Author",
}
KNOWN_FOLDER_NAMES = {
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": "ProgramFiles",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "ProgramFilesX86",
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "System",
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "a77f5d77-2e2b-44c3-a6a2-aba601054a51": "Programs",
    "625b53c3-ab48-4ec1-ba1f-a1ef4146fc19": "StartMenu",
    "8983036c-27c0-404b-8f08-102d10dcfd74": "SendTo",
    "ae50c081-ebd2-438a-8655-8a092e34987a": "Recent",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "Profile",
    "3eb685db-65f9-4cf6-a03a-e3ef65729f3d": "RoamingAppData",
    "f1b32785-6fba-4fcf-9d55-7b8e7f157091": "LocalAppData",
    "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97": "ProgramData",
    "c4aa340d-f20f-4863-afef-f87ef2e6ba25": "PublicDesktop",
    "ed4824af-dce4-45a8-81e2-fc7965083634": "PublicDocuments",
    "1777f761-68ad-4d8a-87bd-30b759fa33dd": "Favorites",
}


def parse_lnk_tracker_data_block(block_data: bytes) -> dict[str, object]:
    machine_id = decode_text(block_data[0x10:0x20].split(b"\x00", 1)[0], "cp1252") if len(block_data) >= 0x20 else ""
    droid_file = format_guid_le(block_data[0x30:0x40])
    birth_droid_file = format_guid_le(block_data[0x50:0x60])
    return {
        "parse_status": "parsed-candidate" if len(block_data) >= 0x60 else "truncated-candidate",
        "machine_id": machine_id,
        "droid_volume_identifier": format_guid_le(block_data[0x20:0x30]),
        "droid_file_identifier": droid_file,
        "birth_droid_volume_identifier": format_guid_le(block_data[0x40:0x50]),
        "birth_droid_file_identifier": birth_droid_file,
        "droid_file_mac_address": uuid_v1_mac(block_data[0x30:0x40]),
        "droid_file_timestamp": uuid_v1_time(block_data[0x30:0x40]),
        "birth_droid_file_mac_address": uuid_v1_mac(block_data[0x50:0x60]),
        "birth_droid_file_timestamp": uuid_v1_time(block_data[0x50:0x60]),
        "validation_status": "candidate-requires-known-answer-corpus",
    }


def uuid_v1_mac(raw: bytes) -> str:
    if len(raw) != 16:
        return ""
    value = uuid.UUID(bytes_le=raw)
    if value.version != 1:
        return ""
    return ":".join(f"{byte:02x}" for byte in value.node.to_bytes(6, "big"))


def uuid_v1_time(raw: bytes) -> str:
    """UUID v1 timestamp (100 ns since 1582-10-15) -> ISO-8601 UTC."""
    if len(raw) != 16:
        return ""
    value = uuid.UUID(bytes_le=raw)
    if value.version != 1:
        return ""
    # 1582-10-15 -> 1601-01-01 is 18 years + leap days = 5748192000000000 ticks.
    filetime = value.time - 5_748_192_000_000_000
    return windows_filetime_to_iso(filetime) if filetime > 0 else ""


def extract_property_store_string_candidates(data: bytes) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    patterns = (
        re.compile(rb"[\x20-\x7e]{4,160}"),
        re.compile(rb"(?:[\x20-\x7e]\x00){4,160}"),
    )
    for pattern, encoding in ((patterns[0], "cp1252"), (patterns[1], "utf-16le")):
        for match in pattern.finditer(data):
            if len(candidates) >= MAX_LNK_PROPERTY_STORE_STRING_CANDIDATES:
                return candidates
            text = decode_text(match.group(0), encoding)
            if text and text not in seen:
                seen.add(text)
                candidates.append(text)
    return candidates



def shell_item_type_hint(value: int) -> str:
    if (value & 0x70) == 0x30:
        return "file-system"
    if (value & 0x70) == 0x20:
        return "volume"
    if (value & 0x70) == 0x40:
        return "network"
    return f"unknown-0x{value:02X}"


def parse_lnk_string_data(data: bytes, link_flags: int) -> tuple[dict[str, str], int]:
    offset = LNK_HEADER_SIZE
    if link_flags & 0x00000001:
        id_list_size = read_u16(data, offset)
        offset += 2 + id_list_size
    if link_flags & 0x00000002:
        link_info_size = read_u32(data, offset)
        offset += link_info_size
    strings: dict[str, str] = {}
    is_unicode = bool(link_flags & 0x00000080)
    for flag, name in STRING_DATA_FIELDS:
        if not (link_flags & flag):
            continue
        value, offset = read_lnk_counted_string(data, offset, is_unicode)
        strings[name] = value
    return strings, offset


def parse_lnk_link_info(data: bytes, link_flags: int) -> dict[str, object]:
    """MS-SHLLINK 2.3 LinkInfo: VolumeID, LocalBasePath, network link, suffix."""
    if not (link_flags & 0x00000002):
        return {}
    offset = LNK_HEADER_SIZE
    if link_flags & 0x00000001:
        offset += 2 + read_u16(data, offset)
    size = read_u32(data, offset)
    if size < 0x1C or offset + size > len(data):
        return {"parse_status": "invalid-link-info", "offset": offset, "size": size}
    block = data[offset : offset + size]
    header_size = read_u32(block, 4)
    link_info_flags = read_u32(block, 8)
    volume_id_offset = read_u32(block, 12)
    local_base_path_offset = read_u32(block, 16)
    network_link_offset = read_u32(block, 20)
    common_path_suffix_offset = read_u32(block, 24)
    has_volume = bool(link_info_flags & 0x1)
    has_network = bool(link_info_flags & 0x2)
    result: dict[str, object] = {
        "parse_status": "parsed",
        "offset": offset,
        "size": size,
        "header_size": header_size,
        "link_info_flags": link_info_flags,
        "has_volume_id_and_local_base_path": has_volume,
        "has_common_network_relative_link": has_network,
        "local_base_path_offset": local_base_path_offset,
        "common_path_suffix_offset": common_path_suffix_offset,
        "local_base_path": read_c_string(block, local_base_path_offset, "lnk-ansi") if has_volume else "",
        "common_path_suffix": read_c_string(block, common_path_suffix_offset, "lnk-ansi"),
    }
    if has_volume and volume_id_offset:
        result.update(parse_lnk_volume_id(block, volume_id_offset))
    if header_size >= 0x24:
        unicode_base_offset = read_u32(block, 28)
        unicode_suffix_offset = read_u32(block, 32)
        result["local_base_path_unicode_offset"] = unicode_base_offset
        result["common_path_suffix_unicode_offset"] = unicode_suffix_offset
        result["local_base_path_unicode"] = read_c_string(block, unicode_base_offset, "utf-16le") if has_volume else ""
        result["common_path_suffix_unicode"] = read_c_string(block, unicode_suffix_offset, "utf-16le")
        if result["local_base_path_unicode"]:
            result["local_base_path"] = result["local_base_path_unicode"]
        if result["common_path_suffix_unicode"]:
            result["common_path_suffix"] = result["common_path_suffix_unicode"]
    if has_network and network_link_offset:
        result.update(parse_lnk_network_link(block, network_link_offset))
    # MS-SHLLINK: the target's full path is LocalBasePath + CommonPathSuffix,
    # or NetName (\\server\share) + "\" + CommonPathSuffix for network links.
    # Writers that already embed the complete path are handled by the suffix check.
    local_base = str(result["local_base_path"])
    suffix = str(result["common_path_suffix"])
    if local_base:
        result["full_path"] = join_lnk_base_suffix(local_base, suffix)
        result["full_path_source"] = "local-base-path+common-path-suffix"
    elif result.get("net_name"):
        result["full_path"] = join_lnk_base_suffix(str(result["net_name"]), suffix)
        result["full_path_source"] = "net-name+common-path-suffix"
    else:
        result["full_path"] = suffix
        result["full_path_source"] = "common-path-suffix-only" if suffix else ""
    return result


def parse_lnk_volume_id(block: bytes, offset: int) -> dict[str, object]:
    size = read_u32(block, offset)
    if size < 0x10 or offset + size > len(block):
        return {"volume_id_parse_status": "invalid-volume-id"}
    volume = block[offset : offset + size]
    drive_type = read_u32(volume, 4)
    serial = read_u32(volume, 8)
    label_offset = read_u32(volume, 12)
    if label_offset == 0x14:
        label = read_c_string(volume, read_u32(volume, 16), "utf-16le")
        label_encoding = "utf-16le"
    else:
        label = read_c_string(volume, label_offset, "lnk-ansi") if label_offset else ""
        label_encoding = "ansi"
    return {
        "volume_id_parse_status": "parsed",
        "drive_type": drive_type,
        "drive_type_name": LNK_DRIVE_TYPES.get(drive_type, f"unknown-{drive_type}"),
        "volume_serial_number": f"{serial:08X}",
        "volume_label": label,
        "volume_label_encoding": label_encoding,
    }


def parse_lnk_network_link(block: bytes, offset: int) -> dict[str, object]:
    size = read_u32(block, offset)
    if size < 0x14 or offset + size > len(block):
        return {"network_link_parse_status": "invalid-common-network-relative-link"}
    link = block[offset : offset + size]
    flags = read_u32(link, 4)
    net_name_offset = read_u32(link, 8)
    device_name_offset = read_u32(link, 12)
    provider_type = read_u32(link, 16)
    net_name = read_c_string(link, net_name_offset, "lnk-ansi")
    device_name = read_c_string(link, device_name_offset, "lnk-ansi") if flags & 0x1 else ""
    if net_name_offset > 0x14 and size >= 0x1C:
        net_name = read_c_string(link, read_u32(link, 20), "utf-16le") or net_name
        if flags & 0x1:
            device_name = read_c_string(link, read_u32(link, 24), "utf-16le") or device_name
    return {
        "network_link_parse_status": "parsed",
        "network_link_flags": flags,
        "net_name": net_name,
        "device_name": device_name,
        "network_provider_type": f"0x{provider_type:08X}" if flags & 0x2 else "",
    }


LNK_DRIVE_TYPES = {
    0: "unknown",
    1: "no-root-dir",
    2: "removable",
    3: "fixed",
    4: "remote",
    5: "cdrom",
    6: "ramdisk",
}


def join_lnk_base_suffix(base: str, suffix: str) -> str:
    if not base:
        return suffix
    if not suffix or base.lower().endswith(suffix.lower()):
        return base
    return base.rstrip("\\") + "\\" + suffix.lstrip("\\")


def jump_list_metadata(path: Path, artifact_type: str) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError:
        return {"jump_list_parse_status": "read-error"}
    ole_streams = parse_ole_compound_streams(data) if data.startswith(CFB_SIGNATURE) else []
    destinations = extract_jumplist_destinations(data, ole_streams)
    destlist_metadata = parse_destlist_metadata(ole_streams)
    destlist_entries_all = list(destlist_metadata.pop("destlist_entries_all", None) or [])
    enrich_destinations_with_destlist_candidates(destinations, destlist_entries_all)
    embedded_paths = sorted(
        {
            item
            for item in [
                *extract_windows_paths(data),
                *(embedded_path for destination in destinations for embedded_path in destination.get("embedded_paths", [])),
                *(str(destination.get("target_path") or "") for destination in destinations),
            ]
            if item
        }
    )
    stream_summaries = [
        {
            "index": int(stream["index"]),
            "name": str(stream["name"]),
            "path": str(stream["path"]),
            "size": int(stream["size"]),
            "start_sector": int(stream["start_sector"]),
            "sha256": str(stream.get("sha256") or ""),
        }
        for stream in ole_streams[:MAX_OLE_STREAMS]
    ]
    stream_summaries_truncated = len(ole_streams) > MAX_OLE_STREAMS
    validation_checks = jumplist_validation_checks(data, ole_streams, destinations, destlist_metadata)
    report_grade = recent_report_grade_assessment(
        recent_validation_matrix(validation_checks),
        validation_required=True,
        gap_ids=["#14"],
        blockers=jumplist_commercial_blockers(destlist_metadata),
    )
    evidence = jumplist_evidence(path, artifact_type, data, stream_summaries, destinations, destlist_metadata)
    core_accuracy_gates = jumplist_core_accuracy_gates(
        {
            "source_path": str(path.resolve()),
            "source_hashes": file_hashes(path),
            "application_id_hash": path.stem.split(".", 1)[0],
            "ole_streams": stream_summaries,
            "destinations": destinations,
            "destlist_metadata": destlist_metadata,
            "validation_checks": validation_checks,
        }
    )
    details = {
        "jump_list_parse_status": "parsed-ole-stream-lnk" if ole_streams and destinations else "parsed-embedded-lnk" if destinations else "inventory",
        "coverage_status": "native-destlist-candidate" if destlist_metadata.get("destlist_parse_status") == "parsed-candidate" else "mapped",
        "reportability": "triage",
        "parser_confidence": jumplist_parser_confidence(destinations, destlist_metadata),
        "evidence_strength": "jumplist-destination-candidate" if destinations else "jumplist-container-presence",
        "commercial_grade_ready": False,
        "source_path": str(path.resolve()),
        "source_hashes": file_hashes(path),
        "artifact_type": artifact_type,
        "container_hint": "ole-compound-file" if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") else "custom-binary",
        "jumplist_kind": "automatic" if artifact_type == "jumplist-automatic" else "custom",
        "application_id_hash": path.stem.split(".", 1)[0],
        "ole_parse_status": "parsed" if ole_streams else "not-ole" if not data.startswith(CFB_SIGNATURE) else "no-streams",
        "ole_stream_count": len(ole_streams),
        "ole_streams": stream_summaries,
        "ole_streams_truncated": stream_summaries_truncated,
        "embedded_paths": embedded_paths,
        "destination_count": len(destinations),
        "destination_stream_count": len({str(destination.get("stream_path") or "") for destination in destinations if destination.get("stream_path")}),
        "destinations": destinations[:MAX_JUMPLIST_INLINE_DESTINATIONS],
        "destinations_truncated": len(destinations) > MAX_JUMPLIST_INLINE_DESTINATIONS,
        "destinations_total": len(destinations),
        "jumplist_evidence": evidence,
        "validation_checks": validation_checks,
        "core_accuracy_gates": core_accuracy_gates,
        "recent_validation_matrix": recent_validation_matrix(validation_checks),
        "recent_report_grade_assessment": report_grade,
        "recent_native_capabilities": JUMPLIST_CAPABILITIES,
        "commercial_uplift_evidence": jumplist_commercial_uplift_evidence(
            {
                "source_path": str(path.resolve()),
                "source_hashes": file_hashes(path),
                "artifact_type": artifact_type,
                "application_id_hash": path.stem.split(".", 1)[0],
                "recent_validation_matrix": recent_validation_matrix(validation_checks),
                "recent_report_grade_assessment": report_grade,
                "destination_count": len(destinations),
                "ole_stream_count": len(ole_streams),
                "destlist_parse_status": destlist_metadata.get("destlist_parse_status", ""),
            }
        ),
        "forensic_review": build_forensic_review(
            gap_id="#14",
            artifact_goal="JumpList DestList and embedded LNK destination evidence",
            primary_evidence=[
                f"app_id_hash={path.stem.split('.', 1)[0]}",
                f"destinations={len(destinations)}",
                f"streams={len(ole_streams)}",
                f"destlist={destlist_metadata.get('destlist_parse_status', '')}",
            ],
            validation_required=True,
            report_grade_assessment=report_grade,
            commercial_grade_ready=False,
            caveats=[
                "DestList fields are candidate-level and OS-version validation is incomplete.",
                "Deleted JumpList entry recovery is not report-grade.",
            ],
        ),
        "validation_guidance": (
            "Jump List rows recover OLE stream provenance, embedded Shell Link destinations, and bounded DestList metadata candidates. "
            "Validate OS-version-specific DestList field semantics, deleted entries, and account context with a dedicated Jump List parser before final testimony."
        ),
        "commercial_grade_blockers": report_grade["blockers"],
        **destlist_metadata,
        "note": "OLE Jump List streams are traversed when recoverable; DestList rows are exposed as metadata candidates and embedded Shell Link/path extraction is provided for triage search.",
    }
    details["jumplist_analyst_review_profile"] = jumplist_analyst_review_profile(details)
    details["jumplist_destlist_depth_manifest"] = jumplist_destlist_depth_manifest(details)
    details["jumplist_destlist_depth_manifest_hash"] = details["jumplist_destlist_depth_manifest"]["manifest_sha256"]
    details["_jumplist_entries"] = jumplist_entry_payloads(artifact_type, destlist_entries_all, destinations)
    return details


# (source key, row key) pairs for ``jumplist-entry`` rows.
JUMPLIST_ENTRY_DESTLIST_FIELDS = (
    ("entry_number", "destlist_entry_number"),
    ("lnk_stream_name", "lnk_stream_name"),
    ("lnk_stream_present", "lnk_stream_present"),
    ("destlist_version", "destlist_version"),
    ("layout_status", "destlist_layout_status"),
    ("entry_offset", "destlist_entry_offset"),
    ("path", "destlist_path"),
    ("hostname", "destlist_hostname"),
    ("hostname_encoding", "destlist_hostname_encoding"),
    ("hostname_raw_hex", "destlist_hostname_raw_hex"),
    ("last_modified_at", "destlist_last_modified_at"),
    ("last_modified_filetime", "destlist_last_modified_filetime"),
    ("pin_status", "destlist_pin_status"),
    ("pinned", "destlist_pinned"),
    ("access_count", "destlist_access_count"),
    ("access_count_float_v1", "destlist_access_count_float_v1"),
    ("volume_droid", "destlist_volume_droid"),
    ("file_droid", "destlist_file_droid"),
    ("birth_volume_droid", "destlist_birth_volume_droid"),
    ("birth_file_droid", "destlist_birth_file_droid"),
    ("file_droid_mac_address", "destlist_file_droid_mac_address"),
    ("file_droid_timestamp", "destlist_file_droid_timestamp"),
    ("checksum_hex", "destlist_checksum_hex"),
    ("entry_sha256", "destlist_entry_sha256"),
)
JUMPLIST_ENTRY_LNK_FIELDS = (
    ("target_path", "target_path"),
    ("target_created_at", "target_created_at"),
    ("target_accessed_at", "target_accessed_at"),
    ("target_modified_at", "target_modified_at"),
    ("target_file_size", "target_file_size"),
    ("working_dir", "working_dir"),
    ("command_line_arguments", "command_line_arguments"),
    ("volume_serial_number", "volume_serial_number"),
    ("drive_type_name", "drive_type_name"),
    ("volume_label", "volume_label"),
    ("net_name", "net_name"),
    ("tracker_machine_id", "tracker_machine_id"),
    ("has_tracker_data", "has_tracker_data"),
    ("stream_name", "lnk_stream_name"),
    ("stream_sha256", "lnk_stream_sha256"),
    ("lnk_offset", "lnk_offset"),
)


def jumplist_entry_payloads(
    artifact_type: str,
    destlist_entries: Sequence[Mapping[str, object]],
    destinations: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """One payload per DestList entry (joined to its LNK stream by entry
    number = hex stream name), plus LNK streams without a DestList entry and
    custom-destination LNKs. No cap: every entry becomes a ``jumplist-entry`` row."""
    by_stream = {str(item.get("stream_name") or ""): item for item in destinations if item.get("stream_name")}
    used_streams: set[str] = set()
    payloads: list[dict[str, object]] = []
    for entry in destlist_entries:
        if entry.get("layout_status") is None:
            continue  # legacy heuristic candidates are not emitted as rows
        payload: dict[str, object] = {"destlist_entry_present": True}
        payload.update({target: entry.get(source) for source, target in JUMPLIST_ENTRY_DESTLIST_FIELDS if source in entry})
        stream_name = str(entry.get("lnk_stream_name") or "")
        destination = by_stream.get(stream_name)
        if destination:
            used_streams.add(stream_name)
            payload.update({target: destination.get(source) for source, target in JUMPLIST_ENTRY_LNK_FIELDS})
        payload["timestamp"] = str(entry.get("last_modified_at") or "")
        payload["timestamp_source"] = "destlist_entry_last_modified" if payload["timestamp"] else "missing_destlist_time"
        payload["timestamp_kind"] = "last-access"
        payloads.append(payload)
    for destination in destinations:
        stream_name = str(destination.get("stream_name") or "")
        if stream_name in used_streams:
            continue
        payload = {"destlist_entry_present": False}
        payload.update({target: destination.get(source) for source, target in JUMPLIST_ENTRY_LNK_FIELDS})
        payload["timestamp"] = ""
        payload["timestamp_source"] = "none-lnk-target-times-are-target-file-metadata"
        payload["timestamp_kind"] = ""
        payloads.append(payload)
    return payloads


def jumplist_evidence(
    path: Path,
    artifact_type: str,
    data: bytes,
    stream_summaries: Sequence[dict[str, object]],
    destinations: Sequence[dict[str, object]],
    destlist_metadata: dict[str, object],
) -> dict[str, object]:
    return {
        "container": {
            "application_id_hash": path.stem.split(".", 1)[0],
            "kind": "automatic" if artifact_type == "jumplist-automatic" else "custom",
            "container_hint": "ole-compound-file" if data.startswith(CFB_SIGNATURE) else "custom-binary",
            "ole_stream_count": len(stream_summaries),
            "stream_names": [str(item.get("name") or "") for item in stream_summaries],
        },
        "destlist": {
            "parse_status": destlist_metadata.get("destlist_parse_status", ""),
            "declared_entry_count": destlist_metadata.get("destlist_declared_entry_count", 0),
            "candidate_count": destlist_metadata.get("destlist_entry_candidate_count", 0),
            "unlinked_entry_candidate_count": destlist_metadata.get("destlist_unlinked_entry_candidate_count", 0),
            "deleted_or_unlinked_entry_review_status": destlist_metadata.get(
                "destlist_deleted_or_unlinked_entry_review_status",
                "",
            ),
            "unlinked_entry_candidates": list(destlist_metadata.get("destlist_unlinked_entry_candidates") or [])[:10],
            "validation_checks": dict(destlist_metadata.get("destlist_validation_checks") or {}),
        },
        "destinations": [
            {
                "target_path": str(destination.get("target_path") or ""),
                "stream_path": str(destination.get("stream_path") or ""),
                "lnk_offset": destination.get("lnk_offset", 0),
                "has_tracker_data": bool(destination.get("has_tracker_data")),
                "destlist_entry_offset_candidate": destination.get("destlist_entry_offset_candidate"),
                "destlist_layout_candidate": destination.get("destlist_layout_candidate", ""),
                "destlist_validation_status": destination.get("destlist_validation_status", ""),
                "destlist_entry_citation_hash": (
                    destination.get("destlist_entry_citation", {}).get("citation_hash")
                    if isinstance(destination.get("destlist_entry_citation"), Mapping)
                    else ""
                ),
                "filetime_candidates": list(destination.get("destlist_filetime_candidates") or [])[:4],
            }
            for destination in destinations[:50]
        ],
        "review_guidance": [
            "compare target_path with DestList path candidate and LNK stream path",
            "verify application ID mapping before attributing the source application",
            "treat deleted DestList entries as unsupported until slack recovery is validated",
        ],
    }


def recent_stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def lnk_target_context_citation_profile(details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    link_info = details.get("link_info") if isinstance(details.get("link_info"), Mapping) else {}
    tracker = details.get("tracker_data") if isinstance(details.get("tracker_data"), Mapping) else {}
    validation_checks = (
        details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    )
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    extra_blocks = [item for item in details.get("extra_data_blocks") or [] if isinstance(item, Mapping)]
    property_blocks = [item for item in details.get("property_store_blocks") or [] if isinstance(item, Mapping)]
    target_context = {
        "target_path": str(details.get("target_path") or ""),
        "working_dir": str(details.get("working_dir") or ""),
        "relative_path": str(details.get("relative_path") or ""),
        "command_line_arguments": str(details.get("command_line_arguments") or ""),
        "icon_location": str(details.get("icon_location") or ""),
        "target_created_at": str(details.get("target_created_at") or ""),
        "target_accessed_at": str(details.get("target_accessed_at") or ""),
        "target_modified_at": str(details.get("target_modified_at") or ""),
        "target_file_size": int(details.get("target_file_size") or 0),
        "tracker_machine_id": str(tracker.get("machine_id") or ""),
    }
    header_fields = [
        {"field": "header_size", "structure": "ShellLinkHeader", "offset": 0x00, "size": 4, "value": int(details.get("lnk_header_size") or 0)},
        {"field": "link_clsid", "structure": "ShellLinkHeader", "offset": 0x04, "size": 16, "value": "validated"},
        {"field": "link_flags", "structure": "ShellLinkHeader", "offset": 0x14, "size": 4, "value": int(details.get("link_flags") or 0)},
        {"field": "file_attributes", "structure": "ShellLinkHeader", "offset": 0x18, "size": 4, "value": int(details.get("file_attributes") or 0)},
        {"field": "target_created_at", "structure": "ShellLinkHeader", "offset": 0x1C, "size": 8, "value": target_context["target_created_at"]},
        {"field": "target_accessed_at", "structure": "ShellLinkHeader", "offset": 0x24, "size": 8, "value": target_context["target_accessed_at"]},
        {"field": "target_modified_at", "structure": "ShellLinkHeader", "offset": 0x2C, "size": 8, "value": target_context["target_modified_at"]},
        {"field": "target_file_size", "structure": "ShellLinkHeader", "offset": 0x34, "size": 4, "value": target_context["target_file_size"]},
        {"field": "show_command", "structure": "ShellLinkHeader", "offset": 0x3C, "size": 4, "value": int(details.get("show_command") or 0)},
        {"field": "hot_key", "structure": "ShellLinkHeader", "offset": 0x40, "size": 2, "value": int(details.get("hot_key") or 0)},
    ]
    string_fields = [
        {"field": "target_path", "structure": "LinkInfo/StringData/embedded path", "value": target_context["target_path"]},
        {"field": "working_dir", "structure": "StringData", "value": target_context["working_dir"]},
        {"field": "relative_path", "structure": "StringData", "value": target_context["relative_path"]},
        {"field": "command_line_arguments", "structure": "StringData", "value": target_context["command_line_arguments"]},
        {"field": "icon_location", "structure": "StringData", "value": target_context["icon_location"]},
    ]
    field_sources = header_fields + [item for item in string_fields if item["value"] not in ("", None)]
    if tracker:
        field_sources.append(
            {
                "field": "tracker_machine_id",
                "structure": "TrackerDataBlock",
                "block_offset": next(
                    (int(block.get("offset") or 0) for block in extra_blocks if block.get("type") == "TrackerDataBlock"),
                    0,
                ),
                "value": target_context["tracker_machine_id"],
            }
        )
    profile_payload = {
        "profile_version": "lnk-target-context-citation-profile-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 17,
        "gap_id": "#17",
        "qc_prep_item_number": QC_PREP_LNK_ITEM,
        "qc_prep_item_goal": QC_PREP_LNK_GOAL,
        "source": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "entry_name": str(details.get("entry_name") or ""),
            "source_format": "lnk-shell-link",
        },
        "source_viewer_locator": {
            "viewer": "lnk-shell-link",
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "header_offset": 0,
            "header_size": LNK_HEADER_SIZE,
            "string_data_end_offset": int(details.get("string_data_offset") or 0),
            "extra_data_block_count": len(extra_blocks),
        },
        "target_context": {
            **target_context,
            "target_identity_hash": recent_stable_sha256(target_context),
        },
        "field_sources": field_sources,
        "link_info_bounds": {
            "parse_status": str(link_info.get("parse_status") or "not-present"),
            "offset": int(str(link_info.get("offset") or "0")),
            "size": int(str(link_info.get("size") or "0")),
            "header_size": int(str(link_info.get("header_size") or "0")),
            "local_base_path_offset": int(str(link_info.get("local_base_path_offset") or "0")),
            "common_path_suffix_offset": int(str(link_info.get("common_path_suffix_offset") or "0")),
        },
        "extra_data_bounds": [
            {
                "index": int(block.get("index") or 0),
                "offset": int(block.get("offset") or 0),
                "size": int(block.get("size") or 0),
                "signature": str(block.get("signature") or ""),
                "type": str(block.get("type") or ""),
                "parse_status": str(block.get("parse_status") or ""),
            }
            for block in extra_blocks
        ],
        "tracker_context": {
            "present": bool(tracker),
            "parse_status": str(tracker.get("parse_status") or ""),
            "machine_id": str(tracker.get("machine_id") or ""),
            "droid_file_identifier": str(tracker.get("droid_file_identifier") or ""),
            "birth_droid_file_identifier": str(tracker.get("birth_droid_file_identifier") or ""),
            "validation_status": str(tracker.get("validation_status") or ""),
        },
        "property_store_review": {
            "block_count": len(property_blocks),
            "embedded_path_count": sum(len(block.get("embedded_paths") or []) for block in property_blocks),
            "string_candidate_count": sum(len(block.get("string_candidates") or []) for block in property_blocks),
            "guid_candidate_count": sum(len(block.get("guid_candidates") or []) for block in property_blocks),
            "candidate_profile_hash": recent_stable_sha256(
                [
                    {
                        "embedded_paths": list(block.get("embedded_paths") or []),
                        "strings": list(block.get("string_candidates") or []),
                        "guids": list(block.get("guid_candidates") or []),
                    }
                    for block in property_blocks
                ]
            ),
            "reportability": "review-only",
        },
        "validation_summary": {
            "passed_check_ids": sorted(str(key).replace("_", "-") for key, value in validation_checks.items() if bool(value)),
            "failed_check_ids": sorted(str(key).replace("_", "-") for key, value in validation_checks.items() if not bool(value)),
            "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        },
        "reportability_decision": lnk_reportability_decision(report_grade, details),
    }
    # Keep the displayed locator path, but do not let a temp mount/root path make
    # the stable citation hash change for identical shortcut bytes.
    hash_payload = dict(profile_payload)
    hash_payload["source"] = {**profile_payload["source"], "source_path": ""}
    hash_payload["source_viewer_locator"] = {
        **profile_payload["source_viewer_locator"],
        "source_path": "",
    }
    profile_payload["profile_sha256"] = recent_stable_sha256(hash_payload)
    return profile_payload


def lnk_metadata_depth_manifest(details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    reportability = lnk_reportability_decision(report_grade, details)
    link_info = details.get("link_info") if isinstance(details.get("link_info"), Mapping) else {}
    shell_items = details.get("shell_item_metadata") if isinstance(details.get("shell_item_metadata"), Mapping) else {}
    tracker = details.get("tracker_data") if isinstance(details.get("tracker_data"), Mapping) else {}
    validation_checks = (
        details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    )
    target_context_profile = (
        details.get("lnk_target_context_citation_profile")
        if isinstance(details.get("lnk_target_context_citation_profile"), Mapping)
        else {}
    )
    extra_blocks = [item for item in details.get("extra_data_blocks") or [] if isinstance(item, Mapping)]
    property_blocks = [item for item in details.get("property_store_blocks") or [] if isinstance(item, Mapping)]
    manifest_payload = {
        "manifest_version": "lnk-metadata-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-016-020",
        "item_number": 17,
        "gap_id": "#17",
        "qc_prep_item_number": QC_PREP_LNK_ITEM,
        "qc_prep_item_goal": QC_PREP_LNK_GOAL,
        "qc_prep_contract": dict(QC_PREP_LNK_CONTRACT),
        "artifact_type": str(details.get("artifact_type") or "recent-shortcut"),
        "source": {
            "source_path": str(details.get("source_path") or ""),
            "source_sha256": str(hashes.get("sha256") or ""),
            "entry_name": str(details.get("entry_name") or ""),
            "source_format": "lnk-shell-link",
        },
        "row_identity": {
            "target_path": str(details.get("target_path") or ""),
            "working_dir": str(details.get("working_dir") or ""),
            "relative_path": str(details.get("relative_path") or ""),
            "command_line_arguments": str(details.get("command_line_arguments") or ""),
            "icon_location": str(details.get("icon_location") or ""),
            "tracker_machine_id": str(tracker.get("machine_id") or ""),
            "identity_hash": recent_stable_sha256(
                {
                    "target_path": str(details.get("target_path") or ""),
                    "working_dir": str(details.get("working_dir") or ""),
                    "arguments": str(details.get("command_line_arguments") or ""),
                    "tracker_machine_id": str(tracker.get("machine_id") or ""),
                }
            ),
        },
        "header_validation": {
            "parse_status": str(details.get("lnk_parse_status") or ""),
            "header_size": int(details.get("lnk_header_size") or 0),
            "clsid_validated": str(details.get("lnk_parse_status") or "") == "parsed",
            "link_flags_raw": int(details.get("link_flags") or 0),
            "link_flag_names": list(details.get("link_flag_names") or []),
            "file_attributes_raw": int(details.get("file_attributes") or 0),
            "file_attribute_names": list(details.get("file_attribute_names") or []),
        },
        "target_and_string_data": {
            "target_path": str(details.get("target_path") or ""),
            "embedded_paths": list(details.get("embedded_paths") or [])[:50],
            "description": str(details.get("description") or ""),
            "relative_path": str(details.get("relative_path") or ""),
            "working_dir": str(details.get("working_dir") or ""),
            "command_line_arguments": str(details.get("command_line_arguments") or ""),
            "icon_location": str(details.get("icon_location") or ""),
            "target_created_at": str(details.get("target_created_at") or ""),
            "target_accessed_at": str(details.get("target_accessed_at") or ""),
            "target_modified_at": str(details.get("target_modified_at") or ""),
            "target_file_size": int(details.get("target_file_size") or 0),
            "string_data_offset": int(details.get("string_data_offset") or 0),
        },
        "linkinfo_and_shell_items": {
            "link_info_parse_status": str(link_info.get("parse_status") or "not-present"),
            "local_base_path": str(link_info.get("local_base_path") or ""),
            "common_path_suffix": str(link_info.get("common_path_suffix") or ""),
            "shell_item_parse_status": str(shell_items.get("parse_status") or ""),
            "shell_item_count": len(shell_items.get("items") or []),
            "full_shell_item_semantics_validated": False,
        },
        "extra_data": {
            "extra_data_block_count": len(extra_blocks),
            "extra_data_block_types": [str(item.get("type") or "") for item in extra_blocks],
            "has_tracker_data": bool(tracker),
            "tracker_parse_status": str(tracker.get("parse_status") or ""),
            "tracker_machine_id": str(tracker.get("machine_id") or ""),
            "tracker_guid_validation_status": str(tracker.get("validation_status") or ""),
            "property_store_block_count": len(property_blocks),
            "full_property_store_decode_available": bool(
                validation_checks.get("full_property_store_decode_available")
            ),
        },
        "target_context_citation_profile": {
            "profile_version": str(target_context_profile.get("profile_version") or ""),
            "profile_sha256": str(target_context_profile.get("profile_sha256") or ""),
            "field_source_count": len(target_context_profile.get("field_sources") or []),
            "extra_data_bound_count": len(target_context_profile.get("extra_data_bounds") or []),
            "viewer": (
                target_context_profile.get("source_viewer_locator", {}).get("viewer")
                if isinstance(target_context_profile.get("source_viewer_locator"), Mapping)
                else ""
            ),
        },
        "citation_refs": [
            {
                "kind": "lnk-source-file",
                "source_path": str(details.get("source_path") or ""),
                "source_sha256": str(hashes.get("sha256") or ""),
            },
            {
                "kind": "lnk-header",
                "header_size": int(details.get("lnk_header_size") or 0),
                "link_flags_raw": int(details.get("link_flags") or 0),
            },
            {
                "kind": "lnk-string-data",
                "string_data_offset": int(details.get("string_data_offset") or 0),
                "target_path": str(details.get("target_path") or ""),
            },
            {
                "kind": "lnk-link-info",
                "parse_status": str(link_info.get("parse_status") or "not-present"),
                "local_base_path": str(link_info.get("local_base_path") or ""),
            },
            {
                "kind": "lnk-extra-data",
                "extra_data_block_count": len(extra_blocks),
                "extra_data_block_types": [str(item.get("type") or "") for item in extra_blocks],
            },
            {
                "kind": "lnk-tracker",
                "machine_id": str(tracker.get("machine_id") or ""),
                "validation_status": str(tracker.get("validation_status") or ""),
            },
            {
                "kind": "lnk-target-context-profile",
                "profile_sha256": str(target_context_profile.get("profile_sha256") or ""),
                "target_identity_hash": (
                    target_context_profile.get("target_context", {}).get("target_identity_hash")
                    if isinstance(target_context_profile.get("target_context"), Mapping)
                    else ""
                ),
            },
        ],
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "report_grade_ready": bool(report_grade.get("report_grade_ready")),
            "commercial_grade_ready": False,
            "target_context_complete": False,
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "decode and validate full Shell Item and property-store semantics",
            "decode LinkInfo drive, volume, and network provider fields with trusted diff evidence",
            "validate TrackerDataBlock GUID and machine-id semantics against known-answer shortcuts",
            "attach LECmd or equivalent trusted parser record-level diff for critical shortcuts",
        ],
    }
    manifest_payload["manifest_sha256"] = recent_stable_sha256(manifest_payload)
    return manifest_payload


def lnk_analyst_review_profile(details: Mapping[str, object]) -> dict[str, object]:
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    tracker = details.get("tracker_data") if isinstance(details.get("tracker_data"), Mapping) else {}
    target_context_profile = (
        details.get("lnk_target_context_citation_profile")
        if isinstance(details.get("lnk_target_context_citation_profile"), Mapping)
        else {}
    )
    source_values = {
        "target_path": str(details.get("target_path") or ""),
        "working_dir": str(details.get("working_dir") or ""),
        "command_line_arguments": str(details.get("command_line_arguments") or ""),
        "tracker_machine_id": str(tracker.get("machine_id") or ""),
        "target_created_at": str(details.get("target_created_at") or ""),
        "target_modified_at": str(details.get("target_modified_at") or ""),
        "target_accessed_at": str(details.get("target_accessed_at") or ""),
    }
    failed_checks = sorted(str(key) for key, value in checks.items() if value is False)
    blockers = sorted(set(str(item) for item in report_grade.get("blockers", []) if str(item)))
    return {
        "profile_version": "lnk-analyst-review-profile-v1",
        "qc_prep_item_number": QC_PREP_LNK_ITEM,
        "qc_prep_item_goal": QC_PREP_LNK_GOAL,
        "artifact_type": str(details.get("artifact_type") or "recent-shortcut"),
        "severity": "medium",
        "summary": "Shell Link shortcut pivot with target path, LinkInfo/StringData, timestamps, and tracker context.",
        "evidence_interpretation": "shortcut target/context metadata; account, shell-item, and property-store semantics still need validation",
        "not_proof_of": ["file opened by a specific user without correlation", "complete Shell Item semantics", "complete PropertyStore metadata"],
        "analyst_questions": [
            "Does LECmd confirm the same target, working directory, arguments, timestamps, and tracker fields?",
            "Do MFT/USN/JumpList/ShellBags corroborate the target path and access timeline?",
            "Is the shortcut target local, removable, network, or cloud-backed, and is that provider context validated?",
        ],
        "primary_pivots": [
            "target_path",
            "working_dir",
            "command_line_arguments",
            "tracker_machine_id",
            "target_created_at",
            "target_modified_at",
            "target_accessed_at",
        ],
        "target_context_citation_profile_hash": str(target_context_profile.get("profile_sha256") or ""),
        "source_field_values": {key: value for key, value in source_values.items() if value not in ("", None, [], {})},
        "correlation_targets": ["MFT", "USN", "JumpList", "ShellBags", "Windows Search", "LECmd"],
        "risk_tags": ["shortcut-context", "lnk-validation-required"],
        "validation_required": True,
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": blockers,
        "report_guidance": (
            "Use LNK rows as shortcut-context pivots. Final target-use or user-attribution claims require "
            "trusted parser diff and filesystem/recent-artifact correlation."
        ),
    }


def jumplist_destlist_depth_manifest(details: Mapping[str, object]) -> dict[str, object]:
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    evidence = details.get("jumplist_evidence") if isinstance(details.get("jumplist_evidence"), Mapping) else {}
    container = evidence.get("container") if isinstance(evidence.get("container"), Mapping) else {}
    destlist = evidence.get("destlist") if isinstance(evidence.get("destlist"), Mapping) else {}
    destinations = [item for item in details.get("destinations") or [] if isinstance(item, Mapping)]
    destlist_checks = (
        details.get("destlist_validation_checks")
        if isinstance(details.get("destlist_validation_checks"), Mapping)
        else {}
    )
    reportability = jumplist_reportability_decision(report_grade, details)
    source = {
        "source_path": str(details.get("source_path") or ""),
        "source_sha256": str(hashes.get("sha256") or ""),
        "artifact_type": str(details.get("artifact_type") or ""),
        "application_id_hash": str(details.get("application_id_hash") or ""),
        "jumplist_kind": str(details.get("jumplist_kind") or ""),
    }
    container_identity = {
        "container_hint": str(details.get("container_hint") or ""),
        "ole_parse_status": str(details.get("ole_parse_status") or ""),
        "ole_stream_count": int(details.get("ole_stream_count") or 0),
        "stream_names": list(container.get("stream_names") or [])[:50],
        "destination_count": int(details.get("destination_count") or 0),
        "destination_stream_count": int(details.get("destination_stream_count") or 0),
    }
    manifest_payload = {
        "manifest_version": "jumplist-destlist-depth-manifest-v1",
        "parser_version": PARSER_VERSION,
        "commercial_batch_id": "commercial-uplift-011-015",
        "item_number": 14,
        "qc_prep_item_number": QC_PREP_JUMPLIST_ITEM,
        "qc_prep_item_goal": "Deepen JumpList DestList, CFB/OLE stream, AppID mapping, deleted entry recovery, and embedded LNK linkage.",
        "gap_id": "#14",
        "artifact_type": str(details.get("artifact_type") or ""),
        "qc_prep_contract": {
            "implemented": [
                "CFB/OLE stream inventory with bounded stream limits",
                "DestList header and entry candidate parsing",
                "embedded LNK destination extraction and linkage candidates",
                "AppID hash provenance and deleted/unlinked entry warning",
                "trusted JLECmd/LECmd-style DestList diff helper",
            ],
            "usable_outputs": ["jumplist-automatic", "jumplist-custom"],
            "validated_by_current_tests": [
                "DestList linked destination fixture",
                "unlinked/deleted entry review-only candidate fixture",
                "trusted JumpList diff pass",
                "DestList offset mismatch blocking",
            ],
            "not_report_grade_until": [
                "OS-version-specific DestList field semantics are validated",
                "AppID hash mapping database is attached",
                "deleted/unlinked entry recovery is known-answer validated",
                "embedded LNK and DestList entries are diffed against trusted parser output",
            ],
        },
        "source": source,
        "container_identity": container_identity,
        "container_identity_hash": recent_stable_sha256(container_identity),
        "destlist_decoding": {
            "parse_status": str(details.get("destlist_parse_status") or ""),
            "stream_count": int(details.get("destlist_stream_count") or 0),
            "declared_entry_count_candidates": list(details.get("destlist_declared_entry_count_candidates") or [])[:10],
            "entry_candidate_count": int(details.get("destlist_entry_candidate_count") or 0),
            "unlinked_entry_candidate_count": int(details.get("destlist_unlinked_entry_candidate_count") or 0),
            "deleted_or_unlinked_entry_review_status": str(
                details.get("destlist_deleted_or_unlinked_entry_review_status") or ""
            ),
            "has_destlist_stream": bool(destlist_checks.get("has_destlist_stream")),
            "declared_count_matches_candidates": bool(destlist_checks.get("declared_count_matches_candidates")),
            "report_grade": bool(destlist_checks.get("report_grade")),
            "os_version_semantics_validated": False,
            "deleted_entry_recovery_validated": bool(JUMPLIST_CAPABILITIES["destlist_deleted_entry_recovery"]),
            "account_metadata_decoded": bool(JUMPLIST_CAPABILITIES["destlist_account_metadata_decode"]),
        },
        "destination_linkage": {
            "destination_count": len(destinations),
            "linked_lnk_stream_count": sum(1 for item in destinations if item.get("stream_path")),
            "target_paths": [str(item.get("target_path") or "") for item in destinations if item.get("target_path")][:50],
            "linked_destlist_candidate_count": sum(
                1 for item in destinations if str(item.get("destlist_validation_status") or "") == "candidate-linked-lnk-stream"
            ),
            "destination_preview": [
                {
                    "target_path": str(item.get("target_path") or ""),
                    "stream_path": str(item.get("stream_path") or ""),
                    "destlist_entry_index_candidate": item.get("destlist_entry_index_candidate", ""),
                    "destlist_entry_offset_candidate": item.get("destlist_entry_offset_candidate", ""),
                    "destlist_layout_candidate": str(item.get("destlist_layout_candidate") or ""),
                    "destlist_validation_status": str(item.get("destlist_validation_status") or ""),
                    "destlist_entry_citation_hash": (
                        item.get("destlist_entry_citation", {}).get("citation_hash")
                        if isinstance(item.get("destlist_entry_citation"), Mapping)
                        else ""
                    ),
                    "has_tracker_data": bool(item.get("has_tracker_data")),
                }
                for item in destinations[:25]
            ],
        },
        "appid_mapping": {
            "application_id_hash": str(details.get("application_id_hash") or ""),
            "application_name_mapping_available": bool(JUMPLIST_CAPABILITIES["appid_hash_mapping"]),
            "blocker": "application-id-hash-to-application-name-map-not-bundled",
        },
        "citation_refs": [
            {
                "kind": "jumplist-source-container",
                "source_path": str(details.get("source_path") or ""),
                "source_sha256": str(hashes.get("sha256") or ""),
            },
            {
                "kind": "jumplist-cfb-stream-inventory",
                "ole_stream_count": int(details.get("ole_stream_count") or 0),
                "stream_names": list(container.get("stream_names") or [])[:50],
            },
            {
                "kind": "jumplist-destlist-candidates",
                "parse_status": str(destlist.get("parse_status") or details.get("destlist_parse_status") or ""),
                "candidate_count": int(destlist.get("candidate_count") or details.get("destlist_entry_candidate_count") or 0),
                "unlinked_entry_candidate_count": int(destlist.get("unlinked_entry_candidate_count") or 0),
            },
            {
                "kind": "jumplist-embedded-lnk-destinations",
                "destination_count": len(destinations),
            },
            {
                "kind": "jumplist-appid-hash",
                "application_id_hash": str(details.get("application_id_hash") or ""),
                "mapping_available": bool(JUMPLIST_CAPABILITIES["appid_hash_mapping"]),
            },
        ],
        "reportability": {
            "allowed_use": reportability["allowed_use"],
            "decision": reportability["decision"],
            "report_grade_ready": bool(report_grade.get("report_grade_ready")),
            "commercial_grade_ready": False,
            "destlist_semantics_final": False,
            "deleted_entries_recovered": False,
            "blockers": reportability["blockers"],
        },
        "required_before_commercial_grade": [
            "validate OS-version-specific DestList header and entry field semantics",
            "attach AppID hash to application-name mapping provenance",
            "validate deleted/unlinked entry recovery against slack/known-answer corpus",
            "diff embedded LNK and DestList entries against JLECmd/LECmd output",
        ],
    }
    manifest_payload["manifest_sha256"] = recent_stable_sha256(manifest_payload)
    return manifest_payload


def jumplist_analyst_review_profile(details: Mapping[str, object]) -> dict[str, object]:
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    validation_checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), Mapping) else {}
    destinations = [item for item in details.get("destinations") or [] if isinstance(item, Mapping)]
    source_values = {
        "application_id_hash": str(details.get("application_id_hash") or ""),
        "jumplist_kind": str(details.get("jumplist_kind") or ""),
        "destination_count": int(details.get("destination_count") or 0),
        "destlist_parse_status": str(details.get("destlist_parse_status") or ""),
        "target_paths": [str(item.get("target_path") or "") for item in destinations if item.get("target_path")][:25],
    }
    failed_checks = sorted(str(key) for key, value in validation_checks.items() if not bool(value))
    blockers = sorted(
        set(str(item) for item in report_grade.get("blockers", []) if str(item))
        | set(JUMPLIST_COMMERCIAL_BLOCKERS)
    )
    return {
        "profile_version": "jumplist-analyst-review-profile-v1",
        "artifact_type": str(details.get("artifact_type") or ""),
        "severity": "medium" if destinations else "info",
        "summary": "JumpList recent-destination pivot with OLE stream, DestList, and embedded LNK context.",
        "evidence_interpretation": "recent destination/container evidence; DestList fields remain candidate-level until version validation",
        "not_proof_of": ["file opened by a specific user without account/context validation", "final DestList semantics", "deleted entry recovery"],
        "analyst_questions": [
            "Which application does the AppID hash map to, and is that mapping documented?",
            "Do embedded LNK targets match DestList entry candidates?",
            "Does JLECmd/LECmd confirm the same destinations and MRU/pin semantics?",
        ],
        "primary_pivots": ["application_id_hash", "jumplist_kind", "destination_count", "destlist_parse_status", "target_paths"],
        "source_field_values": {key: value for key, value in source_values.items() if value not in ("", None, [], {})},
        "correlation_targets": ["LNK viewer", "MFT", "USN", "ShellBags", "Windows Search", "Application activity"],
        "risk_tags": ["recent-destination", "destlist-validation-required"],
        "validation_required": bool(report_grade.get("status") != "report-grade-ready" or failed_checks),
        "failed_validation_checks": failed_checks,
        "report_grade_ready": bool(report_grade.get("report_grade_ready")),
        "commercial_blockers": blockers,
        "report_guidance": (
            "Use JumpList rows as recent-destination review leads. Final MRU, pin, account, or deleted-entry claims require "
            "dedicated parser diff and OS-version-specific DestList validation."
        ),
    }


def jumplist_core_accuracy_gates(details: dict[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), dict) else {}
    destlist_metadata = (
        details.get("destlist_metadata") if isinstance(details.get("destlist_metadata"), dict) else {}
    )
    destinations = [item for item in details.get("destinations") or [] if isinstance(item, dict)]
    trusted_diff = (
        details.get("jumplist_trusted_diff")
        if isinstance(details.get("jumplist_trusted_diff"), Mapping)
        else {}
    )
    evidence_refs = [
        f"source_path:{details.get('source_path', '')}",
        f"app_id_hash:{details.get('application_id_hash', '')}",
    ]
    if hashes.get("sha256"):
        evidence_refs.append(f"source_sha256:{hashes['sha256']}")

    satisfied: list[str] = []
    if details.get("ole_streams") or checks.get("has_ole_stream_inventory"):
        satisfied.append("CFB stream inventory")
    if destlist_metadata.get("destlist_header_candidates") or destlist_metadata.get("destlist_entry_candidates"):
        satisfied.append("DestList header/entry layout")
    if destinations and any(destination.get("stream_path") or destination.get("target_path") for destination in destinations):
        satisfied.append("embedded LNK linkage")
    if details.get("application_id_hash"):
        satisfied.append("AppID mapping provenance")
    if (destlist_metadata.get("destlist_unlinked_entry_candidate_count") or 0) or checks.get(
        "deleted_or_unlinked_entry_review_available"
    ):
        satisfied.append("deleted/unlinked entry candidate review")
    if not JUMPLIST_CAPABILITIES["destlist_deleted_entry_recovery"]:
        satisfied.append("deleted-entry warning")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted JumpList DestList diff pass")
    return [build_accuracy_gate(14, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def extract_jumplist_destinations(
    data: bytes,
    ole_streams: Sequence[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    destinations: list[dict[str, object]] = []
    if ole_streams:
        for stream in ole_streams:
            stream_data = stream.get("data")
            if not isinstance(stream_data, bytes):
                continue
            append_lnk_destinations(destinations, stream_data, stream=stream)
    if not ole_streams or not destinations:
        append_lnk_destinations(destinations, data)
    return destinations


DESTLIST_V1_FIXED_SIZE = 0x72
DESTLIST_V3_FIXED_SIZE = 0x82
DESTLIST_V3_TRAILER_SIZE = 4
DESTLIST_MAX_PATH_CHARS = 32768


def decode_destlist_hostname(raw: bytes) -> tuple[str, str]:
    """NetBIOS name (16 bytes ANSI). Korean systems write cp949 (e.g. 진료실1)."""
    value = raw.split(b"\x00", 1)[0]
    if not value:
        return "", "empty"
    try:
        return value.decode("ascii"), "ascii"
    except UnicodeDecodeError:
        pass
    for encoding in LNK_ANSI_CODEPAGES:
        try:
            return value.decode(encoding), encoding
        except (UnicodeDecodeError, LookupError):
            continue
    return value.decode("cp1252", errors="replace"), "cp1252-replace"


def parse_destlist_entries_strict(
    data: bytes,
    version: int,
    source: Mapping[str, object],
    lnk_stream_names: set[str],
) -> list[dict[str, object]] | None:
    """Decode every DestList entry with the version's documented layout.

    v1 (Windows 7/8): fixed 0x72 bytes, path length u16 at 0x70.
    v3+ (Windows 10/11): fixed 0x82 bytes (access count u32 at 0x74), path
    length u16 at 0x80, UTF-16 path, then a 4-byte trailer.
    Returns ``None`` when the stream does not follow the layout so callers can
    fall back to the legacy candidate scan (and say so).
    """
    if version == 1:
        fixed_size, trailer, layout_name = DESTLIST_V1_FIXED_SIZE, 0, "win7-win8-fixed114"
    elif version >= 2:
        fixed_size, trailer, layout_name = DESTLIST_V3_FIXED_SIZE, DESTLIST_V3_TRAILER_SIZE, "win10-plus-fixed130"
    else:
        return None
    entries: list[dict[str, object]] = []
    offset = DESTLIST_HEADER_SIZE
    while offset + fixed_size <= len(data):
        path_chars = read_u16(data, offset + fixed_size - 2)
        path_end = offset + fixed_size + path_chars * 2
        entry_end = path_end + trailer
        if path_chars > DESTLIST_MAX_PATH_CHARS or entry_end > len(data):
            return None
        raw_path = data[offset + fixed_size : path_end]
        path = raw_path.decode("utf-16le", errors="replace")
        if "\x00" in path:
            return None
        entry_number = read_u32(data, offset + 0x58)
        stream_name = f"{entry_number:x}"
        hostname, hostname_encoding = decode_destlist_hostname(data[offset + 0x48 : offset + 0x58])
        last_modified_filetime = read_u64(data, offset + 0x64)
        pin_status = struct.unpack_from("<i", data, offset + 0x6C)[0]
        entry_bytes = data[offset:entry_end]
        linked = stream_name in lnk_stream_names
        entry: dict[str, object] = {
            **source,
            "index": len(entries),
            "entry_offset": offset,
            "entry_size_candidate": entry_end - offset,
            "layout_candidate": layout_name,
            "layout_status": f"decoded-destlist-v{version}",
            "fixed_header_size_candidate": fixed_size,
            "destlist_version": version,
            "checksum_hex": f"{read_u64(data, offset):016x}",
            "volume_droid": format_guid_le(data[offset + 0x08 : offset + 0x18]),
            "file_droid": format_guid_le(data[offset + 0x18 : offset + 0x28]),
            "birth_volume_droid": format_guid_le(data[offset + 0x28 : offset + 0x38]),
            "birth_file_droid": format_guid_le(data[offset + 0x38 : offset + 0x48]),
            "file_droid_mac_address": uuid_v1_mac(data[offset + 0x18 : offset + 0x28]),
            "file_droid_timestamp": uuid_v1_time(data[offset + 0x18 : offset + 0x28]),
            "hostname": hostname,
            "hostname_encoding": hostname_encoding,
            "hostname_raw_hex": data[offset + 0x48 : offset + 0x58].split(b"\x00", 1)[0].hex(),
            "entry_number": entry_number,
            "lnk_stream_name": stream_name,
            "lnk_stream_present": linked,
            "last_modified_at": windows_filetime_to_iso(last_modified_filetime),
            "last_modified_filetime": last_modified_filetime,
            "pin_status": pin_status,
            "pinned": pin_status != -1,
            "path": path,
            "path_char_count": path_chars,
            # Legacy candidate keys kept for consumers of the v1 schema.
            "path_candidate": path,
            "path_char_count_candidate": path_chars,
            "entry_id_candidate": entry_number,
            "entry_id_candidate_offset": 0x58,
            "pin_status_candidate": pin_status,
            "pin_status_candidate_offset": 0x6C,
            "hostname_candidates": [{"offset": 0x48, "hostname_candidate": hostname}] if hostname else [],
            "filetime_candidates": (
                [{"offset": 0x64, "timestamp_candidate": windows_filetime_to_iso(last_modified_filetime)}]
                if last_modified_filetime
                else []
            ),
            "matched_lnk_stream_candidates": (
                [{"field_offset": 0x58, "field_value": entry_number, "stream_name_candidate": stream_name}] if linked else []
            ),
            "validation_status": "candidate-linked-lnk-stream" if linked else "candidate-unlinked",
            "parser_confidence": 0.9 if linked else 0.8,
            "entry_sha256": sha256_bytes(entry_bytes),
        }
        if version >= 2:
            entry["access_count"] = read_u32(data, offset + 0x74)
            entry["unknown_u32_0x70"] = read_u32(data, offset + 0x70)
            entry["trailer_hex"] = data[path_end:entry_end].hex()
        else:
            entry["access_count_float_v1"] = round(struct.unpack_from("<f", data, offset + 0x60)[0], 3)
        entries.append(entry)
        offset = entry_end
    return entries


def parse_destlist_metadata(ole_streams: Sequence[dict[str, object]]) -> dict[str, object]:
    destlist_streams = [
        stream
        for stream in ole_streams
        if str(stream.get("name") or "").lower() == "destlist" or str(stream.get("path") or "").lower().endswith("/destlist")
    ]
    if not ole_streams:
        return {
            "destlist_parse_status": "not-ole",
            "destlist_stream_count": 0,
            "destlist_streams": [],
            "destlist_header_candidates": [],
            "destlist_entry_candidate_count": 0,
            "destlist_entry_candidates": [],
            "destlist_validation_checks": {"has_destlist_stream": False, "report_grade": False},
        }
    if not destlist_streams:
        return {
            "destlist_parse_status": "not-present",
            "destlist_stream_count": 0,
            "destlist_streams": [],
            "destlist_header_candidates": [],
            "destlist_entry_candidate_count": 0,
            "destlist_entry_candidates": [],
            "destlist_validation_checks": {"has_destlist_stream": False, "report_grade": False},
        }

    lnk_stream_names = {
        str(stream.get("name") or "")
        for stream in ole_streams
        if str(stream.get("name") or "").lower() != "destlist"
    }
    stream_summaries: list[dict[str, object]] = []
    header_candidates: list[dict[str, object]] = []
    entry_candidates: list[dict[str, object]] = []
    declared_counts: list[int] = []
    layout_statuses: list[str] = []
    parse_status = "unsupported-or-empty"
    for stream in destlist_streams:
        stream_data = stream.get("data")
        if not isinstance(stream_data, bytes):
            continue
        source = destlist_stream_summary(stream, stream_data)
        stream_summaries.append(source)
        if len(stream_data) < DESTLIST_HEADER_SIZE:
            continue
        header = parse_destlist_header_candidate(stream_data, source)
        header_candidates.append(header)
        declared_count = int(header.get("declared_entry_count_candidate") or 0)
        if declared_count:
            declared_counts.append(declared_count)
        strict_entries = parse_destlist_entries_strict(
            stream_data, int(header.get("version_candidate") or 0), source, lnk_stream_names
        )
        if strict_entries is not None:
            entries = strict_entries
            layout_statuses.append(f"decoded-destlist-v{int(header.get('version_candidate') or 0)}")
        else:
            entries = parse_destlist_entry_candidates(stream_data, source, lnk_stream_names, declared_count)
            layout_statuses.append("legacy-heuristic-candidates")
        entry_candidates.extend(entries)
        if entries or header:
            parse_status = "parsed-candidate"

    validation_checks = destlist_validation_checks(
        bool(destlist_streams),
        declared_counts,
        len(entry_candidates),
        entry_candidates,
    )
    unlinked_entry_candidates = [
        candidate
        for candidate in entry_candidates
        if not candidate.get("matched_lnk_stream_candidates")
    ]
    return {
        "destlist_parse_status": parse_status,
        "destlist_stream_count": len(destlist_streams),
        "destlist_streams": stream_summaries,
        "destlist_header_candidates": header_candidates,
        "destlist_declared_entry_count_candidates": declared_counts,
        "destlist_layout_status": layout_statuses[0] if len(set(layout_statuses)) == 1 else ",".join(layout_statuses),
        "destlist_entry_candidate_count": len(entry_candidates),
        # Inline lists are capped (disclosed below); every entry is also
        # emitted as its own ``jumplist-entry`` row by the provider.
        "destlist_entry_candidates": entry_candidates[:MAX_DESTLIST_ENTRIES],
        "destlist_entry_candidates_truncated": len(entry_candidates) > MAX_DESTLIST_ENTRIES,
        "destlist_entries_all": entry_candidates,
        "destlist_unlinked_entry_candidate_count": len(unlinked_entry_candidates),
        "destlist_unlinked_entry_candidates": unlinked_entry_candidates[:MAX_DESTLIST_ENTRIES],
        "destlist_unlinked_entry_candidates_truncated": len(unlinked_entry_candidates) > MAX_DESTLIST_ENTRIES,
        "destlist_deleted_or_unlinked_entry_review_status": (
            "candidate-review-only-not-recovered"
            if unlinked_entry_candidates
            else "none-detected"
        ),
        "destlist_validation_checks": validation_checks,
    }


def destlist_stream_summary(stream: dict[str, object], stream_data: bytes) -> dict[str, object]:
    return {
        "source_stream_name": str(stream.get("name") or ""),
        "source_stream_path": str(stream.get("path") or ""),
        "source_stream_index": int(stream.get("index") or 0),
        "source_stream_size": int(stream.get("size") or len(stream_data)),
        "source_stream_start_sector": int(stream.get("start_sector") or 0),
        "source_stream_sha256": sha256_bytes(stream_data),
    }


def parse_destlist_header_candidate(data: bytes, source: dict[str, object]) -> dict[str, object]:
    return {
        **source,
        "header_size_candidate": DESTLIST_HEADER_SIZE,
        "version_candidate": read_u32(data, 0),
        "declared_entry_count_candidate": read_u32(data, 4),
        "pinned_entry_count_candidate": struct.unpack_from("<i", data, 8)[0] if len(data) >= 12 else 0,
        "last_entry_number": read_u32(data, 16),
        "last_revision_number": read_u32(data, 24),
        "unknown_header_u32_0c": read_u32(data, 12),
        "last_entry_id_candidate": read_u64(data, 16),
        "raw_header_sha256": sha256_bytes(data[:DESTLIST_HEADER_SIZE]),
    }


def parse_destlist_entry_candidates(
    data: bytes,
    source: dict[str, object],
    lnk_stream_names: set[str],
    declared_count: int,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    offset = DESTLIST_HEADER_SIZE
    limit = min(declared_count or MAX_DESTLIST_ENTRIES, MAX_DESTLIST_ENTRIES)
    while len(candidates) < limit and offset < len(data):
        candidate = best_destlist_entry_candidate(data, offset, len(candidates), source, lnk_stream_names)
        if not candidate:
            break
        candidates.append(candidate)
        next_offset = int(candidate["entry_offset"]) + int(candidate["entry_size_candidate"])
        if next_offset <= offset:
            break
        offset = next_offset
    return candidates


def best_destlist_entry_candidate(
    data: bytes,
    offset: int,
    index: int,
    source: dict[str, object],
    lnk_stream_names: set[str],
) -> dict[str, object] | None:
    layout_candidates: list[dict[str, object]] = []
    for layout_name, fixed_size in DESTLIST_ENTRY_LAYOUTS:
        if offset + fixed_size > len(data):
            continue
        path_char_count = read_u16(data, offset + fixed_size - 2)
        if path_char_count > 1024:
            continue
        end = offset + fixed_size + path_char_count * 2
        if end > len(data):
            continue
        path = decode_text(data[offset + fixed_size : end], "utf-16le")
        score = 0
        if path_char_count == 0 or path:
            score += 2
        if "\\" in path or "/" in path:
            score += 2
        matched_streams_for_layout = matched_lnk_stream_candidates(data[offset : offset + fixed_size], lnk_stream_names)
        if matched_streams_for_layout:
            score += 2
        layout_candidates.append(
            {
                "layout_candidate": layout_name,
                "fixed_header_size_candidate": fixed_size,
                "path_char_count_candidate": path_char_count,
                "path_candidate": path,
                "entry_size_candidate": end - offset,
                "layout_score": score,
                "matched_lnk_stream_candidate_count": len(matched_streams_for_layout),
            }
        )
    if not layout_candidates:
        return None
    selected_layout = sorted(
        layout_candidates,
        key=lambda item: (
            int(item["layout_score"]),
            int(item["fixed_header_size_candidate"]),
        ),
        reverse=True,
    )[0]
    layout_name = str(selected_layout["layout_candidate"])
    fixed_size = int(selected_layout["fixed_header_size_candidate"])
    path_candidate_value = str(selected_layout["path_candidate"])
    entry_size = int(selected_layout["entry_size_candidate"])
    prefix = data[offset : offset + fixed_size]
    matched_streams = matched_lnk_stream_candidates(prefix, lnk_stream_names)
    filetime_candidates = destlist_filetime_candidates(prefix)
    entry_id_candidate = read_u32(prefix, 4) if len(prefix) >= 8 else None
    pin_status_candidate = read_u32(prefix, 8) if len(prefix) >= 12 else None
    validation_status = "candidate-linked-lnk-stream" if matched_streams else "candidate-unlinked"
    citation = {
        **source,
        "entry_index": index,
        "entry_offset": offset,
        "entry_size": entry_size,
        "layout_candidate": layout_name,
        "path_candidate": path_candidate_value,
        "matched_lnk_stream_candidates": matched_streams,
        "entry_prefix_sha256": sha256_bytes(prefix),
        "entry_sha256": sha256_bytes(data[offset : offset + entry_size]),
    }
    return {
        **source,
        "index": index,
        "entry_offset": offset,
        "entry_size_candidate": entry_size,
        "layout_candidate": layout_name,
        "fixed_header_size_candidate": fixed_size,
        "layout_selection_profile": {
            "profile_version": "destlist-layout-selection-v1",
            "selected_layout": layout_name,
            "selected_layout_score": int(selected_layout["layout_score"]),
            "layout_candidates": layout_candidates,
            "selection_basis": [
                "UTF-16 path length field fits selected fixed header size",
                "path contains separator when present",
                "numeric field matches embedded LNK stream name when present",
            ],
            "os_version_semantics_validated": False,
        },
        "path_candidate": path_candidate_value,
        "path_char_count_candidate": int(selected_layout["path_char_count_candidate"]),
        "entry_id_candidate": entry_id_candidate,
        "entry_id_candidate_offset": 4,
        "pin_status_candidate": pin_status_candidate,
        "pin_status_candidate_offset": 8,
        "destlist_entry_semantics_warning": (
            "entry_id/pin_status candidates read from documented DestList fixed-header offsets; "
            "OS-version layout confirmation and JLECmd trusted diff still required before report use"
        ),
        "droid_guid_candidates": destlist_guid_candidates(prefix),
        "hostname_candidates": destlist_hostname_candidates(prefix),
        "filetime_candidates": filetime_candidates,
        "numeric_field_candidates": destlist_numeric_candidates(prefix, lnk_stream_names),
        "matched_lnk_stream_candidates": matched_streams,
        "validation_status": validation_status,
        "parser_confidence": destlist_entry_confidence(path_candidate_value, matched_streams, filetime_candidates),
        "entry_prefix_sha256": citation["entry_prefix_sha256"],
        "entry_sha256": citation["entry_sha256"],
        "destlist_entry_citation": {
            **citation,
            "citation_hash": recent_stable_sha256(citation),
            "reportability": "candidate-destlist-entry-citation",
            "commercial_blockers": [
                "destlist-os-version-specific-field-validation-required",
                "jumplist-destlist-trusted-diff-required",
            ],
        },
    }


def destlist_guid_candidates(prefix: bytes) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for offset in (0, 16, 32, 48):
        raw = prefix[offset : offset + 16]
        if len(raw) != 16 or raw == b"\x00" * 16:
            continue
        candidates.append({"offset": offset, "guid_candidate": str(uuid.UUID(bytes_le=raw))})
    return candidates


def destlist_hostname_candidates(prefix: bytes) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for offset in (64, 72, 80):
        raw = prefix[offset : offset + 16]
        text = decode_text(raw, "utf-16le")
        if 2 <= len(text) <= 15 and re.fullmatch(r"[A-Za-z0-9_.-]+", text):
            candidates.append({"offset": offset, "hostname_candidate": text})
    return candidates


def destlist_filetime_candidates(prefix: bytes) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for offset in range(0, max(0, len(prefix) - 7), 4):
        value = read_u64(prefix, offset)
        timestamp = plausible_filetime_to_iso(value)
        if timestamp:
            candidates.append({"offset": offset, "timestamp_candidate": timestamp})
        if len(candidates) >= MAX_DESTLIST_CANDIDATE_TIMES:
            break
    return candidates


def destlist_numeric_candidates(prefix: bytes, lnk_stream_names: set[str]) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for offset in range(0, len(prefix) - 3, 4):
        value = read_u32(prefix, offset)
        if value == 0 or value > 10_000_000:
            continue
        item: dict[str, object] = {"offset": offset, "u32_candidate": value}
        if str(value) in lnk_stream_names:
            item["matches_lnk_stream_name"] = str(value)
        candidates.append(item)
        if len(candidates) >= MAX_DESTLIST_NUMERIC_CANDIDATES:
            break
    return candidates


def matched_lnk_stream_candidates(prefix: bytes, lnk_stream_names: set[str]) -> list[dict[str, object]]:
    matches: list[dict[str, object]] = []
    for offset in range(0, len(prefix) - 3, 4):
        value = read_u32(prefix, offset)
        stream_name = str(value)
        if stream_name in lnk_stream_names:
            matches.append({"field_offset": offset, "field_value": value, "stream_name_candidate": stream_name})
    return matches


def destlist_entry_confidence(
    path: str,
    matched_streams: Sequence[dict[str, object]],
    filetime_candidates: Sequence[dict[str, object]],
) -> float:
    confidence = 0.42
    if path:
        confidence += 0.08
    if matched_streams:
        confidence += 0.16
    if filetime_candidates:
        confidence += 0.08
    return min(confidence, 0.74)


def destlist_validation_checks(
    has_destlist_stream: bool,
    declared_counts: Sequence[int],
    entry_candidate_count: int,
    entry_candidates: Sequence[dict[str, object]],
) -> dict[str, object]:
    linked_count = sum(1 for entry in entry_candidates if entry.get("matched_lnk_stream_candidates"))
    declared_total = max(declared_counts) if declared_counts else 0
    return {
        "has_destlist_stream": has_destlist_stream,
        "declared_entry_count_max": declared_total,
        "entry_candidate_count": entry_candidate_count,
        "declared_count_matches_candidates": bool(declared_total and declared_total == entry_candidate_count),
        "linked_lnk_stream_candidate_count": linked_count,
        "unlinked_destlist_entry_candidate_count": max(entry_candidate_count - linked_count, 0),
        "deleted_or_unlinked_entry_review_available": entry_candidate_count > linked_count,
        "all_candidates_link_to_lnk_stream": bool(entry_candidate_count and linked_count == entry_candidate_count),
        "account_metadata_report_grade": False,
        "deleted_entry_recovery_available": False,
        "report_grade": False,
    }


def enrich_destinations_with_destlist_candidates(
    destinations: list[dict[str, object]],
    destlist_candidates: object,
) -> None:
    if not isinstance(destlist_candidates, list):
        return
    by_stream: dict[str, list[dict[str, object]]] = {}
    for candidate in destlist_candidates:
        if not isinstance(candidate, dict):
            continue
        for match in candidate.get("matched_lnk_stream_candidates", []):
            if not isinstance(match, dict):
                continue
            stream_name = str(match.get("stream_name_candidate") or "")
            if stream_name:
                by_stream.setdefault(stream_name, []).append(candidate)
    for destination in destinations:
        stream_name = str(destination.get("stream_name") or "")
        matches = by_stream.get(stream_name, [])
        if not matches:
            continue
        match = matches[0]
        destination.update(
            {
                "destlist_entry_index_candidate": match.get("index"),
                "destlist_entry_offset_candidate": match.get("entry_offset"),
                "destlist_path_candidate": match.get("path_candidate", ""),
                "destlist_hostname_candidates": match.get("hostname_candidates", []),
                "destlist_filetime_candidates": match.get("filetime_candidates", []),
                "destlist_validation_status": match.get("validation_status", ""),
                "destlist_layout_candidate": match.get("layout_candidate", ""),
                "destlist_entry_citation": match.get("destlist_entry_citation", {}),
            }
        )


def jumplist_validation_checks(
    data: bytes,
    ole_streams: Sequence[dict[str, object]],
    destinations: Sequence[dict[str, object]],
    destlist_metadata: dict[str, object],
) -> dict[str, object]:
    destlist_checks = destlist_metadata.get("destlist_validation_checks")
    return {
        "is_ole_compound": data.startswith(CFB_SIGNATURE),
        "ole_streams_recovered": len(ole_streams),
        "embedded_lnk_destinations_recovered": len(destinations),
        "has_destlist_stream": bool(destlist_checks.get("has_destlist_stream")) if isinstance(destlist_checks, dict) else False,
        "destlist_candidate_decoding_available": destlist_metadata.get("destlist_parse_status") == "parsed-candidate",
        "destlist_report_grade": False,
        "requires_external_validation": True,
    }


def recent_validation_matrix(checks: dict[str, object]) -> list[dict[str, object]]:
    labels = {
        "has_valid_header": ("LNK valid header", "critical"),
        "has_target_path": ("Target path", "high"),
        "has_timestamps": ("LNK timestamps", "medium"),
        "has_link_info": ("LinkInfo", "medium"),
        "has_shell_item_idlist": ("Shell item IDList", "medium"),
        "has_tracker_data": ("TrackerDataBlock", "medium"),
        "has_property_store_data_block": ("PropertyStoreDataBlock candidate provenance", "medium"),
        "full_property_store_decode_available": ("Full property store decode", "critical"),
        "is_ole_compound": ("OLE compound file", "high"),
        "ole_streams_recovered": ("OLE streams recovered", "medium"),
        "embedded_lnk_destinations_recovered": ("Embedded LNK destinations", "high"),
        "has_destlist_stream": ("DestList stream", "high"),
        "destlist_candidate_decoding_available": ("DestList candidate decoding", "medium"),
        "unlinked_destlist_entry_candidate_count": ("Unlinked DestList entry candidates", "medium"),
        "deleted_or_unlinked_entry_review_available": ("Deleted/unlinked entry review candidates", "medium"),
        "destlist_report_grade": ("DestList report-grade decode", "critical"),
        "requires_external_validation": ("External validation", "critical"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key in {
            "extra_data_block_count",
            "unlinked_destlist_entry_candidate_count",
            "deleted_or_unlinked_entry_review_available",
        }:
            continue
        label, severity = labels.get(key, (key.replace("_", " "), "medium"))
        negative_requirement = key.startswith("requires_")
        passed = bool(value)
        if isinstance(value, int):
            passed = value > 0
        if negative_requirement:
            passed = not bool(value)
        matrix.append({"id": key.replace("_", "-"), "label": label, "passed": passed, "severity": severity, "detail": value})
    return matrix


def recent_report_grade_assessment(
    validation_matrix: list[dict[str, object]],
    *,
    validation_required: bool,
    gap_ids: list[str],
    blockers: Sequence[str],
) -> dict[str, object]:
    failed = [str(item.get("id")) for item in validation_matrix if not item.get("passed")]
    all_blockers = set(blockers)
    all_blockers.update(f"validation-check-failed:{item}" for item in failed)
    if validation_required:
        all_blockers.add("recent-files-validation-required")
    return {
        "report_grade_ready": False,
        "status": "validation-required" if failed else "triage-validated-report-grade-blocked",
        "blockers": sorted(all_blockers),
        "validated_strengths": [str(item.get("id")) for item in validation_matrix if item.get("passed")],
        "commercial_gap_ids": gap_ids,
        "next_validation_step": "Validate JumpList DestList semantics, deleted entries, account context, and Shell Link property stores with known-answer corpus before report-grade use.",
    }


def lnk_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("recent_validation_matrix") if isinstance(details.get("recent_validation_matrix"), list) else []
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("lnk_trusted_diff")
        if isinstance(details.get("lnk_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    target_context_profile = (
        details.get("lnk_target_context_citation_profile")
        if isinstance(details.get("lnk_target_context_citation_profile"), Mapping)
        else {}
    )
    reportability_decision = lnk_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-016-020",
        "item_numbers": [17],
        "qc_prep_item_numbers": [QC_PREP_LNK_ITEM],
        "qc_prep_contracts": [dict(QC_PREP_LNK_CONTRACT)],
        "implementation_track": "native-parser-depth",
        "objective": "Expose Shell Link header, LinkInfo/StringData/ExtraData validation and remaining property-store blockers.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"target_path:{details.get('target_path', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
            f"target_context_profile_sha256:{target_context_profile.get('profile_sha256', '')}",
        ],
        "implemented_controls": {
            "target_context_citation_profile_present": bool(target_context_profile),
            "target_context_citation_profile_hash": str(target_context_profile.get("profile_sha256") or ""),
            "field_source_count": len(target_context_profile.get("field_sources") or []),
            "extra_data_bound_count": len(target_context_profile.get("extra_data_bounds") or []),
        },
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": reportability_decision,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "lnk_trusted_diff": trusted_diff,
        "large_data_controls": {
            "bounded_extra_data_blocks": True,
            "max_extra_data_blocks": MAX_LNK_EXTRA_DATA_BLOCKS,
            "max_shell_items": MAX_LNK_SHELL_ITEMS,
            "target_context_citation_profile_present": bool(target_context_profile),
            "target_context_citation_profile_hash": str(target_context_profile.get("profile_sha256") or ""),
            "property_store_decode_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish Shell Item property store semantics and tracker/LinkInfo known-answer corpus validation.",
        "external_evidence_required": True,
    }


def lnk_reportability_decision(
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("lnk-shell-item-property-store-validation-required")
    blockers.add("lnk-tracker-and-linkinfo-cross-tool-diff-required")
    blockers.add("lnk-trusted-parser-diff-required")
    return {
        "profile_version": "lnk-reportability-decision-v1",
        "commercial_gap_id": "#17",
        "qc_prep_item_number": QC_PREP_LNK_ITEM,
        "qc_prep_item_goal": QC_PREP_LNK_GOAL,
        "qc_prep_contract": dict(QC_PREP_LNK_CONTRACT),
        "decision": "do-not-report-target-context-as-complete",
        "allowed_use": "shortcut-target-and-metadata-triage-pivot",
        "blockers": sorted(blockers),
        "required_before_report": [
            "Shell Item and property-store semantics validated",
            "LinkInfo drive/network provider fields decoded and diffed",
            "Tracker GUID and machine ID semantics verified",
            "LECmd or known-answer corpus attached for critical shortcuts",
        ],
    }


def jumplist_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("recent_validation_matrix") if isinstance(details.get("recent_validation_matrix"), list) else []
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    trusted_diff = (
        details.get("jumplist_trusted_diff")
        if isinstance(details.get("jumplist_trusted_diff"), Mapping)
        else {"status": "not-attached"}
    )
    reportability_decision = jumplist_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-011-015",
        "item_numbers": [14],
        "qc_prep_item_numbers": [QC_PREP_JUMPLIST_ITEM],
        "implementation_track": "native-parser-depth",
        "objective": "Expose JumpList DestList validation, OLE/LNK provenance, deleted-entry blockers, and AppID gaps for #14 / QC-prep #29.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
            f"app_id_hash:{details.get('application_id_hash', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "reportability_decision": reportability_decision,
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "jumplist_trusted_diff": trusted_diff,
        "large_data_controls": {
            "bounded_ole_stream_inventory": True,
            "ole_stream_count": int(details.get("ole_stream_count") or 0),
            "destination_count": int(details.get("destination_count") or 0),
            "destlist_parse_status": str(details.get("destlist_parse_status") or ""),
            "deleted_entry_recovery_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish OS-version DestList field validation, deleted-entry recovery, and AppID mapping corpus checks.",
        "external_evidence_required": True,
    }


def jumplist_reportability_decision(
    report_grade: Mapping[str, object],
    details: Mapping[str, object],
) -> dict[str, object]:
    blockers = set(str(item) for item in report_grade.get("blockers") or [])
    blockers.add("jumplist-destlist-version-semantics-validation-required")
    blockers.add("jumplist-deleted-entry-recovery-validation-required")
    blockers.add("jumplist-destlist-trusted-diff-required")
    return {
        "profile_version": "jumplist-reportability-decision-v1",
        "commercial_gap_id": "#14",
        "qc_prep_item_number": QC_PREP_JUMPLIST_ITEM,
        "decision": "do-not-report-destlist-semantics-as-final",
        "allowed_use": "recent-destination-triage-pivot",
        "blockers": sorted(blockers),
        "source_location_available": bool(details.get("application_id_hash") or details.get("source_hashes")),
        "required_before_report": [
            "DestList OS-version field semantics validated",
            "AppID hash mapping database attached",
            "deleted entry recovery or explicit limitation documented",
            "embedded LNK stream and DestList entry cross-tool diff attached",
        ],
    }


def jumplist_parser_confidence(destinations: Sequence[dict[str, object]], destlist_metadata: dict[str, object]) -> float:
    confidence = 0.45
    if destinations:
        confidence += 0.2
    if destlist_metadata.get("destlist_parse_status") == "parsed-candidate":
        confidence += 0.1
    return min(confidence, 0.78)


def jumplist_commercial_blockers(destlist_metadata: dict[str, object]) -> list[str]:
    blockers = list(JUMPLIST_COMMERCIAL_BLOCKERS)
    if destlist_metadata.get("destlist_parse_status") != "parsed-candidate":
        blockers.insert(0, "destlist-stream-not-present-or-unrecoverable")
    return blockers


def build_jumplist_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_jumplist_diff_payload(
        index_jumplist_rows(rapid_rows),
        index_jumplist_rows(trusted_rows),
        trusted_tool=trusted_tool,
    )


def build_lnk_trusted_diff(
    rapid_rows: Sequence[Mapping[str, object]],
    trusted_rows: Sequence[Mapping[str, object]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    return build_lnk_diff_payload(index_lnk_rows(rapid_rows), index_lnk_rows(trusted_rows), trusted_tool=trusted_tool)


def index_lnk_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        payload = lnk_diff_row_payload(row)
        link_info = payload.get("link_info") if isinstance(payload.get("link_info"), Mapping) else {}
        tracker = payload.get("tracker_data") if isinstance(payload.get("tracker_data"), Mapping) else {}
        property_store_blocks = payload.get("property_store_blocks")
        first_property_store = (
            property_store_blocks[0]
            if isinstance(property_store_blocks, Sequence)
            and not isinstance(property_store_blocks, (str, bytes, bytearray))
            and property_store_blocks
            and isinstance(property_store_blocks[0], Mapping)
            else {}
        )

        target = normalized_diff_value(
            first_alias(payload, "target_path", "target", "local_base_path", "path", "targetpath")
            or first_alias(link_info, "local_base_path", "local_base_path_unicode", "common_path_suffix")
        )
        working_dir = normalized_diff_value(first_alias(payload, "working_dir", "working_directory"))
        arguments = normalized_diff_value(first_alias(payload, "command_line_arguments", "arguments", "commandlinearguments"))
        key = target or normalized_diff_value(first_alias(payload, "source_path", "entry_name", "filename"))
        if not key:
            continue
        indexed[key] = {
            "target_path": target,
            "working_dir": working_dir,
            "arguments": arguments,
            "created": normalized_diff_value(first_alias(payload, "target_created_at", "created", "creation_time", "creationtime")),
            "accessed": normalized_diff_value(first_alias(payload, "target_accessed_at", "accessed", "accessed_time", "accesstime")),
            "modified": normalized_diff_value(first_alias(payload, "target_modified_at", "modified", "modified_time", "modifiedtime")),
            "description": normalized_diff_value(first_alias(payload, "description", "name")),
            "relative_path": normalized_diff_value(first_alias(payload, "relative_path", "relativepath")),
            "icon_location": normalized_diff_value(first_alias(payload, "icon_location", "iconlocation")),
            "link_flags": normalized_diff_list(first_alias(payload, "link_flag_names", "link_flags", "flags")),
            "file_attributes": normalized_diff_list(first_alias(payload, "file_attribute_names", "file_attributes", "attributes")),
            "target_file_size": normalized_int_text(first_alias(payload, "target_file_size", "file_size", "filesize")),
            "show_command": normalized_int_text(first_alias(payload, "show_command", "showcommand")),
            "hot_key": normalized_int_text(first_alias(payload, "hot_key", "hotkey")),
            "link_info_local_base_path": normalized_diff_value(
                first_alias(link_info, "local_base_path", "localbasepath")
                or first_alias(payload, "local_base_path", "localbasepath")
            ),
            "link_info_common_path_suffix": normalized_diff_value(
                first_alias(link_info, "common_path_suffix", "commonpathsuffix")
                or first_alias(payload, "common_path_suffix", "commonpathsuffix")
            ),
            "tracker_machine": normalized_diff_value(
                first_alias(payload, "machine_id", "tracker_machine_id")
                or first_alias(tracker, "machine_id", "tracker_machine_id")
            ),
            "tracker_droid_file": normalized_diff_value(
                first_alias(payload, "droid_file_identifier")
                or first_alias(tracker, "droid_file_identifier", "droid_file")
            ),
            "tracker_birth_droid_file": normalized_diff_value(
                first_alias(payload, "birth_droid_file_identifier")
                or first_alias(tracker, "birth_droid_file_identifier", "birth_droid_file")
            ),
            "property_store_paths": normalized_diff_list(
                first_alias(payload, "property_store_paths", "property_store_embedded_paths")
                or first_alias(first_property_store, "embedded_paths", "path")
            ),
            "property_store_strings": normalized_diff_list(
                first_alias(payload, "property_store_strings", "string_candidates")
                or first_alias(first_property_store, "string_candidates", "strings")
            ),
        }
    return indexed


def lnk_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def build_lnk_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in LNK_TRUSTED_TOOLS
    }
    common = sorted(set(rapid_index) & set(trusted_index))
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in common:
        for field, rapid_value in rapid_index[key].items():
            trusted_value = trusted_index[key].get(field, "")
            if rapid_value and trusted_value and rapid_value != trusted_value:
                mismatches.append({"lnk_key": key, "field": field, "rapid_value": rapid_value, "trusted_value": trusted_value})
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "lnk-trusted-parser-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-lnk-output-as-final",
            "blockers": [] if status == "pass" else ["lnk-trusted-parser-diff-required"],
        },
    }


def index_jumplist_rows(rows: Sequence[Mapping[str, object]]) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        for candidate in jumplist_diff_candidate_rows(row):
            app_id = normalized_diff_value(first_alias(candidate, "application_id_hash", "appid", "app_id", "application_id"))
            entry_id = normalized_int_text(
                first_alias(
                    candidate,
                    "entry_id",
                    "entry_number",
                    "destlist_entry_id",
                    "destlist_entry_index_candidate",
                    "stream_path",
                    "entrynumber",
                    "index",
                )
            )
            target_path = normalized_diff_value(
                first_alias(candidate, "target_path", "destlist_path_candidate", "path_candidate", "path", "file_path", "filename")
            )
            stream_path = normalized_diff_value(first_alias(candidate, "stream_path", "stream", "lnk_stream", "stream_name"))
            entry_offset = normalized_int_text(
                first_alias(candidate, "destlist_entry_offset_candidate", "entry_offset", "destlist_entry_offset", "offset")
            )
            key = jumplist_diff_key(app_id=app_id, entry_id=entry_id, target_path=target_path, stream_path=stream_path, entry_offset=entry_offset)
            if not key:
                continue
            indexed[key] = {
                "application_id_hash": app_id,
                "entry_id": entry_id,
                "stream_path": stream_path,
                "target_path": target_path,
                "timestamp": normalized_diff_value(
                    first_alias(
                        candidate,
                        "timestamp",
                        "last_modified",
                        "last_accessed",
                        "accessed_at",
                        "last_access_time",
                        "lastaccesstime",
                    )
                ),
                "mru": normalized_diff_value(first_alias(candidate, "mru", "rank", "pin_status", "pinned")),
                "entry_offset": entry_offset,
                "hostname": normalized_diff_list(
                    first_alias(candidate, "hostname", "host_name", "machine_id", "destlist_hostname_candidates", "hostname_candidates")
                ),
                "validation_status": normalized_diff_value(
                    first_alias(candidate, "destlist_validation_status", "validation_status", "entry_validation_status")
                ),
            }
    return indexed


def jumplist_diff_candidate_rows(row: Mapping[str, object]) -> list[Mapping[str, object]]:
    payload = jumplist_diff_row_payload(row)
    candidates: list[Mapping[str, object]] = []
    destinations = payload.get("destinations")
    if isinstance(destinations, Sequence) and not isinstance(destinations, (str, bytes, bytearray)):
        for destination in destinations:
            if isinstance(destination, Mapping):
                candidates.append(merge_jumplist_candidate(payload, destination))
    destlist_metadata = payload.get("destlist_metadata") if isinstance(payload.get("destlist_metadata"), Mapping) else payload
    entry_candidates = destlist_metadata.get("destlist_entry_candidates") if isinstance(destlist_metadata, Mapping) else None
    if isinstance(entry_candidates, Sequence) and not isinstance(entry_candidates, (str, bytes, bytearray)):
        for entry in entry_candidates:
            if isinstance(entry, Mapping):
                candidates.append(merge_jumplist_candidate(payload, entry))
    return candidates or [payload]


def jumplist_diff_row_payload(row: Mapping[str, object]) -> Mapping[str, object]:
    details = row.get("details")
    if not isinstance(details, Mapping):
        return row
    payload = dict(details)
    for key, value in row.items():
        if key == "details":
            continue
        payload.setdefault(key, value)
    return payload


def merge_jumplist_candidate(parent: Mapping[str, object], child: Mapping[str, object]) -> Mapping[str, object]:
    merged = dict(parent)
    merged.update(child)
    merged.setdefault("application_id_hash", parent.get("application_id_hash", ""))
    merged.setdefault("entry_id", child.get("destlist_entry_index_candidate", child.get("index", "")))
    merged.setdefault("entry_offset", child.get("destlist_entry_offset_candidate", child.get("entry_offset", "")))
    merged.setdefault("target_path", child.get("target_path", child.get("destlist_path_candidate", child.get("path_candidate", ""))))
    return merged


def jumplist_diff_key(*, app_id: str, entry_id: str, target_path: str, stream_path: str, entry_offset: str) -> str:
    if app_id and entry_id and target_path:
        return f"{app_id}|{entry_id}|{target_path}"
    if app_id and stream_path and target_path:
        return f"{app_id}|{stream_path}|{target_path}"
    if app_id and entry_offset and target_path:
        return f"{app_id}|{entry_offset}|{target_path}"
    return "|".join(item for item in (app_id, entry_id, stream_path, target_path, entry_offset) if item)


def build_jumplist_diff_payload(
    rapid_index: Mapping[str, Mapping[str, str]],
    trusted_index: Mapping[str, Mapping[str, str]],
    *,
    trusted_tool: str,
) -> dict[str, object]:
    recognized = trusted_tool.strip().lower().replace(" ", "") in {
        item.replace(" ", "").lower() for item in JUMPLIST_TRUSTED_TOOLS
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
                        "destlist_key": key,
                        "field": field,
                        "rapid_value": rapid_value,
                        "trusted_value": trusted_value,
                    }
                )
                break
    status = "pass" if recognized and common and not missing and not extra and not mismatches else "diffs-present"
    return {
        "mode": "jumplist-destlist-trusted-diff-v1",
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
            "decision": "trusted-diff-passed" if status == "pass" else "do-not-use-destlist-output-as-final",
            "blockers": [] if status == "pass" else ["jumplist-destlist-trusted-diff-required"],
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


def normalized_diff_list(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        parts = [part.strip() for part in re.split(r"[,;|]", value) if part.strip()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        parts = [normalize_jumplist_list_item(item) for item in value]
    else:
        parts = [str(value).strip()]
    return "|".join(sorted({normalized_diff_value(part) for part in parts if part}))


def normalize_jumplist_list_item(value: object) -> str:
    if isinstance(value, Mapping):
        return str(
            first_alias(
                value,
                "hostname_candidate",
                "hostname",
                "machine_id",
                "path",
                "embedded_path",
                "string",
                "string_candidate",
                "guid",
                "value",
                "name",
            )
            or ""
        ).strip()
    return str(value).strip()


def append_lnk_destinations(
    destinations: list[dict[str, object]],
    data: bytes,
    stream: dict[str, object] | None = None,
) -> None:
    seen = {
        (
            str(destination.get("stream_path") or ""),
            int(destination.get("lnk_offset") or 0),
            str(destination.get("target_path") or ""),
        )
        for destination in destinations
    }
    for offset in find_lnk_offsets(data):
        metadata = parse_lnk_metadata_from_bytes(data[offset:])
        if metadata.get("lnk_parse_status") != "parsed":
            continue
        target_path = str(metadata.get("target_path") or "")
        embedded_paths = [str(value) for value in metadata.get("embedded_paths", []) if value]
        stream_path = str(stream.get("path") or "") if stream else ""
        dedupe_key = (stream_path, offset, target_path)
        if dedupe_key in seen:
            continue
        destination = {
            "index": len(destinations),
            "lnk_offset": offset,
            "target_path": target_path,
            "embedded_paths": embedded_paths,
            "target_created_at": metadata.get("target_created_at", ""),
            "target_accessed_at": metadata.get("target_accessed_at", ""),
            "target_modified_at": metadata.get("target_modified_at", ""),
            "working_dir": metadata.get("working_dir", ""),
            "command_line_arguments": metadata.get("command_line_arguments", ""),
            "link_flag_names": metadata.get("link_flag_names", []),
            "has_tracker_data": bool(metadata.get("tracker_data")),
            "extra_data_block_count": len(metadata.get("extra_data_blocks", [])),
            "target_file_size": metadata.get("target_file_size", 0),
            "volume_serial_number": metadata.get("volume_serial_number", ""),
            "drive_type_name": metadata.get("drive_type_name", ""),
            "volume_label": metadata.get("volume_label", ""),
            "net_name": metadata.get("net_name", ""),
            "tracker_machine_id": metadata.get("tracker_machine_id", ""),
        }
        if stream:
            destination.update(
                {
                    "stream_name": str(stream.get("name") or ""),
                    "stream_path": stream_path,
                    "stream_size": int(stream.get("size") or 0),
                    "stream_index": int(stream.get("index") or 0),
                    "stream_start_sector": int(stream.get("start_sector") or 0),
                    "stream_sha256": str(stream.get("sha256") or ""),
                }
            )
        else:
            destination.update({"stream_name": "container-scan", "stream_path": "", "stream_sha256": sha256_bytes(data)})
        destinations.append(destination)
        seen.add(dedupe_key)


def parse_ole_compound_streams(data: bytes) -> list[dict[str, object]]:
    if len(data) < 512 or not data.startswith(CFB_SIGNATURE):
        return []
    sector_size = 1 << read_u16(data, 0x1E)
    mini_sector_size = 1 << read_u16(data, 0x20)
    if sector_size not in (512, 4096) or mini_sector_size != 64:
        return []
    directory_start = read_u32(data, 0x30)
    mini_cutoff_size = read_u32(data, 0x38) or 4096
    mini_fat_start = read_u32(data, 0x3C)
    difat_entries = [
        read_u32(data, 0x4C + index * 4)
        for index in range(109)
        if read_u32(data, 0x4C + index * 4) not in (CFB_FREESECT, CFB_ENDOFCHAIN)
    ]
    # Extended DIFAT chain (files with more than 109 FAT sectors).
    difat_sector = read_u32(data, 0x44)
    visited_difat: set[int] = set()
    while difat_sector not in (CFB_FREESECT, CFB_ENDOFCHAIN) and difat_sector not in visited_difat:
        visited_difat.add(difat_sector)
        sector = cfb_sector(data, sector_size, difat_sector)
        if not sector:
            break
        for offset in range(0, sector_size - 4, 4):
            value = read_u32(sector, offset)
            if value not in (CFB_FREESECT, CFB_ENDOFCHAIN):
                difat_entries.append(value)
        difat_sector = read_u32(sector, sector_size - 4)
    fat = build_cfb_fat(data, sector_size, difat_entries)
    if not fat:
        return []
    directory_data = read_cfb_chain(data, fat, directory_start, sector_size, MAX_OLE_STREAM_BYTES)
    entries = parse_cfb_directory_entries(directory_data)
    if not entries:
        return []
    root = next((entry for entry in entries if entry["type"] == 5), entries[0])
    mini_fat_data = read_cfb_chain(data, fat, mini_fat_start, sector_size, MAX_OLE_STREAM_BYTES)
    mini_fat = [read_u32(mini_fat_data, offset) for offset in range(0, len(mini_fat_data), 4)]
    mini_stream = read_cfb_chain(data, fat, int(root["start_sector"]), sector_size, MAX_OLE_STREAM_BYTES)

    streams: list[dict[str, object]] = []
    for entry_index, path_parts in walk_cfb_directory(entries, int(root.get("child_id", CFB_ENDOFCHAIN)), ()):
        entry = entries[entry_index]
        if entry["type"] != 2:
            continue
        size = int(entry["size"])
        if size < mini_cutoff_size and mini_stream and mini_fat:
            stream_data = read_cfb_mini_chain(mini_stream, mini_fat, int(entry["start_sector"]), mini_sector_size, size)
            if not stream_data and int(entry["start_sector"]) < len(fat):
                stream_data = read_cfb_chain(data, fat, int(entry["start_sector"]), sector_size, min(size, MAX_OLE_STREAM_BYTES))[:size]
        else:
            stream_data = read_cfb_chain(data, fat, int(entry["start_sector"]), sector_size, min(size, MAX_OLE_STREAM_BYTES))[:size]
        streams.append(
            {
                "index": entry_index,
                "name": str(entry["name"]),
                "path": "/".join(path_parts),
                "size": size,
                "start_sector": int(entry["start_sector"]),
                "data": stream_data,
                "sha256": sha256_bytes(stream_data),
            }
        )
    return streams


def build_cfb_fat(data: bytes, sector_size: int, fat_sector_ids: Sequence[int]) -> list[int]:
    fat: list[int] = []
    for sector_id in fat_sector_ids:
        sector = cfb_sector(data, sector_size, sector_id)
        if not sector:
            continue
        fat.extend(read_u32(sector, offset) for offset in range(0, len(sector), 4))
    return fat


def read_cfb_chain(data: bytes, fat: Sequence[int], start_sector: int, sector_size: int, limit: int) -> bytes:
    if start_sector in (CFB_FREESECT, CFB_ENDOFCHAIN) or start_sector >= len(fat):
        return b""
    chunks: list[bytes] = []
    seen: set[int] = set()
    sector_id = start_sector
    remaining = limit
    while sector_id not in (CFB_FREESECT, CFB_ENDOFCHAIN) and sector_id < len(fat) and sector_id not in seen and remaining > 0:
        seen.add(sector_id)
        chunk = cfb_sector(data, sector_size, sector_id)
        if not chunk:
            break
        chunks.append(chunk[:remaining])
        remaining -= len(chunk)
        sector_id = fat[sector_id]
    return b"".join(chunks)


def read_cfb_mini_chain(
    mini_stream: bytes,
    mini_fat: Sequence[int],
    start_sector: int,
    mini_sector_size: int,
    size: int,
) -> bytes:
    if start_sector in (CFB_FREESECT, CFB_ENDOFCHAIN) or start_sector >= len(mini_fat):
        return b""
    chunks: list[bytes] = []
    seen: set[int] = set()
    sector_id = start_sector
    while sector_id not in (CFB_FREESECT, CFB_ENDOFCHAIN) and sector_id < len(mini_fat) and sector_id not in seen:
        seen.add(sector_id)
        start = sector_id * mini_sector_size
        chunks.append(mini_stream[start : start + mini_sector_size])
        sector_id = mini_fat[sector_id]
        if sum(len(chunk) for chunk in chunks) >= size:
            break
    return b"".join(chunks)[:size]


def parse_cfb_directory_entries(directory_data: bytes) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for offset in range(0, len(directory_data), 128):
        entry = directory_data[offset : offset + 128]
        if len(entry) < 128:
            break
        name_len = read_u16(entry, 64)
        object_type = entry[66]
        if object_type not in (1, 2, 5) or name_len < 2:
            # Keep unused slots so list indices stay equal to directory
            # entry IDs (sibling/child links are IDs, not list positions).
            entries.append(
                {"name": "", "type": 0, "left_id": CFB_FREESECT, "right_id": CFB_FREESECT,
                 "child_id": CFB_FREESECT, "start_sector": CFB_ENDOFCHAIN, "size": 0}
            )
            continue
        raw_name = entry[: min(64, name_len - 2)]
        entries.append(
            {
                "name": decode_text(raw_name, "utf-16le"),
                "type": object_type,
                "left_id": read_u32(entry, 68),
                "right_id": read_u32(entry, 72),
                "child_id": read_u32(entry, 76),
                "start_sector": read_u32(entry, 116),
                "size": read_u64(entry, 120),
            }
        )
    return entries


def walk_cfb_directory(
    entries: Sequence[dict[str, object]],
    entry_id: int,
    parent_path: tuple[str, ...],
    seen: set[int] | None = None,
) -> Iterable[tuple[int, tuple[str, ...]]]:
    if seen is None:
        seen = set()
    if entry_id in (CFB_FREESECT, CFB_ENDOFCHAIN) or entry_id >= len(entries) or entry_id in seen:
        return
    seen.add(entry_id)
    entry = entries[entry_id]
    yield from walk_cfb_directory(entries, int(entry["left_id"]), parent_path, seen)
    name = str(entry["name"])
    current_path = (*parent_path, name)
    yield entry_id, current_path
    if entry["type"] == 1:
        yield from walk_cfb_directory(entries, int(entry["child_id"]), current_path, seen)
    yield from walk_cfb_directory(entries, int(entry["right_id"]), parent_path, seen)


def cfb_sector(data: bytes, sector_size: int, sector_id: int) -> bytes:
    start = 512 + sector_id * sector_size
    if sector_id < 0 or start >= len(data):
        return b""
    # A short final sector is returned as-is: Jump Lists are commonly written
    # (and acquired) without padding the last sector to the sector size.
    return data[start : start + sector_size]


def find_lnk_offsets(data: bytes) -> Iterable[int]:
    offset = 0
    while True:
        offset = data.find(b"\x4c\x00\x00\x00" + LNK_CLSID, offset)
        if offset < 0:
            return
        yield offset
        offset += 1


def read_lnk_counted_string(data: bytes, offset: int, is_unicode: bool) -> tuple[str, int]:
    if offset + 2 > len(data):
        return "", len(data)
    char_count = read_u16(data, offset)
    offset += 2
    byte_count = char_count * 2 if is_unicode else char_count
    raw = data[offset : offset + byte_count]
    if is_unicode:
        return decode_text(raw, "utf-16le"), min(len(data), offset + byte_count)
    return decode_lnk_ansi(raw), min(len(data), offset + byte_count)


def extract_windows_paths(data: bytes) -> list[str]:
    paths = {decode_lnk_ansi(match.group(0)).rstrip("\\") for match in WINDOWS_PATH_RE.finditer(data)}
    for match in UTF16_WINDOWS_PATH_RE.finditer(data):
        text = decode_text(match.group(0), "utf-16le").rstrip("\x00\\")
        if len(text) >= 4:
            paths.add(text)
    return sorted(item for item in paths if item)


def read_c_string(data: bytes, offset: int, encoding: str) -> str:
    if offset <= 0 or offset >= len(data):
        return ""
    step = 2 if encoding == "utf-16le" else 1
    end = offset
    terminator = b"\x00\x00" if step == 2 else b"\x00"
    while end + step <= len(data):
        if data[end : end + step] == terminator:
            break
        end += step
    if encoding == "lnk-ansi":
        return decode_lnk_ansi(data[offset:end])
    return decode_text(data[offset:end], encoding)


def decode_lnk_ansi(data: bytes) -> str:
    # MS-SHLLINK ANSI strings use the *writer's* system codepage. The evidence
    # codepage is tried first (Korean cp949 for this tool's casework), then the
    # analysis host's ANSI codepage, then cp1252, so results do not depend on
    # the analyst workstation locale.
    raw = data.strip(b"\x00")
    try:
        return raw.decode("ascii").strip("\x00\r\n\t ")
    except UnicodeDecodeError:
        pass
    for encoding in (*LNK_ANSI_CODEPAGES, "mbcs" if os.name == "nt" else "cp1252"):
        try:
            return raw.decode(encoding).strip("\x00\r\n\t ")
        except (UnicodeDecodeError, LookupError):
            continue
    return decode_text(raw, "cp1252")


LNK_ANSI_CODEPAGES = ("cp949",)


def decode_text(data: bytes, encoding: str) -> str:
    return data.decode(encoding, errors="ignore").strip("\x00\r\n\t ")


def first_non_empty(*values: object) -> str:
    for value in values:
        text = str(value or "")
        if text:
            return text
    return ""


def flag_names(value: int, names: dict[int, str]) -> list[str]:
    return [name for flag, name in names.items() if value & flag]


def format_guid_le(data: bytes) -> str:
    if len(data) != 16:
        return ""
    first, second, third = struct.unpack_from("<IHH", data, 0)
    tail = data[8:]
    return f"{first:08x}-{second:04x}-{third:04x}-{tail[0]:02x}{tail[1]:02x}-{tail[2:].hex()}"


def windows_filetime_to_iso(value: int) -> str:
    """FILETIME -> ISO-8601 UTC with integer arithmetic (no float, pre-1970 safe)."""
    if value <= 0:
        return ""
    try:
        return (FILETIME_EPOCH + timedelta(microseconds=value // 10)).isoformat()
    except OverflowError:
        return ""


FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def plausible_filetime_to_iso(value: int) -> str:
    timestamp = windows_filetime_to_iso(value)
    if not timestamp:
        return ""
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return ""
    if datetime(1990, 1, 1, tzinfo=timezone.utc) <= parsed <= datetime(2035, 1, 1, tzinfo=timezone.utc):
        return timestamp
    return ""


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0] if offset + 2 <= len(data) else 0


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0] if offset + 4 <= len(data) else 0


def read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0] if offset + 8 <= len(data) else 0


def file_hashes(path: Path) -> dict[str, str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return {}
    return {"sha256": digest.hexdigest()}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
