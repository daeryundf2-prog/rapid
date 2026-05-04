from __future__ import annotations

import hashlib
import re
import struct
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence, Tuple

from ...core.forensic_accuracy import build_accuracy_gate
from ...core.models import ArtifactRecord
from .common import build_forensic_review, isoformat_from_timestamp, iter_windows_user_homes

RECENT_ROOT = ("AppData", "Roaming", "Microsoft", "Windows", "Recent")
PARSER_VERSION = "windows-recent-files-v4"
MAX_JUMPLIST_EMBEDDED_LNKS = 50
MAX_OLE_STREAMS = 128
MAX_OLE_STREAM_BYTES = 8 * 1024 * 1024
MAX_LNK_EXTRA_DATA_BLOCKS = 64
MAX_LNK_SHELL_ITEMS = 128
MAX_DESTLIST_ENTRIES = 128
MAX_DESTLIST_CANDIDATE_TIMES = 8
MAX_DESTLIST_NUMERIC_CANDIDATES = 12
DESTLIST_HEADER_SIZE = 32
DESTLIST_ENTRY_LAYOUTS: Tuple[Tuple[str, int], ...] = (
    ("win7-win8-fixed114", 114),
    ("win10-plus-fixed130", 130),
)
JUMPLIST_COMMERCIAL_BLOCKERS = [
    "destlist-os-version-specific-field-validation-required",
    "destlist-deleted-entry-recovery-not-implemented",
    "destlist-account-metadata-not-fully-decoded",
    "application-id-hash-to-application-name-map-not-bundled",
]
JUMPLIST_CAPABILITIES = {
    "lnk_header_decode": True,
    "lnk_linkinfo_decode": True,
    "lnk_tracker_block_candidate_decode": True,
    "ole_stream_inventory": True,
    "embedded_lnk_destination_extraction": True,
    "destlist_header_candidate_decode": True,
    "destlist_entry_candidate_decode": True,
    "full_shell_item_property_store_decode": False,
    "destlist_deleted_entry_recovery": False,
    "destlist_account_metadata_decode": False,
    "appid_hash_mapping": False,
}
RECENT_PATTERNS: Tuple[Tuple[str, str, Sequence[str]], ...] = (
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
            if not recent_root.is_dir():
                continue
            for artifact_type, pattern, extra_parts in RECENT_PATTERNS:
                scan_root = recent_root.joinpath(*extra_parts)
                if not scan_root.is_dir():
                    continue
                for candidate in sorted(scan_root.glob(pattern), key=lambda item: item.name.lower()):
                    if not candidate.is_file():
                        continue
                    stat_result = candidate.stat()
                    yield ArtifactRecord(
                        provider=self.name,
                        artifact_type=artifact_type,
                        path=str(candidate.resolve()),
                        supported=self.supported(),
                        details={
                            "parser": "windows-recent-files",
                            "parser_version": PARSER_VERSION,
                            "user": user_root.name,
                            "entry_name": candidate.name,
                            "entry_hint": candidate.stem,
                            "size": stat_result.st_size,
                            "modified_at": isoformat_from_timestamp(stat_result.st_mtime),
                            **recent_file_metadata(candidate, artifact_type),
                        },
                    )


def recent_file_metadata(path: Path, artifact_type: str) -> dict[str, object]:
    base = {"source_hashes": file_hashes(path)}
    if artifact_type == "recent-shortcut":
        return {**base, **parse_lnk_metadata(path)}
    return {**base, **jump_list_metadata(path, artifact_type)}


def parse_lnk_metadata(path: Path) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError:
        return {"lnk_parse_status": "read-error"}
    metadata = parse_lnk_metadata_from_bytes(data)
    metadata["core_accuracy_gates"] = lnk_core_accuracy_gates(
        {
            **metadata,
            "source_path": str(path.resolve()),
            "source_hashes": file_hashes(path),
        }
    )
    if metadata.get("lnk_parse_status") == "parsed":
        metadata["commercial_uplift_evidence"] = lnk_commercial_uplift_evidence(
            {
                **metadata,
                "source_path": str(path.resolve()),
                "source_hashes": file_hashes(path),
                "artifact_type": "recent-shortcut",
            }
        )
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
    target_path = first_non_empty(
        link_info.get("local_base_path"),
        string_data.get("relative_path"),
        next(iter(embedded_paths), ""),
    )
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
    if details.get("target_created_at") or details.get("target_accessed_at") or details.get("target_modified_at"):
        satisfied.append("timestamp/source field provenance")
    return [build_accuracy_gate(17, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def parse_lnk_extra_data(data: bytes, offset: int) -> tuple[list[dict[str, object]], dict[str, object]]:
    blocks: list[dict[str, object]] = []
    tracker_data: dict[str, object] = {}
    while offset + 4 <= len(data) and len(blocks) < MAX_LNK_EXTRA_DATA_BLOCKS:
        block_size = read_u32(data, offset)
        if block_size == 0:
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
        blocks.append(block_summary)
        offset += block_size
    return blocks, tracker_data


def parse_lnk_tracker_data_block(block_data: bytes) -> dict[str, object]:
    machine_id = decode_text(block_data[0x10:0x20], "cp1252") if len(block_data) >= 0x20 else ""
    return {
        "parse_status": "parsed-candidate" if len(block_data) >= 0x60 else "truncated-candidate",
        "machine_id": machine_id,
        "droid_volume_identifier": format_guid_le(block_data[0x20:0x30]),
        "droid_file_identifier": format_guid_le(block_data[0x30:0x40]),
        "birth_droid_volume_identifier": format_guid_le(block_data[0x40:0x50]),
        "birth_droid_file_identifier": format_guid_le(block_data[0x50:0x60]),
        "validation_status": "candidate-requires-known-answer-corpus",
    }


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


def parse_lnk_link_info(data: bytes, link_flags: int) -> dict[str, str]:
    if not (link_flags & 0x00000002):
        return {}
    offset = LNK_HEADER_SIZE
    if link_flags & 0x00000001:
        offset += 2 + read_u16(data, offset)
    size = read_u32(data, offset)
    if size < 0x1C or offset + size > len(data):
        return {"parse_status": "invalid-link-info"}
    block = data[offset : offset + size]
    header_size = read_u32(block, 4)
    local_base_path_offset = read_u32(block, 16)
    common_path_suffix_offset = read_u32(block, 24)
    result = {
        "parse_status": "parsed",
        "local_base_path": read_c_string(block, local_base_path_offset, "cp1252"),
        "common_path_suffix": read_c_string(block, common_path_suffix_offset, "cp1252"),
    }
    if header_size >= 0x24:
        result["local_base_path_unicode"] = read_c_string(block, read_u32(block, 28), "utf-16le")
        result["common_path_suffix_unicode"] = read_c_string(block, read_u32(block, 36), "utf-16le")
        if result["local_base_path_unicode"]:
            result["local_base_path"] = result["local_base_path_unicode"]
        if result["common_path_suffix_unicode"]:
            result["common_path_suffix"] = result["common_path_suffix_unicode"]
    return result


def jump_list_metadata(path: Path, artifact_type: str) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError:
        return {"jump_list_parse_status": "read-error"}
    ole_streams = parse_ole_compound_streams(data) if data.startswith(CFB_SIGNATURE) else []
    destinations = extract_jumplist_destinations(data, ole_streams)
    destlist_metadata = parse_destlist_metadata(ole_streams)
    enrich_destinations_with_destlist_candidates(destinations, destlist_metadata.get("destlist_entry_candidates", []))
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
    return {
        "jump_list_parse_status": "parsed-ole-stream-lnk" if ole_streams and destinations else "parsed-embedded-lnk" if destinations else "inventory",
        "coverage_status": "native-destlist-candidate" if destlist_metadata.get("destlist_parse_status") == "parsed-candidate" else "mapped",
        "reportability": "triage",
        "parser_confidence": jumplist_parser_confidence(destinations, destlist_metadata),
        "evidence_strength": "jumplist-destination-candidate" if destinations else "jumplist-container-presence",
        "commercial_grade_ready": False,
        "container_hint": "ole-compound-file" if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") else "custom-binary",
        "jumplist_kind": "automatic" if artifact_type == "jumplist-automatic" else "custom",
        "application_id_hash": path.stem.split(".", 1)[0],
        "ole_parse_status": "parsed" if ole_streams else "not-ole" if not data.startswith(CFB_SIGNATURE) else "no-streams",
        "ole_stream_count": len(ole_streams),
        "ole_streams": stream_summaries,
        "embedded_paths": embedded_paths,
        "destination_count": len(destinations),
        "destination_stream_count": len({str(destination.get("stream_path") or "") for destination in destinations if destination.get("stream_path")}),
        "destinations": destinations,
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
            "validation_checks": dict(destlist_metadata.get("destlist_validation_checks") or {}),
        },
        "destinations": [
            {
                "target_path": str(destination.get("target_path") or ""),
                "stream_path": str(destination.get("stream_path") or ""),
                "lnk_offset": destination.get("lnk_offset", 0),
                "has_tracker_data": bool(destination.get("has_tracker_data")),
                "destlist_entry_offset_candidate": destination.get("destlist_entry_offset_candidate"),
                "destlist_validation_status": destination.get("destlist_validation_status", ""),
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


def jumplist_core_accuracy_gates(details: dict[str, object]) -> list[dict[str, object]]:
    checks = details.get("validation_checks") if isinstance(details.get("validation_checks"), dict) else {}
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), dict) else {}
    destlist_metadata = (
        details.get("destlist_metadata") if isinstance(details.get("destlist_metadata"), dict) else {}
    )
    destinations = [item for item in details.get("destinations") or [] if isinstance(item, dict)]
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
    if not JUMPLIST_CAPABILITIES["destlist_deleted_entry_recovery"]:
        satisfied.append("deleted-entry warning")
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
            if len(destinations) >= MAX_JUMPLIST_EMBEDDED_LNKS:
                break
    if not ole_streams or not destinations:
        append_lnk_destinations(destinations, data)
    return destinations[:MAX_JUMPLIST_EMBEDDED_LNKS]


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
        entries = parse_destlist_entry_candidates(stream_data, source, lnk_stream_names, declared_count)
        entry_candidates.extend(entries)
        if entries or header:
            parse_status = "parsed-candidate"

    validation_checks = destlist_validation_checks(
        bool(destlist_streams),
        declared_counts,
        len(entry_candidates),
        entry_candidates,
    )
    return {
        "destlist_parse_status": parse_status,
        "destlist_stream_count": len(destlist_streams),
        "destlist_streams": stream_summaries,
        "destlist_header_candidates": header_candidates,
        "destlist_declared_entry_count_candidates": declared_counts,
        "destlist_entry_candidate_count": len(entry_candidates),
        "destlist_entry_candidates": entry_candidates[:MAX_DESTLIST_ENTRIES],
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
        "pinned_entry_count_candidate": read_u32(data, 8),
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
    layout_candidates: list[tuple[int, str, int, str, int]] = []
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
        if matched_lnk_stream_candidates(data[offset : offset + fixed_size], lnk_stream_names):
            score += 2
        layout_candidates.append((score, layout_name, fixed_size, path, end - offset))
    if not layout_candidates:
        return None
    _, layout_name, fixed_size, path, entry_size = sorted(layout_candidates, key=lambda item: item[0], reverse=True)[0]
    prefix = data[offset : offset + fixed_size]
    matched_streams = matched_lnk_stream_candidates(prefix, lnk_stream_names)
    filetime_candidates = destlist_filetime_candidates(prefix)
    validation_status = "candidate-linked-lnk-stream" if matched_streams else "candidate-unlinked"
    return {
        **source,
        "index": index,
        "entry_offset": offset,
        "entry_size_candidate": entry_size,
        "layout_candidate": layout_name,
        "fixed_header_size_candidate": fixed_size,
        "path_candidate": path,
        "droid_guid_candidates": destlist_guid_candidates(prefix),
        "hostname_candidates": destlist_hostname_candidates(prefix),
        "filetime_candidates": filetime_candidates,
        "numeric_field_candidates": destlist_numeric_candidates(prefix, lnk_stream_names),
        "matched_lnk_stream_candidates": matched_streams,
        "validation_status": validation_status,
        "parser_confidence": destlist_entry_confidence(path, matched_streams, filetime_candidates),
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
        "full_property_store_decode_available": ("Full property store decode", "critical"),
        "is_ole_compound": ("OLE compound file", "high"),
        "ole_streams_recovered": ("OLE streams recovered", "medium"),
        "embedded_lnk_destinations_recovered": ("Embedded LNK destinations", "high"),
        "has_destlist_stream": ("DestList stream", "high"),
        "destlist_candidate_decoding_available": ("DestList candidate decoding", "medium"),
        "destlist_report_grade": ("DestList report-grade decode", "critical"),
        "requires_external_validation": ("External validation", "critical"),
    }
    matrix: list[dict[str, object]] = []
    for key, value in checks.items():
        if key in {"extra_data_block_count"}:
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
    return {
        "batch_id": "commercial-uplift-016-020",
        "item_numbers": [17],
        "implementation_track": "native-parser-depth",
        "objective": "Expose Shell Link header, LinkInfo/StringData/ExtraData validation and remaining property-store blockers.",
        "source_refs": [
            f"source_path:{details.get('source_path', '')}",
            f"source_sha256:{hashes.get('sha256', '')}",
            f"target_path:{details.get('target_path', '')}",
            f"artifact_type:{details.get('artifact_type', '')}",
        ],
        "passed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and item.get("passed")
        ],
        "failed_validation_matrix_ids": [
            str(item.get("id")) for item in matrix if isinstance(item, Mapping) and not item.get("passed")
        ],
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or []),
        "large_data_controls": {
            "bounded_extra_data_blocks": True,
            "max_extra_data_blocks": MAX_LNK_EXTRA_DATA_BLOCKS,
            "max_shell_items": MAX_LNK_SHELL_ITEMS,
            "property_store_decode_required_for_commercial_claims": True,
        },
        "next_internal_step": "Finish Shell Item property store semantics and tracker/LinkInfo known-answer corpus validation.",
        "external_evidence_required": True,
    }


def jumplist_commercial_uplift_evidence(details: Mapping[str, object]) -> dict[str, object]:
    matrix = details.get("recent_validation_matrix") if isinstance(details.get("recent_validation_matrix"), list) else []
    report_grade = (
        details.get("recent_report_grade_assessment")
        if isinstance(details.get("recent_report_grade_assessment"), Mapping)
        else {}
    )
    hashes = details.get("source_hashes") if isinstance(details.get("source_hashes"), Mapping) else {}
    reportability_decision = jumplist_reportability_decision(report_grade, details)
    return {
        "batch_id": "commercial-uplift-011-015",
        "item_numbers": [14],
        "implementation_track": "native-parser-depth",
        "objective": "Expose JumpList DestList validation, OLE/LNK provenance, deleted-entry blockers, and AppID gaps.",
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
    return {
        "profile_version": "jumplist-reportability-decision-v1",
        "commercial_gap_id": "#14",
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
        if len(destinations) >= MAX_JUMPLIST_EMBEDDED_LNKS:
            break


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
        if len(streams) >= MAX_OLE_STREAMS:
            break
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
    end = start + sector_size
    if sector_id < 0 or end > len(data):
        return b""
    return data[start:end]


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
    encoding = "utf-16le" if is_unicode else "cp1252"
    return decode_text(raw, encoding), min(len(data), offset + byte_count)


def extract_windows_paths(data: bytes) -> list[str]:
    paths = {decode_text(match.group(0), "cp1252").rstrip("\\") for match in WINDOWS_PATH_RE.finditer(data)}
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
    return decode_text(data[offset:end], encoding)


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
    if value <= 0:
        return ""
    try:
        seconds = (value - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


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
