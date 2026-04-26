from __future__ import annotations

import hashlib
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence, Tuple

from ...core.models import ArtifactRecord
from .common import isoformat_from_timestamp, iter_windows_user_homes

RECENT_ROOT = ("AppData", "Roaming", "Microsoft", "Windows", "Recent")
RECENT_PATTERNS: Tuple[Tuple[str, str, Sequence[str]], ...] = (
    ("recent-shortcut", "*.lnk", ()),
    ("jumplist-automatic", "*.automaticDestinations-ms", ("AutomaticDestinations",)),
    ("jumplist-custom", "*.customDestinations-ms", ("CustomDestinations",)),
)
LNK_HEADER_SIZE = 0x4C
LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
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

    embedded_paths = extract_windows_paths(data)
    if len(data) < LNK_HEADER_SIZE or data[:4] != b"\x4c\x00\x00\x00" or data[4:20] != LNK_CLSID:
        return {
            "lnk_parse_status": "unsupported-header",
            "target_path": "",
            "embedded_paths": embedded_paths,
        }

    link_flags = read_u32(data, 0x14)
    file_attributes = read_u32(data, 0x18)
    string_data, string_offset = parse_lnk_string_data(data, link_flags)
    link_info = parse_lnk_link_info(data, link_flags)
    target_path = first_non_empty(
        link_info.get("local_base_path"),
        string_data.get("relative_path"),
        next(iter(embedded_paths), ""),
    )
    paths = sorted({item for item in [target_path, *embedded_paths] if item})
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
        "string_data_offset": string_offset,
    }


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
    return {
        "jump_list_parse_status": "inventory",
        "container_hint": "ole-compound-file" if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") else "custom-binary",
        "jumplist_kind": "automatic" if artifact_type == "jumplist-automatic" else "custom",
        "embedded_paths": extract_windows_paths(data),
        "note": "Jump List destination stream parsing is not fully decoded yet; embedded path extraction is provided for triage search.",
    }


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


def windows_filetime_to_iso(value: int) -> str:
    if value <= 0:
        return ""
    try:
        seconds = (value - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
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
