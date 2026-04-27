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
PARSER_VERSION = "windows-recent-files-v3"
MAX_JUMPLIST_EMBEDDED_LNKS = 50
MAX_OLE_STREAMS = 128
MAX_OLE_STREAM_BYTES = 8 * 1024 * 1024
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
    return parse_lnk_metadata_from_bytes(data)


def parse_lnk_metadata_from_bytes(data: bytes) -> dict[str, object]:
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
    ole_streams = parse_ole_compound_streams(data) if data.startswith(CFB_SIGNATURE) else []
    destinations = extract_jumplist_destinations(data, ole_streams)
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
        }
        for stream in ole_streams[:MAX_OLE_STREAMS]
    ]
    return {
        "jump_list_parse_status": "parsed-ole-stream-lnk" if ole_streams and destinations else "parsed-embedded-lnk" if destinations else "inventory",
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
        "note": "OLE Jump List streams are traversed when recoverable; otherwise embedded Shell Link and path extraction is provided for triage search.",
    }


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
        }
        if stream:
            destination.update(
                {
                    "stream_name": str(stream.get("name") or ""),
                    "stream_path": stream_path,
                    "stream_size": int(stream.get("size") or 0),
                    "stream_index": int(stream.get("index") or 0),
                }
            )
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
