"""Bounded ShellItem (SHITEMID) decoding for ShellBags BagMRU values.

Implements the commonly observed item classes only:

- 0x1f root/GUID folder items (mapped to known folder names)
- 0x2f drive letter items
- 0x31/0x32/0x35/0x36/0xb1 file-system items (extension-block long names)
- 0x61 URI items
- 0x71 control-panel/GUID items
- 0x74 delegate items (zip/archive contents; best-effort name extraction)

Items of other classes are preserved as typed placeholders so the decoded
path never silently drops a level. All decoders record which method produced
the name so downstream validation can audit coverage.
"""

from __future__ import annotations

import struct
import uuid
from collections.abc import Iterator

MAX_SHELLITEM_LIST_BYTES = 1024 * 1024
MAX_SHELLITEMS_PER_LIST = 512

KNOWN_FOLDER_GUIDS = {
    "{20d04fe0-3aea-1069-a2d8-08002b30309d}": "My Computer",
    "{21ec2020-3aea-1069-a2dd-08002b30309d}": "Control Panel",
    "{208d2c60-3aea-1069-a2d7-08002b30309d}": "Network",
    "{2227a280-3aea-1069-a2de-08002b30309d}": "Printers",
    "{645ff040-5081-101b-9f08-00aa002f954e}": "Recycle Bin",
    "{59031a47-3f72-44a7-89c5-5595fe6b30ee}": "User Profile",
    "{679f85cb-0220-4080-b29b-5540cc05aab6}": "Libraries",
    "{b4bfcc3a-db2c-424c-b029-7fe99a87c641}": "Desktop",
    "{031e4825-7b94-4dc3-b131-e946b44c8dd5}": "Libraries",
    "{fdd39ad0-238f-46af-adb4-6c85480369c7}": "Documents",
    "{33e28130-4e1e-4676-835a-98395c3bc3bb}": "Pictures",
    "{4bd8d571-6d19-48d3-be97-422220080e43}": "Music",
    "{18989b1d-99b5-455b-841c-ab7c74e4ddfc}": "Videos",
    "{374de290-123f-4565-9164-39c4925e467b}": "Downloads",
    "{0762d272-c50a-4bb0-a382-697dcd729b80}": "Users",
    "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}": "System32",
    "{f38bf404-1d43-42f2-9305-67de0b28fc23}": "Windows",
    "{905e63b6-c1bf-494e-b29c-65b732d3d21a}": "Program Files",
    "{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}": "Program Files (x86)",
    "{d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27}": "System",
    "{a39193cc-55b8-4244-aa44-e9bc5db04762}": "ProgramData",
    "{b6ebfb86-6907-413c-9af7-4fc2abf07cc5}": "Public",
    "{9339a431-9b4a-432e-a46b-95d20c17ea11}": "Common AppData",
}

BEEF0004_SIGNATURE = b"\x04\x00\xef\xbe"
FILESYSTEM_ITEM_TYPES = {0x31, 0x32, 0x35, 0x36, 0xB1}


def iter_shellitems(blob: bytes) -> Iterator[bytes]:
    """Split a shellitem list into individual items."""
    if len(blob) > MAX_SHELLITEM_LIST_BYTES:
        return
    cursor = 0
    emitted = 0
    while cursor + 3 <= len(blob) and emitted < MAX_SHELLITEMS_PER_LIST:
        size = struct.unpack_from("<H", blob, cursor)[0]
        if size == 0:
            return
        if size < 3 or cursor + size > len(blob):
            return
        yield blob[cursor : cursor + size]
        emitted += 1
        cursor += size


def _decode_ansi(data: bytes) -> str:
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    try:
        return data.decode("cp949").strip()
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace").strip()


def _decode_utf16_name(data: bytes) -> str:
    end = len(data) - (len(data) % 2)
    cursor = 0
    while cursor + 2 <= end:
        if data[cursor : cursor + 2] == b"\x00\x00":
            break
        cursor += 2
    data = data[:cursor]
    try:
        return data.decode("utf-16-le").strip()
    except UnicodeDecodeError:
        return ""


def _decode_extension_block_name(item: bytes) -> tuple[str, str]:
    """Extract the long name from a 0xBEEF0004 extension block.

    The block stores a u16 ``long_name_offset`` at block+16 (relative to the
    block start); the name sits at ``block_start + long_name_offset`` —
    UTF-16LE for version >= 7, ANSI for version 3. A UTF-16 tail scan is the
    fallback when the offset field is absent.
    """
    cursor = 0
    while True:
        index = item.find(BEEF0004_SIGNATURE, cursor)
        if index < 4:
            return "", ""
        block_start = index - 4
        version = struct.unpack_from("<H", item, block_start + 2)[0]
        if block_start + 18 <= len(item):
            name_offset = struct.unpack_from("<H", item, block_start + 16)[0]
            absolute = block_start + name_offset
            if name_offset and absolute < len(item):
                if version >= 7:
                    name = _decode_utf16_name(item[absolute:])
                    method = "extension-block-utf16"
                else:
                    name = _decode_ansi(item[absolute:])
                    method = "extension-block-ansi"
                if name:
                    return name, method
        if version >= 7:
            name = _longest_utf16_run(item[index + 4 :])
            if name:
                return name, "extension-block-utf16-tail"
        cursor = index + 1


def _decode_short_name(item: bytes) -> str:
    """Best-effort ANSI 8.3 short name embedded after the fixed fs fields."""
    for start in (14, 12, 10):
        if start >= len(item):
            break
        candidate = _decode_ansi(item[start:])
        if (
            len(candidate) >= 2
            and candidate.isprintable()
            and all(ch not in candidate for ch in '<>"|?*')
        ):
            return candidate
    return ""


def _decode_guid_name(payload: bytes) -> tuple[str, str]:
    if len(payload) < 18:
        return "", ""
    try:
        guid = str(uuid.UUID(bytes_le=payload[2:18])).lower()
    except ValueError:
        return "", ""
    if guid == "00000000-0000-0000-0000-000000000000":
        return "", ""
    guid = "{" + guid + "}"
    return KNOWN_FOLDER_GUIDS.get(guid, "CLSID " + guid), "guid"


def _decode_drive_text(data: bytes) -> str:
    index = 0
    while True:
        index = data.find(b":\\", index)
        if index < 1:
            return ""
        drive = data[index - 1 : index + 2]
        if 0x41 <= drive[0] <= 0x7A and chr(drive[0]).isalpha():
            return drive.decode("ascii")
        index += 1


def _longest_utf16_run(data: bytes, min_chars: int = 3) -> str:
    best = ""
    run = bytearray()
    for index in range(0, len(data) - 1, 2):
        code = struct.unpack_from("<H", data, index)[0]
        if 0x20 <= code < 0xD800 or 0xE000 <= code < 0xFFFE:
            run += data[index : index + 2]
            continue
        if len(run) >= min_chars * 2:
            candidate = run.decode("utf-16-le", errors="replace").strip()
            if len(candidate) > len(best):
                best = candidate
        run = bytearray()
    if len(run) >= min_chars * 2:
        candidate = run.decode("utf-16-le", errors="replace").strip()
        if len(candidate) > len(best):
            best = candidate
    return best


def decode_shellitem(item: bytes) -> dict[str, object]:
    """Decode one shellitem into a name plus decode-method metadata."""
    if len(item) < 3:
        return {"name": "", "item_type": 0, "decode_method": "truncated"}
    item_type = item[2]
    payload = item[3:]
    result: dict[str, object] = {"item_type": item_type, "size": len(item)}

    if item_type in (0x1F, 0x2E):
        name, method = _decode_guid_name(item[2:])
        if not name:
            name = _decode_drive_text(payload) or _decode_ansi(payload[6:])
            method = "drive-text" if name else "root-fallback"
        elif name.startswith("CLSID ") and b"1SPS" in payload:
            hint = _longest_utf16_run(payload)
            if hint:
                name, method = hint, "property-store-utf16"
        result.update(name=name or "<root-folder>", decode_method=method)
    elif item_type == 0xC3:
        name = _decode_ansi(payload[2:])
        result.update(name=name or "<network-item>", decode_method="network-ansi" if name else "unresolved")
    elif item_type == 0x2F:
        name = _decode_ansi(payload)
        result.update(name=name or "<drive>", decode_method="drive-letter")
    elif item_type in FILESYSTEM_ITEM_TYPES:
        name, method = _decode_extension_block_name(item)
        if not name:
            name = _decode_short_name(item)
            method = "ansi-short-name" if name else "unresolved"
        result.update(name=name or f"<fs-item-0x{item_type:02x}>", decode_method=method)
    elif item_type == 0x61:
        name = _decode_ansi(payload[2:] if len(payload) > 2 else payload)
        result.update(name=name or "<uri>", decode_method="uri-ansi" if name else "unresolved")
    elif item_type == 0x71:
        name, method = _decode_guid_name(item[2:])
        result.update(name=name or "<control-panel>", decode_method=method or "control-panel-fallback")
    elif item_type == 0x74:
        name = _longest_utf16_run(payload)
        method = "delegate-utf16-scan"
        if not name:
            name = _decode_ansi(payload[8:] if len(payload) > 8 else payload)
            method = "delegate-ansi-scan"
        result.update(name=name or "<delegate-item>", decode_method=method if name else "unresolved")
    else:
        result.update(name=f"<shellitem-0x{item_type:02x}>", decode_method="unsupported-type")
    return result


def decode_shellitem_path(blob: bytes) -> tuple[str, list[dict[str, object]]]:
    """Decode a shellitem list into a path segment string."""
    segments: list[str] = []
    items: list[dict[str, object]] = []
    for item in iter_shellitems(blob):
        decoded = decode_shellitem(item)
        items.append(decoded)
        name = str(decoded.get("name") or "")
        if name:
            segments.append(name)
    path = "\\".join(segments)
    if segments and segments[0].endswith(":"):
        path = segments[0] + "\\" + "\\".join(segments[1:])
    return path, items
