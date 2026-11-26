"""Read framed Explorer Taskband PIDLs and Shell Links without scanning unframed data."""

from __future__ import annotations

from .shellitem import MAX_SHELLITEM_LIST_BYTES, iter_shellitems

MAX_TASKBAND_VALUE_BYTES = 16 * 1024 * 1024
MAX_TASKBAND_ENTRIES = 4096
MAX_LISTED_UNDECODED_FRAMES = 32


def decode_taskband_value(value_name: str, data: bytes) -> tuple[list[dict[str, object]], dict[str, object]]:
    """One cited target per decodable entry, plus the walk's coverage (offsets are relative to the value).

    Favorites frames start with a zero tag and a little-endian DWORD PIDL size; ``ff`` ends the list.
    FavoritesResolve frames start directly with a DWORD Shell Link size and run to the end of the value.
    An invalid outer size leaves the next boundary unknown, so the walk stops there and says why.
    """
    favorites = value_name.casefold() == "favorites"
    pins: list[dict[str, object]] = []
    undecoded: list[int] = []
    frames = oversized = 0
    offset = 0
    end_status = ""
    if len(data) > MAX_TASKBAND_VALUE_BYTES:
        end_status = "value-too-large"
    while not end_status:
        if frames >= MAX_TASKBAND_ENTRIES:
            end_status = "frame-cap"
            break
        if favorites:
            if offset >= len(data):
                end_status = "missing-terminator"
                break
            if data[offset] == 0xFF:
                end_status = "terminator"
                offset += 1
                break
            if data[offset] != 0:
                end_status = "unrecognized-entry-tag"
                break
            header = offset + 1
        elif offset == len(data):
            end_status = "end-of-value"
            break
        else:
            header = offset
        if header + 4 > len(data):
            end_status = "truncated-frame-header"
            break
        size = int.from_bytes(data[header : header + 4], "little")
        start = header + 4
        if size == 0:
            end_status = "zero-length-frame"
            break
        if start + size > len(data):
            end_status = "frame-exceeds-value"
            break
        pin_index = frames
        frames += 1
        offset = start + size
        if size > MAX_SHELLITEM_LIST_BYTES:
            oversized += 1
            undecoded.append(pin_index)
            continue
        payload = data[start:offset]
        if favorites:
            target, method = pidl_target(payload)
            app_id = ""
        else:
            target, method, app_id = shell_link_target(payload)
        if not (target or app_id):
            undecoded.append(pin_index)
            continue
        pins.append({
            "pin_index": pin_index,
            "value_data_offset": start,
            "value_data_length": size,
            "application": app_id or target,
            "app_id": app_id,
            "target_path": target,
            "target_path_source": method,
        })
    clean = end_status in {"terminator", "end-of-value"} and not undecoded and offset == len(data)
    summary: dict[str, object] = {
        "value_name": value_name,
        "value_size": len(data),
        "decode_status": "decoded" if clean else "partial",
        "end_status": end_status,
        "end_offset": offset,
        "trailing_bytes": len(data) - offset if end_status == "terminator" else 0,
        "frames_seen": frames,
        "pins_decoded": len(pins),
        "undecoded_frames": len(undecoded),
        "undecoded_frame_indices": undecoded[:MAX_LISTED_UNDECODED_FRAMES],
        "oversized_frames": oversized,
        "frame_cap": MAX_TASKBAND_ENTRIES,
        "value_byte_cap": MAX_TASKBAND_VALUE_BYTES,
        "frame_byte_cap": MAX_SHELLITEM_LIST_BYTES,
    }
    return pins, summary


def pidl_target(data: bytes) -> tuple[str, str]:
    from .shellbags import decode_shell_item_entry, join_shell_path

    # Validate the entire bounded list, including its two-byte TerminalID.
    items = list(iter_shellitems(data))
    if not items or sum(map(len, items)) + 2 != len(data) or data[-2:] != b"\x00\x00":
        return "", ""
    entries = [decode_shell_item_entry(item) for item in items]
    names = [str(entry["name"]) for entry in entries]
    if not names[-1] or names[-1].startswith("<"):
        return "", ""
    return join_shell_path(names), "shell-item-id-list"


def shell_link_target(data: bytes) -> tuple[str, str, str]:
    from .recent_files import (
        LNK_CLSID,
        LNK_HEADER_SIZE,
        lnk_structural_length,
        parse_lnk_metadata_from_bytes,
    )

    if (
        data[:4] != LNK_HEADER_SIZE.to_bytes(4, "little")
        or data[4:20] != LNK_CLSID
        or data[-4:] != bytes(4)
        or lnk_structural_length(data) != len(data)
    ):
        return "", "", ""
    details = parse_lnk_metadata_from_bytes(data)
    app_id = next((
        prop["value"]
        for block in details["property_store_blocks"]
        for prop in block["properties"]
        if prop["name"] == "System.AppUserModel.ID" and isinstance(prop["value"], str)
    ), "")
    method = str(details["target_path_source"])
    # A printable string anywhere in a damaged link is insufficient to identify a pin.
    if method and method != "embedded-path-string-scan":
        return str(details["target_path"]), method, app_id
    if details["environment_target"]:
        return str(details["environment_target"]), "environment-target", app_id
    if details["link_flags"] & 1:
        size = int.from_bytes(data[76:78], "little")
        target, method = pidl_target(data[78:78 + size])
        return target, method, app_id
    return "", "", app_id
