"""Read framed Explorer Taskband PIDLs and Shell Links without scanning unframed data."""

from __future__ import annotations

from collections.abc import Iterator

from .shellitem import MAX_SHELLITEM_LIST_BYTES, iter_shellitems

MAX_TASKBAND_VALUE_BYTES = 16 * 1024 * 1024
MAX_TASKBAND_ENTRIES = 4096


def taskband_entries(value_name: str, data: bytes) -> Iterator[dict[str, object]]:
    """Yield one cited target per decodable entry (offsets are relative to the registry value).

    Favorites frames start with a zero tag and a little-endian DWORD PIDL size.
    FavoritesResolve frames start directly with a DWORD Shell Link size.
    An invalid outer size leaves the next boundary unknown; stop at that point.
    """
    if len(data) > MAX_TASKBAND_VALUE_BYTES:
        return
    favorites = value_name.casefold() == "favorites"
    offset = 0
    for pin_index in range(MAX_TASKBAND_ENTRIES):
        if favorites:
            if offset >= len(data) or data[offset] != 0:  # ff ends the Favorites stream
                break
            offset += 1
        if offset + 4 > len(data):
            break
        size = int.from_bytes(data[offset : offset + 4], "little")
        start = offset + 4
        offset = start + size
        if size == 0 or offset > len(data):
            break
        if size > MAX_SHELLITEM_LIST_BYTES:
            continue
        payload = data[start:offset]
        if favorites:
            target, method = pidl_target(payload)
            app_id = ""
        else:
            target, method, app_id = shell_link_target(payload)
        if target or app_id:
            yield {
                "pin_index": pin_index,
                "value_data_offset": start,
                "value_data_length": size,
                "application": app_id or target,
                "app_id": app_id,
                "target_path": target,
                "target_path_source": method,
            }


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
    from .recent_files import LNK_CLSID, LNK_HEADER_SIZE, lnk_structural_length, parse_lnk_metadata_from_bytes

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
