"""NTFS volume identity: the ``$Boot`` VBR and the ``$Volume`` MFT record (#3).

Shared by the ``windows-filesystem`` collector (``artifacts.windows.system_extras``
re-exports these names) and the ``ntfs-meta`` analysis, which writes one
``ntfs-volume-information`` row from the ``$Boot`` / ``$MFT`` it extracted
(plan r6-followups §2 갈래 C). Stdlib only; never raises on corrupt input --
``vbr_parse_status`` / ``volume_record_status`` say why a part was not decoded.
"""

from __future__ import annotations

from pathlib import Path

VBR_OEM_NTFS = b"NTFS    "
BOOT_SECTOR_BYTES = 512
MFT_RECORD_SIZES = (1024, 2048, 4096)
VOLUME_RECORD_NUMBER = 3


def parse_ntfs_vbr(boot: bytes) -> dict[str, object]:
    """Fields of an NTFS boot sector; ``parse_status`` says why a sector was not decoded."""
    if len(boot) < 512:
        return {"vbr_parse_status": "truncated"}
    if boot[3:11] != VBR_OEM_NTFS:
        return {"vbr_parse_status": "not-ntfs", "oem_id": boot[3:11].decode("ascii", errors="replace").strip()}
    bytes_per_sector = int.from_bytes(boot[0x0B:0x0D], "little")
    raw_spc = boot[0x0D]
    sectors_per_cluster = 1 << (256 - raw_spc) if raw_spc > 0x80 else raw_spc
    total_sectors = int.from_bytes(boot[0x28:0x30], "little")
    cluster_size = bytes_per_sector * sectors_per_cluster if bytes_per_sector and sectors_per_cluster else 0

    def record_size(raw: int) -> int | None:
        signed = raw - 256 if raw > 127 else raw
        if signed < 0:
            return 1 << -signed if -signed < 31 else None
        return signed * cluster_size if cluster_size else None

    vsn = int.from_bytes(boot[0x48:0x50], "little")
    low = vsn & 0xFFFFFFFF
    return {
        "vbr_parse_status": "parsed",
        "oem_id": boot[3:11].decode("ascii").strip(),
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "cluster_size": cluster_size,
        "media_descriptor": f"{boot[0x15]:02X}",
        "hidden_sectors": int.from_bytes(boot[0x1C:0x20], "little"),
        "total_sectors": total_sectors,
        "volume_size_bytes": total_sectors * bytes_per_sector if bytes_per_sector else None,
        "mft_lcn": int.from_bytes(boot[0x30:0x38], "little"),
        "mft_mirror_lcn": int.from_bytes(boot[0x38:0x40], "little"),
        "mft_record_size": record_size(boot[0x40]),
        "index_record_size": record_size(boot[0x44]),
        "volume_serial_number_64": f"{vsn:016X}",
        "volume_serial_number": f"{low:08X}",
        "volume_serial_display": f"{low >> 16:04X}-{low & 0xFFFF:04X}",
        "boot_signature_valid": boot[510:512] == b"\x55\xaa",
    }


def apply_fixups(record: bytes, sector_size: int = 512) -> bytes | None:
    if len(record) < 48 or record[:4] != b"FILE":
        return None
    usa_offset = int.from_bytes(record[4:6], "little")
    usa_count = int.from_bytes(record[6:8], "little")
    if usa_count < 1 or usa_offset + usa_count * 2 > len(record):
        return None
    data = bytearray(record)
    check = data[usa_offset : usa_offset + 2]
    for index in range(1, usa_count):
        end = index * sector_size
        if end > len(data):
            break
        if data[end - 2 : end] != check:
            return None
        data[end - 2 : end] = data[usa_offset + index * 2 : usa_offset + index * 2 + 2]
    return bytes(data)


NTFS_VOLUME_FLAGS = {
    0x0001: "dirty",
    0x0002: "resize-logfile",
    0x0004: "upgrade-on-mount",
    0x0008: "mounted-on-nt4",
    0x0010: "delete-usn-underway",
    0x0020: "repair-object-ids",
    0x8000: "chkdsk-modified",
}


def parse_volume_record(record: bytes, sector_size: int = 512) -> dict[str, object]:
    """``$VOLUME_NAME`` (0x60) and ``$VOLUME_INFORMATION`` (0x70) of MFT record 3.

    The fixup stride is the volume's ``bytes_per_sector`` (4Kn disks: 4096), not a fixed 512."""
    data = apply_fixups(record, sector_size if sector_size in (512, 1024, 2048, 4096) else 512)
    if data is None:
        return {"volume_record_status": "invalid-file-record"}
    offset = int.from_bytes(data[0x14:0x16], "little")
    out: dict[str, object] = {"volume_record_status": "parsed"}
    guard = 0
    while 0 < offset < len(data) - 8 and guard < 64:
        guard += 1
        attr_type = int.from_bytes(data[offset : offset + 4], "little")
        if attr_type == 0xFFFFFFFF:
            break
        length = int.from_bytes(data[offset + 4 : offset + 8], "little")
        if length < 16 or offset + length > len(data):
            out["volume_record_status"] = "attribute-overrun"
            break
        resident = data[offset + 8] == 0
        if resident:
            content_length = int.from_bytes(data[offset + 0x10 : offset + 0x14], "little")
            content_offset = int.from_bytes(data[offset + 0x14 : offset + 0x16], "little")
            content = data[offset + content_offset : offset + content_offset + content_length]
            if attr_type == 0x60:
                out["volume_label"] = content.decode("utf-16-le", errors="replace")
            elif attr_type == 0x70 and len(content) >= 12:
                flags = int.from_bytes(content[10:12], "little")
                out.update(
                    {
                        "ntfs_version": f"{content[8]}.{content[9]}",
                        "volume_flags": flags,
                        "volume_flag_names": [name for bit, name in NTFS_VOLUME_FLAGS.items() if flags & bit],
                        "volume_dirty": bool(flags & 0x0001),
                    }
                )
        offset += length
    return out


def read_volume_information(boot_path: Path | None, mft_path: Path | None) -> dict[str, object]:
    """VBR fields of ``boot_path`` plus the ``$Volume`` record (#3) of ``mft_path`` (either may be ``None``).

    The MFT record size comes from the VBR when it states 1024/2048/4096, else 1024; the fixup
    stride is the VBR's ``bytes_per_sector``."""
    fields: dict[str, object] = {}
    if boot_path is not None:
        try:
            with boot_path.open("rb") as handle:
                fields.update(parse_ntfs_vbr(handle.read(BOOT_SECTOR_BYTES)))
        except OSError as exc:
            fields["vbr_parse_status"] = f"unreadable: {type(exc).__name__}"
    if mft_path is not None:
        record_size = fields.get("mft_record_size")
        size = record_size if isinstance(record_size, int) and record_size in MFT_RECORD_SIZES else 1024
        try:
            with mft_path.open("rb") as handle:
                handle.seek(VOLUME_RECORD_NUMBER * size)
                sector = fields.get("bytes_per_sector")
                fields.update(parse_volume_record(handle.read(size), sector if isinstance(sector, int) else 512))
        except OSError as exc:
            fields["volume_record_status"] = f"unreadable: {type(exc).__name__}"
    return fields


def volume_information_decoded(fields: dict[str, object]) -> bool:
    """At least one part (VBR or ``$Volume``) decoded: the folder is NTFS metadata."""
    return fields.get("vbr_parse_status") == "parsed" or fields.get("volume_record_status") == "parsed"
