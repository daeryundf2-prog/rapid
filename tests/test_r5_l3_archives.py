"""R5 L3 archives: EGG / ALZ entry listing and ISO 9660 (+ Joliet) listing, hooked into the
archive inventory (synthetic fixtures built here, no real archives)."""

from __future__ import annotations

import bz2
import datetime as dt
import lzma
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from rapidtriage.artifacts.generic import collect_archive_inventory
from rapidtriage.core.egg_archive import (
    EGG_BLOCK,
    EGG_ENCRYPT,
    EGG_END,
    EGG_FILE,
    EGG_FILENAME,
    EGG_SOLID,
    EGG_WINDOWS_INFO,
    ArchiveFormatError,
    list_alz,
    list_egg,
)
from rapidtriage.core.files import CATEGORY_MAGICS
from rapidtriage.core.iso9660 import IsoFormatError, list_iso

FILETIME_2024 = int((dt.datetime(2024, 5, 1, 12, 0, tzinfo=dt.timezone.utc).timestamp() + 11644473600) * 10_000_000)
METHODS = {"store": 0, "deflate": 1, "bzip2": 2, "azo": 3, "lzma": 4}


def extra(signature: int, data: bytes, flag: int = 0) -> bytes:
    return struct.pack("<IBH", signature, flag, len(data)) + data


def lzma_block(data: bytes) -> bytes:
    """4-byte prefix + 5 LZMA properties + raw LZMA1 stream (the layout core.egg_archive reads)."""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}]
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    props = bytes([3 + 0 * 9 + 2 * 45]) + struct.pack("<I", 1 << 16)
    return b"\x00\x00\x00\x00" + props + raw


def compress(method: str, data: bytes) -> bytes:
    if method == "store":
        return data
    if method == "deflate":
        encoder = zlib.compressobj(9, zlib.DEFLATED, -15)
        return encoder.compress(data) + encoder.flush()
    if method == "bzip2":
        return bz2.compress(data)
    if method == "lzma":
        return lzma_block(data)
    return b"AZO-OPAQUE" + data[:4]


def egg_file(
    name: str,
    data: bytes,
    method: str = "deflate",
    *,
    encrypted: bool = False,
    name_encrypted: bool = False,
    file_id: int = 1,
) -> bytes:
    headers = struct.pack("<IIQ", EGG_FILE, file_id, len(data))
    headers += extra(EGG_FILENAME, name.encode("utf-8"), 0x08 if name_encrypted else 0)
    headers += extra(EGG_WINDOWS_INFO, struct.pack("<QB", FILETIME_2024, 0x20))
    if encrypted:
        headers += extra(EGG_ENCRYPT, b"\x02" + b"\x00" * 18)
    headers += struct.pack("<I", EGG_END)
    payload = compress(method, data)
    block = struct.pack("<IBBIII", EGG_BLOCK, METHODS[method], 0, len(data), len(payload), zlib.crc32(data) & 0xFFFFFFFF)
    block += struct.pack("<I", EGG_END) + payload
    return headers + block


def egg_archive(*files: bytes, solid: bool = False) -> bytes:
    head = b"EGGA" + struct.pack("<HII", 0x0100, 0x12345678, 0)
    if solid:
        head += extra(EGG_SOLID, b"")
    head += struct.pack("<I", EGG_END)
    return head + b"".join(files) + struct.pack("<I", EGG_END)


def alz_archive(entries: list[tuple[str, bytes, bool]]) -> bytes:
    out = b"ALZ\x01" + b"\x0a\x00\x00\x00"
    for name, data, encrypted in entries:
        raw_name = name.encode("cp949")
        descriptor = 0x40 | (0x01 if encrypted else 0)  # 4-byte size fields
        dos = ((2024 - 1980) << 25) | (5 << 21) | (1 << 16) | (12 << 11)
        out += b"BLZ\x01" + struct.pack("<HBIBB", len(raw_name), 0x20, dos, descriptor, 0)
        out += struct.pack("<BBI", 0, 0, zlib.crc32(data) & 0xFFFFFFFF) + struct.pack("<II", len(data), len(data))
        out += raw_name + (b"\x00" * 12 if encrypted else b"") + data
    return out + b"CLZ\x01" + b"\x00" * 8 + b"CLZ\x02"


def dir_record(name: bytes, extent: int, size: int, *, directory: bool) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    struct.pack_into("<I", record, 2, extent)
    struct.pack_into(">I", record, 6, extent)
    struct.pack_into("<I", record, 10, size)
    struct.pack_into(">I", record, 14, size)
    record[18:25] = bytes([124, 5, 1, 12, 30, 0, 36])  # 2024-05-01 12:30:00 +09:00
    record[25] = 0x02 if directory else 0x00
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def iso_image(*, joliet: bool = True, udf_only: bool = False) -> bytes:
    sector = 2048
    image = bytearray(sector * 40)
    if udf_only:
        image[16 * sector : 16 * sector + 6] = b"\x00BEA01"
        image[17 * sector : 17 * sector + 6] = b"\x00NSR02"
        return bytes(image)

    def descriptor(kind: int, root_extent: int, escape: bytes = b"") -> bytes:
        block = bytearray(sector)
        block[0] = kind
        block[1:6] = b"CD001"
        block[6] = 1
        block[40:72] = b"SYNTH_VOLUME".ljust(32)
        struct.pack_into("<I", block, 80, 40)
        struct.pack_into("<H", block, 128, sector)
        block[88 : 88 + len(escape)] = escape
        block[156:190] = dir_record(b"\x00", root_extent, sector, directory=True)
        block[813:830] = b"2024050112300000" + bytes([36])
        return bytes(block)

    image[16 * sector : 17 * sector] = descriptor(1, 20)
    if joliet:
        image[17 * sector : 18 * sector] = descriptor(2, 22, b"%/E")
        image[18 * sector] = 255
        image[18 * sector + 1 : 18 * sector + 6] = b"CD001"
    else:
        image[17 * sector] = 255
        image[17 * sector + 1 : 17 * sector + 6] = b"CD001"
    # Primary tree (8.3 names): / -> DOCS/ -> REPORT.PDF;1, SETUP.EXE;1
    primary_root = dir_record(b"\x00", 20, sector, directory=True) + dir_record(b"\x01", 20, sector, directory=True)
    primary_root += dir_record(b"DOCS", 21, sector, directory=True) + dir_record(b"SETUP.EXE;1", 30, 5, directory=False)
    image[20 * sector : 20 * sector + len(primary_root)] = primary_root
    primary_docs = dir_record(b"\x00", 21, sector, directory=True) + dir_record(b"\x01", 20, sector, directory=True)
    primary_docs += dir_record(b"REPORT.PDF;1", 31, 7, directory=False)
    image[21 * sector : 21 * sector + len(primary_docs)] = primary_docs
    # Joliet tree (UTF-16BE long names)
    joliet_root = dir_record(b"\x00", 22, sector, directory=True) + dir_record(b"\x01", 22, sector, directory=True)
    joliet_root += dir_record("문서".encode("utf-16-be"), 23, sector, directory=True)
    joliet_root += dir_record("setup.exe;1".encode("utf-16-be"), 30, 5, directory=False)
    image[22 * sector : 22 * sector + len(joliet_root)] = joliet_root
    joliet_docs = dir_record(b"\x00", 23, sector, directory=True) + dir_record(b"\x01", 22, sector, directory=True)
    joliet_docs += dir_record("보고서 최종.pdf;1".encode("utf-16-be"), 31, 7, directory=False)
    joliet_docs += dir_record("loop".encode("utf-16-be"), 22, sector, directory=True)  # loop back to root
    image[23 * sector : 23 * sector + len(joliet_docs)] = joliet_docs
    image[30 * sector : 30 * sector + 5] = b"MZ..."
    image[31 * sector : 31 * sector + 7] = b"%PDF-1."
    return bytes(image)


class EggTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def write(self, name: str, data: bytes) -> Path:
        path = self.base / name
        path.write_bytes(data)
        return path

    def test_methods_extract_and_list(self) -> None:
        body = "고객 명단 synthetic ".encode() * 50
        path = self.write(
            "leak.egg",
            egg_archive(
                egg_file("문서/stored.txt", body, "store", file_id=1),
                egg_file("문서/deflate.txt", body, "deflate", file_id=2),
                egg_file("bz.txt", body, "bzip2", file_id=3),
                egg_file("lz.txt", body, "lzma", file_id=4),
                egg_file("azo.bin", body, "azo", file_id=5),
            ),
        )
        listing = list_egg(path)
        self.assertEqual(listing["analysis_status"], "egg-parsed")
        entries = {entry["name"]: entry for entry in listing["entries"]}
        self.assertEqual(set(entries), {"문서/stored.txt", "문서/deflate.txt", "bz.txt", "lz.txt", "azo.bin"})
        for name in ("문서/stored.txt", "문서/deflate.txt", "bz.txt", "lz.txt"):
            self.assertTrue(entries[name]["crc_ok"], name)
            self.assertEqual(len(entries[name]["sha256"]), 64, name)
        self.assertIsNone(entries["azo.bin"]["sha256"])
        self.assertEqual(entries["azo.bin"]["extract_note"], "list-only-method:azo")
        self.assertEqual(entries["bz.txt"]["last_modified"], "2024-05-01T12:00:00Z")
        self.assertEqual(entries["bz.txt"]["uncompressed_size"], len(body))

    def test_encrypted_and_header_encrypted_are_listed_not_extracted(self) -> None:
        path = self.write(
            "secret.egg",
            egg_archive(egg_file("plan.xlsx", b"x" * 100, encrypted=True), egg_file("hidden", b"y" * 10, name_encrypted=True, file_id=2)),
        )
        listing = list_egg(path)
        plan = listing["entries"][0]
        self.assertTrue(plan["encrypted"])
        self.assertEqual(plan["encryption_method"], "aes-256")
        self.assertIsNone(plan["sha256"])
        self.assertTrue(listing["header_encrypted"])
        self.assertEqual(listing["entries"][1]["name_encoding"], "encrypted")

    def test_solid_is_list_only_and_corrupt_is_partial(self) -> None:
        solid = list_egg(self.write("solid.egg", egg_archive(egg_file("a.txt", b"a" * 20), solid=True)))
        self.assertTrue(solid["solid"])
        self.assertIsNone(solid["entries"][0]["sha256"])
        data = egg_archive(egg_file("a.txt", b"a" * 20), egg_file("b.txt", b"b" * 20, file_id=2))
        truncated = list_egg(self.write("cut.egg", data[: len(data) - 30]))
        self.assertEqual(truncated["analysis_status"], "egg-partial")
        self.assertEqual([entry["name"] for entry in truncated["entries"]], ["a.txt"])
        with self.assertRaises(ArchiveFormatError):
            list_egg(self.write("fake.egg", b"PK\x03\x04 not an egg"))

    def test_decompression_bomb_guard(self) -> None:
        bomb_data = b"\x00" * (4 * 1024 * 1024)
        listing = list_egg(self.write("bomb.egg", egg_archive(egg_file("zeros.bin", bomb_data, "deflate"))))
        entry = listing["entries"][0]
        self.assertEqual(entry["extract_note"], "decompression-guard")
        self.assertIsNone(entry["sha256"])

    def test_alz_listing(self) -> None:
        path = self.write("old.alz", alz_archive([("자료/명단.txt", b"hello", False), ("암호.doc", b"secret", True)]))
        listing = list_alz(path)
        self.assertEqual(listing["analysis_status"], "alz-parsed")
        names = [entry["name"] for entry in listing["entries"]]
        self.assertEqual(names, ["자료/명단.txt", "암호.doc"])
        self.assertTrue(listing["entries"][1]["encrypted"])
        self.assertEqual(listing["entries"][0]["last_modified"], "2024-05-01T12:00:00")
        cut = list_alz(self.write("cut.alz", alz_archive([("a.txt", b"x" * 50, False)])[:40]))
        self.assertEqual(cut["analysis_status"], "alz-partial")

    def test_magics_registered(self) -> None:
        ids = {item[0] for item in CATEGORY_MAGICS}
        self.assertTrue({"egg", "alz"} <= ids)


class IsoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_joliet_listing_with_loop_guard(self) -> None:
        path = self.base / "invoice.iso"
        path.write_bytes(iso_image())
        listing = list_iso(path)
        names = {entry["name"]: entry for entry in listing["entries"]}
        self.assertIn("문서/보고서 최종.pdf", names)
        self.assertIn("setup.exe", names)
        self.assertEqual(names["문서/보고서 최종.pdf"]["uncompressed_size"], 7)
        self.assertEqual(names["setup.exe"]["last_modified"], "2024-05-01T12:30:00+09:00")
        self.assertTrue(listing["volume"]["joliet"])
        self.assertEqual(listing["volume"]["volume_id"], "SYNTH_VOLUME")
        self.assertIn("directory-loop-skipped", listing["notes"])

    def test_primary_only_and_udf_only(self) -> None:
        path = self.base / "plain.iso"
        path.write_bytes(iso_image(joliet=False))
        names = {entry["name"] for entry in list_iso(path)["entries"]}
        self.assertEqual(names, {"DOCS", "DOCS/REPORT.PDF", "SETUP.EXE"})
        udf = self.base / "udf.iso"
        udf.write_bytes(iso_image(udf_only=True))
        listing = list_iso(udf)
        self.assertEqual((listing["analysis_status"], listing["udf_present"], listing["entries"]), ("udf-detected-not-listed", True, []))
        bad = self.base / "bad.iso"
        bad.write_bytes(b"\x00" * 100)
        with self.assertRaises(IsoFormatError):
            list_iso(bad)


class InventoryHookTests(unittest.TestCase):
    def test_archive_inventory_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pack.egg").write_bytes(egg_archive(egg_file("run.exe", b"MZ" * 10, encrypted=True), egg_file("in.zip", b"PK", file_id=2)))
            (root / "old.alz").write_bytes(alz_archive([("a.txt", b"a", False)]))
            (root / "disk.iso").write_bytes(iso_image())
            (root / "broken.egg").write_bytes(b"EGGA\x00")
            rows = {Path(record.path).name: record.details for record in collect_archive_inventory(root)}
        egg = rows["pack.egg"]
        self.assertEqual((egg["archive_format"], egg["entry_count"], egg["encrypted_entry_count"]), ("egg", 2, 1))
        self.assertEqual((egg["executable_entry_count"], egg["nested_archive_entry_count"]), (1, 1))
        self.assertIn("archive-encrypted-entry", egg["risk_flags"])
        self.assertEqual(rows["old.alz"]["archive_format"], "alz")
        iso = rows["disk.iso"]
        self.assertEqual(iso["archive_format"], "iso9660")
        self.assertEqual(iso["archive_inventory_profile"]["iso_volume"]["volume_id"], "SYNTH_VOLUME")
        broken = rows["broken.egg"]
        self.assertEqual(broken["coverage_status"], "egg-open-failed")
        self.assertIn("archive-open-failed", broken["risk_flags"])


if __name__ == "__main__":
    unittest.main()
