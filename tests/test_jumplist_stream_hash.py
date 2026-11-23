"""D12: a CFB stream's SHA-256 covers the whole stream, not the parsed prefix.

Parsing keeps at most ``MAX_OLE_STREAM_BYTES`` (8 MiB) of a stream; the
hash recorded next to the full stream size must still be the SHA-256 of every
stream byte, and a broken sector chain must not present a prefix hash as the
stream hash.
"""

from __future__ import annotations

import hashlib
import struct
import unittest

from rapidtriage.artifacts.windows.recent_files import (
    MAX_OLE_STREAM_BYTES,
    parse_ole_compound_streams,
)
from tests.windows_artifact_fixtures import cfb_directory_entry

SECTOR = 512
END, FREE, FATSECT, DIFSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFC


def single_stream_cfb(payload: bytes) -> bytes:
    """CFB v3 (512-byte sectors, one DIFAT sector) holding one regular stream."""
    data_sectors = (len(payload) + SECTOR - 1) // SECTOR
    fat_sectors = 1
    while fat_sectors * 128 < data_sectors + fat_sectors + 2:
        fat_sectors += 1
    assert 109 < fat_sectors <= 236
    difat_sector, directory_sector, first_data = fat_sectors, fat_sectors + 1, fat_sectors + 2
    header = bytearray(SECTOR)
    header[:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<5H", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<9I", header, 40, 0, fat_sectors, directory_sector, 0, 4096, END, 0, difat_sector, 1)
    struct.pack_into("<109I", header, 76, *range(109))
    extra = list(range(109, fat_sectors))
    difat = struct.pack("<128I", *extra, *([FREE] * (127 - len(extra))), END)
    fat_entries = [FATSECT] * fat_sectors + [DIFSECT, END]
    fat_entries += list(range(first_data + 1, first_data + data_sectors)) + [END]
    fat_entries += [FREE] * (fat_sectors * 128 - len(fat_entries))
    fat = struct.pack(f"<{len(fat_entries)}I", *fat_entries)
    directory = cfb_directory_entry("Root Entry", 5, child_id=1, start_sector=END)
    directory += cfb_directory_entry("DestList", 2, start_sector=first_data, stream_size=len(payload))
    return bytes(header) + fat + difat + directory.ljust(SECTOR, b"\0") + payload.ljust(data_sectors * SECTOR, b"\0")


def synthetic_payload(size: int) -> bytes:
    block = hashlib.sha256(b"d12-synthetic-stream").digest()
    return (block * (size // len(block) + 1))[:size]


class CfbStreamHashTests(unittest.TestCase):
    def test_stream_hash_covers_every_byte_at_and_above_the_parse_cap(self) -> None:
        for size in (MAX_OLE_STREAM_BYTES, MAX_OLE_STREAM_BYTES + 1):
            with self.subTest(size=size):
                payload = synthetic_payload(size)
                (stream,) = parse_ole_compound_streams(single_stream_cfb(payload))
                self.assertEqual(stream["size"], size)
                self.assertEqual(stream["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(stream["hashed_bytes"], size)
                self.assertEqual(stream["sha256_scope"], "full-stream")
                self.assertEqual(stream["parsed_bytes"], min(size, MAX_OLE_STREAM_BYTES))

    def test_broken_chain_reports_prefix_hash_with_its_byte_range(self) -> None:
        payload = synthetic_payload(MAX_OLE_STREAM_BYTES + 1)
        container = single_stream_cfb(payload)
        cut = len(container) - 3 * SECTOR  # the last stream sectors are missing
        (stream,) = parse_ole_compound_streams(container[:cut])
        hashed = stream["hashed_bytes"]
        self.assertLess(hashed, len(payload))
        self.assertEqual(stream["sha256"], "")
        self.assertEqual(stream["sha256_scope"], "readable-prefix-only")
        self.assertEqual(stream["readable_prefix_sha256"], hashlib.sha256(payload[:hashed]).hexdigest())


if __name__ == "__main__":
    unittest.main()
