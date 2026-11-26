"""Generate Unified Log sidecars from synthetic addresses, strings and clock anchors."""
import random
import struct
import unittest
from unittest.mock import patch

from rapidtriage.artifacts import unified_sidecars as sidecars

UUID = "00112233445566778899aabbccddeeff"
BOOT = "11002200330044005500660077008800"
BASE_NS = 1_000_000_000_000_000_000


def make_uuidtext(entries, image_path):
    """Build UUIDText v2.1 from (virtual address, NUL-terminated bytes) pairs."""
    descriptors = b"".join(struct.pack("<II", start, len(data)) for start, data in entries)
    payload = b"".join(data for _, data in entries)
    return struct.pack("<4I", 0x66778899, 2, 1, len(entries)) + descriptors + payload + image_path.encode() + b"\0"


def make_dsc(version, address, text, image_path):
    """Build a shared-cache string file with one UTF-8 format and one image."""
    payload = text.encode() + b"\0"
    start = 60 if version == 1 else 72
    if version == 1:
        location = struct.pack("<4I", 0, address, start, len(payload))
        image = struct.pack("<II16sI", address, len(payload), bytes(16), start + len(payload))
    else:
        location = struct.pack("<QIIQ", address, start, len(payload), 0)
        image = struct.pack("<QI16sI", address, len(payload), bytes(16), start + len(payload))
    header = struct.pack("<IHHII", 0x64736368, version, 0, 1, 1)
    return header + location + image + payload + image_path.encode() + b"\0"


def make_timesync(boot_uuid, numerator, denominator, boot_ns, anchors):
    header = struct.pack(
        "<HHI16sIIqii", 0xBBB0, 48, 0, bytes.fromhex(boot_uuid), numerator, denominator, boot_ns, 0, 0,
    )
    return header + b"".join(struct.pack("<IIQqii", 0x207354, 0, ticks, ns, 0, 0) for ticks, ns in anchors)


class UnifiedSidecarTests(unittest.TestCase):
    def setUp(self):
        self.index = sidecars.Sidecars()

    def test_uuidtext_out_of_order_ranges_use_physical_order(self):
        entries = [(0x104, b"two\0"), (0x100, b"one\0"), (0x200, b"test\0value\0")]
        path = "/synthetic/demo"
        self.index.add_strings("uuidtext", UUID.upper(), make_uuidtext(entries, path))
        for addr, expected in [(0x100, "one"), (0x104, "two"), (0x205, "value"), (0x108, ""), (-1, "")]:
            self.assertEqual(self.index.resolve("uuidtext", UUID, addr), (expected, path))
        self.assertEqual(self.index.resolve("uuidtext", BOOT, 0x100), ("", ""))

    def test_string_does_not_cross_range_or_length_limit(self):
        entries = [(0, b"unterminated"), (20, b"other\0"), (100, b"x" * 4100 + b"\0")]
        self.index.add_strings("uuidtext", UUID, make_uuidtext(entries, "/synthetic/demo"))
        for addr in [0, 100]:
            self.assertEqual(self.index.resolve("uuidtext", UUID, addr)[0], "")

    def test_shared_cache_v1_v2_and_high_address(self):
        for version, addr in [(1, 0x010203), (2, 0x200010203)]:
            with self.subTest(version=version):
                index = sidecars.Sidecars()
                index.add_strings("dsc", UUID, make_dsc(version, addr, "통합 로그", "/synthetic/library"))
                self.assertEqual(index.resolve("dsc", UUID, addr), ("통합 로그", "/synthetic/library"))
                self.assertEqual(index.resolve("dsc", UUID, addr - 1), ("", ""))
                self.assertEqual(index.resolve("dsc", UUID, addr + len("통합 로그".encode()) + 1), ("", ""))

    def test_invalid_range_does_not_poison_following_table(self):
        blobs = [
            make_uuidtext([(32, b"long\0"), (33, b"x\0")], "/demo"),
            make_uuidtext([(32, b"only\0")], "/demo")[:-1],
            struct.pack("<4I", 0x66778899, 2, 1, 0xFFFFFFFF),
        ]
        for data in blobs:
            with self.assertRaises(sidecars.SidecarError):
                self.index.add_strings("uuidtext", UUID, data)
        invalid = bytearray(make_dsc(2, 20, "sample", "/demo"))
        struct.pack_into("<I", invalid, 24, 0xFFFFFFFF)
        with self.assertRaises(sidecars.SidecarError) as caught:
            self.index.add_strings("dsc", UUID, invalid)
        self.assertEqual(caught.exception.offset, 16)
        self.index.add_strings("uuidtext", UUID, make_uuidtext([(10, b"yes\0")], "/demo"))
        self.assertEqual(self.index.resolve("uuidtext", UUID, 10)[0], "yes")

    def test_clock_segments_choose_latest_preceding_anchor_and_exact_ratio(self):
        self.index.add_timesync(make_timesync(BOOT, 125, 3, BASE_NS, [(600, BASE_NS + 9_000)]))
        self.index.add_timesync(make_timesync(BOOT, 125, 3, BASE_NS, [(300, BASE_NS + 5_000)]))
        self.index.add_timesync(make_timesync(UUID, 1, 1, BASE_NS + 2_000_000_000, []))
        self.assertEqual(self.index.wall_time(BOOT, 3), "2001-09-09T01:46:40.000000125Z")
        self.assertEqual(self.index.wall_time(BOOT, 301), "2001-09-09T01:46:40.000005041Z")
        self.assertEqual(self.index.wall_time(BOOT, 600), "2001-09-09T01:46:40.000009000Z")
        self.assertEqual(self.index.wall_time(UUID, 0), "2001-09-09T01:46:42.000000000Z")
        self.assertEqual(self.index.wall_time("f" * 32, 600), "")

    def test_damaged_tail_keeps_previous_calibrations(self):
        data = make_timesync(BOOT, 1, 1, BASE_NS, [(80, BASE_NS + 1000)])
        with self.assertRaises(sidecars.SidecarError) as caught:
            self.index.add_timesync(data + b"Ts\x20\x00")
        self.assertEqual(caught.exception.offset, 80)
        self.assertEqual(self.index.wall_time(BOOT, 81), "2001-09-09T01:46:40.000001001Z")
        with self.assertRaisesRegex(sidecars.SidecarError, "timebase"):
            self.index.add_timesync(make_timesync(UUID, 0, 1, BASE_NS, []))
        self.assertEqual(self.index.wall_time(UUID, 10), "")

    def test_clock_record_at_tick_zero_takes_precedence_over_boot_time(self):
        stepped = BASE_NS - 1_070_000_000
        self.index.add_timesync(make_timesync(BOOT, 1, 1, BASE_NS, [(0, stepped), (500, BASE_NS)]), "boot.timesync")
        self.assertEqual(self.index.wall_time(BOOT, 10), "2001-09-09T01:46:38.930000010Z")
        self.assertEqual(self.index.clock_source(BOOT, 10), ("boot.timesync", 48))
        self.index.add_timesync(make_timesync(BOOT, 1, 1, BASE_NS, [(0, stepped)]))
        with self.assertRaises(sidecars.SidecarError) as caught:
            self.index.add_timesync(make_timesync(BOOT, 1, 1, BASE_NS + 1, []))
        self.assertEqual((str(caught.exception), caught.exception.offset), ("conflicting-timesync-boot-time", 32))

    def test_clock_source_tracks_preceding_record_across_files(self):
        first = make_timesync(BOOT, 1, 1, BASE_NS, [(100, BASE_NS + 41), (300, BASE_NS + 42)])
        second = make_timesync(BOOT, 1, 1, BASE_NS, [(200, BASE_NS + 43)])
        self.index.add_timesync(first, "first.timesync")
        self.index.add_timesync(second, "second.timesync")
        self.assertEqual(self.index.clock_source(BOOT, 0), ("first.timesync", 0))
        self.assertEqual(self.index.clock_source(BOOT, 199), ("first.timesync", 48))
        self.assertEqual(self.index.clock_source(BOOT, 299), ("second.timesync", 48))
        self.assertEqual(self.index.clock_source(BOOT, 300), ("first.timesync", 80))
        self.assertEqual(self.index.clock_source(UUID, 100), ("", 0))

    def test_high_tick_values_and_clock_limits(self):
        ticks = 2**60
        self.index.add_timesync(make_timesync(BOOT, 2, 1, BASE_NS, [(ticks, BASE_NS + 100)]))
        self.assertEqual(self.index.wall_time(BOOT, ticks + 1), "2001-09-09T01:46:40.000000102Z")
        self.index.add_timesync(make_timesync(UUID, 0xFFFFFFFF, 1, BASE_NS, []))
        self.assertEqual(self.index.wall_time(UUID, 2**64 - 1), "")
        with patch.object(sidecars, "MAX_CLOCK_RECORDS", 3), self.assertRaisesRegex(ValueError, "clock-record-limit"):
            self.index.add_timesync(make_timesync(UUID, 1, 1, BASE_NS, []))

    def test_bounded_index_is_shared_between_string_files(self):
        data = make_dsc(1, 1000, "ready", "/demo")
        with patch.object(sidecars, "MAX_DESCRIPTORS", 2):
            self.index.add_strings("dsc", UUID, data)
            with self.assertRaisesRegex(ValueError, "string-index-limit"):
                self.index.add_strings("dsc", BOOT, data)
            self.assertEqual(self.index.resolve("dsc", UUID, 1000), ("ready", "/demo"))

    def test_mutated_sidecars_are_bounded_and_errors_have_offsets(self):
        rng = random.Random(51)
        samples = [
            ("uuidtext", make_uuidtext([(12, b"demo\0")], "/demo")),
            ("dsc", make_dsc(2, 12, "demo", "/demo")),
            ("clock", make_timesync(BOOT, 1, 1, BASE_NS, [(12, BASE_NS + 12)])),
        ]
        for kind, original in samples:
            for _ in range(150):
                blob = bytearray(original)
                for _change in range(rng.randrange(1, 5)):
                    blob[rng.randrange(len(blob))] ^= rng.randrange(1, 256)
                blob = bytes(blob[:rng.randrange(len(blob) + 1)])
                index = sidecars.Sidecars()
                try:
                    if kind == "clock":
                        index.add_timesync(blob)
                        index.wall_time(BOOT, 12)
                    else:
                        index.add_strings(kind, UUID, blob)
                        index.resolve(kind, UUID, 12)
                except sidecars.SidecarError as exc:
                    self.assertGreaterEqual(exc.offset, 0)
                    self.assertLessEqual(exc.offset, len(blob))
