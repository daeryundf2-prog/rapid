"""Synthetic random-access journal fixtures. No local journal or native decoder required."""
import lzma
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts import journald

FILE_ID = bytes(range(16, 32))


def data_hash(payload, flag, keyed):
    """The stored DATA hash: of the uncompressed payload, keyed by the file ID when requested."""
    if flag == 1:
        try:
            payload = lzma.decompress(payload)
        except lzma.LZMAError:
            return 0
    elif flag:
        return 0  # opaque LZ4/ZSTD fixtures cannot be hashed
    return journald._siphash24(payload, FILE_ID) if keyed else journald._jenkins_hash64(payload)


def make_journal(entries, *, compact=False, keyed=False, state=0):
    """Build indexed ENTRY/DATA objects whose item and DATA hash words match the payloads."""
    data = bytearray(272)
    data[:8] = b"LPKSHHRH"
    data[16] = state
    data[24:40] = FILE_ID
    offsets = {"entries": [], "arrays": [], "data": []}
    objects = []
    header_flags = (16 if compact else 0) | (4 if keyed else 0)

    def append(kind, payload, flags=0):
        offset = len(data)
        objects.append(offset)
        data.extend(struct.pack("<BB6xQ", kind, flags, 16 + len(payload)) + payload)
        data.extend(bytes(-len(data) % 8))
        return offset

    data_table = append(4, bytes(16))
    field_table = append(5, bytes(16))
    for sequence, fields in enumerate(entries, 1):
        items = bytearray()
        for field in fields:
            flag, payload = field if isinstance(field, tuple) else (0, field)
            header_flags |= {0: 0, 1: 1, 2: 2, 4: 8}[flag]
            hash_word = data_hash(payload, flag, keyed)
            metadata = struct.pack("<6Q", hash_word, 0, 0, 0, 0, 1)
            if compact:
                metadata += bytes(8)
            address = append(1, metadata + payload, flag)
            offsets["data"].append(address)
            items.extend(struct.pack("<I", address) if compact else struct.pack("<QQ", address, hash_word))
        info = struct.pack("<QQQ16sQ", sequence, sequence * 1_000_001, sequence * 50, bytes(range(16)), 0)
        offset = append(3, info + items)
        offsets["entries"].append(offset)
        for address in offsets["data"][-len(fields):] if fields else ():
            struct.pack_into("<Q", data, address + 40, offset)
        # One global array per entry makes a later damaged link testable.
        array = append(6, bytes(8) + struct.pack("<I" if compact else "<Q", offset))
        if offsets["arrays"]:
            struct.pack_into("<Q", data, offsets["arrays"][-1] + 16, array)
        offsets["arrays"].append(array)
    struct.pack_into("<I", data, 12, header_flags)
    struct.pack_into("<8Q", data, 88, 272, len(data) - 272, data_table + 16, 16, field_table + 16, 16,
                     objects[-1], len(objects))
    struct.pack_into("<4Q", data, 152, len(entries), len(entries), int(bool(entries)),
                     offsets["arrays"][0] if entries else 0)
    return data, offsets


class JournalTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "evidence"
        self.path = self.root / "var/log/journal/machine/sample.journal"
        self.path.parent.mkdir(parents=True)

    def rows(self, data):
        self.path.write_bytes(data)
        return [row.details for row in journald.JournaldProvider().collect(self.root)]

    def test_regular_and_compact_entries_with_both_hash_modes(self):
        expected = {
            "_HOSTNAME": "test.invalid", "_SYSTEMD_UNIT": "sample.service", "_COMM": "sample", "_EXE": "/bin/sample",
            "_CMDLINE": "sample run", "_UID": "1000", "_PID": "24", "PRIORITY": "6",
            "SYSLOG_IDENTIFIER": "unit-test", "MESSAGE": "합성 메시지", "_BOOT_ID": bytes(range(16)).hex(),
        }
        fields = [f"{key}={value}".encode() for key, value in expected.items()]
        fields += [b"EXTRA=one", b"EXTRA=two", b"BINARY=\xff\x00"]
        for compact in (False, True):
            for keyed in (False, True):
                with self.subTest(compact=compact, keyed=keyed):
                    data, offsets = make_journal([fields, [b"MESSAGE=next"]], compact=compact, keyed=keyed)
                    first, second = self.rows(data)
                    self.assertEqual(first["fields"], {
                        **expected, "__REALTIME_TIMESTAMP": 1_000_001, "__MONOTONIC_TIMESTAMP": 50,
                        "EXTRA": ["one", "two"], "BINARY": {"encoding": "base64", "data": "/wA="},
                    })
                    self.assertEqual(first["timestamp"], "1970-01-01T00:00:01.000001+00:00")
                    self.assertEqual(first["journal_state"], "offline")
                    self.assertEqual(first["coverage_status"], "parsed")
                    self.assertEqual(first["compact"], compact)
                    self.assertEqual(first["keyed_hash"], keyed)
                    self.assertEqual(first["source_offset"], offsets["entries"][0])
                    self.assertEqual(first["length"], 64 + len(fields) * (4 if compact else 16))
                    self.assertEqual(first["entry_array_offset"], offsets["arrays"][0])
                    self.assertEqual(first["data_offsets"], offsets["data"][:-1])
                    self.assertEqual(second["sequence_number"], 2)
                    self.assertEqual(second["fields"]["_BOOT_ID"], bytes(range(16)).hex())

    def test_xz_large_and_unsupported_compression_and_dirty_file(self):
        value = "긴메시지" * 20_000
        fields = [(1, lzma.compress(("MESSAGE=" + value).encode())), (2, b"opaque-lz4"), (4, b"opaque-zstd")]
        data, offsets = make_journal([fields], compact=True, keyed=True, state=1)
        self.path = self.path.with_suffix(".journal~")
        dirty, row = self.rows(data)
        self.assertEqual((dirty["reason"], dirty["source_offset"]), ("online-state", 16))
        self.assertEqual(row["journal_state"], "online")
        self.assertEqual(row["coverage_status"], "partial")
        self.assertEqual(row["fields"]["MESSAGE"], value)
        self.assertEqual(row["limitations"], [
            {"reason": "compressed-unsupported", "source_offset": address, "codec": codec,
             "format_reference": journald.FORMAT_REFERENCE, "reference_offset": offsets["entries"][0] + 64 + idx * 4}
            for idx, (codec, address) in enumerate(zip(("LZ4", "ZSTD"), offsets["data"][1:]), 1)
        ])

    def test_capped_and_invalid_xz_keep_other_fields(self):
        data, _ = make_journal([[
            (1, lzma.compress(b"MESSAGE=" + b"a" * journald.MAX_PAYLOAD)),
            (1, lzma.compress(b"BAD=truncated")[:-5]), b"PRIORITY=5",
        ]])
        row, = self.rows(data)
        self.assertEqual(row["fields"]["PRIORITY"], "5")
        self.assertNotIn("MESSAGE", row["fields"])
        self.assertEqual([issue["reason"] for issue in row["limitations"]], ["field-size-limit", "invalid-xz"])

    def test_bad_references_leave_other_fields_and_entries(self):
        data, offsets = make_journal([[b"MESSAGE=keep", b"EXTRA=bad", b"SECOND=bad"], [b"MESSAGE=later"]])
        entry = offsets["entries"][0]
        struct.pack_into("<Q", data, entry + 64 + 16, 123)
        struct.pack_into("<Q", data, entry + 64 + 32 + 8, 99)
        first, second = self.rows(data)
        self.assertEqual(first["fields"]["MESSAGE"], "keep")
        # A disagreeing item hash is flagged; the readable value is kept for review.
        self.assertEqual(first["fields"]["SECOND"], "bad")
        self.assertEqual(first["coverage_status"], "partial")
        self.assertEqual(first["limitations"], [
            {"source_offset": 123, "reason": "invalid-object-offset", "reference_offset": entry + 80},
            {"source_offset": offsets["data"][2], "reason": "item-hash-mismatch", "reference_offset": entry + 96,
             "item_hash": "0000000000000063", "data_hash": f"{data_hash(b'SECOND=bad', 0, False):016x}"},
        ])
        self.assertEqual(second["fields"]["MESSAGE"], "later")

    def test_hash_functions_match_reference_vectors(self):
        # lookup3.c (public domain) driver vectors and hashlittle2 output for the same inputs.
        self.assertEqual(journald._jenkins_hash64(b""), 0xDEADBEEFDEADBEEF)
        self.assertEqual(journald._jenkins_hash64(b"Four score and seven years ago"), 0x17770551CE7226E6)
        self.assertEqual(journald._jenkins_hash64(b"A" * 12), 0x02EEA781C8B1BAD4)
        self.assertEqual(journald._jenkins_hash64(b"MESSAGE=hello"), 0x87DDEFF2FD1BD06D)
        # SipHash-2-4 paper (Appendix A) and reference vectors.h, key 00..0f.
        key = bytes(range(16))
        self.assertEqual(journald._siphash24(bytes(range(15)), key), 0xA129CA6149BE45E5)
        self.assertEqual(journald._siphash24(b"", key), 0x726FDB47DD0E0E31)
        self.assertEqual(journald._siphash24(b"MESSAGE=hello", key), 0xC1E47240469D2E88)

    def test_data_hash_recomputed_with_the_file_hash_function(self):
        for compact in (False, True):
            for keyed in (False, True):
                with self.subTest(compact=compact, keyed=keyed):
                    data, offsets = make_journal(
                        [[b"MESSAGE=keep", (1, lzma.compress(b"XZ=value"))]], compact=compact, keyed=keyed)
                    row, = self.rows(data)
                    self.assertEqual(row["coverage_status"], "parsed")
                    message = offsets["data"][0]
                    prefix = 72 if compact else 64
                    data[message + prefix + 9] = ord("E")
                    row, = self.rows(data)
                    self.assertEqual(row["fields"]["MESSAGE"], "kEep")
                    self.assertEqual(row["limitations"], [{
                        "reason": "data-hash-mismatch", "source_offset": message,
                        "reference_offset": offsets["entries"][0] + 64,
                        "hash_function": "siphash24" if keyed else "jenkins-lookup3",
                        "data_hash": f"{data_hash(b'MESSAGE=keep', 0, keyed):016x}",
                        "computed_hash": f"{data_hash(b'MESSAGE=kEep', 0, keyed):016x}",
                    }])
        # The keyed hash depends on the file ID; the Jenkins hash does not.
        for keyed in (False, True):
            data, _ = make_journal([[b"MESSAGE=keep"]], keyed=keyed)
            data[24] ^= 1
            row, = self.rows(data)
            self.assertEqual([issue["reason"] for issue in row["limitations"]], ["data-hash-mismatch"] if keyed else [])

    def test_realtime_validity_and_raw_clock_values(self):
        data, offsets = make_journal([[b"MESSAGE=x"]])
        entry = offsets["entries"][0]
        for realtime, expected in ((1, "1970-01-01T00:00:00.000001+00:00"),
                                   (1_764_115_200_123_456, "2025-11-26T00:00:00.123456+00:00"),
                                   (2**55 - 1, "3111-09-16T23:10:18.963967+00:00"), (0, None), (2**55, None)):
            with self.subTest(realtime=realtime):
                struct.pack_into("<Q", data, entry + 24, realtime)
                row, = self.rows(data)
                self.assertEqual(row["timestamp"], expected)
                self.assertEqual((row["realtime_raw"], row["monotonic_raw"]), (realtime, 50))
                self.assertEqual(row["fields"]["__REALTIME_TIMESTAMP"], realtime)
                self.assertEqual([issue["reason"] for issue in row["limitations"]],
                                 [] if expected else ["timestamp-out-of-range"])

    def test_sequence_and_monotonic_validity_are_checked_separately(self):
        # systemd journal-file.c check_object(): seqnum > 0 and VALID_MONOTONIC (< 2^55).
        data, offsets = make_journal([[b"MESSAGE=x"]])
        entry = offsets["entries"][0]
        cases = (((1, 0), []), ((1, 2**55 - 1), []), ((0, 0), [("invalid-sequence-number", 16)]),
                 ((1, 2**55), [("monotonic-out-of-range", 32)]), ((1, 2**64 - 1), [("monotonic-out-of-range", 32)]),
                 ((0, 2**55), [("invalid-sequence-number", 16), ("monotonic-out-of-range", 32)]))
        for (sequence, monotonic), expected in cases:
            with self.subTest(sequence=sequence, monotonic=monotonic):
                struct.pack_into("<Q", data, entry + 16, sequence)
                struct.pack_into("<Q", data, entry + 32, monotonic)
                row, = self.rows(data)
                self.assertEqual((row["sequence_number"], row["monotonic_raw"]), (sequence, monotonic))
                self.assertEqual(row["fields"]["__MONOTONIC_TIMESTAMP"], monotonic)
                self.assertEqual(row["timestamp"], "1970-01-01T00:00:01.000001+00:00")
                self.assertEqual([(i["reason"], i["source_offset"] - entry) for i in row["limitations"]], expected)
                self.assertEqual(row["coverage_status"], "partial" if expected else "parsed")

    def test_stored_reserved_clock_field_is_kept_and_flagged(self):
        data, offsets = make_journal([[b"__REALTIME_TIMESTAMP=5", b"MESSAGE=x"]])
        row, = self.rows(data)
        self.assertEqual(row["fields"]["__REALTIME_TIMESTAMP"], "5")
        self.assertEqual(row["realtime_raw"], 1_000_001)
        self.assertEqual(row["timestamp"], "1970-01-01T00:00:01.000001+00:00")
        self.assertEqual(row["limitations"], [{"reason": "reserved-timestamp-field",
                                               "source_offset": offsets["entries"][0] + 24,
                                               "field": "__REALTIME_TIMESTAMP"}])

    def test_file_cap_follows_sorted_paths(self):
        data, _ = make_journal([[b"MESSAGE=x"]])
        for name in ("system@b.journal", "system@a.journal~", "system.journal"):
            (self.path.parent / name).write_bytes(data)
        with patch.object(journald, "MAX_FILES", 2):
            rows = list(journald.JournaldProvider().collect(self.root))
        self.assertEqual([Path(row.path).name for row in rows],
                         ["system.journal", "system@a.journal~", "system@b.journal"])
        self.assertEqual(rows[-1].details["reason"], "file-limit")

    def test_header_and_conflicting_boot_field_preserved_with_offsets(self):
        data, offsets = make_journal([[b"_BOOT_ID=" + b"1" * 32]])
        row, = self.rows(data)
        self.assertEqual(row["boot_id"], bytes(range(16)).hex())
        self.assertEqual(row["fields"]["_BOOT_ID"], "1" * 32)
        self.assertEqual(row["limitations"], [{
            "reason": "boot-id-mismatch", "source_offset": offsets["data"][0],
            "reference_offset": offsets["entries"][0] + 64, "entry_boot_id_offset": offsets["entries"][0] + 40,
        }])

    def test_unused_final_array_capacity_is_not_read_as_entries(self):
        for compact in (False, True):
            data, offsets = make_journal([[b"MESSAGE=allocated"]], compact=compact)
            array = offsets["arrays"][0]
            capacity = 16384
            size = 24 + capacity * (4 if compact else 8)
            data.extend(bytes(array + size - len(data)))
            struct.pack_into("<Q", data, array + 8, size)
            struct.pack_into("<Q", data, 96, len(data) - 272)
            # The budget allows the header and single indexed item, not the zero-filled tail.
            with patch.object(journald, "MAX_BYTES", 1024):
                row, = self.rows(data)
            self.assertEqual(row["fields"]["MESSAGE"], "allocated")
            self.assertEqual(row["coverage_status"], "parsed")

    def test_bad_array_target_and_truncated_final_array(self):
        data, offsets = make_journal([[b"MESSAGE=first"], [b"MESSAGE=second"]])
        rows = self.rows(data[:-4])
        self.assertEqual([r.get("reason", "entry") for r in rows],
                         ["truncated-arena", "entry", "truncated-array", "incomplete-entry-index"])
        self.assertEqual(rows[1]["fields"]["MESSAGE"], "first")
        array = offsets["arrays"][0]
        struct.pack_into("<Q", data, array + 16, array)
        first, diag = self.rows(data)
        self.assertEqual(first["source_offset"], offsets["entries"][0])
        self.assertEqual((diag["reason"], diag["source_offset"]), ("entry-array-cycle", array))

    def test_invalid_entry_target_does_not_hide_later_entry(self):
        data, offsets = make_journal([[b"MESSAGE=first"], [b"MESSAGE=last"]])
        struct.pack_into("<Q", data, offsets["arrays"][0] + 24, offsets["data"][0])
        issue, row = self.rows(data)
        self.assertEqual(issue["reason"], "unexpected-object-type")
        self.assertEqual(row["fields"]["MESSAGE"], "last")

    def test_short_header_invalid_features_and_timestamp_range(self):
        self.assertEqual(self.rows(b"short")[0]["reason"], "truncated-read")
        data, offsets = make_journal([[b"MESSAGE=x"]], state=2)
        struct.pack_into("<Q", data, offsets["entries"][0] + 24, 2**64 - 1)
        row, = self.rows(data)
        self.assertEqual(row["journal_state"], "archived")
        self.assertIsNone(row["timestamp"])
        self.assertEqual(row["fields"]["__REALTIME_TIMESTAMP"], 2**64 - 1)
        self.assertEqual(row["limitations"][0]["reason"], "timestamp-out-of-range")
        struct.pack_into("<I", data, 12, 32)
        self.assertEqual(self.rows(data)[0]["reason"], "unsupported-incompatible-flags")

    def test_limits_on_decoded_rows_fields_bytes_and_files(self):
        data, _ = make_journal([[b"A=first", b"B=capped"], [b"MESSAGE=later"]])
        with patch.object(journald, "MAX_FIELDS", 1), patch.object(journald, "MAX_ENTRIES", 1):
            first, issue = self.rows(data)
        self.assertEqual(first["fields"]["A"], "first")
        self.assertNotIn("B", first["fields"])
        self.assertEqual(first["limitations"][0]["reason"], "field-count-limit")
        self.assertEqual(issue["reason"], "entry-limit")
        with patch.object(journald, "MAX_BYTES", 208):
            self.assertEqual(self.rows(data)[0]["reason"], "byte-limit")
        with patch.object(journald, "MAX_DATA_REFS", 2):
            first, issue = self.rows(data)
            self.assertEqual(first["fields"]["A"], "first")
            self.assertEqual(issue["reason"], "data-reference-limit")
        with patch.object(journald, "MAX_FILES", 0):
            self.assertEqual(self.rows(data)[0]["reason"], "file-limit")

    def test_discovery_confined_to_journal_directory(self):
        data, _ = make_journal([[b"MESSAGE=outside"]])
        outside = self.root.parent / "outside.journal"
        outside.write_bytes(data)
        (self.root / "var/log/other.journal").write_bytes(data)
        self.path.symlink_to(outside)
        provider = journald.JournaldProvider()
        self.assertEqual(list(provider.collect(self.root)), [])
        other_root = self.root.parent / "other-root"
        other_root.mkdir()
        (other_root / "var").symlink_to(self.root / "var", target_is_directory=True)
        self.path.unlink()
        self.path.write_bytes(data)
        self.assertEqual(list(provider.collect(other_root)), [])
