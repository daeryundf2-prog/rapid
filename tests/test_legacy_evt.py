from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows.eventlog import WindowsEventLogProvider


def sample_record(number: int, *, source: str = "Source", event: int = 0xC0010017, text: str = "sample") -> bytes:
    names = f"{source}\0Node\0".encode("utf-16-le")
    insertions = f"{text}\0Ω\0".encode("utf-16-le")
    size = (56 + len(names) + len(insertions) + 7) & ~3
    record = bytearray(size)
    struct.pack_into("<I4s4I3H", record, 0, size, b"LfLe", number, 1, 3, event, 4, 2, 5)
    struct.pack_into("<I", record, 36, 56 + len(names))
    record[56 : 56 + len(names) + len(insertions)] = names + insertions
    struct.pack_into("<I", record, size - 4, size)
    return bytes(record)


def bounds(start: int, end: int, following: int, first: int, *, dirty: bool = False) -> tuple[bytes, bytes]:
    values = struct.pack("<4I", start, end, following, first)
    header = struct.pack("<I4sII", 48, b"LfLe", 1, 1) + values + struct.pack("<4I", 65536, int(dirty), 0, 48)
    eof = struct.pack("<5I", 40, 0x11111111, 0x22222222, 0x33333333, 0x44444444) + values + struct.pack("<I", 40)
    return header, eof


class LegacyEvtTests(unittest.TestCase):
    def parse(self, blob: bytes, name: str = "example.evt") -> tuple[list[dict], dict]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_bytes(blob)
            rows = list(WindowsEventLogProvider(record_detail="triage").collect(path.parent))
        self.assertLessEqual({row.artifact_type for row in rows}, {"eventlog-event", "eventlog-file", "eventlog-summary"})
        events = [row.details for row in rows if row.artifact_type == "eventlog-event"]
        files = [row.details for row in rows if row.artifact_type == "eventlog-file"]
        self.assertEqual(len(files), 1)
        self.assertEqual(len(events), files[0]["native_record_count"])
        return events, files[0]

    def test_fields_and_stale_record_after_eof(self):
        record = sample_record(12)
        header, eof = bounds(48, 48 + len(record), 13, 12)
        events, inventory = self.parse(header + record + eof + sample_record(13))
        self.assertEqual(inventory["native_parse_status"], "complete-active-record-walk")
        self.assertEqual(len(events), 1)
        row = events[0]
        self.assertEqual((row["record_id"], row["event_id"], row["event_id_qualifiers"]), ("12", "23", 0xC001))
        self.assertEqual((row["provider_name"], row["computer"]), ("Source", "Node"))
        self.assertEqual(row["timestamp"], "1970-01-01T00:00:01+00:00")
        self.assertEqual(row["evt_time_written"], "1970-01-01T00:00:03+00:00")
        self.assertEqual(row["event_data"], {"Insertion1": "sample", "Insertion2": "Ω"})
        self.assertEqual((row["evt_record_offset"], row["evt_record_size"]), (48, len(record)))

    def test_legacy_event_id_collision_and_triage_insertion_limits(self):
        text = "-".join(["000011"] * 8) + " " + "x" * 600
        record = sample_record(1, source="", event=4624, text=text)
        header, eof = bounds(48, 48 + len(record), 2, 1)
        events, inventory = self.parse(header + record + eof, "SecEvent.evt")
        self.assertEqual(len(events), 1)
        row = events[0]
        self.assertEqual((row["channel"], row["evt_channel_source"]), ("Security", "filename"))
        self.assertEqual(len(row["event_data"]["Insertion1"]), 512)
        self.assertTrue(row["event_data"]["Insertion1"].startswith("XXXXXX-"))
        self.assertEqual(row["event_data_truncated_fields"], ["Insertion1"])
        self.assertEqual(inventory["text_truncated_rows"], 1)

    def test_out_of_range_time_does_not_set_summary_bounds(self):
        records = bytearray()
        for index, generated in enumerate((1, 946684800, 0xFFFFFFFF), 1):
            record = bytearray(sample_record(index))
            struct.pack_into("<I", record, 12, generated)
            records.extend(record)
        header, eof = bounds(48, 48 + len(records), 4, 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "example.evt").write_bytes(header + records + eof)
            summary, = (r.details for r in WindowsEventLogProvider().collect(root) if r.artifact_type == "eventlog-summary")
        self.assertEqual(summary["event_count"], 3)
        self.assertEqual(summary["timestamp_out_of_range_count"], 2)
        self.assertEqual(summary["first_event_at"], "2000-01-01T00:00:00+00:00")
        self.assertEqual(summary["last_event_at"], summary["first_event_at"])

    def test_wrapped_split_record_and_padding(self):
        first, second = sample_record(7), sample_record(8)
        start = 300
        for split in (60, len(first)):
            with self.subTest(split=split):
                # A 12-byte unusable tail follows a whole first record in the second case.
                padding = struct.pack("<3I", 0x27, 0x27, 0x27) if split == len(first) else b""
                prefix = first[split:] + second
                header, eof = bounds(start, 48 + len(prefix), 9, 7)
                head = header + prefix + eof
                events, inventory = self.parse(head.ljust(start, b"\0") + first[:split] + padding)
                self.assertEqual(inventory["native_parse_status"], "complete-active-record-walk")
                self.assertEqual([r["record_id"] for r in events], ["7", "8"])
                self.assertEqual(events[1]["evt_record_offset"], 48 + len(first) - split)

    def test_fresh_empty_log_oldest_number_in_header_and_eof(self):
        header, _ = bounds(48, 48, 1, 0)
        _, eof = bounds(48, 48, 1, 1)
        events, inventory = self.parse(header + eof + bytes(64))
        self.assertEqual(events, [])
        self.assertEqual(inventory["native_parse_status"], "complete-active-record-walk")

    def test_dirty_header_requires_unique_consistent_eof(self):
        record = sample_record(4)
        header, _ = bounds(48, 48, 1, 0, dirty=True)
        end = 48 + len(record)
        _, eof = bounds(48, end, 5, 4)
        events, inventory = self.parse(header + record + eof)
        self.assertEqual(inventory["native_parse_status"], "complete-active-record-walk")
        self.assertEqual([r["record_id"] for r in events], ["4"])
        _, another = bounds(end + 40, end + 40, 5, 5)
        events, inventory = self.parse(header + record + eof + another)
        self.assertEqual(events, [])
        self.assertEqual(inventory["native_parse_status"], "ambiguous-dirty-eof")

    def test_damaged_record_never_crosses_confirmed_end(self):
        valid = sample_record(2)
        for damage in ("size", "trailer", "sequence", "strings"):
            with self.subTest(damage=damage):
                damaged = bytearray(sample_record(3))
                field, value = {
                    "size": (0, len(damaged) + 4),
                    "trailer": (len(damaged) - 4, 4),
                    "sequence": (8, 9),
                    "strings": (36, len(damaged) - 2),
                }[damage]
                struct.pack_into("<I", damaged, field, value)
                header, eof = bounds(48, 48 + len(valid) + len(damaged), 4, 2)
                events, inventory = self.parse(header + valid + damaged + eof)
                self.assertEqual([row["record_id"] for row in events], ["2"])
                self.assertTrue(inventory["native_parse_status"].startswith("invalid-"))
