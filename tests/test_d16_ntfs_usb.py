"""D16 review: Recycle Bin, MFT/USN, USB and SetupAPI regressions.

- A ``$I`` entry pairs only with the ``$R`` file of the identical suffix; a
  double-extension sibling is another file (item 4).
- Truncated MFT records (short tail, rewritten allocated length) keep the
  volume slot geometry and never link a foreign file reference (item 5).
- A USN record whose parent slot was reused gets no historical path (item 6).
- A USBSTOR serial and ContainerID naming different devices in the same hive
  is reported as a conflict; a ContainerID shared by two devices keeps both
  candidates (item 9).
- SetupAPI sections past the 500th keep their times (item 20).
- Empty or truncated ``$I`` metadata is not "recycled, high" (item 21).
- Quoted SetupAPI device strings do not create a separate device (item 24).
"""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rapidtriage.artifacts.windows import registry, system
from rapidtriage.artifacts.windows.filesystem import (
    WindowsFilesystemProvider,
    collect_recycle_bin_artifacts,
)
from tests.test_d14_artefacts import mft_record
from tests.test_parser_quality_registry import REG_SZ, HiveWriter, Key, sz, write_hive
from tests.windows_artifact_fixtures import build_minimal_usn_journal

BASE_FILETIME = 133485408000000000


def recycle_v1(path: str) -> bytes:
    return struct.pack("<QQQ", 1, 7, BASE_FILETIME) + (path + "\0").encode("utf-16le").ljust(520, b"\0")


def recycle_v2(path: str) -> bytes:
    name = (path + "\0").encode("utf-16le")
    return struct.pack("<QQQI", 2, 8, BASE_FILETIME, len(name) // 2) + name


class RecycleBinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = self.root / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
        self.base.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def rows(self) -> dict[str, dict[str, object]]:
        return {Path(row.path).name: row.details for row in collect_recycle_bin_artifacts(self.root)}

    def test_payload_pairs_only_with_exact_suffix(self) -> None:
        path = "C:\\docs\\unit.txt"
        (self.base / "$IA.txt").write_bytes(recycle_v1(path))
        (self.base / "$IB.txt").write_bytes(recycle_v2(path))
        (self.base / "$IC.txt").write_bytes(recycle_v2(path))
        (self.base / "$RA.txt").write_bytes(b"1234567")
        (self.base / "$RB.txt").write_bytes(b"12345678")
        (self.base / "$RC.txt.txt").write_bytes(b"unrelated-file")

        rows = self.rows()

        for name, payload in (("$IA.txt", b"1234567"), ("$IB.txt", b"12345678")):
            with self.subTest(name=name):
                details = rows[name]
                self.assertTrue(str(details["paired_payload_path"]).endswith("$R" + name[2:]))
                self.assertEqual(details["paired_payload_hashes"]["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(details["coverage_status"], "i-r-pair-mapped")
                self.assertEqual(details["original_path"], path)
        orphan = rows["$IC.txt"]
        self.assertEqual(orphan["paired_payload_path"], "")
        self.assertEqual(orphan["paired_payload_hashes"], {})
        self.assertEqual(orphan["coverage_status"], "i-file-only")

    def test_empty_and_truncated_metadata_withhold_recycled_state(self) -> None:
        path = "C:\\docs\\unit.txt"
        (self.base / "$IA.txt").write_bytes(recycle_v1(path))
        (self.base / "$IB.txt").write_bytes(recycle_v2(path))
        (self.base / "$ID.txt").write_bytes(b"")
        (self.base / "$IE.txt").write_bytes(recycle_v2(path)[:-10])

        rows = self.rows()

        for name in ("$IA.txt", "$IB.txt"):
            with self.subTest(name=name):
                self.assertEqual(rows[name]["metadata_status"], "parsed")
                self.assertEqual(rows[name]["recovery"]["deletion_state"], "recycled")
                self.assertEqual(rows[name]["recovery"]["confidence"], "high")
        for name, status in (("$ID.txt", "unreadable"), ("$IE.txt", "partial")):
            with self.subTest(name=name):
                details = rows[name]
                self.assertEqual(details["metadata_status"], status)
                self.assertEqual(details["original_path"], "")
                self.assertNotEqual(details["recovery"]["deletion_state"], "recycled")
                self.assertNotEqual(details["recovery"]["confidence"], "high")
                self.assertTrue(details["metadata_issue"])


def mft_file(slot: int, sequence: int, name: str, parent: int, *, directory: bool = False, size: int = 1024) -> bytearray:
    data = bytearray(mft_record(size, slot))
    label = data.index("deleted.txt".encode("utf-16le"))
    field = label - 66
    data[field + 64] = len(name)
    data[label : label + len(name) * 2] = name.encode("utf-16le")
    struct.pack_into("<Q", data, field, parent)
    struct.pack_into("<H", data, 0x10, sequence)
    struct.pack_into("<H", data, 0x16, 3 if directory else 1)
    return data


def reference(slot: int, sequence: int) -> int:
    return sequence << 48 | slot


def usn_record(name: str, sequence: int, parent: int, slot: int = 42) -> bytearray:
    data = bytearray(build_minimal_usn_journal(name, datetime(2024, 1, 1, tzinfo=timezone.utc), 0x200))
    struct.pack_into("<QQ", data, 8, reference(slot, sequence), parent)
    return data


class MftUsnLinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_damaged_record_keeps_volume_slot_and_links_nothing_else(self) -> None:
        size = 4096
        for label, allocated, trim in (("control", 4096, 0), ("wrong-length", 1024, 0), ("clipped-last", 4096, 1)):
            with self.subTest(label=label):
                folder = self.root / label
                folder.mkdir()
                previous = mft_file(2, 3, "previous", reference(5, 1), size=size)
                record = mft_file(3, 3, "third.txt", reference(5, 1), size=size)
                struct.pack_into("<I", record, 0x1C, allocated)
                (folder / "$MFT").write_bytes(bytes(2 * size) + previous + record[: size - trim])
                (folder / "$J").write_bytes(usn_record("slot12.txt", 3, reference(5, 1), 12))

                rows = list(WindowsFilesystemProvider().collect(folder))

                mft = next(
                    row.details
                    for row in rows
                    if row.artifact_type == "mft-record" and row.details["record_offset"] == 3 * size
                )
                usn = next(row.details["usn_bounded_mft_path"] for row in rows if row.artifact_type == "usn-record")
                self.assertEqual(mft["record_number"], "3")
                self.assertFalse(mft["record_number_header_mismatch"])
                self.assertEqual(usn["path_candidate"], "")
                self.assertFalse(usn["complete_within_bounded_mft_cache"])
                if label == "control":
                    self.assertEqual(mft["record_geometry_status"], "consistent")
                else:
                    self.assertEqual(mft["record_geometry_status"], "damaged")
                    self.assertTrue(mft["record_geometry_issues"])
                    self.assertEqual(mft["validation_status"], "valid-with-warnings")

    def test_parent_generation_reuse_leaves_historic_path_unresolved(self) -> None:
        table = bytearray(43 * 1024)
        for slot, record in (
            (5, mft_file(5, 1, ".", reference(5, 1), directory=True)),
            (11, mft_file(11, 4, "newfolder", reference(5, 1), directory=True)),
            (42, mft_file(42, 3, "current.txt", reference(11, 4))),
        ):
            table[slot * 1024 : (slot + 1) * 1024] = record
        (self.root / "$MFT").write_bytes(table)
        journal = bytearray()
        for name, sequence, parent_sequence in (("former.txt", 3, 2), ("current.txt", 3, 4)):
            data = usn_record(name, sequence, reference(11, parent_sequence))
            struct.pack_into("<q", data, 24, len(journal))
            journal.extend(data)
        (self.root / "$J").write_bytes(journal)

        rows = {
            row.details["file_path"]: row.details["usn_bounded_mft_path"]
            for row in WindowsFilesystemProvider().collect(self.root)
            if row.artifact_type == "usn-record"
        }

        former = rows["former.txt"]
        self.assertTrue(former["file_reference_link"]["file_sequence_match"])
        self.assertFalse(former["file_reference_link"]["parent_sequence_match"])
        self.assertEqual(former["path_candidate"], "")
        self.assertFalse(former["complete_within_bounded_mft_cache"])
        self.assertEqual(former["status"], "unresolved-mft-parent-sequence-mismatch")
        self.assertIn("parent-reference-sequence-mismatch:usn=2,mft=4", former["file_reference_link"]["unresolved_reasons"])
        self.assertEqual(former["current_mft_path"]["path"], "\\newfolder\\current.txt")
        current = rows["current.txt"]
        self.assertEqual(current["path_candidate"], "\\newfolder\\current.txt")
        self.assertTrue(current["complete_within_bounded_mft_cache"])


def container(number: int) -> str:
    return "{00000000-0000-0000-0000-" + f"{number:012d}" + "}"


def usb(hive: Key, control_set: int, pid: str, instance: str, container_number: int) -> None:
    node = hive.path(f"ControlSet{control_set:03d}\\Enum\\USB\\VID_1234&PID_{pid}\\{instance}")
    node.value("ContainerID", REG_SZ, sz(container(container_number)))


def storage(hive: Key, control_set: int, name: str, instance: str, container_number: int) -> None:
    node = hive.path(f"ControlSet{control_set:03d}\\Enum\\USBSTOR\\Disk&Ven_Sample&Prod_{name}&Rev_1\\{instance}&0")
    node.value("ContainerID", REG_SZ, sz(container(container_number)))


class UsbJoinConflictTests(unittest.TestCase):
    def test_serial_and_container_conflict_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Rows carry resolved paths; on Windows the temp dir may be an 8.3 short name.
            root = Path(tmp).resolve()
            for label, current in (("A", 2), ("B", 1)):
                hive = Key("ROOT")
                hive.path("Select").value("Current", 4, current.to_bytes(4, "little"))
                for control_set in (1, 2):
                    usb(hive, control_set, f"{label}00{control_set}", "BASE", 1)
                    storage(hive, control_set, "Baseline", "BASE", 1)
                if label == "A":
                    usb(hive, current, "C001", "SHARED", 2)
                    usb(hive, current, "C002", "OTHER", 3)
                    storage(hive, current, "Conflict", "SHARED", 3)
                    usb(hive, current, "D001", "DIFF1", 4)
                    usb(hive, current, "D002", "DIFF2", 4)
                    storage(hive, current, "Ambiguous", "NO-SERIAL-MATCH", 4)
                write_hive(root, f"{label}/Windows/System32/config/SYSTEM", HiveWriter().build(hive))

            rows = {
                (Path(row.path).relative_to(root).parts[0], row.details["product"]): row.details
                for row in registry.WindowsRegistryProvider().collect(root)
                if row.artifact_type == "windows-usb-device"
            }

        self.assertEqual(rows[("A", "Baseline")]["pid"], "A002")
        self.assertEqual(rows[("B", "Baseline")]["pid"], "B001")
        conflict = rows[("A", "Conflict")]
        self.assertEqual(conflict["pid"], "")
        self.assertEqual(conflict["usb_join_method"], "conflict-serial-vs-container-id")
        self.assertEqual(sorted(item["pid"] for item in conflict["usb_join_ambiguous_candidates"]), ["C001", "C002"])
        ambiguous = rows[("A", "Ambiguous")]
        self.assertEqual(ambiguous["pid"], "")
        self.assertEqual(ambiguous["usb_join_method"], "ambiguous-container-id")
        self.assertEqual(sorted(item["pid"] for item in ambiguous["usb_join_ambiguous_candidates"]), ["D001", "D002"])


def setupapi_section(index: int, *, start: bool = True, body: str = "", status: str = "0x00000000") -> str:
    day = 1 + index % 20
    rows = [f">>>  [Device Install - USB\\VID_1234&PID_{index:04X}\\UNIT{index}]"]
    if start:
        rows.append(f">>>  2024/03/{day:02d} 12:34:56.789: Section start")
    rows.extend([body, f"<<<  [2024/03/{day:02d} 12:36:00.000: Section end]", f"<<<  [Exit Status({status})]", ""])
    return "\r\n".join(rows)


class SetupApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.log = Path(self.temp.name) / "setupapi.dev.log"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_sections_past_the_500th_keep_their_times(self) -> None:
        for count in (499, 500, 501):
            with self.subTest(count=count):
                self.log.write_bytes("".join(setupapi_section(i) for i in range(1, count + 1)).encode("ascii"))
                entries = system.parse_setupapi_usb_entries(self.log)
                self.assertEqual(len(entries), count)
                for index in (count - 1, count):
                    day = 1 + index % 20
                    entry = entries[index - 1]
                    self.assertTrue(str(entry["device_id"]).endswith(f"\\UNIT{index}"))
                    self.assertEqual(entry["section_start"], f"2024-03-{day:02d}T12:34:56.789")
                    self.assertEqual(entry["section_end"], f"2024-03-{day:02d}T12:36:00.000")

    def test_quoted_device_string_is_the_same_device(self) -> None:
        mention = 'dvi: Parameter = "USB\\VID_1234&PID_0001\\UNIT1"'
        self.log.write_bytes(
            (
                setupapi_section(1, body=mention)
                + setupapi_section(2, start=False)
                + setupapi_section(3, status="0x00000001")
            ).encode("ascii")
        )

        details = next(system.collect_setupapi_usb_artifacts(self.log.parent)).details

        self.assertEqual(details["usb_device_review_profile"]["device_count"], 3)
        first = [entry for entry in details["install_entries"] if str(entry["device_id"]).endswith("\\UNIT1")]
        self.assertEqual(len(first), 2)
        self.assertEqual({entry["device_id"] for entry in first}, {"USB\\VID_1234&PID_0001\\UNIT1"})
        self.assertEqual(len({entry["line_number"] for entry in first}), 2)
        self.assertFalse(details["scan_truncated"])


if __name__ == "__main__":
    unittest.main()
