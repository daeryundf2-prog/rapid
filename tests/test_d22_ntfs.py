"""D22 review: MFT slot trust, USN rename paths, USB identifier conflicts,
hash-less compare, Recycle Bin 100 ns, SetupAPI case and ISO hundredths.

- A 4 KiB MFT slot is trusted for file-reference links only when its geometry
  and header agree; a clipped record with no intact neighbour keeps its slot
  (3, never 1 KiB slot 12) and links nothing (D22 1, D16 5).
- A serial and a ContainerID naming disjoint device sets join neither side;
  every candidate is kept (D22 3, D16 9).
- Without hashes, equal lengths are "content not verified", never a match (D22 9).
- A USN record written before a rename gets its own name's path; the current
  MFT name stays an observation (D22 12).
- Recycle Bin deletion times keep 100 ns ticks into the timeline (D22 15).
- SetupAPI instance IDs that differ only by case are one device (D22 16).
- ISO 9660 volume times keep hundredths of a second (D22 17).
"""

from __future__ import annotations

import datetime as dt
import struct
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows import registry, system
from rapidtriage.artifacts.windows.filesystem import WindowsFilesystemProvider
from rapidtriage.core.compare import compare_paths
from rapidtriage.core.iso9660 import list_iso
from rapidtriage.core.timeline import event_sort_key, extract_artifact_events
from tests.test_d16_ntfs_usb import (
    BASE_FILETIME,
    mft_file,
    recycle_v2,
    reference,
    setupapi_section,
    storage,
    usb,
    usn_record,
)
from tests.test_parser_quality_registry import HiveWriter, Key, write_hive
from tests.test_r5_l3_archives import iso_image


class MftSlotTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def collect(self, folder: Path, table: bytes, journal: bytes) -> tuple[dict[str, object], dict[str, object]]:
        folder.mkdir()
        (folder / "$MFT").write_bytes(table)
        (folder / "$J").write_bytes(journal)
        rows = list(WindowsFilesystemProvider().collect(folder))
        mft = next(
            row.details
            for row in rows
            if row.artifact_type == "mft-record" and row.details["record_offset"] == 3 * 4096
        )
        usn = next(row.details["usn_bounded_mft_path"] for row in rows if row.artifact_type == "usn-record")
        return mft, usn

    def test_slot_twelve_stays_unresolved_with_or_without_neighbours(self) -> None:
        size = 4096
        record = mft_file(3, 3, "third.txt", reference(5, 1), size=size)
        previous = mft_file(2, 3, "previous", reference(5, 1), size=size)
        for neighbour in (False, True):
            for trim in (0, 1):
                with self.subTest(neighbour=neighbour, trim=trim):
                    head = bytes(2 * size) + previous if neighbour else bytes(3 * size)
                    mft, usn = self.collect(
                        self.root / f"n{int(neighbour)}-t{trim}",
                        head + record[: size - trim],
                        usn_record("other.txt", 3, reference(5, 1), 12),
                    )
                    self.assertEqual(mft["record_number"], "3")
                    self.assertEqual(mft["record_number_header"], 3)
                    self.assertEqual(usn["path_candidate"], "")
                    self.assertFalse(usn["complete_within_bounded_mft_cache"])
                    if trim:
                        self.assertEqual(mft["record_geometry_status"], "damaged")
                    if trim and not neighbour:
                        # No intact record fixes the stride: the clipped
                        # record keeps its slot but is not trusted.
                        self.assertFalse(mft["record_number_trusted"])

    def test_clipped_record_without_neighbours_links_no_file_reference(self) -> None:
        size = 4096
        record = mft_file(3, 3, "third.txt", reference(5, 1), size=size)
        _, usn = self.collect(
            self.root / "slot3",
            bytes(3 * size) + record[: size - 1],
            usn_record("third.txt", 3, reference(5, 1), 3),
        )
        self.assertFalse(usn["file_reference_cache_hit"])
        self.assertEqual(usn["path_candidate"], "")

    def test_header_disagreement_is_not_trusted_for_links(self) -> None:
        size = 4096
        previous = mft_file(2, 3, "previous", reference(5, 1), size=size)
        record = mft_file(9, 3, "third.txt", reference(5, 1), size=size)
        mft, usn = self.collect(
            self.root / "header",
            bytes(2 * size) + previous + record,
            usn_record("third.txt", 3, reference(5, 1), 3),
        )
        self.assertEqual(mft["record_number"], "3")
        self.assertTrue(mft["record_number_header_mismatch"])
        self.assertFalse(mft["record_number_trusted"])
        self.assertFalse(usn["file_reference_cache_hit"])

    def test_intact_record_without_neighbours_is_trusted(self) -> None:
        size = 4096
        record = mft_file(3, 3, "third.txt", reference(5, 1), size=size)
        mft, usn = self.collect(
            self.root / "intact",
            bytes(3 * size) + record,
            usn_record("third.txt", 3, reference(5, 1), 3),
        )
        self.assertTrue(mft["record_number_trusted"])
        self.assertEqual(mft["record_geometry_status"], "consistent")
        self.assertTrue(usn["file_reference_cache_hit"])


class UsnRenameTests(unittest.TestCase):
    def test_record_before_rename_keeps_its_own_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table = bytearray(43 * 1024)
            for slot, sequence, name, parent, directory in (
                (5, 1, ".", reference(5, 1), True),
                (11, 4, "records", reference(5, 1), True),
                (42, 3, "new.txt", reference(11, 4), False),
            ):
                table[slot * 1024 : (slot + 1) * 1024] = mft_file(slot, sequence, name, parent, directory=directory)
            (root / "$MFT").write_bytes(table)
            journal = bytearray()
            for name, reason in (("old.txt", 0x1000), ("new.txt", 0x2000)):
                row = usn_record(name, 3, reference(11, 4))
                struct.pack_into("<q", row, 24, len(journal))
                struct.pack_into("<I", row, 40, reason)
                journal.extend(row)
            (root / "$J").write_bytes(journal)

            rows = {
                row.details["file_path"]: row.details["usn_bounded_mft_path"]
                for row in WindowsFilesystemProvider().collect(root)
                if row.artifact_type == "usn-record"
            }

        old = rows["old.txt"]
        self.assertEqual(old["path_candidate"], "\\records\\old.txt")
        self.assertEqual(old["current_mft_path"]["path"], "\\records\\new.txt")
        self.assertFalse(old["file_reference_link"]["current_mft_name_match"])
        self.assertNotEqual(old["status"], "matched-file-reference-cache")
        new = rows["new.txt"]
        self.assertEqual(new["path_candidate"], "\\records\\new.txt")
        self.assertEqual(new["status"], "matched-file-reference-cache")
        self.assertTrue(new["complete_within_bounded_mft_cache"])


class UsbDisjointCandidateTests(unittest.TestCase):
    def test_disjoint_serial_and_container_sets_stay_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            hive = Key("ROOT")
            hive.path("Select").value("Current", 4, (1).to_bytes(4, "little"))
            for pid, serial, container in (("1001", "COMMON", 1), ("1002", "COMMON", 2), ("1003", "SEPARATE", 3)):
                usb(hive, 1, pid, serial, container)
            for label, serial, container in (("Agree", "COMMON", 2), ("Unrelated", "COMMON", 3), ("NoSerial", "ABSENT", 3)):
                storage(hive, 1, label, serial, container)
            write_hive(root, "Windows/System32/config/SYSTEM", HiveWriter().build(hive))
            rows = {
                row.details["product"]: row.details
                for row in registry.WindowsRegistryProvider().collect(root)
                if row.artifact_type == "windows-usb-device"
            }

        unrelated = rows["Unrelated"]
        self.assertEqual(unrelated["pid"], "")
        self.assertEqual(unrelated["usb_join_method"], "conflict-serial-vs-container-id")
        self.assertEqual(
            sorted(item["pid"] for item in unrelated["usb_join_ambiguous_candidates"]), ["1001", "1002", "1003"]
        )
        self.assertEqual(rows["Agree"]["pid"], "1002")
        self.assertEqual(rows["Agree"]["usb_join_method"], "serial+container-id")
        self.assertEqual(rows["NoSerial"]["pid"], "1003")
        self.assertEqual(rows["NoSerial"]["usb_join_method"], "container-id")


class HashlessCompareTests(unittest.TestCase):
    def test_equal_length_is_not_a_content_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = root / "a.txt"
            left.write_bytes(b"alpha\n")
            right = root / "b.txt"
            outcomes = {}
            for label, value in (("same", b"alpha\n"), ("same-length", b"bravo\n"), ("other-length", b"charlie\n")):
                right.write_bytes(value)
                for hashed in (True, False):
                    result = compare_paths(left, right, hash_files=hashed)["results"][0]
                    outcomes[label, hashed] = (result["status"], result["summary"], bool(result["diff"].get("included")))
            binary_left = root / "a.bin"
            binary_right = root / "b.bin"
            binary_left.write_bytes(b"\x00\x01")
            binary_right.write_bytes(b"\x00\x02")
            binary = compare_paths(binary_left, binary_right, hash_files=False)["results"][0]

        self.assertEqual(outcomes["same", True][0], "same")
        self.assertEqual(outcomes["same-length", True][0], "different")
        self.assertEqual(outcomes["other-length", True][0], "different")
        # No hashes: identical text is still unverified, a text diff proves a difference.
        self.assertEqual(outcomes["same", False][0], "same-size-content-unverified")
        self.assertIn("content not verified", outcomes["same", False][1])
        self.assertNotIn("match", outcomes["same", False][1])
        self.assertEqual(outcomes["same-length", False], ("different", "a.txt differs from b.txt", True))
        self.assertEqual(outcomes["other-length", False][0], "different")
        self.assertEqual(binary["status"], "same-size-content-unverified")


class RecycleBinTickTests(unittest.TestCase):
    def test_deletion_ticks_reach_the_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
            folder.mkdir(parents=True)
            for label, tick in (("A", 7), ("B", 1), ("C", 10)):
                record = bytearray(recycle_v2("C:\\sample\\" + label + ".txt"))
                struct.pack_into("<Q", record, 16, BASE_FILETIME + tick)
                (folder / ("$I" + label)).write_bytes(record)
            rows = [row for row in WindowsFilesystemProvider().collect(root) if row.artifact_type == "recycle-bin-entry"]
            details = {Path(row.path).name: row.details for row in rows}
            events = extract_artifact_events(
                {"kind": "windows-filesystem", "artifacts": [row.to_dict() for row in rows]}, root
            )

        self.assertEqual(details["$IA"]["deleted_at_filetime"], BASE_FILETIME + 7)
        self.assertEqual(details["$IA"]["deleted_at_100ns"], "2024-01-01T00:00:00.0000007Z")
        deleted = [event for event in sorted(events, key=event_sort_key) if event.get("timestamp_kind") == "deleted"]
        self.assertEqual([Path(event["path"]).name for event in deleted], ["$IB", "$IA", "$IC"])
        self.assertEqual(
            [event["details"]["timestamp_utc_ticks"] for event in deleted],
            [str(BASE_FILETIME + 1), str(BASE_FILETIME + 7), str(BASE_FILETIME + 10)],
        )


class SetupApiCaseTests(unittest.TestCase):
    def test_instance_id_case_is_one_device(self) -> None:
        name = r"USB\VID_1234&PID_0001\UNIT1"
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "setupapi.dev.log"
            for spelling in (name, name.lower()):
                with self.subTest(spelling=spelling):
                    log.write_text(setupapi_section(1, body=f'dvi: Parameter = "{spelling}"'), encoding="ascii")
                    details = next(system.collect_setupapi_usb_artifacts(Path(tmp))).details
                    profile = details["usb_device_review_profile"]
                    self.assertEqual([entry["device_id"] for entry in details["install_entries"]], [name, spelling])
                    self.assertEqual(profile["device_count"], 1)
                    device = profile["devices"][0]
                    self.assertEqual(device["install_context_count"], 2)
                    self.assertEqual(device["device_id_spellings"], list(dict.fromkeys([name, spelling])))


class IsoVolumeTimeTests(unittest.TestCase):
    def test_hundredths_of_a_second_are_kept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "clock.iso"
            listings = {}
            for hundredths in ("00", "01", "99"):
                image = bytearray(iso_image(joliet=False))
                image[16 * 2048 + 813 + 14 : 16 * 2048 + 813 + 16] = hundredths.encode()
                path.write_bytes(image)
                listings[hundredths] = list_iso(path)

        for hundredths, listing in listings.items():
            with self.subTest(hundredths=hundredths):
                created = dt.datetime.fromisoformat(listing["volume"]["created_at"])
                self.assertEqual(created.microsecond, int(hundredths) * 10_000)
                self.assertEqual(created.utcoffset(), dt.timedelta(hours=9))
                self.assertEqual(created.replace(microsecond=0).isoformat(), "2024-05-01T12:30:00+09:00")
        # Directory records keep whole seconds and are unaffected.
        self.assertEqual(listings["00"]["entries"], listings["99"]["entries"])


if __name__ == "__main__":
    unittest.main()
