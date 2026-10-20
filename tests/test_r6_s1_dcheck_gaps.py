"""R6 S1 follow-up: parser gaps found by the D-drive existing-evidence check (validation §5.5).

Synthetic fixtures only: split (multi-volume) EGG sets, ZIP files named ``.egg`` and GOM Player
``_RECENTMEDIA*`` companions / key LastWrite in a synthetic NTUSER hive.
"""

from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.artifacts.generic import collect_archive_inventory
from rapidtriage.artifacts.windows.media_players import WindowsMediaPlayersProvider
from rapidtriage.core.egg_archive import EGG_END, EGG_SPLIT, list_egg
from rapidtriage.core.timeline import iter_artifact_detail_events
from tests import r5_l1_fixtures as fx
from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_DWORD,
    REG_SZ,
    HiveWriter,
    Key,
    dword,
    sz,
)
from tests.test_r5_l3_archives import egg_file, extra

IDS = (0x11111111, 0x22222222, 0x33333333)


def split_volumes(body: bytes, cuts: list[int], *, ids: tuple[int, ...] = IDS) -> list[bytes]:
    """EGG volumes: each has its own header with split prev/next IDs; ``body`` is cut at ``cuts``."""
    pieces = [body[a:b] for a, b in zip([0, *cuts], [*cuts, len(body)])]
    volumes = []
    for index, piece in enumerate(pieces):
        prev_id = ids[index - 1] if index else 0
        next_id = ids[index + 1] if index + 1 < len(pieces) else 0
        head = b"EGGA" + struct.pack("<HII", 0x0100, ids[index], 0)
        head += extra(EGG_SPLIT, struct.pack("<II", prev_id, next_id)) + struct.pack("<I", EGG_END)
        volumes.append(head + piece)
    return volumes


class SplitEggTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.one = egg_file("a.txt", b"alpha " * 40, "store", file_id=1)
        self.two = egg_file("문서/b.txt", "분할 경계 synthetic ".encode() * 60, "deflate", file_id=2)
        self.three = egg_file("c.bin", b"\x01\x02" * 50, "store", file_id=3)
        self.body = self.one + self.two + self.three + struct.pack("<I", EGG_END)
        # Cut 1 inside the header of b.txt, cut 2 inside b.txt's compressed data (spanning entry).
        self.cuts = [len(self.one) + 10, len(self.one) + len(self.two) - 15]

    def write_set(self, names: list[str], volumes: list[bytes]) -> list[Path]:
        paths = []
        for name, data in zip(names, volumes):
            if name:
                (self.base / name).write_bytes(data)
                paths.append(self.base / name)
        return paths

    def test_three_volumes_listed_as_one_stream(self) -> None:
        volumes = split_volumes(self.body, self.cuts)
        paths = self.write_set(["set.vol1.egg", "set.vol2.egg", "set.vol3.egg"], volumes)
        listing = list_egg(paths[0])
        self.assertEqual(listing["analysis_status"], "egg-parsed")
        self.assertEqual([entry["name"] for entry in listing["entries"]], ["a.txt", "문서/b.txt", "c.bin"])
        self.assertTrue(all(entry["crc_ok"] for entry in listing["entries"]))  # spanning entry decoded
        self.assertEqual(listing["split_volumes"], ["set.vol1.egg", "set.vol2.egg", "set.vol3.egg"])
        self.assertEqual((listing["volume_count"], listing["split_link"], listing["missing_volumes"]), (3, "header-id", []))
        self.assertTrue(listing["split"])

    def test_linked_by_header_ids_not_names(self) -> None:
        volumes = split_volumes(self.body, self.cuts)
        paths = self.write_set(["first.egg", "zz-renamed.egg", "aa-other.egg"], volumes)
        listing = list_egg(paths[0])
        self.assertEqual(listing["analysis_status"], "egg-parsed")
        self.assertEqual(listing["split_volumes"], ["first.egg", "zz-renamed.egg", "aa-other.egg"])
        self.assertEqual(len(listing["entries"]), 3)

    def test_missing_middle_volume_is_partial(self) -> None:
        volumes = split_volumes(self.body, self.cuts)
        paths = self.write_set(["set.vol1.egg", "", "set.vol3.egg"], volumes)
        listing = list_egg(paths[0])
        self.assertEqual(listing["analysis_status"], "egg-partial")
        self.assertEqual([entry["name"] for entry in listing["entries"]], ["a.txt"])
        self.assertEqual(listing["missing_volumes"], [{"volume_index": 2, "header_id": "22222222", "expected_name": "set.vol2.egg"}])
        self.assertIn("set.vol2.egg", listing["reason_ko"])
        self.assertIn("split-volume-missing", listing["notes"])

    def test_non_first_volume_lists_nothing(self) -> None:
        volumes = split_volumes(self.body, self.cuts)
        paths = self.write_set(["set.vol1.egg", "set.vol2.egg", "set.vol3.egg"], volumes)
        member = list_egg(paths[1])
        self.assertEqual((member["analysis_status"], member["entries"]), ("egg-split-member", []))
        self.assertEqual(member["split_first_volume"], "set.vol1.egg")
        self.assertEqual(member["reason_ko"], "분할 볼륨(첫 볼륨에서 목록)")

    def test_non_first_volume_alone(self) -> None:
        volumes = split_volumes(self.body, self.cuts)
        paths = self.write_set(["", "set.vol2.egg", ""], volumes)
        alone = list_egg(paths[0])
        self.assertEqual((alone["analysis_status"], alone["entries"]), ("egg-partial", []))
        self.assertTrue(alone["split_member"])
        self.assertIn("첫 볼륨이 없어", alone["reason_ko"])

    def test_inventory_lists_the_set_once(self) -> None:
        self.write_set(["set.vol1.egg", "set.vol2.egg", "set.vol3.egg"], split_volumes(self.body, self.cuts))
        rows = {Path(record.path).name: record.details for record in collect_archive_inventory(self.base)}
        self.assertEqual(rows["set.vol1.egg"]["entry_count"], 3)
        self.assertEqual(rows["set.vol1.egg"]["archive_inventory_profile"]["volume_count"], 3)
        for name in ("set.vol2.egg", "set.vol3.egg"):
            self.assertEqual(rows[name]["entry_count"], 0)
            self.assertEqual(rows[name]["coverage_status"], "egg-split-member")
            self.assertEqual(rows[name]["archive_inventory_profile"]["split_first_volume"], "set.vol1.egg")


class ZipNamedEggTests(unittest.TestCase):
    def test_zip_named_egg_is_routed_to_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with zipfile.ZipFile(root / "tool-1.0-py3.egg", "w") as archive:
                archive.writestr("EGG-INFO/PKG-INFO", "Name: tool\n")
                archive.writestr("tool/__init__.py", "")
            listing = list_egg(root / "tool-1.0-py3.egg")
            self.assertEqual((listing["analysis_status"], listing["format_mismatch"]), ("egg-format-mismatch", "zip"))
            self.assertIn("ZIP", listing["reason_ko"])
            rows = [record.details for record in collect_archive_inventory(root)]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coverage_status"], "zip-central-directory-parsed")
        self.assertEqual(rows[0]["entry_count"], 2)
        profile = rows[0]["archive_inventory_profile"]
        self.assertEqual((profile["format_mismatch"], profile["format_hint"]), ("zip", "zip"))


def gom_hive() -> bytes:
    root = Key("ROOT")
    option = root.path(r"Software\GRETECH\GomPlayer\OPTION")
    option.value("_RECENTMEDIANAME000", REG_SZ, sz("0123456789ABCDEF0123456789ABCDEF"))
    option.value("_RECENTMEDIAPOS000", REG_DWORD, dword(3236))
    option.value("_RECENTMEDIAAUDIOINDEX000", REG_DWORD, dword(1))
    option.value("_RECENTMEDIAAUDIOINDEXDVD000", REG_DWORD, dword(0))
    option.value("_RECENTMEDIANAME1", REG_SZ, sz("FEDCBA9876543210FEDCBA9876543210"))
    option.value("_RECENTMEDIAPOS1", REG_BINARY, b"\x10\x20")
    return HiveWriter().build(root)


class GomRecentTests(unittest.TestCase):
    def test_companions_key_time_and_timeline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = fx.home(root)
            (home / "NTUSER.DAT").write_bytes(gom_hive())
            records = [record for record in WindowsMediaPlayersProvider().collect(root) if record.artifact_type == "media-player-recent"]
        rows = {record.details["mru_order"]: record.details for record in records}
        first, second = rows[0], rows[1]
        self.assertEqual((first["resume_position_raw"], first["resume_position_raw_value"]), (3236, "3236"))
        self.assertEqual((first["audio_index_raw"], first["audio_index_dvd_raw"]), ("1", "0"))
        self.assertEqual(first["resume_position_value_name"], "_RECENTMEDIAPOS000")
        self.assertEqual((second["resume_position_raw"], second["resume_position_raw_value"]), (None, "1020"))
        self.assertEqual((second["audio_index_raw"], second["audio_index_dvd_raw"]), ("", ""))
        for row in (first, second):
            self.assertTrue(row["list_last_written"])
            self.assertEqual(row["key_last_written_at"], row["list_last_written"])
            self.assertEqual(row["key_path"], r"HKCU\Software\GRETECH\GomPlayer\OPTION")
            self.assertEqual(row["timestamp"], "")  # never a per-entry play time
        events = [event for row in (first, second) for event in iter_artifact_detail_events("media-player-recent", row)]
        self.assertEqual({event["timestamp_kind"] for event in events}, {"last-written"})
        self.assertEqual({event["scope"] for event in events}, {"key"})
        self.assertEqual(len({event["identity"] for event in events}), 1)  # one key -> one timeline event

    def test_ini_rows_have_no_timeline_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fx.vlc_files(fx.home(root))
            records = [record for record in WindowsMediaPlayersProvider().collect(root) if record.artifact_type == "media-player-recent"]
        self.assertTrue(records)
        for record in records:
            self.assertEqual(list(iter_artifact_detail_events("media-player-recent", record.details)), [])


if __name__ == "__main__":
    unittest.main()
