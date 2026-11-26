"""Synthetic NTUSER and UTF-16 .reg equivalents for Explorer taskbar activity."""

from __future__ import annotations

import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts.windows.registry import (
    WindowsRegistryProvider,
    filetime_to_iso_ticks,
)
from rapidtriage.artifacts.windows.registry_depth import EXPLORER
from rapidtriage.artifacts.windows.taskband import decode_taskband_value
from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_DWORD,
    HiveWriter,
    Key,
    dword,
    write_hive,
)

FEATURES = ("AppSwitched", "AppLaunch", "ShowJumpView", "AppBadgeUpdated", "TrayButtonClicked")
TICKS = 133_801_632_000_000_007
APP = r"C:\가상\실험.exe"
SID = "S-1-5-21-100-200-300-1001"


def pidl(path_name: str) -> bytes:
    # A drive item, a file entry with a Unicode primary name, and a TerminalID.
    drive = b"\x07\x00\x2fC:\x5c\x00"
    entry = b"\x36" + bytes(11) + path_name.encode("utf-16-le") + bytes(2)
    return drive + (len(entry) + 2).to_bytes(2, "little") + entry + bytes(2)


def lnk(path_name: str) -> bytes:
    # A ShellLinkHeader, Unicode RelativePath StringData and TerminalBlock.
    header = bytearray(76)
    header[0:4] = dword(76)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    header[20:24] = dword(0x88)
    value = path_name.encode("utf-16-le")
    return bytes(header) + (len(value) // 2).to_bytes(2, "little") + value + bytes(4)


def property_store_block(app_id: str) -> bytes:
    from uuid import UUID

    # Serialized Property Storage for PKEY_AppUserModel_ID, VT_LPWSTR.
    raw = (app_id + "\0").encode("utf-16-le")
    typed = dword(0x1F) + dword(len(raw) // 2) + raw
    prop = dword(9 + len(typed)) + dword(5) + bytes(1) + typed
    fmtid = UUID("9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3").bytes_le
    storage = dword(28 + len(prop)) + b"1SPS" + fmtid + prop + bytes(4)
    return dword(12 + len(storage)) + dword(0xA0000009) + storage + bytes(4)


def full_lnk(item_list: bytes, local_path: str, app_id: str) -> bytes:
    # IDList, LinkInfo with a VolumeID and LocalBasePath, Unicode NAME_STRING, property store.
    header = bytearray(76)
    header[0:4] = dword(76)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    header[20:24] = dword(0x1 | 0x2 | 0x4 | 0x80)
    volume = dword(17) + dword(3) + dword(0x1234) + dword(16) + b"\0"
    base = local_path.encode("ascii") + b"\0"
    info = dword(28) + dword(1) + dword(28) + dword(28 + len(volume)) + dword(0) + dword(28 + len(volume) + len(base))
    info = dword(4 + len(info) + len(volume) + len(base) + 1) + info + volume + base + b"\0"
    name = "pin".encode("utf-16-le")
    return (bytes(header) + len(item_list).to_bytes(2, "little") + item_list + info
            + (len(name) // 2).to_bytes(2, "little") + name + property_store_block(app_id) + bytes(4))


APP_ID = "가상.도구"
APP_ID_LINK = dword(76) + bytes.fromhex("0114020000000000c000000000000046") + bytes(56) + property_store_block(APP_ID) + bytes(4)
FULL_LINK = full_lnk(pidl("도구.lnk"), "C:\\Synthetic\\tool.exe", APP_ID)


def taskband_values() -> dict[str, bytes]:
    favorites = b""
    resolved = b""
    for name in ("도구.lnk", "문서.lnk"):
        item = pidl(name)
        favorites += b"\0" + dword(len(item)) + item
        link = lnk("..\\" + name)
        resolved += dword(len(link)) + link
    return {"Favorites": favorites + b"\xff", "FavoritesResolve": resolved}


def make_export(mount: str) -> str:
    lines = ["Windows Registry Editor Version 5.00", ""]
    for index, feature in enumerate(FEATURES):
        lines.append(rf"[{mount}\{EXPLORER}\FeatureUsage\{feature}]")
        escaped = APP.replace("\\", "\\\\")
        lines.append(f'"{escaped}"=dword:{index:08x}')
    lines.append(rf"[{mount}\{EXPLORER}\TaskBand]")
    for name, blob in taskband_values().items():
        prefix = ",".join(f"{b:02x}" for b in blob[:12])
        rest = ",".join(f"{b:02x}" for b in blob[12:])
        lines.extend([f'"{name}"=hex:{prefix},\\', f"  {rest}"])
    return "\r\n".join(lines)


class TaskbarProviderTests(unittest.TestCase):
    def check_rows(self, rows: list, *, user: str, hive: bool) -> None:
        feature_rows = [r.details for r in rows if r.artifact_type == "execution-feature-usage"]
        pins = [r.details for r in rows if r.artifact_type == "registry-taskband-pin"]
        summaries = {r.details["value_name"]: r.details for r in rows if r.artifact_type == "registry-taskband-summary"}
        self.assertEqual({name: (s["decode_status"], s["end_status"], s["frames_seen"], s["pins_decoded"])
                          for name, s in summaries.items()},
                         {"Favorites": ("decoded", "terminator", 2, 2),
                          "FavoritesResolve": ("decoded", "end-of-value", 2, 2)})
        self.assertEqual(len(feature_rows), 5)
        self.assertEqual({r["feature"]: r["count"] for r in feature_rows}, dict(zip(FEATURES, range(5))))
        self.assertTrue(all(r["application"] == r["value_name"] == APP for r in feature_rows))
        self.assertEqual(len(pins), 4)
        for name, blob in taskband_values().items():
            targets = sorted((r for r in pins if r["value_name"] == name), key=lambda r: r["pin_index"])
            for index, leaf in enumerate(("도구.lnk", "문서.lnk")):
                row = targets[index]
                payload = pidl(leaf) if name == "Favorites" else lnk("..\\" + leaf)
                offset = row["value_data_offset"]
                self.assertEqual(blob[offset:offset + row["value_data_length"]], payload)
                self.assertEqual(row["target_path"], ("C:\\" if name == "Favorites" else "..\\") + leaf)
        for row in feature_rows + pins:
            self.assertEqual(row["user"], user)
            self.assertEqual(row["key_last_written_filetime"], str(TICKS) if hive else None)
            self.assertEqual(row["key_last_written_at"], filetime_to_iso_ticks(TICKS) if hive else "")
            self.assertEqual(row["timestamp"], row["key_last_written_at"])
            self.assertEqual(row["timestamp_kind"], "last-written" if hive else "")
            self.assertTrue(row["source_path"])
            self.assertTrue(row["source_hashes"]["sha256"])
            self.assertGreater(row["source_offset"], 0)
            if hive:
                self.assertEqual(row["source_offset"], row["key_cell_offset"])
            else:
                line = Path(row["source_path"]).read_text(encoding="utf-16").splitlines()[row["source_offset"] - 1]
                self.assertTrue(line.endswith(row["key_path"].split("\\")[-1] + "]"))

    def test_ntuser_uses_selected_engine(self) -> None:
        root = Key("ROOT")
        explorer = root.path(EXPLORER)
        for index, feature in enumerate(FEATURES):
            explorer.path("FeatureUsage").key(feature, stamp=TICKS).value(APP, REG_DWORD, dword(index))
        taskband = explorer.key("TaskBand", stamp=TICKS)
        for name, data in taskband_values().items():
            taskband.value(name, REG_BINARY, data)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            write_hive(base, "Users/시험/NTUSER.DAT", HiveWriter().build(root))
            rows = list(WindowsRegistryProvider().collect(base))
            if os.environ.get("RAPIDTRIAGE_REGISTRY_ENGINE") == "rust":
                inventory = next(r for r in rows if r.artifact_type == "registry-hive")
                self.assertEqual(inventory.details.get("native_registry_engine"), "rust")
            self.check_rows(rows, user="시험", hive=True)

    def test_utf16_continued_export_with_and_without_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for mount, user in ((rf"HKEY_USERS\{SID}", SID), ("HKEY_CURRENT_USER", ""), (r"HKU\StagedHive", "")):
                with self.subTest(mount=mount):
                    (base / "synthetic.reg").write_text(make_export(mount), encoding="utf-16")
                    self.check_rows(list(WindowsRegistryProvider().collect(base)), user=user, hive=False)

    def test_bad_frames_preserve_next_known_boundary(self) -> None:
        item = pidl("손상.lnk")
        # A valid prefix of a damaged PIDL must not become a target.
        damaged = item[:-2] + b"\x08\x00\x31\x00\x00"
        frame = b"\x00" + dword(len(item)) + item
        stream = b"\x00" + dword(len(damaged)) + damaged + frame + b"\x00\xff\xff"
        rows, summary = decode_taskband_value("Favorites", stream)
        self.assertEqual([r["pin_index"] for r in rows], [1])
        self.assertEqual(summary["undecoded_frame_indices"], [0])
        self.assertEqual((summary["decode_status"], summary["end_status"]), ("partial", "truncated-frame-header"))
        self.assertEqual(summary["end_offset"], len(stream) - 3)
        # No naked path-string scan or resynchronization beyond truncated outer frames.
        rows, summary = decode_taskband_value("FavoritesResolve", dword(1000) + lnk(APP))
        self.assertEqual((rows, summary["end_status"], summary["frames_seen"]), ([], "frame-exceeds-value", 0))
        damaged = lnk(APP)[:-2]
        valid = lnk("..\\도구.exe")
        stream = dword(len(damaged)) + damaged + dword(len(valid)) + valid
        rows, summary = decode_taskband_value("FavoritesResolve", stream)
        self.assertEqual([r["target_path"] for r in rows], ["..\\도구.exe"])
        self.assertEqual((summary["frames_seen"], summary["undecoded_frames"], summary["end_status"]),
                         (2, 1, "end-of-value"))

    def test_walk_end_is_disclosed(self) -> None:
        item = pidl("도구.lnk")
        frame = b"\x00" + dword(len(item)) + item
        cases = {
            frame + b"\xff": ("decoded", "terminator", 0),
            frame + b"\xff\x00\x01": ("partial", "terminator", 2),
            frame: ("partial", "missing-terminator", 0),
            frame + b"\x14" + dword(len(item)) + item + b"\xff": ("partial", "unrecognized-entry-tag", 0),
            frame + b"\x00" + dword(0) + b"\xff": ("partial", "zero-length-frame", 0),
        }
        for stream, expected in cases.items():
            with self.subTest(stream=stream[-8:].hex()):
                rows, summary = decode_taskband_value("Favorites", stream)
                self.assertEqual(len(rows), 1)
                self.assertEqual((summary["decode_status"], summary["end_status"], summary["trailing_bytes"]), expected)

    def test_app_id_only_shell_link(self) -> None:
        pin, = decode_taskband_value("FavoritesResolve", dword(len(APP_ID_LINK)) + APP_ID_LINK)[0]
        self.assertEqual(pin["app_id"], APP_ID)
        self.assertEqual(pin["application"], APP_ID)
        self.assertEqual(pin["target_path"], "")

    def test_taskband_limits(self) -> None:
        data = taskband_values()["Favorites"]
        with patch("rapidtriage.artifacts.windows.taskband.MAX_TASKBAND_ENTRIES", 1):
            rows, summary = decode_taskband_value("Favorites", data)
        self.assertEqual((len(rows), summary["end_status"], summary["decode_status"]), (1, "frame-cap", "partial"))
        with patch("rapidtriage.artifacts.windows.taskband.MAX_TASKBAND_VALUE_BYTES", len(data) - 1):
            rows, summary = decode_taskband_value("Favorites", data)
        self.assertEqual((rows, summary["end_status"], summary["frames_seen"]), ([], "value-too-large", 0))
        with patch("rapidtriage.artifacts.windows.taskband.MAX_SHELLITEM_LIST_BYTES", 8):
            rows, summary = decode_taskband_value("Favorites", data)
        self.assertEqual((rows, summary["oversized_frames"], summary["end_status"]), ([], 2, "terminator"))

    def test_mutated_values_never_raise_and_stay_in_bounds(self) -> None:
        rng = random.Random(20261126)
        seeds = [
            *taskband_values().items(),
            ("FavoritesResolve", dword(len(APP_ID_LINK)) + APP_ID_LINK),
            ("FavoritesResolve", dword(len(FULL_LINK)) + FULL_LINK),
        ]
        for _ in range(3000):
            name, seed = rng.choice(seeds)
            data = bytearray(seed)
            for _ in range(rng.randint(1, 6)):
                at = rng.randrange(len(data))
                choice = rng.random()
                if choice < 0.5:
                    data[at] = rng.randrange(256)
                elif choice < 0.7:
                    del data[at:at + rng.randint(1, 16)]
                elif choice < 0.85:
                    data[at:at] = rng.randbytes(rng.randint(1, 16))
                else:
                    data[at:at + 4] = rng.choice((0, 1, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF)).to_bytes(4, "little")
                if not data:
                    break
            rows, summary = decode_taskband_value(name, bytes(data))
            self.assertEqual(summary["pins_decoded"] + summary["undecoded_frames"], summary["frames_seen"])
            self.assertLessEqual(summary["end_offset"], len(data))
            for row in rows:
                self.assertLessEqual(row["value_data_offset"] + row["value_data_length"], len(data))
