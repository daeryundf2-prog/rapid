"""Synthetic NTUSER and UTF-16 .reg equivalents for Explorer taskbar activity."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider, filetime_to_iso_ticks
from rapidtriage.artifacts.windows.registry_depth import EXPLORER
from rapidtriage.artifacts.windows.taskband import taskband_entries
from tests.test_parser_quality_registry import REG_BINARY, REG_DWORD, HiveWriter, Key, dword, write_hive

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
        rows = list(taskband_entries("Favorites", stream))
        self.assertEqual([r["pin_index"] for r in rows], [1])
        # No naked path-string scan or resynchronization beyond truncated outer frames.
        self.assertEqual(list(taskband_entries("FavoritesResolve", dword(1000) + lnk(APP))), [])
        damaged = lnk(APP)[:-2]
        valid = lnk("..\\도구.exe")
        stream = dword(len(damaged)) + damaged + dword(len(valid)) + valid
        rows = list(taskband_entries("FavoritesResolve", stream))
        self.assertEqual([r["target_path"] for r in rows], ["..\\도구.exe"])

    def test_app_id_only_shell_link(self) -> None:
        from uuid import UUID

        header = bytearray(lnk("")[:76])
        header[20:24] = bytes(4)
        # Serialized Property Storage for PKEY_AppUserModel_ID, VT_LPWSTR.
        app_id = "가상.도구"
        raw = (app_id + "\0").encode("utf-16-le")
        typed = dword(0x1F) + dword(len(raw) // 2) + raw
        prop = dword(9 + len(typed)) + dword(5) + bytes(1) + typed
        fmtid = UUID("9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3").bytes_le
        storage = dword(28 + len(prop)) + b"1SPS" + fmtid + prop + bytes(4)
        block = dword(12 + len(storage)) + dword(0xA0000009) + storage + bytes(4)
        link = bytes(header) + block + bytes(4)
        pin, = taskband_entries("FavoritesResolve", dword(len(link)) + link)
        self.assertEqual(pin["app_id"], app_id)
        self.assertEqual(pin["application"], app_id)
        self.assertEqual(pin["target_path"], "")

    def test_taskband_limits(self) -> None:
        data = taskband_values()["Favorites"]
        with patch("rapidtriage.artifacts.windows.taskband.MAX_TASKBAND_ENTRIES", 1):
            self.assertEqual(len(list(taskband_entries("Favorites", data))), 1)
        with patch("rapidtriage.artifacts.windows.taskband.MAX_TASKBAND_VALUE_BYTES", len(data) - 1):
            self.assertEqual(list(taskband_entries("Favorites", data)), [])
