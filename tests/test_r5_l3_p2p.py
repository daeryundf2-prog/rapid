"""R5 L3 P2P provider: bencode, .torrent, qBittorrent / uTorrent / FrostWire resume data and eMule
(synthetic fixtures generated here; no real torrents of real content)."""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts import artifact_collectors
from rapidtriage.artifacts.p2p import (
    BencodeError,
    P2PArtifactsProvider,
    bdecode,
    torrent_summary,
    tracker_host,
)
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.run.constants import GENERAL_FORENSIC_ARTIFACT_KINDS
from rapidtriage.core.triage_rules.base import FlagContext, RowView
from rapidtriage.core.triage_rules.p2p import (
    EmuleSharedUploaded,
    TorrentSeedingUploaded,
)

PASSKEY = "0123456789abcdefPASSKEY"


def bencode(value: object) -> bytes:
    if isinstance(value, int):
        return b"i%de" % value
    if isinstance(value, str):
        value = value.encode("utf-8")
    if isinstance(value, bytes):
        return b"%d:%s" % (len(value), value)
    if isinstance(value, list):
        return b"l" + b"".join(bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        items = sorted((key.encode() if isinstance(key, str) else key, item) for key, item in value.items())
        return b"d" + b"".join(bencode(key) + bencode(item) for key, item in items) + b"e"
    raise TypeError(value)


INFO = {
    "name": "synthetic-pack",
    "piece length": 16384,
    "pieces": b"\x00" * 20,
    "files": [
        {"length": 100, "path": ["docs", "a.txt"]},
        {"length": 200, "path": ["b.bin"]},
        {"length": 5, "path": [".pad", "5"], "attr": "p"},
    ],
}
TORRENT = {
    "announce": f"https://tracker.example.org:8443/{PASSKEY}/announce",
    "announce-list": [[f"udp://open.example.net:1337/announce?passkey={PASSKEY}"]],
    "creation date": 1_700_000_000,
    "created by": "synthetic-maker/1.0",
    "comment": "합성 테스트",
    "info": INFO,
}
INFO_HASH = hashlib.sha1(bencode(INFO)).hexdigest()


def met_tag_string(tag_id: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<BB", 0x82, tag_id) + struct.pack("<H", len(raw)) + raw


def met_tag_u32(tag_id: int, value: int) -> bytes:
    return struct.pack("<BBI", 0x83, tag_id, value)


def met_entry(name: str, size: int, file_hash: bytes, *, uploaded: int, accepted: int, date: int) -> bytes:
    tags = [
        met_tag_string(0x01, name),
        met_tag_u32(0x02, size),
        met_tag_u32(0x50, uploaded),
        met_tag_u32(0x52, accepted),
        met_tag_u32(0x34, date + 60),
        struct.pack("<BH", 0x03, 2) + b"\x09\x31" + struct.pack("<I", 7),  # old-style gap tag name
    ]
    return struct.pack("<I", date) + file_hash + struct.pack("<H", 0) + struct.pack("<I", len(tags)) + b"".join(tags)


class BencodeTests(unittest.TestCase):
    def test_torrent_summary_info_hash_and_tracker_redaction(self) -> None:
        summary = torrent_summary(bencode(TORRENT))
        self.assertEqual(summary["info_hash"], INFO_HASH)
        self.assertEqual((summary["name"], summary["file_count"], summary["total_size"]), ("synthetic-pack", 2, 300))
        self.assertEqual(summary["files"][0], {"path": "docs/a.txt", "length": 100})
        self.assertEqual(summary["trackers"], ["https://tracker.example.org:8443", "udp://open.example.net:1337"])
        self.assertNotIn(PASSKEY, json.dumps(summary, ensure_ascii=False))
        self.assertEqual(summary["created_at"], "2023-11-14T22:13:20Z")
        self.assertEqual(tracker_host("not a url"), "")

    def test_v2_file_tree_and_limits(self) -> None:
        info = {"name": "v2", "meta version": 2, "piece length": 16384, "file tree": {"dir": {"x.bin": {"": {"length": 42}}}}}
        summary = torrent_summary(bencode({"info": info}))
        self.assertEqual(summary["info_hash_v2"], hashlib.sha256(bencode(info)).hexdigest())
        self.assertEqual((summary["file_count"], summary["files"][0]["path"]), (1, "dir/x.bin"))
        for bad in (b"d4:infoi1e", b"i12", b"5:ab", b"x", b"l" * 200 + b"e" * 200, b"d3:keyi1e" + b"i00000000000000000000000000001e"):
            with self.assertRaises(BencodeError):
                bdecode(bad)


class ProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "Users" / "lee"

    def write(self, relative: str, data: bytes | str) -> Path:
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def collect(self) -> dict[str, list[dict[str, object]]]:
        out: dict[str, list[dict[str, object]]] = {}
        for record in P2PArtifactsProvider().collect(self.root):
            out.setdefault(record.artifact_type, []).append(record.details)
        return out

    def test_bittorrent_clients(self) -> None:
        backup = "AppData/Local/qBittorrent/BT_backup"
        self.write(f"{backup}/{INFO_HASH}.torrent", bencode(TORRENT))
        self.write(
            f"{backup}/{INFO_HASH}.fastresume",
            bencode(
                {
                    "info-hash": bytes.fromhex(INFO_HASH),
                    "qBt-name": "synthetic-pack",
                    "qBt-savePath": "D:\\Downloads\\",
                    "added_time": 1_700_000_100,
                    "completed_time": 1_700_000_900,
                    "total_uploaded": 123_456,
                    "total_downloaded": 300,
                    "qBt-category": "test",
                    "trackers": [[f"https://tracker.example.org/{PASSKEY}/announce"]],
                }
            ),
        )
        self.write(
            "AppData/Roaming/uTorrent/resume.dat",
            bencode(
                {
                    ".fileguard": "0123",
                    "rec": {"x": 1},
                    "other.torrent": {"caption": "other", "path": "C:\\Users\\lee\\Downloads\\other", "added_on": 1_700_001_000,
                                      "completed_on": 0, "downloaded": 10, "uploaded": 0, "info": b"\x11" * 20},
                }
            ),
        )
        self.write("Documents/FrostWire/Torrents/fw.torrent", bencode({"info": {"name": "fw", "length": 9, "piece length": 16384, "pieces": b""}}))
        self.write("Downloads/random.torrent", b"d4:info")  # corrupt
        rows = self.collect()
        torrents = {row["client"]: row for row in rows["p2p-torrent"]}
        self.assertEqual(set(torrents), {"qbittorrent", "frostwire"})
        self.assertEqual(torrents["qbittorrent"]["info_hash"], INFO_HASH)
        transfers = {row["client"]: row for row in rows["p2p-transfer"]}
        qbt = transfers["qbittorrent"]
        self.assertEqual((qbt["state"], qbt["uploaded_bytes"], qbt["info_hash"]), ("completed", 123_456, INFO_HASH))
        self.assertEqual(qbt["timestamp_kind"], "transfer-completed")
        utorrent = transfers["utorrent"]
        self.assertEqual((utorrent["state"], utorrent["client_entry_key"], utorrent["info_hash"]), ("incomplete", "other.torrent", "11" * 20))
        errors = rows["p2p-parse-error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["reason"], "torrent-unreadable")
        serialized = json.dumps(rows, ensure_ascii=False, default=str)
        self.assertNotIn(PASSKEY, serialized)
        for group in rows.values():
            for row in group:
                self.assertTrue(row["parser_version"].startswith("p2p-artifacts"))
                self.assertIn("recovery_method", row)
                self.assertTrue(row["source_path"])
        self.assertEqual(qbt["user"], "lee")

    def test_emule(self) -> None:
        file_hash = bytes(range(16))
        known = b"\x0e" + struct.pack("<I", 2)
        known += met_entry("공유영상.avi", 700_000_000, file_hash, uploaded=5_000_000, accepted=3, date=1_700_000_000)
        known += met_entry("idle.txt", 10, b"\x01" * 16, uploaded=0, accepted=0, date=1_700_000_000)
        config = "AppData/Local/eMule/config"
        self.write(f"{config}/known.met", known)
        self.write(f"{config}/AC_SearchStrings.dat", "\ufeff첫검색\r\nsecond term\r\n".encode("utf-16-le"))
        self.write(f"{config}/preferences.ini", "[eMule]\r\nNick=합성닉\r\nIncomingDir=D:\\eMule\\Incoming\r\nUserHash=SHOULDNOTAPPEAR\r\n")
        part = b"\xe0" + struct.pack("<I", 1_700_000_500) + b"\x22" * 16 + struct.pack("<H", 0)
        part_tags = [met_tag_string(0x01, "downloading.mkv"), met_tag_u32(0x02, 1000), met_tag_u32(0x08, 400), met_tag_string(0x12, "001.part")]
        part += struct.pack("<I", len(part_tags)) + b"".join(part_tags)
        self.write("AppData/Local/eMule/Temp/001.part.met", part)
        self.write(f"{config}/../Temp/002.part.met", b"\xe0\x00")  # truncated
        rows = self.collect()
        shared = {row["file_name"]: row for row in rows["p2p-shared-file"]}
        video = shared["공유영상.avi"]
        self.assertEqual(video["ed2k_hash"], file_hash.hex().upper())
        self.assertEqual((video["all_time_uploaded_bytes"], video["all_time_accepted"]), (5_000_000, 3))
        self.assertEqual(video["ed2k_link"], f"ed2k://|file|공유영상.avi|700000000|{file_hash.hex().upper()}|/")
        self.assertEqual(video["timestamp_kind"], "last-shared")
        terms = [row["term"] for row in rows["p2p-search-term"]]
        self.assertEqual(terms, ["첫검색", "second term"])
        config_row = rows["p2p-client-config"][0]
        self.assertEqual((config_row["nick"], config_row["incoming_dir"]), ("합성닉", "D:\\eMule\\Incoming"))
        self.assertNotIn("SHOULDNOTAPPEAR", json.dumps(rows, ensure_ascii=False, default=str))
        transfer = rows["p2p-transfer"][0]
        self.assertEqual((transfer["file_name"], transfer["downloaded_bytes"], transfer["state"]), ("downloading.mkv", 400, "incomplete"))
        self.assertEqual(rows["p2p-parse-error"][0]["reason"], "part-met-unreadable")

    def test_truncated_known_met_keeps_rows(self) -> None:
        known = b"\x0e" + struct.pack("<I", 2) + met_entry("a.bin", 1, b"\x02" * 16, uploaded=0, accepted=0, date=1_700_000_000)
        known += b"\x00\x01"  # second entry truncated
        self.write("AppData/Local/eMule/config/known.met", known)
        rows = self.collect()
        self.assertEqual(len(rows["p2p-shared-file"]), 1)
        self.assertTrue(rows["p2p-parse-error"][0]["reason"].startswith("known-met-truncated"))

    def test_registration_and_rules(self) -> None:
        self.assertIn("p2p", artifact_collectors())
        self.assertIn("p2p", GENERAL_FORENSIC_ARTIFACT_KINDS)
        self.assertEqual(artifact_type_domain("p2p", "p2p-transfer"), "web")
        ctx = FlagContext()

        def view(artifact_type: str, details: dict[str, object]) -> RowView:
            return RowView(kind="p2p", collection="artifacts", source_kind="p2p", index=0, row={"artifact_type": artifact_type, "details": details})

        seeding = TorrentSeedingUploaded()
        self.assertIsNotNone(seeding.apply(view("p2p-transfer", {"client": "qbittorrent", "uploaded_bytes": 10, "name": "x"}), ctx))
        self.assertIsNone(seeding.apply(view("p2p-transfer", {"client": "qbittorrent", "uploaded_bytes": 0}), ctx))
        emule = EmuleSharedUploaded()
        self.assertIsNotNone(emule.apply(view("p2p-shared-file", {"all_time_uploaded_bytes": 0, "all_time_accepted": 2, "file_name": "x"}), ctx))


if __name__ == "__main__":
    unittest.main()
