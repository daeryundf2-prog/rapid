"""Build the fixed synthetic profiling corpus into a new directory in a source checkout.

Use --image to also package the tree as a raw FAT volume (requires mtools).
NTFS metadata in the tree is a pair of exported streams. No disk mounts required.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import struct
import subprocess
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from rapidtriage.artifacts.windows.browser import FIREFOX_PROFILE_ROOT
from rapidtriage.artifacts.windows.recent_files import RECENT_ROOT
from tests import ntfs_r3_fixtures as ntfs
from tests import windows_artifact_fixtures as fixtures
from tests.test_parser_quality_eventlog import Event, EvtxWriter, wstr
from tests.test_parser_quality_registry import (
    REG_DWORD,
    REG_SZ,
    HiveWriter,
    Key,
    sz,
)

EVENT_COUNT = 500_000
MFT_COUNT = 65_536
JOURNAL_COUNT = 262_144
VISIT_COUNT = 2048
RECORDS_PER_CHUNK = 200
EPOCH = datetime(2024, 1, 1, tzinfo=timezone.utc)
BASE_TICKS = ntfs.filetime(EPOCH.isoformat())


def output_path(root: Path, relative: str) -> Path:
    dest = root / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    return dest


class AlignedWriter(EvtxWriter):
    def _record(self, chunk, event, templates):
        raw = super()._record(chunk, event, templates)
        # BinXML EOF, zero padding and duplicate length of the 8-byte aligned record.
        length = (len(raw) + 1 + 7) // 8 * 8
        return (
            raw[:4]
            + struct.pack("<I", length)
            + raw[8:-4]
            + bytes(length - len(raw))
            + struct.pack("<I", length)
        )


def event(number: int) -> Event:
    return Event(
        record_id=number,
        provider="SampleProvider",
        event_id=100 + number % 2,
        channel="Application",
        computer="fixture.invalid",
        when=BASE_TICKS + 101 * number,
        data=[("Phase", wstr("begin" if number % 2 else "ended"))],
    )


def write_evtx(path: Path, event_count: int) -> int:
    chunk_count = (event_count + RECORDS_PER_CHUNK - 1) // RECORDS_PER_CHUNK
    header = bytearray(4096)
    header[:8] = b"ElfFile\0"
    struct.pack_into(
        "<QQQIHHHH",
        header,
        8,
        0,
        chunk_count - 1,
        event_count + 1,
        128,
        1,
        3,
        4096,
        chunk_count,
    )
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    slack_count = 0
    with path.open("xb") as handle:
        handle.write(header)
        for index in range(chunk_count):
            start = index * RECORDS_PER_CHUNK + 1
            events = [
                event(i)
                for i in range(start, min(start + RECORDS_PER_CHUNK, event_count + 1))
            ]
            slack = [event(event_count + index + 1)] if index % 100 == 0 else []
            slack_count += len(slack)
            writer = AlignedWriter()
            writer.build_chunk(events, slack=slack)
            chunk = writer.chunks[0]
            end = struct.unpack_from("<I", chunk, 48)[0]
            struct.pack_into("<I", chunk, 52, zlib.crc32(chunk[512:end]))
            struct.pack_into("<I", chunk, 124, zlib.crc32(chunk[:120] + chunk[128:512]))
            handle.write(chunk)
    return slack_count


def write_ntfs(tree: Path, mft_count: int, journal_count: int) -> None:
    times = (EPOCH.isoformat(),) * 4
    with (tree / "$MFT").open("xb") as mft:
        for index in range(mft_count):
            name = "." if index == 5 else f"sample{index:05}.bin"
            row = bytearray(
                ntfs.mft_record_times(
                    name=name, parent=5, si=times, fn=times, in_use=index % 7 != 0
                )
            )
            struct.pack_into("<I", row, 44, index)
            if index == 5:
                struct.pack_into("<H", row, 22, 3)
            mft.write(row)
    with output_path(tree, "$Extend/$UsnJrnl/$J").open("xb") as usn:
        for index in range(journal_count):
            entry = index % mft_count
            name = "." if entry == 5 else f"sample{entry:05}.bin"
            record = bytearray(
                fixtures.build_minimal_usn_journal(
                    name, EPOCH, (0x100, 1, 0x200, 0x80000000)[index % 4]
                )
            )
            struct.pack_into(
                "<QQQQ",
                record,
                8,
                (1 << 48) | entry,
                (1 << 48) | 5,
                usn.tell(),
                BASE_TICKS + 101 * index,
            )
            usn.write(record)


def write_other_artifacts(tree: Path, visit_count: int) -> None:
    system32 = tree / "Windows/System32"
    system = Key("ROOT")
    system.path("Select").value("Current", REG_DWORD, (1).to_bytes(4, "little"))
    system.path(r"ControlSet001\Control\TimeZoneInformation").value(
        "TimeZoneKeyName", REG_SZ, sz("UTC")
    )
    output_path(system32, "config/SYSTEM").write_bytes(HiveWriter().build(system))
    software = Key("ROOT")
    for index in range(128):
        software.path(rf"Sample\Apps\Program{index}").value(
            "Version", REG_SZ, sz("1.0")
        )
    output_path(system32, "config/SOFTWARE").write_bytes(HiveWriter().build(software))
    output_path(system32, "sru/SRUDB.dat").write_bytes(
        fixtures._minimal_ese_database_with_catalog()
    )
    fixtures._write_prefetch_fixture(
        tree / "Windows/Prefetch/POWERSHELL.EXE-12345678.pf"
    )

    user_root = tree / "Users/Sample"
    recent = user_root.joinpath(*RECENT_ROOT)
    target = r"C:\Users\Sample\Documents\note.txt"
    lnk = fixtures.build_minimal_lnk(target, EPOCH)
    output_path(recent, "note.lnk").write_bytes(lnk)
    dest_list = fixtures.build_minimal_destlist(1, target, EPOCH)
    output_path(
        recent, "AutomaticDestinations/1234567890abcdef.automaticDestinations-ms"
    ).write_bytes(
        fixtures.build_minimal_ole_jumplist_streams(
            [("DestList", dest_list), ("1", lnk)]
        )
    )
    path = output_path(
        user_root.joinpath(*FIREFOX_PROFILE_ROOT), "sample.default/places.sqlite"
    )
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)"
        )
        db.execute(
            "CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER, from_visit INTEGER)"
        )
        db.executemany(
            "INSERT INTO moz_places VALUES (?, ?, ?, 1)",
            (
                (i, f"https://example.invalid/{i}", f"Sample {i}")
                for i in range(1, visit_count + 1)
            ),
        )
        db.executemany(
            "INSERT INTO moz_historyvisits VALUES (?, ?, ?, 1, 0)",
            (
                (i, i, int(EPOCH.timestamp()) * 1_000_000 + i)
                for i in range(1, visit_count + 1)
            ),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new output directory")
    parser.add_argument("--image", action="store_true")
    parser.add_argument(
        "--pilot", action="store_true", help="generate a 1% calibration dataset"
    )
    args = parser.parse_args()
    divisor = 100 if args.pilot else 1
    event_count, mft_count = EVENT_COUNT // divisor, MFT_COUNT // divisor
    journal_count, visit_count = JOURNAL_COUNT // divisor, VISIT_COUNT // divisor
    args.output.mkdir(parents=True, exist_ok=False)
    tree = args.output / "tree"
    tree.mkdir()
    slack = write_evtx(
        output_path(tree, "Windows/System32/winevt/Logs/Application.evtx"), event_count
    )
    write_ntfs(tree, mft_count, journal_count)
    write_other_artifacts(tree, visit_count)
    for path in tree.rglob("*"):
        os.utime(path, (EPOCH.timestamp(), EPOCH.timestamp()))
    sizes = {
        p.relative_to(tree).as_posix(): p.stat().st_size
        for p in sorted(tree.rglob("*"))
        if p.is_file()
    }
    print(
        json.dumps(
            {
                "allocated_events": event_count,
                "slack_events": slack,
                "mft_records": mft_count,
                "usn_records": journal_count,
                "browser_visits": visit_count,
                "file_sizes": sizes,
            }
        ),
        flush=True,
    )
    if args.image:
        image = args.output / "windows.img"
        with image.open("xb") as volume:
            volume.truncate(320 * 1024**2)
        subprocess.run(
            ["mformat", "-i", str(image), "-F", "-N", "43", "-v", "SYNTHETIC", "::"],
            check=True,
        )
        subprocess.run(
            ["mcopy", "-i", str(image), "-s", "-m", *sorted(tree.iterdir()), "::/"],
            check=True,
        )


if __name__ == "__main__":
    main()
