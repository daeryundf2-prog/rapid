"""Generate a four-event archive using only synthetic binary fields."""
import argparse
from pathlib import Path

from tests.test_unified_sidecars import make_dsc, make_timesync, make_uuidtext
from tests.unified_trace_fixture import BOOT, CACHE, MAIN, make_trace


def write_fixture(store, strings):
    """Create either a .logarchive or separate diagnostics and uuidtext directories."""
    files = {
        store / "Persist/sample.tracev3": make_trace(),
        store / "timesync/boot.timesync": make_timesync(
            BOOT, 125, 3, 1_600_000_000_000_000_000, [(1000, 1_600_000_002_000_000_000)]),
        strings / MAIN[:2] / MAIN[2:]: make_uuidtext(
            [(0x100, b"%{public}s / %{private}s\0"), (0x120, b"started\0"), (0x140, b"value %u\0")],
            "/synthetic/demo"),
        strings / "dsc" / CACHE: make_dsc(2, 0x200, "begin", "/synthetic/library"),
    }
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="New .logarchive directory")
    archive = parser.parse_args().archive
    if archive.suffix.lower() != ".logarchive":
        parser.error("output directory must end in .logarchive")
    archive.mkdir(parents=True, exist_ok=False)
    write_fixture(archive, archive)
