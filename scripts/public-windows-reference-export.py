"""Export allocated comparison inputs from a public NTFS test image by attribute address."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

# Match only the current installation and direct profile hives. Exclude backup,
# transaction, recovered and shadow-copy trees from the live reference set.
LOCATIONS = re.compile(
    r"Windows/System32/config/(?:SAM|SYSTEM|SOFTWARE)"
    r"|Windows/System32/winevt/Logs/[^/:\\]+\.evtx"
    r"|(?:Users|Documents and Settings)/[^/:\\]+/NTUSER\.DAT",
    re.IGNORECASE,
)
BROWSER = re.compile(
    r"Users/[^/:\\]+/AppData/Local/[^/:\\]+/[^/:\\]+/User Data/(?:Default|Profile \d+)/"
    r"(?:History|Web Data|Login Data|(?:Network/)?Cookies)(?:-wal|-shm|-journal)?",
    re.IGNORECASE,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", required=True, type=Path, help="allocated fls -r -u -m / output")
    parser.add_argument("--image", required=True, type=Path, help="first segment supplied to fls")
    parser.add_argument("--sector", required=True, type=int, help="NTFS start sector supplied to fls")
    parser.add_argument("--output", required=True, type=Path, help="fresh directory inside private storage")
    parser.add_argument("--event-log", action="append", help="EVTX filename glob, repeatable (default: all)")
    parser.add_argument("--include-browser", action="store_true", help="include Chromium profile databases and journals")
    parser.add_argument("--max-bytes", type=int, help="reject selections with more than this many listed bytes before extracting")
    args = parser.parse_args()
    selected = []
    counts: Counter[str] = Counter()
    with args.body.open(encoding="utf-8", errors="surrogateescape") as listing:
        for line in listing:
            _, tail = line.rstrip("\n").split("|", 1)
            name, address, mode, _, _, size, *_ = tail.rsplit("|", 9)
            relative = name.removeprefix("/")
            browser = args.include_browser and BROWSER.fullmatch(relative)
            if not (LOCATIONS.fullmatch(relative) or browser) or not mode.startswith("r/r"):
                continue
            path = PurePosixPath(relative)
            if any(part in {".", ".."} for part in relative.split("/")) or not re.fullmatch(r"\d+-128-\d+", address):
                raise ValueError("invalid reference path or unnamed stream address")
            if path.suffix.casefold() == ".evtx":
                if args.event_log and not any(fnmatchcase(path.name.casefold(), p.casefold()) for p in args.event_log):
                    continue
                family = "EVTX"
            else:
                family = "browser" if browser else path.name.upper()
            length = int(size)
            if length < 0:
                raise ValueError("negative stream length")
            selected.append((path, address, length))
            counts[family] += 1
    total = sum(length for _, _, length in selected)
    if args.max_bytes is not None and total > args.max_bytes:
        parser.error(f"selected {total} bytes exceeds the {args.max_bytes} byte limit")
    print(f"files={len(selected)} bytes={total}", *(f"{name}={n}" for name, n in sorted(counts.items())), flush=True)
    args.output.mkdir(parents=True, exist_ok=False)
    for path, address, length in selected:
        destination = args.output / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            subprocess.run(["icat", "-o", str(args.sector), args.image, address], check=True, stdout=stream)
        if destination.stat().st_size != length:
            raise ValueError("reference export length differs from listing")


if __name__ == "__main__":
    main()
