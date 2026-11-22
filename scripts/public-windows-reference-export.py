"""Export allocated comparison inputs from a public NTFS test image by attribute address."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path, PurePosixPath

# Match only the current installation and direct profile hives. Exclude backup,
# transaction, recovered and shadow-copy trees from the live reference set.
LOCATIONS = re.compile(
    r"Windows/System32/config/(?:SAM|SYSTEM|SOFTWARE)"
    r"|Windows/System32/winevt/Logs/[^/:\\]+\.evtx"
    r"|(?:Users|Documents and Settings)/[^/:\\]+/NTUSER\.DAT",
    re.IGNORECASE,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--body", required=True, type=Path, help="allocated fls -r -u -m / output")
    parser.add_argument("--image", required=True, type=Path, help="first segment supplied to fls")
    parser.add_argument("--sector", required=True, type=int, help="NTFS start sector supplied to fls")
    parser.add_argument("--output", required=True, type=Path, help="fresh directory inside private storage")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    counts = {"SAM": 0, "SYSTEM": 0, "SOFTWARE": 0, "NTUSER.DAT": 0, "EVTX": 0}
    with args.body.open(encoding="utf-8", errors="surrogateescape") as listing:
        for line in listing:
            _, tail = line.rstrip("\n").split("|", 1)
            name, address, mode, _, _, size, *_ = tail.rsplit("|", 9)
            relative = name.removeprefix("/")
            if not LOCATIONS.fullmatch(relative) or not mode.startswith("r/r"):
                continue
            parts = relative.split("/")
            if any(part in {".", ".."} for part in parts) or not re.fullmatch(r"\d+-128-\d+", address):
                raise ValueError("invalid reference path or unnamed stream address")
            destination = args.output / PurePosixPath(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                subprocess.run(["icat", "-o", str(args.sector), args.image, address], check=True, stdout=stream)
            if destination.stat().st_size != int(size):
                raise ValueError("reference export length differs from listing")
            family = "EVTX" if destination.suffix.lower() == ".evtx" else destination.name.upper()
            counts[family] += 1
    print(" ".join(f"{name}={count}" for name, count in counts.items()))


if __name__ == "__main__":
    main()
