#!/usr/bin/env python3
"""Detect drift in vendored lazy-contracts files.

``contracts/PIN.json`` records the upstream commit and the expected
sha256 of each vendored file. This check recomputes the hash of every
file in ``contracts/`` and fails when a pinned file is missing, a hash
no longer matches, or a file is present that the pin does not cover
(other than ``PIN.json`` itself).

Exit status:
    1  drift detected (hash mismatch, missing, or unpinned files)
    0  clean
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACTS_DIR = REPO_ROOT / "contracts"
PIN_FILENAME = "PIN.json"


def sha256_file(path: Path) -> str:
    """Return the hex sha256 digest of a file's contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_drift(contracts_dir: Path, pin_path: Path) -> dict:
    """Compare contracts_dir contents against the pinned sha256 map."""
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    pinned: dict[str, str] = pin.get("sha256", {})

    missing: list[str] = []
    mismatched: list[dict] = []
    for name, expected in sorted(pinned.items()):
        path = contracts_dir / name
        if not path.is_file():
            missing.append(name)
            continue
        actual = sha256_file(path)
        if actual != expected:
            mismatched.append(
                {"file": name, "expected": expected, "actual": actual}
            )

    unpinned = sorted(
        child.name
        for child in contracts_dir.iterdir()
        if child.is_file() and child.name != PIN_FILENAME and child.name not in pinned
    )

    return {"missing": missing, "mismatched": mismatched, "unpinned": unpinned}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check vendored contracts/ files against contracts/PIN.json",
    )
    parser.add_argument(
        "--contracts-dir",
        type=Path,
        default=DEFAULT_CONTRACTS_DIR,
        help="vendored contracts directory (default: %(default)s)",
    )
    parser.add_argument(
        "--pin",
        type=Path,
        default=None,
        help="path to PIN.json (default: <contracts-dir>/PIN.json)",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    args = parser.parse_args(argv)

    contracts_dir = args.contracts_dir
    pin_path = args.pin or contracts_dir / PIN_FILENAME

    if not contracts_dir.is_dir():
        print(f"contracts directory not found: {contracts_dir}")
        return 1
    if not pin_path.is_file():
        print(f"pin file not found: {pin_path}")
        return 1

    result = check_drift(contracts_dir, pin_path)
    drift_count = (
        len(result["missing"]) + len(result["mismatched"]) + len(result["unpinned"])
    )

    if args.json:
        print(
            json.dumps(
                {**result, "drift_count": drift_count},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for name in result["missing"]:
            print(f"MISSING {name}: pinned in {pin_path} but not present")
        for entry in result["mismatched"]:
            print(
                f"DRIFT {entry['file']}: sha256 {entry['actual']} "
                f"!= pinned {entry['expected']}"
            )
        for name in result["unpinned"]:
            print(f"UNPINNED {name}: present but not covered by {pin_path}")
        print(f"contract drift check: {drift_count} drifted file(s)")

    if drift_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
