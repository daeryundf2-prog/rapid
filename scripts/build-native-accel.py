#!/usr/bin/env python3
"""Build the rapidcore PyO3 extension and stage it for native_accel (R4-1).

Runs `cargo build -p rapidcore --features python --release` in
`engines/rust/`, then copies the produced cdylib into
`rapidtriage/native/rapidcore_native.<ext>` where `rapidtriage.core.native_accel`
picks it up. The staged artifact is gitignored — rebuild after checkout.

Usage: python scripts/build-native-accel.py [--json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_ROOT = REPO_ROOT / "engines" / "rust"
NATIVE_DIR = REPO_ROOT / "rapidtriage" / "native"

EXTENSION_NAMES = {
    "win32": ("rapidcore.dll", "rapidcore_native.pyd"),
    "darwin": ("librapidcore.dylib", "rapidcore_native.so"),
    "linux": ("librapidcore.so", "rapidcore_native.so"),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    src_name, dst_name = EXTENSION_NAMES.get(sys.platform, EXTENSION_NAMES["linux"])
    build = subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            "rapidcore",
            "--features",
            "python",
            "--release",
        ],
        cwd=RUST_ROOT,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        result = {"ok": False, "stage": "cargo", "stderr": build.stderr[-4000:]}
        print(json.dumps(result) if args.json else result)
        return 1

    produced = RUST_ROOT / "target" / "release" / src_name
    if not produced.exists():
        result = {"ok": False, "stage": "locate", "expected": str(produced)}
        print(json.dumps(result) if args.json else result)
        return 1

    NATIVE_DIR.mkdir(parents=True, exist_ok=True)
    target = NATIVE_DIR / dst_name
    shutil.copy2(produced, target)
    result = {"ok": True, "staged": str(target), "bytes": target.stat().st_size}
    print(json.dumps(result) if args.json else f"staged {target} ({target.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
