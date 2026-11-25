#!/usr/bin/env python3
"""Build the rapid-ntfs PyO3 extension and stage it for rapidtriage.core.ntfs_native.

Runs `cargo build -p rapid-ntfs --features python --release` in `engines/rust/`
and copies the cdylib to `rapidtriage/native/rapid_ntfs_native.<ext>` (gitignored,
rebuild after checkout). The Rust parser is used only when
RAPIDTRIAGE_NTFS_ENGINE=rust is set; see docs/architecture/rapid-ntfs.md.

Usage: python scripts/build-rapid-ntfs.py [--json]
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
    "win32": ("rapid_ntfs.dll", "rapid_ntfs_native.pyd"),
    "darwin": ("librapid_ntfs.dylib", "rapid_ntfs_native.so"),
    "linux": ("librapid_ntfs.so", "rapid_ntfs_native.so"),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    src_name, dst_name = EXTENSION_NAMES.get(sys.platform, EXTENSION_NAMES["linux"])
    command = ["cargo", "build", "-p", "rapid-ntfs", "--features", "python", "--release"]
    if sys.platform == "darwin":
        # extension-module leaves libpython symbols unresolved; macOS needs them looked up at load time.
        command = ["cargo", "rustc", "-p", "rapid-ntfs", "--features", "python", "--release", "--lib", "--",
                   "-C", "link-arg=-undefined", "-C", "link-arg=dynamic_lookup"]
    build = subprocess.run(command, cwd=RUST_ROOT, capture_output=True, text=True)
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
