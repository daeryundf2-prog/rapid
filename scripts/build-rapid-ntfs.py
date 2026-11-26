#!/usr/bin/env python3
"""Build the rapid-ntfs PyO3 extension and stage it for rapidtriage.core.ntfs_native.

Runs `cargo build -p rapid-ntfs --features python --release` in `engines/rust/`
against the interpreter running this script (PYO3_PYTHON) and copies the cdylib
to `rapidtriage/native/rapid_ntfs_native<EXT_SUFFIX>` (gitignored; rebuild after
checkout). The suffix carries the interpreter tag (e.g. `.cpython-312-darwin.so`,
`.cp312-win_amd64.pyd`), so another Python version never imports this build.
The Rust parser is used only when RAPIDTRIAGE_NTFS_ENGINE=rust is set; see
docs/architecture/rapid-ntfs.md.

Usage: python scripts/build-rapid-ntfs.py [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_ROOT = REPO_ROOT / "engines" / "rust"
NATIVE_DIR = REPO_ROOT / "rapidtriage" / "native"

CDYLIB_NAMES = {
    "win32": "rapid_ntfs.dll",
    "darwin": "librapid_ntfs.dylib",
    "linux": "librapid_ntfs.so",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    src_name = CDYLIB_NAMES.get(sys.platform, CDYLIB_NAMES["linux"])
    dst_name = "rapid_ntfs_native" + str(sysconfig.get_config_var("EXT_SUFFIX"))
    build = subprocess.run(
        ["cargo", "build", "-p", "rapid-ntfs", "--features", "python", "--release"],
        cwd=RUST_ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "PYO3_PYTHON": sys.executable},
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
    result = {"ok": True, "staged": str(target), "bytes": target.stat().st_size, "python": sys.executable}
    print(json.dumps(result) if args.json else f"staged {target} ({target.stat().st_size} bytes) for {sys.executable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
