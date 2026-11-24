#!/usr/bin/env python3
"""Build the rapid-extract PyO3 extension and stage it as rapidtriage/native/rapid_extract_native.

Runs `cargo build -p rapid-extract --features python --release` in `engines/rust/` and copies
the cdylib to `rapidtriage/native/rapid_extract_native.<ext>`, where
`rapidtriage.core.e01_extract_engine` loads it when `RAPIDTRIAGE_E01_EXTRACT_ENGINE=rust`.
The staged artifact is gitignored; rebuild after checkout.

Usage: python scripts/build-e01-extract-native.py [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUST_ROOT = REPO_ROOT / "engines" / "rust"
NATIVE_DIR = REPO_ROOT / "rapidtriage" / "native"
MODULE = "rapid_extract_native"


def file_names() -> tuple[str, str]:
    """(cargo output file, staged module file) on this platform."""
    if sys.platform == "win32":
        return "rapid_extract.dll", f"{MODULE}.pyd"
    if sys.platform == "darwin":
        return "librapid_extract.dylib", f"{MODULE}.so"
    return "librapid_extract.so", f"{MODULE}.so"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    build = subprocess.run(
        ["cargo", "build", "-p", "rapid-extract", "--features", "python", "--release"],
        cwd=RUST_ROOT,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        result = {"ok": False, "stage": "cargo", "stderr": build.stderr[-4000:]}
        print(json.dumps(result) if args.json else result)
        return 1

    src_name, dst_name = file_names()
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR") or RUST_ROOT / "target")
    produced = target_dir / "release" / src_name
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
