#!/usr/bin/env python3
"""Build a PyO3 extension crate and stage it under rapidtriage/native/ (R4-1).

Runs `cargo build -p <crate> --features python --release` in `engines/rust/`, then
copies the produced cdylib into `rapidtriage/native/<module>.<ext>`:

- `rapidcore` (default) -> `rapidcore_native`, picked up by `rapidtriage.core.native_accel`;
- `rapid-registry` -> `rapid_registry_native`, the registry hive reader selected with
  `RAPIDTRIAGE_REGISTRY_ENGINE=rust` (see `rapidtriage.artifacts.windows.registry_engine`).

The staged artifact is gitignored — rebuild after checkout.

Usage: python scripts/build-native-accel.py [--crate rapid-registry] [--json]
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

# crate -> (cdylib stem, Python module name)
EXTENSION_CRATES = {
    "rapidcore": ("rapidcore", "rapidcore_native"),
    "rapid-registry": ("rapid_registry", "rapid_registry_native"),
}


def extension_file_names(crate: str) -> tuple[str, str]:
    """(cargo output file, staged module file) for ``crate`` on this platform."""
    stem, module = EXTENSION_CRATES[crate]
    if sys.platform == "win32":
        return f"{stem}.dll", f"{module}.pyd"
    if sys.platform == "darwin":
        return f"lib{stem}.dylib", f"{module}.so"
    return f"lib{stem}.so", f"{module}.so"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--crate", choices=sorted(EXTENSION_CRATES), default="rapidcore")
    args = parser.parse_args()

    src_name, dst_name = extension_file_names(args.crate)
    build = subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            args.crate,
            "--features",
            "python",
            "--release",
        ],
        cwd=RUST_ROOT,
        capture_output=True,
        # cargo writes UTF-8; the locale codec (cp949 on Korean Windows) crashed the reader thread.
        encoding="utf-8",
        errors="replace",
    )
    if build.returncode != 0:
        result = {"ok": False, "stage": "cargo", "stderr": build.stderr[-4000:]}
        print(json.dumps(result) if args.json else result)
        return 1

    # CARGO_TARGET_DIR moves the build output (needed when the checkout path is not ASCII:
    # the MinGW linker cannot write to such a path). cargo resolves a relative value against its
    # cwd (RUST_ROOT); joining onto RUST_ROOT does the same and leaves absolute values unchanged.
    target_dir = RUST_ROOT / (os.environ.get("CARGO_TARGET_DIR") or "target")
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
