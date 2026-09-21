#!/usr/bin/env python3
"""Known-answer check for native ShellBags BagMRU decoding.

Decodes every BagMRU node in a real UsrClass.dat/NTUSER.DAT into a shell
namespace path, then verifies how many decoded ``<DRIVE>:\\`` paths resolve to
real directories/files in the extracted image tree. ShellBags frequently
reference since-deleted folders, so existence coverage is reported alongside
parent-path coverage and decode-method mix rather than asserted as 100%.

Usage:
    python scripts/shellbags-known-answer.py --hive <UsrClass.dat> --fs-root <extract-root> --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rapidtriage.artifacts.windows.shellbags import (
    collect_native_shellbag_hive,
)


def _fs_candidate(fs_root: Path, shell_path: str) -> Path | None:
    """Map 'My Computer\\C:\\dir\\file' onto '<fs_root>/dir/file'."""
    parts = [part for part in shell_path.split("\\") if part]
    drive_index = next(
        (index for index, part in enumerate(parts) if len(part) == 2 and part[1] == ":"),
        None,
    )
    if drive_index is None:
        return None
    if parts[drive_index].upper() != "C:":
        return None
    candidate = fs_root
    for part in parts[drive_index + 1 :]:
        candidate = candidate / part
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hive", required=True)
    parser.add_argument("--fs-root", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    hive = Path(args.hive)
    fs_root = Path(args.fs_root)
    records = list(collect_native_shellbag_hive(hive))
    entries = [record for record in records if record.artifact_type == "shellbag-entry"]

    methods: Counter[str] = Counter()
    exists = 0
    parent_exists = 0
    missing: list[str] = []
    fs_paths = 0
    for record in entries:
        details = record.details
        shell_path = str(details.get("shell_path") or "")
        methods[str(details.get("shellitem", {}).get("decode_method") or "root")] += 1
        candidate = _fs_candidate(fs_root, shell_path)
        if candidate is None:
            continue
        fs_paths += 1
        if candidate.exists():
            exists += 1
        elif candidate.parent.exists():
            parent_exists += 1
        else:
            missing.append(shell_path)

    report = {
        "hive": str(hive.resolve()),
        "entries": len(entries),
        "decode_methods": dict(methods.most_common()),
        "fs_resolvable_paths": fs_paths,
        "exists_in_image": exists,
        "parent_exists_in_image": parent_exists,
        "missing_in_image": len(missing),
        "existence_ratio": round(exists / fs_paths, 4) if fs_paths else None,
        "missing_samples": missing[:20],
    }
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(
            f"entries={report['entries']} fs_paths={fs_paths} "
            f"exists={exists} parent_exists={parent_exists} missing={len(missing)} "
            f"existence_ratio={report['existence_ratio']}"
        )
        print(f"methods: {report['decode_methods']}")
    out = Path(__file__).resolve().parents[2] / "trusted-ref" / "shellbags-known-answer.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
