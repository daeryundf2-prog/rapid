#!/usr/bin/env python3
"""Evidence snapshot: record and compare every file under evidence roots (R8 T-003, QA-001).

Snapshot: for each file under the roots, the relative path, size, mtime_ns and SHA-256.
Compare: list changed / new / deleted files; exit 1 when anything differs.

  python scripts/r8-evidence-snapshot.py --root E:/evid --output D:/qa/evid_before.json
  python scripts/r8-evidence-snapshot.py --compare D:/qa/evid_before.json D:/qa/evid_after.json
  # F.1 V-RD shorthand (roots from R8_EVIDENCE_ROOTS, state dir from R8_QA_DIR):
  python scripts/r8-evidence-snapshot.py --before
  python scripts/r8-evidence-snapshot.py --after --diff

Read-only on the evidence: nothing is written inside a root, and an output path inside a
root is refused. ``--redact-names`` replaces relative paths with their SHA-256 so the JSON
carries no file names (comparison still works because the same name hashes the same).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "r8-evidence-snapshot/1"
CHUNK = 1024 * 1024
ENV_ROOTS = "R8_EVIDENCE_ROOTS"
ENV_STATE = "R8_QA_DIR"
BEFORE_NAME = "evid_before.json"
AFTER_NAME = "evid_after.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _name_key(rel: str, redact: bool) -> str:
    return (
        "sha256:" + hashlib.sha256(rel.encode("utf-8")).hexdigest() if redact else rel
    )


def snapshot(roots: list[Path], *, redact_names: bool = False) -> dict:
    files: dict[str, dict] = {}
    for idx, root in enumerate(roots):
        root = root.resolve()
        targets = (
            [root]
            if root.is_file()
            else sorted(p for p in root.rglob("*") if p.is_file())
        )
        for path in targets:
            rel = path.name if root.is_file() else path.relative_to(root).as_posix()
            key = _name_key(f"{idx}/{rel}", redact_names)
            st = path.stat()
            files[key] = {
                "size": st.st_size,
                "mtime_ns": st.st_mtime_ns,
                "sha256": sha256_file(path),
            }
    return {
        "schema": SCHEMA,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "redacted_names": redact_names,
        "roots": len(roots) if redact_names else [str(r) for r in roots],
        "file_count": len(files),
        "total_bytes": sum(f["size"] for f in files.values()),
        "files": files,
    }


def compare(before: dict, after: dict) -> dict:
    a, b = before["files"], after["files"]
    changed = []
    for key in sorted(a.keys() & b.keys()):
        fields = [
            f for f in ("size", "mtime_ns", "sha256") if a[key].get(f) != b[key].get(f)
        ]
        if fields:
            changed.append({"path": key, "fields": fields})
    result = {
        "changed": changed,
        "new": sorted(b.keys() - a.keys()),
        "deleted": sorted(a.keys() - b.keys()),
    }
    if before.get("redacted_names") != after.get("redacted_names"):
        result["warning"] = (
            "snapshots differ in --redact-names; paths cannot be matched"
        )
    result["identical"] = not (changed or result["new"] or result["deleted"])
    return result


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _write_json(path: Path, data: dict, roots: list[Path]) -> None:
    for root in roots:
        if _inside(path, root if root.is_dir() else root.parent):
            raise SystemExit(f"refusing to write inside an evidence root: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _roots_from(args: argparse.Namespace) -> list[Path]:
    raw = list(args.root or [])
    if not raw and os.environ.get(ENV_ROOTS):
        raw = [p for p in os.environ[ENV_ROOTS].split(os.pathsep) if p]
    roots = [Path(p) for p in raw]
    for root in roots:
        if not root.exists():
            raise SystemExit(f"evidence root not found: {root}")
    return roots


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--root",
        action="append",
        help=f"evidence folder or file (repeatable; default ${ENV_ROOTS})",
    )
    ap.add_argument(
        "--output",
        type=Path,
        help="snapshot or diff JSON destination (outside the roots)",
    )
    ap.add_argument("--compare", nargs=2, type=Path, metavar=("BEFORE", "AFTER"))
    ap.add_argument(
        "--before", action="store_true", help=f"snapshot to ${ENV_STATE}/{BEFORE_NAME}"
    )
    ap.add_argument(
        "--after", action="store_true", help=f"snapshot to ${ENV_STATE}/{AFTER_NAME}"
    )
    ap.add_argument(
        "--diff",
        action="store_true",
        help="with --after: compare against the before snapshot",
    )
    ap.add_argument(
        "--state-dir",
        type=Path,
        help=f"folder for --before/--after (default ${ENV_STATE})",
    )
    ap.add_argument(
        "--redact-names",
        action="store_true",
        help="store SHA-256 of relative paths instead of names",
    )
    ap.add_argument("--json", action="store_true", help="print the result JSON")
    args = ap.parse_args(argv)

    if args.compare:
        before, after = (
            json.loads(p.read_text(encoding="utf-8")) for p in args.compare
        )
        result = compare(before, after)
        if args.output:
            _write_json(args.output, result, [])
        _print_diff(result, args.json)
        return 0 if result["identical"] else 1

    roots = _roots_from(args)
    if not roots:
        ap.error(f"--root (or ${ENV_ROOTS}) is required for a snapshot")
    if args.before or args.after:
        state = args.state_dir or (
            Path(os.environ[ENV_STATE]) if os.environ.get(ENV_STATE) else None
        )
        if state is None:
            ap.error(f"--before/--after need --state-dir or ${ENV_STATE}")
        output = state / (BEFORE_NAME if args.before else AFTER_NAME)
    elif args.output:
        output = args.output
    else:
        ap.error("--output is required (snapshots are never written into the evidence)")
    data = snapshot(roots, redact_names=args.redact_names)
    _write_json(output, data, roots)
    if args.json:
        print(
            json.dumps(
                {k: v for k, v in data.items() if k != "files"},
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(
            f"snapshot: {data['file_count']} files, {data['total_bytes']} bytes -> {output}"
        )
    if args.after and args.diff:
        before_path = output.parent / BEFORE_NAME
        result = compare(json.loads(before_path.read_text(encoding="utf-8")), data)
        _write_json(output.parent / "evid_diff.json", result, roots)
        _print_diff(result, args.json)
        return 0 if result["identical"] else 1
    return 0


def _print_diff(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(
        f"changed {len(result['changed'])} · new {len(result['new'])} · deleted {len(result['deleted'])}"
        f" -> {'IDENTICAL' if result['identical'] else 'DIFFERENT'}"
    )
    for item in result["changed"]:
        print(f"  changed {item['path']} ({', '.join(item['fields'])})")
    for path in result["new"]:
        print(f"  new     {path}")
    for path in result["deleted"]:
        print(f"  deleted {path}")
    if "warning" in result:
        print(f"  warning: {result['warning']}")


if __name__ == "__main__":
    sys.exit(main())
