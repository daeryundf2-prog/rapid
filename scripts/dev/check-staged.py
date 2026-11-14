#!/usr/bin/env python3
"""Fail when the git index holds files that must not be committed (plan task T-149).

Run it right before ``git commit``.  It looks only at staged additions,
copies, modifications and renames (``git diff --cached``), and fails on:

* the built frontend bundle ``rapidtriage/web/static/v2/**`` — task worktrees
  never commit it; the coordinator builds and commits it once per wave
  (pass ``--allow-bundle`` there);
* anything under a ``node_modules/`` directory;
* local dev state files named ``.rt-dev.*``;
* evidence-like images: E01/E02..., Ex01..., dd, raw, img, vhd, vhdx, aff;
* blobs larger than ``--max-bytes`` (default 5 MiB);
* CRLF or mixed line endings in the staged copy, unless the path is in
  ``scripts/dev/eol-baseline.json``.

Examples::

    python scripts/dev/check-staged.py
    python scripts/dev/check-staged.py --allow-bundle --json

Exit codes: 0 clean, 1 something blocked, 2 usage/git error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

DEFAULT_REPO = Path(__file__).resolve().parents[2]
BASELINE_NAME = "scripts/dev/eol-baseline.json"
BUNDLE_PREFIX = "rapidtriage/web/static/v2/"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
EVIDENCE_SUFFIX = re.compile(r"\.(e\d{2}|ex\d{2}|dd|raw|img|vhdx?|aff)$", re.IGNORECASE)


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> str:
    return subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        cwd=repo,
        input=stdin,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8", "surrogateescape")


def staged_paths(repo: Path) -> list[str]:
    out = _git(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    return [path for path in out.split("\0") if path]


def classify(data: bytes) -> str | None:
    """'crlf', 'mixed' or None (LF only or binary); same rule as check-eol.py."""
    if b"\0" in data[:8000]:
        return None
    crlf = data.count(b"\r\n")
    if not crlf:
        return None
    return "mixed" if data.count(b"\n") > crlf else "crlf"


def blob_sizes(repo: Path, paths: list[str]) -> dict[str, int]:
    """Size in bytes of each path's staged blob."""
    if not paths:
        return {}
    request = "".join(f":{path}\n" for path in paths).encode("utf-8", "surrogateescape")
    lines = _git(
        repo, "cat-file", "--batch-check=%(objectsize)", stdin=request
    ).splitlines()
    return {
        path: int(line)
        for path, line in zip(paths, lines, strict=True)
        if line.isdigit()
    }


def index_eol(
    repo: Path, paths: list[str], sizes: dict[str, int], max_bytes: int
) -> dict[str, str]:
    """Line-ending kind of each staged blob that is small enough to read."""
    wanted = [path for path in paths if path in sizes and sizes[path] <= max_bytes]
    if not wanted:
        return {}
    request = "".join(f":{path}\n" for path in wanted).encode(
        "utf-8", "surrogateescape"
    )
    out = subprocess.run(
        ["git", "-c", "core.quotepath=off", "cat-file", "--batch"],
        cwd=repo,
        input=request,
        capture_output=True,
        check=True,
    ).stdout
    eols: dict[str, str] = {}
    pos = 0
    for path in wanted:
        header_end = out.index(b"\n", pos)
        header = out[pos:header_end].split()
        pos = header_end + 1
        if len(header) == 3:
            size = int(header[2])
            kind = classify(out[pos : pos + size])
            pos += size + 1
            if kind:
                eols[path] = kind
    return eols


def load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {
        entry["path"] for entry in json.loads(path.read_text(encoding="utf-8"))["files"]
    }


def path_reason(path: str, allow_bundle: bool) -> str | None:
    posix = PurePosixPath(path)
    if not allow_bundle and path.startswith(BUNDLE_PREFIX):
        return (
            "built frontend bundle (coordinator commits it; use --allow-bundle there)"
        )
    if "node_modules" in posix.parts[:-1]:
        return "node_modules content"
    if posix.name.startswith(".rt-dev."):
        return "local dev state file (.rt-dev.*)"
    if EVIDENCE_SUFFIX.search(posix.name):
        return "evidence-like image extension (keep evidence outside Git)"
    return None


def check(
    repo: Path, baseline_path: Path, *, allow_bundle: bool, max_bytes: int
) -> dict:
    paths = staged_paths(repo)
    baseline = load_baseline(baseline_path)
    sizes = blob_sizes(repo, paths)
    eols = index_eol(repo, paths, sizes, max_bytes)
    blocked = []
    for path in paths:
        reasons = []
        reason = path_reason(path, allow_bundle)
        if reason:
            reasons.append(reason)
        if sizes.get(path, 0) > max_bytes:
            reasons.append(f"{sizes[path]} bytes is over the {max_bytes}-byte limit")
        if path in eols and path not in baseline:
            reasons.append(f"{eols[path].upper()} line endings (repo is LF only)")
        if reasons:
            blocked.append({"path": path, "reasons": reasons})
    return {"ok": not blocked, "staged_count": len(paths), "blocked": blocked}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--repo", type=Path, default=DEFAULT_REPO, help="git checkout to check"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help=f"CRLF baseline JSON (default: <repo>/{BASELINE_NAME})",
    )
    parser.add_argument(
        "--allow-bundle",
        action="store_true",
        help=f"allow {BUNDLE_PREFIX}** (coordinator only)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="largest staged blob allowed",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        result = check(
            repo,
            args.baseline or repo / BASELINE_NAME,
            allow_bundle=args.allow_bundle,
            max_bytes=args.max_bytes,
        )
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError) as exc:
        print(f"check-staged: error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for entry in result["blocked"]:
            print(f"check-staged: {entry['path']}: {'; '.join(entry['reasons'])}")
        if result["blocked"]:
            print(
                "check-staged: unstage with `git restore --staged <path>`; stage files by name, never `git add -A`"
            )
        else:
            print(f"check-staged: ok ({result['staged_count']} staged file(s))")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
