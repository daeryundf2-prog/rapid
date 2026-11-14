#!/usr/bin/env python3
"""Fail when a tracked or new file has CRLF line endings (plan task T-149).

The repository is LF only.  Files that already had CRLF when this guard was
added are listed in ``scripts/dev/eol-baseline.json``; they may keep their
endings until someone fixes them.  The baseline is a ratchet: it may only
shrink.  A baseline entry whose file is now clean (or gone) fails the check
until it is removed, so a fixed file cannot go back to CRLF later.

What is checked (a few batched git calls, well under two seconds):

* the index copy of every tracked file (what the next commit will contain);
* the working-tree copy of tracked and untracked, not-ignored files, except
  where ``.gitattributes`` asks for CRLF in the working tree (``eol=crlf``,
  e.g. ``*.ps1``) — git stores those as LF.

Binary files (a NUL byte in the first 8000 bytes, git's own test) never count.

Examples::

    python scripts/dev/check-eol.py
    python scripts/dev/check-eol.py --json
    python scripts/dev/check-eol.py --repo <other checkout> --baseline <file>

Exit codes: 0 clean, 1 new CRLF or stale baseline entry, 2 usage/git error.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

DEFAULT_REPO = Path(__file__).resolve().parents[2]
BASELINE_NAME = "scripts/dev/eol-baseline.json"
BAD = ("crlf", "mixed")


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        cwd=repo,
        input=stdin,
        capture_output=True,
        check=True,
    ).stdout


def _paths(raw: bytes) -> list[str]:
    return [p for p in raw.decode("utf-8", "surrogateescape").split("\0") if p]


def classify(data: bytes) -> str | None:
    """'crlf', 'mixed' or None (LF only, no newline, or binary) — like git's i/ and w/ columns."""
    if b"\0" in data[:8000]:
        return None
    crlf = data.count(b"\r\n")
    if not crlf:
        return None
    return "mixed" if data.count(b"\n") > crlf else "crlf"


def _index_blobs(repo: Path, paths: list[str]) -> dict[str, bytes]:
    """Staged contents of ``paths`` via one ``git cat-file --batch`` call."""
    if not paths:
        return {}
    request = "".join(f":{path}\n" for path in paths).encode("utf-8", "surrogateescape")
    out = _git(repo, "cat-file", "--batch", stdin=request)
    blobs: dict[str, bytes] = {}
    pos = 0
    for path in paths:
        header_end = out.index(b"\n", pos)
        header = out[pos:header_end].split()
        pos = header_end + 1
        if len(header) == 3:
            size = int(header[2])
            blobs[path] = out[pos : pos + size]
            pos += size + 1
    return blobs


def _crlf_attr(repo: Path, paths: list[str]) -> set[str]:
    """Paths whose ``.gitattributes`` say ``eol=crlf`` (CRLF expected in the working tree)."""
    if not paths:
        return set()
    request = "".join(f"{path}\0" for path in paths).encode("utf-8", "surrogateescape")
    fields = _paths(_git(repo, "check-attr", "-z", "--stdin", "eol", stdin=request))
    return {fields[i] for i in range(0, len(fields) - 2, 3) if fields[i + 2] == "crlf"}


def find_crlf(repo: Path) -> dict[str, str]:
    """Map path -> 'crlf' or 'mixed' for every file with CRLF in index or working tree.

    Stat-clean tracked files have identical index and working-tree bytes, so the
    working-tree copy is read for every file and the index blob only for files
    that differ from it (``git diff``).  This is several times faster than
    ``git ls-files --eol`` on Windows.
    """
    # The three listings are independent: start them together (process start-up dominates on Windows).
    procs = [
        subprocess.Popen(
            ["git", "-c", "core.quotepath=off", *args],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        for args in (
            ("ls-files", "-z"),
            ("ls-files", "-z", "--others", "--exclude-standard"),
            ("diff", "--name-only", "-z"),
        )
    ]
    outputs = []
    for proc in procs:
        out, _ = proc.communicate()
        if proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, proc.args)
        outputs.append(_paths(out))
    tracked, untracked, changed = outputs
    found: dict[str, str] = {}
    worktree_hits: dict[str, str] = {}
    for path in dict.fromkeys(tracked + untracked):
        try:
            kind = classify((repo / path).read_bytes())
        except OSError:
            continue
        if kind:
            worktree_hits[path] = kind
    tracked_set = set(tracked)
    crlf_attr = _crlf_attr(repo, list(worktree_hits))
    # Index blobs are read where they may differ from the working tree: files
    # git reports as changed, and eol=crlf files (stored LF, checked out CRLF).
    read_index = [p for p in changed if p in tracked_set]
    read_index += [
        p
        for p in worktree_hits
        if p in crlf_attr and p in tracked_set and p not in read_index
    ]
    for path, kind in worktree_hits.items():
        if path not in crlf_attr:
            found[path] = kind
    for path, data in _index_blobs(repo, read_index).items():
        kind = classify(data)
        if kind:
            found[path] = kind
    return found


def load_baseline(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {entry["path"]: entry["eol"] for entry in data["files"]}


def check(repo: Path, baseline_path: Path) -> dict:
    baseline = load_baseline(baseline_path) if baseline_path.is_file() else {}
    found = find_crlf(repo)
    new = sorted(path for path in found if path not in baseline)
    stale = sorted(path for path in baseline if path not in found)
    return {
        "ok": not new and not stale,
        "baseline_count": len(baseline),
        "crlf_count": len(found),
        "new": [{"path": path, "eol": found[path]} for path in new],
        "stale_baseline": stale,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--repo", type=Path, default=DEFAULT_REPO, help="git checkout to check"
    )
    parser.add_argument(
        "--baseline", type=Path, help=f"baseline JSON (default: <repo>/{BASELINE_NAME})"
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    baseline_path = args.baseline or repo / BASELINE_NAME
    try:
        result = check(repo, baseline_path)
    except (subprocess.CalledProcessError, OSError, ValueError, KeyError) as exc:
        print(f"check-eol: error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for entry in result["new"]:
            print(f"check-eol: {entry['eol'].upper()} line endings: {entry['path']}")
        for path in result["stale_baseline"]:
            print(f"check-eol: now clean, remove from {BASELINE_NAME}: {path}")
        if result["new"]:
            print("check-eol: convert to LF (e.g. dos2unix <file>) before committing")
        if result["ok"]:
            print(
                f"check-eol: ok ({result['baseline_count']} baseline file(s) still CRLF)"
            )
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
