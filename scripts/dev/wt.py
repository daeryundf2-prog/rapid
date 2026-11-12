#!/usr/bin/env python3
"""Worktree tool for parallel RapidTriage work (plan task T-150).

Commands::

    python scripts/dev/wt.py new <branch> [--from <ref>] [--name <dir>]
    python scripts/dev/wt.py rm <name-or-path> [--force]
    python scripts/dev/wt.py prune [--merged-into <ref>] [--dry-run | --apply] [--force] [--json]

``new`` creates ``.claude/worktrees/<name>``, links ``frontend/node_modules`` to the
main checkout's copy (a junction on Windows, a symlink elsewhere), picks three
ports from the name hash (API 8720-8789, Vite 5200-5269, e2e 8800-8869; a slot
already used by another worktree is skipped) and writes them to ``.rt-dev.env``.

``rm`` stops only the process trees whose PIDs are recorded in ``.rt-dev.pids``,
removes the ``node_modules`` link itself (never what it points to), then runs
``git worktree remove``.  A dirty or locked worktree is refused unless
``--force``.  Deleting a worktree while the link is still in place can wipe the
real ``node_modules``, which is why the link always goes first.

``prune`` lists unlocked worktrees under ``.claude/worktrees`` and local
branches that are merged into ``--merged-into``.  It deletes nothing unless
``--apply`` is given.

The main checkout is never a target, and the main ``frontend/node_modules`` is
never written to.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

WORKTREES_DIR = Path(".claude") / "worktrees"
NODE_MODULES = Path("frontend") / "node_modules"
ENV_FILE = ".rt-dev.env"
PIDS_FILE = ".rt-dev.pids"
OWN_FILES = (ENV_FILE, PIDS_FILE)
DEFAULT_INTEGRATION = "feat/r6-ux"
PROTECTED_BRANCHES = frozenset({"main", "master"})

PORT_SLOTS = 70
API_BASE = 8720
VITE_BASE = 5200
E2E_BASE = 8800
RESERVED_PORTS = frozenset({8710, 8791})
PORT_KEYS = ("RAPIDTRIAGE_API_PORT", "RAPIDTRIAGE_VITE_PORT", "RAPIDTRIAGE_E2E_PORT")

IS_WINDOWS = os.name == "nt"


class WtError(RuntimeError):
    """A refusal or failure that is reported to the user with exit code 1."""


# --------------------------------------------------------------------------- git


def git(
    args: list[str], cwd: Path, check: bool = True
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if check and proc.returncode != 0:
        raise WtError(
            f"git {' '.join(args)} failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc


def main_root(start: Path) -> Path:
    """Return the main checkout (the parent of the shared .git directory)."""
    common = git(
        ["rev-parse", "--path-format=absolute", "--git-common-dir"], start
    ).stdout.strip()
    common_path = Path(common)
    if common_path.name != ".git":
        raise WtError(f"unsupported repository layout (common dir {common_path})")
    return common_path.parent.resolve()


def same_path(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a.resolve())) == os.path.normcase(str(b.resolve()))


def same_path_lexical(a: Path, b: Path) -> bool:
    """Compare without following links (a junction must not resolve to its target)."""
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def is_within(child: Path, parent: Path) -> bool:
    child_s = os.path.normcase(str(child.resolve()))
    parent_s = os.path.normcase(str(parent.resolve()))
    return child_s == parent_s or child_s.startswith(parent_s.rstrip("\\/") + os.sep)


@dataclass
class Worktree:
    path: Path
    head: str = ""
    branch: str | None = None
    locked: bool = False
    prunable: bool = False
    detached: bool = False


def list_worktrees(root: Path) -> list[Worktree]:
    out = git(["worktree", "list", "--porcelain"], root).stdout
    items: list[Worktree] = []
    current: Worktree | None = None
    for line in out.splitlines():
        if line.startswith("worktree "):
            current = Worktree(path=Path(line[len("worktree ") :]))
            items.append(current)
        elif current is None:
            continue
        elif line.startswith("HEAD "):
            current.head = line[5:]
        elif line.startswith("branch "):
            current.branch = line[7:].removeprefix("refs/heads/")
        elif line == "detached":
            current.detached = True
        elif line == "locked" or line.startswith("locked "):
            current.locked = True
        elif line == "prunable" or line.startswith("prunable "):
            current.prunable = True
    return items


# ------------------------------------------------------------------------- ports


def port_offset(name: str) -> int:
    return (
        int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:4], "big")
        % PORT_SLOTS
    )


def ports_for(offset: int) -> tuple[int, int, int]:
    return API_BASE + offset, VITE_BASE + offset, E2E_BASE + offset


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.startswith("#"):
            values[key.strip()] = value.strip()
    return values


def used_offsets(root: Path, skip: Path | None = None) -> set[int]:
    used: set[int] = set()
    base = root / WORKTREES_DIR
    if not base.is_dir():
        return used
    for child in base.iterdir():
        if skip is not None and same_path(child, skip):
            continue
        env = read_env(child / ENV_FILE)
        try:
            used.add(int(env["RAPIDTRIAGE_API_PORT"]) - API_BASE)
        except (KeyError, ValueError):
            continue
    return used


def allocate_ports(name: str, used: set[int]) -> tuple[int, int, int]:
    start = port_offset(name)
    for step in range(PORT_SLOTS):
        offset = (start + step) % PORT_SLOTS
        if offset in used:
            continue
        ports = ports_for(offset)
        if RESERVED_PORTS.isdisjoint(ports):
            return ports
    raise WtError(
        f"all {PORT_SLOTS} port slots are in use; remove stale worktrees first"
    )


# ------------------------------------------------------------------------- links


def is_link(path: Path) -> bool:
    return path.is_symlink() or os.path.isjunction(path)


def make_link(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    if IS_WINDOWS:
        proc = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0 or not os.path.isjunction(link):
            raise WtError(
                f"mklink /J failed: {proc.stderr.strip() or proc.stdout.strip()}"
            )
    else:
        os.symlink(target, link, target_is_directory=True)


def remove_link(link: Path) -> None:
    """Remove only the link entry; refuse anything that is a real directory."""
    if not is_link(link):
        raise WtError(f"{link} is not a junction/symlink; refusing to remove it")
    if IS_WINDOWS and os.path.isjunction(link):
        proc = subprocess.run(
            ["cmd", "/c", "rmdir", str(link)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise WtError(f"rmdir of junction {link} failed: {proc.stderr.strip()}")
    else:
        link.unlink()
    if os.path.lexists(link):
        raise WtError(f"link {link} still present after removal")


# --------------------------------------------------------------------- processes


def read_pids(path: Path) -> list[int]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [int(tok) for tok in re.findall(r"\d+", text) if int(tok) > 0]


def kill_tree(pid: int) -> bool:
    if pid == os.getpid():
        return False
    if IS_WINDOWS:
        proc = subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0
    import signal

    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return False
    return True


# ---------------------------------------------------------------------- commands


def safe_name(branch: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", branch).strip("-.")
    if not name:
        raise WtError(f"cannot derive a directory name from {branch!r}")
    return name


def cmd_new(root: Path, branch: str, ref: str, name: str | None) -> dict[str, object]:
    dir_name = safe_name(name or branch)
    path = root / WORKTREES_DIR / dir_name
    if os.path.lexists(path):
        raise WtError(f"{path} already exists")
    ports = allocate_ports(dir_name, used_offsets(root))

    exists = git(
        ["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], root, check=False
    )
    if exists.returncode == 0:
        git(["worktree", "add", str(path), branch], root)
    else:
        git(["worktree", "add", "-b", branch, str(path), ref], root)

    target = root / NODE_MODULES
    link = path / NODE_MODULES
    linked = False
    if target.is_dir() and not os.path.lexists(link):
        make_link(link, target)
        linked = True

    api, vite, e2e = ports
    (path / ENV_FILE).write_text(
        "# written by scripts/dev/wt.py new; local only\n"
        f"RT_WT_NAME={dir_name}\n"
        f"RT_WT_BRANCH={branch}\n"
        f"RAPIDTRIAGE_API_PORT={api}\n"
        f"RAPIDTRIAGE_VITE_PORT={vite}\n"
        f"RAPIDTRIAGE_E2E_PORT={e2e}\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "path": str(path),
        "branch": branch,
        "node_modules_linked": linked,
        "ports": {"api": api, "vite": vite, "e2e": e2e},
    }


def dirty_entries(path: Path) -> list[str]:
    out = git(["status", "--porcelain", "--ignore-submodules"], path).stdout
    dirty = []
    nm = NODE_MODULES.as_posix()
    for line in out.splitlines():
        entry = line[3:].strip().strip('"').rstrip("/")
        if entry in OWN_FILES or entry == nm or entry.startswith(nm + "/"):
            continue
        dirty.append(line)
    return dirty


def resolve_target(root: Path, spec: str) -> Path:
    candidate = Path(spec)
    if candidate.is_absolute():
        return Path(os.path.abspath(candidate))
    by_name = root / WORKTREES_DIR / spec
    if os.path.lexists(by_name) or len(candidate.parts) == 1:
        return by_name
    return Path(os.path.abspath(candidate))


def find_links(path: Path, depth: int = 3) -> list[Path]:
    """Junctions/symlinks in the top ``depth`` levels (not descending into them or .git)."""
    found: list[Path] = []
    level = [path]
    for _ in range(depth):
        nxt: list[Path] = []
        for directory in level:
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for entry in entries:
                child = Path(entry.path)
                if is_link(child):
                    found.append(child)
                elif entry.is_dir(follow_symlinks=False) and entry.name not in {
                    ".git",
                    "node_modules",
                }:
                    nxt.append(child)
        level = nxt
    return found


def guard_target(root: Path, path: Path) -> None:
    if same_path(path, root):
        raise WtError("refusing to touch the main checkout")
    if not is_within(path, root / WORKTREES_DIR) or same_path(
        path, root / WORKTREES_DIR
    ):
        raise WtError(f"{path} is not under {root / WORKTREES_DIR}")
    if is_within(Path.cwd(), path):
        raise WtError(
            "refusing to remove the worktree that contains the current directory"
        )


def cmd_rm(root: Path, spec: str, force: bool) -> dict[str, object]:
    path = resolve_target(root, spec)
    guard_target(root, path)
    known = {os.path.normcase(str(w.path.resolve())): w for w in list_worktrees(root)}
    wt = known.get(os.path.normcase(str(path.resolve())))
    if wt is None:
        raise WtError(f"{path} is not a registered worktree")
    if wt.locked and not force:
        raise WtError(f"{path} is locked (in use); pass --force to remove it anyway")
    if path.is_dir():
        dirty = dirty_entries(path)
        if dirty and not force:
            raise WtError(
                f"{path} has uncommitted changes ({len(dirty)}); pass --force to discard"
            )
        others = [
            p for p in find_links(path) if not same_path_lexical(p, path / NODE_MODULES)
        ]
        if others:
            names = ", ".join(str(p) for p in others)
            raise WtError(
                f"other junctions/symlinks found ({names}); remove them with rmdir first"
            )

    killed = [pid for pid in read_pids(path / PIDS_FILE) if kill_tree(pid)]

    link = path / NODE_MODULES
    real_nm = root / NODE_MODULES
    unlinked = False
    if os.path.lexists(link) and is_link(link):
        remove_link(link)
        unlinked = True
    elif link.is_dir() and real_nm.is_dir() and os.path.samefile(link, real_nm):
        raise WtError(
            f"{link} resolves to the main node_modules but is not a plain link; refusing"
        )

    for own in OWN_FILES:
        try:
            (path / own).unlink()
        except FileNotFoundError:
            pass

    args = ["worktree", "remove"]
    if force:
        args += ["--force", "--force"] if wt.locked else ["--force"]
    git([*args, str(path)], root)
    return {"path": str(path), "killed_pids": killed, "node_modules_unlinked": unlinked}


@dataclass
class PrunePlan:
    merged_into: str
    worktrees: list[dict[str, object]] = field(default_factory=list)
    branches: list[str] = field(default_factory=list)
    skipped_locked: int = 0
    skipped_unmerged: int = 0
    skipped_outside: int = 0
    missing: int = 0


def build_prune_plan(root: Path, ref: str) -> PrunePlan:
    git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], root)
    plan = PrunePlan(merged_into=ref)
    merged = set(
        git(
            ["branch", "--merged", ref, "--format=%(refname:short)"], root
        ).stdout.split()
    )
    managed = root / WORKTREES_DIR
    checked_out: set[str] = set()
    removable_branches: set[str] = set()

    for wt in list_worktrees(root):
        if same_path(wt.path, root):
            if wt.branch:
                checked_out.add(wt.branch)
            continue
        inside = is_within(wt.path, managed)
        if not inside or wt.locked:
            if wt.branch:
                checked_out.add(wt.branch)
            if not inside:
                plan.skipped_outside += 1
            else:
                plan.skipped_locked += 1
            continue
        if wt.branch:
            is_merged = wt.branch in merged
        else:
            is_merged = (
                git(
                    ["merge-base", "--is-ancestor", wt.head, ref], root, check=False
                ).returncode
                == 0
            )
        if not is_merged:
            if wt.branch:
                checked_out.add(wt.branch)
            plan.skipped_unmerged += 1
            continue
        if wt.prunable or not wt.path.is_dir():
            plan.missing += 1
        if wt.branch:
            removable_branches.add(wt.branch)
        plan.worktrees.append(
            {
                "path": str(wt.path),
                "branch": wt.branch,
                "missing": wt.prunable or not wt.path.is_dir(),
            }
        )

    ref_short = ref.removeprefix("refs/heads/")
    for branch in sorted(merged):
        if branch in PROTECTED_BRANCHES or branch == ref_short:
            continue
        if branch in checked_out and branch not in removable_branches:
            continue
        plan.branches.append(branch)
    return plan


def apply_prune(root: Path, plan: PrunePlan, force: bool) -> dict[str, list[str]]:
    removed: list[str] = []
    failed: list[str] = []
    for item in plan.worktrees:
        path = str(item["path"])
        if item["missing"]:
            continue
        try:
            cmd_rm(root, path, force)
            removed.append(path)
        except WtError as exc:
            failed.append(f"{path}: {exc}")
    if any(item["missing"] for item in plan.worktrees):
        git(["worktree", "prune"], root)
    still_out = {w.branch for w in list_worktrees(root) if w.branch}
    deleted: list[str] = []
    for branch in plan.branches:
        if branch in still_out:
            failed.append(f"branch {branch}: still checked out")
            continue
        proc = git(["branch", "-D", branch], root, check=False)
        (deleted if proc.returncode == 0 else failed).append(
            branch
            if proc.returncode == 0
            else f"branch {branch}: {proc.stderr.strip()}"
        )
    return {"removed_worktrees": removed, "deleted_branches": deleted, "failed": failed}


# --------------------------------------------------------------------------- cli


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "-C", "--repo", type=Path, default=Path.cwd(), help="any path inside the repo"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser(
        "new", help="create a worktree with node_modules link and ports"
    )
    p_new.add_argument("branch")
    p_new.add_argument(
        "--from", dest="ref", default="HEAD", help="start point for a new branch"
    )
    p_new.add_argument(
        "--name", help="directory name under .claude/worktrees (default: branch)"
    )

    p_rm = sub.add_parser("rm", help="remove a worktree after unlinking node_modules")
    p_rm.add_argument("target", help="directory name under .claude/worktrees or a path")
    p_rm.add_argument(
        "--force", action="store_true", help="remove even if dirty or locked"
    )

    p_prune = sub.add_parser(
        "prune", help="list (or with --apply delete) merged worktrees/branches"
    )
    p_prune.add_argument("--merged-into", default=DEFAULT_INTEGRATION)
    mode = p_prune.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="list only (the default)")
    mode.add_argument(
        "--apply", action="store_true", help="actually remove worktrees and branches"
    )
    p_prune.add_argument(
        "--force", action="store_true", help="with --apply: remove dirty worktrees too"
    )
    p_prune.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = main_root(args.repo)
        if args.command == "new":
            result = cmd_new(root, args.branch, args.ref, args.name)
            print(json.dumps(result, indent=2))
        elif args.command == "rm":
            result = cmd_rm(root, args.target, args.force)
            print(json.dumps(result, indent=2))
        else:
            plan = build_prune_plan(root, args.merged_into)
            report: dict[str, object] = asdict(plan)
            report["worktree_count"] = len(plan.worktrees)
            report["branch_count"] = len(plan.branches)
            report["applied"] = bool(args.apply)
            if args.apply:
                report.update(apply_prune(root, plan, args.force))
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                verb = "removing" if args.apply else "would remove"
                for item in plan.worktrees:
                    print(f"worktree  {item['path']}  [{item['branch'] or 'detached'}]")
                for branch in plan.branches:
                    print(f"branch    {branch}")
                print(
                    f"{verb}: {len(plan.worktrees)} worktrees, {len(plan.branches)} branches "
                    f"merged into {plan.merged_into} (skipped: {plan.skipped_locked} locked, "
                    f"{plan.skipped_unmerged} unmerged, {plan.skipped_outside} outside .claude/worktrees)"
                )
                if args.apply and report.get("failed"):
                    for line in report["failed"]:  # type: ignore[union-attr]
                        print(f"failed    {line}", file=sys.stderr)
            if args.apply and report.get("failed"):
                return 1
    except WtError as exc:
        print(f"wt: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
