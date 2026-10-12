"""Directory walk that never leaves its root through a link.

API analysis jobs walk evidence trees that the examiner did not build. A
symlink or an NTFS junction (or any other directory reparse point) inside such
a tree can point outside the run's allowed roots, or back at an ancestor so
that a naive ``rglob`` never terminates. ``iter_files_no_links``:

* lists directories with ``os.scandir`` and never descends into a symlinked
  directory, a junction, or any directory carrying
  ``FILE_ATTRIBUTE_REPARSE_POINT`` (Python 3.11 has no
  ``DirEntry.is_junction``; the attribute is read from
  ``entry.stat(follow_symlinks=False)``);
* never yields a symlinked file, nor a file whose reparse tag is a *name
  surrogate* (a link); data-carrying reparse files (WOF-compressed, dedup,
  cloud placeholders) are still yielded because they are real file content;
* counts what it skipped in ``WalkStats`` (``skipped_links``, ``pruned_dirs``,
  ``unreadable_dirs``) so callers can report it;
* calls ``check_cancel`` every ``every`` walked directory entries, files or
  not, so even a huge or adversarial tree stays cancellable.

CLI paths keep their historical (link-following) walkers; this module is
opt-in.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# Reparse tags with this bit set are name surrogates (junctions, symlinks).
REPARSE_TAG_NAME_SURROGATE = 0x20000000
CANCEL_CHECK_EVERY = 500


@dataclass
class WalkStats:
    skipped_links: int = 0
    pruned_dirs: int = 0
    unreadable_dirs: int = 0


def _reparse_info(entry: os.DirEntry[str]) -> tuple[bool, int]:
    """``(has_reparse_attribute, reparse_tag)``; always ``(False, 0)`` off Windows."""
    if os.name != "nt":
        return False, 0
    info = entry.stat(follow_symlinks=False)
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT), int(getattr(info, "st_reparse_tag", 0) or 0)


def entry_is_directory_link(entry: os.DirEntry[str]) -> bool:
    """A directory entry the walk must not descend into (symlink, junction, any reparse point)."""
    if entry.is_symlink():
        return True
    is_junction = getattr(entry, "is_junction", None)  # Python 3.12+
    if is_junction is not None and is_junction():
        return True
    has_reparse, _tag = _reparse_info(entry)
    return has_reparse


def entry_is_file_link(entry: os.DirEntry[str]) -> bool:
    """A file entry that is a link (symlink or name-surrogate reparse point)."""
    if entry.is_symlink():
        return True
    has_reparse, tag = _reparse_info(entry)
    # An unknown tag (0) with the reparse attribute is treated as a link.
    return has_reparse and (tag == 0 or bool(tag & REPARSE_TAG_NAME_SURROGATE))


def lstat_is_link(path: str | os.PathLike[str]) -> bool:
    """``os.lstat``-based link test for one path (symlink, junction, name-surrogate reparse point)."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    if not attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    tag = int(getattr(info, "st_reparse_tag", 0) or 0)
    return tag == 0 or bool(tag & REPARSE_TAG_NAME_SURROGATE) or stat.S_ISDIR(info.st_mode)


def iter_files_no_links(
    root: Path,
    *,
    check_cancel: Callable[[], None] | None = None,
    every: int = CANCEL_CHECK_EVERY,
    prune_dir: Callable[[Path], bool] | None = None,
    stats: WalkStats | None = None,
) -> Iterator[Path]:
    """Regular files below ``root`` (depth first, names sorted per directory), links skipped.

    ``prune_dir(path)`` returning true skips that directory's subtree (e.g.
    run-output folders). ``root`` itself is walked as given; callers resolve
    and confine it first.
    """
    stats = stats if stats is not None else WalkStats()
    every = max(1, int(every))
    pending: list[Path] = [Path(root)]
    walked = 0
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            stats.unreadable_dirs += 1
            continue
        for entry in entries:
            walked += 1
            if check_cancel is not None and walked % every == 0:
                check_cancel()
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry_is_directory_link(entry):
                        stats.skipped_links += 1
                        continue
                    path = Path(entry.path)
                    if prune_dir is not None and prune_dir(path):
                        stats.pruned_dirs += 1
                        continue
                    pending.append(path)
                elif entry_is_file_link(entry):
                    stats.skipped_links += 1
                elif entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
            except OSError:
                continue
