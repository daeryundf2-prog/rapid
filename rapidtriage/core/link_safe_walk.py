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

CLI paths keep their historical walkers (``rglob``/``os.walk``, which follow
file links); the run's evidence walks (``files.iter_evidence_paths``,
``docs.scan_document_candidates``) filter them with ``RootLinkGuard`` so a link
never takes them outside the run root. ``iter_files_no_links`` is opt-in.
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
    return info_is_link(os.lstat(path))


def info_is_link(info: os.stat_result) -> bool:
    """Whether an ``lstat`` result is a link (symlink, junction, name-surrogate reparse point)."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    if not attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    tag = int(getattr(info, "st_reparse_tag", 0) or 0)
    return tag == 0 or bool(tag & REPARSE_TAG_NAME_SURROGATE) or stat.S_ISDIR(info.st_mode)


class RootLinkGuard:
    """Keeps an evidence walk inside its root when the walk itself follows links.

    ``allows(path)`` is false when ``path``, or a directory between it and
    ``root``, is a symlink/junction whose target resolves outside ``root``: an
    absolute link in evidence collected elsewhere would otherwise feed the
    analysis server's own files into the run outputs. Links that stay inside
    ``root`` are kept. Directory answers are memoized, so a walk pays one
    ``lstat`` per checked path plus one per directory; ``on_lstat(path, info)``
    receives each ``lstat`` result (stat caches can reuse it).
    """

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        on_lstat: Callable[[str, os.stat_result], None] | None = None,
    ) -> None:
        self._root = os.path.abspath(root)
        self._root_prefix = self._root.rstrip(os.sep) + os.sep
        real = os.path.normcase(os.path.realpath(root))
        self._real_root = real
        self._real_prefix = real.rstrip(os.sep) + os.sep
        self._on_lstat = on_lstat
        self._directories: dict[str, bool] = {}

    def allows(self, path: str | os.PathLike[str]) -> bool:
        text = os.path.abspath(path)
        return self._directory_allowed(os.path.dirname(text)) and self._entry_allowed(text, os.fspath(path))

    def _directory_allowed(self, directory: str) -> bool:
        if directory == self._root or not directory.startswith(self._root_prefix):
            return True
        allowed = self._directories.get(directory)
        if allowed is None:
            allowed = self._directory_allowed(os.path.dirname(directory)) and self._entry_allowed(directory, None)
            self._directories[directory] = allowed
        return allowed

    def _entry_allowed(self, text: str, reported_as: str | None) -> bool:
        try:
            info = os.lstat(text)
        except (OSError, ValueError):
            return True  # gone or unreadable: the caller's own stat/open fails as before
        if self._on_lstat is not None and reported_as is not None:
            self._on_lstat(reported_as, info)
        if not info_is_link(info):
            return True
        try:
            real = os.path.normcase(os.path.realpath(text))
        except (OSError, ValueError):
            return False
        return real == self._real_root or real.startswith(self._real_prefix)


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
