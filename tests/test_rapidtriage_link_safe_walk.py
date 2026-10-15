"""Link-safe evidence walk (``core.link_safe_walk``) and its opt-in use by ``core.vsc``."""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from rapidtriage.core import link_safe_walk, vsc
from rapidtriage.core.link_safe_walk import WalkStats, iter_files_no_links
from tests.test_rapidtriage_analyses import make_directory_link


class Cancelled(Exception):
    pass


class LinkSafeWalkTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "root"
        (self.root / "sub").mkdir(parents=True)
        (self.root / "a.txt").write_text("a", encoding="utf-8")
        (self.root / "sub" / "b.txt").write_text("b", encoding="utf-8")
        self.outside = self.base / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("outside", encoding="utf-8")

    def link(self, target: Path, link: Path) -> None:
        errors = make_directory_link(target, link)
        if errors:
            self.skipTest(f"cannot create a junction/symlink here: {errors}")

    def names(self, paths) -> list[str]:
        return sorted(path.relative_to(self.root).as_posix() for path in paths)

    def test_links_out_of_the_root_are_never_followed(self) -> None:
        self.link(self.outside, self.root / "esc")
        stats = WalkStats()
        self.assertEqual(self.names(iter_files_no_links(self.root, stats=stats)), ["a.txt", "sub/b.txt"])
        self.assertEqual(stats.skipped_links, 1)

    def test_symlinked_file_is_skipped(self) -> None:
        try:
            os.symlink(self.outside / "secret.txt", self.root / "secret-link.txt")
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create a file symlink here: {exc}")
        stats = WalkStats()
        self.assertEqual(self.names(iter_files_no_links(self.root, stats=stats)), ["a.txt", "sub/b.txt"])
        self.assertEqual(stats.skipped_links, 1)

    def test_junction_loop_terminates(self) -> None:
        self.link(self.root, self.root / "sub" / "loop")
        result: list[list[str]] = []
        worker = threading.Thread(target=lambda: result.append(self.names(iter_files_no_links(self.root))), daemon=True)
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "the walk must not follow a junction loop")
        self.assertEqual(result, [["a.txt", "sub/b.txt"]])

    def test_cancel_check_runs_every_n_entries_and_stops_the_walk(self) -> None:
        for number in range(20):
            (self.root / f"f{number:02d}.bin").write_bytes(b"x")
        calls: list[int] = []

        def check() -> None:
            calls.append(1)
            if len(calls) == 2:
                raise Cancelled()

        seen: list[Path] = []
        with self.assertRaises(Cancelled):
            for path in iter_files_no_links(self.root, check_cancel=check, every=5):
                seen.append(path)
        self.assertEqual(len(calls), 2)
        self.assertLess(len(seen), 22)

    def test_prune_dir_skips_subtrees(self) -> None:
        stats = WalkStats()
        paths = iter_files_no_links(self.root, prune_dir=lambda path: path.name == "sub", stats=stats)
        self.assertEqual(self.names(paths), ["a.txt"])
        self.assertEqual(stats.pruned_dirs, 1)

    @unittest.skipUnless(os.name == "nt", "reparse attributes exist on Windows only")
    def test_reparse_attribute_detects_junctions_without_is_junction(self) -> None:
        # Python 3.11 DirEntry has no is_junction: the attribute check alone must catch it.
        def entry(attributes: int, tag: int) -> SimpleNamespace:
            info = SimpleNamespace(st_file_attributes=attributes, st_reparse_tag=tag)
            return SimpleNamespace(is_symlink=lambda: False, stat=lambda follow_symlinks=True: info)

        junction = entry(link_safe_walk.FILE_ATTRIBUTE_REPARSE_POINT | 0x10, 0xA0000003)
        self.assertTrue(link_safe_walk.entry_is_directory_link(junction))
        self.assertFalse(link_safe_walk.entry_is_directory_link(entry(0x10, 0)))
        wof_file = entry(link_safe_walk.FILE_ATTRIBUTE_REPARSE_POINT, 0x80000017)  # data-carrying, not a link
        self.assertFalse(link_safe_walk.entry_is_file_link(wof_file))
        self.assertTrue(link_safe_walk.entry_is_file_link(entry(link_safe_walk.FILE_ATTRIBUTE_REPARSE_POINT, 0xA000000C)))

    def test_vsc_walks_skip_links_only_when_asked(self) -> None:
        self.link(self.outside, self.root / "esc")
        default = vsc.build_file_index(self.root, compute_hashes=False, case_sensitive=False)
        self.assertIn("esc/secret.txt", default, "the CLI walk keeps following links as before")
        stats = WalkStats()
        safe = vsc.build_file_index(self.root, compute_hashes=False, case_sensitive=False, skip_links=True, stats=stats)
        self.assertEqual(sorted(safe), ["a.txt", "sub/b.txt"])
        self.assertEqual(stats.skipped_links, 1)
        self.assertEqual(vsc.count_files_bounded(self.root, limit=10, skip_links=True), 2)
        self.assertEqual(vsc.count_files_bounded(self.root, limit=10), 3)

    def test_vsc_discover_skips_run_output_folders_and_excluded_dirs(self) -> None:
        current = self.base / "current"
        current.mkdir()
        (self.base / "HarddiskVolumeShadowCopy1").mkdir()
        (self.base / "rapidtriage-run-20261012").mkdir()
        own = self.base / "case-output-1"
        (own / "HarddiskVolumeShadowCopy2").mkdir(parents=True)
        payload = vsc.discover_vsc_snapshot_roots(current, max_depth=1, exclude_dirs=[own], skip_links=True)
        names = {Path(row["path"]).name for row in payload["snapshots"]}
        self.assertIn("HarddiskVolumeShadowCopy1", names)
        self.assertNotIn("rapidtriage-run-20261012", names)
        self.assertFalse(names & {"case-output-1", "HarddiskVolumeShadowCopy2"}, names)


if __name__ == "__main__":
    unittest.main()
