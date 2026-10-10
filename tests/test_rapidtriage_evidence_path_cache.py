from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rapidtriage.core import files as files_module
from rapidtriage.core.files import (
    disable_evidence_path_cache,
    enable_evidence_path_cache,
    iter_evidence_paths,
)

PATTERNS = (
    "*",
    "$I*",
    "*.reg",
    "Report.wer",
    "*Zone.Identifier",
    "SRUDB.dat",
    "*.apk",
    "$Recycle.Bin",
    "applicationHost.config",
)


def build_evidence_tree(root: Path) -> None:
    layout = [
        "Windows/System32/config/SYSTEM",
        "Windows/System32/config/SOFTWARE",
        "Windows/System32/sru/SRUDB.dat",
        "Windows/System32/inetsrv/config/applicationHost.config",
        "Windows/System32/winevt/Logs/Security.evtx",
        "Windows/System32/Tasks/Microsoft/Updater",
        "exports/system.reg",
        "exports/UPPER.REG",
        "exports/.hidden.reg",
        "$Recycle.Bin/S-1-5-21-1/$IABC123.txt",
        "$Recycle.Bin/S-1-5-21-1/$RABC123.txt",
        "$Recycle.Bin/S-1-5-21-1/$iLower.docx",
        "ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_1/Report.wer",
        "Users/alice/AppData/Local/Microsoft/Windows/WER/ReportQueue/AppCrash_2/report.WER",
        "Users/alice/Downloads/setup.exe_Zone.Identifier",
        "Users/alice/Downloads/app.apk",
        "Users/alice/Downloads/nested/archive/Game.APK",
        "Users/alice/NTUSER.DAT",
        "Users/bob/Documents/srudb.dat",
        "Users/bob/rapidtriage-run-old/leftover.reg",
        "rapidtriage-run-hacking/rapidtriage-docs.json",
        "rapidtriage-run-progress.json",
    ]
    for relative in layout:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding="utf-8")
    (root / "Users" / "carol" / "Empty").mkdir(parents=True)


def collect(root: Path, pattern: str) -> list[str]:
    return [str(path) for path in iter_evidence_paths(root, pattern)]


class EvidencePathCacheTests(unittest.TestCase):
    def tearDown(self) -> None:
        # Never leak an enabled cache into other test modules.
        while files_module._EVIDENCE_PATH_CACHE_USERS:
            disable_evidence_path_cache()

    def test_cache_is_disabled_by_default(self) -> None:
        self.assertFalse(files_module._EVIDENCE_PATH_CACHE_ENABLED)
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_evidence_tree(root)
            collect(root, "*")
        self.assertEqual(files_module._EVIDENCE_PATH_CACHE, {})

    def test_cached_results_match_uncached_walk_for_roots_and_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            build_evidence_tree(root)
            roots = [
                root,
                root / "Users",
                root / "Users" / "alice",
                root / "Windows" / "System32",
                root / "ProgramData",
                root / "$Recycle.Bin",
                root / "Users" / "bob" / "rapidtriage-run-old",
                root / "Users" / "carol" / "Empty",
                root / "missing",
                root / "Windows" / "System32" / "sru" / "SRUDB.dat",
            ]
            if os.name == "nt":
                roots.append(Path(str(root / "users" / "ALICE")))
            expected = {(str(item), pattern): collect(item, pattern) for item in roots for pattern in PATTERNS}

            enable_evidence_path_cache()
            try:
                # Warm the cache from the top-level root first, then answer
                # every sub-root and pattern from that single snapshot.
                collect(root, "*")
                actual = {(str(item), pattern): collect(item, pattern) for item in roots for pattern in PATTERNS}
            finally:
                disable_evidence_path_cache()

        for key, paths in expected.items():
            self.assertEqual(sorted(actual[key]), sorted(paths), key)
            self.assertEqual(len(actual[key]), len(paths), key)
        # Sanity: the fixture actually exercises pruning and case-folding.
        top = expected[(str(root), "*")]
        self.assertFalse(any("rapidtriage-run" in item for item in top))
        reg_names = sorted(Path(item).name for item in expected[(str(root), "*.reg")])
        if os.name == "nt":
            self.assertEqual(reg_names, [".hidden.reg", "UPPER.REG", "system.reg"])
            self.assertEqual(len(expected[(str(root), "$I*")]), 2)
        else:
            self.assertEqual(reg_names, [".hidden.reg", "system.reg"])

    def test_sub_root_queried_before_parent_matches_uncached_walk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "evidence"
            build_evidence_tree(root)
            users = root / "Users"
            expected_users = collect(users, "*")
            expected_root = collect(root, "*.apk")

            enable_evidence_path_cache()
            try:
                self.assertEqual(sorted(collect(users, "*")), sorted(expected_users))
                self.assertEqual(sorted(collect(root, "*.apk")), sorted(expected_root))
                # The parent snapshot replaces the narrower sub-root snapshot.
                self.assertEqual(len(files_module._EVIDENCE_PATH_CACHE), 1)
            finally:
                disable_evidence_path_cache()

    def test_cache_walks_each_tree_once_and_clears_on_disable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_evidence_tree(root)
            original_rglob = Path.rglob
            with mock.patch.object(Path, "rglob", autospec=True, side_effect=original_rglob) as rglob:
                enable_evidence_path_cache()
                try:
                    first = collect(root, "*")
                    self.assertEqual(rglob.call_count, 1)
                    second = collect(root, "*")
                    collect(root / "Users", "*")
                    collect(root, "*.reg")
                    collect(root / "Windows", "SRUDB.dat")
                    self.assertEqual(rglob.call_count, 1)
                    self.assertEqual(first, second)
                    # Patterns with separators bypass the cache and walk normally.
                    list(iter_evidence_paths(root, "Users/*"))
                    self.assertEqual(rglob.call_count, 2)
                    self.assertTrue(files_module._EVIDENCE_PATH_CACHE)
                finally:
                    disable_evidence_path_cache()
                self.assertEqual(files_module._EVIDENCE_PATH_CACHE, {})
                self.assertFalse(files_module._EVIDENCE_PATH_CACHE_ENABLED)
                collect(root, "*")
                self.assertEqual(rglob.call_count, 3)
                self.assertEqual(files_module._EVIDENCE_PATH_CACHE, {})

    def test_literal_pattern_casing_follows_selected_pathlib_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            build_evidence_tree(root)
            users = root / "Users"
            enable_evidence_path_cache()
            try:
                collect(root, "*")
                # Python <3.12 (_PreciseSelector): literal names take the
                # pattern's casing, wildcard patterns keep on-disk names.
                with mock.patch.object(files_module, "_literal_pattern_uses_pattern_casing", return_value=True):
                    legacy_literal = collect(users, "Report.wer")
                    legacy_wildcard = collect(users, "*.WER")
                    legacy_dir = collect(root, "$Recycle.Bin")
                # Python 3.12+: every match keeps its on-disk name.
                with mock.patch.object(files_module, "_literal_pattern_uses_pattern_casing", return_value=False):
                    modern_literal = collect(users, "Report.wer")
            finally:
                disable_evidence_path_cache()
            # Probe while the fixture still exists: case-insensitive filesystems
            # (Windows, default macOS APFS) resolve the pattern's casing.
            wer_probe = users / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "WER" / "ReportQueue" / "AppCrash_2"
            fs_case_insensitive = (wer_probe / "Report.wer").exists()

        wer_dir = users / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "WER" / "ReportQueue" / "AppCrash_2"
        # 3.12+ matches on-disk names: case-insensitive only where pathlib
        # normalises case (Windows). <3.12 probes ``dir / pattern`` for
        # existence, so any case-insensitive filesystem (Windows, default
        # macOS APFS) yields the pattern's casing.
        self.assertEqual(modern_literal, [str(wer_dir / "report.WER")] if os.name == "nt" else [])
        self.assertEqual(legacy_literal, [str(wer_dir / "Report.wer")] if fs_case_insensitive else [])
        self.assertEqual(legacy_wildcard, [str(wer_dir / "report.WER")])
        self.assertEqual(legacy_dir, [str(root / "$Recycle.Bin")])
        self.assertEqual(
            files_module._literal_pattern_uses_pattern_casing(),
            sys.version_info < (3, 12),
        )

    def test_nested_enable_keeps_cache_until_last_disable(self) -> None:
        enable_evidence_path_cache()
        enable_evidence_path_cache()
        disable_evidence_path_cache()
        self.assertTrue(files_module._EVIDENCE_PATH_CACHE_ENABLED)
        disable_evidence_path_cache()
        self.assertFalse(files_module._EVIDENCE_PATH_CACHE_ENABLED)


if __name__ == "__main__":
    unittest.main()
