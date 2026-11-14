"""R8 T-197: ``scripts/collector-profile.py`` on a synthetic tree (no real evidence)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "collector-profile.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("collector_profile", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


profile = _load_script()


def _synthetic_tree(base: Path) -> Path:
    root = base / "tree"
    recent = root / "Users" / "tester" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    recent.mkdir(parents=True)
    (recent / "a.lnk").write_bytes(b"not a shell link" * 8)
    (root / "Windows" / "System32").mkdir(parents=True)
    (root / "Windows" / "System32" / "x.bin").write_bytes(b"\x00" * 64)
    return root


class ClassifyTests(unittest.TestCase):
    def test_frames_group_by_module(self) -> None:
        self.assertEqual(profile.classify_frame("C:/py/Lib/pathlib.py", "rglob"), "traversal")
        self.assertEqual(profile.classify_frame("C:/py/Lib/pathlib.py", "read_bytes"), "read")
        self.assertEqual(profile.classify_frame("~", "<built-in method nt.scandir>"), "traversal")
        self.assertEqual(profile.classify_frame("~", "<method 'read' of '_io.BufferedReader' objects>"), "read")
        self.assertEqual(profile.classify_frame("D:/x/rapidtriage/core/files.py", "iter_evidence_paths"), "traversal")
        self.assertEqual(profile.classify_frame("D:/x/rapidtriage/core/artifacts.py", "stream_artifact_collection"), "output")
        self.assertEqual(profile.classify_frame("D:/x/rapidtriage/artifacts/email.py", "parse_pst"), "parse")

    def test_bucket_stats_sums_exclusive_time(self) -> None:
        stats = {
            ("C:/py/Lib/pathlib.py", 1, "rglob"): (1, 1, 2.0, 2.0, {}),
            ("D:/x/rapidtriage/artifacts/email.py", 1, "parse"): (1, 1, 6.0, 6.0, {}),
            ("~", 0, "<built-in method io.open>"): (1, 1, 1.0, 1.0, {}),
        }
        seconds, top = profile.bucket_stats(stats)
        self.assertEqual((seconds["traversal"], seconds["parse"], seconds["read"]), (2.0, 6.0, 1.0))
        self.assertEqual(top[0]["bucket"], "parse")

    def test_cause_labels(self) -> None:
        self.assertEqual(profile.classify_cause({"traversal": 8, "read": 1, "parse": 1, "output": 0}, wall=10), "전체 순회")
        self.assertEqual(profile.classify_cause({"traversal": 1, "read": 8, "parse": 1, "output": 0}, wall=10), "대용량 훑기")
        self.assertEqual(profile.classify_cause({"traversal": 1, "read": 1, "parse": 8, "output": 0}, wall=10), "파싱")
        self.assertEqual(profile.classify_cause({"traversal": 3, "read": 3, "parse": 3, "output": 1}, wall=10), "기타")
        self.assertEqual(profile.classify_cause({"traversal": 1, "read": 0, "parse": 0, "output": 0}, wall=0.1), "기타")

    def test_sanitize_drops_paths(self) -> None:
        text = profile._sanitize(r"failed D:\evidence\tree\Users\bob\x.dat and /mnt/x/y/z.db", Path(r"D:\evidence\tree"))
        self.assertNotIn("bob", text)
        self.assertNotIn("evidence", text)

    def test_markdown_table_handles_plain_partial_and_failed_rows(self) -> None:
        base = {"wall_s": 1.0, "artifact_count": 0, "walk_calls": 1, "walk_entries": 5, "unique_files_opened": 2, "big_files_opened": 0}
        report = {
            "collectors": [
                {"kind": "a", **base},
                {"kind": "b", **base, "buckets_s": dict.fromkeys(profile.BUCKETS, 1.0), "cause": "파싱", "partial_by_budget": True},
                {"kind": "c", "error": "timeout after 5 s"},
            ]
        }
        table = profile.markdown_table(report)
        self.assertIn("| a |", table)
        self.assertIn("파싱 (부분)", table)
        self.assertIn("실패: timeout", table)

    def test_top_collectors_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            providers = {"a": {"duration_ms": 1000}, "b": {"duration_ms": 9000}, "c": {"duration_ms": 5000}}
            (run / "rapidtriage-run-progress.json").write_text(json.dumps({"providers": providers}), encoding="utf-8")
            self.assertEqual([k for k, _ in profile.top_collectors(run, 2)], ["b", "c"])


class EndToEndTests(unittest.TestCase):
    def test_profiles_one_collector_and_keeps_tree_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = _synthetic_tree(base)
            out = base / "out"
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = profile.main(["--root", str(root), "--output-dir", str(out), "--kinds", "recent-files", "--json", "--timeout", "300"])
            self.assertEqual(code, 0, buffer.getvalue())
            report = json.loads(buffer.getvalue())
            self.assertTrue(report["tree"]["unchanged"])
            (row,) = report["collectors"]
            self.assertEqual(row["kind"], "recent-files")
            self.assertEqual(row["writes_blocked"], 0)
            self.assertGreaterEqual(row["walk_calls"], 0)
            self.assertEqual(set(row["buckets_s"]), set(profile.BUCKETS))
            self.assertGreaterEqual(row["profiled_s"], 0)  # a tiny synthetic tree can round to 0 on a fast runner
            self.assertIn(row["cause"], {"전체 순회", "대용량 훑기", "파싱", "기타"})

    def test_output_dir_inside_root_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _synthetic_tree(Path(tmp))
            self.assertEqual(profile.main(["--root", str(root), "--output-dir", str(root / "o"), "--kinds", "p2p"]), 2)


if __name__ == "__main__":
    unittest.main()
