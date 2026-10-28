from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("r8_bench", REPO_ROOT / "scripts" / "r8-bench.py")
bench = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bench)


RUN_START_EPOCH = 1_000_000.0


def _write_run_outputs(out_dir: Path) -> None:
    """Write a run summary shaped like a real rapidtriage-run-summary.json."""
    steps = []
    for name, offset in (("manifest", 1.5), ("docs", 2.0)):
        output = out_dir / f"rapidtriage-{name}.json"
        output.write_text("{}", encoding="utf-8")
        os.utime(output, (RUN_START_EPOCH + offset, RUN_START_EPOCH + offset))
        steps.append({"name": name, "status": "completed", "output": str(output)})
    summary = {
        "steps": steps,
        "summary": {"scanned_file_count": 10, "files_extracted_count": 2, "artifacts": {"x": 1}},
        "safety": {"artifact_scheduler": {"max_workers": 4, "manifest": {"events": [{"duration_ms": 300}, {"duration_ms": 200}]}}},
        "coverage": [{"area": "carving", "reason_code": "scan-cap", "limit": 1, "observed": 2, "unit": "bytes"}],
    }
    (out_dir / "rapidtriage-run-summary.json").write_text(json.dumps(summary), encoding="utf-8")


class R8BenchTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.image = self.root / "case.E01"
        self.image.write_bytes(b"segment-one")
        self.out_root = self.root / "out"
        self.rapid_root = self.root / "checkout"
        self.rapid_root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, fake_runner, extra: list[str] | None = None) -> tuple[int, dict]:
        argv = ["--image", str(self.image), "--label", "t", "--out-root", str(self.out_root), *(extra or [])]
        with (
            mock.patch.object(bench, "run_sampled", fake_runner),
            mock.patch.object(bench.time, "time", return_value=RUN_START_EPOCH),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            code = bench.main(argv)
        out_json = self.out_root / "t" / bench.image_set_id(Path(os.path.abspath(self.image))) / "r8-bench.json"
        return code, json.loads(out_json.read_text(encoding="utf-8"))

    def test_image_set_id_is_12_hex_of_path_sha256(self) -> None:
        expected = hashlib.sha256(str(self.image).encode("utf-8")).hexdigest()[:12]
        self.assertEqual(bench.image_set_id(self.image), expected)
        self.assertRegex(expected, r"^[0-9a-f]{12}$")

    def test_success_writes_schema_stages_counts_and_coverage(self) -> None:
        def fake_runner(cmd, log_path, cwd):
            _write_run_outputs(Path(cmd[cmd.index("--output-dir") + 1]))
            return 0, 123.4, 55.0

        code, data = self._run(fake_runner)

        self.assertEqual(code, 0)
        self.assertEqual(data["schema"], "r8-bench-v1")
        self.assertEqual(data["run_exit_code"], 0)
        self.assertEqual(data["stages"], {"manifest": 1.5, "docs": 2.0})
        self.assertEqual(data["provider_ms"], {"manifest": 500})
        self.assertEqual(data["counts"], {"scanned_file_count": 10, "files_extracted_count": 2})
        self.assertEqual(data["coverage"][0]["reason_code"], "scan-cap")
        self.assertEqual(data["peak_rss_mb"], 123.4)
        self.assertEqual(data["system_cpu_mean"], 55.0)
        self.assertEqual(data["cpu_count"], os.cpu_count())
        self.assertTrue(data["segments_unchanged"])
        self.assertNotIn(self.image.name, json.dumps(data))

    def test_missing_outputs_yield_empty_sections(self) -> None:
        code, data = self._run(lambda cmd, log_path, cwd: (0, None, None))

        self.assertEqual(code, 0)
        self.assertEqual(data["stages"], {})
        self.assertEqual(data["counts"], {})
        self.assertEqual(data["provider_ms"], {})
        self.assertEqual(data["coverage"], [])
        self.assertIsNone(data["peak_rss_mb"])
        self.assertIsNone(data["system_cpu_mean"])

    def test_changed_segment_exits_3(self) -> None:
        def fake_runner(cmd, log_path, cwd):
            self.image.write_bytes(b"segment-one-changed")
            return 0, None, None

        code, data = self._run(fake_runner)

        self.assertEqual(code, bench.EXIT_SEGMENTS_CHANGED)
        self.assertFalse(data["segments_unchanged"])

    def test_run_failure_still_writes_json(self) -> None:
        code, data = self._run(lambda cmd, log_path, cwd: (1, None, None))

        self.assertEqual(code, 1)
        self.assertEqual(data["run_exit_code"], 1)
        self.assertTrue(data["segments_unchanged"])

    def test_rapid_root_is_subprocess_cwd_and_code_rev(self) -> None:
        seen: dict[str, Path] = {}

        def fake_runner(cmd, log_path, cwd):
            seen["cwd"] = cwd
            return 0, None, None

        with mock.patch.object(bench, "git_short_head", return_value="abc1234") as head:
            _, data = self._run(fake_runner, ["--rapid-root", str(self.rapid_root)])

        self.assertEqual(seen["cwd"], Path(os.path.abspath(self.rapid_root)))
        head.assert_called_once_with(Path(os.path.abspath(self.rapid_root)))
        self.assertEqual(data["code_rev"], "abc1234")

    def test_rapid_root_defaults_to_repo_root(self) -> None:
        seen: dict[str, Path] = {}

        def fake_runner(cmd, log_path, cwd):
            seen["cwd"] = cwd
            return 0, None, None

        self._run(fake_runner)

        self.assertEqual(seen["cwd"], bench.REPO_ROOT)

    def test_run_sampled_runs_in_given_cwd(self) -> None:
        log_path = self.root / "probe.log"
        code, peak, cpu = bench.run_sampled(
            [sys.executable, "-c", "import os; print(os.getcwd())"], log_path, self.rapid_root
        )

        self.assertEqual(code, 0)
        printed = Path(log_path.read_text(encoding="utf-8").strip())
        self.assertEqual(printed.resolve(), self.rapid_root.resolve())

    def test_git_short_head_is_none_when_git_missing(self) -> None:
        with mock.patch.object(bench.subprocess, "run", side_effect=OSError("no git")):
            self.assertIsNone(bench.git_short_head(self.rapid_root))

    def test_snapshot_counts_only_segments_sharing_stem(self) -> None:
        (self.root / "case.E02").write_bytes(b"two")
        (self.root / "case.E100").write_bytes(b"ignored")
        (self.root / "case.txt").write_bytes(b"ignored")
        (self.root / "other.E01").write_bytes(b"ignored")

        self.assertEqual(len(bench.snapshot_segments(self.image)), 2)

    def test_snapshot_covers_ex01_and_post_e99_segments(self) -> None:
        for name in ("case.Ex01", "case.EAA", "case.ExAA", "case.E99"):
            (self.root / name).write_bytes(b"segment")
        (self.root / "case.E100").write_bytes(b"ignored")
        before = bench.snapshot_segments(self.image)

        self.assertEqual(len(before), 5)
        (self.root / "case.ExAA").write_bytes(b"segment-changed")
        self.assertNotEqual(bench.snapshot_segments(self.image), before)


if __name__ == "__main__":
    unittest.main()
