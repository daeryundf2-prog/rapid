from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dashcam_tools import ingest, report
from dashcam_tools import _rename_impl as rename_impl


class DashcamToolsTests(unittest.TestCase):
    def test_ingest_rsync_copy_wraps_missing_rsync_as_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            src = root / "src"
            dst = root / "dst"
            src.mkdir()

            with patch("dashcam_tools.ingest.subprocess.run", side_effect=FileNotFoundError("rsync missing")):
                with self.assertRaisesRegex(RuntimeError, "FileNotFoundError: rsync missing"):
                    ingest.rsync_copy(src, dst)

    def test_ingest_unmount_command_converts_missing_tool_to_completed_process(self) -> None:
        with patch("dashcam_tools.ingest.subprocess.run", side_effect=FileNotFoundError("fusermount missing")):
            result = ingest.run_unmount_command(["fusermount", "-u", "/mnt/evidence"])

        self.assertEqual(result.returncode, 127)
        self.assertIn("FileNotFoundError: fusermount missing", result.stderr)

    def test_ingest_run_renamer_counts_failed_profiles(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], check: bool = False):
            calls.append(cmd)
            return SimpleNamespace(returncode=1 if cmd[-1] == "bad" else 0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("dashcam_tools.ingest.subprocess.run", side_effect=fake_run):
                failures = ingest.run_renamer(
                    Path(tmp_dir),
                    ["good", "bad"],
                    strict_ocr=False,
                    prefer_start=False,
                    workers=1,
                    max_ocr=0,
                    extra_args=[],
                )

        self.assertEqual(failures, 1)
        self.assertEqual([call[-1] for call in calls], ["good", "bad"])

    def test_rename_main_returns_nonzero_when_file_rename_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            video = root / "20240102_030405.mp4"
            video.write_bytes(b"video")
            bad_destination = root / "missing-parent" / "20240102_030405.mp4"

            with patch("dashcam_tools._rename_impl.unique_path", return_value=bad_destination):
                exit_code = rename_impl.main(
                    [
                        "--dir",
                        str(root),
                        "--profile",
                        "generic",
                        "--no-meta",
                        "--no-ocr",
                        "--state",
                        str(root / "state.sqlite"),
                    ]
                )

        self.assertEqual(exit_code, 1)

    def test_report_records_hash_errors_without_silent_degradation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            video = root / "20240102_030405.mp4"
            output_json = root / "timeline.json"
            output_csv = root / "timeline.csv"
            video.write_bytes(b"video")

            with patch("dashcam_tools.report.compute_hash", side_effect=OSError("hash denied")):
                with patch(
                    "dashcam_tools.report.get_file_times",
                    return_value=(None, dt.datetime(2024, 1, 2, 3, 4, 5)),
                ):
                    exit_code = report.main(
                        [
                            "--dir",
                            str(root),
                            "--profile",
                            "generic",
                            "--no-ocr",
                            "--hash",
                            "sha256",
                            "--csv",
                            str(output_csv),
                            "--json",
                            str(output_json),
                        ]
                    )

            payload = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["summary"]["error_count"], 1)
        self.assertTrue(payload["summary"]["degraded"])
        self.assertEqual(payload["errors"][0]["stage"], "hash")
        self.assertIn("OSError: hash denied", payload["errors"][0]["error"])


if __name__ == "__main__":
    unittest.main()
