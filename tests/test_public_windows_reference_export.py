"""Check the public-image export budget before any files are extracted."""

import io
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

export = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/public-windows-reference-export.py"))


class PublicWindowsExportTests(unittest.TestCase):
    def test_budget_includes_browser_journal_and_filtered_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            listing = root / "allocated.body"
            output = root / "source"
            profile = "/Users/profile/AppData/Local/vendor/browser/User Data/Default/"
            logs = "/Windows/System32/winevt/Logs/"
            records = [(profile + "History", 200), (profile + "History-wal", 45),
                       (logs + "System.evtx", 30), (logs + "Application.evtx", 1000)]
            listing.write_text("".join(
                f"0|{path}|{i}-128-1|r/rrwxrwxrwx|0|0|{size}|0|0|0|0\n"
                for i, (path, size) in enumerate(records, 1)
            ))
            argv = ["export", "--body", str(listing), "--image", "example.E01", "--sector", "0",
                    "--output", str(output), "--include-browser", "--event-log", "system.evtx", "--max-bytes", "250"]
            err = io.StringIO()
            with patch.object(sys, "argv", argv), patch("subprocess.run") as icat, redirect_stderr(err):
                with self.assertRaises(SystemExit) as raised:
                    export["main"]()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("selected 275 bytes exceeds the 250 byte limit", err.getvalue())
            icat.assert_not_called()
            self.assertFalse(output.exists())

    def test_short_long_and_failed_streams_leave_no_reference_tree(self):
        popen = subprocess.Popen
        for size, status in ((2, 0), (4, 0), (3, 1)):
            with self.subTest(size=size, status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                listing = root / "allocated.body"
                listing.write_text(
                    "0|/Windows/System32/config/SYSTEM|7-128-1|r/rrwx|0|0|3|0|0|0|0\n"
                    "0|/Windows/System32/config/SOFTWARE|8-128-1|r/rrwx|0|0|3|0|0|0|0\n"
                )
                output = root / "ref"
                argv = ["export", "--body", str(listing), "--image", "sample.E01",
                        "--sector", "0", "--output", str(output), "--max-bytes", "6"]

                def fake_icat(command, *, size=size, status=status, **kwargs):
                    second = command[-1] == "8-128-1"
                    script = "import sys; sys.stdout.buffer.write(b'x' * int(sys.argv[1])); sys.exit(int(sys.argv[2]))"
                    return popen([sys.executable, "-c", script, str(size if second else 3),
                                  str(status if second else 0)], **kwargs)

                with patch.object(sys, "argv", argv), patch.object(subprocess, "Popen", fake_icat):
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        export["main"]()
                self.assertFalse(output.exists())

    def test_legacy_system_root_machine_hive_and_named_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            listing = root / "allocated.body"
            listing.write_text(
                "0|/WINNT/system32/config/SAM|7-128-1|r/rrwx|0|0|3|0|0|0|0\n"
                "0|/WINNT/system32/config/SAM:extra|7-128-2|r/rrwx|0|0|3|0|0|0|0\n"
            )
            output = root / "ref"
            argv = ["export", "--body", str(listing), "--image", "sample.E01",
                    "--sector", "63", "--output", str(output)]
            popen = subprocess.Popen

            def fake_icat(command, **kwargs):
                self.assertEqual(list(map(str, command)), ["icat", "-o", "63", "sample.E01", "7-128-1"])
                return popen([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'abc')"], **kwargs)

            with patch.object(sys, "argv", argv), patch.object(subprocess, "Popen", fake_icat):
                export["main"]()
            self.assertEqual((output / "WINNT/system32/config/SAM").read_bytes(), b"abc")

    def test_publication_failure_releases_reserved_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = root / "allocated.body"
            body.write_text("0|/Windows/System32/config/SYSTEM|7-128-1|r/rrwx|0|0|0|0|0|0|0\n")
            output = root / "ref"
            argv = ["export", "--body", str(body), "--image", "sample.E01",
                    "--sector", "0", "--output", str(output)]

            popen = subprocess.Popen

            def empty_stream(_command, **kwargs):
                return popen([sys.executable, "-c", "pass"], **kwargs)

            with (
                patch.object(sys, "argv", argv),
                patch.object(subprocess, "Popen", empty_stream),
                patch.object(Path, "rename", side_effect=OSError("synthetic publication failure")),
                self.assertRaisesRegex(OSError, "publication failure"),
            ):
                export["main"]()
            self.assertFalse(output.exists())
