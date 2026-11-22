"""Check the public-image export budget before any files are extracted."""

import io
import runpy
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
