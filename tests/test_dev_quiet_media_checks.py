"""tests/quiet_media_checks.py (T-148): deepfake_lens check tracebacks stay out of test output."""

from __future__ import annotations

import contextlib
import io
import logging
import unittest
from pathlib import Path

from tests import quiet_media_checks


def _log_like_a_failed_check() -> str:
    """What deepfake_lens.checks.run_check does for an unreadable image, with stderr captured."""
    logger = logging.getLogger("deepfake_lens.checks")
    with contextlib.redirect_stderr(io.StringIO()) as err:
        try:
            raise OSError("Truncated File Read")
        except OSError:
            logger.exception("check %s failed", "image_class")
    return err.getvalue()


class QuietMediaChecksTests(unittest.TestCase):
    def setUp(self) -> None:
        root = logging.getLogger()
        # Only the last-resort handler (stderr) may be in play, as in a plain unittest run.
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        root.handlers = []
        package = logging.getLogger("deepfake_lens")
        self.addCleanup(package.setLevel, package.level)
        package.setLevel(logging.NOTSET)

    def test_silence_and_restore(self) -> None:
        self.assertIn("Truncated File Read", _log_like_a_failed_check())
        quiet_media_checks.setUpModule()
        try:
            self.assertEqual(_log_like_a_failed_check(), "")
            # nested opt-ins (one module importing another) unwind one level at a time
            quiet_media_checks.silence()
            quiet_media_checks.restore()
            self.assertEqual(_log_like_a_failed_check(), "")
        finally:
            quiet_media_checks.tearDownModule()
        self.assertEqual(logging.getLogger("deepfake_lens").level, logging.NOTSET)
        self.assertIn("check image_class failed", _log_like_a_failed_check())
        quiet_media_checks.tearDownModule()  # an extra restore is harmless
        self.assertEqual(logging.getLogger("deepfake_lens").level, logging.NOTSET)

    def test_noisy_modules_opt_in(self) -> None:
        tests_dir = Path(__file__).resolve().parent
        for name in ("test_rapidtriage_run", "test_rapidtriage_api", "test_rapidtriage_schemas"):
            with self.subTest(module=name):
                text = (tests_dir / f"{name}.py").read_text(encoding="utf-8")
                self.assertIn("setUpModule = quiet_media_checks.setUpModule", text)
                self.assertIn("tearDownModule = quiet_media_checks.tearDownModule", text)
        for name in ("test_upgrade_r7_state", "test_r8_import_readonly"):  # own tearDownModule
            with self.subTest(module=name):
                text = (tests_dir / f"{name}.py").read_text(encoding="utf-8")
                self.assertIn("setUpModule = quiet_media_checks.setUpModule", text)
                self.assertIn("    quiet_media_checks.tearDownModule()", text)


if __name__ == "__main__":
    unittest.main()
