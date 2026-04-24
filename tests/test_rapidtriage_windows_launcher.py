from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


class RapidTriageWindowsLauncherTests(unittest.TestCase):
    def test_windows_launchers_exist_and_call_doctor_before_web(self) -> None:
        ps1 = REPO_ROOT / "scripts" / "windows" / "start-rapidtriage.ps1"
        bat = REPO_ROOT / "scripts" / "windows" / "start-rapidtriage.bat"

        self.assertTrue(ps1.is_file())
        self.assertTrue(bat.is_file())

        ps1_text = ps1.read_text(encoding="utf-8")
        bat_text = bat.read_text(encoding="utf-8")

        self.assertIn("Python virtual environment", ps1_text)
        self.assertIn("rapidtriage\", \"doctor", ps1_text)
        self.assertIn("rapidtriage\", \"web", ps1_text)
        self.assertLess(ps1_text.index("rapidtriage\", \"doctor"), ps1_text.index("rapidtriage\", \"web"))
        self.assertIn("ExecutionPolicy Bypass", bat_text)
        self.assertIn("start-rapidtriage.ps1", bat_text)

    def test_windows_quickstart_documents_launcher_and_fallbacks(self) -> None:
        doc = REPO_ROOT / "docs" / "rapidtriage-windows-quickstart.md"
        readme = REPO_ROOT / "README.md"

        self.assertTrue(doc.is_file())
        doc_text = doc.read_text(encoding="utf-8")
        readme_text = readme.read_text(encoding="utf-8")

        self.assertIn(".\\scripts\\windows\\start-rapidtriage.ps1", doc_text)
        self.assertIn("rapidtriage doctor", doc_text)
        self.assertIn("mounted/extracted folder", doc_text)
        self.assertIn("docs/rapidtriage-windows-quickstart.md", readme_text)
