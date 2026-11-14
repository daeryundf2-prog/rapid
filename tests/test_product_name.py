"""T-170 (D66): one product name across the screen, the CLI ``--version`` and the reports.

The UI strings live in TSX source (the wordmark, the landing heading, the page title); the CLI and
the report writers read ``rapidtriage.PRODUCT_NAME``. This test compares the three surfaces so a
rename in one place cannot drift from the others, and checks that "RapidForensic" never reaches a
rendered screen or an exported report.
"""

from __future__ import annotations

import io
import re
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from rapidtriage import PRODUCT_NAME, __version__
from rapidtriage.cli import main as cli_main
from rapidtriage.core.case_db.reporting import render_case_db_report_markdown
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    pdf_hex_text,
    write_case_report_exports,
)

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
OLD_NAME = "RapidForensic"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _wordmark_text(source: str) -> str:
    """The Brand wordmark's visible text with the inner JSX tags removed."""
    match = re.search(r'<span className="brand-word">(.*?)</span>\s*</span>', source, re.DOTALL)
    if not match:
        raise AssertionError("brand-word span not found in BrandMark.tsx")
    return re.sub(r"<[^>]+>", "", match.group(1)).strip()


def _cli_version() -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli_main(["--version"])
    if code not in (0, None):
        raise AssertionError(f"--version exited {code}")
    return buffer.getvalue().strip()


class ProductNameTest(unittest.TestCase):
    def test_decided_name(self) -> None:
        self.assertEqual(PRODUCT_NAME, "RapidTriage")

    def test_ui_surfaces_use_the_product_name(self) -> None:
        brand = _read("frontend/src/shell/BrandMark.tsx")
        self.assertEqual(_wordmark_text(brand), PRODUCT_NAME)
        landing = _read("frontend/src/features/case/Landing.tsx")
        heading = re.search(r'<h1 id="landing-title"[^>]*>\s*(.*?)\s*</h1>', landing, re.DOTALL)
        self.assertIsNotNone(heading)
        assert heading is not None
        self.assertEqual(heading.group(1).strip(), PRODUCT_NAME)
        index_html = _read("frontend/index.html")
        self.assertIn(f"<title>{PRODUCT_NAME}</title>", index_html)

    def test_cli_version_uses_the_product_name(self) -> None:
        self.assertEqual(_cli_version(), f"{PRODUCT_NAME} {__version__}")

    def test_case_db_report_uses_the_product_name(self) -> None:
        markdown, _ = render_case_db_report_markdown(
            case_id="case-1",
            items=[],
            citation_index=[],
            status_counts={},
            verification_counts={},
            item_preview_limit=10,
        )
        self.assertTrue(markdown.startswith(f"# {PRODUCT_NAME} Case DB Report Export"))
        self.assertNotIn(OLD_NAME, markdown)

    def test_four_report_formats_carry_the_same_tool_name(self) -> None:
        markdown = build_case_report_markdown(
            run_summary={},
            case_payload={"case_id": "case-1"},
            submission_manifest={"generated_at": "2026-11-12T00:00:00Z", "evidence": []},
        )
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_case_report_exports(markdown, Path(tmp) / "report.md")
            md = Path(paths["md"]).read_text(encoding="utf-8")
            html = Path(paths["html"]).read_text(encoding="utf-8")
            with zipfile.ZipFile(paths["docx"]) as archive:
                docx = "".join(archive.read(name).decode("utf-8") for name in archive.namelist())
            pdf = Path(paths["pdf"]).read_bytes().decode("latin-1")
        pdf_name = pdf_hex_text(PRODUCT_NAME)[1:-1]
        pdf_old = pdf_hex_text(OLD_NAME)[1:-1]
        surfaces = {"md": md, "html": html, "docx": docx}
        for kind, text in surfaces.items():
            with self.subTest(kind=kind):
                self.assertIn(PRODUCT_NAME, text)
                self.assertNotIn(OLD_NAME, text)
        self.assertIn(pdf_name, pdf)
        self.assertNotIn(pdf_old, pdf)

    def test_rendered_frontend_source_has_no_old_name(self) -> None:
        # Font-family names ("RapidForensic UI") are CSS identifiers, never rendered text.
        offenders = []
        for path in (FRONTEND / "src").rglob("*.tsx"):
            if ".test." in path.name:
                continue
            if OLD_NAME in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
