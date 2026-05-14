from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.files import run_files_scan


class FileSignatureMismatchTests(unittest.TestCase):
    def test_file_scan_flags_extension_signature_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disguised = root / "holiday.jpg"
            normal = root / "screenshot.png"
            disguised.write_bytes(b"MZ\x90\x00not really a jpeg")
            normal.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)

            payload = run_files_scan(root, categories=["images"])

        self.assertEqual(payload["summary"]["signature_checked_count"], 2)
        self.assertEqual(payload["summary"]["signature_mismatch_count"], 1)
        self.assertEqual(payload["summary"]["signature_unrecognized_known_extension_count"], 0)
        by_name = {row["name"]: row for row in payload["candidates"]}
        self.assertEqual(by_name["holiday.jpg"]["file_signature"]["status"], "extension-signature-mismatch")
        self.assertEqual(by_name["holiday.jpg"]["file_signature"]["detected"], "windows-pe")
        self.assertEqual(by_name["screenshot.png"]["file_signature"]["status"], "signature-matches-extension")
        self.assertEqual(payload["signature_mismatch_candidates"][0]["name"], "holiday.jpg")
        self.assertEqual(payload["signature_mismatch_candidates"][0]["forensic_review"]["status"], "needs-review")

    def test_unknown_header_for_known_extension_is_not_hidden_or_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            truncated_pdf = root / "broken.pdf"
            truncated_pdf.write_bytes(b"not a pdf header")

            payload = run_files_scan(root, categories=["documents"])

        self.assertEqual(payload["summary"]["candidate_count"], 1)
        self.assertEqual(payload["summary"]["signature_checked_count"], 1)
        self.assertEqual(payload["summary"]["signature_mismatch_count"], 0)
        self.assertEqual(payload["summary"]["signature_unrecognized_known_extension_count"], 1)
        self.assertEqual(
            payload["candidates"][0]["file_signature"]["status"],
            "unrecognized-header-for-known-extension",
        )


if __name__ == "__main__":
    unittest.main()
