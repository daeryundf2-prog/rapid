from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.carving import run_bounded_carving


class RapidTriageCarvingTests(unittest.TestCase):
    def test_parser_exposes_carve_subcommand(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("carve", commands)
        self.assertIn("--max-candidates", commands["carve"].format_help())

    def test_bounded_carving_reports_offsets_and_hashes_without_extracting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            blob = b"noise" + b"%PDF-1.7\nbody\n%%EOF" + b"gap" + b"\xff\xd8\xffimage\xff\xd9"
            (root / "unallocated.bin").write_bytes(blob)

            payload = run_bounded_carving(root, output_dir, max_candidates=10)

            self.assertEqual(payload["command"], "carve")
            self.assertEqual(payload["summary"]["candidate_count"], 2)
            self.assertEqual(payload["summary"]["extracted_count"], 0)
            kinds = {entry["kind"] for entry in payload["entries"]}
            self.assertEqual(kinds, {"pdf", "jpeg"})
            offsets = {entry["kind"]: entry["offset"] for entry in payload["entries"]}
            self.assertEqual(offsets["pdf"], 5)
            self.assertGreater(offsets["jpeg"], offsets["pdf"])
            self.assertTrue((output_dir / "rapidtriage-carve.json").is_file())
            self.assertFalse((output_dir / "carved").exists())

    def test_bounded_carving_extracts_candidates_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            (root / "slack.bin").write_bytes(b"prefix\x89PNG\r\n\x1a\npayloadIEND\xaeB`\x82suffix")

            payload = run_bounded_carving(root, output_dir, extract=True)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["extracted_count"], 1)
            extracted_path = Path(str(payload["entries"][0]["extracted_path"]))
            self.assertTrue(extracted_path.is_file())
            self.assertEqual(extracted_path.suffix, ".png")

    def test_cli_carve_outputs_json_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            (root / "slack.bin").write_bytes(b"PK\x03\x04zip-fragment")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                exit_code = main(["carve", str(root), "--output-dir", str(output_dir), "--extract", "--json"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertTrue((output_dir / "rapidtriage-carve.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-carve.audit.json").is_file())


if __name__ == "__main__":
    unittest.main()
