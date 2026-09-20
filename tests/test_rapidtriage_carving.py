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
            blob = b"noise" + b"%PDF-1.7\nbody\n%%EOF" + b"gap" + b"\xff\xd8\xff\xe0image\xff\xd9"
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
            (root / "slack.bin").write_bytes(b"prefix\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDRpayloadIEND\xaeB`\x82suffix")

            payload = run_bounded_carving(root, output_dir, extract=True)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["extracted_count"], 1)
            extracted_path = Path(str(payload["entries"][0]["extracted_path"]))
            self.assertTrue(extracted_path.is_file())
            self.assertEqual(extracted_path.suffix, ".png")

    def test_sqlite_carving_uses_declared_size_and_validates_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            header = (
                b"SQLite format 3\x00"
                + (1024).to_bytes(2, "big")  # page size
                + b"\x02\x02"  # write/read versions (WAL)
                + b"\x00"  # reserved space
                + b"\x40\x20\x20"  # payload fractions
                + b"\x00\x00\x00\x01"  # change counter
                + (3).to_bytes(4, "big")  # database size in pages
            )
            blob = b"pad" + header + b"\x00" * (3 * 1024 - len(header)) + b"trailing"
            (root / "free.bin").write_bytes(blob)

            payload = run_bounded_carving(root, output_dir, max_candidates=10)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            entry = payload["entries"][0]
            self.assertEqual(entry["kind"], "sqlite")
            self.assertEqual(entry["status"], "length-field")
            self.assertEqual(entry["size"], 3 * 1024)
            self.assertEqual(entry["end_offset"], 3 + 3 * 1024)
            self.assertEqual(entry["confidence"], "high")
            self.assertEqual(entry["recovery"]["boundary_method"], "length-field")
            self.assertEqual(entry["recovery"]["candidate_kind"], "carved")
            self.assertEqual(entry["recovery"]["validation_status"], "validated")

    def test_structural_rejection_emits_false_positive_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            # SQLite magic with garbage page-size/format bytes.
            (root / "noise.bin").write_bytes(
                b"xx" + b"SQLite format 3\x00" + b"\xff\xff" + b"\x09\x09" + b"junk" * 8
            )

            payload = run_bounded_carving(root, output_dir, max_candidates=10)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["summary"]["rejected_count"], 1)
            entry = payload["entries"][0]
            self.assertEqual(entry["status"], "false-positive-rejected")
            self.assertTrue(entry["rejected_reason"])
            self.assertEqual(entry["recovery"]["validation_status"], "rejected")
            self.assertEqual(entry["recovery"]["candidate_kind"], "carved")

    def test_chunk_boundary_header_is_carved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            # Place a PNG header straddling the 8 MiB scan-chunk boundary.
            filler = b"A" * (8 * 1024 * 1024 - 4)
            blob = (
                filler
                + b"\x89PNG\r\n\x1a\n"
                + b"\x00\x00\x00\x0dIHDR"
                + b"chunkdata"
                + b"IEND\xaeB`\x82"
                + b"tail"
            )
            (root / "big.bin").write_bytes(blob)

            payload = run_bounded_carving(root, output_dir, max_candidates=10)

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            entry = payload["entries"][0]
            self.assertEqual(entry["kind"], "png")
            self.assertEqual(entry["offset"], len(filler))
            self.assertEqual(entry["status"], "footer-validated")

    def test_resume_continues_from_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            (root / "a.bin").write_bytes(b"%PDF-1.4\na\n%%EOF")
            (root / "b.bin").write_bytes(b"%PDF-1.5\nb\n%%EOF")

            first = run_bounded_carving(root, output_dir, max_candidates=1)
            self.assertEqual(first["summary"]["candidate_count"], 1)
            checkpoint = output_dir / "rapidtriage-carve.checkpoint.json"
            self.assertTrue(checkpoint.is_file())

            resumed = run_bounded_carving(root, output_dir, max_candidates=1, resume=True)
            self.assertTrue(resumed["resume"]["resumed_from_checkpoint"])
            self.assertEqual(resumed["summary"]["candidate_count"], 1)
            self.assertEqual(
                resumed["entries"][0]["offset"], first["entries"][0]["offset"]
            )

    def test_resume_rejects_changed_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            (root / "a.bin").write_bytes(b"%PDF-1.4\na\n%%EOF")
            run_bounded_carving(root, output_dir, max_candidates=1)

            from rapidtriage.core.carving import CarvingError

            with self.assertRaises(CarvingError):
                run_bounded_carving(root, output_dir, max_candidates=5, resume=True)

    def test_kind_filter_limits_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case"
            output_dir = Path(tmp_dir) / "carve"
            root.mkdir()
            (root / "mixed.bin").write_bytes(
                b"%PDF-1.4\na\n%%EOF" + b"gap" + b"\xff\xd8\xff\xe0img\xff\xd9"
            )

            payload = run_bounded_carving(root, output_dir, kinds=["jpeg"])

            self.assertEqual(payload["summary"]["candidate_count"], 1)
            self.assertEqual(payload["entries"][0]["kind"], "jpeg")

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
