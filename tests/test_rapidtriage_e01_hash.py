from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.e01_hash import run_e01_streaming_hash


class RapidTriageE01HashTests(unittest.TestCase):
    def test_e01_streaming_hash_writes_full_hash_and_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "case.E01"
            source.write_bytes((b"EVF" + b"A" * 1024) * 8)
            expected_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()

            payload = run_e01_streaming_hash(
                source_path=source,
                output_dir=root / "hash-out",
                algorithms=("sha256", "md5"),
                chunk_size=1024,
                checkpoint_interval_bytes=2048,
            )
            checkpoint = json.loads(Path(payload["outputs"]["checkpoint"]).read_text(encoding="utf-8"))

            self.assertTrue(Path(payload["outputs"]["json"]).is_file())
            self.assertTrue(Path(payload["outputs"]["markdown"]).is_file())

        self.assertEqual(payload["profile_version"], "e01-streaming-full-hash-v1")
        self.assertEqual(payload["digests"]["sha256"], expected_sha256)
        self.assertEqual(payload["bytes_hashed"], payload["source"]["size_bytes"])
        self.assertEqual(checkpoint["status"], "complete")
        self.assertEqual(checkpoint["bytes_hashed"], payload["source"]["size_bytes"])
        self.assertTrue(payload["background_job_ready"])
        self.assertRegex(payload["manifest_sha256"], r"^[0-9a-f]{64}$")

    def test_e01_hash_cli_emits_json(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["e01-hash", "case.E01", "--output-dir", "out"])
        self.assertEqual(args.command, "e01-hash")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "case.E01"
            source.write_bytes(b"EVF-cli-hash")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "e01-hash",
                        str(source),
                        "--output-dir",
                        str(root / "hash-out"),
                        "--algorithm",
                        "sha256",
                        "--chunk-size",
                        "4",
                        "--checkpoint-interval-bytes",
                        "4",
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["digests"]["sha256"], hashlib.sha256(b"EVF-cli-hash").hexdigest())


if __name__ == "__main__":
    unittest.main()
