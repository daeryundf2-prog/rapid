from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.known_answer_qc import run_known_answer_qc


class RapidTriageKnownAnswerQcTests(unittest.TestCase):
    def test_known_answer_qc_hashes_evidence_and_passes_trusted_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "cfreds-string-search.txt"
            evidence.write_text("needle at known offset", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "datasets": [
                            {
                                "id": "cfreds-string-001",
                                "name": "CFReDS string search tiny fixture",
                                "source": "local-smoke",
                                "corpus_family": "string-search",
                                "status": "pass",
                                "item_numbers": [81],
                                "evidence_paths": [str(evidence)],
                                "expected": {"assertions": ["needle string is found", "source hash is preserved"]},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = run_known_answer_qc(manifest_path=manifest, trusted_manifest_path=manifest, output_dir=root / "qc")

            self.assertTrue(Path(payload["outputs"]["json"]).is_file())
            self.assertTrue(Path(payload["outputs"]["markdown"]).is_file())

        self.assertEqual(payload["summary"]["dataset_count"], 1)
        self.assertEqual(payload["summary"]["trusted_diff_status"], "pass")
        self.assertEqual(payload["validation"]["datasets"][0]["expected_assertion_count"], 2)
        self.assertEqual(payload["validation"]["datasets"][0]["evidence_hash_count"], 1)
        self.assertRegex(payload["validation"]["known_answer_pipeline_manifest_hash"], r"^[0-9a-f]{64}$")

    def test_known_answer_qc_cli_emits_json(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["known-answer-qc", "--manifest", "manifest.json", "--output-dir", "out"])
        self.assertEqual(args.command, "known-answer-qc")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence.txt"
            evidence.write_text("expected", encoding="utf-8")
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "datasets": [
                            {
                                "id": "dataset-1",
                                "status": "pass",
                                "evidence_paths": [str(evidence)],
                                "expected": {"required_assertions": ["expected text exists"]},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "known-answer-qc",
                        "--manifest",
                        str(manifest),
                        "--trusted-manifest",
                        str(manifest),
                        "--output-dir",
                        str(root / "qc"),
                        "--json",
                    ]
                )
            payload = json.loads(stdout.getvalue())

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["summary"]["dataset_count"], 1)
        self.assertEqual(payload["summary"]["trusted_diff_status"], "pass")


if __name__ == "__main__":
    unittest.main()
