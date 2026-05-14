from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.files import run_files_scan
from rapidtriage.core.hash_cache import reset_hash_cache


class FileKnownGoodSuppressionTests(unittest.TestCase):
    def test_known_good_feed_marks_rows_without_hiding_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            known_good = root / "known-good-note.txt"
            suspicious = root / "suspicious-note.txt"
            known_good.write_text("standard operating system help text\n", encoding="utf-8")
            suspicious.write_text("needle exfil staging note\n", encoding="utf-8")
            feed = Path(tmp) / "known-good.txt"
            feed.write_text(hashlib.sha256(known_good.read_bytes()).hexdigest() + "\n", encoding="utf-8")

            reset_hash_cache()
            payload = run_files_scan(root, categories=["documents"], known_good_hash_feeds=[feed])

        self.assertEqual(payload["summary"]["raw_candidate_count"], 2)
        self.assertEqual(payload["summary"]["candidate_count"], 2)
        self.assertEqual(payload["summary"]["known_good_match_count"], 1)
        self.assertEqual(payload["summary"]["known_good_suppressed_count"], 0)
        by_name = {row["name"]: row for row in payload["candidates"]}
        self.assertEqual(by_name["known-good-note.txt"]["known_good_status"], "known-good-feed-match")
        self.assertEqual(by_name["known-good-note.txt"]["report_suppression_status"], "candidate-known-good-reviewable")
        self.assertEqual(by_name["suspicious-note.txt"]["known_good_status"], "not-known-good")
        self.assertTrue(payload["known_good_suppression_profile"]["configured"])
        self.assertFalse(payload["known_good_suppression_profile"]["hide_known_good"])

    def test_hide_known_good_removes_rows_but_preserves_suppression_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            known_good = root / "known-good-note.txt"
            suspicious = root / "suspicious-note.txt"
            known_good.write_text("standard operating system help text\n", encoding="utf-8")
            suspicious.write_text("needle exfil staging note\n", encoding="utf-8")
            feed = Path(tmp) / "known-good.json"
            feed.write_text(json.dumps({"sha256": hashlib.sha256(known_good.read_bytes()).hexdigest()}), encoding="utf-8")

            reset_hash_cache()
            payload = run_files_scan(
                root,
                categories=["documents"],
                known_good_hash_feeds=[feed],
                hide_known_good=True,
            )

        self.assertEqual(payload["summary"]["raw_candidate_count"], 2)
        self.assertEqual(payload["summary"]["candidate_count"], 1)
        self.assertEqual(payload["summary"]["known_good_match_count"], 1)
        self.assertEqual(payload["summary"]["known_good_suppressed_count"], 1)
        self.assertEqual([row["name"] for row in payload["candidates"]], ["suspicious-note.txt"])
        self.assertEqual(payload["known_good_suppressed_candidates"][0]["name"], "known-good-note.txt")
        self.assertEqual(
            payload["known_good_suppressed_candidates"][0]["known_good_match"]["algorithm"],
            "sha256",
        )

    def test_files_cli_accepts_known_good_feed_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            known_good = root / "known-good-note.txt"
            suspicious = root / "suspicious-note.txt"
            known_good.write_text("standard operating system help text\n", encoding="utf-8")
            suspicious.write_text("needle exfil staging note\n", encoding="utf-8")
            feed = Path(tmp) / "known-good.csv"
            feed.write_text("sha256\n" + hashlib.sha256(known_good.read_bytes()).hexdigest() + "\n", encoding="utf-8")
            output = Path(tmp) / "files.json"

            reset_hash_cache()
            exit_code = main(
                [
                    "files",
                    str(root),
                    "--category",
                    "documents",
                    "--known-good-hash-feed",
                    str(feed),
                    "--hide-known-good",
                    "--output",
                    str(output),
                ]
            )

            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["summary"]["candidate_count"], 1)
        self.assertEqual(payload["summary"]["known_good_suppressed_count"], 1)
        self.assertEqual(payload["known_good_suppression_profile"]["feed_count"], 1)


if __name__ == "__main__":
    unittest.main()
