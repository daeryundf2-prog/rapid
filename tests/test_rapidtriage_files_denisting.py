from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from rapidtriage.cli import main
from rapidtriage.core.files import run_files_scan
from rapidtriage.core.hash_cache import reset_hash_cache
from rapidtriage.core.search import run_unified_search


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

    def test_nsrl_rds_csv_feed_marks_rows_with_source_traceability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            known_good = root / "windows-help.txt"
            suspicious = root / "exfil-note.txt"
            known_good.write_text("standard windows help payload\n", encoding="utf-8")
            suspicious.write_text("needle staging payload\n", encoding="utf-8")
            body = known_good.read_bytes()
            feed = Path(tmp) / "nsrl-rds.csv"
            feed.write_text(
                "\n".join(
                    [
                        "SHA-1,MD5,CRC32,FileName,FileSize,ProductCode,OpSystemCode,SpecialCode",
                        ",".join(
                            [
                                hashlib.sha1(body).hexdigest(),
                                hashlib.md5(body).hexdigest(),
                                "00000000",
                                "windows-help.txt",
                                str(len(body)),
                                "12345",
                                "362",
                                "",
                            ]
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            reset_hash_cache()
            payload = run_files_scan(root, categories=["documents"], known_good_hash_feeds=[feed])

        by_name = {row["name"]: row for row in payload["candidates"]}
        known_row = by_name["windows-help.txt"]
        self.assertEqual(known_row["known_good_status"], "known-good-feed-match")
        self.assertEqual(known_row["known_good_match"]["feed_format"], "nsrl-rds-csv")
        self.assertEqual(known_row["known_good_match"]["feed_name"], "nsrl-rds.csv")
        source_detail = known_row["known_good_match"]["source_detail"]
        self.assertEqual(source_detail["row_number"], 2)
        self.assertIn(source_detail["hash_column"], {"MD5", "SHA-1"})
        self.assertEqual(source_detail["nsrl_file_name"], "windows-help.txt")
        self.assertEqual(payload["summary"]["known_good_nsrl_rds_feed_count"], 1)
        self.assertEqual(payload["summary"]["known_good_nsrl_rds_row_count"], 1)
        profile = payload["known_good_suppression_profile"]
        self.assertEqual(profile["feed_format_counts"]["nsrl-rds-csv"], 1)
        self.assertEqual(profile["feed_summaries"][0]["format"], "nsrl-rds-csv")
        self.assertTrue(profile["feed_summaries"][0]["nsrl_rds_header_detected"])
        self.assertEqual(profile["feed_summaries"][0]["row_count"], 1)

    def test_nsrl_rds_txt_feed_is_parsed_as_structured_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            known_good = root / "windows-help.txt"
            known_good.write_text("standard windows help payload\n", encoding="utf-8")
            body = known_good.read_bytes()
            feed = Path(tmp) / "NSRLFile.txt"
            feed.write_text(
                "\n".join(
                    [
                        "SHA-1,MD5,CRC32,FileName,FileSize,ProductCode,OpSystemCode,SpecialCode",
                        ",".join(
                            [
                                hashlib.sha1(body).hexdigest(),
                                hashlib.md5(body).hexdigest(),
                                "00000000",
                                "windows-help.txt",
                                str(len(body)),
                                "12345",
                                "362",
                                "",
                            ]
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            reset_hash_cache()
            payload = run_files_scan(root, categories=["documents"], known_good_hash_feeds=[feed])

        known_row = payload["candidates"][0]
        self.assertEqual(known_row["known_good_status"], "known-good-feed-match")
        self.assertEqual(known_row["known_good_match"]["feed_format"], "nsrl-rds-csv")
        self.assertEqual(known_row["known_good_match"]["source_detail"]["nsrl_file_name"], "windows-help.txt")
        self.assertEqual(payload["summary"]["known_good_nsrl_rds_feed_count"], 1)
        self.assertEqual(payload["summary"]["known_good_nsrl_rds_row_count"], 1)

    def test_known_good_index_cli_builds_reusable_feed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            feed_dir = Path(tmp) / "feeds"
            root.mkdir()
            feed_dir.mkdir()
            known_good = root / "known-good-note.txt"
            known_good.write_text("standard operating system help text\n", encoding="utf-8")
            feed = feed_dir / "known-good.sha256"
            feed.write_text(hashlib.sha256(known_good.read_bytes()).hexdigest() + "\n", encoding="utf-8")
            index_output = Path(tmp) / "known-good-index.json"

            exit_code = main(
                [
                    "known-good-index",
                    str(feed_dir),
                    "--output",
                    str(index_output),
                ]
            )
            reset_hash_cache()
            payload = run_files_scan(root, categories=["documents"], known_good_hash_feeds=[index_output])
            index_payload = json.loads(index_output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(index_payload["profile_version"], "known-good-index-v1")
        self.assertEqual(index_payload["summary"]["record_count"], 1)
        self.assertEqual(index_payload["records"][0]["algorithm"], "sha256")
        self.assertEqual(payload["summary"]["known_good_match_count"], 1)
        self.assertEqual(payload["known_good_suppression_profile"]["feed_format_counts"]["json-index"], 1)

    def test_known_good_index_cli_accepts_zipped_nsrl_rds_feed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "case"
            root.mkdir()
            known_good = root / "windows-calc.exe"
            known_good.write_bytes(b"MZstandard windows executable fixture\n")
            body = known_good.read_bytes()
            nsrl_text = (
                "SHA-1,MD5,CRC32,FileName,FileSize,ProductCode,OpSystemCode,SpecialCode\n"
                + ",".join(
                    [
                        hashlib.sha1(body).hexdigest(),
                        hashlib.md5(body).hexdigest(),
                        "00000000",
                        "windows-calc.exe",
                        str(len(body)),
                        "12345",
                        "362",
                        "",
                    ]
                )
                + "\n"
            )
            zip_feed = Path(tmp) / "NSRL-RDS.zip"
            with zipfile.ZipFile(zip_feed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("RDS/NSRLFile.txt", nsrl_text)
            index_output = Path(tmp) / "known-good-index.json"

            exit_code = main(["known-good-index", str(zip_feed), "--output", str(index_output)])
            reset_hash_cache()
            payload = run_files_scan(root, categories=["executables"], known_good_hash_feeds=[index_output])
            index_payload = json.loads(index_output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(index_payload["summary"]["zip_feed_count"], 1)
        self.assertEqual(index_payload["summary"]["zip_parsed_member_count"], 1)
        self.assertEqual(index_payload["summary"]["nsrl_rds_feed_count"], 1)
        self.assertEqual(index_payload["summary"]["nsrl_rds_row_count"], 1)
        self.assertEqual(index_payload["feed_summaries"][0]["format"], "zip")
        self.assertEqual(index_payload["feed_summaries"][0]["archive_members"][0]["member"], "RDS/NSRLFile.txt")
        self.assertEqual(payload["summary"]["known_good_match_count"], 1)
        match = payload["candidates"][0]["known_good_match"]
        self.assertEqual(match["source_detail"]["archive_member"], "RDS/NSRLFile.txt")
        self.assertEqual(match["source_detail"]["feed_container_format"], "zip")
        self.assertEqual(match["source_detail"]["nsrl_file_name"], "windows-calc.exe")

    def test_unified_search_can_hide_known_good_file_hits(self) -> None:
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
            files_payload = run_files_scan(root, categories=["documents"], known_good_hash_feeds=[feed])
            files_output = Path(tmp) / "rapidtriage-files.json"
            files_output.write_text(json.dumps(files_payload), encoding="utf-8")
            run_summary = {"outputs": {"files": str(files_output)}}

            reviewable = run_unified_search(
                run_summary,
                ["known-good-note"],
                include_ocr=False,
                include_analysis=False,
            )
            hidden = run_unified_search(
                run_summary,
                ["known-good-note"],
                include_ocr=False,
                include_analysis=False,
                hide_known_good=True,
            )

        self.assertEqual(reviewable["summary"]["match_count"], 1)
        self.assertEqual(reviewable["summary"]["known_good_match_count"], 1)
        self.assertEqual(reviewable["summary"]["known_good_suppressed_count"], 0)
        self.assertEqual(reviewable["matches"][0]["known_good_search_status"], "known-good-reviewable")
        self.assertEqual(hidden["summary"]["match_count"], 0)
        self.assertEqual(hidden["summary"]["known_good_match_count"], 1)
        self.assertEqual(hidden["summary"]["known_good_suppressed_count"], 1)
        profile = hidden["known_good_search_suppression_profile"]
        self.assertTrue(profile["hide_known_good"])
        self.assertEqual(profile["suppressed_previews"][0]["title"], "known-good-note.txt")


if __name__ == "__main__":
    unittest.main()
