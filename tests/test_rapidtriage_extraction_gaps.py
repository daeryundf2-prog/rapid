from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts.windows.filesystem import (
    collect_recovered_ads_artifacts,
    parse_zone_identifier,
)
from rapidtriage.core.e01 import extract_e01_to_directory, resolve_e01_extract_dir
from rapidtriage.core.extraction_failures import (
    ADS_MAP_NAME,
    ADS_SOURCE_ID,
    E01_STAGE_STATUS_NAME,
    EXTRACTION_FAILURES_NAME,
    LONG_PATH_MAP_NAME,
    LONG_PATH_SOURCE_ID,
    TSK_RECOVER_STDERR_LOG_NAME,
    ZERO_BYTE_LISTING_NAME,
    ZERO_BYTE_SOURCE_ID,
    ExtractedFile,
    PrefixSet,
    build_zero_byte_listing,
    classify_listing_entry,
    extended_length_path,
    match_extracted_to_listing,
    parse_fls_line,
    parse_fls_listing_bytes,
    parse_tsk_recover_stderr,
    recover_ads_streams,
    recover_long_path_files,
    select_long_path_targets,
)
from rapidtriage.core.files import run_files_scan

TS = "2024-10-07 22:23:30 (UTC)"


def fls_row(meta: str, name: bytes | str, size: int, *, ts: str = TS) -> bytes:
    raw_name = name.encode("utf-8") if isinstance(name, str) else name
    tail = "\t".join([ts, ts, ts, ts, str(size), "0", "0"]).encode("ascii")
    return meta.encode("ascii") + b":\t" + raw_name + b"\t" + tail + b"\r\n"


LONG_DIR = "/".join(["d" * 90, "e" * 90, "f" * 60])
LONG_REL = f"{LONG_DIR}/long-report.docx"


def sample_listing() -> bytes:
    return b"".join(
        [
            fls_row("d/d 30-144-1", "Users", 56),
            fls_row("r/r 64-128-4", "Users/evidence.txt", 13),
            fls_row("r/r 64-128-5", "Users/evidence.txt:Zone.Identifier", 80),
            fls_row("r/r 70-128-4", LONG_REL, 5),
            fls_row("r/r 71-128-4", "Users/empty.docx", 0),
            fls_row("r/r * 72-128-4", "Users/deleted.docx", 9),
            fls_row("r/r 73-128-4", "Users/\ubcf4\uace0\uc11c.pdf".encode("cp949"), 4),
            fls_row("r/r 0-128-1", "$MFT", 4096),
        ]
    )


ZONE_BLOB = b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ref.example/\r\nHostUrl=https://dl.example/a.zip\r\n"


def fake_icat_payload(address: str) -> bytes:
    if address == "70":
        return b"long!"
    if address == "64-128-5":
        return ZONE_BLOB
    return b""


def stream_runner_factory(listing: bytes, calls: list[list[str]]):
    def runner(command, dest: Path):
        calls.append(list(command))
        Path(dest).parent.mkdir(parents=True, exist_ok=True)
        payload = listing if command[0] == "fls" else fake_icat_payload(command[-1])
        with open(extended_length_path(dest), "wb") as handle:
            handle.write(payload)
        return subprocess.CompletedProcess(command, 0, b"", "")

    return runner


class FlsListingParsingTests(unittest.TestCase):
    def test_parses_long_format_ascii_row(self) -> None:
        entry = parse_fls_line(fls_row("r/r 64907-128-4", "ProgramData/MakeMarkerFile.xml", 3004), "cp949")
        assert entry is not None
        self.assertEqual(entry.inode, 64907)
        self.assertEqual((entry.attr_type, entry.attr_id), (128, 4))
        self.assertEqual(entry.size, 3004)
        self.assertEqual(entry.name_hint, "ProgramData/MakeMarkerFile.xml")
        self.assertEqual(entry.mtime, "2024-10-07T22:23:30+00:00")
        self.assertEqual(classify_listing_entry(entry), "content")

    def test_decodes_cp949_name_hint_and_keeps_surrogateescape_path(self) -> None:
        raw = "Users/user/Downloads/\uc9c4\uc815\uc11c.pdf".encode("cp949")
        entry = parse_fls_line(fls_row("r/r 166939-128-3", raw, 1200), "cp949")
        assert entry is not None
        self.assertEqual(entry.name_hint, "Users/user/Downloads/\uc9c4\uc815\uc11c.pdf")
        self.assertFalse(entry.name_lossy)
        self.assertEqual(entry.path.encode("utf-8", errors="surrogateescape"), raw)

    def test_flags_lossy_question_mark_names_and_ads_deleted_realloc(self) -> None:
        lossy = parse_fls_line(fls_row("r/r 5-128-4", "Users/emoji ?.txt", 3), "cp949")
        ads = parse_fls_line(fls_row("r/r 346018-128-9", "Users/a.xls:Zone.Identifier", 26), "cp949")
        deleted = parse_fls_line(fls_row("r/r * 7-128-1(realloc)", "Users/gone.txt", 3), "cp949")
        zero = parse_fls_line(fls_row("r/r 8-128-4", "Temp/x.tmp", 0), "cp949")
        assert lossy and ads and deleted and zero
        self.assertTrue(lossy.name_lossy)
        self.assertTrue(ads.is_ads)
        self.assertEqual(ads.stream_name, "Zone.Identifier")
        self.assertEqual(ads.host_hint, "Users/a.xls")
        self.assertEqual(ads.address, "346018-128-9")
        self.assertEqual(classify_listing_entry(ads), "ads")
        self.assertTrue(deleted.deleted)
        self.assertTrue(deleted.realloc)
        self.assertEqual(classify_listing_entry(deleted), "deleted")
        self.assertEqual(classify_listing_entry(zero), "zero-byte")

    def test_short_listing_without_long_columns_has_unknown_size(self) -> None:
        entry = parse_fls_line(b"r/r 64-128-4:\tUsers/a.txt\r\n", "cp949")
        assert entry is not None
        self.assertIsNone(entry.size)
        self.assertEqual(classify_listing_entry(entry), "size-unknown")


class TskRecoverStderrTests(unittest.TestCase):
    def test_parses_concatenated_create_write_and_extract_lines(self) -> None:
        root = r"D:\out\_e01\fs"
        stderr = (
            rf"Error Creating File ({root}\ProgramData\WER\AppCrash_x\WPR_initiated_Logger_2)"
            rf"Error writing file {root}\ProgramData\WER\a.xml" "\n"
            "Error extracting file from image (ntfs_attrwalk_special: past end: 4096 0 Meta: 366698 Status: Deleted)\n"
            rf"Error Creating File ({root}\Users\(weird)\name)Error Creating File ({root}\Users\b)"
            rf"Error writing file {root}\Users\c.val" "\n"
            "Error extracting file from image (ntfs_uncompress_compunit: Phrase token (max: 2)) (573032 - type: 128  id: 4 Status: Deleted)\n"
        )
        rows = parse_tsk_recover_stderr(stderr, extract_root=root)
        reasons = [row["reason"] for row in rows]
        self.assertEqual(reasons, ["create-failed", "write-failed", "create-failed", "create-failed", "write-failed"])
        self.assertEqual(rows[0]["relative_path"], "ProgramData/WER/AppCrash_x/WPR_initiated_Logger_2")
        self.assertEqual(rows[1]["inode"], 366698)
        self.assertTrue(rows[1]["deleted"])
        self.assertEqual(rows[2]["relative_path"], "Users/(weird)/name")
        self.assertEqual((rows[4]["inode"], rows[4]["attr_type"], rows[4]["attr_id"]), (573032, 128, 4))

    def test_prefix_set_handles_nested_prefixes(self) -> None:
        prefixes = PrefixSet(["a/b", "a/b/c", "x/y"])
        self.assertEqual(prefixes.match("a/b/c/d"), "a/b")
        self.assertIsNone(prefixes.match("a/c"))
        self.assertEqual(prefixes.match("x/yz"), "x/y")


class MatchingTests(unittest.TestCase):
    def test_exact_wildcard_and_parent_size_tiers(self) -> None:
        listing = b"".join(
            [
                fls_row("r/r 10-128-4", "Docs/A.txt", 3),
                fls_row("r/r 11-128-4", "Docs/emoji ?.txt", 4),
                fls_row("r/r 12-128-4", "Docs/\xff\xfe.bin", 77),
                fls_row("r/r 13-128-4", "Docs/other.bin", 78),
            ]
        )
        entries = parse_fls_listing_bytes(listing, "ascii")
        extracted = [
            ExtractedFile("docs/a.TXT", 3),
            ExtractedFile("Docs/emoji \U0001f600.txt", 4),
            ExtractedFile("Docs/real-name.bin", 77),
            ExtractedFile("Docs/orphan.bin", 1),
        ]
        matches, unmatched = match_extracted_to_listing(extracted, entries)
        self.assertEqual(matches["docs/a.TXT"][0].inode, 10)
        self.assertEqual(matches["docs/a.TXT"][1], "path-exact")
        self.assertEqual(matches["Docs/emoji \U0001f600.txt"][1], "path-wildcard")
        self.assertEqual(matches["Docs/real-name.bin"], (entries[2], "parent-size"))
        self.assertEqual([item.relative_path for item in unmatched], ["Docs/orphan.bin"])


class GapRecoveryTests(unittest.TestCase):
    def test_long_path_targets_are_recovered_with_icat_and_mapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "_e01"
            extract_dir = stage / "fs"
            (extract_dir / "Users").mkdir(parents=True)
            (extract_dir / "Users" / "evidence.txt").write_text("fraud invoice", encoding="utf-8")
            entries = parse_fls_listing_bytes(sample_listing(), "cp949")
            targets = select_long_path_targets(entries, extract_dir=extract_dir)
            self.assertEqual([entry.inode for entry in targets], [70])
            calls: list[list[str]] = []
            payload = recover_long_path_files(
                targets,
                stage=stage,
                image="case.E01",
                offset_sector=2048,
                stream_runner=stream_runner_factory(b"", calls),
            )
            self.assertEqual(calls, [["icat", "-o", "2048", "case.E01", "70"]])
            self.assertEqual(payload["recovered_count"], 1)
            row = payload["files"][0]
            self.assertEqual(row["original_relative_path"], LONG_REL)
            self.assertEqual(row["sha256"], hashlib.sha256(b"long!").hexdigest())
            self.assertTrue((stage / "long" / "70.bin").is_file())
            self.assertTrue((stage / LONG_PATH_MAP_NAME).is_file())

    def test_long_path_cap_emits_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "_e01"
            entries = parse_fls_listing_bytes(sample_listing(), "cp949")
            targets = select_long_path_targets(entries, extract_dir=stage / "fs")
            payload = recover_long_path_files(
                targets,
                stage=stage,
                image="case.E01",
                offset_sector=0,
                stream_runner=stream_runner_factory(b"", []),
                max_bytes=1,
            )
            self.assertEqual(payload["attempted_count"], 0)
            self.assertIn("capped", payload["warnings"][0])

    def test_extended_length_path_prefix(self) -> None:
        if os.name != "nt":
            self.assertEqual(extended_length_path("/tmp/x"), "/tmp/x")
            return
        self.assertTrue(extended_length_path(r"C:\a\b").startswith("\\\\?\\C:\\a"))
        self.assertTrue(extended_length_path(r"\\server\share\x").startswith("\\\\?\\UNC\\server\\share"))
        self.assertEqual(extended_length_path("\\\\?\\C:\\a"), "\\\\?\\C:\\a")

    def test_zero_byte_listing_skips_files_present_on_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "_e01"
            extract_dir = stage / "fs"
            (extract_dir / "Users").mkdir(parents=True)
            listing = sample_listing() + fls_row("r/r 80-128-4", "Users/present-empty.txt", 0)
            (extract_dir / "Users" / "present-empty.txt").write_bytes(b"")
            payload = build_zero_byte_listing(parse_fls_listing_bytes(listing, "cp949"), stage=stage, extract_dir=extract_dir)
            self.assertEqual([row["inode"] for row in payload["files"]], [71])
            self.assertEqual(payload["skipped_present_on_disk"], 1)
            self.assertEqual(payload["files"][0]["timestamps"]["mtime"], "2024-10-07T22:23:30+00:00")

    def test_ads_recovery_prioritizes_zone_identifier_and_caps_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "_e01"
            listing = sample_listing() + fls_row("r/r 90-128-6", "Users/big.bin:payload", 5_000_000)
            calls: list[list[str]] = []
            payload = recover_ads_streams(
                parse_fls_listing_bytes(listing, "cp949"),
                stage=stage,
                image="case.E01",
                offset_sector=0,
                stream_runner=stream_runner_factory(b"", calls),
            )
            self.assertEqual(payload["stream_count"], 2)
            self.assertEqual(payload["zone_identifier_count"], 1)
            self.assertEqual(payload["streams"][0]["stream_name"], "Zone.Identifier")
            self.assertEqual(payload["streams"][1]["status"], "skipped-size-cap")
            self.assertEqual(calls, [["icat", "-o", "0", "case.E01", "64-128-5"]])
            self.assertTrue((stage / "ads" / "64-128-5.bin").is_file())

    def test_zone_identifier_parser(self) -> None:
        parsed = parse_zone_identifier(ZONE_BLOB)
        self.assertEqual(parsed["zone_id"], "3")
        self.assertEqual(parsed["zone_name"], "internet")
        self.assertEqual(parsed["host_url"], "https://dl.example/a.zip")
        self.assertEqual(parsed["referrer_url"], "https://ref.example/")
        utf16 = parse_zone_identifier(b"\xff\xfe" + "[ZoneTransfer]\r\nZoneId=2\r\n".encode("utf-16-le"))
        self.assertEqual(utf16["zone_name"], "trusted-sites")


class E01GapStageIntegrationTests(unittest.TestCase):
    def _extract(self, root: Path, calls: list[list[str]]):
        e01_path = root / "case.E01"
        e01_path.write_bytes(b"EVF")
        stage_dir = root / "out" / "_e01"

        def fake_runner(command):
            calls.append(list(command))
            if command[1:] == ["--version"]:
                return subprocess.CompletedProcess(command, 0, f"{command[0]} 1.0\n", "")
            if command[0] == "mmls":
                return subprocess.CompletedProcess(command, 0, "001: 0000002048 0000020000 NTFS\n", "")
            if command[0] == "tsk_recover":
                target = Path(command[-1])
                (target / "Users").mkdir(parents=True, exist_ok=True)
                (target / "Users" / "evidence.txt").write_text("fraud invoice", encoding="utf-8")
                (target / "Users" / "\ubcf4\uace0\uc11c.pdf").write_bytes(b"%PDF")
                stderr = f"Error Creating File ({target}\\{LONG_DIR.replace('/', chr(92))}\\long-rep)"
                return subprocess.CompletedProcess(command, 0, "", stderr)
            return subprocess.CompletedProcess(command, 0, "", "")

        def resolver(name):
            return None if name == "ewfmount" else f"/usr/bin/{name}"

        stream_calls: list[list[str]] = []
        with patch("rapidtriage.core.e01.native_e01_available", return_value=False), patch(
            "rapidtriage.core.extraction_failures.legacy_listing_encoding", return_value="cp949"
        ):
            result = extract_e01_to_directory(
                e01_path,
                stage_dir,
                runner=fake_runner,
                tool_resolver=resolver,
                stream_runner=stream_runner_factory(sample_listing(), stream_calls),
            )
        calls.extend(stream_calls)
        return result, stage_dir

    def test_extraction_writes_failures_long_path_zero_byte_and_ads_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            calls: list[list[str]] = []
            result, stage_dir = self._extract(root, calls)
            self.assertEqual(result.extract_dir.name, "fs")
            self.assertTrue((stage_dir / TSK_RECOVER_STDERR_LOG_NAME).is_file())
            failures = json.loads((stage_dir / EXTRACTION_FAILURES_NAME).read_text(encoding="utf-8"))
            self.assertEqual(failures["failures"][0]["reason"], "create-failed")
            self.assertEqual(failures["failures"][0]["inode"], 70)
            fls_call = next(call for call in calls if call[0] == "fls")
            self.assertEqual(fls_call[:6], ["fls", "-r", "-p", "-l", "-z", "UTC"])
            self.assertIn(["icat", "-o", "2048", str(root / "case.E01"), "70"], calls)
            long_map = json.loads((stage_dir / LONG_PATH_MAP_NAME).read_text(encoding="utf-8"))
            self.assertEqual(long_map["recovered_count"], 1)
            zero = json.loads((stage_dir / ZERO_BYTE_LISTING_NAME).read_text(encoding="utf-8"))
            self.assertEqual([row["relative_path"] for row in zero["files"]], ["Users/empty.docx"])
            ads = json.loads((stage_dir / ADS_MAP_NAME).read_text(encoding="utf-8"))
            self.assertEqual(ads["recovered_count"], 1)
            status = json.loads((stage_dir / E01_STAGE_STATUS_NAME).read_text(encoding="utf-8"))
            gap = status["stages"]["extraction-gap-recovery"]
            self.assertEqual(gap["status"], "completed")
            self.assertEqual(gap["inode_map_match_counts"].get("path-exact"), 2)
            self.assertEqual(status["extract_dir_layout"]["current_name"], "fs")
            self.assertIn("filesystem", status["extract_dir_layout"]["legacy_names"])

            payload = run_files_scan(result.extract_dir, categories=["documents"])
            by_source = {}
            for candidate in payload["candidates"]:
                by_source.setdefault(candidate["recovery"]["source_id"], []).append(candidate)
            long_rows = by_source[LONG_PATH_SOURCE_ID]
            self.assertEqual(len(long_rows), 1)
            self.assertTrue(long_rows[0]["path"].endswith("long-report.docx"))
            self.assertEqual(long_rows[0]["recovery"]["deletion_state"], "allocated")
            self.assertEqual(long_rows[0]["recovery"]["mft_ref"], 70)
            self.assertTrue(long_rows[0]["recovery"]["content_path"].endswith("70.bin"))
            zero_rows = by_source[ZERO_BYTE_SOURCE_ID]
            self.assertEqual(zero_rows[0]["size"], 0)
            self.assertEqual(zero_rows[0]["name"], "empty.docx")
            on_disk = by_source["filesystem-scan"]
            self.assertEqual(sorted(row["recovery"].get("mft_ref") for row in on_disk), [64, 73])

            records = list(collect_recovered_ads_artifacts(result.extract_dir))
            self.assertEqual([record.artifact_type for record in records], ["zone-identifier"])
            details = records[0].details
            self.assertEqual(details["zone_id"], "3")
            self.assertEqual(details["host_url"], "https://dl.example/a.zip")
            self.assertEqual(details["source_id"], ADS_SOURCE_ID)
            self.assertTrue(records[0].path.endswith("evidence.txt:Zone.Identifier"))

    def test_zero_byte_sidecar_deduped_against_on_disk_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result, stage_dir = self._extract(root, [])
            (result.extract_dir / "Users" / "EMPTY.docx").write_bytes(b"")
            payload = run_files_scan(result.extract_dir, categories=["documents"])
            sources = [candidate["recovery"]["source_id"] for candidate in payload["candidates"]]
            self.assertNotIn(ZERO_BYTE_SOURCE_ID, sources)

    def test_legacy_filesystem_root_is_kept_for_completed_checkpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "_e01"
            legacy = stage / "filesystem"
            legacy.mkdir(parents=True)
            self.assertEqual(resolve_e01_extract_dir(stage, {"extract_dir": str(legacy)}), legacy)
            self.assertEqual(resolve_e01_extract_dir(stage, {}), stage / "fs")
            self.assertEqual(resolve_e01_extract_dir(stage, {"extract_dir": str(Path(tmp) / "x" / "filesystem")}), stage / "fs")


class CoverageScriptTests(unittest.TestCase):
    def _load_script(self):
        path = Path(__file__).resolve().parents[1] / "scripts" / "fls-coverage-diff.py"
        spec = importlib.util.spec_from_file_location("fls_coverage_diff", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_reports_content_zero_byte_and_ads_rates(self) -> None:
        module = self._load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fls = root / "fls-rpl.txt"
            fls.write_bytes(sample_listing())
            files_json = root / "files.json"
            files_json.write_text(
                json.dumps(
                    {
                        "candidates": [
                            {"path": r"C:\run\_e01\fs\Users\evidence.txt"},
                            {"path": "C:\\run\\_e01\\fs\\Users\\\ubcf4\uace0\uc11c.pdf"},
                            {"path": "C:\\run\\_e01\\fs\\" + LONG_REL.replace("/", "\\"), "recovery": {"mft_ref": 70}},
                            {"path": r"C:\run\_e01\fs\Users\evidence.txt:Zone.Identifier"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = root / "report.json"
            with patch("rapidtriage.core.extraction_failures.legacy_listing_encoding", return_value="cp949"), redirect_stdout(
                io.StringIO()
            ):
                code = module.main(
                    ["--fls", str(fls), "--files-json", str(files_json), "--strip-prefix", "_e01/fs", "--output", str(output)]
                )
            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            coverage = report["coverage"]
            self.assertEqual(coverage["a_content_bearing_allocated"]["denominator_rows"], 3)
            self.assertEqual(coverage["a_content_bearing_allocated"]["covered_rows"], 3)
            self.assertEqual(coverage["b_zero_byte_listing"]["denominator_rows"], 1)
            self.assertEqual(coverage["b_zero_byte_listing"]["listed_rows"], 0)
            self.assertEqual(coverage["c_ads_listing"]["rate"], 1.0)
            self.assertEqual(report["matching"]["method_counts"], {"path-exact": 2})
            self.assertEqual(report["per_directory_deficit"][0]["directory"], "Users")
            self.assertEqual(report["per_directory_deficit"][0]["zero_byte_deficit"], 1)


if __name__ == "__main__":
    unittest.main()
