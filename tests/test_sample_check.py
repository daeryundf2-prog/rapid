"""scripts/sample-check.py on synthetic samples generated here (R6 S1 lane B, Q-S1-6).

No real sample, no evidence folder: every input is written into a temporary folder.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import zlib
from pathlib import Path

from tests import r5_l1_fixtures as fx
from tests.test_r5_l3_archives import alz_archive, egg_archive, egg_file
from tests.test_r5_l3_p2p import INFO_HASH, TORRENT, bencode

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "sample-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("rapidtriage_sample_check_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sample_check = _load_module()


def run_script(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            code = sample_check.main(list(args))
        except SystemExit as exc:  # argparse usage errors
            code = int(exc.code or 0)
    return code, out.getvalue()


class SampleCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.sample = self.tmp / "sample"
        self.sample.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def known(self, payload: dict) -> Path:
        path = self.tmp / "known-answer.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def check(self, parser: str, payload: dict, *extra: str) -> tuple[int, dict]:
        code, text = run_script("--parser", parser, "--input", str(self.sample), "--expect", str(self.known(payload)), "--json", *extra)
        return code, json.loads(text)

    # -- provider parsers -------------------------------------------------

    def vlc_known(self, drive: str = "E") -> dict:
        return {
            "parser": "media-player",
            "expect": [
                {
                    "match": {"artifact_type": "media-player-recent", "player_id": "vlc", "media_path": "E:\\영상\\clip01.mp4"},
                    "fields": {"drive_letter": drive, "resume_position_seconds": 0},
                },
                {
                    "match": {"artifact_type": "media-player-recent", "media_path": "C:\\Users\\alice\\Videos\\a, b.mkv"},
                    "fields": {"resume_position_seconds": 125.0, "details.drive_letter": "C"},
                },
            ],
            "counts": {"media-player-recent": 4},
        }

    def test_vlc_ini_matches_known_answer(self) -> None:
        fx.vlc_files(fx.home(self.sample))
        code, report = self.check("media-player", self.vlc_known())
        self.assertEqual(code, 0, report)
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["expectations"], {"total": 2, "matched": 2, "mismatch": 0, "missing": 0, "recall": 1.0})
        self.assertEqual(report["artifact_type_counts"]["media-player-recent"], 4)
        self.assertEqual(report["rows_not_in_known_answer"], report["row_count"] - 2)

    def test_mismatch_reports_field_names_only_unless_show_values(self) -> None:
        fx.vlc_files(fx.home(self.sample))
        code, report = self.check("media-player", self.vlc_known(drive="Z"))
        self.assertEqual(code, 1)
        self.assertEqual(report["results"][0]["status"], "mismatch")
        self.assertEqual(report["results"][0]["mismatched_fields"], ["drive_letter"])
        dumped = json.dumps(report, ensure_ascii=False)
        for value in ("clip01", "alice", "영상"):
            self.assertNotIn(value, dumped)
        code, shown = self.check("media-player", self.vlc_known(drive="Z"), "--show-values")
        self.assertEqual(code, 1)
        self.assertEqual(shown["results"][0]["values"], {"drive_letter": {"expected": "Z", "actual": "E"}})

    def test_missing_expectation_and_count_mismatch(self) -> None:
        fx.vlc_files(fx.home(self.sample))
        payload = self.vlc_known()
        payload["expect"].append({"match": {"media_path": "Q:\\nothing.mp4"}, "fields": {}})
        payload["counts"] = {"media-player-recent": 5}
        code, report = self.check("media-player", payload)
        self.assertEqual(code, 1)
        self.assertEqual(report["results"][2]["status"], "missing")
        self.assertEqual(report["counts"], [{"artifact_type": "media-player-recent", "expected": 5, "actual": 4, "ok": False}])
        _code, text = run_script("--parser", "media-player", "--input", str(self.sample), "--expect", str(self.known(payload)))
        self.assertIn("expect[2] missing", text)
        self.assertNotIn("nothing.mp4", text)

    def test_torrent_bencode_sample(self) -> None:
        torrent = self.sample / "Users" / "lee" / "Downloads" / "x.torrent"
        torrent.parent.mkdir(parents=True)
        torrent.write_bytes(bencode(TORRENT))
        code, report = self.check(
            "p2p",
            {
                "parser": "p2p",
                "expect": [{"match": {"artifact_type": "p2p-torrent"}, "fields": {"info_hash": INFO_HASH, "name": "synthetic-pack"}}],
                "counts": {"p2p-torrent": 1},
            },
        )
        self.assertEqual(code, 0, report)

    # -- archives ---------------------------------------------------------

    def test_egg_and_alz_entries(self) -> None:
        lzma_data = b"lzma-sample " * 20
        (self.sample / "s.egg").write_bytes(
            egg_archive(egg_file("a.txt", b"hello", "deflate"), egg_file("b.bin", lzma_data, "lzma", file_id=2))
        )
        (self.sample / "s.alz").write_bytes(alz_archive([("문서.txt", b"abc", False)]))
        code, report = self.check(
            "egg",
            {
                "parser": "egg",
                "expect": [
                    {"match": {"name": "a.txt"}, "fields": {"uncompressed_size": 5, "sha256": hashlib.sha256(b"hello").hexdigest()}},
                    {"match": {"name": "b.bin"}, "fields": {"sha256": hashlib.sha256(lzma_data).hexdigest(), "compression_methods": ["lzma"]}},
                ],
                "counts": {"egg-entry": 2, "egg-archive": 1},
            },
        )
        self.assertEqual(code, 0, report)
        code, report = self.check(
            "alz",
            {
                "parser": "alz",
                "expect": [{"match": {"name": "문서.txt"}, "fields": {"uncompressed_size": 3, "crc32": f"{zlib.crc32(b'abc'):08x}"}}],
                "counts": {"alz-entry": 1},
            },
        )
        self.assertEqual(code, 0, report)

    def test_corrupt_egg_is_isolated(self) -> None:
        (self.sample / "bad.egg").write_bytes(b"NOTANEGG")
        code, report = self.check("egg", {"parser": "egg", "expect": [], "counts": {"egg-open-failed": 1}})
        self.assertEqual(code, 0, report)
        self.assertEqual(report["parser_error_types"], {"ArchiveFormatError": 1})

    # -- url carving ------------------------------------------------------

    def test_url_carve_recall_and_extra_rows(self) -> None:
        blob = b"\x00junk http://alpha.example.com/a junk " + "https://beta.example.org/b?x=1".encode("utf-16-le") + b" http://gamma.example.net/c\x00"
        (self.sample / "pagefile.sys").write_bytes(blob)
        code, report = self.check(
            "url-carve",
            {
                "parser": "url-carve",
                "expect": [
                    {"match": {"url": "http://alpha.example.com/a"}, "fields": {"encoding": "ascii"}},
                    {"match": {"url": "https://beta.example.org/b?x=1"}, "fields": {"encoding": "utf-16le"}},
                ],
            },
        )
        self.assertEqual(code, 0, report)
        self.assertEqual(report["row_count"], 3)
        self.assertEqual(report["rows_not_in_known_answer"], 1)

    # -- input errors -----------------------------------------------------

    def test_input_errors_exit_2(self) -> None:
        payload = {"parser": "egg", "expect": []}
        code, _ = run_script("--parser", "alz", "--input", str(self.sample), "--expect", str(self.known(payload)))
        self.assertEqual(code, 2)
        code, _ = run_script("--parser", "egg", "--input", str(self.tmp / "missing"), "--expect", str(self.known(payload)))
        self.assertEqual(code, 2)
        code, _ = run_script("--parser", "nope", "--input", str(self.sample), "--expect", str(self.known(payload)))
        self.assertEqual(code, 2)
        code, _ = run_script("--parser", "egg", "--input", str(self.sample))
        self.assertEqual(code, 2)
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"expect": [{"match": [], "fields": {}}]}), encoding="utf-8")
        code, _ = run_script("--parser", "egg", "--input", str(self.sample), "--expect", str(bad))
        self.assertEqual(code, 2)

    # -- --probe-hash -----------------------------------------------------

    def test_probe_hash_finds_md5_of_utf16_path(self) -> None:
        original = "C:\\Videos\\영상.mp4"
        target = hashlib.md5(original.lower().encode("utf-16-le")).hexdigest().upper()
        code, text = run_script("--probe-hash", target, "--candidate-path", "D:\\other.mp4", "--candidate-path", original, "--json")
        report = json.loads(text)
        self.assertEqual(code, 0)
        self.assertIn(
            {"candidate": "path[1]", "variant": "utf-16le/lower/as-is", "algorithm": "md5", "position": "full"},
            report["matches"],
        )
        self.assertNotIn("Videos", text)
        self.assertNotIn(target.lower(), text)

    def test_probe_hash_file_content_head_and_crc_slice(self) -> None:
        media = self.tmp / "clip.bin"
        data = bytes(range(256)) * 64
        media.write_bytes(data)
        head_md5 = hashlib.md5(data[:4096]).hexdigest()
        code, text = run_script("--probe-hash", head_md5, "--candidate-file", str(media), "--json")
        self.assertEqual(code, 0)
        self.assertIn("content/head-4096", {hit["variant"] for hit in json.loads(text)["matches"]})
        crc = f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
        target = "0" * 8 + crc + "0" * 16
        code, text = run_script("--probe-hash", target, "--candidate-file", str(media), "--json")
        hits = json.loads(text)["matches"]
        self.assertIn({"candidate": "file[0]", "variant": "content/whole", "algorithm": "crc32", "position": "slice@8"}, hits)
        sha_prefix = hashlib.sha1(data).hexdigest()[:32]
        code, text = run_script("--probe-hash", sha_prefix, "--candidate-file", str(media), "--json")
        self.assertIn({"candidate": "file[0]", "variant": "content/whole", "algorithm": "sha1", "position": "prefix"}, json.loads(text)["matches"])

    def test_probe_hash_no_match_and_bad_input(self) -> None:
        code, text = run_script("--probe-hash", "f" * 32, "--candidate-path", "C:\\a.mp4")
        self.assertEqual(code, 1)
        self.assertIn("NO-MATCH", text)
        self.assertEqual(run_script("--probe-hash", "xyz", "--candidate-path", "a")[0], 2)
        self.assertEqual(run_script("--probe-hash", "a" * 32)[0], 2)
        self.assertEqual(run_script("--probe-hash", "a" * 32, "--candidate-file", str(self.tmp / "missing"))[0], 2)


if __name__ == "__main__":
    unittest.main()
