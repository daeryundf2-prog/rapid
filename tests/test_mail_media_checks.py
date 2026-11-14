"""mail-reference-diff.py and media-hash-check.py on synthetic inputs (T-212)."""

from __future__ import annotations

import contextlib
import io
import json
import unittest

from tests.reference_diff_helpers import ReferenceDiffCase, write_csv, write_jsonl

MESSAGES = [
    ("<m1@example.com>", "Quarterly numbers", "a@example.com", "Mon, 03 Jun 2024 09:00:00 +0900", ["q.xlsx"]),
    ("<m2@example.com>", "Lunch", "b@example.com", "Mon, 03 Jun 2024 12:00:00 +0000", []),
    ("<m3@example.com>", "Contract draft", "c@example.com", "Tue, 04 Jun 2024 08:30:00 +0000", ["a.docx", "b.pdf"]),
]

MD5 = "0123456789abcdef0123456789abcdef"
SHA1 = "0123456789abcdef0123456789abcdef01234567"
BAD_MD5 = "fedcba9876543210fedcba9876543210"

EWF_OK = f"""ewfverify 20140608

Verify started at: Jun 01, 2024 10:00:00
This could take a while.

Verify completed at: Jun 01, 2024 10:00:10

Read: 64 MiB (67108864 bytes) in 10 second(s) with 6.4 MiB/s (6710886 bytes/second).

MD5 hash stored in file:\t\t{MD5}
MD5 hash calculated over data:\t\t{MD5}
SHA1 hash stored in file:\t\t{SHA1}
SHA1 hash calculated over data:\t\t{SHA1}

ewfverify: SUCCESS
"""

EWF_DAMAGED = f"""ewfverify 20140608

Verify completed at: Jun 01, 2024 10:00:10

Read errors during verification:
\tat sector(s): 128 - 191 (number: 64) in segment file(s): synthetic.E01.
\ttotal number of errors: 1

MD5 hash stored in file:\t\t{MD5}
MD5 hash calculated over data:\t\t{BAD_MD5}

ewfverify: FAILURE
"""

FTK_LOG = f"""Created By AccessData(R) FTK(R) Imager

Case Information:
Acquired using: ADI4.7
Case Number: SYN-0001
Evidence Number: 1

[Computed Hashes]
 MD5 checksum:    {MD5}
 SHA1 checksum:   {SHA1}

Image Information:
 Acquisition started:   Sat Jun 01 09:00:00 2024
 Segment list:
  synthetic.E01

Image Verification Results:
 Verification started:  Sat Jun 01 09:30:00 2024
 MD5 checksum:    {MD5} : verified
 SHA1 checksum:   {SHA1} : verified

No bad blocks found in image
"""



MAIL_HEADER = ["InternetMessageId", "Subject", "From", "Date", "Attachments"]


def ours_messages(messages):
    return [
        {"provider": "email", "artifact_type": "email-message", "path": "C:/synthetic/box.mbox", "supported": True,
         "details": {"message_id": mid, "subject": subject, "from": sender, "date": date,
                     "attachment_count": len(files), "attachments": [{"name": f} for f in files]}}
        for mid, subject, sender, date, files in messages
    ]


def reference_messages(messages):
    return [[mid.strip("<>").upper(), subject, sender, date, ";".join(files)]
            for mid, subject, sender, date, files in messages]


class MailReferenceDiffTests(ReferenceDiffCase):
    script_name = "mail-reference-diff"

    def _diff(self, ours, reference):
        code, report, stderr = self.run_diff(
            write_jsonl(self.tmp / "ours.jsonl", ours), write_csv(self.tmp / "messages.csv", MAIL_HEADER, reference)
        )
        self.assert_contract(report)
        return code, report, stderr

    def test_message_count_match(self) -> None:
        code, report, _ = self._diff(ours_messages(MESSAGES), reference_messages(MESSAGES))
        self.assertEqual(code, 0)
        self.assertTrue(report["match"])
        self.assertEqual(report["messages"], {"ours": 3, "reference": 3})
        self.assertEqual(report["attachments"], {"ours": 3, "reference": 3, "missing": 0})
        self.assertEqual((report["recall"], report["mismatched"]), (1.0, []))

    def test_one_attachment_missing(self) -> None:
        ours = ours_messages(MESSAGES)
        ours[2]["details"]["attachment_count"] = 1
        ours[2]["details"]["attachments"] = [{"name": "a.docx"}]
        code, report, _ = self._diff(ours, reference_messages(MESSAGES))
        self.assertEqual(code, 1)
        self.assertFalse(report["match"])
        self.assertEqual((report["attachments"]["missing"], report["recall"]), (1, 1.0))
        self.assertEqual([(item["key"], item["fields"]) for item in report["mismatched"]],
                         [("m3@example.com", {"attachment_count": {"ours": 1, "reference": 2}})])

    def test_message_without_id_keyed_by_sender_subject_date(self) -> None:
        messages = [("", "No id", "d@example.com", "Wed, 05 Jun 2024 10:00:00 +0900", [])]
        reference = reference_messages(messages)
        reference[0][3] = "2024-06-05 01:00:00"
        code, report, _ = self._diff(ours_messages(messages), reference)
        self.assertEqual(code, 0)
        self.assertTrue(report["match"])

    def test_missing_input_exits_2(self) -> None:
        self.assert_missing_input_exit_2(write_csv(self.tmp / "present.csv", MAIL_HEADER, reference_messages(MESSAGES)))


class MediaHashCheckTests(ReferenceDiffCase):
    script_name = "media-hash-check"

    def _file(self, name: str, text: str, encoding: str = "utf-8") -> str:
        path = self.tmp / name
        path.write_text(text, encoding=encoding)
        return str(path)

    def _run(self, *argv, expect: int):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = self.module.main([*argv, "--json"])
        self.assertEqual(code, expect)
        report = json.loads(stdout.getvalue())
        self.assert_contract(report)
        return report

    def test_media_hash_match(self) -> None:
        ours = self._file("ours.json", json.dumps({"command": "source-metadata", "hash_status": "computed",
                                                   "hashes": {"md5": MD5.upper(), "sha1": SHA1}}))
        report = self._run("--reference", self._file("ewfverify.txt", EWF_OK),
                           "--acquisition-log", self._file("image.txt", FTK_LOG, "utf-16"), "--ours", ours, expect=0)
        self.assertTrue(report["match"])
        self.assertEqual((report["error_chunks"], report["mismatched"], len(report["comparisons"])), (0, [], 6))
        self.assertEqual(report["sources"]["acquisition_log"]["hashes"], {"md5": MD5, "sha1": SHA1})

    def test_damaged_set(self) -> None:
        report = self._run("--reference", self._file("ewfverify.txt", EWF_DAMAGED),
                           "--acquisition-log", self._file("image.txt", FTK_LOG), expect=1)
        self.assertFalse(report["match"])
        self.assertGreaterEqual(report["error_chunks"], 1)
        self.assertEqual(report["sources"]["ewfverify"]["result"], "FAILURE")
        self.assertEqual({item["pair"] for item in report["mismatched"]},
                         {"ewfverify-stored-vs-calculated", "acquisition-log-vs-ewfverify-calculated"})

    def test_recorded_or_expected_hash_is_never_ours(self) -> None:
        # WB-12 review P1-5: the experiment that used to pass by comparing a recorded hash with itself.
        circular = self._file("ours.json", json.dumps({"evidence": {
            "expected_md5": MD5, "hash_recorded": {"md5": MD5}, "container_sha256": "ab" * 32}}))
        ewf = self._file("ewfverify.txt", EWF_OK)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self.module.main(["--reference", ewf, "--ours", circular]), 2)
            self.assertIn("RapidTriage가 계산한 해시를 찾지 못했습니다", stderr.getvalue())
            for key in ("evidence.expected_md5", "evidence.hash_recorded", "inventory_sha256", "record_sha256"):
                self.assertEqual(self.module.main(["--reference", ewf, "--ours", circular, "--ours-key", key]), 2)
        self.assertIn("RapidTriage가 계산한 해시가 아닙니다", stderr.getvalue())
        computed = self._file("computed.json", json.dumps({"run": {"media": {"md5": MD5, "sha1": SHA1}}}))
        report = self._run("--reference", ewf, "--ours", computed, "--ours-key", "run.media", expect=0)
        self.assertEqual(report["sources"]["ours"]["key"], "run.media")
        self.assertIn("컨테이너", report["sources"]["ours"]["scope"])
        not_computed = self._file("pending.json", json.dumps({"hash_status": "not-requested", "hashes": {"md5": MD5}}))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.module.main(["--reference", ewf, "--ours", not_computed]), 2)

    def test_ours_without_a_shared_algorithm_is_not_a_match(self) -> None:
        # WB-13 review P1-4 experiment: ewfverify MD5 stored = calculated, ours a computed SHA-256 only.
        ewf_md5 = "\n".join(line for line in EWF_OK.splitlines() if "SHA1" not in line) + "\n"
        ours = self._file("ours.json", json.dumps({"command": "source-metadata", "hash_status": "computed",
                                                   "extension": ".dd", "hashes": {"sha256": "ab" * 32}}))
        report = self._run("--reference", self._file("ewfverify.txt", ewf_md5), "--ours", ours, expect=1)
        self.assertFalse(report["match"])
        self.assertIs(report["ours_compared"], False)
        self.assertEqual([item["pair"] for item in report["comparisons"]], ["ewfverify-stored-vs-calculated"])
        self.assertIn("우리 해시와 겹치는 알고리즘 없음", report["match_reasons"][0])

    def test_missing_algorithm_in_ours_is_not_a_match(self) -> None:
        ours = self._file("ours.json", json.dumps({"command": "source-metadata", "hash_status": "computed",
                                                   "extension": ".dd", "hashes": {"md5": MD5}}))
        report = self._run("--reference", self._file("ewfverify.txt", EWF_OK), "--ours", ours, expect=1)
        self.assertFalse(report["match"])
        self.assertIs(report["ours_compared"], True)
        self.assertEqual(report["missing"], [{"source": "ewfverify-calculated", "algorithm": "sha1"}])
        self.assertTrue(any("RapidTriage 해시에 없는 알고리즘: sha1" in reason for reason in report["match_reasons"]))

    def test_e01_container_hash_is_never_counted_as_a_match(self) -> None:
        payload = {"command": "source-metadata", "hash_status": "computed", "name": "synthetic.E01",
                   "extension": ".e01", "hashes": {"md5": MD5, "sha1": SHA1}}
        ours = self._file("ours.json", json.dumps(payload))
        ewf = self._file("ewfverify.txt", EWF_OK)
        report = self._run("--reference", ewf, "--ours", ours, expect=1)
        self.assertFalse(report["match"])
        self.assertEqual(report["match_reasons"], ["컨테이너 해시 — 매체 해시와 비교 불가"])
        self.assertIs(report["ours_compared"], False)
        self.assertEqual(report["sources"]["ours"]["scope_kind"], "container")
        self.assertFalse(any(item["pair"].startswith("ours-vs-") for item in report["comparisons"]))
        # A raw image named as such (or --ours-scope media) is a media hash and is compared.
        report = self._run("--reference", ewf, "--ours", ours, "--ours-scope", "media", expect=0)
        self.assertEqual((report["match"], report["ours_compared"], report["match_reasons"]), (True, True, []))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.module.main(["--reference", ewf, "--ours", ours]), 1)
        self.assertIn("일치 아님: 컨테이너 해시 — 매체 해시와 비교 불가", stdout.getvalue())

    def test_hashes_without_hash_status_are_not_taken_as_computed(self) -> None:
        ours = self._file("ours.json", json.dumps({"hashes": {"md5": MD5, "sha1": SHA1}}))
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(self.module.main(["--reference", self._file("ewfverify.txt", EWF_OK), "--ours", ours]), 2)
        self.assertIn("RapidTriage가 계산한 해시를 찾지 못했습니다", stderr.getvalue())

    def test_bad_blocks_in_the_acquisition_log_fail_the_match(self) -> None:
        log = FTK_LOG.replace("No bad blocks found in image", "Bad Blocks: 37\nNo bad blocks found in segment 2")
        report = self._run("--reference", self._file("ewfverify.txt", EWF_OK),
                           "--acquisition-log", self._file("image.txt", log), expect=1)
        self.assertFalse(report["match"])
        self.assertEqual((report["bad_sectors"], report["error_chunks"]), (37, 37))
        self.assertEqual(report["error_chunk_sources"], {"ewfverify_error_ranges": 0, "acquisition_log_bad_sectors": 37})
        self.assertEqual(report["mismatched"], [])
        parsed = self.module.parse_acquisition_log("Bad sectors: 2\nread errors: 3\nNo bad sectors\n")
        self.assertEqual(parsed["bad_sectors"], 5)

    def test_inputs_required(self) -> None:
        only_log = self._file("only.txt", "no hashes here\n")
        for argv in ([], ["--reference", str(self.tmp / "missing.txt")], ["--acquisition-log", only_log]):
            stderr = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stderr(stderr):
                self.assertEqual(self.module.main(argv), 2)
                self.assertIn("오류:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
