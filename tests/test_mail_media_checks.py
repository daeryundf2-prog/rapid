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
        ours = self._file("ours.json", json.dumps({"evidence": {"image": {"md5": MD5.upper(), "sha1": SHA1}}}))
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

    def test_inputs_required(self) -> None:
        only_log = self._file("only.txt", "no hashes here\n")
        for argv in ([], ["--reference", str(self.tmp / "missing.txt")], ["--acquisition-log", only_log]):
            stderr = io.StringIO()
            with self.subTest(argv=argv), contextlib.redirect_stderr(stderr):
                self.assertEqual(self.module.main(argv), 2)
                self.assertIn("오류:", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
