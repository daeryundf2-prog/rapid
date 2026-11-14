"""mail-reference-diff.py and media-hash-check.py on synthetic inputs (T-212)."""

from __future__ import annotations

import contextlib
import csv
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"rt_{name.replace('-', '_')}_test", SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mail = _load("mail-reference-diff")
media = _load("media-hash-check")

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


class MailReferenceDiffTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _ours(self, messages):
        return [
            {"provider": "email", "artifact_type": "email-message", "path": "C:/synthetic/box.mbox", "supported": True,
             "details": {"message_id": mid, "subject": subject, "from": sender, "date": date,
                         "attachment_count": len(files), "attachments": [{"name": f} for f in files]}}
            for mid, subject, sender, date, files in messages
        ]

    def _reference(self, messages):
        return [{"InternetMessageId": mid.strip("<>").upper(), "Subject": subject, "From": sender, "Date": date,
                 "Attachments": ";".join(files)}
                for mid, subject, sender, date, files in messages]

    def _run(self, ours, reference):
        ours_path = self.root / "ours.jsonl"
        ours_path.write_text("".join(json.dumps(row) + "\n" for row in ours), encoding="utf-8")
        ref_path = self.root / "messages.csv"
        with ref_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(reference[0]))
            writer.writeheader()
            writer.writerows(reference)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = mail.main(["--ours", str(ours_path), "--reference", str(ref_path), "--json"])
        self.assertEqual(code, 0)
        return json.loads(stdout.getvalue())

    def test_message_count_match(self) -> None:
        report = self._run(self._ours(MESSAGES), self._reference(MESSAGES))
        self.assertTrue(report["match"])
        self.assertEqual(report["messages"], {"ours": 3, "reference": 3})
        self.assertEqual(report["attachments"], {"ours": 3, "reference": 3, "missing": 0})
        self.assertEqual((report["recall"], report["mismatched"]), (1.0, []))
        for key in ("recall", "matched", "missing", "mismatched", "reference_tool"):
            self.assertIn(key, report)

    def test_one_attachment_missing(self) -> None:
        ours = self._ours(MESSAGES)
        ours[2]["details"]["attachment_count"] = 1
        ours[2]["details"]["attachments"] = [{"name": "a.docx"}]
        report = self._run(ours, self._reference(MESSAGES))
        self.assertFalse(report["match"])
        self.assertEqual(report["attachments"]["missing"], 1)
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["mismatched"], [{"key": "m3@example.com", "fields": {
            "attachment_count": {"ours": "1", "reference": "2"}}}])

    def test_message_without_id_keyed_by_sender_subject_date(self) -> None:
        messages = [("", "No id", "d@example.com", "Wed, 05 Jun 2024 10:00:00 +0900", [])]
        reference = self._reference(messages)
        reference[0]["Date"] = "2024-06-05 01:00:00"
        report = self._run(self._ours(messages), reference)
        self.assertTrue(report["match"])


class MediaHashCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _file(self, name: str, text: str, encoding: str = "utf-8") -> str:
        path = self.root / name
        path.write_text(text, encoding=encoding)
        return str(path)

    def _run(self, *argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = media.main([*argv, "--json"])
        self.assertEqual(code, 0)
        return json.loads(stdout.getvalue())

    def test_media_hash_match(self) -> None:
        ours = self._file("ours.json", json.dumps({"evidence": {"image": {"md5": MD5.upper(), "sha1": SHA1}}}))
        report = self._run("--reference", self._file("ewfverify.txt", EWF_OK),
                           "--acquisition-log", self._file("image.txt", FTK_LOG, "utf-16"), "--ours", ours)
        self.assertTrue(report["match"])
        self.assertEqual(report["error_chunks"], 0)
        self.assertEqual(report["mismatched"], [])
        self.assertEqual(len(report["comparisons"]), 6)
        self.assertEqual(report["sources"]["acquisition_log"]["hashes"], {"md5": MD5, "sha1": SHA1})

    def test_damaged_set(self) -> None:
        report = self._run("--reference", self._file("ewfverify.txt", EWF_DAMAGED),
                           "--acquisition-log", self._file("image.txt", FTK_LOG))
        self.assertFalse(report["match"])
        self.assertGreaterEqual(report["error_chunks"], 1)
        self.assertEqual(report["sources"]["ewfverify"]["result"], "FAILURE")
        self.assertEqual({item["pair"] for item in report["mismatched"]},
                         {"ewfverify-stored-vs-calculated", "acquisition-log-vs-ewfverify-calculated"})

    def test_inputs_required(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(media.main(["--json"]), 2)
            self.assertEqual(media.main(["--reference", str(self.root / "missing.txt")]), 2)
            only_log = self._file("only.txt", "no hashes here\n")
            self.assertEqual(media.main(["--acquisition-log", only_log]), 2)


if __name__ == "__main__":
    unittest.main()
