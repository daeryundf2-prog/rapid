"""WER ``Report.wer`` decoding: Windows writes the file as UTF-16 LE with a BOM."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from rapidtriage.artifacts.windows.system import (
    collect_wer_reports,
    decode_text_auto,
    parse_key_value_file,
    preview_text,
)

WER_TEXT = (
    "Version=1\n"
    "EventType=APPCRASH\n"
    "EventTime=133929489512828096\n"
    "ReportType=2\n"
    "Consent=1\n"
    "UploadTime=133929489520000000\n"
    "ReportIdentifier=a8948791-178a-475c-9a38-de610f05e947\n"
    "Response.BucketId=2124567890123456789\n"
    "Sig[0].Name=Application Name\n"
    "Sig[0].Value=ALPDF.exe\n"
    "Sig[3].Name=Fault Module Name\n"
    "Sig[3].Value=KERNELBASE.dll\n"
    "Sig[6].Name=Exception Code\n"
    "Sig[6].Value=c0000005\n"
    "AppName=ALPDF.exe\n"
    "AppPath=C:\\Program Files (x86)\\ALPDF\\ALPDF.exe\n"
    "FaultModuleName=KERNELBASE.dll\n"
    "FriendlyEventName=작동이 중지됨\n"
)


def write_report(root: Path, text: str, encoding: str) -> Path:
    report_dir = root / "ProgramData" / "Microsoft" / "Windows" / "WER" / "ReportArchive" / "AppCrash_ALPDF.exe_1"
    report_dir.mkdir(parents=True)
    path = report_dir / "Report.wer"
    path.write_bytes(text.encode(encoding))
    return path


class WerReportDecodingTests(unittest.TestCase):
    def test_decode_text_auto_handles_boms_and_bare_utf16(self) -> None:
        self.assertEqual(decode_text_auto("a=1\n".encode("utf-16")), "a=1\n")
        self.assertEqual(decode_text_auto("a=1\n".encode("utf-16-be")), "a=1\n")
        self.assertEqual(decode_text_auto(b"\xff\xfe" + "a=1\n".encode("utf-16-le")), "a=1\n")
        self.assertEqual(decode_text_auto(b"\xef\xbb\xbf" + b"a=1\n"), "a=1\n")
        self.assertEqual(decode_text_auto("한글=값\n".encode()), "한글=값\n")
        self.assertEqual(decode_text_auto(b""), "")

    def test_utf16_report_fields_are_decoded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_report(root, WER_TEXT, "utf-16")
            fields = parse_key_value_file(path)
            self.assertEqual(fields["AppName"], "ALPDF.exe")
            self.assertEqual(fields["FaultModuleName"], "KERNELBASE.dll")
            self.assertEqual(fields["FriendlyEventName"], "작동이 중지됨")
            self.assertNotIn("\ufeffVersion", fields)
            self.assertEqual(fields["Version"], "1")
            self.assertTrue(preview_text(path).startswith("Version=1\nEventType=APPCRASH"))

            records = list(collect_wer_reports(root))
            self.assertEqual(len(records), 1)
            details = records[0].details
            self.assertEqual(details["application_name"], "ALPDF.exe")
            self.assertEqual(details["fault_module_name"], "KERNELBASE.dll")
            self.assertEqual(details["report_id"], "a8948791-178a-475c-9a38-de610f05e947")
            self.assertEqual(details["event_type"], "APPCRASH")
            self.assertTrue(str(details["event_time"]).startswith("2025-"))
            self.assertTrue(details["validation_checks"]["has_application"])
            self.assertTrue(details["validation_checks"]["has_fault_module"])
            self.assertTrue(details["validation_checks"]["has_event_time"])
            self.assertEqual(details["fields"]["AppPath"], "C:\\Program Files (x86)\\ALPDF\\ALPDF.exe")

    def test_utf8_report_still_parses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_report(root, WER_TEXT, "utf-8")
            records = list(collect_wer_reports(root))
            self.assertEqual(records[0].details["application_name"], "ALPDF.exe")
            self.assertEqual(records[0].details["fault_module_name"], "KERNELBASE.dll")


if __name__ == "__main__":
    unittest.main()
