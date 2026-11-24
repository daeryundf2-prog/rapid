"""D22 mail review: forwarded-message attribution (collector, API viewer/export, external export preview),
EMLX trailer isolation, ICS recurrence exceptions."""

from __future__ import annotations

import base64
import hashlib
import json
import plistlib
import tempfile
import unittest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from rapidtriage.artifacts.email_external import external_email_message_sample
from rapidtriage.cli import main

HAS_FASTAPI = True
try:
    from rapidtriage.api.app.email import (
        build_email_attachment_package,
        build_email_preview,
    )
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    HAS_FASTAPI = False


def synthetic_message(subject: str, body: str) -> EmailMessage:
    message = EmailMessage(policy=policy.SMTP)
    message["Subject"] = subject
    message.set_content(body)
    return message


def forwarded_envelope(subject: str = "Cover") -> bytes:
    """Outer text SYNTH_OUTER, an attached message (SYNTH_INNER) and a 7-byte control attachment."""
    outer = synthetic_message(subject, "SYNTH_OUTER")
    outer.add_attachment(synthetic_message("Enclosure", "SYNTH_INNER"), filename="forwarded.eml")
    outer.add_attachment(b"control", maintype="application", subtype="octet-stream", filename="control.bin")
    return outer.as_bytes()


def collect_email_rows(evidence: Path, output: Path) -> dict[str, list[dict]]:
    exit_code = main(["artifacts", str(evidence), "--kind", "email", "--output", str(output)])
    if exit_code != 0:
        raise AssertionError(f"artifacts exited {exit_code}")
    rows: dict[str, list[dict]] = {}
    for row in json.loads(output.read_text(encoding="utf-8"))["artifacts"]:
        rows.setdefault(Path(row["path"]).name, []).append(row)
    return rows


class ForwardedMessageAttributionTests(unittest.TestCase):
    """D22-5: an attached message/rfc822 is its own message, not part of the enclosing body."""

    def test_enclosed_message_text_and_bytes_belong_to_the_attachment(self) -> None:
        envelope = forwarded_envelope()
        reference = BytesParser(policy=policy.SMTP).parsebytes(envelope)
        enclosed_reference = list(reference.iter_attachments())[0].get_payload()[0].as_bytes(policy=policy.SMTP)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "nested.eml").write_bytes(envelope)
            details = collect_email_rows(evidence, root / "mail.json")["nested.eml"][0]["details"]

        self.assertEqual(details["body_preview"], "SYNTH_OUTER")
        self.assertEqual(details["body_sha256"], hashlib.sha256(b"SYNTH_OUTER").hexdigest())
        forwarded, control = details["attachments"]

        self.assertEqual(forwarded["filename"], "forwarded.eml")
        self.assertEqual(forwarded["content_type"], "message/rfc822")
        self.assertEqual(forwarded["hash_basis"], "enclosed-message-source-bytes")
        offset, size = forwarded["source_byte_offset"], forwarded["size"]
        stored = envelope[offset : offset + size]
        self.assertEqual(size, len(enclosed_reference))
        self.assertEqual(stored, enclosed_reference)
        self.assertEqual(forwarded["sha256"], hashlib.sha256(stored).hexdigest())
        self.assertEqual(forwarded["source_viewer_locator"]["hash_basis"], "enclosed-message-source-bytes")
        enclosed = forwarded["enclosed_message"]
        self.assertEqual(enclosed["subject"], "Enclosure")
        self.assertEqual(enclosed["body_preview"], "SYNTH_INNER")
        self.assertEqual(enclosed["body_sha256"], hashlib.sha256(b"SYNTH_INNER").hexdigest())
        self.assertEqual(enclosed["attachment_count"], 0)

        self.assertEqual(control["filename"], "control.bin")
        self.assertEqual(control["size"], 7)
        self.assertEqual(control["sha256"], hashlib.sha256(b"control").hexdigest())
        self.assertEqual(control["hash_basis"], "decoded-transfer-payload")
        self.assertEqual(
            set(details["attachment_hash_basis_definitions"]),
            {"decoded-transfer-payload", "enclosed-message-source-bytes", "enclosed-message-reserialized-crlf"},
        )


ATTACHMENT_IDENTITY = ("index", "filename", "content_type", "size", "sha256", "hash_basis", "source_byte_offset")


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for the API email viewer")
class ForwardedMessageApiViewerTests(unittest.TestCase):
    """D22-5 follow-up: viewer preview and attachment export number and hash attachments like the collector."""

    def assert_viewer_matches_collector(self, source: Path, suffix: str, rows: list[dict], data: bytes) -> None:
        preview = build_email_preview(source, suffix, run_id="run-d22")
        self.assertEqual(len(preview["email"]["messages"]), len(rows))
        for message_index, (summary, row) in enumerate(zip(preview["email"]["messages"], rows), start=1):
            collected = row["details"]["attachments"]
            self.assertEqual(summary["body_preview"].strip(), "SYNTH_OUTER")
            self.assertEqual(
                [{key: item.get(key) for key in ATTACHMENT_IDENTITY} for item in summary["attachments"]],
                [{key: item.get(key) for key in ATTACHMENT_IDENTITY} for item in collected],
            )
            self.assertEqual(collected[0]["hash_basis"], "enclosed-message-source-bytes")
            for attachment in collected:
                package = build_email_attachment_package(
                    run_id="run-d22",
                    source_path=source,
                    suffix=suffix,
                    message_index=message_index,
                    attachment_index=attachment["index"],
                    include_content=True,
                )
                exported = base64.b64decode(package["content_base64"])
                self.assertEqual(package["filename"], attachment["filename"])
                self.assertEqual(package["hash_basis"], attachment["hash_basis"])
                self.assertEqual(len(exported), attachment["size"])
                self.assertEqual(package["hashes"]["sha256"], attachment["sha256"])
                self.assertEqual(hashlib.sha256(exported).hexdigest(), attachment["sha256"])
                if attachment["hash_basis"] == "enclosed-message-source-bytes":
                    offset = attachment["source_byte_offset"]
                    self.assertEqual(data[offset : offset + len(exported)], exported)

    def test_eml_preview_and_export_match_collector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            source = evidence / "nested.eml"
            data = forwarded_envelope()
            source.write_bytes(data)
            rows = collect_email_rows(evidence, root / "mail.json")["nested.eml"]
            self.assert_viewer_matches_collector(source, ".eml", rows, data)

    def test_mbox_preview_and_export_match_collector(self) -> None:
        separator = b"From sender@example.test Mon Jan  1 00:00:00 2025\n"
        data = separator + forwarded_envelope("First") + b"\n" + separator + forwarded_envelope("Second")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            source = evidence / "folder.mbox"
            source.write_bytes(data)
            rows = [
                row
                for row in collect_email_rows(evidence, root / "mail.json")["folder.mbox"]
                if row["artifact_type"] == "email-message"
            ]
            self.assertEqual([row["details"]["subject"] for row in rows], ["First", "Second"])
            self.assert_viewer_matches_collector(source, ".mbox", rows, data)


class ForwardedMessageExternalPreviewTests(unittest.TestCase):
    """D22-5 follow-up: an external-tool export sample previews only the outer message's own text."""

    def test_external_sample_preview_excludes_enclosed_text(self) -> None:
        sample = external_email_message_sample(Path("export.eml"), {}, 1, forwarded_envelope())
        self.assertEqual(sample["body_preview"], "SYNTH_OUTER")
        self.assertEqual([item["filename"] for item in sample["attachments"]], ["forwarded.eml", "control.bin"])
        self.assertEqual(sample["attachments"][0]["enclosed_message"]["body_preview"], "SYNTH_INNER")


class EmlxTrailerTests(unittest.TestCase):
    """D22-8: only the declared byte count is the message; the Apple plist trailer is separate metadata."""

    def test_declared_length_bounds_the_message_and_trailer_is_reported_separately(self) -> None:
        mail = synthetic_message("Length control", "SYNTH_BODY").as_bytes()
        trailers = {
            "control.emlx": b"",
            "one.emlx": plistlib.dumps({"flags": 1, "reviewMarker": "SYNTH_METADATA"}),
            "two.emlx": plistlib.dumps({"flags": 2}),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            for name, trailer in trailers.items():
                (evidence / name).write_bytes(str(len(mail)).encode("ascii") + b"\n" + mail + trailer)
            rows = collect_email_rows(evidence, root / "mail.json")
            file_hashes = {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest() for name in trailers}

        details = {name: rows[name][0]["details"] for name in trailers}
        for name, info in details.items():
            with self.subTest(name=name):
                self.assertEqual(info["body_preview"], "SYNTH_BODY")
                self.assertNotIn("plist", info["body_preview"])
                self.assertEqual(info["source_hashes"]["sha256"], file_hashes[name])
                container = info["emlx_container"]
                self.assertEqual(container["declared_message_length"], len(mail))
                self.assertTrue(container["declared_length_within_file"])
                self.assertEqual(container["message_offset"], len(str(len(mail))) + 1)
                self.assertEqual(container["message_sha256"], hashlib.sha256(mail).hexdigest())
                self.assertEqual(container["trailer_length"], len(trailers[name]))
                self.assertEqual(
                    container["trailer_sha256"], hashlib.sha256(trailers[name]).hexdigest() if trailers[name] else ""
                )
        self.assertEqual(len({info["body_sha256"] for info in details.values()}), 1)
        self.assertNotIn("trailer_format", details["control.emlx"]["emlx_container"])
        self.assertEqual(details["one.emlx"]["emlx_container"]["trailer_format"], "apple-property-list")
        self.assertEqual(
            details["one.emlx"]["emlx_container"]["trailer_metadata"], {"flags": 1, "reviewMarker": "SYNTH_METADATA"}
        )
        self.assertEqual(details["two.emlx"]["emlx_container"]["trailer_metadata"], {"flags": 2})


class CalendarRecurrenceExceptionTests(unittest.TestCase):
    """D22-13: EXDATE and RECURRENCE-ID survive extraction so series exceptions are linkable by UID."""

    def test_exdate_and_recurrence_id_are_preserved(self) -> None:
        lines = [
            "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Fixture//Calendar//EN",
            "BEGIN:VEVENT", "UID:series", "DTSTAMP:20250101T120000Z", "DTSTART:20250101T100000Z",
            "RRULE:FREQ=DAILY;COUNT=4", "EXDATE:20250102T100000Z", "SUMMARY:Series", "END:VEVENT",
            "BEGIN:VEVENT", "UID:series", "DTSTAMP:20250101T120000Z", "RECURRENCE-ID:20250103T100000Z",
            "DTSTART:20250103T130000Z", "SUMMARY:Moved", "END:VEVENT",
            "BEGIN:VEVENT", "UID:zoned", "DTSTAMP:20250101T120000Z", "DTSTART;TZID=UTC:20250201T090000",
            "RRULE:FREQ=WEEKLY;COUNT=6", "EXDATE;TZID=UTC:20250208T090000,20250215T090000",
            "EXDATE;VALUE=DATE:20250301", "SUMMARY:Zoned", "END:VEVENT",
            "BEGIN:VEVENT", "UID:zoned", "DTSTAMP:20250101T120000Z",
            "RECURRENCE-ID;TZID=UTC;RANGE=THISANDFUTURE:20250222T090000",
            "DTSTART;TZID=UTC:20250222T110000", "SUMMARY:Zoned moved", "END:VEVENT",
            "END:VCALENDAR",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "series.ics").write_bytes(("\r\n".join(lines) + "\r\n").encode("ascii"))
            rows = [row["details"] for row in collect_email_rows(evidence, root / "mail.json")["series.ics"]]

        by_title = {row["title"]: row for row in rows}
        series, moved = by_title["Series"], by_title["Moved"]
        self.assertEqual(series["recurrence_rule"], "FREQ=DAILY;COUNT=4")
        self.assertEqual(
            series["recurrence_exception_dates"],
            [{"value": "20250102T100000Z", "params": {}, "time": "2025-01-02T10:00:00Z", "all_day": False, "timezone_status": "utc"}],
        )
        self.assertEqual(series["recurrence_id"], {})
        self.assertEqual(moved["uid"], series["uid"])
        self.assertEqual(moved["start"], "2025-01-03T13:00:00Z")
        self.assertEqual(moved["recurrence_id"]["value"], "20250103T100000Z")
        self.assertEqual(moved["recurrence_id"]["time"], "2025-01-03T10:00:00Z")
        self.assertEqual(moved["recurrence_exception_dates"], [])

        zoned, zoned_moved = by_title["Zoned"], by_title["Zoned moved"]
        self.assertEqual(
            [(item["value"], item["params"]) for item in zoned["recurrence_exception_dates"]],
            [
                ("20250208T090000", {"TZID": "UTC"}),
                ("20250215T090000", {"TZID": "UTC"}),
                ("20250301", {"VALUE": "DATE"}),
            ],
        )
        self.assertEqual(
            [item["time"] for item in zoned["recurrence_exception_dates"]],
            ["2025-02-08T09:00:00Z", "2025-02-15T09:00:00Z", "2025-03-01"],
        )
        self.assertTrue(zoned["recurrence_exception_dates"][2]["all_day"])
        self.assertEqual(zoned_moved["recurrence_id"]["value"], "20250222T090000")
        self.assertEqual(zoned_moved["recurrence_id"]["params"], {"TZID": "UTC", "RANGE": "THISANDFUTURE"})
        self.assertEqual(zoned_moved["recurrence_id"]["time"], "2025-02-22T09:00:00Z")


if __name__ == "__main__":
    unittest.main()
