"""Synthetic pffexport/readpst output trees and ICS files (r2 M2). All values are synthetic.

The pffexport tree follows libpff ``pffexport -f all -t <target>``: ``<target>.export`` holds the
folder hierarchy with ``Message00001`` / ``Appointment00001`` / ``Contact00001`` item folders
(``OutlookHeaders.txt``, ``InternetHeaders.txt``, ``Recipients.txt``, ``Message.txt``,
``Attachments/``), ``<target>.recovered`` the recovered items.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PST_HEADER = b"!BDN" + b"\x00" * 508

ICS_THREE_EVENTS = (
    "BEGIN:VCALENDAR\r\n"
    "VERSION:2.0\r\n"
    "PRODID:-//RapidTriage//Synthetic//KO\r\n"
    "BEGIN:VTIMEZONE\r\n"
    "TZID:Asia/Seoul\r\n"
    "BEGIN:STANDARD\r\n"
    "DTSTART:19700101T000000\r\n"
    "TZOFFSETFROM:+0900\r\n"
    "TZOFFSETTO:+0900\r\n"
    "END:STANDARD\r\n"
    "END:VTIMEZONE\r\n"
    "BEGIN:VEVENT\r\n"
    "UID:evt-1@example.com\r\n"
    "DTSTAMP:20240301T000000Z\r\n"
    "DTSTART:20240305T010000Z\r\n"
    "DTEND:20240305T020000Z\r\n"
    "SUMMARY:분기 실적 검토\\, 1차\r\n"
    "LOCATION:본사 3층 회의실\r\n"
    "ORGANIZER;CN=Alice Kim:mailto:alice@example.com\r\n"
    "ATTENDEE;CN=Bob Lee;PARTSTAT=ACCEPTED:mailto:bob@example.com\r\n"
    "ATTENDEE;CN=\"Partner, Inc\":mailto:carol@partner.example.net\r\n"
    "DESCRIPTION:첫 줄\\n둘째 줄 접힌\r\n"
    "  줄 이어짐\r\n"
    "BEGIN:VALARM\r\n"
    "ACTION:DISPLAY\r\n"
    "DESCRIPTION:알림(이벤트 설명 아님)\r\n"
    "END:VALARM\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "UID:evt-2@example.com\r\n"
    "DTSTART;TZID=Asia/Seoul:20240306T090000\r\n"
    "DTEND;TZID=Asia/Seoul:20240306T100000\r\n"
    "SUMMARY:외부 미팅\r\n"
    "RRULE:FREQ=WEEKLY;COUNT=4\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "UID:evt-3@example.com\r\n"
    "DTSTART;VALUE=DATE:20240310\r\n"
    "DTEND;VALUE=DATE:20240311\r\n"
    "SUMMARY:연차\r\n"
    "END:VEVENT\r\n"
    "BEGIN:VEVENT\r\n"
    "UID:evt-unterminated@example.com\r\n"
    "SUMMARY:끝나지 않은 일정\r\n"
    "END:VCALENDAR\r\n"
)


def write_item(folder: Path, files: dict[str, str | bytes], attachments: dict[str, bytes] | None = None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = folder / name
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    for name, data in (attachments or {}).items():
        (folder / "Attachments").mkdir(exist_ok=True)
        (folder / "Attachments" / name).write_bytes(data)
    return folder


def outlook_headers(subject: str, submit: str, *, flags: str = "0x00000001 (Read)", sender: str = "Alice Kim", address: str = "alice@example.com") -> str:
    return (
        f"Client submit time:\t\t{submit}\n"
        f"Delivery time:\t\t\t{submit}\n"
        f"Flags:\t\t\t\t{flags}\n"
        f"Subject:\t\t\t{subject}\n"
        f"Conversation topic:\t\t{subject}\n"
        f"Sender name:\t\t\t{sender}\n"
        f"Sender email address:\t\t{address}\n"
    )


def recipients(*entries: tuple[str, str, str]) -> str:
    blocks = []
    for index, (name, address, kind) in enumerate(entries, start=1):
        blocks.append(
            f"Recipient: {index}\nDisplay name:\t\t\t{name}\nEmail address:\t\t\t{address}\nAddress type:\t\t\tSMTP\nRecipient type:\t\t\t{kind}\n"
        )
    return "\n".join(blocks)


def write_pffexport_tree(export_dir: Path, stem: str = "mailbox") -> Path:
    """``<export_dir>/<stem>.export`` + ``<stem>.recovered`` with 4 messages, 1 appointment, 1 contact."""
    top = export_dir / f"{stem}.export" / "Top of Personal Folders"
    write_item(
        top / "Inbox" / "Message00001",
        {
            "OutlookHeaders.txt": outlook_headers("견적 요청", "Mar 04, 2024 01:02:03.123456789 UTC", sender="Bob Lee", address="bob@example.com"),
            "InternetHeaders.txt": (
                "From: Bob Lee <bob@example.com>\nTo: Alice Kim <alice@example.com>\nSubject: =?utf-8?B?6rKs7KCBIOyalOyyrQ==?=\n"
                "Message-ID: <inbox-1@example.com>\nDate: Mon, 04 Mar 2024 01:02:03 +0000\n"
                "Authentication-Results: mx.example.com; spf=pass\n"
            ),
            "Recipients.txt": recipients(("Alice Kim", "alice@example.com", "To")),
            "Message.txt": "안녕하세요, 견적 부탁드립니다.",
            "ConversationIndex.txt": "01D9 AABB CCDD",
        },
    )
    write_item(
        top / "Sent Items" / "Message00001",
        {
            "OutlookHeaders.txt": outlook_headers("자료 송부", "Mar 05, 2024 10:00:00 UTC"),
            "Recipients.txt": recipients(
                ("Mallory", "mallory@gmail.com", "To"),
                ("Bob Lee", "bob@example.com", "CC"),
                ("Hidden", "hidden@partner.example.net", "BCC"),
            ),
            "Message.html": "<html><body><p>첨부 확인 바랍니다</p></body></html>",
        },
        attachments={"설계도.pdf": b"%PDF-1.7 synthetic", "고객명단.xlsx": b"PK\x03\x04synthetic"},
    )
    write_item(
        top / "Deleted Items" / "Message00001",
        {"OutlookHeaders.txt": outlook_headers("삭제한 메일", "Mar 06, 2024 09:00:00 UTC", flags="0x00000000")},
    )
    # Damaged item: binary garbage instead of text files must not stop the export.
    write_item(top / "Inbox" / "Message00002", {"OutlookHeaders.txt": b"\x00\xff\xfe\x00garbage", "Recipients.txt": b"\xff" * 64})
    write_item(
        top / "Calendar" / "Appointment00001",
        {
            "OutlookHeaders.txt": outlook_headers("주간 회의", "Mar 01, 2024 00:00:00 UTC"),
            "Appointment.txt": "Start time:\t\tMar 07, 2024 01:00:00 UTC\nEnd time:\t\tMar 07, 2024 02:00:00 UTC\nLocation:\t\t대회의실\n",
            "Recipients.txt": recipients(("Bob Lee", "bob@example.com", "To")),
        },
    )
    write_item(
        top / "Contacts" / "Contact00001",
        {
            "Contact.txt": (
                "File under:\t\tLee, Bob\nGiven name:\t\tBob\nSurname:\t\tLee\nEmail address 1:\tbob@example.com\n"
                "Business phone number:\t+82-2-555-0100\nMobile phone number:\t010-5555-0101\nCompany name:\t\tExample Corp\nTitle:\t\t\t과장\n"
            )
        },
    )
    write_item(
        export_dir / f"{stem}.recovered" / "Message00001",
        {"OutlookHeaders.txt": outlook_headers("복구된 메일", "Feb 01, 2024 00:00:00 UTC", flags="0x00000000")},
    )
    return export_dir


def write_readpst_tree(export_dir: Path) -> Path:
    inbox = export_dir / "Personal Folders" / "Inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / "mbox").write_bytes(
        b"From \"bob@example.com\" Mon Mar  4 01:02:03 2024\n"
        b"From: Bob Lee <bob@example.com>\nTo: alice@example.com\nSubject: readpst one\nMessage-ID: <rp-1@example.com>\n"
        b"Date: Mon, 04 Mar 2024 01:02:03 +0000\nStatus: RO\nMIME-Version: 1.0\n"
        b"Content-Type: multipart/mixed; boundary=XX\n\n--XX\nContent-Type: text/plain\n\nbody one\n"
        b"--XX\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=\"a.pdf\"\nContent-Transfer-Encoding: base64\n\nJVBERi0xLjc=\n--XX--\n"
        b"\nFrom \"carol@example.com\" Tue Mar  5 01:02:03 2024\n"
        b"From: carol@example.com\nTo: alice@example.com\nSubject: readpst two\nDate: Tue, 05 Mar 2024 01:02:03 +0000\n\nbody two\n"
    )
    calendar = export_dir / "Personal Folders" / "Calendar"
    calendar.mkdir(parents=True, exist_ok=True)
    (calendar / "calendar").write_text(ICS_THREE_EVENTS, encoding="utf-8")
    contacts = export_dir / "Personal Folders" / "Contacts"
    contacts.mkdir(parents=True, exist_ok=True)
    (contacts / "contacts").write_text(
        "BEGIN:VCARD\nVERSION:3.0\nFN:Bob Lee\nN:Lee;Bob;;;\nEMAIL;TYPE=INTERNET:bob@example.com\nTEL;TYPE=CELL:010-5555-0101\nORG:Example Corp\nEND:VCARD\n",
        encoding="utf-8",
    )
    return export_dir


def fake_pffexport_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
    """Stands in for ``pffexport -f all -t <target> <pst>``: writes the synthetic tree next to ``<target>``."""
    target = Path(command[command.index("-t") + 1])
    write_pffexport_tree(target.parent, target.name)
    return subprocess.CompletedProcess(command, 0, "pffexport synthetic\n", "")


def fake_tool_resolver(name: str) -> str | None:
    return f"/usr/bin/{name}" if name == "pffexport" else None


def no_tools(_name: str) -> str | None:
    return None
