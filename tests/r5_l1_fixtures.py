"""Synthetic fixtures for R5 L1 (communication and media apps).

Everything is generated in code: SQLite stores (Phone Link, Viber, Facebook
Messenger msys, Thunderbird Gloda / address book / calendar), mbox and .eml
files, ini / playlist files, a minimal regf NTUSER hive (the writer of
``tests.test_parser_quality_registry``), a fake ESE header and PSD files.
Names, numbers and addresses are invented (``example.com`` / ``example.org``,
``010-0000-xxxx``); no real application data and no PII.

Planted secret byte strings (``SECRET_*``) go into files that must never be
read (Signal ``config.json``, Thunderbird ``logins.json`` / ``key4.db``,
Windows Live Mail ``*_Password2``): the tests assert they never appear in any
output.
"""

from __future__ import annotations

import sqlite3
import struct
from datetime import datetime, timezone
from pathlib import Path

from tests.test_parser_quality_registry import (
    REG_DWORD,
    REG_SZ,
    HiveWriter,
    Key,
    dword,
    sz,
)

SECRET_SIGNAL = "R5L1-SIGNAL-SECRET-KEY-6f1c0ffee0ddba11"
SECRET_LOGINS = "R5L1-TB-LOGINS-SECRET-9a8b7c6d5e4f"
SECRET_KEY4 = b"R5L1-TB-KEY4-SECRET-\x01\x02\x03-deadbeef"
SECRET_LIVE_MAIL = "R5L1-WLM-PASSWORD2-SECRET-0badc0de"
SECRETS = (SECRET_SIGNAL, SECRET_LOGINS, SECRET_KEY4.decode("latin-1"), SECRET_LIVE_MAIL)

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
MESSAGE_TIME = datetime(2024, 5, 6, 7, 8, 9, tzinfo=timezone.utc)


def filetime(moment: datetime) -> int:
    delta = moment - EPOCH_1601
    return (delta.days * 86400 + delta.seconds) * 10_000_000


def unix_ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)
    return path


def sqlite_db(path: Path, script: str, rows: dict[str, list[tuple]] | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.executescript(script)
        for table, values in (rows or {}).items():
            for row in values:
                connection.execute(f"INSERT INTO {table} VALUES ({', '.join('?' for _ in row)})", row)
        connection.commit()
    finally:
        connection.close()
    return path


def home(root: Path, user: str = "alice") -> Path:
    path = root / "Users" / user
    (path / "AppData" / "Roaming").mkdir(parents=True, exist_ok=True)
    (path / "AppData" / "Local").mkdir(parents=True, exist_ok=True)
    return path


# --- media players --------------------------------------------------------------------------------


def vlc_files(user_home: Path) -> None:
    vlc = user_home / "AppData" / "Roaming" / "vlc"
    write(
        vlc / "vlc-qt-interface.ini",
        "[General]\nfiledialog-path=@Invalid()\n\n[RecentsMRU]\n"
        'list=file:///E:/%EC%98%81%EC%83%81/clip01.mp4, "file:///C:/Users/alice/Videos/a, b.mkv", '
        "http://stream.example.com/live.m3u8, file://nas01/share/movie.avi\n"
        "times=0, 125000, 0, 61500\n",
    )
    write(vlc / "vlcrc", "# comment\n[core]\n#snapshot-path=\nsnapshot-path=D:\\Snaps\ninput-record-path=D:\\Rec\n")


def potplayer_files(user_home: Path) -> None:
    base = user_home / "AppData" / "Roaming" / "PotPlayerMini64"
    ini = (
        "[Settings]\r\nSkinPath=C:\\Program Files\\DAUM\\PotPlayer\\Skins\\x.dsf\r\n"
        "LastPlayFile=F:\\backup\\secret_video.mp4\r\n"
        "[RememberFiles]\r\n0=D:\\Movies\\film1.mkv\r\n1=\\\\nas01\\media\\film2.mp4\r\n2=not a path\r\n"
    )
    write(base / "PotPlayerMini64.ini", b"\xff\xfe" + ini.encode("utf-16-le"))
    write(
        base / "Playlist" / "PotPlayerMini64.dpl",
        "DAUMPLAYLIST\nplayname=E:\\usb\\clip9.mp4\ntopindex=0\n1*file*E:\\usb\\clip9.mp4\n1*played*1\n"
        "2*file*https://video.example.org/v.mp4\n",
    )


def ntuser_media_hive() -> bytes:
    root = Key("ROOT")
    pot = root.path(r"Software\DAUM\PotPlayer64")
    pot.path("RememberFiles").value("0", REG_SZ, sz(r"G:\캠코더\영상1.mp4")).value("1", REG_SZ, sz(r"C:\Users\alice\Downloads\b.avi"))
    pot.path("Settings").value("SkinName", REG_SZ, sz(r"C:\skins\a.dsf"))
    gom = root.path(r"Software\GRETECH\GomPlayer")
    gom.path("RecentFile").value("Recent1", REG_SZ, sz(r"H:\gom\clip.wmv"))
    # Layout seen on a real NTUSER (values synthetic): hashed recent list + resume position, recent folder.
    gom.path("OPTION").value("_RECENTMEDIANAME000", REG_SZ, sz("0123456789ABCDEF0123456789ABCDEF")).value(
        "_RECENTMEDIAPOS000", REG_DWORD, dword(3236)
    ).value("sRecentFolder", REG_SZ, sz("J:\\export\\cctv\\")).value("sRecentURL", REG_SZ, sz(""))
    root.path(r"Software\KMPlayer\KMP4.0\OptionArea").value("LastPlayFile", REG_SZ, sz(r"I:\km\clip.flv"))
    return HiveWriter().build(root)


# --- Phone Link -------------------------------------------------------------------------------------

PHONE_LINK_PACKAGE = ("AppData", "Local", "Packages", "Microsoft.YourPhone_8wekyb3d8bbwe", "LocalCache", "Indexed")
DEVICE_A = "{AAAAAAAA-1111-2222-3333-444444444444}"
DEVICE_B = "{BBBBBBBB-1111-2222-3333-444444444444}"


def phone_link_device_a(user_home: Path) -> Path:
    database = user_home.joinpath(*PHONE_LINK_PACKAGE, DEVICE_A, "System", "Database")
    ft = filetime(MESSAGE_TIME)
    sqlite_db(
        database / "phone.db",
        """
        CREATE TABLE conversation (thread_id INTEGER, recipient_list TEXT, summary TEXT, msg_count INTEGER);
        CREATE TABLE message (message_id INTEGER, thread_id INTEGER, from_address TEXT, body TEXT, status INTEGER,
                              type INTEGER, timestamp INTEGER, read INTEGER);
        CREATE TABLE mms (message_id INTEGER, thread_id INTEGER, msg_box INTEGER, timestamp INTEGER, subject TEXT);
        CREATE TABLE mms_part (message_id INTEGER, content_type TEXT, text TEXT, name TEXT);
        """,
        {
            "conversation": [(7, "010-0000-1111", "내일 봐요", 3)],
            "message": [
                (1, 7, "010-0000-1111", "내일 3시에 만나요", 0, 1, ft, 1),
                (2, 7, "", "알겠어요", 0, 2, ft + 600_000_000, 1),
            ],
            "mms": [(3, 7, 1, ft + 1_200_000_000, "")],
            "mms_part": [(3, "text/plain", "사진 보냄", None), (3, "image/jpeg", None, "IMG_0001.jpg")],
        },
    )
    sqlite_db(
        database / "calling.db",
        "CREATE TABLE call_history (phone_number TEXT, display_name TEXT, call_type INTEGER, duration INTEGER, start_time INTEGER);",
        {"call_history": [("010-0000-2222", "김철수", 3, 0, unix_ms(MESSAGE_TIME)), ("010-0000-1111", "", 2, 95, unix_ms(MESSAGE_TIME) + 60_000)]},
    )
    sqlite_db(
        database / "contacts.db",
        """
        CREATE TABLE contact (contact_id INTEGER, display_name TEXT);
        CREATE TABLE phonenumber (contact_id INTEGER, phone_number TEXT, display_phone_number TEXT);
        CREATE TABLE emailaddress (contact_id INTEGER, address TEXT);
        """,
        {"contact": [(11, "김철수")], "phonenumber": [(11, "01000002222", "010-0000-2222")], "emailaddress": [(11, "chulsoo@example.com")]},
    )
    sqlite_db(
        database / "photos.db",
        "CREATE TABLE photo (photo_id INTEGER, name TEXT, taken_time INTEGER, last_updated_time INTEGER, size INTEGER, uri TEXT, mime_type TEXT);",
        {"photo": [(5, "IMG_0001.jpg", unix_ms(MESSAGE_TIME), unix_ms(MESSAGE_TIME) + 1000, 123456,
                    "content://media/external/images/media/5", "image/jpeg")]},
    )
    sqlite_db(
        database / "settings.db",
        "CREATE TABLE device_info (device_name TEXT, model TEXT, manufacturer TEXT);",
        {"device_info": [("Alice의 Galaxy", "SM-S000", "samsung")]},
    )
    return database


def phone_link_device_b(user_home: Path) -> Path:
    """Variant schema (renamed columns, Unix seconds) plus one damaged database."""
    database = user_home.joinpath(*PHONE_LINK_PACKAGE, DEVICE_B, "System", "Database")
    sqlite_db(
        database / "phone.db",
        "CREATE TABLE messages (id INTEGER, conversation_id INTEGER, address TEXT, text TEXT, msg_box INTEGER, date INTEGER);",
        {"messages": [(1, 9, "010-0000-3333", "variant schema row", 2, int(MESSAGE_TIME.timestamp()))]},
    )
    write(database / "calling.db", b"SQLite format 3\x00" + b"\xde\xad" * 600)
    return database


# --- desktop messengers -------------------------------------------------------------------------------


def viber(user_home: Path, number: str = "821000000000") -> Path:
    db = user_home / "AppData" / "Roaming" / "ViberPC" / number / "viber.db"
    sqlite_db(
        db,
        """
        CREATE TABLE Events (EventID INTEGER, TimeStamp INTEGER, Direction INTEGER, Type INTEGER, ContactID INTEGER, ChatID INTEGER);
        CREATE TABLE Messages (EventID INTEGER, Type INTEGER, Body TEXT, PayloadPath TEXT);
        CREATE TABLE Contact (ContactID INTEGER, Name TEXT, ClientName TEXT, Number TEXT);
        CREATE TABLE ChatInfo (ChatID INTEGER, Name TEXT);
        """,
        {
            "Events": [
                (100, unix_ms(MESSAGE_TIME), 0, 1, 1, 50),
                (101, unix_ms(MESSAGE_TIME) + 5000, 1, 1, 1, 50),
                (102, unix_ms(MESSAGE_TIME) + 9000, 0, 2, 1, 50),
                (103, unix_ms(MESSAGE_TIME) + 9500, 0, 9, 1, 50),
            ],
            "Messages": [
                (100, 1, "hello from viber", None),
                (101, 1, "reply from owner", None),
                (102, 2, "", r"C:\Users\alice\Documents\ViberDownloads\photo_1.jpg"),
            ],
            "Contact": [(1, "Bob Example", "", "+821000000001")],
            "ChatInfo": [(50, "Bob chat")],
        },
    )
    return db


def facebook_messenger(user_home: Path, *, known_schema: bool = True) -> Path:
    local = user_home.joinpath("AppData", "Local", "Packages", "FacebookInc.Messenger_8xx8rvfyw5nnt", "LocalState")
    if known_schema:
        return sqlite_db(
            local / "msys_100000000000001.db",
            """
            CREATE TABLE messages (message_id TEXT, thread_key INTEGER, sender_id INTEGER, text TEXT, timestamp_ms INTEGER);
            CREATE TABLE contacts (id INTEGER, name TEXT);
            CREATE TABLE threads (thread_key INTEGER, thread_name TEXT);
            """,
            {
                "messages": [("mid.1", 77, 9001, "fb desktop hello", unix_ms(MESSAGE_TIME))],
                "contacts": [(9001, "Carol Example")],
                "threads": [(77, "Carol thread")],
            },
        )
    return sqlite_db(local / "msys_100000000000002.db", "CREATE TABLE secure_message_store (blob BLOB);", {"secure_message_store": [(b"\x00\x01",)]})


def signal(user_home: Path) -> Path:
    root = user_home / "AppData" / "Roaming" / "Signal"
    write(root / "config.json", '{"key": "' + SECRET_SIGNAL + '", "encryptedKey": "' + SECRET_SIGNAL + '"}')
    write(root / "sql" / "db.sqlite", b"\x8a\x11\x93" * 400)  # SQLCipher: no plaintext header
    write(root / "attachments.noindex" / "ab" / "ab12cd34", b"\x00" * 64)
    return root


def qq(user_home: Path) -> Path:
    root = user_home / "Documents" / "Tencent Files" / "123456789"
    write(root / "Msg3.0.db", b"\x91\x02" * 300)
    write(root / "nt_qq" / "nt_db" / "nt_msg.db", b"SQLite header encrypted?" + b"\x00" * 64)
    write(root / "FileRecv" / "contract.pdf", b"%PDF-1.4 synthetic")
    return root


# --- mail clients -------------------------------------------------------------------------------------

THUNDERBIRD_PROFILE = "abcd1234.default-release"


def _message(subject: str, message_id: str, *, status: str = "0001", body: str = "본문입니다", attachment: bool = False,
             date: str = "Mon, 06 May 2024 07:08:09 +0000", sender: str = "Bob <bob@example.org>") -> bytes:
    headers = (
        f"X-Mozilla-Status: {status}\nX-Mozilla-Status2: 00000000\nMessage-ID: <{message_id}>\nDate: {date}\n"
        f"From: {sender}\nTo: Alice <alice@example.com>\nSubject: {subject}\nMIME-Version: 1.0\n"
    )
    if not attachment:
        return (headers + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n" + body + "\n").encode()
    return (
        headers
        + 'Content-Type: multipart/mixed; boundary="b1"\n\n--b1\nContent-Type: text/plain; charset=utf-8\n\n'
        + body
        + '\n--b1\nContent-Type: application/pdf\nContent-Disposition: attachment; filename="plan.pdf"\n'
        + "Content-Transfer-Encoding: base64\n\nJVBERi0xLjQ=\n--b1--\n"
    ).encode()


def mbox(*messages: bytes) -> bytes:
    out = b""
    for message in messages:
        out += b"From - Mon May 06 07:08:09 2024\n" + message + b"\n"
    return out


def thunderbird(user_home: Path) -> Path:
    profile = user_home / "AppData" / "Roaming" / "Thunderbird" / "Profiles" / THUNDERBIRD_PROFILE
    write(profile / "compatibility.ini", "[Compatibility]\nLastVersion=115.10.1_20240101000000/20240101000000\n")
    write(
        profile / "prefs.js",
        "// Mozilla User Preferences\n"
        'user_pref("mail.account.account1.identities", "id1");\n'
        'user_pref("mail.account.account1.server", "server1");\n'
        'user_pref("mail.account.account2.server", "server2");\n'
        'user_pref("mail.identity.id1.fullName", "Alice Example");\n'
        'user_pref("mail.identity.id1.useremail", "alice@example.com");\n'
        'user_pref("mail.identity.id1.smtpServer", "smtp1");\n'
        'user_pref("mail.server.server1.directory-rel", "[ProfD]ImapMail/imap.example.com");\n'
        'user_pref("mail.server.server1.hostname", "imap.example.com");\n'
        'user_pref("mail.server.server1.type", "imap");\n'
        'user_pref("mail.server.server1.userName", "alice@example.com");\n'
        f'user_pref("mail.server.server1.password", "{SECRET_LOGINS}");\n'
        'user_pref("mail.server.server2.directory-rel", "[ProfD]Mail/Local Folders");\n'
        'user_pref("mail.server.server2.hostname", "Local Folders");\n'
        'user_pref("mail.server.server2.type", "none");\n'
        'user_pref("mail.smtpserver.smtp1.hostname", "smtp.example.com");\n'
        'user_pref("browser.startup.homepage", "about:blank");\n',
    )
    imap = profile / "ImapMail" / "imap.example.com"
    write(imap / "INBOX", mbox(
        _message("견적서 송부", "m1@example.org", attachment=True),
        _message("From line inside", "m2@example.org", body="Hello\nFrom the body line (not a separator)\nbye"),
    ))
    write(imap / "INBOX.msf", "// <!-- <mdb:mork:z v=\"1.4\"/> -->")
    write(imap / "INBOX.sbd" / "Projects", mbox(_message("하위 폴더 메일", "m3@example.org")))
    write(imap / "INBOX.sbd" / "Projects.msf", "msf")
    local = profile / "Mail" / "Local Folders"
    write(local / "Trash", mbox(_message("지운 메일", "m4@example.org", status="0009")))
    write(local / "Trash.msf", "msf")
    write(local / "msgFilterRules.dat", "version=\"9\"\n")
    write(profile / "logins.json", '{"logins":[{"encryptedPassword":"' + SECRET_LOGINS + '"}]}')
    write(profile / "key4.db", b"SQLite format 3\x00" + SECRET_KEY4 + b"\x00" * 64)
    sqlite_db(
        profile / "global-messages-db.sqlite",
        """
        CREATE TABLE folderLocations (id INTEGER, folderURI TEXT, dirtyStatus INTEGER, name TEXT, indexingPriority INTEGER);
        CREATE TABLE messages (id INTEGER, folderID INTEGER, messageKey INTEGER, conversationID INTEGER, date INTEGER,
                               headerMessageID TEXT, deleted INTEGER, jsonAttributes TEXT, notability INTEGER);
        CREATE TABLE messagesText_content (docid INTEGER, c0body TEXT, c1subject TEXT, c2attachmentNames TEXT, c3author TEXT, c4recipients TEXT);
        CREATE TABLE contacts (id INTEGER, directoryUUID TEXT, contactUUID TEXT, popularity INTEGER, frecency INTEGER, name TEXT, jsonAttributes TEXT);
        CREATE TABLE identities (id INTEGER, contactID INTEGER, kind TEXT, value TEXT, description TEXT, relay INTEGER);
        """,
        {
            "folderLocations": [(1, "imap://alice@imap.example.com/INBOX", 0, "INBOX", 0)],
            "messages": [
                (1, 1, 10, 1, int(MESSAGE_TIME.timestamp() * 1_000_000), "m1@example.org", 0, "{}", 0),
                (2, 1, 11, 2, int(MESSAGE_TIME.timestamp() * 1_000_000), "gone@example.org", 0, "{}", 0),
            ],
            "messagesText_content": [
                (1, "matched body", "견적서 송부", "", "bob@example.org", "alice@example.com"),
                (2, "only in the index", "삭제된 메일 제목", "old.xlsx", "dave@example.org", "alice@example.com"),
            ],
            "contacts": [(1, None, None, 10, 10, "Dave Example", "{}")],
            "identities": [(1, 1, "email", "dave@example.org", None, 0)],
        },
    )
    sqlite_db(
        profile / "abook.sqlite",
        "CREATE TABLE properties (card TEXT, name TEXT, value TEXT);",
        {"properties": [("c1", "DisplayName", "Erin Example"), ("c1", "PrimaryEmail", "erin@example.com"),
                        ("c1", "CellularNumber", "010-0000-4444"), ("c1", "Company", "Example Co")]},
    )
    start = int(datetime(2024, 6, 1, 1, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)
    sqlite_db(
        profile / "calendar-data" / "local.sqlite",
        """
        CREATE TABLE cal_events (cal_id TEXT, id TEXT, time_created INTEGER, last_modified INTEGER, title TEXT, priority INTEGER,
                                 privacy TEXT, ical_status TEXT, flags INTEGER, event_start INTEGER, event_end INTEGER,
                                 event_stamp INTEGER, event_start_tz TEXT, event_end_tz TEXT, recurrence_id INTEGER);
        CREATE TABLE cal_properties (item_id TEXT, key TEXT, value TEXT, recurrence_id INTEGER, cal_id TEXT);
        CREATE TABLE cal_attendees (item_id TEXT, icalString TEXT, recurrence_id INTEGER, cal_id TEXT);
        """,
        {
            "cal_events": [("cal-1", "evt-1", start, start, "거래처 미팅", 0, None, "CONFIRMED", 0, start, start + 3_600_000_000,
                            start, "Asia/Seoul", "Asia/Seoul", None)],
            "cal_properties": [("evt-1", "LOCATION", "강남역 카페", None, "cal-1")],
            "cal_attendees": [("evt-1", "ATTENDEE;CN=Bob:mailto:bob@example.org", None, "cal-1")],
        },
    )
    return profile


def windows_mail(user_home: Path) -> Path:
    livecomm = user_home.joinpath("AppData", "Local", "Packages", "microsoft.windowscommunicationsapps_8wekyb3d8bbwe",
                                  "LocalState", "Indexed", "LiveComm")
    account = livecomm / "a1b2c3d4e5f60708" / "120712-0049"
    write(account / "Mail" / "0001.eml", _message("윈도우 메일", "wm1@example.org").replace(b"X-Mozilla-Status: 0001\n", b""))
    write(account / "Att" / "plan.pdf", b"%PDF-1.4")
    # ESE-shaped header (signature at offset 4) and UTF-16 address strings; not a decodable database.
    store = b"\x00" * 4 + bytes.fromhex("efcdab89") + b"\x00" * 248 + "owner@example.com".encode("utf-16-le") + b"\x00" * 64
    write(account / "store.vol", store + b"peer@example.org\x00")
    return livecomm


def live_mail(user_home: Path) -> Path:
    root = user_home / "AppData" / "Local" / "Microsoft" / "Windows Live Mail"
    account = root / "imap.example.net (alice)"
    write(
        account / "account{0A1B2C3D-0000-1111-2222-333344445555}.oeaccount",
        '<?xml version="1.0" encoding="utf-8"?>\n<MessageAccount>\n'
        '<Account_Name type="SZ">imap.example.net</Account_Name>\n'
        '<IMAP_Server type="SZ">imap.example.net</IMAP_Server>\n'
        '<IMAP_User_Name type="SZ">alice</IMAP_User_Name>\n'
        f'<IMAP_Password2 type="BINARY">{SECRET_LIVE_MAIL}</IMAP_Password2>\n'
        '<SMTP_Email_Address type="SZ">alice@example.net</SMTP_Email_Address>\n'
        '<SMTP_Server type="SZ">smtp.example.net</SMTP_Server>\n</MessageAccount>\n',
    )
    write(account / "Inbox" / "msg1.eml", _message("라이브 메일", "lm1@example.net").replace(b"X-Mozilla-Status: 0001\n", b""))
    return root


# --- PSD ------------------------------------------------------------------------------------------

PSD_XMP = """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
 xmlns:stEvt="http://ns.adobe.com/xap/1.0/sType/ResourceEvent#" xmlns:photoshop="http://ns.adobe.com/photoshop/1.0/"
 xmp:CreatorTool="Adobe Photoshop 25.0 (Windows)" xmp:CreateDate="2024-05-01T10:00:00+09:00"
 xmp:ModifyDate="2024-05-02T11:30:00+09:00" xmpMM:DocumentID="adobe:docid:photoshop:11111111"
 xmpMM:OriginalDocumentID="xmp.did:22222222" xmpMM:InstanceID="xmp.iid:33333333">
<xmpMM:History><rdf:Seq>
<rdf:li stEvt:action="created" stEvt:when="2024-05-01T10:00:00+09:00" stEvt:softwareAgent="Adobe Photoshop 25.0 (Windows)"/>
<rdf:li><stEvt:action>saved</stEvt:action><stEvt:when>2024-05-02T11:30:00+09:00</stEvt:when>
<stEvt:softwareAgent>Adobe Photoshop 25.0 (Windows)</stEvt:softwareAgent><stEvt:changed>/</stEvt:changed></rdf:li>
</rdf:Seq></xmpMM:History>
<photoshop:DocumentAncestors><rdf:Bag><rdf:li>xmp.did:aaaa</rdf:li><rdf:li>adobe:docid:photoshop:bbbb</rdf:li></rdf:Bag></photoshop:DocumentAncestors>
</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>"""
THUMB_JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x11" * 40 + b"\xff\xd9"


def _resource(resource_id: int, data: bytes) -> bytes:
    block = b"8BIM" + struct.pack(">H", resource_id) + b"\x00\x00" + struct.pack(">I", len(data)) + data
    return block + (b"\x00" if len(data) % 2 else b"")


def psd_bytes(*, width: int = 640, height: int = 480, xmp: str = PSD_XMP, thumbnail: bytes | None = THUMB_JPEG) -> bytes:
    header = b"8BPS" + struct.pack(">H6xHIIHH", 1, 3, height, width, 8, 3)
    resources = _resource(0x03ED, b"\x00" * 16) + _resource(0x0424, xmp.encode("utf-8"))
    if thumbnail is not None:
        resources += _resource(0x040C, struct.pack(">IIIIIIHH", 1, 160, 120, 480, 57600, len(thumbnail), 24, 1) + thumbnail)
    return header + struct.pack(">I", 0) + struct.pack(">I", len(resources)) + resources + struct.pack(">I", 0) + b"\x00\x00" + b"\x00" * 32
