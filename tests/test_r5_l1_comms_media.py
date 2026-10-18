"""R5 L1 — communication and media apps (plan r5-residual §3 L1; re-audit §3 items 2, 3, 11, 12, 13, 26, 27).

Synthetic fixtures only (``tests/r5_l1_fixtures.py``). Covers the media-player,
windows-phone-link and email-clients providers, the Viber / Facebook Messenger /
Signal / QQ additions to windows-messenger, PSD metadata in media-image, corrupt
input isolation, caps, the no-secret-extraction guarantee (Q-R5-2), catalogue /
domain mapping (Q-R5-3) and that runs schedule the new kinds.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts import artifact_collectors
from rapidtriage.artifacts import email_clients as email_clients_module
from rapidtriage.artifacts.email import EmailArtifactsProvider
from rapidtriage.artifacts.email_clients import (
    EmailClientsProvider,
    client_mail_path_filter,
    iter_mbox_messages,
    parse_prefs_js,
    prtime_iso,
)
from rapidtriage.artifacts.media import (
    build_image_record,
    psd_structure,
    sniff_image_format,
)
from rapidtriage.artifacts.windows import media_players as media_players_module
from rapidtriage.artifacts.windows.media_players import (
    WindowsMediaPlayersProvider,
    media_location,
    qt_string_list,
)
from rapidtriage.artifacts.windows.messenger import WindowsMessengerProvider
from rapidtriage.artifacts.windows.phone_link import (
    WindowsPhoneLinkProvider,
    decode_phone_time,
)
from rapidtriage.core.artifact_domains import artifact_type_domain
from rapidtriage.core.run import RUN_PROFILES
from rapidtriage.core.triage_rules.catalog import load_catalog
from tests import r5_l1_fixtures as fx

NEW_TYPES = {
    "media-player": ("media-player-recent", "media-player-inventory", "media-player-parse-error"),
    "windows-phone-link": (
        "phone-link-message",
        "phone-link-call",
        "phone-link-contact",
        "phone-link-photo",
        "phone-link-device",
        "phone-link-parse-error",
    ),
    "email-clients": ("email-client-account", "email-client-profile", "email-client-store", "email-client-parse-error"),
}


def rows_of(provider: object, root: Path) -> list[dict[str, object]]:
    return [record.to_dict() for record in provider.collect(root)]  # type: ignore[attr-defined]


def of_type(rows: list[dict[str, object]], artifact_type: str) -> list[dict[str, object]]:
    return [row["details"] for row in rows if row["artifact_type"] == artifact_type]  # type: ignore[misc]


def assert_provenance(case: unittest.TestCase, details: dict[str, object]) -> None:
    for key in ("recovery_method", "parser_version", "source_path"):
        case.assertTrue(details.get(key), f"{key} missing: {sorted(details)[:20]}")


class MediaPlayerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = fx.home(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_qt_list_and_locations(self) -> None:
        self.assertEqual(qt_string_list('a, "b, c", d'), ["a", "b, c", "d"])
        self.assertEqual(media_location("file:///E:/%EC%98%81%EC%83%81/a.mp4")["media_path"], "E:\\영상\\a.mp4")  # type: ignore[index]
        unc = media_location("file://nas01/share/m.avi")
        self.assertEqual((unc or {}).get("location_kind"), "unc-network")
        self.assertEqual((unc or {}).get("network_host"), "nas01")
        self.assertEqual((media_location("rtsp://cam.example.com/live") or {}).get("location_kind"), "stream-url")
        self.assertIsNone(media_location("not a path"))
        self.assertTrue((media_location("prefix D:\\x\\y.mp4") or {}).get("extracted_from_value"))

    def test_vlc_potplayer_gom_kmplayer_rows(self) -> None:
        fx.vlc_files(self.home)
        fx.potplayer_files(self.home)
        (self.home / "NTUSER.DAT").write_bytes(fx.ntuser_media_hive())
        rows = rows_of(WindowsMediaPlayersProvider(), self.root)
        recent = of_type(rows, "media-player-recent")
        by_player = Counter(str(item["player_id"]) for item in recent)
        self.assertEqual(by_player, Counter({"vlc": 4, "potplayer": 7, "gom": 3, "kmplayer": 1}))
        gom_hash = next(item for item in recent if item.get("extraction") == "gom-recentmedia-hash")
        self.assertEqual((gom_hash["media_hash"], gom_hash["resume_position_raw"], gom_hash["mru_order"]),
                         ("0123456789abcdef0123456789abcdef", 3236, 0))
        self.assertEqual((gom_hash["media_path"], gom_hash["location_kind"], gom_hash["product_key"]), ("", "hash-only", "GomPlayer"))
        folder = next(item for item in recent if item.get("registry_value_name") == "sRecentFolder")
        self.assertEqual((folder["entry_kind"], folder["drive_letter"]), ("folder", "J"))
        vlc = [item for item in recent if item["player_id"] == "vlc"]
        self.assertEqual(vlc[0]["media_path"], "E:\\영상\\clip01.mp4")
        self.assertEqual(vlc[0]["drive_letter"], "E")
        self.assertEqual(vlc[1]["media_path"], "C:\\Users\\alice\\Videos\\a, b.mkv")
        self.assertEqual(vlc[1]["resume_position_seconds"], 125.0)
        self.assertEqual(vlc[2]["location_kind"], "stream-url")
        self.assertEqual(vlc[0]["verification"], "public-source-documented")
        paths = {str(item.get("media_path") or item.get("media_url")) for item in recent}
        self.assertIn("F:\\backup\\secret_video.mp4", paths)  # [Settings] LastPlayFile
        self.assertNotIn("C:\\Program Files\\DAUM\\PotPlayer\\Skins\\x.dsf", paths)  # not a recent value
        self.assertNotIn("C:\\skins\\a.dsf", paths)
        self.assertIn("G:\\캠코더\\영상1.mp4", paths)
        registry = [item for item in recent if item["recovery_method"] == "registry-value"]
        self.assertTrue(all(item["list_last_written_source"] == "registry-key-last-written" for item in registry))
        self.assertTrue(all(item["verification"] == "unconfirmed" and item["confidence"] == "low" for item in registry))
        self.assertTrue(all(item["timestamp"] == "" for item in recent))  # the list time is never a per-entry time
        playlist = [item for item in recent if item["source_format"] == "potplayer-dpl"]
        self.assertEqual(len(playlist), 2)
        self.assertTrue(playlist[0].get("playlist_current_item"))
        inventory = {item["player_id"]: item for item in of_type(rows, "media-player-inventory")}
        self.assertEqual(inventory["vlc"]["snapshot_path"], "D:\\Snaps")
        self.assertEqual(inventory["vlc"]["record_path"], "D:\\Rec")
        for item in recent:
            assert_provenance(self, item)

    def test_corrupt_hive_is_isolated_and_vlc_still_read(self) -> None:
        fx.vlc_files(self.home)
        (self.home / "NTUSER.DAT").write_bytes(b"not a hive" * 50)
        (self.home / "AppData" / "Roaming" / "PotPlayerMini64").mkdir(parents=True)
        (self.home / "AppData" / "Roaming" / "PotPlayerMini64" / "PotPlayerMini64.ini").write_bytes(b"\x00\xff\xfe\x81" * 100)
        rows = rows_of(WindowsMediaPlayersProvider(), self.root)
        self.assertEqual(len(of_type(rows, "media-player-parse-error")), 1)
        self.assertEqual(len([item for item in of_type(rows, "media-player-recent") if item["player_id"] == "vlc"]), 4)

    def test_row_cap(self) -> None:
        fx.vlc_files(self.home)
        with mock.patch.object(media_players_module, "MAX_ROWS_PER_PLAYER", 2):
            provider = WindowsMediaPlayersProvider()
            rows = rows_of(provider, self.root)
        self.assertEqual(len(of_type(rows, "media-player-recent")), 2)
        self.assertIn("row-cap", of_type(rows, "media-player-inventory")[0]["caps_hit"])  # type: ignore[operator]
        self.assertTrue(any("상한" in note for note in provider.collection_notes))

    def test_nothing_found_note(self) -> None:
        provider = WindowsMediaPlayersProvider()
        self.assertEqual(rows_of(provider, self.root), [])
        self.assertTrue(provider.collection_notes)


class PhoneLinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = fx.home(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_time_decoding(self) -> None:
        expected = "2024-05-06T07:08:09+00:00"
        self.assertEqual(decode_phone_time(fx.filetime(fx.MESSAGE_TIME)), (expected, "windows-filetime"))
        self.assertEqual(decode_phone_time(fx.unix_ms(fx.MESSAGE_TIME)), (expected, "unix-ms"))
        self.assertEqual(decode_phone_time(int(fx.MESSAGE_TIME.timestamp())), (expected, "unix-s"))
        self.assertEqual(decode_phone_time(str(fx.unix_ms(fx.MESSAGE_TIME) * 1000)), (expected, "unix-us"))
        self.assertEqual(decode_phone_time("2024-05-06T16:08:09+09:00"), (expected, "iso-8601"))
        self.assertEqual(decode_phone_time("2024-05-06 16:08:09"), ("", ""))  # no offset: never an instant
        self.assertEqual(decode_phone_time(12), ("", ""))

    def test_rows_across_schema_variants_and_corrupt_db(self) -> None:
        fx.phone_link_device_a(self.home)
        fx.phone_link_device_b(self.home)
        rows = rows_of(WindowsPhoneLinkProvider(), self.root)
        messages = of_type(rows, "phone-link-message")
        self.assertEqual(len(messages), 4)
        first = next(item for item in messages if item["message_id"] == "1")
        self.assertEqual(first["direction"], "incoming")
        self.assertEqual(first["sender"], "010-0000-1111")
        self.assertEqual(first["timestamp"], "2024-05-06T07:08:09+00:00")
        self.assertEqual(first["timestamp_encoding"], "windows-filetime")
        self.assertEqual(first["timestamp_kind"], "message")
        self.assertEqual(first["read_state"], "읽음")
        mms = next(item for item in messages if item["message_kind"] == "mms")
        self.assertEqual(mms["message_text"], "사진 보냄")
        self.assertEqual(mms["attachments"], ["IMG_0001.jpg"])
        variant = next(item for item in messages if item["device_id"] == fx.DEVICE_B)
        self.assertEqual((variant["direction"], variant["recipient"], variant["timestamp_encoding"]), ("outgoing", "010-0000-3333", "unix-s"))
        calls = of_type(rows, "phone-link-call")
        self.assertEqual({item["call_type"] for item in calls}, {"부재중", "발신"})
        self.assertEqual(next(item for item in calls if item["call_type"] == "발신")["duration_seconds"], 95)
        contact = of_type(rows, "phone-link-contact")[0]
        self.assertEqual((contact["contact_name"], contact["phone"], contact["email"]), ("김철수", "010-0000-2222", "chulsoo@example.com"))
        photo = of_type(rows, "phone-link-photo")[0]
        self.assertEqual((photo["file_name"], photo["timestamp_kind"], photo["file_size"]), ("IMG_0001.jpg", "photo-taken", 123456))
        devices = {item["device_id"]: item for item in of_type(rows, "phone-link-device")}
        self.assertEqual(devices[fx.DEVICE_A]["device_name"], "Alice의 Galaxy")
        self.assertEqual(devices[fx.DEVICE_A]["message_rows"], 3)
        errors = of_type(rows, "phone-link-parse-error")
        self.assertEqual(len(errors), 1)
        self.assertTrue(str(errors[0]["source_path"]).endswith("calling.db"))
        self.assertEqual(devices[fx.DEVICE_B]["parse_error_count"], 1)
        for item in messages + calls + [contact, photo]:
            assert_provenance(self, item)

    def test_empty_device_folder_is_inventory_only(self) -> None:
        self.home.joinpath(*fx.PHONE_LINK_PACKAGE, "{EMPTY}").mkdir(parents=True)
        rows = rows_of(WindowsPhoneLinkProvider(), self.root)
        self.assertEqual([row["artifact_type"] for row in rows], ["phone-link-device"])
        self.assertEqual(rows[0]["details"]["coverage_status"], "inventory-only")  # type: ignore[index]
        self.assertTrue(rows[0]["details"]["reason_ko"])  # type: ignore[index]


class MessengerAdditionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = fx.home(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def collect(self) -> list[dict[str, object]]:
        return rows_of(WindowsMessengerProvider(), self.root)

    def test_viber_join(self) -> None:
        fx.viber(self.home)
        rows = [row for row in self.collect() if row["details"]["app_id"] == "viber"]  # type: ignore[index]
        messages = of_type(rows, "chat-message")
        self.assertEqual(len(messages), 2)
        incoming = next(item for item in messages if item["message_text"] == "hello from viber")
        self.assertEqual((incoming["direction"], incoming["sender"], incoming["recipient"]), ("incoming", "Bob Example", "821000000000"))
        self.assertEqual(incoming["conversation_title"], "Bob chat")
        self.assertEqual(incoming["viber_direction_raw"], 0)
        outgoing = next(item for item in messages if item["message_text"] == "reply from owner")
        self.assertEqual(outgoing["direction"], "outgoing")
        attachment = of_type(rows, "chat-attachment")[0]
        self.assertEqual(attachment["file_name"], "photo_1.jpg")
        self.assertEqual(of_type(rows, "chat-contact")[0]["phone"], "+821000000001")
        inventory = of_type(rows, "chat-app-inventory")[0]
        self.assertFalse(inventory["inventory_only"])
        self.assertEqual(inventory["stores"][0]["mapper"], "viber")  # type: ignore[index]

    def test_facebook_messenger_best_effort(self) -> None:
        fx.facebook_messenger(self.home)
        fx.facebook_messenger(self.home, known_schema=False)
        rows = [row for row in self.collect() if row["details"]["app_id"] == "facebook-messenger"]  # type: ignore[index]
        message = of_type(rows, "chat-message")[0]
        self.assertEqual((message["sender"], message["conversation_title"]), ("Carol Example", "Carol thread"))
        self.assertEqual(message["schema_confidence"], "best-effort-msys")
        self.assertEqual(len(of_type(rows, "chat-app-inventory")), 1)

    def test_facebook_unknown_schema_is_inventory(self) -> None:
        fx.facebook_messenger(self.home, known_schema=False)
        rows = [row for row in self.collect() if row["details"]["app_id"] == "facebook-messenger"]  # type: ignore[index]
        inventory = of_type(rows, "chat-app-inventory")[0]
        self.assertTrue(inventory["inventory_only"])
        self.assertIn("최선 노력", str(inventory["reason_ko"]))

    def test_signal_and_qq_inventory_only_without_secrets(self) -> None:
        fx.signal(self.home)
        fx.qq(self.home)
        rows = self.collect()
        signal = next(item for item in of_type(rows, "chat-app-inventory") if item["app_id"] == "signal")
        self.assertTrue(signal["inventory_only"])
        self.assertIn("config.json", str(signal["reason_ko"]))
        key_file = signal["key_material_files"][0]  # type: ignore[index]
        self.assertEqual((key_file["name"], key_file["present"], key_file["content_read"]), ("config.json", True, False))
        self.assertEqual(of_type([row for row in rows if row["details"]["app_id"] == "signal"], "chat-message"), [])  # type: ignore[index]
        qq = next(item for item in of_type(rows, "chat-app-inventory") if item["app_id"] == "qq")
        self.assertTrue(qq["inventory_only"])
        self.assertEqual(qq["encrypted_store_count"], 2)
        received = [item for item in of_type(rows, "chat-attachment") if item["app_id"] == "qq"]
        self.assertEqual([item["file_name"] for item in received], ["contract.pdf"])
        dump = json.dumps(rows, ensure_ascii=False, default=str)
        self.assertNotIn(fx.SECRET_SIGNAL, dump)


class EmailClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = fx.home(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_mbox_stream_and_prefs(self) -> None:
        path = fx.write(self.root / "mbox", fx.mbox(fx._message("a", "a@x"), fx._message("b", "b@x", body="x\nFrom inside\ny")))
        messages = list(iter_mbox_messages(path, read_limit=1 << 20))
        self.assertEqual(len(messages), 2)
        self.assertIn(b"From inside", messages[1][1])
        self.assertEqual(len(list(iter_mbox_messages(path, read_limit=40))), 1)  # bounded read
        prefs = parse_prefs_js('user_pref("mail.server.server1.password", "x");\nuser_pref("mail.identity.id1.useremail", "a@b.c");\n')
        self.assertEqual(prefs, {"mail.identity.id1.useremail": "a@b.c"})
        self.assertEqual(prtime_iso(1_714_979_289_000_000), "2024-05-06T07:08:09Z")

    def test_thunderbird_profile(self) -> None:
        fx.thunderbird(self.home)
        rows = rows_of(EmailClientsProvider(), self.root)
        messages = of_type(rows, "email-message")
        by_subject = {item["subject"]: item for item in messages}
        self.assertEqual(set(by_subject), {"견적서 송부", "From line inside", "하위 폴더 메일", "지운 메일", "삭제된 메일 제목"})
        inbox = by_subject["견적서 송부"]
        self.assertEqual((inbox["mail_client"], inbox["account"], inbox["folder"]), ("Thunderbird", "alice@example.com", "INBOX"))
        self.assertEqual(inbox["read_state"], "읽음")
        self.assertEqual(inbox["attachment_count"], 1)
        self.assertTrue(inbox["source_sha256"])
        self.assertEqual(by_subject["하위 폴더 메일"]["folder"], "INBOX/Projects")
        trash = by_subject["지운 메일"]
        self.assertEqual((trash["deleted_state"], trash["account"]), ("deleted-or-recovered-candidate", "Local Folders"))
        self.assertIn("expunged", trash["mozilla_flags"])  # type: ignore[operator]
        index_only = by_subject["삭제된 메일 제목"]
        self.assertEqual((index_only["deleted_state"], index_only["source_format"]), ("index-only", "thunderbird-gloda"))
        attachments = of_type(rows, "email-attachment")
        self.assertEqual([item["filename"] for item in attachments], ["plan.pdf"])
        contacts = {item["display_name"]: item for item in of_type(rows, "contact")}
        self.assertEqual(contacts["Erin Example"]["email"], "erin@example.com")
        self.assertEqual(contacts["Erin Example"]["phone"], "010-0000-4444")
        self.assertIn("Dave Example", contacts)
        event = of_type(rows, "calendar-event")[0]
        self.assertEqual((event["title"], event["start"], event["location"]), ("거래처 미팅", "2024-06-01T01:00:00Z", "강남역 카페"))
        self.assertEqual(event["attendees"], ["bob@example.org"])
        accounts = {item["account"]: item for item in of_type(rows, "email-client-account")}
        self.assertEqual(accounts["alice@example.com"]["smtp_hosts"], ["smtp.example.com"])
        profile = of_type(rows, "email-client-profile")[0]
        self.assertEqual(profile["client_version"], "115.10.1")
        self.assertEqual({item["name"] for item in profile["credential_store_files"]}, {"logins.json", "key4.db"})  # type: ignore[union-attr]
        self.assertEqual((profile["gloda_indexed_messages"], profile["gloda_matched_mbox"], profile["gloda_index_only_rows"]), (2, 1, 1))
        self.assertEqual(profile["mail_folder_count"], 3)
        for item in messages + attachments + list(contacts.values()) + [event]:
            assert_provenance(self, item)

    def test_windows_mail_and_live_mail(self) -> None:
        fx.windows_mail(self.home)
        fx.live_mail(self.home)
        rows = rows_of(EmailClientsProvider(), self.root)
        messages = {item["subject"]: item for item in of_type(rows, "email-message")}
        windows_mail = messages["윈도우 메일"]
        self.assertEqual((windows_mail["mail_client"], windows_mail["folder"], windows_mail["account"]), ("Windows Mail", "Mail", "a1b2c3d4e5f60708"))
        live = messages["라이브 메일"]
        self.assertEqual((live["mail_client"], live["folder"], live["account"]), ("Windows Live Mail", "Inbox", "alice@example.net"))
        store = of_type(rows, "email-client-store")[0]
        self.assertTrue(store["ese_signature_valid"])
        self.assertEqual(set(store["address_candidates"]), {"owner@example.com", "peer@example.org"})  # type: ignore[arg-type]
        account = next(item for item in of_type(rows, "email-client-account") if item["mail_client"] == "Windows Live Mail")
        self.assertEqual(account["server_hostname"], "imap.example.net")
        self.assertNotIn("IMAP_Password2", account["account_fields"])  # type: ignore[operator]

    def test_no_secret_bytes_in_any_output(self) -> None:
        fx.thunderbird(self.home)
        fx.live_mail(self.home)
        fx.signal(self.home)
        dump = ""
        for provider in (EmailClientsProvider(), EmailArtifactsProvider(), WindowsMessengerProvider()):
            dump += json.dumps(rows_of(provider, self.root), ensure_ascii=False, default=str)
        for secret in fx.SECRETS:
            self.assertNotIn(secret, dump)

    def test_generic_email_provider_skips_client_files(self) -> None:
        fx.thunderbird(self.home)
        fx.windows_mail(self.home)
        fx.live_mail(self.home)
        loose = self.root / "export" / "Inbox"
        fx.write(loose, fx.mbox(fx._message("loose", "loose@x")))
        fx.write(self.root / "export" / "Inbox.msf", "msf")
        fx.write(self.root / "export" / "plain.eml", fx._message("plain eml", "plain@x"))
        rows = rows_of(EmailArtifactsProvider(), self.root)
        subjects = sorted(str(item.get("subject")) for item in of_type(rows, "email-message"))
        self.assertEqual(subjects, ["loose", "plain eml"])
        owner = client_mail_path_filter(self.root)
        self.assertEqual(owner(self.home / "AppData" / "Local" / "Microsoft" / "Windows Live Mail" / "x" / "a.eml"), "Windows Live Mail")
        self.assertEqual(owner(self.root / "export" / "plain.eml"), "")

    def test_corrupt_gloda_and_store_isolated(self) -> None:
        profile = fx.thunderbird(self.home)
        (profile / "global-messages-db.sqlite").write_bytes(b"SQLite format 3\x00" + b"\xff" * 2000)
        (profile / "abook.sqlite").write_bytes(b"garbage")
        rows = rows_of(EmailClientsProvider(), self.root)
        errors = of_type(rows, "email-client-parse-error")
        self.assertEqual([Path(str(item["source_path"])).name for item in errors], ["global-messages-db.sqlite"])
        self.assertEqual(len(of_type(rows, "email-message")), 4)  # the mbox folders are still read

    def test_message_cap(self) -> None:
        fx.thunderbird(self.home)
        with mock.patch.object(email_clients_module, "MAX_MESSAGES_PER_ROOT", 2):
            rows = rows_of(EmailClientsProvider(), self.root)
        profile = of_type(rows, "email-client-profile")[0]
        self.assertIn("message-cap", profile["caps_hit"])  # type: ignore[operator]
        mbox_rows = [item for item in of_type(rows, "email-message") if item["source_format"] == "thunderbird-mbox"]
        self.assertEqual(len(mbox_rows), 2)


class PsdTests(unittest.TestCase):
    def test_psd_metadata_and_thumbnail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "편집본.psd"
            path.write_bytes(fx.psd_bytes())
            record = build_image_record(path)
        details = record.details
        self.assertEqual(record.artifact_type, "media-image")
        self.assertEqual((details["content_format"], details["width"], details["height"]), ("psd", 640, 480))
        self.assertEqual((details["psd_color_mode"], details["psd_bit_depth"], details["dimension_source"]), ("RGB", 8, "psd-header"))
        self.assertEqual(details["xmp_creator_tool"], "Adobe Photoshop 25.0 (Windows)")
        self.assertEqual(details["xmp_history_count"], 2)
        self.assertEqual(details["xmp_history"][1]["action"], "saved")  # type: ignore[index]
        self.assertEqual(details["xmp_history"][1]["changed"], "/")  # type: ignore[index]
        self.assertEqual(details["xmp_document_ancestor_count"], 2)
        self.assertEqual(details["xmp_original_document_id"], "xmp.did:22222222")
        thumbnail = details["thumbnail_preview"]
        self.assertTrue(thumbnail["available"])  # type: ignore[index]
        self.assertTrue(str(thumbnail["data_uri"]).startswith("data:image/jpeg;base64,"))  # type: ignore[index]
        self.assertEqual(details["coverage_status"], "container-metadata-only")

    def test_truncated_and_oversized_thumbnail(self) -> None:
        self.assertEqual(sniff_image_format(b"8BPS\x00\x01" + b"\x00" * 20), "psd")
        data = fx.psd_bytes()
        self.assertEqual(psd_structure(data[:20])["status"], "truncated-header")
        self.assertEqual(psd_structure(data[:200])["status"], "truncated-resources")
        big = fx.psd_bytes(thumbnail=b"\xff\xd8" + b"\x00" * (70 * 1024))
        thumbnail = psd_structure(big)["psd"]["thumbnail"]  # type: ignore[index]
        self.assertFalse(thumbnail["available"])
        self.assertEqual(thumbnail["reason"], "thumbnail-exceeds-inline-limit")


class RegistrationTests(unittest.TestCase):
    def test_catalog_domains_and_runs(self) -> None:
        catalog = load_catalog()
        collectors = artifact_collectors()
        for kind, types in NEW_TYPES.items():
            self.assertIn(kind, collectors)
            for artifact_type in types:
                self.assertIsNotNone(catalog.family_for(artifact_type, kind), artifact_type)
            for profile in ("seizure", "fraud", "hacking"):
                self.assertIn(kind, RUN_PROFILES[profile].artifacts_kinds)
        families = {family["id"]: family for family in catalog.families}
        for family_id in ("phone-link-message", "media-player", "email-client-account"):
            semantics = {column.get("semantic") for column in families[family_id]["core_columns"] + families[family_id]["aux_columns"]}
            self.assertTrue(semantics - {None}, family_id)
        self.assertEqual(catalog.family_for("email-message", "email-clients"), "email")
        self.assertEqual(artifact_type_domain("windows-phone-link", "phone-link-call"), "mobile")
        self.assertEqual(artifact_type_domain("windows-phone-link", "phone-link-message"), "messaging")
        self.assertEqual(artifact_type_domain("media-player", "media-player-recent"), "media")
        self.assertEqual(artifact_type_domain("email-clients", "email-client-account"), "messaging")

    def test_media_player_content_type_comes_from_the_played_file(self) -> None:
        from rapidtriage.api.app.row_conditions import (
            path_is_content,
            row_content_types,
        )

        self.assertFalse(path_is_content("media-player-recent"))
        row = {"artifact_type": "media-player-recent", "path": "C:/Users/a/AppData/Roaming/vlc/vlc-qt-interface.ini",
               "details": {"media_path": "E:\\clip.mkv"}}
        self.assertEqual(row_content_types(row, "artifacts"), {"video"})

    def test_sqlite_fixture_is_plain_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = fx.viber(Path(tmp))
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM Events").fetchone()[0], 4)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
