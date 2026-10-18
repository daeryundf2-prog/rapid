"""R5 adversarial-review regressions (plan r5-residual-2026-10-18 §5 "적대적 리뷰 후속 수정").

Every fixture is synthetic and generated here: no real hives, images, backups or credentials.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
import tarfile
import tempfile
import time
import tracemalloc
import unittest
import zlib
from pathlib import Path
from typing import ClassVar
from unittest import mock

from tests.test_parser_quality_registry import REG_SZ, HiveWriter, Key, sz, write_hive

OLD_PASSWORD = "OLDWINSCPPASSWORDHEX-DEADBEEF1234"
CUR_PASSWORD = "CURWINSCPPASSWORDHEX-CAFEBABE9999"


def _hive_with_deleted_password(*, current: bool) -> bytes:
    """A hive whose WinSCP session has (optionally) a current Password and a free vk ``Password`` cell
    holding an older password (what an overwritten/deleted value leaves in the hive)."""
    root = Key("ROOT")
    session = root.path(r"Software\Martin Prikryl\WinSCP 2\Sessions\a@h").value("HostName", REG_SZ, sz("h.example"))
    if current:
        session.value("Password", REG_SZ, sz(CUR_PASSWORD))
    writer = HiveWriter()
    root_offset = writer.serialize(root, 0, root=True)
    data = sz(OLD_PASSWORD)
    data_offset = writer.alloc(data, free=True)
    body = bytearray(28)
    body[0:2] = b"vk"
    body[2:4] = (8).to_bytes(2, "little")
    body[4:8] = len(data).to_bytes(4, "little")
    body[8:12] = data_offset.to_bytes(4, "little")
    body[12:16] = REG_SZ.to_bytes(4, "little")
    body[16:18] = (1).to_bytes(2, "little")  # compressed (ASCII) name
    body[20:] = b"Password"
    writer.alloc(bytes(body), free=True)
    cells = writer.cells
    hbin_size = 32 + len(cells)
    hbin_size += (-hbin_size) % 4096
    hbin = bytearray(hbin_size)
    hbin[0:4] = b"hbin"
    hbin[8:12] = hbin_size.to_bytes(4, "little")
    hbin[32 : 32 + len(cells)] = cells
    base = bytearray(4096)
    base[0:4] = b"regf"
    base[4:8] = base[8:12] = (7).to_bytes(4, "little")
    base[20:24] = (1).to_bytes(4, "little")
    base[24:28] = (5).to_bytes(4, "little")
    base[32:36] = (1).to_bytes(4, "little")
    base[36:40] = root_offset.to_bytes(4, "little")
    base[40:44] = hbin_size.to_bytes(4, "little")
    base[44:48] = (1).to_bytes(4, "little")
    checksum = 0
    for index in range(0, 508, 4):
        checksum ^= int.from_bytes(base[index : index + 4], "little")
    base[508:512] = checksum.to_bytes(4, "little")
    return bytes(base) + bytes(hbin)


class DeletedRegistrySecretTests(unittest.TestCase):
    """#1 — an old/deleted PuTTY/WinSCP password never reaches hive strings, value recovery or the summary."""

    def collect(self, *, current: bool) -> list:
        from rapidtriage.artifacts.windows.registry import WindowsRegistryProvider

        with tempfile.TemporaryDirectory() as temp:
            write_hive(Path(temp), "Users/bob/NTUSER.DAT", _hive_with_deleted_password(current=current))
            return list(WindowsRegistryProvider().collect(Path(temp)))

    def test_old_password_absent_everywhere(self) -> None:
        for current in (True, False):
            records = self.collect(current=current)
            by_type = {record.artifact_type for record in records}
            self.assertIn("registry-value-recovery-candidate", by_type)
            for record in records:
                text = json.dumps(record.to_dict(), ensure_ascii=False, default=str)
                self.assertNotIn(OLD_PASSWORD, text, (current, record.artifact_type))
                self.assertNotIn(CUR_PASSWORD, text, (current, record.artifact_type))
                self.assertNotIn(hashlib.sha256(OLD_PASSWORD.encode()).hexdigest(), text)
            recovered = [r for r in records if r.artifact_type == "registry-value-recovery-candidate" and r.details.get("name") == "Password"]
            self.assertTrue(recovered)
            manifest = recovered[0].details["registry_report_citation_manifest"]
            self.assertIn('"decoded_data_preview_sha256": ""', json.dumps(manifest, default=str))

    def test_helpers(self) -> None:
        from rapidtriage.artifacts.windows.registry import is_secret_value_cell

        self.assertTrue(is_secret_value_cell({"name": "ProxyPassword"}))
        self.assertFalse(is_secret_value_cell({"name": "HostName"}))


class SecretDocumentTests(unittest.TestCase):
    """#2 / #11 — browser/mail/FTP credential stores withheld; WinSCP/FileZilla/PGP masked; extract skips them."""

    FILES: ClassVar[dict[str, str]] = {
        "Users/a/AppData/Roaming/Signal/config.json": '{"key":"SIGNALSQLCIPHERKEY0123456789abcdef"} 저장하지',
        "Users/a/AppData/Roaming/Thunderbird/Profiles/x.default/logins.json": '{"encryptedPassword":"TBENCPASSWORDBLOB=="} 저장하지',
        "Users/a/AppData/Roaming/Mozilla/Firefox/Profiles/y/logins-backup.json": '{"encryptedPassword":"FFBACKUPBLOB=="} 저장하지',
        "Users/a/AppData/Roaming/FileZilla/sitemanager.xml": '<Server><Pass encoding="base64">RklMRVpJTExBU0VDUkVU</Pass></Server> 저장하지',
        "Users/a/Documents/export.xml": '<Servers><Server><Host>h</Host><Pass encoding="base64">RVhQT1JURURQQVNT</Pass></Server></Servers>',
        "Users/a/Documents/WinSCP-portable.ini": "[Sessions\\s]\nHostName=h\nPassword=WINSCPPORTABLEINISECRET\n",
        "Users/a/Documents/WinSCP-bare.ini": "[Sessions]\nHostName=h\nPassword=WINSCPBAREINISECRET\n",
        "Users/a/Documents/keys.txt": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nPGPPRIVATESECRETBODY\n-----END PGP PRIVATE KEY BLOCK-----\n",
        "Users/a/Documents/ec.txt": "-----BEGIN EC PRIVATE KEY-----\nECPRIVATESECRETBODY\n-----END EC PRIVATE KEY-----\n",
    }
    SECRETS = (
        "SIGNALSQLCIPHERKEY", "TBENCPASSWORDBLOB", "FFBACKUPBLOB", "RklMRVpJTExBU0VDUkVU", "RVhQT1JURURQQVNT",
        "WINSCPPORTABLEINISECRET", "WINSCPBAREINISECRET", "PGPPRIVATESECRETBODY", "ECPRIVATESECRETBODY",
    )

    def test_scan_and_extract_text(self) -> None:
        from rapidtriage.artifacts.windows.system_extras import (
            WITHHELD_TEXT,
            is_secret_store_path,
        )
        from rapidtriage.core.docs import extract_text, scan_document_candidates

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative, body in self.FILES.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            texts = {}
            for candidate in scan_document_candidates(root):
                path = Path(candidate.path)
                texts[path.name] = extract_text(path, path.suffix.lstrip("."))
        joined = "\n".join(texts.values())
        for secret in self.SECRETS:
            self.assertNotIn(secret, joined, secret)
        self.assertEqual(texts["config.json"], WITHHELD_TEXT)
        self.assertEqual(texts["logins.json"], WITHHELD_TEXT)
        self.assertIn("HostName=h", texts["WinSCP-portable.ini"])
        self.assertIn("<Host>h</Host>", texts["export.xml"])
        self.assertIn("PGP PRIVATE KEY BLOCK", texts["keys.txt"])
        for name in ("key3.db", "key4.db", "signons.sqlite", "Login Data", "Login Data For Account", "recentservers.xml"):
            self.assertTrue(is_secret_store_path(Path("C:/Users/a/AppData/Local/x") / name), name)
        for name in ("config.json", "logins.txt", "login.json"):
            self.assertFalse(is_secret_store_path(Path("C:/Users/a/AppData/Roaming/App") / name), name)

    def test_reg_hex_continuation_masked(self) -> None:
        from rapidtriage.artifacts.windows.system_extras import (
            file_holds_store_secret,
            redact_secret_store_text,
        )

        backslash = "\\"
        reg = (
            "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\s]\r\n"
            '"HostName"="h"\r\n"Password"=hex(1):57,00,49,00,4e,00,53,00,43,00,50,00,' + backslash + "\r\n  58,00,59,00,00,00\r\n"
            '"UserName"="u"\r\n'
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sessions.reg"
            path.write_bytes(bytes([0xFF, 0xFE]) + reg.encode("utf-16-le"))  # regedit exports are UTF-16LE
            self.assertTrue(file_holds_store_secret(path))
            text = redact_secret_store_text(path, reg)
        self.assertNotIn("58,00,59", text)
        self.assertNotIn("57,00,49", text)
        self.assertIn('"UserName"="u"', text)
        self.assertIn('"HostName"="h"', text)

    def test_run_extract_skips_secret_files(self) -> None:
        from rapidtriage.core.docs import run_docs_search
        from rapidtriage.core.extract import run_extract

        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            for relative, body in self.FILES.items():
                path = evidence / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body + "\n저장하지", encoding="utf-8")
            plain = evidence / "Users/a/Documents/plain.txt"
            plain.write_text("평범한 문서 저장하지", encoding="utf-8")
            payload = run_docs_search(evidence, ["저장하지"])
            output = Path(temp) / "out"
            manifest = run_extract(Path(temp) / "docs.json", output, payload=payload)
            copied = sorted(Path(entry["extracted_path"]).name for entry in manifest["entries"])
            skipped = {Path(item["original_path"]).name: item["reason"] for item in manifest["skipped"]}
            data = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
        self.assertEqual(copied, ["plain.txt"])
        for relative in self.FILES:
            self.assertEqual(skipped.get(Path(relative).name), "secret-redacted", relative)
        for secret in self.SECRETS:
            self.assertNotIn(secret.encode(), data)


class UrlRedactionTests(unittest.TestCase):
    """#3 / #10 — userinfo and credential query keys are redacted (carving, location URLs, Google stubs)."""

    def test_redact_url_userinfo_and_keys(self) -> None:
        from rapidtriage.artifacts.url_redaction import REDACTED_VALUE, redact_url

        self.assertEqual(redact_url("https://alice:Hunter2@ftp.example.com/x"), f"https://{REDACTED_VALUE}@ftp.example.com/x")
        self.assertEqual(redact_url("ftp://bob@h.example.org/"), f"ftp://{REDACTED_VALUE}@h.example.org/")
        self.assertEqual(redact_url("https://www.google.com/maps/@37.5,127.0,15z"), "https://www.google.com/maps/@37.5,127.0,15z")
        self.assertEqual(redact_url("mail alice@example.com"), "mail alice@example.com")
        url = "https://l.example.com/cb?refresh_token=RT1&client_secret=CS1&password=PW1&id_token=ID1&apikey=AK1&api_key=AK2&resourcekey=RK1&passwd=P2&pwd=P3&pass=P4&otp=123456&secret=S1&passkey=PK1&page=2"
        out = redact_url(url)
        for value in ("RT1", "CS1", "PW1", "ID1", "AK1", "AK2", "RK1", "P2", "P3", "P4", "123456", "S1", "PK1"):
            self.assertNotIn(f"={value}", out)
        self.assertIn("page=2", out)
        self.assertIn(f"_dk_https://{REDACTED_VALUE}@a.com", redact_url("1/0/_dk_https://u:p@a.com"))

    def test_url_carving_rows(self) -> None:
        from rapidtriage.core.url_carving import UrlCarveState, scan_url_source

        data = (
            b"xx https://alice:Hunter2Secret@ftp.example.com/x  "
            b"https://login.example.com/cb?refresh_token=RTSECRET123&client_secret=CSSECRET&password=PWSECRET&id_token=IDTOK&apikey=APIKEY1 "
            b"https://www.google.com/maps/@37.5,127.0,15z  "
        )
        data += "https://bob:Pw0rdUTF16@h.example.org/a ".encode("utf-16-le")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "pagefile.sys"
            path.write_bytes(data)
            rows, _ = scan_url_source(path, state=UrlCarveState(None, 100), read_limit=len(data))
        text = json.dumps(rows, ensure_ascii=False)
        for secret in ("Hunter2Secret", "alice:", "RTSECRET123", "CSSECRET", "PWSECRET", "IDTOK", "APIKEY1", "Pw0rdUTF16"):
            self.assertNotIn(secret, text)
        maps = next(row for row in rows if "google.com/maps" in str(row["url"]))
        self.assertEqual(maps["latitude"], 37.5)
        self.assertTrue(all(row["url_tokens_redacted"] for row in rows if "example" in str(row["url"])))

    def test_location_url_candidate(self) -> None:
        from rapidtriage.artifacts.windows.location_urls import build_location_candidate
        from rapidtriage.core.models import ArtifactRecord

        record = ArtifactRecord(
            provider="browser",
            artifact_type="browser-history",
            path="History",
            supported=True,
            details={"url": "https://u:SECRETPW@www.google.com/maps/search/coffee/@37.5,127.0,15z?api_key=KEYSECRET", "browser": "chrome"},
        )
        from rapidtriage.core.derived.map_urls import parse_map_url

        parsed = parse_map_url(record.details["url"])
        self.assertIsNotNone(parsed)
        row = build_location_candidate(record, parsed)
        text = json.dumps(row.details, ensure_ascii=False, default=str)
        self.assertNotIn("SECRETPW", text)
        self.assertNotIn("KEYSECRET", text)

    def test_google_stub_url_redacted(self) -> None:
        from rapidtriage.artifacts.cloud_sync import parse_google_stub

        fields = parse_google_stub(json.dumps({"url": "https://drive.google.com/open?id=1AbCdEfGhIjKlMnOp&resourcekey=0-RKSECRET"}).encode())
        self.assertNotIn("RKSECRET", str(fields["stub_url"]))
        self.assertIn("id=1AbCdEfGhIjKlMnOp", str(fields["stub_url"]))


class MediaPlayerUrlTests(unittest.TestCase):
    """#4 — stream URLs in media-player rows lose userinfo and token query values."""

    def test_vlc_stream_url_redacted(self) -> None:
        from rapidtriage.artifacts.windows.media_players import (
            WindowsMediaPlayersProvider,
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            vlc = root / "Users" / "alice" / "AppData" / "Roaming" / "vlc"
            vlc.mkdir(parents=True)
            (root / "Users" / "alice" / "AppData" / "Local").mkdir(parents=True)
            (vlc / "vlc-qt-interface.ini").write_text(
                "[RecentsMRU]\nlist=http://viewer:CAMPASSWORD@cam.example.com/live.m3u8?token=STREAMTOKEN&ch=1\ntimes=0\n",
                encoding="utf-8",
            )
            rows = [record for record in WindowsMediaPlayersProvider().collect(root) if record.artifact_type == "media-player-recent"]
        self.assertEqual(len(rows), 1)
        text = json.dumps(rows[0].details, ensure_ascii=False)
        self.assertNotIn("CAMPASSWORD", text)
        self.assertNotIn("STREAMTOKEN", text)
        self.assertIn("cam.example.com", rows[0].details["media_url"])
        self.assertEqual(rows[0].details["url_host"], "cam.example.com")
        self.assertEqual(len(rows[0].details["media_url_sha256"]), 64)


class PsdXmpTests(unittest.TestCase):
    """#5 — a crafted multi-MiB XMP packet parses in linear time."""

    def test_crafted_xmp_is_fast(self) -> None:
        from rapidtriage.artifacts.media import parse_psd_xmp

        crafted = (
            "<xmpMM:History>" + "<rdf:li a>" * 420_000 + "</xmpMM:History>",
            "<xmpMM:History>x" * 270_000,
            "<photoshop:DocumentAncestors>" * 150_000,
        )
        for text in crafted:
            self.assertGreaterEqual(len(text), 2 * 1024 * 1024)
            started = time.perf_counter()
            result = parse_psd_xmp(text)
            self.assertLess(time.perf_counter() - started, 1.0)
            self.assertTrue(result["xmp_truncated"])

    def test_history_still_parsed(self) -> None:
        from rapidtriage.artifacts.media import parse_psd_xmp

        text = (
            '<x xmp:CreatorTool="Adobe Photoshop 25.0"><xmpMM:History><rdf:Seq>'
            '<rdf:li stEvt:action="created" stEvt:when="2024-05-01T12:00:00+09:00"/>'
            "<rdf:li><stEvt:action>saved</stEvt:action><stEvt:softwareAgent>Photoshop</stEvt:softwareAgent></rdf:li>"
            "<rdf:lighter/></rdf:Seq></xmpMM:History>"
            "<photoshop:DocumentAncestors><rdf:Bag><rdf:li>xmp.did:1</rdf:li></rdf:Bag></photoshop:DocumentAncestors></x>"
        )
        result = parse_psd_xmp(text)
        self.assertEqual(result["creator_tool"], "Adobe Photoshop 25.0")
        self.assertEqual(result["history"], [{"action": "created", "when": "2024-05-01T12:00:00+09:00"}, {"action": "saved", "softwareAgent": "Photoshop"}])
        self.assertEqual(result["document_ancestors"], ["xmp.did:1"])
        self.assertFalse(result["xmp_truncated"])


def _zlib_zeros(prefix: bytes, chunks: int) -> bytes:
    encoder = zlib.compressobj(9)
    parts = [encoder.compress(prefix)]
    zeros = b"\0" * (64 * 1024 * 1024)
    parts.extend(encoder.compress(zeros) for _ in range(chunks))
    parts.append(encoder.flush())
    return b"".join(parts)


class AdbBackupHardeningTests(unittest.TestCase):
    """#6 / #7 — the zlib bomb stays memory-bounded; a PAX mtime overflow never escapes."""

    def write(self, temp: str, data: bytes) -> Path:
        path = Path(temp) / "phone.ab"
        path.write_bytes(data)
        return path

    def test_zlib_bomb_memory_bounded(self) -> None:
        from rapidtriage.artifacts.mobile.adb_backup import collect_adb_backup

        info = tarfile.TarInfo("apps/com.x/f/big.bin")
        info.size = 4 * 1024**3
        header = info.tobuf(format=tarfile.GNU_FORMAT)
        for prefix in (b"", header):
            blob = _zlib_zeros(prefix, 16)  # ~1 MiB compressed -> 1 GiB of zeros
            with tempfile.TemporaryDirectory() as temp:
                path = self.write(temp, b"ANDROID BACKUP\n5\n1\nnone\n" + blob)
                tracemalloc.start()
                try:
                    rows = list(collect_adb_backup(path))
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
            self.assertLess(peak, 100 * 1024 * 1024)
            if prefix:
                self.assertEqual(rows[0].details["status"], "partial")
                self.assertIn("AdbBackupError", rows[0].details["status_reason"])

    def test_pax_mtime_overflow(self) -> None:
        from rapidtriage.artifacts.mobile import MobileExportProvider
        from rapidtriage.artifacts.mobile.adb_backup import (
            collect_adb_backup,
            member_mtime,
        )

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, mtime in (("apps/com.x/f/a.txt", "1e300"), ("apps/com.x/f/b.txt", "1700000000")):
                info = tarfile.TarInfo(name)
                info.size = 3
                info.pax_headers = {"mtime": mtime}
                archive.addfile(info, io.BytesIO(b"abc"))
        data = b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(buffer.getvalue())
        with tempfile.TemporaryDirectory() as temp:
            rows = list(collect_adb_backup(self.write(temp, data)))
            provider_rows = list(MobileExportProvider().collect(Path(temp)))
        self.assertEqual(rows[0].details["status"], "completed")
        members = {row.details["member_name"]: row.details for row in rows[1:]}
        self.assertIsNone(members["apps/com.x/f/a.txt"]["member_mtime"])
        self.assertEqual(members["apps/com.x/f/b.txt"]["member_mtime"], "2023-11-14T22:13:20Z")
        self.assertEqual(len(provider_rows), 3)
        for value in (float("inf"), float("nan"), -5, 0, "x", None, 1e300):
            self.assertIsNone(member_mtime(value))

    def test_provider_isolates_unexpected_failure(self) -> None:
        from rapidtriage.artifacts.mobile import MobileExportProvider

        with tempfile.TemporaryDirectory() as temp:
            self.write(temp, b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(b"\0" * 1024))
            provider = MobileExportProvider()
            with mock.patch("rapidtriage.artifacts.mobile.collector.collect_adb_backup", side_effect=RuntimeError("boom")):
                rows = list(provider.collect(Path(temp)))
        self.assertEqual([row.artifact_type for row in rows], ["android-backup"])
        self.assertEqual(rows[0].details["status"], "unreadable")
        self.assertIn("RuntimeError", rows[0].details["status_reason"])
        self.assertTrue(any("adb 백업" in note for note in provider.collection_notes))


class EmailDedupeTests(unittest.TestCase):
    """#8 — the email provider skips only the .eml files the email-clients provider actually read."""

    def test_capped_client_root_keeps_remaining_messages(self) -> None:
        from rapidtriage.artifacts import email_clients
        from rapidtriage.artifacts.email import EmailArtifactsProvider
        from rapidtriage.artifacts.email_clients import EmailClientsProvider

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inbox = root / "Users" / "bob" / "AppData" / "Local" / "Microsoft" / "Windows Live Mail" / "acct" / "Inbox"
            inbox.mkdir(parents=True)
            for index in range(3):
                (inbox / f"m{index}.eml").write_bytes(
                    f"From: a@example.com\r\nTo: b@example.com\r\nSubject: s{index}\r\nMessage-ID: <m{index}@x>\r\n\r\nbody{index}\r\n".encode()
                )
            with mock.patch.object(email_clients, "MAX_MESSAGES_PER_ROOT", 2):
                client_paths = {Path(record.path).name for record in EmailClientsProvider().collect(root) if record.path.endswith(".eml")}
                generic_paths = {Path(record.path).name for record in EmailArtifactsProvider().collect(root) if record.path.endswith(".eml")}
            uncapped = {Path(record.path).name for record in EmailArtifactsProvider().collect(root) if record.path.endswith(".eml")}
        self.assertEqual(client_paths, {"m0.eml", "m1.eml"})
        self.assertEqual(generic_paths, {"m2.eml"})
        self.assertEqual(uncapped, set())

    def test_plausible_mbox_name(self) -> None:
        from rapidtriage.artifacts.email import plausible_mbox_name

        self.assertTrue(plausible_mbox_name(Path("D:/x/Mail/Local Folders/Inbox")))
        self.assertFalse(plausible_mbox_name(Path("D:/x/cache2/entries/0123456789ABCDEF0123456789ABCDEF01234567")))
        self.assertFalse(plausible_mbox_name(Path("D:/x/Cache/Inbox")))
        self.assertTrue(plausible_mbox_name(Path("C:/Temp/case/export/Inbox"), Path("C:/Temp/case")))


class EggBudgetTests(unittest.TestCase):
    """#9 — an EGG block whose compressed size exceeds the member cap is never read into memory."""

    def test_oversized_compressed_block_and_archive_budget(self) -> None:
        from rapidtriage.core import egg_archive
        from tests.test_r5_l3_archives import egg_archive as build_egg
        from tests.test_r5_l3_archives import egg_file

        data = bytes(range(256)) * 64
        archive = build_egg(*(egg_file(f"f{index}.bin", data, "store", file_id=index) for index in range(3)))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "a.egg"
            path.write_bytes(archive)
            with mock.patch.object(egg_archive, "MAX_ARCHIVE_DECOMPRESSED_BYTES", len(data) * 2):
                listing = egg_archive.list_egg(path)
            with mock.patch.object(egg_archive, "MAX_MEMBER_BYTES", len(data) - 1):
                capped = egg_archive.list_egg(path)
        notes = [entry["extract_note"] for entry in listing["entries"]]
        self.assertEqual(notes, ["", "", "archive-decompression-budget"])
        self.assertIsNone(listing["entries"][2]["sha256"])
        self.assertTrue(all(entry["sha256"] is None for entry in capped["entries"]))


class PlausibleFindingTests(unittest.TestCase):
    """Reviewer's "plausible" items that were confirmed and fixed."""

    def test_naver_xy_sanity_and_place_id(self) -> None:
        from rapidtriage.core.derived.map_urls import parse_map_url

        katech = parse_map_url("https://map.naver.com/?x=309000&y=552000&query=%EC%B9%B4%ED%8E%98")
        self.assertIsNone(katech["latitude"])
        self.assertEqual(katech["query"], "카페")
        wgs = parse_map_url("https://map.naver.com/?x=127.0&y=37.5")
        self.assertEqual((wgs["latitude"], wgs["longitude"]), (37.5, 127.0))
        self.assertIsNone(parse_map_url("https://map.naver.com/p/entry/place/1234567"))
        named = parse_map_url("https://map.naver.com/v5/place/%EC%8B%9C%EC%B2%AD")
        self.assertEqual(named["query"], "시청")

    def test_v2_only_torrent_has_no_v1_hash(self) -> None:
        from rapidtriage.artifacts.p2p import torrent_summary
        from tests.test_r5_l3_p2p import INFO, bencode

        v2 = {"name": "v2", "meta version": 2, "piece length": 16384, "file tree": {"x.bin": {"": {"length": 42}}}}
        summary = torrent_summary(bencode({"info": v2}))
        self.assertEqual((summary["info_hash"], summary["torrent_version"]), ("", "v2"))
        self.assertEqual(summary["info_hash_v2"], hashlib.sha256(bencode(v2)).hexdigest())
        hybrid = dict(INFO, **{"meta version": 2})
        summary = torrent_summary(bencode({"info": hybrid}))
        self.assertEqual(summary["torrent_version"], "hybrid")
        self.assertEqual(summary["info_hash"], hashlib.sha1(bencode(hybrid)).hexdigest())
        self.assertEqual(torrent_summary(bencode({"info": INFO}))["torrent_version"], "v1")

    def test_emule_boolarray_length(self) -> None:
        from rapidtriage.artifacts.p2p import _Met

        # BOOLARRAY of 8 bits: eMule skips 8 // 8 + 1 = 2 bytes, then the next tag follows.
        payload = struct.pack("<BB", 0x86, 0x10) + struct.pack("<H", 8) + b"\xff\x00" + struct.pack("<BBI", 0x83, 0x02, 77)
        reader = _Met(struct.pack("<I", 2) + payload)
        self.assertEqual(reader.tags().get("file_size"), 77)

    def test_ntfs_volume_fixups_use_sector_size(self) -> None:
        from rapidtriage.artifacts.windows.system_extras import parse_volume_record

        record = bytearray(4096)
        record[0:4] = b"FILE"
        record[4:6] = (48).to_bytes(2, "little")
        record[6:8] = (2).to_bytes(2, "little")  # 4Kn: one 4096-byte sector -> USN + 1 entry
        record[48:50] = b"\x07\x00"
        record[50:52] = b"\xaa\xbb"
        record[0x14:0x16] = (56).to_bytes(2, "little")
        label = "합성".encode("utf-16-le")
        attribute = bytearray(24 + len(label))
        attribute[0:4] = (0x60).to_bytes(4, "little")
        attribute[4:8] = len(attribute).to_bytes(4, "little")
        attribute[0x10:0x14] = len(label).to_bytes(4, "little")
        attribute[0x14:0x16] = (24).to_bytes(2, "little")
        attribute[24:] = label
        record[56 : 56 + len(attribute)] = attribute
        end = 56 + len(attribute)
        record[end : end + 4] = b"\xff\xff\xff\xff"
        record[4094:4096] = b"\x07\x00"
        parsed = parse_volume_record(bytes(record), 4096)
        self.assertEqual((parsed["volume_record_status"], parsed["volume_label"]), ("parsed", "합성"))
        self.assertEqual(parse_volume_record(bytes(record), 512)["volume_record_status"], "invalid-file-record")

    def test_iso_directory_read_budget(self) -> None:
        from rapidtriage.core import iso9660
        from tests.test_r5_l3_archives import iso_image

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "a.iso"
            path.write_bytes(iso_image())
            with mock.patch.object(iso9660, "MAX_TOTAL_DIRECTORY_BYTES", 2048):
                listing = iso9660.list_iso(path)
            full = iso9660.list_iso(path)
        self.assertIn("directory-read-cap-reached", listing["notes"])
        self.assertEqual(listing["analysis_status"], "iso9660-partial")
        self.assertGreater(len(full["entries"]), len(listing["entries"]))


if __name__ == "__main__":
    unittest.main()
