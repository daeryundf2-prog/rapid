"""Parser-quality round 1 (W5 docs/kakao/memory): synthetic binary fixtures reproducing the
real-data review findings for generic documents, KakaoTalk registry traces and minidumps."""

from __future__ import annotations

import contextlib
import datetime as dt
import sqlite3
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

from rapidtriage.artifacts.generic import (
    GenericDocumentArtifactProvider,
    collect_document_metadata_risk,
    collect_local_llm_inventory,
    collect_sticky_notes,
    filetime_to_iso,
    pdf_date_to_iso,
)
from rapidtriage.artifacts.kakaotalk_windows import (
    collect_registry_kakao_candidates,
    decode_registry_value_strings,
    inspect_sqlite_database,
)
from rapidtriage.artifacts.memory import (
    MemoryVolatilityProvider,
    ipv4_indicator_strength,
    is_printf_template,
)

FILETIME_UNIX_EPOCH = 116444736000000000


def filetime(moment: dt.datetime) -> int:
    delta = moment - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return FILETIME_UNIX_EPOCH + (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


# ---------------------------------------------------------------- CFB / property-set builders


def build_property_set(properties: list[tuple[int, int, bytes]], *, codepage: int = 1200) -> bytes:
    """[MS-OLEPS] stream with one section. ``properties`` = (pid, vt, encoded value body)."""
    entries = [(1, struct.pack("<IhH", 0x02, codepage - 65536 if codepage > 32767 else codepage, 0))]
    for pid, vt, body in properties:
        raw = struct.pack("<I", vt) + body
        raw += b"\x00" * ((4 - len(raw) % 4) % 4)
        entries.append((pid, raw))
    header_size = 8 + 8 * len(entries)
    offsets = []
    blob = b""
    for _pid, raw in entries:
        offsets.append(header_size + len(blob))
        blob += raw
    section = struct.pack("<II", header_size + len(blob), len(entries))
    section += b"".join(struct.pack("<II", pid, offset) for (pid, _raw), offset in zip(entries, offsets))
    section += blob
    header = struct.pack("<HHI", 0xFFFE, 0, 0x00020006) + b"\x00" * 16 + struct.pack("<I", 1)
    header += b"\x11" * 16 + struct.pack("<I", 48)
    return header + section


def lpwstr(text: str) -> bytes:
    encoded = (text + "\x00").encode("utf-16le")
    return struct.pack("<I", len(text) + 1) + encoded


def lpstr(text: str, encoding: str = "cp949") -> bytes:
    encoded = text.encode(encoding) + b"\x00"
    return struct.pack("<I", len(encoded)) + encoded


def ft_value(value: int) -> bytes:
    return struct.pack("<Q", value)


def build_cfb(streams: dict[str, bytes]) -> bytes:
    """Minimal v3 compound file: every stream (< 4096 bytes) lives in the mini stream."""
    sector = 512
    mini = 64
    names = list(streams)
    ministream = b""
    minifat: list[int] = []
    starts: dict[str, int] = {}
    for name in names:
        data = streams[name]
        count = max(1, -(-len(data) // mini))
        starts[name] = len(minifat)
        for index in range(count):
            minifat.append(len(minifat) + 1 if index < count - 1 else 0xFFFFFFFE)
        ministream += data + b"\x00" * (count * mini - len(data))
    entries = [("Root Entry", 5, 0, len(ministream))] + [(name, 2, starts[name], len(streams[name])) for name in names]
    directory = b""
    for index, (name, kind, start, size) in enumerate(entries):
        encoded = (name + "\x00").encode("utf-16le")
        raw = encoded.ljust(64, b"\x00") + struct.pack("<HBB", len(encoded), kind, 1)
        left = 0xFFFFFFFF
        right = index + 1 if 1 <= index < len(entries) - 1 else 0xFFFFFFFF
        child = 1 if index == 0 and len(entries) > 1 else 0xFFFFFFFF
        raw += struct.pack("<III", left, right, child) + b"\x00" * 16 + b"\x00" * 4 + b"\x00" * 16
        raw += struct.pack("<IQ", start, size)
        raw = raw.ljust(128, b"\x00")
        directory += raw
    directory += b"\x00" * ((-len(directory)) % sector)
    minifat_bytes = struct.pack(f"<{len(minifat)}I", *minifat)
    minifat_bytes += b"\xff" * ((-len(minifat_bytes)) % sector)
    ministream += b"\x00" * ((-len(ministream)) % sector)
    dir_sectors = len(directory) // sector
    minifat_sectors = len(minifat_bytes) // sector
    ministream_sectors = max(1, len(ministream) // sector) if ministream else 0
    fat_sid = 0
    dir_start = 1
    minifat_start = dir_start + dir_sectors
    ministream_start = minifat_start + minifat_sectors
    total = ministream_start + ministream_sectors
    fat = [0xFFFFFFFF] * (sector // 4)
    fat[fat_sid] = 0xFFFFFFFD

    def chain(start: int, count: int) -> None:
        for index in range(count):
            fat[start + index] = start + index + 1 if index < count - 1 else 0xFFFFFFFE

    chain(dir_start, dir_sectors)
    chain(minifat_start, minifat_sectors)
    chain(ministream_start, ministream_sectors)
    assert total <= len(fat)
    root = bytearray(directory[:128])
    struct.pack_into("<I", root, 0x74, ministream_start if ministream else 0xFFFFFFFE)
    directory = bytes(root) + directory[128:]
    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)
    struct.pack_into("<I", header, 0x30, dir_start)
    struct.pack_into("<I", header, 0x38, 4096)
    struct.pack_into("<III", header, 0x3C, minifat_start, minifat_sectors, 0xFFFFFFFE)
    struct.pack_into("<I", header, 0x48, 0)
    difat = [fat_sid] + [0xFFFFFFFF] * 108
    struct.pack_into("<109I", header, 0x4C, *difat)
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    return bytes(header) + fat_bytes + directory + minifat_bytes + ministream


CREATED = dt.datetime(2024, 3, 4, 5, 6, 7, tzinfo=dt.timezone.utc)
SAVED = dt.datetime(2024, 3, 5, 1, 2, 3, tzinfo=dt.timezone.utc)
PRINTED = dt.datetime(2024, 3, 6, 9, 0, 0, tzinfo=dt.timezone.utc)


def summary_information_stream() -> bytes:
    return build_property_set(
        [
            (2, 0x1F, lpwstr("분기 보고서")),
            (4, 0x1F, lpwstr("홍길동")),
            (7, 0x1F, lpwstr("Normal.dotm")),
            (8, 0x1F, lpwstr("김철수")),
            (9, 0x1F, lpwstr("7")),
            (10, 0x40, ft_value(5_400 * 10_000_000)),
            (11, 0x40, ft_value(filetime(PRINTED))),
            (12, 0x40, ft_value(filetime(CREATED))),
            (13, 0x40, ft_value(filetime(SAVED))),
            (14, 0x03, struct.pack("<i", 3)),
            (18, 0x1F, lpwstr("Microsoft Office Word")),
        ]
    )


def doc_summary_information_stream() -> bytes:
    return build_property_set(
        [(15, 0x1E, lpstr("대륜병원")), (14, 0x1E, lpstr("원장")), (2, 0x1E, lpstr("내부"))],
        codepage=949,
    )


def word_fib(*, encrypted: bool) -> bytes:
    fib = bytearray(64)
    struct.pack_into("<HH", fib, 0, 0xA5EC, 0x00C1)
    struct.pack_into("<H", fib, 0x0A, 0x0100 if encrypted else 0x0000)
    return bytes(fib)


def biff_workbook(*, filepass: bool) -> bytes:
    stream = struct.pack("<HH", 0x0809, 16) + b"\x00" * 16
    if filepass:
        stream += struct.pack("<HH", 0x002F, 6) + struct.pack("<HHH", 1, 1, 1)
    stream += struct.pack("<HH", 0x000A, 0)
    return stream


def hwp_file_header(properties: int) -> bytes:
    header = b"HWP Document File".ljust(32, b"\x00")
    header += struct.pack("<II", 0x05010001, properties)
    return header.ljust(256, b"\x00")


def build_pdf(objects: dict[int, bytes], trailer: bytes) -> bytes:
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for number in sorted(objects):
        offsets[number] = len(out)
        out += b"%d 0 obj\n" % number + objects[number] + b"\nendobj\n"
    xref = len(out)
    size = max(objects) + 1
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for number in range(1, size):
        out += b"%010d 00000 n \n" % offsets.get(number, 0)
    out += b"trailer\n" + trailer + b"\nstartxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


# ---------------------------------------------------------------- generic documents


class GenericOle2MetadataTests(unittest.TestCase):
    def collect(self, files: dict[str, bytes]) -> dict[str, object]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name, data in files.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        return {Path(record.path).name: record for record in collect_document_metadata_risk(root)}

    def test_doc_summary_information_property_sets_top_level(self) -> None:
        cfb = build_cfb(
            {
                "\x05SummaryInformation": summary_information_stream(),
                "\x05DocumentSummaryInformation": doc_summary_information_stream(),
                "WordDocument": word_fib(encrypted=False),
            }
        )
        details = self.collect({"report.doc": cfb})["report.doc"].details
        self.assertEqual(details["container_format"], "ole2-cfb")
        self.assertEqual(details["title"], "분기 보고서")
        self.assertEqual(details["author"], "홍길동")
        self.assertEqual(details["last_modified_by"], "김철수")
        self.assertEqual(details["template"], "Normal.dotm")
        self.assertEqual(details["revision"], "7")
        self.assertEqual(details["created_at"], "2024-03-04T05:06:07+00:00")
        self.assertEqual(details["modified_at"], "2024-03-05T01:02:03+00:00")
        self.assertEqual(details["last_printed_at"], "2024-03-06T09:00:00+00:00")
        # PIDSI_EDITTIME is a duration, not a 1601-based timestamp.
        self.assertEqual(details["total_edit_time_seconds"], 5400)
        self.assertEqual(details["total_edit_time"], "PT1H30M0S")
        self.assertEqual(details["company"], "대륜병원")
        self.assertEqual(details["manager"], "원장")
        self.assertEqual(details["page_count"], 3)
        self.assertFalse(details["encrypted"])
        self.assertIn("SummaryInformation", details["metadata_profile"]["property_sets"])

    def test_filetime_conversion_is_integer_exact(self) -> None:
        moment = dt.datetime(2025, 5, 28, 23, 35, 57, 123456, tzinfo=dt.timezone.utc)
        self.assertEqual(filetime_to_iso(filetime(moment)), moment.isoformat())
        self.assertEqual(filetime_to_iso(0), "")

    def test_encrypted_documents_are_flagged(self) -> None:
        encrypted_ooxml = build_cfb(
            {"EncryptionInfo": struct.pack("<HHI", 4, 4, 0x40) + b"<encryption/>", "EncryptedPackage": b"\x00" * 200}
        )
        records = self.collect(
            {
                "secret 비번12345.xlsx": encrypted_ooxml,
                "locked.doc": build_cfb({"WordDocument": word_fib(encrypted=True)}),
                "locked.xls": build_cfb({"Workbook": biff_workbook(filepass=True)}),
                "plain.xls": build_cfb({"Workbook": biff_workbook(filepass=False)}),
                "dist.hwp": build_cfb({"FileHeader": hwp_file_header(0x1 | 0x4)}),
                "locked.pdf": build_pdf(
                    {1: b"<< /Type /Catalog >>", 2: b"<< /Producer (x) >>", 3: b"<< /Filter /Standard /V 2 >>"},
                    b"<< /Size 4 /Root 1 0 R /Info 2 0 R /Encrypt 3 0 R /ID [<00><00>] >>",
                ),
            }
        )
        xlsx = records["secret 비번12345.xlsx"].details
        self.assertTrue(xlsx["encrypted"])
        self.assertEqual(xlsx["encryption_reason"], "ooxml-encrypted-package")
        self.assertEqual(xlsx["metadata_profile"]["encryption"]["encryption_scheme"], "agile")
        self.assertIn("document-encrypted", xlsx["risk_flags"])
        self.assertEqual(records["locked.doc"].details["encryption_reason"], "word-fib-fEncrypted")
        self.assertEqual(records["locked.xls"].details["encryption_reason"], "biff-filepass-record")
        self.assertFalse(records["plain.xls"].details["encrypted"])
        hwp = records["dist.hwp"].details
        self.assertTrue(hwp["encrypted"])
        self.assertEqual(hwp["encryption_reason"], "hwp-distribution-document")
        header = hwp["metadata_profile"]["hwp_file_header"]
        self.assertEqual(header["version"], "5.1.0.1")
        self.assertTrue(header["flags"]["compressed"])
        self.assertFalse(header["flags"]["password_encrypted"])
        self.assertEqual(records["locked.pdf"].details["encryption_reason"], "pdf-trailer-encrypt-dictionary")

    def test_hwp_summary_information(self) -> None:
        summary = build_property_set(
            [
                (2, 0x1F, lpwstr("인계장")),
                (4, 0x1F, lpwstr("user")),
                (9, 0x1F, lpwstr("10, 0, 0, 11131 WIN32LEWindows_8")),
                (12, 0x40, ft_value(filetime(CREATED))),
            ]
        )
        cfb = build_cfb({"FileHeader": hwp_file_header(0x1), "\x05HwpSummaryInformation": summary})
        details = self.collect({"인계장.hwp": cfb})["인계장.hwp"].details
        self.assertEqual(details["container_format"], "hwp5-cfb")
        self.assertEqual(details["title"], "인계장")
        self.assertEqual(details["author"], "user")
        self.assertEqual(details["application_version"], "10, 0, 0, 11131 WIN32LEWindows_8")
        self.assertNotIn("revision", details)
        self.assertEqual(details["created_at"], "2024-03-04T05:06:07+00:00")
        self.assertFalse(details["encrypted"])


class GenericPdfInfoTests(unittest.TestCase):
    def profile_for(self, data: bytes) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doc.pdf"
            path.write_bytes(data)
            records = list(collect_document_metadata_risk(Path(tmp)))
        self.assertEqual(len(records), 1)
        return records[0].details

    def test_info_dictionary_strings_dates_and_pdfdoc_encoding(self) -> None:
        author_hex = ("\ufeff홍길동").encode("utf-16-be").hex().encode("ascii")
        info = (
            b"<< /Author <" + author_hex + b"> /Title (Report \\(final\\) \x92) /Producer (iText) "
            b"/Creator 4 0 R /CreationDate (D:20240102030405+09'00') /ModDate (D:20240203040506Z) >>"
        )
        data = build_pdf(
            {1: b"<< /Type /Catalog >>", 2: info, 4: b"(Hwp 2018 10.0.0.1)"},
            b"<< /Size 5 /Root 1 0 R /Info 2 0 R /ID [(\\343C<=)(\\343C<=)] >>",
        )
        details = self.profile_for(data)
        self.assertEqual(details["author"], "홍길동")
        self.assertEqual(details["title"], "Report (final) \u2122")
        self.assertEqual(details["application"], "Hwp 2018 10.0.0.1")
        self.assertEqual(details["created_at"], "2024-01-02T03:04:05+09:00")
        self.assertEqual(details["modified_at"], "2024-02-03T04:05:06+00:00")
        self.assertFalse(details["encrypted"])

    def test_info_in_compressed_object_stream_with_xref_stream_trailer(self) -> None:
        payload_objects = b"<< /Author (Kim) /CreationDate (D:20230101000000) >>"
        header = b"7 0 "
        objstm = header + payload_objects
        compressed = zlib.compress(objstm)
        stream_obj = (
            b"<< /Type /ObjStm /N 1 /First %d /Filter /FlateDecode /Length %d >>\nstream\n" % (len(header), len(compressed))
            + compressed
            + b"\nendstream"
        )
        xref_obj = b"<< /Type /XRef /Size 9 /Root 1 0 R /Info 7 0 R /W [1 2 1] >>\nstream\n\nendstream"
        data = build_pdf({1: b"<< /Type /Catalog >>", 5: stream_obj, 8: xref_obj}, b"<< /Size 9 /Root 1 0 R >>")
        details = self.profile_for(data)
        self.assertEqual(details["author"], "Kim")
        self.assertEqual(details["created_at"], "2023-01-01T00:00:00")
        self.assertIn("created_at", details["timestamps_without_zone"])
        self.assertTrue(str(details["metadata_profile"]["info_source"]).endswith("object-stream"))

    def test_pdf_date_partial_and_negative_offset(self) -> None:
        self.assertEqual(pdf_date_to_iso("D:2006"), "2006-01-01T00:00:00")
        self.assertEqual(pdf_date_to_iso("D:20060117130714-07'00'"), "2006-01-17T13:07:14-07:00")


class GenericOoxmlAndInventoryTests(unittest.TestCase):
    def test_ooxml_last_printed_revision_template_edit_time_top_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "memo.docx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("[Content_Types].xml", "<Types/>")
                archive.writestr(
                    "docProps/core.xml",
                    '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
                    "<dc:creator>Alice</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy>"
                    "<cp:lastPrinted>2024-01-05T06:07:00Z</cp:lastPrinted><cp:revision>12</cp:revision>"
                    "<dcterms:created>2024-01-01T00:00:00Z</dcterms:created><dcterms:modified>2024-01-02T00:00:00</dcterms:modified>"
                    "</cp:coreProperties>",
                )
                archive.writestr(
                    "docProps/app.xml",
                    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                    "<Template>Normal.dotm</Template><TotalTime>12</TotalTime><Application>Microsoft Office Word</Application>"
                    "<Company>ACME</Company></Properties>",
                )
            details = next(iter(collect_document_metadata_risk(root))).details
        self.assertEqual(details["last_printed_at"], "2024-01-05T06:07:00Z")
        self.assertEqual(details["revision"], "12")
        self.assertEqual(details["template"], "Normal.dotm")
        self.assertEqual(details["total_edit_time_seconds"], 720)
        self.assertEqual(details["company"], "ACME")
        self.assertEqual(details["timestamps_without_zone"], ["modified_at"])
        self.assertIn("lastPrinted", details["timestamp_candidates"])

    def test_owner_lock_files(self) -> None:
        name = "홍길동"
        word_lock = bytearray(162)
        ansi = name.encode("cp949")
        word_lock[0] = len(name)
        word_lock[1 : 1 + len(ansi)] = ansi
        struct.pack_into("<H", word_lock, 0x36, len(name))
        word_lock[0x38 : 0x38 + len(name) * 2] = name.encode("utf-16le")
        excel_lock = bytearray(165)
        excel_lock[0] = 6
        excel_lock[1:0x37] = b"Mind03".ljust(0x36, b" ")
        struct.pack_into("<H", excel_lock, 0x37, 6)
        excel_lock[0x39 : 0x39 + 12] = "Mind03".encode("utf-16le")
        hancom = bytearray(668)
        hancom[0:36] = "HCellShareFileInfo".encode("utf-16le")
        hancom[0x4C:0x50] = b"\x01\x00\x01\x00"
        host = "진료실1".encode("utf-16le")
        hancom[0x50 : 0x50 + len(host)] = host
        hancom[0x6E : 0x6E + 8] = "user".encode("utf-16le")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "~$견서 수정중.docx").write_bytes(bytes(word_lock))
            (root / "~$일일마감.xlsx").write_bytes(bytes(excel_lock))
            (root / "~$목록.xls").write_bytes(bytes(hancom))
            records = {Path(record.path).name: record for record in collect_document_metadata_risk(root)}
        self.assertEqual({record.artifact_type for record in records.values()}, {"document-lock-owner"})
        self.assertEqual(records["~$견서 수정중.docx"].details["lock_owner"], "홍길동")
        self.assertEqual(records["~$일일마감.xlsx"].details["lock_owner"], "Mind03")
        hancom_details = records["~$목록.xls"].details
        self.assertEqual(hancom_details["lock_owner"], "user")
        self.assertEqual(hancom_details["lock_owner_host"], "진료실1")
        self.assertEqual(hancom_details["lock_format"], "hancom-cell-share-info")

    def test_no_placeholder_rows_and_zip_local_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "pack.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                info = zipfile.ZipInfo("plain.txt", date_time=(2024, 12, 6, 18, 19, 22))
                archive.writestr(info, "x")
            # Legacy Korean zip: cp949 bytes without the UTF-8 flag (0x800).
            raw = bytearray(archive_path.read_bytes())
            korean = "김태미.pdf".encode("cp949")
            self.assertEqual(len(korean), len(b"plain.txt") + 1)
            data = bytes(raw).replace(b"plain.txt", korean[: len(b"plain.txt")])
            archive_path.write_bytes(data)
            records = list(GenericDocumentArtifactProvider().collect(root))
        self.assertFalse([record for record in records if record.artifact_type == "document-pattern"])
        self.assertFalse([record for record in records if record.path == str(root)])
        archive = next(record for record in records if record.artifact_type == "archive-file-inventory")
        profile = archive.details["archive_inventory_profile"]
        self.assertEqual(profile["entry_time_timezone"], "local-unknown")
        entry = profile["sample_entries"][0]
        self.assertEqual(entry["last_modified"], "2024-12-06T18:19:22")
        self.assertEqual(entry["timezone"], "local-unknown")
        self.assertEqual(entry["name_encoding"], "cp949")
        self.assertTrue(entry["name"].startswith("김태미"))

    def test_bin_is_not_a_local_llm_model_without_magic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "firmware.bin").write_bytes(b"\x7fELF" + b"\x00" * 64)
            models = root / ".ollama" / "models"
            models.mkdir(parents=True)
            (models / "cache.bin").write_bytes(b"random cache bytes" * 4)
            (models / "real-model.bin").write_bytes(b"GGUF\x03\x00\x00\x00" + b"\x00" * 64)
            header = b'{"__metadata__":{}}'
            (root / "weights.bin").write_bytes(struct.pack("<Q", len(header)) + header + b"\x00" * 16)
            rows = {Path(record.path).name: record for record in collect_local_llm_inventory(root)}
        self.assertNotIn("firmware.bin", rows)
        self.assertNotIn("cache.bin", rows)
        self.assertEqual(rows["real-model.bin"].details["model_format_magic"], "gguf")
        self.assertEqual(rows["weights.bin"].details["model_format_magic"], "safetensors")
        self.assertNotIn("modified_at", rows["weights.bin"].details)
        self.assertIn("source_file_mtime", rows["weights.bin"].details)


class GenericSqliteSnapshotTests(unittest.TestCase):
    def test_evidence_sqlite_is_never_opened_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "Packages" / "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe" / "plum.sqlite"
            db.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(db)) as connection, connection:
                connection.execute("CREATE TABLE Note (Text TEXT, IsDeleted INTEGER)")
                connection.execute("INSERT INTO Note VALUES ('meeting notes for alice@example.com', 0)")
            before = sorted(item.name for item in db.parent.iterdir())
            mtime = db.stat().st_mtime_ns
            real_connect = sqlite3.connect
            targets: list[str] = []

            def recording_connect(target, *args, **kwargs):
                targets.append(str(target))
                return real_connect(target, *args, **kwargs)

            with mock.patch("sqlite3.connect", side_effect=recording_connect):
                rows = list(collect_sticky_notes(root))
            after = sorted(item.name for item in db.parent.iterdir())
            self.assertEqual(mtime, db.stat().st_mtime_ns)
        self.assertTrue(any(row.artifact_type == "sticky-note" for row in rows))
        self.assertEqual(before, after)
        self.assertTrue(targets)
        self.assertFalse([target for target in targets if str(db.parent.as_posix()) in target.replace("\\", "/")])


# ---------------------------------------------------------------- KakaoTalk registry traces


class HiveBuilder:
    """Tiny regf writer: one hbin, nk/vk/value-list/data cells laid out back to back."""

    def __init__(self) -> None:
        self.cells = bytearray()

    def add_cell(self, payload: bytes) -> int:
        size = 4 + len(payload)
        size += (-size) % 8
        offset = len(self.cells)
        self.cells += struct.pack("<i", -size) + payload + b"\x00" * (size - 4 - len(payload))
        return offset + 0x20  # relative to the first hbin (hbin header is 0x20 bytes)

    def add_nk(self, name: str, parent: int, *, root: bool = False) -> int:
        encoded = name.encode("latin-1")
        payload = bytearray(0x4C + len(encoded))
        payload[0:2] = b"nk"
        struct.pack_into("<H", payload, 2, 0x20 | (0x4 if root else 0))
        struct.pack_into("<Q", payload, 4, filetime(SAVED))
        struct.pack_into("<I", payload, 0x10, parent)
        struct.pack_into("<I", payload, 0x24, 0)
        struct.pack_into("<I", payload, 0x28, 0xFFFFFFFF)
        struct.pack_into("<H", payload, 0x48, len(encoded))
        payload[0x4C:] = encoded
        return self.add_cell(bytes(payload))

    def set_values(self, nk_offset: int, values: list[tuple[str, int, bytes]]) -> None:
        vk_offsets = []
        for name, value_type, data in values:
            if len(data) <= 4:
                data_field = int.from_bytes(data.ljust(4, b"\x00"), "little")
                size_field = len(data) | 0x80000000
            else:
                data_field = self.add_cell(data)
                size_field = len(data)
            encoded = name.encode("latin-1")
            vk = b"vk" + struct.pack("<HIIIHH", len(encoded), size_field, data_field, value_type, 1, 0) + encoded
            vk_offsets.append(self.add_cell(vk))
        listing = self.add_cell(struct.pack(f"<{len(vk_offsets)}I", *vk_offsets))
        absolute = nk_offset - 0x20 + 4
        struct.pack_into("<I", self.cells, absolute + 0x24, len(vk_offsets))
        struct.pack_into("<I", self.cells, absolute + 0x28, listing)

    def build(self) -> bytes:
        size = 0x20 + len(self.cells)
        size += (-size) % 0x1000
        free = size - 0x20 - len(self.cells)
        body = bytes(self.cells) + (struct.pack("<i", free) + b"\x00" * (free - 4) if free >= 8 else b"\x00" * free)
        hbin = b"hbin" + struct.pack("<II", 0, size) + b"\x00" * 20 + body
        base = bytearray(0x1000)
        base[0:4] = b"regf"
        struct.pack_into("<I", base, 0x24, 0x20)
        struct.pack_into("<I", base, 0x28, len(hbin))
        return bytes(base) + hbin


def utf16z(text: str) -> bytes:
    return (text + "\x00").encode("utf-16le")


class KakaoRegistryTraceTests(unittest.TestCase):
    def build_hive(self, extra_values: int = 0) -> bytes:
        hive = HiveBuilder()
        root = hive.add_nk("ROOT", 0, root=True)
        software = hive.add_nk("Software", root)
        kakao = hive.add_nk("Kakao", software)
        talk = hive.add_nk("KakaoTalk", kakao)
        hive.set_values(
            talk,
            [
                ("InstallPath", 1, utf16z(r"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe")),
                ("Version", 1, utf16z("4.2.0")),
                ("Flags", 4, struct.pack("<I", 7)),
            ],
        )
        recent = hive.add_nk("RecentDocs", software)
        link = b"\x10\x00\x00\x00" + r"\\진료실1\Users".encode("cp949") + b"\x00" + "user\\Documents\\카카오톡 받은 파일\\KakaoTalk_20211206.png".encode("cp949") + b"\x00\x00"
        hive.set_values(recent, [("Link", 3, link), ("Other", 3, b"\x01\x02\x03\x04\x05\x06")])
        mui = hive.add_nk("MuiCache", software)
        hive.set_values(
            mui,
            [
                (r"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe.FriendlyAppName", 1, utf16z("KakaoTalk")),
                (r"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe.ApplicationCompany", 1, utf16z("Kakao Corp.")),
            ]
            + [(f"C:\\Apps\\KakaoTalk{index}\\KakaoTalk.exe.FriendlyAppName", 1, utf16z("KakaoTalk")) for index in range(extra_values)],
        )
        return hive.build()

    def collect(self, blob: bytes) -> list:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "NTUSER.DAT"
        path.write_bytes(blob)
        return collect_registry_kakao_candidates(path)

    def test_cell_bounded_rows_with_cp949_decoding_and_korean_label(self) -> None:
        rows = self.collect(self.build_hive())
        values = [row for row in rows if row.details["source_subtype"] == "native-hive-value"]
        keys = [row for row in rows if row.details["source_subtype"] == "native-hive-key"]
        self.assertEqual({row.details["registry_key_path"] for row in keys}, {"Software\\Kakao", "Software\\Kakao\\KakaoTalk"})
        by_name = {row.details["registry_value_name"]: row for row in values}
        install = by_name["InstallPath"]
        self.assertEqual(install.details["registry_key_path"], "Software\\Kakao\\KakaoTalk")
        self.assertEqual(install.details["registry_value_type"], "REG_SZ")
        self.assertEqual(install.details["candidate_value"], r"C:\Program Files (x86)\Kakao\KakaoTalk\KakaoTalk.exe")
        self.assertEqual(install.details["registry_key_last_written"], SAVED.isoformat())
        link = by_name["Link"]
        self.assertTrue(any("진료실1" in text for text in link.details["decoded_strings"]))
        self.assertIn("cp949", link.details["metadata"]["decoded_string_encodings"])
        self.assertNotIn("Version", by_name)
        self.assertNotIn("Flags", by_name)
        self.assertNotIn("Other", by_name)
        for row in rows:
            self.assertNotIn("vk", row.details["candidate_value"].replace("Kakao", ""))
            self.assertNotRegex(row.details["candidate_value"], "[\u00c0-\u00ff]")
            self.assertEqual(row.details["evidence_nature"], "registry-string-trace")
            self.assertIn("대화 내용 아님", row.details["display_label"])
            self.assertFalse(row.details["candidates_truncated"])
        self.assertEqual(rows[0].details["registry_trace_total"], len(rows))

    def test_no_silent_200_cap_and_distinct_rows(self) -> None:
        rows = self.collect(self.build_hive(extra_values=250))
        values = [row for row in rows if row.details["source_subtype"] == "native-hive-value"]
        self.assertEqual(len(values), 2 + 2 + 250)
        self.assertEqual(len({(row.details["registry_key_path"], row.details["registry_value_name"]) for row in values}), len(values))
        self.assertTrue(all(not row.details["candidates_truncated"] for row in rows))

    def test_ansi_value_strings_decode_utf8_then_cp949(self) -> None:
        strings = decode_registry_value_strings(3, b"\x00" + "진료실1".encode("cp949") + b"\x00" + "카카오톡".encode() + b"\x00")
        self.assertEqual([text for text, _encoding in strings], ["진료실1", "카카오톡"])
        self.assertEqual([encoding for _text, encoding in strings], ["cp949", "utf-8"])

    def test_app_database_inspection_uses_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "chatLogs_1.db"
            with contextlib.closing(sqlite3.connect(db)) as connection, connection:
                connection.execute("CREATE TABLE chat (id INTEGER)")
            result = inspect_sqlite_database(db)
            leftovers = sorted(item.name for item in Path(tmp).iterdir())
        self.assertEqual(result["open_status"], "opened-read-only")
        self.assertEqual(result["access_method"], "sqlite-working-snapshot")
        self.assertEqual(leftovers, ["chatLogs_1.db"])


# ---------------------------------------------------------------- minidump / memory IOC


DUMP_TIME = 1748475357  # 2025-05-28T23:35:57Z
CREATE_TIME = 1748474093


def build_minidump(extra_memory: bytes) -> bytes:
    streams: list[tuple[int, bytes]] = []
    system_info = struct.pack("<HHHBB", 9, 6, 0x9A04, 8, 1) + struct.pack("<IIIII", 10, 0, 26100, 2, 0)
    system_info += b"\x00" * (56 - len(system_info))
    streams.append((7, system_info))
    misc = struct.pack("<IIIIII", 24, 0x3, 4536, CREATE_TIME, 2, 3)
    streams.append((15, misc))
    exception = struct.pack("<II", 4242, 0) + struct.pack("<IIQQII", 0xC0000374, 1, 0, 0x7FFBEB03E0E5, 0, 0)
    exception += b"\x00" * (15 * 8) + struct.pack("<II", 0, 0)
    streams.append((6, exception))
    header_size = 32
    directory_size = 12 * (len(streams) + 1)
    cursor = header_size + directory_size
    blobs = b""
    entries: list[tuple[int, int, int]] = []
    for stream_type, data in streams:
        entries.append((stream_type, len(data), cursor + len(blobs)))
        blobs += data
    module_rva = cursor + len(blobs)
    name = r"C:\Program Files\AhnLab\Safe Transaction\ASDSvc.exe".encode("utf-16le")
    module_size = 4 + 108
    name_rva = module_rva + module_size
    fixed = struct.pack("<13I", 0xFEEF04BD, 0x10000, (10 << 16) | 0, (19041 << 16) | 1, (10 << 16) | 0, (19041 << 16) | 1, 0, 0, 0, 0, 0, 0, 0)
    module = struct.pack("<QIIII", 0x7FF600000000, 0x10000, 0x1234, 1700000000, name_rva) + fixed + b"\x00" * 32
    module_stream = struct.pack("<I", 1) + module
    entries.append((4, len(module_stream), module_rva))
    blobs += module_stream + struct.pack("<I", len(name)) + name + b"\x00\x00"
    header = b"MDMP" + struct.pack("<IIIIIQ", 0xA793 | (0x1234 << 16), len(entries), header_size, 0, DUMP_TIME, 0x1)
    directory = b"".join(struct.pack("<III", *entry) for entry in entries)
    return header + directory + blobs + extra_memory


NOISY_ANSI = (
    b"\x00GET http://%s/jk?c=%u&p=%s&k=%d HTTP/1.1\x00"
    b"\x001.3.6.1\x00\x002.5.4.10\x00\x001.2.840.113549\x00\x0010.0.19041.1\x00"
    b"\x00ComSpec=C:\\WINDOWS\\system32\\cmd.exe\x00COMPUTERNAME=" + "진료실1".encode("cp949") + b"\x00"
    b"\x00version 2.25.0.24\x00"
)
NOISY_UTF16 = "ComSpec=C:\\WINDOWS\\system32\\cmd.exe\x00COMPUTERNAME=진료실1\x00".encode("utf-16le")


def noisy_minidump() -> bytes:
    data = build_minidump(b"") + NOISY_ANSI
    # UTF-16 environment blocks are 2-byte aligned and NUL separated in a real process.
    data += b"\x00" * (4 + len(data) % 2)
    return data + NOISY_UTF16


class MemoryMinidumpTests(unittest.TestCase):
    def collect(self, data: bytes, name: str = "ASDSvc.exe.4536.dmp") -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_bytes(data)
            rows = list(MemoryVolatilityProvider().collect(Path(tmp)))
        self.assertEqual(len(rows), 1)
        return rows[0].details

    def test_minidump_header_streams_to_top_level_fields(self) -> None:
        details = self.collect(build_minidump(b""))
        self.assertEqual(details["timestamp"], "2025-05-28T23:35:57+00:00")
        self.assertEqual(details["dump_time"], "2025-05-28T23:35:57+00:00")
        self.assertEqual(details["pid"], 4536)
        self.assertEqual(details["process_create_time"], dt.datetime.fromtimestamp(CREATE_TIME, dt.timezone.utc).isoformat())
        self.assertEqual(details["exception_code"], "0xc0000374")
        self.assertEqual(details["exception_name"], "STATUS_HEAP_CORRUPTION")
        self.assertEqual(details["exception_address"], "0x7ffbeb03e0e5")
        self.assertEqual(details["exception_thread_id"], 4242)
        self.assertEqual(details["processor_architecture"], "AMD64")
        self.assertEqual(details["os_version"], "10.0.26100")
        self.assertEqual(details["process_name"], "ASDSvc.exe")
        self.assertEqual(details["module_count"], 1)
        module = details["minidump"]["modules"][0]
        self.assertEqual(module["file_version"], "10.0.19041.1")
        self.assertEqual(module["timestamp"], 1700000000)
        self.assertIn("minidump-header-parsed", details["risk_flags"])

    def test_printf_oid_comspec_noise_is_not_an_indicator(self) -> None:
        details = self.collect(noisy_minidump())
        pivots = details["indicator_pivots"]
        self.assertFalse([pivot for pivot in pivots if pivot["type"] == "url"])
        ips = {pivot["value"]: pivot["evidence_strength"] for pivot in pivots if pivot["type"] == "ip"}
        for noise in ("1.3.6.1", "2.5.4.10", "10.0.19041.1", "1.2.840.113"):
            self.assertNotIn(noise, ips)
        self.assertNotIn("2.25.0.24", ips)  # version string / UUID OID arc: dropped (round 2)
        self.assertFalse([pivot for pivot in pivots if pivot["type"] in {"process-candidate", "suspicious-string"}])
        self.assertEqual(details["environment_variables"]["COMPUTERNAME"], ["진료실1"])
        self.assertNotIn("network-indicator", details["risk_flags"])
        self.assertEqual(details["risk_score"], 0)
        self.assertNotIn("\u00c1\u00f8", str(details))  # no latin-1 mojibake of cp949 진료실

    def test_real_indicators_still_score(self) -> None:
        memory = b"\x00powershell.exe -enc SQBFAFgA\x00https://c2.example.test/task\x00203.0.113.9\x00mimikatz\x00"
        details = self.collect(build_minidump(memory))
        self.assertIn("process-command-line-indicator", details["risk_flags"])
        self.assertIn("credential-or-antiforensics-tool-string", details["risk_flags"])
        self.assertIn("network-indicator", details["risk_flags"])
        self.assertGreaterEqual(details["risk_score"], 60)

    def test_ip_and_printf_helpers(self) -> None:
        self.assertEqual(ipv4_indicator_strength("1.3.6.1", "\x00", "\x00"), "")
        self.assertEqual(ipv4_indicator_strength("1.2.3.4", "\x00", ".5"), "")
        self.assertEqual(ipv4_indicator_strength("1.2.3.4", "v", "\x00"), "")
        self.assertEqual(ipv4_indicator_strength("127.0.0.1", "", ""), "")
        self.assertEqual(ipv4_indicator_strength("0.0.0.0", "", ""), "")
        self.assertEqual(ipv4_indicator_strength("2.24.0.31", "", ""), "")
        self.assertEqual(ipv4_indicator_strength("192.168.0.100", " ", " "), "triage")
        self.assertEqual(ipv4_indicator_strength("203.0.113.9", "", ""), "triage")
        self.assertTrue(is_printf_template("http://%s/jk?c=%u"))
        self.assertTrue(is_printf_template("http://host/x?id=%d"))
        self.assertFalse(is_printf_template("https://example.com/a%2Fb?q=%EC%B9%B4"))


if __name__ == "__main__":
    unittest.main()
