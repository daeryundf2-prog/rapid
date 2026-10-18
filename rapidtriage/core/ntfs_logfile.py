"""Bounded NTFS ``$LogFile`` parser: RSTR / RCRD pages -> transaction rows (plan r3-os-depth §3.3).

Layout (LFS 1.1/2.0, as documented by libfsntfs "NTFS metadata files" and
the Linux-NTFS ``logfile.h``):

* restart pages (``RSTR``, normally the first two pages): update sequence
  array, chkdsk LSN, system/log page size, restart area (current LSN,
  ``seq_number_bits``, ``log_page_data_offset``, file size);
* record pages (``RCRD``): update sequence array, last LSN / file offset,
  ``next_record_offset``, then log records from ``log_page_data_offset``. A
  log record is an LFS header (``this_lsn``, previous / undo-next LSN, client
  data length, record type, transaction id, flags) followed by the NTFS client
  data: redo / undo operation codes, their data offsets and lengths, target
  attribute, LCNs, record offset, cluster block offset and target VCN.

Every page's fixups are applied and checked first; a page whose update
sequence numbers do not match, or whose magic is wrong, is counted as
corrupt and skipped (isolated) -- the rest of the file still parses. Records
are read inside one page only: a record that continues on the next page is
emitted with ``spans_pages = true`` and only the part in this page decoded.

Targets: ``target_mft_entry`` is a *candidate* computed as
``target_vcn * cluster_size / mft_record_size + cluster_block_offset * 512 /
mft_record_size`` (defaults 4096 / 1024): the open attribute table that says
which attribute ``target_attribute`` names is not replayed. File name
candidates are ``$FILE_NAME`` structures found in the redo / undo data (index
entries and file records), with their $FN created time as the time estimate.
"""

from __future__ import annotations

import datetime as dt
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

PARSER_NAME = "rapidtriage-ntfs-logfile"
PARSER_VERSION = "1"
ROW_SOURCE = "logfile-transaction"
ARTIFACT_TYPE = "ntfs-logfile-transaction"

DEFAULT_PAGE_SIZE = 4096
DEFAULT_PAGE_DATA_OFFSET = 0x40
DEFAULT_SEQ_NUMBER_BITS = 0  # unknown: LSN -> file offset check skipped
SECTOR_SIZE = 512
LFS_RECORD_HEADER_SIZE = 0x30
NTFS_CLIENT_HEADER_SIZE = 0x20
# Bounds: a real $LogFile is 2-256 MB; one page holds at most a few hundred records.
MAX_LOGFILE_BYTES = 1024 * 1024 * 1024
MAX_PAGES = 262_144
MAX_RECORDS_PER_PAGE = 512
MAX_ROWS = 2_000_000
MAX_CLIENT_DATA = 65_536
MAX_NAME_CANDIDATES = 4
CORRUPT_SAMPLE_LIMIT = 50

RECORD_TYPES = {1: "client-record", 2: "client-restart"}

# NTFS log operation codes (redo / undo).
OPERATION_NAMES: dict[int, tuple[str, str]] = {
    0x00: ("Noop", "없음"),
    0x01: ("CompensationLogRecord", "보상 레코드"),
    0x02: ("InitializeFileRecordSegment", "파일 레코드 초기화(생성)"),
    0x03: ("DeallocateFileRecordSegment", "파일 레코드 해제(삭제)"),
    0x04: ("WriteEndOfFileRecordSegment", "파일 레코드 끝 쓰기"),
    0x05: ("CreateAttribute", "속성 생성"),
    0x06: ("DeleteAttribute", "속성 삭제"),
    0x07: ("UpdateResidentValue", "상주 값 갱신"),
    0x08: ("UpdateNonresidentValue", "비상주 값 갱신"),
    0x09: ("UpdateMappingPairs", "매핑 쌍 갱신"),
    0x0A: ("DeleteDirtyClusters", "더티 클러스터 삭제"),
    0x0B: ("SetNewAttributeSizes", "속성 크기 설정"),
    0x0C: ("AddIndexEntryRoot", "인덱스 항목 추가(루트)"),
    0x0D: ("DeleteIndexEntryRoot", "인덱스 항목 삭제(루트)"),
    0x0E: ("AddIndexEntryAllocation", "인덱스 항목 추가(할당)"),
    0x0F: ("DeleteIndexEntryAllocation", "인덱스 항목 삭제(할당)"),
    0x10: ("WriteEndOfIndexBuffer", "인덱스 버퍼 끝 쓰기"),
    0x11: ("SetIndexEntryVcnRoot", "인덱스 VCN 설정(루트)"),
    0x12: ("SetIndexEntryVcnAllocation", "인덱스 VCN 설정(할당)"),
    0x13: ("UpdateFileNameRoot", "파일 이름 갱신(루트)"),
    0x14: ("UpdateFileNameAllocation", "파일 이름 갱신(할당)"),
    0x15: ("SetBitsInNonresidentBitMap", "비트맵 비트 설정"),
    0x16: ("ClearBitsInNonresidentBitMap", "비트맵 비트 해제"),
    0x17: ("HotFix", "핫픽스"),
    0x18: ("EndTopLevelAction", "최상위 작업 끝"),
    0x19: ("PrepareTransaction", "트랜잭션 준비"),
    0x1A: ("CommitTransaction", "트랜잭션 커밋"),
    0x1B: ("ForgetTransaction", "트랜잭션 잊기"),
    0x1C: ("OpenNonresidentAttribute", "비상주 속성 열기"),
    0x1D: ("OpenAttributeTableDump", "열린 속성 테이블 덤프"),
    0x1E: ("AttributeNamesDump", "속성 이름 덤프"),
    0x1F: ("DirtyPageTableDump", "더티 페이지 테이블 덤프"),
    0x20: ("TransactionTableDump", "트랜잭션 테이블 덤프"),
    0x21: ("UpdateRecordDataRoot", "레코드 데이터 갱신(루트)"),
    0x22: ("UpdateRecordDataAllocation", "레코드 데이터 갱신(할당)"),
}
# Operations whose redo / undo data carry a $FILE_NAME (index entries, file records).
NAME_BEARING_OPS = frozenset({0x02, 0x05, 0x0C, 0x0D, 0x0E, 0x0F, 0x13, 0x14})
# Operations whose target is an MFT file record (target_mft_entry is meaningful).
MFT_TARGET_OPS = frozenset({0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0B, 0x0C, 0x0D, 0x13, 0x21})

_FILETIME_MIN = 119_600_064_000_000_000  # 1980-01-01
_FILETIME_MAX = 159_017_436_000_000_000  # 2104-12-31


def operation_label(code: int) -> str:
    name = OPERATION_NAMES.get(code)
    if name is None:
        return f"알 수 없음(0x{code:02X})"
    return f"{name[1]}({name[0]})"


def operation_name(code: int) -> str:
    name = OPERATION_NAMES.get(code)
    return name[0] if name else f"Unknown0x{code:02X}"


class FixupError(ValueError):
    """The page's update sequence array does not match its sector tails."""


def apply_fixups(page: bytes, *, sector_size: int = SECTOR_SIZE) -> bytes:
    """Validate and apply the update sequence array of a multi-sector page; raises :class:`FixupError`."""
    if len(page) < 8:
        raise FixupError("페이지가 너무 짧습니다")
    usa_offset, usa_count = struct.unpack_from("<HH", page, 4)
    sectors = len(page) // sector_size
    if usa_count < 2 or usa_count - 1 != sectors or usa_offset < 8 or usa_offset + 2 * usa_count > len(page):
        raise FixupError(f"업데이트 시퀀스 배열 범위 오류(offset={usa_offset}, count={usa_count})")
    fixed = bytearray(page)
    usn = page[usa_offset : usa_offset + 2]
    for index in range(1, usa_count):
        tail = sector_size * index - 2
        if page[tail : tail + 2] != usn:
            raise FixupError(f"섹터 {index - 1} 업데이트 시퀀스 번호 불일치")
        fixed[tail : tail + 2] = page[usa_offset + 2 * index : usa_offset + 2 * index + 2]
    return bytes(fixed)


def _filetime_iso(value: int) -> str | None:
    if not _FILETIME_MIN <= value <= _FILETIME_MAX:
        return None
    seconds, ticks = divmod(value, 10_000_000)
    moment = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=seconds, microseconds=ticks // 10)
    return moment.isoformat()


def file_name_candidates(data: bytes, *, limit: int = MAX_NAME_CANDIDATES) -> list[dict[str, object]]:
    """``$FILE_NAME`` structures in ``data``: ``[{name, parent_entry, created_at}]`` (bounded, deduplicated).

    A candidate at ``p`` needs four plausible FILETIMEs at ``p+8..p+40``, a
    namespace 0-3 at ``p+65`` and a 1-255 character UTF-16 name without
    control characters at ``p+66``.
    """
    found: list[dict[str, object]] = []
    seen: set[str] = set()
    end = len(data) - 68
    position = 0
    while position <= end and len(found) < limit:
        name_length = data[position + 64]
        namespace = data[position + 65]
        if 0 < name_length and namespace <= 3 and position + 66 + 2 * name_length <= len(data):
            times = struct.unpack_from("<QQQQ", data, position + 8)
            if all(_FILETIME_MIN <= value <= _FILETIME_MAX for value in times):
                raw = data[position + 66 : position + 66 + 2 * name_length]
                try:
                    name = raw.decode("utf-16le")
                except UnicodeDecodeError:
                    name = ""
                if name and all(ch.isprintable() and ch not in "\\/:*?\"<>|" for ch in name) and name not in seen:
                    seen.add(name)
                    parent = int.from_bytes(data[position : position + 8], "little") & 0x0000FFFFFFFFFFFF
                    found.append({"name": name, "parent_entry": parent, "created_at": _filetime_iso(times[0])})
                    position += 66 + 2 * name_length
                    continue
        position += 2
    return found


@dataclass
class LogFileScan:
    """Counters of one bounded parse (the analysis summary)."""

    file_size: int = 0
    page_size: int = DEFAULT_PAGE_SIZE
    page_data_offset: int = DEFAULT_PAGE_DATA_OFFSET
    seq_number_bits: int = DEFAULT_SEQ_NUMBER_BITS
    restart_pages: int = 0
    restart_current_lsn: int | None = None
    record_pages: int = 0
    empty_pages: int = 0
    corrupt_pages: int = 0
    corrupt_samples: list[dict[str, object]] = field(default_factory=list)
    record_count: int = 0
    truncated_records: int = 0
    rejected_records: int = 0
    row_cap_reached: bool = False
    page_cap_reached: bool = False
    byte_cap_reached: bool = False

    def summary(self) -> dict[str, object]:
        return {
            "logfile_size_bytes": self.file_size,
            "logfile_page_size": self.page_size,
            "logfile_page_data_offset": self.page_data_offset,
            "logfile_seq_number_bits": self.seq_number_bits,
            "logfile_restart_page_count": self.restart_pages,
            "logfile_restart_current_lsn": self.restart_current_lsn,
            "logfile_record_page_count": self.record_pages,
            "logfile_empty_page_count": self.empty_pages,
            "logfile_corrupt_page_count": self.corrupt_pages,
            "logfile_corrupt_pages": self.corrupt_samples,
            "logfile_record_count": self.record_count,
            "logfile_truncated_record_count": self.truncated_records,
            "logfile_rejected_record_count": self.rejected_records,
            "logfile_row_cap_reached": self.row_cap_reached,
            "logfile_page_cap_reached": self.page_cap_reached,
            "logfile_byte_cap_reached": self.byte_cap_reached,
        }

    def corrupt(self, offset: int, reason: str) -> None:
        self.corrupt_pages += 1
        if len(self.corrupt_samples) < CORRUPT_SAMPLE_LIMIT:
            self.corrupt_samples.append({"page_offset": offset, "reason": reason})


def parse_restart_page(page: bytes) -> dict[str, int]:
    """Fields of a fixed-up RSTR page (system/log page size, restart area values)."""
    chkdsk_lsn, system_page_size, log_page_size, area_offset, minor, major = struct.unpack_from("<QIIHhh", page, 8)
    values: dict[str, int] = {
        "chkdsk_lsn": chkdsk_lsn,
        "system_page_size": system_page_size,
        "log_page_size": log_page_size,
        "minor_version": minor,
        "major_version": major,
    }
    if 0 < area_offset and area_offset + 0x30 <= len(page):
        current_lsn = struct.unpack_from("<Q", page, area_offset)[0]
        seq_bits = struct.unpack_from("<I", page, area_offset + 0x10)[0]
        file_size = struct.unpack_from("<Q", page, area_offset + 0x18)[0]
        data_offset = struct.unpack_from("<H", page, area_offset + 0x26)[0]
        values.update(current_lsn=current_lsn, seq_number_bits=seq_bits, file_size=file_size, page_data_offset=data_offset)
    return values


def _plausible_page_size(value: int) -> bool:
    return 512 <= value <= 65536 and not value & (value - 1)


def _lsn_offset(lsn: int, seq_bits: int) -> int | None:
    if not 0 < seq_bits < 64:
        return None
    return (lsn & ((1 << (64 - seq_bits)) - 1)) << 3


def _record_row(
    page: bytes,
    position: int,
    *,
    page_offset: int,
    page_end: int,
    scan: LogFileScan,
    cluster_size: int,
    mft_record_size: int,
) -> tuple[dict[str, object] | None, int]:
    """One log record at ``position`` -> (row or None, size consumed; 0 = stop the page)."""
    if position + LFS_RECORD_HEADER_SIZE > page_end:
        return None, 0
    this_lsn, previous_lsn, undo_next_lsn, data_length, client_id, record_type, transaction_id, flags = struct.unpack_from(
        "<QQQIIIIH", page, position
    )
    if this_lsn == 0:
        return None, 0
    if record_type not in RECORD_TYPES or data_length > MAX_CLIENT_DATA:
        scan.rejected_records += 1
        return None, 0
    total = (LFS_RECORD_HEADER_SIZE + data_length + 7) & ~7
    data_start = position + LFS_RECORD_HEADER_SIZE
    available = min(data_length, page_end - data_start)
    spans = available < data_length or bool(flags & 1)
    client = page[data_start : data_start + max(0, available)]
    row: dict[str, object] = {
        "source": ROW_SOURCE,
        "lsn": this_lsn,
        "previous_lsn": previous_lsn,
        "undo_next_lsn": undo_next_lsn,
        "client_data_length": data_length,
        "client_id": client_id,
        "record_type": RECORD_TYPES[record_type],
        "transaction_id": transaction_id,
        "spans_pages": spans,
        "page_offset": page_offset,
        "record_offset": page_offset + position,
    }
    expected = _lsn_offset(this_lsn, scan.seq_number_bits)
    if expected is not None:
        row["lsn_page_match"] = page_offset <= expected < page_offset + scan.page_size
    if record_type == 1 and len(client) >= NTFS_CLIENT_HEADER_SIZE:
        (redo_op, undo_op, redo_offset, redo_length, undo_offset, undo_length, target_attribute, lcns, record_offset,
         attribute_offset, cluster_block_offset) = struct.unpack_from("<HHHHHHHHHHH", client, 0)
        target_vcn = struct.unpack_from("<Q", client, 0x18)[0]
        row.update(
            {
                "redo_op": redo_op,
                "redo_op_name": operation_name(redo_op),
                "redo_op_label": operation_label(redo_op),
                "undo_op": undo_op,
                "undo_op_name": operation_name(undo_op),
                "undo_op_label": operation_label(undo_op),
                "redo_length": redo_length,
                "undo_length": undo_length,
                "target_attribute": target_attribute,
                "lcns_to_follow": lcns,
                "attribute_record_offset": record_offset,
                "attribute_offset": attribute_offset,
                "cluster_block_offset": cluster_block_offset,
                "target_vcn": target_vcn,
                "operation": f"{operation_label(redo_op)} / 취소: {operation_label(undo_op)}",
            }
        )
        if redo_op in MFT_TARGET_OPS or undo_op in MFT_TARGET_OPS:
            entry = (target_vcn * cluster_size + cluster_block_offset * SECTOR_SIZE) // mft_record_size
            row["target_mft_entry"] = entry
            row["target_mft_entry_basis"] = f"vcn×{cluster_size}+블록×512÷{mft_record_size}(후보)"
        names: list[dict[str, object]] = []
        if redo_op in NAME_BEARING_OPS or undo_op in NAME_BEARING_OPS:
            for offset, length in ((redo_offset, redo_length), (undo_offset, undo_length)):
                if length and offset + length <= len(client):
                    names.extend(file_name_candidates(client[offset : offset + length]))
        if names:
            unique = list({item["name"]: item for item in names}.values())[:MAX_NAME_CANDIDATES]
            row["file_name_candidates"] = [item["name"] for item in unique]
            row["file_name"] = unique[0]["name"]
            row["parent_entry_candidate"] = unique[0]["parent_entry"]
            times = [str(item["created_at"]) for item in unique if item.get("created_at")]
            if times:
                row["time_estimate"] = max(times)
                row["time_estimate_basis"] = "$FILE_NAME 생성 시각(파일 이름 후보)"
    if spans:
        scan.truncated_records += 1
    row.update({"recovery_method": "parsed", "parser": PARSER_NAME, "parser_version": PARSER_VERSION})
    return row, total


def iter_logfile_rows(
    path: Path,
    *,
    cluster_size: int = 4096,
    mft_record_size: int = 1024,
    max_rows: int = MAX_ROWS,
    max_bytes: int = MAX_LOGFILE_BYTES,
    max_pages: int = MAX_PAGES,
    scan: LogFileScan | None = None,
    check_cancel: Callable[[], None] | None = None,
) -> Iterator[dict[str, object]]:
    """Stream ``logfile-transaction`` rows of ``path`` (pages read one at a time); ``scan`` collects counters."""
    scan = scan if scan is not None else LogFileScan()
    size = path.stat().st_size
    scan.file_size = size
    rows = 0
    with path.open("rb") as handle:
        # Restart pages first: they name the page size and the record layout.
        head = handle.read(min(size, 2 * 65536))
        # The second restart page sits one system page after the first; record
        # pages start after both (2 x system page size).
        system_page_size = 0
        candidates = [0]
        while candidates:
            candidate = candidates.pop(0)
            if head[candidate : candidate + 4] != b"RSTR" or candidate + 0x30 > len(head):
                continue
            system_page = struct.unpack_from("<I", head, candidate + 0x10)[0]
            log_page = struct.unpack_from("<I", head, candidate + 0x14)[0]
            if not (_plausible_page_size(system_page) and _plausible_page_size(log_page)):
                scan.corrupt(candidate, "재시작 페이지 크기 값이 올바르지 않음")
                continue
            if candidate == 0:
                candidates.append(system_page)
            try:
                fixed = apply_fixups(head[candidate : candidate + system_page])
            except FixupError as exc:
                scan.corrupt(candidate, f"재시작 페이지 픽스업 오류: {exc}")
                continue
            values = parse_restart_page(fixed)
            scan.restart_pages += 1
            system_page_size = system_page_size or system_page
            if scan.restart_current_lsn is None or values.get("current_lsn", 0) > scan.restart_current_lsn:
                scan.restart_current_lsn = values.get("current_lsn")
            scan.page_size = log_page
            if 0 < values.get("seq_number_bits", 0) < 64:
                scan.seq_number_bits = values["seq_number_bits"]
            data_offset = values.get("page_data_offset", 0)
            if LFS_RECORD_HEADER_SIZE <= data_offset < log_page:
                scan.page_data_offset = data_offset
        page_size = scan.page_size
        offset = 2 * system_page_size
        pages = 0
        while offset + page_size <= size:
            if check_cancel is not None and pages % 256 == 0:
                check_cancel()
            if offset >= max_bytes:
                scan.byte_cap_reached = True
                break
            if pages >= max_pages:
                scan.page_cap_reached = True
                break
            handle.seek(offset)
            page = handle.read(page_size)
            pages += 1
            page_offset = offset
            offset += page_size
            magic = page[:4]
            if magic == b"RSTR":
                continue
            if magic in (b"\xff\xff\xff\xff", b"\x00\x00\x00\x00"):
                scan.empty_pages += 1
                continue
            if magic != b"RCRD":
                scan.corrupt(page_offset, f"알 수 없는 페이지 서명 {magic.hex()}")
                continue
            try:
                fixed = apply_fixups(page)
            except FixupError as exc:
                scan.corrupt(page_offset, f"픽스업 오류: {exc}")
                continue
            scan.record_pages += 1
            next_record = struct.unpack_from("<H", fixed, 0x18)[0]
            page_end = next_record if scan.page_data_offset < next_record <= page_size else page_size
            position = scan.page_data_offset
            for _ in range(MAX_RECORDS_PER_PAGE):
                row, consumed = _record_row(
                    fixed,
                    position,
                    page_offset=page_offset,
                    page_end=page_end,
                    scan=scan,
                    cluster_size=cluster_size,
                    mft_record_size=mft_record_size,
                )
                if row is None:
                    break
                if rows >= max_rows:
                    scan.row_cap_reached = True
                    return
                rows += 1
                scan.record_count += 1
                yield row
                if row["spans_pages"]:
                    break
                position += consumed
                if position >= page_end:
                    break
