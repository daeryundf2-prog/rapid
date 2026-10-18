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
corrupt and skipped (isolated) -- the rest of the file still parses. A record
whose client data continues on the next page(s) is reassembled from them
(``spans_pages = true``, ``spanning_reassembled``); the continuation is skipped
before the next page's own records. When a continuation page is unusable the
record keeps the part read so far and is counted as unresolved.

Targets: ``target_mft_entry`` is a *candidate* computed as
``target_vcn * cluster_size / mft_record_size + cluster_block_offset * 512 /
mft_record_size``; the cluster size comes from the volume boot sector when the
caller has it (``cluster_size_basis``), else 4096 is assumed; the open attribute table that says
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
MFT_TARGET_OPS = frozenset({0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0B, 0x0C, 0x0D, 0x11, 0x13, 0x21})
# Record pages after the restart area that may be tail copies (LFS 1.1) / buffer pages (LFS 2.0):
# their LSNs are remembered so the same record found again later is not emitted twice.
TAIL_COPY_PAGES = 34

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
    reassembled_records: int = 0
    unresolved_spanning_records: int = 0
    duplicate_lsn_records: int = 0
    restart_page_offsets: list[int] = field(default_factory=list)
    lfs_version: str = ""
    cluster_size: int = 4096
    cluster_size_basis: str = "assumed-default-4096"
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
            "logfile_reassembled_record_count": self.reassembled_records,
            "logfile_unresolved_spanning_record_count": self.unresolved_spanning_records,
            "logfile_duplicate_lsn_record_count": self.duplicate_lsn_records,
            "logfile_lfs_version": self.lfs_version,
            "logfile_cluster_size": self.cluster_size,
            "logfile_cluster_size_basis": self.cluster_size_basis,
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


@dataclass
class _Header:
    """The LFS header of one log record (``client`` = the client data read so far)."""

    this_lsn: int
    previous_lsn: int
    undo_next_lsn: int
    data_length: int
    client_id: int
    record_type: int
    transaction_id: int
    flags: int
    page_offset: int
    record_offset: int
    client: bytearray = field(default_factory=bytearray)

    @property
    def missing(self) -> int:
        return self.data_length - len(self.client)


def _read_header(page: bytes, position: int, page_end: int, scan: LogFileScan) -> _Header | None:
    """The record header at ``position`` (``None`` = no further record in this page)."""
    if position + LFS_RECORD_HEADER_SIZE > page_end:
        return None
    this_lsn, previous_lsn, undo_next_lsn, data_length, client_id, record_type, transaction_id, flags = struct.unpack_from(
        "<QQQIIIIH", page, position
    )
    if this_lsn == 0:
        return None
    if record_type not in RECORD_TYPES or data_length > MAX_CLIENT_DATA:
        scan.rejected_records += 1
        return None
    return _Header(this_lsn, previous_lsn, undo_next_lsn, data_length, client_id, record_type, transaction_id, flags, 0, 0)


def _record_row(
    header: _Header,
    *,
    spans: bool,
    complete: bool,
    scan: LogFileScan,
    cluster_size: int,
    cluster_size_basis: str,
    mft_record_size: int,
) -> dict[str, object]:
    """Row of one log record; ``client`` may be partial (``complete=False``: unresolved page-spanning tail)."""
    client = bytes(header.client)
    row: dict[str, object] = {
        "source": ROW_SOURCE,
        "lsn": header.this_lsn,
        "previous_lsn": header.previous_lsn,
        "undo_next_lsn": header.undo_next_lsn,
        "client_data_length": header.data_length,
        "client_id": header.client_id,
        "record_type": RECORD_TYPES[header.record_type],
        "transaction_id": header.transaction_id,
        "spans_pages": spans,
        "page_offset": header.page_offset,
        "record_offset": header.record_offset,
    }
    if spans:
        row["spanning_reassembled"] = complete
    expected = _lsn_offset(header.this_lsn, scan.seq_number_bits)
    if expected is not None:
        row["lsn_page_match"] = header.page_offset <= expected < header.page_offset + scan.page_size
    if header.record_type == 1 and len(client) >= NTFS_CLIENT_HEADER_SIZE:
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
            row["cluster_size"] = cluster_size
            row["cluster_size_basis"] = cluster_size_basis
        names: list[dict[str, object]] = []
        partial_data = False
        if redo_op in NAME_BEARING_OPS or undo_op in NAME_BEARING_OPS:
            for offset, length in ((redo_offset, redo_length), (undo_offset, undo_length)):
                if not length or offset >= len(client):
                    continue
                if offset + length > len(client):
                    partial_data = True  # redo/undo data cut at the page end: decode what is there
                names.extend(file_name_candidates(client[offset : offset + length]))
        if partial_data:
            row["redo_undo_data_partial"] = True
        if names:
            unique = list({item["name"]: item for item in names}.values())[:MAX_NAME_CANDIDATES]
            row["file_name_candidates"] = [item["name"] for item in unique]
            row["file_name"] = unique[0]["name"]
            row["parent_entry_candidate"] = unique[0]["parent_entry"]
            times = [str(item["created_at"]) for item in unique if item.get("created_at")]
            if times:
                row["time_estimate"] = max(times)
                row["time_estimate_basis"] = "$FILE_NAME 생성 시각(파일 이름 후보)"
    row.update({"recovery_method": "parsed", "parser": PARSER_NAME, "parser_version": PARSER_VERSION})
    return row


def boot_sector_cluster_size(boot: bytes) -> int | None:
    """Cluster size from an NTFS boot sector (``bytes per sector × sectors per cluster``), else ``None``."""
    if len(boot) < 0x0E or boot[3:11] != b"NTFS    ":
        return None
    bytes_per_sector = int.from_bytes(boot[0x0B:0x0D], "little")
    raw = boot[0x0D]
    sectors = 1 << (256 - raw) if raw > 0x80 else raw
    if bytes_per_sector not in (512, 1024, 2048, 4096) or not sectors or sectors & (sectors - 1):
        return None
    size = bytes_per_sector * sectors
    return size if 512 <= size <= 2 * 1024 * 1024 else None


def _read_restart_pages(head: bytes, scan: LogFileScan) -> int:
    """Parse the restart pages in ``head``; returns the system page size (0 = none valid).

    The first page normally sits at 0 and the second one system page later. When the first one
    is unreadable (bad magic, implausible sizes, broken fixups) the second is searched at every
    plausible page size, so a damaged first restart page does not lose the restart area.
    """
    system_page_size = 0
    candidates = [0]
    tried: set[int] = set()
    fallback_added = False
    while candidates:
        candidate = candidates.pop(0)
        if candidate in tried:
            continue
        tried.add(candidate)
        valid = False
        if head[candidate : candidate + 4] == b"RSTR" and candidate + 0x30 <= len(head):
            system_page = struct.unpack_from("<I", head, candidate + 0x10)[0]
            log_page = struct.unpack_from("<I", head, candidate + 0x14)[0]
            if not (_plausible_page_size(system_page) and _plausible_page_size(log_page)):
                scan.corrupt(candidate, "재시작 페이지 크기 값이 올바르지 않음")
            elif candidate + system_page > len(head):
                scan.corrupt(candidate, "재시작 페이지가 파일 끝을 넘음")
            else:
                if candidate == 0:
                    candidates.append(system_page)
                try:
                    fixed = apply_fixups(head[candidate : candidate + system_page])
                except FixupError as exc:
                    scan.corrupt(candidate, f"재시작 페이지 픽스업 오류: {exc}")
                else:
                    valid = True
                    values = parse_restart_page(fixed)
                    scan.restart_pages += 1
                    if candidate:
                        scan.restart_page_offsets.append(candidate)
                    system_page_size = system_page_size or system_page
                    if scan.restart_current_lsn is None or values.get("current_lsn", 0) > scan.restart_current_lsn:
                        scan.restart_current_lsn = values.get("current_lsn")
                    scan.page_size = log_page
                    scan.lfs_version = f"{values.get('major_version', 0)}.{values.get('minor_version', 0)}"
                    if 0 < values.get("seq_number_bits", 0) < 64:
                        scan.seq_number_bits = values["seq_number_bits"]
                    data_offset = values.get("page_data_offset", 0)
                    if LFS_RECORD_HEADER_SIZE <= data_offset < log_page and data_offset % 8 == 0:
                        scan.page_data_offset = data_offset
        if candidate == 0 and not valid and not fallback_added:
            # Second restart page: one system page after the first (any plausible size).
            fallback_added = True
            candidates.extend(size for size in (512 << shift for shift in range(8)) if head[size : size + 4] == b"RSTR")
    if system_page_size == 0 and scan.restart_page_offsets:
        system_page_size = scan.restart_page_offsets[0]
    return system_page_size


def iter_logfile_rows(
    path: Path,
    *,
    cluster_size: int | None = None,
    mft_record_size: int = 1024,
    max_rows: int = MAX_ROWS,
    max_bytes: int = MAX_LOGFILE_BYTES,
    max_pages: int = MAX_PAGES,
    scan: LogFileScan | None = None,
    check_cancel: Callable[[], None] | None = None,
) -> Iterator[dict[str, object]]:
    """Stream ``logfile-transaction`` rows of ``path`` (pages read one at a time); ``scan`` collects counters.

    A record whose client data continues on the next page(s) is reassembled from the following
    pages' data areas (the continuation is skipped there, 8-byte aligned, before that page's own
    records); when a following page is corrupt, empty or missing the record is emitted with the
    part read so far (``spanning_reassembled = false``) and counted as unresolved. Records of the
    first :data:`TAIL_COPY_PAGES` record pages (LFS 1.1 tail copies / 2.0 buffer pages) are
    remembered by LSN, and a later copy of the same LSN is not emitted again.

    ``cluster_size`` (for ``target_mft_entry``) comes from the caller (boot sector); without it
    the default 4096 is assumed and the rows say so (``cluster_size_basis``).
    """
    scan = scan if scan is not None else LogFileScan()
    cluster_basis = "boot-sector" if cluster_size else "assumed-default-4096"
    cluster = cluster_size or 4096
    scan.cluster_size = cluster
    scan.cluster_size_basis = cluster_basis
    size = path.stat().st_size
    scan.file_size = size
    rows = 0
    tail_lsns: set[int] = set()
    with path.open("rb") as handle:
        head = handle.read(min(size, 2 * 65536 + 65536))
        system_page_size = _read_restart_pages(head, scan)
        page_size = scan.page_size
        offset = 2 * system_page_size  # 0 without a valid restart page: every page is examined
        pages = 0
        pending: _Header | None = None
        pending_page = 0

        def finish(header: _Header, *, complete: bool) -> dict[str, object]:
            if not complete:
                scan.truncated_records += 1
                scan.unresolved_spanning_records += 1
            else:
                scan.reassembled_records += 1
            return _record_row(
                header, spans=True, complete=complete, scan=scan, cluster_size=cluster,
                cluster_size_basis=cluster_basis, mft_record_size=mft_record_size,
            )

        def accept(row: dict[str, object], page_index: int) -> bool | None:
            """``True`` = yield, ``False`` = a tail-copy duplicate (dropped), ``None`` = row cap reached."""
            nonlocal rows
            lsn = int(row["lsn"])  # type: ignore[arg-type]
            if page_index < TAIL_COPY_PAGES:
                tail_lsns.add(lsn)
            elif lsn in tail_lsns:
                scan.duplicate_lsn_records += 1
                return False
            if rows >= max_rows:
                scan.row_cap_reached = True
                return None
            rows += 1
            scan.record_count += 1
            return True

        while True:
            if offset + page_size > size:
                break
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
            fixed: bytes | None = None
            if magic == b"RSTR":
                pass
            elif magic in (b"\xff\xff\xff\xff", b"\x00\x00\x00\x00"):
                scan.empty_pages += 1
            elif magic != b"RCRD":
                scan.corrupt(page_offset, f"알 수 없는 페이지 서명 {magic.hex()}")
            else:
                try:
                    fixed = apply_fixups(page)
                except FixupError as exc:
                    scan.corrupt(page_offset, f"픽스업 오류: {exc}")
            if fixed is None:
                if pending is not None:  # the continuation page is unusable: flag the record
                    row = finish(pending, complete=False)
                    pending = None
                    verdict = accept(row, pending_page)
                    if verdict is None:
                        return
                    if verdict:
                        yield row
                continue
            page_index = pages - 1  # ordinal of the page after the restart area
            scan.record_pages += 1
            data_offset = scan.page_data_offset
            next_record = struct.unpack_from("<H", fixed, 0x18)[0]
            page_end = next_record if data_offset < next_record <= page_size else page_size
            position = data_offset
            if pending is not None:
                take = min(pending.missing, page_size - data_offset)
                pending.client += fixed[data_offset : data_offset + take]
                if pending.missing > 0:
                    continue  # the record covers this whole page too
                row = finish(pending, complete=True)
                pending = None
                verdict = accept(row, pending_page)
                if verdict is None:
                    return
                if verdict:
                    yield row
                position = data_offset + ((take + 7) & ~7)
                page_end = max(page_end, position)
            for _ in range(MAX_RECORDS_PER_PAGE):
                limit = page_end
                header = _read_header(fixed, position, page_end, scan)
                if header is None and position >= page_end:
                    # ``next_record_offset`` may name the start of a record that continues on
                    # the next page: accept it when its LSN belongs to this page.
                    header = _read_header(fixed, position, page_size, scan)
                    expected = _lsn_offset(header.this_lsn, scan.seq_number_bits) if header is not None else None
                    if header is None or expected is None or not page_offset <= expected < page_offset + page_size:
                        break
                    limit = page_size
                if header is None:
                    break
                header.page_offset = page_offset
                header.record_offset = page_offset + position
                data_start = position + LFS_RECORD_HEADER_SIZE
                available = max(0, min(header.data_length, limit - data_start, page_size - data_start))
                header.client += fixed[data_start : data_start + available]
                if header.missing > 0:
                    if limit < page_size and data_start + header.data_length <= page_size:
                        # Fits in the page but runs past next_record_offset: read it whole.
                        header.client += fixed[data_start + available : data_start + header.data_length]
                    else:
                        pending = header  # continues on the next page
                        pending_page = page_index
                        break
                row = _record_row(
                    header, spans=bool(header.flags & 1), complete=True, scan=scan, cluster_size=cluster,
                    cluster_size_basis=cluster_basis, mft_record_size=mft_record_size,
                )
                verdict = accept(row, page_index)
                if verdict is None:
                    return
                if verdict:
                    yield row
                position += (LFS_RECORD_HEADER_SIZE + header.data_length + 7) & ~7
                if position >= page_size:
                    break
        if pending is not None:
            row = finish(pending, complete=False)
            if accept(row, pending_page):
                yield row
