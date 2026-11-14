"""NTFS indicators: $MFT / $UsnJrnl / ADS / Recycle Bin (catalogue: Windows §6)."""

from __future__ import annotations

import datetime as dt
import re
from array import array
from collections import defaultdict
from collections.abc import Iterator, Mapping

from ..ntfs_timestamps import SI_BEFORE_FN_MIN_DELTA_SECONDS
from .base import (
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_list,
    evidence,
    extension,
    parse_time,
    register,
    select,
    split_windows_path,
    user_writable_marker,
    window_groups,
)

MFT_TYPES = frozenset({"mft-record", "mft-file"})
USN_TYPES = frozenset({"usn-record"})
MFT_ROWS = select(collections={"artifacts", "analysis"}, kinds={"ntfs-meta", "windows-filesystem"})
TIME_NAMES = ("created_at", "modified_at", "mft_modified_at", "accessed_at")


def row_source(row: RowView) -> str:
    """``mft`` / ``usn`` / ``""`` for an NTFS metadata row."""
    if row.collection == "analysis":
        return row.text("source")
    if row.type in MFT_TYPES:
        return "mft"
    if row.type in USN_TYPES:
        return "usn"
    return ""


def mft_times(row: RowView) -> dict[str, dt.datetime | None]:
    """``si_*`` / ``fn_*`` times of an MFT row (analysis rows: flat keys; artifact rows: nested attributes)."""
    times: dict[str, dt.datetime | None] = {}
    si = row.get("standard_information")
    fn_entries = as_list(row.get("file_name_entries"))
    fn = fn_entries[0] if fn_entries and isinstance(fn_entries[0], Mapping) else {}
    for name in TIME_NAMES:
        times[f"si_{name}"] = parse_time(row.get(f"si_{name}")) or (parse_time(si.get(name)) if isinstance(si, Mapping) else None)
        times[f"fn_{name}"] = parse_time(row.get(f"fn_{name}")) or parse_time(fn.get(name))
    return times


def entry_key(row: RowView) -> tuple[str, int] | None:
    number = row.number("entry_number", "record_number")
    return (row.kind, int(number)) if number is not None else None


def usn_reasons(row: RowView) -> str:
    parts = [str(item) for item in as_list(row.get("reason_flags"))] or [row.text("reason")]
    return "|".join(parts).upper()


def mft_path(row: RowView) -> str:
    return row.text("path", "file_path", "name", "file_name")


SI_BEFORE_FN_SUPPRESS_PATHS = ("\\windows\\winsxs\\", "\\windows\\servicing\\", "\\windows\\softwaredistribution\\")
SI_BEFORE_FN_EXECUTABLES = ("exe", "dll", "sys", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "jar", "lnk")
_EPOCH_UTC = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
_EXTRA_DIGITS = re.compile(r"(\.\d{6})\d+")
FILETIME_FLOOR_YEAR = 1601  # FILETIME 0 (1601-01-01) = "no time"; 1970 is a real (if odd) $SI value


def ntfs_time(value: object) -> dt.datetime | None:
    """:func:`parse_time` without its 1971 floor: only FILETIME 0 (year 1601) is "no time" for $SI/$FN
    (two BSH IME files carry $SI 1970-01-02, which the analysis' own $SI/$FN check counts)."""
    moment = parse_time(value)
    if moment is not None or not isinstance(value, str):
        return moment
    try:
        moment = dt.datetime.fromisoformat(_EXTRA_DIGITS.sub(r"\1", value.strip().replace("Z", "+00:00")))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc) if moment.year > FILETIME_FLOOR_YEAR else None


def _si_fn_times(row: RowView) -> dict[str, dt.datetime | None]:
    si = row.get("standard_information")
    fn_entries = as_list(row.get("file_name_entries"))
    fn = fn_entries[0] if fn_entries and isinstance(fn_entries[0], Mapping) else {}
    times: dict[str, dt.datetime | None] = {}
    for name in ("created_at", "modified_at", "mft_modified_at"):
        times[f"si_{name}"] = ntfs_time(row.get(f"si_{name}")) or (ntfs_time(si.get(name)) if isinstance(si, Mapping) else None)
    times["fn_created_at"] = ntfs_time(row.get("fn_created_at")) or ntfs_time(fn.get("created_at"))
    return times


@register("ntfs.si_before_fn")
class SiBeforeFn(Rule):
    """$SI Created earlier than $FN Created by more than ``min_delta_seconds``, graded by corroborators.

    A plain $SI < $FN is what every timestamp-preserving copy, archive extraction and Windows servicing
    leaves (174,854 of 1,421,896 records of the BSH $MFT, R6 S4), so the catalogue grade (A) needs a
    timestomp-like corroborator:

    * ``zero_subsecond_si`` -- $SI created, modified *and* MFT-modified all have zero sub-seconds while
      $FN created has them (second-precision SetFileTime/timestomp tools; an extraction keeps the
      archive's 2-second times in created/modified, but NTFS writes MFT-modified itself);
    * ``si_changed_before_fn`` -- $SI modified *and* MFT-modified are also earlier than $FN created by
      more than the threshold (creating the name updates $SI MFT-modified; only a tool that rewrites
      all $SI times leaves it behind).

    An executable/script under a user-writable folder without those is capped at B; everything else at
    C. A hit with no corroborator is dropped (no flag) when its path is under a servicing folder
    (``suppress_path_markers``) or when it belongs to a bulk pattern: at least ``bulk_min_records``
    hits of the same source whose $FN created lies within +/-``bulk_bucket_seconds``/2 of its own (a
    sliding window, so a feature update or tree copy straddling a clock hour is still one wave; the
    count is the evidence ``bucket_hits``). Corroborated hits are never dropped (mass timestomping
    stays visible).

    Memory: the ~175k hits of a 1.4M-record $MFT are kept column-wise (epoch-microsecond
    ``array('q')`` columns, interned kind/type/marker codes, one path string each) instead of
    datetime tuples.
    """

    selector = MFT_ROWS

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.executables = frozenset(str(item).lower().lstrip(".") for item in self.param("executable_extensions", SI_BEFORE_FN_EXECUTABLES))
        self.threshold = float(self.param("min_delta_seconds", SI_BEFORE_FN_MIN_DELTA_SECONDS))
        self.bucket_seconds = max(1, int(float(self.param("bulk_bucket_seconds", 3600))))
        # Interned strings (row kind, row type, user-writable marker) -> small codes.
        self._names: list[str] = []
        self._codes: dict[str, int] = {}
        # Hit columns, one entry per candidate row.
        self._kind = array("H")
        self._type = array("H")
        self._index = array("q")
        self._si = array("q")
        self._fn = array("q")
        self._si_modified = array("q")
        self._si_changed = array("q")
        self._corroborators = array("B")  # bit 0 zero_subsecond_si, bit 1 si_changed_before_fn
        self._marker = array("H")  # code of the user-writable marker of an executable ("" = none)
        self._paths: list[str] = []

    def _code(self, text: str) -> int:
        code = self._codes.get(text)
        if code is None:
            code = self._codes[text] = len(self._names)
            self._names.append(text)
        return code

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row_source(row) != "mft":
            return None
        times = _si_fn_times(row)
        si, fn = times["si_created_at"], times["fn_created_at"]
        if si is None or fn is None:
            return None
        threshold = self.threshold
        delta = (fn - si).total_seconds()
        if delta <= threshold:
            return None
        si_modified, si_changed = times["si_modified_at"], times["si_mft_modified_at"]
        corroborators = 0
        if (
            si_modified is not None
            and si_changed is not None
            and not (si.microsecond or si_modified.microsecond or si_changed.microsecond)
            and fn.microsecond
        ):
            corroborators |= 1
        if (
            si_modified is not None
            and si_changed is not None
            and (fn - si_modified).total_seconds() > threshold
            and (fn - si_changed).total_seconds() > threshold
        ):
            corroborators |= 2
        path = mft_path(row)
        executable = ""
        if row.flag("directory") is not True and extension(path) in self.executables:
            executable = user_writable_marker(path)
        self._kind.append(self._code(row.kind))
        self._type.append(self._code(row.type))
        self._index.append(row.index)
        self._si.append(_epoch_us(si))
        self._fn.append(_epoch_us(fn))
        self._si_modified.append(_epoch_us(si_modified))
        self._si_changed.append(_epoch_us(si_changed))
        self._corroborators.append(corroborators)
        self._marker.append(self._code(executable))
        self._paths.append(path)
        return None

    @property
    def candidate_count(self) -> int:
        """Rows read so far with $SI created < $FN created by more than the threshold (before grading/suppression);
        ``scripts/rule-validation.py`` compares it with the analysis' own ``si_created_before_fn`` count."""
        return len(self._paths)

    def window_counts(self) -> list[int]:
        """Per hit: hits of the same row kind whose $FN created lies within +/-``bulk_bucket_seconds``/2
        of its own, itself included (sort by (kind, $FN created), then a two-pointer sweep: O(n log n))."""
        half = self.bucket_seconds * 1_000_000 // 2
        kinds, fns = self._kind, self._fn
        order = sorted(range(len(fns)), key=lambda position: (kinds[position], fns[position]))
        counts = [0] * len(order)
        low = high = 0
        for current, position in enumerate(order):
            kind, moment = kinds[position], fns[position]
            if kinds[order[low]] != kind:  # first hit of the next kind
                low = current
            while fns[order[low]] < moment - half:
                low += 1
            high = max(high, current)
            while high + 1 < len(order) and kinds[order[high + 1]] == kind and fns[order[high + 1]] <= moment + half:
                high += 1
            counts[position] = high - low + 1
        return counts

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult, str]]:
        bulk_min = int(self.param("bulk_min_records", 500))
        markers = tuple(str(item).lower() for item in self.param("suppress_path_markers", SI_BEFORE_FN_SUPPRESS_PATHS))
        counts = self.window_counts()
        names = self._names
        for position, path in enumerate(self._paths):
            window_hits = counts[position]
            corroborator_bits = self._corroborators[position]
            if not corroborator_bits:
                probe = "\\" + split_windows_path(path)[1]
                if window_hits >= bulk_min or any(marker in probe for marker in markers):
                    continue  # servicing / bulk copy pattern: informational only, no flag
            ref = (names[self._kind[position]], self._index[position])
            row_type = names[self._type[position]]
            si, fn = self._si[position], self._fn[position]
            fields = {
                "path": path,
                "si_created_at": _from_epoch_us(si),
                "fn_created_at": _from_epoch_us(fn),
                "delta_seconds": (fn - si) // 1_000_000,
                "si_modified_at": _from_epoch_us(self._si_modified[position]),
                "si_mft_modified_at": _from_epoch_us(self._si_changed[position]),
            }
            if corroborator_bits:
                corroborators = [name for bit, name in CORROBORATOR_BITS if corroborator_bits & bit]
                note = "타임스톰핑 정황: " + ", ".join(CORROBORATOR_LABELS[name] for name in corroborators)
                yield ref, RuleResult(evidence(**fields, corroborators=corroborators, bucket_hits=window_hits), note=note), row_type
                continue
            executable = names[self._marker[position]]
            if executable:
                note = f"보강 근거 없음: 사용자 쓰기 가능 경로({executable})의 실행·스크립트 파일"
                yield ref, RuleResult(evidence(**fields, bucket_hits=window_hits), note=note, grade="B"), row_type
            else:
                note = "보강 근거 없음: 시각 보존 복사·압축 해제에서도 흔한 모양"
                yield ref, RuleResult(evidence(**fields, bucket_hits=window_hits), note=note, grade="C"), row_type


NO_TIME_US = -(2**63)  # array('q') sentinel: missing $SI modified / MFT-modified
_US = dt.timedelta(microseconds=1)
CORROBORATOR_BITS = ((1, "zero_subsecond_si"), (2, "si_changed_before_fn"))


def _epoch_us(moment: dt.datetime | None) -> int:
    """Aware UTC datetime -> integer microseconds since 1970 (``NO_TIME_US`` for ``None``)."""
    return NO_TIME_US if moment is None else (moment - _EPOCH_UTC) // _US


def _from_epoch_us(value: int) -> dt.datetime | None:
    return None if value == NO_TIME_US else _EPOCH_UTC + dt.timedelta(microseconds=value)


CORROBORATOR_LABELS = {
    "zero_subsecond_si": "$SI 생성·수정·MFT 수정 초 미만 0($FN은 아님)",
    "si_changed_before_fn": "$SI 수정·MFT 수정도 $FN 생성보다 앞섬",
}


@register("ntfs.zero_subsecond")
class ZeroSubsecond(Rule):
    """$SI Created and Modified with zero sub-seconds while $FN Created has sub-seconds (second-precision tool)."""

    selector = MFT_ROWS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row_source(row) != "mft":
            return None
        times = mft_times(row)
        si_created, si_modified, fn_created = times["si_created_at"], times["si_modified_at"], times["fn_created_at"]
        if si_created is None or si_modified is None or fn_created is None:
            return None
        if si_created.microsecond or si_modified.microsecond or not fn_created.microsecond:
            return None
        return RuleResult(evidence(path=mft_path(row), si_created_at=si_created, si_modified_at=si_modified, fn_created_at=fn_created))


class _UsnMftJoin(Rule):
    """MFT rows and USN rows of the same source joined on the MFT entry number in ``finalize``."""

    selector = MFT_ROWS

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.mft: dict[tuple[str, int], dict[str, dt.datetime | None]] = {}
        self.usn: list[tuple[RowRef, tuple[str, int], dt.datetime, str, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        source = row_source(row)
        key = entry_key(row)
        if key is None:
            return None
        if source == "mft":
            self.mft[key] = mft_times(row)
        elif source == "usn":
            moment = row.time("timestamp")
            reasons = usn_reasons(row)
            if moment is not None and self.wants(reasons):
                self.usn.append((row.ref, key, moment, reasons, mft_path(row)))
        return None

    def wants(self, reasons: str) -> bool:
        raise NotImplementedError


@register("ntfs.fn_manipulation")
class FnManipulation(_UsnMftJoin):
    """After a USN RENAME_NEW_NAME the $FN change time should follow the rename; a $FN time far from it suggests $FN timestomping."""

    def wants(self, reasons: str) -> bool:
        return "RENAME_NEW_NAME" in reasons

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        tolerance = dt.timedelta(seconds=float(self.param("tolerance_seconds", 2)))
        latest: dict[tuple[str, int], tuple[RowRef, dt.datetime, str]] = {}
        for ref, key, moment, _reasons, path in self.usn:
            if key not in latest or moment > latest[key][1]:
                latest[key] = (ref, moment, path)
        for key, (ref, moment, path) in latest.items():
            times = self.mft.get(key)
            fn_changed = times.get("fn_mft_modified_at") if times else None
            if fn_changed is not None and fn_changed < moment - tolerance:
                yield ref, RuleResult(evidence(path=path, rename_at=moment, fn_mft_modified_at=fn_changed), note="마지막 이름 변경보다 $FN 변경 시각이 앞섬")


@register("ntfs.usn_basic_info_change")
class UsnBasicInfoChange(_UsnMftJoin):
    """USN BASIC_INFO_CHANGE whose entry's $SI Modified lies more than ``backdate_days`` before the change (never alone)."""

    def wants(self, reasons: str) -> bool:
        return "BASIC_INFO_CHANGE" in reasons

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        backdate = dt.timedelta(days=float(self.param("backdate_days", 1)))
        for ref, key, moment, reasons, path in self.usn:
            times = self.mft.get(key)
            si_modified = times.get("si_modified_at") if times else None
            if si_modified is not None and si_modified < moment - backdate:
                yield ref, RuleResult(
                    evidence(path=path, usn_time=moment, si_modified_at=si_modified, reasons=reasons),
                    note="속성 변경과 같은 플래그: 단독 판단 금지",
                )


@register("ntfs.time_inversion")
class TimeInversion(Rule):
    """$SI Modified earlier than $SI Created (typical of copies, also of manipulation)."""

    selector = MFT_ROWS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row_source(row) != "mft":
            return None
        times = mft_times(row)
        created, modified = times["si_created_at"], times["si_modified_at"]
        if created is None or modified is None or modified >= created - dt.timedelta(seconds=1):
            return None
        return RuleResult(evidence(path=mft_path(row), si_created_at=created, si_modified_at=modified))


@register("ntfs.ads_executable")
class AdsExecutable(Rule):
    """Alternate data stream (not Zone.Identifier) whose content is a PE (MZ) file."""

    selector = select(types={"ads-stream-candidate"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        stream = row.text("stream_name")
        if stream.lower().strip(":").startswith("zone.identifier"):
            return None
        kind = row.text("detected_signature_kind", "stream_family").lower()
        header = row.text("header_hex", "signature_hex").lower()
        if kind not in {"pe", "windows-pe", "exe", "dll", "mz", "pe-executable", "executable"} and not header.startswith("4d5a"):
            return None
        return RuleResult(evidence(host=row.text("host_file_path", "host_file_name", "target_name"), stream_name=stream, signature=kind or header[:8]))


@register("ntfs.zone_identifier")
class ZoneIdentifierInternet(Rule):
    """Zone.Identifier ZoneId=3 (Internet) with a HostUrl: where the file was downloaded from."""

    selector = select(types={"zone-identifier"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        zone = row.text("zone_id", "app_zone_id")
        url = row.text("host_url")
        if zone != "3" or not url:
            return None
        return RuleResult(evidence(file=row.text("host_file_path", "host_file_name", "target_name"), zone_id=zone, host_url=url, referrer=row.text("referrer_url")))


@register("ntfs.deletion_trace")
class DeletionTrace(Rule):
    """Recycle-Bin $I record or deleted MFT entry of a document/archive/image (``sensitive_extensions``)."""

    selector = select(types={"recycle-bin-entry", "mft-record", "mft-file"}, collections={"artifacts", "analysis"}, kinds=None)

    def accepts(self, collection: str, source_kind: str, artifact_type: str) -> bool:
        if collection == "analysis":
            return source_kind == "ntfs-meta"
        return super().accepts(collection, source_kind, artifact_type)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        sensitive = {str(item).lower().lstrip(".") for item in self.param("sensitive_extensions", [])}
        if row.type == "recycle-bin-entry":
            path = row.text("original_path")
            if extension(path) in sensitive:
                return RuleResult(evidence(original_path=path, deleted_at=row.text("deleted_at"), size=row.get("deleted_file_size")))
            return None
        if row_source(row) != "mft" or row.flag("in_use") is not False or row.flag("directory") is True:
            return None
        path = mft_path(row)
        if extension(path) in sensitive:
            return RuleResult(evidence(path=path, entry_number=row.get("entry_number", "record_number")), note="미할당(삭제) MFT 엔트리")
        return None


@register("ntfs.mass_change")
class MassChange(Rule):
    """≥ ``min_count`` USN RENAME/DELETE records within ``window_seconds`` (ransomware/wiping pattern)."""

    selector = MFT_ROWS

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.events: dict[str, list[tuple[dt.datetime, RowRef]]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row_source(row) != "usn":
            return None
        reasons = usn_reasons(row)
        if "RENAME" not in reasons and "FILE_DELETE" not in reasons:
            return None
        moment = row.time("timestamp")
        if moment is not None:
            self.events[row.kind].append((moment, row.ref))
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        window = dt.timedelta(seconds=float(self.param("window_seconds", 60)))
        minimum = int(self.param("min_count", 1000))
        for items in self.events.values():
            for group in window_groups(items, window, minimum):
                first, last = group[0][0], group[-1][0]
                for _moment, ref in group:
                    yield ref, RuleResult(evidence(burst_count=len(group), burst_start=first, burst_end=last))
