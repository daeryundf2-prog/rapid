"""NTFS indicators: $MFT / $UsnJrnl / ADS / Recycle Bin (catalogue: Windows §6)."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Iterator, Mapping

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


@register("ntfs.si_before_fn")
class SiBeforeFn(Rule):
    """$STANDARD_INFORMATION Created earlier than $FILE_NAME Created by more than ``min_delta_seconds`` (timestomping)."""

    selector = MFT_ROWS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row_source(row) != "mft":
            return None
        times = mft_times(row)
        si, fn = times["si_created_at"], times["fn_created_at"]
        if si is None or fn is None:
            return None
        delta = (fn - si).total_seconds()
        if delta <= float(self.param("min_delta_seconds", 60)):
            return None
        return RuleResult(evidence(path=mft_path(row), si_created_at=si, fn_created_at=fn, delta_seconds=int(delta)))


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
