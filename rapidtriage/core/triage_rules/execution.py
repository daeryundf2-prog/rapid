"""Execution-trace indicators: Prefetch / Amcache / ShimCache / BAM / SRUM (catalogue: Windows §3)."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Iterator

from ...artifacts.windows.prefetch import prefetch_executable_entry
from .base import (
    PERSISTENCE_MARKERS,
    FlagContext,
    RowRef,
    RowView,
    Rule,
    RuleResult,
    as_list,
    base_name,
    evidence,
    parse_time,
    register,
    select,
    split_windows_path,
    suspicious_command,
    under_system_dir,
    user_writable_marker,
)
from .registry import removable_letters, removable_or_network, squirrel_autostart

PREFETCH = select(types={"prefetch-file"}, kinds={"windows-prefetch"})
EXECUTION_TYPES = ("amcache-entry", "shimcache-entry", "bam-entry")
TRACES = select(types={"prefetch-file", *EXECUTION_TYPES}, kinds={"windows-prefetch", "windows-execution"})
SUSPICIOUS_EXEC_MARKERS = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
)
SYSTEM_BINARIES = (
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsm.exe",
    "spoolsv.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "conhost.exe",
    "dllhost.exe",
    "rundll32.exe",
    "cmd.exe",
    "powershell.exe",
)
SYSTEM_BINARY_DIRS = ("windows\\system32\\", "windows\\syswow64\\", "windows\\winsxs\\", "windows\\servicing\\")


def prefetch_executable_path(row: RowView) -> str:
    """The executable's own path among a Prefetch row's referenced files (``""`` when not listed).

    Uses ``executable_reference_path`` (picked by the parser from *every* decoded path, before
    the 1,000-entry inline cap), then the decoded file-metrics entries (``referenced_files[].path``)
    and the inline ``referenced_paths`` list (rows of older parser versions). A 29-character
    header name is a prefix match; an ``.exe``/``.com``/``.scr`` candidate is preferred.
    """
    name = row.text("executable_hint", "header_executable_name", "filename_executable_hint").lower()
    if not name:
        return ""
    text = row.text("executable_reference_path")
    if not text:
        decoded = [item.get("path") for item in as_list(row.get("referenced_files")) if isinstance(item, dict)]
        text = prefetch_executable_entry(name, [*decoded, *as_list(row.get("referenced_paths"))])
    if not text:
        return ""
    start = text.find("\\")
    return text[start:] if start > 0 else text


def trace_path(row: RowView) -> str:
    if row.type == "prefetch-file":
        return prefetch_executable_path(row)
    return row.text("executable_path", "decoded_name", "display_path", "full_path")


def trace_name(row: RowView) -> str:
    if row.type == "prefetch-file":
        return row.text("executable_hint", "header_executable_name", "filename_executable_hint").lower()
    return base_name(trace_path(row))


def source_label(row: RowView) -> str:
    return {"prefetch-file": "prefetch", "amcache-entry": "amcache", "shimcache-entry": "shimcache", "bam-entry": "bam"}.get(row.type, row.type)


@register("execution.suspicious_path")
class SuspiciousPath(Rule):
    """Executed from Temp/Downloads/AppData/Public/Recycle Bin or a removable drive."""

    selector = TRACES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        path = trace_path(row)
        if not path:
            return None
        lowered = "\\" + split_windows_path(path)[1]
        if any(str(prefix).lower() in lowered for prefix in self.param("exclude_markers", [])):
            return None
        reason = user_writable_marker(path, SUSPICIOUS_EXEC_MARKERS) or removable_or_network(path, removable_letters(ctx))
        if not reason:
            return None
        return RuleResult(evidence(source=source_label(row), path=path, reason=reason, last_run_at=row.text("last_run_at", "timestamp")))


@register("execution.runcount_spike")
class RunCountSpike(Rule):
    """All eight Prefetch run times within ``window_minutes``: a burst of repeated runs."""

    selector = PREFETCH

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if trace_name(row) in SYSTEM_BINARIES or under_system_dir(trace_path(row)):
            return None  # Windows components run in bursts by design
        times = sorted(moment for moment in (parse_time(value) for value in as_list(row.get("last_run_times"))) if moment is not None)
        minimum = int(self.param("min_runs", 8))
        if len(times) < minimum:
            return None
        span = times[-1] - times[0]
        if span > dt.timedelta(minutes=float(self.param("window_minutes", 60))):
            return None
        return RuleResult(
            evidence(executable=trace_name(row), run_count=row.get("run_count"), first=times[0], last=times[-1], runs_in_window=len(times)),
            note=f"최근 실행 {len(times)}회가 {int(span.total_seconds() // 60)}분 안에 몰림",
        )


@register("execution.name_mismatch")
class NameMismatch(Rule):
    """A Windows system binary name (svchost.exe, lsass.exe …) executed outside System32/SysWOW64."""

    selector = TRACES

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        path = trace_path(row)
        name = base_name(path)
        if name not in SYSTEM_BINARIES:
            return None
        _drive, rest = split_windows_path(path)
        if not rest or rest.startswith(SYSTEM_BINARY_DIRS) or "\\" not in rest:
            return None
        return RuleResult(evidence(source=source_label(row), name=name, path=path))


@register("execution.deleted_executable")
class DeletedExecutable(Rule):
    """Prefetch/Amcache/BAM executable absent from the file listing although its folder was listed."""

    selector = select(types={"prefetch-file", "amcache-entry", "bam-entry"}, kinds={"windows-prefetch", "windows-execution"})

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        path = trace_path(row)
        if not path or ctx.file_missing(path) is not True:
            return None
        return RuleResult(evidence(source=source_label(row), path=path), note="같은 폴더의 다른 파일은 목록에 있으나 이 실행 파일은 없음")


@register("execution.cross_mismatch")
class CrossMismatch(Rule):
    """ShimCache executable outside Windows/Program Files with no Prefetch or Amcache entry of that name."""

    selector = TRACES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.seen: set[str] = set()
        self.shim: list[tuple[RowRef, str]] = []

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "shimcache-entry":
            path = trace_path(row)
            if path.lower().endswith(".exe") and not under_system_dir(path):
                self.shim.append((row.ref, path))
        elif row.type in {"prefetch-file", "amcache-entry"}:
            name = trace_name(row)
            if name:
                self.seen.add(name)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        if not self.seen:
            return  # no Prefetch/Amcache at all (e.g. disabled on servers): nothing to compare
        for ref, path in self.shim:
            if base_name(path) not in self.seen:
                yield ref, RuleResult(evidence(path=path), note="ShimCache에만 있음(Prefetch/Amcache 없음)")


@register("execution.srum_bulk_upload")
class SrumBulkUpload(Rule):
    """SRUM network usage row with BytesSent ≥ ``min_bytes_sent`` for an app outside ``allowed_apps``."""

    selector = select(prefixes=("srum-",))

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        sent = row.number("bytes_sent", "BytesSent")
        if sent is None or sent < float(self.param("min_bytes_sent", 500 * 1024 * 1024)):
            return None
        app = row.text("executable_path", "app_id", "application_name")
        lowered = app.lower()
        if any(str(item).lower() in lowered for item in self.param("allowed_apps", [])):
            return None
        return RuleResult(evidence(app=app, bytes_sent=int(sent), bytes_received=row.get("bytes_received"), timestamp=row.text("timestamp")))


@register("execution.multi_source")
class MultiSource(Rule):
    """Same executable (outside Windows/Program Files) in Prefetch, Amcache and BAM: execution corroborated."""

    selector = TRACES

    def __init__(self, params=None) -> None:
        super().__init__(params)
        self.sources: dict[str, set[str]] = defaultdict(set)
        self.rows: dict[str, list[RowRef]] = defaultdict(list)

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.type == "shimcache-entry":
            return None
        path = trace_path(row)
        name = trace_name(row)
        if not name or (path and under_system_dir(path)):
            return None
        self.sources[name].add(source_label(row))
        self.rows[name].append(row.ref)
        return None

    def finalize(self, ctx: FlagContext) -> Iterator[tuple[RowRef, RuleResult]]:
        minimum = int(self.param("min_sources", 3))
        for name, sources in self.sources.items():
            if len(sources) >= minimum:
                for ref in self.rows[name]:
                    yield ref, RuleResult(evidence(executable=name, sources=sorted(sources)), note="실행 신뢰도 보강 지표(의심 아님)")


# --- R5 L2: startup items (StartupApproved registry rows and Startup-folder files) ---------------

STARTUP_ITEMS = select(types={"startup-item"}, kinds={"windows-registry", "windows-system"})


@register("execution.startup_user_path")
class StartupUserPath(Rule):
    """An enabled (or state-unknown) startup item whose command/target is in a user-writable path,
    a script, encoded PowerShell or a LOLBin (StartupApproved rows joined with Run, Startup-folder files)."""

    selector = STARTUP_ITEMS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.flag("enabled") is False:
            return None  # disabled in Task Manager: not run at logon
        command = row.text("command", "target_path")
        if not command:
            return None
        probe = "\\" + split_windows_path(command.strip('"').split('"')[0])[1]
        if any(str(marker).lower() in probe for marker in self.param("exclude_markers", [])):
            return None
        reasons = suspicious_command(command, PERSISTENCE_MARKERS)
        if row.text("item_kind") == "script":
            reasons.append("시작프로그램 폴더의 스크립트")
        if not reasons:
            return None
        name = row.text("item_name", "value_name")
        if all(reason.startswith("사용자 쓰기 경로") for reason in reasons) and squirrel_autostart(
            name, command, list(self.param("squirrel_value_prefixes", []))
        ):
            return None
        return RuleResult(
            evidence(
                item_name=name,
                command=command,
                startup_source=row.text("startup_source_label", "startup_source"),
                scope=row.text("scope"),
                reasons=reasons,
            )
        )
