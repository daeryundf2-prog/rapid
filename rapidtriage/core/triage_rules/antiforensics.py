"""Anti-forensics indicators: wipers, cleaners, timestomping and disk-encryption tools (plan r3-os-depth §3.1 O1).

The signature list is the rule params (``catalog/antiforensics.yaml``, one entry per tool
with its source URL): ``products`` are regexes over a program's display name (word
boundaries, so an unrelated "… Cleaner" app never matches ``\\bccleaner\\b``),
``executables`` exact file names, ``services`` exact service names and ``commands``
regexes over command lines. ``builtin`` tools (cipher.exe, the BitLocker wizard) ship with
Windows: their file names alone are not flagged, only execution traces and command lines.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .base import (
    FlagContext,
    RowView,
    Rule,
    RuleResult,
    as_list,
    base_name,
    evidence,
    parse_time,
    register,
    select,
    under_system_dir,
)

INSTALL_TYPES = frozenset({"windows-installed-program", "registry-install-state", "uwp-package"})
SERVICE_TYPES = frozenset({"windows-service-config"})
TRACE_TYPES = frozenset(
    {
        "prefetch-file",
        "amcache-entry",
        "amcache-schema-row",
        "bam-entry",
        "bam-schema-entry",
        "userassist-schema-entry",
        "shimcache-schema-entry",
        "execution-pca",
        "execution-feature-usage",
    }
)
COMMAND_TYPES = frozenset({"powershell-history-command"})
FILE_TYPES = frozenset({"file"})
PROCESS_EVENT_IDS = frozenset({"4688", "1"})
SOURCE_LABELS = {
    "windows-installed-program": "설치 프로그램",
    "registry-install-state": "설치 상태(App Paths·MSI)",
    "uwp-package": "UWP 패키지",
    "windows-service-config": "서비스",
    "prefetch-file": "Prefetch",
    "amcache-entry": "Amcache",
    "amcache-schema-row": "Amcache",
    "bam-entry": "BAM",
    "bam-schema-entry": "BAM",
    "userassist-schema-entry": "UserAssist",
    "shimcache-schema-entry": "ShimCache",
    "execution-pca": "PCA",
    "execution-feature-usage": "FeatureUsage",
    "powershell-history-command": "PowerShell 히스토리",
    "eventlog-event": "이벤트 로그(프로세스 생성)",
    "file": "파일 이름",
}


@dataclass(frozen=True)
class Signature:
    id: str
    name: str
    category: str
    builtin: bool
    products: tuple[re.Pattern[str], ...]
    executables: frozenset[str]
    services: frozenset[str]
    commands: tuple[re.Pattern[str], ...]
    source: str


def load_signatures(raw: object) -> list[Signature]:
    signatures: list[Signature] = []
    for item in as_list(raw):
        if not isinstance(item, Mapping) or not item.get("id"):
            continue
        signatures.append(
            Signature(
                id=str(item["id"]),
                name=str(item.get("name") or item["id"]),
                category=str(item.get("category") or ""),
                builtin=bool(item.get("builtin")),
                products=tuple(re.compile(str(pattern), re.IGNORECASE) for pattern in as_list(item.get("products"))),
                executables=frozenset(str(name).casefold() for name in as_list(item.get("executables"))),
                services=frozenset(str(name).casefold() for name in as_list(item.get("services"))),
                commands=tuple(re.compile(str(pattern), re.IGNORECASE) for pattern in as_list(item.get("commands"))),
                source=str(item.get("source") or ""),
            )
        )
    return signatures


def row_candidates(row: RowView) -> tuple[list[str], list[str], list[str], list[str]]:
    """``(product names, executable names, service names, command lines)`` a row offers for matching."""
    products: list[str] = []
    executables: list[str] = []
    services: list[str] = []
    commands: list[str] = []
    kind = row.type
    if kind in INSTALL_TYPES:
        products.extend(text for text in (row.text("display_name"), row.text("application_name"), row.text("package_name")) if text)
        executables.append(base_name(row.text("executable_path")))
        if kind == "registry-install-state" and row.text("state_source") == "app-paths":
            executables.append(row.text("application_name").casefold())
    elif kind in SERVICE_TYPES:
        services.append(row.text("service_name").casefold())
        products.append(row.text("display_name"))
        executables.append(base_name(row.text("image_path")))
    elif kind == "prefetch-file":
        executables.append(row.text("executable_hint", "header_executable_name", "filename_executable_hint").casefold())
    elif kind in TRACE_TYPES:
        executables.append(base_name(row.text("executable_path", "decoded_name", "display_path", "full_path", "application")))
    elif kind in COMMAND_TYPES:
        commands.append(row.text("command", "command_line", "activity_value"))
    elif kind == "eventlog-event":
        if row.event_id() in PROCESS_EVENT_IDS:
            commands.append(row.ev_text("CommandLine", "ProcessCommandLine"))
            executables.append(base_name(row.ev_text("NewProcessName", "Image")))
    elif kind in FILE_TYPES:
        executables.append(base_name(row.text("name") or row.path()))
    return [text for text in products if text], [name for name in executables if name], [name for name in services if name], [
        text for text in commands if text
    ]


def match_signature(row: RowView, signatures: Iterable[Signature]) -> tuple[Signature, str, str] | None:
    """The first signature the row matches: ``(signature, matched field, matched value)``."""
    products, executables, services, commands = row_candidates(row)
    file_row = row.type in FILE_TYPES
    for signature in signatures:
        if file_row and (signature.builtin or under_system_dir(row.text("path") or row.path())):
            continue
        for name in executables:
            if name in signature.executables:
                return signature, "executable", name
        for name in services:
            if name in signature.services:
                return signature, "service", name
        for text in products:
            if any(pattern.search(text) for pattern in signature.products):
                return signature, "product", text
        for text in commands:
            if any(pattern.search(text) for pattern in signature.commands):
                return signature, "command", text
    return None


TOOL_ROWS = select(
    collections={"artifacts", "files"},
    types=INSTALL_TYPES | SERVICE_TYPES | TRACE_TYPES | COMMAND_TYPES | FILE_TYPES | {"eventlog-event"},
)


@register("antiforensics.tool_present")
class ToolPresent(Rule):
    """A row of an anti-forensics / disk-encryption tool from the catalogue signature list."""

    selector = TOOL_ROWS

    def prepare(self, ctx: FlagContext) -> None:
        self.signatures = load_signatures(self.param("signatures", []))

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        hit = match_signature(row, self.signatures)
        if hit is None:
            return None
        signature, field, value = hit
        return RuleResult(
            evidence(
                tool=signature.name,
                category=signature.category,
                source=SOURCE_LABELS.get(row.type, row.type),
                matched_field=field,
                matched_value=value,
                signature_source=signature.source,
            ),
            note=f"{signature.name} 흔적({SOURCE_LABELS.get(row.type, row.type)})",
        )


def run_times(row: RowView) -> list[dt.datetime]:
    """Execution times a trace row records (install/inventory rows have none)."""
    if row.type == "prefetch-file":
        values = [*as_list(row.get("last_run_times")), *(row.get(f"run_time_{index}") for index in range(1, 9))]
        if not values:
            values = [row.get("last_run_at")]
    elif row.type in {"bam-entry", "bam-schema-entry", "userassist-schema-entry"}:
        values = [row.get("timestamp", "last_run_at", "last_executed_at")]
    elif row.type == "execution-pca":
        values = [row.get("last_run_at", "event_at")]
    elif row.type in {"eventlog-event", "powershell-history-command"}:
        values = [row.get("timestamp", "time_created", "TimeCreated")]
    else:
        values = []
    moments = {moment for moment in (parse_time(value) for value in values) if moment is not None}
    return sorted(moments)


@register("antiforensics.wiper_run_after_incident")
class WiperRunAfterIncident(Rule):
    """A wiper / cleaner / timestomping tool executed after the incident start (window from the run or params)."""

    selector = select(
        collections={"artifacts"},
        types={"prefetch-file", "bam-entry", "bam-schema-entry", "userassist-schema-entry", "execution-pca", "eventlog-event", "powershell-history-command"},
    )

    def prepare(self, ctx: FlagContext) -> None:
        categories = {str(item) for item in as_list(self.param("categories", ["wiper", "cleaner", "timestomp"]))}
        self.signatures = [item for item in load_signatures(self.param("signatures", [])) if item.category in categories]
        self.start = ctx.incident_start or parse_time(self.param("incident_start"))
        end = ctx.incident_end or parse_time(self.param("incident_end"))
        self.until = end + dt.timedelta(days=float(self.param("grace_days", 30))) if end is not None else None

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if self.start is None:
            return None
        hit = match_signature(row, self.signatures)
        if hit is None:
            return None
        after = [moment for moment in run_times(row) if moment >= self.start and (self.until is None or moment <= self.until)]
        if not after:
            return None
        signature, _field, value = hit
        return RuleResult(
            evidence(
                tool=signature.name,
                category=signature.category,
                source=SOURCE_LABELS.get(row.type, row.type),
                matched_value=value,
                run_after_incident=after,
                incident_start=self.start,
            ),
            note=f"사건 시작 이후 {signature.name} 실행 {len(after)}회",
        )
