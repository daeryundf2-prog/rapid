from __future__ import annotations

import datetime as dt
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

from .audit import compute_sha256
from .input_root import InputRoot, resolve_input_root

COLLECT_PLAN_VERSION = "1.0"
MAX_MATCHES_PER_TARGET = 50
DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT = 5000
DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
BROAD_DIRECTORY_LABELS = {
    "Windows user profiles",
    "Registry hive directory",
    "macOS user profiles",
}


class CollectPlanError(ValueError):
    """Raised when a collect-plan request cannot be built."""


@dataclass(frozen=True)
class CollectTarget:
    category: str
    label: str
    relative_path: str
    kind: str
    artifact_kind: str
    recommended_action: str
    notes: str = ""


WINDOWS_TARGETS: tuple[CollectTarget, ...] = (
    CollectTarget(
        "EventLogs",
        "Windows EVTX log directory",
        "Windows/System32/winevt/Logs",
        "directory",
        "eventlog",
        "scan-or-import",
        "Binary EVTX files are inventoried; export XML/JSON/CSV with EvtxECmd, Hayabusa, Chainsaw, or Velociraptor for normalized rows.",
    ),
    CollectTarget(
        "EventLogs",
        "External event log parser exports",
        "analysis/*event*",
        "glob",
        "eventlog",
        "import",
        "Use this for Hayabusa/Chainsaw/EvtxECmd/Velociraptor exports placed next to the mounted image.",
    ),
    CollectTarget(
        "AccountUsage",
        "Windows user profiles",
        "Users",
        "directory",
        "windows-os-account",
        "scan",
        "Profiles, NTUSER.DAT, UsrClass.dat, Recent items, browser data, and PowerShell history normally fan out below this path.",
    ),
    CollectTarget(
        "AccountUsage",
        "Registry hive directory",
        "Windows/System32/config",
        "directory",
        "windows-os-account",
        "scan-or-export",
        "SYSTEM/SOFTWARE/SAM/SECURITY hives support computer/account/timezone and execution context when exported.",
    ),
    CollectTarget(
        "AccountUsage",
        "Per-user NTUSER.DAT hives",
        "Users/*/NTUSER.DAT",
        "glob",
        "windows-os-account",
        "scan-or-export",
        "User hives are high value for UserAssist, Run keys, ShellBags, typed paths, and account-specific settings.",
    ),
    CollectTarget(
        "BrowserHistory",
        "Chromium browser profiles",
        "Users/*/AppData/Local/*/*/User Data/*/History",
        "glob",
        "browser",
        "scan",
        "Chrome, Edge, Brave, and Chromium-style History SQLite databases are searched from user profiles.",
    ),
    CollectTarget(
        "BrowserHistory",
        "Firefox profiles",
        "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
        "glob",
        "browser",
        "scan",
        "Firefox places.sqlite contains history and download-related browsing context.",
    ),
    CollectTarget(
        "EvidenceOfExecution",
        "PowerShell PSReadLine history",
        "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        "glob",
        "windows-execution",
        "scan",
        "Fast signal for interactive commands, LotL behavior, staged downloads, and cleanup attempts.",
    ),
    CollectTarget(
        "EvidenceOfExecution",
        "Windows Prefetch directory",
        "Windows/Prefetch",
        "directory",
        "windows-prefetch",
        "scan",
        "Prefetch parsing provides executable hints, best-effort run counts, last run times, and referenced path pivots.",
    ),
    CollectTarget(
        "EvidenceOfExecution",
        "Amcache hive",
        "Windows/AppCompat/Programs/Amcache.hve",
        "file",
        "windows-execution",
        "export-or-import",
        "Export with a trusted parser for normalized execution rows.",
    ),
    CollectTarget(
        "EvidenceOfExecution",
        "SRUM database",
        "Windows/System32/sru/SRUDB.dat",
        "file",
        "windows-execution",
        "inventory-or-export",
        "Preserve SRUDB.dat for ESE header/hash/string pivots; export with SrumECmd or libesedb/esedbexport for full application resource and network usage rows.",
    ),
    CollectTarget(
        "SearchIndex",
        "Windows Search EDB",
        "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
        "file",
        "windows-search-index",
        "inventory-or-export",
        "Preserve Windows.edb for ESE header/hash/string pivots; export CSV/JSON with WinSearchDBAnalyzer, ESEDatabaseView, or libesedb/esedbexport for normalized keyword-search rows.",
    ),
    CollectTarget(
        "SearchIndex",
        "Windows Search parser exports",
        "analysis/*search*",
        "glob",
        "windows-search-index",
        "import",
        "Place Windows Search CSV, JSON, JSONL, or NDJSON exports here to index paths, titles, URLs, and content snippets.",
    ),
    CollectTarget(
        "Persistence",
        "Task Scheduler XML tasks",
        "Windows/System32/Tasks",
        "directory",
        "windows-system",
        "scan",
        "Scheduled tasks provide persistence, execution, author, user SID, command, and trigger clues.",
    ),
    CollectTarget(
        "Persistence",
        "Startup folders",
        "Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
        "glob",
        "recent-files",
        "scan",
        "Startup entries are quick persistence review targets.",
    ),
    CollectTarget(
        "Persistence",
        "WMI repository",
        "Windows/System32/wbem/Repository",
        "directory",
        "windows-system",
        "review",
        "Useful for WMI persistence; RapidTriage extracts bounded string pivots, but preserve it for dedicated WMI parser validation.",
    ),
    CollectTarget(
        "RemoteAccess",
        "Remote Desktop cache",
        "Users/*/AppData/Local/Microsoft/Terminal Server Client/Cache",
        "glob",
        "windows-remote-access",
        "review",
        "RDP cache artifacts can support remote-access review and screenshots/thumbnails workflows.",
    ),
    CollectTarget(
        "RemoteAccess",
        "Default RDP connection files",
        "Users/*/Documents/*.rdp",
        "glob",
        "windows-remote-access",
        "scan",
        "RDP files can expose full address, username hint, gateway host, display mode, and modified time.",
    ),
    CollectTarget(
        "RemoteAccess",
        "Remote-access application logs",
        "ProgramData/*/*log*",
        "glob",
        "docs",
        "search",
        "TeamViewer, AnyDesk, VPN, EDR, and support-tool logs often land under ProgramData vendor folders.",
    ),
    CollectTarget(
        "FileSystemTimeline",
        "Master File Table",
        "$MFT",
        "file",
        "windows-filesystem",
        "inventory-or-export",
        "Native $MFT files are hashed and scanned for bounded FILE header/path pivots; external CSV/JSON exports remain best for full timeline decoding.",
    ),
    CollectTarget(
        "FileSystemTimeline",
        "USN Journal",
        "$Extend/$UsnJrnl/$J",
        "file",
        "windows-filesystem",
        "inventory-or-export",
        "Native USN journal files are hashed and recoverable v2/v3 records are emitted; external parser exports remain best for full validation.",
    ),
    CollectTarget(
        "FileSystemTimeline",
        "Recycle Bin",
        "$Recycle.Bin",
        "directory",
        "recent-files",
        "scan",
        "Deleted-file names and paths are high-value triage clues.",
    ),
    CollectTarget(
        "FileSystemTimeline",
        "MFT/USN parser exports",
        "analysis/*",
        "glob",
        "windows-filesystem",
        "import",
        "Place MFT/USN CSV, JSON, JSONL, or NDJSON exports here for normalized filesystem timeline import.",
    ),
    CollectTarget(
        "CloudAndSync",
        "Common sync folders",
        "Users/*/*Drive*",
        "glob",
        "cloud-export",
        "scan",
        "OneDrive, Google Drive, iCloud Drive, and similar folders can hold synced evidence and metadata exports.",
    ),
)

MACOS_TARGETS: tuple[CollectTarget, ...] = (
    CollectTarget(
        "AccountUsage",
        "macOS user profiles",
        "Users",
        "directory",
        "macos-system",
        "scan",
        "User homes provide browser, quarantine, LaunchAgent, documents, downloads, and review context.",
    ),
    CollectTarget(
        "BrowserHistory",
        "Safari history databases",
        "Users/*/Library/Safari/History.db",
        "glob",
        "macos-system",
        "scan",
        "Safari History.db is normalized by macos-system when present.",
    ),
    CollectTarget(
        "BrowserHistory",
        "Chromium browser profiles",
        "Users/*/Library/Application Support/*/*/History",
        "glob",
        "macos-system",
        "scan",
        "Chrome, Edge, Brave, and Chromium-style profile databases are searched from user homes.",
    ),
    CollectTarget(
        "BrowserHistory",
        "Firefox profiles",
        "Users/*/Library/Application Support/Firefox/Profiles/*/places.sqlite",
        "glob",
        "macos-system",
        "scan",
        "Firefox places.sqlite contains history and download-related browsing context.",
    ),
    CollectTarget(
        "EvidenceOfExecution",
        "LaunchServices quarantine database",
        "Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
        "glob",
        "macos-system",
        "scan",
        "Quarantine events help trace downloaded files back to agents and origin URLs.",
    ),
    CollectTarget(
        "Persistence",
        "User LaunchAgents",
        "Users/*/Library/LaunchAgents",
        "glob",
        "macos-system",
        "scan",
        "User LaunchAgents are common persistence and auto-run targets.",
    ),
    CollectTarget(
        "Persistence",
        "System LaunchDaemons",
        "Library/LaunchDaemons",
        "directory",
        "macos-system",
        "scan",
        "System LaunchDaemons provide machine-wide persistence clues.",
    ),
    CollectTarget(
        "FileSystemTimeline",
        "User Trash folders",
        "Users/*/.Trash",
        "glob",
        "files",
        "scan",
        "Deleted-file staging area for user-level recovery and intent review.",
    ),
    CollectTarget(
        "RemoteAccess",
        "Remote login and shell history candidates",
        "Users/*/.*history",
        "glob",
        "docs",
        "search",
        "Shell history is useful for remote login, command execution, and cleanup review when present.",
    ),
    CollectTarget(
        "CloudAndSync",
        "macOS cloud and sync folders",
        "Users/*/Library/Mobile Documents",
        "glob",
        "cloud-export",
        "scan",
        "iCloud Drive and Mobile Documents can contain synchronized user evidence.",
    ),
)

PROFILE_TARGETS: Mapping[str, tuple[CollectTarget, ...]] = {
    "windows-core": WINDOWS_TARGETS,
    "macos-core": MACOS_TARGETS,
    "intrusion": tuple(
        target
        for target in WINDOWS_TARGETS + MACOS_TARGETS
        if target.category in {"EventLogs", "EvidenceOfExecution", "Persistence", "RemoteAccess", "AccountUsage", "SearchIndex"}
    ),
    "browser-history": tuple(
        target for target in WINDOWS_TARGETS + MACOS_TARGETS if target.category in {"BrowserHistory", "CloudAndSync"}
    ),
    "filesystem-timeline": tuple(
        target for target in WINDOWS_TARGETS + MACOS_TARGETS if target.category == "FileSystemTimeline"
    ),
    "full": WINDOWS_TARGETS + MACOS_TARGETS,
}


def supported_collect_profiles() -> tuple[str, ...]:
    return tuple(PROFILE_TARGETS.keys())


def build_collect_plan(root: Path | InputRoot, *, profile: str = "full", input_kind: str | None = None) -> Dict[str, object]:
    normalized_profile = profile.strip().lower()
    if normalized_profile not in PROFILE_TARGETS:
        supported = ", ".join(supported_collect_profiles())
        raise CollectPlanError(f"unsupported collect profile: {profile} (supported: {supported})")

    input_root = resolve_input_root(root, kind=input_kind)
    root_path = input_root.root_path
    if root_path.exists() and not root_path.is_dir():
        raise CollectPlanError("collect-plan expects a mounted/exported folder root, not an evidence container file")

    targets = [describe_target(root_path, target) for target in PROFILE_TARGETS[normalized_profile]]
    return {
        "command": "collect-plan",
        "schema_version": COLLECT_PLAN_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": normalized_profile,
        "root": str(root_path),
        "input_root": input_root.to_dict(),
        "summary": summarize_targets(targets),
        "targets": targets,
        "next_steps": build_next_steps(targets),
    }


def run_collect_export(
    root: Path | InputRoot,
    output_dir: Path,
    *,
    profile: str = "intrusion",
    input_kind: str | None = None,
    copy_files: bool = False,
    max_file_count: int = DEFAULT_COLLECT_EXPORT_MAX_FILE_COUNT,
    max_total_bytes: int = DEFAULT_COLLECT_EXPORT_MAX_TOTAL_BYTES,
    overwrite: bool = False,
) -> Dict[str, object]:
    plan = build_collect_plan(root, profile=profile, input_kind=input_kind)
    root_path = Path(plan["root"])
    evidence_dir = output_dir / "evidence"
    output_dir.mkdir(parents=True, exist_ok=True)
    if copy_files:
        evidence_dir.mkdir(parents=True, exist_ok=True)

    entries: list[Dict[str, object]] = []
    skipped: list[Dict[str, object]] = []
    copied_bytes = 0
    seen_sources: set[str] = set()

    for target in plan["targets"]:
        if not bool(target.get("exists")):
            skipped.append(skip_record(target, reason="missing-target"))
            continue
        if target.get("label") in BROAD_DIRECTORY_LABELS:
            skipped.append(skip_record(target, reason="broad-directory-inventory-only"))
            continue
        for source_path in iter_target_export_files(target):
            source_key = str(source_path.resolve())
            if source_key in seen_sources:
                skipped.append(skip_record(target, source_path=source_path, reason="duplicate-source"))
                continue
            seen_sources.add(source_key)
            if source_path.is_symlink():
                skipped.append(skip_record(target, source_path=source_path, reason="symlink-skipped"))
                continue
            if not source_path.exists() or not source_path.is_file():
                skipped.append(skip_record(target, source_path=source_path, reason="not-a-file"))
                continue
            try:
                source_stat = source_path.stat()
            except (OSError, PermissionError) as exc:
                skipped.append(skip_record(target, source_path=source_path, reason="stat-failed", error=str(exc)))
                continue
            if max_file_count and len(entries) >= max_file_count:
                skipped.append(skip_record(target, source_path=source_path, reason="max-file-count"))
                continue
            if max_total_bytes and copied_bytes + source_stat.st_size > max_total_bytes:
                skipped.append(skip_record(target, source_path=source_path, reason="max-total-bytes"))
                continue

            relative_path = safe_relative(source_path, root_path)
            destination_path = evidence_dir / relative_path
            entry = {
                "category": target["category"],
                "artifact_kind": target["artifact_kind"],
                "target_label": target["label"],
                "source_path": str(source_path),
                "relative_path": relative_path,
                "destination_path": str(destination_path),
                "size": source_stat.st_size,
                "modified_at": dt.datetime.fromtimestamp(source_stat.st_mtime, dt.timezone.utc).isoformat(),
                "sha256": compute_sha256(source_path),
                "copied": False,
            }
            if copy_files:
                if destination_path.exists() and not overwrite:
                    skipped.append(skip_record(target, source_path=source_path, reason="destination-exists"))
                    continue
                try:
                    destination_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_path, destination_path)
                except (OSError, PermissionError) as exc:
                    skipped.append(skip_record(target, source_path=source_path, reason="copy-failed", error=str(exc)))
                    continue
                entry["copied"] = True
                entry["destination_sha256"] = compute_sha256(destination_path)
                copied_bytes += source_stat.st_size
            else:
                skipped.append(skip_record(target, source_path=source_path, reason="dry-run"))
            entries.append(entry)

    return {
        "command": "collect-export",
        "schema_version": COLLECT_PLAN_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": plan["profile"],
        "root": str(root_path),
        "output_dir": str(output_dir),
        "evidence_dir": str(evidence_dir),
        "safety": {
            "copy_files": copy_files,
            "max_file_count": max_file_count,
            "max_total_bytes": max_total_bytes,
            "overwrite": overwrite,
            "broad_directory_labels_skipped": sorted(BROAD_DIRECTORY_LABELS),
        },
        "summary": {
            "planned_target_count": plan["summary"]["target_count"],
            "present_target_count": plan["summary"]["present_count"],
            "selected_file_count": len(entries),
            "copied_file_count": sum(1 for entry in entries if entry.get("copied")),
            "skipped_count": len(skipped),
            "copied_bytes": copied_bytes,
        },
        "plan": plan,
        "entries": entries,
        "skipped": skipped,
        "next_steps": [
            f"Re-ingest copied evidence with: rapidtriage run {evidence_dir} --mode hacking --read-only",
            "Review skipped rows before treating the export as complete.",
        ],
    }


def describe_target(root: Path, target: CollectTarget) -> Dict[str, object]:
    base = {
        "category": target.category,
        "label": target.label,
        "relative_path": target.relative_path,
        "kind": target.kind,
        "artifact_kind": target.artifact_kind,
        "recommended_action": target.recommended_action,
        "notes": target.notes,
    }
    if target.kind == "glob":
        matches = sorted(root.glob(target.relative_path), key=lambda item: item.as_posix().lower())
        visible_matches = [describe_path(match, root) for match in matches[:MAX_MATCHES_PER_TARGET]]
        base.update(
            {
                "path": str(root / target.relative_path),
                "exists": bool(matches),
                "match_count": len(matches),
                "matches": visible_matches,
                "truncated": len(matches) > MAX_MATCHES_PER_TARGET,
            }
        )
        return base

    path = root / target.relative_path
    base.update(describe_path(path, root))
    base["exists"] = path.exists()
    return base


def iter_target_export_files(target: Mapping[str, object]) -> Iterable[Path]:
    if target.get("kind") == "glob":
        for match in target.get("matches", []):
            if not isinstance(match, Mapping) or not match.get("path"):
                continue
            yield from iter_exportable_files(Path(str(match["path"])))
        return
    if target.get("path"):
        yield from iter_exportable_files(Path(str(target["path"])))


def iter_exportable_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        return
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if entry.is_symlink():
                yield entry
                continue
            if entry.is_dir():
                pending.append(entry)
            elif entry.is_file():
                yield entry


def skip_record(
    target: Mapping[str, object],
    *,
    reason: str,
    source_path: Path | None = None,
    error: str | None = None,
) -> Dict[str, object]:
    record = {
        "category": target.get("category"),
        "artifact_kind": target.get("artifact_kind"),
        "target_label": target.get("label"),
        "source_path": str(source_path) if source_path else target.get("path"),
        "reason": reason,
    }
    if error:
        record["error"] = error
    return record


def describe_path(path: Path, root: Path) -> Dict[str, object]:
    record: Dict[str, object] = {
        "path": str(path),
        "relative_path": safe_relative(path, root),
        "exists": path.exists(),
    }
    if not path.exists():
        return record
    try:
        stat_result = path.stat()
    except (OSError, PermissionError):
        record["error"] = "stat-failed"
        return record
    if path.is_dir():
        record["path_kind"] = "directory"
        record["direct_child_count"] = count_direct_children(path)
    elif path.is_file():
        record["path_kind"] = "file"
        record["size"] = stat_result.st_size
    else:
        record["path_kind"] = "other"
    record["modified_at"] = dt.datetime.fromtimestamp(stat_result.st_mtime, dt.timezone.utc).isoformat()
    return record


def safe_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def count_direct_children(path: Path) -> int:
    try:
        return sum(1 for _ in path.iterdir())
    except (OSError, PermissionError):
        return 0


def summarize_targets(targets: Sequence[Mapping[str, object]]) -> Dict[str, object]:
    present = [target for target in targets if bool(target.get("exists"))]
    missing = [target for target in targets if not bool(target.get("exists"))]
    category_counts: Dict[str, Dict[str, int]] = {}
    artifact_counts: Dict[str, Dict[str, int]] = {}
    for target in targets:
        increment_summary(category_counts, str(target["category"]), bool(target.get("exists")))
        increment_summary(artifact_counts, str(target["artifact_kind"]), bool(target.get("exists")))
    return {
        "target_count": len(targets),
        "present_count": len(present),
        "missing_count": len(missing),
        "category_counts": category_counts,
        "artifact_kind_counts": artifact_counts,
        "missing_by_category": summarize_missing(missing),
    }


def increment_summary(summary: Dict[str, Dict[str, int]], key: str, exists: bool) -> None:
    if key not in summary:
        summary[key] = {"target_count": 0, "present_count": 0, "missing_count": 0}
    summary[key]["target_count"] += 1
    if exists:
        summary[key]["present_count"] += 1
    else:
        summary[key]["missing_count"] += 1


def summarize_missing(targets: Iterable[Mapping[str, object]]) -> Dict[str, List[str]]:
    missing: Dict[str, List[str]] = {}
    for target in targets:
        category = str(target["category"])
        missing.setdefault(category, []).append(str(target["label"]))
    return missing


def build_next_steps(targets: Sequence[Mapping[str, object]]) -> list[str]:
    present_artifacts = sorted({str(target["artifact_kind"]) for target in targets if target.get("exists")})
    steps = [
        "Review present targets before running heavy extraction; this plan does not copy evidence.",
        "Run rapidtriage run ROOT --mode hacking --read-only for a broad first pass after the plan looks correct.",
    ]
    if present_artifacts:
        steps.append("Focused collectors likely to produce rows: " + ", ".join(present_artifacts) + ".")
    if any(target.get("kind") == "glob" and target.get("truncated") for target in targets):
        steps.append("One or more glob targets were truncated in the plan; inspect the source folder directly before exporting.")
    return steps
