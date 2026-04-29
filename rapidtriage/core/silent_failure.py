from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


MAX_TARGET_SCAN_FILES = 20_000


@dataclass(frozen=True)
class ArtifactTargetRule:
    kind: str
    patterns: tuple[str, ...]
    description: str


ARTIFACT_TARGET_RULES: tuple[ArtifactTargetRule, ...] = (
    ArtifactTargetRule(
        "eventlog",
        ("*.evtx", "*.evt", "*winevt/logs/*"),
        "Windows event logs were present but no eventlog artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "windows-prefetch",
        ("*.pf", "*windows/prefetch/*"),
        "Prefetch files were present but no prefetch artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "windows-filesystem",
        ("$mft", "$usnjrnl", "$j", "*.mft", "*$extend/$usnjrnl*"),
        "NTFS filesystem artifacts were present but no filesystem artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "windows-execution",
        ("amcache.hve", "ntuser.dat", "usrclass.dat", "system", "software", "sam", "*.reg"),
        "Execution/registry source files were present but no execution artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "windows-os-account",
        ("sam", "security", "system", "software", "*.reg"),
        "Account/OS hive sources were present but no account artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "windows-search-index",
        ("windows.edb", "srudb.dat", "*.edb"),
        "Windows Search/SRUM database files were present but no search-index artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "browser",
        ("history", "places.sqlite", "cookies", "web data", "login data", "session storage", "local storage"),
        "Browser profile stores were present but no browser artifacts were emitted.",
    ),
    ArtifactTargetRule(
        "recent-files",
        ("*.lnk", "*.automaticdestinations-ms", "*.customdestinations-ms"),
        "Recent-file sources were present but no recent-file artifacts were emitted.",
    ),
)


def build_silent_failure_report(
    *,
    root: Path,
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
    safety: Mapping[str, object],
) -> dict[str, object]:
    target_inventory = inventory_target_files(root)
    checks: list[dict[str, object]] = []
    checks.extend(build_core_stage_checks(docs_payload, files_payload, timeline_payload))
    checks.extend(build_artifact_gap_checks(target_inventory, artifact_payloads))
    checks.extend(build_parser_error_checks(artifact_payloads))
    checks.extend(build_extract_gap_checks(docs_extract_payload, files_extract_payload, safety))

    risk_checks = [item for item in checks if item["level"] in {"warning", "failed"}]
    status = "pass"
    if any(item["level"] == "failed" for item in checks):
        status = "failed"
    elif any(item["level"] == "warning" for item in checks):
        status = "warning"
    elif any(item["level"] == "notice" for item in checks):
        status = "notice"

    return {
        "status": status,
        "silent_failure_risk": bool(risk_checks),
        "check_count": len(checks),
        "risk_check_count": len(risk_checks),
        "target_inventory": {
            "root": str(root),
            "scanned_file_count": target_inventory["scanned_file_count"],
            "truncated": target_inventory["truncated"],
            "max_files": MAX_TARGET_SCAN_FILES,
            "target_counts": target_inventory["target_counts"],
            "sample_paths": target_inventory["sample_paths"],
        },
        "checks": checks,
        "operator_guidance": build_operator_guidance(risk_checks),
    }


def inventory_target_files(root: Path) -> dict[str, object]:
    counts = {rule.kind: 0 for rule in ARTIFACT_TARGET_RULES}
    samples: dict[str, list[str]] = {rule.kind: [] for rule in ARTIFACT_TARGET_RULES}
    scanned = 0
    truncated = False
    try:
        iterator = root.rglob("*") if root.is_dir() else iter([root])
        for path in iterator:
            if not path.is_file():
                continue
            scanned += 1
            normalized = normalize_path(path)
            for rule in ARTIFACT_TARGET_RULES:
                if matches_any(normalized, rule.patterns):
                    counts[rule.kind] += 1
                    if len(samples[rule.kind]) < 5:
                        samples[rule.kind].append(str(path))
            if scanned >= MAX_TARGET_SCAN_FILES:
                truncated = True
                break
    except OSError:
        truncated = True
    return {
        "scanned_file_count": scanned,
        "truncated": truncated,
        "target_counts": counts,
        "sample_paths": samples,
    }


def build_core_stage_checks(
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    timeline_payload: Mapping[str, object],
) -> list[dict[str, object]]:
    file_summary = files_payload.get("summary", {})
    doc_summary = docs_payload.get("summary", {})
    timeline_summary = timeline_payload.get("summary", {})
    scanned_count = int_value(file_summary, "scanned_file_count")
    file_candidate_count = int_value(file_summary, "candidate_count")
    doc_candidate_count = int_value(doc_summary, "candidate_count")
    doc_match_count = int_value(doc_summary, "match_count")
    timeline_count = int_value(timeline_summary, "event_count")
    checks = [
        make_check(
            "files-scanned",
            "failed" if scanned_count == 0 else "pass",
            f"scanned_file_count={scanned_count}",
            "No files were scanned; the evidence root, mount, or input adapter may be wrong.",
        ),
        make_check(
            "documents-indexed",
            "notice" if scanned_count and doc_candidate_count == 0 else "pass",
            f"document_candidate_count={doc_candidate_count}, scanned_file_count={scanned_count}",
            "No supported documents were indexed; confirm document extensions and extraction dependencies.",
        ),
        make_check(
            "keyword-search-yield",
            "notice" if doc_candidate_count and doc_match_count == 0 else "pass",
            f"document_match_count={doc_match_count}, document_candidate_count={doc_candidate_count}",
            "Documents were indexed but configured keywords produced no hits.",
        ),
    ]
    if file_candidate_count or doc_match_count:
        checks.append(
            make_check(
                "timeline-yield",
                "warning" if timeline_count == 0 else "pass",
                f"timeline_event_count={timeline_count}, file_candidate_count={file_candidate_count}, document_match_count={doc_match_count}",
                "Candidate evidence exists but no timeline events were produced.",
            )
        )
    return checks


def build_artifact_gap_checks(
    target_inventory: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    counts = target_inventory.get("target_counts", {})
    checks: list[dict[str, object]] = []
    for rule in ARTIFACT_TARGET_RULES:
        target_count = int(counts.get(rule.kind, 0)) if isinstance(counts, Mapping) else 0
        if rule.kind not in artifact_payloads and target_count == 0:
            continue
        artifact_count = int_value(artifact_payloads.get(rule.kind, {}), "artifact_count", parent_key="summary")
        level = "warning" if target_count > 0 and artifact_count == 0 else "pass"
        checks.append(
            make_check(
                f"artifact-yield-{rule.kind}",
                level,
                f"target_count={target_count}, artifact_count={artifact_count}",
                rule.description,
            )
        )
    return checks


def build_parser_error_checks(
    artifact_payloads: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    for kind, payload in artifact_payloads.items():
        error_count = int_value(payload, "parser_error_count", parent_key="summary")
        if error_count:
            checks.append(
                make_check(
                    f"parser-errors-{kind}",
                    "failed",
                    f"parser_error_count={error_count}",
                    f"{kind} parser reported isolated errors; review parser_errors before reporting.",
                )
            )
    return checks


def build_extract_gap_checks(
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    safety: Mapping[str, object],
) -> list[dict[str, object]]:
    if safety.get("read_only") or safety.get("dry_run"):
        return []
    checks = []
    for name, payload in (("docs-extract", docs_extract_payload), ("files-extract", files_extract_payload)):
        summary = payload.get("summary", {})
        selected = int_value(summary, "selected_count")
        extracted = int_value(summary, "extracted_count")
        skipped = int_value(summary, "skipped_count")
        if selected and not extracted:
            checks.append(
                make_check(
                    f"{name}-yield",
                    "warning",
                    f"selected_count={selected}, extracted_count={extracted}, skipped_count={skipped}",
                    f"{name} selected evidence but extracted nothing; review skip reasons before reporting.",
                )
            )
    return checks


def make_check(check_id: str, level: str, detail: str, message: str) -> dict[str, object]:
    return {
        "id": check_id,
        "level": level,
        "detail": detail,
        "message": message,
        "requires_review": level in {"notice", "warning", "failed"},
    }


def build_operator_guidance(risk_checks: Sequence[Mapping[str, object]]) -> list[str]:
    if not risk_checks:
        return ["No high-risk silent-failure pattern was detected for this run."]
    return [
        "Do not treat this run as complete until warning/failed checks are reviewed.",
        "Compare high-value parsers against trusted tools before report-grade conclusions.",
        "If target files exist but artifact count is zero, inspect parser_errors, source paths, and mounted-image completeness.",
    ]


def int_value(payload: Mapping[str, object], key: str, *, parent_key: str | None = None) -> int:
    if parent_key:
        parent = payload.get(parent_key, {})
        if isinstance(parent, Mapping):
            return int_value(parent, key)
        return 0
    try:
        return int(payload.get(key, 0))
    except (TypeError, ValueError):
        return 0


def normalize_path(path: Path) -> str:
    return str(path).replace("\\", "/").lower()


def matches_any(value: str, patterns: Sequence[str]) -> bool:
    name = value.rsplit("/", 1)[-1]
    for pattern in patterns:
        normalized = pattern.lower()
        if fnmatch.fnmatch(name, normalized) or fnmatch.fnmatch(value, normalized) or normalized in value:
            return True
    return False
