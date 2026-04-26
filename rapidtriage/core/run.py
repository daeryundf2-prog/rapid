from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Union

from .audit import write_audit_record
from .artifacts import run_artifact_collection
from .docs import build_manifest, run_docs_search, write_result
from .e01 import E01ExtractionError, E01ExtractionResult, extract_e01_to_directory, is_e01_path
from .extract import DEFAULT_EXTRACT_MANIFEST_NAME, SUPPORTED_DOC_KINDS, run_extract
from .files import run_files_scan
from .input_root import InputRoot, derive_child_input_root, resolve_input_root
from .reporting import build_run_report_context, render_run_markdown_report
from .rules import RuleSet, summarize_payload_annotations
from .timeline import build_timeline_report, run_timeline

SUPPORTED_RUN_MODES: tuple[str, ...] = ("seizure", "fraud", "hacking", "recovery")
IMPLEMENTED_RUN_MODES = set(SUPPORTED_RUN_MODES)
RUN_DOC_EXTRACT_KINDS = SUPPORTED_DOC_KINDS


@dataclass(frozen=True)
class RunProfile:
    mode: str
    description: str
    keywords: tuple[str, ...]
    docs_extract_kinds: tuple[str, ...]
    file_extract_categories: tuple[str, ...]
    file_scan_categories: tuple[str, ...]
    file_scan_path_contains: tuple[str, ...] = ()
    scan_root_parts: tuple[str, ...] = ()
    preferred_locations: tuple[str, ...] = ()
    artifacts_kinds: tuple[str, ...] = ()


RUN_PROFILES: Dict[str, RunProfile] = {
    "seizure": RunProfile(
        mode="seizure",
        description="Seizure triage focused on user folders, recent modifications, and high-value documents, archives, and databases.",
        keywords=("seizure", "download", "desktop", "document", "archive", "database", "recent", "evidence"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "databases", "emails", "disk-images", "mobile-images", "vehicle-images"),
        file_scan_categories=(
            "documents",
            "archives",
            "databases",
            "emails",
            "disk-images",
            "mobile-images",
            "memory-dumps",
            "vehicle-images",
            "images",
        ),
        scan_root_parts=("Users",),
        preferred_locations=("downloads", "desktop", "documents"),
        artifacts_kinds=("browser", "recent-files", "windows-system"),
    ),
    "fraud": RunProfile(
        mode="fraud",
        description="Document-forward fraud triage focused on payment, account, and invoice evidence.",
        keywords=("fraud", "invoice", "payment", "transfer", "bank", "account", "receipt", "refund"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "databases", "emails", "mobile-images"),
        file_scan_categories=("documents", "archives", "databases", "emails", "mobile-images", "images"),
        artifacts_kinds=("browser", "recent-files", "windows-system"),
    ),
    "hacking": RunProfile(
        mode="hacking",
        description="Intrusion triage focused on suspicious binaries, credential theft, persistence, and attacker tooling.",
        keywords=("hacking", "malware", "credential", "powershell", "persistence", "ransomware", "shell", "exfil"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("executables", "archives", "databases", "documents", "emails", "memory-dumps"),
        file_scan_categories=("executables", "archives", "databases", "documents", "emails", "memory-dumps", "images"),
        artifacts_kinds=("browser", "recent-files", "windows-system"),
    ),
    "recovery": RunProfile(
        mode="recovery",
        description="Recovery triage focused on deleted, recycled, or restorable file candidates without doing carving.",
        keywords=("recovery", "deleted", "recycle", "trash", "restore", "backup", "recent"),
        docs_extract_kinds=RUN_DOC_EXTRACT_KINDS,
        file_extract_categories=("documents", "archives", "images", "emails", "disk-images", "mobile-images", "vehicle-images"),
        file_scan_categories=(
            "documents",
            "archives",
            "images",
            "emails",
            "disk-images",
            "mobile-images",
            "memory-dumps",
            "vehicle-images",
        ),
        file_scan_path_contains=("recycle",),
        preferred_locations=("$recycle.bin", "recycle", "trash", "deleted"),
        artifacts_kinds=("recent-files",),
    ),
}


class RunModeError(ValueError):
    """Raised when the requested run mode is invalid or unsupported."""


def run_triage_mode(
    root: Union[InputRoot, Path],
    *,
    mode: str,
    output_dir: Path,
    input_kind: str | None = None,
    dry_run: bool = False,
    read_only: bool = False,
    max_extract_size_bytes: int = 0,
    max_file_count: int = 0,
    overwrite: bool = False,
    rule_set: RuleSet | None = None,
) -> Dict[str, object]:
    normalized_mode = mode.lower()
    if normalized_mode not in SUPPORTED_RUN_MODES:
        supported = ", ".join(SUPPORTED_RUN_MODES)
        raise RunModeError(f"unsupported run mode: {mode} (supported: {supported})")
    if normalized_mode not in IMPLEMENTED_RUN_MODES:
        available = ", ".join(sorted(IMPLEMENTED_RUN_MODES))
        raise RunModeError(f"run mode '{normalized_mode}' is not implemented yet (currently available: {available})")

    profile = RUN_PROFILES[normalized_mode]
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    input_root, e01_result = prepare_run_input_root(root, input_kind=input_kind, output_dir=output_dir)
    scan_root = resolve_scan_root(input_root.root_path, profile)
    scan_input_root = derive_child_input_root(input_root, scan_root)

    manifest_path = output_dir / "rapidtriage-manifest.json"
    docs_path = output_dir / "rapidtriage-docs.json"
    docs_index_path = output_dir / "rapidtriage-docs-index.json"
    files_path = output_dir / "rapidtriage-files.json"
    artifacts_dir = output_dir / "artifacts"
    docs_extract_dir = output_dir / "docs-extract"
    files_extract_dir = output_dir / "files-extract"
    docs_extract_manifest = docs_extract_dir / DEFAULT_EXTRACT_MANIFEST_NAME
    files_extract_manifest = files_extract_dir / DEFAULT_EXTRACT_MANIFEST_NAME
    timeline_path = output_dir / "rapidtriage-timeline.json"
    timeline_report_path = output_dir / "rapidtriage-timeline-report.md"
    summary_path = output_dir / "rapidtriage-run-summary.json"
    report_path = output_dir / "rapidtriage-run-report.md"
    e01_metadata_path = output_dir / "rapidtriage-e01.json"

    if e01_result is not None:
        write_result(e01_result.to_dict(), e01_metadata_path)

    manifest_payload = build_manifest(input_root, profile.keywords)
    docs_payload = run_docs_search(scan_input_root, profile.keywords, rule_set=rule_set, index_output=docs_index_path)
    docs_payload["manifest"] = manifest_payload
    docs_payload["scan_scope_root"] = str(scan_input_root.root_path)

    files_payload = run_files_scan(
        scan_input_root,
        categories=profile.file_scan_categories,
        path_contains=profile.file_scan_path_contains or None,
        rule_set=rule_set,
    )
    files_payload["scan_scope_root"] = str(scan_input_root.root_path)

    write_result(manifest_payload, manifest_path)
    write_result(docs_payload, docs_path)
    write_result(files_payload, files_path)

    artifact_outputs: Dict[str, Path] = {}
    artifact_payloads: Dict[str, Dict[str, object]] = {}
    for kind in profile.artifacts_kinds:
        artifact_path = artifacts_dir / f"rapidtriage-artifacts-{kind}.json"
        artifact_payload = run_artifact_collection(input_root, kind=kind, rule_set=rule_set)
        artifact_outputs[kind] = artifact_path
        artifact_payloads[kind] = artifact_payload
        write_result(artifact_payload, artifact_path)

    docs_extract_payload = run_extract(
        docs_path,
        docs_extract_dir,
        kinds=profile.docs_extract_kinds,
        dry_run=dry_run,
        read_only=read_only,
        max_extract_size_bytes=max_extract_size_bytes,
        max_file_count=max_file_count,
        overwrite=overwrite,
    )
    files_extract_payload = run_extract(
        files_path,
        files_extract_dir,
        categories=profile.file_extract_categories,
        dry_run=dry_run,
        read_only=read_only,
        max_extract_size_bytes=max_extract_size_bytes,
        max_file_count=max_file_count,
        overwrite=overwrite,
    )
    write_result(docs_extract_payload, docs_extract_manifest)
    write_result(files_extract_payload, files_extract_manifest)

    timeline_payload = run_timeline(
        root=input_root.root_path,
        input_kind=input_root.kind,
        files_inputs=[files_path],
        docs_inputs=[docs_path],
        artifacts_inputs=list(artifact_outputs.values()),
        rule_set=rule_set,
    )
    write_result(timeline_payload, timeline_path)
    timeline_report_path.write_text(build_timeline_report(timeline_payload), encoding="utf-8")

    outputs = {
        "manifest": manifest_path,
        "docs": docs_path,
        "docs_index": docs_index_path,
        "files": files_path,
        "docs_extract_manifest": docs_extract_manifest,
        "files_extract_manifest": files_extract_manifest,
        "timeline": timeline_path,
        "timeline_report": timeline_report_path,
        **{f"artifacts_{kind}": path for kind, path in artifact_outputs.items()},
        "summary": summary_path,
        "report": report_path,
    }
    if e01_result is not None:
        outputs = {"e01": e01_metadata_path, **outputs}
    summary_payload = build_run_summary(
        root=input_root.root_path,
        output_dir=output_dir,
        profile=profile,
        manifest_payload=manifest_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        outputs=outputs,
        safety={
            "dry_run": dry_run,
            "read_only": read_only,
            "max_extract_size_bytes": max_extract_size_bytes,
            "max_file_count": max_file_count,
            "overwrite": overwrite,
        },
        rule_set=rule_set,
        source=build_run_source_record(input_root, e01_result=e01_result),
    )
    audit_output = output_dir / "rapidtriage-run-audit.json"
    summary_payload["audit"] = str(audit_output)
    report_path.write_text(
        build_markdown_report(
            summary_payload,
            docs_payload=docs_payload,
            files_payload=files_payload,
            docs_extract_payload=docs_extract_payload,
            files_extract_payload=files_extract_payload,
            artifact_payloads=artifact_payloads,
            timeline_payload=timeline_payload,
        ),
        encoding="utf-8",
    )
    write_result(summary_payload, summary_path)
    write_audit_record(
        audit_output,
        command="run",
        options={
            "mode": normalized_mode,
            "output_dir": str(output_dir),
            "input_kind": input_root.kind,
            "scan_scope_root": str(scan_input_root.root_path),
            "rules": rule_set.path if rule_set else None,
            "dry_run": dry_run,
            "read_only": read_only,
            "max_extract_size_bytes": max_extract_size_bytes,
            "max_file_count": max_file_count,
            "overwrite": overwrite,
            "e01_source": str(e01_result.source_path) if e01_result else None,
            "e01_extracted_root": str(e01_result.extract_dir) if e01_result else None,
        },
        input_root=input_root,
        input_files=[("e01-source", e01_result.source_path)] if e01_result else [],
        output_files=[
            *([("e01-metadata", e01_metadata_path)] if e01_result else []),
            ("manifest", manifest_path),
            ("docs", docs_path),
            ("docs-index", docs_index_path),
            ("files", files_path),
            ("docs-extract-manifest", docs_extract_manifest),
            ("files-extract-manifest", files_extract_manifest),
            ("timeline-json", timeline_path),
            ("timeline-report", timeline_report_path),
            *[(f"artifacts-{kind}", path) for kind, path in artifact_outputs.items()],
            ("run-summary", summary_path),
            ("run-report", report_path),
            *[
                (f"docs-extract:{entry['relative_path']}", Path(entry["extracted_path"]).resolve())
                for entry in docs_extract_payload.get("entries", [])
            ],
            *[
                (f"files-extract:{entry['relative_path']}", Path(entry["extracted_path"]).resolve())
                for entry in files_extract_payload.get("entries", [])
            ],
        ],
    )
    return summary_payload


def prepare_run_input_root(
    root: Union[InputRoot, Path],
    *,
    input_kind: str | None,
    output_dir: Path,
) -> tuple[InputRoot, E01ExtractionResult | None]:
    if isinstance(root, InputRoot):
        return resolve_input_root(root, kind=input_kind), None

    root_path = Path(root).expanduser().resolve()
    if is_e01_path(root_path):
        try:
            result = extract_e01_to_directory(root_path, output_dir / "_e01")
        except E01ExtractionError as exc:
            raise RunModeError(str(exc)) from exc
        return InputRoot(source_path=str(root_path), root_path=result.extract_dir, kind="e01-derived"), result
    return resolve_input_root(root_path, kind=input_kind), None


def build_run_source_record(
    input_root: InputRoot,
    *,
    e01_result: E01ExtractionResult | None,
) -> dict[str, object]:
    if e01_result is None:
        return {
            "type": input_root.kind,
            "source_path": input_root.source_path,
            "analysis_root": str(input_root.root_path),
        }
    return {
        "type": "e01",
        "source_path": str(e01_result.source_path),
        "analysis_root": str(e01_result.extract_dir),
        "stage_dir": str(e01_result.stage_dir),
        "partition_start_sector": e01_result.partition_start_sector,
    }


def build_run_summary(
    *,
    root: Path,
    output_dir: Path,
    profile: RunProfile,
    manifest_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
    outputs: Mapping[str, Path],
    safety: Mapping[str, object],
    rule_set: RuleSet | None = None,
    source: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    provider_counts = {
        str(provider["name"]): len(provider.get("artifacts", []))
        for provider in manifest_payload.get("providers", [])
        if isinstance(provider, dict) and provider.get("name")
    }
    windows_provider_counts = {
        name: count for name, count in provider_counts.items() if name.startswith("windows-")
    }
    artifact_type_counts = dict(count_artifact_types(manifest_payload.get("providers", [])))
    keyword_counts = dict(count_matched_keywords(docs_payload.get("results", [])))
    file_category_counts = dict(files_payload.get("summary", {}).get("category_counts", {}))
    artifact_summary = {
        kind: {
            "artifact_count": int(payload.get("summary", {}).get("artifact_count", 0)),
            "artifact_type_counts": dict(payload.get("summary", {}).get("artifact_type_counts", {})),
            "output": str(outputs.get(f"artifacts_{kind}", "")),
        }
        for kind, payload in artifact_payloads.items()
    }
    preferred_candidates = collect_preferred_candidates(
        files_payload.get("candidates", []),
        preferred_locations=profile.preferred_locations,
    )
    recent_candidates = summarize_file_candidates(files_payload.get("candidates", []), limit=5)
    large_candidates = summarize_large_file_candidates(files_payload.get("candidates", []), limit=5)

    step_rows = build_step_rows(
        manifest_payload=manifest_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
        outputs=outputs,
    )
    processing_summary = build_processing_summary(step_rows, safety=safety)

    payload = {
        "command": "run",
        "mode": profile.mode,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
        "source": dict(source or {}),
        "scan_scope_root": str(files_payload.get("scan_scope_root") or docs_payload.get("scan_scope_root") or root),
        "output_dir": str(output_dir),
        "profile": {
            "description": profile.description,
            "keywords": list(profile.keywords),
            "docs_extract_kinds": list(profile.docs_extract_kinds),
            "file_extract_categories": list(profile.file_extract_categories),
            "file_scan_categories": list(profile.file_scan_categories),
            "file_scan_path_contains": list(profile.file_scan_path_contains),
            "preferred_locations": list(profile.preferred_locations),
            "artifacts_kinds": list(profile.artifacts_kinds),
        },
        "safety": dict(safety),
        "outputs": {name: str(path) for name, path in outputs.items()},
        "steps": step_rows,
        "processing": processing_summary,
        "summary": {
            "document_candidate_count": int(docs_payload.get("summary", {}).get("candidate_count", 0)),
            "document_match_count": int(docs_payload.get("summary", {}).get("match_count", 0)),
            "scanned_file_count": int(files_payload.get("summary", {}).get("scanned_file_count", 0)),
            "file_candidate_count": int(files_payload.get("summary", {}).get("candidate_count", 0)),
            "provider_artifact_counts": provider_counts,
            "windows_provider_artifact_counts": windows_provider_counts,
            "artifact_type_counts": artifact_type_counts,
            "matched_keyword_counts": keyword_counts,
            "file_category_counts": file_category_counts,
            "artifacts": artifact_summary,
            "docs_extracted_count": int(docs_extract_payload.get("summary", {}).get("extracted_count", 0)),
            "files_extracted_count": int(files_extract_payload.get("summary", {}).get("extracted_count", 0)),
            "preferred_location_candidate_count": len(preferred_candidates),
            "timeline_event_count": int(timeline_payload.get("summary", {}).get("event_count", 0)),
        },
        "highlights": {
            "document_hits": summarize_document_hits(docs_payload.get("results", []), limit=5),
            "recent_file_candidates": recent_candidates,
            "large_file_candidates": large_candidates,
            "preferred_location_candidates": preferred_candidates[:5],
        },
    }
    if rule_set is not None:
        annotation_summary = summarize_payload_annotations(files_payload, docs_payload, *artifact_payloads.values())
        payload["rule_set"] = {
            "path": rule_set.path,
            "format": rule_set.format,
            "rule_count": rule_set.rule_count,
        }
        if annotation_summary["matched_rules"]:
            payload["matched_rules"] = annotation_summary["matched_rules"]
        if annotation_summary["ioc_hits"]:
            payload["ioc_hits"] = annotation_summary["ioc_hits"]
        payload["summary"]["matched_rule_count"] = int(annotation_summary["matched_rule_count"])
        payload["summary"]["ioc_hit_count"] = int(annotation_summary["ioc_hit_count"])
    return payload


def build_step_rows(
    *,
    manifest_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
    outputs: Mapping[str, Path],
) -> List[Dict[str, object]]:
    provider_count = len(manifest_payload.get("providers", []))
    artifact_count_by_kind = {
        kind: int(payload.get("summary", {}).get("artifact_count", 0))
        for kind, payload in artifact_payloads.items()
    }
    rows: List[Dict[str, object]] = [
        annotate_step(
            {
                "name": "manifest",
                "status": "completed",
                "output": str(outputs["manifest"]),
                "provider_count": provider_count,
            },
            warning_level="notice" if provider_count == 0 else "none",
            warning_messages=["No manifest providers were collected."] if provider_count == 0 else [],
        ),
        annotate_step(
            {
                "name": "docs",
                "status": "completed",
                "output": str(outputs["docs"]),
                "candidate_count": int(docs_payload.get("summary", {}).get("candidate_count", 0)),
                "match_count": int(docs_payload.get("summary", {}).get("match_count", 0)),
            },
            warning_level=docs_warning_level(docs_payload),
            warning_messages=docs_warning_messages(docs_payload),
        ),
        annotate_step(
            {
                "name": "docs-index",
                "status": "completed",
                "output": str(outputs["docs_index"]),
                "strategy": str(docs_payload.get("index", {}).get("strategy", "")),
                "document_count": int(docs_payload.get("index", {}).get("document_count", 0)),
                "term_count": int(docs_payload.get("index", {}).get("term_count", 0)),
            },
            warning_level=docs_index_warning_level(docs_payload),
            warning_messages=docs_index_warning_messages(docs_payload),
        ),
        annotate_step(
            {
                "name": "files",
                "status": "completed",
                "output": str(outputs["files"]),
                "scanned_file_count": int(files_payload.get("summary", {}).get("scanned_file_count", 0)),
                "candidate_count": int(files_payload.get("summary", {}).get("candidate_count", 0)),
            },
            warning_level=files_warning_level(files_payload),
            warning_messages=files_warning_messages(files_payload),
        ),
    ]
    for kind, payload in artifact_payloads.items():
        artifact_count = artifact_count_by_kind[kind]
        rows.append(
            annotate_step(
                {
                    "name": f"artifacts-{kind}",
                    "status": "completed",
                    "output": str(outputs[f"artifacts_{kind}"]),
                    "artifact_count": artifact_count,
                },
                warning_level="notice" if artifact_count == 0 else "none",
                warning_messages=[f"No {kind} artifact rows were collected."] if artifact_count == 0 else [],
            )
        )
    docs_extract_step = build_extract_step(
        "docs-extract",
        outputs["docs_extract_manifest"],
        docs_extract_payload,
    )
    files_extract_step = build_extract_step(
        "files-extract",
        outputs["files_extract_manifest"],
        files_extract_payload,
    )
    timeline_count = int(timeline_payload.get("summary", {}).get("event_count", 0))
    rows.extend(
        [
            docs_extract_step,
            files_extract_step,
            annotate_step(
                {
                    "name": "timeline",
                    "status": "completed",
                    "output": str(outputs["timeline"]),
                    "event_count": timeline_count,
                    "report": str(outputs["timeline_report"]),
                },
                warning_level="notice" if timeline_count == 0 else "none",
                warning_messages=[
                    "No timeline events were produced. Confirm the source has supported timestamps/artifacts."
                ]
                if timeline_count == 0
                else [],
            ),
        ]
    )
    return rows


def build_processing_summary(
    steps: List[Dict[str, object]],
    *,
    safety: Mapping[str, object],
) -> Dict[str, object]:
    warnings: List[Dict[str, object]] = []
    for step in steps:
        level = str(step.get("warning_level") or "none")
        messages = step.get("warning_messages", [])
        if level == "none" or not isinstance(messages, list):
            continue
        for message in messages:
            warnings.append(
                {
                    "step": str(step.get("name", "")),
                    "level": level,
                    "message": str(message),
                }
            )

    max_extract_size = int(safety.get("max_extract_size_bytes") or 0)
    max_file_count = int(safety.get("max_file_count") or 0)
    read_only = bool(safety.get("read_only"))
    dry_run = bool(safety.get("dry_run"))
    profile_label = infer_processing_profile_label(
        read_only=read_only,
        dry_run=dry_run,
        max_extract_size_bytes=max_extract_size,
        max_file_count=max_file_count,
    )
    return {
        "profile_label": profile_label,
        "dry_run": dry_run,
        "read_only": read_only,
        "overwrite": bool(safety.get("overwrite")),
        "caps": {
            "max_extract_size_bytes": max_extract_size,
            "max_file_count": max_file_count,
        },
        "step_count": len(steps),
        "warning_count": len(warnings),
        "highest_warning_level": highest_warning_level([str(item["level"]) for item in warnings]),
        "warnings": warnings,
    }


def infer_processing_profile_label(
    *,
    read_only: bool,
    dry_run: bool,
    max_extract_size_bytes: int,
    max_file_count: int,
) -> str:
    if dry_run:
        return "Dry run - no extraction"
    if read_only:
        return "Fast first pass - read-only"
    if max_extract_size_bytes or max_file_count:
        return "Standard - bounded extraction"
    return "Deep - uncapped extraction"


def build_extract_step(name: str, output: Path, payload: Mapping[str, object]) -> Dict[str, object]:
    summary = payload.get("summary", {})
    selected_count = int(summary.get("selected_count", 0)) if isinstance(summary, Mapping) else 0
    extracted_count = int(summary.get("extracted_count", 0)) if isinstance(summary, Mapping) else 0
    skipped_count = int(summary.get("skipped_count", 0)) if isinstance(summary, Mapping) else 0
    skip_reason_counts = count_skip_reasons(payload)
    warning_messages = extract_warning_messages(
        selected_count=selected_count,
        extracted_count=extracted_count,
        skipped_count=skipped_count,
        skip_reason_counts=skip_reason_counts,
    )
    warning_level = extract_warning_level(skip_reason_counts, selected_count=selected_count, skipped_count=skipped_count)
    status = "completed"
    if selected_count and skipped_count and not extracted_count:
        status = "skipped"
    elif skipped_count:
        status = "completed_with_warnings"
    return annotate_step(
        {
            "name": name,
            "status": status,
            "output": str(output),
            "selected_count": selected_count,
            "extracted_count": extracted_count,
            "skipped_count": skipped_count,
            "skip_reasons": skip_reason_counts,
        },
        warning_level=warning_level,
        warning_messages=warning_messages,
    )


def annotate_step(
    row: Dict[str, object],
    *,
    warning_level: str,
    warning_messages: List[str],
) -> Dict[str, object]:
    row["warning_level"] = warning_level
    row["warning_messages"] = warning_messages
    return row


def docs_warning_level(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {})
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    match_count = int(summary.get("match_count", 0)) if isinstance(summary, Mapping) else 0
    if candidate_count == 0:
        return "notice"
    if match_count == 0:
        return "notice"
    return "none"


def docs_warning_messages(payload: Mapping[str, object]) -> List[str]:
    summary = payload.get("summary", {})
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    match_count = int(summary.get("match_count", 0)) if isinstance(summary, Mapping) else 0
    if candidate_count == 0:
        return ["No supported document candidates were found."]
    if match_count == 0:
        return ["Documents were scanned, but no configured keywords matched."]
    return []


def docs_index_warning_level(payload: Mapping[str, object]) -> str:
    index = payload.get("index", {})
    document_count = int(index.get("document_count", 0)) if isinstance(index, Mapping) else 0
    return "notice" if document_count == 0 else "none"


def docs_index_warning_messages(payload: Mapping[str, object]) -> List[str]:
    index = payload.get("index", {})
    document_count = int(index.get("document_count", 0)) if isinstance(index, Mapping) else 0
    if document_count == 0:
        return ["No documents were added to the keyword index."]
    return []


def files_warning_level(payload: Mapping[str, object]) -> str:
    summary = payload.get("summary", {})
    scanned_count = int(summary.get("scanned_file_count", 0)) if isinstance(summary, Mapping) else 0
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    if scanned_count == 0:
        return "warning"
    if candidate_count == 0:
        return "notice"
    return "none"


def files_warning_messages(payload: Mapping[str, object]) -> List[str]:
    summary = payload.get("summary", {})
    scanned_count = int(summary.get("scanned_file_count", 0)) if isinstance(summary, Mapping) else 0
    candidate_count = int(summary.get("candidate_count", 0)) if isinstance(summary, Mapping) else 0
    if scanned_count == 0:
        return ["No files were scanned. Check the evidence root or mounted-image path."]
    if candidate_count == 0:
        return ["Files were scanned, but no profile-matched candidates were found."]
    return []


def count_skip_reasons(payload: Mapping[str, object]) -> Dict[str, int]:
    skipped = payload.get("skipped", [])
    counts: Counter[str] = Counter()
    if not isinstance(skipped, list):
        return {}
    for item in skipped:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "unknown")
        counts[reason] += 1
    return dict(sorted(counts.items()))


def extract_warning_level(
    skip_reason_counts: Mapping[str, int],
    *,
    selected_count: int,
    skipped_count: int,
) -> str:
    if not skipped_count:
        return "notice" if selected_count == 0 else "none"
    if any(reason in skip_reason_counts for reason in {"max-file-count", "max-extract-size", "missing"}):
        return "warning"
    return "notice"


def extract_warning_messages(
    *,
    selected_count: int,
    extracted_count: int,
    skipped_count: int,
    skip_reason_counts: Mapping[str, int],
) -> List[str]:
    messages: List[str] = []
    if selected_count == 0:
        messages.append("No items matched the extraction filters.")
    if skipped_count and not extracted_count:
        messages.append("Selected items were not extracted; review skip reasons before reporting.")
    elif skipped_count:
        messages.append("Some selected items were skipped during extraction.")
    if "read-only" in skip_reason_counts:
        messages.append("Extraction skipped by read-only profile.")
    if "dry-run" in skip_reason_counts:
        messages.append("Extraction skipped because dry run was enabled.")
    if "max-file-count" in skip_reason_counts:
        messages.append("Extraction capped by max file count.")
    if "max-extract-size" in skip_reason_counts:
        messages.append("Extraction capped by max extract size.")
    if "missing" in skip_reason_counts:
        messages.append("Some selected source paths were missing.")
    if "destination-exists" in skip_reason_counts:
        messages.append("Existing destination files were preserved; enable overwrite only when intended.")
    return messages


def highest_warning_level(levels: List[str]) -> str:
    priority = {"none": 0, "notice": 1, "warning": 2, "failed": 3}
    if not levels:
        return "none"
    return max(levels, key=lambda level: priority.get(level, 0))


def resolve_scan_root(root: Path, profile: RunProfile) -> Path:
    if not profile.scan_root_parts:
        return root
    candidate = root.joinpath(*profile.scan_root_parts)
    if candidate.exists():
        return candidate
    return root


def count_artifact_types(providers: object) -> Counter[str]:
    counts: Counter[str] = Counter()
    if not isinstance(providers, list):
        return counts
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        artifacts = provider.get("artifacts", [])
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            artifact_type = artifact.get("artifact_type")
            if artifact_type:
                counts[str(artifact_type)] += 1
    return counts


def count_matched_keywords(results: object) -> Counter[str]:
    counts: Counter[str] = Counter()
    if not isinstance(results, list):
        return counts
    for result in results:
        if not isinstance(result, dict):
            continue
        for keyword in result.get("matched_keywords", []):
            counts[str(keyword)] += 1
    return counts


def summarize_document_hits(results: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(results, list):
        return []
    items: List[Dict[str, object]] = []
    for result in results[:limit]:
        if not isinstance(result, dict):
            continue
        items.append(
            {
                "path": result.get("path"),
                "kind": result.get("kind"),
                "matched_keywords": list(result.get("matched_keywords", [])),
                "preview": result.get("preview"),
            }
        )
    return items


def summarize_file_candidates(candidates: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(candidates, list):
        return []
    items: List[Dict[str, object]] = []
    for candidate in candidates[:limit]:
        if not isinstance(candidate, dict):
            continue
        items.append(
            {
                "path": candidate.get("path"),
                "categories": list(candidate.get("categories", [])),
                "extension": candidate.get("extension"),
                "size": candidate.get("size"),
                "modified_at": candidate.get("modified_at"),
            }
        )
    return items


def summarize_large_file_candidates(candidates: object, *, limit: int) -> List[Dict[str, object]]:
    if not isinstance(candidates, list):
        return []
    sorted_candidates = sorted(
        (candidate for candidate in candidates if isinstance(candidate, dict)),
        key=lambda item: (-int(item.get("size", 0)), str(item.get("path", ""))),
    )
    items: List[Dict[str, object]] = []
    for candidate in sorted_candidates[:limit]:
        items.append(
            {
                "path": candidate.get("path"),
                "categories": list(candidate.get("categories", [])),
                "size": candidate.get("size"),
                "modified_at": candidate.get("modified_at"),
            }
        )
    return items


def collect_preferred_candidates(candidates: object, *, preferred_locations: Sequence[str]) -> List[Dict[str, object]]:
    if not isinstance(candidates, list) or not preferred_locations:
        return []
    normalized_locations = [value.lower() for value in preferred_locations]
    selected = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        path_value = str(candidate.get("path", "")).lower()
        if not any(location in path_value for location in normalized_locations):
            continue
        selected.append(
            {
                "path": candidate.get("path"),
                "categories": list(candidate.get("categories", [])),
                "size": candidate.get("size"),
                "modified_at": candidate.get("modified_at"),
            }
        )
    return selected


def build_markdown_report(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object] | None = None,
    files_payload: Mapping[str, object] | None = None,
    docs_extract_payload: Mapping[str, object] | None = None,
    files_extract_payload: Mapping[str, object] | None = None,
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    timeline_payload: Mapping[str, object] | None = None,
) -> str:
    report_context = build_run_report_context(
        summary_payload,
        docs_payload=docs_payload,
        files_payload=files_payload,
        docs_extract_payload=docs_extract_payload,
        files_extract_payload=files_extract_payload,
        artifact_payloads=artifact_payloads,
        timeline_payload=timeline_payload,
    )
    return render_run_markdown_report(report_context)


def build_key_hit_rows(
    summary_payload: Mapping[str, object],
    *,
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    timeline_payload: Mapping[str, object],
) -> List[str]:
    rows: List[str] = []
    matched_rules = summary_payload.get("matched_rules", [])
    if isinstance(matched_rules, list) and matched_rules:
        rows.append(f"Matched rules: {', '.join(str(item) for item in matched_rules[:5])}")

    ioc_hits = summary_payload.get("ioc_hits", [])
    if isinstance(ioc_hits, list):
        for hit in ioc_hits[:3]:
            if not isinstance(hit, dict):
                continue
            rows.append(
                f"IOC `{hit.get('value')}` detected via `{hit.get('type')}`"
                f" (rule `{hit.get('rule_id')}`)"
            )

    for item in docs_payload.get("results", [])[:3]:
        if not isinstance(item, dict):
            continue
        keywords = ", ".join(str(keyword) for keyword in item.get("matched_keywords", []))
        rows.append(f"Document hit `{item.get('path')}` keywords={keywords or 'none'}")

    for item in files_payload.get("candidates", [])[:2]:
        if not isinstance(item, dict):
            continue
        rows.append(
            f"File candidate `{item.get('path')}` categories={', '.join(str(value) for value in item.get('categories', []))}"
        )

    for kind, payload in artifact_payloads.items():
        artifact_count = int(payload.get("summary", {}).get("artifact_count", 0))
        if artifact_count:
            rows.append(f"Artifact collector `{kind}` returned {artifact_count} row(s)")

    for event in timeline_payload.get("events", [])[:2]:
        if not isinstance(event, dict):
            continue
        rows.append(
            f"Timeline `{event.get('timestamp')}` `{event.get('event_type')}` — {event.get('summary')}"
        )

    seen: set[str] = set()
    deduped: List[str] = []
    for row in rows:
        if row in seen:
            continue
        seen.add(row)
        deduped.append(row)
    return deduped[:10]


def append_related_document_rows(lines: List[str], results: object) -> None:
    if not isinstance(results, list) or not results:
        lines.append("- none")
        return
    for item in results[:10]:
        if not isinstance(item, dict):
            continue
        keywords = ", ".join(str(keyword) for keyword in item.get("matched_keywords", [])) or "none"
        lines.append(
            f"- `{item.get('path')}` ({item.get('kind')}) keywords={keywords}: {item.get('preview')}"
        )
        matched_rules = item.get("matched_rules", [])
        if isinstance(matched_rules, list) and matched_rules:
            lines.append(f"  - matched_rules: {', '.join(str(rule_id) for rule_id in matched_rules)}")
        ioc_hits = item.get("ioc_hits", [])
        if isinstance(ioc_hits, list) and ioc_hits:
            values = ", ".join(str(hit.get('value')) for hit in ioc_hits[:5] if isinstance(hit, dict))
            lines.append(f"  - ioc_hits: {values}")


def append_artifact_summary_rows(lines: List[str], artifact_payloads: Mapping[str, Mapping[str, object]]) -> None:
    if not artifact_payloads:
        lines.append("- none")
        return
    for kind, payload in artifact_payloads.items():
        summary = payload.get("summary", {})
        lines.append(
            f"- `{kind}` count={summary.get('artifact_count', 0)}"
            f" types={dict(summary.get('artifact_type_counts', {}))}"
        )
        artifacts = payload.get("artifacts", [])
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts[:3]:
            if not isinstance(artifact, dict):
                continue
            lines.append(
                f"  - `{artifact.get('artifact_type')}` `{artifact.get('path')}` provider=`{artifact.get('provider')}`"
            )


def append_timeline_rows(lines: List[str], timeline_payload: Mapping[str, object]) -> None:
    summary = timeline_payload.get("summary", {})
    events = timeline_payload.get("events", [])
    if not isinstance(events, list) or not events:
        lines.append("- none")
        return
    lines.extend(
        [
            f"- Event count: {summary.get('event_count', 0)}",
            f"- Earliest event: `{summary.get('earliest_event_at')}`",
            f"- Latest event: `{summary.get('latest_event_at')}`",
        ]
    )
    for event in events[:15]:
        if not isinstance(event, dict):
            continue
        lines.append(
            f"- `{event.get('timestamp')}` `{event.get('source')}` `{event.get('event_type')}`"
            f" `{event.get('path')}` — {event.get('summary')}"
        )
        matched_rules = event.get("matched_rules", [])
        if isinstance(matched_rules, list) and matched_rules:
            lines.append(f"  - matched_rules: {', '.join(str(rule_id) for rule_id in matched_rules)}")
        ioc_hits = event.get("ioc_hits", [])
        if isinstance(ioc_hits, list) and ioc_hits:
            values = ", ".join(str(hit.get('value')) for hit in ioc_hits[:5] if isinstance(hit, dict))
            lines.append(f"  - ioc_hits: {values}")


def append_extract_rows(
    lines: List[str],
    *,
    title: str,
    payload: Mapping[str, object],
    source_label: str,
) -> None:
    lines.extend([title, ""])
    summary = payload.get("summary", {})
    lines.append(
        f"- selected={summary.get('selected_count', 0)} extracted={summary.get('extracted_count', 0)}"
        f" skipped={summary.get('skipped_count', 0)} source={source_label}"
    )
    entries = payload.get("entries", [])
    if isinstance(entries, list) and entries:
        for entry in entries[:10]:
            if not isinstance(entry, dict):
                continue
            lines.append(
                f"  - `{entry.get('original_path')}` -> `{entry.get('extracted_path')}`"
                f" size={entry.get('size')} sha256={entry.get('sha256')}"
            )
    else:
        lines.append("  - none")
