from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Union

from .artifacts import run_artifact_collection
from .docs import build_manifest, run_docs_search, write_result
from .extract import DEFAULT_EXTRACT_MANIFEST_NAME, run_extract
from .files import run_files_scan
from .input_root import InputRoot, derive_child_input_root, resolve_input_root

SUPPORTED_RUN_MODES: tuple[str, ...] = ("seizure", "fraud", "hacking", "recovery")
IMPLEMENTED_RUN_MODES = set(SUPPORTED_RUN_MODES)


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
        docs_extract_kinds=("txt", "pdf", "docx"),
        file_extract_categories=("documents", "archives", "databases"),
        file_scan_categories=("documents", "archives", "databases"),
        scan_root_parts=("Users",),
        preferred_locations=("downloads", "desktop", "documents"),
        artifacts_kinds=("browser", "recent-files"),
    ),
    "fraud": RunProfile(
        mode="fraud",
        description="Document-forward fraud triage focused on payment, account, and invoice evidence.",
        keywords=("fraud", "invoice", "payment", "transfer", "bank", "account", "receipt", "refund"),
        docs_extract_kinds=("txt", "pdf", "docx"),
        file_extract_categories=("documents", "archives", "databases"),
        file_scan_categories=("documents", "archives", "databases"),
        artifacts_kinds=("browser", "recent-files"),
    ),
    "hacking": RunProfile(
        mode="hacking",
        description="Intrusion triage focused on suspicious binaries, credential theft, persistence, and attacker tooling.",
        keywords=("hacking", "malware", "credential", "powershell", "persistence", "ransomware", "shell", "exfil"),
        docs_extract_kinds=("txt", "pdf", "docx"),
        file_extract_categories=("executables", "archives", "databases"),
        file_scan_categories=("executables", "archives", "databases"),
        artifacts_kinds=("browser", "recent-files"),
    ),
    "recovery": RunProfile(
        mode="recovery",
        description="Recovery triage focused on deleted, recycled, or restorable file candidates without doing carving.",
        keywords=("recovery", "deleted", "recycle", "trash", "restore", "backup", "recent"),
        docs_extract_kinds=("txt", "pdf", "docx"),
        file_extract_categories=("documents", "archives", "images"),
        file_scan_categories=("documents", "archives", "images"),
        file_scan_path_contains=("recycle",),
        preferred_locations=("$recycle.bin", "recycle", "trash", "deleted"),
        artifacts_kinds=("recent-files",),
    ),
}


class RunModeError(ValueError):
    """Raised when the requested run mode is invalid or unsupported."""


def run_triage_mode(root: Union[InputRoot, Path], *, mode: str, output_dir: Path, input_kind: str | None = None) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    normalized_mode = mode.lower()
    if normalized_mode not in SUPPORTED_RUN_MODES:
        supported = ", ".join(SUPPORTED_RUN_MODES)
        raise RunModeError(f"unsupported run mode: {mode} (supported: {supported})")
    if normalized_mode not in IMPLEMENTED_RUN_MODES:
        available = ", ".join(sorted(IMPLEMENTED_RUN_MODES))
        raise RunModeError(f"run mode '{normalized_mode}' is not implemented yet (currently available: {available})")

    profile = RUN_PROFILES[normalized_mode]
    output_dir = output_dir.expanduser().resolve()
    scan_root = resolve_scan_root(input_root.root_path, profile)
    scan_input_root = derive_child_input_root(input_root, scan_root)

    manifest_path = output_dir / "rapidtriage-manifest.json"
    docs_path = output_dir / "rapidtriage-docs.json"
    files_path = output_dir / "rapidtriage-files.json"
    artifacts_dir = output_dir / "artifacts"
    docs_extract_dir = output_dir / "docs-extract"
    files_extract_dir = output_dir / "files-extract"
    docs_extract_manifest = docs_extract_dir / DEFAULT_EXTRACT_MANIFEST_NAME
    files_extract_manifest = files_extract_dir / DEFAULT_EXTRACT_MANIFEST_NAME
    summary_path = output_dir / "rapidtriage-run-summary.json"
    report_path = output_dir / "rapidtriage-run-report.md"

    manifest_payload = build_manifest(input_root, profile.keywords)
    docs_payload = run_docs_search(scan_input_root, profile.keywords)
    docs_payload["manifest"] = manifest_payload
    docs_payload["scan_scope_root"] = str(scan_input_root.root_path)

    files_payload = run_files_scan(
        scan_input_root,
        categories=profile.file_scan_categories,
        path_contains=profile.file_scan_path_contains or None,
    )
    files_payload["scan_scope_root"] = str(scan_input_root.root_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    write_result(manifest_payload, manifest_path)
    write_result(docs_payload, docs_path)
    write_result(files_payload, files_path)

    artifact_outputs: Dict[str, Path] = {}
    artifact_payloads: Dict[str, Dict[str, object]] = {}
    for kind in profile.artifacts_kinds:
        artifact_path = artifacts_dir / f"rapidtriage-artifacts-{kind}.json"
        artifact_payload = run_artifact_collection(input_root, kind=kind)
        artifact_outputs[kind] = artifact_path
        artifact_payloads[kind] = artifact_payload
        write_result(artifact_payload, artifact_path)

    docs_extract_payload = run_extract(docs_path, docs_extract_dir, kinds=profile.docs_extract_kinds)
    files_extract_payload = run_extract(files_path, files_extract_dir, categories=profile.file_extract_categories)
    write_result(docs_extract_payload, docs_extract_manifest)
    write_result(files_extract_payload, files_extract_manifest)

    outputs = {
        "manifest": manifest_path,
        "docs": docs_path,
        "files": files_path,
        "docs_extract_manifest": docs_extract_manifest,
        "files_extract_manifest": files_extract_manifest,
        **{f"artifacts_{kind}": path for kind, path in artifact_outputs.items()},
        "summary": summary_path,
        "report": report_path,
    }
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
        outputs=outputs,
    )
    report_path.write_text(build_markdown_report(summary_payload), encoding="utf-8")
    write_result(summary_payload, summary_path)
    return summary_payload


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
    outputs: Mapping[str, Path],
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

    return {
        "command": "run",
        "mode": profile.mode,
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(root),
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
        "outputs": {name: str(path) for name, path in outputs.items()},
        "steps": build_step_rows(
            manifest_payload=manifest_payload,
            docs_payload=docs_payload,
            files_payload=files_payload,
            docs_extract_payload=docs_extract_payload,
            files_extract_payload=files_extract_payload,
            artifact_payloads=artifact_payloads,
            outputs=outputs,
        ),
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
        },
        "highlights": {
            "document_hits": summarize_document_hits(docs_payload.get("results", []), limit=5),
            "recent_file_candidates": recent_candidates,
            "large_file_candidates": large_candidates,
            "preferred_location_candidates": preferred_candidates[:5],
        },
    }


def build_step_rows(
    *,
    manifest_payload: Mapping[str, object],
    docs_payload: Mapping[str, object],
    files_payload: Mapping[str, object],
    docs_extract_payload: Mapping[str, object],
    files_extract_payload: Mapping[str, object],
    artifact_payloads: Mapping[str, Mapping[str, object]],
    outputs: Mapping[str, Path],
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = [
        {
            "name": "manifest",
            "status": "completed",
            "output": str(outputs["manifest"]),
            "provider_count": len(manifest_payload.get("providers", [])),
        },
        {
            "name": "docs",
            "status": "completed",
            "output": str(outputs["docs"]),
            "candidate_count": int(docs_payload.get("summary", {}).get("candidate_count", 0)),
            "match_count": int(docs_payload.get("summary", {}).get("match_count", 0)),
        },
        {
            "name": "files",
            "status": "completed",
            "output": str(outputs["files"]),
            "scanned_file_count": int(files_payload.get("summary", {}).get("scanned_file_count", 0)),
            "candidate_count": int(files_payload.get("summary", {}).get("candidate_count", 0)),
        },
    ]
    for kind, payload in artifact_payloads.items():
        rows.append(
            {
                "name": f"artifacts-{kind}",
                "status": "completed",
                "output": str(outputs[f"artifacts_{kind}"]),
                "artifact_count": int(payload.get("summary", {}).get("artifact_count", 0)),
            }
        )
    rows.extend(
        [
            {
                "name": "docs-extract",
                "status": "completed",
                "output": str(outputs["docs_extract_manifest"]),
                "selected_count": int(docs_extract_payload.get("summary", {}).get("selected_count", 0)),
                "extracted_count": int(docs_extract_payload.get("summary", {}).get("extracted_count", 0)),
            },
            {
                "name": "files-extract",
                "status": "completed",
                "output": str(outputs["files_extract_manifest"]),
                "selected_count": int(files_extract_payload.get("summary", {}).get("selected_count", 0)),
                "extracted_count": int(files_extract_payload.get("summary", {}).get("extracted_count", 0)),
            },
        ]
    )
    return rows


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


def build_markdown_report(summary_payload: Mapping[str, object]) -> str:
    profile = summary_payload["profile"]
    outputs = summary_payload["outputs"]
    summary = summary_payload["summary"]
    steps = summary_payload["steps"]
    highlights = summary_payload["highlights"]

    lines = [
        "# rapidtriage run report",
        "",
        f"- Mode: `{summary_payload['mode']}`",
        f"- Root: `{summary_payload['root']}`",
        f"- Scan scope root: `{summary_payload['scan_scope_root']}`",
        f"- Generated at: `{summary_payload['generated_at']}`",
        f"- Output directory: `{summary_payload['output_dir']}`",
        "",
        "## Mode profile",
        "",
        f"- Description: {profile['description']}",
        f"- Keywords: {', '.join(profile['keywords'])}",
        f"- Docs extract kinds: {', '.join(profile['docs_extract_kinds'])}",
        f"- File extract categories: {', '.join(profile['file_extract_categories'])}",
        f"- File scan categories: {', '.join(profile['file_scan_categories'])}",
        "",
        "## Step outputs",
        "",
    ]
    for step in steps:
        detail_parts = [f"{key}={value}" for key, value in step.items() if key not in {"name", "status", "output"}]
        detail_text = ", ".join(detail_parts) if detail_parts else "no metrics"
        lines.append(f"- `{step['name']}` ({step['status']}): `{step['output']}` — {detail_text}")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Document candidates: {summary['document_candidate_count']}",
            f"- Document matches: {summary['document_match_count']}",
            f"- Scanned files: {summary['scanned_file_count']}",
            f"- File candidates: {summary['file_candidate_count']}",
            f"- Docs extracted: {summary['docs_extracted_count']}",
            f"- Files extracted: {summary['files_extracted_count']}",
            f"- Preferred-location candidates: {summary['preferred_location_candidate_count']}",
            "",
            "### Windows provider artifact counts",
            "",
        ]
    )

    windows_counts = summary.get("windows_provider_artifact_counts", {})
    if windows_counts:
        for name, count in windows_counts.items():
            lines.append(f"- `{name}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "### Dedicated artifact outputs", ""])
    artifacts_summary = summary.get("artifacts", {})
    if artifacts_summary:
        for kind, details in artifacts_summary.items():
            lines.append(
                f"- `{kind}`: count={details['artifact_count']} output=`{details['output']}`"
            )
    else:
        lines.append("- none")

    lines.extend(["", "### Matched keyword counts", ""])
    keyword_counts = summary.get("matched_keyword_counts", {})
    if keyword_counts:
        for keyword, count in keyword_counts.items():
            lines.append(f"- `{keyword}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "### File category counts", ""])
    category_counts = summary.get("file_category_counts", {})
    if category_counts:
        for category, count in category_counts.items():
            lines.append(f"- `{category}`: {count}")
    else:
        lines.append("- none")

    lines.extend(["", "## Highlighted document hits", ""])
    document_hits = highlights.get("document_hits", [])
    if document_hits:
        for item in document_hits:
            lines.append(
                f"- `{item['path']}` ({item['kind']}) keywords={', '.join(item['matched_keywords'])}: {item['preview']}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Recent file candidates", ""])
    recent_candidates = highlights.get("recent_file_candidates", [])
    if recent_candidates:
        for item in recent_candidates:
            lines.append(
                f"- `{item['path']}` categories={', '.join(item['categories'])} size={item['size']} modified={item['modified_at']}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Largest file candidates", ""])
    large_candidates = highlights.get("large_file_candidates", [])
    if large_candidates:
        for item in large_candidates:
            lines.append(
                f"- `{item['path']}` categories={', '.join(item['categories'])} size={item['size']} modified={item['modified_at']}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Preferred location candidates", ""])
    preferred_candidates = highlights.get("preferred_location_candidates", [])
    if preferred_candidates:
        for item in preferred_candidates:
            lines.append(
                f"- `{item['path']}` categories={', '.join(item['categories'])} size={item['size']} modified={item['modified_at']}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Output paths", ""])
    for name, path in outputs.items():
        lines.append(f"- `{name}`: `{path}`")
    return "\n".join(lines) + "\n"
