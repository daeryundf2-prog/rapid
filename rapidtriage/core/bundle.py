from __future__ import annotations

import datetime as dt
import json
import shutil
import zipfile
from pathlib import Path
from typing import Mapping, Sequence

from .case import load_case_payload
from .case_report import build_case_report_markdown
from .docs import write_result
from .submission import build_submission_manifest, compute_hashes


class BundleError(ValueError):
    """Raised when a submission bundle cannot be created."""


def build_submission_bundle(
    *,
    case_json: Path,
    output_dir: Path,
    allowed_roots: Sequence[Path],
    include_all: bool = False,
    max_items: int = 500,
    title: str | None = None,
) -> dict[str, object]:
    case_json = case_json.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    case_payload = load_case_payload(case_json)
    manifest = build_submission_manifest(
        case_payload,
        allowed_roots=allowed_roots,
        include_all=include_all,
        max_items=max_items,
    )
    manifest_path = output_dir / "rapidtriage-submission-manifest.json"
    selected_path = output_dir / "rapidtriage-selected-evidence.json"
    report_path = output_dir / "rapidtriage-case-report.md"
    audit_path = output_dir / "rapidtriage-bundle-audit.json"
    zip_path = output_dir.with_suffix(".zip")

    write_result(manifest, manifest_path)
    selected = build_selected_evidence_list(manifest)
    write_result(selected, selected_path)
    report_markdown = build_case_report_markdown(
        run_summary={},
        case_payload=case_payload,
        submission_manifest=manifest,
        metadata={"title": title or case_payload.get("title") or "RapidTriage submission bundle"},
    )
    report_path.write_text(report_markdown, encoding="utf-8")
    audit = {
        "command": "bundle",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_json": str(case_json),
        "output_dir": str(output_dir),
        "outputs": {
            "manifest": str(manifest_path),
            "selected_evidence": str(selected_path),
            "report": str(report_path),
        },
    }
    write_result(audit, audit_path)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in (manifest_path, selected_path, report_path, audit_path):
            archive.write(path, path.name)
    integrity = compute_hashes(zip_path)
    bundle_manifest = {
        "command": "bundle",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": manifest.get("case_id", ""),
        "output_dir": str(output_dir),
        "archive": str(zip_path),
        "archive_hashes": integrity,
        "summary": {
            "hashed_item_count": manifest.get("summary", {}).get("hashed_item_count", 0)
            if isinstance(manifest.get("summary"), Mapping)
            else 0,
            "skipped_count": manifest.get("summary", {}).get("skipped_count", 0)
            if isinstance(manifest.get("summary"), Mapping)
            else 0,
        },
        "outputs": {
            "manifest": str(manifest_path),
            "selected_evidence": str(selected_path),
            "report": str(report_path),
            "audit": str(audit_path),
            "archive": str(zip_path),
        },
    }
    write_result(bundle_manifest, output_dir / "rapidtriage-bundle-manifest.json")
    return bundle_manifest


def build_selected_evidence_list(manifest: Mapping[str, object]) -> dict[str, object]:
    items = manifest.get("items") if isinstance(manifest.get("items"), list) else []
    selected = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
        selected.append(
            {
                "bookmark_id": item.get("bookmark_id", ""),
                "summary": item.get("summary", ""),
                "path": evidence.get("path", ""),
                "size": evidence.get("size", 0),
                "hashes": evidence.get("hashes", {}),
                "review": item.get("review", {}),
            }
        )
    return {
        "command": "selected-evidence",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "items": selected,
    }


def copy_if_requested(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
