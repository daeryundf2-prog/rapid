from __future__ import annotations

import datetime as dt
import html
import json
import shutil
import zipfile
from pathlib import Path
from typing import Mapping, Sequence

from .case import load_case_payload
from .case_report import build_case_report_markdown, report_export_csp, write_case_report_exports
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
    reviewer_path = output_dir / "rapidtriage-reviewer.html"
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
    report_exports = write_case_report_exports(report_markdown, report_path)
    reviewer_path.write_text(render_reviewer_html(manifest, selected, report_markdown), encoding="utf-8")
    audit = {
        "command": "bundle",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_json": str(case_json),
        "output_dir": str(output_dir),
        "outputs": {
            "manifest": str(manifest_path),
            "selected_evidence": str(selected_path),
            "report": report_exports["md"],
            "report_html": report_exports["html"],
            "report_docx": report_exports["docx"],
            "report_pdf": report_exports["pdf"],
            "report_export_manifest": report_exports["manifest"],
            "reviewer": str(reviewer_path),
        },
    }
    write_result(audit, audit_path)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in (
            manifest_path,
            selected_path,
            Path(report_exports["md"]),
            Path(report_exports["html"]),
            Path(report_exports["docx"]),
            Path(report_exports["pdf"]),
            Path(report_exports["manifest"]),
            reviewer_path,
            audit_path,
        ):
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
            "report": report_exports["md"],
            "report_html": report_exports["html"],
            "report_docx": report_exports["docx"],
            "report_pdf": report_exports["pdf"],
            "report_export_manifest": report_exports["manifest"],
            "reviewer": str(reviewer_path),
            "audit": str(audit_path),
            "archive": str(zip_path),
        },
    }
    write_result(bundle_manifest, output_dir / "rapidtriage-bundle-manifest.json")
    return bundle_manifest


def render_reviewer_html(
    manifest: Mapping[str, object],
    selected: Mapping[str, object],
    report_markdown: str,
) -> str:
    items = selected.get("items") if isinstance(selected.get("items"), list) else []
    manifest_summary = manifest.get("summary") if isinstance(manifest.get("summary"), Mapping) else {}
    rows = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        hashes = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        rows.append(
            "<tr>"
            f"<td>{escape(item.get('bookmark_id', ''))}</td>"
            f"<td>{escape(item.get('summary', ''))}<br><small>{escape(item.get('path', ''))}</small></td>"
            f"<td>{escape(review.get('status', ''))}</td>"
            f"<td><code>{escape(hashes.get('sha256', ''))}</code></td>"
            "</tr>"
        )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8" />',
            '<meta name="viewport" content="width=device-width, initial-scale=1" />',
            '<meta name="referrer" content="no-referrer" />',
            f'<meta http-equiv="Content-Security-Policy" content="{escape(report_export_csp())}" />',
            "<title>RapidTriage Reviewer Bundle</title>",
            "<style>",
            "body{font-family:Georgia,serif;margin:32px;background:#f7f2ea;color:#1f2528}",
            "main{max-width:1100px;margin:auto;background:white;border:1px solid #ddd0bf;border-radius:12px;padding:24px}",
            "table{width:100%;border-collapse:collapse;margin:16px 0}th,td{border-bottom:1px solid #eee;padding:10px;text-align:left;vertical-align:top}",
            "code,pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8f5ef;padding:2px 4px;border-radius:4px}",
            ".metric{display:inline-block;margin:4px 10px 4px 0;padding:8px 10px;border:1px solid #ddd0bf;border-radius:999px;font-weight:bold}",
            "</style>",
            "</head>",
            "<body><main>",
            "<h1>RapidTriage Reviewer Bundle</h1>",
            "<p>This portable review package contains selected artifact metadata, analyst review state, hashes, and report text. It does not include the original evidence image.</p>",
            f"<span class=\"metric\">Case: {escape(manifest.get('case_id', ''))}</span>",
            f"<span class=\"metric\">Hashed items: {escape(manifest_summary.get('hashed_item_count', 0))}</span>",
            f"<span class=\"metric\">Skipped: {escape(manifest_summary.get('skipped_count', 0))}</span>",
            "<h2>Selected Evidence</h2>",
            "<table><thead><tr><th>Bookmark</th><th>Evidence</th><th>Review</th><th>SHA256</th></tr></thead><tbody>",
            "\n".join(rows) if rows else '<tr><td colspan="4">No selected evidence.</td></tr>',
            "</tbody></table>",
            "<h2>Report Draft</h2>",
            f"<pre>{escape(report_markdown)}</pre>",
            "</main></body></html>",
        ]
    )


def escape(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


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
