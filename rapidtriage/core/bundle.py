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
    bundle_manifest_path = output_dir / "rapidtriage-bundle-manifest.json"
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
        "allowed_roots": [str(root.expanduser().resolve()) for root in allowed_roots],
        "integrity_note": "The bundle archive hash is stored in rapidtriage-bundle-manifest.json after ZIP creation.",
        "outputs": {
            "manifest": str(manifest_path),
            "selected_evidence": str(selected_path),
            "report": report_exports["md"],
            "report_html": report_exports["html"],
            "report_docx": report_exports["docx"],
            "report_pdf": report_exports["pdf"],
            "report_export_manifest": report_exports["manifest"],
            "reviewer": str(reviewer_path),
            "bundle_manifest": str(bundle_manifest_path),
        },
    }
    write_result(audit, audit_path)
    preliminary_manifest = {
        "command": "bundle",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": manifest.get("case_id", ""),
        "output_dir": str(output_dir),
        "archive": str(zip_path),
        "archive_hashes": {},
        "summary": {
            "hashed_item_count": manifest.get("summary", {}).get("hashed_item_count", 0)
            if isinstance(manifest.get("summary"), Mapping)
            else 0,
            "skipped_count": manifest.get("summary", {}).get("skipped_count", 0)
            if isinstance(manifest.get("summary"), Mapping)
            else 0,
        },
        "outputs": audit["outputs"] | {"audit": str(audit_path), "archive": str(zip_path)},
        "custody_note": "Reviewer bundle contains review metadata, selected evidence hashes, and report drafts; it does not include the original evidence image.",
    }
    write_result(preliminary_manifest, bundle_manifest_path)
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
            bundle_manifest_path,
        ):
            archive.write(path, path.name)
    integrity = compute_hashes(zip_path)
    bundle_manifest = {
        **preliminary_manifest,
        "command": "bundle",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": manifest.get("case_id", ""),
        "output_dir": str(output_dir),
        "archive": str(zip_path),
        "archive_hashes": integrity,
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
            "bundle_manifest": str(bundle_manifest_path),
            "archive": str(zip_path),
        },
    }
    write_result(bundle_manifest, bundle_manifest_path)
    return bundle_manifest


def render_reviewer_html(
    manifest: Mapping[str, object],
    selected: Mapping[str, object],
    report_markdown: str,
) -> str:
    items = selected.get("items") if isinstance(selected.get("items"), list) else []
    manifest_summary = manifest.get("summary") if isinstance(manifest.get("summary"), Mapping) else {}
    status_counts = count_review_statuses(items)
    selected_preview = build_selected_preview(items)
    rows = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        hashes = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []
        rows.append(
            "<tr>"
            f"<td>{escape(item.get('bookmark_id', ''))}</td>"
            f"<td>{escape(item.get('summary', ''))}<br><small>{escape(item.get('path', ''))}</small><br><small>Tags: {escape(', '.join(str(tag) for tag in tags) or 'none')}</small></td>"
            f"<td>{escape(review.get('status', ''))}<br><small>{escape(item.get('note', ''))}</small></td>"
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
            ".preview{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:16px 0}.card{border:1px solid #eee0cf;border-radius:10px;padding:12px;background:#fffaf2}.card small{color:#64706a}",
            "</style>",
            "</head>",
            "<body><main>",
            "<h1>RapidTriage Reviewer Bundle</h1>",
            "<p>This portable review package contains selected artifact metadata, analyst review state, hashes, and report text. It does not include the original evidence image.</p>",
            "<p><strong>Integrity:</strong> verify <code>rapidtriage-submission-manifest.json</code>, <code>rapidtriage-case-report.exports.json</code>, and <code>rapidtriage-bundle-manifest.json</code> before external handoff.</p>",
            f"<span class=\"metric\">Case: {escape(manifest.get('case_id', ''))}</span>",
            f"<span class=\"metric\">Hashed items: {escape(manifest_summary.get('hashed_item_count', 0))}</span>",
            f"<span class=\"metric\">Skipped: {escape(manifest_summary.get('skipped_count', 0))}</span>",
            f"<span class=\"metric\">Relevant: {escape(status_counts.get('relevant', 0))}</span>",
            f"<span class=\"metric\">Needs review: {escape(status_counts.get('needs-review', 0))}</span>",
            "<h2>Reviewer Checklist</h2>",
            "<ul>",
            "<li>Open the selected evidence list first, then compare each row against the hash manifest.</li>",
            "<li>Use the report draft as a narrative aid, not as a substitute for source-evidence validation.</li>",
            "<li>If a path is unavailable, request the examiner's authoritative evidence copy instead of using this bundle as source evidence.</li>",
            "</ul>",
            "<h2>Quick Preview</h2>",
            '<section class="preview">',
            selected_preview or '<article class="card">No selected evidence preview.</article>',
            "</section>",
            "<h2>Selected Evidence</h2>",
            "<table><thead><tr><th>Bookmark</th><th>Evidence</th><th>Review / note</th><th>SHA256</th></tr></thead><tbody>",
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
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        selected.append(
            {
                "bookmark_id": item.get("bookmark_id", ""),
                "summary": item.get("summary", ""),
                "path": evidence.get("path", ""),
                "size": evidence.get("size", 0),
                "hashes": evidence.get("hashes", {}),
                "review": review,
                "tags": item.get("tags", []),
                "note": item.get("note", ""),
                "reference": item.get("reference", {}),
                "modified_at": evidence.get("modified_at", ""),
                "hash_status": "hashed" if evidence.get("hashes") else "missing",
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


def count_review_statuses(items: object) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(items, list):
        return counts
    for item in items:
        if not isinstance(item, Mapping):
            continue
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        status = str(review.get("status") or "unreviewed")
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_selected_preview(items: object, *, limit: int = 6) -> str:
    if not isinstance(items, list):
        return ""
    cards: list[str] = []
    for item in items[:limit]:
        if not isinstance(item, Mapping):
            continue
        review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
        hashes = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        sha256 = str(hashes.get("sha256") or "")
        cards.append(
            "<article class=\"card\">"
            f"<strong>{escape(item.get('summary') or item.get('bookmark_id') or 'Evidence')}</strong><br>"
            f"<small>{escape(item.get('path', ''))}</small><br>"
            f"<span>Status: {escape(review.get('status', 'unreviewed'))}</span><br>"
            f"<span>SHA256: <code>{escape(sha256[:24] + ('...' if len(sha256) > 24 else ''))}</code></span>"
            "</article>"
        )
    return "\n".join(cards)
