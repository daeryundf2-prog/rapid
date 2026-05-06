from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import shutil
import zipfile
from pathlib import Path
from typing import Mapping, Sequence

from .case import load_case_payload
from .case_report import build_case_report_markdown, report_export_csp, write_case_report_exports
from .docs import write_result
from .forensic_accuracy import build_accuracy_gate
from .submission import build_submission_manifest, compute_hashes

COURT_EXHIBIT_EXPORT_GAP_ID = "#94"
TAMPER_EVIDENT_AUDIT_BUNDLE_GAP_ID = "#100"
COURT_EXHIBIT_TRUSTED_DIFF_BLOCKER_94 = "trusted-court-exhibit-manifest-diff-missing"
COURT_EXHIBIT_TRUSTED_TOOLS = {"court-exhibit-checklist", "selected-evidence-manifest", "signed-exhibit-index"}


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
    court_exhibit_path = output_dir / "rapidtriage-court-exhibit-index.json"
    tamper_audit_path = output_dir / "rapidtriage-tamper-evident-audit-bundle.json"
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
            "court_exhibit_index": str(court_exhibit_path),
            "tamper_evident_audit_bundle": str(tamper_audit_path),
            "bundle_manifest": str(bundle_manifest_path),
        },
    }
    write_result(audit, audit_path)
    court_exhibit_index = build_court_exhibit_index(
        manifest=manifest,
        selected=selected,
        output_paths=[
            ("submission_manifest", manifest_path),
            ("selected_evidence", selected_path),
            ("report_markdown", Path(report_exports["md"])),
            ("report_html", Path(report_exports["html"])),
            ("report_docx", Path(report_exports["docx"])),
            ("report_pdf", Path(report_exports["pdf"])),
            ("report_export_manifest", Path(report_exports["manifest"])),
            ("reviewer_html", reviewer_path),
            ("bundle_audit", audit_path),
        ],
    )
    write_result(court_exhibit_index, court_exhibit_path)
    tamper_audit_bundle = build_tamper_evident_audit_bundle(
        output_paths=[
            ("submission_manifest", manifest_path),
            ("selected_evidence", selected_path),
            ("report_markdown", Path(report_exports["md"])),
            ("report_html", Path(report_exports["html"])),
            ("report_docx", Path(report_exports["docx"])),
            ("report_pdf", Path(report_exports["pdf"])),
            ("report_export_manifest", Path(report_exports["manifest"])),
            ("reviewer_html", reviewer_path),
            ("court_exhibit_index", court_exhibit_path),
            ("bundle_audit", audit_path),
        ],
    )
    write_result(tamper_audit_bundle, tamper_audit_path)
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
        "court_exhibit_package": {
            "index": str(court_exhibit_path),
            "status": "review-package-ready",
            "note": "Use the exhibit index with the archive SHA256; original evidence images remain outside this bundle.",
        },
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
            court_exhibit_path,
            tamper_audit_path,
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
            "court_exhibit_index": str(court_exhibit_path),
            "tamper_evident_audit_bundle": str(tamper_audit_path),
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


def build_court_exhibit_index(
    *,
    manifest: Mapping[str, object],
    selected: Mapping[str, object],
    output_paths: Sequence[tuple[str, Path]],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    items = selected.get("items") if isinstance(selected.get("items"), list) else []
    exhibit_items = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, Mapping):
            continue
        hashes = item.get("hashes") if isinstance(item.get("hashes"), Mapping) else {}
        reference = item.get("reference") if isinstance(item.get("reference"), Mapping) else {}
        exhibit_items.append(
            {
                "exhibit_id": f"EXH-{index:04d}",
                "bookmark_id": str(item.get("bookmark_id") or ""),
                "summary": str(item.get("summary") or ""),
                "path": str(item.get("path") or ""),
                "sha256": str(hashes.get("sha256") or ""),
                "review_status": str((item.get("review") or {}).get("status") if isinstance(item.get("review"), Mapping) else ""),
                "source_reference": dict(reference),
                "hash_status": str(item.get("hash_status") or ""),
            }
        )
    output_hashes = []
    for label, path in output_paths:
        if not path.exists() or not path.is_file():
            continue
        output_hashes.append(
            {
                "label": label,
                "path": str(path),
                "hashes": compute_hashes(path),
                "size_bytes": path.stat().st_size,
            }
        )
    blockers = []
    if not trusted_diff or trusted_diff.get("status") != "pass":
        blockers.append(COURT_EXHIBIT_TRUSTED_DIFF_BLOCKER_94)
    return {
        "command": "court-exhibit-index",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "case_id": str(manifest.get("case_id") or ""),
        "commercial_gap_ids": [COURT_EXHIBIT_EXPORT_GAP_ID],
        "summary": {
            "exhibit_item_count": len(exhibit_items),
            "output_hash_count": len(output_hashes),
            "commercial_gap_ids": [COURT_EXHIBIT_EXPORT_GAP_ID],
        },
        "exhibits": exhibit_items,
        "output_hashes": output_hashes,
        "trusted_court_exhibit_diff": dict(trusted_diff) if trusted_diff else missing_court_exhibit_trusted_diff(),
        "core_accuracy_gates": court_exhibit_core_accuracy_gates(
            exhibits=exhibit_items,
            output_hashes=output_hashes,
            trusted_diff=trusted_diff,
        ),
        "blockers": blockers,
        "custody_note": "This index documents selected report exhibits and generated bundle outputs. It does not include original evidence images.",
        "verification_steps": [
            "Verify archive SHA256 from rapidtriage-bundle-manifest.json.",
            "Verify each generated output hash before handoff.",
            "Cross-check each exhibit path/hash against the authoritative source evidence.",
        ],
    }


def build_tamper_evident_audit_bundle(*, output_paths: Sequence[tuple[str, Path]]) -> dict[str, object]:
    entries = []
    previous_hash = ""
    for label, path in output_paths:
        if not path.exists() or not path.is_file():
            continue
        entry = {
            "label": label,
            "path": str(path),
            "hashes": compute_hashes(path),
            "size_bytes": path.stat().st_size,
            "previous_entry_hash": previous_hash,
        }
        entry_hash = hashlib.sha256(
            json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        entry["entry_hash"] = entry_hash
        previous_hash = entry_hash
        entries.append(entry)
    return {
        "command": "tamper-evident-audit-bundle",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "commercial_gap_ids": [TAMPER_EVIDENT_AUDIT_BUNDLE_GAP_ID],
        "summary": {
            "entry_count": len(entries),
            "head_hash": previous_hash,
            "commercial_gap_ids": [TAMPER_EVIDENT_AUDIT_BUNDLE_GAP_ID],
        },
        "entries": entries,
        "core_accuracy_gates": tamper_evident_bundle_core_accuracy_gates(entries=entries, head_hash=previous_hash),
        "verification_steps": [
            "Recompute each output hash.",
            "Recompute each entry_hash in order using previous_entry_hash.",
            "Compare the final head_hash against this file and the bundle manifest.",
        ],
        "limitation": "This is an export-time hash chain. External signing/notarization is still required for formal immutability.",
    }


def court_exhibit_core_accuracy_gates(
    *,
    exhibits: Sequence[Mapping[str, object]],
    output_hashes: Sequence[Mapping[str, object]],
    trusted_diff: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    satisfied = ["verification steps emitted"]
    if exhibits and all(item.get("exhibit_id") for item in exhibits):
        satisfied.append("exhibit IDs assigned")
    if any(item.get("sha256") for item in exhibits):
        satisfied.append("selected evidence hashes preserved")
    if output_hashes:
        satisfied.append("generated output hashes captured")
    if any(item.get("source_reference") for item in exhibits):
        satisfied.append("source references preserved")
    if trusted_diff and trusted_diff.get("status") == "pass":
        satisfied.append("trusted court exhibit manifest diff pass")
    return [
        build_accuracy_gate(
            94,
            satisfied_checks=satisfied,
            evidence_refs=[
                f"exhibit_count:{len(exhibits)}",
                f"output_hash_count:{len(output_hashes)}",
            ],
        )
    ]


def missing_court_exhibit_trusted_diff() -> dict[str, object]:
    return {
        "status": "missing",
        "trusted_tool": None,
        "commercial_gap_ids": [COURT_EXHIBIT_EXPORT_GAP_ID],
        "blocker": COURT_EXHIBIT_TRUSTED_DIFF_BLOCKER_94,
        "required_trusted_tools": sorted(COURT_EXHIBIT_TRUSTED_TOOLS),
    }


def build_court_exhibit_trusted_diff(
    rapid_index: Mapping[str, object],
    trusted_index: Mapping[str, object],
    *,
    trusted_tool: str = "court-exhibit-checklist",
) -> dict[str, object]:
    mismatches = []
    for field in ("exhibits", "output_hashes"):
        rapid_value = normalize_court_exhibit_value(rapid_index.get(field))
        trusted_value = normalize_court_exhibit_value(trusted_index.get(field))
        if rapid_value != trusted_value:
            mismatches.append({"field": field, "rapid": rapid_value, "trusted": trusted_value})
    status = "pass" if not mismatches and trusted_tool in COURT_EXHIBIT_TRUSTED_TOOLS else "fail"
    return {
        "status": status,
        "trusted_tool": trusted_tool,
        "commercial_gap_ids": [COURT_EXHIBIT_EXPORT_GAP_ID],
        "compared_fields": ["exhibits", "output_hashes"],
        "mismatches": mismatches,
        "blocker": None if status == "pass" else COURT_EXHIBIT_TRUSTED_DIFF_BLOCKER_94,
    }


def normalize_court_exhibit_value(value: object) -> object:
    if isinstance(value, list):
        return sorted(json.dumps(item, ensure_ascii=False, sort_keys=True, default=str) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, default=str)
    return value


def tamper_evident_bundle_core_accuracy_gates(
    *,
    entries: Sequence[Mapping[str, object]],
    head_hash: str,
) -> list[dict[str, object]]:
    satisfied = ["external signing limitation emitted"]
    if entries:
        satisfied.append("generated output hashes captured")
    if all("previous_entry_hash" in item for item in entries):
        satisfied.append("previous-entry hash chain generated")
    if all(item.get("entry_hash") for item in entries):
        satisfied.append("entry hashes emitted")
    if head_hash:
        satisfied.append("head hash recorded")
    return [
        build_accuracy_gate(
            100,
            satisfied_checks=satisfied,
            evidence_refs=[f"entry_count:{len(entries)}", f"head_hash:{head_hash}"],
        )
    ]


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
