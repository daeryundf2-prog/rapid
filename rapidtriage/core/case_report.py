from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import re
import zipfile
from collections.abc import Mapping
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from .. import PRODUCT_NAME
from . import case_report_items as report_items
from .ai_report import AI_SECTION_ID, ai_usage_section_lines, ai_usage_summary
from .korean_report import TEMPLATE_ID as KOREAN_EXPERT_TEMPLATE_ID
from .korean_report import build_korean_expert_report
from .report_candidates import report_scope_notes
from .step_labels import run_mode_ko

CASE_REPORT_EXPORTS = {
    "md": "rapidtriage-case-report.md",
    "html": "rapidtriage-case-report.html",
    "docx": "rapidtriage-case-report.docx",
    "pdf": "rapidtriage-case-report.pdf",
    "manifest": "rapidtriage-case-report.exports.json",
}


def build_case_report_markdown(
    *,
    run_summary: Mapping[str, object],
    case_payload: Mapping[str, object],
    submission_manifest: Mapping[str, object],
    metadata: Mapping[str, object] | None = None,
    report_context: Mapping[str, object] | None = None,
) -> str:
    """``report_context``: ``{"scope": build_run_scope(...), "steps": summarize_steps(...)}`` from
    the API layer (the core layer does not import it); absent values are reported as "기록 없음"."""
    metadata = metadata or {}
    report_context = report_context or {}
    case_title = str(metadata.get("title") or case_payload.get("title") or f"{PRODUCT_NAME} 사건 보고서")
    case_id = str(metadata.get("case_number") or case_payload.get("case_id") or "")
    template = str(metadata.get("template") or "legal-handoff")
    if template == KOREAN_EXPERT_TEMPLATE_ID:
        return build_korean_expert_report(
            run_summary=run_summary,
            case_payload=case_payload,
            submission_manifest=submission_manifest,
            metadata=metadata,
            report_context=report_context,
        )
    technical = template == "technical-appendix"
    case_title = report_items.md_inline(case_title)
    case_id = report_items.md_inline(case_id)
    investigator = report_items.author_label(report_items.md_inline(metadata.get("investigator")))
    organization = report_items.md_inline(metadata.get("organization") or "")
    requester = report_items.md_inline(metadata.get("requester") or "")
    scope = str(metadata.get("scope") or f"검토 대상으로 지정된 증거 파일과 {PRODUCT_NAME} 분석 산출물을 기준으로 작성함.")
    conclusion = str(metadata.get("conclusion") or "검토 결과 및 증거 해시는 아래 항목과 같음.")
    offset_minutes, display_label = report_items.display_timezone(run_summary)
    roots = report_items.roots_for(run_summary)

    lines = [
        "# 디지털 포렌식 분석 보고서",
        "",
        f"> 보고서 양식: {report_items.md_inline(report_items.template_label(template))} ({report_items.md_code(template)})",
        f"> 구성 기준: {report_items.template_policy(template)}",
        "",
        "## 1. 사건 정보",
        "",
        f"- 보고서 제목: {case_title}",
        f"- 사건 번호: {case_id or '미기재'}",
        f"- 분석자: {investigator}",
        f"- 소속/기관: {organization or '미기재'}",
        f"- 의뢰자/의뢰기관: {requester or '미기재'}",
        f"- 생성 시각: {report_items.format_evidence_time(submission_manifest.get('generated_at'), offset_minutes)}",
        "",
    ]

    if template == "hash-only":
        return build_hash_only_report(lines=lines, submission_manifest=submission_manifest, roots=roots)

    if template == "executive-summary":
        lines.extend(
            [
                "## 요약",
                "",
                "이 보고서는 의사결정자를 위해 검토된 증거를 추린 것임. 해시 등 기술 정보는 각 증거 항목에 함께 적음.",
                "",
            ]
        )

    lines.extend(
        [
            "## 2. 분석 대상 및 범위",
            "",
            f"- 분석 모드: {run_mode_ko(run_summary.get('mode'))}"
            + (f" ({report_items.md_code(run_summary.get('mode', ''))})" if technical else ""),
            *report_items.subject_lines(run_summary, technical=technical),
            *report_items.reproducibility_lines(
                run_summary, report_context, display_label=display_label, technical=technical
            ),
            report_items.conditions_line(submission_manifest, case_payload),
            "",
            scope,
            "",
            "## 3. 분석 절차 요약",
            "",
        ]
    )

    if template == "executive-summary":
        lines.append("- 의사결정자 요약에서는 분석기 경로와 단계별 산출물을 생략함. 필요하면 기술 부록 양식으로 다시 생성해 확인함.")
    else:
        lines.extend(report_items.step_lines(run_summary, technical=technical) or ["- 절차 정보 없음"])

    lines.extend(["", "## 4. 주요 검토 결과", ""])
    case_summary = case_payload.get("summary") if isinstance(case_payload.get("summary"), Mapping) else {}
    manifest_summary = submission_manifest.get("summary") if isinstance(submission_manifest.get("summary"), Mapping) else {}
    lines.extend(
        [
            f"- 검토 항목 수: {case_summary.get('bookmark_count', 0)}",
            f"- 보고서 포함 후보 수: {case_summary.get('report_item_count', 0)}",
            f"- 해시 산출 항목 수: {manifest_summary.get('hashed_item_count', 0)}",
            f"- 해시 산출 제외 항목 수: {manifest_summary.get('skipped_count', 0)}",
            *report_scope_notes(case_payload, submission_manifest),
            "",
        ]
    )
    lines.extend(report_items.review_table("### 침해 지표 검토 항목", build_case_indicator_rows(case_payload), "- 저장된 지표 검토 항목 없음."))
    lines.extend(report_items.review_table("### A/B 비교 검토 항목", build_case_compare_rows(case_payload), "- 저장된 비교 검토 항목 없음."))

    # R7 AI 갈래 C: "AI 사용" section with the server-side evidence gap table (report option
    # ``sections``: absent = default on, ``["ai-usage"]`` on, ``[]`` off; a run without the
    # ai-agent kind still gets the gap table).
    if report_section_enabled(metadata, AI_SECTION_ID) and run_summary:
        lines.extend(ai_usage_section_lines(ai_usage_summary(run_summary.get("output_dir")), metadata=metadata))

    # R8 T-027: every report candidate -- files and artifact rows -- with its row info.
    lines.extend(["## 5. 보고서 포함 항목 및 증거 해시", ""])
    entries = report_items.report_entries(case_payload, submission_manifest)
    for index, entry in enumerate(entries, start=1):
        bookmark = entry["bookmark"] if isinstance(entry.get("bookmark"), Mapping) else {}
        lines.extend(
            report_items.entry_lines(
                index,
                entry,
                roots=roots,
                offset_minutes=offset_minutes,
                source_hits=extract_source_hit_notes(str(bookmark.get("note") or "")),
                show_copy_path=technical,
            )
        )
    if not entries:
        lines.extend(["- 보고서 포함으로 표시한 항목이 없음.", ""])

    lines.extend(["## 6. 해시 산출 제외 항목", "", *report_items.skipped_lines(submission_manifest, roots)])

    lines.extend(
        [
            "",
            "## 7. 결론 및 의견",
            "",
            conclusion,
            "",
            "## 8. 첨부 산출물",
            "",
            "- `rapidtriage-case.json`: 검토/북마크/분류 기록",
            "- `rapidtriage-submission-manifest.json`: 제출 후보 증거 해시 목록",
            "- `rapidtriage-submission-manifest.audit.json`: 제출 해시 매니페스트 생성 감사 기록",
            "- `rapidtriage-run-report.md`: 자동 분석 요약 보고서",
            "",
        ]
    )
    if technical:
        lines.extend(report_items.technical_appendix_lines(run_summary))
    return "\n".join(lines)


def report_section_enabled(metadata: Mapping[str, object], section_id: str) -> bool:
    """Optional section ``section_id``: on unless the request's ``sections`` list omits it."""
    sections = metadata.get("sections")
    if sections is None:
        return True
    return isinstance(sections, (list, tuple)) and section_id in sections


def template_noise_policy(template: str) -> str:
    return report_items.template_policy(template)


def extract_source_hit_notes(note: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in note.splitlines():
        cleaned = line.strip()
        if cleaned.lower().startswith("current-file hit:") or cleaned.lower().startswith("docs-index hit:"):
            is_docs_index = cleaned.lower().startswith("docs-index hit:")
            prefix = r"^docs-index hit:\s*" if is_docs_index else r"^current-file hit:\s*"
            hit = re.sub(prefix, "", cleaned, flags=re.IGNORECASE)
            if hit:
                current = {"citation": hit, "source_type": "docs-index" if is_docs_index else "source-search"}
                hits.append(current)
            continue
        if not current or not cleaned:
            continue
        if cleaned.lower().startswith("snippet:"):
            current["snippet"] = trim_report_inline_text(
                re.sub(r"^snippet:\s*", "", cleaned, flags=re.IGNORECASE)
            )
            continue
        if cleaned.lower().startswith("structured citation:"):
            current["structured_citation"] = trim_report_inline_text(
                re.sub(r"^structured citation:\s*", "", cleaned, flags=re.IGNORECASE),
                limit=360,
            )
            continue
        if cleaned.lower().startswith("source locator:"):
            current["source_locator"] = trim_report_inline_text(
                re.sub(r"^source locator:\s*", "", cleaned, flags=re.IGNORECASE),
                limit=96,
            )
            continue
        if cleaned.lower().startswith("matched terms:"):
            current["matched_terms"] = trim_report_inline_text(
                re.sub(r"^matched terms:\s*", "", cleaned, flags=re.IGNORECASE),
                limit=180,
            )
            continue
        if cleaned.lower().startswith("result hash:"):
            current["result_hash"] = trim_report_inline_text(
                re.sub(r"^result hash:\s*", "", cleaned, flags=re.IGNORECASE),
                limit=96,
            )
            continue
        if cleaned.lower().startswith("review hint:"):
            current["review_hint"] = trim_report_inline_text(
                re.sub(r"^review hint:\s*", "", cleaned, flags=re.IGNORECASE)
            )
            continue
        if "verify" in cleaned.lower() or "review" in cleaned.lower():
            current.setdefault("review_hint", trim_report_inline_text(cleaned))
    return hits


def trim_report_inline_text(value: str, *, limit: int = 240) -> str:
    normalized = re.sub(r"\s+", " ", str(value)).strip()
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 3]}..."


def build_case_indicator_rows(case_payload: Mapping[str, object], *, limit: int = 20) -> list[dict[str, object]]:
    return build_case_source_review_rows(case_payload, "indicators", limit=limit)


def build_case_compare_rows(case_payload: Mapping[str, object], *, limit: int = 20) -> list[dict[str, object]]:
    return build_case_source_review_rows(case_payload, "compare", limit=limit)


def build_case_source_review_rows(
    case_payload: Mapping[str, object],
    source_command: str,
    *,
    limit: int = 20,
) -> list[dict[str, object]]:
    bookmarks = case_payload.get("bookmarks")
    if not isinstance(bookmarks, list):
        return []
    rows: list[dict[str, object]] = []
    for bookmark in bookmarks:
        if not isinstance(bookmark, Mapping):
            continue
        reference = bookmark.get("reference") if isinstance(bookmark.get("reference"), Mapping) else {}
        if reference.get("command") != source_command:
            continue
        review = bookmark.get("review") if isinstance(bookmark.get("review"), Mapping) else {}
        rows.append(
            {
                "summary": str(bookmark.get("summary") or bookmark.get("bookmark_id") or source_command),
                "status": str(review.get("status") or "unreviewed"),
                "include_in_report": bool(review.get("include_in_report")),
                "tags": ", ".join(str(tag) for tag in bookmark.get("tags", []) if tag),
                "note": str(bookmark.get("note") or ""),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def build_hash_only_report(
    *,
    lines: list[str],
    submission_manifest: Mapping[str, object],
    roots: list[Path] | None = None,
) -> str:
    lines.extend(report_items.hash_only_lines(submission_manifest, roots or []))
    return "\n".join(lines)


def write_case_report_exports(markdown: str, markdown_path: Path) -> dict[str, str]:
    """Write markdown plus portable HTML, DOCX, PDF, and hash manifest variants."""
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    paths = case_report_export_paths(markdown_path)
    paths["md"].write_text(markdown, encoding="utf-8")
    paths["html"].write_text(render_case_report_html(markdown), encoding="utf-8")
    write_case_report_docx(markdown, paths["docx"])
    write_case_report_pdf(markdown, paths["pdf"])
    manifest = build_case_report_export_manifest(paths)
    paths["manifest"].write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {key: str(path) for key, path in paths.items()}


def case_report_export_paths(markdown_path: Path) -> dict[str, Path]:
    base_dir = markdown_path.parent
    return {
        "md": markdown_path,
        "html": base_dir / CASE_REPORT_EXPORTS["html"],
        "docx": base_dir / CASE_REPORT_EXPORTS["docx"],
        "pdf": base_dir / CASE_REPORT_EXPORTS["pdf"],
        "manifest": base_dir / CASE_REPORT_EXPORTS["manifest"],
    }


def build_case_report_export_manifest(paths: Mapping[str, Path]) -> dict[str, object]:
    files: dict[str, object] = {}
    for format_name in ("md", "html", "docx", "pdf"):
        path = paths[format_name]
        files[format_name] = {
            "path": str(path),
            "filename": path.name,
            "size": path.stat().st_size,
            "sha256": hash_path(path),
        }
    return {
        "command": "case-report.exports",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "formats": list(files),
        "security": {
            "html_escaped": True,
            "xml_escaped": True,
            "pdf_hex_encoded": True,
            "content_security_policy": report_export_csp(),
        },
        "files": files,
    }


def hash_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def render_case_report_html(markdown: str) -> str:
    title = f"{PRODUCT_NAME} 사건 보고서"
    body: list[str] = []
    in_list = False
    in_code = False
    code_lines: list[str] = []
    table_rows: list[str] = []

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped.startswith("```"):
            if in_code:
                body.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
                code_lines = []
                in_code = False
            else:
                in_list = close_list(body, in_list)
                in_code = True
            continue
        if in_code:
            code_lines.append(line)
            continue
        if not stripped:
            in_list = close_list(body, in_list)
            table_rows = flush_table(body, table_rows)
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            in_list = close_list(body, in_list)
            table_rows.append(stripped)
            continue
        table_rows = flush_table(body, table_rows)
        if stripped.startswith("# "):
            in_list = close_list(body, in_list)
            title = strip_markdown_inline(stripped[2:])
            body.append(f"<h1>{html.escape(title)}</h1>")
        elif stripped.startswith("## "):
            in_list = close_list(body, in_list)
            body.append(f"<h2>{html.escape(strip_markdown_inline(stripped[3:]))}</h2>")
        elif stripped.startswith("### "):
            in_list = close_list(body, in_list)
            body.append(f"<h3>{html.escape(strip_markdown_inline(stripped[4:]))}</h3>")
        elif stripped.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{render_inline_markdown(stripped[2:])}</li>")
        elif stripped.startswith("> "):
            in_list = close_list(body, in_list)
            body.append(f"<blockquote>{render_inline_markdown(stripped[2:])}</blockquote>")
        else:
            in_list = close_list(body, in_list)
            body.append(f"<p>{render_inline_markdown(stripped)}</p>")
    if in_code:
        body.append(f"<pre><code>{html.escape(chr(10).join(code_lines))}</code></pre>")
    flush_table(body, table_rows)
    close_list(body, in_list)
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="ko">',
            "<head>",
            '<meta charset="utf-8" />',
            '<meta name="viewport" content="width=device-width, initial-scale=1" />',
            '<meta name="referrer" content="no-referrer" />',
            f'<meta http-equiv="Content-Security-Policy" content="{html.escape(report_export_csp(), quote=True)}" />',
            f"<title>{html.escape(title)}</title>",
            "<style>",
            "body{margin:0;background:#f4efe6;color:#1d2528;font:16px/1.65 'Noto Serif KR','Apple SD Gothic Neo',Georgia,serif}",
            "main{max-width:980px;margin:32px auto;padding:36px;background:#fff;border:1px solid #dccfbd;border-radius:16px;box-shadow:0 18px 48px rgba(32,28,20,.08)}",
            "h1,h2,h3{line-height:1.25;color:#162326}h1{font-size:2rem;margin-top:0}h2{margin-top:2rem;border-bottom:1px solid #eadfce;padding-bottom:.35rem}",
            "blockquote{margin:1rem 0;padding:.75rem 1rem;border-left:4px solid #9f7b4d;background:#faf6ef}",
            "code{background:#f4efe6;padding:.1rem .3rem;border-radius:4px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#162326;color:#f6efe1;padding:1rem;border-radius:10px}",
            "li{margin:.25rem 0}ul{padding-left:1.35rem}",
            "table{border-collapse:collapse;margin:1rem 0;width:100%;font-size:.92rem}th,td{border:1px solid #dccfbd;padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:#faf6ef}",
            ".meta{margin-bottom:1.5rem;color:#5b645f;font-size:.92rem}",
            "</style>",
            "</head>",
            "<body><main>",
            f'<p class="meta">{PRODUCT_NAME}로 생성함. 법적 제출 전에 원본 증거와 해시값을 확인할 것.</p>',
            *body,
            "</main></body></html>",
            "",
        ]
    )


def report_export_csp() -> str:
    return "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def flush_table(body: list[str], rows: list[str]) -> list[str]:
    """Render collected Markdown table lines (``| a | b |``; a ``| --- |`` second line marks the header)."""
    if not rows:
        return rows
    cells = [[cell.strip() for cell in row.strip("|").split("|")] for row in rows]
    has_header = len(cells) > 1 and all(cell and set(cell) <= set("-: ") for cell in cells[1])
    body.append("<table>")
    for index, row in enumerate(cells):
        if has_header and index == 1:
            continue
        tag = "th" if has_header and index == 0 else "td"
        body.append("<tr>" + "".join(f"<{tag}>{render_inline_markdown(cell)}</{tag}>" for cell in row) + "</tr>")
    body.append("</table>")
    return []


def close_list(body: list[str], in_list: bool) -> bool:
    if in_list:
        body.append("</ul>")
    return False


def render_inline_markdown(value: str) -> str:
    escaped = html.escape(value)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def strip_markdown_inline(value: str) -> str:
    return value.replace("`", "").replace("**", "").strip()


def write_case_report_docx(markdown: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", DOCX_CONTENT_TYPES)
        archive.writestr("_rels/.rels", DOCX_RELS)
        archive.writestr("docProps/core.xml", docx_core_properties())
        archive.writestr("docProps/app.xml", DOCX_APP_PROPERTIES)
        archive.writestr("word/document.xml", docx_document_xml(markdown))


def write_case_report_pdf(markdown: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pdf_lines = markdown_to_pdf_lines(markdown)
    pages = paginate_pdf_lines(pdf_lines)
    path.write_bytes(build_pdf_document(pages))


def markdown_to_pdf_lines(markdown: str) -> list[tuple[str, int]]:
    lines: list[tuple[str, int]] = []
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line:
            lines.append(("", 10))
            continue
        size = 10
        prefix = ""
        if line.startswith("# "):
            size = 18
            line = line[2:].strip()
        elif line.startswith("## "):
            size = 14
            line = line[3:].strip()
        elif line.startswith("### "):
            size = 12
            line = line[4:].strip()
        elif line.startswith("- "):
            prefix = "- "
            line = line[2:].strip()
        elif line.startswith("> "):
            prefix = "> "
            line = line[2:].strip()
        cleaned = prefix + strip_markdown_inline(line)
        for wrapped in wrap_pdf_text(cleaned, max_chars=92 if size <= 10 else 72):
            lines.append((wrapped, size))
    return lines


def wrap_pdf_text(text: str, *, max_chars: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    chunks = []
    remaining = text
    while remaining:
        chunks.append(remaining[:max_chars])
        remaining = remaining[max_chars:]
    return chunks


def paginate_pdf_lines(lines: list[tuple[str, int]]) -> list[list[tuple[str, int, float]]]:
    pages: list[list[tuple[str, int, float]]] = []
    current: list[tuple[str, int, float]] = []
    y = 760.0
    for text, size in lines:
        height = 10.0 if not text else max(13.0, size * 1.55)
        if y - height < 48 and current:
            pages.append(current)
            current = []
            y = 760.0
        if text:
            current.append((text, size, y))
        y -= height
    pages.append(current)
    return pages


def build_pdf_document(pages: list[list[tuple[str, int, float]]]) -> bytes:
    objects: list[bytes] = [
        b"",
        b"",
        b"<< /Type /Font /Subtype /Type0 /BaseFont /HYGoThic-Medium /Encoding /UniKS-UCS2-H /DescendantFonts [4 0 R] >>",
        b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /HYGoThic-Medium /CIDSystemInfo << /Registry (Adobe) /Ordering (Korea1) /Supplement 2 >> /FontDescriptor 5 0 R >>",
        b"<< /Type /FontDescriptor /FontName /HYGoThic-Medium /Flags 4 /FontBBox [-1000 -1000 1000 1000] /ItalicAngle 0 /Ascent 880 /Descent -120 /CapHeight 700 /StemV 80 >>",
    ]
    page_ids: list[int] = []
    for page in pages:
        content = build_pdf_page_content(page)
        content_id = len(objects) + 1
        objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")
        page_id = len(objects) + 1
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("ascii")
        )
        page_ids.append(page_id)
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    return serialize_pdf(objects)


def build_pdf_page_content(page: list[tuple[str, int, float]]) -> bytes:
    commands: list[str] = []
    for text, size, y in page:
        commands.append(f"BT /F1 {size} Tf 72 {y:.2f} Td {pdf_hex_text(text)} Tj ET")
    return "\n".join(commands).encode("ascii")


def pdf_hex_text(text: str) -> str:
    return "<" + text.encode("utf-16-be", errors="replace").hex().upper() + ">"


def serialize_pdf(objects: list[bytes]) -> bytes:
    output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_start = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def docx_document_xml(markdown: str) -> str:
    paragraphs: list[str] = []
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line:
            paragraphs.append("<w:p/>")
            continue
        kind = "body"
        if line.startswith("# "):
            kind = "title"
            line = line[2:].strip()
        elif line.startswith("## "):
            kind = "heading1"
            line = line[3:].strip()
        elif line.startswith("### "):
            kind = "heading2"
            line = line[4:].strip()
        elif line.startswith("- "):
            kind = "bullet"
            line = "• " + line[2:].strip()
        elif line.startswith("> "):
            kind = "quote"
            line = line[2:].strip()
        paragraphs.append(docx_paragraph(strip_markdown_inline(line), kind))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        + "".join(paragraphs)
        + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr>'
        "</w:body></w:document>"
    )


def docx_paragraph(text: str, kind: str) -> str:
    sizes = {"title": "36", "heading1": "28", "heading2": "24", "quote": "22", "body": "21", "bullet": "21"}
    bold = kind in {"title", "heading1", "heading2"}
    italic = kind == "quote"
    indent = '<w:ind w:left="360" w:hanging="180"/>' if kind == "bullet" else ""
    spacing = '<w:spacing w:after="160"/>'
    run_props = f'<w:rPr>{"<w:b/>" if bold else ""}{"<w:i/>" if italic else ""}<w:sz w:val="{sizes.get(kind, "21")}"/></w:rPr>'
    return (
        f"<w:p><w:pPr>{spacing}{indent}</w:pPr><w:r>{run_props}"
        f'<w:t xml:space="preserve">{xml_escape(text)}</w:t></w:r></w:p>'
    )


def docx_core_properties() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:dcmitype="http://purl.org/dc/dcmitype/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{xml_escape(PRODUCT_NAME)} 사건 보고서</dc:title>"
        f"<dc:creator>{xml_escape(PRODUCT_NAME)}</dc:creator>"
        f"<cp:lastModifiedBy>{xml_escape(PRODUCT_NAME)}</cp:lastModifiedBy>"
        "</cp:coreProperties>"
    )


DOCX_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
"""


DOCX_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""


DOCX_APP_PROPERTIES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>RapidTriage</Application>
</Properties>
"""
