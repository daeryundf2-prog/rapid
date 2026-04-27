from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import re
import zipfile
from pathlib import Path
from typing import Mapping
from xml.sax.saxutils import escape as xml_escape


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
) -> str:
    metadata = metadata or {}
    case_title = str(metadata.get("title") or case_payload.get("title") or "rapidtriage case report")
    case_id = str(metadata.get("case_number") or case_payload.get("case_id") or "")
    template = str(metadata.get("template") or "legal-handoff")
    investigator = str(metadata.get("investigator") or "")
    organization = str(metadata.get("organization") or "")
    requester = str(metadata.get("requester") or "")
    scope = str(metadata.get("scope") or "검토 대상으로 지정된 증거 파일과 rapidtriage 분석 산출물을 기준으로 작성함.")
    conclusion = str(metadata.get("conclusion") or "검토 결과 및 증거 해시는 아래 항목과 같음.")

    lines = [
        "# 디지털 포렌식 분석 보고서",
        "",
        f"> Report template: `{template}`",
        "",
        "## 1. 사건 정보",
        "",
        f"- 보고서 제목: {case_title}",
        f"- 사건 번호: {case_id or '미기재'}",
        f"- 분석자: {investigator or '미기재'}",
        f"- 소속/기관: {organization or '미기재'}",
        f"- 의뢰자/의뢰기관: {requester or '미기재'}",
        f"- 생성 시각: `{submission_manifest.get('generated_at', '')}`",
        "",
    ]

    if template == "hash-only":
        return build_hash_only_report(
            lines=lines,
            submission_manifest=submission_manifest,
        )

    if template == "executive-summary":
        lines.extend(
            [
                "## Executive summary",
                "",
                "This report highlights reviewed evidence selected for decision-makers. Technical hash details remain attached to each evidence item.",
                "",
            ]
        )

    lines.extend(
        [
            "## 2. 분석 대상 및 범위",
            "",
            f"- 분석 모드: `{run_summary.get('mode', '')}`",
            f"- 원본/분석 루트: `{run_summary.get('root', '')}`",
            f"- 분석 범위 루트: `{run_summary.get('scan_scope_root', '')}`",
            f"- 산출물 디렉터리: `{run_summary.get('output_dir', '')}`",
            "",
            scope,
            "",
            "## 3. 분석 절차 요약",
            "",
        ]
    )

    for step in run_summary.get("steps", []):
        if not isinstance(step, Mapping):
            continue
        lines.append(
            f"- `{step.get('name')}`: {step.get('status')} "
            f"(output=`{step.get('output', '')}`)"
        )
    if not any(line.startswith("- `") for line in lines[-20:]):
        lines.append("- 절차 정보 없음")

    lines.extend(
        [
            "",
            "## 4. 주요 검토 결과",
            "",
        ]
    )
    case_summary = case_payload.get("summary") if isinstance(case_payload.get("summary"), Mapping) else {}
    lines.extend(
        [
            f"- 검토 항목 수: {case_summary.get('bookmark_count', 0)}",
            f"- 보고서 포함 후보 수: {case_summary.get('report_item_count', 0)}",
            f"- 해시 산출 항목 수: {submission_manifest.get('summary', {}).get('hashed_item_count', 0)}",
            f"- 해시 산출 제외 항목 수: {submission_manifest.get('summary', {}).get('skipped_count', 0)}",
            "",
        ]
    )
    indicator_rows = build_case_indicator_rows(case_payload)
    lines.extend(["### IOC/Indicator review pivots", ""])
    if indicator_rows:
        for item in indicator_rows:
            lines.append(
                f"- `{item.get('summary')}` status=`{item.get('status')}`"
                f" report={item.get('include_in_report')} tags={item.get('tags') or '없음'}"
                f" note={item.get('note') or '없음'}"
            )
    else:
        lines.append("- 저장된 indicator 리뷰 항목 없음.")
    lines.append("")

    compare_rows = build_case_compare_rows(case_payload)
    lines.extend(["### A/B compare review pivots", ""])
    if compare_rows:
        for item in compare_rows:
            lines.append(
                f"- `{item.get('summary')}` status=`{item.get('status')}`"
                f" report={item.get('include_in_report')} tags={item.get('tags') or '없음'}"
                f" note={item.get('note') or '없음'}"
            )
    else:
        lines.append("- 저장된 compare 리뷰 항목 없음.")
    lines.append("")

    lines.extend(["## 5. 제출 증거 및 해시값", ""])
    items = submission_manifest.get("items")
    if isinstance(items, list) and items:
        for index, item in enumerate(items, start=1):
            if not isinstance(item, Mapping):
                continue
            evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
            hashes = evidence.get("hashes") if isinstance(evidence.get("hashes"), Mapping) else {}
            review = item.get("review") if isinstance(item.get("review"), Mapping) else {}
            lines.extend(
                [
                    f"### 5.{index}. {item.get('summary') or evidence.get('name') or 'Evidence'}",
                    "",
                    f"- 북마크 ID: `{item.get('bookmark_id', '')}`",
                    f"- 파일명: `{evidence.get('name', '')}`",
                    f"- 경로: `{evidence.get('path', '')}`",
                    f"- 크기: {evidence.get('size', 0)} bytes",
                    f"- 수정 시각: `{evidence.get('modified_at', '')}`",
                    f"- 검토 상태: `{review.get('status', '')}`",
                    f"- 태그: {', '.join(str(tag) for tag in item.get('tags', [])) or '없음'}",
                    f"- 분석자 메모: {item.get('note') or '없음'}",
                    f"- MD5: `{hashes.get('md5', '')}`",
                    f"- SHA1: `{hashes.get('sha1', '')}`",
                    f"- SHA256: `{hashes.get('sha256', '')}`",
                    "",
                ]
            )
    else:
        lines.append("- 제출 후보로 지정되어 해시 산출된 증거가 없음.")
        lines.append("")

    skipped = submission_manifest.get("skipped")
    lines.extend(["## 6. 해시 산출 제외 항목", ""])
    if isinstance(skipped, list) and skipped:
        for item in skipped:
            if isinstance(item, Mapping):
                lines.append(f"- `{item.get('path', '')}`: {item.get('reason', '')}")
    else:
        lines.append("- 없음")

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
    if template == "technical-appendix":
        processing = run_summary.get("processing") if isinstance(run_summary.get("processing"), Mapping) else {}
        lines.extend(
            [
                "## 9. Technical appendix",
                "",
                f"- Processing profile: `{processing.get('profile_label', '')}`",
                f"- Processing warning count: {processing.get('warning_count', 0)}",
                f"- Highest warning level: `{processing.get('highest_warning_level', 'none')}`",
                "",
            ]
        )
    return "\n".join(lines)


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
) -> str:
    lines.extend(["## 2. 제출 증거 해시 목록", ""])
    items = submission_manifest.get("items")
    if isinstance(items, list) and items:
        for index, item in enumerate(items, start=1):
            if not isinstance(item, Mapping):
                continue
            evidence = item.get("evidence") if isinstance(item.get("evidence"), Mapping) else {}
            hashes = evidence.get("hashes") if isinstance(evidence.get("hashes"), Mapping) else {}
            lines.extend(
                [
                    f"### 2.{index}. {item.get('summary') or evidence.get('name') or 'Evidence'}",
                    "",
                    f"- 경로: `{evidence.get('path', '')}`",
                    f"- MD5: `{hashes.get('md5', '')}`",
                    f"- SHA1: `{hashes.get('sha1', '')}`",
                    f"- SHA256: `{hashes.get('sha256', '')}`",
                    "",
                ]
            )
    else:
        lines.append("- 해시 산출된 제출 증거가 없음.")
        lines.append("")
    skipped = submission_manifest.get("skipped")
    lines.extend(["## 3. 해시 산출 제외 항목", ""])
    if isinstance(skipped, list) and skipped:
        for item in skipped:
            if isinstance(item, Mapping):
                lines.append(f"- `{item.get('path', '')}`: {item.get('reason', '')}")
    else:
        lines.append("- 없음")
    lines.append("")
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
    title = "RapidTriage Case Report"
    body: list[str] = []
    in_list = False
    in_code = False
    code_lines: list[str] = []

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
            continue
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
            ".meta{margin-bottom:1.5rem;color:#5b645f;font-size:.92rem}",
            "</style>",
            "</head>",
            "<body><main>",
            '<p class="meta">Generated by RapidTriage. Verify source evidence and hashes before legal submission.</p>',
            *body,
            "</main></body></html>",
            "",
        ]
    )


def report_export_csp() -> str:
    return "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


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
        "<dc:title>RapidTriage Case Report</dc:title>"
        "<dc:creator>RapidTriage</dc:creator>"
        "<cp:lastModifiedBy>RapidTriage</cp:lastModifiedBy>"
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
