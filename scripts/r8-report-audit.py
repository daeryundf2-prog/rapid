#!/usr/bin/env python3
"""Audit exported reports for required fields and forbidden strings (R8 T-003).

Extracts text from md / txt / html / json / docx / pdf (stdlib only; PDF text extraction is
best-effort: uncompressed and Flate streams, Tj/TJ string operators) and checks:

  required   tool version, catalog version, evidence hash, processing scope,
             failed/partial stages, time zone, conditions (label or JSON key)
  forbidden  English section titles, raw ``status=`` tokens, assertive wording

Exit 1 when any file misses a required field, contains a forbidden string, or yields no text.

  python scripts/r8-report-audit.py D:/qa/exports/report.docx D:/qa/exports/report.pdf --json
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import zipfile
import zlib
from pathlib import Path

REQUIRED_FIELDS: dict[str, re.Pattern[str]] = {
    "tool_version": re.compile(
        r"도구 버전|프로그램 버전|tool[_ ]version|RapidTriage\s+v?\d+\.\d+",
        re.IGNORECASE,
    ),
    "catalog_version": re.compile(r"카탈로그 버전|catalog[_ ]version", re.IGNORECASE),
    "evidence_hash": re.compile(
        r"증거 해시|evidence[_ ]hash|(?:SHA-?256|MD5)\s*[:=]?\s*[0-9a-f]{32,64}",
        re.IGNORECASE,
    ),
    "processing_scope": re.compile(
        r"처리 범위|processing[_ ]scope|\bscope\b", re.IGNORECASE
    ),
    "failed_partial_stages": re.compile(
        r"실패[·/ ]?부분 단계|실패한 단계|부분 단계|failed[_ ]stages|partial[_ ]stages",
        re.IGNORECASE,
    ),
    "time_zone": re.compile(r"시간대|time[_ ]?zone|\bUTC[+-]\d", re.IGNORECASE),
    "conditions": re.compile(r"조건|conditions|filters?\b", re.IGNORECASE),
}

FORBIDDEN_TITLES = (
    "Executive Summary",
    "Summary of Findings",
    "Findings",
    "Evidence Summary",
    "Timeline",
    "Methodology",
    "Conclusion",
    "Appendix",
)
FORBIDDEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "english_title": re.compile(
        r"^[#\s]*(?:"
        + "|".join(re.escape(t) for t in FORBIDDEN_TITLES)
        + r")\s*:?\s*$",
        re.MULTILINE,
    ),
    "raw_status_token": re.compile(r"\bstatus="),
    "assertive_wording": re.compile(
        r"틀림없이|명백히|확실히|확정적으로|증명되었다|증명됐다|의심의 여지"
    ),
}


# ---------------------------------------------------------------- extraction


def _xml_text(xml: str) -> str:
    xml = re.sub(r"</w:p>|<w:br/>|<w:tab/>", "\n", xml)
    return html.unescape(re.sub(r"<[^>]+>", "", xml))


def text_docx(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        parts = [
            n
            for n in zf.namelist()
            if re.match(r"word/(document|header\d*|footer\d*|footnotes)\.xml$", n)
        ]
        return "\n".join(
            _xml_text(zf.read(n).decode("utf-8", errors="replace"))
            for n in sorted(parts)
        )


def text_html(raw: str) -> str:
    raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", raw)
    raw = re.sub(r"(?i)<br\s*/?>|</(p|div|h\d|li|tr|td|th)>", "\n", raw)
    return html.unescape(re.sub(r"<[^>]+>", "", raw))


def _flatten_json(value, prefix: str = "") -> list[str]:
    lines: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            lines.append(str(k))
            lines += _flatten_json(v, f"{prefix}{k}.")
    elif isinstance(value, list):
        for v in value:
            lines += _flatten_json(v, prefix)
    elif value is not None:
        lines.append(f"{prefix.rstrip('.')}: {value}")
    return lines


def _pdf_string(raw: bytes) -> str:
    out = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == 0x5C and i + 1 < len(raw):  # backslash escape
            n = raw[i + 1]
            if 0x30 <= n <= 0x37:
                m = re.match(rb"[0-7]{1,3}", raw[i + 1 : i + 4])
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
                continue
            out.append({0x6E: 10, 0x72: 13, 0x74: 9}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    data = bytes(out)
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    return data.decode("latin-1")


def text_pdf(path: Path) -> str:
    data = path.read_bytes()
    chunks: list[bytes] = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.DOTALL):
        body = m.group(1)
        try:
            body = zlib.decompress(body)
        except zlib.error:
            pass
        chunks.append(body)
    texts: list[str] = []
    for body in chunks:
        for m in re.finditer(
            rb"\((?:\\.|[^\\)])*\)\s*Tj|\[(?:[^\]]*)\]\s*TJ|<([0-9A-Fa-f\s]+)>\s*Tj",
            body,
        ):
            seg = m.group(0)
            if m.group(1):
                hexs = re.sub(rb"\s", b"", m.group(1))
                raw = bytes.fromhex(hexs.decode())
                texts.append(
                    raw.decode("utf-16-be", errors="replace")
                    if len(raw) % 2 == 0
                    else raw.decode("latin-1")
                )
            else:
                texts.append(
                    "".join(
                        _pdf_string(s[1:-1])
                        for s in re.findall(rb"\((?:\\.|[^\\)])*\)", seg)
                    )
                )
        texts.append("\n")
    return "".join(texts)


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".docx":
        return text_docx(path)
    if suffix == ".pdf":
        return text_pdf(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    if suffix in {".html", ".htm"}:
        return text_html(raw)
    if suffix == ".json":
        try:
            return "\n".join(_flatten_json(json.loads(raw)))
        except json.JSONDecodeError:
            return raw
    return raw


# ---------------------------------------------------------------- audit


def audit_text(text: str) -> dict:
    missing = [name for name, rx in REQUIRED_FIELDS.items() if not rx.search(text)]
    forbidden = {
        name: len(rx.findall(text))
        for name, rx in FORBIDDEN_PATTERNS.items()
        if rx.search(text)
    }
    empty = not text.strip()
    return {
        "missing_fields": missing,
        "forbidden": forbidden,
        "empty": empty,
        "ok": not missing and not forbidden and not empty,
    }


def audit_file(path: Path) -> dict:
    try:
        text = extract_text(path)
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return {"file": str(path), "ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"file": str(path), **audit_text(text)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="+", type=Path, help="report files or folders")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    files: list[Path] = []
    for p in args.paths:
        files += sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
    results = [audit_file(f) for f in files]
    report = {
        "files": len(results),
        "failed": sum(1 for r in results if not r["ok"]),
        "results": results,
    }
    if args.output:
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        for r in results:
            detail = r.get("error") or "; ".join(
                filter(
                    None,
                    [
                        "missing " + ",".join(r["missing_fields"])
                        if r["missing_fields"]
                        else "",
                        "forbidden "
                        + ",".join(f"{k}x{v}" for k, v in r["forbidden"].items())
                        if r["forbidden"]
                        else "",
                        "no text" if r["empty"] else "",
                    ],
                )
            )
            print(f"{'ok  ' if r['ok'] else 'FAIL'} {r['file']} {detail}")
        print(f"{report['failed']}/{report['files']} failed")
    return 1 if report["failed"] or not results else 0


if __name__ == "__main__":
    sys.exit(main())
