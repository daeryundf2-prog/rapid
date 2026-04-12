from __future__ import annotations

import datetime as dt
import json
import os
import platform
import re
import zipfile
import zlib
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Union
from xml.etree import ElementTree as ET

from ..artifacts import all_providers
from .input_root import InputRoot, resolve_input_root
from .models import DocumentCandidate, DocumentMatch

SUPPORTED_DOC_EXTS = {".txt", ".pdf", ".docx"}
TEXT_EXTS = {"txt"}


def scan_document_candidates(root: Union[InputRoot, Path], limit: int = 0) -> List[DocumentCandidate]:
    input_root = resolve_input_root(root)
    candidates: List[DocumentCandidate] = []
    for dirpath, _, files in os.walk(input_root.root_path):
        for name in files:
            path = Path(dirpath) / name
            suffix = path.suffix.lower()
            if suffix not in SUPPORTED_DOC_EXTS:
                continue
            stat = path.stat()
            candidates.append(
                DocumentCandidate(
                    path=str(path),
                    kind=suffix.lstrip("."),
                    size=stat.st_size,
                    modified_at=dt.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                )
            )
            if limit and len(candidates) >= limit:
                return candidates
    return candidates


def build_manifest(root: Union[InputRoot, Path], keywords: Sequence[str], *, input_kind: str | None = None) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    provider_rows = []
    for provider in all_providers():
        provider_rows.append(
            {
                "name": provider.name,
                "description": provider.description,
                "target_platform": provider.target_platform,
                "supported": provider.supported(),
                "artifacts": [item.to_dict() for item in provider.collect(input_root.root_path)],
            }
        )
    return {
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(input_root.root_path),
        "platform": platform.platform(),
        "keywords": list(keywords),
        "providers": provider_rows,
    }


def run_docs_search(
    root: Union[InputRoot, Path],
    keywords: Sequence[str],
    limit: int = 0,
    *,
    input_kind: str | None = None,
) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    normalized = [item.lower() for item in keywords]
    candidates = scan_document_candidates(input_root, limit=limit)
    matches: List[DocumentMatch] = []
    for candidate in candidates:
        text = extract_text(Path(candidate.path), candidate.kind)
        matched = [keyword for keyword in normalized if keyword in text.lower()]
        if not matched:
            continue
        matches.append(
            DocumentMatch(
                path=candidate.path,
                kind=candidate.kind,
                matched_keywords=matched,
                preview=build_preview(text, matched[0]),
                size=candidate.size,
            )
        )
    return {
        "command": "docs",
        "root": str(input_root.root_path),
        "generated_at": dt.datetime.now().isoformat(),
        "summary": {
            "candidate_count": len(candidates),
            "match_count": len(matches),
            "supported_extensions": sorted(SUPPORTED_DOC_EXTS),
        },
        "manifest": build_manifest(input_root, normalized),
        "candidates": [item.to_dict() for item in candidates],
        "results": [item.to_dict() for item in matches],
    }


def write_result(payload: Dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_text(path: Path, kind: str) -> str:
    if kind in TEXT_EXTS:
        return path.read_text(encoding="utf-8", errors="ignore")
    if kind == "docx":
        return _extract_docx_text(path)
    if kind == "pdf":
        return _extract_pdf_text(path)
    return ""


def _extract_docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        with archive.open("word/document.xml") as handle:
            xml_data = handle.read()
    root = ET.fromstring(xml_data)
    texts = []
    for node in root.iter():
        if node.tag.endswith("}t") and node.text:
            texts.append(node.text)
    return " ".join(texts)


def _extract_pdf_text(path: Path) -> str:
    data = path.read_bytes()
    snippets: List[str] = []
    for stream in re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        candidates = [stream]
        try:
            candidates.append(zlib.decompress(stream))
        except zlib.error:
            pass
        for item in candidates:
            snippets.extend(_extract_pdf_literal_strings(item))
    if not snippets:
        snippets.extend(_extract_pdf_literal_strings(data))
    return " ".join(snippets)


def _extract_pdf_literal_strings(blob: bytes) -> List[str]:
    found = []
    for raw in re.findall(rb"\((.*?)(?<!\\)\)", blob, re.S):
        text = (
            raw.replace(b"\\n", b"\n")
            .replace(b"\\r", b"\r")
            .replace(b"\\t", b"\t")
            .replace(b"\\(", b"(")
            .replace(b"\\)", b")")
            .replace(b"\\\\", b"\\")
        )
        cleaned = text.decode("latin-1", errors="ignore").strip()
        if cleaned:
            found.append(cleaned)
    return found


def build_preview(text: str, keyword: str, radius: int = 80) -> str:
    lower = text.lower()
    index = lower.find(keyword.lower())
    if index < 0:
        return text[: radius * 2].strip()
    start = max(0, index - radius)
    end = min(len(text), index + len(keyword) + radius)
    preview = text[start:end].strip()
    return preview.replace("\n", " ")
