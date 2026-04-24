from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import re
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Union
from xml.etree import ElementTree as ET

from ..artifacts import all_providers
from .input_root import InputRoot, resolve_input_root
from .models import DocumentCandidate, DocumentMatch
from .rules import RuleSet, annotate_docs_payload

SUPPORTED_DOC_EXTS = {
    ".cfg",
    ".conf",
    ".csv",
    ".docx",
    ".eml",
    ".htm",
    ".html",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".odp",
    ".ods",
    ".odt",
    ".pdf",
    ".pptx",
    ".rtf",
    ".tsv",
    ".txt",
    ".xlsx",
    ".xml",
    ".yaml",
    ".yml",
}
TEXT_EXTS = {
    "cfg",
    "conf",
    "csv",
    "eml",
    "ini",
    "json",
    "jsonl",
    "log",
    "md",
    "tsv",
    "txt",
    "xml",
    "yaml",
    "yml",
}
HTML_EXTS = {"htm", "html"}
OFFICE_OPEN_XML_EXTS = {"docx", "pptx", "xlsx"}
OPEN_DOCUMENT_EXTS = {"odp", "ods", "odt"}
DOCS_INDEX_TOKEN_PATTERN = re.compile(r"[\w@./:-]{2,}", flags=re.UNICODE)
DOCS_INDEX_VERSION = 1


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
    rule_set: RuleSet | None = None,
    index_output: Path | None = None,
) -> Dict[str, object]:
    input_root = resolve_input_root(root, kind=input_kind)
    normalized = [item.lower() for item in keywords]
    candidates = scan_document_candidates(input_root, limit=limit)
    matches: List[DocumentMatch] = []
    text_by_path: Dict[str, str] = {}
    for candidate in candidates:
        try:
            text = extract_text(Path(candidate.path), candidate.kind)
        except (OSError, UnicodeError, zipfile.BadZipFile, ET.ParseError):
            text = ""
        text_by_path[candidate.path] = text
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
    payload = {
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
    if rule_set is not None:
        annotate_docs_payload(payload, rule_set, text_by_path=text_by_path)
    if index_output is not None:
        index_payload = build_docs_index(input_root, candidates, text_by_path)
        write_result(index_payload, index_output)
        payload["index"] = {
            "command": "docs-index",
            "path": str(index_output),
            "strategy": index_payload["strategy"],
            "version": index_payload["version"],
            "document_count": index_payload["summary"]["indexed_document_count"],
            "term_count": index_payload["summary"]["term_count"],
        }
    return payload


def build_docs_index(
    root: Union[InputRoot, Path],
    candidates: Sequence[DocumentCandidate],
    text_by_path: Dict[str, str],
) -> Dict[str, object]:
    input_root = resolve_input_root(root)
    documents = []
    postings: Dict[str, List[Dict[str, int]]] = {}
    total_occurrences = 0
    for document_id, candidate in enumerate(candidates):
        text = text_by_path.get(candidate.path, "")
        token_counts = Counter(tokenize_index_terms(text))
        total_occurrences += sum(token_counts.values())
        documents.append(
            {
                "id": document_id,
                "path": candidate.path,
                "kind": candidate.kind,
                "size": candidate.size,
                "modified_at": candidate.modified_at,
                "text_sha256": hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest(),
                "text_length": len(text),
                "token_count": sum(token_counts.values()),
                "unique_token_count": len(token_counts),
            }
        )
        for term, count in sorted(token_counts.items()):
            postings.setdefault(term, []).append({"document_id": document_id, "count": count})

    return {
        "command": "docs-index",
        "version": DOCS_INDEX_VERSION,
        "root": str(input_root.root_path),
        "generated_at": dt.datetime.now().isoformat(),
        "strategy": "processed-text-inverted-index",
        "analyzer": {
            "case_fold": True,
            "token_pattern": DOCS_INDEX_TOKEN_PATTERN.pattern,
            "stores_full_text": False,
            "stores_text_hashes": True,
        },
        "summary": {
            "candidate_count": len(candidates),
            "indexed_document_count": sum(1 for item in documents if int(item["text_length"]) > 0),
            "term_count": len(postings),
            "token_occurrence_count": total_occurrences,
        },
        "documents": documents,
        "terms": postings,
    }


def tokenize_index_terms(text: str) -> List[str]:
    return [match.group(0).lower()[:256] for match in DOCS_INDEX_TOKEN_PATTERN.finditer(text)]


def write_result(payload: Dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_text(path: Path, kind: str) -> str:
    if kind in TEXT_EXTS:
        return path.read_text(encoding="utf-8", errors="ignore")
    if kind in HTML_EXTS:
        return _strip_markup(path.read_text(encoding="utf-8", errors="ignore"))
    if kind in OFFICE_OPEN_XML_EXTS:
        return _extract_office_open_xml_text(path, kind)
    if kind in OPEN_DOCUMENT_EXTS:
        return _extract_open_document_text(path)
    if kind == "pdf":
        return _extract_pdf_text(path)
    if kind == "rtf":
        return _extract_rtf_text(path)
    return ""


def _extract_office_open_xml_text(path: Path, kind: str) -> str:
    prefixes = {
        "docx": ("word/document.xml",),
        "pptx": ("ppt/slides/slide",),
        "xlsx": ("xl/sharedStrings.xml", "xl/worksheets/sheet"),
    }[kind]
    with zipfile.ZipFile(path) as archive:
        texts = []
        for name in archive.namelist():
            if not name.endswith(".xml") or not any(name.startswith(prefix) for prefix in prefixes):
                continue
            with archive.open(name) as handle:
                texts.extend(_extract_xml_text(handle.read()))
    return " ".join(texts)


def _extract_open_document_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        if "content.xml" not in archive.namelist():
            return ""
        with archive.open("content.xml") as handle:
            return " ".join(_extract_xml_text(handle.read()))


def _extract_xml_text(xml_data: bytes) -> List[str]:
    root = ET.fromstring(xml_data)
    texts = []
    for node in root.iter():
        if node.text and node.text.strip():
            texts.append(node.text.strip())
    return texts


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


def _extract_rtf_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore")
    text = re.sub(r"\\'[0-9a-fA-F]{2}", " ", text)
    text = re.sub(r"\\[a-zA-Z]+\d* ?", " ", text)
    text = text.replace("{", " ").replace("}", " ")
    return re.sub(r"\s+", " ", text).strip()


def _strip_markup(text: str) -> str:
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def build_preview(text: str, keyword: str, radius: int = 80) -> str:
    lower = text.lower()
    index = lower.find(keyword.lower())
    if index < 0:
        return text[: radius * 2].strip()
    start = max(0, index - radius)
    end = min(len(text), index + len(keyword) + radius)
    preview = text[start:end].strip()
    return preview.replace("\n", " ")
