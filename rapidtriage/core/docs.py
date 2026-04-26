from __future__ import annotations

import datetime as dt
import email
import hashlib
import json
import os
import platform
import re
import zipfile
import zlib
from collections import Counter
from email import policy
from email.message import EmailMessage
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
    ".mbox",
    ".msg",
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
    if kind == "eml":
        return _extract_eml_text(path)
    if kind == "mbox":
        return _extract_mbox_text(path)
    if kind == "msg":
        return _extract_msg_text(path)
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


def _extract_eml_text(path: Path) -> str:
    message = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    return _email_message_to_text(message)


def _extract_mbox_text(path: Path, *, message_limit: int = 25) -> str:
    data = path.read_bytes()
    chunks = re.split(rb"\n(?=From [^\n]+\n)", data)
    texts: list[str] = []
    for chunk in chunks[:message_limit]:
        if chunk.startswith(b"From "):
            chunk = chunk.split(b"\n", 1)[1] if b"\n" in chunk else b""
        if not chunk.strip():
            continue
        message = email.message_from_bytes(chunk, policy=policy.default)
        texts.append(_email_message_to_text(message))
    return "\n\n".join(text for text in texts if text)


def _extract_msg_text(path: Path, *, scan_limit: int = 2 * 1024 * 1024) -> str:
    blob = path.read_bytes()[:scan_limit]
    strings = _unique_strings([*_extract_ascii_strings(blob), *_extract_utf16_strings(blob)])
    return "\n".join(strings)


def _email_message_to_text(message: EmailMessage) -> str:
    header_names = ("From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID", "In-Reply-To")
    sections: list[str] = []
    for name in header_names:
        value = message.get(name)
        if value:
            sections.append(f"{name}: {value}")
    body_parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            body = _email_part_to_text(part)
            if body:
                body_parts.append(body)
    else:
        body = _email_part_to_text(message)
        if body:
            body_parts.append(body)
    sections.extend(body_parts)
    return "\n".join(sections)


def _email_part_to_text(part: EmailMessage) -> str:
    content_type = part.get_content_type().lower()
    if content_type not in {"text/plain", "text/html"}:
        return ""
    try:
        content = part.get_content()
    except (LookupError, UnicodeDecodeError):
        payload = part.get_payload(decode=True) or b""
        content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    if not isinstance(content, str):
        return ""
    if content_type == "text/html":
        return _strip_markup(content)
    return content.strip()


def _extract_ascii_strings(blob: bytes, *, min_chars: int = 5) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in blob:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_chars:
            strings.append(current.decode("ascii", errors="ignore"))
        current.clear()
    if len(current) >= min_chars:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings


def _extract_utf16_strings(blob: bytes, *, min_chars: int = 4) -> list[str]:
    strings: list[str] = []
    for start in (0, 1):
        current = bytearray()
        for index in range(start, len(blob) - 1, 2):
            value = int.from_bytes(blob[index : index + 2], "little", signed=False)
            if 32 <= value <= 126:
                current.extend(blob[index : index + 2])
                continue
            if len(current) >= min_chars * 2:
                strings.append(current.decode("utf-16le", errors="ignore").strip())
            current.clear()
        if len(current) >= min_chars * 2:
            strings.append(current.decode("utf-16le", errors="ignore").strip())
    return strings


def _unique_strings(values: list[str]) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = " ".join(value.split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
        if len(unique) >= 500:
            break
    return unique


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
