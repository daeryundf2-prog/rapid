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
from typing import Dict, List, Mapping, Sequence, Union
from xml.etree import ElementTree as ET

from ..artifacts import all_providers
from .input_root import InputRoot, resolve_input_root
from .models import DocumentCandidate, DocumentMatch
from .rules import RuleSet, annotate_docs_payload
from .safe_xml import safe_xml_fromstring

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
    ".pst",
    ".rtf",
    ".ost",
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
MAX_EXTRACT_TEXT_BYTES = 50_000_000
MAX_ZIP_TEXT_MEMBER_BYTES = 10_000_000
MAX_ZIP_TEXT_TOTAL_BYTES = 50_000_000
MAX_ZIP_TEXT_MEMBER_COUNT = 2_000
MAX_PDF_STREAM_DECOMPRESSED_BYTES = 10_000_000


class TextExtractionTooLarge(ValueError):
    pass
BOUNDED_MAIL_CONTAINER_SCAN_LIMIT = 2 * 1024 * 1024


def scan_document_candidates(root: Union[InputRoot, Path], limit: int = 0) -> List[DocumentCandidate]:
    input_root = resolve_input_root(root)
    candidates: List[DocumentCandidate] = []
    for dirpath, _, files in os.walk(input_root.root_path):
        for name in files:
            path = Path(dirpath) / name
            suffix = path.suffix.lower()
            if suffix not in SUPPORTED_DOC_EXTS:
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            candidates.append(
                DocumentCandidate(
                    path=str(path),
                    kind=suffix.lstrip("."),
                    size=stat.st_size,
                    modified_at=dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc).isoformat(),
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
    extraction_errors: list[dict[str, object]] = []
    for candidate in candidates:
        try:
            text = extract_text(Path(candidate.path), candidate.kind)
        except TextExtractionTooLarge as exc:
            text = ""
            extraction_errors.append(
                document_extraction_error(candidate, "input-too-large", exc, recoverable=True)
            )
        except (OSError, UnicodeError, zipfile.BadZipFile, ET.ParseError, ValueError) as exc:
            text = ""
            extraction_errors.append(
                document_extraction_error(candidate, "text-extraction-failed", exc, recoverable=True)
            )
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
    if extraction_errors:
        payload["summary"]["extraction_error_count"] = len(extraction_errors)
        payload["summary"]["skipped_document_count"] = len(extraction_errors)
        payload["extraction_errors"] = extraction_errors
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


def document_extraction_error(
    candidate: DocumentCandidate,
    reason: str,
    exc: BaseException,
    *,
    recoverable: bool,
) -> dict[str, object]:
    return {
        "path": candidate.path,
        "kind": candidate.kind,
        "size": candidate.size,
        "reason": reason,
        "error_type": type(exc).__name__,
        "message": str(exc),
        "recoverable": recoverable,
        "effect": "document-skipped-search-continues",
    }


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


def normalize_index_query_terms(keywords: Sequence[str]) -> list[str]:
    terms: list[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        raw = str(keyword).strip()
        if not raw:
            continue
        tokens = tokenize_index_terms(raw)
        if not tokens:
            tokens = [raw.lower()[:256]]
        for token in tokens:
            if token in seen:
                continue
            seen.add(token)
            terms.append(token)
    return terms


def load_docs_index(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("docs-index payload must be a JSON object")
    if payload.get("command") != "docs-index":
        raise ValueError("input is not a docs-index payload")
    if payload.get("strategy") != "processed-text-inverted-index":
        raise ValueError("unsupported docs-index strategy")
    if not isinstance(payload.get("documents"), list) or not isinstance(payload.get("terms"), dict):
        raise ValueError("docs-index payload is missing documents or terms")
    return payload


def query_docs_index(index_path: Path, keywords: Sequence[str], *, limit: int = 500) -> dict[str, object]:
    resolved = index_path.expanduser().resolve()
    payload = load_docs_index(resolved)
    index_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    result = search_docs_index_payload(payload, keywords, limit=limit)
    result["index_file"] = {
        "path": str(resolved),
        "sha256": index_sha256,
        "size": resolved.stat().st_size,
    }
    result["query_hash"] = hashlib.sha256(
        json.dumps(
            {
                "index_sha256": index_sha256,
                "terms": result["query"]["terms"],
                "limit": result["query"]["effective_limit"],
            },
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8", errors="ignore")
    ).hexdigest()
    return result


def search_docs_index_payload(
    index_payload: Mapping[str, object],
    keywords: Sequence[str],
    *,
    limit: int = 500,
) -> dict[str, object]:
    query_terms = normalize_index_query_terms(keywords)
    effective_limit = max(1, min(int(limit or 500), 5000))
    documents = {
        int(document["id"]): document
        for document in index_payload.get("documents", [])
        if isinstance(document, dict) and "id" in document
    }
    terms = index_payload.get("terms") if isinstance(index_payload.get("terms"), dict) else {}
    scored: dict[int, dict[str, object]] = {}
    for term in query_terms:
        posting_rows = terms.get(term, []) if isinstance(terms, dict) else []
        if not isinstance(posting_rows, list):
            continue
        for posting in posting_rows:
            if not isinstance(posting, dict):
                continue
            document_id = int(posting.get("document_id", -1))
            if document_id not in documents:
                continue
            count = max(0, int(posting.get("count") or 0))
            row = scored.setdefault(
                document_id,
                {
                    "document_id": document_id,
                    "score": 0,
                    "matched_terms": [],
                },
            )
            row["score"] = int(row["score"]) + count
            row["matched_terms"].append({"term": term, "count": count})

    ranked = sorted(
        scored.values(),
        key=lambda item: (
            -int(item["score"]),
            str(documents[int(item["document_id"])].get("path", "")),
            int(item["document_id"]),
        ),
    )
    results = []
    for item in ranked[:effective_limit]:
        document = documents[int(item["document_id"])]
        result_core = {
            "document_id": int(item["document_id"]),
            "source_locator": f"docs-index://document/{int(item['document_id'])}",
            "path": document.get("path"),
            "kind": document.get("kind"),
            "size": document.get("size"),
            "modified_at": document.get("modified_at"),
            "text_sha256": document.get("text_sha256"),
            "text_length": document.get("text_length"),
            "token_count": document.get("token_count"),
            "unique_token_count": document.get("unique_token_count"),
            "score": int(item["score"]),
            "matched_terms": item["matched_terms"],
            "preview_available": False,
            "verification_hint": "Open the source document or run source-search/docs for hit context; docs-index stores no full extracted text.",
        }
        results.append(
            {
                **result_core,
                "result_hash": hashlib.sha256(
                    json.dumps(result_core, ensure_ascii=False, sort_keys=True).encode("utf-8", errors="ignore")
                ).hexdigest(),
            }
        )

    found_terms = {match["term"] for result in results for match in result["matched_terms"]}
    query_core = {
        "keywords": list(keywords),
        "terms": query_terms,
        "requested_limit": int(limit or 0),
        "effective_limit": effective_limit,
        "term_count": len(query_terms),
    }
    summary = {
        "document_count": len(documents),
        "term_count": len(terms) if isinstance(terms, dict) else 0,
        "query_term_count": len(query_terms),
        "matched_document_count": len(ranked),
        "returned_result_count": len(results),
        "truncated": len(ranked) > len(results),
        "missing_terms": [term for term in query_terms if term not in found_terms],
        "stores_full_text": False,
    }
    output_core = {
        "command": "docs-index-search",
        "profile_version": "docs-index-query-v1",
        "generated_at": dt.datetime.now().isoformat(),
        "root": index_payload.get("root"),
        "index_strategy": index_payload.get("strategy"),
        "index_version": index_payload.get("version"),
        "query": query_core,
        "summary": summary,
        "results": results,
        "result_hashes": [item["result_hash"] for item in results],
        "commercial_claim_allowed": False,
        "commercial_blockers": [
            "source-viewer-hit-context-validation-required",
            "sqlite-fts-parity-diff-required",
            "million-row-runtime-evidence-required",
        ],
    }
    return {
        **output_core,
        "payload_hash": hashlib.sha256(
            json.dumps(output_core, ensure_ascii=False, sort_keys=True).encode("utf-8", errors="ignore")
        ).hexdigest(),
    }


def write_result(payload: Dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def extract_text(
    path: Path,
    kind: str,
    *,
    max_input_bytes: int = MAX_EXTRACT_TEXT_BYTES,
    max_archive_member_bytes: int = MAX_ZIP_TEXT_MEMBER_BYTES,
    max_archive_total_bytes: int = MAX_ZIP_TEXT_TOTAL_BYTES,
    max_archive_member_count: int = MAX_ZIP_TEXT_MEMBER_COUNT,
    max_pdf_stream_decompressed_bytes: int = MAX_PDF_STREAM_DECOMPRESSED_BYTES,
) -> str:
    if max_input_bytes > 0 and path.stat().st_size > max_input_bytes:
        raise TextExtractionTooLarge(f"{kind} file exceeds text extraction size limit")
    if kind in TEXT_EXTS:
        return path.read_text(encoding="utf-8", errors="ignore")
    if kind == "eml":
        return _extract_eml_text(path)
    if kind == "mbox":
        return _extract_mbox_text(path)
    if kind == "msg":
        return _extract_bounded_container_text(path)
    if kind in {"ost", "pst"}:
        return _extract_bounded_container_text(path)
    if kind in HTML_EXTS:
        return _strip_markup(path.read_text(encoding="utf-8", errors="ignore"))
    if kind in OFFICE_OPEN_XML_EXTS:
        return _extract_office_open_xml_text(
            path,
            kind,
            max_member_bytes=max_archive_member_bytes,
            max_total_bytes=max_archive_total_bytes,
            max_member_count=max_archive_member_count,
        )
    if kind in OPEN_DOCUMENT_EXTS:
        return _extract_open_document_text(
            path,
            max_member_bytes=max_archive_member_bytes,
            max_total_bytes=max_archive_total_bytes,
            max_member_count=max_archive_member_count,
        )
    if kind == "pdf":
        return _extract_pdf_text(path, max_stream_decompressed_bytes=max_pdf_stream_decompressed_bytes)
    if kind == "rtf":
        return _extract_rtf_text(path)
    return ""


def _check_zip_member_limits(
    archive: zipfile.ZipFile,
    names: list[str],
    *,
    max_member_bytes: int,
    max_total_bytes: int,
    max_member_count: int,
) -> None:
    if max_member_count > 0 and len(names) > max_member_count:
        raise TextExtractionTooLarge("archive contains too many text extraction members")
    total = 0
    for name in names:
        info = archive.getinfo(name)
        if max_member_bytes > 0 and info.file_size > max_member_bytes:
            raise TextExtractionTooLarge(f"archive member exceeds text extraction size limit: {name}")
        total += info.file_size
        if max_total_bytes > 0 and total > max_total_bytes:
            raise TextExtractionTooLarge("archive expands beyond text extraction size limit")


def _extract_office_open_xml_text(
    path: Path,
    kind: str,
    *,
    max_member_bytes: int = MAX_ZIP_TEXT_MEMBER_BYTES,
    max_total_bytes: int = MAX_ZIP_TEXT_TOTAL_BYTES,
    max_member_count: int = MAX_ZIP_TEXT_MEMBER_COUNT,
) -> str:
    prefixes = {
        "docx": ("word/document.xml",),
        "pptx": ("ppt/slides/slide",),
        "xlsx": ("xl/sharedStrings.xml", "xl/worksheets/sheet"),
    }[kind]
    with zipfile.ZipFile(path) as archive:
        texts = []
        names = [
            name
            for name in archive.namelist()
            if name.endswith(".xml") and any(name.startswith(prefix) for prefix in prefixes)
        ]
        _check_zip_member_limits(
            archive,
            names,
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
            max_member_count=max_member_count,
        )
        for name in names:
            with archive.open(name) as handle:
                texts.extend(_extract_xml_text(handle.read()))
    return " ".join(texts)


def _extract_open_document_text(
    path: Path,
    *,
    max_member_bytes: int = MAX_ZIP_TEXT_MEMBER_BYTES,
    max_total_bytes: int = MAX_ZIP_TEXT_TOTAL_BYTES,
    max_member_count: int = MAX_ZIP_TEXT_MEMBER_COUNT,
) -> str:
    with zipfile.ZipFile(path) as archive:
        if "content.xml" not in archive.namelist():
            return ""
        _check_zip_member_limits(
            archive,
            ["content.xml"],
            max_member_bytes=max_member_bytes,
            max_total_bytes=max_total_bytes,
            max_member_count=max_member_count,
        )
        with archive.open("content.xml") as handle:
            return " ".join(_extract_xml_text(handle.read()))


def _extract_xml_text(xml_data: bytes) -> List[str]:
    root = safe_xml_fromstring(xml_data)
    texts = []
    for node in root.iter():
        if node.text and node.text.strip():
            texts.append(node.text.strip())
    return texts


def _extract_pdf_text(
    path: Path,
    *,
    max_stream_decompressed_bytes: int = MAX_PDF_STREAM_DECOMPRESSED_BYTES,
) -> str:
    data = path.read_bytes()
    snippets: List[str] = []
    for stream in re.findall(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        candidates = [stream]
        try:
            candidates.append(
                _decompress_pdf_stream(
                    stream,
                    max_decompressed_bytes=max_stream_decompressed_bytes,
                )
            )
        except zlib.error:
            pass
        for item in candidates:
            snippets.extend(_extract_pdf_literal_strings(item))
    if not snippets:
        snippets.extend(_extract_pdf_literal_strings(data))
    return " ".join(snippets)


def _decompress_pdf_stream(stream: bytes, *, max_decompressed_bytes: int) -> bytes:
    if max_decompressed_bytes <= 0:
        return zlib.decompress(stream)
    decompressor = zlib.decompressobj()
    data = decompressor.decompress(stream, max_decompressed_bytes + 1)
    if len(data) > max_decompressed_bytes or decompressor.unconsumed_tail:
        raise TextExtractionTooLarge("pdf stream expands beyond text extraction size limit")
    tail = decompressor.flush()
    if len(data) + len(tail) > max_decompressed_bytes:
        raise TextExtractionTooLarge("pdf stream expands beyond text extraction size limit")
    return data + tail


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


def _extract_bounded_container_text(path: Path, *, scan_limit: int = BOUNDED_MAIL_CONTAINER_SCAN_LIMIT) -> str:
    blob = _read_prefix(path, scan_limit)
    strings = _unique_strings([*_extract_ascii_strings(blob), *_extract_utf16_strings(blob)])
    return "\n".join(strings)


def _read_prefix(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


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
