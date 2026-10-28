from __future__ import annotations

import datetime as dt
import email
import hashlib
import json
import os
import platform
import re
import struct
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Protocol
from xml.etree import ElementTree as ET

from ..artifacts import all_providers, collect_cached
from ..artifacts.windows.antiforensics import redact_recovery_key_text
from ..artifacts.windows.system_extras import redact_secret_store_text
from .doc_text import (
    OLE_SIGNATURE,
    DocumentText,
    TextTooLarge,
    decode_text_bytes,
    extract_doc_text,
    extract_hwp_text,
    extract_hwpx_text,
    extract_pdf_document_text,
    extract_ppt_text,
    extract_xls_text,
)
from .doc_text import (
    finalize as finalize_document_text,
)
from .files import file_time_origin_for_input_kind, is_tool_output_dir
from .input_root import InputRoot, resolve_input_root
from .json_safe import json_default
from .models import DocumentCandidate, DocumentMatch
from .rules import RuleSet, annotate_docs_payload
from .safe_xml import safe_xml_fromstring
from .textnorm import locate_normalized, normalize_nfc, normalize_search_text

SUPPORTED_DOC_EXTS = {
    ".cell",
    ".cfg",
    ".conf",
    ".csv",
    ".doc",
    ".docx",
    ".hwp",
    ".hwpx",
    ".show",
    ".xls",
    ".ppt",
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
# Hancom Office 2014+ .cell/.show are OOXML containers (older ones are OLE).
HANCOM_OOXML_KINDS = {"cell": "xlsx", "show": "pptx"}
NATIVE_BINARY_EXTRACTORS = {
    "hwp": extract_hwp_text,
    "hwpx": extract_hwpx_text,
    "doc": extract_doc_text,
    "xls": extract_xls_text,
    "ppt": extract_ppt_text,
}
OPEN_DOCUMENT_EXTS = {"odp", "ods", "odt"}
DOCS_INDEX_TOKEN_PATTERN = re.compile(r"[\w@./:-]{2,}", flags=re.UNICODE)
# v2: index terms are NFC + casefold (v1 used str.lower(), so NFD text indexed
# as decomposed jamo). v1 indexes still load; queries are normalized either way.
DOCS_INDEX_VERSION = 2
MAX_EXTRACT_TEXT_BYTES = 50_000_000
MAX_ZIP_TEXT_MEMBER_BYTES = 10_000_000
MAX_ZIP_TEXT_TOTAL_BYTES = 50_000_000
MAX_ZIP_TEXT_MEMBER_COUNT = 2_000
MAX_PDF_STREAM_DECOMPRESSED_BYTES = 10_000_000


# One exception type for docs.py and the native extractors (doc_text).
TextExtractionTooLarge = TextTooLarge
BOUNDED_MAIL_CONTAINER_SCAN_LIMIT = 2 * 1024 * 1024
MANIFEST_COLLECT_MAX_WORKERS = 8


class ManifestProgress(Protocol):
    """Per-provider progress sink used by ``build_manifest`` (see core/run/progress.py)."""

    def provider_running(self, kind: str) -> None: ...

    def provider_finished(self, kind: str, *, status: str, artifact_count: int, **extra: object) -> None: ...


def scan_document_candidates(root: InputRoot | Path, limit: int = 0) -> list[DocumentCandidate]:
    input_root = resolve_input_root(root)
    origin = file_time_origin_for_input_kind(input_root.kind)
    candidates: list[DocumentCandidate] = []
    for dirpath, dirnames, files in os.walk(input_root.root_path):
        dirnames[:] = [name for name in dirnames if not is_tool_output_dir(Path(dirpath) / name)]
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
                    modified_at_origin=origin,
                )
            )
            if limit and len(candidates) >= limit:
                return candidates
    return candidates


def manifest_collect_workers(task_count: int) -> int:
    """Bounded worker count shared by the manifest and artifact stages.

    Provider collection is dominated by evidence-tree walks and file reads
    (I/O bound), so the cap is ``min(8, cpu_count)`` rather than the CPU count.
    """
    limit = min(MANIFEST_COLLECT_MAX_WORKERS, os.cpu_count() or 4)
    return max(1, min(limit, int(task_count)))


def provider_progress_key(provider: object) -> str:
    """Provider identity used by run progress (the collector kind)."""
    kind = str(getattr(provider, "collector_kind", "") or "").strip().lower()
    return kind or str(getattr(provider, "name", "") or "")


def manifest_summary_row(
    provider: object,
    payload: Mapping[str, object],
    *,
    output_path: Path | None = None,
) -> dict[str, object]:
    """Manifest provider row that references a per-kind artifacts output.

    Carries counts and the ``records_path`` of the JSONL row stream instead
    of an ``artifacts`` array (run-pipeline-mitigations I13).
    """
    from .artifact_profiles import payload_record_count, resolve_records_path

    summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
    records_path = resolve_records_path(payload, output_path)
    row: dict[str, object] = {
        "name": provider.name,
        "description": provider.description,
        "target_platform": provider.target_platform,
        "supported": provider.supported(),
        "artifact_count": payload_record_count(payload),
        "artifact_type_counts": dict(summary.get("artifact_type_counts") or {}),
        "records_path": str(records_path) if records_path is not None else None,
        "artifacts_output": str(output_path) if output_path is not None else None,
    }
    status = str(summary.get("collection_status") or "")
    if status and status != "completed":
        row["collection_status"] = status
    parser_errors = payload.get("parser_errors")
    if isinstance(parser_errors, list) and parser_errors:
        row["parser_errors"] = list(parser_errors)
    return row


def build_manifest(
    root: InputRoot | Path,
    keywords: Sequence[str],
    *,
    input_kind: str | None = None,
    progress: ManifestProgress | None = None,
    artifact_payloads: Mapping[str, Mapping[str, object]] | None = None,
    artifact_outputs: Mapping[str, Path] | None = None,
    records_dir: Path | None = None,
) -> dict[str, object]:
    """Assemble provider rows, collecting providers in parallel.

    Rows keep ``all_providers()`` order. Standalone (no ``records_dir``),
    each row embeds its ``artifacts`` array; providers already collected in
    this process (``collect_cached``) are cache hits. In a run,
    ``artifact_payloads``/``artifact_outputs`` (the artifacts stage results)
    and ``records_dir`` make every row a summary that points at the per-kind
    JSONL row stream: covered kinds reuse the artifacts-stage output and
    uncovered providers are collected into ``records_dir``. A provider whose
    collect raises is isolated (``collection_status: failed-isolated``)
    instead of aborting the whole manifest.
    """
    input_root = resolve_input_root(root, kind=input_kind)
    root_path = input_root.root_path
    providers = list(all_providers())
    covered = dict(artifact_payloads or {})
    outputs = dict(artifact_outputs or {})

    # Run plan hooks (core/run/progress.RunProgress): skipped/cancelled
    # manifest-group tasks are not collected; running ones can be cancelled.
    should_run = getattr(progress, "task_should_run", None)
    task_status = getattr(progress, "task_status", None)
    cancel_checker = getattr(progress, "cancel_checker", None)
    rows_reporter = getattr(progress, "rows_reporter", None)

    def collect_summary_row(provider: object, progress_key: str) -> dict[str, object]:
        from .artifacts import run_artifact_collection

        assert records_dir is not None
        # Providers outside the run profile are not run outputs
        # (artifacts_<kind>); keep them apart from the per-kind outputs.
        output_path = records_dir / MANIFEST_ONLY_RECORDS_DIR / f"rapidtriage-artifacts-{progress_key}.json"
        payload = run_artifact_collection(
            input_root,
            kind=progress_key,
            records_path=output_path.with_suffix(".jsonl"),
            use_cache=False,
            check_cancel=cancel_checker(progress_key) if callable(cancel_checker) else None,
            on_rows=rows_reporter(progress_key) if callable(rows_reporter) else None,
        )
        write_result(payload, output_path, indent=None)
        row = manifest_summary_row(provider, payload, output_path=output_path)
        summary = payload.get("summary") if isinstance(payload.get("summary"), Mapping) else {}
        if summary.get("provider_stop_timeout"):
            row["provider_thread_left_running"] = str(summary.get("provider_thread") or "")
        return row

    def collect_row(provider: object) -> dict[str, object]:
        progress_key = provider_progress_key(provider)
        if progress_key in covered:
            return manifest_summary_row(provider, covered[progress_key], output_path=outputs.get(progress_key))
        if records_dir is not None and callable(should_run) and not should_run(progress_key):
            status = str(task_status(progress_key) or "skipped") if callable(task_status) else "skipped"
            return planned_out_manifest_row(provider, status)
        if progress is not None:
            progress.provider_running(progress_key)
        if records_dir is not None:
            row = collect_summary_row(provider, progress_key)
            if progress is not None:
                collection_status = str(row.get("collection_status") or "")
                status = {"failed-isolated": "error", "cancelled-partial": "partial"}.get(collection_status, "completed")
                if status == "partial" and not int(row.get("artifact_count") or 0):
                    status = "cancelled"
                stuck_thread = row.pop("provider_thread_left_running", None)
                progress.provider_finished(
                    progress_key,
                    status=status,
                    artifact_count=int(row.get("artifact_count") or 0),
                    # Only a RunProgress gets here with a stuck thread (cancel checker).
                    **({"stuck_thread": stuck_thread} if stuck_thread else {}),
                )
            return row
        row: dict[str, object] = {
            "name": provider.name,
            "description": provider.description,
            "target_platform": provider.target_platform,
            "supported": provider.supported(),
        }
        try:
            row["artifacts"] = [item.to_dict() for item in collect_cached(provider, root_path)]
        except Exception as exc:
            row["artifacts"] = []
            row["collection_status"] = "failed-isolated"
            row["parser_errors"] = [
                {
                    "kind": progress_key,
                    "collector": str(provider.name),
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            ]
            if progress is not None:
                progress.provider_finished(progress_key, status="error", artifact_count=0)
            return row
        if progress is not None:
            progress.provider_finished(progress_key, status="completed", artifact_count=len(row["artifacts"]))
        return row

    with ThreadPoolExecutor(
        max_workers=manifest_collect_workers(len(providers)),
        thread_name_prefix="rapidtriage-manifest",
    ) as executor:
        # executor.map yields in submission order, keeping the manifest
        # provider order deterministic regardless of completion order.
        provider_rows = list(executor.map(collect_row, providers))
    return {
        "generated_at": dt.datetime.now().isoformat(),
        "root": str(input_root.root_path),
        "platform": platform.platform(),
        "keywords": list(keywords),
        "providers": provider_rows,
    }


def planned_out_manifest_row(provider: object, status: str) -> dict[str, object]:
    """Manifest row of a provider the run plan skipped or cancelled before it started (no rows)."""
    return {
        "name": provider.name,
        "description": provider.description,
        "target_platform": provider.target_platform,
        "supported": provider.supported(),
        "artifact_count": 0,
        "artifact_type_counts": {},
        "records_path": None,
        "artifacts_output": None,
        "collection_status": status if status in {"skipped", "cancelled"} else "skipped",
        "plan_status": status,
    }


# Subdirectory of artifacts/ holding rows of providers the run profile
# does not schedule (collected only for the manifest).
MANIFEST_ONLY_RECORDS_DIR = "manifest-only"

MANIFEST_SUMMARY_PROVIDER_FIELDS = ("name", "description", "target_platform", "supported")


def build_manifest_summary(manifest_payload: Mapping[str, object]) -> dict[str, object]:
    """Reduce a manifest to per-provider counts for embedding in docs.json.

    The full artifact rows stay in ``rapidtriage-manifest.json`` and
    ``artifacts/rapidtriage-artifacts-<kind>.json``; docs.json keeps only
    ``{name, description, target_platform, supported, artifact_count}`` per
    provider so the same artifact arrays are never stored twice.
    """
    providers: list[dict[str, object]] = []
    for provider in manifest_payload.get("providers") or []:
        if not isinstance(provider, Mapping):
            continue
        row = {field: provider.get(field) for field in MANIFEST_SUMMARY_PROVIDER_FIELDS}
        artifacts = provider.get("artifacts")
        if isinstance(artifacts, list):
            row["artifact_count"] = len(artifacts)
        else:
            row["artifact_count"] = int(provider.get("artifact_count") or 0)
        providers.append(row)
    summary = {
        key: manifest_payload[key]
        for key in ("generated_at", "root", "platform", "keywords")
        if key in manifest_payload
    }
    summary["providers"] = providers
    return summary


# Keyword hits that only occur inside Windows shell boilerplate: desktop.ini
# ``[.ShellClassInfo]`` sections and ``shell32.dll`` resource references
# match a "shell" mode keyword without any user content.
DOCS_NOISE_TOKENS: dict[str, tuple[str, ...]] = {
    "shell-class-info": (".shellclassinfo", "shellclassinfo", "shell32.dll", "shell32"),
}


def keyword_noise_hint(haystack: str, keywords: Sequence[str]) -> str:
    """Noise hint name when every matched keyword occurs only inside noise tokens."""
    if not keywords:
        return ""
    for hint, tokens in DOCS_NOISE_TOKENS.items():
        stripped = haystack
        for token in tokens:
            stripped = stripped.replace(token, " ")
        if stripped != haystack and not any(keyword in stripped for keyword in keywords):
            return hint
    return ""


def run_docs_search(
    root: InputRoot | Path,
    keywords: Sequence[str],
    limit: int = 0,
    *,
    input_kind: str | None = None,
    rule_set: RuleSet | None = None,
    index_output: Path | None = None,
    manifest: Mapping[str, object] | None = None,
    text_sink: Callable[[str, str, str], None] | None = None,
) -> dict[str, object]:
    """Search documents under ``root``; ``manifest`` reuses an already-built
    provider manifest (run pipeline) instead of collecting providers again.

    ``text_sink(path, text, extraction_error)`` receives every candidate's
    extracted text in candidate order (the run pipeline spools it for the
    persist step's case DB so documents are not extracted twice)."""
    input_root = resolve_input_root(root, kind=input_kind)
    normalized = [normalize_search_text(item) for item in keywords]
    candidates = scan_document_candidates(input_root, limit=limit)
    matches: list[DocumentMatch] = []
    text_by_path: dict[str, str] = {}
    extraction_errors: list[dict[str, object]] = []
    status_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    for candidate in candidates:
        extraction_error = ""
        try:
            result = extract_document_text(Path(candidate.path), candidate.kind)
        except TextExtractionTooLarge as exc:
            result = DocumentText("", status="too-large", reason=f"{exc}")
            extraction_error = f"{type(exc).__name__}: {exc}"
            extraction_errors.append(
                document_extraction_error(candidate, "input-too-large", exc, recoverable=True)
            )
        except (OSError, UnicodeError, zipfile.BadZipFile, ET.ParseError, ValueError, struct.error, IndexError, KeyError) as exc:
            result = DocumentText("", status="error", reason=f"{type(exc).__name__}: {exc}")
            extraction_error = f"{type(exc).__name__}: {exc}"
            extraction_errors.append(
                document_extraction_error(candidate, "text-extraction-failed", exc, recoverable=True)
            )
        text = result.text
        candidate.text_status = result.status
        candidate.extraction_method = result.method
        candidate.text_length = len(text)
        candidate.encrypted = result.encrypted
        candidate.text_reason = result.reason
        status_counts[result.status] += 1
        if result.method:
            method_counts[result.method] += 1
        if result.status in {"encrypted", "binary-rejected", "unsupported"} and not extraction_error:
            # Not an exception, but the document was not (fully) indexed: say so.
            extraction_error = f"{result.status}: {result.reason}"
        text_by_path[candidate.path] = text
        if text_sink is not None:
            text_sink(candidate.path, text, extraction_error)
        haystack = normalize_search_text(text) if normalized else ""
        matched = [keyword for keyword in normalized if keyword in haystack]
        candidate.matched = bool(matched)
        candidate.matched_keywords = list(matched)
        if not matched:
            continue
        matches.append(
            DocumentMatch(
                path=candidate.path,
                kind=candidate.kind,
                matched_keywords=matched,
                preview=build_preview(text, matched[0]),
                size=candidate.size,
                noise_hint=keyword_noise_hint(haystack, matched),
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
            "text_status_counts": dict(sorted(status_counts.items())),
            "extraction_method_counts": dict(sorted(method_counts.items())),
            "indexed_with_text_count": sum(1 for item in candidates if item.text_length > 0),
            "encrypted_count": sum(1 for item in candidates if item.encrypted),
            "zero_text_count": sum(1 for item in candidates if item.text_length == 0),
            "zero_text_reason_counts": dict(
                Counter(item.text_reason or item.text_status for item in candidates if item.text_length == 0).most_common(30)
            ),
            "ocr_available": False,
            "listing_contract": "candidates lists every document; matched=true rows are the keyword hits (results)",
            "size_caps": build_docs_size_cap_disclosure(candidates),
        },
        "manifest": build_manifest_summary(
            manifest if manifest is not None else build_manifest(input_root, normalized)
        ),
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
        # Machine-read inverted index: written compact (C JSON encoder);
        # the indented writer took minutes on large cases.
        write_result(index_payload, index_output, indent=None)
        payload["index"] = {
            "command": "docs-index",
            "path": str(index_output),
            "strategy": index_payload["strategy"],
            "version": index_payload["version"],
            "document_count": index_payload["summary"]["indexed_document_count"],
            "term_count": index_payload["summary"]["term_count"],
        }
    return payload


def build_docs_size_cap_disclosure(candidates: Sequence[DocumentCandidate]) -> dict[str, object]:
    """Text-extraction size caps and the documents they stopped (``too-large``)."""
    too_large = [item for item in candidates if item.text_status == "too-large"]
    binary = [item for item in candidates if item.text_status == "binary-rejected"]
    return {
        "max_input_bytes": MAX_EXTRACT_TEXT_BYTES,
        "max_archive_member_bytes": MAX_ZIP_TEXT_MEMBER_BYTES,
        "max_archive_total_bytes": MAX_ZIP_TEXT_TOTAL_BYTES,
        "max_pdf_stream_decompressed_bytes": MAX_PDF_STREAM_DECOMPRESSED_BYTES,
        "too_large_count": len(too_large),
        "too_large_samples": [
            {"path": item.path, "size": item.size, "reason": item.text_reason} for item in too_large[:20]
        ],
        "binary_rejected_count": len(binary),
        "truncated": bool(too_large),
        "note": (
            f"크기 상한 초과 문서 {len(too_large)}건은 본문을 추출·색인하지 않았습니다(파일 {MAX_EXTRACT_TEXT_BYTES // 1_000_000} MB, "
            f"압축 멤버 {MAX_ZIP_TEXT_MEMBER_BYTES // 1_000_000} MB 상한). 비인쇄 문자 비율 초과 {len(binary)}건도 색인하지 않았습니다."
        ),
    }


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
    root: InputRoot | Path,
    candidates: Sequence[DocumentCandidate],
    text_by_path: dict[str, str],
) -> dict[str, object]:
    input_root = resolve_input_root(root)
    documents = []
    postings: dict[str, list[dict[str, int]]] = {}
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
            "case_fold_method": "unicode-casefold",
            "unicode_normalization": "NFC",
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


def tokenize_index_terms(text: str) -> list[str]:
    # Tokenize the NFC form (NFD combining marks are not ``\w`` and would split
    # words), then casefold each token; queries go through the same function.
    return [
        normalize_search_text(match.group(0))[:256]
        for match in DOCS_INDEX_TOKEN_PATTERN.finditer(normalize_nfc(text))
    ]


def normalize_index_query_terms(keywords: Sequence[str]) -> list[str]:
    terms: list[str] = []
    seen: set[str] = set()
    for keyword in keywords:
        raw = str(keyword).strip()
        if not raw:
            continue
        tokens = tokenize_index_terms(raw)
        if not tokens:
            tokens = [normalize_search_text(raw)[:256]]
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


MAX_SUBSTRING_EXPANSIONS_PER_TERM = 20000


def expand_index_query_terms(
    query_terms: Sequence[str],
    terms: Mapping[str, object],
    *,
    max_expansions: int = MAX_SUBSTRING_EXPANSIONS_PER_TERM,
) -> tuple[dict[str, list[str]], bool]:
    """Indexed tokens containing each query term (the term itself first)."""
    expansions: dict[str, list[str]] = {}
    truncated = False
    vocabulary = list(terms) if isinstance(terms, Mapping) else []
    for term in query_terms:
        if not term:
            continue
        found = [term] if term in terms else []
        for indexed in vocabulary:
            if indexed != term and term in indexed:
                if len(found) >= max_expansions:
                    truncated = True
                    break
                found.append(indexed)
        expansions[term] = found
    return expansions, truncated


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
    # Parser-quality r2: the index stores whole tokens only ("근로계약서를"),
    # so a query term is also matched inside longer indexed tokens
    # (substring over the vocabulary; Korean particles/compounds).
    expansions, expansion_truncated = expand_index_query_terms(query_terms, terms)
    for term in query_terms:
        posting_rows: list[object] = []
        for indexed_term in expansions.get(term, [term]):
            rows = terms.get(indexed_term, []) if isinstance(terms, dict) else []
            if isinstance(rows, list):
                posting_rows.extend(rows)
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
            matched = row["matched_terms"]
            existing = next((item for item in matched if item["term"] == term), None)
            if existing is None:
                matched.append({"term": term, "count": count})
            else:
                existing["count"] = int(existing["count"]) + count

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
        "match_mode": "token+substring",
        "substring_expanded_terms": {term: len(expansions.get(term, [])) for term in query_terms},
        "substring_expansion_truncated": expansion_truncated,
        "recall_note": (
            "색인은 단어(토큰) 단위입니다: 질의어는 색인 토큰 안의 부분 문자열로도 찾습니다(예: '계약' → '근로계약서를'). "
            "토큰 경계를 넘는 구절은 찾지 못하며, 원문 확인은 문서 검색(docs/source-search)으로 하십시오."
            + (" 부분 일치 확장이 상한에 걸려 일부 토큰을 보지 않았습니다." if expansion_truncated else "")
        ),
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


def write_result(payload: dict[str, object], output: Path, *, indent: int | None = 2) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", buffering=4 * 1024 * 1024) as handle:
        separators = (",", ":") if indent is None else None
        json.dump(payload, handle, ensure_ascii=False, indent=indent, separators=separators, default=json_default)
        handle.write("\n")


def extract_document_text(
    path: Path,
    kind: str,
    *,
    max_input_bytes: int = MAX_EXTRACT_TEXT_BYTES,
) -> DocumentText:
    """Text plus status (ok/encrypted/no-text/binary-rejected/unsupported).

    Native binary formats (HWP/HWPX/DOC/XLS/PPT, PDF) go through
    ``core.doc_text``; the other kinds wrap :func:`extract_text`. An OOXML
    file that is an OLE container is an encrypted Office document.
    """
    result = _extract_document_text(path, kind, max_input_bytes=max_input_bytes)
    # BitLocker recovery passwords are masked by content (checksum-validated), whatever the
    # file name, before the text reaches the docs output, the docs index or the case DB.
    # R5 L2: wallet/credential stores and private keys are withheld, saved-password lines masked.
    redacted = redact_secret_store_text(path, redact_recovery_key_text(path.name, result.text))
    return result if redacted == result.text else replace(result, text=redacted)


def _extract_document_text(path: Path, kind: str, *, max_input_bytes: int) -> DocumentText:
    kind = kind.lower()
    if max_input_bytes > 0 and path.stat().st_size > max_input_bytes:
        raise TextExtractionTooLarge(f"{kind} file exceeds text extraction size limit")
    if kind in NATIVE_BINARY_EXTRACTORS:
        return NATIVE_BINARY_EXTRACTORS[kind](path)
    if kind == "pdf":
        return extract_pdf_document_text(path)
    if kind in OFFICE_OPEN_XML_EXTS or kind in HANCOM_OOXML_KINDS or kind in OPEN_DOCUMENT_EXTS:
        with path.open("rb") as handle:
            head = handle.read(8)
        if head == OLE_SIGNATURE:
            if kind in HANCOM_OOXML_KINDS:
                legacy = extract_xls_text if kind == "cell" else extract_ppt_text
                return legacy(path)
            return finalize_document_text("", method="ooxml", encrypted=True, empty_reason="암호화된 Office 문서(OLE EncryptionInfo 컨테이너)")
        if not head.startswith(b"PK"):
            return DocumentText("", status="unsupported", method="ooxml", reason="ZIP/OLE 헤더 없음")
        effective = HANCOM_OOXML_KINDS.get(kind, kind)
        text = extract_text(path, effective, max_input_bytes=max_input_bytes)
        return finalize_document_text(text, method=f"{effective}-xml")
    text = extract_text(path, kind, max_input_bytes=max_input_bytes)
    return finalize_document_text(text, method=f"{kind}-text")


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
    """Plain text of a document; checksum-valid BitLocker recovery passwords are masked
    whatever the file name (:func:`~rapidtriage.artifacts.windows.antiforensics.redact_recovery_key_text`)."""
    text = _extract_text(
        path,
        kind,
        max_input_bytes=max_input_bytes,
        max_archive_member_bytes=max_archive_member_bytes,
        max_archive_total_bytes=max_archive_total_bytes,
        max_archive_member_count=max_archive_member_count,
        max_pdf_stream_decompressed_bytes=max_pdf_stream_decompressed_bytes,
    )
    return redact_secret_store_text(path, redact_recovery_key_text(path.name, text))


def _extract_text(
    path: Path,
    kind: str,
    *,
    max_input_bytes: int,
    max_archive_member_bytes: int,
    max_archive_total_bytes: int,
    max_archive_member_count: int,
    max_pdf_stream_decompressed_bytes: int,
) -> str:
    if max_input_bytes > 0 and path.stat().st_size > max_input_bytes:
        raise TextExtractionTooLarge(f"{kind} file exceeds text extraction size limit")
    if kind in NATIVE_BINARY_EXTRACTORS:
        return NATIVE_BINARY_EXTRACTORS[kind](path).text
    if kind in HANCOM_OOXML_KINDS:
        kind = HANCOM_OOXML_KINDS[kind]
    if kind in TEXT_EXTS:
        return decode_text_bytes(path.read_bytes())
    if kind == "eml":
        return _extract_eml_text(path)
    if kind == "mbox":
        return _extract_mbox_text(path)
    if kind == "msg":
        return _extract_bounded_container_text(path)
    if kind in {"ost", "pst"}:
        return _extract_bounded_container_text(path)
    if kind in HTML_EXTS:
        return _strip_markup(decode_text_bytes(path.read_bytes()))
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
        native = extract_pdf_document_text(path, max_stream_bytes=max_pdf_stream_decompressed_bytes)
        if native.status in {"ok", "encrypted", "no-text", "binary-rejected"}:
            return native.text
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


def _extract_xml_text(xml_data: bytes) -> list[str]:
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
    """Literal strings shown by PDF text objects (``BT`` ... ``ET``).

    Each stream is inflated when it is Flate-compressed (raw otherwise) and
    only strings inside text objects are kept: scanning compressed bytes or
    font/image streams for ``(...)`` produced megabytes of binary noise per
    PDF (and a multi-GB docs index) without adding readable text. A file
    without any stream (rare hand-written PDFs) is still scanned whole.
    """
    data = path.read_bytes()
    snippets: list[str] = []
    found_stream = False
    for match in _PDF_STREAM_RE.finditer(data):
        found_stream = True
        stream = match.group(1)
        try:
            content = _decompress_pdf_stream(stream, max_decompressed_bytes=max_stream_decompressed_bytes)
        except zlib.error:
            content = stream
        snippets.extend(_extract_pdf_text_object_strings(content))
    if not found_stream:
        snippets.extend(_extract_pdf_literal_strings(data))
    return " ".join(snippets)


_PDF_TEXT_OBJECT_RE = re.compile(rb"\bBT\b(.*?)\bET\b", re.DOTALL)
_PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.DOTALL)


def _extract_pdf_text_object_strings(content: bytes) -> list[str]:
    if b"BT" not in content:
        return []
    found: list[str] = []
    for block in _PDF_TEXT_OBJECT_RE.findall(content):
        found.extend(_extract_pdf_literal_strings(block))
    return found


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


def _extract_pdf_literal_strings(blob: bytes) -> list[str]:
    found = []
    for raw in re.findall(rb"\((.*?)(?<!\\)\)", blob, re.DOTALL):
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
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def build_preview(text: str, keyword: str, radius: int = 80) -> str:
    # Match offsets come from normalized (NFC + casefold) text, whose length can
    # differ from ``text``; locate_normalized maps the span onto the NFC form of
    # the text, so the preview is cut from that form (== ``text`` when NFC).
    located = locate_normalized(text, keyword)
    if located is None:
        return normalize_nfc(text[: radius * 2]).strip()
    display, index, match_end = located
    start = max(0, index - radius)
    end = min(len(display), match_end + radius)
    preview = display[start:end].strip()
    return preview.replace("\n", " ")
