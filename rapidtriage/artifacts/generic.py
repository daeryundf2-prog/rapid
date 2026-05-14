from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import re
import sqlite3
import zipfile
from pathlib import Path
from typing import Iterable, Mapping, Sequence
from xml.etree import ElementTree as ET

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "generic-documents-v4"
STICKY_NOTE_ROW_LIMIT = 5000
STICKY_NOTE_RECOVERY_SCAN_BYTES = 8 * 1024 * 1024
STICKY_NOTE_RECOVERY_LIMIT = 40
LARGE_FILE_HASH_DEFER_BYTES = 64 * 1024 * 1024
DESKTOP_AI_TABLE_LIMIT = 20
DESKTOP_AI_MESSAGE_ROW_LIMIT = 200
DESKTOP_AI_MESSAGE_TABLE_LIMIT = 5
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
URL_RE = re.compile(r"(?i)https?://[^\s\x00\"'<>]{4,300}")
LOCAL_LLM_PATH_TERMS = {
    "ollama": "Ollama",
    "lm studio": "LM Studio",
    "lmstudio": "LM Studio",
    "gpt4all": "GPT4All",
}
DESKTOP_AI_APP_PATH_TERMS = {
    "chatgpt": "ChatGPT Desktop",
    "openai": "OpenAI/ChatGPT Desktop",
    "copilot": "Microsoft Copilot Desktop",
    "claude": "Claude Desktop",
    "anthropic": "Claude Desktop",
    "gemini": "Gemini Desktop/WebView",
    "perplexity": "Perplexity Desktop/WebView",
}
LOCAL_LLM_MODEL_SUFFIXES = {".gguf", ".ggml", ".bin", ".safetensors"}
LOCAL_LLM_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".log", ".txt", ".sqlite", ".db"}
LOCAL_LLM_PROMPT_SCAN_BYTES = 2 * 1024 * 1024
LOCAL_LLM_PROMPT_ROW_LIMIT = 200
LOCAL_LLM_TEXT_PROMPT_TERMS = (
    "prompt",
    "user:",
    "assistant:",
    "human:",
    "system:",
    "response",
    "completion",
    "conversation",
    "chat",
)
DOCUMENT_METADATA_SUFFIXES = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
OOXML_VBA_PATHS = {"word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin"}
OOXML_PROPS_PATHS = {"docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"}
ODF_META_PATHS = {"meta.xml"}
DESKTOP_AI_APP_SUFFIXES = {
    ".sqlite",
    ".sqlite3",
    ".db",
    ".json",
    ".log",
    ".ldb",
    ".localstorage",
    ".dat",
    ".txt",
}
DESKTOP_AI_APP_STORAGE_MARKERS = (
    "appdata",
    "application support",
    "containers",
    "packages",
    "local storage",
    "indexeddb",
    "leveldb",
    "session storage",
)


class GenericDocumentArtifactProvider:
    collector_kind = "generic-documents"
    name = "generic-documents"
    description = "Cross-platform document candidates discovered from the filesystem"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        for suffix in (".txt", ".pdf", ".docx"):
            yield ArtifactRecord(
                provider=self.name,
                artifact_type="document-pattern",
                path=str(root),
                supported=True,
                details={"extension": suffix},
            )
        yield from collect_document_metadata_risk(root)
        yield from collect_sticky_notes(root)
        yield from collect_local_llm_inventory(root)
        yield from collect_desktop_ai_app_inventory(root)


def collect_document_metadata_risk(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in DOCUMENT_METADATA_SUFFIXES:
            continue
        profile = document_metadata_profile(path)
        if profile.get("analysis_status") == "not-a-zip-document":
            continue
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="document-metadata-risk",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "document-metadata-risk",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": safe_source_hashes(path),
                "document_family": profile.get("document_family", ""),
                "metadata_profile": profile,
                "author_candidates": profile.get("author_candidates", []),
                "timestamp_candidates": profile.get("timestamp_candidates", {}),
                "macro_profile": profile.get("macro_profile", {}),
                "external_reference_candidates": profile.get("external_reference_candidates", []),
                "coverage_status": "document-metadata-and-risk-profile",
                "validation_required": bool(profile.get("risk_flags")),
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "office-version-metadata-fixture-required",
                    "macro-static-analysis-not-complete",
                    "trusted-document-parser-diff-required",
                ],
                "risk_flags": profile.get("risk_flags", []),
            },
        )


def collect_sticky_notes(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.name.lower() != "plum.sqlite":
            continue
        yield from collect_sticky_notes_sqlite(path)


def document_metadata_profile(path: Path) -> dict[str, object]:
    suffix = path.suffix.lower()
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if suffix in {".docx", ".xlsx", ".pptx"}:
                props = extract_ooxml_properties(archive, names)
                macro_paths = sorted(
                    name for name in names if name in OOXML_VBA_PATHS or name.lower().endswith("vbaproject.bin")
                )
                external_refs = extract_ooxml_external_references(archive, names)
                family = suffix.lstrip(".")
            elif suffix in {".odt", ".ods", ".odp"}:
                props = extract_odf_properties(archive, names)
                macro_paths = sorted(name for name in names if "script" in name.lower() or "basic/" in name.lower())
                external_refs = []
                family = suffix.lstrip(".")
            else:
                props = {}
                macro_paths = []
                external_refs = []
                family = suffix.lstrip(".")
    except (OSError, zipfile.BadZipFile):
        return {"analysis_status": "not-a-zip-document", "document_family": suffix.lstrip(".")}
    author_candidates = unique_values(
        [
            str(props.get(key) or "")
            for key in ("creator", "lastModifiedBy", "initialCreator", "generator", "company", "manager")
        ]
    )
    timestamp_candidates = {
        key: value
        for key, value in props.items()
        if key.lower() in {"created", "modified", "creationdate", "date"} and value
    }
    risk_flags = document_metadata_risk_flags(author_candidates, macro_paths, external_refs, props)
    return {
        "profile_version": "document-metadata-risk-profile-v1",
        "analysis_status": "parsed",
        "document_family": family,
        "properties": props,
        "author_candidates": author_candidates,
        "timestamp_candidates": timestamp_candidates,
        "macro_profile": {
            "macro_present": bool(macro_paths),
            "macro_paths": macro_paths[:20],
            "macro_scan_status": "vba-project-present" if macro_paths else "not-detected",
        },
        "external_reference_candidates": external_refs[:50],
        "risk_flags": risk_flags,
        "values_are_candidates": True,
        "validation_guidance": (
            "Document metadata and VBA presence are triage pivots. Confirm author/timestamp semantics and macro behavior "
            "with a dedicated Office/ODF parser or sandbox before reporting intent or malware conclusions."
        ),
    }


def extract_ooxml_properties(archive: zipfile.ZipFile, names: set[str]) -> dict[str, str]:
    props: dict[str, str] = {}
    for name in sorted(OOXML_PROPS_PATHS.intersection(names)):
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        props.update(extract_xml_leaf_text(xml_data))
    return props


def extract_odf_properties(archive: zipfile.ZipFile, names: set[str]) -> dict[str, str]:
    props: dict[str, str] = {}
    for name in sorted(ODF_META_PATHS.intersection(names)):
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        props.update(extract_xml_leaf_text(xml_data))
    return props


def extract_xml_leaf_text(xml_data: bytes) -> dict[str, str]:
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return {}
    props: dict[str, str] = {}
    for node in root.iter():
        if not node.text or not node.text.strip():
            continue
        tag = node.tag.rsplit("}", 1)[-1]
        props.setdefault(tag, node.text.strip()[:500])
    return props


def extract_ooxml_external_references(archive: zipfile.ZipFile, names: set[str]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for name in sorted(item for item in names if item.endswith(".rels")):
        try:
            xml_data = archive.read(name)
        except (KeyError, OSError):
            continue
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError:
            continue
        for node in root.iter():
            target = str(node.attrib.get("Target") or "")
            mode = str(node.attrib.get("TargetMode") or "")
            if mode.lower() == "external" or target.lower().startswith(("http://", "https://", "file://", "\\\\")):
                refs.append(
                    {
                        "relationship_file": name,
                        "target": target[:500],
                        "target_mode": mode,
                        "type": str(node.attrib.get("Type") or "")[:200],
                    }
                )
    return refs


def document_metadata_risk_flags(
    author_candidates: Sequence[str],
    macro_paths: Sequence[str],
    external_refs: Sequence[Mapping[str, str]],
    props: Mapping[str, str],
) -> list[str]:
    flags = ["document-metadata-profile"]
    if author_candidates:
        flags.append("document-author-metadata")
    if macro_paths:
        flags.append("document-macro-present")
    if external_refs:
        flags.append("document-external-reference-candidate")
    if any(str(value).strip() for key, value in props.items() if key.lower() in {"created", "modified"}):
        flags.append("document-timestamp-metadata")
    return flags


def collect_sticky_notes_sqlite(path: Path) -> Iterable[ArtifactRecord]:
    source_hashes = safe_source_hashes(path)
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.Error:
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="sticky-note-db-unreadable",
            path=str(path.resolve()),
            supported=False,
            details={
                "parser": "sticky-notes-plum",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "coverage_status": "sqlite-open-failed",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": sticky_notes_blockers(),
            },
        )
        return
    with contextlib.closing(connection):
        tables = sticky_note_candidate_tables(connection)
        schema_profile = sticky_notes_schema_profile(connection, tables)
        emitted = 0
        live_note_hashes: set[str] = set()
        for table_name, columns in tables:
            if emitted >= STICKY_NOTE_ROW_LIMIT:
                break
            text_column = first_matching_column(columns, ("text", "content", "body", "note", "plain", "payload"))
            if not text_column:
                continue
            created_column = first_matching_column(columns, ("createdat", "created", "createtime", "creationtime"))
            updated_column = first_matching_column(columns, ("updatedat", "updated", "modified", "modifiedtime", "lastmodified"))
            deleted_column = first_matching_column(columns, ("isdeleted", "deleted", "trashed"))
            color_column = first_matching_column(columns, ("color", "theme"))
            account_column = first_matching_column(columns, ("account", "user", "userid", "email"))
            sql = f'SELECT rowid, * FROM "{table_name}" LIMIT ?'
            try:
                rows = connection.execute(sql, (STICKY_NOTE_ROW_LIMIT - emitted,)).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                text = optional_text(row[text_column])
                if not text.strip():
                    continue
                text_hash = sha256_text(text)
                live_note_hashes.add(text_hash)
                emitted += 1
                is_deleted = boolish(row[deleted_column]) if deleted_column else False
                account_hint = optional_text(row[account_column]) if account_column else ""
                yield ArtifactRecord(
                    provider=GenericDocumentArtifactProvider.name,
                    artifact_type="sticky-note",
                    path=str(path.resolve()),
                    supported=True,
                    details={
                        "parser": "sticky-notes-plum",
                        "parser_version": PARSER_VERSION,
                        "source_path": str(path.resolve()),
                        "source_hashes": source_hashes,
                        "source_table": table_name,
                        "source_index": emitted - 1,
                        "rowid": row["rowid"],
                        "created_at": normalize_sqlite_time(row[created_column]) if created_column else "",
                        "updated_at": normalize_sqlite_time(row[updated_column]) if updated_column else "",
                        "is_deleted": is_deleted,
                        "account_hint": account_hint,
                        "color_hint": optional_text(row[color_column]) if color_column else "",
                        "text_preview": redact_note_preview(text),
                        "text_sha256": text_hash,
                        "text_length": len(text),
                        "sticky_note_schema_profile": schema_profile,
                        "sticky_note_review_profile": sticky_note_review_profile(
                            text=text,
                            is_deleted=is_deleted,
                            account_hint=account_hint,
                            source_table=table_name,
                            recovered=False,
                        ),
                        "coverage_status": "plum-sqlite-row-normalized",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": sticky_notes_blockers(),
                        "risk_flags": sticky_note_risk_flags(text, is_deleted, account_hint=account_hint),
                    },
                )
        for candidate_index, candidate in enumerate(sticky_note_recovery_candidates(path, live_note_hashes)):
            yield ArtifactRecord(
                provider=GenericDocumentArtifactProvider.name,
                artifact_type="sticky-note-recovery-candidate",
                path=str(path.resolve()),
                supported=True,
                details={
                    "parser": "sticky-notes-plum",
                    "parser_version": PARSER_VERSION,
                    "source_path": str(path.resolve()),
                    "source_hashes": source_hashes,
                    "source_index": candidate_index,
                    "source_offset": candidate["source_offset"],
                    "encoding": candidate["encoding"],
                    "recovery_method": candidate["recovery_method"],
                    "recovery_reason": candidate["recovery_reason"],
                    "text_preview": redact_note_preview(str(candidate["text"])),
                    "text_sha256": sha256_text(str(candidate["text"])),
                    "text_length": len(str(candidate["text"])),
                    "sticky_note_schema_profile": schema_profile,
                    "sticky_note_review_profile": sticky_note_review_profile(
                        text=str(candidate["text"]),
                        is_deleted=True,
                        account_hint=str(candidate.get("account_hint", "")),
                        source_table="bounded-string-scan",
                        recovered=True,
                    ),
                    "coverage_status": "plum-sqlite-bounded-string-recovery-candidate",
                    "validation_required": True,
                    "commercial_grade_ready": False,
                    "commercial_grade_blockers": sticky_notes_blockers(),
                    "risk_flags": sticky_note_risk_flags(
                        str(candidate["text"]),
                        True,
                        account_hint=str(candidate.get("account_hint", "")),
                    ),
                },
            )


def sticky_note_candidate_tables(connection: sqlite3.Connection) -> list[tuple[str, list[str]]]:
    try:
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    except sqlite3.Error:
        return []
    candidates: list[tuple[str, list[str]]] = []
    for table_row in table_rows:
        table_name = str(table_row[0])
        try:
            columns = [
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
            ]
        except sqlite3.Error:
            continue
        normalized = {normalize_column(column) for column in columns}
        if normalized.intersection({"text", "content", "body", "note", "plain", "payload"}):
            candidates.append((table_name, columns))
    return candidates


def sticky_notes_schema_profile(
    connection: sqlite3.Connection,
    candidate_tables: Sequence[tuple[str, list[str]]],
) -> dict[str, object]:
    candidate_names = {table_name for table_name, _columns in candidate_tables}
    try:
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    except sqlite3.Error:
        table_rows = []
    table_profiles: list[dict[str, object]] = []
    for table_row in table_rows[:30]:
        table_name = str(table_row[0])
        try:
            columns = [
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
            ]
        except sqlite3.Error:
            columns = []
        table_profiles.append(
            {
                "name": table_name,
                "columns": columns,
                "row_count": sqlite_count_rows(connection, table_name),
                "is_note_candidate": table_name in candidate_names,
                "has_text_column": bool(
                    first_matching_column(columns, ("text", "content", "body", "note", "plain", "payload"))
                ),
                "has_deleted_column": bool(first_matching_column(columns, ("isdeleted", "deleted", "trashed"))),
                "has_account_column": bool(first_matching_column(columns, ("account", "user", "userid", "email"))),
                "has_timestamp_column": bool(
                    first_matching_column(
                        columns,
                        ("createdat", "created", "createtime", "creationtime", "updatedat", "modified", "lastmodified"),
                    )
                ),
            }
        )
    return {
        "profile_version": "sticky-notes-schema-profile-v1",
        "database_open_status": "opened",
        "table_count": len(table_rows),
        "bounded_table_count": len(table_profiles),
        "candidate_note_table_count": len(candidate_tables),
        "candidate_note_tables": [table_name for table_name, _columns in candidate_tables],
        "tables": table_profiles,
        "truncated_tables": len(table_rows) > len(table_profiles),
        "validation_required": True,
        "validation_guidance": (
            "Schema profile identifies plausible Sticky Notes tables and columns. Confirm app version, account/device "
            "attribution, deleted state, and row semantics against a known-answer plum.sqlite fixture before reporting."
        ),
    }


def sticky_note_recovery_candidates(path: Path, live_text_hashes: set[str]) -> list[dict[str, object]]:
    blob = read_prefix(path, STICKY_NOTE_RECOVERY_SCAN_BYTES)
    candidates: list[dict[str, object]] = []
    seen_hashes: set[str] = set(live_text_hashes)
    for encoding, iterator in (
        ("ascii", iter_ascii_strings_with_offsets(blob, minimum=14)),
        ("utf-16le", iter_utf16le_strings_with_offsets(blob, minimum=14)),
    ):
        for offset, text in iterator:
            cleaned = " ".join(text.split())
            text_hash = sha256_text(cleaned)
            if text_hash in seen_hashes or not looks_like_sticky_note_recovery_text(cleaned):
                continue
            seen_hashes.add(text_hash)
            candidates.append(
                {
                    "source_offset": offset,
                    "encoding": encoding,
                    "text": cleaned,
                    "account_hint": first_regex_match(cleaned, EMAIL_RE),
                    "recovery_method": "bounded-sqlite-string-scan",
                    "recovery_reason": "string-fragment-not-present-in-live-note-rows",
                }
            )
            if len(candidates) >= STICKY_NOTE_RECOVERY_LIMIT:
                return candidates
    return candidates


def sticky_note_review_profile(
    *,
    text: str,
    is_deleted: bool,
    account_hint: str,
    source_table: str,
    recovered: bool,
) -> dict[str, object]:
    lowered = text.lower()
    sensitive_terms = [
        term
        for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed", "recovery")
        if term in lowered
    ]
    urls = [match.group(0) for match in URL_RE.finditer(text)][:10]
    emails = [match.group(0) for match in EMAIL_RE.finditer(text)][:10]
    return {
        "profile_version": "sticky-note-review-profile-v1",
        "source_table": source_table,
        "source_kind": "bounded-recovery-candidate" if recovered else "sqlite-live-row",
        "deleted_state": "deleted-or-recovered-candidate" if is_deleted else "live-row",
        "text_length": len(text),
        "sensitive_term_hits": sensitive_terms,
        "url_candidates": urls,
        "email_candidates": emails,
        "account_hint_present": bool(account_hint),
        "values_are_candidates": recovered,
        "source_viewer_hint": "Open plum.sqlite with the SQLite/hex viewer and verify the row or source offset before reporting.",
        "report_blockers": [
            "app-version-schema-fixture-required",
            "deleted-state-trusted-diff-required" if is_deleted or recovered else "row-semantics-trusted-diff-required",
            "account-device-attribution-corroboration-required",
        ],
    }


def looks_like_sticky_note_recovery_text(text: str) -> bool:
    if len(text) < 14 or len(text) > 2000:
        return False
    lowered = text.lower()
    if any(term in lowered for term in ("create table", "sqlite_", "pragma ", "index ", "microsoft.msn", "http://schemas")):
        return False
    if not any(character.isalpha() for character in text):
        return False
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        return True
    if first_regex_match(text, EMAIL_RE) or first_regex_match(text, URL_RE):
        return True
    return " " in text and len(text.split()) >= 3


def iter_ascii_strings_with_offsets(blob: bytes, *, minimum: int) -> Iterable[tuple[int, str]]:
    start: int | None = None
    current = bytearray()
    for index, value in enumerate(blob):
        if 32 <= value <= 126:
            if start is None:
                start = index
            current.append(value)
            continue
        if start is not None and len(current) >= minimum:
            yield start, current.decode("utf-8", errors="replace")
        start = None
        current = bytearray()
    if start is not None and len(current) >= minimum:
        yield start, current.decode("utf-8", errors="replace")


def iter_utf16le_strings_with_offsets(blob: bytes, *, minimum: int) -> Iterable[tuple[int, str]]:
    start: int | None = None
    chars: list[str] = []
    index = 0
    while index + 1 < len(blob):
        value = blob[index]
        null = blob[index + 1]
        if 32 <= value <= 126 and null == 0:
            if start is None:
                start = index
            chars.append(chr(value))
            index += 2
            continue
        if start is not None and len(chars) >= minimum:
            yield start, "".join(chars)
        start = None
        chars = []
        index += 1
    if start is not None and len(chars) >= minimum:
        yield start, "".join(chars)


def collect_local_llm_inventory(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        product = infer_local_llm_product(path)
        suffix = path.suffix.lower()
        if not product and suffix not in LOCAL_LLM_MODEL_SUFFIXES:
            continue
        if not product and suffix in LOCAL_LLM_MODEL_SUFFIXES:
            product = "Local LLM model file"
        if suffix not in LOCAL_LLM_MODEL_SUFFIXES and suffix not in LOCAL_LLM_CONFIG_SUFFIXES:
            continue
        stat_result = safe_stat(path)
        source_hashes = safe_source_hashes(path)
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="local-llm-artifact",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "local-llm-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": source_hashes,
                "product_hint": product,
                "artifact_role": local_llm_role(path),
                "model_name_hint": local_llm_model_name_hint(path),
                "source_size": stat_result.get("size", 0),
                "modified_at": stat_result.get("modified_at", ""),
                "coverage_status": "local-llm-file-inventory",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "application-version-and-schema-not-verified",
                    "prompt-history-db-parser-not-complete",
                    "model-download-provenance-not-validated",
                ],
                "risk_flags": local_llm_risk_flags(path),
            },
        )
        yield from collect_local_llm_prompt_candidates(path=path, product=product, source_hashes=source_hashes)


def collect_local_llm_prompt_candidates(
    *,
    path: Path,
    product: str,
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    suffix = path.suffix.lower()
    if suffix in LOCAL_LLM_MODEL_SUFFIXES:
        return
    if suffix in {".sqlite", ".db"}:
        yield from collect_local_llm_sqlite_prompt_candidates(path=path, product=product, source_hashes=source_hashes)
        return
    if suffix not in {".json", ".yaml", ".yml", ".toml", ".log", ".txt"}:
        return
    data = read_prefix(path, LOCAL_LLM_PROMPT_SCAN_BYTES)
    if not data:
        return
    text = data.decode("utf-8", errors="replace")
    emitted = 0
    for offset, fragment in local_llm_text_prompt_fragments(text):
        if emitted >= LOCAL_LLM_PROMPT_ROW_LIMIT:
            break
        emitted += 1
        direction = local_llm_prompt_direction(fragment)
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="local-llm-prompt-candidate",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "local-llm-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": dict(source_hashes),
                "product_hint": product,
                "source_index": emitted - 1,
                "source_offset": offset,
                "source_kind": "bounded-text-fragment",
                "direction": direction,
                "content_preview": redact_note_preview(fragment),
                "content_sha256": sha256_text(fragment),
                "content_length": len(fragment),
                "local_llm_review_profile": local_llm_review_profile(
                    product=product,
                    direction=direction,
                    content=fragment,
                    source_kind="bounded-text-fragment",
                ),
                "coverage_status": "local-llm-prompt-fragment-candidate",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "local-llm-app-schema-version-not-validated",
                    "prompt-history-format-not-confirmed",
                    "conversation-thread-pairing-not-complete",
                ],
                "risk_flags": local_llm_prompt_risk_flags(direction, fragment),
            },
        )


def collect_local_llm_sqlite_prompt_candidates(
    *,
    path: Path,
    product: str,
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.Error:
        return
    emitted = 0
    with contextlib.closing(connection):
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        except sqlite3.Error:
            return
        for table_row in table_rows[:DESKTOP_AI_TABLE_LIMIT]:
            if emitted >= LOCAL_LLM_PROMPT_ROW_LIMIT:
                break
            table_name = str(table_row["name"])
            try:
                columns = [
                    str(row["name"])
                    for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
                ]
            except sqlite3.Error:
                continue
            content_column = first_matching_column(
                columns,
                ("prompt", "content", "text", "message", "input", "output", "response", "completion"),
            )
            if not content_column:
                continue
            role_column = first_matching_column(columns, ("role", "sender", "speaker", "type"))
            created_column = first_matching_column(
                columns,
                ("createdat", "created_at", "created", "timestamp", "time", "date", "updatedat", "updated_at"),
            )
            selected_columns = ["rowid", content_column]
            for optional_column in (role_column, created_column):
                if optional_column and optional_column not in selected_columns:
                    selected_columns.append(optional_column)
            sql = (
                "SELECT "
                + ", ".join("rowid" if column == "rowid" else quote_sqlite_identifier(column) for column in selected_columns)
                + f" FROM {quote_sqlite_identifier(table_name)} LIMIT ?"
            )
            try:
                rows = connection.execute(sql, (LOCAL_LLM_PROMPT_ROW_LIMIT - emitted,)).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                content = optional_text(row[content_column])
                if not content.strip():
                    continue
                role_hint = optional_text(row[role_column]) if role_column else ""
                direction = local_llm_prompt_direction(role_hint or content_column)
                emitted += 1
                yield ArtifactRecord(
                    provider=GenericDocumentArtifactProvider.name,
                    artifact_type="local-llm-prompt-candidate",
                    path=str(path.resolve()),
                    supported=True,
                    details={
                        "parser": "local-llm-inventory",
                        "parser_version": PARSER_VERSION,
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "product_hint": product,
                        "source_table": table_name,
                        "source_index": emitted - 1,
                        "rowid": row["rowid"],
                        "source_kind": "sqlite-row",
                        "role_hint": role_hint,
                        "direction": direction,
                        "created_at": normalize_sqlite_time(row[created_column]) if created_column else "",
                        "content_preview": redact_note_preview(content),
                        "content_sha256": sha256_text(content),
                        "content_length": len(content),
                        "local_llm_review_profile": local_llm_review_profile(
                            product=product,
                            direction=direction,
                            content=content,
                            source_kind="sqlite-row",
                        ),
                        "coverage_status": "local-llm-sqlite-prompt-row-candidate",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": [
                            "local-llm-app-schema-version-not-validated",
                            "service-or-app-export-diff-required",
                            "conversation-thread-pairing-not-complete",
                        ],
                        "risk_flags": local_llm_prompt_risk_flags(direction, content),
                    },
                )


def collect_desktop_ai_app_inventory(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.suffix.lower() not in DESKTOP_AI_APP_SUFFIXES:
            continue
        product = infer_desktop_ai_product(path)
        if not product:
            continue
        stat_result = safe_stat(path)
        sqlite_profile = desktop_ai_sqlite_profile(path)
        message_tables = sqlite_profile.get("message_table_candidates", []) if isinstance(sqlite_profile, Mapping) else []
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="desktop-ai-app-artifact",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "desktop-ai-app-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": safe_source_hashes(path),
                "product_hint": product,
                "artifact_role": desktop_ai_app_role(path),
                "source_size": stat_result.get("size", 0),
                "modified_at": stat_result.get("modified_at", ""),
                "database_profile": sqlite_profile,
                "message_table_candidates": message_tables,
                "coverage_status": "desktop-ai-app-file-inventory",
                "validation_required": True,
                "commercial_grade_ready": False,
                "commercial_grade_blockers": [
                    "desktop-ai-app-schema-version-not-validated",
                    "prompt-history-db-parser-not-complete",
                    "service-export-diff-required",
                ],
                "risk_flags": desktop_ai_app_risk_flags(path, sqlite_profile),
            },
        )
        yield from collect_desktop_ai_conversation_candidates(
            path=path,
            product=product,
            sqlite_profile=sqlite_profile,
            source_hashes=safe_source_hashes(path),
        )


def collect_desktop_ai_conversation_candidates(
    *,
    path: Path,
    product: str,
    sqlite_profile: Mapping[str, object],
    source_hashes: Mapping[str, str],
) -> Iterable[ArtifactRecord]:
    if path.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        return
    message_tables = sqlite_profile.get("message_table_candidates")
    if not isinstance(message_tables, list) or not message_tables:
        return
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.Error:
        return
    emitted = 0
    with contextlib.closing(connection):
        for table_profile in message_tables[:DESKTOP_AI_MESSAGE_TABLE_LIMIT]:
            if emitted >= DESKTOP_AI_MESSAGE_ROW_LIMIT or not isinstance(table_profile, Mapping):
                break
            table_name = str(table_profile.get("name") or "")
            columns = [str(column) for column in table_profile.get("columns") or []]
            if not table_name or not columns:
                continue
            content_column = first_matching_column(
                columns,
                ("content", "text", "message", "body", "prompt", "answer", "response", "completion"),
            )
            if not content_column:
                continue
            role_column = first_matching_column(columns, ("role", "author", "sender", "speaker", "type"))
            created_column = first_matching_column(
                columns,
                ("createdat", "created_at", "created", "timestamp", "time", "date", "updatedat", "updated_at"),
            )
            conversation_column = first_matching_column(
                columns,
                ("conversationid", "conversation_id", "chatid", "chat_id", "threadid", "thread_id", "sessionid"),
            )
            selected_columns = ["rowid", content_column]
            for optional_column in (role_column, created_column, conversation_column):
                if optional_column and optional_column not in selected_columns:
                    selected_columns.append(optional_column)
            sql = (
                "SELECT "
                + ", ".join("rowid" if column == "rowid" else quote_sqlite_identifier(column) for column in selected_columns)
                + f" FROM {quote_sqlite_identifier(table_name)} LIMIT ?"
            )
            try:
                rows = connection.execute(sql, (DESKTOP_AI_MESSAGE_ROW_LIMIT - emitted,)).fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                content = optional_text(row[content_column])
                if not content.strip():
                    continue
                role_hint = optional_text(row[role_column]) if role_column else ""
                conversation_hint = optional_text(row[conversation_column]) if conversation_column else ""
                created_at = normalize_sqlite_time(row[created_column]) if created_column else ""
                direction = desktop_ai_message_direction(role_hint, content_column)
                emitted += 1
                yield ArtifactRecord(
                    provider=GenericDocumentArtifactProvider.name,
                    artifact_type="desktop-ai-conversation-candidate",
                    path=str(path.resolve()),
                    supported=True,
                    details={
                        "parser": "desktop-ai-app-inventory",
                        "parser_version": PARSER_VERSION,
                        "source_path": str(path.resolve()),
                        "source_hashes": dict(source_hashes),
                        "product_hint": product,
                        "source_table": table_name,
                        "source_index": emitted - 1,
                        "rowid": row["rowid"],
                        "role_hint": role_hint,
                        "direction": direction,
                        "conversation_id_hint": conversation_hint,
                        "created_at": created_at,
                        "content_preview": redact_note_preview(content),
                        "content_sha256": sha256_text(content),
                        "content_length": len(content),
                        "desktop_ai_conversation_review_profile": desktop_ai_conversation_review_profile(
                            product=product,
                            table_name=table_name,
                            direction=direction,
                            role_hint=role_hint,
                            created_at=created_at,
                            conversation_hint=conversation_hint,
                            content=content,
                        ),
                        "coverage_status": "desktop-ai-sqlite-message-row-candidate",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": [
                            "desktop-ai-app-schema-version-not-validated",
                            "service-export-diff-required",
                            "conversation-thread-pairing-not-complete",
                        ],
                        "risk_flags": desktop_ai_conversation_risk_flags(direction, content),
                    },
                )


def infer_desktop_ai_product(path: Path) -> str:
    lowered = str(path).lower().replace("\\", "/").replace("_", " ")
    if not any(marker in lowered for marker in DESKTOP_AI_APP_STORAGE_MARKERS):
        return ""
    for term, product in DESKTOP_AI_APP_PATH_TERMS.items():
        if term in lowered:
            return product
    return ""


def desktop_ai_app_role(path: Path) -> str:
    suffix = path.suffix.lower()
    lowered_name = path.name.lower()
    if suffix in {".sqlite", ".sqlite3", ".db"}:
        return "application-database"
    if suffix in {".ldb", ".localstorage"} or "leveldb" in str(path).lower():
        return "browser-engine-storage"
    if suffix == ".log":
        return "application-log"
    if suffix == ".json":
        return "configuration-or-export-fragment"
    if "conversation" in lowered_name or "chat" in lowered_name or "message" in lowered_name:
        return "possible-prompt-history"
    return "application-cache-or-metadata"


def desktop_ai_sqlite_profile(path: Path) -> dict[str, object]:
    if path.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
        return {"database_open_status": "not-sqlite-extension"}
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        return {"database_open_status": "open-failed", "error": str(exc)}
    tables: list[dict[str, object]] = []
    message_candidates: list[dict[str, object]] = []
    with contextlib.closing(connection):
        try:
            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        except sqlite3.Error as exc:
            return {"database_open_status": "schema-read-failed", "error": str(exc)}
        for table_row in table_rows[:DESKTOP_AI_TABLE_LIMIT]:
            table_name = str(table_row["name"])
            try:
                columns = [
                    str(row["name"])
                    for row in connection.execute(f"PRAGMA table_info({quote_sqlite_identifier(table_name)})").fetchall()
                ]
            except sqlite3.Error:
                columns = []
            row_count = sqlite_count_rows(connection, table_name)
            table_profile = {"name": table_name, "columns": columns, "row_count": row_count}
            tables.append(table_profile)
            normalized_columns = {normalize_column(column) for column in columns}
            if normalized_columns.intersection({"role", "author", "sender", "content", "text", "message", "prompt", "answer", "response"}):
                message_candidates.append(table_profile)
    return {
        "database_open_status": "opened",
        "table_count": len(table_rows),
        "bounded_table_count": len(tables),
        "tables": tables,
        "message_table_candidates": message_candidates,
        "truncated_tables": len(table_rows) > DESKTOP_AI_TABLE_LIMIT,
    }


def sqlite_count_rows(connection: sqlite3.Connection, table_name: str) -> int | None:
    try:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {quote_sqlite_identifier(table_name)}").fetchone()
    except sqlite3.Error:
        return None
    return int(row["count"] or 0) if row is not None else None


def quote_sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def desktop_ai_app_risk_flags(path: Path, sqlite_profile: Mapping[str, object]) -> list[str]:
    flags = ["desktop-ai-app-artifact", "ai-service-usage"]
    role = desktop_ai_app_role(path)
    if role in {"application-database", "possible-prompt-history"}:
        flags.append("possible-ai-prompt-history")
    if sqlite_profile.get("message_table_candidates"):
        flags.append("ai-message-table-candidate")
    return flags


def desktop_ai_message_direction(role_hint: str, content_column: str) -> str:
    normalized_role = normalize_column(role_hint)
    normalized_column = normalize_column(content_column)
    if normalized_role in {"user", "human", "client", "prompt"} or normalized_column == "prompt":
        return "user-prompt-candidate"
    if normalized_role in {"assistant", "ai", "bot", "model", "system"}:
        return "assistant-response-candidate" if normalized_role != "system" else "system-message-candidate"
    if normalized_column in {"answer", "response", "completion"}:
        return "assistant-response-candidate"
    return "message-candidate"


def desktop_ai_conversation_review_profile(
    *,
    product: str,
    table_name: str,
    direction: str,
    role_hint: str,
    created_at: str,
    conversation_hint: str,
    content: str,
) -> dict[str, object]:
    return {
        "profile_version": "desktop-ai-conversation-review-profile-v1",
        "product_hint": product,
        "source_table": table_name,
        "direction": direction,
        "role_hint": role_hint,
        "created_at_present": bool(created_at),
        "conversation_id_present": bool(conversation_hint),
        "content_length": len(content),
        "url_candidates": [match.group(0) for match in URL_RE.finditer(content)][:10],
        "email_candidates": [match.group(0) for match in EMAIL_RE.finditer(content)][:10],
        "sensitive_term_hits": [
            term
            for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed", "credential")
            if term in content.lower()
        ],
        "values_are_candidates": True,
        "source_viewer_hint": (
            "Open the desktop AI SQLite row and compare it with a service export before reporting prompt/answer content."
        ),
        "not_proof_of": [
            "complete-service-side-transcript",
            "message-delivery-or-read-state",
            "conversation-thread-completeness",
        ],
        "report_blockers": [
            "desktop-app-version-schema-fixture-required",
            "service-export-diff-required",
            "thread-pairing-validation-required",
        ],
    }


def desktop_ai_conversation_risk_flags(direction: str, content: str) -> list[str]:
    lowered = content.lower()
    flags = ["desktop-ai-conversation-candidate", "ai-service-usage"]
    if direction == "user-prompt-candidate":
        flags.append("ai-user-prompt-candidate")
    elif direction == "assistant-response-candidate":
        flags.append("ai-assistant-response-candidate")
    if first_regex_match(content, URL_RE):
        flags.append("ai-message-url-candidate")
    if first_regex_match(content, EMAIL_RE):
        flags.append("ai-message-email-candidate")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        flags.append("possible-sensitive-ai-content")
    return flags


def infer_local_llm_product(path: Path) -> str:
    lowered = str(path).lower().replace("_", " ")
    for term, product in LOCAL_LLM_PATH_TERMS.items():
        if term in lowered:
            return product
    return ""


def local_llm_role(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in LOCAL_LLM_MODEL_SUFFIXES:
        return "model-file"
    if suffix in {".sqlite", ".db"}:
        return "application-database"
    if suffix == ".log":
        return "application-log"
    return "configuration-or-metadata"


def local_llm_model_name_hint(path: Path) -> str:
    if path.suffix.lower() in LOCAL_LLM_MODEL_SUFFIXES:
        return path.stem
    parent = path.parent.name
    return parent if parent.lower() not in {"models", "blobs", "manifests"} else path.stem


def local_llm_risk_flags(path: Path) -> list[str]:
    flags = ["local-ai-artifact"]
    if path.suffix.lower() in LOCAL_LLM_MODEL_SUFFIXES:
        flags.append("local-model-file")
    lowered = str(path).lower()
    if any(term in lowered for term in ("history", "prompt", "chat", "conversation")):
        flags.append("possible-prompt-history")
    return flags


def local_llm_text_prompt_fragments(text: str) -> list[tuple[int, str]]:
    fragments: list[tuple[int, str]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        cleaned = " ".join(line.split()).strip()
        lowered = cleaned.lower()
        if 12 <= len(cleaned) <= 4000 and any(term in lowered for term in LOCAL_LLM_TEXT_PROMPT_TERMS):
            fragments.append((offset, cleaned[:2000]))
        offset += len(line.encode("utf-8", errors="replace"))
    if fragments:
        return fragments[:LOCAL_LLM_PROMPT_ROW_LIMIT]
    for match in re.finditer(r"(?is)(prompt|response|completion|conversation|chat)[\"'\s:=]{1,12}.{20,800}", text):
        fragments.append((match.start(), " ".join(match.group(0).split())[:2000]))
        if len(fragments) >= LOCAL_LLM_PROMPT_ROW_LIMIT:
            break
    return fragments


def local_llm_prompt_direction(value: str) -> str:
    normalized = normalize_column(value)
    lowered = value.lower()
    if normalized in {"user", "human", "prompt", "input"} or "user:" in lowered or "human:" in lowered:
        return "user-prompt-candidate"
    if normalized in {"assistant", "model", "bot", "response", "completion", "output"} or "assistant:" in lowered:
        return "assistant-response-candidate"
    if normalized == "system" or "system:" in lowered:
        return "system-message-candidate"
    return "local-llm-message-candidate"


def local_llm_review_profile(*, product: str, direction: str, content: str, source_kind: str) -> dict[str, object]:
    return {
        "profile_version": "local-llm-review-profile-v1",
        "product_hint": product,
        "source_kind": source_kind,
        "direction": direction,
        "content_length": len(content),
        "url_candidates": [match.group(0) for match in URL_RE.finditer(content)][:10],
        "email_candidates": [match.group(0) for match in EMAIL_RE.finditer(content)][:10],
        "sensitive_term_hits": [
            term
            for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed", "credential")
            if term in content.lower()
        ],
        "values_are_candidates": True,
        "source_viewer_hint": "Open the local LLM log/database source before using this prompt candidate in a report.",
        "not_proof_of": [
            "complete-conversation-thread",
            "message-delivery",
            "model-output-authenticity",
        ],
        "report_blockers": [
            "local-llm-version-fixture-required",
            "prompt-history-schema-diff-required",
            "thread-pairing-validation-required",
        ],
    }


def local_llm_prompt_risk_flags(direction: str, content: str) -> list[str]:
    flags = ["local-llm-prompt-candidate", "local-ai-artifact"]
    lowered = content.lower()
    if direction == "user-prompt-candidate":
        flags.append("local-llm-user-prompt-candidate")
    elif direction == "assistant-response-candidate":
        flags.append("local-llm-assistant-response-candidate")
    if first_regex_match(content, URL_RE):
        flags.append("local-llm-url-candidate")
    if first_regex_match(content, EMAIL_RE):
        flags.append("local-llm-email-candidate")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        flags.append("possible-sensitive-local-llm-content")
    return flags


def safe_source_hashes(path: Path) -> dict[str, str]:
    stat_result = safe_stat(path)
    size = int(stat_result.get("size", 0) or 0)
    if size and size <= LARGE_FILE_HASH_DEFER_BYTES:
        try:
            hashes = compute_hashes(path)
        except OSError:
            hashes = {}
        if hashes:
            return hashes
    return {
        "md5": "",
        "sha1": "",
        "sha256": "",
        "hash_status": "deferred-large-file" if size > LARGE_FILE_HASH_DEFER_BYTES else "unavailable",
        "path_sha256": sha256_text(str(path.resolve())),
    }


def safe_stat(path: Path) -> dict[str, object]:
    try:
        stat_result = path.stat()
    except OSError:
        return {"size": 0, "modified_at": ""}
    return {
        "size": int(stat_result.st_size),
        "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
    }


def read_prefix(path: Path, limit: int) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return b""


def first_regex_match(value: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(value)
    return match.group(0) if match else ""


def first_matching_column(columns: Sequence[str], names: Sequence[str]) -> str:
    by_normalized = {normalize_column(column): column for column in columns}
    for name in names:
        column = by_normalized.get(normalize_column(name))
        if column:
            return column
    for normalized_name in names:
        wanted = normalize_column(normalized_name)
        for column in columns:
            if wanted in normalize_column(column):
                return column
    return ""


def normalize_column(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def unique_values(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        cleaned = " ".join(str(value).split()).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        output.append(cleaned)
    return output


def optional_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def boolish(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "deleted"}


def normalize_sqlite_time(value: object) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10_000_000_000_000:
            number = number / 1_000_000
        elif number > 10_000_000_000:
            number = number / 1000
        try:
            return dt.datetime.fromtimestamp(number, dt.timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return str(value)
    return str(value)


def redact_note_preview(text: str) -> str:
    preview = " ".join(text.split())[:1200]
    return preview


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sticky_note_risk_flags(text: str, is_deleted: bool, *, account_hint: str = "") -> list[str]:
    lowered = text.lower()
    flags = ["sticky-note-text"]
    if is_deleted:
        flags.append("deleted-note-row")
    if account_hint or first_regex_match(text, EMAIL_RE):
        flags.append("sticky-note-account-or-email-candidate")
    if first_regex_match(text, URL_RE):
        flags.append("sticky-note-url-candidate")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey", "seed")):
        flags.append("possible-sensitive-note")
    return flags


def sticky_notes_blockers() -> list[str]:
    return [
        "sticky-notes-schema-version-not-verified",
        "deleted-row-recovery-not-complete",
        "account-and-device-attribution-needs-corroboration",
    ]
