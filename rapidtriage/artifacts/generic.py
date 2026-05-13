from __future__ import annotations

import datetime as dt
import hashlib
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ..core.models import ArtifactRecord
from ..core.submission import compute_hashes

PARSER_VERSION = "generic-documents-v2"
STICKY_NOTE_ROW_LIMIT = 5000
LARGE_FILE_HASH_DEFER_BYTES = 64 * 1024 * 1024
LOCAL_LLM_PATH_TERMS = {
    "ollama": "Ollama",
    "lm studio": "LM Studio",
    "lmstudio": "LM Studio",
    "gpt4all": "GPT4All",
}
LOCAL_LLM_MODEL_SUFFIXES = {".gguf", ".ggml", ".bin", ".safetensors"}
LOCAL_LLM_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".log", ".txt", ".sqlite", ".db"}


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
        yield from collect_sticky_notes(root)
        yield from collect_local_llm_inventory(root)


def collect_sticky_notes(root: Path) -> Iterable[ArtifactRecord]:
    for path in sorted(root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file() or path.name.lower() != "plum.sqlite":
            continue
        yield from collect_sticky_notes_sqlite(path)


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
    with connection:
        tables = sticky_note_candidate_tables(connection)
        emitted = 0
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
                emitted += 1
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
                        "is_deleted": boolish(row[deleted_column]) if deleted_column else False,
                        "account_hint": optional_text(row[account_column]) if account_column else "",
                        "color_hint": optional_text(row[color_column]) if color_column else "",
                        "text_preview": redact_note_preview(text),
                        "text_sha256": sha256_text(text),
                        "text_length": len(text),
                        "coverage_status": "plum-sqlite-row-normalized",
                        "validation_required": True,
                        "commercial_grade_ready": False,
                        "commercial_grade_blockers": sticky_notes_blockers(),
                        "risk_flags": sticky_note_risk_flags(text, boolish(row[deleted_column]) if deleted_column else False),
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
            columns = [str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table_name}")').fetchall()]
        except sqlite3.Error:
            continue
        normalized = {normalize_column(column) for column in columns}
        if normalized.intersection({"text", "content", "body", "note", "plain", "payload"}):
            candidates.append((table_name, columns))
    return candidates


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
        yield ArtifactRecord(
            provider=GenericDocumentArtifactProvider.name,
            artifact_type="local-llm-artifact",
            path=str(path.resolve()),
            supported=True,
            details={
                "parser": "local-llm-inventory",
                "parser_version": PARSER_VERSION,
                "source_path": str(path.resolve()),
                "source_hashes": safe_source_hashes(path),
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


def sticky_note_risk_flags(text: str, is_deleted: bool) -> list[str]:
    lowered = text.lower()
    flags = ["sticky-note-text"]
    if is_deleted:
        flags.append("deleted-note-row")
    if any(term in lowered for term in ("password", "passwd", "otp", "secret", "token", "api key", "apikey")):
        flags.append("possible-sensitive-note")
    return flags


def sticky_notes_blockers() -> list[str]:
    return [
        "sticky-notes-schema-version-not-verified",
        "deleted-row-recovery-not-complete",
        "account-and-device-attribution-needs-corroboration",
    ]
