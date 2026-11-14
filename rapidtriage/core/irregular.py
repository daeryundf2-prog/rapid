"""예외 항목 (R7 갈래 A, Nuix P13 irregular items) -- nine categories mapped from existing row fields.

Rows of the files collection (``candidates`` / ``inventory``) and of the artifact kinds are
classified; a row may fall in several categories. Documents (``rapidtriage-docs.json``
candidates) are joined to their files row by path.

* ``bad-extension`` -- files: ``file_signature.mismatch`` with a known other format behind the
  extension (``magic-not-expected-for-extension``); artifacts: ``file-signature-mismatch`` rows.
* ``corrupted`` -- artifacts: 부분 결과 (``row_conditions.row_is_partial``: parser error,
  truncation, failing parse / decrypt status) or an archive that could not be opened
  (``archive_inventory_profile.analysis_status`` ``*-open-failed``); files: an unreadable header
  (``file_signature.status = read-error``) or a document whose text extraction failed
  (``text_status = error``).
* ``deleted`` -- files: ``is_deleted``, a deleted ``deletion_state`` or a deleted / carved
  ``recovery.candidate_kind``; artifacts: ``deleted_state`` / ``is_deleted`` / ``deleted`` set.
* ``empty`` -- files: 0 bytes; artifacts: a 0-byte mail attachment or backup member file.
* ``encrypted`` -- artifacts: ``encrypted`` / ``encryption.encrypted`` true, encrypted archive
  entries (``encrypted_entry_count`` > 0, ``archive-encrypted-*`` types / risk flags); files: a
  document whose extraction reported it encrypted.
* ``non-searchable-pdf`` -- files: a PDF document with no extracted text (0 characters).
* ``text-stripped`` -- files: a document whose body was judged binary and left out of the index
  (``text_status = binary-rejected``). Documents whose binary characters were removed and the
  rest indexed (``salvage_text``) leave no trace in the run outputs and are not counted.
* ``unrecognized`` -- files: a known extension whose expected signature is missing
  (``extension-expected-signature-missing``).
* ``unsupported`` -- artifacts: rows a provider marked ``supported: false``; files: documents
  whose format has no text extractor (``text_status = unsupported``).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from .families import SourceRow, details_of, norm_path

# Read-cap truncation keys of 부分 결과 (keep aligned with api/app/row_conditions.py).
PARTIAL_TRUNCATION_KEYS: tuple[str, ...] = (
    "truncated",
    "parse_truncated",
    "scan_truncated",
    "stream_truncated",
    "file_scan_truncated",
    "sqlite_scan_truncated",
    "cache_body_truncated",
    "key_truncated",
    "native_records_truncated",
    "message_rows_truncated",
    "archive_embedded_parse_truncated",
)

IRREGULAR_FILE_NAME = "rapidtriage-irregular.json"
IRREGULAR_FORMAT = "rapidtriage-irregular-v1"
CATEGORIES: tuple[str, ...] = (
    "bad-extension",
    "corrupted",
    "deleted",
    "empty",
    "encrypted",
    "non-searchable-pdf",
    "text-stripped",
    "unrecognized",
    "unsupported",
)
CATEGORY_LABELS: dict[str, str] = {
    "bad-extension": "확장자 불일치",
    "corrupted": "손상·부분 읽기",
    "deleted": "삭제됨",
    "empty": "빈 파일",
    "encrypted": "암호화",
    "non-searchable-pdf": "검색 불가 PDF",
    "text-stripped": "본문 제외(바이너리)",
    "unrecognized": "형식 미상",
    "unsupported": "미지원 형식",
}
CATEGORY_HELP: dict[str, str] = {
    "bad-extension": "확장자와 파일 서명이 다른 형식을 가리킵니다",
    "corrupted": "파서가 끝까지 읽지 못했거나 열지 못한 항목입니다",
    "deleted": "삭제 상태로 기록된 항목입니다",
    "empty": "0바이트 항목입니다",
    "encrypted": "암호가 걸린 문서·압축·저장소입니다",
    "non-searchable-pdf": "추출된 본문이 없는 PDF입니다(스캔 이미지일 수 있음)",
    "text-stripped": "본문이 바이너리로 판정돼 색인에서 빠진 문서입니다",
    "unrecognized": "확장자는 알지만 기대한 파일 서명이 없습니다",
    "unsupported": "본문을 꺼낼 파서가 없는 형식입니다",
}
_DELETED_STATES = frozenset({"deleted", "deleted-in-app", "recycled", "unallocated", "unallocated-candidate", "orphan", "carved", "recovered"})
_DELETED_KINDS = frozenset({"deleted", "recycled", "carved", "unallocated", "orphan"})
_NOT_DELETED = frozenset({"", "unknown", "allocated", "active", "live", "not-deleted", "none", "in-use", "existing"})

PartialCheck = Callable[[Mapping[str, object]], bool]


def _true(value: object) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in {"true", "yes", "1"})


def _positive(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _deleted_state(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return bool(text) and text not in _NOT_DELETED and (text in _DELETED_STATES or "deleted" in text)


def files_categories(row: Mapping[str, object], document: Mapping[str, object] | None) -> list[str]:
    """Categories of one files row (``document``: its docs candidate, when it is a document)."""
    found: list[str] = []
    signature = row.get("file_signature") if isinstance(row.get("file_signature"), Mapping) else {}
    direction = str(signature.get("mismatch_direction") or "") if isinstance(signature, Mapping) else ""
    if isinstance(signature, Mapping) and signature.get("mismatch") is True and direction != "extension-expected-signature-missing":
        found.append("bad-extension")
    text_status = str(document.get("text_status") or "") if document else ""
    if (isinstance(signature, Mapping) and signature.get("status") == "read-error") or text_status == "error":
        found.append("corrupted")
    recovery = row.get("recovery") if isinstance(row.get("recovery"), Mapping) else {}
    if (
        _true(row.get("is_deleted"))
        or _deleted_state(row.get("deletion_state"))
        or (isinstance(recovery, Mapping) and (recovery.get("candidate_kind") in _DELETED_KINDS or _deleted_state(recovery.get("deletion_state"))))
    ):
        found.append("deleted")
    size = row.get("size")
    if isinstance(size, int) and not isinstance(size, bool) and size == 0:
        found.append("empty")
    if document and (document.get("encrypted") is True or text_status == "encrypted"):
        found.append("encrypted")
    if document:
        path = str(document.get("path") or row.get("path") or "").lower()
        kind = str(document.get("kind") or "").lower()
        length = document.get("text_length")
        is_pdf = kind == "pdf" or path.endswith(".pdf")
        if is_pdf and isinstance(length, int) and length == 0 and text_status not in ("encrypted", "too-large", "error"):
            found.append("non-searchable-pdf")
        if text_status == "binary-rejected":
            found.append("text-stripped")
        if text_status == "unsupported":
            found.append("unsupported")
    if direction == "extension-expected-signature-missing":
        found.append("unrecognized")
    return found


def _encrypted_artifact(row: Mapping[str, object], details: Mapping[str, object]) -> bool:
    artifact_type = str(row.get("artifact_type") or "")
    if artifact_type.startswith("archive-encrypted"):
        return True
    if _true(details.get("encrypted")):
        return True
    encryption = details.get("encryption")
    if isinstance(encryption, Mapping) and _true(encryption.get("encrypted")):
        return True
    if _positive(details.get("encrypted_entry_count")):
        return True
    flags = details.get("risk_flags")
    return isinstance(flags, list) and any(isinstance(flag, str) and flag.startswith("archive-encrypted") for flag in flags)


def artifact_categories(row: Mapping[str, object], partial: PartialCheck) -> list[str]:
    """Categories of one artifact row (``partial``: ``row_conditions.row_is_partial``)."""
    details = details_of(row)
    artifact_type = str(row.get("artifact_type") or "")
    found: list[str] = []
    if artifact_type == "file-signature-mismatch":
        found.append("bad-extension")
    profile = details.get("archive_inventory_profile")
    open_failed = isinstance(profile, Mapping) and str(profile.get("analysis_status") or "").endswith("-open-failed")
    if open_failed or partial(row):
        found.append("corrupted")
    if _true(details.get("is_deleted")) or _true(details.get("deleted")) or _deleted_state(details.get("deleted_state")):
        found.append("deleted")
    size = details.get("size")
    zero = isinstance(size, int) and not isinstance(size, bool) and size == 0
    if zero and (artifact_type == "email-attachment" or (artifact_type == "android-backup-member" and details.get("member_type") == "file")):
        found.append("empty")
    if _encrypted_artifact(row, details):
        found.append("encrypted")
    if row.get("supported") is False:
        found.append("unsupported")
    return found


# Raw-bytes probes: an artifact JSONL line without any of them cannot be irregular (the API
# scanner parses only lines holding one; a kind whose shared profiles hold one parses every line).
ARTIFACT_PROBES: tuple[bytes, ...] = (
    b'"file-signature-mismatch"',
    b'"archive_inventory_profile"',
    b'"parser_error"',
    b'"parse_status"',
    b'"decrypt_status"',
    b'"coverage"',
    *(f'"{key}"'.encode("ascii") for key in PARTIAL_TRUNCATION_KEYS),
    b"invalid",
    b"unreadable",
    b"parse-error",
    b"parser-error",
    b"scan-error",
    b'"is_deleted"',
    b'"deleted"',
    b'"deleted_state"',
    b'"encrypt',
    b"archive-encrypted",
    b'"supported":false',
    b'"supported": false',
    b'"email-attachment"',
    b'"android-backup-member"',
)


BUCKETS: tuple[str, ...] = ("candidates", "inventory", "artifacts")


def bucket_of(source: SourceRow) -> str | None:
    """``candidates`` / ``inventory`` (files lanes) or ``artifacts``; ``None`` for other rows."""
    if source.collection == "artifacts":
        return "artifacts"
    if source.collection == "files":
        lane = source.locator.split("/")[1] if source.locator.count("/") >= 2 else ""
        return lane if lane in ("candidates", "inventory") else None
    return None


@dataclass
class IrregularIndex:
    """Refs per category (item order), kept per listing: files candidates, files inventory
    (``/files?scope=inventory``) and artifacts."""

    by_category: dict[str, dict[str, list[str]]] = field(default_factory=lambda: {name: {bucket: [] for bucket in BUCKETS} for name in CATEGORIES})

    def add(self, ref: str, bucket: str | None, categories: Iterable[str]) -> None:
        for name in categories:
            refs = self.by_category.get(name)
            if refs is not None and bucket in refs:
                refs[bucket].append(ref)

    def refs(self, category: str) -> list[str]:
        refs = self.by_category.get(category) or {}
        return [ref for bucket in BUCKETS for ref in refs.get(bucket, [])]

    def summary(self) -> dict[str, object]:
        categories = []
        unique: set[str] = set()
        per_list: dict[str, set[str]] = {bucket: set() for bucket in BUCKETS}
        total = 0
        for name in CATEGORIES:
            refs = self.by_category[name]
            counts = {bucket: len(refs[bucket]) for bucket in BUCKETS}
            for bucket in BUCKETS:
                unique.update(refs[bucket])
                per_list[bucket].update(refs[bucket])
            count = sum(counts.values())
            total += count
            categories.append(
                {
                    "id": name,
                    "label": CATEGORY_LABELS[name],
                    "help": CATEGORY_HELP[name],
                    "count": count,
                    "files": counts["candidates"] + counts["inventory"],
                    **counts,
                }
            )
        return {
            "categories": categories,
            "total": total,
            "unique_items": len(unique),
            # Rows in at least one category, per list (what ``irregular=<every id>`` lists there).
            "unique_by_list": {bucket: len(refs) for bucket, refs in per_list.items()},
        }


def classify(
    rows: Iterable[SourceRow],
    documents: Mapping[str, Mapping[str, object]],
    partial: PartialCheck,
) -> IrregularIndex:
    """Classify files and artifact rows (``documents``: docs candidates by :func:`families.norm_path`)."""
    index = IrregularIndex()
    for source in rows:
        index.add(source.ref, bucket_of(source), row_categories(source, documents, partial))
    return index


def row_categories(source: SourceRow, documents: Mapping[str, Mapping[str, object]], partial: PartialCheck) -> list[str]:
    if source.collection == "files":
        return files_categories(source.row, documents.get(norm_path(source.row.get("path"))))
    if source.collection == "artifacts":
        return artifact_categories(source.row, partial)
    return []


def irregular_document(index: IrregularIndex) -> dict[str, object]:
    return {
        "format": IRREGULAR_FORMAT,
        "summary": index.summary(),
        "refs": {name: index.by_category[name] for name in CATEGORIES},
    }


def irregular_index_from_document(document: Mapping[str, object]) -> IrregularIndex:
    refs = document.get("refs")
    if not isinstance(refs, dict):
        raise ValueError("irregular document shape")
    index = IrregularIndex()
    for name in CATEGORIES:
        stored = refs.get(name)
        if not isinstance(stored, dict):
            raise ValueError(f"irregular category {name}")
        for bucket in BUCKETS:
            values = stored.get(bucket)
            if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
                raise ValueError(f"irregular refs {name}/{bucket}")
            index.by_category[name][bucket] = list(values)
    return index
