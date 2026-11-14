"""Entity reveal (R7 lane B): one personal value of one search row, audited.

The search index never stores a personal number (only its SHA-256 and mask). A reveal

1. is refused with 403 when ``RAPIDTRIAGE_PII_REVEAL`` is ``off`` (``0``/``false``/``no``);
2. checks in the index that the row (``collection``/``kind``/``locator``, its primary row)
   posts the value (``value_sha256``) and that the value is a masked kind;
3. needs the run's case DB (no audit, no reveal: 409);
4. re-reads that one source record from the run outputs, flattens it exactly as the index
   build did and finds the value whose SHA-256 matches (in memory only);
5. writes one append-only ``audit_event`` (``search.entity.reveal``: kind, SHA-256, mask,
   reason, index build -- never the value) and only then answers the value, once, with
   ``Cache-Control: no-store``. Nothing is logged or cached server-side.

One request reveals one value of one row (no bulk reveal); the console asks for the reason
once per browser session and keeps a revealed value only in the open panel.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from fastapi import HTTPException

from ...core.case_db.database import CaseDatabase
from ...core.jobs import RunJob
from ...core.search_index.build import load_source_docs, read_index_meta, reveal_entity
from ...core.search_index.patterns import (
    ENTITY_RULE,
    KIND_LABELS,
    SENSITIVE_KINDS,
    mask_sensitive,
)
from ...core.search_index.schema import INDEX_FILE_NAME, open_read_only
from .search_index_service import CORRUPT_INDEX, NO_INDEX, _case_exists, run_case

REVEAL_ENV = "RAPIDTRIAGE_PII_REVEAL"
REVEAL_OFF_VALUES = frozenset({"off", "0", "false", "no", "disabled"})
REVEAL_ACTION = "search.entity.reveal"
REVEAL_DISABLED = "개인정보 원값 보기가 꺼져 있습니다(RAPIDTRIAGE_PII_REVEAL=off). 관리자에게 문의하세요"
REVEAL_OLD_INDEX = "이 검색 색인은 개체 추출 이전 형식(v4)입니다. 처리 단계에서 색인을 다시 만드세요"
REVEAL_NOT_IN_ROW = "이 행에는 그 개체가 없습니다(검색 색인 기준)"
REVEAL_NOT_SENSITIVE = "IP 주소·호스트는 가려지지 않아 공개할 값이 없습니다"
REVEAL_NO_CASE_DB = "케이스 DB가 없어 공개 기록(감사)을 남길 수 없습니다. 케이스 DB를 만든 뒤 다시 시도하세요"
REVEAL_SOURCE_GONE = "런 출력에서 그 값을 다시 찾지 못했습니다(출력이 바뀌었으면 색인을 다시 만드세요)"
REVEAL_AUDIT_FAILED = "공개 기록(감사)을 남기지 못해 값을 보여 주지 않습니다: {reason}"


def reveal_enabled() -> bool:
    return os.environ.get(REVEAL_ENV, "").strip().lower() not in REVEAL_OFF_VALUES


def _indexed_value(index_path: Path, collection: str, kind: str, locator: str, sha: bytes) -> tuple[str, str] | None:
    """``(kind, mask)`` of the value when the row's primary index row posts it."""
    connection = open_read_only(index_path)
    try:
        row = connection.execute(
            "SELECT v.kind, v.masked FROM search_doc d JOIN search_entity e ON e.doc_id = d.doc_id "
            "JOIN search_entity_value v ON v.value_id = e.value_id "
            "WHERE d.collection = ? AND d.kind = ? AND d.locator = ? AND d.doc_id = d.group_id AND v.value_sha256 = ? LIMIT 1",
            (collection, kind, locator, sha),
        ).fetchone()
    finally:
        connection.close()
    return (str(row[0]), str(row[1])) if row is not None else None


def reveal_value(job: RunJob, run_id: str, output_dir: Path, *, collection: str, kind: str, locator: str, value_sha256: str, reason: str) -> dict[str, object]:
    if not reveal_enabled():
        raise HTTPException(status_code=403, detail=REVEAL_DISABLED)
    index_path = output_dir / INDEX_FILE_NAME
    meta, unreadable = read_index_meta(index_path)
    if meta is None:
        raise HTTPException(status_code=409 if unreadable else 404, detail=CORRUPT_INDEX.format(reason=unreadable) if unreadable else NO_INDEX)
    if meta.get("entities") != ENTITY_RULE:
        raise HTTPException(status_code=409, detail=REVEAL_OLD_INDEX)
    sha = bytes.fromhex(value_sha256)
    try:
        indexed = _indexed_value(index_path, collection, kind, locator, sha)
    except sqlite3.Error as exc:
        raise HTTPException(status_code=409, detail=CORRUPT_INDEX.format(reason=str(exc))) from exc
    if indexed is None:
        raise HTTPException(status_code=404, detail=REVEAL_NOT_IN_ROW)
    entity_kind, masked = indexed
    if entity_kind not in SENSITIVE_KINDS:
        raise HTTPException(status_code=400, detail=REVEAL_NOT_SENSITIVE)
    database, case_id = run_case(job, run_id)
    if not _case_exists(database, case_id):
        raise HTTPException(status_code=409, detail=REVEAL_NO_CASE_DB)
    loaded = load_source_docs(output_dir, job.summary or {}, collection=collection, kind=kind, locator=locator)
    found = reveal_entity(*loaded, sha) if loaded is not None else None
    if found is None:
        raise HTTPException(status_code=409, detail=REVEAL_SOURCE_GONE)
    value, _entity = found
    params = {
        "run_id": run_id,
        "collection": collection,
        "kind": kind,
        "locator": locator,
        "entity_kind": entity_kind,
        "value_sha256": value_sha256,
        "masked": masked,
        "reason": mask_sensitive(reason.strip())[:500],
        "index_build_id": meta.get("build_id"),
    }
    try:
        audit_id = CaseDatabase(database).add_audit_event(
            case_id=case_id,
            action=REVEAL_ACTION,
            target_type="search_entity",
            target_id=f"{collection}:{kind}:{locator}",
            actor="local-user",
            tool_name="rapidtriage-search",
            params_json=json.dumps(params, ensure_ascii=False, sort_keys=True),
            result="ok",
        )
    except (sqlite3.Error, OSError) as exc:
        raise HTTPException(status_code=409, detail=REVEAL_AUDIT_FAILED.format(reason=exc.__class__.__name__)) from exc
    return {
        "run_id": run_id,
        "collection": collection,
        "kind": kind,
        "locator": locator,
        "entity_kind": entity_kind,
        "label": KIND_LABELS.get(entity_kind, entity_kind),
        "masked": masked,
        "value_sha256": value_sha256,
        "value": value,
        "audit_id": audit_id,
    }
