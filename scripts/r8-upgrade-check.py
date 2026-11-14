#!/usr/bin/env python3
"""Upgrade check: does state written by the R7 build still open on this build? (R8 T-355, QA-206)

Checks, each reported as counts (never row contents):

  case DB     schema version / columns / integrity, then marks, notes, user tags and saved searches
              counted raw (before) and through the current code (after); the difference must be 0.
              ``--write`` opens a *copy* with the current code: ``case-backup`` runs first (one
              backup DB file, hash equal to the DB before the open), then the schema is applied.
              Without ``--write`` the DB is opened ``mode=ro`` and nothing is written.
  run folder  R7 run summary (no ``run_scope`` / ``fingerprint_mode``), read-only verdict when the
              folder is inside its evidence (D37), report candidates by the one rule
              (``is_report_candidate`` over bookmark JSON + active case DB marks) and a
              before/after stat snapshot proving no write.
  audit       export audit records (R7 sidecar JSON or JSON lines): a record without
              ``previous_record_sha256`` is "사슬 이전" (pre-chain), never "깨짐"; a chained record
              must carry the SHA-256 of the previous line.
  storage     the three R7 browser keys (역할 · 담당자 이름 · 테마) are still read by the frontend
              (key in the UI contract and its owner file); an absent R7 value reads as the default.

Anything the current build cannot open gets a Korean message instead of a traceback.

  python scripts/r8-upgrade-check.py --run D:/old-runs/run-0423 --evidence-root E:/evidence --json
  python scripts/r8-upgrade-check.py --case-db C:/copy/rapidtriage-case.db --write --backup-dir C:/copy/bak
  python scripts/r8-upgrade-check.py --synthetic C:/tmp/r7-upgrade --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rapidtriage.core.backup import BackupError, build_case_backup
from rapidtriage.core.case_db import (
    CaseDatabase,
    CaseDatabaseError,
    list_case_tags,
)
from rapidtriage.core.case_db.intake import CaseIntake
from rapidtriage.core.case_db.schema import (
    ARTIFACT_DATA_COLUMNS,
    REVIEW_MARK_MIGRATION_COLUMNS,
    SCHEMA_VERSION,
)
from rapidtriage.core.jobs import output_inside_evidence_reason
from rapidtriage.core.report_candidates import is_report_candidate

DEFAULT_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "upgrade" / "r7-state.json"
DEFAULT_FRONTEND_SRC = REPO_ROOT / "frontend" / "src"
UI_CONTRACT = Path("contracts") / "uiContract.ts"
SUMMARY_NAME = "rapidtriage-run-summary.json"
CASE_JSON_NAME = "rapidtriage-case.json"
CASE_DB_NAME = "rapidtriage-case.db"
CHAIN_FIELD = "previous_record_sha256"
R7_ABSENT_SUMMARY_KEYS = ("run_scope", "fingerprint_mode")
# Tables a current-schema DB has; one missing means the current code would migrate on open.
CURRENT_TABLES = ("case_record", "review_mark", "saved_search", "case_note", "case_tag", "histogram_baseline")
COUNT_KEYS = ("review_marks", "case_notes", "user_tags", "saved_searches")
ACTIVE_MARK_SQL = (
    "NOT (status = 'unreviewed' AND include_in_report = 0 AND COALESCE(note, '') = '' "
    "AND COALESCE(tags_json, '[]') IN ('[]', '') "
    "AND COALESCE(verification_status, 'unverified') IN ('unverified', ''))"
)


# --- helpers -------------------------------------------------------------------------------------


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def open_ro(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.expanduser().resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def stat_snapshot(root: Path) -> dict[str, tuple[int, int]]:
    """Relative path -> (size, mtime_ns) of every file below ``root`` (cheap on big run folders)."""
    snapshot: dict[str, tuple[int, int]] = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            try:
                info = path.stat()
            except OSError:
                continue
            snapshot[str(path.relative_to(root))] = (info.st_size, info.st_mtime_ns)
    return snapshot


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def _scalar(connection: sqlite3.Connection, sql: str, params: Sequence[object] = ()) -> int:
    row = connection.execute(sql, tuple(params)).fetchone()
    return int(row[0] or 0) if row else 0


# --- case DB -------------------------------------------------------------------------------------


def inspect_case_db(path: Path) -> dict[str, object]:
    """Raw, read-only view of a case DB: version, shape, integrity and the four counts."""
    try:
        connection = open_ro(path)
    except sqlite3.Error as exc:
        return {"readable": False, "message": f"케이스 DB를 열 수 없습니다: {exc}"}
    try:
        tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        version = 0
        if "schema_info" in tables:
            row = connection.execute("SELECT value FROM schema_info WHERE key = 'schema_version'").fetchone()
            version = int(row[0]) if row and str(row[0]).isdigit() else -1
        mark_columns = _columns(connection, "review_mark") if "review_mark" in tables else set()
        artifact_columns = _columns(connection, "artifact") if "artifact" in tables else set()
        missing = sorted(
            [f"table:{name}" for name in CURRENT_TABLES if name not in tables]
            + [f"review_mark.{name}" for name in (*REVIEW_MARK_MIGRATION_COLUMNS, "tag_ids_json") if name not in mark_columns]
            + [f"artifact.{name}" for name in ARTIFACT_DATA_COLUMNS if "artifact" in tables and name not in artifact_columns]
        )
        integrity = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        case_ids = sorted(str(row[0]) for row in connection.execute("SELECT case_id FROM case_record")) if "case_record" in tables else []
        counts = {
            "review_marks": _scalar(connection, "SELECT COUNT(*) FROM review_mark") if "review_mark" in tables else 0,
            "include_in_report_marks": _scalar(
                connection, f"SELECT COUNT(*) FROM review_mark WHERE include_in_report = 1 AND {ACTIVE_MARK_SQL}"
            )
            if "review_mark" in tables
            else 0,
            "case_notes": _scalar(
                connection, "SELECT COUNT(*) FROM case_note WHERE deleted_at IS NULL OR deleted_at = ''"
            )
            if "case_note" in tables
            else 0,
            "user_tags": _raw_user_tags(connection, tables),
            "saved_searches": _scalar(connection, "SELECT COUNT(*) FROM saved_search") if "saved_search" in tables else 0,
        }
    except sqlite3.Error as exc:
        return {"readable": False, "message": f"케이스 DB를 읽을 수 없습니다: {exc}"}
    finally:
        connection.close()
    unsupported = version not in (0, SCHEMA_VERSION)
    return {
        "readable": True,
        "schema_version": version,
        "expected_schema_version": SCHEMA_VERSION,
        "unsupported": unsupported,
        "message": (
            f"이 케이스 DB의 스키마 버전({version})은 지금 프로그램(지원 버전 {SCHEMA_VERSION})이 열 수 없습니다. "
            "DB를 고치지 않았습니다. 이 DB를 만든 버전으로 여세요."
            if unsupported
            else ""
        ),
        "migration_needed": bool(missing) or version == 0,
        "missing": missing,
        "integrity": "ok" if integrity == ["ok"] else "; ".join(integrity[:5]),
        "case_ids": case_ids,
        "counts": counts,
    }


def _raw_user_tags(connection: sqlite3.Connection, tables: set[str]) -> int:
    """Live user tags; on a DB from before the tag table, the distinct tag names on marks."""
    if "case_tag" in tables:
        return _scalar(connection, "SELECT COUNT(*) FROM case_tag WHERE kind = 'user' AND deleted_at = ''")
    if "review_mark" not in tables:
        return 0
    names: set[str] = set()
    for (raw,) in connection.execute("SELECT tags_json FROM review_mark"):
        try:
            values = json.loads(raw or "[]")
        except json.JSONDecodeError:
            continue
        if isinstance(values, list):
            names.update(str(value).strip().casefold() for value in values if str(value).strip())
    return len(names)


def read_with_current_code(path: Path, case_ids: Iterable[str]) -> dict[str, int]:
    """The four counts through the current code's readers (applies the current schema: writes)."""
    database = CaseDatabase(path)
    database.initialize()
    intake = CaseIntake(connect=database.connect)
    counts = dict.fromkeys(COUNT_KEYS, 0)
    for case_id in case_ids:
        counts["review_marks"] += len(database.list_review_marks(case_id))
        counts["case_notes"] += int(intake.list_notes(case_id)["count"])
        with database.connect() as connection:
            counts["user_tags"] += sum(1 for tag in list_case_tags(connection, case_id) if tag.get("kind") == "user")
        counts["saved_searches"] += len(database.list_saved_searches(case_id))
    return counts


def check_case_db(
    path: Path,
    *,
    write: bool = False,
    backup_dir: Path | None = None,
    expected: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Open one case DB the way an upgrade does; ``write`` only on a copy (backup first)."""
    path = path.expanduser().resolve()
    result: dict[str, object] = {"database": str(path), "mode": "write" if write else "read-only", "problems": []}
    problems: list[str] = result["problems"]  # type: ignore[assignment]
    if not path.is_file():
        problems.append(f"케이스 DB 파일이 없습니다: {path}")
        return result
    hash_before = file_sha256(path)
    before = inspect_case_db(path)
    result["before"] = before
    if not before.get("readable"):
        problems.append(str(before["message"]))
        return result
    if before["unsupported"]:
        problems.append(str(before["message"]))
        result["unchanged"] = file_sha256(path) == hash_before
        return result
    if before["integrity"] != "ok":
        problems.append(f"케이스 DB 무결성 검사 실패: {before['integrity']}")
    counts_before: dict[str, int] = dict(before["counts"])  # type: ignore[arg-type]
    if not write:
        result["counts"] = counts_before
        result["unchanged"] = file_sha256(path) == hash_before
        if before["migration_needed"]:
            result["notice"] = "지금 프로그램으로 열면 스키마를 올립니다(백업 후 이관). 이 점검은 읽기만 했습니다."
        if not result["unchanged"]:
            problems.append("읽기 전용 점검 중 케이스 DB가 바뀌었습니다.")
        _compare_expected(result, counts_before, expected)
        return result
    if backup_dir is None:
        problems.append("--write에는 --backup-dir가 필요합니다(이관 전 백업).")
        return result
    result.update(_backup_then_open(path, backup_dir, hash_before, before, counts_before))
    problems.extend(result.pop("_problems"))  # type: ignore[arg-type]
    _compare_expected(result, dict(result.get("counts_after") or {}), expected)
    return result


def _backup_then_open(
    path: Path,
    backup_dir: Path,
    hash_before: str,
    before: Mapping[str, object],
    counts_before: Mapping[str, int],
) -> dict[str, object]:
    problems: list[str] = []
    out: dict[str, object] = {"_problems": problems}
    try:
        manifest = build_case_backup(database_path=path, output_dir=backup_dir)
    except BackupError as exc:
        problems.append(f"이관 전 백업을 만들지 못해 열지 않았습니다: {exc}")
        return out
    db_copies = [item for item in manifest.get("files", []) if isinstance(item, Mapping) and item.get("label") == "case_database"]
    backup_hashes = [str(dict(item.get("hashes") or {}).get("sha256") or "") for item in db_copies]
    out["backup"] = {
        "files": len(db_copies),
        "taken_before_open": bool(backup_hashes) and all(value == hash_before for value in backup_hashes),
        "migration_needed": bool(before["migration_needed"]),
        "missing_before": list(before["missing"]),  # type: ignore[arg-type]
    }
    if len(db_copies) != 1 or not out["backup"]["taken_before_open"]:  # type: ignore[index]
        problems.append("이관 전 백업 DB 파일이 1개가 아니거나 열기 전 해시와 다릅니다.")
    schema_errors: list[str] = []
    counts_after = dict.fromkeys(COUNT_KEYS, 0)
    try:
        counts_after = read_with_current_code(path, before["case_ids"])  # type: ignore[arg-type]
    except (CaseDatabaseError, sqlite3.Error, KeyError) as exc:
        schema_errors.append(str(exc))
    after = inspect_case_db(path)
    if after.get("integrity") != "ok":
        schema_errors.append(f"integrity: {after.get('integrity')}")
    if after.get("migration_needed"):
        schema_errors.append(f"열기 뒤에도 빠진 항목: {', '.join(after.get('missing') or [])}")  # type: ignore[arg-type]
    out["schema_errors"] = schema_errors
    out["counts_before"] = dict(counts_before)
    out["counts_after"] = counts_after
    out["diff"] = {key: int(counts_after[key]) - int(counts_before[key]) for key in COUNT_KEYS}
    if schema_errors:
        problems.append(f"스키마 오류 {len(schema_errors)}건: {schema_errors[0]}")
    changed = [f"{key} {value:+d}" for key, value in out["diff"].items() if value]  # type: ignore[union-attr]
    if changed:
        problems.append(f"지금 프로그램으로 연 뒤 건수가 달라졌습니다: {', '.join(changed)}")
    return out


def _compare_expected(result: dict[str, object], counts: Mapping[str, int], expected: Mapping[str, object] | None) -> None:
    if not expected:
        return
    problems: list[str] = result["problems"]  # type: ignore[assignment]
    for key in COUNT_KEYS:
        if key in expected and int(counts.get(key, -1)) != int(expected[key]):  # type: ignore[arg-type]
            problems.append(f"{key}: 기대 {expected[key]}건, 실제 {counts.get(key)}건")


# --- export audit --------------------------------------------------------------------------------


def iter_audit_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file() and ".audit" in item.name))
        elif path.is_file():
            files.append(path)
    return files


def check_audit(paths: Iterable[Path]) -> dict[str, object]:
    """Pre-chain / chained / broken export audit records (an R7 record is pre-chain, not broken)."""
    totals = {"records": 0, "pre_chain": 0, "chained": 0, "broken": 0, "unreadable": 0}
    broken: list[dict[str, object]] = []
    files = iter_audit_files(paths)
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            whole = json.loads(text)
        except json.JSONDecodeError:
            whole = None
        if isinstance(whole, dict):  # R7 sidecar: one indented JSON record per export
            totals["records"] += 1
            totals["chained" if CHAIN_FIELD in whole else "pre_chain"] += 1
            continue
        previous_line: str | None = None
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None
            if not isinstance(record, dict):
                totals["unreadable"] += 1
                broken.append({"file": str(path), "line": number, "reason": "JSON 한 줄로 읽을 수 없음"})
                previous_line = line
                continue
            totals["records"] += 1
            if CHAIN_FIELD not in record:
                totals["pre_chain"] += 1
            else:
                totals["chained"] += 1
                wanted = hashlib.sha256(previous_line.encode("utf-8")).hexdigest() if previous_line is not None else ""
                if str(record.get(CHAIN_FIELD) or "") != wanted:
                    totals["broken"] += 1
                    broken.append({"file": str(path), "line": number, "reason": "직전 줄 해시 불일치"})
            previous_line = line
    return {
        "files": len(files),
        **totals,
        "label": f"사슬 이전 {totals['pre_chain']}줄",
        "broken_lines": broken,
    }


# --- browser storage -----------------------------------------------------------------------------

_CONTRACT_ENTRY = re.compile(r'\{\s*key:\s*"([^"]+)",\s*area:\s*"(local|session)",\s*file:\s*"([^"]+)",?\s*\}')


def contract_storage_keys(frontend_src: Path) -> dict[str, str]:
    """Storage key -> owner file (relative to ``frontend/src``) from the UI contract."""
    contract = frontend_src / UI_CONTRACT
    if not contract.is_file():
        return {}
    return {key: owner for key, _area, owner in _CONTRACT_ENTRY.findall(contract.read_text(encoding="utf-8"))}


def check_storage_keys(entries: Sequence[Mapping[str, object]], frontend_src: Path = DEFAULT_FRONTEND_SRC) -> dict[str, object]:
    """Each R7 key is read by its owner module; an absent R7 value (``null``) reads as the default."""
    contract = contract_storage_keys(frontend_src)
    items: list[dict[str, object]] = []
    for entry in entries:
        key = str(entry.get("key") or "")
        value = entry.get("r7_value")
        owner = contract.get(key)
        item: dict[str, object] = {"item": entry.get("item"), "label": entry.get("label"), "key": key, "owner": owner}
        if value is None:
            item["read"] = True
            item["how"] = "R7 값 없음: 새 빌드 기본값" + (f" (키 계약 {owner})" if owner else "")
        elif owner is None:
            item["read"] = False
            item["how"] = f"UI 계약(frontend/src/{UI_CONTRACT.as_posix()})에 '{key}' 키가 없어 R7 값을 읽지 못합니다."
        else:
            owner_path = frontend_src / owner
            source = owner_path.read_text(encoding="utf-8") if owner_path.is_file() else ""
            allowed = entry.get("allowed")
            value_ok = not isinstance(allowed, list) or value in allowed
            item["read"] = f'"{key}"' in source and value_ok
            item["how"] = (
                f"{owner}이(가) 읽음"
                if item["read"]
                else f"{owner}에서 '{key}'를 읽는 코드를 찾지 못했거나 R7 값({value})을 받지 않습니다."
            )
        items.append(item)
    read = sum(1 for item in items if item["read"])
    return {"read": read, "total": len(items), "label": f"R7 저장 키 읽기 {read}/{len(items)}", "items": items}


# --- run folder ----------------------------------------------------------------------------------


def check_run_folder(folder: Path, *, evidence_root: str | None = None) -> dict[str, object]:
    """Read-only verdict on an old run folder (counts only, no write; proven by a stat snapshot)."""
    folder = folder.expanduser().resolve()
    problems: list[str] = []
    result: dict[str, object] = {"output_dir": str(folder), "problems": problems}
    summary_path = folder / SUMMARY_NAME
    if not summary_path.is_file():
        problems.append(f"결과 폴더에 실행 요약({SUMMARY_NAME})이 없어 가져올 수 없습니다: {folder}")
        return result
    before = stat_snapshot(folder)
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(f"실행 요약을 읽을 수 없습니다: {exc}")
        return result
    if not isinstance(summary, dict) or not isinstance(summary.get("outputs"), dict):
        problems.append("실행 요약에 outputs가 없어 지금 프로그램으로 가져올 수 없습니다(지원하지 않는 형식).")
        return result
    root = evidence_root or str(summary.get("root") or "")
    result["r7_summary"] = [key for key in R7_ABSENT_SUMMARY_KEYS if key not in summary]
    result["readonly_reason"] = output_inside_evidence_reason(folder, root)
    bookmarks = _case_json_bookmarks(folder / CASE_JSON_NAME, problems)
    json_candidates = sum(1 for item in bookmarks if is_report_candidate(item))
    db_counts: dict[str, object] = {}
    database = folder / CASE_DB_NAME
    if database.is_file():
        db_counts = inspect_case_db(database)
        if db_counts.get("unsupported") or not db_counts.get("readable"):
            problems.append(str(db_counts.get("message")))
    marks = dict(db_counts.get("counts") or {})  # type: ignore[arg-type]
    result["bookmarks"] = len(bookmarks)
    result["review_marks"] = int(marks.get("review_marks", 0))
    result["report_candidates"] = {
        "case_json": json_candidates,
        "case_db": int(marks.get("include_in_report_marks", 0)),
        "count": json_candidates + int(marks.get("include_in_report_marks", 0)),
    }
    result["case_db_migration_needed"] = bool(db_counts.get("migration_needed"))
    result["writes"] = 0 if stat_snapshot(folder) == before else 1
    if result["writes"]:
        problems.append("읽기 전용 점검 중 결과 폴더가 바뀌었습니다.")
    return result


def _case_json_bookmarks(path: Path, problems: list[str]) -> list[Mapping[str, object]]:
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(f"검토 목록 파일({CASE_JSON_NAME})을 읽을 수 없습니다: {exc}")
        return []
    items = payload.get("bookmarks") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        problems.append(f"검토 목록 파일({CASE_JSON_NAME})에 bookmarks 목록이 없습니다(지원하지 않는 형식).")
        return []
    return [item for item in items if isinstance(item, Mapping)]


# --- synthetic R7 state --------------------------------------------------------------------------


def load_fixture(path: Path = DEFAULT_FIXTURE) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_r7_case_db(fixture: Mapping[str, object], path: Path, *, before_tag_table: bool = False) -> Path:
    """A case DB with the R7 DDL of the fixture and its synthetic rows.

    ``before_tag_table`` drops ``case_tag`` / ``histogram_baseline`` / ``review_mark.tag_ids_json``
    (an older DB whose tags are strings only), so opening it runs a real migration."""
    path.parent.mkdir(parents=True, exist_ok=True)
    case = dict(fixture["case"])  # type: ignore[arg-type]
    case_id, stamp = str(case["case_id"]), str(case["created_at"])
    connection = sqlite3.connect(path)
    try:
        for statement in fixture["schema_sql"]:  # type: ignore[union-attr]
            connection.execute(str(statement))
        connection.execute(
            "INSERT OR REPLACE INTO schema_info (key, value) VALUES ('schema_version', ?)",
            (str(fixture.get("schema_version", SCHEMA_VERSION)),),
        )
        connection.execute(
            "INSERT INTO case_record (case_id, name, examiner, citation_prefix, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, case["name"], case.get("examiner", ""), case["citation_prefix"], stamp, stamp),
        )
        tag_ids: dict[str, int] = {}
        for index, name in enumerate(fixture["tags"]):  # type: ignore[arg-type]
            cursor = connection.execute(
                "INSERT INTO case_tag (case_id, name, kind, color_token, created_by, created_at, updated_at) "
                "VALUES (?, ?, 'user', ?, ?, ?, ?)",
                (case_id, name, f"tag-{index + 1}", case.get("examiner", ""), stamp, stamp),
            )
            tag_ids[str(name)] = int(cursor.lastrowid or 0)
        prefix = case["citation_prefix"]
        for index, mark in enumerate(fixture["review_marks"], start=1):  # type: ignore[arg-type]
            names = list(mark["tags"])
            connection.execute(
                "INSERT INTO review_mark (citation_id, case_id, target_type, target_id, status, tags_json, tag_ids_json, "
                "note, include_in_report, reviewer, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"{prefix}-RM-{index:04d}", case_id, mark["target_type"], mark["target_id"], mark["status"],
                    json.dumps(names, ensure_ascii=False), json.dumps([tag_ids[name] for name in names]),
                    mark["note"], int(bool(mark["include_in_report"])), case.get("examiner", ""), stamp, stamp,
                ),
            )
        for note in fixture["case_notes"]:  # type: ignore[union-attr]
            connection.execute(
                "INSERT INTO case_note (case_id, author, created_at, updated_at, text) VALUES (?, ?, ?, ?, ?)",
                (case_id, note["author"], stamp, stamp, note["text"]),
            )
        for index, search in enumerate(fixture["saved_searches"], start=1):  # type: ignore[arg-type]
            connection.execute(
                "INSERT INTO saved_search (citation_id, case_id, name, keywords_json, filters_json, created_by, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"{prefix}-SS-{index:04d}", case_id, search["name"], json.dumps(search["keywords"], ensure_ascii=False),
                    json.dumps(search["filters"], ensure_ascii=False), case.get("examiner", ""), stamp, stamp,
                ),
            )
        if before_tag_table:
            connection.execute("DROP TABLE case_tag")
            connection.execute("DROP TABLE histogram_baseline")
            connection.execute("ALTER TABLE review_mark DROP COLUMN tag_ids_json")
        connection.commit()
    finally:
        connection.close()
    return path


def write_r7_audit(fixture: Mapping[str, object], folder: Path) -> dict[str, Path]:
    """The fixture's export audit records as R7 sidecars (one JSON each) and as JSON lines."""
    folder.mkdir(parents=True, exist_ok=True)
    records = list(fixture["export_audit_records"])  # type: ignore[arg-type]
    sidecars = folder / "sidecars"
    sidecars.mkdir(exist_ok=True)
    for index, record in enumerate(records, start=1):
        (sidecars / f"export-{index}.audit.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    lines = folder / "exports.audit.jsonl"
    lines.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records), encoding="utf-8", newline="\n"
    )
    return {"sidecars": sidecars, "lines": lines}


def run_synthetic(work_dir: Path, fixture_path: Path = DEFAULT_FIXTURE) -> dict[str, object]:
    """Build the R7 fixture state under ``work_dir`` and run the case DB, audit and storage checks."""
    fixture = load_fixture(fixture_path)
    expected = dict(fixture["expected"])  # type: ignore[arg-type]
    database = build_r7_case_db(fixture, work_dir / "case" / CASE_DB_NAME)
    audit = write_r7_audit(fixture, work_dir / "audit")
    return {
        "fixture": str(fixture_path),
        "case_db": check_case_db(database, write=True, backup_dir=work_dir / "backup", expected=expected),
        "audit": {name: check_audit([path]) for name, path in audit.items()},
        "storage": check_storage_keys(fixture["browser_storage"]),  # type: ignore[arg-type]
    }


# --- CLI -----------------------------------------------------------------------------------------


def collect_problems(report: Mapping[str, object]) -> list[str]:
    found: list[str] = []
    for value in report.values():
        if isinstance(value, Mapping):
            found.extend(str(item) for item in value.get("problems", []) or [])
            if isinstance(value.get("broken"), int) and value["broken"]:
                found.append(f"감사 깨짐 {value['broken']}줄")
            if "read" in value and "total" in value and value["read"] != value["total"]:
                found.append(str(value.get("label")))
            found.extend(collect_problems({key: item for key, item in value.items() if isinstance(item, Mapping)}))
        elif isinstance(value, list):
            found.extend(collect_problems({str(index): item for index, item in enumerate(value) if isinstance(item, Mapping)}))
    return found


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case-db", action="append", default=[], type=Path, help="case DB to check (read-only unless --write)")
    parser.add_argument("--run", action="append", default=[], type=Path, help="old run output folder (read-only, counts only)")
    parser.add_argument("--evidence-root", help="evidence root of --run (default: the summary's root)")
    parser.add_argument("--audit", action="append", default=[], type=Path, help="export audit file or folder")
    parser.add_argument("--storage", action="store_true", help="check the fixture's R7 browser storage keys")
    parser.add_argument("--write", action="store_true", help="open --case-db with the current code (use on a copy)")
    parser.add_argument("--backup-dir", type=Path, help="case-backup output for --write (must be empty)")
    parser.add_argument("--synthetic", type=Path, metavar="WORK_DIR", help="build the R7 fixture state here and check it")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report: dict[str, object] = {}
    if args.synthetic is not None:
        report["synthetic"] = run_synthetic(args.synthetic.expanduser().resolve(), args.fixture)
    for index, path in enumerate(args.case_db):
        backup = args.backup_dir / f"db-{index}" if args.backup_dir is not None and len(args.case_db) > 1 else args.backup_dir
        report[f"case_db:{path}"] = check_case_db(path, write=args.write, backup_dir=backup)
    for path in args.run:
        report[f"run:{path}"] = check_run_folder(path, evidence_root=args.evidence_root)
    if args.audit:
        report["audit"] = check_audit(args.audit)
    if args.storage:
        report["storage"] = check_storage_keys(load_fixture(args.fixture)["browser_storage"])  # type: ignore[arg-type]
    if not report:
        build_parser().print_usage(sys.stderr)
        return 2
    problems = collect_problems(report)
    report["problems"] = problems
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    else:
        for name, section in report.items():
            if name != "problems":
                print(f"[{name}] {json.dumps(section, ensure_ascii=False, default=str)[:400]}")
        print("문제 없음" if not problems else "\n".join(f"문제: {item}" for item in problems))
    return 1 if problems else 0


if __name__ == "__main__":
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            _stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
