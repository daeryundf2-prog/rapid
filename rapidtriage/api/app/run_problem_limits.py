"""Engine and parser limits as Korean processing-problem items (R8 T-184, GAP-271/262/263/264).

The problems list (``run_problems``) used to say nothing about the engine's own limits: E01
extraction truncation and read errors, the ``$MFT`` / USN record caps and the ``$LogFile`` scan
window, and the collector caps whose hit is not recorded at all (T-165 inventory). This module
turns what the run already recorded into Korean limitation lines -- it never changes the engine:

* E01 -- the native extraction stats (``files``/``errors``/``truncated``/``deleted_*``/
  ``depth_skips``/``file_limit``) and the four-axis scope (T-023), split by axis (allocated walk vs
  deleted sweep).
* NTFS system files -- the ``windows-filesystem`` output's ``summary.artifact_type_counts`` (rows
  per type, bounded head read) and the size of ``$MFT`` / ``$LogFile`` / ``$UsnJrnl`` in the
  analysed root (``stat`` only).
* Undisclosed caps -- collectors that ran and carry a cap whose hit is never recorded.

Every cap number is read from the run (``file_limit``) or the collector constant at call time and
formatted here; no limit is written into a sentence by hand. The silent-failure detector's English
yield messages are replaced by Korean sentences built from the check id and its counts.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ...artifacts.windows.filesystem import (
    NATIVE_SCAN_LIMIT,
    NTFS_LOGFILE_SCAN_LIMIT,
    USN_RECORD_SCAN_LIMIT,
)
from ...core.submission import evidence_relative_roots
from .run_scope import _image_source, build_run_scope
from .run_steps_summary import classify_step_status

#: ``parse_mft_record_headers`` stops at this many records. The engine writes it as a literal
#: (``len(records) >= 5000``); ``tests/test_r8_run_problems.py`` pins this mirror to the T-165 caps
#: inventory so the two cannot drift.
MFT_RECORD_SCAN_LIMIT = 5000
#: ``_walk_ntfs_dir`` skips folders deeper than this (``depth > 64``); pinned like the MFT mirror.
E01_WALK_MAX_DEPTH = 64
MIB = 1024 * 1024
FILESYSTEM_OUTPUT = "artifacts_windows-filesystem"

LIMIT_REASONS = {
    "e01-extract-cap": "E01 추출 상한 도달 (전수 아님)",
    "e01-read-error": "E01 읽기 오류 (내용 미추출)",
    "e01-depth-cap": "E01 폴더 깊이 상한으로 건너뜀",
    "ntfs-parse-cap": "NTFS 기록 분석 상한 도달 ($MFT·USN·$LogFile)",
    "undisclosed-cap": "도달 여부가 기록되지 않는 상한",
}

#: (step kind, module, constant, unit, Korean label) -- GAP-272 caps whose hit is not recorded.
UNDISCLOSED_CAPS: tuple[tuple[str, str, str, str, str], ...] = (
    ("kakaotalk-windows", "rapidtriage.artifacts.kakaotalk_messages", "PICTURE_ROW_LIMIT", "count", "카카오톡 사진 행"),
    ("kakaotalk-windows", "rapidtriage.artifacts.kakaotalk_windows", "KAKAO_APP_DB_LIMIT", "count", "카카오톡 앱 DB 파일"),
    ("email", "rapidtriage.artifacts.email", "CONTAINER_SCAN_LIMIT", "bytes", "메일 컨테이너 검사 범위(파일당)"),
    ("cloud-export", "rapidtriage.artifacts.cloud", "CLOUD_ARCHIVE_PARSE_ENTRY_LIMIT", "count", "클라우드 보관 파일 안 분석 항목(보관 파일당)"),
    ("cloud-export", "rapidtriage.artifacts.cloud", "CLOUD_ARCHIVE_MBOX_MESSAGE_LIMIT", "count", "클라우드 보관 mbox 메시지(파일당)"),
    ("windows-execution", "rapidtriage.artifacts.windows.execution", "SHIMCACHE_MAX_ENTRIES", "count", "ShimCache 항목"),
    ("eventlog", "rapidtriage.artifacts.windows.eventlog", "ETL_SCAN_LIMIT", "bytes", "ETL 로그 검사 범위(파일당)"),
    ("memory-volatility", "rapidtriage.artifacts.memory", "MEMORY_DUMP_SCAN_LIMIT", "bytes", "메모리 덤프 검사 범위(파일당)"),
)

OutputSummary = Callable[[str], Mapping[str, Any]]


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def count_text(value: int) -> str:
    return f"{value:,}"


def size_text(value: int) -> str:
    """``8 MiB`` for whole MiB, else ``1.5 MiB`` / ``512바이트``."""
    if value >= MIB:
        mib = value / MIB
        return f"{mib:,.0f} MiB" if value % MIB == 0 else f"{mib:,.1f} MiB"
    return f"{value:,}바이트"


def cap_text(value: int, unit: str) -> str:
    return size_text(value) if unit == "bytes" else f"{count_text(value)}건"


def _item(reason_id: str, step: str, level: str, message: str) -> dict[str, Any]:
    return {"reason_id": reason_id, "source": "engine_limit", "step": step, "level": level, "message": message}


# --- E01 extraction -------------------------------------------------------------------------


def _raw_stats(summary: Mapping[str, Any], run_dir: Path | None) -> Mapping[str, Any]:
    source = _image_source(summary, run_dir)
    manifest = source.get("recovered_root_manifest") if isinstance(source, Mapping) else None
    stats = manifest.get("native_extraction_stats") if isinstance(manifest, Mapping) else None
    return stats if isinstance(stats, Mapping) else {}


def e01_limit_items(summary: Mapping[str, Any], run_dir: Path | None) -> list[dict[str, Any]]:
    """E01 truncation (per axis), read errors (per axis) and depth skips from the extraction stats."""
    stats = _raw_stats(summary, run_dir)
    if not stats:
        return []
    limit = _int(stats.get("file_limit"))
    truncated = _int(stats.get("truncated"))
    deleted_errors = _int(stats.get("deleted_read_errors"))
    attempted = _int(stats.get("deleted_files")) + deleted_errors
    allocated_errors = max(_int(stats.get("errors")) - deleted_errors, 0)
    items: list[dict[str, Any]] = []
    if truncated:
        limit_text = f"파일 {count_text(limit)}개" if limit else "파일 수 상한"
        if attempted:
            # The deleted sweep only writes while files < limit: the allocated walk finished.
            items.append(_item(
                "e01-extract-cap", "e01", "warning",
                f"E01 추출 상한({limit_text})에 닿아 삭제 파일 레코드 {count_text(truncated)}건은 내용 추출을 "
                "시도하지 않았습니다(삭제 영역 축). 할당 파일 순회는 상한 전에 끝난 것으로 추정합니다.",
            ))
        else:
            items.append(_item(
                "e01-extract-cap", "e01", "warning",
                f"E01 추출 상한({limit_text})에 닿아 파일 {count_text(truncated)}개를 추출하지 않았습니다. "
                "할당 파일 순회가 잘렸을 수 있고(할당 영역 축) 삭제 레코드는 시도하지 않았습니다(삭제 영역 축).",
            ))
    if allocated_errors:
        items.append(_item(
            "e01-read-error", "e01", "warning",
            f"E01 할당 영역 읽기 오류 {count_text(allocated_errors)}건 — 해당 파일·폴더의 내용은 추출되지 않았습니다"
            "(디렉터리 목록 실패 포함 가능).",
        ))
    if deleted_errors:
        items.append(_item(
            "e01-read-error", "e01", "warning",
            f"E01 삭제 레코드 읽기 오류 {count_text(deleted_errors)}건 — 레코드는 있으나 내용을 읽지 못했습니다(삭제 영역 축).",
        ))
    depth_skips = _int(stats.get("depth_skips"))
    if depth_skips:
        items.append(_item(
            "e01-depth-cap", "e01", "warning",
            f"E01 폴더 깊이 상한({count_text(E01_WALK_MAX_DEPTH)}단계)보다 깊은 폴더 {count_text(depth_skips)}개를 "
            "건너뛰었습니다(할당 영역 축).",
        ))
    return items


# --- NTFS system files ----------------------------------------------------------------------


def _system_file(roots: list[Path], *names: str) -> Path | None:
    for root in roots:
        for name in names:
            candidate = root.joinpath(*name.split("/"))
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                continue
    return None


def _size(path: Path | None) -> int:
    if path is None:
        return 0
    try:
        return path.stat().st_size
    except OSError:
        return 0


def ntfs_limit_items(
    summary: Mapping[str, Any],
    run_dir: Path | None,
    output_summary: OutputSummary,
) -> list[dict[str, Any]]:
    """``$MFT`` / USN record caps and the ``$LogFile`` scan window, when the filesystem collector ran."""
    outputs = summary.get("outputs")
    if not isinstance(outputs, Mapping) or FILESYSTEM_OUTPUT not in outputs:
        return []
    kind_summary = output_summary(FILESYSTEM_OUTPUT)
    counts = kind_summary.get("artifact_type_counts") if isinstance(kind_summary, Mapping) else None
    counts = counts if isinstance(counts, Mapping) else {}
    roots = evidence_relative_roots(summary)
    step = "artifacts-windows-filesystem"
    items: list[dict[str, Any]] = []

    window_text = size_text(NATIVE_SCAN_LIMIT)
    mft_rows = _int(counts.get("mft-record"))
    mft_size = _size(_system_file(roots, "$MFT"))
    scope_mft = build_run_scope(summary, run_dir).get("mft") if mft_rows else None
    mft_total = _int(scope_mft.get("records")) if isinstance(scope_mft, Mapping) else 0
    if mft_rows >= MFT_RECORD_SCAN_LIMIT:
        total = f"전체 {count_text(mft_total)}건 중 " if mft_total else ""
        window = f", 파일 앞 {window_text}만 읽음" if mft_size > NATIVE_SCAN_LIMIT else ""
        items.append(_item(
            "ntfs-parse-cap", step, "warning",
            f"$MFT 레코드 분석 상한({count_text(MFT_RECORD_SCAN_LIMIT)}건)에 닿아 {total}{count_text(mft_rows)}건만 "
            f"타임라인·파일 이력에 반영했습니다{window}. 나머지 레코드의 생성·삭제 이력은 없습니다.",
        ))
    elif mft_rows and mft_size > NATIVE_SCAN_LIMIT:
        # Only the read window applies: the record cap was not reached (review P2-16).
        items.append(_item(
            "ntfs-parse-cap", step, "warning",
            f"$MFT {size_text(mft_size)} 중 앞 {window_text}만 읽어 {count_text(mft_rows)}건을 타임라인·파일 이력에 "
            f"반영했습니다(레코드 상한 {count_text(MFT_RECORD_SCAN_LIMIT)}건에는 닿지 않음). "
            "뒤 구간 레코드의 생성·삭제 이력은 없습니다.",
        ))

    usn_rows = _int(counts.get("usn-record"))
    usn_size = _size(_system_file(roots, "$Extend/$UsnJrnl", "$Extend/$J", "$UsnJrnl", "$J"))
    if usn_rows >= USN_RECORD_SCAN_LIMIT:
        window = f", 파일 앞 {window_text}만 읽음" if usn_size > NATIVE_SCAN_LIMIT else ""
        items.append(_item(
            "ntfs-parse-cap", step, "warning",
            f"USN 저널 레코드 분석 상한({count_text(USN_RECORD_SCAN_LIMIT)}건)에 닿아 {count_text(usn_rows)}건만 "
            f"반영했습니다{window}. 이후 이름 변경·삭제 기록은 없습니다.",
        ))
    elif usn_size > NATIVE_SCAN_LIMIT:
        found = (
            f"{count_text(usn_rows)}건을 반영했습니다(레코드 상한 {count_text(USN_RECORD_SCAN_LIMIT)}건에는 닿지 않음)"
            if usn_rows
            else "반영한 레코드가 0건입니다(저널 앞부분은 비어 있는 경우가 많음)"
        )
        items.append(_item(
            "ntfs-parse-cap", step, "warning",
            f"USN 저널 {size_text(usn_size)} 중 앞 {window_text}만 읽어 {found}. "
            "뒤 구간의 이름 변경·삭제 기록은 확인하지 않았습니다(기록이 없다는 뜻이 아님).",
        ))

    logfile_size = _size(_system_file(roots, "$LogFile"))
    if logfile_size > NTFS_LOGFILE_SCAN_LIMIT:
        found = (
            "" if _int(counts.get("ntfs-logfile-transaction-candidate")) else " 그 구간에서 찾은 트랜잭션 후보는 0건입니다."
        )
        items.append(_item(
            "ntfs-parse-cap", step, "warning",
            f"$LogFile {size_text(logfile_size)} 중 앞 {size_text(NTFS_LOGFILE_SCAN_LIMIT)}만 훑었습니다(부분).{found} "
            "이후 구간의 트랜잭션 후보는 찾지 않았습니다.",
        ))
    return items


# --- undisclosed caps -----------------------------------------------------------------------


def _cap_value(module_name: str, constant: str) -> int:
    try:
        module = importlib.import_module(module_name)
    except Exception:  # an optional collector dependency may be missing; skip its cap
        return 0
    return _int(getattr(module, constant, 0))


def undisclosed_cap_items(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One notice per cap of a collector that ran but never records whether the cap was hit."""
    ran: set[str] = set()
    for step in summary.get("steps") or []:
        if not isinstance(step, Mapping):
            continue
        name = str(step.get("name") or "")
        if name.startswith("artifacts-") and classify_step_status(step.get("status")) in ("completed", "partial"):
            ran.add(name.removeprefix("artifacts-"))
    items: list[dict[str, Any]] = []
    for kind, module_name, constant, unit, label in UNDISCLOSED_CAPS:
        if kind not in ran:
            continue
        value = _cap_value(module_name, constant)
        if not value:
            continue
        items.append(_item(
            "undisclosed-cap", f"artifacts-{kind}", "notice",
            f"{label} 상한 {cap_text(value, unit)}: 이 상한에 닿았는지 결과에 기록되지 않아 전수인지 확인할 수 없습니다.",
        ))
    return items


def engine_limit_items(
    summary: Mapping[str, Any],
    run_dir: Path | None,
    output_summary: OutputSummary,
) -> list[dict[str, Any]]:
    return [
        *e01_limit_items(summary, run_dir),
        *ntfs_limit_items(summary, run_dir, output_summary),
        *undisclosed_cap_items(summary),
    ]


# --- Korean yield messages ------------------------------------------------------------------

_DETAIL_RE = re.compile(r"(\w+)=(\d+)")
_NO_ROWS_RE = re.compile(r"No ([\w-]+) artifact rows were collected\.?")


def _details(text: str) -> dict[str, int]:
    return {key: int(value) for key, value in _DETAIL_RE.findall(text)}


def korean_silent_message(check: Mapping[str, Any]) -> str:
    """Korean sentence for a silent-failure check (its English ``message`` is replaced)."""
    check_id = str(check.get("id") or "")
    detail = _details(str(check.get("detail") or ""))
    if check_id.startswith("artifact-yield-"):
        kind = check_id.removeprefix("artifact-yield-")
        return (
            f"{kind}: 대상 파일 {count_text(detail.get('target_count', 0))}개가 있으나 수집된 행 "
            f"{count_text(detail.get('artifact_count', 0))}건 — 분석기 오류·원본 경로·이미지 완전성을 확인해야 합니다."
        )
    if check_id.startswith("parser-errors-"):
        kind = check_id.removeprefix("parser-errors-")
        return (
            f"{kind}: 분석기가 격리된 오류 {count_text(detail.get('parser_error_count', 0))}건을 보고했습니다 — "
            "보고서에 쓰기 전에 분석기 오류 목록을 검토해야 합니다."
        )
    if check_id == "files-scanned":
        return "검사한 파일이 0개입니다 — 증거 루트·마운트·입력 방식이 잘못됐을 수 있습니다."
    if check_id == "documents-indexed":
        return (
            f"파일 {count_text(detail.get('scanned_file_count', 0))}개를 검사했으나 색인한 지원 문서가 0건입니다 — "
            "문서 확장자와 추출 의존성을 확인해야 합니다."
        )
    if check_id == "keyword-search-yield":
        return (
            f"문서 {count_text(detail.get('document_candidate_count', 0))}건을 색인했으나 설정한 검색어와 "
            "일치한 문서가 0건입니다."
        )
    if check_id == "timeline-yield":
        return (
            f"후보 파일 {count_text(detail.get('file_candidate_count', 0))}건·일치 문서 "
            f"{count_text(detail.get('document_match_count', 0))}건이 있으나 타임라인 이벤트가 0건입니다."
        )
    if check_id.endswith("-yield") and "selected_count" in detail:
        name = check_id.removesuffix("-yield")
        return (
            f"{name}: 선택한 증거 {count_text(detail['selected_count'])}건 중 추출 "
            f"{count_text(detail.get('extracted_count', 0))}건(건너뜀 {count_text(detail.get('skipped_count', 0))}건) — "
            "건너뛴 사유를 확인해야 합니다."
        )
    message = str(check.get("message") or "")
    return f"{check_id}: {message}" if message else check_id


def korean_warning_message(message: str) -> str:
    """Known English run warnings in Korean; everything else unchanged."""
    match = _NO_ROWS_RE.fullmatch(message.strip())
    if match:
        return f"{match.group(1)}: 수집된 행 없음"
    if message.strip() == "No manifest providers were collected.":
        return "수집된 매니페스트 제공자 없음"
    return message
