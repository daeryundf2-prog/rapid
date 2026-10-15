"""Kind runners for the analysis workbench (plan P1 §3.2).

Every runner calls an existing core function and only adapts its output to
``<kind>-row`` records, progress units and cancellation checks:

* ``carve`` -- ``core.carving`` (signature selection + ``_scan_source``, the
  same per-file scan ``run_bounded_carving`` uses), one source file per unit;
* ``vsc-discover`` / ``vsc-compare`` / ``vsc-extract`` -- ``core.vsc``;
* ``ntfs-meta`` -- ``core.ntfs_metadata.extract_ntfs_metadata`` (Sleuth Kit)
  and the native ``parse_mft_record_headers`` / ``parse_usn_record_scan``
  parsers plus ``resolve_mft_bounded_path`` for full paths;
* ``ocr-batch`` -- the ``pytesseract`` + ``imread_unicode_safe`` engine the
  search OCR path uses; results are reused by the image viewer
  (``find_ocr_result``);
* ``memory-import`` -- ``MemoryVolatilityProvider.collect`` on a directory;
* ``cross-case`` -- ``core.cross_case.correlate_case_databases`` over run
  case databases;
* ``search-index`` -- ``core.search_index.build.build_search_index`` (the run's
  ``rapidtriage-search.db``; full or incremental per analysis).
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import unicodedata
from array import array
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ...core.carving import (
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_CARVE_BYTES,
    DEFAULT_MAX_SCAN_BYTES,
    SIGNATURE_KINDS,
    STATUS_REJECTED,
    CarvingError,
    _scan_source,
    _select_signatures,
    normalize_extensions,
)
from ...core.files import RUN_OUTPUT_DIR_PREFIX
from ...core.jobs import is_relative_to
from ...core.link_safe_walk import WalkStats, iter_files_no_links
from .analyses import (
    ANALYSIS_ROOTS_ENV,
    ANALYSIS_RUNNER,
    ROWS_FILE_NAME,
    AnalysisContext,
    AnalysisFailure,
    AnalysisSpec,
    RunScope,
    _root_forms,
    _under_any,
    analyses_root,
    extra_analysis_roots,
    run_scope,
)
from .helpers import allowed_source_roots
from .jsonl_records import iter_artifact_records, iter_jsonl_records

GIB = 1024 * 1024 * 1024
# Directory walks check for cancellation every this many walked entries.
CANCEL_CHECK_EVERY = 500


def run_output_pruner(output_dir: Path) -> Callable[[Path], bool]:
    """``prune_dir`` for evidence walks: this run's output dir and any ``rapidtriage-run*`` folder.

    Same rule as ``core.files.iter_evidence_paths`` (the tool's own outputs are
    never re-read as evidence), applied per directory so pruned subtrees are
    never listed.
    """
    own = os.path.normcase(os.path.abspath(output_dir))

    def prune(path: Path) -> bool:
        return path.name.startswith(RUN_OUTPUT_DIR_PREFIX) or os.path.normcase(os.path.abspath(path)) == own

    return prune


def iter_evidence_files(
    ctx: AnalysisContext, root: Path, stats: WalkStats
) -> Iterator[Path]:
    """Files under ``root`` for a kind runner: links never followed, run outputs pruned, cancellable."""
    if root.is_file():
        yield root
        return
    yield from iter_files_no_links(
        root,
        check_cancel=ctx.check_cancel,
        every=CANCEL_CHECK_EVERY,
        prune_dir=run_output_pruner(ctx.scope.output_dir.resolve()),
        stats=stats,
    )


class _Options(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _row_path_key(value: object) -> str:
    """NFC + casefold path key with ``/`` separators (no leading separator)."""
    text = unicodedata.normalize("NFC", str(value or "")).replace("\\", "/").casefold()
    return text.strip("/")


def _row_path_keys(value: object) -> list[str]:
    """``_row_path_key`` of ``value`` as given and, for an absolute path, of its resolved form.

    Rows record paths as their walk saw them (resolved roots), older rows and
    callers may spell the same file through a symlinked directory or a
    Windows 8.3 short name: both spellings must find the same stored result.
    """
    keys = [_row_path_key(value)]
    text = str(value or "")
    if text and os.path.isabs(text):
        try:
            resolved = _row_path_key(Path(text).resolve())
        except (OSError, RuntimeError, ValueError):
            resolved = None
        if resolved is not None and resolved not in keys:
            keys.append(resolved)
    return keys


# --- carve ----------------------------------------------------------------------


class CarveOptions(_Options):
    ext: list[str] | None = None
    kinds: list[str] | None = None
    max_scan_bytes: int = Field(DEFAULT_MAX_SCAN_BYTES, ge=1, le=16 * GIB)
    max_carve_bytes: int = Field(DEFAULT_MAX_CARVE_BYTES, ge=1, le=GIB)
    max_candidates: int = Field(DEFAULT_MAX_CANDIDATES, ge=1, le=100_000)
    extract: bool = False
    # ``false-positive-rejected`` candidates (length 0) never count toward
    # ``max_candidates``; they are only counted unless this asks for rows too.
    include_rejected: bool = False

    @field_validator("ext", mode="before")
    @classmethod
    def _split_ext(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()] or None
        return value

    @field_validator("kinds")
    @classmethod
    def _known_kinds(cls, value: list[str] | None) -> list[str] | None:
        if not value:
            return None
        wanted = [str(item).strip().lower() for item in value if str(item).strip()]
        unknown = sorted(set(wanted) - set(SIGNATURE_KINDS))
        if unknown:
            raise ValueError(f"알 수 없는 시그니처 종류입니다: {', '.join(unknown)} (가능: {', '.join(SIGNATURE_KINDS)})")
        return wanted or None


def prepare_carve(options: CarveOptions, scope: RunScope) -> dict[str, object]:
    payload = options.model_dump()
    if options.ext:
        payload["ext"] = sorted(normalize_extensions(options.ext))
    return payload


def run_carve(ctx: AnalysisContext) -> None:
    options: CarveOptions = ctx.options  # type: ignore[assignment]
    root = ctx.scope.scan_root()
    if not root.exists():
        raise AnalysisFailure(f"스캔 루트가 없습니다: {root}")
    try:
        signatures = _select_signatures(options.kinds)
    except CarvingError as exc:
        raise AnalysisFailure(str(exc)) from exc
    allowed = normalize_extensions(options.ext)
    ctx.set_message("소스 파일 목록 작성 중")
    # Sources are spooled to disk (one JSON string per line) instead of held in
    # memory: the walk order (names sorted per directory) is deterministic.
    walk_stats = WalkStats()
    spool = ctx.directory / "carve-sources.staging.jsonl"
    source_count = 0
    with spool.open("w", encoding="utf-8") as out:
        for path in iter_evidence_files(ctx, root, walk_stats):
            if allowed and path.suffix.lower() not in allowed:
                continue
            out.write(json.dumps(str(path), ensure_ascii=False) + "\n")
            source_count += 1
    try:
        _carve_sources(ctx, options, root, signatures, spool, source_count, walk_stats)
    finally:
        spool.unlink(missing_ok=True)


def _iter_spooled(spool: Path) -> Iterator[Path]:
    with spool.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield Path(json.loads(line))


def _carve_sources(
    ctx: AnalysisContext,
    options: CarveOptions,
    root: Path,
    signatures,
    spool: Path,
    source_count: int,
    walk_stats: WalkStats,
) -> None:
    carved_dir = ctx.directory / "carved"
    if options.extract:
        carved_dir.mkdir(parents=True, exist_ok=True)
    ctx.set_total(source_count, unit="파일", message=f"소스 파일 {source_count}개")
    candidates = 0
    rejected = 0
    rejected_rows = 0
    scanned_files = 0
    scanned_bytes = 0
    kind_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    skipped: list[dict[str, object]] = []
    cap_reached = False

    def emit(entry: dict[str, object]) -> None:
        # Rows are written as each candidate is built, so a cancel inside a
        # large file keeps the candidates found before it.
        nonlocal candidates, rejected, rejected_rows
        status = str(entry.get("status") or "")
        if status == STATUS_REJECTED:
            rejected += 1
            if not options.include_rejected or rejected_rows >= options.max_candidates:
                return
            rejected_rows += 1
        else:
            candidates += 1
            kind_counts[str(entry.get("kind"))] += 1
        status_counts[status] += 1
        notes = status
        if entry.get("rejected_reason"):
            notes = f"{status}: {entry['rejected_reason']}"
        ctx.write_row(
            ctx.row(
                {
                    "signature_kind": entry.get("kind"),
                    "source_path": entry.get("source_path"),
                    "offset": entry.get("offset"),
                    "offset_hex": f"0x{int(entry.get('offset') or 0):x}",
                    "end_offset": entry.get("end_offset"),
                    "length": entry.get("size"),
                    "sha256": entry.get("sha256"),
                    "extracted_path": entry.get("extracted_path"),
                    "confidence": entry.get("confidence"),
                    "status": status,
                    "extension": entry.get("extension"),
                    "notes": notes,
                },
                path=str(entry.get("source_path") or ""),
            )
        )

    for path in _iter_spooled(spool):
        ctx.check_cancel()
        if candidates >= options.max_candidates:
            cap_reached = True
            break
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"stat-error:{exc}"})
            ctx.advance()
            continue
        if size <= 0:
            ctx.advance()
            continue
        try:
            # Cancellation is checked per scan chunk (8 MB) and per candidate,
            # not only per file: a 256 MB source no longer delays a cancel.
            _entries, scanned = _scan_source(
                path,
                read_limit=min(size, options.max_scan_bytes),
                source_root=root,
                output_dir=carved_dir,
                extract=options.extract,
                max_carve_bytes=options.max_carve_bytes,
                remaining=options.max_candidates - candidates,
                signatures=signatures,
                check_cancel=ctx.check_cancel,
                on_entry=emit,
                count_rejected=False,
            )
        except OSError as exc:
            skipped.append({"path": str(path), "reason": f"read-error:{exc}"})
            ctx.advance()
            continue
        scanned_files += 1
        scanned_bytes += scanned
        ctx.advance(message=f"{path.name} · 후보 {candidates}건")
    if cap_reached or candidates >= options.max_candidates:
        # Remaining sources are skipped by the cap: the job is done, not 2% done.
        done = ctx.progress_done()
        ctx.set_total(done, message=f"후보 상한 {options.max_candidates}건 도달 · 파일 {done}/{source_count}개 확인")
    ctx.summary.update(
        {
            "source_root": str(root),
            "source_file_count": source_count,
            # Symlinks/junctions are never followed (evidence integrity); counted here.
            "skipped_link_count": walk_stats.skipped_links,
            "pruned_output_dir_count": walk_stats.pruned_dirs,
            "scanned_file_count": scanned_files,
            "scanned_byte_count": scanned_bytes,
            "candidate_count": candidates,
            # Structurally rejected header matches: never counted toward the cap.
            "rejected_count": rejected,
            "rejected_row_count": rejected_rows,
            "candidate_cap_reached": cap_reached or candidates >= options.max_candidates,
            "kind_counts": dict(kind_counts),
            "status_counts": dict(status_counts),
            "skipped_count": len(skipped),
            "skipped": skipped[:200],
            "extract_dir": str(carved_dir) if options.extract else None,
            "limitation": "시그니처 카빙은 선별 보조 수단입니다. 후보는 헥스 뷰어에서 offset을 확인한 뒤 인용하세요.",
        }
    )


# --- VSC ------------------------------------------------------------------------


class VscDiscoverOptions(_Options):
    # The scan root's parent is searched at most one level deep (plan §3.2).
    max_depth: int = Field(1, ge=0, le=1)


def run_vsc_discover(ctx: AnalysisContext) -> None:
    from ...core.vsc import VscCompareError, discover_vsc_snapshot_roots

    options: VscDiscoverOptions = ctx.options  # type: ignore[assignment]
    root = ctx.scope.scan_root()
    ctx.set_total(1, unit="디렉터리", message=f"{root} 주변 스냅샷 폴더 탐색 중")
    try:
        # Outside-root search roots/candidates are skipped before any filesystem call.
        payload = discover_vsc_snapshot_roots(
            root,
            max_depth=options.max_depth,
            allowed_roots=ctx.scope.input_roots(),
            check_cancel=ctx.check_cancel,
            skip_links=True,
            exclude_dirs=[ctx.scope.output_dir],
        )
    except VscCompareError as exc:
        raise AnalysisFailure(f"VSC 탐색 실패: {exc}") from exc
    excluded = _confine_discovery(payload, ctx.scope)
    _write_json(ctx.directory / "vsc-discovery.json", payload)
    for snapshot in payload.get("snapshots") or []:
        ctx.write_row(
            ctx.row(
                {
                    "snapshot_root": snapshot.get("path"),
                    "label": snapshot.get("label"),
                    "score": snapshot.get("score"),
                    "reason": snapshot.get("reason"),
                    "file_count_bounded": snapshot.get("file_count_sample"),
                    "exists": snapshot.get("exists"),
                }
            )
        )
    ctx.advance()
    ctx.summary.update(
        {
            "current_root": payload.get("current_root"),
            "search_roots": payload.get("search_roots"),
            "snapshot_count": payload.get("snapshot_count"),
            "excluded_outside_roots": excluded,
            "limitation": payload.get("operator_note"),
        }
    )


def _confine_discovery(payload: dict[str, object], scope: RunScope) -> int:
    """Drop outside-root snapshots/search roots from a discovery payload (in place); return the excluded count.

    The core walk already skips them; this keeps every written payload free of
    paths compare/extract would refuse even if a candidate resolved elsewhere.
    """
    from ...core.vsc import is_run_output_dir, stable_json_hash

    excluded = int(payload.get("excluded_outside_roots") or 0)
    snapshots = [row for row in payload.get("snapshots") or [] if isinstance(row, Mapping)]
    own_output = [scope.output_dir.resolve()]
    # The run's own outputs (e.g. analyses/<id>/extract copies named after a
    # snapshot) are never offered as snapshots; they are not "outside" either.
    snapshots = [row for row in snapshots if not is_run_output_dir(Path(str(row.get("path") or "")), own_output)]
    kept = [row for row in snapshots if scope.allows_input(str(row.get("path") or ""))]
    excluded += len(snapshots) - len(kept)
    payload["snapshots"] = kept
    payload["snapshot_count"] = len(kept)
    payload["search_roots"] = [str(path) for path in payload.get("search_roots") or [] if scope.allows_input(str(path))]
    payload["excluded_outside_roots"] = excluded
    if "manifest_sha256" in payload:
        payload["manifest_sha256"] = stable_json_hash(payload)
    return excluded


def resolve_snapshot_root(raw: str, scope: RunScope) -> Path:
    """A snapshot directory under the allowed roots (discover results get no exemption)."""
    candidate = scope.resolve_input_path(str(raw), label="스냅샷 루트")
    if not candidate.is_dir():
        raise HTTPException(status_code=400, detail=f"스냅샷 루트가 디렉터리가 아닙니다: {candidate}")
    return candidate


class VscCompareOptions(_Options):
    snapshot_root: str = Field(..., min_length=1)
    hash: bool = False
    case_sensitive: bool = False
    max_records: int = Field(10_000, ge=1, le=1_000_000)


def prepare_vsc_compare(options: VscCompareOptions, scope: RunScope) -> dict[str, object]:
    payload = options.model_dump()
    payload["snapshot_root"] = str(resolve_snapshot_root(options.snapshot_root, scope))
    return payload


def run_vsc_compare(ctx: AnalysisContext) -> None:
    from ...core.vsc import VscCompareError, compare_vsc_snapshots

    options: VscCompareOptions = ctx.options  # type: ignore[assignment]
    root = ctx.scope.scan_root()
    snapshot = Path(options.snapshot_root)
    ctx.set_total(None, unit="파일 인덱스 항목", message="현재 루트와 스냅샷 파일 인덱스 작성 중")
    try:
        payload = compare_vsc_snapshots(
            root,
            [snapshot],
            compute_hashes=options.hash,
            case_sensitive=options.case_sensitive,
            max_records=options.max_records,
            allowed_roots=ctx.scope.input_roots(),
            check_cancel=ctx.check_cancel,
            skip_links=True,
            exclude_dirs=[ctx.scope.output_dir],
        )
    except VscCompareError as exc:
        raise AnalysisFailure(f"VSC 비교 실패: {exc}") from exc
    if isinstance(payload.get("snapshot_discovery"), dict):
        _confine_discovery(payload["snapshot_discovery"], ctx.scope)
    comparisons = payload.get("comparisons") or []
    records = [record for comparison in comparisons for record in comparison.get("records") or []]
    ctx.set_total(len(records), message=f"변경 {len(records)}건 기록 중")
    for record in records:
        ctx.check_cancel()
        status = str(record.get("status") or "")
        side = record.get("current") if status == "added" else record.get("snapshot")
        side = side if isinstance(side, Mapping) else {}
        ctx.write_row(
            ctx.row(
                {
                    "status": status,
                    "path": record.get("relative_path"),
                    "size": side.get("size"),
                    "sha256": side.get("sha256"),
                    "modified_at": side.get("modified_at"),
                    "snapshot_root": str(snapshot),
                    "source_path": side.get("path"),
                },
                path=str(side.get("path") or ""),
            )
        )
        ctx.advance()
    for comparison in comparisons:
        comparison["records"] = []  # rows.jsonl holds them
    _write_json(ctx.directory / "vsc-compare.json", payload)
    # Counts are exact over every change; only the row listing is capped
    # (deleted -> modified -> added), and a cap hit is stated in Korean.
    change_count = sum(int((c.get("summary") or {}).get("change_count") or 0) for c in comparisons)
    truncated = any((c.get("summary") or {}).get("truncated") for c in comparisons)
    ctx.summary.update(
        {
            "current_root": payload.get("current_root"),
            "snapshot_root": str(snapshot),
            **(payload.get("summary") or {}),
            "change_count": change_count,
            "record_count": len(records),
            "truncated": truncated,
            "truncated_reason": (
                f"변경 {change_count:,}건 중 {len(records):,}건만 행으로 기록했습니다(최대 기록 수 {options.max_records:,}건). "
                "삭제·수정 항목을 먼저 기록하고 추가 항목은 뒤에 둡니다. 건수(deleted/modified/added)는 전체 기준입니다. "
                "모든 행을 보려면 최대 기록 수를 늘리세요."
                if truncated
                else None
            ),
        }
    )


class VscExtractOptions(_Options):
    snapshot_root: str = Field(..., min_length=1)
    status: list[Literal["deleted", "modified", "added"]] = Field(default_factory=lambda: ["deleted", "modified"], min_length=1)
    max_file_count: int = Field(1000, ge=1, le=100_000)
    max_total_bytes: int = Field(2 * GIB, ge=1, le=256 * GIB)
    overwrite: bool = False
    output_dir: str | None = None


# Skipped items listed as rows (the per-reason counts stay exact).
VSC_EXTRACT_MAX_SKIPPED_ROWS = 10_000

EVIDENCE_OUTPUT_MESSAGE = "추출 출력 경로가 증거 경로({what}) 안에 있어 쓸 수 없습니다: {path}"


def reject_output_in_evidence(destination: Path, snapshot: Path, scope: RunScope) -> None:
    """403 when an extract destination lies in evidence: the snapshot, scan/source/stage/input roots.

    A destination under the run output directory is allowed when the evidence
    root merely contains that directory (output kept next to the evidence),
    never when the evidence root sits inside it (a stage dir) or is the snapshot.
    """
    output_forms = _root_forms([scope.output_dir, scope.summary.get("output_dir")])
    in_output = _under_any(destination, output_forms)
    source = scope.source
    evidence_values = [scope.summary.get(key) for key in ("root", "scan_scope_root")]
    evidence_values += [source.get(key) for key in ("analysis_root", "stage_dir", "source_path")]
    evidence_values += allowed_source_roots(scope.summary)
    # Operator input roots (RAPIDTRIAGE_ANALYSIS_ROOTS) are evidence too.
    evidence_values += extra_analysis_roots(ANALYSIS_ROOTS_ENV)
    evidence = [root for root in _root_forms(evidence_values) if root not in output_forms]
    for root in _root_forms([snapshot]):
        if _under_any(destination, [root]):
            raise HTTPException(status_code=403, detail=EVIDENCE_OUTPUT_MESSAGE.format(what="스냅샷", path=destination))
    for root in evidence:
        if not _under_any(destination, [root]):
            continue
        if in_output and not _under_any(root, output_forms):
            continue  # evidence root holds the run output dir; the destination is inside the latter
        raise HTTPException(
            status_code=403, detail=EVIDENCE_OUTPUT_MESSAGE.format(what="스캔·소스·스테이지·입력 루트", path=destination)
        )


def prepare_vsc_extract(options: VscExtractOptions, scope: RunScope) -> dict[str, object]:
    payload = options.model_dump()
    snapshot = resolve_snapshot_root(options.snapshot_root, scope)
    payload["snapshot_root"] = str(snapshot)
    if options.output_dir:
        destination = scope.resolve_output_path(options.output_dir, label="추출 출력")
        payload["output_dir"] = str(destination)
    else:
        destination = analyses_root(scope.output_dir).resolve()  # default: analyses/<id>/extract
    reject_output_in_evidence(destination, snapshot, scope)
    return payload


def run_vsc_extract(ctx: AnalysisContext) -> None:
    from ...core.vsc import VscCompareError, extract_vsc_changes

    options: VscExtractOptions = ctx.options  # type: ignore[assignment]
    root = ctx.scope.scan_root()
    destination = Path(options.output_dir) if options.output_dir else ctx.directory / "extract"
    ctx.set_total(None, unit="파일", message="스냅샷 변경 파일 복사 중")
    try:
        manifest = extract_vsc_changes(
            root,
            [Path(options.snapshot_root)],
            destination,
            statuses=options.status,
            max_file_count=options.max_file_count,
            max_total_bytes=options.max_total_bytes,
            overwrite=options.overwrite,
            allowed_roots=ctx.scope.input_roots(),
            check_cancel=ctx.check_cancel,
            skip_links=True,
            exclude_dirs=[ctx.scope.output_dir],
            # Select from the complete change set of the chosen statuses (no
            # listing cap); copying is bounded by max_file_count/max_total_bytes.
            max_records=0,
            max_skipped_records=VSC_EXTRACT_MAX_SKIPPED_ROWS,
        )
    except VscCompareError as exc:
        raise AnalysisFailure(f"VSC 추출 실패: {exc}") from exc
    copied = manifest.get("copied") or []
    skipped = manifest.get("skipped") or []
    ctx.set_total(len(copied) + len(skipped))
    for item in copied:
        ctx.write_row(
            ctx.row(
                {
                    "path": item.get("relative_path"),
                    "destination": item.get("destination_path"),
                    "size": item.get("size"),
                    "sha256": item.get("destination_sha256"),
                    "source_sha256": item.get("source_sha256"),
                    "source_path": item.get("source_path"),
                    "status": item.get("status"),
                    "modified_at": item.get("modified_at"),
                    "skipped_reason": None,
                },
                path=str(item.get("destination_path") or ""),
            )
        )
        ctx.advance()
    for item in skipped:
        ctx.write_row(
            ctx.row(
                {
                    "path": item.get("relative_path"),
                    "destination": item.get("destination_path"),
                    "status": item.get("status"),
                    "skipped_reason": item.get("reason"),
                }
            )
        )
        ctx.advance()
    _write_json(ctx.directory / "rapidtriage-vsc-extract.json", manifest)
    summary = manifest.get("summary") if isinstance(manifest.get("summary"), Mapping) else {}
    ctx.summary.update({"evidence_root": manifest.get("evidence_root"), **summary})
    ctx.summary["comparison_summary"] = manifest.get("comparison_summary")
    ctx.summary.update(_extract_truncation(summary, options))


def _extract_truncation(summary: Mapping[str, object], options: VscExtractOptions) -> dict[str, object]:
    """``truncated`` + Korean ``truncated_reason`` when selected changes were not all copied by a cap."""
    reasons = summary.get("skipped_reason_counts") if isinstance(summary.get("skipped_reason_counts"), Mapping) else {}
    by_count = int(reasons.get("max-file-count") or 0)
    by_bytes = int(reasons.get("max-total-bytes") or 0)
    skipped = int(summary.get("skipped_count") or 0)
    listed = int(summary.get("skipped_listed_count") or 0)
    parts: list[str] = []
    if by_count:
        parts.append(f"최대 파일 수({options.max_file_count:,}개) 초과로 {by_count:,}건")
    if by_bytes:
        parts.append(f"최대 총 바이트({options.max_total_bytes / GIB:,.2f} GB) 초과로 {by_bytes:,}건")
    reason = None
    if parts:
        reason = f"선택한 변경 {int(summary.get('selected_count') or 0):,}건 중 " + ", ".join(parts) + "을 복사하지 않았습니다. 상한을 늘려 다시 실행하세요."
    if listed < skipped:
        note = f"건너뛴 항목 {skipped:,}건 중 {listed:,}건만 행으로 기록했습니다(사유별 건수는 summary.skipped_reason_counts)."
        reason = f"{reason} {note}" if reason else note
    return {"truncated": bool(parts) or listed < skipped, "truncated_reason": reason}


# --- NTFS metadata ------------------------------------------------------------------

# Fallback FILE record size when the MFT header does not state one.
MFT_RECORD_SIZE = 1024
MFT_RECORD_SIZES = (1024, 2048, 4096)
MFT_RECORD_SIZE_PROBE_BYTES = 64 * 1024
# parse_mft_record_headers stops after 5000 "FILE" hits (aligned or not), so a
# chunk keeps headroom for in-content "FILE" strings.
MFT_CHUNK_RECORDS = 2048
# Path reconstruction keeps every record's (sequence, name, parent) in memory:
# about 45 bytes + the UTF-8 name per record in ``_NodeView``'s arrays, i.e.
# roughly 500 MB at this many records. A larger $MFT is extracted but not
# parsed (``summary.parse_status = "too_large"``).
MFT_MAX_PARSE_RECORDS = 8_000_000
USN_WINDOW_BYTES = 16 * 1024 * 1024
USN_WINDOW_OVERLAP = 65536
USN_RECORD_LIMIT_PER_WINDOW = 10_000_000


def _default_ntfs_extractor(*args, **kwargs):
    from ...core.ntfs_metadata import extract_ntfs_metadata

    return extract_ntfs_metadata(*args, **kwargs)


# Tests replace this hook to mock the Sleuth Kit runner.
NTFS_EXTRACTOR = _default_ntfs_extractor


class NtfsMetaOptions(_Options):
    partition_start_sector: int | None = Field(None, ge=0)
    full_journal: bool = False
    parse: bool = True
    image_path: str | None = None
    # ``image``: extract $MFT/$UsnJrnl with Sleuth Kit; ``mft``: ``image_path``
    # is an already-extracted raw $MFT parsed directly (no Sleuth Kit). Omitted
    # (``None``): detected -- a file whose offset 0 holds a FILE record header
    # with a 1024/2048/4096 allocated size that divides the file size is a $MFT.
    # The stored options always carry the resolved value.
    source: Literal["image", "mft"] | None = None


def raw_mft_record_size(path: Path) -> int | None:
    """Record size when ``path`` looks like a raw $MFT (FILE header at offset 0, size a multiple of it)."""
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(0x20)
    except OSError:
        return None
    if len(head) < 0x20 or head[:4] != b"FILE":
        return None
    allocated = int.from_bytes(head[0x1C:0x20], "little")
    if allocated not in MFT_RECORD_SIZES or size <= 0 or size % allocated:
        return None
    return allocated


def prepare_ntfs_meta(options: NtfsMetaOptions, scope: RunScope) -> dict[str, object]:
    payload = options.model_dump()
    if options.image_path:
        image = scope.resolve_input_path(options.image_path, label="디스크 이미지")
        if not image.is_file():
            raise HTTPException(
                status_code=400,
                detail=f"지정한 image_path가 파일이 아닙니다: {image}. 디스크 이미지(E01/raw) 또는 추출한 $MFT 파일을 지정하세요",
            )
    else:
        image = scope.source_path()
        if image is None or not image.is_file():
            raise HTTPException(
                status_code=400,
                detail=(
                    "NTFS 메타 분석에는 디스크 이미지(E01/raw) 또는 추출한 $MFT 파일이 필요합니다. "
                    f"이 런의 소스는 파일이 아닙니다: {image}. image_path 옵션으로 파일을 지정하세요"
                ),
            )
    detected = raw_mft_record_size(image) is not None
    if options.source == "mft" and not detected:
        raise HTTPException(
            status_code=400,
            detail=(
                f"$MFT 파일로 읽을 수 없습니다: {image}. 오프셋 0에 FILE 레코드 서명이 없거나 "
                "파일 크기가 레코드 크기(1024/2048/4096바이트)의 배수가 아닙니다"
            ),
        )
    payload["image_path"] = str(image)
    payload["source"] = options.source or ("mft" if detected else "image")
    return payload


_MISSING = -1


class _NodeView(Mapping):
    """``resolve_mft_bounded_path`` node mapping over parallel arrays indexed by record number.

    Records are dense (number = offset // record size), so per record this
    keeps three ``int64`` (sequence, parent, parent sequence), a name offset
    and length into one UTF-8 ``bytearray`` and a namespace code -- no per-node
    dict or tuple. ``-1`` marks an absent record / missing reference.
    """

    def __init__(self) -> None:
        self._sequence = array("q")
        self._parent = array("q")
        self._parent_sequence = array("q")
        self._name_start = array("q")
        self._name_length = array("H")
        self._namespace = bytearray()
        self._names = bytearray()
        self._namespaces: list[str] = []
        self._namespace_codes: dict[str, int] = {}
        self._count = 0

    def add(self, number: int, *, sequence: int, name: str, parent: object, parent_sequence: object, namespace: str) -> None:
        if number < 0:
            return
        grow = number + 1 - len(self._sequence)
        if grow > 0:
            fill = [_MISSING] * grow
            for column in (self._sequence, self._parent, self._parent_sequence, self._name_start):
                column.extend(fill)
            self._name_length.extend([0] * grow)
            self._namespace.extend(b"\x00" * grow)
        if self._sequence[number] == _MISSING:
            self._count += 1
        encoded = name.encode("utf-8")[:65535]
        self._sequence[number] = max(0, int(sequence))
        self._parent[number] = int(parent) if isinstance(parent, int) and parent >= 0 else _MISSING
        self._parent_sequence[number] = (
            int(parent_sequence) if isinstance(parent_sequence, int) and parent_sequence >= 0 else _MISSING
        )
        self._name_start[number] = len(self._names)
        self._name_length[number] = len(encoded)
        self._names.extend(encoded)
        code = self._namespace_codes.get(namespace)
        if code is None and len(self._namespaces) < 255:
            self._namespaces.append(namespace)
            code = self._namespace_codes[namespace] = len(self._namespaces)
        self._namespace[number] = code or 0

    def __contains__(self, key: object) -> bool:
        return isinstance(key, int) and 0 <= key < len(self._sequence) and self._sequence[key] != _MISSING

    def __getitem__(self, key: int) -> dict[str, object]:
        if key not in self:
            raise KeyError(key)
        start = self._name_start[key]
        parent = self._parent[key]
        parent_sequence = self._parent_sequence[key]
        code = self._namespace[key]
        return {
            "record_number": key,
            "sequence_number": self._sequence[key],
            "name": bytes(self._names[start : start + self._name_length[key]]).decode("utf-8", "replace"),
            "parent_record_number": "" if parent == _MISSING else parent,
            "parent_sequence_number": "" if parent_sequence == _MISSING else parent_sequence,
            "namespace": self._namespaces[code - 1] if code else "",
        }

    def __iter__(self) -> Iterator[int]:
        return (number for number, sequence in enumerate(self._sequence) if sequence != _MISSING)

    def __len__(self) -> int:
        return self._count


def mft_record_size(mft_path: Path) -> int:
    """FILE record size from the first aligned record header (allocated size at 0x1C), else 1024."""
    with mft_path.open("rb") as handle:
        head = handle.read(MFT_RECORD_SIZE_PROBE_BYTES)
    offset = head.find(b"FILE")
    while 0 <= offset and offset + 0x20 <= len(head):
        if offset % 512 == 0:
            allocated = int.from_bytes(head[offset + 0x1C : offset + 0x20], "little")
            if allocated in MFT_RECORD_SIZES and offset % allocated == 0:
                return allocated
        offset = head.find(b"FILE", offset + 1)
    return MFT_RECORD_SIZE


def _mft_data_size(record: Mapping[str, object], file_name: Mapping[str, object]) -> int | None:
    for item in record.get("data_attributes") or []:
        if isinstance(item, Mapping):
            for key in ("real_size", "size", "value_length"):
                if isinstance(item.get(key), int):
                    return int(item[key])
    value = file_name.get("real_size")
    return int(value) if isinstance(value, int) else None


def parse_mft_file(ctx: AnalysisContext, mft_path: Path, nodes: _NodeView, record_size: int) -> dict[str, object]:
    """Parse ``MFT.bin`` chunk by chunk into rows (paths via the bounded parent cache)."""
    from ...artifacts.windows.filesystem import (
        mft_preferred_file_name_entry,
        parse_mft_record_headers,
        resolve_mft_bounded_path,
    )

    staging = ctx.directory / "mft-records.staging.jsonl"
    record_count = 0
    with mft_path.open("rb") as handle, staging.open("w", encoding="utf-8") as out:
        base = 0
        while True:
            ctx.check_cancel()
            blob = handle.read(MFT_CHUNK_RECORDS * record_size)
            if not blob:
                break
            for record in parse_mft_record_headers(blob):
                offset = int(record.get("record_offset") or 0)
                if offset % record_size:
                    continue  # "FILE" inside record content, not a record header
                number = (base + offset) // record_size
                file_name = mft_preferred_file_name_entry(record)
                parent = file_name.get("parent_reference") if isinstance(file_name.get("parent_reference"), Mapping) else {}
                name = str(file_name.get("file_name") or "")
                nodes.add(
                    number,
                    sequence=int(record.get("sequence_number") or 0),
                    name=name,
                    parent=parent.get("record_number", ""),
                    parent_sequence=parent.get("sequence_number", ""),
                    namespace=str(file_name.get("namespace") or ""),
                )
                si = record.get("standard_information") if isinstance(record.get("standard_information"), Mapping) else {}
                si_times = si.get("timestamps") if isinstance(si.get("timestamps"), Mapping) else {}
                fn_times = file_name.get("timestamps") if isinstance(file_name.get("timestamps"), Mapping) else {}
                out.write(
                    json.dumps(
                        {
                            "entry_number": number,
                            "sequence_number": record.get("sequence_number"),
                            "in_use": bool(record.get("in_use")),
                            "directory": bool(record.get("directory")),
                            # Unnamed records (no $FILE_NAME: extension/unused records) carry
                            # name null; the console titles them by entry_number + in_use.
                            "name": name or None,
                            "parent_entry_number": parent.get("record_number"),
                            "size": _mft_data_size(record, file_name),
                            "created_at": si_times.get("created_at") or fn_times.get("created_at"),
                            "modified_at": si_times.get("modified_at") or fn_times.get("modified_at"),
                            "mft_modified_at": si_times.get("mft_modified_at") or fn_times.get("mft_modified_at"),
                            "accessed_at": si_times.get("accessed_at") or fn_times.get("accessed_at"),
                            # $STANDARD_INFORMATION and $FILE_NAME times kept apart
                            # (the merged fields above prefer $SI and fall back to $FN).
                            "si_created_at": si_times.get("created_at"),
                            "si_modified_at": si_times.get("modified_at"),
                            "si_mft_modified_at": si_times.get("mft_modified_at"),
                            "si_accessed_at": si_times.get("accessed_at"),
                            "fn_created_at": fn_times.get("created_at"),
                            "fn_modified_at": fn_times.get("modified_at"),
                            "fn_mft_modified_at": fn_times.get("mft_modified_at"),
                            "fn_accessed_at": fn_times.get("accessed_at"),
                            "file_attributes": si.get("file_attributes") if si else file_name.get("file_attributes"),
                            "attributes": list(si.get("file_attribute_names") or [])
                            if si
                            else list(file_name.get("file_attribute_names") or []),
                            "record_offset": base + offset,
                            "flags": record.get("flags"),
                            "validation_status": record.get("validation_status"),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                record_count += 1
            chunk_records = len(blob) // record_size
            base += len(blob)
            ctx.advance(chunk_records, message=f"MFT 파싱 · 레코드 {record_count:,}개")
    ctx.set_message("MFT 경로 재구성 중")
    status_counts: Counter[str] = Counter()
    in_use = 0
    with staging.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle):
            if index % 4096 == 0:
                ctx.check_cancel()
            details = json.loads(line)
            resolved = resolve_mft_bounded_path(int(details["entry_number"]), nodes)
            path = str(resolved.get("path") or details.get("name") or "")
            status_counts[str(resolved.get("status") or "")] += 1
            parent_path = path.rsplit("\\", 1)[0] if "\\" in path.strip("\\") else "\\"
            details.update({"source": "mft", "path": path, "parent_path": parent_path, "path_status": resolved.get("status")})
            in_use += 1 if details.get("in_use") else 0
            ctx.write_row(ctx.row(details, path=path))
    staging.unlink(missing_ok=True)
    return {
        "mft_record_size": record_size,
        "mft_record_count": record_count,
        "mft_in_use_count": in_use,
        "mft_deleted_count": record_count - in_use,
        "path_status_counts": dict(status_counts),
    }


def parse_usn_file(ctx: AnalysisContext, journal_path: Path, nodes: _NodeView) -> dict[str, object]:
    from ...artifacts.windows.filesystem import (
        parse_usn_record_scan,
        resolve_mft_bounded_path,
    )

    size = journal_path.stat().st_size
    parent_paths: dict[int, str] = {}
    count = 0
    position = 0
    with journal_path.open("rb") as handle:
        while position < size:
            ctx.check_cancel()
            handle.seek(position)
            blob = handle.read(USN_WINDOW_BYTES + USN_WINDOW_OVERLAP)
            if len(blob) < 60:
                break
            last_window = position + len(blob) >= size
            scan = parse_usn_record_scan(
                blob,
                record_limit=USN_RECORD_LIMIT_PER_WINDOW,
                max_scan_bytes=None if last_window else USN_WINDOW_BYTES,
            )
            records = scan.get("records") or []
            for record in records:
                file_ref = record.get("file_reference_number_decoded") or {}
                parent_ref = record.get("parent_file_reference_number_decoded") or {}
                parent_number = parent_ref.get("record_number") if isinstance(parent_ref, Mapping) else None
                parent_path = ""
                if isinstance(parent_number, int) and parent_number in nodes:
                    if parent_number not in parent_paths:
                        parent_paths[parent_number] = str(resolve_mft_bounded_path(parent_number, nodes).get("path") or "")
                    parent_path = parent_paths[parent_number]
                file_name = str(record.get("file_name") or "")
                path = f"{parent_path.rstrip(chr(92))}\\{file_name}" if parent_path else file_name
                ctx.write_row(
                    ctx.row(
                        {
                            "source": "usn",
                            "usn": record.get("usn"),
                            "reason": record.get("reason"),
                            "reason_flags": record.get("reason_flags"),
                            "file_name": file_name,
                            "timestamp": record.get("timestamp"),
                            "entry_number": file_ref.get("record_number") if isinstance(file_ref, Mapping) else None,
                            "parent_entry_number": parent_number,
                            "parent_path": parent_path or None,
                            "path": path,
                            "file_attributes": record.get("file_attribute_names"),
                            "record_offset": position + int(record.get("record_offset") or 0),
                            "validation_status": record.get("validation_status"),
                        },
                        path=path,
                    )
                )
            count += len(records)
            ctx.extend(len(records), message=f"USN 파싱 · 레코드 {count:,}개")
            if last_window:
                break
            position += max(int(scan.get("last_scanned_offset") or 0), 1)
    return {"usn_record_count": count, "usn_scanned_bytes": size}


def run_ntfs_meta(ctx: AnalysisContext) -> None:
    from ...core.ntfs_metadata import NTFSMetadataError

    options: NtfsMetaOptions = ctx.options  # type: ignore[assignment]
    image = Path(str(options.image_path))
    ctx.summary["image"] = str(image)
    ctx.summary["source"] = options.source or "image"
    if options.source == "mft":
        # Already-extracted raw $MFT: parsed in place, no Sleuth Kit and no copy.
        ctx.set_total(2, unit="단계·레코드", message="추출한 $MFT 파일을 바로 파싱합니다")
        try:
            size = image.stat().st_size
        except OSError as exc:
            raise AnalysisFailure(f"$MFT 파일을 읽을 수 없습니다: {exc}") from exc
        manifest: Mapping[str, object] = {
            "extraction_status": "not-needed-raw-mft",
            "partition": None,
            "skipped": [],
            "outputs": {"mft": {"path": str(image), "size_bytes": size, "sha256": None, "extraction_mode": "raw-mft-input"}},
            "manifest_path": None,
        }
    else:
        ctx.set_total(2, unit="단계·레코드", message="Sleuth Kit으로 $MFT·$UsnJrnl 추출 중")
        try:
            manifest = NTFS_EXTRACTOR(
                image,
                ctx.directory / "ntfs",
                partition_start_sector=options.partition_start_sector,
                sparse_journal=not options.full_journal,
            )
        except NTFSMetadataError as exc:
            message = str(exc)
            if message.startswith("missing Sleuth Kit tools"):
                message = f"Sleuth Kit 도구가 없습니다({message.split(':', 1)[-1].strip()}). mmls·fls·icat를 PATH에 설치하세요"
            raise AnalysisFailure(f"NTFS 메타 추출 실패: {message}") from exc
        except OSError as exc:
            raise AnalysisFailure(f"NTFS 메타 추출 실패: {exc}") from exc
    outputs = manifest.get("outputs") if isinstance(manifest.get("outputs"), Mapping) else {}
    ctx.summary.update(
        {
            "extraction_status": manifest.get("extraction_status"),
            "partition": manifest.get("partition"),
            "skipped": manifest.get("skipped"),
            "outputs": {
                name: {key: entry.get(key) for key in ("path", "size_bytes", "sha256", "extraction_mode")}
                for name, entry in outputs.items()
                if isinstance(entry, Mapping)
            },
            "manifest_path": manifest.get("manifest_path"),
            "filesystem": "NTFS",
        }
    )
    ctx.advance(2, message="추출 생략(추출한 $MFT 입력)" if options.source == "mft" else "추출 완료")
    ctx.check_cancel()
    if not options.parse:
        return
    nodes = _NodeView()
    mft = outputs.get("mft") if isinstance(outputs.get("mft"), Mapping) else None
    ctx.summary["parse_status"] = "parsed"
    if mft and mft.get("path"):
        mft_path = Path(str(mft["path"]))
        record_size = mft_record_size(mft_path)
        estimated = mft_path.stat().st_size // record_size
        if estimated > MFT_MAX_PARSE_RECORDS:
            ctx.summary.update(
                {
                    "parse_status": "too_large",
                    "mft_record_size": record_size,
                    "parse_skipped_reason": (
                        f"$MFT 레코드 {estimated:,}개가 파싱 한도({MFT_MAX_PARSE_RECORDS:,}개)를 넘어 "
                        "MFT 행을 만들지 않았습니다(추출 파일은 보존됨)"
                    ),
                }
            )
        else:
            ctx.set_total(2 + estimated, message="MFT 파싱 중")
            ctx.summary.update(parse_mft_file(ctx, mft_path, nodes, record_size))
    journal = outputs.get("usn_journal") if isinstance(outputs.get("usn_journal"), Mapping) else None
    if journal and journal.get("path"):
        ctx.summary.update(parse_usn_file(ctx, Path(str(journal["path"])), nodes))
    ctx.summary["limitation"] = (
        "경로는 MFT 부모 참조로 재구성한 후보입니다(경로 상태 path_status 참고). "
        "USN 오프셋은 희소 구간을 뺀 추출 파일 기준일 수 있습니다."
    )


# --- OCR batch ----------------------------------------------------------------------

OCR_LANGUAGE_PATTERN = re.compile(r"^[A-Za-z_]{3,16}$")


class OcrTarget(_Options):
    kind: Literal["media-image"] | None = None
    locators: list[str] | None = Field(None, min_length=1, max_length=1000)

    @model_validator(mode="after")
    def _one_target(self) -> OcrTarget:
        if bool(self.kind) == bool(self.locators):
            raise ValueError("대상은 kind(media-image) 또는 locators 중 하나만 지정하세요")
        return self


class OcrBatchOptions(_Options):
    target: OcrTarget = Field(default_factory=lambda: OcrTarget(kind="media-image"))
    max_items: int = Field(50, ge=1, le=1000)
    languages: list[str] = Field(default_factory=lambda: ["kor", "eng"], min_length=1, max_length=8)
    retry_failures: bool = False
    # Filled by prepare from target.locators (client values are overwritten).
    resolved_paths: list[str] | None = None

    @field_validator("languages")
    @classmethod
    def _language_codes(cls, value: list[str]) -> list[str]:
        for item in value:
            if not OCR_LANGUAGE_PATTERN.fullmatch(item):
                raise ValueError(f"OCR 언어 코드가 올바르지 않습니다: {item!r} (예: kor, eng)")
        return value


def _artifact_payload(scope: RunScope, kind: str) -> tuple[dict[str, object], Path] | None:
    try:
        path = scope.store.output_path(scope.run_id, f"artifacts_{kind}")
        return scope.store.read_output(scope.run_id, f"artifacts_{kind}"), path
    except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError):
        return None


def _locator_path(scope: RunScope, locator: str) -> str:
    text = locator.strip()
    for prefix, kind in (("/artifacts/", "media-image"), ("/candidates/", None)):
        if not text.startswith(prefix):
            continue
        tail = text[len(prefix):]
        if not tail.isdigit():
            raise HTTPException(status_code=400, detail=f"로케이터 형식이 올바르지 않습니다: {locator}")
        index = int(tail)
        if kind is not None:
            loaded = _artifact_payload(scope, kind)
            if loaded is None:
                raise HTTPException(status_code=400, detail="이 런에는 미디어 이미지 결과가 없습니다")
            payload, payload_path = loaded
            for _record_index, row in iter_artifact_records(payload, payload_path=payload_path, start=index, limit=1):
                return str(row.get("path") or "")
            raise HTTPException(status_code=400, detail=f"로케이터에 해당하는 행이 없습니다: {locator}")
        try:
            files = scope.store.read_output(scope.run_id, "files")
        except (KeyError, RuntimeError, PermissionError, FileNotFoundError, OSError) as exc:
            raise HTTPException(status_code=400, detail="이 런에는 파일 목록이 없습니다") from exc
        candidates = files.get("candidates") if isinstance(files.get("candidates"), list) else []
        if index >= len(candidates) or not isinstance(candidates[index], Mapping):
            raise HTTPException(status_code=400, detail=f"로케이터에 해당하는 행이 없습니다: {locator}")
        return str(candidates[index].get("path") or "")
    return text


def prepare_ocr_batch(options: OcrBatchOptions, scope: RunScope) -> dict[str, object]:
    payload = options.model_dump()
    payload["resolved_paths"] = None
    if options.target.locators:
        resolved: list[str] = []
        for locator in options.target.locators[: options.max_items]:
            raw = _locator_path(scope, locator)
            path = scope.resolve_input_path(raw, label="OCR 대상")
            if str(path) not in resolved:
                resolved.append(str(path))
        payload["resolved_paths"] = resolved
    return payload


def _media_image_paths(scope: RunScope, limit: int) -> list[Path]:
    from ...core.search import IMAGE_EXTS

    loaded = _artifact_payload(scope, "media-image")
    if loaded is None:
        raise AnalysisFailure("이 런에는 미디어 이미지(media-image) 결과가 없습니다")
    payload, payload_path = loaded
    roots = scope.input_roots()
    seen: set[str] = set()
    paths: list[Path] = []
    for _index, row in iter_artifact_records(payload, payload_path=payload_path):
        raw = str(row.get("path") or "")
        if not raw or raw in seen:
            continue
        seen.add(raw)
        path = Path(raw)
        if path.suffix.lower() not in IMAGE_EXTS or not path.is_file():
            continue
        resolved = path.resolve()
        if not any(resolved == root or is_relative_to(resolved, root) for root in roots):
            continue
        paths.append(resolved)
        if len(paths) >= limit:
            break
    return paths


def _default_ocr_engine():
    """``(cv2, pytesseract)`` or raise with the reason (same engine as search OCR)."""
    import cv2
    import pytesseract

    pytesseract.get_tesseract_version()
    return cv2, pytesseract


# Tests replace this hook to fake the OCR engine.
OCR_ENGINE_LOADER = _default_ocr_engine

OCR_ENGINE_MISSING_MESSAGE = "OCR 엔진(tesseract)을 찾을 수 없습니다. tesseract를 설치하고 PATH에 추가하세요."


def ocr_engine_error(exc: BaseException) -> str:
    """Korean reason for an unusable OCR engine (no English library text in the message)."""
    if isinstance(exc, ModuleNotFoundError):
        module = exc.name or "pytesseract/opencv"
        return f"OCR 모듈({module})이 설치되어 있지 않습니다. RapidTriage OCR 의존성(pytesseract, opencv-python)을 설치하세요."
    text = f"{type(exc).__name__} {exc}".lower()
    if "notfound" in text or "not installed" in text or "not in your path" in text or isinstance(exc, FileNotFoundError):
        return OCR_ENGINE_MISSING_MESSAGE
    return f"OCR 엔진(tesseract)을 사용할 수 없습니다({type(exc).__name__}). tesseract 설치와 PATH를 확인하세요."


def _engine_missing_text(text: str) -> bool:
    lowered = text.lower()
    return "tesseractnotfound" in lowered or "not installed" in lowered or "not in your path" in lowered


def _is_engine_missing(exc: BaseException) -> bool:
    return type(exc).__name__ == "TesseractNotFoundError" or _engine_missing_text(str(exc))


OCR_ROW_FAILED_PREFIX = "OCR 실패: "
OCR_ROW_REASONS = {
    "missing": OCR_ENGINE_MISSING_MESSAGE,
    "decode": "이미지를 디코딩할 수 없습니다",
    "language": "OCR 언어 데이터를 불러올 수 없습니다. tesseract 언어 데이터(tessdata) 설치를 확인하세요.",
    "read": "이미지 파일을 읽을 수 없습니다",
    "other": "이미지를 처리하지 못했습니다(원문은 error_detail)",
}
OCR_ROW_ERRORS = frozenset(OCR_ROW_FAILED_PREFIX + reason for reason in OCR_ROW_REASONS.values())


def ocr_row_error(exc: BaseException | str) -> str:
    """Korean per-row OCR error (the raw library text goes to ``details.error_detail``)."""
    text = exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"
    lowered = text.lower()
    if _engine_missing_text(text):
        reason = "missing"
    elif "디코딩" in text or "decode" in lowered:
        reason = "decode"
    elif "language" in lowered or "data file" in lowered or "tessdata" in lowered:
        reason = "language"
    elif isinstance(exc, OSError) or "permission" in lowered or "no such file" in lowered:
        reason = "read"
    else:
        reason = "other"
    return OCR_ROW_FAILED_PREFIX + OCR_ROW_REASONS[reason]


def korean_ocr_row_details(details: Mapping[str, object]) -> dict[str, object]:
    """OCR row details whose ``error`` is one of the Korean row errors; other text moves to ``error_detail``.

    Rows stored before row errors were Korean (``"OCR 실패: <library text>"``)
    are served and copied with the Korean error and the original text kept.
    """
    result = dict(details)
    error = result.get("error")
    if isinstance(error, str) and error and error not in OCR_ROW_ERRORS:
        result["error_detail"] = result.get("error_detail") or error
        result["error"] = ocr_row_error(error.removeprefix(OCR_ROW_FAILED_PREFIX))
    return result


def ocr_image(engine, path: Path, languages: str) -> dict[str, object]:
    """OCR one image: ``{text, confidence}`` from one ``image_to_data`` pass."""
    from ...core.image_io import imread_unicode_safe

    cv2, pytesseract = engine
    image = imread_unicode_safe(cv2, path)
    if image is None:
        raise OSError("이미지를 디코딩할 수 없습니다")
    data = pytesseract.image_to_data(image, lang=languages, output_type=pytesseract.Output.DICT)
    lines: OrderedDict[tuple[object, ...], list[str]] = OrderedDict()
    confidences: list[float] = []
    for index, word in enumerate(data.get("text") or []):
        word = str(word or "").strip()
        if not word:
            continue
        key = tuple((data.get(name) or [0] * (index + 1))[index] for name in ("block_num", "par_num", "line_num"))
        lines.setdefault(key, []).append(word)
        try:
            confidence = float((data.get("conf") or [])[index])
        except (TypeError, ValueError, IndexError):
            continue
        if confidence >= 0:
            confidences.append(confidence)
    text = "\n".join(" ".join(words) for words in lines.values())
    return {"text": text, "confidence": round(sum(confidences) / len(confidences), 1) if confidences else None}


def run_ocr_batch(ctx: AnalysisContext) -> None:
    import time

    options: OcrBatchOptions = ctx.options  # type: ignore[assignment]
    if options.resolved_paths is not None:
        paths = [Path(item) for item in options.resolved_paths]
    else:
        ctx.set_message("미디어 이미지 목록 작성 중")
        paths = _media_image_paths(ctx.scope, options.max_items)
    languages = "+".join(options.languages)
    ctx.set_total(len(paths), unit="이미지", message=f"이미지 {len(paths)}장")
    own_id = str(ctx.state.get("analysis_id"))
    earlier = [state for state in ANALYSIS_RUNNER.list_states(ctx.scope.output_dir) if state.get("analysis_id") != own_id]
    engine = None
    counts: Counter[str] = Counter()
    reused = 0

    def summarize(engine_error: str | None = None, engine_detail: str | None = None) -> None:
        ctx.summary.update(
            {
                "image_count": len(paths),
                "status_counts": dict(counts),
                # ok + empty: OCR ran (empty = no text found); failed includes copied earlier failures.
                "succeeded_count": counts["ok"] + counts["empty"],
                "failed_count": counts["failed"],
                "reused_count": reused,
                "languages": options.languages,
                "engine_error": engine_error,
                "engine_error_detail": engine_detail,
                "limitation": "OCR 텍스트는 원본 이미지와 대조한 뒤 인용하세요.",
            }
        )

    def engine_unavailable(exc: BaseException) -> AnalysisFailure:
        # Every remaining image would fail the same way: end the analysis failed.
        message = ocr_engine_error(exc)
        summarize(message, f"{type(exc).__name__}: {exc}")
        return AnalysisFailure(message)

    for path in paths:
        ctx.check_cancel()
        previous = find_ocr_result(ctx.scope.output_dir, path, states=earlier)
        if previous is None and not options.retry_failures:
            previous = find_ocr_result(ctx.scope.output_dir, path, states=earlier, include_failed=True)
        if previous is not None:
            details = korean_ocr_row_details({key: previous.get(key) for key in OCR_DETAIL_KEYS})
            details["reused_from"] = previous.get("analysis_id")
            reused += 1
        else:
            started = time.monotonic()
            details = {"source_path": str(path), "language": languages, "text": "", "text_length": 0, "confidence": None}
            if engine is None:
                try:
                    engine = OCR_ENGINE_LOADER()
                except Exception as exc:  # missing binary or module
                    raise engine_unavailable(exc) from exc
            try:
                result = ocr_image(engine, path, languages)
                text = str(result.get("text") or "")
                details.update(
                    {
                        "text": text,
                        "text_length": len(text),
                        "confidence": result.get("confidence"),
                        "status": "ok" if text.strip() else "empty",
                        "error": None,
                    }
                )
            except Exception as exc:
                if _is_engine_missing(exc):
                    raise engine_unavailable(exc) from exc
                details.update({"status": "failed", "error": ocr_row_error(exc), "error_detail": f"{type(exc).__name__}: {exc}"})
            details["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        counts[str(details.get("status"))] += 1
        ctx.write_row(ctx.row(details, path=str(path)))
        ctx.advance(message=f"{path.name} · {details.get('status')}")
    summarize()


OCR_DETAIL_KEYS = ("source_path", "text", "text_length", "confidence", "language", "elapsed_ms", "status", "error", "error_detail")
_OCR_INDEX_LOCK = threading.Lock()
_OCR_INDEX_CACHE: OrderedDict[tuple[str, int, int, int], dict[str, dict[str, object]]] = OrderedDict()
OCR_INDEX_CACHE_MAX_ENTRIES = 16


def _ocr_index(rows_path: Path, row_count: int) -> dict[str, dict[str, object]]:
    """``source_path`` key -> details of the first ``row_count`` records (never a line still being written)."""
    try:
        stat = rows_path.stat()
    except OSError:
        return {}
    key = (str(rows_path), row_count, stat.st_size, stat.st_mtime_ns)
    with _OCR_INDEX_LOCK:
        cached = _OCR_INDEX_CACHE.get(key)
        if cached is not None:
            _OCR_INDEX_CACHE.move_to_end(key)
            return cached
    index: dict[str, dict[str, object]] = {}
    for record_index, _offset, row, _line in iter_jsonl_records(rows_path):
        if record_index >= row_count:
            break
        details = row.get("details") if isinstance(row, Mapping) else None
        if isinstance(details, Mapping) and details.get("source_path"):
            for path_key in _row_path_keys(details["source_path"]):
                index[path_key] = dict(details)
    with _OCR_INDEX_LOCK:
        _OCR_INDEX_CACHE[key] = index
        while len(_OCR_INDEX_CACHE) > OCR_INDEX_CACHE_MAX_ENTRIES:
            _OCR_INDEX_CACHE.popitem(last=False)
    return index


def find_ocr_result(
    output_dir: Path,
    source_path: Path | str,
    *,
    states: list[dict[str, object]] | None = None,
    include_failed: bool = False,
) -> dict[str, object] | None:
    """Newest stored ``ocr-batch`` result for ``source_path`` (``details`` + ``analysis_id``).

    Failed rows are skipped unless ``include_failed`` (an older batch with
    text then wins over a newer failure). ``states`` is the run's analysis
    list (newest first), taken once per batch by callers that loop. The
    image viewer calls this before reporting "no OCR sidecar", so a batch OCR
    is never repeated for the same image.
    """
    keys = _row_path_keys(source_path)
    if states is None:
        states = ANALYSIS_RUNNER.list_states(output_dir)
    for state in states:
        if state.get("kind") != "ocr-batch" or state.get("status") not in {"completed", "cancelled", "running"}:
            continue
        rows_path = analyses_root(output_dir) / str(state.get("analysis_id")) / ROWS_FILE_NAME
        index = _ocr_index(rows_path, int(state.get("row_count") or 0))
        found = next((index[key] for key in keys if key in index), None)
        if found is None:
            continue
        if found.get("status") == "failed" and not include_failed:
            continue
        return {**found, "analysis_id": state.get("analysis_id")}
    return None


# --- memory import --------------------------------------------------------------------


class MemoryImportOptions(_Options):
    volatility_output_dir: str = Field(..., min_length=1)


def prepare_memory_import(options: MemoryImportOptions, scope: RunScope) -> dict[str, object]:
    directory = scope.resolve_input_path(options.volatility_output_dir, label="Volatility 출력 디렉터리")
    if not directory.is_dir():
        raise HTTPException(status_code=400, detail=f"Volatility 출력 디렉터리가 아닙니다: {directory}")
    return {"volatility_output_dir": str(directory)}


def run_memory_import(ctx: AnalysisContext) -> None:
    from ...artifacts.memory import MemoryVolatilityProvider

    options: MemoryImportOptions = ctx.options  # type: ignore[assignment]
    directory = Path(options.volatility_output_dir)
    walk_stats = WalkStats()
    # Links are never followed (a junction could point outside the allowed roots or loop).
    files = sorted(iter_evidence_files(ctx, directory, walk_stats), key=lambda item: str(item).lower())
    ctx.set_total(len(files), unit="출력 파일", message=f"출력 파일 {len(files)}개")
    type_counts: Counter[str] = Counter()
    seen_sources: set[str] = set()
    for record in MemoryVolatilityProvider().collect_files(files):
        ctx.check_cancel()
        payload = record.to_dict()
        details = dict(payload.get("details") or {})
        details["memory_artifact_type"] = payload.get("artifact_type")
        details["provider"] = payload.get("provider")
        details["supported"] = payload.get("supported")
        type_counts[str(payload.get("artifact_type"))] += 1
        source = str(details.get("source_path") or payload.get("path") or "")
        if source and source not in seen_sources:
            seen_sources.add(source)
            ctx.advance(message=f"{Path(source).name} 가져오는 중")
        ctx.write_row(ctx.row(details, path=str(payload.get("path") or "")))
    ctx.summary.update(
        {
            "volatility_output_dir": str(directory),
            "file_count": len(files),
            "skipped_link_count": walk_stats.skipped_links,
            "imported_file_count": len(seen_sources),
            "artifact_type_counts": dict(type_counts),
        }
    )


# --- cross-case -------------------------------------------------------------------------


class CrossCaseOptions(_Options):
    case_ids: list[str] = Field(..., min_length=1, max_length=20)
    max_shared: int = Field(500, ge=1, le=5000)


def cross_case_eligibility(job) -> dict[str, object]:
    """Run-list fields for the cross-case dialog (no DB is opened; one ``stat``).

    ``case_db_available``: the run's canonical case DB file exists.
    ``cross_case_eligible``: the run can be picked as a ``case_ids`` entry
    (completed/failed, summary with output dir, case DB present); otherwise
    ``cross_case_ineligible_reason`` says why in Korean (else ``None``).
    """
    from ...core.jobs import run_output_dir
    from ...core.run.persist import CASE_DB_FILE_NAME
    from .analyses import RUN_READY_STATUSES

    available = False
    reason: str | None = None
    if job.summary is None:
        reason = "런 요약이 없어 비교할 수 없습니다"
    else:
        try:
            output_dir = run_output_dir(job.summary)
        except RuntimeError:
            reason = "런 요약에 출력 디렉터리가 없어 비교할 수 없습니다"
        else:
            try:
                available = (Path(output_dir).expanduser() / CASE_DB_FILE_NAME).is_file()
            except OSError:
                available = False
            if not available:
                reason = "케이스 DB(rapidtriage-case.db)가 없어 비교할 수 없습니다"
    if job.status not in RUN_READY_STATUSES:
        reason = "완료되거나 실패한 런만 비교할 수 있습니다"
    return {
        "case_db_available": available,
        "cross_case_eligible": reason is None,
        "cross_case_ineligible_reason": reason,
    }


def _run_case_database(store, run_id: str) -> Path:
    from .run_review import canonical_run_case

    try:
        scope = run_scope(store, run_id)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(status_code=400, detail=f"케이스(런)를 찾을 수 없습니다: {run_id}") from exc
        raise HTTPException(status_code=400, detail=f"케이스(런)가 완료되지 않았습니다: {run_id}") from exc
    database, _case_id = canonical_run_case(scope.summary, run_id)
    if not database.is_file():
        raise HTTPException(status_code=400, detail=f"케이스 DB가 없습니다: {run_id} ({database})")
    return database


class _OccurrenceLocator:
    """Case-DB occurrence (database, case scope, citation id) -> run-output row ``{collection, kind, locator}``.

    Uses the review-map resolver (``RunLocatorIndex.locate``) of the run that
    owns the database, so a cross-case row links straight to the other
    case's files/artifacts row. One read-only connection per database.
    """

    def __init__(self, store, databases: Mapping[str, str]) -> None:
        self.store = store
        self.databases = databases
        self._connections: dict[str, sqlite3.Connection] = {}
        self._indexes: dict[tuple[str, str], object] = {}

    def _index(self, database: str, case_scope: str):
        from .run_review import RunLocatorIndex

        key = (database, case_scope)
        if key in self._indexes:
            return self._indexes[key]
        index = None
        run_id = self.databases.get(database)
        try:
            scope = run_scope(self.store, run_id) if run_id else None
            if scope is not None:
                connection = self._connections.get(database)
                if connection is None:
                    connection = sqlite3.connect(f"{Path(database).as_uri()}?mode=ro", uri=True)
                    self._connections[database] = connection
                outputs = scope.summary.get("outputs")
                index = RunLocatorIndex(
                    connection, case_scope, outputs if isinstance(outputs, Mapping) else {}, output_dir=scope.output_dir
                )
        except (HTTPException, sqlite3.Error, OSError, ValueError):
            index = None
        self._indexes[key] = index
        return index

    def locate(self, database: str, case_scope: str, citation_id: str, table: str) -> dict[str, str] | None:
        index = self._index(database, case_scope)
        if index is None or not citation_id:
            return None
        try:
            row = index.connection.execute(  # type: ignore[attr-defined]
                f"SELECT id FROM {table} WHERE citation_id = ? AND case_id = ?", (citation_id, case_scope)
            ).fetchone()
            if row is None:
                return None
            return index.locate(table, str(row[0]))  # type: ignore[attr-defined]
        except sqlite3.Error:
            return None

    def close(self) -> None:
        for connection in self._connections.values():
            connection.close()
        self._connections.clear()


def prepare_cross_case(options: CrossCaseOptions, scope: RunScope) -> dict[str, object]:
    case_ids = [item.strip() for item in options.case_ids if item.strip() and item.strip() != scope.run_id]
    if not case_ids:
        raise HTTPException(status_code=400, detail="비교할 다른 케이스를 하나 이상 선택하세요")
    for run_id in [scope.run_id, *case_ids]:
        _run_case_database(scope.store, run_id)
    return {"case_ids": list(dict.fromkeys(case_ids)), "max_shared": options.max_shared}


def run_cross_case(ctx: AnalysisContext) -> None:
    from ...core.cross_case import CrossCaseError, correlate_case_databases

    options: CrossCaseOptions = ctx.options  # type: ignore[assignment]
    run_ids = [ctx.scope.run_id, *options.case_ids]
    databases = {str(_run_case_database(ctx.scope.store, run_id).resolve()): run_id for run_id in run_ids}
    pair_count = len(databases) * (len(databases) - 1) // 2
    ctx.set_total(pair_count, unit="케이스 쌍", message=f"케이스 {len(databases)}개 비교 중")
    try:
        report = correlate_case_databases([Path(path) for path in databases], max_shared=options.max_shared)
    except (CrossCaseError, OSError) as exc:
        raise AnalysisFailure(f"교차 케이스 비교 실패: {exc}") from exc
    ctx.check_cancel()

    def cases(occurrences: list[Mapping[str, object]]) -> list[str]:
        return sorted({databases.get(str(Path(str(o.get("database"))).resolve()), str(o.get("scope"))) for o in occurrences})

    locator = _OccurrenceLocator(ctx.scope.store, databases)

    def occurrence_rows(occurrences: list[Mapping[str, object]], kind: str) -> list[dict[str, object]]:
        table = "artifact" if kind == "artifact" else "file_record"
        rows: list[dict[str, object]] = []
        for o in occurrences[:20]:
            database = str(Path(str(o.get("database"))).resolve())
            run_id = databases.get(database, "")
            rows.append(
                {
                    "case_id": run_id,
                    # The run to open for this occurrence (same value as case_id, explicit for links).
                    "run_id": run_id or None,
                    "case_scope": o.get("case_id"),
                    "citation_id": o.get("citation_id"),
                    "path": o.get("path"),
                    # Row of that run's output (review-map shape) or None when the case DB row
                    # has no run-output locator (e.g. imported from elsewhere).
                    "target": locator.locate(database, str(o.get("case_id") or ""), str(o.get("citation_id") or ""), table),
                }
            )
        return rows

    groups = (
        ("shared_hashes", lambda e: (str(e.get("value")), str(e.get("algorithm")))),
        ("shared_paths", lambda e: (str(e.get("normalized_path")), "path")),
        ("shared_artifact_identifiers", lambda e: (f"{e.get('artifact_type')}: {e.get('title')}", "artifact")),
    )
    try:
        for name, describe in groups:
            for entry in report.get(name) or []:
                ctx.check_cancel()
                indicator, kind = describe(entry)
                occurrences = [o for o in entry.get("occurrences") or [] if isinstance(o, Mapping)]
                ctx.write_row(
                    ctx.row(
                        {
                            "indicator": indicator,
                            "kind": kind,
                            "cases": cases(occurrences),
                            "first_seen": None,
                            "last_seen": None,
                            "occurrence_count": entry.get("occurrence_count"),
                            "scope_count": entry.get("scope_count"),
                            "occurrences": occurrence_rows(occurrences, kind),
                        }
                    )
                )
    finally:
        locator.close()
    ctx.advance(pair_count)
    _write_json(ctx.directory / "cross-case-correlation.json", report)
    ctx.summary.update(
        {
            "case_ids": run_ids,
            **(report.get("summary") or {}),
            "report_hash": report.get("report_hash"),
            "limitation": "케이스 DB에는 지표 시각이 없어 first_seen/last_seen은 비어 있습니다.",
        }
    )


# --- search-index ---------------------------------------------------------------------------


class SearchIndexOptions(_Options):
    mode: Literal["full", "incremental"] = "full"
    analysis_ids: list[str] = Field(default_factory=list, max_length=200)

    @field_validator("analysis_ids")
    @classmethod
    def _analysis_ids(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item or ""):
                raise ValueError(f"분석 id 형식이 아닙니다: {item!r}")
        return value


def run_search_index(ctx: AnalysisContext) -> None:
    """Build (``full``) or update (``incremental``) ``rapidtriage-search.db`` (plan search §3.0).

    One progress unit per output file / analysis; the build checks for
    cancellation every 500 rows. No result rows: the summary carries
    ``doc_count``, ``by_domain``, ``text_bytes``, ``db_bytes``, ``elapsed_s``,
    ``skipped`` and ``tokenizer``.
    """
    from ...core.artifact_domains import artifact_type_domain
    from ...core.search_index.build import (
        BuildHooks,
        IndexSwapFailed,
        build_search_index,
    )

    options: SearchIndexOptions = ctx.options  # type: ignore[assignment]
    hooks = BuildHooks(
        set_total=lambda total: ctx.set_total(total, unit="출력 파일", message="색인할 출력 파일을 셌습니다"),
        advance=lambda message: ctx.advance(message=message),
        check_cancel=ctx.check_cancel,
    )
    try:
        summary = build_search_index(
            ctx.scope.output_dir,
            ctx.scope.summary,
            run_id=ctx.scope.run_id,
            mode=options.mode,
            analysis_ids=options.analysis_ids,
            hooks=hooks,
            domain_of=artifact_type_domain,
            load_state=ANALYSIS_RUNNER.load_state,
        )
    except IndexSwapFailed as exc:
        # The old index stays; ``summary.status = build-failed-swap`` feeds GET …/search/index.
        ctx.summary.update(exc.summary)
        raise AnalysisFailure(exc.reason) from exc
    ctx.summary.update(summary)


# --- shared -------------------------------------------------------------------------------


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    from .analyses import atomic_write_json

    atomic_write_json(path, payload)


# --- row labels (review board) -------------------------------------------------------

VSC_STATUS_LABELS = {"deleted": "삭제", "modified": "수정", "added": "추가"}


def _base_name(value: object) -> str:
    text = str(value or "").rstrip("\\/")
    return re.split(r"[\\/]", text)[-1] if text else ""


def analysis_kind_label(kind: str) -> str:
    """``카빙 결과`` etc.: the kind's label + "결과" (unknown kinds: ``분석 결과``)."""
    spec = KIND_RUNNERS.get(kind)
    return f"{spec.label} 결과" if spec is not None else "분석 결과"


def analysis_row_title(kind: str, row: Mapping[str, object], record_index: int) -> str:
    """A human title for one analysis result row (review board, never a raw id)."""
    details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
    path = str(row.get("path") or "")
    title = ""
    if kind == "carve":
        source = _base_name(details.get("source_path") or path)
        signature = str(details.get("signature_kind") or details.get("extension") or "후보")
        title = f"{signature} 후보 @ {details.get('offset_hex') or details.get('offset')} · {source}" if source else ""
    elif kind == "vsc-discover":
        title = str(details.get("label") or details.get("snapshot_root") or "")
    elif kind == "vsc-compare":
        status = VSC_STATUS_LABELS.get(str(details.get("status") or ""), str(details.get("status") or ""))
        title = f"{status} · {details.get('path') or _base_name(path)}" if status else str(details.get("path") or "")
    elif kind == "vsc-extract":
        title = str(details.get("path") or _base_name(details.get("destination")) or "")
    elif kind == "ntfs-meta":
        if details.get("source") == "usn":
            name = str(details.get("path") or details.get("file_name") or "") or f"MFT 엔트리 #{details.get('entry_number')}"
            reason = str(details.get("reason") or "")
            title = f"USN {reason} · {name}" if reason else f"USN · {name}"
        else:
            name = str(details.get("path") or details.get("name") or "")
            state = "" if details.get("in_use", True) else " (삭제됨)"
            title = (name or f"MFT 엔트리 #{details.get('entry_number')} (이름 없음)") + state
    elif kind == "ocr-batch":
        title = _base_name(details.get("source_path") or path)
        text = " ".join(str(details.get("text") or "").split())
        if title and text:
            title = f"{title} · {text[:60]}"
    elif kind == "memory-import":
        name = _base_name(path) or str(details.get("name") or details.get("process_name") or "")
        title = f"{details.get('memory_artifact_type') or '메모리'} · {name}" if name else str(details.get("memory_artifact_type") or "")
    elif kind == "cross-case":
        title = f"{details.get('kind') or '지표'} · {details.get('indicator') or ''}".rstrip(" ·")
    return title.strip() or f"{analysis_kind_label(kind)} #{record_index}"



_COMMON_LABELS = {
    "ext": "확장자",
    "kinds": "시그니처 종류",
    "max_scan_bytes": "파일당 최대 스캔 바이트",
    "max_carve_bytes": "후보당 최대 카빙 바이트",
    "max_candidates": "최대 후보 수",
    "extract": "카빙 파일 저장",
    "include_rejected": "거부된 후보 행 포함",
    "max_depth": "최대 탐색 깊이",
    "snapshot_root": "스냅샷 루트",
    "hash": "해시 비교",
    "case_sensitive": "대소문자 구분",
    "max_records": "최대 기록 수",
    "status": "변경 상태",
    "max_file_count": "최대 파일 수",
    "max_total_bytes": "최대 총 바이트",
    "overwrite": "덮어쓰기",
    "output_dir": "출력 디렉터리",
    "partition_start_sector": "파티션 시작 섹터",
    "full_journal": "전체 저널",
    "parse": "파싱",
    "image_path": "디스크 이미지",
    "target": "대상",
    "target.kind": "대상 종류",
    "target.locators": "대상 로케이터",
    "max_items": "최대 이미지 수",
    "languages": "OCR 언어",
    "retry_failures": "실패 재시도",
    "volatility_output_dir": "Volatility 출력 디렉터리",
    "case_ids": "비교 케이스",
    "max_shared": "최대 공유 지표 수",
    "mode": "색인 방식",
    "analysis_ids": "분석 id",
}

KIND_RUNNERS: dict[str, AnalysisSpec] = {
    spec.kind: spec
    for spec in (
        AnalysisSpec("carve", "카빙", "파일", CarveOptions, run_carve, prepare_carve, _COMMON_LABELS),
        AnalysisSpec("vsc-discover", "볼륨 섀도우 탐색", "디렉터리", VscDiscoverOptions, run_vsc_discover, None, _COMMON_LABELS),
        AnalysisSpec(
            "vsc-compare", "볼륨 섀도우 비교", "파일 인덱스 항목", VscCompareOptions, run_vsc_compare, prepare_vsc_compare, _COMMON_LABELS
        ),
        AnalysisSpec("vsc-extract", "볼륨 섀도우 추출", "파일", VscExtractOptions, run_vsc_extract, prepare_vsc_extract, _COMMON_LABELS),
        AnalysisSpec("ntfs-meta", "NTFS 메타(MFT/USN)", "단계·레코드", NtfsMetaOptions, run_ntfs_meta, prepare_ntfs_meta, _COMMON_LABELS),
        AnalysisSpec("ocr-batch", "OCR 일괄", "이미지", OcrBatchOptions, run_ocr_batch, prepare_ocr_batch, _COMMON_LABELS),
        AnalysisSpec(
            "memory-import", "메모리(Volatility 가져오기)", "출력 파일", MemoryImportOptions, run_memory_import, prepare_memory_import, _COMMON_LABELS
        ),
        AnalysisSpec("cross-case", "교차 케이스", "케이스 쌍", CrossCaseOptions, run_cross_case, prepare_cross_case, _COMMON_LABELS),
        AnalysisSpec("search-index", "검색 색인", "출력 파일", SearchIndexOptions, run_search_index, None, _COMMON_LABELS),
    )
}
