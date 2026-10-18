"""Evidence tree builder for the /v2 three-pane workbench.

Produces a single ``GET /api/runs/{run_id}/tree`` payload so the frontend can
render the left evidence tree with one request. Counts come from the canonical
``summary.counts`` block plus per-output ``summary`` sections, which are read
with a bounded head scan (artifact payloads can reach tens of MB on real
images, so full ``json.load`` per file is avoided when the summary block is
near the top of the pretty-printed output).
"""

from __future__ import annotations

import json
import threading
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ...core.artifact_domains import (
    ARTIFACT_DOMAIN_TABLE,
    DOMAIN_LABELS,
    artifact_type_domain,
)
from ...core.eventlog_channels import (
    CHANNEL_COUNTS_KEY,
    EVENTLOG_KIND,
    SCM_COUNT_KEY,
    channel_group_nodes,
)
from ...core.jobs import RunJobStore, read_output_json, run_output_dir
from ...core.run.plan import plan_counts_brief
from .analyses import ANALYSIS_RUNNER
from .artifact_filter import record_field_value
from .derived import tree_derived_node
from .helpers import (
    default_case_path,
    enrich_summary_counts,
    get_job,
    get_output_path,
    run_not_finished_message,
    run_progress_payload,
)
from .jsonl_records import iter_artifact_records, jsonl_records_path
from .triage_flags import kind_flag_counts, tree_flags_section

SUMMARY_SCAN_BYTES = 65536

# Rows that are pivots/strings, not evidence records (W2 ``*-string-candidate``).
NON_EVIDENCE_TYPE_SUFFIXES: tuple[str, ...] = ("-string-candidate",)
# Kept for callers that enumerate groups (derived from the table).
ARTIFACT_GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = tuple(
    (
        domain,
        DOMAIN_LABELS[domain],
        tuple(kind for row_domain, kind, types in ARTIFACT_DOMAIN_TABLE if row_domain == domain and types is None),
    )
    for domain in DOMAIN_LABELS
)


# Plan P1 §3.3 "분석 작업" nodes: (node key, Korean label, analysis kinds).
# ``web-logs`` runs no analysis: it links to the windows-system kind filtered
# to WEB_LOG_ARTIFACT_TYPES (server ``artifact_type=`` filter).
ANALYSIS_NODES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("carve", "카빙", ("carve",)),
    ("vsc", "볼륨 섀도우", ("vsc-discover", "vsc-compare", "vsc-extract")),
    ("ntfs-meta", "NTFS 메타(MFT/USN)", ("ntfs-meta",)),
    ("ocr-batch", "OCR 일괄", ("ocr-batch",)),
    ("memory-import", "메모리", ("memory-import",)),
    ("web-logs", "웹 로그·웹셸", ()),
    ("cross-case", "교차 케이스", ("cross-case",)),
    ("triage-flags", "특이사항", ("triage-flags",)),
)
ANALYSIS_BRIEF_COUNT_KEYS: tuple[str, ...] = ("source_counts", "source_in_use_counts", "kind_counts")
WEB_LOG_KIND = "windows-system"
WEB_LOG_ARTIFACT_TYPES: tuple[str, ...] = ("web-server-log", "webshell-source-candidate")

FILE_CATEGORY_LABELS: dict[str, str] = {
    "documents": "문서",
    "images": "이미지",
    "archives": "압축",
    "databases": "데이터베이스",
    "emails": "이메일",
    "mobile-images": "모바일 이미지",
    "executables": "실행 파일",
    "memory-dumps": "메모리 덤프",
    "disk-images": "디스크 이미지",
    "vehicle-images": "차량 이미지",
    "other": "기타",
}

KIND_LABELS: dict[str, str] = {
    "windows-os-account": "OS 계정",
    "eventlog": "EVTX",
    "windows-registry": "레지스트리 하이브",
    "windows-shellbags": "ShellBags",
    "windows-execution": "실행 흔적",
    "windows-prefetch": "Prefetch",
    "windows-search-index": "Windows 검색 색인",
    "recent-files": "최근 파일·LNK",
    "windows-remote-access": "원격 접속",
    "browser": "브라우저",
    "email": "이메일",
    "kakaotalk-windows": "카카오톡 (Windows)",
    "windows-messenger": "데스크톱 메신저 (Windows)",
    "kakaotalk-macos": "카카오톡 (macOS)",
    "mobile-export": "모바일 내보내기",
    "cloud-export": "클라우드 내보내기",
    "cloud-sync": "클라우드 동기화 클라이언트",
    "android-apk": "Android APK",
    "media-image": "미디어 이미지",
    "synthetic-media": "합성 미디어",
    "generic-documents": "문서",
    "memory-volatility": "메모리 (Volatility)",
    "windows-filesystem": "파일시스템 기록",
    "windows-system": "Windows 시스템",
    "linux-system": "Linux 시스템",
    "macos-system": "macOS 시스템",
}


# r2 console fix M2/M4: per-value row counts and inventory notes of a few kinds,
# read with one bounded row scan per output (cached by file signature).
# kind -> the record field counted per value and artifact_type
# (``field_type_counts``; the console's per-browser / per-app nodes and the
# ``browser=`` / ``service=`` filters of ``GET /artifacts``).
FIELD_FACET_KINDS: dict[str, str] = {"browser": "browser", "windows-messenger": "service"}
# kind -> (inventory artifact_type, status field): rows counted by status with
# their Korean ``reason`` (``inventory_notes``; why a typed node is empty —
# PST tools switched off / missing, KakaoTalk key material missing).
INVENTORY_NOTE_KINDS: dict[str, tuple[str, str]] = {
    "email": ("email-container-inventory", "status"),
    "kakaotalk-windows": ("kakaotalk-app-inventory", "decryption_status"),
}
FACET_SCAN_CAP = 1_000_000
FACET_CACHE_SIZE = 64
_FACET_CACHE: OrderedDict[tuple[object, ...], dict[str, Any]] = OrderedDict()
_FACET_LOCK = threading.Lock()


def _file_signature(path: Path | None) -> tuple[object, ...]:
    if path is None:
        return ()
    try:
        stat = path.stat()
    except OSError:
        return (str(path), None)
    return (str(path), stat.st_mtime_ns, stat.st_size)


def scan_kind_facets(payload: Mapping[str, object], payload_path: Path, kind: str) -> dict[str, Any]:
    """``field_type_counts`` / ``inventory_notes`` of one kind output (one bounded row scan)."""
    field = FIELD_FACET_KINDS.get(kind)
    note = INVENTORY_NOTE_KINDS.get(kind)
    if field is None and note is None:
        return {}
    by_value: dict[str, dict[str, int]] = {}
    notes: dict[str, dict[str, Any]] = {}
    truncated = False
    for scanned, (_index, row) in enumerate(iter_artifact_records(payload, payload_path=payload_path)):
        if scanned >= FACET_SCAN_CAP:
            truncated = True
            break
        artifact_type = str(row.get("artifact_type") or "")
        if field is not None:
            value = record_field_value(row, field)
            if value:
                per_type = by_value.setdefault(value, {})
                per_type[artifact_type] = per_type.get(artifact_type, 0) + 1
        if note is not None and artifact_type == note[0]:
            status = record_field_value(row, note[1]) or "unknown"
            entry = notes.setdefault(
                status,
                {
                    "artifact_type": artifact_type,
                    "status": status,
                    "status_label": record_field_value(row, "status_label") or status,
                    "count": 0,
                    "reason": record_field_value(row, "reason"),
                },
            )
            entry["count"] += 1
    facets: dict[str, Any] = {}
    if field is not None:
        facets["field_type_counts"] = {
            field: {value: dict(sorted(types.items())) for value, types in sorted(by_value.items())}
        }
    if note is not None:
        facets["inventory_notes"] = sorted(notes.values(), key=lambda item: (-int(item["count"]), str(item["status"])))
    if truncated:
        facets["facets_truncated"] = True
    return facets


def kind_facets(store: RunJobStore, run_id: str, kind: str) -> dict[str, Any]:
    """Cached :func:`scan_kind_facets` of ``artifacts_<kind>`` (``{}`` when absent or unreadable)."""
    if kind not in FIELD_FACET_KINDS and kind not in INVENTORY_NOTE_KINDS:
        return {}
    name = f"artifacts_{kind}"
    try:
        path = get_output_path(store, run_id, name)
        payload = store.read_output(run_id, name)
    except (HTTPException, RuntimeError, OSError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    key = (kind, *_file_signature(path), *_file_signature(jsonl_records_path(payload, path)))
    with _FACET_LOCK:
        cached = _FACET_CACHE.get(key)
        if cached is not None:
            _FACET_CACHE.move_to_end(key)
            return cached
    try:
        facets = scan_kind_facets(payload, path, kind)
    except OSError:
        return {}
    with _FACET_LOCK:
        _FACET_CACHE[key] = facets
        while len(_FACET_CACHE) > FACET_CACHE_SIZE:
            _FACET_CACHE.popitem(last=False)
    return facets


def read_output_key(path: Path, key: str) -> Any:
    """Return a top-level key of a run output JSON via a bounded head scan.

    Falls back to a full parse when the key is absent from the head region.
    """
    try:
        with path.open("rb") as handle:
            head = handle.read(SUMMARY_SCAN_BYTES).decode("utf-8", errors="replace")
        marker = head.find(f'"{key}"')
        if marker >= 0:
            colon = head.find(":", marker)
            if colon >= 0:
                try:
                    decoded, _ = json.JSONDecoder().raw_decode(head, colon + 1)
                    return decoded
                except json.JSONDecodeError:
                    pass
        # Full-parse fallback goes through the shared LRU so large outputs
        # (tens of MB) are not re-parsed on every tree/issues request.
        payload = read_output_json(path)
    except (OSError, json.JSONDecodeError):
        return None
    return payload.get(key) if isinstance(payload, dict) else None


def read_output_summary(path: Path) -> dict[str, Any]:
    """Return the ``summary`` object of a run output JSON."""
    summary = read_output_key(path, "summary")
    return summary if isinstance(summary, dict) else {}


def _node(node_id: str, label: str, count: int, children: list[dict[str, Any]] | None = None, **extra: Any) -> dict[str, Any]:
    node: dict[str, Any] = {"id": node_id, "label": label, "count": count}
    if children is not None:
        node["children"] = children
    node.update(extra)
    return node


def _type_counts(kind_summary: dict[str, Any]) -> dict[str, int]:
    """``artifact_type -> count`` from a kind output's ``summary.artifact_type_counts`` (no row scan)."""
    counts = kind_summary.get("artifact_type_counts")
    if not isinstance(counts, dict):
        return {}
    return {str(name): int(value) for name, value in sorted(counts.items()) if isinstance(value, int)}


def _case_bookmark_count(store: RunJobStore, run_id: str) -> int:
    try:
        case_path = default_case_path(store, run_id)
    except HTTPException:
        return 0
    if case_path is None or not case_path.exists():
        return 0
    try:
        payload = json.loads(case_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    bookmarks = payload.get("bookmarks") if isinstance(payload, dict) else None
    return len(bookmarks) if isinstance(bookmarks, list) else 0


LIVE_MESSAGE = "런 진행 중 · 완료된 그룹만 표시 · 검색/타임라인은 마무리 후"
LIVE_STOPPED_MESSAGE = "런이 끝나지 않았습니다 · 완료된 그룹만 표시 · 이어서 실행하면 나머지를 처리합니다"
LIVE_READABLE_TASK_STATUSES = frozenset({"completed", "partial"})
TASK_STATE_REASONS = {
    "skipped": "건너뜀",
    "cancelled": "취소됨",
    "failed": "실패",
}


def _plan_task_reason(task: Mapping[str, Any], group: Mapping[str, Any], queue_position: int | None) -> str:
    status = str(task.get("status") or "")
    reason = str(task.get("reason") or "")
    if status == "running":
        rows = int(task.get("rows_so_far") or 0)
        return f"처리 중 (그룹 {group.get('label')}, 지금까지 {rows:,}행)"
    if status == "queued":
        position = f", 대기 {queue_position}번째" if queue_position else ""
        return f"대기 중 (그룹 {group.get('label')}{position})"
    if status in {"completed", "partial"}:
        return "매니페스트 단계 공급자 · 런 마무리 후 열립니다"
    label = TASK_STATE_REASONS.get(status, status)
    return f"{label} · {reason}" if reason else label


def live_run_block(store: RunJobStore, run_id: str, job: Any | None = None) -> dict[str, Any]:
    """``live`` block of ``/tree`` and ``/artifacts`` for a run without a summary (plan P2 §3.4)."""
    job = job if job is not None else get_job(store, run_id)
    progress = run_progress_payload(job)
    plan = progress.get("plan") if isinstance(progress, dict) else None
    provisional = store.provisional_outputs(run_id)
    available = sorted(name.removeprefix("artifacts_") for name in provisional if name.startswith("artifacts_"))
    pending: list[str] = []
    states: dict[str, dict[str, Any]] = {}
    queue_position = 0
    for group in (plan or {}).get("groups") or []:
        if not isinstance(group, dict):
            continue
        for task in group.get("tasks") or []:
            if not isinstance(task, dict) or task.get("type") != "provider":
                continue
            kind = str(task.get("id"))
            status = str(task.get("status") or "queued")
            if status == "queued":
                queue_position += 1
            readable = f"artifacts_{kind}" in provisional
            states[kind] = {
                "state": status,
                "group": group.get("id"),
                "group_label": group.get("label"),
                "rows_so_far": int(task.get("rows_so_far") or 0),
                **({} if readable else {"reason": _plan_task_reason(task, group, queue_position if status == "queued" else None)}),
                **({"reason": f"일부 완료 · {task.get('reason') or '취소'} (지금까지의 행만)"} if status == "partial" else {}),
            }
            if not readable:
                pending.append(kind)
    run_status = job.status
    if isinstance(progress, dict) and progress.get("status") == "interrupted":
        run_status = "interrupted"
    active = run_status in {"queued", "running"}
    return {
        "run_status": run_status,
        "partial": True,
        "available_kinds": available,
        "pending_kinds": pending,
        "files_available": "files" in provisional,
        "message": LIVE_MESSAGE if active else LIVE_STOPPED_MESSAGE,
        "plan_counts": plan_counts_brief(plan),
        "kind_states": states,
    }


def build_live_run_tree(store: RunJobStore, run_id: str, job: Any) -> dict[str, Any]:
    """Evidence tree of a run without a summary: finished provider kinds open, the rest dimmed with a reason."""
    live = live_run_block(store, run_id, job)
    if not live["available_kinds"] and not live["kind_states"] and job.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail=run_not_finished_message(job))
    states: dict[str, dict[str, Any]] = live.pop("kind_states")
    kind_summaries: dict[str, dict[str, Any]] = {}
    for kind in live["available_kinds"]:
        try:
            kind_summaries[kind] = read_output_summary(get_output_path(store, run_id, f"artifacts_{kind}"))
        except HTTPException:
            kind_summaries[kind] = {}
    for kind in live["pending_kinds"]:
        kind_summaries.setdefault(kind, {})
    facets = {kind: kind_facets(store, run_id, kind) for kind in live["available_kinds"]}
    groups = build_artifact_domain_groups(kind_summaries, kind_facets={kind: item for kind, item in facets.items() if item})
    total = 0
    for group in groups:
        group_total = 0
        for node in group.get("children") or []:
            kind = str(node.get("kind") or "")
            state = states.get(kind)
            if kind in live["available_kinds"]:
                node["state"] = state["state"] if state else "completed"
                if state and state.get("reason"):
                    node["reason"] = state["reason"]
                group_total += int(node.get("count") or 0)
                continue
            node["state"] = state["state"] if state else "pending"
            node["disabled"] = True
            node["reason"] = (state or {}).get("reason") or "처리 전"
            if state and state.get("state") == "running":
                node["rows_so_far"] = state.get("rows_so_far", 0)
            node.pop("children", None)
        group["count"] = group_total
        total += group_total
    nodes: list[dict[str, Any]] = []
    if live["files_available"]:
        try:
            files_summary = read_output_summary(get_output_path(store, run_id, "files"))
        except HTTPException:
            files_summary = {}
        files_children = [
            _node(f"files:{category}", FILE_CATEGORY_LABELS.get(category, category), count, collection="files", category=category)
            for category, count in (files_summary.get("category_counts") or {}).items()
            if isinstance(count, int)
        ]
        nodes.append(
            _node("files", "파일", int(files_summary.get("candidate_count") or 0), children=files_children, collection="files")
        )
    else:
        nodes.append(_node("files", "파일", 0, collection="files", state="pending", disabled=True, reason="파일 인벤토리 단계 후 열립니다"))
    nodes.append(_node("artifacts", "아티팩트", total, children=groups, collection="artifacts"))
    for node_id, label in (("docs", "문서"), ("timeline", "타임라인"), ("indicators", "지표 후보")):
        nodes.append(_node(node_id, label, 0, collection=node_id, state="pending", disabled=True, reason="런 마무리 후 사용할 수 있습니다"))
    request = job.request
    return {
        "run_id": run_id,
        "root": {
            "label": Path(request.root).name if request and request.root else run_id,
            "mode": request.mode if request else None,
            "status": live["run_status"],
        },
        "nodes": nodes,
        "live": live,
    }


def build_run_tree(store: RunJobStore, run_id: str) -> dict[str, Any]:
    """Assemble the evidence tree for one run (live view while the run has no summary)."""
    job = get_job(store, run_id)
    if job.summary is None:
        return build_live_run_tree(store, run_id, job)

    try:
        case_path = default_case_path(store, run_id)
    except HTTPException:
        case_path = None
    summary = enrich_summary_counts(job.summary, case_path=case_path)
    inner = summary.get("summary") if isinstance(summary.get("summary"), dict) else summary
    counts = inner.get("counts") if isinstance(inner.get("counts"), dict) else {}
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), dict) else {}

    nodes: list[dict[str, Any]] = []
    try:
        flags_section, flags_summary = tree_flags_section(run_output_dir(job.summary))
    except RuntimeError:
        flags_section, flags_summary = None, None

    # --- 파일: category children from the files output summary --------------
    files_children: list[dict[str, Any]] = []
    files_count = int(counts.get("files") or 0)
    try:
        files_summary = read_output_summary(get_output_path(store, run_id, "files"))
    except HTTPException:
        files_summary = {}
    category_counts = files_summary.get("category_counts")
    if isinstance(category_counts, dict):
        for category, count in category_counts.items():
            if not isinstance(count, int):
                continue
            files_children.append(
                _node(
                    f"files:{category}",
                    FILE_CATEGORY_LABELS.get(category, category),
                    count,
                    collection="files",
                    category=category,
                )
            )
    # Parser-quality r2: files outside the selected categories are inventoried
    # (files.json ``inventory``; case DB file_record). "기타" = the "other"
    # category of that inventory; selected-category nodes above stay candidates.
    # Inventory nodes carry ``scope="inventory"``: their rows are paged by
    # ``GET /files?scope=inventory&category=<category>``.
    inventory_counts = files_summary.get("inventory_category_counts")
    if isinstance(inventory_counts, dict):
        known = {str(child.get("category")) for child in files_children}
        for category, count in sorted(inventory_counts.items(), key=lambda item: (item[0] != "other", item[0])):
            if not isinstance(count, int) or not count or str(category) in known:
                continue
            files_children.append(
                _node(
                    f"files:{category}",
                    FILE_CATEGORY_LABELS.get(str(category), str(category)),
                    count,
                    collection="files",
                    category=str(category),
                    source="inventory",
                    scope="inventory",
                    inventory_only=True,
                )
            )
    if files_count or files_children:
        files_extra: dict[str, Any] = {}
        if isinstance(files_summary.get("inventory_count"), int):
            files_extra["inventory_count"] = int(files_summary["inventory_count"])
        if flags_summary is not None:
            files_extra["flag_counts"] = _sum_grades(
                [kind_flag_counts(flags_summary, "files:candidates"), kind_flag_counts(flags_summary, "files:inventory")]
            )
        nodes.append(
            _node("files", "파일", files_count, children=files_children, collection="files", **files_extra)
        )

    # --- 아티팩트: group -> kind -> artifact_type ---------------------------
    kind_summaries: dict[str, dict[str, Any]] = {}
    for name in sorted(outputs):
        if not name.startswith("artifacts_"):
            continue
        kind = name.removeprefix("artifacts_")
        try:
            kind_summaries[kind] = read_output_summary(get_output_path(store, run_id, name))
        except HTTPException:
            kind_summaries[kind] = {}

    artifacts_total = int(counts.get("artifacts") or 0)
    facets = {kind: kind_facets(store, run_id, kind) for kind in kind_summaries}
    artifact_groups = build_artifact_domain_groups(
        kind_summaries, flags_summary=flags_summary, kind_facets={kind: item for kind, item in facets.items() if item}
    )
    if artifacts_total or artifact_groups:
        nodes.append(
            _node("artifacts", "아티팩트", artifacts_total, children=artifact_groups, collection="artifacts")
        )

    nodes.append(build_analyses_node(summary, kind_summaries.get(WEB_LOG_KIND) or {}))

    # 통합 보기 (plan axiom-adoption §3.2): absent while the run has no completed derived set.
    try:
        derived_node = tree_derived_node(run_output_dir(job.summary))
    except RuntimeError:
        derived_node = None
    if derived_node is not None:
        nodes.append(derived_node)

    # --- 문서 / 타임라인 / 지표 / 리뷰 선별 / 검증 이슈 -----------------------
    docs_count = int(counts.get("docs") or 0)
    document_candidates = int(counts.get("document_candidates") or 0)
    if docs_count or document_candidates:
        # count = keyword matches (what GET /docs pages today);
        # candidate_count = every document candidate (all are listed once the
        # docs route pages ``candidates`` with a matched filter).
        nodes.append(
            _node(
                "docs",
                "문서",
                docs_count,
                collection="docs",
                candidate_count=document_candidates,
                match_count=docs_count,
            )
        )
    timeline_count = int(counts.get("timeline_events") or 0)
    if timeline_count:
        nodes.append(_node("timeline", "타임라인", timeline_count, collection="timeline"))
    indicator_count = int(counts.get("indicators") or 0)
    if indicator_count:
        try:
            indicator_summary = read_output_summary(get_output_path(store, run_id, "indicators"))
        except HTTPException:
            indicator_summary = {}
        # "지표 후보" when no detection rule was applied (parser-quality r1).
        indicator_label = str(indicator_summary.get("display_label") or "지표 후보")
        nodes.append(
            _node(
                "indicators",
                indicator_label,
                indicator_count,
                collection="indicators",
                rule_count=int(indicator_summary.get("rule_count") or 0),
                truncated=bool(indicator_summary.get("truncated")),
                total_before_cap=indicator_summary.get("total_before_cap"),
            )
        )

    # 검색 결과 (plan search §3.3): index status + saved searches with their last counts.
    from .search_index_service import tree_search_node

    nodes.append(tree_search_node(job, run_id))

    bookmark_count = _case_bookmark_count(store, run_id)
    nodes.append(_node("review", "리뷰 선별", bookmark_count, collection="review"))

    issue_count = int(counts.get("validation_issues") or 0)
    nodes.append(_node("issues", "검증 이슈", issue_count, collection="issues"))

    request = job.request
    tree: dict[str, Any] = {
        "run_id": run_id,
        "root": {
            "label": Path(request.root).name if request and request.root else run_id,
            "mode": request.mode if request else None,
            "status": job.status,
        },
        "nodes": nodes,
    }
    # 특이사항 (viewer-families U-F4): absent while the run has no completed triage-flags set.
    if flags_section is not None:
        tree["flags"] = flags_section
    return tree


def _sum_grades(items: list[dict[str, int]]) -> dict[str, int]:
    return {grade: sum(int(item.get(grade) or 0) for item in items) for grade in ("A", "B", "C")}


def build_artifact_domain_groups(
    kind_summaries: dict[str, dict[str, Any]],
    *,
    flags_summary: Mapping[str, object] | None = None,
    kind_facets: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Domain -> kind -> artifact_type nodes from :data:`ARTIFACT_DOMAIN_TABLE`.

    ``kind_facets`` (:func:`kind_facets`) adds ``field_type_counts`` /
    ``inventory_notes`` to every node of that kind (each a whole-kind value).

    With ``flags_summary`` (a ``triage-flags`` summary) every kind node and
    domain group carries ``flag_counts`` = flagged rows by strongest grade:
    the rows of the types placed in that node (the primary node also counts
    cross-row flags whose row type is unknown), the group the sum of its kinds.
    """
    placement: dict[str, dict[str, dict[str, int]]] = {}
    kind_order: dict[str, list[str]] = {}
    for kind, kind_summary in sorted(kind_summaries.items()):
        type_counts = _type_counts(kind_summary)
        default = artifact_type_domain(kind, "")
        if not type_counts:
            placement.setdefault(default, {}).setdefault(kind, {})
            kind_order.setdefault(default, []).append(kind)
            continue
        for artifact_type, count in type_counts.items():
            domain = artifact_type_domain(kind, artifact_type)
            bucket = placement.setdefault(domain, {})
            if kind not in bucket:
                kind_order.setdefault(domain, []).append(kind)
            bucket.setdefault(kind, {})[artifact_type] = count
    groups: list[dict[str, Any]] = []
    for domain in [*DOMAIN_LABELS, "other"]:
        bucket = placement.get(domain)
        if not bucket:
            continue
        kind_nodes: list[dict[str, Any]] = []
        group_count = 0
        group_flags: list[dict[str, int]] = []
        for kind in kind_order.get(domain, []):
            kind_summary = kind_summaries.get(kind) or {}
            types = bucket[kind]
            primary = artifact_type_domain(kind, "") == domain
            kind_count = int(kind_summary.get("artifact_count") or 0) if primary and len(placement_domains(placement, kind)) == 1 else sum(types.values())
            group_count += kind_count
            type_children = [
                _node(
                    f"artifacts:{kind}:{artifact_type}",
                    artifact_type,
                    count,
                    collection="artifacts",
                    kind=kind,
                    artifact_type=artifact_type,
                    domain=domain,
                    **({"non_evidence": True} if artifact_type.endswith(NON_EVIDENCE_TYPE_SUFFIXES) else {}),
                )
                for artifact_type, count in sorted(types.items())
            ]
            extra: dict[str, Any] = {}
            notes = kind_summary.get("collection_notes")
            if isinstance(notes, list) and notes:
                extra["collection_notes"] = [str(item) for item in notes]
            # Forwarded as-is (also "completed") so the console can say
            # "제공자 건너뜀(사유)" from skip_reasons / skipped_row_count.
            if kind_summary.get("collection_status"):
                extra["collection_status"] = str(kind_summary.get("collection_status"))
            skip_reasons = kind_summary.get("skip_reasons")
            if isinstance(skip_reasons, dict) and skip_reasons:
                extra["skip_reasons"] = {str(reason): int(count) for reason, count in skip_reasons.items() if isinstance(count, int)}
            if isinstance(kind_summary.get("skipped_row_count"), int):
                extra["skipped_row_count"] = int(kind_summary["skipped_row_count"])
            extra.update((kind_facets or {}).get(kind) or {})
            # eventlog: recovered records whose id is below the first live
            # record (``evtx_record_id_position = "stale-below-first"``). The
            # tree has no details-level sub-nodes, so only the count is sent;
            # 0 is forwarded so the console can tell "none" from "old output".
            stale = kind_summary.get("stale_below_first_record_count")
            if primary and isinstance(stale, int) and not isinstance(stale, bool):
                extra["stale_below_first_record_count"] = stale
            # eventlog channel groups (plan r3-os-depth §3.2 O2): counts from the
            # kind summary's raw ``channel_counts`` (absent on older outputs, so
            # the console shows "—"); ``channels`` = exact ``channel=`` values.
            channel_counts = kind_summary.get(CHANNEL_COUNTS_KEY)
            if primary and kind == EVENTLOG_KIND and isinstance(channel_counts, dict):
                extra["channel_counts"] = {
                    str(name): int(value)
                    for name, value in channel_counts.items()
                    if isinstance(value, int) and not isinstance(value, bool)
                }
                extra["channel_groups"] = channel_group_nodes(channel_counts, kind_summary.get(SCM_COUNT_KEY))
            if flags_summary is not None:
                if not types:
                    flag_counts = kind_flag_counts(flags_summary, kind) if primary else kind_flag_counts(flags_summary, kind, [])
                else:
                    flag_counts = kind_flag_counts(flags_summary, kind, [*types, *([""] if primary else [])])
                extra["flag_counts"] = flag_counts
                group_flags.append(flag_counts)
            kind_nodes.append(
                _node(
                    f"artifacts:{kind}" if primary else f"artifacts:{kind}@{domain}",
                    KIND_LABELS.get(kind, kind),
                    kind_count,
                    children=type_children or None,
                    collection="artifacts",
                    kind=kind,
                    domain=domain,
                    # whole-kind counts on the primary node (existing contract);
                    # domain_artifact_type_counts = the types placed here.
                    artifact_type_counts=_type_counts(kind_summary) if primary else dict(sorted(types.items())),
                    domain_artifact_type_counts=dict(sorted(types.items())),
                    **extra,
                )
            )
        group_extra: dict[str, Any] = {"flag_counts": _sum_grades(group_flags)} if flags_summary is not None else {}
        groups.append(
            _node(f"artifacts-group:{domain}", DOMAIN_LABELS.get(domain, "기타"), group_count, children=kind_nodes, **group_extra)
        )
    return groups


def placement_domains(placement: dict[str, dict[str, dict[str, int]]], kind: str) -> list[str]:
    return [domain for domain, bucket in placement.items() if kind in bucket]


def _analysis_brief(state: dict[str, Any] | None) -> dict[str, Any] | None:
    if state is None:
        return None
    brief = {
        "analysis_id": state.get("analysis_id"),
        "kind": state.get("kind"),
        "status": state.get("status"),
        "finished_at": state.get("finished_at"),
        "row_count": state.get("row_count"),
    }
    # R3 §3.3 sub-node counts: ntfs-meta rows per source (타임스탬프 불일치, $LogFile),
    # carve candidates per signature kind (계열 노드 "복구됨(카빙)").
    summary = state.get("summary") if isinstance(state.get("summary"), Mapping) else {}
    for key in ANALYSIS_BRIEF_COUNT_KEYS:
        counts = summary.get(key)
        if isinstance(counts, Mapping):
            brief[key] = {str(name): int(value) for name, value in counts.items() if isinstance(value, int)}
    return brief


def build_analyses_node(summary: dict[str, Any], web_log_summary: dict[str, Any]) -> dict[str, Any]:
    """The "분석 작업" group: one node per analysis family.

    ``latest`` is the newest analysis of the node's kinds (any status),
    ``latest_completed`` the newest completed one; ``count`` is
    ``latest_completed.row_count`` (0 when none). ``state`` aliases ``latest``.
    Web logs link to the windows-system kind filtered by artifact type.
    """
    try:
        states = ANALYSIS_RUNNER.list_states(run_output_dir(summary))
    except RuntimeError:
        states = []
    children: list[dict[str, Any]] = []
    for key, label, kinds in ANALYSIS_NODES:
        if key == "web-logs":
            type_counts = web_log_summary.get("artifact_type_counts")
            type_counts = type_counts if isinstance(type_counts, dict) else {}
            count = sum(int(type_counts.get(name) or 0) for name in WEB_LOG_ARTIFACT_TYPES)
            children.append(
                _node(
                    f"analysis:{key}",
                    label,
                    count,
                    collection="analysis",
                    kind=key,
                    analysis_kinds=[],
                    latest=None,
                    latest_completed=None,
                    state=None,
                    link={
                        "collection": "artifacts",
                        "kind": WEB_LOG_KIND,
                        "artifact_types": list(WEB_LOG_ARTIFACT_TYPES),
                        "node_ids": [f"artifacts:{WEB_LOG_KIND}:{name}" for name in WEB_LOG_ARTIFACT_TYPES],
                    },
                )
            )
            continue
        latest = _analysis_brief(next((item for item in states if item.get("kind") in kinds), None))
        completed = _analysis_brief(
            next((item for item in states if item.get("kind") in kinds and item.get("status") == "completed"), None)
        )
        children.append(
            _node(
                f"analysis:{key}",
                label,
                int(completed["row_count"] or 0) if completed else 0,  # count source: latest_completed
                collection="analysis",
                kind=key,
                analysis_kinds=list(kinds),
                latest=latest,
                latest_completed=completed,
                state=latest,  # alias of ``latest`` kept for earlier clients
            )
        )
    return _node("analyses", "분석 작업", len([item for item in states if item.get("kind")]), children=children, collection="analysis")


def build_run_issues(store: RunJobStore, run_id: str) -> dict[str, Any]:
    """Normalize validation issues for the tree's "검증 이슈" collection.

    Rows mirror the canonical ``validation_issues`` formula: step warnings
    (already normalized in ``processing.warnings``) plus per-parser error
    entries from each ``artifacts_*`` output's ``parser_errors`` list.
    """
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail=run_not_finished_message(job))

    rows: list[dict[str, Any]] = []
    processing = job.summary.get("processing")
    if isinstance(processing, dict):
        warnings = processing.get("warnings")
        if isinstance(warnings, list):
            for warning in warnings:
                if not isinstance(warning, dict):
                    continue
                rows.append(
                    {
                        "step": warning.get("step", ""),
                        "kind": "단계 경고",
                        "level": warning.get("level", ""),
                        "message": warning.get("message", ""),
                    }
                )

    outputs = job.summary.get("outputs")
    if isinstance(outputs, dict):
        for name in sorted(outputs):
            if not name.startswith("artifacts_"):
                continue
            kind = name.removeprefix("artifacts_")
            try:
                path = get_output_path(store, run_id, name)
            except HTTPException:
                continue
            parser_errors = read_output_key(path, "parser_errors")
            if not isinstance(parser_errors, list):
                continue
            for error in parser_errors:
                message = error if isinstance(error, str) else json.dumps(error, ensure_ascii=False)
                rows.append(
                    {
                        "step": f"artifacts-{kind}",
                        "kind": "파서 오류",
                        "level": "error",
                        "message": message,
                    }
                )

    return {"issues": rows, "count": len(rows)}
