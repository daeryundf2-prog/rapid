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
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ...core.jobs import RunJobStore
from .helpers import default_case_path, enrich_summary_counts, get_job, get_output_path

SUMMARY_SCAN_BYTES = 65536

# Plan section 6-2 artifact grouping: (group_id, Korean label, kind ids).
ARTIFACT_GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("os-account", "운영체제·계정", ("windows-os-account",)),
    ("event-log", "이벤트 로그", ("eventlog",)),
    ("registry", "레지스트리", ("windows-registry", "windows-shellbags")),
    ("execution", "실행 흔적", ("windows-execution", "windows-prefetch", "windows-search-index")),
    ("file-usage", "파일 사용", ("recent-files",)),
    ("remote-access", "원격 접속", ("windows-remote-access",)),
    ("browser", "브라우저", ("browser",)),
    ("messaging-mail", "메신저·메일", ("email", "kakaotalk-windows", "kakaotalk-macos", "mobile-export")),
    ("cloud", "클라우드 내보내기", ("cloud-export",)),
    ("mobile", "모바일", ("android-apk",)),
    ("media", "미디어", ("media-image", "synthetic-media")),
    ("documents", "문서", ("generic-documents",)),
    ("memory", "메모리", ("memory-volatility",)),
    ("filesystem-system", "파일시스템·시스템", ("windows-filesystem", "windows-system", "linux-system", "macos-system")),
)

FILE_CATEGORY_LABELS: dict[str, str] = {
    "documents": "문서",
    "images": "이미지",
    "archives": "압축",
    "databases": "데이터베이스",
    "emails": "이메일",
    "mobile-images": "모바일 이미지",
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
    "kakaotalk-macos": "카카오톡 (macOS)",
    "mobile-export": "모바일 내보내기",
    "cloud-export": "클라우드 내보내기",
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
        payload = json.loads(path.read_text(encoding="utf-8"))
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


def build_run_tree(store: RunJobStore, run_id: str) -> dict[str, Any]:
    """Assemble the evidence tree for one completed run."""
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")

    try:
        case_path = default_case_path(store, run_id)
    except HTTPException:
        case_path = None
    summary = enrich_summary_counts(job.summary, case_path=case_path)
    inner = summary.get("summary") if isinstance(summary.get("summary"), dict) else summary
    counts = inner.get("counts") if isinstance(inner.get("counts"), dict) else {}
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), dict) else {}

    nodes: list[dict[str, Any]] = []

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
    if files_count or files_children:
        nodes.append(
            _node("files", "파일", files_count, children=files_children, collection="files")
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
    artifact_groups: list[dict[str, Any]] = []
    grouped_kinds: set[str] = set()
    for group_id, group_label, kinds in ARTIFACT_GROUPS:
        kind_nodes: list[dict[str, Any]] = []
        group_count = 0
        for kind in kinds:
            if kind not in kind_summaries:
                continue
            grouped_kinds.add(kind)
            kind_summary = kind_summaries[kind]
            kind_count = int(kind_summary.get("artifact_count") or 0)
            group_count += kind_count
            type_counts = kind_summary.get("artifact_type_counts")
            type_children: list[dict[str, Any]] = []
            if isinstance(type_counts, dict):
                for artifact_type, count in sorted(type_counts.items()):
                    if not isinstance(count, int):
                        continue
                    type_children.append(
                        _node(
                            f"artifacts:{kind}:{artifact_type}",
                            artifact_type,
                            count,
                            collection="artifacts",
                            kind=kind,
                            artifact_type=artifact_type,
                        )
                    )
            kind_nodes.append(
                _node(
                    f"artifacts:{kind}",
                    KIND_LABELS.get(kind, kind),
                    kind_count,
                    children=type_children or None,
                    collection="artifacts",
                    kind=kind,
                )
            )
        if kind_nodes:
            artifact_groups.append(
                _node(f"artifacts-group:{group_id}", group_label, group_count, children=kind_nodes)
            )
    # Kinds not covered by the declared groups still surface under "기타".
    other_nodes: list[dict[str, Any]] = []
    other_count = 0
    for kind, kind_summary in sorted(kind_summaries.items()):
        if kind in grouped_kinds:
            continue
        kind_count = int(kind_summary.get("artifact_count") or 0)
        other_count += kind_count
        other_nodes.append(
            _node(
                f"artifacts:{kind}",
                KIND_LABELS.get(kind, kind),
                kind_count,
                collection="artifacts",
                kind=kind,
            )
        )
    if other_nodes:
        artifact_groups.append(_node("artifacts-group:other", "기타", other_count, children=other_nodes))
    if artifacts_total or artifact_groups:
        nodes.append(
            _node("artifacts", "아티팩트", artifacts_total, children=artifact_groups, collection="artifacts")
        )

    # --- 문서 / 타임라인 / 지표 / 리뷰 선별 / 검증 이슈 -----------------------
    docs_count = int(counts.get("docs") or 0)
    if docs_count:
        nodes.append(_node("docs", "문서", docs_count, collection="docs"))
    timeline_count = int(counts.get("timeline_events") or 0)
    if timeline_count:
        nodes.append(_node("timeline", "타임라인", timeline_count, collection="timeline"))
    indicator_count = int(counts.get("indicators") or 0)
    if indicator_count:
        nodes.append(_node("indicators", "지표", indicator_count, collection="indicators"))

    bookmark_count = _case_bookmark_count(store, run_id)
    nodes.append(_node("review", "리뷰 선별", bookmark_count, collection="review"))

    issue_count = int(counts.get("validation_issues") or 0)
    nodes.append(_node("issues", "검증 이슈", issue_count, collection="issues"))

    request = job.request
    return {
        "run_id": run_id,
        "root": {
            "label": Path(request.root).name if request and request.root else run_id,
            "mode": request.mode if request else None,
            "status": job.status,
        },
        "nodes": nodes,
    }


def build_run_issues(store: RunJobStore, run_id: str) -> dict[str, Any]:
    """Normalize validation issues for the tree's "검증 이슈" collection.

    Rows mirror the canonical ``validation_issues`` formula: step warnings
    (already normalized in ``processing.warnings``) plus per-parser error
    entries from each ``artifacts_*`` output's ``parser_errors`` list.
    """
    job = get_job(store, run_id)
    if job.summary is None:
        raise HTTPException(status_code=409, detail="run is not completed")

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
