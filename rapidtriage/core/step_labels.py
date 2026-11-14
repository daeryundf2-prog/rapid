"""Korean run-step and run-mode names shared by the report templates (WB-10).

Mirrors ``frontend/src/features/stages/stepLabels.ts`` ``STEP_NAME_LABEL`` and
``frontend/src/app/collections.ts`` ``RUN_MODE_LABEL``. Report bodies show these names; the raw
step ids stay in the technical appendix template only (WB-8 P2-15).
"""

from __future__ import annotations

from .artifact_domains import ARTIFACT_DOMAIN_TABLE, DOMAIN_LABELS

#: Korean run-mode names (``frontend/src/app/collections.ts`` ``RUN_MODE_LABEL``).
RUN_MODE_KO = {
    "fraud": "문서·부정 조사",
    "seizure": "전수 수집",
    "hacking": "침해사고",
    "recovery": "복구",
    "quick": "빠른 선별",
}
#: Korean run-step names (``frontend/src/features/stages/stepLabels.ts`` ``STEP_NAME_LABEL``).
STEP_NAME_KO = {
    "fingerprint": "증거 지문(해시)",
    "artifacts": "아티팩트 수집",
    "carve": "카빙",
    "extract": "추출",
    "persist": "결과 저장",
    "report": "보고서 작성",
    "manifest": "증거 목록(매니페스트)",
    "docs": "문서 텍스트 추출",
    "docs-index": "문서 색인",
    "files": "파일 목록",
    "docs-extract": "문서 추출",
    "files-extract": "파일 추출",
    "timeline": "타임라인",
    "indicators": "지표 요약",
    "silent-failure-detector": "누락 위험 점검",
    "triage": "분류",
    "prepare": "준비",
    "finalize": "마무리",
    "triage-flags": "특이사항",
    "derived": "통합 보기",
    "case-db": "케이스 DB",
}
#: Artifact kind -> Korean evidence-tree domain label (``core.artifact_domains`` kind defaults).
KIND_DOMAIN_KO = {kind: DOMAIN_LABELS[domain] for domain, kind, types in ARTIFACT_DOMAIN_TABLE if types is None}


def run_mode_ko(mode: object) -> str:
    """Korean run-mode name; ``기타 모드`` for an unknown id (never the raw id)."""
    key = str(mode or "").strip().lower()
    if not key:
        return "기록 없음"
    return RUN_MODE_KO.get(key, "기타 모드")


def step_name_ko(name: object) -> str:
    """Korean name of a run step; never the raw step id (``artifacts-<kind>`` -> the kind's domain)."""
    key = str(name or "").strip().lower()
    if key in STEP_NAME_KO:
        return STEP_NAME_KO[key]
    if key.startswith("artifacts-"):
        domain = KIND_DOMAIN_KO.get(key[len("artifacts-") :])
        return f"아티팩트 수집: {domain}" if domain else "아티팩트 수집: 기타 종류"
    return "기타 단계"


#: Korean names of a bookmark's source collection (``core.case.CASE_SOURCE_ROWS`` commands and
#: ``api.app.search.normalize_bookmark_source`` values) for report "출처" columns (T-026).
SOURCE_NAME_KO = {
    "files": "파일 목록",
    "docs": "문서 검색",
    "artifacts": "아티팩트",
    "artifact": "아티팩트",
    "timeline": "타임라인",
    "indicators": "지표 요약",
    "compare": "비교",
}


def source_name_ko(source: object) -> str:
    """Korean name of a bookmark source; ``artifacts_<kind>`` / ``artifacts:<kind>`` -> the kind's
    domain; ``기타 출처`` for an unknown id (never the raw id)."""
    key = str(source or "").strip().lower()
    if key in SOURCE_NAME_KO:
        return SOURCE_NAME_KO[key]
    for prefix in ("artifacts_", "artifacts:"):
        if key.startswith(prefix):
            domain = KIND_DOMAIN_KO.get(key[len(prefix) :].strip())
            return f"아티팩트: {domain}" if domain else "아티팩트: 기타 종류"
    return "기타 출처" if key else ""
