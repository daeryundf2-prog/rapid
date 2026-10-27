"""Korean label hints for the ai-agent kind (R7 stage 3.5).

The console (lane D) maps raw values to Korean through its value-label tables; these are the
hints it starts from, one table per raw-value column. Product names (``tool_label``) stay as
written by the vendor.
"""

from __future__ import annotations

__all__ = [
    "ARTIFACT_TYPE_LABELS_KO",
    "CATEGORY_LABELS_KO",
    "COVERAGE_STATUS_LABELS_KO",
    "CREDENTIAL_KIND_LABELS_KO",
    "EXECUTION_SOURCE_LABELS_KO",
    "INSTALL_KIND_LABELS_KO",
    "KIND_LABEL_KO",
    "MODEL_LOCATION_LABELS_KO",
    "TIMESTAMP_KIND_LABELS_KO",
    "label_ko",
]

KIND_LABEL_KO = "AI 사용 기록"

ARTIFACT_TYPE_LABELS_KO: dict[str, str] = {
    "ai-tool-presence": "AI 도구 존재·설치",
    "ai-credential-presence": "AI 자격 증명 파일 존재(값 미수집)",
    "unknown-ai-tool-candidate": "미분류 AI 도구 후보",
    "ai-model-file": "AI 모델 파일",
    "ai-agent-session": "AI 에이전트 세션",
    "ai-agent-message": "AI 에이전트 메시지",
    "ai-agent-tool-call": "AI 도구 호출",
    "ai-agent-file-touch": "AI 파일 접촉",
    "ai-mcp-server": "MCP 서버",
    "ai-instruction-file": "AI 지침·메모리 파일",
    "ai-account": "AI 계정",
    "ai-code-attribution": "AI 코드 기여",
    "ai-usage-stat": "AI 사용량",
    "ai-agent-parse-error": "AI 기록 읽기 오류",
}
INSTALL_KIND_LABELS_KO: dict[str, str] = {
    "path": "경로 흔적",
    "npm-global": "npm 전역 패키지",
    "pip": "pip 패키지",
    "winget": "winget 패키지",
    "msix": "MSIX 앱 패키지",
    "vscode-extension": "편집기 확장",
    "execution": "실행 흔적",
}
COVERAGE_STATUS_LABELS_KO: dict[str, str] = {
    "local-verified": "실물 확인 경로",
    "official": "공식 문서 근거",
    "third-party": "외부 자료 근거",
    "inferred": "추정 경로",
    "unverified": "미검증",
    "schema-not-validated": "구조 미검증",
}
CATEGORY_LABELS_KO: dict[str, str] = {
    "chatbot": "챗봇",
    "cli_agent": "CLI 코딩 에이전트",
    "ide_agent": "IDE 에이전트",
    "harness": "하니스·확장",
    "cloud_agent": "클라우드 에이전트",
    "local_llm": "로컬 LLM",
}
CREDENTIAL_KIND_LABELS_KO: dict[str, str] = {
    "catalog-credential": "카탈로그 자격 증명 경로",
    "name-pattern": "이름 패턴(토큰·OAuth·쿠키·비밀)",
}
EXECUTION_SOURCE_LABELS_KO: dict[str, str] = {
    "prefetch": "Prefetch",
    "amcache": "Amcache",
    "shimcache": "ShimCache",
    "srum": "SRUM",
    "bam": "BAM",
    "userassist": "UserAssist",
    "pca": "PCA",
    "feature-usage": "FeatureUsage",
    "windows-execution": "실행 흔적",
}
MODEL_LOCATION_LABELS_KO: dict[str, str] = {
    "model-folder": "도구 모델 폴더",
    "user-folder": "사용자 폴더",
}
TIMESTAMP_KIND_LABELS_KO: dict[str, str] = {
    "modified": "수정 시각",
    "executed": "마지막 실행 시각",
}
_TABLES: dict[str, dict[str, str]] = {
    "artifact_type": ARTIFACT_TYPE_LABELS_KO,
    "install_kind": INSTALL_KIND_LABELS_KO,
    "coverage_status": COVERAGE_STATUS_LABELS_KO,
    "category": CATEGORY_LABELS_KO,
    "credential_kind": CREDENTIAL_KIND_LABELS_KO,
    "execution_source": EXECUTION_SOURCE_LABELS_KO,
    "location": MODEL_LOCATION_LABELS_KO,
    "timestamp_kind": TIMESTAMP_KIND_LABELS_KO,
}


def label_ko(column: str, value: object) -> str:
    """Korean label of a raw ``column`` value (the raw value when no hint exists)."""
    text = str(value or "")
    return _TABLES.get(column, {}).get(text, text)
