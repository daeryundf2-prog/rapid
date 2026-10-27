/**
 * AI 사용 (R7 단계 3.5 갈래 D): Korean readings of the raw values of the `ai-agent` kind's rows
 * (plan docs/plans/r7-ai-usage-2026-10-27.md §3.3/§3.5). Starts from the backend hints
 * (rapidtriage/core/ai_catalog/labels.py) plus the values the session adapters write (갈래 B:
 * role, tool_kind, op, MCP status, credential / presence / instruction kinds). A value with no
 * reading is shown as written (the tooltip keeps the raw value) — never a guessed meaning.
 */

import { AI_TOOL_NAMES } from "./aiToolNames";

/** Every artifact type of the `ai-agent` kind (base.AI_ARTIFACT_TYPES + 갈래 B's two extra types). */
export const AI_TYPE_LABELS: Readonly<Record<string, string>> = {
  "ai-tool-presence": "AI 도구 흔적(설치·실행·경로)",
  "ai-credential-presence": "AI 자격 증명 파일(값 미수집)",
  "unknown-ai-tool-candidate": "미분류 AI 도구 후보",
  "ai-model-file": "AI 모델 파일",
  "ai-agent-session": "AI 에이전트 세션",
  "ai-agent-message": "AI 에이전트 메시지",
  "ai-agent-tool-call": "AI 도구 호출",
  "ai-agent-file-touch": "AI 파일 접촉",
  "ai-mcp-server": "MCP 서버",
  "ai-instruction-file": "AI 지침·메모리 파일",
  "ai-account": "AI 계정",
  "ai-account-switch": "AI 계정 전환",
  "ai-retention-cleanup": "AI 기록 보존 정리",
  "ai-code-attribution": "AI 코드 기여",
  "ai-usage-stat": "AI 사용량",
  "ai-agent-parse-error": "AI 기록 읽기 오류",
};

/** AI types other collectors write (browser exports, desktop AI app stores). */
export const OTHER_AI_TYPE_LABELS: Readonly<Record<string, string>> = {
  "ai-service-export-conversation": "AI 서비스 내보내기 대화",
  "desktop-ai-app-artifact": "데스크톱 AI 앱 파일",
  "local-llm-artifact": "로컬 LLM 앱 파일",
  "local-llm-prompt-candidate": "로컬 LLM 프롬프트 후보",
};

export const AI_TYPES: readonly string[] = Object.keys(AI_TYPE_LABELS);

export function isAiType(type: string | null | undefined): boolean {
  return Boolean(type && Object.hasOwn(AI_TYPE_LABELS, type));
}

/** Value domains of the AI rows (one table per raw-value column). */
export type AiValueDomain =
  | "role"
  | "toolKind"
  | "op"
  | "installKind"
  | "presenceKind"
  | "coverage"
  | "credentialKind"
  | "instructionKind"
  | "status"
  | "approval"
  | "transport"
  | "category"
  | "source"
  | "opSource"
  | "location";

export const AI_VALUE_LABELS: Readonly<Record<AiValueDomain, Readonly<Record<string, string>>>> = {
  /** `ai-agent-message.role`. */
  role: {
    user: "사용자",
    human: "사용자",
    assistant: "어시스턴트",
    model: "어시스턴트",
    agent: "에이전트",
    system: "시스템",
    developer: "개발자 지침",
    tool: "도구 결과",
    ledger: "작업 기록",
    summary: "요약",
  },
  /** `ai-agent-tool-call.tool_kind` (plan §3.3 kind). */
  toolKind: {
    shell: "셸 명령",
    read: "파일 읽기",
    write: "파일 쓰기",
    edit: "파일 편집",
    search: "검색",
    mcp: "MCP 도구",
    browser: "브라우저 조작",
    web: "웹 요청",
    task: "하위 에이전트",
    other: "기타",
  },
  /** `ai-agent-file-touch.op`. */
  op: {
    read: "읽기",
    write: "쓰기",
    edit: "편집",
    delete: "삭제",
    create: "생성",
    move: "이동",
    copy: "복사",
    list: "목록 보기",
    workspace: "작업 폴더",
  },
  /** `ai-tool-presence.install_kind` (labels.py INSTALL_KIND_LABELS_KO). */
  installKind: {
    path: "경로 흔적",
    "npm-global": "npm 전역 패키지",
    pip: "pip 패키지",
    winget: "winget 패키지",
    msix: "MSIX 앱 패키지",
    "vscode-extension": "편집기 확장",
    execution: "실행 흔적",
  },
  /** `ai-tool-presence.presence_kind` (session adapters: what the location is). */
  presenceKind: {
    "adapter-summary": "세션 저장소 요약",
    "tool-home": "도구 홈 폴더",
    "tool-data": "도구 데이터 폴더",
    database: "데이터베이스",
    settings: "설정 파일",
    "user-config": "사용자 설정",
    "ide-state": "편집기 상태 DB",
    "app-data": "앱 데이터 폴더",
    "app-log": "앱 로그",
    logs: "로그 폴더",
    "log-db": "로그 DB",
    "shell-snapshots": "셸 스냅샷",
    "live-session-marker": "실행 중 세션 표식",
    "git-worktrees": "Git 작업 트리 목록",
    "browser-extension-native-host": "브라우저 확장 연결 앱",
    "msix-package": "MSIX 앱 패키지",
    "account-config-copies": "계정 설정 사본",
    cache: "캐시",
    "memory-store": "메모리 저장소",
    "cloud-agents": "클라우드 에이전트 기록",
    "migration-backup": "이전·백업 사본",
    "raw-model-io": "모델 원시 입출력 로그",
    "bundled-cli": "내장 CLI",
    plugins: "플러그인",
    opencode: "OpenCode 폴더",
  },
  /** `coverage_status` (labels.py COVERAGE_STATUS_LABELS_KO). */
  coverage: {
    "local-verified": "실물 확인 경로",
    official: "공식 문서 근거",
    "third-party": "외부 자료 근거",
    inferred: "추정 경로",
    unverified: "미검증",
    "schema-not-validated": "구조 미검증",
    "parser-error": "읽기 오류",
  },
  /** `ai-credential-presence.credential_kind` — what kind of secret the file holds (value never read). */
  credentialKind: {
    "catalog-credential": "카탈로그 자격 증명 경로",
    "name-pattern": "이름 패턴(토큰·OAuth·쿠키·비밀)",
    "auth-status": "인증 상태",
    "auth-file": "인증 파일",
    "auth-token": "인증 토큰",
    "oauth-credentials": "OAuth 자격 증명",
    "oauth-token": "OAuth 토큰",
    "session-key": "세션 키",
    "session-tokens": "세션 토큰",
    "ssh-tokens": "SSH 원격 토큰",
    "browser-cookies": "브라우저 쿠키",
    "encrypted-account-credential": "암호화된 계정 자격 증명",
    "sandbox-secrets": "샌드박스 비밀",
    "mcp-oauth": "MCP OAuth 잠금",
    "secret-storage": "비밀 저장소 항목",
    "credential-file": "자격 증명 파일",
  },
  /** `ai-instruction-file.instruction_kind` (file names stay as written). */
  instructionKind: {
    "agent-artifact": "에이전트 산출물",
    skill: "스킬",
    "memory-db": "메모리 DB",
    "rollout-summary": "세션 요약",
    "pasted-text": "붙여 넣은 텍스트",
    steering: "지침(steering)",
    brief: "작업 개요",
    plan: "계획",
    rules: "규칙",
    memory: "메모리",
    settings: "설정",
  },
  /** `status` of sessions, tool calls and MCP servers. */
  status: {
    configured: "설정됨",
    connected: "연결됨",
    disconnected: "연결 끊김",
    failed: "실패",
    pending: "대기",
    "needs-auth": "인증 필요",
    cached: "도구 목록 캐시",
    used: "사용됨",
    completed: "완료",
    success: "성공",
    error: "오류",
    cancelled: "취소",
    running: "실행 중",
    active: "진행 중",
    done: "완료",
    idle: "대기 중",
    IDLE: "대기 중",
    archived: "보관됨",
    unverified: "미검증",
    "parser-error": "읽기 오류",
  },
  /** `ai-agent-tool-call.approval`. */
  approval: {
    approved: "승인",
    auto: "자동 승인",
    denied: "거부",
    rejected: "거부",
    pending: "승인 대기",
  },
  /** `ai-mcp-server.transport`. */
  transport: {
    stdio: "로컬 프로세스(stdio)",
    http: "HTTP",
    "streamable-http": "HTTP(스트리밍)",
    sse: "SSE",
    ws: "웹소켓",
  },
  /** `category` (labels.py CATEGORY_LABELS_KO). */
  category: {
    chatbot: "챗봇",
    cli_agent: "CLI 코딩 에이전트",
    ide_agent: "IDE 에이전트",
    harness: "하니스·확장",
    cloud_agent: "클라우드 에이전트",
    local_llm: "로컬 LLM",
  },
  /** `source` — where a row was read from: presence evidence class, or the store table / file. */
  source: {
    "catalog-path": "카탈로그 경로",
    "install:npm-global": "npm 전역 패키지",
    "install:pip": "pip 패키지",
    "install:winget": "winget 패키지",
    "install:msix": "MSIX 앱 패키지",
    "install:vscode-extension": "편집기 확장",
    "execution:prefetch": "실행 흔적(Prefetch)",
    "execution:amcache": "실행 흔적(Amcache)",
    "execution:shimcache": "실행 흔적(ShimCache)",
    "execution:srum": "실행 흔적(SRUM)",
    "execution:bam": "실행 흔적(BAM)",
    "execution:userassist": "실행 흔적(UserAssist)",
    "execution:pca": "실행 흔적(PCA)",
    "execution:feature-usage": "실행 흔적(FeatureUsage)",
    "execution:windows-execution": "실행 흔적",
    transcript: "대화 전사",
    "agent-message": "에이전트 메시지",
    "history.jsonl": "입력 기록(history.jsonl)",
    thread_timeline_ledger: "스레드 작업 기록",
    "threads.first_user_message": "스레드 첫 메시지",
    automation_runs: "자동화 실행 기록",
    "rollout-jsonl": "세션 전개 기록",
    "agent-transcripts": "에이전트 전사",
    chats: "대화 기록",
    "message+part": "메시지 표",
    input_history: "입력 기록",
    tool_usage: "도구 사용 표",
    tool_use: "도구 호출",
    attachment: "세션 첨부 상태",
    "mcp-tool-cache": "MCP 도구 캐시",
    "mcp-log": "MCP 로그",
    ai_code_hashes: "AI 코드 해시 표",
    scored_commits: "커밋 기여 점수 표",
    model_usage: "모델 사용량 표",
    "threads.tokens_used": "스레드 토큰 사용량",
    "plan-usage-history.json": "요금제 사용 기록",
    "git-trailer": "Git 커밋 트레일러",
    execution: "실행 흔적",
    install: "설치 흔적",
  },
  /** `ai-agent-file-touch.op_source` — how the path and operation were read. */
  opSource: {
    "tool-input": "도구 입력값",
    "command-heuristic": "명령 문자열에서 추정",
    workspace_uris: "작업 폴더 목록",
    "scratch-listing": "작업 공간 파일 목록",
    codeBlockDiff: "코드 변경 블록",
  },
  /** `ai-model-file.location` (labels.py MODEL_LOCATION_LABELS_KO). */
  location: {
    "model-folder": "도구 모델 폴더",
    "user-folder": "사용자 폴더",
  },
};

/** Korean reading of `raw` in `domain`, undefined when the table has none. */
export function aiValueReading(domain: AiValueDomain, raw: unknown): string | undefined {
  if (typeof raw !== "string" || !raw) return undefined;
  const table = AI_VALUE_LABELS[domain];
  return table[raw] ?? table[raw.toLowerCase()];
}

/** Display text: the reading, else the value as written. */
export function aiValueLabel(domain: AiValueDomain, raw: unknown): string {
  if (raw === null || raw === undefined) return "";
  return aiValueReading(domain, raw) ?? String(raw);
}

/** Record keys of AI rows whose values read through one domain (grid cells and the 메타 tab). */
export const AI_KEY_DOMAINS: Readonly<Record<string, AiValueDomain>> = {
  role: "role",
  tool_kind: "toolKind",
  op: "op",
  install_kind: "installKind",
  presence_kind: "presenceKind",
  coverage_status: "coverage",
  credential_kind: "credentialKind",
  instruction_kind: "instructionKind",
  status: "status",
  approval: "approval",
  transport: "transport",
  category: "category",
  source: "source",
  op_source: "opSource",
  location: "location",
};

/** Product name of a catalog tool id ("claude-code" → "Claude Code"); undefined when unknown. */
export function aiToolName(tool: unknown): string | undefined {
  return typeof tool === "string" && tool ? AI_TOOL_NAMES[tool] : undefined;
}

/**
 * The tool a row names: the adapter's own label (`tool_label`, e.g. "Claude (desktop)"), else the
 * catalog name of `tool`, else the value as written.
 */
export function aiToolDisplay(details: Record<string, unknown>): string {
  const label = typeof details.tool_label === "string" ? details.tool_label.trim() : "";
  const tool = typeof details.tool === "string" ? details.tool : "";
  if (label && label !== tool) return label;
  return aiToolName(tool) ?? (label || tool);
}

/** Korean value label of an AI row's record key (the 메타 tab), undefined when none applies. */
export function aiKeyValueLabel(
  type: string | null | undefined,
  key: string,
  raw: unknown,
): string | undefined {
  if (!isAiType(type)) return undefined;
  if (key === "tool") return aiToolName(raw);
  if (typeof raw === "boolean") {
    if (key === "destructive") return raw ? "파괴적 작업" : "파괴적 아님";
    if (key === "value_collected" || key === "hash_collected" || key === "content_collected")
      return raw ? "수집함" : "수집 안 함";
  }
  const domain = AI_KEY_DOMAINS[key];
  return domain ? aiValueReading(domain, raw) : undefined;
}

/** "예" / "아니오" / "" of a tri-state flag (`destructive`, `exists_in_evidence`, `active`). */
export function yesNo(value: unknown, yes = "예", no = "아니오"): string {
  if (value === true || value === 1 || value === "true") return yes;
  if (value === false || value === 0 || value === "false") return no;
  return "";
}
