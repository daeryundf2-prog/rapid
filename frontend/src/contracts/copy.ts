/**
 * UI copy dictionary (D.3, D65; T-157). Tests refer to on-screen Korean text by key instead of
 * repeating literals, so a wording change is one edit here. Accessible names that are part of the
 * user contract stay in `uiContract.ts` (A11Y_NAMES); this module is plain copy and may change.
 *
 * Source: the glossary of the R7/R8 plans (docs/plans/r8). T-361 moves the glossary itself into
 * `contracts/glossary.ts` and this module reads from it. Formatters return the exact text the UI
 * renders for a value; specs that need a pattern build it from them (`copyPattern`).
 */
type Value = number | string;
/** Numbers as the UI prints them (ko-KR grouping); strings pass through (pattern slots). */
const n = (value: Value) => (typeof value === "number" ? value.toLocaleString("ko-KR") : value);

/** Escape text for use inside a RegExp. */
export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * RegExp source for a formatter whose value varies: `copyPattern(COPY.tree.emptyShow)` →
 * `결과 없는 계열 \d+개 표시`. `slot` replaces the value (default: digits).
 */
export function copyPattern(format: (value: string) => string, slot = "\\d+"): string {
  const marker = "\u0001";
  return escapeRegExp(format(marker)).replace(marker, slot);
}

export const COPY = {
  common: {
    countUnit: "건",
    count: (value: Value) => `${n(value)}건`,
    total: (value: Value) => `총 ${n(value)}건`,
    delete: "삭제",
    name: "이름",
    shortcut: "단축키",
    more: "더보기",
    /** Tree node / link name: `label, n건`. */
    countedNode: (label: string, value: Value) => `${label}, ${n(value)}건`,
  },
  filter: {
    /** Condition line (search landmark), panel dialog and its heading. */
    title: "조건",
    applied: "적용된 조건",
    columnSet: "열 구성",
    density: "밀도",
    flags: "특이사항",
    removeChip: (chip: string) => `${chip} 조건 제거`,
    pathChip: (value: string) => `경로 ${value}`,
    flagGradeChip: (grade: string) => `특이사항 ${grade} 이상`,
  },
  grid: {
    itemColumn: "항목",
    summaryColumn: "주요 세부 정보",
    timeColumn: "날짜 및 시각",
    flagCell: (grade: string) => `특이사항 ${grade} `,
    notCollected: "수집 안 함",
    thumbnails: "썸네일 격자",
  },
  tree: {
    name: "케이스 탐색 트리",
    search: "트리 검색",
    gradeAtLeast: (grade: string) => `${grade} 등급 이상`,
    emptyShow: (count: Value) => `결과 없는 계열 ${count}개 표시`,
    emptyHide: (count: Value) => `결과 없는 계열 ${count}개 숨김`,
    family: { location: "위치·여행" },
  },
  viewer: {
    region: "원본 뷰어",
    bottomPanel: "뷰어 패널 (아래)",
    windowTitle: (title: string) => `뷰어 — ${title}`,
    poppedOut: "창으로 보는 중 · 되돌리기",
    tabMeta: "메타",
    tabImage: "이미지",
    metaTail: ["소스", "복구 방법", "삭제된 출처", "위치", "증거 번호", "파서 버전", "원본 행"],
    relatedMedia: (count: Value) => `관련 미디어 ${count}`,
  },
  review: {
    relevant: "관련 있음",
    markDescription: (label: string) => `검토 표시: ${label}`,
    manageTags: "태그 관리",
    manageTagsOpener: "태그 관리…",
    newTag: "새 태그",
    deleteTag: (tag: string) => `${tag} 태그 삭제`,
    deleteTagConfirm: "태그 삭제 확인",
    tagNode: (tag: string, key: string, count: Value) => `${tag}, 단축키 ${key}, ${n(count)}건`,
    colors: { red: "빨강", green: "초록", purple: "보라" },
    propagateOnly: (tag: string) => `'${tag}'만 전파`,
    propagateByHash: (tags: string) => `같은 해시 행에 태그 전파 (${tags})`,
    propagated: (count: Value, tag: string) =>
      `같은 해시 행 ${n(count)}건에 태그 '${tag}'을(를) 전파했습니다`,
  },
  histogram: {
    saveBaseline: "현재 건수를 기준선으로 저장…",
    baselineName: "기준선 이름",
    compareRow: (delta: Value) => `증감 ${delta}, 노드 열기`,
  },
  ai: {
    domain: "AI 사용",
    nodes: {
      sessions: "세션",
      messages: "메시지",
      toolCalls: "도구 호출",
      fileTouches: "파일 접촉",
      mcpServers: "MCP 서버",
      instructionFiles: "지침·메모리 파일",
      credentialPresence: "자격 증명 존재(값 없음)",
      accounts: "계정·전환",
      codeContribution: "AI 코드 기여",
      usage: "사용량",
      retention: "보존 정리",
      tools: "도구·설치",
      pathTraces: "경로 흔적(카탈로그 경로)",
      installTraces: "설치 흔적(npm·pip·winget·MSIX·확장)",
    },
    columns: { tool: "도구", start: "시작", end: "종료", messages: "메시지", toolCalls: "도구 호출" },
    subAgents: (count: Value) => `하위 ${count}개`,
    roleUser: "사용자",
    openChat: "대화 보기",
    subAgentSessions: "하위 에이전트 세션",
    findInFiles: "파일 목록에서 찾기",
    sessionsLink: (count: Value) => `AI 세션 ${count}개 보기`,
    valueNotCollected: "값 미수집",
    messageBody: "메시지 본문",
  },
} as const;
