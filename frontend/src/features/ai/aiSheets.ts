/**
 * 메타 tab 핵심 sections of the AI rows (R7 단계 3.5 갈래 D): what an examiner reads first —
 * session (도구 · 제목 · 시각 · 계정 · 모델 · 토큰 · 작업 폴더 · Git), message, tool call, file
 * touch, MCP server, credential file (no value), account. Every other key stays listed below.
 */

import type { FieldDef, FieldSheet } from "../viewer/fieldSheets";

const time = (key: FieldDef["key"], label: string, timeKind: string): FieldDef => ({
  key,
  label,
  format: "time",
  timeKind,
});

const TOOL: FieldDef = { key: ["tool_label", "tool"], label: "도구" };
const ACCOUNT: FieldDef = { key: ["account_key", "user"], label: "계정" };
const SESSION: FieldDef = { key: "session_id", label: "세션 ID", format: "mono" };

export const AI_FIELD_SHEETS: readonly FieldSheet[] = [
  {
    id: "ai-agent-session",
    label: "AI 에이전트 세션",
    types: ["ai-agent-session"],
    core: [
      TOOL,
      { key: ["title", "preview"], label: "제목" },
      time("started_at", "시작", "started"),
      time("ended_at", "종료", "ended"),
      ACCOUNT,
      { key: "tool_account_key", label: "도구 계정" },
      { key: ["model", "models"], label: "모델" },
      { key: "messages", label: "메시지 수", format: "number" },
      { key: "tool_calls", label: "도구 호출 수", format: "number" },
      { key: "tokens_in", label: "입력 토큰", format: "number" },
      { key: "tokens_out", label: "출력 토큰", format: "number" },
      { key: ["cwd", "project_label"], label: "작업 폴더", format: "path" },
      { key: "git_branch", label: "Git 브랜치" },
      { key: "git_origin", label: "Git 원격 저장소" },
      { key: ["permission_mode", "sandbox_mode"], label: "권한 모드" },
      { key: "parent_session_id", label: "상위 세션 ID", format: "mono" },
      SESSION,
    ],
    recordId: ["session_id"],
  },
  {
    id: "ai-agent-message",
    label: "AI 에이전트 메시지",
    types: ["ai-agent-message"],
    core: [
      TOOL,
      { key: "role", label: "역할" },
      time(["ts", "timestamp"], "시각", "message"),
      { key: "text", label: "본문" },
      { key: "tool_use_count", label: "도구 호출 수", format: "number" },
      { key: "seq", label: "순번", format: "number" },
      SESSION,
    ],
    recordId: ["session_id"],
  },
  {
    id: "ai-agent-tool-call",
    label: "AI 도구 호출",
    types: ["ai-agent-tool-call"],
    core: [
      TOOL,
      time(["ts", "timestamp"], "시각", "run"),
      { key: "tool_name", label: "호출 도구" },
      { key: "tool_kind", label: "호출 종류" },
      { key: "command", label: "명령", format: "mono" },
      { key: "target_path", label: "대상 경로", format: "path" },
      { key: "target_url", label: "대상 URL", format: "url" },
      { key: "destructive", label: "파괴적 작업" },
      { key: "approval", label: "승인" },
      { key: "exit_code", label: "종료 코드", format: "number" },
      SESSION,
    ],
    recordId: ["call_id", "session_id"],
  },
  {
    id: "ai-agent-file-touch",
    label: "AI 파일 접촉",
    types: ["ai-agent-file-touch"],
    core: [
      TOOL,
      time(["ts", "timestamp"], "시각", "observed"),
      { key: "op", label: "작업" },
      { key: "touched_path", label: "접촉 경로", format: "path" },
      { key: "exists_in_evidence", label: "증거에 있음" },
      { key: "op_source", label: "작업 판단 근거" },
      SESSION,
    ],
  },
  {
    id: "ai-mcp-server",
    label: "MCP 서버",
    types: ["ai-mcp-server"],
    core: [
      TOOL,
      { key: "server", label: "MCP 서버" },
      { key: "status", label: "상태" },
      { key: "transport", label: "연결 방식" },
      { key: "endpoint", label: "명령·주소", format: "mono" },
      { key: "tools", label: "도구 목록" },
    ],
  },
  {
    id: "ai-credential-presence",
    label: "AI 자격 증명 파일(값 미수집)",
    types: ["ai-credential-presence"],
    core: [
      TOOL,
      { key: "credential_kind", label: "자격 증명 종류" },
      { key: "key_name", label: "키 이름" },
      { key: "size", label: "크기", format: "bytes" },
      time(["file_mtime", "mtime"], "수정 시각", "modified"),
      { key: "value_collected", label: "값 수집" },
      { key: "hash_collected", label: "해시 수집" },
    ],
  },
  {
    id: "ai-account",
    label: "AI 계정",
    types: ["ai-account", "ai-account-switch"],
    core: [
      TOOL,
      { key: ["tool_account_key", "from_account"], label: "도구 계정" },
      { key: "org_label", label: "조직" },
      { key: "email_domain", label: "이메일 도메인" },
      { key: "active", label: "활성" },
      time(["first_seen", "ts"], "처음 확인", "added"),
      time("last_seen", "마지막 확인", "last-used"),
    ],
  },
  {
    id: "ai-other",
    label: "AI 사용 기록",
    prefixes: ["ai-"],
    types: ["unknown-ai-tool-candidate"],
    core: [TOOL, ACCOUNT, { key: "coverage_status", label: "근거 수준" }],
  },
];
