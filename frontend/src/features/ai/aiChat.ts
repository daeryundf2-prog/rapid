/**
 * 대화 보기 of AI agent sessions (R7 단계 3.5 갈래 D, plan §3.5): `ai-agent-message` rows become
 * role bubbles of their session (`session_id` = the conversation), `ai-agent-tool-call` rows folded
 * blocks (호출 도구 · 명령 / 대상), `ai-agent-file-touch` rows links to the file list. Session rows
 * name the conversations (제목 · 도구) and are not bubbles themselves. Pure.
 */

import type { GridRow } from "../../contracts/collection";
import type { Route } from "../../router";
import { aiToolDisplay, aiValueLabel } from "./aiLabels";

type Details = Record<string, unknown>;

/** Row types the conversation view draws for an AI session (bubbles, tool blocks, file links). */
export const AI_CHAT_TYPES = ["ai-agent-message", "ai-agent-tool-call", "ai-agent-file-touch"] as const;
/** The types a session's 대화 보기 route requests (the session rows name the conversations). */
export const AI_CONVERSATION_TYPES = ["ai-agent-session", ...AI_CHAT_TYPES] as const;

const text = (value: unknown): string =>
  typeof value === "string" ? value.trim() : typeof value === "number" ? String(value) : "";

function detailsOf(row: GridRow): Details {
  const details = row.fields.details;
  return typeof details === "object" && details !== null && !Array.isArray(details)
    ? (details as Details)
    : {};
}

export function isAiChatRow(row: GridRow): boolean {
  return (AI_CHAT_TYPES as readonly string[]).includes(row.artifactType ?? "");
}

export function isAiSessionRow(row: GridRow): boolean {
  return row.artifactType === "ai-agent-session";
}

export function aiSessionId(row: GridRow | null | undefined): string {
  return row ? text(detailsOf(row).session_id) : "";
}

/** What a bubble of an AI session shows besides the text. */
export interface AiBubble {
  variant: "message" | "tool" | "file";
  /** 역할 (사용자 / 어시스턴트 …) of a message; "도구 호출" / "파일 접촉" otherwise. */
  roleLabel: string;
  /** Tool calls: 호출 도구 and its kind ("Bash · 셸 명령"). */
  toolName?: string;
  toolKind?: string;
  /** Tool calls: the masked command, else the target path / URL / search pattern. */
  command?: string;
  targetPath?: string;
  destructive?: boolean;
  exitCode?: number;
  /** File touches: 작업 (읽기 / 편집 …) and the path the tool named. */
  op?: string;
  path?: string;
  /** The evidence file (`file_locator`) when the adapter matched one. */
  locator?: string;
}

/** Files-list route of a touched path: the evidence file when known, else its file name. */
export function fileTouchRoute(runId: string, bubble: Pick<AiBubble, "path" | "locator">): Route | null {
  const target = bubble.locator || bubble.path || "";
  if (!runId || !target) return null;
  const name = bubble.locator ? bubble.locator : (target.split(/[\\/]/).filter(Boolean).pop() ?? target);
  return { runId, collection: "files", path: name };
}

/** The bubble of an AI chat row (message / tool call / file touch). */
export function aiBubble(row: GridRow): AiBubble {
  const details = detailsOf(row);
  if (row.artifactType === "ai-agent-tool-call") {
    const exit = details.exit_code;
    return {
      variant: "tool",
      roleLabel: "도구 호출",
      toolName: text(details.tool_name) || text(details.mcp_tool) || "도구",
      toolKind: aiValueLabel("toolKind", details.tool_kind),
      command: text(details.command) || text(details.target_url) || text(details.pattern),
      targetPath: text(details.target_path),
      ...(details.destructive === true ? { destructive: true } : {}),
      ...(typeof exit === "number" ? { exitCode: exit } : {}),
    };
  }
  if (row.artifactType === "ai-agent-file-touch") {
    return {
      variant: "file",
      roleLabel: "파일 접촉",
      op: aiValueLabel("op", details.op),
      path: text(details.touched_path),
      locator: text(details.file_locator),
      toolName: text(details.tool_name),
    };
  }
  return { variant: "message", roleLabel: aiValueLabel("role", details.role) || "메시지" };
}

/** Message fields of an AI chat row (the shape chat.ts builds for messenger rows). */
export function aiChatFields(row: GridRow): {
  conversationId: string;
  conversationLabel: string;
  service: string;
  sender: string;
  timestamp: string | null;
  text: string;
  outgoing: boolean;
  ai: AiBubble;
} {
  const details = detailsOf(row);
  const bubble = aiBubble(row);
  const session = text(details.session_id) || "세션 미상";
  const role = text(details.role).toLowerCase();
  const body =
    bubble.variant === "message"
      ? text(details.text) || (details.text_bytes ? "(본문 미수집 — 메타만 수집한 런)" : "(본문 없음)")
      : bubble.variant === "tool"
        ? [bubble.toolName, bubble.toolKind].filter(Boolean).join(" · ")
        : [bubble.op, bubble.path].filter(Boolean).join(" · ");
  return {
    conversationId: session,
    conversationLabel: `${aiToolDisplay(details) || "AI"} 세션 ${session}`,
    service: aiToolDisplay(details),
    sender: bubble.roleLabel,
    timestamp: text(details.ts) || text(details.timestamp) || row.timestamp || null,
    text: body,
    // The examiner's subject typed it: drawn on the right like an outgoing message.
    outgoing: bubble.variant === "message" && (role === "user" || role === "human"),
    ai: bubble,
  };
}

/** Conversation names from the session rows: "<제목> · <도구>" by session id. */
export function aiSessionLabels(rows: readonly GridRow[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const row of rows) {
    if (!isAiSessionRow(row)) continue;
    const details = detailsOf(row);
    const id = text(details.session_id);
    if (!id) continue;
    const title = text(details.title) || text(details.preview) || `세션 ${id}`;
    const parent = text(details.parent_session_id);
    out.set(id, [title, aiToolDisplay(details), parent ? "하위 에이전트" : ""].filter(Boolean).join(" · "));
  }
  return out;
}

/**
 * 대화 보기 route of a session (and its sub-agent sessions, whose ids extend it): the AI 사용 rows
 * of that session in the conversation view; the view opens the exact session first.
 */
export function aiConversationRoute(runId: string, sessionId: string): Route {
  return {
    runId,
    collection: "artifacts",
    kind: "ai-agent",
    types: [...AI_CONVERSATION_TYPES],
    view: "chat",
    cf: [{ col: "f:session_id", op: ":", value: sessionId }],
  };
}

/** Route of the session rows of `sessionId` (its 세션 row, plus sub-agents whose ids extend it). */
export function aiSessionRowsRoute(runId: string, sessionId: string, field = "session_id"): Route {
  return {
    runId,
    collection: "artifacts",
    kind: "ai-agent",
    types: ["ai-agent-session"],
    cf: [{ col: `f:${field}`, op: ":", value: sessionId }],
    cols: [`details.${field}`],
  };
}

/** Route of one AI type's rows of a session (도구 호출 / 파일 접촉 of this session). */
export function aiSessionTypeRoute(runId: string, sessionId: string, type: string): Route {
  return {
    runId,
    collection: "artifacts",
    kind: "ai-agent",
    types: [type],
    cf: [{ col: "f:session_id", op: ":", value: sessionId }],
  };
}

/** The exact session id a conversation route asks for (`cf=f:session_id:<id>`), else "". */
export function requestedSession(cf: ReadonlyArray<{ col: string; value: string }> | undefined): string {
  return cf?.find((filter) => filter.col === "f:session_id")?.value ?? "";
}
