/**
 * 메타 tab links of an AI agent row (R7 단계 3.5 갈래 D, plan §3.5): a session row opens its
 * 대화 보기 (messages as role bubbles, tool calls folded, file touches linked), its tool calls and
 * file touches, its parent session (sub-agent) and its sub-agent sessions; a message / tool call /
 * file touch row opens its session's 대화 보기 and the session row. Sub-agent families appear in
 * the 계열 tab once the run's family derivation relates them; the parent link works without it.
 */

import type { GridRow } from "../../contracts/collection";
import { type Route, serializeRoute } from "../../router";
import {
  aiConversationRoute,
  aiSessionId,
  aiSessionRowsRoute,
  aiSessionTypeRoute,
  fileTouchRoute,
  isAiChatRow,
  isAiSessionRow,
} from "./aiChat";

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function detailsOf(row: GridRow): Record<string, unknown> {
  const details = row.fields.details;
  return typeof details === "object" && details !== null && !Array.isArray(details)
    ? (details as Record<string, unknown>)
    : {};
}

interface LinkDef {
  id: string;
  label: string;
  route: Route;
  primary?: boolean;
  title?: string;
}

/** The links of one AI row (empty for other rows and AI rows without a session id). */
export function aiSessionLinks(row: GridRow | null, runId: string): LinkDef[] {
  if (!row || !runId || row.ref.collection !== "artifacts") return [];
  const session = aiSessionId(row);
  if (!session) return [];
  const details = detailsOf(row);
  if (isAiSessionRow(row)) {
    const links: LinkDef[] = [
      {
        id: "conversation",
        label: "대화 보기",
        route: aiConversationRoute(runId, session),
        primary: true,
        title: "이 세션의 메시지를 역할별 말풍선으로, 도구 호출을 접힌 블록으로 봅니다",
      },
      {
        id: "tool-calls",
        label: "도구 호출",
        route: aiSessionTypeRoute(runId, session, "ai-agent-tool-call"),
      },
      {
        id: "file-touches",
        label: "파일 접촉",
        route: aiSessionTypeRoute(runId, session, "ai-agent-file-touch"),
      },
    ];
    const parent = text(details.parent_session_id);
    if (parent) {
      links.push({
        id: "parent",
        label: "상위 세션",
        route: aiSessionRowsRoute(runId, parent),
        title: `상위 세션 ${parent}`,
      });
    }
    links.push({
      id: "children",
      label: "하위 에이전트 세션",
      route: aiSessionRowsRoute(runId, session, "parent_session_id"),
      title: "이 세션이 부모인 하위 에이전트(서브에이전트) 세션 목록",
    });
    return links;
  }
  if (!isAiChatRow(row)) return [];
  const links: LinkDef[] = [
    {
      id: "conversation",
      label: "세션 대화 보기",
      route: aiConversationRoute(runId, session),
      primary: true,
    },
    { id: "session", label: "세션 행", route: aiSessionRowsRoute(runId, session) },
  ];
  if (row.artifactType === "ai-agent-file-touch") {
    const route = fileTouchRoute(runId, {
      path: text(details.touched_path),
      locator: text(details.file_locator),
    });
    if (route) links.push({ id: "file", label: "파일 목록에서 찾기", route });
  }
  return links;
}

export function AiSessionLinks({ row, runId }: { row: GridRow | null; runId: string }) {
  const links = aiSessionLinks(row, runId);
  if (!links.length) return null;
  return (
    <nav className="meta-ai-links" aria-label="AI 세션 이동" data-testid="ai-session-links">
      {links.map((link) => (
        <a
          key={link.id}
          className={link.primary ? "button primary" : "button"}
          href={serializeRoute(link.route)}
          title={link.title}
          data-link={link.id}
        >
          {link.label}
        </a>
      ))}
    </nav>
  );
}
