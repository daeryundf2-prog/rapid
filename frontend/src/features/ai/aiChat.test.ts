/**
 * R7 AI 사용 (갈래 D) viewer: a session's 대화 보기 (ChatView model) — role bubbles from the
 * session's messages, tool calls as folded blocks, file touches as file-list links — the session
 * links of the 메타 tab, and the Korean 메타 labels of an AI row (no raw value).
 */
import { describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { parseHash, serializeRoute } from "../../router";
import { COLLECTIONS } from "../grid/columns/index";
import { recordLayout, valueReading } from "../viewer/fieldSheets";
import { viewDisabledReason } from "../views/availability";
import { groupConversations } from "../views/chat";
import { aiSessionLinks } from "./AiSessionLinks";
import { aiConversationRoute, fileTouchRoute, requestedSession } from "./aiChat";
import { AI_SAMPLE_ROWS } from "./aiSampleRows";

const rows: GridRow[] = AI_SAMPLE_ROWS.map((raw, i) =>
  COLLECTIONS.artifacts.mapRow({ ...raw, _kind: "ai-agent", _index: i }, i, {
    ref: { id: "artifacts", kind: "ai-agent" },
  }),
);
const ofType = (type: string) => rows.filter((row) => row.artifactType === type);

describe("AI session conversation (대화 보기)", () => {
  it("is available on the ai-agent kind", () => {
    expect(viewDisabledReason("chat", { id: "artifacts", kind: "ai-agent" })).toBeUndefined();
  });

  it("groups messages, tool calls and file touches by session; the session row names it", () => {
    const conversations = groupConversations(rows);
    const main = conversations.find((c) => c.id === "sess-A");
    expect(main).toBeDefined();
    const session = ofType("ai-agent-session").find(
      (row) => (row.fields.details as Record<string, unknown>).session_id === "sess-A",
    );
    if (session) expect(main?.label).toContain("Claude Code");
    const variants = new Set(main?.messages.map((m) => m.ai?.variant));
    expect(variants.has("message")).toBe(true);
    // Session rows are names, never bubbles.
    expect(main?.messages.some((m) => m.row.artifactType === "ai-agent-session")).toBe(false);
    // Participants are roles of messages, not "도구 호출" blocks.
    expect(main?.participants).not.toContain("도구 호출");
    const user = main?.messages.find((m) => m.ai?.variant === "message" && m.sender === "사용자");
    expect(user?.outgoing).toBe(true);
    const assistant = main?.messages.find((m) => m.sender === "어시스턴트");
    if (assistant) expect(assistant.outgoing).toBe(false);
  });

  it("tool calls carry their command / target; file touches link to the file list", () => {
    const conversations = groupConversations(rows);
    const blocks = conversations.flatMap((c) => c.messages).filter((m) => m.ai?.variant === "tool");
    expect(blocks.length).toBeGreaterThan(0);
    expect(blocks.every((m) => m.ai?.toolName && m.text)).toBe(true);
    expect(blocks.some((m) => m.ai?.command || m.ai?.targetPath)).toBe(true);
    const files = conversations.flatMap((c) => c.messages).filter((m) => m.ai?.variant === "file");
    expect(files.length).toBeGreaterThan(0);
    const route = fileTouchRoute("r1", { path: "C:\\Users\\u1\\proj\\app.py" });
    expect(route).toEqual({ runId: "r1", collection: "files", path: "app.py" });
    expect(fileTouchRoute("r1", { path: "x", locator: "E:\\evidence\\a\\b.txt" })?.path).toBe(
      "E:\\evidence\\a\\b.txt",
    );
  });

  it("the conversation route survives the URL and names the session it opens", () => {
    const route = aiConversationRoute("r1", "sess-A");
    const back = parseHash(serializeRoute(route));
    expect(back.view).toBe("chat");
    expect(back.kind).toBe("ai-agent");
    expect(back.types).toContain("ai-agent-message");
    expect(requestedSession(back.cf)).toBe("sess-A");
  });

  it("메타 links: a session row opens 대화 보기, its calls, touches and parent / sub-agents", () => {
    const sub = ofType("ai-agent-session").find(
      (row) => (row.fields.details as Record<string, unknown>).parent_session_id,
    );
    const top = ofType("ai-agent-session")[0] as GridRow;
    const ids = aiSessionLinks(top, "r1").map((link) => link.id);
    expect(ids).toEqual(expect.arrayContaining(["conversation", "tool-calls", "file-touches", "children"]));
    if (sub) expect(aiSessionLinks(sub, "r1").map((link) => link.id)).toContain("parent");
    const message = ofType("ai-agent-message")[0] as GridRow;
    expect(aiSessionLinks(message, "r1").map((link) => link.label)).toContain("세션 대화 보기");
    const touch = ofType("ai-agent-file-touch")[0] as GridRow;
    expect(aiSessionLinks(touch, "r1").map((link) => link.id)).toContain("file");
    // Other rows get no AI links.
    expect(aiSessionLinks(ofType("ai-tool-presence")[0] ?? null, "r1")).toEqual([]);
  });

  it("메타: a session's core fields read in Korean; enum values are labelled", () => {
    const session = ofType("ai-agent-session")[0] as GridRow;
    const layout = recordLayout(session);
    expect(layout.sheet.id).toBe("ai-agent-session");
    const labels = layout.core.map((entry) => entry.label);
    expect(labels).toEqual(expect.arrayContaining(["도구", "시작", "계정"]));
    expect(valueReading("ai-agent-message", "role", "assistant")).toBe("어시스턴트");
    expect(valueReading("ai-agent-tool-call", "tool_kind", "shell")).toBe("셸 명령");
    expect(valueReading("ai-agent-file-touch", "op", "workspace")).toBe("작업 폴더");
    expect(valueReading("ai-credential-presence", "value_collected", false)).toBe("수집 안 함");
    expect(valueReading("ai-tool-presence", "tool", "claude-code")).toBe("Claude Code");
    // Other kinds keep their own readings (AI tables apply to AI rows only).
    expect(valueReading("browser-history", "role", "user")).toBeUndefined();
  });
});
