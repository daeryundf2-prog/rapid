// 접수 › 증거 › AI 사용 요약 (R7 AI 갈래 D, plan r7-ai-usage §3.5 / Q-AI10): tools by evidence source,
// accounts, period, sessions, tool calls, credential files (값 미수집), the 서버 측 증거 필요 tools and the
// retention warning — computed from the run's rows when the server has no gap report; hidden for a
// run without AI rows.

import { cleanup, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AI_SAMPLE_ROWS } from "../ai/aiSampleRows";
import { summarizeAiUsage } from "../ai/aiUsage";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { AiUsageBlock } from "./caseCards";

const COUNTS = {
  "ai-tool-presence": 83,
  "ai-agent-session": 28,
  "ai-agent-tool-call": 19,
  "ai-credential-presence": 35,
  "ai-account": 7,
};

function tree(counts: Record<string, number> | null) {
  const kinds = counts
    ? [
        {
          id: "artifacts:ai-agent",
          label: "AI 사용 기록",
          collection: "artifacts",
          kind: "ai-agent",
          count: Object.values(counts).reduce((a, b) => a + b, 0),
          artifact_type_counts: counts,
        },
      ]
    : [
        {
          id: "artifacts:browser",
          label: "브라우저",
          collection: "artifacts",
          kind: "browser",
          count: 3,
          artifact_type_counts: {},
        },
      ];
  return {
    run_id: "r1",
    root: {},
    nodes: [{ id: "artifacts", label: "아티팩트", count: 0, children: kinds }],
  };
}

function artifactsPage(call: { url: string }) {
  const params = new URL(call.url, "http://x").searchParams;
  const types = params.getAll("artifact_type");
  const rows = AI_SAMPLE_ROWS.filter((row) => types.includes(String(row.artifact_type)));
  return { artifacts: { "ai-agent": { artifacts: rows, total: rows.length } } };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("AiUsageBlock", () => {
  it("summarises the run's AI usage with links into the AI 사용 nodes", async () => {
    mockFetch({
      "GET /api/runs/r1/tree": tree(COUNTS),
      "GET /api/runs/r1/artifacts": artifactsPage,
    });
    renderWithQuery(<AiUsageBlock runId="r1" />);
    const block = await screen.findByTestId("case-ai-usage");
    await screen.findByTestId("ai-usage-facts");
    expect(within(block).getByTestId("ai-usage-tools").textContent).toMatch(/^\d+개/);
    expect(within(block).getByRole("link", { name: "AI 세션 28개 보기" }).getAttribute("href")).toBe(
      "#/case/r1/explore/artifacts/ai-agent?types=ai-agent-session",
    );
    expect(within(block).getByRole("link", { name: "AI 도구 호출 19건 보기" })).toBeTruthy();
    expect(within(block).getByTestId("ai-usage-credentials").textContent).toContain("값 미수집");
    expect(within(block).getByTestId("ai-usage-period").textContent).toMatch(/~/);
    expect(within(block).getByTestId("ai-usage-gap").textContent).toMatch(/도구|없음/);
    expect(within(block).getByTestId("ai-usage-retention").textContent).toContain("보존 정리 표식 1건");
    // No raw id (tool ids, types) on the card.
    expect(block.textContent).not.toMatch(/ai-agent|claude-code|ai-tool-presence/);
  });

  it("is hidden for a run without AI usage rows (nothing requested)", async () => {
    const { calls } = mockFetch({ "GET /api/runs/r1/tree": tree(null) });
    renderWithQuery(<AiUsageBlock runId="r1" />);
    await vi.waitFor(() => expect(calls.some((call) => call.url.includes("/tree"))).toBe(true));
    expect(screen.queryByTestId("case-ai-usage")).toBeNull();
    expect(calls.some((call) => call.url.includes("/artifacts"))).toBe(false);
  });
});

describe("summarizeAiUsage", () => {
  it("counts tools by source, accounts, credentials and the gap tools", () => {
    const rows = AI_SAMPLE_ROWS.filter((row) => row.artifact_type !== "ai-agent-session");
    const sessions = AI_SAMPLE_ROWS.filter((row) => row.artifact_type === "ai-agent-session");
    const summary = summarizeAiUsage({ rows, sessions });
    expect(summary.toolsBySource.session).toBeGreaterThan(0);
    expect(summary.credentialFiles).toBe(
      rows.filter((r) => r.artifact_type === "ai-credential-presence").length,
    );
    expect(summary.accountSwitches).toBe(rows.filter((r) => r.artifact_type === "ai-account-switch").length);
    expect(summary.periodFrom).toBeTruthy();
    // A tool with a session record is never a gap tool.
    const sessionTools = new Set(sessions.map((r) => (r.details as Record<string, unknown>).tool));
    expect(summary.gapTools.some((tool) => sessionTools.has(tool))).toBe(false);
    expect(summary.gapSource).toBe("computed");
  });

  it("uses the server's gap report when there is one", () => {
    const summary = summarizeAiUsage({
      rows: [],
      sessions: [],
      gap: {
        tools: [
          { tool: "chatgpt", local_evidence: false },
          { tool: "cursor", local_evidence: true },
        ],
      },
    });
    expect(summary.gapTools).toEqual(["chatgpt"]);
    expect(summary.gapSource).toBe("server");
  });
});
