// R7 AI 사용 기록 run options (갈래 D, plan r7-ai-usage §3.5): ai_bodies (default on) / ai_hash_dbs
// (default off) of kind ai-agent (plan group `ai`), sent as collector_options only when they differ
// from the defaults; the 처리 stage section shows the scope a run used.

import { cleanup, fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AiProcessSection, aiScopeText } from "../ai/AiProcessSection";
import { AiRunOptionsField } from "./AiRunOptionsField";
import { aiCollectorOptions, buildRunBody, DEFAULT_RUN_FORM, type RunForm } from "./runForm";
import { summarizeRunRequest } from "./runSummary";
import { mockFetch, renderWithQuery } from "./testUtils";

const PREVIEW = {
  mode: "fraud",
  groups: [
    { id: "files", label: "파일", skippable: false, default_on: true, tasks: [] },
    { id: "ai", label: "AI 사용 기록", skippable: true, default_on: true, tasks: [] },
  ],
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("AI 사용 기록 run options", () => {
  it("defaults: body unchanged (no collector_options)", () => {
    expect(DEFAULT_RUN_FORM.aiBodies).toBe(true);
    expect(DEFAULT_RUN_FORM.aiHashDbs).toBe(false);
    expect(buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e" })).not.toHaveProperty("collector_options");
  });

  it("sends collector_options for ai-agent when an option differs; not when the group is skipped", () => {
    const body = buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e", aiBodies: false });
    expect(body.collector_options).toEqual({ "ai-agent": { ai_bodies: false, ai_hash_dbs: false } });
    expect(aiCollectorOptions({ aiBodies: true, aiHashDbs: true })).toEqual({
      ai_bodies: true,
      ai_hash_dbs: true,
    });
    expect(
      buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e", aiHashDbs: true, skipGroups: ["ai"] }),
    ).not.toHaveProperty("collector_options");
    const rows = summarizeRunRequest(body as unknown as Record<string, unknown>);
    expect(rows.find((row) => row.key === "collector_options")?.value).toBe(
      "AI 사용 기록: 메시지 본문 수집 안 함(메타만) · 대형 DB 해시 안 함",
    );
  });

  it("the dialog field toggles both options; disabled with the reason while the group is skipped", async () => {
    mockFetch({ "GET /api/run-plan/preview": PREVIEW });
    let form: RunForm = { ...DEFAULT_RUN_FORM };
    const onChange = vi.fn((patch: Partial<RunForm>) => {
      form = { ...form, ...patch };
    });
    const view = renderWithQuery(<AiRunOptionsField form={form} onChange={onChange} />);
    const bodies = (await screen.findByLabelText(/메시지 본문 포함/)) as HTMLInputElement;
    expect(bodies.checked).toBe(true);
    fireEvent.click(bodies);
    expect(onChange).toHaveBeenLastCalledWith({ aiBodies: false });
    fireEvent.click(screen.getByLabelText(/대형 AI 데이터베이스 해시/));
    expect(onChange).toHaveBeenLastCalledWith({ aiHashDbs: true });
    view.unmount();
    renderWithQuery(
      <AiRunOptionsField form={{ ...DEFAULT_RUN_FORM, skipGroups: ["ai"] }} onChange={onChange} />,
    );
    expect(((await screen.findByLabelText(/메시지 본문 포함/)) as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByTestId("run-ai-options-skipped").textContent).toContain("AI 사용 기록");
  });

  it("the field is absent when the plan has no ai group", async () => {
    const { calls } = mockFetch({
      "GET /api/run-plan/preview": { mode: "fraud", groups: [PREVIEW.groups[0]] },
    });
    renderWithQuery(<AiRunOptionsField form={DEFAULT_RUN_FORM} onChange={() => {}} />);
    await vi.waitFor(() => expect(calls.length).toBeGreaterThan(0));
    expect(screen.queryByTestId("run-ai-options")).toBeNull();
  });

  it("처리 › AI 사용 기록: state, scope and rows of the run", async () => {
    expect(aiScopeText(undefined)).toContain("기본값");
    mockFetch({
      "GET /api/runs/r1/tree": {
        run_id: "r1",
        root: {},
        nodes: [
          {
            id: "artifacts:ai-agent",
            label: "AI 사용 기록",
            collection: "artifacts",
            kind: "ai-agent",
            count: 12,
            artifact_type_counts: { "ai-agent-session": 3, "ai-agent-parse-error": 1, "ai-tool-presence": 8 },
          },
        ],
      },
    });
    renderWithQuery(
      <AiProcessSection
        runId="r1"
        plan={{
          run_id: "r1",
          run_status: "completed",
          counts: {} as never,
          groups: [
            {
              id: "ai",
              label: "AI 사용 기록",
              status: "completed",
              skippable: true,
              counts: {} as never,
              duration_ms: 2500,
              tasks: [],
            },
          ],
        }}
        request={{ collector_options: { "ai-agent": { ai_bodies: true, ai_hash_dbs: true } } }}
      />,
    );
    await vi.waitFor(() => expect(screen.getByTestId("process-ai-rows").textContent).toContain("12건"));
    expect(screen.getByTestId("process-ai-rows").textContent).toContain("읽기 오류 1건");
    expect(screen.getByTestId("process-ai-scope").textContent).toBe(
      "AI 사용 기록: 메시지 본문 포함(마스킹) · 대형 DB 해시 계산",
    );
    expect(screen.getByTestId("process-ai-status").textContent).toContain("2.5 초");
  });
});
