// R7 AI 사용 기록 run options (갈래 D, plan r7-ai-usage §3.5; r8 T-191): ai_bodies (default on) and
// org_email_domain / evidence_roots / ai_read_mb of kind ai-agent (plan group `ai`), sent as
// collector_options only when they differ from the defaults; ai_hash_dbs is hidden (read nowhere,
// T-320); the 처리 stage section shows the scope a run used.

import { cleanup, fireEvent, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AiProcessSection, aiScopeText } from "../ai/AiProcessSection";
import { AiRunOptionsField } from "./AiRunOptionsField";
import { RunDialog } from "./RunDialog";
import { aiCollectorOptions, buildRunBody, DEFAULT_RUN_FORM, type RunForm, validateRunForm } from "./runForm";
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
    expect(DEFAULT_RUN_FORM).not.toHaveProperty("aiHashDbs");
    expect(buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e" })).not.toHaveProperty("collector_options");
  });

  it("sends collector_options for ai-agent when an option differs; not when the group is skipped", () => {
    const body = buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e", aiBodies: false });
    expect(body.collector_options).toEqual({ "ai-agent": { ai_bodies: false } });
    const filled = {
      aiOrgDomain: " corp.example ",
      aiEvidenceRoots: "D:\\case\\a\n\n E:\\b ",
      aiReadMb: "512",
    };
    expect(aiCollectorOptions(filled)).toEqual({
      org_email_domain: "corp.example",
      evidence_roots: ["D:\\case\\a", "E:\\b"],
      ai_read_mb: 512,
    });
    expect(
      buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e", ...filled, skipGroups: ["ai"] }),
    ).not.toHaveProperty("collector_options");
    const rows = summarizeRunRequest(body as unknown as Record<string, unknown>);
    expect(rows.find((row) => row.key === "collector_options")?.value).toBe(
      "AI 사용 기록: 메시지 본문 수집 안 함(메타만)",
    );
    // The read budget is validated before the run starts (1 .. 1 TiB in MiB); empty = default.
    expect(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e", aiReadMb: "0" }).aiReadMb).toContain(
      "AI 읽기 예산",
    );
    expect(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e", aiReadMb: "abc" }).aiReadMb).toBeDefined();
    expect(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e", aiReadMb: "4096" }).aiReadMb).toBeUndefined();
  });

  it("the dialog field: 본문 + 3 inputs, no dead hash checkbox; disabled while the group is skipped", async () => {
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
    // ai_hash_dbs is read nowhere (T-320): its checkbox is hidden.
    expect(screen.queryByLabelText(/해시/)).toBeNull();
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
    fireEvent.change(screen.getByLabelText(/조직 이메일 도메인/), { target: { value: "corp.example" } });
    expect(onChange).toHaveBeenLastCalledWith({ aiOrgDomain: "corp.example" });
    fireEvent.change(screen.getByLabelText(/사건 증거 폴더/), { target: { value: "D:\\case" } });
    expect(onChange).toHaveBeenLastCalledWith({ aiEvidenceRoots: "D:\\case" });
    fireEvent.change(screen.getByLabelText(/AI 읽기 예산/), { target: { value: "256" } });
    expect(onChange).toHaveBeenLastCalledWith({ aiReadMb: "256" });
    view.unmount();
    renderWithQuery(
      <AiRunOptionsField form={{ ...DEFAULT_RUN_FORM, skipGroups: ["ai"] }} onChange={onChange} />,
    );
    expect(((await screen.findByLabelText(/메시지 본문 포함/)) as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByTestId("run-ai-options-skipped").textContent).toContain("AI 사용 기록");
  });

  it("RunDialog: the 3 inputs ride in collector_options; a bad domain shows the server's sentence", async () => {
    const serverError = "ai-agent.org_email_domain은 이메일 도메인(예: example.com)이어야 합니다";
    const { calls } = mockFetch({
      "GET /api/run-plan/preview": PREVIEW,
      "GET /api/collect-profiles": { profiles: [] },
      "POST /api/runs": new Response(JSON.stringify({ detail: serverError }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }),
    });
    renderWithQuery(<RunDialog runIsActive={false} onClose={() => {}} />);
    fireEvent.change(await screen.findByLabelText(/조직 이메일 도메인/), {
      target: { value: "not a domain" },
    });
    fireEvent.change(screen.getByLabelText(/사건 증거 폴더/), { target: { value: "D:\\case\\evidence" } });
    fireEvent.change(screen.getByLabelText(/AI 읽기 예산/), { target: { value: "1024" } });
    fireEvent.change(screen.getByLabelText(/증거 경로/), { target: { value: "D:/case/img.E01" } });
    fireEvent.change(screen.getByLabelText(/^출력 폴더/), { target: { value: "D:/out/run1" } });
    fireEvent.click(screen.getByRole("button", { name: "실행" }));
    await screen.findByText(new RegExp(serverError.replace(/[().]/g, "\\$&")));
    const post = calls.find((c) => c.method === "POST" && c.url.startsWith("/api/runs"));
    expect((post?.body as Record<string, unknown> | undefined)?.collector_options).toEqual({
      "ai-agent": {
        org_email_domain: "not a domain",
        evidence_roots: ["D:\\case\\evidence"],
        ai_read_mb: 1024,
      },
    });
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
