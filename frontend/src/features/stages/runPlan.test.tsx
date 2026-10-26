// 처리 계획표 (R4 V1 U-P2-1/2/5): the group → task treegrid, its keyboard, row × buttons and
// top controls with Korean disabled reasons, the one polite announcement per transition, and the
// 처리 page (plan replaces the step list; interrupted runs resume).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PlanCounts, PlanGroup, PlanTask, RunPlan } from "../../api/runPlan";
import { resetRunPlanCache } from "../../api/runPlan";
import type { RunWithProgress } from "../../api/runsProgress";
import { caseCommands } from "../../commands/builtin";
import { registerCommands, resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { ProcessPage } from "./ProcessStage";
import { groupAriaLabel, planSummaryText, RunPlanTable } from "./RunPlanTable";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

vi.mock("../grid/DataGrid", () => ({ DataGrid: () => <div data-testid="grid-stub" /> }));

const RUN = "run-1";

function counts(over: Partial<PlanCounts>): PlanCounts {
  return {
    total: 0,
    queued: 0,
    running: 0,
    completed: 0,
    partial: 0,
    failed: 0,
    skipped: 0,
    cancelled: 0,
    ...over,
  };
}

function task(over: Partial<PlanTask> & Pick<PlanTask, "id" | "group" | "label" | "status">): PlanTask {
  return { skippable: true, ...over };
}

function group(
  id: string,
  label: string,
  status: string,
  tasks: PlanTask[],
  over: Partial<PlanGroup> = {},
): PlanGroup {
  const c = counts({ total: tasks.length });
  for (const t of tasks) c[t.status as keyof Omit<PlanCounts, "total">] += 1;
  return { id, label, status, skippable: true, counts: c, tasks, ...over };
}

function fixture(over: Partial<RunPlan> = {}): RunPlan {
  const started = new Date(Date.now() - 192_000).toISOString();
  const groups = [
    group(
      "prepare",
      "준비",
      "completed",
      [
        task({
          id: "prepare",
          group: "prepare",
          label: "준비",
          status: "completed",
          skippable: false,
          duration_ms: 4000,
        }),
      ],
      { skippable: false, duration_ms: 4000 },
    ),
    group("eventlog", "이벤트 로그", "running", [
      task({
        id: "eventlog",
        group: "eventlog",
        label: "이벤트 로그",
        status: "running",
        rows_so_far: 12340,
        started_at: started,
      }),
      task({ id: "eventlog-sysmon", group: "eventlog", label: "Sysmon", status: "queued" }),
    ]),
    group("browser", "웹 브라우저", "queued", [
      task({ id: "browser", group: "browser", label: "웹 브라우저", status: "queued" }),
    ]),
    group("registry", "레지스트리", "skipped", [
      task({
        id: "registry",
        group: "registry",
        label: "레지스트리",
        status: "skipped",
        reason: "실행 전 제외",
      }),
    ]),
    group(
      "email",
      "메일",
      "partial",
      [
        task({
          id: "email",
          group: "email",
          label: "메일",
          status: "partial",
          artifact_count: 51,
          reason: "검사관 요청",
          requested_by: { actor: "web", at: "2026-10-18T01:00:00Z" },
        }),
      ],
      { artifact_count: 51 },
    ),
    group(
      "report",
      "보고서",
      "queued",
      [task({ id: "report", group: "report", label: "보고서", status: "queued", skippable: false })],
      { skippable: false },
    ),
  ];
  return {
    run_id: RUN,
    run_status: "running",
    live: true,
    stale: false,
    started_at: started,
    elapsed_ms: 192_000,
    counts: {
      groups: counts({ total: 6, completed: 1, running: 1, queued: 2, skipped: 1, partial: 1 }),
      tasks: counts({ total: 7, completed: 1, running: 1, queued: 3, skipped: 1, partial: 1 }),
    },
    groups,
    ...over,
  };
}

function renderWithClient(
  ui: ReactElement,
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } }),
) {
  return { client, ...render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>) };
}

beforeEach(() => {
  announceMock.mockClear();
  resetRunPlanCache();
  resetCommandRegistry();
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetCommandRegistry();
});

describe("처리 계획표 (RunPlanTable)", () => {
  it("summarizes the plan and shows states, progress, counts and reasons in Korean", () => {
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />);
    const summary = screen.getByTestId("run-plan-summary").textContent ?? "";
    expect(summary).toMatch(
      /^그룹 6 \/ 태스크 7 · 시작 .+ · 경과 \d\d:\d\d · 완료 1 · 부분 1 · 건너뜀 1 · 취소 0 · 실패 0$/,
    );
    const grid = screen.getByRole("treegrid", { name: "처리 계획표" });
    const eventlog = within(grid).getByRole("row", { name: "이벤트 로그, 실행 중, 0/2 태스크" });
    expect(eventlog.getAttribute("aria-level")).toBe("1");
    expect(eventlog.getAttribute("aria-expanded")).toBe("true"); // running groups open
    expect(eventlog.textContent).toContain("0/2 태스크");
    expect(within(eventlog).getByRole("progressbar", { name: "이벤트 로그 진행률" })).toBeTruthy();
    // The running task: live rows and a ticking elapsed clock.
    const running = screen.getByTestId("run-plan-task-eventlog");
    expect(running.getAttribute("aria-level")).toBe("2");
    expect(running.textContent).toContain("행 12,340");
    expect(running.textContent).toMatch(/03:1\d 경과/);
    expect(within(running).getByText("실행 중")).toBeTruthy();
    expect(screen.getByRole("row", { name: "메일, 일부 완료, 1/1 태스크" }).textContent).toContain("51건");
    expect(screen.getByRole("row", { name: "레지스트리, 건너뜀, 0/1 태스크" })).toBeTruthy();
    expect(groupAriaLabel(fixture().groups[0] as PlanGroup)).toBe("준비, 완료, 1/1 태스크");
    // Reasons of partial / skipped tasks are visible once the group is open.
    fireEvent.keyDown(screen.getByTestId("run-plan-group-email"), { key: "Enter" });
    const partial = screen.getByTestId("run-plan-task-email");
    expect(partial.textContent).toContain("검사관 요청 · 요청: web");
    expect(within(partial).getByText("일부 완료").getAttribute("title")).toContain("검사관 요청");
  });

  it("moves with ↑/↓, expands with → / Enter and collapses with ←", () => {
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />);
    const first = screen.getByTestId("run-plan-group-prepare");
    expect(first.tabIndex).toBe(0);
    first.focus();
    fireEvent.keyDown(first, { key: "ArrowDown" });
    const eventlog = screen.getByTestId("run-plan-group-eventlog");
    expect(document.activeElement).toBe(eventlog);
    fireEvent.keyDown(eventlog, { key: "ArrowRight" }); // already open → first task
    expect(document.activeElement).toBe(screen.getByTestId("run-plan-task-eventlog"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowLeft" }); // task → parent
    expect(document.activeElement).toBe(eventlog);
    fireEvent.keyDown(eventlog, { key: "ArrowLeft" });
    expect(eventlog.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByTestId("run-plan-task-eventlog")).toBeNull();
    fireEvent.keyDown(eventlog, { key: "ArrowDown" });
    const browser = screen.getByTestId("run-plan-group-browser");
    expect(document.activeElement).toBe(browser);
    fireEvent.keyDown(browser, { key: "ArrowRight" });
    expect(browser.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(browser, { key: "Enter" });
    expect(browser.getAttribute("aria-expanded")).toBe("false");
    fireEvent.keyDown(browser, { key: " " });
    expect(browser.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(browser, { key: "End" });
    expect(document.activeElement).toBe(screen.getByTestId("run-plan-group-report"));
  });

  it("row × buttons are out of the tab order and reached with → (← / Esc back to the row)", () => {
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />);
    const buttons = screen.getAllByRole("button", { name: /(취소|건너뛰기)$/ });
    const rowButtons = buttons.filter((button) => button.classList.contains("run-plan-x"));
    expect(rowButtons.length).toBeGreaterThan(0);
    for (const button of rowButtons) expect(button.tabIndex).toBe(-1);
    const task = screen.getByTestId("run-plan-task-eventlog");
    task.focus();
    fireEvent.keyDown(task, { key: "ArrowRight" });
    const x = within(task).getByRole("button", { name: "이벤트 로그 취소" });
    expect(document.activeElement).toBe(x);
    fireEvent.keyDown(x, { key: "ArrowLeft" });
    expect(document.activeElement).toBe(task);
    fireEvent.keyDown(task, { key: "ArrowRight" });
    fireEvent.keyDown(x, { key: "ArrowDown" });
    expect(document.activeElement).toBe(screen.getByTestId("run-plan-task-eventlog-sysmon"));
    // A collapsed group with tasks expands first; a leaf group row reaches its × directly.
    const browser = screen.getByTestId("run-plan-group-browser");
    browser.focus();
    fireEvent.keyDown(browser, { key: "ArrowRight" });
    expect(browser.getAttribute("aria-expanded")).toBe("true");
  });

  it("stops in-flight plan polls before the POST and before writing the reply", async () => {
    const order: string[] = [];
    installFetch({
      "/plan/control": () => {
        order.push("post");
        return jsonResponse({ accepted: [], rejected: [], plan: fixture({ stale: true }) }, 202);
      },
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const cancel = vi.spyOn(client, "cancelQueries").mockImplementation(async () => {
      order.push("cancel");
    });
    const write = vi.spyOn(client, "setQueryData");
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />, client);
    fireEvent.click(screen.getByRole("button", { name: "웹 브라우저 그룹 건너뛰기" }));
    await waitFor(() => expect(write).toHaveBeenCalled());
    expect(order).toEqual(["cancel", "post", "cancel"]);
    expect(cancel).toHaveBeenCalledWith({ queryKey: ["run-plan", RUN] });
  });

  it("row × buttons cancel a running group, skip a queued one and explain the rest", async () => {
    const calls = installFetch({
      "/plan/control": () =>
        jsonResponse({ accepted: [{ group: "eventlog" }], rejected: [], plan: fixture() }, 202),
    });
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />);
    fireEvent.click(screen.getByRole("button", { name: "이벤트 로그 그룹 취소" }));
    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({
      url: `/api/runs/${RUN}/plan/control`,
      method: "POST",
      body: { action: "cancel", targets: [{ group: "eventlog" }] },
    });
    await waitFor(() => expect(announceMock).toHaveBeenCalledWith("이벤트 로그 그룹 취소 요청을 보냈습니다"));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "웹 브라우저 그룹 건너뛰기" }).getAttribute("aria-disabled"),
      ).toBeNull(),
    );
    fireEvent.click(screen.getByRole("button", { name: "웹 브라우저 그룹 건너뛰기" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    expect(calls[1]?.body).toEqual({ action: "skip", targets: [{ group: "browser" }] });
    // Per task: the running one cancels, the queued one skips.
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Sysmon 건너뛰기" }).getAttribute("aria-disabled"),
      ).toBeNull(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Sysmon 건너뛰기" }));
    await waitFor(() => expect(calls).toHaveLength(3));
    expect(calls[2]?.body).toEqual({ action: "skip", targets: [{ task: "eventlog-sysmon" }] });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "이벤트 로그 취소" }).getAttribute("aria-disabled"),
      ).toBeNull(),
    );
    // Finished and required rows explain why they cannot run (and send nothing).
    const finished = screen.getByRole("button", { name: "레지스트리 그룹 취소" });
    expect(finished.getAttribute("aria-disabled")).toBe("true");
    expect(finished.getAttribute("data-disabled-reason")).toBe("이미 끝난 태스크입니다");
    const required = screen.getByRole("button", { name: "보고서 그룹 건너뛰기" });
    expect(required.getAttribute("data-disabled-reason")).toBe(
      "필수 단계는 건너뛰거나 따로 취소할 수 없습니다",
    );
    fireEvent.click(finished);
    fireEvent.click(required);
    expect(calls).toHaveLength(3);
  });

  it("a rejected target is shown and announced assertively", async () => {
    installFetch({
      "/plan/control": () =>
        jsonResponse(
          {
            accepted: [],
            rejected: [
              {
                target: { group: "browser" },
                reason: "이미 시작된 태스크는 건너뛸 수 없습니다. 취소를 사용하세요",
              },
            ],
            plan: fixture(),
          },
          202,
        ),
    });
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />);
    fireEvent.click(screen.getByRole("button", { name: "웹 브라우저 그룹 건너뛰기" }));
    await waitFor(() =>
      expect(announceMock).toHaveBeenCalledWith(
        "웹 브라우저 그룹 건너뛰기 거부: 이미 시작된 태스크는 건너뛸 수 없습니다. 취소를 사용하세요",
        { politeness: "assertive" },
      ),
    );
    expect(useAppStore.getState().notice).toMatchObject({ tone: "error" });
    expect(useAppStore.getState().notice?.text).toContain("거부");
  });

  it("모두 취소 / 지금까지로 마치기 post cancel_all / finish and explain when they cannot", async () => {
    const calls = installFetch({
      "/plan/control": () => jsonResponse({ accepted: [], rejected: [], plan: fixture() }, 202),
    });
    // 모두 취소 asks first: declining sends nothing.
    const confirm = vi.fn(() => false);
    vi.stubGlobal("confirm", confirm);
    const { unmount } = renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />);
    fireEvent.click(screen.getByRole("button", { name: "모두 취소" }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("남은 처리를 모두 취소할까요"));
    expect(calls).toHaveLength(0);
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "모두 취소" }));
    await waitFor(() => expect(calls[0]?.body).toEqual({ action: "cancel_all" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "지금까지로 마치기" }).getAttribute("aria-disabled"),
      ).toBeNull(),
    );
    fireEvent.click(screen.getByRole("button", { name: "지금까지로 마치기" }));
    await waitFor(() => expect(calls[1]?.body).toEqual({ action: "finish" }));
    unmount();

    // Nothing queued: 마치기 has nothing to cancel.
    const noQueue = fixture();
    noQueue.counts.tasks.queued = 0;
    const view = renderWithClient(<RunPlanTable runId={RUN} plan={noQueue} />);
    expect(
      screen.getByRole("button", { name: "지금까지로 마치기" }).getAttribute("data-disabled-reason"),
    ).toBe("대기 중인 태스크가 없습니다");
    view.unmount();

    // A finished run (R7 C-G1): the plan is a record — no 모두 취소 / 마치기, no × column.
    renderWithClient(<RunPlanTable runId={RUN} plan={fixture({ run_status: "completed" })} />);
    for (const name of [
      "모두 취소",
      "지금까지로 마치기",
      "이벤트 로그 그룹 취소",
      "웹 브라우저 그룹 건너뛰기",
    ]) {
      expect(screen.queryByRole("button", { name })).toBeNull();
    }
    expect(document.querySelectorAll("button.run-plan-x")).toHaveLength(0);
    expect(screen.queryByRole("columnheader", { name: "동작" })).toBeNull();
    expect(calls).toHaveLength(2);
  });

  it("announces a finished group once (polite) and refreshes the tree and artifact pages", () => {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    const { rerender } = renderWithClient(<RunPlanTable runId={RUN} plan={fixture()} />, client);
    expect(announceMock).not.toHaveBeenCalled(); // the first plan is history
    const next = fixture();
    const eventlog = next.groups[1] as PlanGroup;
    next.groups[1] = {
      ...eventlog,
      status: "completed",
      artifact_count: 48120,
      counts: counts({ total: 2, completed: 2 }),
    };
    next.counts.tasks = counts({ total: 7, completed: 3, queued: 2, skipped: 1, partial: 1 });
    rerender(
      <QueryClientProvider client={client}>
        <RunPlanTable runId={RUN} plan={next} />
      </QueryClientProvider>,
    );
    expect(announceMock).toHaveBeenCalledTimes(1);
    expect(announceMock).toHaveBeenCalledWith("이벤트 로그 그룹 완료 · 48,120건", { politeness: "polite" });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["run-tree", RUN] });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["collection", RUN, "artifacts"] });
    // The same plan again is not news.
    rerender(
      <QueryClientProvider client={client}>
        <RunPlanTable runId={RUN} plan={{ ...next }} />
      </QueryClientProvider>,
    );
    expect(announceMock).toHaveBeenCalledTimes(1);
  });

  it("summary text helper lists every count", () => {
    expect(planSummaryText(fixture())).toBe(
      "그룹 6 / 태스크 7 · 완료 1 · 부분 1 · 건너뜀 1 · 취소 0 · 실패 0",
    );
  });
});

describe("처리 page with a plan", () => {
  function setRun(run: Partial<RunWithProgress>) {
    const hash = `#/case/${RUN}/process`;
    window.location.hash = hash;
    useAppStore.setState({ route: { ...EMPTY_ROUTE }, runs: [{ run_id: RUN, ...run } as RunWithProgress] });
    useAppStore.getState().syncRouteFromLocation(parseHash(hash));
  }

  it("replaces the step list with the plan table and shows 모두 취소 / 마치기 while running", async () => {
    setRun({
      status: "running",
      request: { root: "C:/ev/case1", mode: "hacking" },
      progress: { plan_counts: { groups: 6, tasks: 7, completed: 1, running: 1, skipped: 1, partial: 1 } },
    });
    installFetch({
      "/plan": () => jsonResponse(fixture()),
      "/summary": () => jsonResponse({ steps: [{ step: "files", status: "completed" }] }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    registerCommands(caseCommands(client));
    renderWithClient(<ProcessPage />, client);
    expect(await screen.findByRole("treegrid", { name: "처리 계획표" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "처리 단계" })).toBeNull();
    expect(screen.getByTestId("process-cancel-all").getAttribute("aria-disabled")).toBeNull();
    expect(screen.getByTestId("process-finish").getAttribute("aria-disabled")).toBeNull();
    expect(screen.queryByTestId("process-resume")).toBeNull();
  });

  it("an interrupted run reads 중단됨 · 서버 재시작 and resumes with {resume: true}", async () => {
    setRun({ status: "interrupted", request: { root: "C:/ev/case1", mode: "hacking" } });
    const calls = installFetch({
      "/plan": () => jsonResponse(fixture({ run_status: "interrupted", outcome: "interrupted" })),
      "/retry": () => jsonResponse({ run_id: "run-2", status: "queued", retry_mode: "resume" }),
      "/summary": () => jsonResponse({ detail: "런 마무리 후 사용할 수 있습니다" }, 409),
      "/analyses": () => jsonResponse({ analyses: [] }),
      "/api/runs": () => jsonResponse({ runs: [] }),
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    registerCommands(caseCommands(client));
    renderWithClient(<ProcessPage />, client);
    expect(screen.getByTestId("process-run-status").textContent).toBe("중단됨 · 서버 재시작");
    const resume = screen.getByTestId("process-resume");
    expect(resume.getAttribute("aria-disabled")).toBeNull();
    expect(screen.getByTestId("process-restart").textContent).toContain("처음부터 다시");
    await act(async () => {
      fireEvent.click(resume);
    });
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/retry"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/retry"))?.body).toEqual({ resume: true });
    // The examiner follows the new run instead of staying on the old one with the button live.
    await waitFor(() => expect(useAppStore.getState().route.runId).toBe("run-2"));
    expect(useAppStore.getState().route.collection).toBe("process");
    expect(window.location.hash).toContain("run-2");
  });

  it("says when the plan cannot be loaded (not a 404) instead of falling back silently", async () => {
    setRun({ status: "completed", request: { root: "C:/ev/case1", mode: "fraud" } });
    installFetch({
      "/plan": () => jsonResponse({ detail: "plan file is corrupt" }, 500),
      "/summary": () => jsonResponse({ steps: [{ step: "files", status: "completed", record_count: 3 }] }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<ProcessPage />);
    const note = await screen.findByTestId("run-plan-error");
    expect(note.textContent).toContain("처리 계획을 불러오지 못했습니다");
    expect(note.textContent).toContain("plan file is corrupt");
  });

  it("keeps the summary step list for an older run without a plan", async () => {
    setRun({ status: "completed", request: { root: "C:/ev/case1", mode: "fraud" } });
    installFetch({
      "/summary": () => jsonResponse({ steps: [{ step: "files", status: "completed", record_count: 3 }] }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<ProcessPage />);
    expect(await screen.findByRole("table", { name: "처리 단계" })).toBeTruthy();
    expect(screen.queryByRole("treegrid")).toBeNull();
    expect(screen.queryByTestId("process-run-actions")).toBeNull();
    // A 404 is "no plan" (older run): no error note.
    expect(screen.queryByTestId("run-plan-error")).toBeNull();
  });
});
