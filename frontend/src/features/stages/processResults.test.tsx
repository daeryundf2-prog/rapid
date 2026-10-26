// R7 L1 (C-G1 · C-G2 · 접수 후속): a finished run's 처리 page leads with the results — 단계표 →
// 공개 사항 → 처리 설정 스냅샷 → 추가 분석 추천 — never a plan of waiting groups with × buttons;
// a plan that does not describe the run says "계획 기록 없음(이전 형식)"; 소요 is completed − started.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PlanCounts, RunPlan } from "../../api/runPlan";
import { resetRunPlanCache } from "../../api/runPlan";
import type { RunWithProgress } from "../../api/runsProgress";
import { resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { ProcessPage, processLayout, stepElapsedText, stepsElapsedMs } from "./ProcessStage";
import { isLegacyPlan } from "./RunPlanTable";

configure({ asyncUtilTimeout: 5000 });
vi.mock("../grid/DataGrid", () => ({ DataGrid: () => <div data-testid="grid-stub" /> }));

const RUN = "af54ff24ed5f";

function counts(over: Partial<PlanCounts> = {}): PlanCounts {
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

/** A plan rebuilt from the preview for a run written before plans: everything still "대기". */
function legacyPlan(over: Partial<RunPlan> = {}): RunPlan {
  const queued = (id: string, label: string) => ({
    id,
    label,
    status: "queued",
    skippable: true,
    counts: counts({ total: 1, queued: 1 }),
    tasks: [{ id, group: id, label, status: "queued", skippable: true }],
  });
  return {
    run_id: RUN,
    run_status: "completed",
    live: false,
    stale: false,
    started_at: null,
    counts: { groups: counts({ total: 2, queued: 2 }), tasks: counts({ total: 2, queued: 2 }) },
    groups: [queued("prepare", "증거 준비"), queued("eventlog", "이벤트 로그")],
    ...over,
  };
}

const SUMMARY = {
  steps: [
    { name: "manifest", status: "completed", provider_count: 24, elapsed_seconds: 1.5 },
    { name: "files", status: "completed", candidate_count: 4770, elapsed_seconds: 600 },
    { name: "timeline", status: "completed", event_count: 120, elapsed_seconds: 1440 },
  ],
  disclosures: { missing_tools: { pst: { available: false, note: "PST 도구 없음" } } },
};

const SNAPSHOT = {
  source: "run-request",
  run_id: RUN,
  captured_at: "2026-10-17T11:18:42Z",
  snapshot: { origin: "run-request", request: { root: "D:/ev", mode: "fraud" } },
};

function setRun(run: Partial<RunWithProgress>) {
  const hash = `#/case/${RUN}/process`;
  window.location.hash = hash;
  useAppStore.setState({
    route: { ...EMPTY_ROUTE },
    runs: [
      { run_id: RUN, request: { root: "D:/rapid-qa/bsh-subset", mode: "fraud" }, ...run } as RunWithProgress,
    ],
  });
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

function renderPage(ui: ReactElement = <ProcessPage />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  resetRunPlanCache();
  resetCommandRegistry();
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("처리 results layout (C-G1)", () => {
  it("a completed run with a stale plan: banner, 0 대기, 0 ×, results first in order", async () => {
    setRun({
      status: "completed",
      created_at: "2026-10-17T11:18:42Z",
      run_times: {
        started_at: "2026-10-17T11:18:45Z",
        completed_at: "2026-10-17T11:52:54Z",
        source: "run-progress",
        imported_at: null,
      },
    } as Partial<RunWithProgress>);
    installFetch({
      "/plan": () => jsonResponse(legacyPlan()),
      "/summary": () => jsonResponse(SUMMARY),
      "/processing-snapshot": () => jsonResponse(SNAPSHOT),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderPage();
    const page = screen.getByTestId("process-page");
    expect(page.getAttribute("data-layout")).toBe("results");
    expect((await screen.findByTestId("run-plan-legacy")).textContent).toContain("계획 기록 없음(이전 형식)");
    await screen.findByRole("table", { name: "처리 단계" });
    await screen.findByTestId("snapshot");
    // No plan table, no × buttons, no "대기" anywhere, no 모두 취소.
    expect(screen.queryByRole("treegrid")).toBeNull();
    expect(page.querySelectorAll("button.run-plan-x")).toHaveLength(0);
    const leaves = [...page.querySelectorAll("*")].filter((e) => e.children.length === 0);
    expect(leaves.filter((e) => e.textContent?.trim() === "대기")).toHaveLength(0);
    expect(screen.queryByTestId("process-cancel-all")).toBeNull();
    // 단계표 → 공개 사항 → 처리 설정 스냅샷 → 추가 분석 추천.
    await screen.findByRole("heading", { name: "공개 사항" });
    const headings = within(page)
      .getAllByRole("heading", { level: 3 })
      .map((h) => h.textContent);
    const order = ["처리 단계", "공개 사항", "처리 설정 스냅샷", "추가 분석 추천"].map((name) =>
      headings.indexOf(name),
    );
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    // 소요 = completed − started; the steps' own durations are listed with their total.
    expect(screen.getByTestId("process-run-elapsed").textContent).toBe("34:09");
    expect(screen.getByTestId("process-step-tally").textContent).toContain("단계 소요 합계 34:01");
    expect(screen.getByRole("table", { name: "처리 단계" }).textContent).toContain("10:00");
  });

  it("a completed run with a real plan keeps it as a folded read-only record", async () => {
    const done: RunPlan = {
      ...legacyPlan(),
      started_at: "2026-10-17T11:18:45Z",
      counts: { groups: counts({ total: 2, completed: 2 }), tasks: counts({ total: 2, completed: 2 }) },
      groups: legacyPlan().groups.map((g) => ({
        ...g,
        status: "completed",
        counts: counts({ total: 1, completed: 1 }),
        tasks: g.tasks.map((t) => ({ ...t, status: "completed" })),
      })),
    };
    setRun({ status: "completed" });
    installFetch({
      "/plan": () => jsonResponse(done),
      "/summary": () => jsonResponse(SUMMARY),
      "/processing-snapshot": () => jsonResponse(SNAPSHOT),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderPage();
    const record = await screen.findByTestId("process-plan-record");
    expect(record.tagName).toBe("DETAILS");
    expect(record.hasAttribute("open")).toBe(false);
    expect(record.querySelectorAll("button.run-plan-x")).toHaveLength(0);
    expect(screen.queryByTestId("run-plan-legacy")).toBeNull();
  });

  it("an imported run without processing times reads 소요 — and 가져옴 on its start", async () => {
    setRun({
      status: "completed",
      origin: "imported",
      created_at: "2026-10-16T23:52:52Z",
      updated_at: "2026-10-18T07:25:05Z",
      run_times: {
        started_at: null,
        completed_at: null,
        source: "none",
        imported_at: "2026-10-16T23:52:52Z",
      },
    } as Partial<RunWithProgress>);
    useAppStore.getState().setTimezone("Asia/Seoul");
    installFetch({
      "/summary": () => jsonResponse(SUMMARY),
      "/processing-snapshot": () => jsonResponse(SNAPSHOT),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderPage();
    expect(screen.getByTestId("process-run-elapsed").textContent).toBe("—");
    expect(screen.getByTestId("process-run-start").textContent).toBe("가져옴 2026-10-17 08:52");
    // A 404 plan of a finished run is "no plan record" too.
    expect((await screen.findByTestId("run-plan-legacy")).textContent).toContain("이전 형식");
    useAppStore.getState().setTimezone(null);
  });
});

describe("process layout helpers", () => {
  it("processLayout: live while queued / running or the plan is live, else results", () => {
    expect(processLayout("running")).toBe("live");
    expect(processLayout("queued")).toBe("live");
    expect(processLayout("completed")).toBe("results");
    expect(processLayout("failed")).toBe("results");
    expect(processLayout("cancelled")).toBe("results");
    expect(processLayout("completed", true)).toBe("live");
  });

  it("isLegacyPlan: a completed run with queued work, or a never-started finished plan", () => {
    expect(isLegacyPlan(legacyPlan())).toBe(true);
    expect(isLegacyPlan(legacyPlan({ run_status: "running" }))).toBe(false);
    expect(isLegacyPlan(legacyPlan({ live: true }))).toBe(false);
    expect(isLegacyPlan(legacyPlan({ run_status: "failed" }))).toBe(true);
    // A failed run that did some work keeps its queued rest (이어서 실행 runs it).
    expect(
      isLegacyPlan(
        legacyPlan({
          run_status: "failed",
          started_at: "2026-10-17T11:18:45Z",
          counts: { groups: counts(), tasks: counts({ total: 2, completed: 1, queued: 1 }) },
        }),
      ),
    ).toBe(false);
  });

  it("step durations read elapsed_seconds and sum to the steps' total", () => {
    expect(stepElapsedText({ elapsed_seconds: 61.4 })).toBe("01:01");
    expect(stepElapsedText({ elapsed_s: "3600" })).toBe("1:00:00");
    expect(stepElapsedText({})).toBe("");
    expect(stepsElapsedMs(SUMMARY.steps)).toBe(2_041_500);
    expect(stepsElapsedMs([{}])).toBeNull();
    // Two timed steps of three: no partial "합계" that reads as a short run.
    expect(stepsElapsedMs([{ elapsed_seconds: 54 }, { elapsed_seconds: 45 }, {}])).toBeNull();
  });
});

describe("live layout keeps the controls (only while running)", () => {
  it("a running run shows the plan table with its × column", async () => {
    setRun({ status: "running" });
    const running: RunPlan = { ...legacyPlan({ run_status: "running", live: true }) };
    installFetch({
      "/plan": () => jsonResponse(running),
      "/summary": () => jsonResponse({ detail: "런 마무리 후 사용할 수 있습니다" }, 409),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderPage();
    const grid = await screen.findByRole("treegrid", { name: "처리 계획표" });
    await waitFor(() => expect(grid.querySelectorAll("button.run-plan-x").length).toBeGreaterThan(0));
    expect(screen.getByTestId("process-page").getAttribute("data-layout")).toBe("live");
    expect(screen.queryByTestId("run-plan-legacy")).toBeNull();
  });
});
