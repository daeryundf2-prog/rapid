// Status bar run line with the R4 V1 plan counts: "그룹 · 태스크 · 실행 중: 이벤트 로그(12,340행) ·
// 건너뜀 3", "응답 없음 · 마지막 신호 n분 전" when the heartbeat stops, and resume for interrupted runs.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RunWithProgress } from "../api/runsProgress";
import { caseCommands } from "../commands/builtin";
import { registerCommands, resetCommandRegistry } from "../commands/registry";
import { resetAppStore, useAppStore } from "../state/store";
import { planProgressText, progressText, StatusBar, staleText } from "./StatusBar";

const RUN = "run-abcdef12";

function run(over: Partial<RunWithProgress> = {}): RunWithProgress {
  return {
    run_id: RUN,
    status: "running",
    created_at: new Date(Date.now() - 60_000).toISOString(),
    request: { root: "D:/ev/case1.E01", mode: "hacking" },
    progress: {
      stage: "artifacts",
      completed_count: 3,
      total_count: 8,
      error_count: 0,
      heartbeat_at: new Date().toISOString(),
      stale: false,
      plan_counts: {
        groups: 23,
        tasks: 36,
        completed: 15,
        partial: 1,
        failed: 0,
        skipped: 3,
        cancelled: 0,
        running: 2,
      },
      current: [
        { task: "eventlog", label: "이벤트 로그", group: "eventlog", rows_so_far: 12340 },
        { task: "windows-filesystem", label: "파일 시스템", group: "filesystem", rows_so_far: null },
      ],
    },
    ...over,
  };
}

function renderBar(item: RunWithProgress) {
  resetAppStore({ route: { runId: RUN, collection: "process" } });
  useAppStore.getState().setRuns([item]);
  const client = new QueryClient();
  registerCommands(caseCommands(client));
  return render(
    <QueryClientProvider client={client}>
      <StatusBar />
    </QueryClientProvider>,
  );
}

beforeEach(() => resetCommandRegistry());
afterEach(() => {
  cleanup();
  resetCommandRegistry();
});

describe("status bar plan progress (R4 V1)", () => {
  it("reads plan counts and the running tasks with their rows", () => {
    expect(planProgressText(run().progress)).toBe(
      "그룹 23 · 태스크 19/36 · 실행 중: 이벤트 로그(12,340행), 파일 시스템 · 건너뜀 3",
    );
    const withGroups = run();
    if (withGroups.progress?.plan_counts) withGroups.progress.plan_counts.groups_done = 7;
    expect(progressText(withGroups)).toMatch(/^그룹 7\/23 · 태스크 19\/36/);
    // No plan counts (older server): the provider line stays.
    expect(
      progressText(
        run({ progress: { stage: "artifacts", completed_count: 3, total_count: 8, running: ["evtx"] } }),
      ),
    ).toBe("artifacts · provider 3/8 · 실행 중: evtx");
  });

  it("says 응답 없음 with the heartbeat age when the run is stale", () => {
    const now = Date.now();
    const old = new Date(now - 3 * 60_000 - 5_000).toISOString();
    const stale = run();
    if (stale.progress) stale.progress.heartbeat_at = old;
    expect(staleText(stale, now)).toBe("응답 없음 · 마지막 신호 3분 전");
    const flagged = run();
    if (flagged.progress) flagged.progress.stale = true;
    expect(staleText(flagged, now)).toBe("응답 없음 · 마지막 신호 1분 전");
    expect(staleText(run(), now)).toBe("");
    expect(staleText(run({ status: "completed" }), now)).toBe("");
  });

  it("renders the plan line, the 응답 없음 warning and 진행 상세… while running", () => {
    const item = run();
    if (item.progress) item.progress.heartbeat_at = new Date(Date.now() - 120_000).toISOString();
    renderBar(item);
    const bar = screen.getByTestId("status-run");
    expect(bar.textContent).toContain("그룹 23 · 태스크 19/36 · 실행 중: 이벤트 로그(12,340행)");
    expect(screen.getByTestId("status-stale").textContent).toBe("응답 없음 · 마지막 신호 2분 전");
    expect(screen.getByRole("progressbar", { name: "태스크 진행률" }).getAttribute("value")).toBe("19");
    expect(screen.getByTestId("run-plan-open").getAttribute("href")).toBe(`#/case/${RUN}/process`);
    expect(screen.getByTestId("run-cancel")).toBeTruthy();
  });

  it("an interrupted run reads 중단됨 · 서버 재시작 and offers 이어서 실행", () => {
    renderBar(run({ status: "interrupted" }));
    const bar = screen.getByTestId("status-run");
    expect(bar.textContent).toContain("중단됨");
    expect(bar.textContent).toContain("서버 재시작");
    expect(screen.queryByTestId("status-stale")).toBeNull();
    expect(screen.getByTestId("run-resume").getAttribute("aria-disabled")).toBeNull();
    expect(screen.queryByTestId("run-cancel")).toBeNull();
  });

  it("an old canceled run reads 취소됨 and can resume", () => {
    renderBar(run({ status: "canceled", progress: null }));
    expect(screen.getByTestId("status-run").textContent).toContain("취소됨");
    expect(screen.getByTestId("run-resume").getAttribute("aria-disabled")).toBeNull();
  });
});
