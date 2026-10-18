// Run-plan commands (R4 V1): 모두 취소 / 지금까지로 마치기 / 이어서 실행 and 런 다시 실행 with Korean
// disabled reasons; `canceled` / `interrupted` runs can be retried.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunWithProgress } from "../api/runsProgress";
import { resetAppStore, useAppStore } from "../state/store";
import { caseCommands, NO_RUN_REASON, queuedTaskCount } from "./builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "./registry";

interface Call {
  url: string;
  method: string;
  body: unknown;
}

let calls: Call[] = [];

function setRun(run: Partial<RunWithProgress>) {
  useAppStore.getState().navigate({ runId: "r1", collection: "process" });
  useAppStore.getState().setRuns([{ run_id: "r1", status: "running", ...run } as RunWithProgress]);
}

beforeEach(() => {
  resetAppStore({ route: { runId: null, collection: null } });
  resetCommandRegistry();
  calls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({
        url,
        method: init?.method ?? "GET",
        body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      });
      const body = url.endsWith("/plan/control")
        ? {
            accepted: [],
            rejected: [],
            plan: { run_id: "r1", run_status: "running", counts: {}, groups: [] },
          }
        : { run_id: "r2", status: "queued" };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }),
  );
  registerCommands(caseCommands({ invalidateQueries: vi.fn(), setQueryData: vi.fn() } as never));
});
afterEach(() => {
  vi.unstubAllGlobals();
  resetCommandRegistry();
});

describe("run plan commands", () => {
  it("need a case, then a running run", async () => {
    for (const id of ["run.plan.cancelAll", "run.plan.finish", "run.resume", "case.retry"]) {
      expect(await runCommand(id)).toEqual({ ok: false, reason: NO_RUN_REASON });
    }
    setRun({ status: "completed" });
    expect(await runCommand("run.plan.cancelAll")).toEqual({ ok: false, reason: "실행 중인 런이 아닙니다" });
    expect(await runCommand("run.plan.finish")).toEqual({ ok: false, reason: "실행 중인 런이 아닙니다" });
    expect(await runCommand("run.resume")).toEqual({
      ok: false,
      reason: "실패·취소·중단된 런만 이어서 실행할 수 있습니다",
    });
    expect(await runCommand("case.retry")).toEqual({
      ok: false,
      reason: "실패·취소·중단된 런만 다시 실행할 수 있습니다",
    });
    expect(calls).toHaveLength(0);
  });

  it("모두 취소 posts cancel_all; 마치기 needs a queued task and posts finish", async () => {
    setRun({ progress: { plan_counts: { tasks: 5, completed: 3, running: 2 } } });
    expect(await runCommand("run.plan.finish")).toEqual({ ok: false, reason: "대기 중인 태스크가 없습니다" });
    expect(await runCommand("run.plan.cancelAll")).toEqual({ ok: true });
    expect(calls[0]).toMatchObject({
      url: "/api/runs/r1/plan/control",
      method: "POST",
      body: { action: "cancel_all" },
    });
    setRun({ progress: { plan_counts: { tasks: 5, completed: 2, running: 2 } } });
    expect(await runCommand("run.plan.finish")).toEqual({ ok: true });
    expect(calls[1]?.body).toEqual({ action: "finish" });
    expect(queuedTaskCount({ tasks: 36, completed: 15, partial: 1, skipped: 3, running: 2 })).toBe(15);
    expect(queuedTaskCount(undefined)).toBeNull();
  });

  it("canceled (old spelling), cancelled and interrupted runs resume or restart", async () => {
    for (const status of ["canceled", "cancelled", "interrupted", "failed"]) {
      setRun({ status });
      expect(await runCommand("run.resume")).toEqual({ ok: true });
      expect(await runCommand("case.retry")).toEqual({ ok: true });
    }
    const retries = calls.filter((call) => call.url.endsWith("/retry"));
    expect(retries).toHaveLength(8);
    expect(retries[0]?.body).toEqual({ resume: true });
    expect(retries[1]?.body).toEqual({ resume: false });
  });
});
