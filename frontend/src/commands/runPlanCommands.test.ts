// Run-plan commands (R4 V1): 모두 취소 / 지금까지로 마치기 / 이어서 실행 and 런 다시 실행 with Korean
// disabled reasons; `canceled` / `interrupted` runs can be retried.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunWithProgress } from "../api/runsProgress";
import { resetAppStore, useAppStore } from "../state/store";
import {
  caseCommands,
  NO_RUN_REASON,
  queuedTaskCount,
  RETRY_CONFLICT_MESSAGE,
  RETRY_IN_FLIGHT_REASON,
} from "./builtin";
import { registerCommands, resetCommandRegistry, runCommand } from "./registry";

interface Call {
  url: string;
  method: string;
  body: unknown;
}

let calls: Call[] = [];
/** Order of plan-cache cancels, fetches and cache writes (cancel must come first). */
let order: string[] = [];
/** Per-test answer of `POST /retry` (default: a new queued run r2). */
let retryAnswer: () => Promise<Response> | Response;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function setRun(run: Partial<RunWithProgress>) {
  useAppStore.getState().navigate({ runId: "r1", collection: "process" });
  useAppStore.getState().setRuns([{ run_id: "r1", status: "running", ...run } as RunWithProgress]);
}

beforeEach(() => {
  resetAppStore({ route: { runId: null, collection: null } });
  resetCommandRegistry();
  calls = [];
  order = [];
  retryAnswer = () => json({ run_id: "r2", status: "queued" });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      order.push(`fetch ${url}`);
      if (url.endsWith("/retry")) {
        calls.push({ url, method: init?.method ?? "GET", body: JSON.parse(String(init?.body)) });
        return retryAnswer();
      }
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
  registerCommands(
    caseCommands({
      invalidateQueries: vi.fn(),
      cancelQueries: vi.fn(async ({ queryKey }: { queryKey: unknown[] }) => {
        order.push(`cancel ${JSON.stringify(queryKey)}`);
      }),
      setQueryData: vi.fn((queryKey: unknown[]) => {
        order.push(`set ${JSON.stringify(queryKey)}`);
      }),
    } as never),
  );
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
      // The examiner followed the new run (r2); back on r1 for 처음부터 다시.
      setRun({ status });
      expect(await runCommand("case.retry")).toEqual({ ok: true });
    }
    const retries = calls.filter((call) => call.url.endsWith("/retry"));
    expect(retries).toHaveLength(8);
    expect(retries[0]?.body).toEqual({ resume: true });
    expect(retries[1]?.body).toEqual({ resume: false });
  });

  it("모두 취소 asks first; plan controls stop plan polls before the POST and before the cache write", async () => {
    setRun({ progress: { plan_counts: { tasks: 5, completed: 2, running: 2 } } });
    vi.stubGlobal(
      "confirm",
      vi.fn(() => false),
    );
    expect(await runCommand("run.plan.cancelAll")).toEqual({ ok: true });
    expect(calls).toHaveLength(0);
    expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("모두 취소할까요"));
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    expect(await runCommand("run.plan.cancelAll")).toEqual({ ok: true });
    const key = JSON.stringify(["run-plan", "r1"]);
    const expected = [`cancel ${key}`, "fetch /api/runs/r1/plan/control", `cancel ${key}`, `set ${key}`];
    expect(order).toEqual(expected);
    order = [];
    expect(await runCommand("run.plan.finish")).toEqual({ ok: true });
    expect(order).toEqual(expected);
  });

  it("이어서 실행 moves to the new run and stays disabled while the request or the retry runs", async () => {
    setRun({ status: "interrupted" });
    let answer: (response: Response) => void = () => undefined;
    retryAnswer = () =>
      new Promise<Response>((resolve) => {
        answer = resolve;
      });
    const pending = runCommand("run.resume");
    await vi.waitFor(() => expect(calls).toHaveLength(1));
    // A second click (or 처음부터 다시) while the first request is out: refused with the reason.
    expect(await runCommand("run.resume")).toEqual({ ok: false, reason: RETRY_IN_FLIGHT_REASON });
    expect(await runCommand("case.retry")).toEqual({ ok: false, reason: RETRY_IN_FLIGHT_REASON });
    answer(json({ run_id: "r2", status: "queued", retry_of_run_id: "r1" }));
    expect(await pending).toEqual({ ok: true });
    expect(calls).toHaveLength(1);
    expect(useAppStore.getState().route).toMatchObject({ runId: "r2", collection: "process" });
    expect(useAppStore.getState().retryPendingRunId).toBeNull();

    // Back on the old run while its retry is still queued / running: still disabled.
    useAppStore.getState().navigate({ runId: "r1", collection: "process" });
    useAppStore.getState().setRuns([
      { run_id: "r1", status: "interrupted" },
      { run_id: "r2", status: "running", retry_of_run_id: "r1" },
    ] as RunWithProgress[]);
    expect(await runCommand("run.resume")).toEqual({ ok: false, reason: RETRY_IN_FLIGHT_REASON });
    // The retry ended (failed): the old run can be retried again.
    retryAnswer = () => json({ run_id: "r3", status: "queued", retry_of_run_id: "r1" });
    useAppStore.getState().setRuns([
      { run_id: "r1", status: "interrupted" },
      { run_id: "r2", status: "failed", retry_of_run_id: "r1" },
    ] as RunWithProgress[]);
    expect(await runCommand("case.retry")).toEqual({ ok: true });
  });

  it("a 409 (already being retried) becomes a Korean message and the examiner stays", async () => {
    setRun({ status: "failed" });
    retryAnswer = () => json({ detail: "already retrying" }, 409);
    const result = await runCommand("case.retry");
    expect(result).toEqual({ ok: false, reason: `런 다시 실행 실패: ${RETRY_CONFLICT_MESSAGE}` });
    expect(useAppStore.getState().notice?.text).toContain(RETRY_CONFLICT_MESSAGE);
    expect(useAppStore.getState().route.runId).toBe("r1");
    expect(useAppStore.getState().retryPendingRunId).toBeNull();
  });
});
