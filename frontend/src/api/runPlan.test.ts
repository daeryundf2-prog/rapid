// R4 V1 run-plan API wrappers: request shapes (URL, method, body, If-None-Match / 304) and the
// one-spelling normalization of statuses.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cancelRun, retryRun } from "./runControl";
import {
  controlRunPlan,
  getRunPlan,
  isPlanPolling,
  normalizePlan,
  previewRunPlan,
  type RunPlan,
  resetRunPlanCache,
} from "./runPlan";
import { normalizeRunStatus } from "./runs";

interface Call {
  url: string;
  method: string;
  body: unknown;
  headers: Record<string, string>;
}

function stubFetch(respond: (call: Call) => Response): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const call: Call = {
        url: String(input),
        method: (init?.method ?? "GET").toUpperCase(),
        body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
        headers: (init?.headers ?? {}) as Record<string, string>,
      };
      calls.push(call);
      return respond(call);
    }),
  );
  return calls;
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

function plan(over: Partial<RunPlan> = {}): RunPlan {
  return {
    run_id: "r1",
    run_status: "running",
    counts: {
      groups: {
        total: 1,
        queued: 0,
        running: 1,
        completed: 0,
        partial: 0,
        failed: 0,
        skipped: 0,
        cancelled: 0,
      },
      tasks: {
        total: 2,
        queued: 1,
        running: 1,
        completed: 0,
        partial: 0,
        failed: 0,
        skipped: 0,
        cancelled: 0,
      },
    },
    groups: [],
    ...over,
  };
}

beforeEach(() => resetRunPlanCache());
afterEach(() => vi.unstubAllGlobals());

describe("run plan API (R4 V1)", () => {
  it("GET /plan sends If-None-Match after an ETag and reuses the cached plan on 304", async () => {
    let first = true;
    const calls = stubFetch(() => {
      if (first) {
        first = false;
        return json(plan(), 200, { etag: '"v1"' });
      }
      return new Response(null, { status: 304 });
    });
    const one = await getRunPlan("r 1");
    expect(calls[0]?.url).toBe("/api/runs/r%201/plan");
    expect(calls[0]?.headers["If-None-Match"]).toBeUndefined();
    const two = await getRunPlan("r 1");
    expect(calls[1]?.headers["If-None-Match"]).toBe('"v1"');
    expect(two).toBe(one);
  });

  it("GET /plan throws the Korean detail on 404", async () => {
    stubFetch(() => json({ detail: "런을 찾을 수 없습니다" }, 404));
    await expect(getRunPlan("x")).rejects.toMatchObject({ status: 404, message: "런을 찾을 수 없습니다" });
  });

  it("POST /plan/control sends the action and targets only when given", async () => {
    const calls = stubFetch(() =>
      json({ accepted: [{ group: "eventlog" }], rejected: [], plan: plan() }, 202),
    );
    const result = await controlRunPlan("r1", "cancel", [{ group: "eventlog" }]);
    expect(calls[0]).toMatchObject({
      url: "/api/runs/r1/plan/control",
      method: "POST",
      body: { action: "cancel", targets: [{ group: "eventlog" }] },
    });
    expect(result.accepted).toEqual([{ group: "eventlog" }]);
    await controlRunPlan("r1", "finish");
    expect(calls[1]?.body).toEqual({ action: "finish" });
  });

  it("GET /run-plan/preview carries mode and the given options", async () => {
    const calls = stubFetch(() => json({ mode: "hacking", groups: [] }));
    await previewRunPlan({
      mode: "hacking",
      carve: false,
      extract: true,
      case_db: true,
      input_kind: "folder",
    });
    expect(calls[0]?.url).toBe(
      "/api/run-plan/preview?mode=hacking&carve=false&extract=true&case_db=true&input_kind=folder",
    );
    await previewRunPlan({ mode: "fraud" });
    expect(calls[1]?.url).toBe("/api/run-plan/preview?mode=fraud");
  });

  it("POST /retry sends {resume}; cancel stays a bare POST", async () => {
    const calls = stubFetch(() => json({ run_id: "r2", status: "queued", retry_mode: "resume" }));
    const job = await retryRun("r1", { resume: true });
    expect(calls[0]).toMatchObject({ url: "/api/runs/r1/retry", method: "POST", body: { resume: true } });
    expect(job.retry_mode).toBe("resume");
    await retryRun("r1");
    expect(calls[1]?.body).toEqual({ resume: false });
    await cancelRun("r1");
    expect(calls[2]).toMatchObject({ url: "/api/runs/r1/cancel", method: "POST", body: undefined });
  });

  it("normalizes canceled → cancelled in runs, groups, tasks and counts", () => {
    expect(normalizeRunStatus("canceled")).toBe("cancelled");
    expect(normalizeRunStatus("Interrupted")).toBe("interrupted");
    const normalized = normalizePlan({
      ...plan({ run_status: "canceled", outcome: "canceled" }),
      groups: [
        {
          id: "g",
          label: "G",
          status: "canceled",
          skippable: true,
          counts: { total: 1, canceled: 1 } as never,
          tasks: [{ id: "t", group: "g", label: "T", status: "canceled" }],
        },
      ],
    });
    expect(normalized.run_status).toBe("cancelled");
    expect(normalized.outcome).toBe("cancelled");
    expect(normalized.groups[0]?.status).toBe("cancelled");
    expect(normalized.groups[0]?.counts.cancelled).toBe(1);
    expect(normalized.groups[0]?.counts.queued).toBe(0);
    expect(normalized.groups[0]?.tasks[0]?.status).toBe("cancelled");
    expect(isPlanPolling("running")).toBe(true);
    expect(isPlanPolling("interrupted")).toBe(false);
  });
});
