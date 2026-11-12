// T-174 status bar: case/evidence names instead of "런 <id>", "부분" when any measured scope axis is
// under 100 %, the failed step count, and a green "완료" only when every axis is 100 % with 0 failed.

import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunScope, StepsSummary } from "../api/dashboard";
import type { RunWithProgress } from "../api/runsProgress";
import { mockFetch, renderWithQuery } from "../features/case/testUtils";
import { resetAppStore, useAppStore } from "../state/store";
import { runIdentityText, runOutcome, StatusBar } from "./StatusBar";

const RUN_ID = "run-c2c2c2c2c2";

const RUN: RunWithProgress = {
  run_id: RUN_ID,
  status: "completed",
  created_at: "2026-11-01T00:00:00Z",
  request: { root: "D:/ev/laptop.E01", mode: "fraud" },
  progress: { stage: "done", error_count: 0 },
};

function scope(over: Partial<RunScope> = {}): RunScope {
  return {
    basis: "inferred",
    partitions: { total: 3, supported: 1, processed: 1 },
    allocated: { listed_pct: 100, content_pct: 100 },
    deleted: { records: 10, attempted: 10, attempted_pct: 100, listed_pct: 100 },
    unallocated: { scanned_pct: null, measured: false },
    caps: [],
    partial: false,
    notes: [],
    ...over,
  };
}

function steps(over: Partial<StepsSummary> = {}): StepsSummary {
  return {
    total: 30,
    completed: 30,
    partial: 0,
    failed: 0,
    skipped: 0,
    incomplete: 0,
    failed_names: [],
    partial_names: [],
    skipped_names: [],
    incomplete_names: [],
    by_status: {},
    ...over,
  };
}

/** C2-like: two supported partitions, one processed; extraction cap reached; 2 failed steps. */
const C2_SCOPE = scope({
  partitions: { total: 4, supported: 2, processed: 1 },
  allocated: { listed_pct: 100, content_pct: 98.4 },
  deleted: { records: 500, attempted: 200, attempted_pct: 40, listed_pct: 38.2 },
  caps: [{ code: "native_extract_file_limit", reached: true, skipped: 300, axis: "deleted" }],
  partial: true,
});
const C2_STEPS = steps({ completed: 26, partial: 2, failed: 2, failed_names: ["srum", "lnk"] });

const CASES = {
  cases: [
    {
      case_id: "c1",
      case_number: "2026-11",
      name: "내부 유출 사건",
      evidence: [
        {
          citation_id: "EV-1",
          case_id: "c1",
          evidence_number: "E-1",
          display_name: "직원 노트북",
          path: "D:/ev/laptop.E01",
          runs: [{ run_id: RUN_ID, exists: true, status: "completed" }],
        },
      ],
    },
  ],
};

function renderBar(dashboard: { scope: RunScope | null; steps: StepsSummary | null }, cases = CASES) {
  mockFetch({
    "GET /api/cases": cases,
    [`GET /api/runs/${RUN_ID}/dashboard`]: { run_id: RUN_ID, completed: true, ...dashboard },
  });
  act(() => {
    resetAppStore({ route: { runId: RUN_ID, collection: "intake" } });
    useAppStore.getState().setRuns([RUN]);
  });
  return renderWithQuery(<StatusBar />);
}

beforeEach(() => resetAppStore());
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("runOutcome (T-174)", () => {
  it("C2: partial with reasons and the failed step count", () => {
    const outcome = runOutcome(C2_SCOPE, C2_STEPS);
    expect(outcome.kind).toBe("partial");
    expect(outcome.failed).toBe(2);
    expect(outcome.reasons).toEqual([
      "파티션 1/2",
      "할당 내용 98.4%",
      "삭제 시도 40%",
      "처리 상한 도달",
      "일부 완료 단계 2",
    ]);
  });

  it("C1: complete only with every measured axis at 100 % and no failed step", () => {
    expect(runOutcome(scope(), steps()).kind).toBe("complete");
    // Unmeasured axes (unallocated null) do not block 완료.
    expect(runOutcome(scope(), steps()).reasons).toEqual([]);
    // One failed step alone is enough to drop 완료.
    expect(runOutcome(scope(), steps({ failed: 1, failed_names: ["evtx"] })).kind).toBe("partial");
    // The server's own partial flag counts even without a sub-100 axis.
    expect(runOutcome(scope({ partial: true }), steps()).reasons).toEqual(["처리 범위 일부"]);
    // A measured unallocated axis counts.
    expect(
      runOutcome(scope({ unallocated: { scanned_pct: 99.9, measured: true } }), steps()).reasons,
    ).toEqual(["비할당 99.9%"]);
  });

  it("unknown when the server sent neither scope nor steps", () => {
    expect(runOutcome(null, null).kind).toBe("unknown");
    expect(runOutcome(scope({ basis: "unavailable" }), null).kind).toBe("unknown");
    // Folder evidence: no scope, but the steps still decide.
    expect(runOutcome(scope({ basis: "unavailable" }), steps()).kind).toBe("complete");
  });
});

describe("runIdentityText (T-174)", () => {
  it("names the case and the evidence the run belongs to", () => {
    expect(runIdentityText(RUN, CASES.cases as never)).toBe("내부 유출 사건 · 직원 노트북");
  });

  it("falls back to the evidence file name, never the run id", () => {
    expect(runIdentityText(RUN, [])).toBe("laptop.E01");
    expect(runIdentityText(RUN, null)).not.toContain(RUN_ID.slice(0, 8));
  });
});

describe("status bar outcome (T-174)", () => {
  it("C2: 부분 + 실패 단계 2 under the case/evidence names; never 완료 · 오류 0", async () => {
    renderBar({ scope: C2_SCOPE, steps: C2_STEPS });
    const chip = await screen.findByText("부분");
    expect(chip.getAttribute("title")).toContain("파티션 1/2");
    expect(screen.getByTestId("status-failed-steps").textContent).toBe("실패 단계 2");
    await waitFor(() =>
      expect(screen.getByTestId("status-run-name").textContent).toBe("내부 유출 사건 · 직원 노트북"),
    );
    const bar = screen.getByTestId("status-run").textContent ?? "";
    expect(bar).not.toContain("완료");
    expect(bar).not.toContain("오류 0");
    expect(bar).not.toContain(`런 ${RUN_ID.slice(0, 8)}`);
    expect(screen.getByTestId("status-run-name").getAttribute("title")).toBe(`런 ID ${RUN_ID}`);
  });

  it("C1: green 완료 with no failed-step count", async () => {
    renderBar({ scope: scope(), steps: steps() });
    const chip = await screen.findByText("완료");
    expect(chip.getAttribute("data-tone")).toBe("ok");
    expect(screen.queryByTestId("status-failed-steps")).toBeNull();
    expect(screen.getByTestId("status-run").textContent).not.toContain("오류 0");
  });

  it("an older server without scope/steps keeps the run status chip", async () => {
    renderBar({ scope: null, steps: null }, { cases: [] });
    await waitFor(() => expect(screen.queryByText("범위 확인 중")).toBeNull());
    expect(screen.getByTestId("status-run").textContent).toContain("완료");
    expect(screen.getByTestId("status-run-name").textContent).toBe("laptop.E01");
  });
});
