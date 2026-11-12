// T-022 (GAP-029, QA-019): the 접수 strip and the 처리 상태 card print the server's step counts
// (`/dashboard` `steps`, T-021 summarize_steps) — for an IMG-B-like run "단계 42 · 완료 39 · 부분 1 ·
// 실패 1 · 건너뜀 1" — while the 12 collectors are a separate "수집기 12"; "12/12 완료·오류 0" is gone.

import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { normalizeSteps } from "../../api/dashboard";
import { StatusCard, StatusStrip } from "./cards";
import { IMG_B_PROVIDERS, IMG_B_STEPS, IMG_B_STEPS_TEXT } from "./stepsFixture";
import type { RunDetail } from "./useDashboardData";

afterEach(cleanup);

const RUN = {
  run_id: "imgb",
  status: "completed",
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T01:00:00Z",
  request: { root: "D:/ev/IMG-B.E01", mode: "fraud" },
  progress: {
    status: "completed",
    started_at: "2026-11-01T00:00:00Z",
    completed_at: "2026-11-01T01:00:00Z",
    providers: IMG_B_PROVIDERS,
    completed_count: 12,
    total_count: 12,
    error_count: 0,
  },
} as unknown as RunDetail;

const STAGES = Array.from({ length: 12 }, (_, i) => ({
  stage: `stage-${i + 1}`,
  state: "done" as const,
  startedAt: null,
  completedAt: null,
  durationMs: null,
}));

function renderBoth(steps: ReturnType<typeof normalizeSteps>) {
  return render(
    <>
      <StatusStrip
        run={RUN}
        stages={STAGES}
        steps={steps}
        crumb={null}
        onOpenSummary={() => {}}
        onOpenSettings={() => {}}
      />
      <StatusCard
        run={RUN}
        stages={STAGES}
        steps={steps}
        counts={undefined}
        outputDir=""
        issues={undefined}
      />
    </>,
  );
}

describe("접수 step counts = the server's summarize_steps (T-022)", () => {
  it("strip and 처리 상태 print the same line; the collectors are a separate 수집기 12", () => {
    const { container } = renderBoth(normalizeSteps(IMG_B_STEPS));
    const strip = screen.getByTestId("dash-strip");
    expect(within(strip).getByTestId("dash-strip-steps").textContent).toBe(IMG_B_STEPS_TEXT);
    const bar = within(strip).getByRole("progressbar", { name: "처리 단계 진행" });
    expect(bar.getAttribute("aria-valuetext")).toBe(IMG_B_STEPS_TEXT);
    expect(bar.getAttribute("aria-valuenow")).toBe("42");
    const summary = screen.getByTestId("stage-details").querySelector("summary");
    expect(summary?.textContent).toBe(`단계 상세 — ${IMG_B_STEPS_TEXT} · 수집기 12`);
    const text = container.textContent ?? "";
    expect(text).not.toMatch(/12\/12/);
    expect(text).not.toMatch(/오류 0/);
    expect(text).not.toMatch(/단계 \d+\/\d+ 완료/);
  });

  it("a finished run without server counts shows no step bar and no guessed n/n", () => {
    const { container } = renderBoth(null);
    expect(within(screen.getByTestId("dash-strip")).queryByRole("progressbar")).toBeNull();
    expect(screen.getByTestId("stage-details").querySelector("summary")?.textContent).toBe(
      "단계 상세 — 수집기 12",
    );
    expect(container.textContent ?? "").not.toMatch(/\d+\/\d+/);
  });
});
