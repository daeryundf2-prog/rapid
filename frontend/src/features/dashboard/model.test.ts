import { describe, expect, it } from "vitest";
import type { ReviewCounts } from "../../api/caseDb";
import { normalizeDashboard, normalizeSteps } from "../../api/dashboard";
import type { RunTree } from "../../api/runs";
import {
  categoryBars,
  formatDuration,
  keywordRows,
  reviewSummary,
  stageRows,
  stepCountsText,
  stepProgress,
} from "./model";
import { IMG_B_STEPS, IMG_B_STEPS_TEXT } from "./stepsFixture";

describe("stageRows", () => {
  it("derives per-stage durations from consecutive completions plus the running stage", () => {
    const rows = stageRows(
      {
        status: "running",
        started_at: "2026-10-11T00:00:00Z",
        stage: "artifacts",
        stage_started_at: "2026-10-11T00:00:05Z",
        completed_stages: [
          { stage: "fingerprint", completed_at: "2026-10-11T00:00:02Z" },
          { stage: "inventory", completed_at: "2026-10-11T00:00:05Z" },
        ],
      },
      Date.parse("2026-10-11T00:01:05Z"),
    );
    expect(rows.map((r) => [r.stage, r.state, r.durationMs])).toEqual([
      ["fingerprint", "done", 2000],
      ["inventory", "done", 3000],
      ["artifacts", "running", 60000],
    ]);
    // C-G4: one format and one rounding with the run chips (formatElapsed, floored seconds).
    expect(formatDuration(2000)).toBe("00:02");
    expect(formatDuration(65000)).toBe("01:05");
    expect(formatDuration(2_048_900)).toBe("34:08");
    expect(formatDuration(3_725_000)).toBe("1:02:05");
    expect(formatDuration(400)).toBe("1초 미만");
    expect(formatDuration(null)).toBe("—");
  });

  it("returns nothing without progress and omits the running row for finished runs", () => {
    expect(stageRows(null)).toEqual([]);
    const done = stageRows({
      status: "completed",
      stage: "persist",
      completed_stages: [{ stage: "persist" }],
    });
    expect(done).toHaveLength(1);
    expect(done[0]?.durationMs).toBeNull();
  });
});

const tree: RunTree = {
  run_id: "r1",
  root: {},
  nodes: [
    {
      id: "artifacts",
      label: "아티팩트",
      count: 130,
      collection: "artifacts",
      children: [
        { id: "artifacts:eventlog", label: "EVTX", count: 100, collection: "artifacts", kind: "eventlog" },
        {
          id: "artifacts:windows-registry",
          label: "레지스트리",
          count: 5,
          collection: "artifacts",
          kind: "windows-registry",
        },
        { id: "artifacts:browser", label: "브라우저", count: 20, collection: "artifacts", kind: "browser" },
        { id: "artifacts:plugin-x", label: "plugin", count: 5, collection: "artifacts", kind: "plugin-x" },
        { id: "artifacts:email", label: "이메일", count: 0, collection: "artifacts", kind: "email" },
      ],
    },
  ],
};

describe("categoryBars", () => {
  it("sums kinds per category, sorts largest first and scales to the largest bar", () => {
    const { bars, total } = categoryBars(tree);
    expect(bars.map((b) => [b.category.id, b.count, b.kinds])).toEqual([
      ["operating-system", 105, ["eventlog", "windows-registry"]],
      ["web", 20, ["browser"]],
      ["other", 5, ["plugin-x"]],
    ]);
    expect(bars[0]?.ratio).toBe(1);
    expect(bars[1]?.ratio).toBeCloseTo(20 / 105);
    expect(total).toBe(130);
  });

  it("is empty without a tree", () => {
    expect(categoryBars(undefined)).toEqual({ bars: [], total: 0 });
  });
});

describe("reviewSummary", () => {
  it("maps case-db status counts, report candidates and case bookmarks to colour-chipped rows", () => {
    const review: ReviewCounts = {
      run_id: "r1",
      database: "/o/case.db",
      case_id: "run-r1",
      exists: true,
      by_status: { relevant: 4, excluded: 1 },
      include_in_report: 2,
      case_json: { bookmarks: 3, include_in_report: 1 },
      report_candidates: 3,
    };
    const { rows, total } = reviewSummary(review);
    expect(rows.map((r) => [r.label, r.count, r.status])).toEqual([
      ["관련 있음", 4, "relevant"],
      ["재검토", 0, "needs-review"],
      ["제외", 1, "excluded"],
      ["보고서 포함", 3, "include-in-report"],
      ["리뷰보드 항목(북마크)", 3, undefined],
    ]);
    expect(rows[0]?.color).toContain("--status-relevant");
    expect(rows[4]?.color).toContain("--status-bookmark");
    expect(total).toBe(5);
    expect(reviewSummary(undefined).rows.every((r) => r.count === 0)).toBe(true);
  });
});

describe("keywordRows", () => {
  it("lists run-profile keywords then saved searches, skipping duplicates and empty searches", () => {
    const rows = keywordRows(
      ["fraud", "invoice", "fraud", " "],
      [
        { name: "계좌", keywords: ["bank", "account"] },
        { name: "빈 검색", keywords: [] },
      ],
    );
    expect(rows.map((r) => [r.label, r.query, r.source])).toEqual([
      ["fraud", "fraud", "profile"],
      ["invoice", "invoice", "profile"],
      ["계좌", "bank account", "saved"],
    ]);
    expect(rows[2]?.savedSearch?.name).toBe("계좌");
  });
});

describe("normalizeDashboard", () => {
  it("fills missing blocks so cards never read through undefined", () => {
    const empty = normalizeDashboard("r1", {});
    expect(empty.profile.keywords).toEqual([]);
    expect(empty.evidence_source.partitions).toEqual([]);
    expect(empty.exports).toEqual([]);
    expect(empty.run_id).toBe("r1");
  });
});

describe("stepCountsText (T-022)", () => {
  it("prints the IMG-B-like counts as the one shared line (failed_isolated is 부분, never 완료)", () => {
    expect(stepCountsText(normalizeSteps(IMG_B_STEPS))).toBe(IMG_B_STEPS_TEXT);
    expect(IMG_B_STEPS_TEXT).toBe("단계 42 · 완료 39 · 부분 1 · 실패 1 · 건너뜀 1");
  });

  it("always prints 단계 · 완료 · 부분 · 실패; 건너뜀 · 미완료 only when non-zero", () => {
    const steps = normalizeSteps({ total: 3, completed: 1, incomplete: 2 });
    expect(stepCountsText(steps)).toBe("단계 3 · 완료 1 · 부분 0 · 실패 0 · 미완료 2");
  });

  it("is empty without server counts (no client-side guess)", () => {
    expect(stepCountsText(null)).toBe("");
    expect(stepCountsText(undefined)).toBe("");
  });
});

describe("stepProgress (T-022)", () => {
  it("uses the server counts; live runs show 진행 단계 n/m; finished runs without counts get no bar", () => {
    expect(stepProgress(normalizeSteps(IMG_B_STEPS), true, 12, 12)).toEqual({
      now: 42,
      max: 42,
      text: IMG_B_STEPS_TEXT,
    });
    expect(stepProgress(null, false, 3, 5)).toEqual({ now: 3, max: 5, text: "진행 단계 3/5" });
    expect(stepProgress(null, true, 12, 12)).toBeNull();
    expect(stepProgress(undefined, false, 0, 0)).toBeNull();
  });
});

describe("normalizeSteps", () => {
  it("keeps the server's classes and names; null for missing or malformed payloads", () => {
    const steps = normalizeSteps(IMG_B_STEPS);
    expect(steps?.partial_names).toEqual(["artifacts-browser"]);
    expect(steps?.by_status).toEqual({ completed: 39, failed: 1, failed_isolated: 1, skipped: 1 });
    expect(normalizeSteps(null)).toBeNull();
    expect(normalizeSteps({ completed: 3 })).toBeNull();
    expect(normalizeSteps("x")).toBeNull();
    expect(normalizeDashboard("r1", { run_id: "r1" }).steps).toBeNull();
    expect(normalizeDashboard("r1", { run_id: "r1", steps: IMG_B_STEPS }).steps?.total).toBe(42);
  });
});
