import { describe, expect, it } from "vitest";
import type { ReviewMapMark } from "../../api/caseDb";
import type { CaseEvidence, RunProblems } from "../../api/cases";
import type { CanonicalCounts } from "../../api/runs";
import { sealState } from "../case/integrity";
import type { TimelineHistogramPayload } from "../views/histogram";
import {
  activityBars,
  isEmptyRun,
  overviewFigures,
  problemsNeedingAttention,
  relevantNotInReport,
  todoItems,
  unreviewedIndicators,
} from "./overviewModel";

function mark(overrides: Partial<ReviewMapMark>): ReviewMapMark {
  return {
    citation_id: "M",
    target_type: "run_output",
    target_id: "1",
    status: "relevant",
    tags: [],
    note: "",
    include_in_report: false,
    updated_at: "2026-11-27T00:00:00Z",
    collection: "timeline",
    kind: "",
    locator: "/events/1",
    ...overrides,
  };
}

function problems(byLevel: Record<string, number>): RunProblems {
  return {
    run_id: "r1",
    total: Object.values(byLevel).reduce((a, b) => a + b, 0),
    by_level: byLevel,
    limit: 20,
    groups: [],
  };
}

const evidence = (status: string, extra: Partial<CaseEvidence> = {}): CaseEvidence => ({
  citation_id: `C-${status}`,
  case_id: "case-1",
  evidence_number: "E-01",
  display_name: "disk",
  source_type: "raw",
  path: "/ev/disk.dd",
  size_bytes: 10,
  hash_verify: true,
  hash_expected: "",
  hash_status: status,
  hash_status_label: status,
  hash_message: "",
  hashes: {},
  added_at: null,
  runs: [],
  ...extra,
});

const counts = (overrides: Partial<CanonicalCounts> = {}): CanonicalCounts => ({
  validation_issues: 0,
  outputs: 0,
  artifacts: 16,
  docs: 5,
  files: 9,
  timeline_events: 720,
  review_items: 0,
  indicators: 39,
  ...overrides,
});

describe("먼저 할 일 (F7)", () => {
  it("lists only what applies, in order: hash, problems, indicators, report gap", () => {
    const items = todoItems({
      seal: sealState([evidence("not-requested")]),
      problems: problems({ warning: 26, notice: 11 }),
      indicators: 39,
      marks: [
        mark({ citation_id: "1", status: "relevant" }),
        mark({ citation_id: "2", status: "relevant", include_in_report: true }),
        mark({ citation_id: "3", collection: "indicators", status: "excluded" }),
      ],
    });
    expect(items.map((item) => item.id)).toEqual(["hash", "problems", "indicators", "report-gap"]);
    expect(items[0]?.text).toBe("증거 1건의 해시를 검증하지 않았습니다");
    expect(items[0]?.action).toBe("검증");
    expect(items[1]?.text).toContain("처리 문제 26건");
    expect(items[2]?.text).toBe("판정하지 않은 지표 후보 38건");
    expect(items[3]?.text).toBe("관련 있음 1건이 보고서에 포함되지 않았습니다");
  });

  it("says a broken seal as an error and names mismatch / failure counts", () => {
    const [item] = todoItems({
      seal: sealState([evidence("mismatched"), evidence("failed", { citation_id: "f" })]),
      problems: undefined,
      indicators: undefined,
      marks: undefined,
    });
    expect(item?.severity).toBe("danger");
    expect(item?.text).toBe("증거 무결성이 깨졌습니다: 기대값 불일치 1건, 계산 실패 1건");
    expect(item?.action).toBe("검증");
    const [mismatchOnly] = todoItems({
      seal: sealState([evidence("mismatched")]),
      problems: undefined,
      indicators: undefined,
      marks: undefined,
    });
    expect(mismatchOnly?.action).toBe("해시 자세히");
  });

  it("is empty when nothing applies (hashing, matched, computed, no seal, notices only, all reviewed)", () => {
    for (const status of ["hashing", "matched", "computed"]) {
      expect(
        todoItems({
          seal: sealState([evidence(status)]),
          problems: problems({ notice: 4 }),
          indicators: 1,
          marks: [mark({ collection: "indicators", status: "excluded" })],
        }),
      ).toEqual([]);
    }
    expect(todoItems({ seal: null, problems: undefined, indicators: undefined, marks: undefined })).toEqual(
      [],
    );
  });

  it("counts problems needing attention (error + warning) and verdict marks only", () => {
    expect(problemsNeedingAttention(problems({ error: 2, warning: 3, notice: 9 }))).toBe(5);
    expect(problemsNeedingAttention(undefined)).toBe(0);
    // Groups win over by_level: the count matches the 처리 문제 card the action opens.
    const group = (level: string, count: number) => ({
      reason_id: level,
      label_ko: level,
      level,
      count,
      steps: [],
      items: [],
    });
    expect(
      problemsNeedingAttention({
        ...problems({ notice: 33, warning: 4 }),
        groups: [group("warning", 23), group("notice", 6)],
      }),
    ).toBe(23);
    expect(
      unreviewedIndicators(5, [
        mark({ collection: "indicators", status: "unreviewed" }),
        mark({ collection: "indicators", status: "relevant" }),
        mark({ collection: "timeline", status: "relevant" }),
      ]),
    ).toBe(4);
    expect(
      unreviewedIndicators(1, [mark({ collection: "indicators" }), mark({ collection: "indicators" })]),
    ).toBe(0);
    expect(unreviewedIndicators(undefined, [])).toBeUndefined();
    expect(relevantNotInReport(undefined)).toBeUndefined();
  });
});

describe("사건 숫자 (F6)", () => {
  it("names the population of every number and sums verdict marks", () => {
    const figures = overviewFigures(counts(), {
      run_id: "r1",
      database: "/db",
      case_id: "c",
      exists: true,
      by_status: { relevant: 7, "needs-review": 3, excluded: 3, unreviewed: 2 },
      include_in_report: 0,
      case_json: { bookmarks: 0, include_in_report: 0 },
      report_candidates: 0,
    });
    expect(figures.map((f) => [f.id, f.value])).toEqual([
      ["timeline", 720],
      ["files", 9],
      ["artifacts", 16],
      ["indicators", 39],
      ["marks", 13],
    ]);
    for (const figure of figures) expect(figure.population.length).toBeGreaterThan(4);
    expect(figures.find((f) => f.id === "files")?.population).toContain("전체 파일 수가 아님");
  });

  it("leaves unknown counts out instead of showing 0", () => {
    expect(overviewFigures(undefined, undefined)).toEqual([]);
  });

  it("detects a run that collected nothing", () => {
    expect(isEmptyRun(counts({ artifacts: 0, docs: 0, files: 0, timeline_events: 0, indicators: 0 }))).toBe(
      true,
    );
    expect(isEmptyRun(counts())).toBe(false);
    expect(isEmptyRun(undefined)).toBe(false);
  });
});

function payload(buckets: Array<[string, number]>, bucketSeconds = 3600): TimelineHistogramPayload {
  return {
    total_events: buckets.reduce((sum, [, c]) => sum + c, 0),
    parsed_events: 0,
    unparsed_events: 0,
    bucket_seconds: bucketSeconds,
    bucket_count: buckets.length,
    range_start: buckets[0]?.[0] ?? null,
    range_end: null,
    sources: [],
    buckets: buckets.map(([start, count], index) => ({
      index,
      start,
      end: new Date(Date.parse(start) + bucketSeconds * 1000).toISOString(),
      count,
    })),
  };
}

describe("날짜별 활동 (F6)", () => {
  it("draws one bar per display-zone day, empty days kept, and finds the busiest day and hour", () => {
    const activity = activityBars(
      payload([
        ["2026-10-17T23:00:00Z", 2], // 10-18 08:00 KST
        ["2026-10-18T05:00:00Z", 4],
        ["2026-10-20T01:00:00Z", 10],
        ["2026-10-20T02:00:00Z", 3],
      ]),
      "Asia/Seoul",
    );
    expect(activity.unit).toBe("day");
    expect(activity.bars.map((bar) => [bar.label, bar.count])).toEqual([
      ["10-18 (일)", 6],
      ["10-19 (월)", 0],
      ["10-20 (화)", 13],
    ]);
    expect(activity.total).toBe(19);
    expect(activity.busiest?.label).toBe("10-20 (화)");
    expect(activity.busiest?.ratio).toBe(1);
    expect(activity.busiestHour).toEqual({
      startMs: Date.parse("2026-10-20T01:00:00Z"),
      endMs: Date.parse("2026-10-20T02:00:00Z"),
      count: 10,
    });
    // Day bounds are KST midnights.
    expect(new Date(activity.bars[0]?.startMs ?? 0).toISOString()).toBe("2026-10-17T15:00:00.000Z");
  });

  it("switches to month bars past 62 days and gives no hour inside a month", () => {
    const activity = activityBars(
      payload(
        [
          ["2026-01-05T00:00:00Z", 3],
          ["2026-04-10T00:00:00Z", 8],
        ],
        86_400,
      ),
      "utc",
    );
    expect(activity.unit).toBe("month");
    expect(activity.bars.map((bar) => [bar.label, bar.count])).toEqual([
      ["2026-01", 3],
      ["2026-02", 0],
      ["2026-03", 0],
      ["2026-04", 8],
    ]);
    expect(activity.busiestHour).toBeNull();
  });

  it("is empty without events", () => {
    expect(activityBars(undefined, "utc").busiest).toBeNull();
    expect(activityBars(payload([["2026-01-01T00:00:00Z", 0]]), "utc").bars).toEqual([]);
  });
});
