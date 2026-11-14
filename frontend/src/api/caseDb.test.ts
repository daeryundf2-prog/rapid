import { describe, expect, it } from "vitest";
import { type ReviewCounts, reportCandidatesText } from "./caseDb";

const base: ReviewCounts = {
  run_id: "r1",
  database: "db",
  case_id: "c1",
  exists: true,
  by_status: {},
  include_in_report: 2,
  case_json: { bookmarks: 2, include_in_report: 1 },
  report_candidates: 3,
};

describe("reportCandidatesText (R8 RI-02)", () => {
  it("shows the one count", () => {
    expect(reportCandidatesText(base)).toBe("3건");
  });

  it("names the mark cap instead of hiding it", () => {
    const text = reportCandidatesText({
      ...base,
      truncated: true,
      report_candidates_detail: {
        count: 3,
        case_db: 2,
        case_json: 1,
        truncated: true,
        case_db_marks_total: 6000,
        case_db_mark_limit: 5000,
      },
    });
    expect(text).toBe("3건 (케이스 DB 표시 6,000건 중 최근 5,000건만 반영)");
  });

  it("shows the read error rather than 0", () => {
    const text = reportCandidatesText({
      ...base,
      report_candidates: null,
      error: { code: "CASE_DB_UNREADABLE", message: "케이스 DB를 읽지 못했습니다: x" },
    });
    expect(text).toBe("케이스 DB를 읽지 못했습니다: x");
  });
});
