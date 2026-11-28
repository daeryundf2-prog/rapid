import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type ReviewMapMark, reviewConflictsOf } from "../../api/caseDb";
import type { GridRow } from "../../contracts/collection";
import { makeRef, makeRow } from "../grid/columns/common";
import { boardTargetTitle, noteFirstLine } from "../grid/columns/review";
import { applyReviewAction, ReviewConflictError, resetCaseDbHandles } from "../grid/reviewActions";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { reviewerLabel } from "./author";
import { hashCheck, reportChecklist, reviewerCounts } from "./boardModel";
import { expectedVersion, rememberReviewMarks, resetMarkVersions, reviewKey } from "./markVersions";
import { conflictSentence, quotedTo, useReviewConflict, withSubject } from "./reviewConflict";

const RUN = "run-c";

function mark(over: Partial<ReviewMapMark>): ReviewMapMark {
  return {
    citation_id: "c",
    target_type: "file_record",
    target_id: "1",
    status: "relevant",
    tags: [],
    note: "",
    include_in_report: false,
    updated_at: "2026-11-28T01:00:00.000001+00:00",
    collection: "files",
    kind: "",
    locator: "/candidates/1",
    ...over,
  };
}

function fileRow(locator: string): GridRow {
  return makeRow(
    makeRef("files", locator),
    { title: `f${locator}`, sourcePath: "C:/x" },
    { pointer: locator },
  );
}

beforeEach(() => {
  resetMarkVersions();
  resetCaseDbHandles();
  useReviewConflict.setState({ prompt: null, seq: 0 });
});
afterEach(() => vi.unstubAllGlobals());

describe("reviewer names (F13)", () => {
  it("empty, web-ui and local-user read 이름 없음", () => {
    expect(["", "web-ui", "local-user", "  "].map(reviewerLabel)).toEqual(Array(4).fill("이름 없음"));
    expect(reviewerLabel("김검사")).toBe("김검사");
  });
});

describe("conflict wording (F14)", () => {
  it("particles follow the last syllable", () => {
    expect(withSubject("김철수")).toBe("김철수가");
    expect(withSubject("이름 없음")).toBe("이름 없음이");
    expect(quotedTo("재검토")).toBe("‘재검토’로");
    expect(quotedTo("관련 있음")).toBe("‘관련 있음’으로");
  });

  it("says who changed the mark, when and to what", () => {
    const [conflict] =
      reviewConflictsOf({
        code: "review-conflict",
        conflicts: [
          {
            target_type: "event",
            target_id: "4",
            expected_updated_at: "a",
            current: {
              exists: true,
              status: "needs-review",
              reviewer: "김철수",
              updated_at: "2026-11-28T05:05:00+00:00",
            },
          },
        ],
      }) ?? [];
    expect(conflict && conflictSentence(conflict, "utc", new Date("2026-11-28T09:00:00Z"))).toBe(
      "김철수가 05:05 UTC에 ‘재검토’로 바꿈",
    );
    expect(reviewConflictsOf({ detail: "x" })).toBeNull();
  });
});

describe("mark versions (F14)", () => {
  it("sends the read version, '' for no mark in a complete map, nothing when unknown", () => {
    expect(expectedVersion(RUN, { locator: reviewKey("files", "", "/candidates/9") })).toBeUndefined();
    rememberReviewMarks(RUN, [mark({})], false);
    expect(expectedVersion(RUN, { locator: reviewKey("files", "", "/candidates/1") })).toBe(
      "2026-11-28T01:00:00.000001+00:00",
    );
    expect(expectedVersion(RUN, { locator: reviewKey("files", "", "/candidates/9") })).toBe("");
    // A newer board row wins over an older map entry.
    expect(expectedVersion(RUN, { target: "file_record:1", boardVersion: "2026-11-28T02:00:00+00:00" })).toBe(
      "2026-11-28T02:00:00+00:00",
    );
    rememberReviewMarks(RUN, [], true);
    expect(expectedVersion(RUN, { locator: reviewKey("files", "", "/candidates/9") })).toBeUndefined();
  });

  it("a 409 opens the prompt and rejects; 내 판정으로 resends with the reported version", async () => {
    rememberReviewMarks(RUN, [mark({})], false);
    const bodies: unknown[] = [];
    let attempt = 0;
    installFetch({
      "/case-db/ensure": () => jsonResponse({ database: "/d.db", case_id: "c" }),
      "/case-db/review-batch": (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        attempt += 1;
        if (attempt === 1) {
          return jsonResponse(
            {
              detail: {
                code: "review-conflict",
                message: "충돌",
                conflicts: [
                  {
                    target_type: "file_record",
                    target_id: "1",
                    expected_updated_at: "2026-11-28T01:00:00.000001+00:00",
                    collection: "files",
                    kind: "",
                    locator: "/candidates/1",
                    current: {
                      exists: true,
                      status: "needs-review",
                      reviewer: "lee",
                      updated_at: "2026-11-28T03:00:00+00:00",
                      expected_updated_at: "2026-11-28T03:00:00+00:00",
                    },
                  },
                ],
              },
            },
            409,
          );
        }
        return jsonResponse({ updated_count: 1, targets: [], marks: [] });
      },
    });
    await expect(applyReviewAction(RUN, [fileRow("/candidates/1")], "excluded")).rejects.toBeInstanceOf(
      ReviewConflictError,
    );
    expect(
      (bodies[0] as { targets: Array<{ expected_updated_at?: string }> }).targets[0]?.expected_updated_at,
    ).toBe("2026-11-28T01:00:00.000001+00:00");
    const prompt = useReviewConflict.getState().prompt;
    expect(prompt?.conflicts).toHaveLength(1);
    await prompt?.resolve("mine");
    expect(
      (bodies[1] as { targets: Array<{ expected_updated_at?: string }> }).targets[0]?.expected_updated_at,
    ).toBe("2026-11-28T03:00:00+00:00");
  });
});

describe("board model (F12/F16)", () => {
  const row = (over: Record<string, unknown>, status: GridRow["reviewStatus"] = "relevant") =>
    makeRow(makeRef("review", String(Math.random())), { title: "t", reviewStatus: status }, over);

  it("checklist: included, 관련 있음 left out (never added automatically), unnamed decisions", () => {
    const rows = [
      row({ includeInReport: true, reviewer: "kim" }),
      row({ includeInReport: false, reviewer: "web-ui" }),
      row({ includeInReport: true, reviewer: "" }, "needs-review"),
      row({ includeInReport: false, reviewer: "kim" }, "excluded"),
    ];
    const check = reportChecklist(rows);
    expect(check.included).toHaveLength(2);
    expect(check.relevantLeftOut).toHaveLength(1);
    expect([check.unnamed, check.unnamedIncluded]).toEqual([2, 1]);
    expect(reviewerCounts(rows)).toEqual([
      { label: "kim", count: 2 },
      { label: "이름 없음", count: 2 },
    ]);
  });

  it("hash check separates matched, broken and unverified evidence", () => {
    expect(
      hashCheck([
        { hash_status: "matched" },
        { hash_status: "computed" },
        { hash_status: "mismatched" },
        { hash_status: "" },
      ]),
    ).toEqual({ total: 4, matched: 1, broken: 1, unverified: 2 });
  });

  it("the board shows the target first and one note line", () => {
    expect(boardTargetTitle("Artifact event: srum-app-usage evidence-bundle.zip")).toBe(
      "srum-app-usage evidence-bundle.zip",
    );
    expect(noteFirstLine("첫 줄\n둘째 줄")).toBe("첫 줄");
  });
});
