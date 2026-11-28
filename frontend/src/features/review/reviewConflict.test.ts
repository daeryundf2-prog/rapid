import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type ReviewConflict, type ReviewMapMark, reviewConflictsOf } from "../../api/caseDb";
import type { GridRow } from "../../contracts/collection";
import { HINT_GROUPS } from "../../shell/ContextHint";
import { KEY_DESCRIPTIONS } from "../../shortcuts";
import { matchesColumnFilter } from "../filters/columnFilters";
import { makeRef, makeRow } from "../grid/columns/common";
import { boardTargetTitle, noteFirstLine, reviewCollection, reviewerTooltip } from "../grid/columns/review";
import {
  applyNote,
  applyReviewAction,
  pinExpected,
  ReviewConflictError,
  rememberWrite,
  resetCaseDbHandles,
} from "../grid/reviewActions";
import { buildReviewMap, overlayReview } from "../grid/reviewMap";
import { installFetch, jsonResponse } from "../grid/testSupport";
import type { ColumnSpec } from "../grid/types";
import { reviewerLabel } from "./author";
import { hashCheck, NOT_IN_REPORT_FILTER, reportChecklist, reviewerCounts } from "./boardModel";
import {
  currentVersion,
  markWriteSeq,
  noteWrittenMarks,
  rememberReviewMarks,
  resetMarkVersions,
  reviewKey,
} from "./markVersions";
import { conflictSentence, quotedTo, useReviewConflict, withObject, withSubject } from "./reviewConflict";

const RUN = "run-c";
const FILE_1 = { locator: reviewKey("files", "", "/candidates/1") };

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
    version: 1,
    collection: "files",
    kind: "",
    locator: "/candidates/1",
    ...over,
  };
}

function fileRow(locator: string, fields: Record<string, unknown> = {}): GridRow {
  return makeRow(
    makeRef("files", locator),
    { title: `f${locator}`, sourcePath: "C:/x" },
    { pointer: locator, ...fields },
  );
}

/** A 409 detail for file_record 1 at /candidates/1. */
function conflictDetail(current: Record<string, unknown>, expected = 1) {
  return {
    detail: {
      code: "review-conflict",
      message: "충돌",
      conflicts: [
        {
          target_type: "file_record",
          target_id: "1",
          expected_version: expected,
          collection: "files",
          kind: "",
          locator: "/candidates/1",
          current: { exists: true, status: "relevant", reviewer: "lee", version: 2, changes: [], ...current },
        },
      ],
    },
  };
}

type Batch = { targets: Array<{ expected_version?: number; expected_updated_at?: string }> };

/** Review-batch bodies; answers 409 for the attempts listed in `refuse`, else stores version `next`. */
function reviewServer(refuse: Record<number, unknown> = {}, next = (n: number) => n + 1) {
  const bodies: Batch[] = [];
  installFetch({
    "/case-db/ensure": () => jsonResponse({ database: "/d.db", case_id: "c" }),
    "/case-db/review-batch": (_url, init) => {
      const body = JSON.parse(String(init?.body)) as Batch;
      bodies.push(body);
      const detail = refuse[bodies.length];
      if (detail) return jsonResponse(detail, 409);
      const sent = body.targets[0]?.expected_version ?? 0;
      return jsonResponse({
        updated_count: 1,
        targets: [
          {
            target_type: "file_record",
            target_id: "1",
            collection: "files",
            kind: "",
            locator: "/candidates/1",
          },
        ],
        marks: [{ target_type: "file_record", target_id: "1", previous_version: sent, version: next(sent) }],
      });
    },
  });
  return bodies;
}

const sentVersion = (body: Batch | undefined) => body?.targets[0]?.expected_version;

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

describe("conflict wording (F14, P2-1, P3-4)", () => {
  const parse = (current: Record<string, unknown>): ReviewConflict =>
    (reviewConflictsOf(conflictDetail(current).detail) ?? [])[0] as ReviewConflict;
  const now = new Date("2026-11-28T09:00:00Z");

  it("particles follow the last syllable", () => {
    expect(withSubject("김철수")).toBe("김철수가");
    expect(withSubject("이름 없음")).toBe("이름 없음이");
    expect(quotedTo("재검토")).toBe("‘재검토’로");
    expect(quotedTo("관련 있음")).toBe("‘관련 있음’으로");
    expect(withObject("메모")).toBe("메모를");
    expect(withObject("보고서 포함")).toBe("보고서 포함을");
  });

  it("a changed verdict names who SET it and when, not whoever wrote last", () => {
    const conflict = parse({
      status: "needs-review",
      reviewer: "lee",
      updated_at: "2026-11-28T05:30:00+00:00",
      status_by: "김철수",
      status_at: "2026-11-28T05:05:00+00:00",
      changes: [
        { version: 3, actor: "lee", changed_at: "2026-11-28T05:30:00+00:00", fields: ["note"] },
        { version: 2, actor: "김철수", changed_at: "2026-11-28T05:05:00+00:00", fields: ["status"] },
      ],
    });
    expect(conflictSentence(conflict, "utc", now)).toBe("김철수가 05:05 UTC에 ‘재검토’로 바꿈 (메모도 바뀜)");
  });

  it("a note-only change says the note changed, by its writer — not that the verdict did", () => {
    const conflict = parse({
      status: "relevant",
      reviewer: "lee",
      updated_at: "2026-11-28T05:30:00+00:00",
      status_by: "kim",
      status_at: "2026-11-28T04:00:00+00:00",
      changes: [{ version: 2, actor: "lee", changed_at: "2026-11-28T05:30:00+00:00", fields: ["note"] }],
    });
    expect(conflictSentence(conflict, "utc", now)).toBe("lee가 05:30 UTC에 메모를 바꿈");
    const cleared = parse({
      exists: false,
      status: "unreviewed",
      changes: [{ version: 4, actor: "박검사", changed_at: "2026-11-28T06:00:00+00:00", fields: ["status"] }],
    });
    expect(conflictSentence(cleared, "utc", now)).toBe("박검사가 06:00 UTC에 표시를 지움");
    expect(reviewConflictsOf({ detail: "x" })).toBeNull();
  });

  it("an older server without changes keeps the verdict sentence", () => {
    const conflict = parse({
      status: "needs-review",
      reviewer: "김철수",
      updated_at: "2026-11-28T05:05:00+00:00",
    });
    expect(conflictSentence(conflict, "utc", now)).toBe("김철수가 05:05 UTC에 ‘재검토’로 바꿈");
  });
});

describe("mark versions (F14, P1-1, P3-1, P3-2, P3-3)", () => {
  it("knows the read version, 0 for no mark in a complete map, nothing when unknown", () => {
    expect(currentVersion(RUN, { locator: reviewKey("files", "", "/candidates/9") })).toBeUndefined();
    rememberReviewMarks(RUN, [mark({ version: 4 })], false);
    expect(currentVersion(RUN, FILE_1)).toBe(4);
    expect(currentVersion(RUN, { locator: reviewKey("files", "", "/candidates/9") })).toBe(0);
    rememberReviewMarks(RUN, [], true);
    expect(currentVersion(RUN, { locator: reviewKey("files", "", "/candidates/9") })).toBeUndefined();
  });

  it("a complete map without a mark someone cleared drops its old version to 0 (P3-3)", () => {
    rememberReviewMarks(RUN, [mark({ version: 3 })], false);
    rememberReviewMarks(RUN, [], false);
    expect(currentVersion(RUN, FILE_1)).toBe(0);
  });

  it("a map load that started before this console's own write does not undo it", () => {
    rememberReviewMarks(RUN, [mark({ version: 1 })], false);
    const since = markWriteSeq();
    noteWrittenMarks(RUN, [{ target_type: "file_record", target_id: "1", previous_version: 1, version: 2 }]);
    rememberReviewMarks(RUN, [mark({ version: 1 })], false, since);
    expect(currentVersion(RUN, FILE_1)).toBe(2);
    rememberReviewMarks(RUN, [], false, since);
    expect(currentVersion(RUN, FILE_1)).toBe(2);
  });

  it("P1-1: a note form pins the version when it opens; a map reload meanwhile gives 409, not an overwrite", async () => {
    const bodies = reviewServer();
    rememberReviewMarks(RUN, [mark({ version: 1 })], false);
    const row = fileRow("/candidates/1");
    const pin = pinExpected(RUN, [row]);
    // The examiner types; the window regains focus and the review map reloads with lee's note.
    rememberReviewMarks(RUN, [mark({ version: 2, note: "lee의 메모" })], false);
    await applyNote(RUN, [row], "kim의 메모", { expected: pin });
    expect(sentVersion(bodies[0])).toBe(1);
    // Without a pin the console would have sent lee's version and overwritten the note silently.
    expect(pinExpected(RUN, [row])).toEqual([2]);
  });

  it("a row action expects the version drawn on the row, not a newer one loaded since", async () => {
    const bodies = reviewServer();
    rememberReviewMarks(RUN, [mark({ version: 5 })], false);
    await applyReviewAction(RUN, [fileRow("/candidates/1", { markVersion: 3 })], "excluded");
    expect(sentVersion(bodies[0])).toBe(3);
  });

  it("P3-2: a decision right after this console's own tag expects the version the tag stored", async () => {
    const bodies = reviewServer();
    rememberReviewMarks(RUN, [mark({ version: 1 })], false);
    const row = fileRow("/candidates/1", { markVersion: 1 });
    // The tag batch answers the requested target's versions (the map has not reloaded yet).
    rememberWrite(RUN, {
      marks: [
        {
          target_type: "file_record",
          target_id: "1",
          collection: "files",
          kind: "",
          locator: "/candidates/1",
          previous_version: 1,
          version: 2,
        },
      ],
    });
    const result = await applyReviewAction(RUN, [row], "excluded");
    expect(sentVersion(bodies[0])).toBe(2);
    expect(result.versions).toEqual([3]);
    // ...and the next one chains on through this console's own writes.
    await applyReviewAction(RUN, [row], "relevant");
    expect(sentVersion(bodies[1])).toBe(3);
  });

  it("someone else's write between the tag and the decision still conflicts", async () => {
    const bodies = reviewServer({ 1: conflictDetail({ version: 3 }, 1) });
    rememberReviewMarks(RUN, [mark({ version: 1 })], false);
    // lee wrote version 2; this console's tag (no expectation) then stored 3 over it.
    rememberWrite(RUN, {
      marks: [{ target_type: "file_record", target_id: "1", previous_version: 2, version: 3 }],
    });
    await expect(
      applyReviewAction(RUN, [fileRow("/candidates/1", { markVersion: 1 })], "excluded"),
    ).rejects.toBeInstanceOf(ReviewConflictError);
    expect(sentVersion(bodies[0])).toBe(1);
  });

  it("a 409 opens the prompt; 내 판정으로 resends with the reported version and settles the error", async () => {
    const bodies = reviewServer({ 1: conflictDetail({ status: "needs-review", version: 2 }) });
    rememberReviewMarks(RUN, [mark({ version: 1 })], false);
    const failure = await applyReviewAction(RUN, [fileRow("/candidates/1")], "excluded").catch((e) => e);
    expect(failure).toBeInstanceOf(ReviewConflictError);
    expect(sentVersion(bodies[0])).toBe(1);
    const prompt = useReviewConflict.getState().prompt;
    expect(prompt?.conflicts).toHaveLength(1);
    await prompt?.resolve("mine");
    expect(sentVersion(bodies[1])).toBe(2);
    await expect((failure as ReviewConflictError).choice).resolves.toBe("mine");
  });

  it("그대로 두기: the examiner saw the current mark, so the same pin then expects it (no second prompt)", async () => {
    const bodies = reviewServer({ 1: conflictDetail({ note: "lee의 메모", version: 2 }) });
    rememberReviewMarks(RUN, [mark({ version: 1 })], false);
    const row = fileRow("/candidates/1");
    const pin = pinExpected(RUN, [row]);
    const failure = (await applyNote(RUN, [row], "kim", { expected: pin }).catch(
      (e) => e,
    )) as ReviewConflictError;
    expect(useReviewConflict.getState().prompt?.mine).toEqual({ note: "kim" });
    await useReviewConflict.getState().prompt?.resolve("keep");
    await expect(failure.choice).resolves.toBe("keep");
    expect(bodies).toHaveLength(1);
    await applyNote(RUN, [row], "kim, lee 메모 읽음", { expected: pin });
    expect(sentVersion(bodies[1])).toBe(2);
  });
});

describe("review-map overlay versions", () => {
  it("rows carry the mark's version; a complete map says 0 where there is no mark", () => {
    const map = buildReviewMap([mark({ version: 7 })], true);
    expect(overlayReview(fileRow("/candidates/1"), map).fields.markVersion).toBe(7);
    expect(overlayReview(fileRow("/candidates/2"), map).fields.markVersion).toBe(0);
    const partial = buildReviewMap([mark({ version: 7 })]);
    const other = fileRow("/candidates/2");
    expect(overlayReview(other, partial)).toBe(other);
  });
});

describe("board model (F12/F16, P2-1, P3-6)", () => {
  const row = (over: Record<string, unknown>, status: GridRow["reviewStatus"] = "relevant") =>
    makeRow(makeRef("review", String(Math.random())), { title: "t", reviewStatus: status }, over);
  const boardRow = (raw: Record<string, unknown>) =>
    reviewCollection.mapRow({ _store: "case-db", ...raw }, 0, { ref: { id: "review" } });
  const column = (id: string) => reviewCollection.columns.find((c) => c.id === id) as ColumnSpec;

  it("checklist: included, 관련 있음 left out (never added automatically), unnamed decisions", () => {
    const rows = [
      row({ includeInReport: true, reviewer: "kim" }),
      row({ includeInReport: false, reviewer: "web-ui" }),
      row({ includeInReport: true, reviewer: "" }, "needs-review"),
      row({ includeInReport: false, reviewer: "kim" }, "excluded"),
      // A report-only mark has no verdict: nobody to name.
      row({ includeInReport: true, reviewer: "" }, "include-in-report"),
    ];
    const check = reportChecklist(rows);
    expect(check.included).toHaveLength(3);
    expect(check.relevantLeftOut).toHaveLength(1);
    expect([check.unnamed, check.unnamedIncluded]).toEqual([2, 1]);
    expect(reviewerCounts(rows)).toEqual([
      { label: "kim", count: 2 },
      { label: "이름 없음", count: 2 },
    ]);
  });

  it("판정자 / 판정 시각 are who set the verdict and when; a later note writer is only the last change", () => {
    const board = boardRow({
      target_type: "file_record",
      target_id: "10",
      status: "excluded",
      include_in_report: true,
      note: "kim의 메모",
      reviewer: "kim",
      updated_at: "2026-11-28T05:30:00+00:00",
      status_by: "lee",
      status_at: "2026-11-28T05:05:00+00:00",
      version: 4,
    });
    expect(column("reviewer").value(board)).toBe("lee");
    expect(column("decidedAt").value(board)).toBe("2026-11-28T05:05:00+00:00");
    expect(board.fields.markVersion).toBe(4);
    expect(reviewerTooltip(board)).toMatch(/^판정자 lee, 마지막 변경 kim /);
    const noteOnly = boardRow({
      target_type: "file_record",
      target_id: "11",
      status: "unreviewed",
      note: "n",
      reviewer: "kim",
    });
    expect(column("reviewer").value(noteOnly)).toBe("");
    expect(reviewerCounts([board, noteOnly])).toEqual([{ label: "lee", count: 1 }]);
  });

  it("a verdict set by Z says so in the 판정자 tooltip (re-review P2)", () => {
    const board = boardRow({
      target_type: "file_record",
      target_id: "12",
      status: "excluded",
      reviewer: "kim",
      status_by: "kim",
      status_at: "2026-11-28T05:05:00+00:00",
      undo_of: { undone_version: 3, undone_reviewer: "lee" },
    });
    // The actor stays the one who pressed Z; the tooltip names the verdict it undid.
    expect(column("reviewer").value(board)).toBe("kim");
    expect(reviewerTooltip(board)).toBe("판정자 kim, 되돌림 (원래 판정: lee v3)");
    expect(KEY_DESCRIPTIONS.undoVerdict).toBe(
      "직전 판정을 되돌림 — 이전 판정을 다시 적용하고 작업자는 되돌린 사람으로 기록. 되돌리기 목록은 이 탭에만 있고 새로고침하면 사라짐",
    );
    expect(HINT_GROUPS.find((group) => group.ids.includes("review.undo"))?.title).toBe(
      `Z: ${KEY_DESCRIPTIONS.undoVerdict}`,
    );
  });

  it("P3-6: the 보고서 filter 포함 does not match 미포함", () => {
    const report = column("report");
    const included = row({ includeInReport: true });
    const left = row({ includeInReport: false });
    const filter = { col: "report", op: ":" as const, value: "포함" };
    expect(matchesColumnFilter(report, included, filter)).toBe(true);
    expect(matchesColumnFilter(report, left, filter)).toBe(false);
    expect(matchesColumnFilter(report, left, NOT_IN_REPORT_FILTER[0] as typeof filter)).toBe(true);
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
