import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../contracts/collection";
import { followFocusKey, rowFocusTarget } from "../features/grid/gridCommands";
import { changedReviewFields, resetCaseDbHandles, restoredPatch } from "../features/grid/reviewActions";
import {
  type RowFocusRequest,
  type RowFocusResult,
  registerRowSource,
  resetRowSources,
} from "../features/review/rowSource";
import { hexCursorSentence } from "../features/viewer/hex";
import { resetAppStore, useAppStore } from "../state/store";
import { registerCommands, resetCommandRegistry, runCommand } from "./registry";
import { reviewCommands } from "./review";
import {
  ADVANCE_STORAGE_KEY,
  NOTHING_TO_UNDO_REASON,
  reviewScope,
  rowScopeLabel,
  useVerdictPrefs,
  useVerdictUndo,
} from "./verdict";

const row = (n: number, patch: Partial<GridRow> = {}): GridRow => ({
  rowKey: `timeline:/events/${n}`,
  ref: { collection: "timeline", locator: `/events/${n}` },
  title: `event ${n}`,
  sourcePath: `C:/e/file${n}.db`,
  timestamp: `2026-10-18T0${n}:02:48Z`,
  artifactType: null,
  provider: null,
  sha256: null,
  reviewStatus: null,
  tags: [],
  fields: {},
  ...patch,
});

let posts: Array<{ url: string; body: Record<string, unknown> }>;
let rows: GridRow[];
let selected: string[];
let moves: RowFocusRequest[];
/** Keys the list shows (null: every row). */
let shown: Set<string> | null;
/** Source calls in order (advance before patch, review P1-2). */
let calls: string[];
let moveResult: RowFocusResult;
let failBatch: boolean;

beforeEach(() => {
  resetCommandRegistry();
  resetRowSources();
  resetCaseDbHandles();
  useVerdictUndo.getState().clear();
  useVerdictPrefs.getState().setAdvance("next");
  resetAppStore({ route: { runId: "r1", collection: "timeline", tz: "utc" } });
  posts = [];
  moves = [];
  shown = null;
  calls = [];
  moveResult = "moved";
  failBatch = false;
  rows = [row(1), row(2, { reviewStatus: "needs-review", tags: ["북마크"] }), row(3)];
  selected = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      posts.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) : {} });
      if (failBatch && String(url).includes("review-batch")) {
        return new Response(JSON.stringify({ error: "boom" }), {
          status: 500,
          headers: { "content-type": "application/json" },
        });
      }
      const payload = String(url).includes("/case-db/ensure")
        ? { database: "D:/out/case.db", case_id: "c1" }
        : { ok: true };
      return new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } });
    }),
  );
  registerRowSource({
    getSelectedRows: () => rows.filter((r) => selected.includes(r.rowKey)),
    getFocusedRow: () => rows[0],
    patchRows: (keys, patch) => {
      calls.push("patch");
      const before = rows;
      rows = rows.map((r) => (keys.includes(r.rowKey) ? patch(r) : r));
      return () => {
        rows = before;
      };
    },
    moveFocus: (request) => {
      calls.push("move");
      moves.push(request);
      return moveResult;
    },
    setSelection: (keys) => {
      selected = [...keys];
      useAppStore.getState().setSelectedRows(selected);
    },
    isShown: (key) => shown?.has(key) ?? true,
    clearSelection: () => {
      selected = [];
      useAppStore.getState().setSelectedRows([]);
    },
  });
  registerCommands(reviewCommands(null));
});

afterEach(() => {
  resetCommandRegistry();
  resetRowSources();
  vi.unstubAllGlobals();
});

const batches = () => posts.filter((p) => p.url === "/api/case-db/review-batch");

describe("reviewScope (F17: one function names and executes the scope)", () => {
  it("two or more selected rows → every selected row; one → the viewer row", () => {
    useAppStore
      .getState()
      .setViewerTarget(
        { ref: rows[0]?.ref as GridRow["ref"], runId: "r1", sourcePath: rows[0]?.sourcePath ?? null },
        { row: rows[0], syncUrl: false },
      );
    selected = [rows[1]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    expect(reviewScope()).toMatchObject({ kind: "row", label: "01:02:48 행", restorable: true });
    selected = [rows[1]?.rowKey as string, rows[2]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    const scope = reviewScope();
    expect(scope.kind).toBe("selection");
    expect(scope.label).toBe("선택 2건");
    expect(scope.rows.map((r) => r.rowKey)).toEqual(selected);
  });

  it("labels a row without a time by its short name", () => {
    expect(rowScopeLabel(row(4, { timestamp: null }), "utc")).toBe("'file4.db' 행");
  });

  it("R on a selection marks exactly the announced rows, clears the selection and moves on", async () => {
    selected = [rows[1]?.rowKey as string, rows[2]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    expect(await runCommand("review.mark.relevant")).toEqual({ ok: true });
    expect(batches()).toHaveLength(1);
    expect(batches()[0]?.body).toMatchObject({
      status: "relevant",
      targets: [
        { collection: "timeline", locator: "/events/2" },
        { collection: "timeline", locator: "/events/3" },
      ],
    });
    expect(selected).toEqual([]);
    expect(moves[0]).toMatchObject({
      after: ["timeline:/events/2", "timeline:/events/3"],
      unreviewed: false,
    });
    expect(useAppStore.getState().notice?.text).toBe("관련 있음 2건 · Z 되돌리기");
  });

  it("그대로 does not move; 다음 미판정 행 asks for the next unjudged row", async () => {
    useVerdictPrefs.getState().setAdvance("stay");
    await runCommand("review.mark.excluded");
    expect(moves).toEqual([]);
    useVerdictPrefs.getState().setAdvance("next-unreviewed");
    expect(window.localStorage.getItem(ADVANCE_STORAGE_KEY)).toBe("next-unreviewed");
    await runCommand("review.mark.excluded");
    expect(moves[0]).toMatchObject({ unreviewed: true });
  });

  it("picks the next row by key before the optimistic patch (review P1-2)", async () => {
    await runCommand("review.mark.relevant");
    expect(calls).toEqual(["move", "patch"]);
    expect(moves[0]).toMatchObject({ after: ["timeline:/events/1"] });
  });

  it("judges only the selected rows the list shows and names the hidden ones (review P2-1)", async () => {
    selected = rows.map((r) => r.rowKey);
    useAppStore.getState().setSelectedRows(selected);
    shown = new Set([rows[0]?.rowKey as string, rows[2]?.rowKey as string]);
    const scope = reviewScope();
    expect(scope).toMatchObject({ kind: "selection", hidden: 1, label: "선택 2건 · 숨은 선택 1건 제외" });
    await runCommand("review.mark.bookmark");
    expect(batches()[0]?.body.targets).toEqual([
      { collection: "timeline", locator: "/events/1" },
      { collection: "timeline", locator: "/events/3" },
    ]);
    expect(useAppStore.getState().notice?.text).toBe("북마크 2건 · Z 되돌리기 · 숨은 선택 1건 제외");
    // The hidden row was not judged: it stays selected.
    expect(selected).toEqual(["timeline:/events/2"]);
  });

  it("one shown selected row with hidden ones is still the selection, not the viewer row", () => {
    selected = [rows[1]?.rowKey as string, rows[2]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    shown = new Set([rows[2]?.rowKey as string]);
    expect(reviewScope()).toMatchObject({ kind: "selection", hidden: 1 });
    expect(reviewScope().rows.map((r) => r.rowKey)).toEqual(["timeline:/events/3"]);
  });

  it("a failed write puts the selection and the cursor back (review P3-3)", async () => {
    failBatch = true;
    selected = [rows[1]?.rowKey as string, rows[2]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    expect((await runCommand("review.mark.needs-review")).ok).toBe(false);
    expect(selected).toEqual(["timeline:/events/2", "timeline:/events/3"]);
    expect(moves.at(-1)).toMatchObject({ key: "timeline:/events/1" });
    expect(rows[2]?.reviewStatus).toBeNull();
  });

  it("says the loaded rows ran out instead of 'none left' (review P3-4)", async () => {
    moveResult = "unloaded";
    await runCommand("review.mark.relevant");
    expect(useAppStore.getState().notice?.text).toBe(
      "관련 있음 1건 · Z 되돌리기 · 불러온 마지막 행 — 아래로 스크롤해 더 불러오기",
    );
    useVerdictPrefs.getState().setAdvance("next-unreviewed");
    await runCommand("review.mark.relevant");
    expect(useAppStore.getState().notice?.text).toBe(
      "관련 있음 1건 · Z 되돌리기 · 불러온 행 중 미판정 없음 — 아래로 스크롤해 더 불러오기",
    );
    moveResult = "end";
    await runCommand("review.mark.relevant");
    expect(useAppStore.getState().notice?.text).toBe("관련 있음 1건 · Z 되돌리기 · 다음 미판정 행 없음");
  });
});

describe("Z undo", () => {
  it("restores the previous status and tags exactly, per previous state", async () => {
    expect(await runCommand("review.undo")).toEqual({ ok: false, reason: NOTHING_TO_UNDO_REASON });
    selected = [rows[0]?.rowKey as string, rows[1]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    await runCommand("review.mark.relevant");
    expect(rows[1]?.reviewStatus).toBe("relevant");
    posts = [];
    expect(await runCommand("review.undo")).toEqual({ ok: true });
    // Row 1 was 미판정, row 2 was 재검토: two requests, each with its own previous status.
    expect(batches().map((p) => [p.body.status, p.body.targets])).toEqual([
      ["unreviewed", [{ collection: "timeline", locator: "/events/1" }]],
      ["needs-review", [{ collection: "timeline", locator: "/events/2" }]],
    ]);
    expect(rows[1]?.reviewStatus).toBe("needs-review");
    expect(useVerdictUndo.getState().entries).toHaveLength(0);
    expect(moves.at(-1)).toMatchObject({ key: "timeline:/events/1" });
  });

  it("a bookmark undo replaces the tags with the previous list", async () => {
    selected = [rows[0]?.rowKey as string, rows[2]?.rowKey as string];
    useAppStore.getState().setSelectedRows(selected);
    await runCommand("review.mark.bookmark");
    posts = [];
    await runCommand("review.undo");
    expect(batches()[0]?.body).toMatchObject({ tags: [] });
    expect(batches()[0]?.body.status).toBeUndefined();
  });

  it("only the changed fields come back", () => {
    expect(changedReviewFields("excluded")).toEqual({ status: true, report: true, tags: false });
    const before = row(1, { reviewStatus: null, fields: { includeInReport: true, note: "x" } });
    const after = restoredPatch(
      before,
      "excluded",
    )(row(1, { reviewStatus: "excluded", fields: { note: "y" } }));
    expect(after).toMatchObject({ reviewStatus: null, fields: { includeInReport: true, note: "y" } });
  });
});

describe("rowFocusTarget", () => {
  const list = [row(0), row(1, { reviewStatus: "relevant" }), row(2), row(3)];
  const at = (i: number) => list[i];
  it("steps, follows the last judged row, skips judged rows and finds keys", () => {
    expect(rowFocusTarget({ step: 1, domFocus: true }, 0, 4, at)).toBe(1);
    expect(rowFocusTarget({ step: -1, domFocus: true }, 0, 4, at)).toBe("end");
    expect(
      rowFocusTarget({ after: ["timeline:/events/0", "timeline:/events/2"], domFocus: true }, 0, 4, at),
    ).toBe(3);
    expect(
      rowFocusTarget({ after: ["timeline:/events/0"], unreviewed: true, domFocus: true }, 0, 4, at),
    ).toBe(2);
    expect(rowFocusTarget({ key: "timeline:/events/3", domFocus: true }, 0, 4, at)).toBe(3);
    expect(rowFocusTarget({ step: 1, domFocus: true }, 3, 4, at)).toBe("end");
  });

  it("stops at unloaded rows and says so", () => {
    const partial = (i: number) => (i < 2 ? list[i] : undefined);
    expect(
      rowFocusTarget({ after: ["timeline:/events/0"], unreviewed: true, domFocus: true }, 0, 4, partial),
    ).toBe("unloaded");
  });
});

describe("followFocusKey (review P1-2)", () => {
  it("follows the advanced-to row when judged rows leave a filtered list", () => {
    // Before: [0, 1, 2, 3]; R on 0 moved the cursor to index 1 (row 1). Row 0 then leaves the
    // filtered list: [1, 2, 3]; index 1 now holds row 2, the cursor must stay on row 1.
    const after = [row(1), row(2), row(3)];
    const at = (i: number) => after[i];
    expect(followFocusKey("timeline:/events/1", 1, 3, at)).toBe(0);
    expect(followFocusKey("timeline:/events/2", 1, 3, at)).toBe(1);
    // A batch of three judged out: the row moved up three.
    const big = [row(4), row(5), row(6), row(7)];
    expect(followFocusKey("timeline:/events/5", 4, 4, (i) => big[i])).toBe(1);
    // Gone: stay put.
    expect(followFocusKey("timeline:/events/9", 1, 3, at)).toBe(1);
  });
});

describe("hex cursor read-out (F26)", () => {
  it("says offset, value and character, and signature edges", () => {
    expect(hexCursorSentence(5, 100, 0x65)).toBe("0x00000005, 값 0x65, 문자 e");
    expect(hexCursorSentence(0, 100, 0x53, { name: "SQLite", offset: 0, length: 6 })).toBe(
      "0x00000000, 값 0x53, 문자 S, SQLite 시그니처 시작",
    );
    expect(hexCursorSentence(9, 100, 0, undefined, { offset: 2, length: 8 })).toBe(
      "0x00000009, 값 0x00, 문자 없음, 레코드 끝",
    );
  });
});
