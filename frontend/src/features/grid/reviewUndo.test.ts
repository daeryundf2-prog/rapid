/**
 * r8 T-036 (GAP-024·025, QA-065): un-press = the previous state, 실행 취소 (one batch = one unit,
 * memory only), and the author is the case's 담당자 — never "web-ui".
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useToastStore } from "../../components/toastStore";
import type { GridRow } from "../../contracts/collection";
import { useAppStore } from "../../state/store";
import { useCaseLinks } from "../case/caseLink";
import { REVIEWER_STORAGE_KEY } from "../review/author";
import { COLLECTIONS } from "./columns";
import { buildGridCommands, type GridCommandHost, NEXT_UNREVIEWED_COMMAND, runBatch } from "./gridCommands";
import {
  applyReviewAction,
  isUndoableAction,
  lastUndo,
  optimisticRestore,
  resetCaseDbHandles,
  snapshotOf,
  UNDO_LABEL,
  UNDO_NOTHING_REASON,
  UNDO_SCOPE_NOTICE,
  UNDO_TOAST_KEY,
  undoLastReview,
  undoneNotice,
  undoToastAction,
} from "./reviewActions";
import { installFetch, jsonResponse } from "./testSupport";

const fileRow = (i: number, extra: Partial<GridRow> = {}): GridRow => ({
  ...COLLECTIONS.files.mapRow({ path: `C:/ev/f${i}.txt`, name: `f${i}.txt` }, i, { ref: { id: "files" } }),
  ...extra,
});

const ENSURE = () => jsonResponse({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" });

type Body = { status?: string; include_in_report?: boolean; reviewer?: string; targets?: unknown[] };
const batches = (calls: { url: string; body?: unknown }[]): Body[] =>
  calls.filter((c) => c.url === "/api/case-db/review-batch").map((c) => c.body as Body);

beforeEach(() => {
  localStorage.removeItem(REVIEWER_STORAGE_KEY);
  useToastStore.getState().clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  resetCaseDbHandles();
  useCaseLinks.setState({ byRun: {}, loading: {} });
});

describe("un-press = previous state (GAP-024, QA-065)", () => {
  it("관련 있음 → 제외 → 해제 goes back to 관련 있음 (3 writes), then to 미검토", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const row = fileRow(1);
    await applyReviewAction("r1", [row], "relevant");
    // The caller's row object lags behind (the viewer's copy): the tab's own writes still count.
    await applyReviewAction("r1", [row], "excluded");
    const cleared = await applyReviewAction("r1", [row], "clear-review");
    expect(cleared.restored).toEqual({ status: "relevant", include: false });
    expect(batches(calls).map((b) => b.status)).toEqual(["relevant", "excluded", "relevant"]);
    // Pressing 관련 있음 off again: the state before it (미검토), not the 제외 that was undone.
    const again = await applyReviewAction("r1", [row], "clear-review");
    expect(again.restored?.status).toBe("unreviewed");
    expect(batches(calls).at(-1)?.status).toBe("unreviewed");
  });

  it("restores the report flag the 제외 mark cleared", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const row = fileRow(2, {
      reviewStatus: "relevant",
      fields: { ...fileRow(2).fields, includeInReport: true },
    });
    await applyReviewAction("r1", [row], "excluded");
    await applyReviewAction("r1", [row], "clear-review");
    expect(batches(calls).at(-1)).toMatchObject({ status: "relevant", include_in_report: true });
  });

  it("after a reload (no session state) the case-DB history names the previous status", async () => {
    const calls = installFetch({
      "/case-db/ensure": ENSURE,
      "/review-history": () =>
        jsonResponse({
          entries: [
            { status_before: "relevant", status_after: "excluded", changed_fields: ["status"] },
            { status_before: "", status_after: "relevant", changed_fields: ["status"] },
          ],
        }),
      "/review-batch": () => jsonResponse({}),
    });
    const row = fileRow(3, { reviewStatus: "excluded" });
    const result = await applyReviewAction("r1", [row], "clear-review");
    expect(result.restored?.status).toBe("relevant");
    expect(calls.some((c) => c.url.startsWith("/api/runs/r1/review-history?collection=files"))).toBe(true);
    // History knows the status only: the report flag is not sent.
    expect(batches(calls)).toEqual([expect.objectContaining({ status: "relevant" })]);
    expect(batches(calls)[0]).not.toHaveProperty("include_in_report");
  });

  it("no history (or an error) falls back to 미검토", async () => {
    const calls = installFetch({
      "/case-db/ensure": ENSURE,
      "/review-history": () => jsonResponse({ detail: "boom" }, 500),
      "/review-batch": () => jsonResponse({}),
    });
    await applyReviewAction("r1", [fileRow(4, { reviewStatus: "needs-review" })], "clear-review");
    expect(batches(calls).map((b) => b.status)).toEqual(["unreviewed"]);
  });

  it("rows going back to different states post one batch per state", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const a = fileRow(5, { reviewStatus: "relevant" });
    const b = fileRow(6);
    await applyReviewAction("r1", [a, b], "needs-review");
    await applyReviewAction("r1", [a, b], "clear-review");
    const last = batches(calls).slice(-2);
    expect(last.map((x) => x.status).sort()).toEqual(["relevant", "unreviewed"]);
  });
});

describe("실행 취소 (IS-042)", () => {
  it("takes a batch of n rows back as one unit, each to its own previous state", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const rows = [fileRow(1, { reviewStatus: "relevant" }), fileRow(2), fileRow(3)];
    await applyReviewAction("r1", rows, "excluded");
    expect(lastUndo("r1")?.entries).toHaveLength(3);
    const undone = await undoLastReview("r1");
    expect(undone.applied).toBe(3);
    expect(undoneNotice(undone)).toBe("실행 취소: 제외 3건을 이전 상태로 되돌렸습니다.");
    const back = batches(calls).slice(1);
    expect(back).toHaveLength(2);
    expect(back).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          status: "relevant",
          include_in_report: false,
          targets: [expect.anything()],
        }),
        expect.objectContaining({
          status: "unreviewed",
          include_in_report: false,
          targets: expect.any(Array),
        }),
      ]),
    );
    expect(lastUndo("r1")).toBeNull();
    await expect(undoLastReview("r1")).rejects.toThrow(UNDO_NOTHING_REASON);
  });

  it("nothing to undo says only the latest marks can be undone (lost on reload)", async () => {
    await expect(undoLastReview("r1")).rejects.toThrow(UNDO_SCOPE_NOTICE);
    expect(UNDO_NOTHING_REASON).toContain("새로고침");
  });

  it("an undone un-press puts the pressed status back", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const row = fileRow(1);
    await applyReviewAction("r1", [row], "relevant");
    await applyReviewAction("r1", [row], "excluded");
    await applyReviewAction("r1", [row], "clear-review");
    await undoLastReview("r1");
    expect(batches(calls).at(-1)?.status).toBe("excluded");
    // …and its previous state is 관련 있음 again.
    await applyReviewAction("r1", [row], "clear-review");
    expect(batches(calls).at(-1)?.status).toBe("relevant");
  });

  it("undo is per run; tags and bookmarks are not judgements", async () => {
    installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    await applyReviewAction("r1", [fileRow(1)], "bookmark");
    await applyReviewAction("r1", [fileRow(1)], "tag", { tag: "증거" });
    expect(lastUndo("r1")).toBeNull();
    expect(isUndoableAction("bookmark")).toBe(false);
    expect(isUndoableAction("clear-review")).toBe(true);
    await applyReviewAction("r1", [fileRow(1)], "include-in-report");
    expect(lastUndo("r1")?.action).toBe("include-in-report");
    expect(lastUndo("r2")).toBeNull();
  });

  it("a failed undo keeps the unit for another try", async () => {
    let fail = false;
    installFetch({
      "/case-db/ensure": ENSURE,
      "/review-batch": () => (fail ? jsonResponse({ detail: "잠김" }, 500) : jsonResponse({})),
    });
    await applyReviewAction("r1", [fileRow(1)], "relevant");
    fail = true;
    await expect(undoLastReview("r1")).rejects.toThrow();
    expect(lastUndo("r1")).not.toBeNull();
  });

  it("the toast button carries Ctrl+Z; a newer mark drops the older button", async () => {
    installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    expect(undoToastAction("r1")).toBeUndefined();
    await applyReviewAction("r1", [fileRow(1)], "relevant");
    const action = undoToastAction("r1");
    expect(action).toMatchObject({ label: UNDO_LABEL, key: UNDO_TOAST_KEY, shortcut: "Ctrl+Z" });
    useToastStore.getState().push("관련: 1건 처리했습니다.", "info", { action });
    expect(useToastStore.getState().toasts).toHaveLength(1);
    await applyReviewAction("r1", [fileRow(2)], "excluded");
    expect(useToastStore.getState().toasts).toHaveLength(0);
  });

  it("optimistic restore and snapshot agree", () => {
    const row = fileRow(1, { reviewStatus: "excluded" });
    expect(snapshotOf(row)).toEqual({ status: "excluded", include: false });
    const back = optimisticRestore({ status: "unreviewed", include: true })(row);
    expect(back.reviewStatus).toBe("include-in-report");
    expect(back.fields.includeInReport).toBe(true);
    expect(optimisticRestore({ status: "unreviewed", include: false })(row).reviewStatus).toBeNull();
  });
});

describe("author = the case's 담당자 (GAP-025)", () => {
  it("signs with the case examiner, a typed name wins, and never sends web-ui", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    await applyReviewAction("r1", [fileRow(1)], "relevant");
    useCaseLinks.getState().setLink("r1", {
      caseId: "c",
      caseNumber: "2026-01",
      evidenceCitationId: "",
      evidenceNumber: "",
      examiner: "  김  검사 ",
    });
    await applyReviewAction("r1", [fileRow(2)], "relevant");
    localStorage.setItem(REVIEWER_STORAGE_KEY, "이 분석관");
    await applyReviewAction("r1", [fileRow(3)], "relevant");
    const reviewers = batches(calls).map((b) => b.reviewer);
    expect(reviewers[0]).toBe("");
    expect(reviewers[1]).toBe("김 검사");
    expect(reviewers[2]).toBe("이 분석관");
    expect(reviewers).not.toContain("web-ui");
  });

  it("uses the open run when no run is given", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    useAppStore.getState().navigate({ ...useAppStore.getState().route, runId: "r1" });
    useCaseLinks.getState().setLink("r1", {
      caseId: "c",
      caseNumber: "",
      evidenceCitationId: "",
      evidenceNumber: "",
      examiner: "담당 검사관",
    });
    await applyReviewAction("r1", [fileRow(1)], "excluded");
    expect(batches(calls)[0]?.reviewer).toBe("담당 검사관");
  });
});

describe("grid: toast button and G", () => {
  const host = (overrides: Partial<GridCommandHost> = {}): GridCommandHost => ({
    runId: "r1",
    collection: { id: "files" },
    getFocusedRow: () => undefined,
    getSelectedRows: () => [fileRow(1), fileRow(2)],
    openRow: () => {},
    setFilter: () => {},
    navigate: () => {},
    patchRows: () => () => {},
    toast: () => {},
    refetch: () => {},
    showExtract: () => {},
    openTagPrompt: () => {},
    runIsActive: false,
    ...overrides,
  });

  it("a batch judgement toast offers 실행 취소; a tag toast does not", async () => {
    installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const toasts: { message: string; action?: string }[] = [];
    const h = host({
      toast: (message, _tone, options) => toasts.push({ message, action: options?.action?.label }),
    });
    await runBatch(h, "excluded");
    await runBatch(h, "tag", "증거");
    expect(toasts).toEqual([
      { message: "제외: 2건 처리했습니다.", action: UNDO_LABEL },
      { message: "태그: 2건 처리했습니다.", action: undefined },
    ]);
  });

  it("G moves to the next unreviewed row, or says there is none", () => {
    const told: string[] = [];
    let found = true;
    const h = host({ focusNextUnreviewed: () => found, toast: (message) => told.push(message) });
    const command = buildGridCommands({ current: h }).find((c) => c.id === NEXT_UNREVIEWED_COMMAND);
    expect(command?.shortcut).toBe("G");
    void command?.run({ runId: "r1" } as never);
    expect(told).toEqual([]);
    found = false;
    void command?.run({ runId: "r1" } as never);
    expect(told).toEqual(["아래에 미검토 행이 없습니다(불러온 행 기준)."]);
  });
});
