/**
 * r8 T-036 follow-up (adversarial bundle WB-5..7, P1-3·P1-4 and P2-1·P2-2): overlapping 실행 취소,
 * un-press keeping a later 보고서 포함, stale "before" across views, and un-press after a reload.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { COLLECTIONS } from "./columns";
import {
  applyReviewAction,
  lastUndo,
  newestStandingChange,
  resetCaseDbHandles,
  UNDO_NOTHING_REASON,
  undoLastReview,
} from "./reviewActions";
import { installFetch, jsonResponse } from "./testSupport";

const fileRow = (i: number, extra: Partial<GridRow> = {}): GridRow => ({
  ...COLLECTIONS.files.mapRow({ path: `C:/ev/f${i}.txt`, name: `f${i}.txt` }, i, { ref: { id: "files" } }),
  ...extra,
});

const ENSURE = () => jsonResponse({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" });

type Body = { status?: string; include_in_report?: boolean; targets?: { locator?: string }[] };
const batches = (calls: { url: string; body?: unknown }[]): Body[] =>
  calls.filter((c) => c.url === "/api/case-db/review-batch").map((c) => c.body as Body);

afterEach(() => {
  vi.unstubAllGlobals();
  resetCaseDbHandles();
});

/** A review-batch route whose answers the test releases one by one. */
function heldBatches() {
  const waiting: ((ok: boolean) => void)[] = [];
  const route = () =>
    new Promise<Response>((resolve) => {
      waiting.push((ok) => resolve(ok ? jsonResponse({}) : jsonResponse({ detail: "잠김" }, 500)));
    });
  const release = async (ok = true) => {
    for (let i = 0; i < 50 && waiting.length === 0; i += 1) await Promise.resolve();
    waiting.shift()?.(ok);
  };
  return { route, release, pending: () => waiting.length };
}

describe("two quick Ctrl+Z presses (P1-3)", () => {
  it("take back the newest unit, then the older one, written in that order", async () => {
    let held: ReturnType<typeof heldBatches> | null = null;
    const calls = installFetch({
      "/case-db/ensure": ENSURE,
      "/review-batch": () => (held ? held.route() : Promise.resolve(jsonResponse({}))),
    });
    await applyReviewAction("r1", [fileRow(1)], "relevant"); // A
    await applyReviewAction("r1", [fileRow(2)], "excluded"); // B
    held = heldBatches();
    const first = undoLastReview("r1");
    const second = undoLastReview("r1");
    // Both units left the stack at once: a third press has nothing left to take.
    expect(lastUndo("r1")).toBeNull();
    await held.release();
    await held.release();
    const [undoneB, undoneA] = await Promise.all([first, second]);
    expect(undoneB.label).toBe("제외");
    expect(undoneA.label).toBe("관련");
    const [markA, markB, ...back] = batches(calls);
    expect(back.map((b) => b.status)).toEqual(["unreviewed", "unreviewed"]);
    // B's rows first, then A's: the second write starts only after the first answered.
    expect(back[0]?.targets).toEqual(markB?.targets);
    expect(back[1]?.targets).toEqual(markA?.targets);
    expect(back[0]?.targets).not.toEqual(back[1]?.targets);
    await expect(undoLastReview("r1")).rejects.toThrow(UNDO_NOTHING_REASON);
  });

  it("a failed first undo puts both units back in stack order", async () => {
    let held: ReturnType<typeof heldBatches> | null = null;
    installFetch({
      "/case-db/ensure": ENSURE,
      "/review-batch": () => (held ? held.route() : Promise.resolve(jsonResponse({}))),
    });
    await applyReviewAction("r1", [fileRow(1)], "relevant");
    await applyReviewAction("r1", [fileRow(2)], "excluded");
    held = heldBatches();
    const first = undoLastReview("r1");
    const second = undoLastReview("r1");
    await held.release(false);
    await expect(first).rejects.toThrow();
    await expect(second).rejects.toThrow();
    // Nothing was taken back: B is the newest again, A under it.
    expect(lastUndo("r1")?.action).toBe("excluded");
    held = null;
    expect((await undoLastReview("r1")).label).toBe("제외");
    expect((await undoLastReview("r1")).label).toBe("관련");
  });
});

describe("un-press keeps a later 보고서 포함 (P1-4)", () => {
  it("관련 → 보고서 포함 → 관련 해제 sends the status only", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const row = fileRow(1);
    await applyReviewAction("r1", [row], "relevant");
    await applyReviewAction("r1", [row], "include-in-report");
    const cleared = await applyReviewAction("r1", [row], "clear-review");
    expect(batches(calls).at(-1)).toEqual(expect.objectContaining({ status: "unreviewed" }));
    expect(batches(calls).at(-1)).not.toHaveProperty("include_in_report");
    expect(cleared.restored).toEqual({ status: "unreviewed", include: true });
  });

  it("제외 → 보고서 포함 → 제외 해제 keeps the flag set after the 제외", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const row = fileRow(2, { reviewStatus: "relevant", fields: { ...fileRow(2).fields, includeInReport: false } });
    await applyReviewAction("r1", [row], "excluded");
    await applyReviewAction("r1", [row], "include-in-report");
    await applyReviewAction("r1", [row], "clear-review");
    expect(batches(calls).at(-1)).toEqual(expect.objectContaining({ status: "relevant" }));
    expect(batches(calls).at(-1)).not.toHaveProperty("include_in_report");
  });
});

describe("stale previous state across views (P2-1)", () => {
  it("a row that shows a state set elsewhere wins over this tab's older write", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    // Grid: 관련 (this tab remembers 관련 for the row's locator key).
    await applyReviewAction("r1", [fileRow(1)], "relevant");
    // The same item was set to 제외 from the 검토 목록 (a case-DB id key); the grid refetched.
    const refetched = fileRow(1, { reviewStatus: "excluded" });
    await applyReviewAction("r1", [refetched], "needs-review");
    await undoLastReview("r1");
    expect(batches(calls).at(-1)?.status).toBe("excluded");
  });
});

describe("un-press after a reload reaches 미검토 (P2-2)", () => {
  it("skips a history change that an earlier un-press took back", async () => {
    let entries = [
      { status_before: "relevant", status_after: "excluded" },
      { status_before: "", status_after: "relevant" },
    ];
    const calls = installFetch({
      "/case-db/ensure": ENSURE,
      "/review-history": () => jsonResponse({ entries }),
      "/review-batch": () => jsonResponse({}),
    });
    const first = await applyReviewAction("r1", [fileRow(3, { reviewStatus: "excluded" })], "clear-review");
    expect(first.restored?.status).toBe("relevant");
    // The server recorded the un-press (excluded → relevant); after another reload:
    entries = [{ status_before: "excluded", status_after: "relevant" }, ...entries];
    resetCaseDbHandles();
    const second = await applyReviewAction("r1", [fileRow(3, { reviewStatus: "relevant" })], "clear-review");
    expect(second.restored?.status).toBe("unreviewed");
    expect(batches(calls).map((b) => b.status)).toEqual(["relevant", "unreviewed"]);
  });

  it("pairs nest; an unmatched newest change stands", () => {
    const c = (before: string, after: string) => ({ before, after });
    expect(newestStandingChange([c("relevant", "excluded"), c("unreviewed", "relevant")])?.before).toBe(
      "relevant",
    );
    expect(
      newestStandingChange([
        c("needs-review", "relevant"),
        c("relevant", "needs-review"),
        c("excluded", "relevant"),
        c("relevant", "excluded"),
        c("unreviewed", "relevant"),
      ])?.before,
    ).toBe("unreviewed");
    expect(newestStandingChange([])).toBeNull();
  });
});
