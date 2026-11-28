import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../contracts/collection";
import { makeRef, makeRow } from "../features/grid/columns/common";
import { resetCaseDbHandles } from "../features/grid/reviewActions";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import { resetMarkVersions } from "../features/review/markVersions";
import { useReviewConflict } from "../features/review/reviewConflict";
import { registerRowSource, resetRowSources } from "../features/review/rowSource";
import { resetAppStore, useAppStore } from "../state/store";
import { registerCommands, resetCommandRegistry, runCommand } from "./registry";
import { reviewCommands } from "./review";
import {
  CONFLICT_WRITE_UNDO_REASON,
  NOTHING_TO_UNDO_REASON,
  useVerdictPrefs,
  useVerdictUndo,
} from "./verdict";

// Z against other examiners' changes (review #106 P1-1 / P2-2, with #102's versioned writes).
const RUN = "run-z";

type Batch = { status?: string; targets: Array<{ expected_version?: number }> };

/** A 409 for file_record 1: lee set 재검토, now at `version`. */
function leeConflict(expected: number, version: number) {
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
          current: {
            exists: true,
            status: "needs-review",
            reviewer: "lee",
            status_by: "lee",
            version,
            changes: [],
          },
        },
      ],
    },
  };
}

let bodies: Batch[];

/** Review-batch server: refuses the attempts in `refuse`, else stores expected+1 (0 when none). */
function server(refuse: Record<number, unknown> = {}) {
  bodies = [];
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
        marks: [{ target_type: "file_record", target_id: "1", previous_version: sent, version: sent + 1 }],
      });
    },
  });
}

const fileRow: GridRow = makeRow(
  makeRef("files", "/candidates/1"),
  { title: "web-activity.log", sourcePath: "C:/x/web-activity.log" },
  { pointer: "/candidates/1" },
);

async function answerPrompt(choice: "mine" | "keep") {
  await vi.waitFor(() => expect(useReviewConflict.getState().prompt).not.toBeNull());
  await useReviewConflict.getState().prompt?.resolve(choice);
}

beforeEach(() => {
  resetCommandRegistry();
  resetRowSources();
  resetCaseDbHandles();
  resetMarkVersions();
  useReviewConflict.setState({ prompt: null, seq: 0 });
  useVerdictUndo.getState().clear();
  useVerdictPrefs.getState().setAdvance("stay");
  resetAppStore({ route: { runId: RUN, collection: "files", tz: "utc" } });
  registerRowSource({ getSelectedRows: () => [], getFocusedRow: () => fileRow });
  registerCommands(reviewCommands(null));
});

afterEach(() => {
  resetCommandRegistry();
  resetRowSources();
  vi.unstubAllGlobals();
});

describe("Z expects the version the verdict wrote (review P1-1)", () => {
  it("sends it; a clean undo goes through", async () => {
    server();
    await runCommand("review.mark.relevant");
    expect(useVerdictUndo.getState().entries.at(-1)?.written).toEqual([1]);
    expect(await runCommand("review.undo")).toEqual({ ok: true });
    expect(bodies[1]).toMatchObject({ status: "unreviewed", targets: [{ expected_version: 1 }] });
  });

  it("someone changed the row since: 409, 그대로 두기 leaves it, says so, and the entry is gone", async () => {
    server({ 2: leeConflict(1, 2) });
    await runCommand("review.mark.relevant");
    const undo = runCommand("review.undo");
    await answerPrompt("keep");
    expect(await undo).toEqual({ ok: true });
    expect(useAppStore.getState().notice?.text).toBe("되돌림: 관련 있음 0건 · lee가 바꾼 1건은 그대로 둠");
    // Only the refused undo went out: lee's 재검토 was not overwritten.
    expect(bodies).toHaveLength(2);
    // A second Z has nothing to retry over lee's change.
    expect(useVerdictUndo.getState().entries).toHaveLength(0);
    expect(await runCommand("review.undo")).toEqual({ ok: false, reason: NOTHING_TO_UNDO_REASON });
    expect(bodies).toHaveLength(2);
  });
});

describe("verdicts written through the conflict prompt (review P2-2)", () => {
  it("내 판정으로 바꾸기 leaves a barrier: Z stops there instead of undoing an older batch", async () => {
    server({ 2: leeConflict(1, 2) });
    // An older batch on the stack.
    await runCommand("review.mark.excluded");
    const verdict = runCommand("review.mark.relevant");
    expect((await verdict).ok).toBe(false);
    await answerPrompt("mine");
    await vi.waitFor(() => expect(useVerdictUndo.getState().entries.at(-1)?.blocked).toBeDefined());
    const sent = bodies.length;
    expect(await runCommand("review.undo")).toEqual({ ok: true });
    expect(useAppStore.getState().notice?.text).toBe(CONFLICT_WRITE_UNDO_REASON);
    expect(bodies).toHaveLength(sent);
  });

  it("그대로 두기 on a fully refused verdict adds nothing to the stack", async () => {
    server({ 1: leeConflict(0, 1) });
    expect((await runCommand("review.mark.relevant")).ok).toBe(false);
    await answerPrompt("keep");
    await Promise.resolve();
    expect(useVerdictUndo.getState().entries).toHaveLength(0);
  });
});

describe("back-to-back verdicts on one row", () => {
  it("the second waits for the first answer and expects the version it stored", async () => {
    server();
    const marked = { ...fileRow, fields: { ...fileRow.fields, markVersion: 4 } };
    resetRowSources();
    registerRowSource({ getSelectedRows: () => [], getFocusedRow: () => marked });
    // R then X before R answered (R, K, X in the grid).
    const first = runCommand("review.mark.relevant");
    const second = runCommand("review.mark.excluded");
    expect(await first).toEqual({ ok: true });
    expect(await second).toEqual({ ok: true });
    expect(bodies.map((body) => body.targets[0]?.expected_version)).toEqual([4, 5]);
  });
});
