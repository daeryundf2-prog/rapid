/**
 * Review queue commands (todo 17): N / Shift+N step to the next / previous row without a user tag.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import { makeRef, makeRow } from "./columns/common";
import {
  buildQueueCommands,
  type GridCommandHost,
  isReviewedRow,
  REVIEW_NEXT_COMMAND,
  REVIEW_PREV_COMMAND,
} from "./gridCommands";

const announced = vi.hoisted(() => [] as string[]);
vi.mock("../../a11y", () => ({
  announce: (text: string) => {
    announced.push(text);
  },
}));

const ctx: CommandContext = {
  runId: "r1",
  collection: "files",
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

function row(index: number, tags: string[] = []): GridRow {
  return { ...makeRow(makeRef("files", `/candidates/${index}`), { title: `f${index}` }, {}), tags };
}

function setup(rows: GridRow[], focusedKey: string | null) {
  const focused: string[] = [];
  let current = focusedKey;
  const host = {
    runId: "r1",
    collection: { id: "files" },
    getRows: () => rows,
    getFocusedRow: () => rows.find((r) => r.rowKey === current),
    focusRowKey: (key: string) => {
      focused.push(key);
      current = key;
    },
  } as unknown as GridCommandHost;
  const list = buildQueueCommands({ current: host });
  const byId = (id: string) => list.find((c) => c.id === id);
  return { focused, next: byId(REVIEW_NEXT_COMMAND), prev: byId(REVIEW_PREV_COMMAND) };
}

beforeEach(() => {
  announced.length = 0;
});

describe("review queue commands", () => {
  it("counts only non-system tags as reviewed", () => {
    expect(isReviewedRow(row(1, ["북마크", "우선순위 2"]))).toBe(false);
    expect(isReviewedRow(row(1, ["북마크", "증거 A"]))).toBe(true);
  });

  it("N moves focus to the next unreviewed row and announces k/n", async () => {
    const rows = [row(1, ["증거 A"]), row(2), row(3, ["북마크"]), row(4)];
    const { focused, next } = setup(rows, rows[0]?.rowKey ?? null);
    await next?.run(ctx);
    expect(focused).toEqual([rows[1]?.rowKey]);
    expect(announced).toEqual(["미검토 1/3"]);
    await next?.run(ctx);
    expect(focused).toEqual([rows[1]?.rowKey, rows[2]?.rowKey]);
    expect(announced.at(-1)).toBe("미검토 2/3");
  });

  it("Shift+N moves to the previous unreviewed row, wrapping", async () => {
    const rows = [row(1), row(2, ["증거 A"]), row(3)];
    const { focused, prev } = setup(rows, rows[0]?.rowKey ?? null);
    await prev?.run(ctx);
    expect(focused).toEqual([rows[2]?.rowKey]);
    expect(announced).toEqual(["미검토 2/2"]);
  });

  it("announces 미검토 없음 and keeps focus when every row is reviewed", async () => {
    const rows = [row(1, ["증거 A"]), row(2, ["증거 B"])];
    const { focused, next } = setup(rows, rows[0]?.rowKey ?? null);
    await next?.run(ctx);
    expect(focused).toEqual([]);
    expect(announced).toEqual(["미검토 없음"]);
  });

  it("is disabled with a reason on an empty list", () => {
    const { next } = setup([], null);
    expect(next?.disabledReason?.(ctx)).toBe("목록에 행이 없습니다.");
  });
});
