import { afterEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { COLLECTIONS } from "./columns";
import { applyNote, resetCaseDbHandles } from "./reviewActions";
import { installFetch, jsonResponse } from "./testSupport";

afterEach(() => {
  vi.unstubAllGlobals();
  resetCaseDbHandles();
});

const fileRow = (i: number): GridRow =>
  COLLECTIONS.files.mapRow({ path: `C:/ev/f${i}.txt`, name: `f${i}.txt` }, i, { ref: { id: "files" } });

describe("applyNote", () => {
  it("posts the same trimmed note for every row in one review-batch (case DB)", async () => {
    const calls = installFetch({
      "/case-db/ensure": () => jsonResponse({ database: "D:/o/case.db", case_id: "run-r1" }),
      "/review-batch": () => jsonResponse({ updated_count: 2 }),
    });
    await applyNote("r1", [fileRow(1), fileRow(2)], "  의심 파일  ");
    expect(calls[1]?.body).toMatchObject({
      run_id: "r1",
      note: "의심 파일",
      targets: [
        { collection: "files", locator: "/candidates/1" },
        { collection: "files", locator: "/candidates/2" },
      ],
    });
  });

  it("falls back to one bookmark note per row when no case DB can be created", async () => {
    const calls = installFetch({
      "/case-db/ensure": () => jsonResponse({ detail: "no case db" }, 400),
      "/bookmarks": () => jsonResponse({}),
    });
    await applyNote("r1", [fileRow(1), fileRow(2)], "  의심 파일  ");
    expect(calls.slice(1).map((c) => c.body)).toEqual([
      { source: "files", pointer: "/candidates/1", note: "의심 파일" },
      { source: "files", pointer: "/candidates/2", note: "의심 파일" },
    ]);
  });

  it("sends case-db rows through review-batch with note only", async () => {
    const calls = installFetch({
      "/case-db/ensure": () => jsonResponse({ database: "D:/o/case.db", case_id: "run-r1" }),
      "/review-batch": () => jsonResponse({ updated_count: 1 }),
    });
    const base = fileRow(1);
    const row: GridRow = {
      ...base,
      ref: { ...base.ref, caseDbId: 11 },
      fields: { ...base.fields, targetType: "file_record" },
    };
    await applyNote("r1", [row], "메모");
    const batch = calls.find((c) => String(c.url).includes("/review-batch"));
    expect(batch?.body).toMatchObject({
      note: "메모",
      targets: [{ target_type: "file_record", target_id: "11" }],
    });
    expect(batch?.body).not.toHaveProperty("status");
  });

  it("rejects an empty note", async () => {
    await expect(applyNote("r1", [fileRow(1)], "   ")).rejects.toThrow();
  });
});
