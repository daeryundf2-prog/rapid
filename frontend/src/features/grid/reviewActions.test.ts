import { afterEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { COLLECTIONS } from "./columns";
import {
  applyReviewAction,
  EXTRACT_LIMIT,
  onReviewApplied,
  optimisticPatch,
  resetCaseDbHandles,
  storeNotice,
} from "./reviewActions";
import { installFetch, jsonResponse } from "./testSupport";

afterEach(() => {
  vi.unstubAllGlobals();
  resetCaseDbHandles();
});

const fileRow = (i: number, extra: Partial<GridRow> = {}): GridRow => ({
  ...COLLECTIONS.files.mapRow({ path: `C:/ev/f${i}.txt`, name: `f${i}.txt` }, i, { ref: { id: "files" } }),
  ...extra,
});

const ENSURE = () => jsonResponse({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" });
const HANDLE = { database: "D:/out/rapidtriage-case.db", case_id: "run-out" };

describe("applyReviewAction", () => {
  it("ensures the case DB once per run, then posts run locators to review-batch (canonical store)", async () => {
    const calls = installFetch({
      "/case-db/ensure": ENSURE,
      "/review-batch": () => jsonResponse({ updated_count: 2 }),
    });
    const result = await applyReviewAction("r1", [fileRow(1), fileRow(2)], "include-in-report");
    await applyReviewAction("r1", [fileRow(3)], "relevant");
    expect(result).toEqual({ applied: 2, store: "case-db" });
    expect(calls.map((c) => c.url)).toEqual([
      "/api/runs/r1/case-db/ensure",
      "/api/case-db/review-batch",
      "/api/case-db/review-batch",
    ]);
    expect(calls[1]?.body).toEqual({
      ...HANDLE,
      run_id: "r1",
      targets: [
        { collection: "files", locator: "/candidates/1" },
        { collection: "files", locator: "/candidates/2" },
      ],
      reviewer: "web-ui",
      include_in_report: true,
    });
    expect(calls[2]?.body).toMatchObject({
      status: "relevant",
      targets: [{ collection: "files", locator: "/candidates/3" }],
    });
  });

  it("artifact rows send their kind; search hits resolve through their pointer", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const artifact = COLLECTIONS.artifacts.mapRow({ _kind: "eventlog", _index: 7 }, 0, {
      ref: { id: "artifacts" },
    });
    const hit = COLLECTIONS.search.mapRow(
      { source: "documents", pointer: "/results/4", path: "C:/ev/a.docx" },
      0,
      { ref: { id: "search" } },
    );
    await applyReviewAction("r1", [artifact, hit], "needs-review");
    expect(calls[1]?.body).toMatchObject({
      status: "needs-review",
      targets: [
        { collection: "artifacts", kind: "eventlog", locator: "/artifacts/7" },
        { collection: "docs", locator: "/results/4" },
      ],
    });
  });

  it("rows with a case-db id post the row id directly", async () => {
    const calls = installFetch({
      "/case-db/ensure": ENSURE,
      "/review-batch": () => jsonResponse({ updated_count: 2 }),
    });
    const base = fileRow(1);
    const rows: GridRow[] = [
      { ...base, ref: { ...base.ref, caseDbId: 11 }, fields: { ...base.fields, targetType: "file_record" } },
      {
        ...base,
        rowKey: "files:/candidates/2",
        ref: { ...base.ref, caseDbId: 12 },
        fields: { targetType: "file_record" },
      },
    ];
    await applyReviewAction("r1", rows, "excluded");
    expect(calls[1]?.body).toEqual({
      ...HANDLE,
      run_id: "r1",
      targets: [
        { target_type: "file_record", target_id: "11" },
        { target_type: "file_record", target_id: "12" },
      ],
      reviewer: "web-ui",
      status: "excluded",
      include_in_report: false,
    });
  });

  it("tag and bookmark actions merge tags (add_tags) instead of replacing them", async () => {
    const calls = installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    await applyReviewAction("r1", [fileRow(3)], "tag", { tag: "증거" });
    await applyReviewAction("r1", [fileRow(3)], "bookmark");
    const batches = calls.filter((c) => c.url === "/api/case-db/review-batch").map((c) => c.body);
    expect(batches.map((b) => (b as { add_tags: string[] }).add_tags)).toEqual([["증거"], ["북마크"]]);
  });

  it("falls back to case.json bookmarks only when no case DB can be created", async () => {
    const calls = installFetch({
      "/case-db/ensure": () => jsonResponse({ detail: "run output is read-only" }, 400),
      "/bookmarks": () => jsonResponse({}),
    });
    const result = await applyReviewAction("r1", [fileRow(1)], "relevant");
    expect(result.store).toBe("bookmarks");
    expect(storeNotice(result)).toContain("case.json");
    expect(calls.map((c) => c.body)).toEqual([
      {},
      { source: "files", pointer: "/candidates/1", review_status: "relevant" },
    ]);
  });

  it("server errors from ensure do not fall back silently", async () => {
    installFetch({ "/case-db/ensure": () => jsonResponse({ detail: "boom" }, 500) });
    await expect(applyReviewAction("r1", [fileRow(1)], "relevant")).rejects.toThrow("boom");
  });

  it("notifies listeners (review-counts / review-map invalidation) after a mark", async () => {
    installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({}) });
    const seen: string[] = [];
    const off = onReviewApplied((runId, store) => seen.push(`${runId}:${store}`));
    await applyReviewAction("r1", [fileRow(1)], "relevant");
    off();
    await applyReviewAction("r1", [fileRow(2)], "relevant");
    expect(seen).toEqual(["r1:case-db"]);
  });

  it("rejects rows whose source location is unknown without calling the API", async () => {
    const calls = installFetch({});
    const outputRow = COLLECTIONS.outputs.mapRow({ name: "x" }, 0, { ref: { id: "outputs" } });
    await expect(applyReviewAction("r1", [outputRow], "relevant")).rejects.toThrow(
      "출처 위치를 알 수 없는 행이 1건",
    );
    expect(calls).toHaveLength(0);
  });

  it("propagates API failures so the caller can roll back", async () => {
    installFetch({ "/case-db/ensure": ENSURE, "/review-batch": () => jsonResponse({ detail: "nope" }, 400) });
    await expect(applyReviewAction("r1", [fileRow(1)], "relevant")).rejects.toThrow("nope");
  });

  it("extract needs source paths and respects the per-call limit", async () => {
    await expect(applyReviewAction("r1", [fileRow(1, { sourcePath: null })], "extract")).rejects.toThrow(
      "원본 경로가 있는 행이 없습니다",
    );
    const many = Array.from({ length: EXTRACT_LIMIT + 1 }, (_, i) => fileRow(i));
    await expect(applyReviewAction("r1", many, "extract")).rejects.toThrow(`${EXTRACT_LIMIT}건까지`);
  });
});

describe("extract via POST /extract", () => {
  it("sends unique paths with locators and returns the manifest", async () => {
    const calls = installFetch({
      "/extract": () =>
        jsonResponse({
          summary: { input_count: 2, selected_count: 2, extracted_count: 2, skipped_count: 0 },
          entries: [],
          skipped: [],
          name: "extract-1",
          download_url: "/api/runs/r1/extract/extract-1/file",
        }),
    });
    const result = await applyReviewAction("r1", [fileRow(1), fileRow(1), fileRow(2)], "extract");
    expect(calls[0]?.url).toBe("/api/runs/r1/extract");
    expect(calls[0]?.body).toEqual({
      rows: [
        { path: "C:/ev/f1.txt", locator: "/candidates/1" },
        { path: "C:/ev/f2.txt", locator: "/candidates/2" },
      ],
    });
    expect(result.applied).toBe(2);
    expect(result.extract?.download_url).toContain("/extract/extract-1/file");
  });
});

describe("optimisticPatch", () => {
  it("sets the review status / tag / include flag without touching other fields", () => {
    const row = fileRow(1);
    expect(optimisticPatch("relevant")(row).reviewStatus).toBe("relevant");
    expect(optimisticPatch("tag", "x")(row).tags).toEqual(["x"]);
    expect(optimisticPatch("include-in-report")(row).fields.includeInReport).toBe(true);
    expect(optimisticPatch("bookmark")(row).tags).toEqual(["북마크"]);
    expect(optimisticPatch("extract")(row)).toBe(row);
  });
});
