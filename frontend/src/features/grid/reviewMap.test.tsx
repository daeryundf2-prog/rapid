import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReviewMapMark } from "../../api/caseDb";
import type { CollectionQuery } from "../../contracts/collection";
import { COLLECTIONS } from "./columns";
import { buildReviewMap, overlayReview, rowReviewKey } from "./reviewMap";
import { filesHandler, installFetch, jsonResponse, queryWrapper, resetGridStore } from "./testSupport";
import { PAGE_SIZE, useCollectionQuery } from "./useCollectionQuery";

const mark = (extra: Partial<ReviewMapMark>): ReviewMapMark => ({
  citation_id: "R-1",
  target_type: "file_record",
  target_id: "12",
  status: "relevant",
  tags: [],
  note: "",
  include_in_report: false,
  updated_at: "2026-10-11T00:00:00Z",
  collection: "files",
  kind: "",
  locator: "/candidates/1",
  ...extra,
});

beforeEach(() => resetGridStore());
afterEach(() => vi.unstubAllGlobals());

describe("review map overlay", () => {
  it("matches grid rows and search hits by collection | kind | locator", () => {
    const map = buildReviewMap([
      mark({ tags: ["북마크"], note: "확인" }),
      mark({ collection: "artifacts", kind: "eventlog", locator: "/artifacts/7", status: "excluded" }),
    ]);
    const file = COLLECTIONS.files.mapRow({ path: "C:/e/a.txt" }, 1, { ref: { id: "files" } });
    const other = COLLECTIONS.files.mapRow({ path: "C:/e/b.txt" }, 2, { ref: { id: "files" } });
    const artifact = COLLECTIONS.artifacts.mapRow({ _kind: "eventlog", _index: 7 }, 0, {
      ref: { id: "artifacts" },
    });
    const hit = COLLECTIONS.search.mapRow({ source: "files", pointer: "/candidates/1" }, 0, {
      ref: { id: "search" },
    });
    expect(rowReviewKey(file)).toBe("files||/candidates/1");
    expect(overlayReview(file, map)).toMatchObject({ reviewStatus: "relevant", tags: ["북마크"] });
    expect(overlayReview(file, map).fields.note).toBe("확인");
    expect(overlayReview(other, map)).toBe(other);
    expect(overlayReview(artifact, map).reviewStatus).toBe("excluded");
    expect(overlayReview(hit, map).reviewStatus).toBe("relevant");
  });

  it("grid rows show the stored case-DB status after a reload (GET /review-map)", async () => {
    installFetch({
      "/files": filesHandler(5),
      "/review-map": () =>
        jsonResponse({ marks: [mark({ locator: "/candidates/2", status: "needs-review" })] }),
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ref: { id: "files" }, offset: 0, limit: PAGE_SIZE };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.loadedRows[2]?.reviewStatus).toBe("needs-review"));
    expect(result.current.loadedRows[1]?.reviewStatus).toBeNull();
  });

  it("the review board lists case-DB marks (re-markable by row id) before case.json bookmarks", async () => {
    installFetch({
      "/review-map": () =>
        jsonResponse({
          marks: [
            mark({ title: "a.txt", path: "C:/e/a.txt", tags: ["북마크"] }),
            mark({ target_type: "artifact", target_id: "40", collection: "artifacts", kind: "eventlog" }),
          ],
        }),
      "/case": () =>
        jsonResponse({
          exists: true,
          case: { bookmarks: [{ bookmark_id: "b1", review: { status: "excluded" } }] },
        }),
    });
    const { wrapper } = queryWrapper();
    const q: CollectionQuery = { ref: { id: "review" }, offset: 0, limit: PAGE_SIZE };
    const { result } = renderHook(() => useCollectionQuery(q, { runId: "run-1" }), { wrapper });
    await waitFor(() => expect(result.current.total).toBe(3));
    const [first, second, third] = result.current.loadedRows;
    expect(first).toMatchObject({
      rowKey: "review:case-db:file_record:12",
      title: "a.txt",
      sourcePath: "C:/e/a.txt",
      reviewStatus: "relevant",
      tags: ["북마크"],
      ref: { caseDbId: 12 },
    });
    expect(first?.fields).toMatchObject({
      targetType: "file_record",
      pointer: "/candidates/1",
      store: "case-db",
    });
    expect(second?.fields).toMatchObject({ targetType: "artifact", sourceCommand: "artifacts:eventlog" });
    expect(third).toMatchObject({ rowKey: "review:bookmark:b1", reviewStatus: "excluded" });
  });
});
