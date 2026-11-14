import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReviewMapMark } from "../../api/caseDb";
import { useToastStore } from "../../components/toastStore";
import type { GridRow } from "../../contracts/collection";
import { COLLECTIONS } from "./columns";
import { applyReviewAction, notifyReviewApplied } from "./reviewActions";
import {
  buildReviewMap,
  detectRemoteChanges,
  invalidateReviewQueries,
  OWN_WRITE_TTL_MS,
  QUIET_AFTER_UNKEYED_WRITE_MS,
  REMOTE_CHANGE_NOTICE,
  recordOwnReviewWrite,
  remoteChangeDetail,
  useReviewMap,
} from "./reviewMap";
import { installFetch, jsonResponse, queryWrapper, resetGridStore } from "./testSupport";

/** r8 T-131 (QA-012): marks another window changed show one merged toast on the next fetch. */

const mark = (index: number, extra: Partial<ReviewMapMark> = {}): ReviewMapMark => ({
  citation_id: `R-${index}`,
  target_type: "file_record",
  target_id: String(index),
  status: "relevant",
  tags: [],
  note: "",
  include_in_report: false,
  updated_at: "2026-11-13T00:00:00Z",
  collection: "files",
  kind: "",
  locator: `/candidates/${index}`,
  ...extra,
});

const fileRow = (index: number): GridRow =>
  COLLECTIONS.files.mapRow({ path: `C:/ev/f${index}.txt`, name: `f${index}.txt` }, index, {
    ref: { id: "files" },
  });

const map = (...marks: ReviewMapMark[]) => buildReviewMap(marks);
const later = (index: number, extra: Partial<ReviewMapMark> = {}) =>
  mark(index, { updated_at: "2026-11-13T00:00:05Z", ...extra });

beforeEach(() => {
  resetGridStore();
  useToastStore.getState().clear();
});
afterEach(() => vi.unstubAllGlobals());

describe("detectRemoteChanges", () => {
  it("the first fetch of a run is the baseline; unchanged marks are not reported", () => {
    expect(detectRemoteChanges("r1", map(mark(1), mark(2)), 0)).toBe(0);
    expect(detectRemoteChanges("r1", map(mark(1), mark(2)), 1)).toBe(0);
  });

  it("marks changed or added by someone else are counted together", () => {
    detectRemoteChanges("r1", map(mark(1), mark(2)), 0);
    const next = map(later(1, { status: "excluded" }), mark(2), mark(3));
    expect(detectRemoteChanges("r1", next, 1)).toBe(2);
    // The new map is the next baseline: the same change is not reported twice.
    expect(detectRemoteChanges("r1", next, 2)).toBe(0);
  });

  it("this tab's own write is not reported while the stored mark shows it", () => {
    detectRemoteChanges("r1", map(mark(1), mark(2)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: [fileRow(1)], mark: { status: "excluded" } }, 10);
    expect(detectRemoteChanges("r1", map(later(1, { status: "excluded" }), mark(2)), 20)).toBe(0);
  });

  it("a row this tab wrote and another window overwrote afterwards is reported (QA-012 ②)", () => {
    detectRemoteChanges("r1", map(mark(1)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: [fileRow(1)], mark: { status: "excluded" } }, 10);
    // This tab's refetch already sees the other window's later "needs-review".
    expect(detectRemoteChanges("r1", map(later(1, { status: "needs-review" })), 20)).toBe(1);
  });

  it("the own write is used once: a later change of the same row is someone else's", () => {
    detectRemoteChanges("r1", map(mark(1)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: [fileRow(1)], mark: { status: "excluded" } }, 10);
    expect(detectRemoteChanges("r1", map(later(1, { status: "excluded" })), 20)).toBe(0);
    const overwritten = later(1, { status: "relevant", updated_at: "2026-11-13T00:00:09Z" });
    expect(detectRemoteChanges("r1", map(overwritten), 30)).toBe(1);
  });

  it("a fetch that does not show the own write yet keeps it for the next fetch", () => {
    detectRemoteChanges("r1", map(mark(1)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: [fileRow(1)], mark: { status: "excluded" } }, 10);
    expect(detectRemoteChanges("r1", map(mark(1)), 20)).toBe(0);
    expect(detectRemoteChanges("r1", map(later(1, { status: "excluded" })), 30)).toBe(0);
  });

  it("own writes expire", () => {
    detectRemoteChanges("r1", map(mark(1)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: [fileRow(1)], mark: { status: "excluded" } }, 10);
    const after = 10 + OWN_WRITE_TTL_MS + 1;
    expect(detectRemoteChanges("r1", map(later(1, { status: "excluded" })), after)).toBe(1);
  });

  it("tag-tool writes (rows this tab cannot key) keep the next fetches quiet for a while", () => {
    detectRemoteChanges("r1", map(mark(1), mark(2)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: null, mark: null }, 10);
    expect(
      detectRemoteChanges(
        "r1",
        map(later(1, { tags: ["외부 반출"] }), later(2, { tags: ["외부 반출"] })),
        20,
      ),
    ).toBe(0);
    const outside = 10 + QUIET_AFTER_UNKEYED_WRITE_MS + 1;
    expect(
      detectRemoteChanges("r1", map(later(1, { tags: [] }), later(2, { tags: ["외부 반출"] })), outside),
    ).toBe(1);
  });

  it("inside the quiet window a change the tag tool cannot explain is still reported (review P2-7)", () => {
    detectRemoteChanges("r1", map(mark(1), mark(2), mark(3)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: null, mark: null }, 10);
    // Row 1: tags only (this tab's tag tool) → quiet. Row 2: another window set a status → reported.
    const fetched = map(later(1, { tags: ["외부 반출"] }), later(2, { status: "excluded" }), mark(3));
    expect(detectRemoteChanges("r1", fetched, 20)).toBe(1);
    // Row 1 changes again inside the window: the tag tool was already seen there → reported.
    const again = map(
      later(1, { tags: ["외부 반출", "북마크"], updated_at: "2026-11-13T00:00:08Z" }),
      later(2, { status: "excluded" }),
      mark(3),
    );
    expect(detectRemoteChanges("r1", again, 30)).toBe(1);
  });

  it("an unkeyed status write (검토 목록 rows) explains only rows that show its status", () => {
    detectRemoteChanges("r1", map(mark(1), mark(2)), 0);
    recordOwnReviewWrite({ runId: "r1", rows: null, mark: { status: "excluded" } }, 10);
    const fetched = map(later(1, { status: "excluded" }), later(2, { status: "needs-review" }));
    expect(detectRemoteChanges("r1", fetched, 20)).toBe(1);
  });

  it("an empty map after a non-empty one is a failed read: no report, the baseline stays (review P2-6)", () => {
    detectRemoteChanges("r1", map(mark(1), mark(2)), 0);
    expect(detectRemoteChanges("r1", map(), 10)).toBe(0);
    expect(detectRemoteChanges("r1", map(mark(1), mark(2)), 20)).toBe(0);
    expect(detectRemoteChanges("r1", map(later(1, { status: "excluded" }), mark(2)), 30)).toBe(1);
  });

  it("runs are tracked separately", () => {
    detectRemoteChanges("r1", map(mark(1)), 0);
    expect(detectRemoteChanges("r2", map(later(1, { status: "excluded" })), 1)).toBe(0);
  });
});

describe("useReviewMap remote-change toast", () => {
  it("shows one merged toast for every row another window changed, on the next fetch", async () => {
    let marks = [mark(1), mark(2), mark(3)];
    installFetch({ "/review-map": () => jsonResponse({ marks, truncated: false }) });
    const { client, wrapper } = queryWrapper();
    const { result } = renderHook(() => useReviewMap("r1"), { wrapper });
    await waitFor(() => expect(result.current?.size).toBe(3));
    expect(useToastStore.getState().toasts).toEqual([]);

    marks = [later(1, { status: "excluded" }), later(2, { status: "excluded" }), mark(3)];
    await act(() => invalidateReviewQueries(client, "r1"));
    await waitFor(() => expect(result.current?.get("files||/candidates/1")?.status).toBe("excluded"));
    const toasts = useToastStore.getState().toasts;
    expect(toasts).toHaveLength(1);
    expect(toasts[0]).toMatchObject({ text: REMOTE_CHANGE_NOTICE, detail: remoteChangeDetail(2) });

    // A further change replaces the toast (same kind merged), never stacks a second one.
    marks = [
      later(1, { status: "excluded" }),
      later(2, { status: "excluded" }),
      later(3, { status: "excluded" }),
    ];
    await act(() => invalidateReviewQueries(client, "r1"));
    await waitFor(() => expect(result.current?.get("files||/candidates/3")?.status).toBe("excluded"));
    expect(useToastStore.getState().toasts.filter((t) => t.text === REMOTE_CHANGE_NOTICE)).toHaveLength(1);
    expect(useToastStore.getState().toasts.at(-1)?.detail).toBe(remoteChangeDetail(1));
  });

  it("switching back to this window refetches inside staleTime and shows the toast (verify T-131)", async () => {
    let marks = [mark(1), mark(2)];
    const calls = installFetch({ "/review-map": () => jsonResponse({ marks, truncated: false }) });
    const { wrapper } = queryWrapper();
    const { result } = renderHook(() => useReviewMap("r1"), { wrapper });
    await waitFor(() => expect(result.current?.size).toBe(2));
    const fetches = () => calls.filter((c) => c.url.includes("/review-map")).length;
    const first = fetches();

    marks = [later(1, { status: "excluded" }), mark(2)];
    // Hidden: a focus event (another window's) sends nothing (T-130).
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    act(() => {
      window.dispatchEvent(new Event("focus"));
    });
    expect(fetches()).toBe(first);
    visibility.mockReturnValue("visible");
    act(() => {
      window.dispatchEvent(new Event("focus"));
    });
    await waitFor(() => expect(result.current?.get("files||/candidates/1")?.status).toBe("excluded"));
    expect(fetches()).toBe(first + 1);
    const toasts = useToastStore.getState().toasts;
    expect(toasts.at(-1)).toMatchObject({ text: REMOTE_CHANGE_NOTICE, detail: remoteChangeDetail(1) });
    visibility.mockRestore();
  });

  it("a 200 with `error` and no marks keeps the last map and raises no toast (review P2-6)", async () => {
    let payload: Record<string, unknown> = { marks: [mark(1), mark(2)], truncated: false };
    installFetch({ "/review-map": () => jsonResponse(payload) });
    const { client, wrapper } = queryWrapper();
    const { result } = renderHook(() => useReviewMap("r1"), { wrapper });
    await waitFor(() => expect(result.current?.size).toBe(2));

    payload = { marks: [], truncated: false, error: "database disk image is malformed" };
    await act(() => invalidateReviewQueries(client, "r1"));
    expect(result.current?.size).toBe(2);
    payload = { marks: [mark(1), mark(2)], truncated: false };
    await act(() => invalidateReviewQueries(client, "r1"));
    await waitFor(() => expect(result.current?.size).toBe(2));
    expect(useToastStore.getState().toasts.some((t) => t.text === REMOTE_CHANGE_NOTICE)).toBe(false);
  });

  it("this tab's own marks (applyReviewAction) and tag tools never raise the toast", async () => {
    let marks = [mark(1), mark(2)];
    installFetch({
      "/review-map": () => jsonResponse({ marks, truncated: false }),
      "/case-db/ensure": () => jsonResponse({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" }),
      "/review-batch": () => {
        marks = [later(1, { status: "excluded" }), later(2, { status: "excluded" })];
        return jsonResponse({ updated_count: 2 });
      },
    });
    const { client, wrapper } = queryWrapper();
    const { result } = renderHook(() => useReviewMap("r1"), { wrapper });
    await waitFor(() => expect(result.current?.size).toBe(2));

    await act(async () => {
      await applyReviewAction("r1", [fileRow(1), fileRow(2)], "excluded");
    });
    await act(() => invalidateReviewQueries(client, "r1"));
    await waitFor(() => expect(result.current?.get("files||/candidates/2")?.status).toBe("excluded"));
    expect(useToastStore.getState().toasts.some((t) => t.text === REMOTE_CHANGE_NOTICE)).toBe(false);

    // Same-hash tag propagation in this tab: rows it never listed change, still no toast.
    marks = [
      later(1, { status: "excluded", tags: ["같은 사진"] }),
      later(2, { status: "excluded", tags: ["같은 사진"] }),
    ];
    notifyReviewApplied("r1");
    await act(() => invalidateReviewQueries(client, "r1"));
    await waitFor(() => expect(result.current?.get("files||/candidates/1")?.tags).toEqual(["같은 사진"]));
    expect(useToastStore.getState().toasts.some((t) => t.text === REMOTE_CHANGE_NOTICE)).toBe(false);
  });
});
