/** r4 §2.3: the row-condition params reach `/artifacts` (cross-kind), `/files` and `/timeline`. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { timelineCollection } from "../features/grid/columns/timeline";
import { installFetch, jsonResponse } from "../features/grid/testSupport";
import {
  fetchArtifactsPage,
  fetchFilesPage,
  fetchTimelinePage,
  resetArtifactCountsCache,
} from "./collections";

beforeEach(() => resetArtifactCountsCache());
afterEach(() => vi.unstubAllGlobals());

const CONDITIONS = { tz: "Asia/Seoul", offhours: "1", content: ["document", "image"] };

describe("row conditions on the wire", () => {
  it("pages all artifact kinds as one cross-kind listing with the conditions", async () => {
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: { eventlog: { artifacts: [{ record_index: 3 }], record_count: 9 } },
          cross_kind: {
            order: [["eventlog", 3]],
            matched: 1,
            next_after: null,
            conditions: { offhours: true },
          },
        }),
    });
    const page = await fetchArtifactsPage(
      "r1",
      undefined,
      0,
      50,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      {
        conditions: CONDITIONS,
      },
    );
    expect(page.total).toBe(1);
    expect(page.rows[0]?._index).toBe(3);
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.searchParams.get("offhours")).toBe("1");
    expect(url.searchParams.get("tz")).toBe("Asia/Seoul");
    expect(url.searchParams.getAll("content")).toEqual(["document", "image"]);
  });

  it("files and timeline send them too; timeline rows keep their record_index locator", async () => {
    const calls = installFetch({
      "/files": () => jsonResponse({ candidates: [], matched: 0, pagination: { filtered: true, total: 0 } }),
      "/timeline": () =>
        jsonResponse({
          events: [{ timestamp: "2025-05-26T10:30:00Z", event_type: "e1", record_index: 17 }],
          matched: 1,
          pagination: { total: 1, filtered: true },
        }),
    });
    await fetchFilesPage("r1", 0, 250, undefined, undefined, { conditions: { partial: "1" } });
    expect(calls[0]?.url).toContain("partial=1");
    const page = await fetchTimelinePage("r1", 0, 250, undefined, { weekday: ["sat", "sun"] });
    expect(calls[1]?.url).toContain("weekday=sat&weekday=sun");
    expect(page.total).toBe(1);
    const mapped = timelineCollection.mapRow(page.rows[0] as Record<string, unknown>, 0, {
      ref: { id: "timeline" },
    });
    expect(mapped.ref.locator).toBe("/events/17");
  });
});
