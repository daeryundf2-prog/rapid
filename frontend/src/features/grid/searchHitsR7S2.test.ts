import { afterEach, describe, expect, it, vi } from "vitest";
import { applyMark, buildCitation, markDisabledReason } from "../viewer/citation";
import { searchCollection } from "./columns/search";
import { buildViewerTarget, citationText } from "./gridCommands";
import { resetCaseDbHandles } from "./reviewActions";
import { installFetch, jsonResponse } from "./testSupport";

afterEach(() => {
  vi.unstubAllGlobals();
  resetCaseDbHandles();
});

const map = (raw: Record<string, unknown>, index = 0) =>
  searchCollection.mapRow(raw, index, { ref: { id: "search" } });

describe("R7 S2 #8: a search hit opened in the viewer is marked, bookmarked and cited by its source row", () => {
  // v2 document hit: no own pointer (the grid's ref falls back to "/search/0").
  const docsHit = {
    source: "documents",
    kind: "docx",
    path: "C:\\Users\\kim\\계약서.docx",
    title: "계약서.docx",
    locator: { collection: "docs", kind: "", pointer: "/candidates/3" },
  };
  const artifactHit = {
    source: "artifacts",
    kind: "eventlog",
    pointer: "/artifacts/12",
    path: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    locator: { collection: "artifacts", kind: "eventlog", pointer: "/artifacts/12" },
  };

  it("docs hit: viewer target carries the API locator; marks enabled; citations name docs:/candidates/3", async () => {
    const row = map(docsHit);
    expect(row.ref.locator).toBe("/search/0");
    const target = buildViewerTarget("run-8", row);
    expect(target.review).toEqual({ collection: "docs", pointer: "/candidates/3" });
    expect(markDisabledReason(target, "relevant")).toBeUndefined();
    expect(markDisabledReason(target, "bookmark")).toBeUndefined();
    expect(buildCitation(target, null)).toContain("위치=docs:/candidates/3");
    expect(buildCitation(target, null)).not.toContain("search:");
    expect(citationText(row)).toContain("[docs:/candidates/3]");

    const calls = installFetch({
      "/api/runs/run-8": () =>
        jsonResponse({
          run_id: "run-8",
          case_db_ready: true,
          case_db: { database: "/o/case.db", case_id: "c1" },
        }),
      "/api/case-db/review-batch": () => jsonResponse({ updated_count: 1 }),
    });
    await applyMark(target, "relevant");
    const post = calls.find((call) => call.url === "/api/case-db/review-batch");
    expect(JSON.stringify(post?.body)).toContain('"collection":"docs"');
    expect(JSON.stringify(post?.body)).toContain('"locator":"/candidates/3"');
  });

  it("artifact hit: kind travels too; container sha256 wording kept", () => {
    const row = map(artifactHit);
    const target = buildViewerTarget("run-8", row);
    expect(target.review).toEqual({ collection: "artifacts", kind: "eventlog", pointer: "/artifacts/12" });
    expect(target.preferredMode).toBe("meta");
    expect(markDisabledReason(target, "bookmark")).toBeUndefined();
    expect(buildCitation(target, "ab".repeat(32), row)).toContain("위치=artifacts:eventlog:/artifacts/12");
    expect(buildCitation(target, "ab".repeat(32), row)).toContain("컨테이너 sha256=");
    expect(citationText(row)).toContain("[artifacts:eventlog:/artifacts/12]");
  });

  it("rows that are not search hits are unchanged (no review field)", () => {
    const target = buildViewerTarget("run-8", {
      ...map(docsHit),
      fields: {},
      ref: { collection: "files", locator: "/candidates/9" },
    });
    expect(target.review).toBeUndefined();
  });
});

describe("R7 S2 #6: archive entry hits get their own row key", () => {
  const parents = [3, 4, 5].map((n) => ({
    source: "files",
    kind: "archive",
    path: `C:\\data\\a${n}.zip`,
    locator: { collection: "files", kind: "", pointer: `/candidates/${n}` },
  }));

  it("12 entries (entry_path on the shared parent locator) + 3 parents → 15 distinct keys", () => {
    const entries = Array.from({ length: 12 }, (_, i) => ({
      ...parents[i % 3],
      entry_path: `dir/file-${i}.txt`,
    }));
    const keys = [...parents, ...entries].map((raw, i) => map(raw, i).rowKey);
    expect(new Set(keys).size).toBe(15);
    expect(map(entries[0] as Record<string, unknown>).fields.entryPath).toBe("dir/file-0.txt");
  });

  it("12 entries with an entry locator (<parent>#entry:<n>) + 3 parents → 15 distinct keys", () => {
    const entries = Array.from({ length: 12 }, (_, i) => {
      const parent = parents[i % 3] as (typeof parents)[number];
      return {
        ...parent,
        locator: { ...parent.locator, pointer: `${parent.locator.pointer}#entry:${i}` },
      };
    });
    const keys = [...parents, ...entries].map((raw, i) => map(raw, i).rowKey);
    expect(new Set(keys).size).toBe(15);
    // The entry locator already makes the key unique: no duplicated suffix.
    expect(map(entries[0] as Record<string, unknown>).rowKey).toBe("search:files::/candidates/3#entry:0");
  });

  it("a hit without entry information keeps its old key", () => {
    expect(map(parents[0] as Record<string, unknown>).rowKey).toBe("search:files::/candidates/3");
  });
});
