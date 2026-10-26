import { describe, expect, it } from "vitest";
import { COLLECTIONS } from ".";
import { snippetSpans } from "./SearchCells";
import { SEARCH_SOURCE_LABELS, searchKindLabel } from "./search";

const ctx = { ref: { id: "search" as const } };
const columnText = (id: string, row: ReturnType<typeof COLLECTIONS.search.mapRow>) => {
  const spec = COLLECTIONS.search.columns.find((c) => c.id === id);
  if (!spec) throw new Error(id);
  return spec.format ? spec.format(row) : String(spec.value(row) ?? "");
};

describe("search results columns (R7)", () => {
  const artifactHit = {
    source: "artifacts",
    kind: "windows-execution",
    artifact_type: "windows-prefetch",
    title: "CHROME.EXE",
    path: "D:\\rapid-qa\\bsh-subset\\Windows\\Prefetch\\CHROME.EXE-1.pf",
    display_path: "Windows\\Prefetch\\CHROME.EXE-1.pf",
    timestamp: "2025-05-19T13:31:08Z",
    snippet: "executable_name: CHROME.EXE",
    snippet_highlights: [[17, 23]],
    preview: "executable_name: CHROME.EXE",
    pointer: "/artifacts/9",
    locator: { collection: "artifacts", kind: "windows-execution", pointer: "/artifacts/9" },
    matched_keywords: ["chrome"],
  };

  it("shows Korean source and type names, not ids", () => {
    const row = COLLECTIONS.search.mapRow(artifactHit, 0, ctx);
    expect(columnText("source", row)).toBe("아티팩트");
    expect(columnText("kind", row)).not.toMatch(/^windows-/);
    expect(searchKindLabel("files", "documents,images", "")).toBe("문서·이미지");
    expect(searchKindLabel("documents", "hwp", "")).toBe("HWP 문서");
    expect(searchKindLabel("indicators", "ioc-scanner-hit", "")).toBe("IOC 스캐너 적중");
    for (const label of Object.values(SEARCH_SOURCE_LABELS)) expect(label).not.toMatch(/^[a-z-]+$/);
  });

  it("uses the record title, time, snippet and the path under the acquisition root", () => {
    const row = COLLECTIONS.search.mapRow(artifactHit, 0, ctx);
    expect(row.title).toBe("CHROME.EXE");
    expect(row.timestamp).toBe("2025-05-19T13:31:08Z");
    expect(row.artifactType).toBe("windows-prefetch");
    expect(columnText("preview", row)).toBe("executable_name: CHROME.EXE");
    expect(columnText("path", row)).toBe("Windows\\Prefetch\\CHROME.EXE-1.pf");
    const pathSpec = COLLECTIONS.search.columns.find((c) => c.id === "path");
    expect(pathSpec?.tooltip?.(row)).toBe(artifactHit.path);
    expect(row.sourcePath).toBe(artifactHit.path);
    expect(row.rowKey).toBe("search:artifacts:windows-execution:/artifacts/9");
  });

  it("falls back to the file name when a hit has no title", () => {
    const row = COLLECTIONS.search.mapRow({ ...artifactHit, title: "", snippet: "" }, 0, ctx);
    expect(row.title).toBe("CHROME.EXE-1.pf");
  });

  it("parses highlight spans defensively", () => {
    expect(
      snippetSpans(
        [
          [0, 2],
          [1, 3],
          [5, 99],
          ["a", 1],
          [4, 5],
        ],
        10,
      ),
    ).toEqual([
      [0, 2],
      [4, 5],
    ]);
    expect(snippetSpans(null, 10)).toEqual([]);
  });
});
