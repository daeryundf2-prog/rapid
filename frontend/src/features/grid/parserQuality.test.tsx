// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { useGridLocalStore } from "./adapter";
import { docsCollection, textStatusLabel } from "./columns/docs";
import { COPY_TIME_TITLE } from "./columns/FileCells";
import { filesCollection, modifiedTimeOf } from "./columns/files";
import { timelineCollection, timestampKindLabel } from "./columns/timeline";
import { DataGrid } from "./DataGrid";
import { bookmarkTarget } from "./reviewActions";
import { installFetch, jsonResponse, mockLayout, renderWithClient, resetGridStore } from "./testSupport";
import type { ColumnSpec } from "./types";

vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: vi.fn(),
}));

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

const column = (columns: ColumnSpec[], id: string) => columns.find((c) => c.id === id) as ColumnSpec;
const mapFile = (raw: Record<string, unknown>) => filesCollection.mapRow(raw, 0, { ref: { id: "files" } });

describe("files 수정 cell (parser-quality r1 time origin)", () => {
  it("prefers fs_modified_at, then the NTFS $SI join for an acquisition copy", () => {
    expect(
      modifiedTimeOf({ fs_modified_at: "2020-01-01T00:00:00Z", modified_at: "2026-10-01T00:00:00Z" }),
    ).toEqual({ value: "2020-01-01T00:00:00Z", origin: "filesystem" });
    expect(
      modifiedTimeOf({
        modified_at: "2026-10-01T00:00:00Z",
        modified_at_origin: "acquisition-copy",
        ntfs: { si_modified_at: "2019-05-05T05:05:05Z" },
      }),
    ).toEqual({ value: "2019-05-05T05:05:05Z", origin: "ntfs-si" });
    expect(modifiedTimeOf({ modified_at: "2021-02-02T00:00:00Z" })).toEqual({
      value: "2021-02-02T00:00:00Z",
      origin: null,
    });
  });

  it("renders an acquisition-copy time muted with the copy title and keeps it out of row.timestamp", () => {
    const row = mapFile({
      path: "C:/x/a.txt",
      modified_at: "2026-10-01T00:00:00Z",
      modified_at_origin: "acquisition-copy",
      categories: ["other", "documents"],
    });
    expect(row.timestamp).toBeNull();
    const spec = column(filesCollection.columns, "timestamp");
    expect(spec.tooltip?.(row)).toBe(COPY_TIME_TITLE);
    render(<div>{spec.render?.(row)}</div>);
    const cell = screen.getByTestId("files-copy-time");
    expect(cell.className).toContain("grid-cell-copytime");
    expect(cell.textContent).toContain(COPY_TIME_TITLE);
    expect(row.fields.categories).toBe("기타, 문서");
  });

  it("출처 preset shows $SI 수정, 삭제됨 chip, attributes and the time origin", () => {
    const row = mapFile({
      path: "C:/x/b.txt",
      modified_at: "2021-02-02T00:00:00Z",
      fs_modified_at: "2021-02-02T00:00:00Z",
      modified_at_origin: "listing",
      is_deleted: true,
      ntfs: { si_modified_at: "2021-02-01T00:00:00Z", attributes: ["ARCHIVE", "HIDDEN"] },
    });
    const ids = filesCollection.columns.filter((c) => c.presets.includes("source")).map((c) => c.id);
    expect(ids).toEqual(
      expect.arrayContaining(["ntfsSiModified", "deleted", "attributes", "modifiedOrigin"]),
    );
    expect(column(filesCollection.columns, "attributes").value(row)).toBe("ARCHIVE, HIDDEN");
    expect(column(filesCollection.columns, "modifiedOrigin").format?.(row)).toBe("이미지 목록(fls/MFT) 시각");
    render(<div>{column(filesCollection.columns, "deleted").render?.(row)}</div>);
    expect(screen.getByText("삭제됨").className).toContain("status-chip");
    expect(row.timestamp).toBe("2021-02-02T00:00:00Z");
  });
});

describe("timeline 시각 종류", () => {
  it("labels timestamp_kind / ts_kind / timestamp_label and shows it in the 시각 tooltip", () => {
    const map = (raw: Record<string, unknown>) =>
      timelineCollection.mapRow(raw, 0, { ref: { id: "timeline" } });
    const row = map({ timestamp: "2024-01-01T00:00:00Z", timestamp_kind: "run-3", source: "artifacts" });
    expect(timestampKindLabel("run-3")).toBe("실행 3");
    expect(column(timelineCollection.columns, "tsKind").format?.(row)).toBe("실행 3");
    expect(column(timelineCollection.columns, "timestamp").tooltip?.(row)).toContain("시각 종류: 실행 3");
    expect(column(timelineCollection.columns, "tsKind").presets).toEqual(["source"]);
    expect(map({ ts_kind: "modified" }).fields.tsKind).toBe("modified");
    expect(map({ timestamp_label: "last-written" }).fields.tsKind).toBe("last-written");
  });
});

describe("docs collection (every document, 일치만 toggle)", () => {
  const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));

  it("lists candidates by default, shows 본문 / 일치, and the toggle asks for matched=1", async () => {
    const calls = installFetch({
      "/docs": (url) =>
        url.searchParams.get("matched") === "1"
          ? jsonResponse({
              candidates: [
                { path: "C:/d/a.hwp", kind: "hwp", matched: true, record_index: 4, text_status: "ok" },
              ],
              matched: 1,
              pagination: { total: 3 },
            })
          : jsonResponse({
              candidates: [
                { path: "C:/d/a.hwp", kind: "hwp", matched: true, text_status: "ok", record_index: 4 },
                {
                  path: "C:/d/b.pdf",
                  kind: "pdf",
                  matched: false,
                  text_status: "encrypted",
                  record_index: 5,
                },
                {
                  path: "C:/d/c.pdf",
                  kind: "pdf",
                  matched: false,
                  text_status: "no-text",
                  text_reason: "텍스트 레이어 없음(이미지 전용 페이지 2/2): OCR 필요",
                  record_index: 6,
                },
              ],
              pagination: { total: 3 },
            }),
    });
    act(() => useGridLocalStore.getState().setRoute({ runId: "run-1", collection: { id: "docs" } }));
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(3));
    expect(calls.some((c) => c.url.includes("/docs") && !c.url.includes("matched=1"))).toBe(true);
    const text = rows().map((r) => r.textContent ?? "");
    expect(text[1]).toContain("암호화");
    expect(text[2]).toContain("이미지만");
    expect(rows()[0]?.getAttribute("data-row-key")).toBe("docs:/candidates/4");

    const toggle = screen.getByTestId("docs-matched-toggle");
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(toggle);
    expect(useGridLocalStore.getState().route.collection).toEqual({ id: "docs", category: "matched" });
    await waitFor(() => expect(rows().length).toBe(1));
    expect(calls.some((c) => c.url.includes("matched=1"))).toBe(true);
    expect(screen.getByTestId("docs-matched-toggle").getAttribute("aria-pressed")).toBe("true");
  });

  it("renders a results-only page (candidates omitted as []) as ordinary grid rows", async () => {
    // paginate_payload(..., "results", omit_fields=("candidates", ...)) keeps `candidates: []`.
    installFetch({
      "/docs": () =>
        jsonResponse({
          results: [
            { path: "C:/d/a.pdf", kind: "pdf", matched_keywords: ["계약"] },
            { path: "C:/d/b.hwp", kind: "hwp", matched_keywords: ["송금"] },
          ],
          candidates: [],
          omitted_fields: ["candidates", "manifest"],
          pagination: { collection: "results", offset: 0, total: 2, has_more: false },
        }),
    });
    act(() => useGridLocalStore.getState().setRoute({ runId: "run-1", collection: { id: "docs" } }));
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(2));
    const all = rows();
    expect(all.every((r) => r.getAttribute("aria-busy") !== "true")).toBe(true);
    expect(all.every((r) => r.hasAttribute("aria-selected") && r.hasAttribute("aria-rowindex"))).toBe(true);
    expect(all.filter((r) => r.tabIndex === 0)).toHaveLength(1);
    expect(all.map((r) => r.getAttribute("data-row-key"))).toEqual(["docs:/results/0", "docs:/results/1"]);
  });

  it("reads an older server's results list and bookmarks candidates as docs", () => {
    const old = docsCollection.mapRow({ path: "C:/d/a.pdf", matched_keywords: ["x"] }, 2, {
      ref: { id: "docs" },
      page: { rows: [], total: 1, offset: 0, backend: "file", truncated: false, elapsedMs: 0 },
    });
    expect(old.ref.locator).toBe("/results/2");
    expect(old.fields.matched).toBe(true);
    const row = docsCollection.mapRow({ path: "C:/d/b.pdf", record_index: 9 }, 0, {
      ref: { id: "docs" },
      page: {
        rows: [],
        total: 1,
        offset: 0,
        backend: "file",
        truncated: false,
        elapsedMs: 0,
        meta: { docs_rows: "candidates" },
      },
    }) as GridRow;
    expect(bookmarkTarget(row)).toEqual({ source: "docs", pointer: "/candidates/9" });
    expect(textStatusLabel("ok")).toBe("본문 있음");
    expect(textStatusLabel("no-text")).toBe("본문 없음");
  });
});
