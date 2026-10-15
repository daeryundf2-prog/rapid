// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FILES_INVENTORY, fetchFilesPage, parseFilesCategory } from "../../api/collections";
import { useGridLocalStore } from "./adapter";
import { artifactColumnsForKind } from "./columns/artifacts";
import { DELETION_UNKNOWN_TITLE } from "./columns/FileCells";
import { deletionStateOf, fileSignatureOf, filesCollection } from "./columns/files";
import { timelineCollection, timelinePathOf, timestampKindsOf } from "./columns/timeline";
import { DataGrid } from "./DataGrid";
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
const mapEvent = (raw: Record<string, unknown>) =>
  timelineCollection.mapRow(raw, 0, { ref: { id: "timeline" } });
const mapFile = (raw: Record<string, unknown>) => filesCollection.mapRow(raw, 0, { ref: { id: "files" } });

describe("timeline labels[] (parser-quality r2: one event per record and instant)", () => {
  const merged = {
    timestamp: "2024-03-01T10:00:00+00:00",
    timestamp_kind: "created",
    labels: ["created", "modified", "accessed"],
    source: "files",
    event_type: "file",
    path: "C:/Users/a/doc.txt",
    summary: "doc.txt",
    details: {},
  };

  it("keeps every time kind, primary first, and shows primary + n in 시각 종류", () => {
    const row = mapEvent(merged);
    expect(timestampKindsOf(merged)).toEqual(["created", "modified", "accessed"]);
    expect(row.fields.tsKind).toBe("created");
    expect(row.fields.timeKinds).toBe("생성 · 수정 · 접근");
    const spec = column(timelineCollection.columns, "tsKind");
    expect(spec.format?.(row)).toBe("생성 +2");
    expect(spec.tooltip?.(row)).toBe("생성 · 수정 · 접근 (created, modified, accessed)");
    expect(column(timelineCollection.columns, "timestamp").tooltip?.(row)).toContain(
      "시각 종류: 생성 · 수정 · 접근",
    );
    render(<div>{spec.render?.(row)}</div>);
    const cell = screen.getByTestId("timeline-time-kinds");
    expect(cell.textContent).toContain("생성");
    expect(cell.querySelector(".grid-tag-chip")?.textContent).toBe("+2");
    expect(cell.querySelector(".grid-tag-chip")?.getAttribute("title")).toBe("생성 · 수정 · 접근");
    expect(cell.querySelector(".sr-only")?.textContent).toBe("(같은 시각: 수정, 접근)");
  });

  it("a single-kind event renders just its label (labels absent or one entry)", () => {
    const row = mapEvent({ ...merged, labels: undefined, timestamp_kind: "run-2" });
    expect(column(timelineCollection.columns, "tsKind").format?.(row)).toBe("실행 2회차");
    render(<div>{column(timelineCollection.columns, "tsKind").render?.(row)}</div>);
    expect(screen.queryByTestId("timeline-time-kinds")).toBeNull();
    expect(screen.getByText("실행 2회차")).toBeTruthy();
    // labels[] without timestamp_kind still names the primary.
    expect(mapEvent({ timestamp: "x", labels: ["visited", "last-visited"] }).fields.tsKind).toBe("visited");
  });

  it("compact event rows (no input_file, trimmed context) still render title and path", () => {
    const compact = {
      timestamp: "2024-03-01T10:00:00+00:00",
      timestamp_kind: "last-written",
      source: "artifacts",
      event_type: "amcache-driver-binary",
      summary: "Amcache 드라이버 바이너리: usbstor.sys",
      details: { source_path: "C:/Windows/AppCompat/Programs/Amcache.hve" },
    };
    const row = mapEvent(compact);
    expect(row.title).toBe("Amcache 드라이버 바이너리: usbstor.sys");
    expect(row.sourcePath).toBe("C:/Windows/AppCompat/Programs/Amcache.hve");
    expect(timelinePathOf({ path: "C:/a", details: { source_path: "C:/b" } })).toBe("C:/a");
    expect(timelinePathOf({ input_file: "C:/in.json" })).toBe("C:/in.json");
    expect(mapEvent({ event_type: "eventlog-event" }).title).toBe("eventlog-event");
  });
});

describe("files inventory scope (전체 파일(인벤토리), 기타 (스캔 제외))", () => {
  it("maps route categories to scope=inventory requests", () => {
    expect(parseFilesCategory(undefined)).toEqual({ rowsKey: "candidates" });
    expect(parseFilesCategory("documents")).toEqual({ category: "documents", rowsKey: "candidates" });
    expect(parseFilesCategory(FILES_INVENTORY)).toEqual({ scope: "inventory", rowsKey: "inventory" });
    expect(parseFilesCategory("inventory:other")).toEqual({
      scope: "inventory",
      category: "other",
      rowsKey: "inventory",
    });
  });

  it("requests ?scope=inventory and reads `inventory` (or `candidates`) rows", async () => {
    const calls = installFetch({
      "/files": (url) =>
        url.searchParams.get("scope") === "inventory"
          ? jsonResponse({
              inventory: [{ path: "C:/x/a.bin", inventory_only: true, categories: [], record_index: 3 }],
              inventory_count: 41,
              candidate_count: 9,
              pagination: { total: 50 },
            })
          : jsonResponse({ candidates: [{ path: "C:/x/b.txt" }], pagination: { total: 9 } }),
    });
    const page = await fetchFilesPage("run-1", 0, 50, undefined, "inventory");
    expect(calls[0]?.url).toContain("scope=inventory");
    expect(calls[0]?.url).not.toContain("category=");
    expect(page.rows).toHaveLength(1);
    expect(page.total).toBe(50);
    expect(page.meta).toMatchObject({ inventory_count: 41, candidate_count: 9 });
    await fetchFilesPage("run-1", 0, 50, undefined, "inventory:other");
    expect(calls[1]?.url).toContain("scope=inventory&category=other");
    await fetchFilesPage("run-1", 0, 50);
    expect(calls[2]?.url).not.toContain("scope=");
  });

  it("the 기타 node's grid lists inventory rows as 기타 with inventory locators", async () => {
    const calls = installFetch({
      "/files": () =>
        jsonResponse({
          candidates: [
            {
              path: "C:/x/setup.log",
              name: "setup.log",
              inventory_only: true,
              categories: [],
              record_index: 7,
            },
          ],
          matched: 1,
          pagination: { total: 1, matched: 1 },
        }),
    });
    act(() =>
      useGridLocalStore
        .getState()
        .setRoute({ runId: "run-1", collection: { id: "files", category: "inventory:other" } }),
    );
    renderWithClient(<DataGrid />);
    const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));
    await waitFor(() => expect(rows().length).toBe(1));
    expect(calls.some((c) => c.url.includes("scope=inventory") && c.url.includes("category=other"))).toBe(
      true,
    );
    expect(rows()[0]?.getAttribute("data-row-key")).toBe("files:/inventory/7");
    const row = mapFile({ path: "C:/x/setup.log", inventory_only: true, categories: [] });
    expect(row.fields.categories).toBe("기타");
  });
});

describe("files deletion_state, match_method, signature (parser-quality r2)", () => {
  it("reads deletion_state (inventory row / recovery) before is_deleted", () => {
    expect(deletionStateOf({ deletion_state: "unknown", is_deleted: true })).toBe("unknown");
    expect(deletionStateOf({ recovery: { deletion_state: "deleted" } })).toBe("deleted");
    expect(deletionStateOf({ is_deleted: false })).toBe("allocated");
    expect(deletionStateOf({ ntfs: { is_deleted: true } })).toBe("deleted");
    expect(deletionStateOf({})).toBeNull();
  });

  it("renders deleted / allocated chips and a muted unknown", () => {
    const spec = column(filesCollection.columns, "deleted");
    const deleted = mapFile({ path: "C:/a", recovery: { deletion_state: "deleted" } });
    const allocated = mapFile({ path: "C:/b", deletion_state: "allocated" });
    const unknown = mapFile({ path: "C:/c", deletion_state: "unknown" });
    expect([deleted, allocated, unknown].map((r) => spec.format?.(r))).toEqual([
      "삭제됨",
      "할당",
      "알 수 없음",
    ]);
    expect(deleted.fields.isDeleted).toBe(true);
    expect(unknown.fields.isDeleted).toBeNull();
    render(
      <div>
        {spec.render?.(deleted)}
        {spec.render?.(allocated)}
        {spec.render?.(unknown)}
      </div>,
    );
    expect(screen.getByText("삭제됨").getAttribute("data-tone")).toBe("danger");
    expect(screen.getByText("할당").className).toContain("status-chip");
    const muted = screen.getByTestId("files-deletion-unknown");
    expect(muted.className).toContain("grid-cell-empty");
    expect(muted.getAttribute("title")).toBe(DELETION_UNKNOWN_TITLE);
    expect(spec.tooltip?.(unknown)).toBe(DELETION_UNKNOWN_TITLE);
  });

  it("출처 preset carries match_method and the aligned signature mismatch fields", () => {
    const ids = filesCollection.columns.filter((c) => c.presets.includes("source")).map((c) => c.id);
    expect(ids).toEqual(expect.arrayContaining(["matchMethod", "signature", "deleted"]));
    const row = mapFile({
      path: "C:/x/invoice.pdf",
      ntfs: { match_method: "relative-path" },
      file_signature: {
        status: "extension-signature-mismatch",
        detected: "zip",
        expected: ["pdf"],
        mismatch: true,
        mismatch_direction: "magic-not-expected-for-extension",
      },
    });
    expect(column(filesCollection.columns, "matchMethod").format?.(row)).toBe("상대 경로");
    expect(mapFile({ path: "C:/y", match_method: "mft-ref" }).fields.matchMethod).toBe("mft-ref");
    const methodCell = (raw: Record<string, unknown>) =>
      column(filesCollection.columns, "matchMethod").format?.(mapFile({ path: "C:/z", ...raw }));
    expect(methodCell({ match_method: "path-fold" })).toBe("경로 일치(대소문자 무시)");
    expect(methodCell({ match_method: "none" })).toBe("일치 없음");
    expect(methodCell({ match_method: null })).toBe("—");
    const sig = column(filesCollection.columns, "signature");
    expect(sig.format?.(row)).toBe("불일치");
    expect(sig.tooltip?.(row)).toBe("확장자와 다른 헤더 서명 · 감지 zip · 기대 pdf");
    render(<div>{sig.render?.(row)}</div>);
    expect(screen.getByTestId("files-signature-mismatch").getAttribute("data-tone")).toBe("warn");
    expect(fileSignatureOf({ file_signature: { status: "signature-matches-extension" } }).state).toBe(
      "match",
    );
    expect(
      fileSignatureOf({ file_signature: { status: "not-applicable", mismatch: false } }).state,
    ).toBeNull();
    // The file-signature-mismatch artifact shows the same direction field.
    const fsCols = artifactColumnsForKind("windows-filesystem");
    expect(fsCols.some((c) => c.header === "불일치 방향")).toBe(true);
  });
});
