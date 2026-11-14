/**
 * T-171 / T-172 follow-up (review wb5-7 P1-7, IS-128): 경로 복사 (grid and viewer), 인용 복사, the
 * viewer header and its tooltip, and the 메타 tab name the path INSIDE the evidence. The analysis
 * PC's result folder (`…\_e01\fs\…`) appears only under 기술 정보.
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveRegion } from "../../a11y";
import { resetAnnouncer } from "../../a11y/announcer";
import type { GridRow } from "../../contracts/collection";
import { evidenceDisplayValue } from "../../utils/pathDisplay";
import { makeRef, makeRow, recoveryFields } from "../grid/columns/common";
import { filesCollection } from "../grid/columns/files";
import { buildGridCommands, citationText, type GridCommandHost } from "../grid/gridCommands";
import { getCommand, resetViewerAdapter, setViewerTarget } from "./adapter";
import { clearCaseDbCache, SOURCE_LOCATION_UNKNOWN } from "./citation";
import { installFetch, metadata, preview, target } from "./testSupport";
import { Viewer } from "./Viewer";

const RAW = "D:\\cases\\2026-001\\run-7\\_e01\\fs\\Users\\kim\\Documents\\a.docx";
const EVIDENCE = "\\Users\\kim\\Documents\\a.docx";
const RECOVERED = "D:\\cases\\2026-001\\run-7\\_e01\\fs\\_deleted_mft\\b.docx";
/** Any trace of the analysis PC's result folder. */
const RESULT_FOLDER = /_e01|[\\/]fs[\\/]|D:\\cases/;

let clipboard: string[];

beforeEach(() => {
  resetAnnouncer();
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
  resetViewerAdapter();
  clearCaseDbCache();
  clipboard = [];
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn(async (text: string) => void clipboard.push(text)) },
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function fileRow(path: string, extra: Record<string, unknown> = {}): GridRow {
  return makeRow(
    makeRef("files", "/candidates/7"),
    { title: path.split("\\").pop() ?? "", sourcePath: path },
    extra,
  );
}

const live = () => (screen.getByTestId("live-polite").textContent ?? "").trim();

async function showViewer(path: string, row?: GridRow) {
  installFetch({
    "source-preview": () =>
      preview({ preview_type: "text", extension: ".docx", text: "hi", path, name: "a.docx" }),
    "source-metadata": (url) => metadata(url.searchParams.get("path") || "", 64),
    "source-hex-range": () => ({ offset: 0, rows: [], length_returned: 0, size: 64 }),
  });
  render(
    <>
      <Viewer />
      <LiveRegion />
    </>,
  );
  act(() => setViewerTarget(target({ sourcePath: path }), row ?? null));
  await waitFor(() => expect(live()).toContain("원본 로드됨"));
}

describe("viewer header and 경로 복사 (P1-7)", () => {
  it("the header path, its tooltip and the title tooltip are the in-evidence path", async () => {
    await showViewer(RAW);
    const path = document.querySelector(".viewer-path .mid-path") as HTMLElement;
    expect(path.textContent).toBe(EVIDENCE);
    expect(path.getAttribute("title")).toBe(EVIDENCE);
    const title = document.querySelector(".viewer-title") as HTMLElement;
    expect(title.getAttribute("title")).toBe(EVIDENCE);
    for (const text of [path.textContent, path.getAttribute("title"), title.getAttribute("title")])
      expect(text ?? "").not.toMatch(RESULT_FOLDER);
  });

  it("경로 복사 and 인용 복사 in the viewer give no result-folder string", async () => {
    await showViewer(RAW);
    await act(() => getCommand("viewer.copy-path")?.run?.(ctxOf()) as Promise<void>);
    await waitFor(() => expect(clipboard).toEqual([EVIDENCE]));
    await act(() => getCommand("viewer.cite")?.run?.(ctxOf()) as Promise<void>);
    await waitFor(() => expect(clipboard).toHaveLength(2));
    expect(clipboard[1]).toContain(`원본=${EVIDENCE}`);
    for (const text of clipboard) expect(text).not.toMatch(RESULT_FOLDER);
  });

  it("a recovered item has no in-evidence path: 경로 복사 says why and the header reads unknown", async () => {
    await showViewer(RECOVERED);
    expect(getCommand("viewer.copy-path")?.disabledReason?.(ctxOf())).toBe(SOURCE_LOCATION_UNKNOWN);
    const path = document.querySelector(".viewer-path .mid-path") as HTMLElement;
    expect(path.textContent).toBe(SOURCE_LOCATION_UNKNOWN);
    expect(path.getAttribute("title") ?? "").not.toMatch(RESULT_FOLDER);
  });

  it("the 메타 tab shows the raw result-folder path only under 기술 정보 (복구 정보 included)", async () => {
    const row = fileRow(RAW, {
      details: { source_path: RAW },
      ...recoveryFields({ candidate_kind: "deleted-entry", source_path: RAW, offset: 4096 }),
    });
    await showViewer(RAW, row);
    fireEvent.click(screen.getByRole("tab", { name: "메타" }));
    const tech = await screen.findByTestId("meta-tech-info");
    expect(within(tech).getByText(RAW, { exact: false })).toBeTruthy();
    const view = document.querySelector(".meta-view") as HTMLElement;
    const outside = view.cloneNode(true) as HTMLElement;
    outside.querySelector("[data-testid='meta-tech-info']")?.remove();
    expect(outside.textContent ?? "").not.toContain("_e01");
    for (const el of outside.querySelectorAll("[title]"))
      expect(el.getAttribute("title")).not.toContain("_e01");
    expect(outside.textContent).toContain(EVIDENCE);
  });
});

describe("grid 경로 복사 · 인용 복사 (P1-7)", () => {
  function host(row: GridRow) {
    const toast = vi.fn();
    const current = {
      runId: "run-7",
      collection: { id: "files" },
      getFocusedRow: () => row,
      getSelectedRows: () => [row],
      openRow: vi.fn(),
      setFilter: vi.fn(),
      navigate: vi.fn(),
      patchRows: () => () => {},
      toast,
      refetch: vi.fn(),
      showExtract: vi.fn(),
      openTagPrompt: vi.fn(),
      runIsActive: false,
    } as unknown as GridCommandHost;
    return { ref: { current }, toast };
  }

  it("copies the in-evidence path, never the result folder", async () => {
    const { ref } = host(fileRow(RAW));
    const command = buildGridCommands(ref).find((c) => c.id === "grid.copyPath");
    expect(command?.disabledReason?.(ctxOf())).toBeUndefined();
    await command?.run?.(ctxOf());
    expect(clipboard).toEqual([EVIDENCE]);
  });

  it("a recovered row's 경로 복사 is disabled with the reason", () => {
    const { ref } = host(fileRow(RECOVERED));
    const command = buildGridCommands(ref).find((c) => c.id === "grid.copyPath");
    expect(command?.disabledReason?.(ctxOf())).toBe(SOURCE_LOCATION_UNKNOWN);
  });

  it("the grid citation names the in-evidence path", () => {
    expect(citationText(fileRow(RAW))).toContain(EVIDENCE);
    expect(citationText(fileRow(RAW))).not.toMatch(RESULT_FOLDER);
    expect(citationText(fileRow(RECOVERED))).toContain(`(${SOURCE_LOCATION_UNKNOWN})`);
  });
});

describe("evidenceDisplayValue", () => {
  it("rewrites result-folder strings at any depth and leaves other values alone", () => {
    const value = { a: RAW, b: [RECOVERED, "x"], c: 3, d: { e: "C:\\evidence\\f.txt" } };
    expect(evidenceDisplayValue(value, "?")).toEqual({
      a: EVIDENCE,
      b: ["?", "x"],
      c: 3,
      d: { e: "C:\\evidence\\f.txt" },
    });
    const plain = { d: "C:\\evidence\\f.txt" };
    expect(evidenceDisplayValue(plain, "?")).toBe(plain);
  });
});

describe("files 이름 carries the 복구 marker (T-171: shown while 경로 is hidden)", () => {
  it("a recovered row's name cell has the marker; a live row's does not", () => {
    const name = filesCollection.columns.find((c) => c.id === "title");
    const recovered = fileRow(RECOVERED, { recovered: true, locationUnknown: true });
    render(<div>{name?.render?.(recovered)}</div>);
    const cell = screen.getByTestId("name-cell-recovered");
    expect(cell.textContent).toBe("복구b.docx");
    expect(cell.getAttribute("title") ?? "").not.toMatch(RESULT_FOLDER);
    cleanup();
    render(<div>{name?.render?.(fileRow(RAW))}</div>);
    expect(screen.queryByTestId("name-cell-recovered")).toBeNull();
  });
});

function ctxOf() {
  return {
    runId: "run-1",
    collection: null,
    selectedRowKeys: [],
    focusedRowKey: null,
    viewerHasTarget: true,
    runIsActive: false,
  };
}
