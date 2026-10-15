import { QueryClient } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunWithProgress } from "../../api/runsProgress";
import type { SourcePreview } from "../../api/viewer";
import { resetCommandRegistry } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { makeRef, makeRow } from "../grid/columns/common";
import {
  buildGridCommands,
  type GridCommandHost,
  OCR_COLLECTION_REASON,
  OCR_NO_IMAGE_REASON,
  OCR_SELECTED_COMMAND,
  ocrLocatorOf,
} from "../grid/gridCommands";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { ImageView } from "../viewer/views/ImageView";
import { buildAnalysisOptions, defaultForm } from "./analysisForm";
import { registerAnalysisCommands } from "./commands";
import { useAnalysisStore } from "./store";

const RUN = "run-1";

const file = (i: number, name: string) =>
  makeRow(
    makeRef("files", `/candidates/${i}`),
    { title: name, sourcePath: `C:/e/${name}` },
    { extension: name.split(".").pop() },
  );
const media = (i: number) =>
  makeRow(makeRef("artifacts", `/artifacts/${i}`, "media-image"), {
    title: `img ${i}`,
    sourcePath: `C:/e/${i}.png`,
  });
const prefetch = makeRow(makeRef("artifacts", "/artifacts/3", "windows-prefetch"), {
  title: "x.pf",
  sourcePath: "C:/x.pf",
});

function host(
  collection: "files" | "artifacts" | "timeline",
  selected: GridRow[],
  focused?: GridRow,
): { current: GridCommandHost } {
  return {
    current: {
      runId: RUN,
      collection: { id: collection },
      getFocusedRow: () => focused,
      getSelectedRows: () => selected,
      openRow: () => undefined,
      setFilter: () => undefined,
      navigate: () => undefined,
      patchRows: () => () => undefined,
      toast: () => undefined,
      refetch: () => undefined,
      showExtract: () => undefined,
      openTagPrompt: () => undefined,
      runIsActive: false,
    } as GridCommandHost,
  };
}

const ctx = {
  runId: RUN,
  collection: "files",
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

beforeEach(() => {
  resetCommandRegistry();
  window.location.hash = `#/case/${RUN}/explore/files`;
  useAppStore.getState().syncRouteFromLocation(parseHash(window.location.hash));
  useAppStore.setState({ runs: [{ run_id: RUN, status: "completed" }] as unknown as RunWithProgress[] });
  useAnalysisStore.setState({ runId: RUN, analyses: [], available: true, dialog: null });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetCommandRegistry();
});

describe("선택 행 OCR 실행 (ocr-batch target.locators)", () => {
  it("maps image rows to /candidates/<n> or /artifacts/<n>; other rows have no locator", () => {
    expect(ocrLocatorOf(file(4, "scan.JPG"))).toBe("/candidates/4");
    expect(ocrLocatorOf(file(5, "memo.docx"))).toBeNull();
    expect(ocrLocatorOf(media(7))).toBe("/artifacts/7");
    expect(ocrLocatorOf(prefetch)).toBeNull();
  });

  it("is disabled with a reason without images, outside files/artifacts, and opens the dialog with locators", () => {
    const command = (h: { current: GridCommandHost }) =>
      buildGridCommands(h).find((c) => c.id === OCR_SELECTED_COMMAND) as NonNullable<
        ReturnType<typeof buildGridCommands>[number]
      >;
    expect(command(host("files", [file(5, "memo.docx")])).disabledReason?.(ctx)).toBe(OCR_NO_IMAGE_REASON);
    expect(command(host("timeline", [file(4, "a.png")])).disabledReason?.(ctx)).toBe(OCR_COLLECTION_REASON);
    expect(command(host("artifacts", [prefetch])).disabledReason?.(ctx)).toBe(OCR_NO_IMAGE_REASON);
    const ok = command(host("files", [file(4, "a.png"), file(5, "memo.docx"), file(6, "b.jpeg")]));
    expect(ok.label).toBe("선택 행 OCR 실행");
    expect(ok.disabledReason?.(ctx)).toBeUndefined();
    void ok.run(ctx);
    expect(useAnalysisStore.getState().dialog).toEqual({
      kind: "ocr-batch",
      preset: { locators: ["/candidates/4", "/candidates/6"] },
    });
    // Focused row only (no selection) works too.
    const single = command(host("artifacts", [], media(2)));
    void single.run(ctx);
    expect(useAnalysisStore.getState().dialog?.preset).toEqual({ locators: ["/artifacts/2"] });
  });

  it("the options body sends target.locators; without them the media-image default stays", () => {
    expect(
      buildAnalysisOptions("ocr-batch", { ...defaultForm("ocr-batch"), locators: ["/artifacts/2"] }).target,
    ).toEqual({
      locators: ["/artifacts/2"],
    });
    expect(buildAnalysisOptions("ocr-batch", defaultForm("ocr-batch")).target).toEqual({
      kind: "media-image",
    });
  });

  it("is blocked with the run reason while an OCR job runs", () => {
    registerAnalysisCommands(new QueryClient());
    useAnalysisStore.setState({
      runId: RUN,
      available: true,
      analyses: [
        {
          analysis_id: "o1",
          kind: "ocr-batch",
          status: "running",
          options: {},
          created_at: "",
          progress: { done: 0, total: null, unit: "", message: "", percent: null },
          row_count: 0,
        },
      ],
    });
    const cmd = buildGridCommands(host("files", [file(4, "a.png")])).find(
      (c) => c.id === OCR_SELECTED_COMMAND,
    );
    expect(cmd?.disabledReason?.(ctx)).toBe("이미 실행 중인 분석이 있습니다");
  });
});

describe('viewer reuses stored OCR (image.ocr_sidecar.source === "analysis")', () => {
  it("shows the stored text in the image mode without any OCR request", async () => {
    const calls = installFetch({
      "/source-image-gallery": () => jsonResponse({ items: [], total: 0, offset: 0, limit: 24 }),
      "/source-file": () => new Response(new Blob([new Uint8Array([137, 80, 78, 71])]), { status: 200 }),
    });
    const preview = {
      path: "C:/e/scan.png",
      name: "scan.png",
      preview_type: "image",
      size: 4,
      image: {
        decoded: true,
        width: 10,
        height: 10,
        ocr_sidecar: { text: "계약서 제3조 위약금", source: "analysis", analysis_id: "o1" },
      },
    } as unknown as SourcePreview;
    render(<ImageView runId={RUN} preview={preview} onOpenPath={() => undefined} />);
    expect(screen.getByText("계약서 제3조 위약금")).toBeTruthy();
    expect(screen.getByTestId("ocr-from-analysis").textContent).toContain("다시 OCR하지 않음");
    await waitFor(() => expect(calls.some((c) => c.url.includes("/source-image-gallery"))).toBe(true));
    expect(calls.filter((c) => /ocr/i.test(c.url))).toEqual([]);
  });
});
