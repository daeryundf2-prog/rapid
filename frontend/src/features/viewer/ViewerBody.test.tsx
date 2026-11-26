import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SourcePreview } from "../../api/viewer";
import { hexRangeHandler, installFetch, preview, target } from "./testSupport";
import { ViewerBody, type ViewerBodyProps } from "./ViewerBody";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** The "no viewer for this type" notice above the hex grid. */
const notice = () => document.querySelector(".viewer-fallback .viewer-unavailable");
/** The file facts listed under the notice, in order. */
const facts = () => Array.from(document.querySelectorAll(".viewer-fallback dd")).map((dd) => dd.textContent);

/** The hex mode of `body` (a ready preview), as the viewer renders it. */
function showHex(body: SourcePreview, overrides: Partial<ViewerBodyProps> = {}) {
  installFetch({ "source-hex-range": hexRangeHandler(body.size) });
  const onOpenOriginal = vi.fn();
  render(
    <ViewerBody
      target={target({ sourcePath: body.path })}
      mode="hex"
      resolving={false}
      highlight={undefined}
      previewState={{ status: "ok", data: body, error: null }}
      metadata={null}
      metadataError={null}
      hashBusy={false}
      row={null}
      sessionMarks={[]}
      terms={[]}
      onComputeHash={() => undefined}
      onOpenPath={() => undefined}
      onCopy={() => undefined}
      onOpenOriginal={onOpenOriginal}
      {...overrides}
    />,
  );
  return onOpenOriginal;
}

const spreadsheet = (overrides: Partial<SourcePreview> = {}) =>
  preview({
    path: "C:/evidence/ledger.xls",
    name: "ledger.xls",
    extension: ".xls",
    mime_type: "application/vnd.ms-excel",
    preview_type: "hex",
    size: 6000,
    ...overrides,
  });

describe("ViewerBody — hex as the fallback for a type with no viewer", () => {
  it("puts the notice, the file facts and 원본 열기 above the hex grid", () => {
    const onOpenOriginal = showHex(spreadsheet());
    expect(notice()).not.toBeNull();
    expect(facts()).toEqual(["XLS", "application/vnd.ms-excel", "6,000바이트 (5.9 KB)"]);
    expect(screen.getByRole("grid")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "원본 열기" }));
    expect(onOpenOriginal).toHaveBeenCalledTimes(1);
  });

  it("adds the server's message to the facts when its own preview failed", () => {
    const message = "Text extraction failed: xlsx file exceeds text extraction size limit";
    showHex(spreadsheet({ extension: ".xlsx", preview_type: "binary", message }));
    expect(facts()).toEqual(["XLSX", "application/vnd.ms-excel", "6,000바이트 (5.9 KB)", message]);
  });

  it("names a file without an extension as such", () => {
    showHex(spreadsheet({ name: "NTUSER", extension: "", mime_type: "application/octet-stream" }));
    expect(facts()[0]).toBe("확장자 없음");
  });

  it("shows the grid alone when hex was chosen for a type that has its own viewer", () => {
    showHex(preview({ name: "notes.txt", extension: ".txt", preview_type: "text", text: "x" }));
    expect(screen.getByRole("grid")).toBeTruthy();
    expect(notice()).toBeNull();
    expect(screen.queryByRole("button", { name: "원본 열기" })).toBeNull();
  });

  it("shows the grid alone when hex opens on a record's byte range", () => {
    showHex(preview({ name: "Security.evtx", extension: ".evtx", preview_type: "hex", size: 4096 }), {
      highlight: { offset: 512, length: 16 },
    });
    expect(screen.getByRole("grid")).toBeTruthy();
    expect(notice()).toBeNull();
  });
});
