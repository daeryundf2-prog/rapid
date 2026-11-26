import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SourcePreview } from "../../../api/viewer";
import { installFetch, preview } from "../testSupport";
import { DocumentView } from "./DocumentView";
import { PDF_INLINE_MAX_BYTES } from "./PdfView";

/** `type` of every blob handed to the frame, in order. */
let framedTypes: string[];

beforeEach(() => {
  framedTypes = [];
  URL.createObjectURL = vi.fn((object: Blob | MediaSource) => {
    framedTypes.push("type" in object ? object.type : "");
    return "blob:pdf";
  });
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, "pdfViewerEnabled");
});

function pdf(overrides: Partial<SourcePreview> = {}): SourcePreview {
  return preview({
    path: "C:/evidence/report.pdf",
    name: "report.pdf",
    extension: ".pdf",
    mime_type: "application/pdf",
    preview_type: "hex",
    size: 2048,
    ...overrides,
  });
}

function show(body: SourcePreview, terms: string[] = []) {
  const onOpenOriginal = vi.fn();
  render(<DocumentView runId="run-1" preview={body} terms={terms} onOpenOriginal={onOpenOriginal} />);
  return onOpenOriginal;
}

const frame = () => screen.findByTitle("report.pdf PDF 보기");
const toggle = (name: string) => screen.getByRole("button", { name });
/** The "cannot show here" block (reason + 원본 열기) that replaces the frame. */
const unavailable = () => document.querySelector(".viewer-unavailable");

describe("DocumentView — PDF", () => {
  it("frames the original's bytes as application/pdf, whatever type the server declared", async () => {
    const calls = installFetch({
      "source-file": () => new Response("%PDF-1.7\n1 0 obj", { headers: { "content-type": "text/html" } }),
    });
    show(pdf());
    const element = await frame();
    expect(element.tagName).toBe("IFRAME");
    expect(element.getAttribute("src")).toBe("blob:pdf");
    expect(framedTypes).toEqual(["application/pdf"]);
    expect(calls[0]?.url.searchParams.get("path")).toBe("C:/evidence/report.pdf");
    expect(toggle("PDF").getAttribute("aria-pressed")).toBe("true");
    expect(unavailable()).toBeNull();
  });

  it("does not frame a .pdf without the PDF header: the reason and 원본 열기 instead", async () => {
    installFetch({ "source-file": () => new Response("<html><script>alert(1)</script></html>") });
    const onOpenOriginal = show(pdf());
    fireEvent.click(await screen.findByRole("button", { name: "원본 열기" }));
    expect(onOpenOriginal).toHaveBeenCalledTimes(1);
    expect(unavailable()?.querySelector(".viewer-error")?.textContent).toContain("%PDF-");
    expect(document.querySelector("iframe")).toBeNull();
    expect(framedTypes).toEqual([]);
  });

  it("opens on the highlighted text when the keywords hit it; the toggle shows the pages", async () => {
    installFetch({ "source-file": () => new Response("%PDF-1.4") });
    show(pdf({ preview_type: "text", text: "이 계약은 무효\n다른 줄" }), ["계약"]);
    expect(toggle("추출 텍스트").getAttribute("aria-pressed")).toBe("true");
    expect(document.querySelector("mark.viewer-hit")?.textContent).toBe("계약");
    expect(document.querySelector("iframe")).toBeNull();
    fireEvent.click(toggle("PDF"));
    expect(await frame()).toBeTruthy();
    expect(document.querySelector("mark.viewer-hit")).toBeNull();
  });

  it("opens on the pages when no keyword hits; the toggle shows the extracted text", async () => {
    installFetch({ "source-file": () => new Response("%PDF-1.4") });
    show(pdf({ preview_type: "text", text: "본문 한 줄" }), ["없는말"]);
    expect(await frame()).toBeTruthy();
    fireEvent.click(toggle("추출 텍스트"));
    expect(screen.getByText("본문 한 줄")).toBeTruthy();
    expect(document.querySelector("iframe")).toBeNull();
  });

  it("shows an empty state, not text lines, for a PDF with no text layer", () => {
    installFetch({ "source-file": () => new Response("%PDF-1.4") });
    show(pdf());
    fireEvent.click(toggle("추출 텍스트"));
    expect(document.querySelector(".viewer-empty")).not.toBeNull();
    expect(document.querySelector(".viewer-lines")).toBeNull();
  });

  it("passes the server's message through when text extraction failed", () => {
    installFetch({ "source-file": () => new Response("%PDF-1.4") });
    show(pdf({ preview_type: "binary", message: "Text extraction failed: bad xref" }));
    fireEvent.click(toggle("추출 텍스트"));
    expect(document.querySelector(".viewer-empty")?.textContent).toContain(
      "Text extraction failed: bad xref",
    );
  });

  it("does not fetch a PDF over the inline limit", () => {
    const calls = installFetch({ "source-file": () => new Response("%PDF-1.4") });
    show(pdf({ size: PDF_INLINE_MAX_BYTES + 1 }));
    expect(unavailable()).not.toBeNull();
    expect(screen.getByRole("button", { name: "원본 열기" })).toBeTruthy();
    expect(document.querySelector("iframe")).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it("does not fetch where the browser shows no PDF inline (pdfViewerEnabled false)", () => {
    Object.defineProperty(navigator, "pdfViewerEnabled", { configurable: true, value: false });
    const calls = installFetch({ "source-file": () => new Response("%PDF-1.4") });
    show(pdf());
    expect(unavailable()).not.toBeNull();
    expect(document.querySelector("iframe")).toBeNull();
    expect(calls).toHaveLength(0);
  });
});

describe("DocumentView — other documents", () => {
  it("shows the extracted text of a DOCX with no PDF toggle", () => {
    const calls = installFetch({});
    show(preview({ name: "memo.docx", extension: ".docx", preview_type: "text", text: "메모 본문" }));
    expect(screen.getByText("메모 본문")).toBeTruthy();
    expect(screen.queryByRole("group", { name: "문서 표시 방식" })).toBeNull();
    expect(calls).toHaveLength(0);
  });
});
