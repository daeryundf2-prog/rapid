// What each typed view shows when it cannot show the file the usual way.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse, preview } from "../testSupport";
import { ImageView } from "./ImageView";
import { MediaView } from "./MediaView";
import { FULL_TEXT_MAX_BYTES, LINE_WINDOW, SourceView } from "./SourceView";

beforeEach(() => {
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** The "cannot show here" block: a reason and the 원본 열기 button. */
const unavailable = () => document.querySelector(".viewer-unavailable");

describe("ImageView — a format the browser cannot decode", () => {
  it("shows the server's JPEG instead, then 원본 열기 when that cannot be shown either", async () => {
    const calls = installFetch({
      "source-file": () => new Response("II*"),
      "source-thumbnail": () => new Response("jpeg"),
      "source-image-gallery": () => ({
        offset: 0,
        limit: 12,
        returned: 0,
        total: 0,
        has_next: false,
        items: [],
      }),
    });
    const rendition = () => calls.find((call) => call.url.pathname.endsWith("/source-thumbnail"));
    const onOpenOriginal = vi.fn();
    render(
      <ImageView
        runId="run-1"
        preview={preview({
          path: "C:/evidence/scan.tiff",
          name: "scan.tiff",
          extension: ".tiff",
          preview_type: "image",
          image: {},
        })}
        onOpenPath={() => undefined}
        onOpenOriginal={onOpenOriginal}
      />,
    );
    const original = await screen.findByAltText("scan.tiff");
    expect(rendition()).toBeUndefined();

    fireEvent.error(original);
    await waitFor(() => expect(rendition()).toBeDefined());
    expect(rendition()?.url.searchParams.get("size")).toBe("512");
    expect(rendition()?.url.searchParams.get("path")).toBe("C:/evidence/scan.tiff");
    const served = await screen.findByAltText("scan.tiff");
    // The rendition is labelled as a preview, with its size limit.
    expect(document.querySelector(".image-figure > p.viewer-note")?.textContent).toContain("512px");
    expect(unavailable()).toBeNull();

    fireEvent.error(served);
    expect(unavailable()).not.toBeNull();
    expect(screen.queryByAltText("scan.tiff")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "원본 열기" }));
    expect(onOpenOriginal).toHaveBeenCalledTimes(1);
  });
});

describe("ImageView — an SVG original", () => {
  it("shows it from a data: URL, never a blob: URL in the console's origin", async () => {
    installFetch({
      "source-file": () =>
        new Response('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', {
          headers: { "content-type": "image/svg+xml" },
        }),
      "source-image-gallery": () => ({
        offset: 0,
        limit: 12,
        returned: 0,
        total: 0,
        has_next: false,
        items: [],
      }),
    });
    render(
      <ImageView
        runId="run-1"
        preview={preview({
          path: "C:/evidence/logo.svg",
          name: "logo.svg",
          extension: ".svg",
          mime_type: "image/svg+xml",
          preview_type: "image",
          image: {},
        })}
        onOpenPath={() => undefined}
        onOpenOriginal={() => undefined}
      />,
    );
    const image = await screen.findByAltText("logo.svg");
    expect(image.getAttribute("src")).toMatch(/^data:image\/svg\+xml;base64,/);
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});

describe("MediaView — a codec the browser cannot play", () => {
  it("replaces the player with the reason and 원본 열기", async () => {
    installFetch({ "source-file": () => new Response("mp4v") });
    const onOpenOriginal = vi.fn();
    render(
      <MediaView
        runId="run-1"
        preview={preview({
          path: "C:/evidence/clip.mp4",
          name: "clip.mp4",
          extension: ".mp4",
          mime_type: "video/mp4",
          preview_type: "media",
          media: {},
        })}
        onCopy={() => undefined}
        onOpenOriginal={onOpenOriginal}
      />,
    );
    const player = await screen.findByLabelText("clip.mp4 재생");
    expect(unavailable()).toBeNull();
    fireEvent.error(player);
    expect(unavailable()).not.toBeNull();
    expect(screen.queryByLabelText("clip.mp4 재생")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "원본 열기" }));
    expect(onOpenOriginal).toHaveBeenCalledTimes(1);
  });
});

describe("SourceView — a text file the server previewed as bytes (over its size limit)", () => {
  const oversized = preview({
    path: "C:/evidence/big.log",
    name: "big.log",
    extension: ".log",
    preview_type: "binary",
    size: 30_000_000,
    message: "Text extraction failed: log file exceeds text extraction size limit",
  });

  it("reads the start of the original as text and says where it stops", async () => {
    const line = `${"x".repeat(99)}\n`;
    const calls = installFetch({
      "source-text": () => ({
        text: line.repeat(Math.ceil(FULL_TEXT_MAX_BYTES / line.length)),
        size: 30_000_000,
        bytes_read: FULL_TEXT_MAX_BYTES,
        complete: false,
        redacted: false,
      }),
    });
    render(<SourceView runId="run-1" preview={oversized} terms={[]} />);
    expect((await screen.findByTestId("source-prefix-note")).textContent).toContain("2 MB");
    expect(document.querySelectorAll(".viewer-line")).toHaveLength(LINE_WINDOW);
    expect(calls[0]?.url.pathname).toBe("/api/runs/run-1/source-text");
    expect(calls[0]?.url.searchParams.get("path")).toBe("C:/evidence/big.log");
    expect(calls[0]?.url.searchParams.get("max_bytes")).toBe(String(FULL_TEXT_MAX_BYTES));
    expect(screen.queryByTestId("source-redacted-note")).toBeNull();
  });

  it("shows the read error instead of an empty view", async () => {
    installFetch({ "source-text": () => jsonResponse({ detail: "원본 파일이 없습니다" }, 404) });
    render(<SourceView runId="run-1" preview={oversized} terms={[]} />);
    await waitFor(() =>
      expect(document.querySelector(".viewer-error")?.textContent).toContain("원본 파일이 없습니다"),
    );
    expect(document.querySelector(".viewer-empty")).toBeNull();
  });
});

/** A BitLocker recovery key as the server masks it (antiforensics.mask_recovery_password). */
const MASKED_KEY = "XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXX53";

describe("SourceView — secrets in the text views", () => {
  const masked = (complete: boolean) => ({
    text: `복구 키: ${MASKED_KEY}\n`,
    size: 30_000_000,
    bytes_read: 64,
    complete,
    redacted: true,
  });

  it("shows the server's masked text past the size limit and says that it is masked", async () => {
    const calls = installFetch({ "source-text": () => masked(false) });
    render(
      <SourceView
        runId="run-1"
        preview={preview({
          path: "C:/evidence/keys.log",
          name: "keys.log",
          extension: ".log",
          size: 30_000_000,
        })}
        terms={[]}
      />,
    );
    expect((await screen.findByTestId("source-redacted-note")).textContent).toContain("원본 열기");
    expect(screen.getByText(`복구 키: ${MASKED_KEY}`)).toBeTruthy();
    expect(calls.map((call) => call.url.pathname)).toEqual(["/api/runs/run-1/source-text"]);
  });

  it("reads 더 보기 through the server's redaction, never the raw source-file", async () => {
    const calls = installFetch({ "source-text": () => masked(true) });
    render(
      <SourceView
        runId="run-1"
        preview={preview({
          path: "C:/evidence/notes.txt",
          name: "notes.txt",
          extension: ".txt",
          preview_type: "text",
          text: "앞부분",
          truncated: true,
        })}
        terms={[]}
      />,
    );
    expect(screen.queryByTestId("source-redacted-note")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "더 보기 (최대 2 MB)" }));
    expect(await screen.findByTestId("source-redacted-note")).toBeTruthy();
    expect(screen.getByText(`복구 키: ${MASKED_KEY}`)).toBeTruthy();
    expect(calls.map((call) => call.url.pathname)).toEqual(["/api/runs/run-1/source-text"]);
  });
});
