import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { THUMB_NO_PREVIEW_TEXT } from "../../views/ThumbGlyph";
import { ImageView } from "./ImageView";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("ImageView undecodable image (r8 verify F2)", () => {
  it("swaps the browser's broken-image icon for the 미리보기 없음 glyph (main image and strip)", async () => {
    const gallery = {
      items: [
        { path: "C:/e/a.png", name: "a.png", is_anchor: true },
        { path: "C:/e/b.png", name: "b.png", is_anchor: false },
      ],
      total: 2,
      offset: 0,
      limit: 12,
      has_next: false,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        String(input).includes("/source-image-gallery")
          ? new Response(JSON.stringify(gallery), {
              status: 200,
              headers: { "content-type": "application/json" },
            })
          : new Response(new Blob([new Uint8Array([1, 2, 3, 4])]), { status: 200 }),
      ),
    );
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => "blob:noise");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    const preview = { path: "C:/e/a.png", name: "a.png", preview_type: "image", size: 4, image: {} };
    const { container } = render(
      <ImageView runId="r1" preview={preview as never} onOpenPath={() => undefined} />,
    );
    await waitFor(() => expect(container.querySelectorAll("img")).toHaveLength(3));
    for (const img of container.querySelectorAll("img")) fireEvent.error(img);
    await waitFor(() => expect(screen.getAllByTestId("image-glyph")).toHaveLength(3));
    expect(container.querySelectorAll("img")).toHaveLength(0);
    expect(screen.getAllByText(THUMB_NO_PREVIEW_TEXT)).toHaveLength(3);
    // The glyph keeps the image's box (main image / strip thumbnail size) and its blur class.
    const main = container.querySelector(".image-figure [data-testid='image-glyph']");
    expect(main?.classList.contains("image-original")).toBe(true);
    const strip = screen.getByTestId("image-strip");
    for (const glyph of strip.querySelectorAll("[data-testid='image-glyph']")) {
      expect(glyph.classList.contains("image-thumb-img")).toBe(true);
    }
    const css = readFileSync(resolve(__dirname, "../viewer.css"), "utf8");
    expect(css).toMatch(/\.image-glyph \{[^}]*display: flex/);
  });
});
