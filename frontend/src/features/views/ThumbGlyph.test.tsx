import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetCommandRegistry } from "../../commands/registry";
import { resetAppStore } from "../../state/store";
import { installFetch, jsonResponse, mockLayout, queryWrapper, resetGridStore } from "../grid/testSupport";
import { THUMB_NO_PREVIEW_TEXT, THUMB_WITHHELD_TEXT, ThumbUnavailableError, thumbGlyph } from "./ThumbGlyph";
import { loadThumbBlob, ThumbnailView } from "./ThumbnailView";

let restoreLayout: () => void = () => {};

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  resetGridStore();
  restoreLayout = mockLayout(800, 600);
});

afterEach(() => {
  cleanup();
  restoreLayout();
  resetCommandRegistry();
  vi.unstubAllGlobals();
});

function renderQ(ui: React.ReactElement) {
  const { wrapper } = queryWrapper();
  return render(ui, { wrapper });
}

describe("thumbnail no-preview glyph (r8 T-017)", () => {
  it("r8 T-017: 204 / 4xx / withheld answers draw the glyph with no fallback; 5xx still falls back", async () => {
    const credential = {
      detail: {
        code: "CREDENTIAL_FILE_WITHHELD",
        message:
          "자격 증명 파일 — 본문 미수집 (credential-name) — 원본 내려받기·미리보기를 제공하지 않습니다",
        credential_reason: "credential-name",
      },
    };
    const calls = installFetch({
      "/source-thumbnail": (url) => {
        const path = url.searchParams.get("path") ?? "";
        if (path.endsWith("broken.jpg"))
          return new Response(null, { status: 204, headers: { "X-RapidTriage-Thumbnail": "unavailable" } });
        if (path.endsWith("gone.jpg")) return jsonResponse({ detail: "not found" }, 404);
        if (path.endsWith("key.png")) return jsonResponse(credential, 403);
        return jsonResponse({ detail: "boom" }, 500);
      },
      "/source-file": () => new Response("original", { status: 200 }),
    });
    const signal = new AbortController().signal;
    for (const [path, withheld] of [
      ["C:/x/broken.jpg", false],
      ["C:/x/gone.jpg", false],
      ["C:/x/key.png", true],
    ] as const) {
      const error = await loadThumbBlob("run-1", path, signal).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ThumbUnavailableError);
      expect((error as ThumbUnavailableError).withheld).toBe(withheld);
      expect((error as Error).message).toBe(withheld ? THUMB_WITHHELD_TEXT : THUMB_NO_PREVIEW_TEXT);
    }
    expect(calls.filter((c) => c.url.includes("/source-file"))).toHaveLength(0);

    const fallback = await loadThumbBlob("run-1", "C:/x/server-error.jpg", signal);
    expect(await fallback.text()).toBe("original");
  });

  it("picks the format glyph by extension", () => {
    expect(thumbGlyph("C:/x/a.JPG")).toBe("image");
    expect(thumbGlyph("C:\\x\\clip.mp4")).toBe("film");
    expect(thumbGlyph("C:/x/report.pdf")).toBe("file-text");
    expect(thumbGlyph("C:/x/noext")).toBe("file-text");
  });
  it("r8 T-017: tiles without a preview draw a glyph + 미리보기 없음, never a blank square", async () => {
    installFetch({
      "/files": () =>
        jsonResponse({
          candidates: ["broken.jpg", "key.png", "bad-decode.png"].map((name) => ({
            path: `C:/case/${name}`,
            name,
          })),
          total: 3,
        }),
      "/source-thumbnail": (url) => {
        const path = url.searchParams.get("path") ?? "";
        if (path.endsWith("broken.jpg")) return new Response(null, { status: 204 });
        if (path.endsWith("key.png")) {
          return jsonResponse(
            { detail: { code: "CREDENTIAL_FILE_WITHHELD", message: "자격 증명 파일" } },
            403,
          );
        }
        return new Response("not-a-jpeg", { status: 200 });
      },
    });
    // jsdom has no object URLs: hand out one so the <img> mounts (and then fails to decode).
    const objectUrls = URL as unknown as Record<string, unknown>;
    const saved = { create: objectUrls.createObjectURL, revoke: objectUrls.revokeObjectURL };
    objectUrls.createObjectURL = () => "blob:x";
    objectUrls.revokeObjectURL = () => undefined;
    try {
      renderQ(<ThumbnailView />);
      const grid = await screen.findByRole("grid", { name: /이미지 3개/ });
      await waitFor(() => expect(grid.querySelectorAll("[data-testid=thumb-glyph]").length).toBe(2));
      const img = await waitFor(() => {
        const found = grid.querySelector("img.thumb-img");
        expect(found).toBeTruthy();
        return found as HTMLImageElement;
      });
      fireEvent.error(img);
      await waitFor(() => expect(grid.querySelectorAll("[data-testid=thumb-glyph]").length).toBe(3));
      expect(grid.querySelector("img")).toBeNull();
      const glyphs = Array.from(grid.querySelectorAll<HTMLElement>("[data-testid=thumb-glyph]"));
      for (const glyph of glyphs) {
        expect(glyph.textContent).toContain(THUMB_NO_PREVIEW_TEXT);
        expect(glyph.querySelector("svg")).toBeTruthy();
        expect(glyph.textContent).not.toMatch(/[A-Za-z]/);
      }
      const withheld = glyphs.filter((g) => g.dataset.withheld !== undefined);
      expect(withheld).toHaveLength(1);
      expect(withheld[0]?.textContent).toContain(THUMB_WITHHELD_TEXT);
    } finally {
      objectUrls.createObjectURL = saved.create;
      objectUrls.revokeObjectURL = saved.revoke;
    }
  });
});
