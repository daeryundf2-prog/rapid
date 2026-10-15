// Real-data QA round 2 (viewer): mode tabs fit a 1280px layout with 메타 always in view, and a
// failed source-metadata request never leaves the hex fallback on an endless "확인하는 중".

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveRegion } from "../../a11y";
import { resetAnnouncer } from "../../a11y/announcer";
import { resetViewerAdapter, setViewerTarget } from "./adapter";
import { clearCaseDbCache } from "./citation";
import { installFetch, jsonResponse, target } from "./testSupport";
import { Viewer } from "./Viewer";

beforeEach(() => {
  resetAnnouncer();
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
  resetViewerAdapter();
  clearCaseDbCache();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("1. viewer mode tabs at 1280px", () => {
  const css = readFileSync(join(process.cwd(), "src/features/viewer/viewer.css"), "utf8");

  it("uses compact tab padding and no strip gap (8 tabs fit the ~424px pane)", () => {
    expect(css).toMatch(/\.viewer-tabs \{[^}]*gap: 0;[^}]*padding: 0 var\(--space-1\);/);
    expect(css).toMatch(/\.viewer-tab \{[^}]*padding: 0 var\(--space-2\);/);
  });

  it("keeps 메타 (provenance) stuck in view when a narrower strip scrolls", () => {
    expect(css).toMatch(
      /\.viewer-tabs > \[data-mode="meta"\],\s*\.viewer-tabs > :has\(> \[data-mode="meta"\]\) \{[^}]*position: sticky;[^}]*right: 0;[^}]*background: var\(--bg-panel\);/,
    );
  });
});

describe("11. a failed source-metadata request shows its error", () => {
  it("hex fallback: preview and metadata both 404 → the server messages, not 파일 크기를 확인하는 중…", async () => {
    installFetch({
      "source-preview": () => jsonResponse({ detail: "원본 파일이 없습니다" }, 404),
      "source-metadata": () => jsonResponse({ detail: "스냅샷 경로를 찾을 수 없습니다" }, 404),
    });
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() =>
      setViewerTarget(
        target({
          ref: { collection: "analysis", kind: "c1", locator: "/rows/3" },
          sourcePath: "C:/ev/HarddiskVolumeShadowCopy1/Users/kim/plan.xlsx",
        }),
      ),
    );
    const error = await screen.findByTestId("viewer-hex-error");
    expect(error.textContent).toContain("원본 파일이 없습니다");
    expect(error.textContent).toContain("스냅샷 경로를 찾을 수 없습니다");
    await waitFor(() => expect(document.body.textContent).not.toContain("파일 크기를 확인하는 중"));
  });
});
