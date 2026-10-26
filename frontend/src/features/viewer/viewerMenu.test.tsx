import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LiveRegion } from "../../a11y";
import { resetAnnouncer } from "../../a11y/announcer";
import { resetViewerAdapter, setViewerTarget } from "./adapter";
import { clearCaseDbCache } from "./citation";
import { installFetch, metadata, preview, target } from "./testSupport";
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

async function showText() {
  installFetch({
    "source-preview": () => preview({ preview_type: "text", text: "hello" }),
    "source-metadata": (url) => metadata(url.searchParams.get("path") || "", 64),
    "source-hex-range": () => ({ offset: 0, rows: [], length_returned: 0, size: 64 }),
  });
  render(
    <>
      <Viewer />
      <LiveRegion />
    </>,
  );
  act(() => setViewerTarget(target({ sourcePath: "C:\\evidence\\Users\\alice\\notes.txt" })));
  await waitFor(() => expect(screen.getByTestId("live-polite").textContent).toContain("원본 로드됨"));
}

describe("viewer header (review #6)", () => {
  it("one ⋯ menu holds the 리뷰 and 원본 sections; no separate 더보기 / 원본 동작 triggers", async () => {
    await showText();
    const header = screen.getByRole("region", { name: "원본 뷰어" });
    expect(within(header).queryByRole("button", { name: "리뷰 더보기" })).toBeNull();
    expect(within(header).queryByRole("button", { name: "원본 동작" })).toBeNull();
    const triggers = within(header)
      .getAllByRole("button")
      .filter((b) => b.getAttribute("aria-haspopup") === "menu");
    // Two menus (r7 L4, C-W9): the one review-status chip ("미검토 ▾") and ⋯ 더보기.
    expect(triggers.map((b) => b.getAttribute("aria-label"))).toEqual(["리뷰 상태: 미검토", "더보기"]);
    fireEvent.click(screen.getByRole("button", { name: "더보기" }));
    const menu = screen.getByRole("menu", { name: "더보기" });
    // 같은 해시 행에 전파 (AXIOM E3): its own section, always on the viewer row.
    expect([...menu.querySelectorAll(".menu-heading")].map((h) => h.textContent)).toEqual([
      "리뷰",
      "태그 전파",
      "원본",
      "피벗",
    ]);
    expect(menu.querySelector("[data-command='review.tags.propagateByHash']")).not.toBeNull();
    const commands = [...menu.querySelectorAll<HTMLElement>("[data-command]")].map((i) => i.dataset.command);
    // 리뷰 first (marks, then 메모…), then 원본 (source actions, 같은 출처의 다른 행, 레코드 JSON),
    // then 피벗 (viewer redesign §5).
    expect(commands.indexOf("viewer.note")).toBeLessThan(commands.indexOf("viewer.open-original"));
    expect(commands.indexOf("navigate.rows-for-source")).toBeLessThan(
      commands.indexOf("viewer.copyRecordJson"),
    );
    expect(commands.indexOf("viewer.copyRecordJson")).toBeLessThan(
      commands.indexOf("viewer.pivot.same-user"),
    );
    expect(commands.at(-1)).toBe("viewer.pivot.source-artifact");
    // Every item keeps the 16px lead slot, so 메모… lines up with the status-dot items.
    for (const item of menu.querySelectorAll("[role^=menuitem]"))
      expect(item.querySelector(".menu-item-lead")).not.toBeNull();
  });

  it("shows the review status as a chip with text and the parent folder as the path line", async () => {
    await showText();
    const status = screen.getByTestId("viewer-review-status");
    expect(status.classList.contains("status-chip")).toBe(true);
    expect(status.textContent).toBe("미검토");
    const path = document.querySelector(".viewer-path .mid-path") as HTMLElement;
    expect(path.getAttribute("title")).toBe("C:\\evidence\\Users\\alice\\notes.txt");
    expect(path.textContent).toBe("C:\\evidence\\Users\\alice");
    expect(path.querySelector(".mid-path-tail")?.textContent).toBe("alice");
  });
});
