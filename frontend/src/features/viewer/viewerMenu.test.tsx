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
  it("one ⋯ menu lists eight entries; 복사… / 고급… / 피벗… hold the rest", async () => {
    await showText();
    const header = screen.getByRole("region", { name: "원본 뷰어" });
    expect(within(header).queryByRole("button", { name: "리뷰 더보기" })).toBeNull();
    expect(within(header).queryByRole("button", { name: "원본 동작" })).toBeNull();
    const triggers = within(header)
      .getAllByRole("button")
      .filter((b) => b.getAttribute("aria-haspopup") === "menu");
    expect(triggers).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "더보기" }));
    const menu = () => screen.getByRole("menu", { name: "더보기" });
    const commands = () =>
      [...menu().querySelectorAll<HTMLElement>("[data-command]")].map((i) => i.dataset.command);
    const headings = () => [...menu().querySelectorAll(".menu-heading")].map((h) => h.textContent);
    const open = (command: string) =>
      fireEvent.click(menu().querySelector(`[data-command='${command}']`) as HTMLElement);

    expect(headings()).toEqual(["리뷰", "원본"]);
    expect(commands()).toEqual([
      "viewer.mark.needs-review",
      "viewer.mark.excluded",
      "viewer.mark.include-in-report",
      "viewer.mark.bookmark",
      "viewer.note",
      "viewer.open-original",
      "viewer.menu.copy",
      "viewer.menu.advanced",
    ]);
    // Every item keeps the 16px lead slot, so 메모… lines up with the status-dot items.
    for (const item of menu().querySelectorAll("[role^=menuitem]"))
      expect(item.querySelector(".menu-item-lead")).not.toBeNull();

    open("viewer.menu.copy");
    expect(commands()).toEqual([
      "viewer.menu.back",
      "viewer.hash",
      "viewer.copy-path",
      "viewer.cite",
      "viewer.copyRecordJson",
    ]);
    open("viewer.menu.back");
    expect(commands()).toHaveLength(8);

    open("viewer.menu.advanced");
    // 같은 해시 행에 전파 (AXIOM E3): its own section, always on the viewer row.
    expect(headings()).toEqual(["고급", "리뷰 도구", "같은 해시 행에 전파"]);
    expect(menu().querySelector("[data-command='review.tags.propagateByHash']")).not.toBeNull();
    expect(commands().slice(0, 3)).toEqual([
      "viewer.menu.back",
      "navigate.rows-for-source",
      "viewer.menu.pivot",
    ]);

    open("viewer.menu.pivot");
    expect(commands()).toEqual([
      "viewer.menu.back",
      "viewer.pivot.same-user",
      "viewer.pivot.same-logon",
      "viewer.pivot.same-hash",
      "viewer.pivot.same-target",
      "viewer.pivot.same-key",
      "viewer.pivot.same-source",
      "viewer.pivot.timeline-window",
      "viewer.pivot.matched-event",
      "viewer.pivot.source-artifact",
    ]);
    // 뒤로 from 피벗 returns to 고급, not to the first level.
    open("viewer.menu.back");
    expect(commands()).toContain("viewer.menu.pivot");
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
