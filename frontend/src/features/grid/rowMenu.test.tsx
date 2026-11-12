// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { act, cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DataGrid } from "./DataGrid";
import {
  filesHandler,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "./testSupport";

/** Row menu (plan r8 T-090, IS-026 / IS-102): eight runnable entries + 더 보기, 태그, placement. */

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", () => ({ announce: announceMock }));

let restoreLayout: () => void;

beforeEach(() => {
  resetGridStore();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));
const rowAt = (i: number) => rows().find((r) => r.getAttribute("data-index") === String(i)) as HTMLElement;

async function renderFiles(total = 600) {
  const calls = installFetch({
    "/files": filesHandler(total),
    "/case-db/ensure": () => jsonResponse({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" }),
    "/review-batch": () => jsonResponse({ ok: true }),
  });
  const view = renderWithClient(<DataGrid />);
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
  return { calls, ...view };
}

describe("row menu (T-090)", () => {
  it("Shift+F10 opens the row menu: eight runnable entries + 더 보기, none disabled; Esc closes it (T-090)", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "F10", shiftKey: true });
    const menu = await screen.findByRole("menu", { name: "행 메뉴" });
    expect(screen.getAllByRole("button", { name: "행 메뉴" })[0]?.getAttribute("aria-expanded")).toBe("true");
    const items = within(menu).getAllByRole("menuitem");
    const labels = items.map((i) => i.querySelector(".menu-item-label")?.textContent);
    // Review #13: right-aligned key hints from the registry.
    const keys = Object.fromEntries(
      items.map((i) => [
        i.querySelector(".menu-item-label")?.textContent,
        i.querySelector(".menu-item-kbd")?.textContent,
      ]),
    );
    expect(keys).toMatchObject({
      "원본 보기": "Enter",
      "관련 있음 표시": "R",
      "재검토 표시": "I",
      "제외 표시": "X",
    });
    expect(keys["보고서 포함 표시"]).toBeUndefined();
    expect(labels).toEqual([
      "원본 보기",
      "관련 있음 표시",
      "재검토 표시",
      "제외 표시",
      "태그…",
      "보고서 포함 표시",
      "타임라인 ±5분",
      "같은 출처 파일",
      "더 보기",
    ]);
    // IS-026: nothing listed that cannot run (no aria-disabled, no reason line).
    expect(menu.querySelector("[aria-disabled]")).toBeNull();
    expect(menu.querySelector(".menu-item-reason")).toBeNull();
    // 더 보기 reveals the rest (runnable only) below a separator and focuses the first of them.
    const more = within(menu).getByRole("menuitem", { name: "더 보기" });
    expect(more.getAttribute("aria-haspopup")).toBe("menu");
    fireEvent.click(more);
    expect(within(menu).queryByRole("menuitem", { name: "더 보기" })).toBeNull();
    const all = within(menu).getAllByRole("menuitem");
    const moreLabels = all
      .slice(items.length - 1)
      .map((i) => i.querySelector(".menu-item-label")?.textContent);
    expect(moreLabels).toEqual([
      "헥스로 보기",
      "경로 복사",
      "인용 복사",
      "타임라인에서 보기",
      "같은 출처 행",
      // 계열 (R7 갈래 A); 선택 행 OCR 실행 and the pivots this row lacks are not listed.
      "계열 보기",
      "상위 항목으로",
      "선택을 상위+하위 항목으로 확장",
      "북마크",
    ]);
    expect(document.activeElement).toBe(all[items.length - 1]);
    expect(menu.querySelector("[aria-disabled]")).toBeNull();
    fireEvent.keyDown(menu, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("row-menu 태그… tags the menu row through the tag prompt (T-090, U-05)", async () => {
    const { calls } = await renderFiles();
    rowAt(2).focus();
    fireEvent.mouseDown(rowAt(2), { button: 0 });
    fireEvent.keyDown(rowAt(2), { key: "F10", shiftKey: true });
    const menu = await screen.findByRole("menu", { name: "행 메뉴" });
    fireEvent.click(within(menu).getByRole("menuitem", { name: "태그…" }));
    expect(screen.queryByRole("menu")).toBeNull();
    const input = await screen.findByPlaceholderText("태그 이름");
    fireEvent.change(input, { target: { value: "증거" } });
    await act(async () => {
      fireEvent.submit(input.closest("form") as HTMLFormElement);
    });
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/review-batch"))).toBe(true));
    expect(calls.find((c) => c.url.endsWith("/review-batch"))?.body).toMatchObject({
      add_tags: ["증거"],
      targets: [{ collection: "files", locator: "/candidates/2" }],
    });
  });

  it("the row menu is portalled to <body> and kept inside a 1280×720 viewport for the bottom row (T-090)", async () => {
    await renderFiles();
    const width = window.innerWidth;
    const height = window.innerHeight;
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1280 });
    Object.defineProperty(window, "innerHeight", { configurable: true, value: 720 });
    try {
      const trigger = screen.getAllByRole("button", { name: "행 메뉴" })[0] as HTMLButtonElement;
      trigger.getBoundingClientRect = () =>
        ({
          top: 690,
          bottom: 712,
          left: 1260,
          right: 1280,
          width: 20,
          height: 22,
          x: 1260,
          y: 690,
        }) as DOMRect;
      const scrollDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollHeight");
      const widthDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetWidth");
      Object.defineProperty(HTMLElement.prototype, "scrollHeight", { configurable: true, get: () => 300 });
      Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => 240 });
      try {
        fireEvent.click(trigger);
        const menu = await screen.findByRole("menu", { name: "행 메뉴" });
        expect(menu.parentElement).toBe(document.body);
        expect(menu.dataset.placement).toBe("above");
        const top = Number.parseFloat(menu.style.top);
        const left = Number.parseFloat(menu.style.left);
        expect(top).toBeGreaterThanOrEqual(8);
        expect(top + 300).toBeLessThanOrEqual(690);
        expect(left + 240).toBeLessThanOrEqual(1280 - 8);
      } finally {
        if (scrollDesc) Object.defineProperty(HTMLElement.prototype, "scrollHeight", scrollDesc);
        if (widthDesc) Object.defineProperty(HTMLElement.prototype, "offsetWidth", widthDesc);
      }
    } finally {
      Object.defineProperty(window, "innerWidth", { configurable: true, value: width });
      Object.defineProperty(window, "innerHeight", { configurable: true, value: height });
    }
  });
});
