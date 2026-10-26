// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { act, cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useToastStore } from "../../components/toastStore";
import type { GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import { getRegisteredCommand, useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import { applyReviewAction } from "./reviewActions";
import {
  filesHandler,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "./testSupport";

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
  vi.useRealTimers();
});

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));
const rowAt = (i: number) => rows().find((r) => r.getAttribute("data-index") === String(i)) as HTMLElement;
const focusedRows = () => rows().filter((r) => r.tabIndex === 0);

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

function ctx(): CommandContext {
  const s = useGridLocalStore.getState();
  return {
    runId: "run-1",
    collection: "files",
    selectedRowKeys: [...s.selectedKeys],
    focusedRowKey: s.focusedRowKey,
    viewerHasTarget: s.target !== null,
    runIsActive: false,
  };
}

describe("DataGrid ARIA", () => {
  it("exposes grid/row/gridcell with total rowcount, rowindex, selected state and one tab stop", async () => {
    await renderFiles(600);
    const grid = screen.getByRole("grid");
    expect(grid.getAttribute("aria-rowcount")).toBe("601"); // total + header row
    expect(grid.getAttribute("aria-multiselectable")).toBe("true");
    expect(Number(grid.getAttribute("aria-colcount"))).toBeGreaterThan(2);
    expect(screen.getAllByRole("columnheader").length).toBeGreaterThan(2);
    const first = rowAt(0);
    expect(first.getAttribute("aria-rowindex")).toBe("2");
    expect(first.getAttribute("aria-selected")).toBe("false");
    expect(within(first).getAllByRole("gridcell").length).toBeGreaterThan(2);
    // Roving tabindex: exactly one row is tabbable.
    expect(focusedRows()).toHaveLength(1);
    expect(focusedRows()[0]).toBe(first);
  });

  it("announces one polite sentence through announce() and renders no live region of its own", async () => {
    const { container } = await renderFiles(600);
    await waitFor(() =>
      expect(announceMock).toHaveBeenCalledWith(expect.stringMatching(/^600건 · 파일 · \d+ms$/)),
    );
    expect(container.querySelector("[aria-live]")).toBeNull();
    expect(container.querySelector("[role=status]:not([aria-label])")).toBeNull();
  });

  it("header buttons set aria-sort and the footer says sorting uses the loaded rows", async () => {
    await renderFiles(600);
    const header = screen
      .getAllByRole("columnheader")
      .find((h) => h.textContent?.includes("크기")) as HTMLElement;
    expect(header.getAttribute("aria-sort")).toBe("none");
    fireEvent.click(within(header).getByRole("button"));
    expect(header.getAttribute("aria-sort")).toBe("ascending");
    expect(screen.getByText(/정렬은 불러온 [0-9]+행 기준/)).toBeTruthy();
    fireEvent.click(within(header).getByRole("button"));
    expect(header.getAttribute("aria-sort")).toBe("descending");
    // Descending size: file sizes grow with the index, so row titles count down.
    const n = (i: number) =>
      Number(/file-(\d+)/.exec(within(rowAt(i)).getAllByRole("gridcell")[1]?.textContent ?? "")?.[1]);
    expect(n(0)).toBeGreaterThan(n(1));
    expect(n(1)).toBeGreaterThan(n(2));
    fireEvent.click(within(header).getByRole("button"));
    expect(header.getAttribute("aria-sort")).toBe("none");
  });
});

describe("DataGrid keyboard", () => {
  it("J on the grid container (no row focused yet) moves the roving row and focuses it", async () => {
    await renderFiles();
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key: "j" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    expect(focusedRows()).toEqual([rowAt(1)]);
  });

  it("ArrowDown/ArrowUp and J/K move the focused row and the tab stop", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    expect(focusedRows()).toEqual([rowAt(1)]);
    fireEvent.keyDown(rowAt(1), { key: "j" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(2)));
    fireEvent.keyDown(rowAt(2), { key: "k" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    fireEvent.keyDown(rowAt(1), { key: "ArrowUp" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(0)));
    // Clamped at the top.
    fireEvent.keyDown(rowAt(0), { key: "ArrowUp" });
    expect(focusedRows()).toEqual([rowAt(0)]);
  });

  it("Home/End/PageDown jump; End loads the last server page", async () => {
    const { calls } = await renderFiles(600);
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "PageDown" });
    await waitFor(() =>
      expect(Number((document.activeElement as HTMLElement).dataset.index)).toBeGreaterThan(3),
    );
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "End" });
    await waitFor(() => expect((document.activeElement as HTMLElement).dataset.index).toBe("599"));
    expect(calls.some((c) => c.url.includes("offset=500"))).toBe(true);
    expect(rowAt(599).getAttribute("aria-rowindex")).toBe("601");
    fireEvent.keyDown(rowAt(599), { key: "Home" });
    await waitFor(() => expect((document.activeElement as HTMLElement).dataset.index).toBe("0"));
  });

  it("Space toggles selection of the focused row; Shift+Arrow extends a range", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    expect(rowAt(0).getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(rowAt(0), { key: " " });
    expect(rowAt(0).getAttribute("aria-selected")).toBe("false");
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    fireEvent.keyDown(rowAt(1), { key: "ArrowDown", shiftKey: true });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(2)));
    expect([0, 1, 2, 3].map((i) => rowAt(i).getAttribute("aria-selected"))).toEqual([
      "true",
      "true",
      "true",
      "false",
    ]);
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(3);
  });

  it("click focuses only; Ctrl-click toggles; Shift-click adds the range (R7)", async () => {
    await renderFiles();
    fireEvent.mouseDown(rowAt(2));
    // A plain click moves the focused row; it never checks or clears rows.
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(0);
    expect(rowAt(2).classList.contains("is-focused")).toBe(true);
    fireEvent.mouseDown(rowAt(2), { ctrlKey: true });
    fireEvent.mouseDown(rowAt(4), { ctrlKey: true });
    expect([...useGridLocalStore.getState().selectedKeys]).toEqual([
      "files:/candidates/2",
      "files:/candidates/4",
    ]);
    fireEvent.mouseDown(rowAt(6), { shiftKey: true });
    // Range from the anchor (row 4) to row 6 is added; row 2 stays checked.
    expect([...useGridLocalStore.getState().selectedKeys].sort()).toEqual([
      "files:/candidates/2",
      "files:/candidates/4",
      "files:/candidates/5",
      "files:/candidates/6",
    ]);
    fireEvent.mouseDown(rowAt(1));
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(4);
    rowAt(1).focus();
    fireEvent.keyDown(rowAt(1), { key: "Escape" });
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(0);
  });

  it("a ticked checkbox survives clicking another row and ticking another box (R7)", async () => {
    await renderFiles();
    const box = (i: number) =>
      rowAt(i).querySelector<HTMLInputElement>('input[type="checkbox"]') as HTMLInputElement;
    fireEvent.click(box(0));
    fireEvent.mouseDown(rowAt(2));
    fireEvent.click(rowAt(2));
    expect(box(0).checked).toBe(true);
    expect(rowAt(2).classList.contains("is-focused")).toBe(true);
    expect(box(2).checked).toBe(false);
    fireEvent.click(box(3));
    expect([...useGridLocalStore.getState().selectedKeys].sort()).toEqual([
      "files:/candidates/0",
      "files:/candidates/3",
    ]);
    expect(screen.getByTestId("grid-footer-selected").textContent).toBe("선택 2건");
    // Shift-click on a box extends from the last toggled box.
    fireEvent.click(box(5), { shiftKey: true });
    expect([...useGridLocalStore.getState().selectedKeys].sort()).toEqual([
      "files:/candidates/0",
      "files:/candidates/3",
      "files:/candidates/4",
      "files:/candidates/5",
    ]);
    // Esc from the focused checkbox clears the selection explicitly.
    box(5).focus();
    fireEvent.keyDown(box(5), { key: "Escape" });
    expect(useGridLocalStore.getState().selectedKeys.size).toBe(0);
    expect(screen.queryByTestId("grid-footer-selected")).toBeNull();
  });

  it("Enter publishes the ViewerTarget and requests viewer focus", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    fireEvent.keyDown(rowAt(1), { key: "Enter" });
    const s = useGridLocalStore.getState();
    expect(s.viewerFocusRequests).toBe(1);
    expect(s.target?.runId).toBe("run-1");
    expect(s.target?.ref).toEqual({ collection: "files", locator: "/candidates/1" });
    expect(s.target?.sourcePath).toBe("C:/evidence/dir1/file-1.txt");
  });

  it("keeps the viewer on the focused row after navigation", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "j" });
    await waitFor(() => expect(useGridLocalStore.getState().target?.ref.locator).toBe("/candidates/1"));
    expect(useGridLocalStore.getState().viewerFocusRequests).toBe(0);
  });

  it("J then an immediate mark applies to the NEW row (identity is published synchronously)", async () => {
    const { calls } = await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "j" });
    // No waiting: the viewer target and focused row are already the new row.
    const s = useGridLocalStore.getState();
    expect(s.target?.ref.locator).toBe("/candidates/1");
    expect(s.focusedRow?.rowKey).toBe("files:/candidates/1");
    await applyReviewAction("run-1", [s.focusedRow as GridRow], "relevant");
    const post = calls.find((c) => c.url.includes("/review-batch"));
    expect(post?.body).toMatchObject({
      run_id: "run-1",
      targets: [{ collection: "files", locator: "/candidates/1" }],
      status: "relevant",
    });
  });

  it("/ focuses the filter input (not while typing elsewhere)", async () => {
    await renderFiles();
    fireEvent.keyDown(document.body, { key: "/" });
    expect(document.activeElement).toBe(screen.getByPlaceholderText(/필터/));
  });

  it("Shift+F10 opens the row menu with the seven grid.* commands and the review items; Esc closes it", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "F10", shiftKey: true });
    const menu = await screen.findByRole("menu", { name: "행 메뉴" });
    expect(screen.getAllByRole("button", { name: "행 메뉴" })[0]?.getAttribute("aria-expanded")).toBe("true");
    const items = within(menu).getAllByRole("menuitem");
    const labels = items.map((i) => i.querySelector(".menu-item-label")?.textContent);
    // Review #13: right-aligned key hints from the registry, and a disabled item's reason line.
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
      북마크: "B",
    });
    expect(keys["보고서 포함 표시"]).toBeUndefined();
    const ocr = items.find((i) => i.dataset.command === "grid.ocrSelected");
    expect(ocr?.querySelector(".menu-item-reason")?.textContent).toBe(
      ocr?.getAttribute("data-disabled-reason"),
    );
    expect(labels).toEqual([
      "원본 보기",
      "헥스로 보기",
      "경로 복사",
      "인용 복사",
      "타임라인에서 보기",
      "같은 출처 행",
      "선택 행 OCR 실행",
      // Record pivots (viewer redesign §5), each disabled with a reason when the row lacks the field.
      "같은 사용자/SID",
      "같은 로그온 ID",
      "같은 해시",
      "같은 대상 경로/실행 파일",
      "같은 레지스트리 키",
      "같은 출처 파일",
      "타임라인 ±5분",
      "탐지 → 원 이벤트 열기",
      "원본 아티팩트 열기",
      "관련 있음 표시",
      "재검토 표시",
      "제외 표시",
      "보고서 포함 표시",
      "북마크",
    ]);
    // Review items are always listed and enabled for a row with a run-output locator.
    const relevant = within(menu).getByRole("menuitem", { name: "관련 있음 표시" });
    expect(relevant.getAttribute("aria-disabled")).toBeNull();
    fireEvent.keyDown(menu, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("grid.css never hides the ⋯ row-menu button from hit-testing (transparent until hover/focus)", () => {
    const gridCss = readFileSync(join(process.cwd(), "src/features/grid/grid.css"), "utf8");
    const rules = [...gridCss.matchAll(/([^{}]*\.grid-rowmenu-btn[^{}]*)\{([^}]*)\}/g)];
    expect(rules.length).toBeGreaterThan(0);
    for (const [, , body] of rules) {
      expect(body).not.toMatch(/visibility\s*:\s*hidden|display\s*:\s*none|pointer-events\s*:\s*none/);
    }
    // Review #9: opacity 0 at rest, back to 1 on row hover / focus (always hit-testable, 20×20).
    const shown = rules.find(([, selector]) => /\.grid-row:hover \.grid-rowmenu-btn/.test(selector ?? ""));
    expect(shown?.[2]).toMatch(/opacity:\s*1/);
    expect(shown?.[1]).toMatch(/:focus-within/);
  });

  it("a row-menu review item marks the menu's row (case-DB review-batch)", async () => {
    const { calls } = await renderFiles();
    rowAt(2).focus();
    fireEvent.mouseDown(rowAt(2), { button: 0 });
    fireEvent.keyDown(rowAt(2), { key: "F10", shiftKey: true });
    const menu = await screen.findByRole("menu", { name: "행 메뉴" });
    fireEvent.click(within(menu).getByRole("menuitem", { name: "관련 있음 표시" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/review-batch"))).toBe(true));
    const batch = calls.find((c) => c.url.endsWith("/review-batch"));
    expect(batch?.body).toMatchObject({
      status: "relevant",
      targets: [{ collection: "files", locator: "/candidates/2" }],
    });
  });

  it("the ⋯ row-menu button is a real, always-rendered button that opens the menu on click", async () => {
    await renderFiles();
    const buttons = screen.getAllByRole("button", { name: "행 메뉴" });
    expect(buttons.length).toBe(rows().length);
    const button = buttons[1] as HTMLButtonElement;
    // Never hidden from hit-testing: no hidden/display toggles on the control itself.
    expect(button.hidden).toBe(false);
    expect(button.style.visibility).toBe("");
    expect(button.style.display).toBe("");
    expect(button.getAttribute("aria-haspopup")).toBe("menu");
    expect(button.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(button);
    const menu = await screen.findByRole("menu", { name: "행 메뉴" });
    // 7 row actions + 9 pivots + 5 review marks (+ contextual entries that apply).
    expect(within(menu).getAllByRole("menuitem")).toHaveLength(21);
    const trigger = screen.getAllByRole("button", { name: "행 메뉴" })[1] as HTMLButtonElement;
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    expect(trigger.getAttribute("aria-controls")).toBe(menu.id);
    expect(document.activeElement).toBe(within(menu).getAllByRole("menuitem")[0]);
    // The same trigger toggles it closed again.
    fireEvent.mouseDown(trigger);
    expect(screen.queryByRole("menu")).not.toBeNull();
    expect(trigger.isConnected).toBe(true);
    fireEvent.click(trigger);
    expect(screen.queryByRole("menu")).toBeNull();
    expect(screen.getAllByRole("button", { name: "행 메뉴" })[1]?.getAttribute("aria-expanded")).toBe(
      "false",
    );
    fireEvent.click(screen.getAllByRole("button", { name: "행 메뉴" })[1] as HTMLButtonElement);
    const reopened = await screen.findByRole("menu", { name: "행 메뉴" });
    expect(useGridLocalStore.getState().focusedRow?.rowKey).toBe("files:/candidates/1");
    fireEvent.keyDown(reopened, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

describe("DataGrid filter", () => {
  it("filters the loaded rows client-side and says so in the footer", async () => {
    await renderFiles(600);
    const input = screen.getByPlaceholderText(/필터/);
    fireEvent.change(input, { target: { value: "file-12" } });
    await waitFor(() => expect(screen.getByText(/서버 필터 미지원/)).toBeTruthy());
    // file-12, file-120..129 (all in the first page of 250) = 11 rows.
    await waitFor(() => expect(rows().length).toBe(11));
    expect(screen.getByText(/불러온 [0-9]+행에서만/)).toBeTruthy();
    fireEvent.change(input, { target: { value: "" } });
    await waitFor(() => expect(screen.queryByText(/서버 필터 미지원/)).toBeNull());
  });

  it("shows an empty message when nothing matches", async () => {
    await renderFiles(50);
    fireEvent.change(screen.getByPlaceholderText(/필터/), { target: { value: "zzzz-no-match" } });
    // The empty state names the filter text (R7 L3, C-D16).
    await waitFor(() => expect(screen.getByText(/'zzzz-no-match'에 맞는 행이 없습니다/)).toBeTruthy());
  });
});

describe("grid chrome (visual-polish S3 / §0)", () => {
  it("column controls are one 열 설정 overflow at the end of the 조건 줄, outside the ARIA grid", async () => {
    await renderFiles(20);
    const button = screen.getByRole("button", { name: "열 설정" });
    expect(button.closest('[role="grid"]')).toBeNull();
    expect(button.closest("search.filter-bar")).toBeTruthy();
    // No separate column toolbar row any more.
    expect(screen.queryByRole("toolbar", { name: /그리드 도구/ })).toBeNull();
    button.focus();
    fireEvent.click(button);
    const popover = screen.getByRole("dialog", { name: "열 설정" });
    // 열 구성 / 밀도 live in the 조건 panel (viewer-families U-F1).
    expect(within(popover).queryByRole("combobox", { name: "열 구성" })).toBeNull();
    expect(within(popover).getByRole("group", { name: "표시할 열" })).toBeTruthy();
    expect(within(popover).getByTestId("grid-colfilter-toggle")).toBeTruthy();
    expect(document.activeElement).toBe(within(popover).getByTestId("grid-colfilter-toggle"));
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "열 설정" })).toBeNull();
    expect(document.activeElement).toBe(button);
    // 밀도 in the 조건 panel; a non-default density shows as a chip with ×.
    fireEvent.click(screen.getByRole("button", { name: /^조건/ }));
    const panel = screen.getByRole("dialog", { name: "조건" });
    fireEvent.change(within(panel).getByRole("combobox", { name: "밀도" }), { target: { value: "compact" } });
    expect(screen.getByRole("region", { name: /그리드$/ }).getAttribute("data-density")).toBe("compact");
    fireEvent.click(screen.getByRole("button", { name: "밀도 촘촘하게 기본값으로 되돌리기" }));
    expect(screen.getByRole("region", { name: /그리드$/ }).getAttribute("data-density")).toBe("default");
  });

  it("the batch bar floats over the grid: selecting does not insert a row above the grid", async () => {
    await renderFiles(20);
    const grid = screen.getByRole("grid");
    const before = grid.previousElementSibling;
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    // One row: the viewer and the row menu serve it, no bar (review #2).
    expect(screen.queryByRole("toolbar", { name: "선택 항목 일괄 처리" })).toBeNull();
    expect(screen.getByRole("region", { name: /그리드$/ }).hasAttribute("data-batch")).toBe(false);
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    const bar = screen.getByRole("toolbar", { name: "선택 항목 일괄 처리" });
    // Rendered after the scroll area inside the grid frame (absolutely positioned), never above it.
    expect(grid.previousElementSibling).toBe(before);
    expect(bar.parentElement?.classList.contains("grid-frame")).toBe(true);
    expect(grid.compareDocumentPosition(bar) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByRole("region", { name: /그리드$/ }).hasAttribute("data-batch")).toBe(true);
    // 관련 있음 is the one primary review action; the rest are ghost buttons.
    expect(within(bar).getByRole("button", { name: "관련 있음" }).classList.contains("primary")).toBe(true);
    expect(within(bar).getByRole("button", { name: "제외" }).classList.contains("ghost")).toBe(true);
  });

  it("the row menu trigger is an icon button (no text glyph)", async () => {
    await renderFiles(5);
    const trigger = within(rowAt(0)).getByRole("button", { name: "행 메뉴" });
    expect(trigger.textContent).toBe("");
    expect(trigger.querySelector("svg[data-icon='more']")).toBeTruthy();
  });
});

describe("DataGrid batch commands", () => {
  it("hides the batch bar with 0 selection and every grid.batch.* command is disabled with a reason", async () => {
    await renderFiles();
    expect(screen.queryByRole("toolbar", { name: "선택 항목 일괄 처리" })).toBeNull();
    for (const action of [
      "relevant",
      "needs-review",
      "excluded",
      "include-in-report",
      "bookmark",
      "tag",
      "extract",
    ]) {
      const command = getRegisteredCommand(`grid.batch.${action}`);
      expect(command, action).toBeDefined();
      expect(command?.disabledReason?.(ctx())).toBe("선택된 행이 없습니다.");
    }
  });

  it("with a selection the bar appears; 관련 posts one case-DB review-batch and updates optimistically", async () => {
    const { calls } = await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    const bar = screen.getByRole("toolbar", { name: "선택 항목 일괄 처리" });
    expect(within(bar).getByText("선택 2건")).toBeTruthy();
    expect(getRegisteredCommand("grid.batch.relevant")?.disabledReason?.(ctx())).toBeUndefined();
    fireEvent.click(within(bar).getByRole("button", { name: "관련 있음" }));
    await waitFor(() => expect(calls.filter((c) => c.url.includes("/review-batch"))).toHaveLength(1));
    expect(calls.find((c) => c.url.includes("/review-batch"))?.body).toMatchObject({
      status: "relevant",
      targets: [
        { collection: "files", locator: "/candidates/0" },
        { collection: "files", locator: "/candidates/1" },
      ],
    });
    // Grid feedback goes to the shell toast stack (U-V7).
    await waitFor(() =>
      expect(useToastStore.getState().toasts.some((t) => /관련: 2건 처리했습니다/.test(t.text))).toBe(true),
    );
    expect(within(rowAt(0)).getByText("관련 있음")).toBeTruthy();
  });

  it("rolls the optimistic mark back and shows a Korean error toast when the API fails", async () => {
    installFetch({
      "/files": filesHandler(50),
      "/case-db/ensure": () => jsonResponse({ database: "D:/out/rapidtriage-case.db", case_id: "run-out" }),
      "/review-batch": () => jsonResponse({ detail: "case locked" }, 500),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    // Review column is not part of the files preset, so inspect the loaded row model through the toast path.
    fireEvent.click(screen.getByRole("button", { name: "제외" }));
    // Grid feedback goes to the shell toast stack (U-V7).
    await waitFor(() =>
      expect(
        useToastStore.getState().toasts.some((t) => /제외 처리에 실패했습니다\. case locked/.test(t.text)),
      ).toBe(true),
    );
    expect(useGridLocalStore.getState().toasts.some((t) => t.tone === "error")).toBe(true);
  });

  it("추출 is disabled (aria-disabled + reason) when the rows have no source path and clicking explains why", async () => {
    installFetch({
      "/docs": () => jsonResponse({ results: [{ kind: "pdf" }, { kind: "pdf" }], total: 2 }),
    });
    useGridLocalStore.getState().setRoute({ collection: { id: "docs" } });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(2));
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    const extract = screen.getByRole("button", { name: "추출" });
    expect(extract.getAttribute("aria-disabled")).toBe("true");
    expect(extract.getAttribute("title")).toBe("원본 경로가 없는 행입니다.");
    fireEvent.click(extract);
    expect(useGridLocalStore.getState().toasts.at(-1)?.message).toBe("원본 경로가 없는 행입니다.");
  });

  it("추출 shows the manifest summary with a ZIP download button", async () => {
    const calls = installFetch({
      "/files": filesHandler(5),
      "/extract/extract-1/file": () => new Response("zip", { status: 200 }),
      "/extract": () =>
        jsonResponse({
          summary: { input_count: 1, selected_count: 1, extracted_count: 1, skipped_count: 1 },
          entries: [],
          skipped: [{ original_path: "C:/x", reason: "missing" }],
          name: "extract-1",
          download_url: "/api/runs/run-1/extract/extract-1/file",
        }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(5));
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    fireEvent.click(screen.getByRole("button", { name: "추출" }));
    const panel = await screen.findByRole("status", { name: "추출 결과" });
    expect(panel.textContent).toContain("추출 1건 / 선택 1건");
    expect(panel.textContent).toContain("건너뜀 1건");
    expect(within(panel).getByRole("button", { name: "ZIP 내려받기" })).toBeTruthy();
    expect(calls.some((c) => c.url === "/api/runs/run-1/extract" && c.method === "POST")).toBe(true);
  });

  it("태그 opens a prompt and applies the typed tag to the selection", async () => {
    const { calls } = await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    fireEvent.click(screen.getByRole("button", { name: "태그" }));
    const input = await screen.findByPlaceholderText("태그 이름");
    fireEvent.change(input, { target: { value: "증거" } });
    await act(async () => {
      fireEvent.submit(input.closest("form") as HTMLFormElement);
    });
    await waitFor(() => expect(calls.some((c) => c.url.includes("/review-batch"))).toBe(true));
    expect(calls.find((c) => c.url.includes("/review-batch"))?.body).toMatchObject({ add_tags: ["증거"] });
  });
});

describe("DataGrid notes and AXIOM preset", () => {
  afterEach(() => window.localStorage.removeItem("rapidtriage.grid.preset"));

  it("메모 appears for a multi-selection and saves one note on every selected row", async () => {
    const { calls } = await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    const bar = screen.getByRole("toolbar", { name: "선택 항목 일괄 처리" });
    fireEvent.click(within(bar).getByRole("button", { name: "메모" }));
    const note = await screen.findByPlaceholderText("선택한 2건에 같은 메모를 저장");
    fireEvent.change(note, { target: { value: "동일 사용자 활동" } });
    await act(async () => {
      fireEvent.submit(note.closest("form") as HTMLFormElement);
    });
    await waitFor(() => expect(calls.filter((c) => c.url.includes("/review-batch"))).toHaveLength(1));
    expect(calls.find((c) => c.url.includes("/review-batch"))?.body).toMatchObject({
      note: "동일 사용자 활동",
      targets: [
        { collection: "files", locator: "/candidates/0" },
        { collection: "files", locator: "/candidates/1" },
      ],
    });
    // Grid feedback goes to the shell toast stack (U-V7).
    await waitFor(() =>
      expect(useToastStore.getState().toasts.some((t) => /메모: 2건에 저장했습니다/.test(t.text))).toBe(true),
    );
  });

  it("the persisted AXIOM preset pins the chip column after the select cell and renders status chips", async () => {
    window.localStorage.setItem("rapidtriage.grid.preset", "axiom");
    await renderFiles(20);
    fireEvent.click(screen.getByRole("button", { name: /^조건/ }));
    expect((screen.getByRole("combobox", { name: "열 구성" }) as HTMLSelectElement).value).toBe("axiom");
    // A non-default preset is an applied condition: a chip on the 조건 줄.
    expect(screen.getByRole("button", { name: "열 구성 AXIOM 스타일 기본값으로 되돌리기" })).toBeTruthy();
    expect(screen.getByRole("region", { name: /그리드$/ }).getAttribute("data-preset")).toBe("axiom");
    const headers = screen.getAllByRole("columnheader");
    expect(headers[1]?.textContent).toContain("태그·상태");
    expect(headers[2]?.textContent).toContain("이름");
    const chipCell = rowAt(0).querySelector<HTMLElement>('[data-col="tagstatus"]');
    const titleCell = rowAt(0).querySelector<HTMLElement>('[data-col="title"]');
    expect(chipCell?.classList.contains("grid-cell-first")).toBe(true);
    expect(chipCell?.style.left).toBe("56px");
    expect(titleCell?.classList.contains("grid-cell-first")).toBe(true);
    expect(titleCell?.style.left).toBe("206px");

    // Two rows: the batch bar is for multi-selections (review #2).
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: " " });
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown", shiftKey: true });
    fireEvent.click(screen.getByRole("button", { name: "관련 있음" }));
    await waitFor(() =>
      expect(
        rowAt(0).querySelector('[data-col="tagstatus"] .status-chip[data-status="relevant"]'),
      ).not.toBeNull(),
    );
  });
});

describe("DataGrid row commands", () => {
  it("grid.* row commands report a reason when no row is focused", async () => {
    installFetch({ "/files": filesHandler(0) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(screen.getByRole("grid")).toBeTruthy());
    for (const id of [
      "grid.openSource",
      "grid.openHex",
      "grid.copyPath",
      "grid.copyCitation",
      "grid.showInTimeline",
      "grid.sameSource",
    ]) {
      expect(getRegisteredCommand(id)?.disabledReason?.(ctx()), id).toBe("행을 먼저 선택하세요.");
    }
  });

  it("같은 출처 행 sets the filter to the row path; 헥스로 보기 publishes preferredMode hex", async () => {
    await renderFiles();
    rowAt(0).focus();
    fireEvent.keyDown(rowAt(0), { key: "ArrowDown" });
    await waitFor(() => expect(document.activeElement).toBe(rowAt(1)));
    await act(async () => {
      await getRegisteredCommand("grid.openHex")?.run(ctx());
    });
    expect(useGridLocalStore.getState().target?.preferredMode).toBe("hex");
    await act(async () => {
      await getRegisteredCommand("grid.sameSource")?.run(ctx());
    });
    expect(useGridLocalStore.getState().route.q).toBe("C:/evidence/dir1/file-1.txt");
  });
});

describe("DataGrid scale", () => {
  it("renders a 281,595-row collection from the first page only and virtualizes the rows", async () => {
    const calls = installFetch({ "/files": filesHandler(281595) });
    const started = performance.now();
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    const elapsed = performance.now() - started;
    expect(screen.getByRole("grid").getAttribute("aria-rowcount")).toBe("281596");
    // Virtualized: only the viewport window (+ overscan) is in the DOM.
    expect(rows().length).toBeLessThan(80);
    // First page plus the single prefetched next page, nothing else.
    await waitFor(() => expect(calls.length).toBeGreaterThanOrEqual(1));
    expect(calls.length).toBeLessThanOrEqual(2);
    expect(calls.every((c) => /offset=(0|250)&limit=250/.test(c.url))).toBe(true);
    // Wall-clock guard only catches gross regressions (e.g. rendering every row); the row and page
    // counts above are the real contract. 1 s flaked under a loaded parallel vitest run.
    expect(elapsed).toBeLessThan(3000);
    await waitFor(() => expect(screen.getByText(/페이지 1\/1,127/)).toBeTruthy());
    expect(screen.getByText(/총 281,595건/)).toBeTruthy();
  });
});
