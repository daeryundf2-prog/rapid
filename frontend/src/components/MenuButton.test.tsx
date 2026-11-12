import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useRef } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useFocusTrap } from "../a11y/focus";
import { MenuButton } from "./MenuButton";
import { placePopover } from "./Popover";

afterEach(cleanup);

function renderMenu(onDisabled = vi.fn(), onCopy = vi.fn()) {
  render(
    <MenuButton
      label="원본 동작"
      onDisabled={onDisabled}
      items={[
        { id: "open", label: "원본 열기", command: "viewer.open-original", onSelect: vi.fn() },
        { id: "copy", label: "경로 복사", command: "viewer.copy-path", onSelect: onCopy },
        {
          id: "cite",
          label: "인용 복사",
          command: "viewer.cite",
          disabledReason: "뷰어에 표시된 행이 없습니다.",
          onSelect: vi.fn(),
        },
        {
          id: "mark",
          label: "북마크",
          checked: true,
          status: "bookmark",
          separator: true,
          onSelect: vi.fn(),
        },
      ]}
    >
      ⋯
    </MenuButton>,
  );
  return screen.getByRole("button", { name: "원본 동작" });
}

describe("MenuButton (visual-polish S5/S6)", () => {
  it("opens a labelled menu, focuses the first item and moves with arrows / Home / End", () => {
    const trigger = renderMenu();
    expect(trigger.getAttribute("aria-haspopup")).toBe("menu");
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(trigger);
    const menu = screen.getByRole("menu", { name: "원본 동작" });
    expect(trigger.getAttribute("aria-controls")).toBe(menu.id);
    const items = Array.from(document.querySelectorAll<HTMLElement>("[role^=menuitem]"));
    expect(document.activeElement).toBe(items[0]);
    fireEvent.keyDown(menu, { key: "ArrowDown" });
    expect(document.activeElement).toBe(items[1]);
    fireEvent.keyDown(menu, { key: "End" });
    expect(document.activeElement).toBe(items[3]);
    fireEvent.keyDown(menu, { key: "ArrowDown" });
    expect(document.activeElement).toBe(items[0]);
    fireEvent.keyDown(menu, { key: "Home" });
    expect(document.activeElement).toBe(items[0]);
  });

  it("toggle items are menuitemcheckbox with aria-checked", () => {
    fireEvent.click(renderMenu());
    const mark = screen.getByRole("menuitemcheckbox", { name: "북마크" });
    expect(mark.getAttribute("aria-checked")).toBe("true");
  });

  it("a disabled item stays listed with its reason and says it instead of running", () => {
    const onDisabled = vi.fn();
    fireEvent.click(renderMenu(onDisabled));
    const cite = screen.getByRole("menuitem", { name: "인용 복사" });
    expect(cite.getAttribute("aria-disabled")).toBe("true");
    expect(document.getElementById(cite.getAttribute("aria-describedby") ?? "")?.textContent).toBe(
      "뷰어에 표시된 행이 없습니다.",
    );
    fireEvent.click(cite);
    expect(onDisabled).toHaveBeenCalledWith("뷰어에 표시된 행이 없습니다.");
    expect(screen.getByRole("menu")).toBeTruthy(); // still open
  });

  it("an enabled item runs, closes the menu and returns focus to the trigger; Esc and Tab close too", () => {
    const onCopy = vi.fn();
    const trigger = renderMenu(vi.fn(), onCopy);
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("menuitem", { name: "경로 복사" }));
    expect(onCopy).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    fireEvent.click(trigger);
    fireEvent.keyDown(
      Array.from(document.querySelectorAll<HTMLElement>("[role^=menuitem]"))[0] as HTMLElement,
      { key: "Escape" },
    );
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    fireEvent.click(trigger);
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Tab" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});

describe("MenuButton portal + collision correction (plan r8 T-014)", () => {
  it("renders the menu in document.body, outside any clipping pane, and keeps focus return", () => {
    const pane = document.createElement("div");
    pane.style.overflow = "clip";
    document.body.appendChild(pane);
    render(
      <MenuButton
        label="더보기"
        testId="viewer-actions-menu"
        items={[{ id: "a", label: "원본 열기", onSelect: vi.fn() }]}
      >
        ⋯
      </MenuButton>,
      { container: pane },
    );
    const trigger = screen.getByTestId("viewer-actions-menu");
    fireEvent.click(trigger);
    const menu = document.getElementById(trigger.getAttribute("aria-controls") ?? "") as HTMLElement;
    expect(menu.getAttribute("aria-label")).toBe("더보기");
    expect(menu.parentElement).toBe(document.body);
    expect(pane.contains(menu)).toBe(false);
    expect(menu.classList.contains("popover-portal")).toBe(true);
    expect(menu.style.left).not.toBe("");
    expect(menu.dataset.placement).toBe("below");
    const item = menu.querySelector<HTMLElement>("[role=menuitem]") as HTMLElement;
    expect(document.activeElement).toBe(item);
    // A press on a portalled item counts as inside (the menu does not close under it).
    fireEvent.pointerDown(item);
    expect(screen.getByRole("menu")).toBeTruthy();
    fireEvent.keyDown(menu, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    pane.remove();
  });

  it("inside a focus trap (the narrow viewer drawer) the portalled menu keeps focus", () => {
    function Drawer() {
      const ref = useRef<HTMLElement>(null);
      useFocusTrap(ref, { active: true, returnFocus: false });
      return (
        <aside ref={ref}>
          <button type="button">닫기</button>
          <MenuButton label="더보기" testId="trap-menu" items={[{ id: "a", label: "A", onSelect: vi.fn() }]}>
            ⋯
          </MenuButton>
        </aside>
      );
    }
    render(<Drawer />);
    const trigger = screen.getByTestId("trap-menu");
    fireEvent.click(trigger);
    const menu = document.getElementById(trigger.getAttribute("aria-controls") ?? "") as HTMLElement;
    const item = menu.querySelector<HTMLElement>("[role=menuitem]") as HTMLElement;
    expect(document.activeElement).toBe(item);
    // An element outside both the drawer and its menu is still pulled back.
    const outside = document.createElement("button");
    document.body.appendChild(outside);
    outside.focus();
    expect(outside).not.toBe(document.activeElement);
    outside.remove();
  });

  // The viewer's ⋯ sits near the viewer pane's left edge; align="end" used to push the list
  // past that edge (first letters cut off). Placement shifts it back inside the viewport.
  const trigger = (left: number, top = 60) => ({ top, bottom: top + 28, left, right: left + 28 });
  const panel = { width: 240, height: 320 };
  for (const width of [880, 1280, 1920]) {
    it(`keeps an end-aligned menu inside a ${width}px viewport at either edge`, () => {
      const viewport = { width, height: 720 };
      for (const left of [0, 12, width / 2, width - 40]) {
        const place = placePopover(trigger(left), panel, viewport, "end");
        expect(place.left).toBeGreaterThanOrEqual(8);
        expect(place.left + panel.width).toBeLessThanOrEqual(width - 8);
      }
      // Room permitting, the end edge still lines up with the trigger.
      const mid = placePopover(trigger(width / 2), panel, viewport, "end");
      expect(mid.left).toBe(width / 2 + 28 - 240);
    });
  }

  it("flips a below menu above near the viewport bottom, and an above menu below near the top", () => {
    const viewport = { width: 880, height: 720 };
    const low = placePopover(trigger(400, 660), panel, viewport, "end");
    expect(low.above).toBe(true);
    expect(low.top + panel.height).toBeLessThanOrEqual(660);
    const high = placePopover(trigger(400, 20), panel, viewport, "end", "above");
    expect(high.above).toBe(false);
    expect(high.top).toBe(20 + 28 + 4);
    const roomy = placePopover(trigger(400, 500), panel, viewport, "end", "above");
    expect(roomy.above).toBe(true);
  });
});

describe("capped menu layout (r8 verify F1)", () => {
  it("menu rows never shrink below their content; the capped menu scrolls instead", () => {
    const css = readFileSync(resolve(__dirname, "popover.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    const menuRule = /\.popover\.menu \{([^}]*)\}/.exec(css)?.[1] ?? "";
    expect(menuRule).toMatch(/flex-direction: column/);
    expect(menuRule).toMatch(/overflow-y: auto/);
    const noShrink =
      /\.popover\.menu > \*,\s*\.popover\.menu \.menu-row > \* \{([^}]*)\}/.exec(css)?.[1] ?? "";
    expect(noShrink).toMatch(/flex: none/);
  });
});
