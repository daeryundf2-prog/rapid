import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MenuButton } from "./MenuButton";

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
