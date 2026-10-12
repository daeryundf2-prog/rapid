// biome-ignore-all lint/a11y: test fixtures intentionally build minimal roving/listbox/dialog widgets
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useRef, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ANNOUNCE_HOLD_MS, announce, resetAnnouncer } from "./announcer";
import { useEscape, useFocusTrap, useRestoreFocus } from "./focus";
import { DisabledReason, LiveRegion, SkipLink } from "./primitives";
import { type RovingOptions, useRovingTabindex } from "./useRovingTabindex";

afterEach(() => {
  cleanup();
  resetAnnouncer();
  vi.useRealTimers();
});

const LABELS = ["Alpha", "Beta", "Bravo", "Charlie", "Delta"];

function List(props: Partial<RovingOptions> & { count?: number }) {
  const ref = useRef<HTMLUListElement>(null);
  const { count = LABELS.length, ...rest } = props;
  const r = useRovingTabindex(ref, { orientation: "vertical", itemSelector: "[role=option]", ...rest });
  return (
    <ul ref={ref} role="listbox" {...r.containerProps}>
      {Array.from({ length: count }, (_, i) => (
        <li key={LABELS[i] ?? i} role="option" aria-selected={false} {...r.getItemProps(i)}>
          {LABELS[i] ?? `Item${i}`}
        </li>
      ))}
    </ul>
  );
}

const opts = () => screen.getAllByRole("option");
const press = (key: string, el: Element = document.activeElement as Element) =>
  fireEvent.keyDown(el, { key });

describe("useRovingTabindex", () => {
  it("gives exactly one tab stop", () => {
    render(<List />);
    expect(opts().map((o) => o.tabIndex)).toEqual([0, -1, -1, -1, -1]);
  });

  it("ArrowDown/ArrowUp move focus and the tab stop, clamped without loop", () => {
    render(<List />);
    opts()[0]?.focus();
    press("ArrowDown");
    expect(document.activeElement).toBe(opts()[1]);
    expect(opts().map((o) => o.tabIndex)).toEqual([-1, 0, -1, -1, -1]);
    press("ArrowUp");
    press("ArrowUp");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("wraps with loop", () => {
    render(<List loop />);
    opts()[0]?.focus();
    press("ArrowUp");
    expect(document.activeElement).toBe(opts()[4]);
    press("ArrowDown");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("horizontal orientation uses Left/Right and ignores Up/Down", () => {
    render(<List orientation="horizontal" />);
    opts()[0]?.focus();
    press("ArrowDown");
    expect(document.activeElement).toBe(opts()[0]);
    press("ArrowRight");
    expect(document.activeElement).toBe(opts()[1]);
    press("ArrowLeft");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("vertical orientation ignores Left/Right", () => {
    render(<List />);
    opts()[0]?.focus();
    press("ArrowRight");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("both orientation accepts all four arrows", () => {
    render(<List orientation="both" />);
    opts()[0]?.focus();
    press("ArrowRight");
    press("ArrowDown");
    expect(document.activeElement).toBe(opts()[2]);
    press("ArrowLeft");
    press("ArrowUp");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("Home/End jump to the ends", () => {
    render(<List />);
    opts()[2]?.focus();
    press("End");
    expect(document.activeElement).toBe(opts()[4]);
    press("Home");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("PageDown/PageUp move by pageSize and clamp", () => {
    render(<List pageSize={2} />);
    opts()[0]?.focus();
    press("PageDown");
    expect(document.activeElement).toBe(opts()[2]);
    press("PageDown");
    press("PageDown");
    expect(document.activeElement).toBe(opts()[4]);
    press("PageUp");
    expect(document.activeElement).toBe(opts()[2]);
    press("PageUp");
    press("PageUp");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("type-ahead jumps to the next matching label and cycles on repeats", () => {
    render(<List typeAhead />);
    opts()[0]?.focus();
    press("c");
    expect(document.activeElement).toBe(opts()[3]);
    press("d");
    expect(document.activeElement).toBe(opts()[3]); // "cd" has no match; stays
  });

  it("type-ahead repeated letter cycles through matches (Beta, Bravo)", () => {
    render(<List typeAhead />);
    opts()[0]?.focus();
    const t = (key: string, timeStamp: number) =>
      fireEvent.keyDown(document.activeElement as Element, { key, timeStamp });
    t("b", 1000);
    expect(document.activeElement).toBe(opts()[1]);
    t("b", 1100);
    expect(document.activeElement).toBe(opts()[2]);
    t("r", 5000); // buffer reset -> "r": no match, focus unchanged
    expect(document.activeElement).toBe(opts()[2]);
  });

  it("does nothing for typed characters when typeAhead is off", () => {
    render(<List />);
    opts()[0]?.focus();
    press("c");
    expect(document.activeElement).toBe(opts()[0]);
  });

  it("focusing an item with the mouse moves the tab stop", () => {
    render(<List />);
    act(() => opts()[3]?.focus());
    expect(opts().map((o) => o.tabIndex)).toEqual([-1, -1, -1, 0, -1]);
  });

  it("leaves keys alone inside nested text inputs", () => {
    function Row() {
      const ref = useRef<HTMLDivElement>(null);
      const r = useRovingTabindex(ref, { orientation: "vertical", itemSelector: "[role=row]" });
      return (
        <div ref={ref} {...r.containerProps}>
          <div role="row" {...r.getItemProps(0)}>
            <input aria-label="cell" />
          </div>
          <div role="row" {...r.getItemProps(1)}>
            two
          </div>
        </div>
      );
    }
    render(<Row />);
    const input = screen.getByLabelText("cell");
    input.focus();
    press("ArrowDown", input);
    expect(document.activeElement).toBe(input);
  });
});

function Dialog({ initial }: { initial?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const second = useRef<HTMLButtonElement>(null);
  useFocusTrap(ref, { active: open, initialFocus: initial ? second : undefined });
  useEscape(() => setOpen(false), open);
  return (
    <div>
      <button type="button" onClick={() => setOpen(true)}>
        open
      </button>
      <button type="button">outside</button>
      {open && (
        <div ref={ref} role="dialog" aria-label="d">
          <button type="button">first</button>
          <button type="button" ref={second}>
            second
          </button>
          <button type="button">last</button>
        </div>
      )}
    </div>
  );
}

describe("useFocusTrap / useEscape", () => {
  it("focuses first tabbable, wraps Tab and Shift+Tab, Esc closes and returns focus", () => {
    render(<Dialog />);
    const opener = screen.getByText("open");
    opener.focus();
    fireEvent.click(opener);
    expect(document.activeElement).toBe(screen.getByText("first"));
    screen.getByText("last").focus();
    fireEvent.keyDown(document.activeElement as Element, { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByText("first"));
    fireEvent.keyDown(document.activeElement as Element, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(screen.getByText("last"));
    fireEvent.keyDown(document.activeElement as Element, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it("honours initialFocus and pulls back focus that escapes", () => {
    render(<Dialog initial />);
    fireEvent.click(screen.getByText("open"));
    expect(document.activeElement).toBe(screen.getByText("second"));
    act(() => screen.getByText("outside").focus());
    expect(screen.getByRole("dialog").contains(document.activeElement)).toBe(true);
  });

  it("only the topmost Escape handler fires", () => {
    const outer = vi.fn();
    const inner = vi.fn();
    function Both() {
      useEscape(outer);
      useEscape(inner);
      return null;
    }
    render(<Both />);
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(inner).toHaveBeenCalledTimes(1);
    expect(outer).not.toHaveBeenCalled();
  });
});

describe("useRestoreFocus", () => {
  it("restores the captured element or the fallback", () => {
    function C() {
      const { capture, restore } = useRestoreFocus();
      return (
        <>
          <button type="button" onClick={capture}>
            a
          </button>
          <button type="button" onClick={() => restore()}>
            b
          </button>
        </>
      );
    }
    render(<C />);
    const a = screen.getByText("a");
    a.focus();
    fireEvent.click(a);
    screen.getByText("b").focus();
    fireEvent.click(screen.getByText("b"));
    expect(document.activeElement).toBe(a);
  });
});

describe("announce / LiveRegion", () => {
  beforeEach(() => vi.useFakeTimers());

  it("mounts one polite and one assertive region", () => {
    render(<LiveRegion />);
    expect(screen.getByRole("status").getAttribute("aria-live")).toBe("polite");
    expect(screen.getByRole("alert").getAttribute("aria-live")).toBe("assertive");
  });

  it("debounces bursts to the last sentence", () => {
    render(<LiveRegion />);
    act(() => {
      announce("1건");
      announce("12건");
      announce("123건");
    });
    expect(screen.getByRole("status").textContent).toBe("");
    act(() => {
      vi.advanceTimersByTime(200);
    });
    expect(screen.getByRole("status").textContent).toBe("123건");
  });

  it("routes assertive separately and re-announces identical text", () => {
    render(<LiveRegion />);
    act(() => {
      announce("검색 실패", { politeness: "assertive" });
      vi.advanceTimersByTime(100);
    });
    expect(screen.getByRole("alert").textContent).toBe("검색 실패");
    expect(screen.getByRole("status").textContent).toBe("");
    act(() => {
      announce("검색 실패", { politeness: "assertive" });
      vi.advanceTimersByTime(100);
    });
    expect(screen.getByRole("alert").textContent).not.toBe("검색 실패"); // NBSP-suffixed
    expect(screen.getByRole("alert").textContent?.trim()).toBe("검색 실패");
  });

  it("truncates long text and collapses whitespace", () => {
    render(<LiveRegion />);
    act(() => {
      announce(`a\n  b ${"x".repeat(500)}`);
      vi.advanceTimersByTime(200);
    });
    const text = (screen.getByRole("status").textContent ?? "").trim();
    expect(text.length).toBeLessThanOrEqual(200);
    expect(text.startsWith("a b x")).toBe(true);
  });

  it("keeps a held stage sentence from being overwritten by a later polite one", () => {
    render(<LiveRegion />);
    const status = screen.getByRole("status");
    act(() => {
      announce("단계: 처리", { hold: true });
      vi.advanceTimersByTime(100);
      announce("1,234건 · sqlite · 12ms"); // grid result count, would have replaced the stage sentence
      vi.advanceTimersByTime(60);
    });
    expect(status.textContent?.trim()).toBe("단계: 처리");
    act(() => {
      vi.advanceTimersByTime(700); // still inside the hold window
    });
    expect(status.textContent?.trim()).toBe("단계: 처리");
    act(() => {
      vi.advanceTimersByTime(ANNOUNCE_HOLD_MS);
    });
    expect(status.textContent?.trim()).toBe("1,234건 · sqlite · 12ms");
  });

  it("does not replace its region elements between announcements", () => {
    render(<LiveRegion />);
    const el = screen.getByRole("status");
    act(() => {
      announce("one");
      vi.advanceTimersByTime(200);
      announce("two");
      vi.advanceTimersByTime(200);
    });
    expect(screen.getByRole("status")).toBe(el);
  });
});

describe("DisabledReason", () => {
  it("keeps the control focusable with aria-disabled and a described tooltip", () => {
    const onClick = vi.fn();
    render(
      <DisabledReason reason="docs-index 산출물이 없는 런입니다">
        <button type="button" onClick={onClick}>
          문서
        </button>
      </DisabledReason>,
    );
    const btn = screen.getByRole("button", { name: "문서" });
    expect(btn.getAttribute("aria-disabled")).toBe("true");
    expect(btn.hasAttribute("disabled")).toBe(false);
    const id = btn.getAttribute("aria-describedby") ?? "";
    const description = document.getElementById(id);
    expect(description?.textContent).toBe("docs-index 산출물이 없는 런입니다");
    // Not part of the page text until shown.
    expect(description?.hasAttribute("hidden")).toBe(true);
    expect(document.querySelector('[role="tooltip"]')).toBeNull();
    btn.focus();
    expect(document.activeElement).toBe(btn);
    fireEvent.click(btn);
    expect(onClick).not.toHaveBeenCalled();
  });

  it("shows the tooltip on focus and hides it on blur", () => {
    render(
      <DisabledReason reason="reason">
        <button type="button">x</button>
      </DisabledReason>,
    );
    const btn = screen.getByRole("button");
    const tip = () => document.querySelector('[role="tooltip"]');
    expect(tip()).toBeNull();
    act(() => btn.focus());
    expect(tip()?.textContent).toBe("reason");
    act(() => btn.blur());
    expect(tip()).toBeNull();
  });

  it("merges an existing aria-describedby", () => {
    render(
      <DisabledReason reason="r">
        <button type="button" aria-describedby="other">
          x
        </button>
      </DisabledReason>,
    );
    expect(screen.getByRole("button").getAttribute("aria-describedby")?.split(" ")[0]).toBe("other");
    expect(screen.getByRole("button").getAttribute("aria-describedby")?.split(" ")).toHaveLength(2);
  });

  it("passes the child through untouched when there is no reason", () => {
    const onClick = vi.fn();
    render(
      <DisabledReason reason={null}>
        <button type="button" onClick={onClick}>
          go
        </button>
      </DisabledReason>,
    );
    const btn = screen.getByRole("button");
    expect(btn.hasAttribute("aria-disabled")).toBe(false);
    fireEvent.click(btn);
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});

describe("SkipLink", () => {
  it("focuses the target (made programmatically focusable) without changing the hash", () => {
    window.location.hash = "#/case/r1/files";
    render(
      <>
        <SkipLink target="main" />
        <main id="main">content</main>
      </>,
    );
    fireEvent.click(screen.getByRole("link"));
    const main = document.getElementById("main") as HTMLElement;
    expect(main.getAttribute("tabindex")).toBe("-1");
    expect(document.activeElement).toBe(main);
    expect(window.location.hash).toBe("#/case/r1/files");
  });
});
