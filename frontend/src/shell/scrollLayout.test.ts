import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { chipStripWheel } from "../features/filters/FilterBar";

/**
 * Scroll review (C1–C6) CSS contract. jsdom does no layout, so these pin the rules the Playwright
 * probe (scratchpad scrollrev) measured: which box scrolls, what may not widen the page.
 */
const src = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const css = (path: string) => readFileSync(resolve(src, path), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

/** Declarations of the first rule whose selector list is exactly `selector`. */
function rule(sheet: string, selector: string): Record<string, string> {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`(?:^|\\})\\s*${escaped}\\s*\\{([^}]*)\\}`).exec(sheet);
  if (!match) throw new Error(`no rule ${selector}`);
  return Object.fromEntries(
    (match[1] ?? "")
      .split(";")
      .map((d) => d.split(":").map((p) => p.trim()))
      .filter(([k, v]) => k && v)
      .map(([k, ...v]) => [k, v.join(":")]),
  );
}

describe("C1 tree panel scrolls its list, not the frame", () => {
  const tree = css("features/tree/tree.css");
  it("the evidence tree fills the panel and its list is the scroller", () => {
    expect(rule(tree, ".evidence-tree")).toMatchObject({
      flex: "1 1 auto",
      "min-height": "0",
      display: "flex",
    });
    expect(rule(tree, '.evidence-tree > ul[role="tree"]')).toMatchObject({
      "overflow-y": "auto",
      "min-height": "0",
      "overscroll-behavior": "contain",
      "scrollbar-gutter": "stable",
    });
    expect(rule(tree, ".evidence-tree-foot")["border-top"]).toContain("var(--line-subtle)");
  });

  it("pane frames clip (focus cannot scroll them) and stage panels fill below the heading", () => {
    expect(rule(css("app/shell.css"), ".pane-frame").overflow).toBe("clip");
    const panel = rule(css("features/stages/stages.css"), ".stage-panel");
    expect(panel).toMatchObject({ flex: "1 1 auto", "min-height": "0", "overflow-y": "auto" });
    expect(panel.height).toBeUndefined();
  });
});

describe("C3 resize handle", () => {
  it("is an 8px strip with a grip token and accent states from data-separator", () => {
    const shell = css("app/shell.css");
    expect(rule(shell, ".resize-handle")).toMatchObject({ width: "8px", cursor: "col-resize" });
    expect(rule(shell, ".resize-handle::after").background).toBe("var(--resize-grip)");
    expect(shell).toContain('.resize-handle[data-separator="hover"]');
    expect(shell).not.toContain("data-resize-handle-state");
  });
});

describe("C4 scrollbars", () => {
  it("every scroller uses the themed thumb", () => {
    const controls = css("tokens/controls.css");
    expect(rule(controls, "*")["scrollbar-color"]).toBe("var(--sb-thumb) var(--sb-track)");
    const tokens = css("tokens/tokens.css");
    expect(tokens.match(/--sb-thumb:/g)?.length).toBe(3); // dark, light, print
  });
});

describe("C5 / C6 / help overflow", () => {
  it("the map table cannot widen the page", () => {
    const map = rule(css("features/views/cardMap.css"), ".map-body");
    expect(map["grid-template-columns"]).toBe("minmax(220px, 320px) minmax(0, 1fr)");
    expect(rule(css("features/views/cardMap.css"), ".map-body > *")["min-width"]).toBe("0");
  });

  it("the filter chip strip shows its scrollbar", () => {
    expect(rule(css("features/filters/filters.css"), ".filter-chips")["scrollbar-width"]).toBe("thin");
  });

  it("the help dialog scrolls its body, not the table", () => {
    const shell = css("app/shell.css");
    expect(rule(shell, ".help-body")).toMatchObject({ overflow: "auto", "min-height": "0" });
    expect(rule(shell, ".help-table").overflow).toBeUndefined();
  });

  it("a vertical wheel over an overflowing chip strip scrolls it sideways", () => {
    const el = document.createElement("ul");
    Object.defineProperty(el, "scrollWidth", { value: 600 });
    Object.defineProperty(el, "clientWidth", { value: 200 });
    const wheel = (deltaX: number, deltaY: number) =>
      chipStripWheel({ currentTarget: el, deltaX, deltaY } as unknown as Parameters<
        typeof chipStripWheel
      >[0]);
    wheel(0, 120);
    expect(el.scrollLeft).toBe(120);
    wheel(80, 10); // a horizontal gesture is left to the browser
    expect(el.scrollLeft).toBe(120);
  });
});
