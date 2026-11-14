import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

/**
 * T-013 (GAP-105 / IS-034): the search-options popover lives inside `.global-search`, so a bare
 * `.global-search input { width: 100% }` stretched its checkboxes into empty bars and pushed the
 * labels below them. jsdom does no layout; these pin the selectors, and the Playwright shot
 * (r8 WB-1 evidence) measures the boxes.
 */
const src = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const css = (path: string) => readFileSync(resolve(src, path), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

/** Every rule as [selector list, declarations]; at-rule wrappers are skipped, their bodies kept. */
function rules(sheet: string): [string, Record<string, string>][] {
  const out: [string, Record<string, string>][] = [];
  for (const match of sheet.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = (match[1] ?? "").trim();
    const body = Object.fromEntries(
      (match[2] ?? "")
        .split(";")
        .map((d) => d.split(":").map((p) => p.trim()))
        .filter(([k, v]) => k && v)
        .map(([k, ...v]) => [k, v.join(":")]),
    );
    out.push([selector, body]);
  }
  return out;
}

const shell = css("app/shell.css");
const controls = css("tokens/controls.css");

describe("T-013 search options checkboxes", () => {
  it("no shell rule styles every input inside .global-search", () => {
    const selectors = rules(shell).flatMap(([s]) => s.split(",").map((p) => p.trim()));
    const bare = selectors.filter((s) => /\.global-search\s+input(?![\w[\]-]*\[type="search"\])/.test(s));
    expect(bare).toEqual([]);
  });

  it("the search field rules target only input[type=search] and keep its geometry", () => {
    const search = rules(shell).filter(([s]) => s === '.global-search input[type="search"]');
    const merged = Object.assign({}, ...search.map(([, body]) => body));
    expect(merged).toMatchObject({
      width: "100%",
      "padding-left": "calc(var(--space-2) + 22px)",
      "padding-right": "36px",
      "font-size": "var(--fs-body)",
    });
  });

  it("checkbox / radio box size is not wrapped in :where (a container `input` rule cannot stretch it)", () => {
    const guard = rules(controls).find(
      ([s]) => s.replace(/\s+/g, " ") === 'input[type="checkbox"], input[type="radio"]',
    );
    expect(guard?.[1]).toMatchObject({ width: "16px", height: "16px", "min-width": "0", padding: "0" });
  });

  describe("computed style (jsdom cascade)", () => {
    let style: HTMLStyleElement | undefined;
    afterEach(() => {
      style?.remove();
      document.body.innerHTML = "";
    });

    it("a checkbox in the popover is 16px wide while the search field stays 100%", () => {
      style = document.createElement("style");
      // Same load order as src/main.tsx: shell.css, then controls.css.
      style.textContent = `${shell}\n${controls}`;
      document.head.append(style);
      document.body.innerHTML = `
        <search class="global-search">
          <form><input id="q" type="search" /></form>
          <div class="search-options-popover"><label><input id="cb" type="checkbox" /> 문서</label></div>
        </search>`;
      const checkbox = getComputedStyle(document.getElementById("cb") as HTMLElement);
      expect(checkbox.width).toBe("16px");
      expect(checkbox.height).toBe("16px");
      expect(getComputedStyle(document.getElementById("q") as HTMLElement).width).toBe("100%");
    });
  });
});
