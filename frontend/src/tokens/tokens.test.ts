import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
// @ts-expect-error untyped node script (the check:contrast gate); its checks are reused here
import * as gate from "../../scripts/check-contrast.mjs";

const { cvdDelta, deltaE2000, parseThemes, STATUS_SEPARATION, statusSeparation } = gate;

const read = (path: string) => readFileSync(resolve(__dirname, path), "utf8");
const tokens = read("./tokens.css");
const themes = parseThemes(tokens) as Record<string, Record<string, string>>;

interface Separation {
  a: string;
  b: string;
  ok: boolean;
  delta: Record<string, number>;
}

describe("review-status colours (F1)", () => {
  it("every theme keeps the statuses apart under normal, deutan and protan vision", () => {
    expect(Object.keys(themes).sort()).toEqual(["dark", "light", "print"]);
    for (const [theme, vars] of Object.entries(themes)) {
      const results = statusSeparation(vars) as Separation[];
      // 5 statuses: 10 status pairs + 15 status × danger/warn/accent pairs.
      expect(results, theme).toHaveLength(25);
      const failing = results.filter((r) => !r.ok).map((r) => `${theme} ${r.a}/${r.b}`);
      expect(failing).toEqual([]);
    }
  });

  it("관련 있음 is not the danger red in any theme", () => {
    for (const [theme, vars] of Object.entries(themes)) {
      expect(vars["--status-relevant"], theme).not.toBe(vars["--danger"]);
      const pair = (statusSeparation(vars) as Separation[]).find(
        (r) => r.a === "--status-relevant" && r.b === "--danger",
      );
      expect(pair?.delta.normal ?? 0, theme).toBeGreaterThanOrEqual(STATUS_SEPARATION.relevantVsDanger);
    }
  });

  it("the gate fails the old palette (relevant = danger red, report ≈ accent for deutans)", () => {
    const old = {
      ...themes.light,
      "--status-relevant": "#b63131",
      "--status-report": "#6c4bbf",
      "--status-excluded": "#a5520c",
    };
    const failing = (statusSeparation(old) as Separation[]).filter((r) => !r.ok).map((r) => `${r.a}/${r.b}`);
    expect(failing).toContain("--status-relevant/--danger");
    expect(failing).toContain("--status-report/--accent");
  });

  it("CIEDE2000 matches the Sharma et al. reference pairs and the simulation keeps greys grey", () => {
    // Sharma, Wu & Dalal (2005) test data, pairs 1 and 17.
    expect(deltaE2000([50, 2.6772, -79.7751], [50, 0, -82.7485])).toBeCloseTo(2.0425, 3);
    expect(deltaE2000([50, 2.5, 0], [73, 25, -18])).toBeCloseTo(27.1492, 3);
    expect(cvdDelta("#808080", "#808080", "deutan")).toBeCloseTo(0, 5);
    // Red and green collapse for deuteranopes far more than for normal vision.
    expect(cvdDelta("#d03030", "#30a030", "deutan")).toBeLessThan(
      cvdDelta("#d03030", "#30a030", "normal") / 2,
    );
  });
});

describe("type scale (F4) and surfaces (F5)", () => {
  const px = (name: string) => {
    const m = new RegExp(`${name}:\\s*([\\d.]+)rem`).exec(tokens);
    return m ? Number(m[1]) * 16 : Number.NaN;
  };

  it("body 14, table and aux 13, title steps at least 1.25× apart", () => {
    expect(px("--fs-body")).toBe(14);
    expect(px("--fs-table")).toBe(13);
    expect(px("--fs-table-aux")).toBe(13);
    expect(px("--fs-aux")).toBe(13);
    expect(px("--fs-screen-title") / px("--fs-panel-title")).toBeGreaterThanOrEqual(1.25);
    expect(px("--fs-case") / px("--fs-screen-title")).toBeGreaterThanOrEqual(1.25);
    expect(px("--fs-figure")).toBeGreaterThan(px("--fs-case"));
  });

  it("dense surfaces use the table size; the stage heading uses the screen title", () => {
    expect(read("../features/grid/grid.css")).toMatch(/\.grid-root \{[^}]*font-size: var\(--fs-table\)/);
    expect(read("../features/views/views.css")).toMatch(
      /\.view-switch-host \{[^}]*font-size: var\(--fs-table\)/,
    );
    expect(read("../features/stages/stages.css")).toMatch(
      /\.stage-heading \{[^}]*font-size: var\(--fs-screen-title\)/,
    );
  });

  it("input edges are the full control line (checked ≥ 3:1 by check:contrast)", () => {
    expect(tokens).toMatch(/--field-edge: var\(--line\);/);
    expect(read("./controls.css")).not.toMatch(/--field-edge:/);
  });
});

describe("verdict is a glyph, never a tint (F2) and the cursor is its own mark (F3)", () => {
  it("no review-status background tints on rows, cards, thumbnails or chat bubbles", () => {
    const grid = read("../features/grid/grid.css");
    expect(grid).not.toMatch(/data-mark=/);
    expect(grid).not.toMatch(/--row-bg/);
    for (const file of ["../features/views/cardMap.css", "../features/views/views.css"]) {
      const css = read(file);
      expect(css, file).not.toMatch(/\[data-review=/);
      expect(css, file).not.toMatch(/color-mix\(in srgb, var\(--status-/);
    }
  });

  it("the cursor row has a 2px inset ring above the sticky cells; selection is the tint", () => {
    const grid = read("../features/grid/grid.css");
    expect(grid).toMatch(
      /\.grid-row\.is-focused::after,\s*\.grid-row:focus-visible::after \{[^}]*z-index: 3;[^}]*box-shadow: inset 0 0 0 var\(--focus-width\) var\(--focus\);/,
    );
    expect(grid).toMatch(/\.grid-row\.is-selected \{\s*background: var\(--bg-selected\);\s*\}/);
    expect(grid).toMatch(/\.grid-verdict \{[^}]*width: 14px;/);
  });
});
