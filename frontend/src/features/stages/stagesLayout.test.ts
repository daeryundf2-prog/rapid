import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * T-016 (visual audit #10, GAP-078) CSS contract for the 처리 stage cards. jsdom does no layout, so
 * these pin the rules; e2e/process-cards.spec.ts measures the boxes at 880–1920.
 */
const here = dirname(fileURLToPath(import.meta.url));
const sheet = readFileSync(resolve(here, "stages.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");

/** Declarations of the first rule whose selector list is exactly `selector`. */
function rule(selector: string): Record<string, string> {
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

describe("T-016 process cards grow with a two-line title", () => {
  it("the card has a 58px floor, never a fixed height", () => {
    const card = rule(".process-card");
    expect(card["min-height"]).toBe("58px");
    expect(card).not.toHaveProperty("height");
    expect(card).not.toHaveProperty("max-height");
    expect(card["grid-template-rows"]).toBe("auto auto");
  });

  it("the title wraps to two lines and the meta line stays one ellipsized line", () => {
    expect(rule(".process-card-title")).toMatchObject({
      "-webkit-line-clamp": "2",
      "line-clamp": "2",
      "overflow-wrap": "anywhere",
      "min-width": "0",
    });
    expect(rule(".process-card-last")).toMatchObject({
      "white-space": "nowrap",
      "text-overflow": "ellipsis",
      overflow: "hidden",
    });
    expect(rule(".process-card-link > .status-chip")["margin-left"]).toBe("auto");
  });
});

describe("T-016 analysis cards leave no holes", () => {
  it("a full-row selected card does not leave an empty cell before it", () => {
    const grid = rule(".analysis-cards");
    expect(grid.display).toBe("grid");
    expect(grid["grid-auto-flow"]).toBe("row dense");
    expect(grid["grid-template-columns"]).toContain("repeat(auto-fill");
    expect(rule(".analysis-card.is-selected")["grid-column"]).toBe("1 / -1");
  });

  it("cards have no fixed height (title and description stack)", () => {
    const card = rule(".analysis-card");
    expect(card["flex-direction"]).toBe("column");
    expect(card).not.toHaveProperty("height");
  });
});
