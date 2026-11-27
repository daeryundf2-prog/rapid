import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// jsdom has no layout, so the rules that keep the 조건 줄 inside a narrow pane are checked as CSS.
// Visual check (PR #77 review, 1440 px with the viewer open and a zoomed time range): the
// one-line row was wider than the centre pane, whose frame clips overflow, so 조건 지우기 was cut
// in half and the result count and 열 설정 were hidden.
const css = readFileSync(join(process.cwd(), "src/features/filters/filters.css"), "utf8");

function rule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`));
  expect(match, selector).toBeTruthy();
  return match?.[1] ?? "";
}

describe("조건 줄 layout", () => {
  it("wraps onto another line instead of overflowing a narrow pane", () => {
    const row = rule(".filter-row");
    expect(row).toMatch(/flex-wrap:\s*wrap/);
    expect(row).not.toMatch(/(^|[^-])height:/);
    expect(rule(".filter-bar")).not.toMatch(/(^|[^-])height:/);
  });

  it("lets the 조건 button shrink and ellipsise its applied summary before anything wraps away", () => {
    expect(rule(".filter-row > .popover-anchor")).toMatch(/min-width:\s*0/);
    const trigger = rule(".filter-row .filter-trigger");
    expect(trigger).toMatch(/flex-shrink:\s*1/);
    expect(trigger).toMatch(/min-width:\s*0/);
    const applied = rule(".filter-trigger-applied");
    expect(applied).toMatch(/min-width:\s*0/);
    expect(applied).toMatch(/text-overflow:\s*ellipsis/);
  });

  it("keeps the row end (count, 열 설정) whole and 조건 저장 · 조건 지우기 · count together", () => {
    expect(rule(".filter-row-end")).toMatch(/flex:\s*none/);
    // Each has margin-left: auto (.grid-btn-quiet, .filter-row-end): on a wrapped line they spread apart.
    const grouped = rule(
      ".filter-row > .grid-btn-quiet + .grid-btn-quiet,\n.filter-row > .grid-btn-quiet + .filter-row-end",
    );
    expect(grouped).toMatch(/margin-left:\s*0/);
  });
});
