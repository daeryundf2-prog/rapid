import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// jsdom has no layout, so the phone top-bar rule is checked as CSS. review #101 P3-3: at 390 px the
// integrity seal and 실행 left the case picker only its chevron — the case name vanished entirely.
const css = readFileSync(join(process.cwd(), "src/app/shell.css"), "utf8");

function phoneBlock(): string {
  const start = css.indexOf("@media (max-width: 599.98px)");
  expect(start).toBeGreaterThan(-1);
  let depth = 0;
  for (let i = css.indexOf("{", start); i < css.length; i += 1) {
    if (css[i] === "{") depth += 1;
    else if (css[i] === "}" && --depth === 0) return css.slice(start, i);
  }
  return "";
}

describe("top bar on phones", () => {
  it("keeps a few letters of the case name next to the seal", () => {
    const block = phoneBlock();
    expect(block).toMatch(/\.case-picker-name\s*\{[^}]*min-width:\s*3em/);
    // The search gives way to its placeholder width so the case area can widen.
    expect(block).toMatch(/\.topbar-case\s*\{[^}]*max-width:\s*50%/);
  });
});
