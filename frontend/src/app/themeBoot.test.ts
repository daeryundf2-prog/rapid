import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { THEME_KEY } from "../state/slices/prefs";

/** The inline <script id="theme-boot"> of index.html (review B2-10: no dark flash for light users). */
function bootScript(): string {
  const html = readFileSync(join(__dirname, "..", "..", "index.html"), "utf8");
  const match = html.match(/<script id="theme-boot">([\s\S]*?)<\/script>/);
  if (!match?.[1]) throw new Error("index.html has no theme-boot script");
  return match[1];
}

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.theme;
});

describe("index.html theme boot", () => {
  it("reads the same storage key as prefs.ts", () => {
    expect(bootScript()).toContain(`"${THEME_KEY}"`);
  });

  it("applies a stored light theme before the app runs", () => {
    window.localStorage.setItem(THEME_KEY, "light");
    new Function(bootScript())();
    expect(document.documentElement.dataset.theme).toBe("light");
  });

  it("leaves the default dark theme (no attribute) when nothing or junk is stored", () => {
    new Function(bootScript())();
    expect(document.documentElement.dataset.theme).toBeUndefined();
    window.localStorage.setItem(THEME_KEY, "<x>");
    new Function(bootScript())();
    expect(document.documentElement.dataset.theme).toBeUndefined();
  });
});
