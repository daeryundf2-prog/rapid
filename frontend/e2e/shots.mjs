// One-off screenshot capture for the console redesign (S6). Not part of the test suite.

import { mkdirSync } from "node:fs";
import { chromium } from "@playwright/test";

const BASE = "http://127.0.0.1:8791";
const TOKEN = "e2e-token";
const OUT = "D:/devin/rapid/docs/screenshots/console-2026-10-11";
mkdirSync(OUT, { recursive: true });

const runs = await (await fetch(`${BASE}/api/runs`, { headers: { "X-RapidTriage-Token": TOKEN } })).json();
const runId = runs.runs[0].run_id;
const log = [];

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await ctx.newPage();
const shot = async (name) => {
  await page.waitForTimeout(600);
  await page.screenshot({ path: `${OUT}/${name}.png` });
  log.push(name);
};
const go = async (hash) => {
  await page.evaluate((h) => (window.location.hash = h), hash);
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(500);
};
const setTheme = async (theme) => {
  await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
};
const openViewer = async () => {
  await page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first().click();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(500);
};

// 1. landing, no case
await page.goto(`${BASE}/#token=${TOKEN}`);
await page.waitForTimeout(1200);
await shot("01-landing-no-case");

// 2. intake
await go(`#/case/${runId}/intake`);
await shot("02-intake");

// 3/4. artifacts with viewer open in 메타 and 헥스
await go(`#/case/${runId}/artifacts`);
await openViewer().catch((e) => log.push(`openViewer failed: ${e.message}`));
await page
  .getByRole("tab", { name: "메타" })
  .click()
  .catch(() => log.push("no 메타 tab"));
await shot("03-artifacts-viewer-meta");
await page
  .getByRole("tab", { name: "헥스" })
  .click()
  .catch(() => log.push("no 헥스 tab"));
await shot("04-artifacts-viewer-hex");

// 5. global search for powershell
await go(`#/case/${runId}/search?q=powershell`);
await shot("05-search-powershell");

// 6. review board
await go(`#/case/${runId}/review`);
await shot("06-review-board");

// 7. dark / light
await go(`#/case/${runId}/artifacts`);
await setTheme("dark");
await shot("07-theme-dark");
await setTheme("light");
await shot("08-theme-light");

// 9. 1024px drawer open
await page.setViewportSize({ width: 1024, height: 900 });
await setTheme("light");
await go(`#/case/${runId}/artifacts`);
await openViewer().catch((e) => log.push(`drawer openViewer failed: ${e.message}`));
await shot("09-drawer-1024-open");

// ---- Second batch (10-16): dashboard, tree categories, filter chips, views, axiom preset, evidence info.
const tryDo = async (label, fn) => {
  try {
    await fn();
  } catch (e) {
    log.push(`${label} failed: ${e.message.split(String.fromCharCode(10))[0]}`);
  }
};
await page.setViewportSize({ width: 1440, height: 900 });
await setTheme("light");
await go(`#/case/${runId}/intake`);
await shot("10-dashboard");

await go(`#/case/${runId}/artifacts`);
await shot("11-tree-categories");

await tryDo("filter chip", async () => {
  await page.getByPlaceholder("검색어 필터 ( / )").first().fill("pdf");
  await page.getByPlaceholder("검색어 필터 ( / )").first().press("Enter");
});
await shot("12-filterbar-chips");

// Thumbnails are only enabled on file nodes (files collection); artifacts shows it disabled with a reason.
await go(`#/case/${runId}/files`);
await tryDo("thumbnails", async () => {
  await page.getByRole("button", { name: "썸네일 보기" }).first().click();
});
await shot("13-view-thumbnails");

await tryDo("histogram", async () => {
  await page.getByRole("button", { name: "히스토그램 보기" }).first().click();
});
await shot("14-view-histogram");

await tryDo("axiom preset", async () => {
  await page
    .getByRole("button", { name: "열 보기" })
    .first()
    .click()
    .catch(() => {});
  await page.getByRole("button", { name: "열 설정" }).click();
  await page.locator(".grid-select select").first().selectOption("axiom");
});
await shot("15-axiom-preset");

await go(`#/case/${runId}/artifacts`);
await tryDo("viewer open", openViewer);
await tryDo("meta tab", async () => {
  await page.getByRole("tab", { name: "메타" }).click();
});
await tryDo("evidence info", async () => {
  await page.getByRole("region", { name: "증거 정보" }).scrollIntoViewIfNeeded();
});
await shot("16-meta-evidence-info");

await browser.close();
console.log(JSON.stringify({ runId, shots: log }, null, 1));
