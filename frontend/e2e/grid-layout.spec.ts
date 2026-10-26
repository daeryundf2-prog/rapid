import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

// R7 stage 1 lane L2 (plan r7 §3.2): grid columns, paths and range honesty in a real browser.
//
// Default: the isolated e2e server (playwright.config webServer) with the bundled sample case.
// Real data (read-only): RT_E2E_BASE=http://127.0.0.1:<port> RT_E2E_TOKEN=<token>
// RT_E2E_RUN=<run id> [RT_E2E_SHOTS=<dir outside Git>] — every non-GET /api request is aborted
// (no export / sample / analysis / review write can reach the run folder).
const BASE = process.env.RT_E2E_BASE ?? "";
const TOKEN = process.env.RT_E2E_TOKEN ?? "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const REAL = Boolean(process.env.RT_E2E_BASE && process.env.RT_E2E_RUN);
const SHOTS = process.env.RT_E2E_SHOTS ?? join(tmpdir(), "rt-e2e-grid-layout");
mkdirSync(SHOTS, { recursive: true });

let runId = process.env.RT_E2E_RUN ?? "";

test.beforeAll(async ({ request }) => {
  if (REAL) return;
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-grid-"));
  const response = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
  const list = await request.get("/api/runs", { headers: HEADERS });
  const body = (await list.json()) as { runs: Array<{ run_id: string }> };
  runId = body.runs[0]?.run_id ?? "";
  expect(runId).not.toBe("");
});

/** Real data: read-only — every non-GET API call is refused before it leaves the browser. */
async function guard(page: Page): Promise<string[]> {
  const blocked: string[] = [];
  if (!REAL) return blocked;
  await page.route("**/api/**", async (route) => {
    const method = route.request().method();
    if (method === "GET" || method === "HEAD") return route.continue();
    blocked.push(`${method} ${new URL(route.request().url()).pathname}`);
    return route.abort();
  });
  return blocked;
}

async function open(page: Page, hash: string): Promise<void> {
  await page.goto(`${BASE}/v2/#token=${TOKEN}`);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
  await page.evaluate((target) => {
    window.location.hash = target;
  }, hash);
  await expect(page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first()).toBeVisible({
    timeout: 60_000,
  });
}

test("1920 · 전체 아티팩트: the grid fits the pane — no sideways scroll (C-D7)", async ({ page }) => {
  await guard(page);
  await page.setViewportSize({ width: 1920, height: 1000 });
  await open(page, `#/case/${runId}/explore/artifacts`);
  const scroll = page.locator(".grid-scroll").first();
  await expect
    .poll(async () => scroll.evaluate((el) => el.scrollWidth - el.clientWidth))
    .toBeLessThanOrEqual(1);
  await expect(page.getByTestId("grid-scope-badge")).toContainText("불러온");
  await page.screenshot({ path: join(SHOTS, "l2-1920-artifacts-all.png") });
});

test("1920 · 파일 목록: no sideways scroll; path cells always hold the file name (C-D8)", async ({
  page,
}) => {
  await guard(page);
  await page.setViewportSize({ width: 1920, height: 1000 });
  await open(page, `#/case/${runId}/explore/files`);
  const scroll = page.locator(".grid-scroll").first();
  await expect
    .poll(async () => scroll.evaluate((el) => el.scrollWidth - el.clientWidth))
    .toBeLessThanOrEqual(1);
  const pairs = await page.evaluate(() =>
    [...document.querySelectorAll('[role="grid"] [role="row"][data-index]')].slice(0, 40).map((row) => ({
      name: (row.querySelector('[data-col="title"]') as HTMLElement | null)?.innerText ?? "",
      path: (row.querySelector('[data-col="path"]') as HTMLElement | null)?.innerText ?? "",
      title: (row.querySelector('[data-col="path"] .mid-path') as HTMLElement | null)?.title ?? "",
    })),
  );
  expect(pairs.length).toBeGreaterThan(0);
  for (const pair of pairs) {
    if (!pair.title) continue;
    const fileName = pair.title.split(/[\\/]/).pop() ?? "";
    expect(pair.path).toContain(fileName);
  }
  await page.screenshot({ path: join(SHOTS, "l2-1920-files.png") });
});

test("1280 + viewer: 조건 on one line, the popover above the viewer and inside the viewport (C-D3, C-D4)", async ({
  page,
}) => {
  const blocked = await guard(page);
  await page.setViewportSize({ width: 1280, height: 720 });
  await open(page, `#/case/${runId}/explore/files`);
  // Open a row: the viewer expands (and the tree folds below 1600px, 구조 D3).
  await page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first().click();
  await expect(page.locator('[data-testid="viewer-region"]:not([data-collapsed])')).toBeVisible();
  await expect(page.getByTestId("tree-rail")).toBeVisible();
  const trigger = page.getByTestId("filter-popover-button");
  const box = await trigger.boundingBox();
  expect(box?.height ?? 99).toBeLessThanOrEqual(30);
  const lines = await trigger.evaluate((el) => {
    const label = el.querySelector(".filter-btn-label") as HTMLElement | null;
    if (!label) return 1;
    const height = label.getBoundingClientRect().height;
    const line = Number.parseFloat(getComputedStyle(label).lineHeight) || height;
    return Math.round(height / line);
  });
  expect(lines).toBeLessThanOrEqual(1);
  await trigger.click();
  const popover = page.getByRole("dialog", { name: "조건" });
  await expect(popover).toBeVisible();
  const rect = await popover.boundingBox();
  expect(rect).not.toBeNull();
  if (rect) {
    expect(rect.x).toBeGreaterThanOrEqual(0);
    expect(rect.y).toBeGreaterThanOrEqual(0);
    expect(rect.x + rect.width).toBeLessThanOrEqual(1280);
    expect(rect.y + rect.height).toBeLessThanOrEqual(720);
  }
  // Nothing (the viewer included) covers the popover's corners.
  const covered = await popover.evaluate((el) => {
    const r = el.getBoundingClientRect();
    const points = [
      [r.left + 4, r.top + 4],
      [r.right - 4, r.top + 4],
      [r.left + 4, r.bottom - 4],
      [r.right - 4, r.bottom - 4],
    ];
    return points.filter(([x, y]) => !el.contains(document.elementFromPoint(x as number, y as number)))
      .length;
  });
  expect(covered).toBe(0);
  await page.screenshot({ path: join(SHOTS, "l2-1280-viewer-condition-popover.png") });
  await page.keyboard.press("Escape");
  expect(blocked.filter((call) => !/case-db\/ensure|saved-searches/.test(call))).toEqual([]);
});

test("a header click sorts only: the viewer keeps its row (C-D2)", async ({ page }) => {
  await guard(page);
  await page.setViewportSize({ width: 1600, height: 900 });
  await open(page, `#/case/${runId}/explore/files`);
  const third = page.locator('[role="grid"] [role="row"][aria-rowindex="4"]').first();
  await third.click();
  const viewerPath = page.locator('[data-testid="viewer-region"] .viewer-path .mid-path');
  await expect(viewerPath).toBeVisible();
  const before = await viewerPath.getAttribute("title");
  const focusedBefore = await page
    .locator('[role="grid"] [role="row"][tabindex="0"]')
    .getAttribute("data-row-key");
  const size = page.locator('[role="columnheader"][data-col="size"]');
  await size.getByRole("button").click();
  await expect(size).toHaveAttribute("aria-sort", "ascending");
  await size.getByRole("button").click();
  await expect(size).toHaveAttribute("aria-sort", "descending");
  await expect(page.getByTestId("grid-sort-status")).toContainText("크기 내림차순");
  expect(await viewerPath.getAttribute("title")).toBe(before);
  const focusedNow = await page.locator('[role="grid"] [role="row"][tabindex="0"]').count();
  if (focusedNow) {
    expect(await page.locator('[role="grid"] [role="row"][tabindex="0"]').getAttribute("data-row-key")).toBe(
      focusedBefore,
    );
  }
  await page.screenshot({ path: join(SHOTS, "l2-1600-files-size-desc.png") });
});
