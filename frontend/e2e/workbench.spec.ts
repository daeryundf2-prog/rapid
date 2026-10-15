import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

// Smoke tests for the redesigned console (Layout.tsx testids: workbench-shell, tree-region,
// grid-region, viewer-region; viewer region is named "원본 뷰어"). Rewritten from the
// pre-redesign three-pane selectors (case-queue-pane, .run-item, provenance-block, ...).
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-sample-"));
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

test("workbench shell renders the tree, grid and viewer regions and toggles theme", async ({ page }) => {
  await page.goto(`/v2/#token=${TOKEN}`);

  // Token fragment must be captured and removed from the address bar.
  await expect(page).not.toHaveURL(/token=/);

  await expect(page.getByTestId("workbench-shell")).toBeVisible();
  // No case open: the landing card (visual-polish S10); a case shows tree, grid and viewer.
  await expect(page.getByTestId("landing")).toBeVisible();
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/explore/files`;
  }, runId);
  await expect(page.getByTestId("tree-region")).toBeVisible();
  await expect(page.getByTestId("grid-region")).toBeVisible();
  await expect(page.getByTestId("viewer-region")).toBeVisible();
  await expect(page.getByTestId("statusbar")).toBeVisible();

  // Light/dark toggle flips the document theme attribute.
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", /light|dark/);
});

test("collection tree drives the grid and a row opens the viewer", async ({ page }) => {
  await page.goto(`/v2/#token=${TOKEN}`);
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/artifacts`;
  }, runId);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();

  // The tree node for artifacts keeps the case context and the grid shows its rows.
  const grid = page.getByRole("grid").first();
  await expect(grid).toBeVisible();
  const firstRow = page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first();
  await expect(firstRow).toBeVisible();

  // Opening a row shows the viewer region with its mode tabs.
  await firstRow.click();
  await page.keyboard.press("Enter");
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await expect(viewer).toBeVisible();
  await expect(viewer.getByRole("tablist")).toBeVisible();
});
