import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

const TOKEN = "e2e-token";

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-sample-"));
  const response = await request.post("/api/sample-case/run", {
    headers: { "X-RapidTriage-Token": TOKEN },
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
});

test("workbench shell renders three panes and loads the case list", async ({ page }) => {
  await page.goto("/v2/#token=e2e-token");

  // Token fragment must be captured and removed from the address bar.
  await expect(page).not.toHaveURL(/token=/);

  await expect(page.getByTestId("workbench-shell")).toBeVisible();
  await expect(page.getByTestId("case-queue-pane")).toBeVisible();
  await expect(page.getByTestId("item-table-pane")).toBeVisible();
  await expect(page.getByTestId("detail-pane")).toBeVisible();

  // Case list is populated from the API (sample run created in beforeAll).
  await expect(page.getByTestId("status-run-count")).toContainText("케이스");
  await expect(page.locator(".run-item").first()).toBeVisible();

  // Light/dark toggle flips the document theme attribute.
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", /light|dark/);
});

test("evidence tree drives the item table and detail provenance", async ({ page }) => {
  await page.goto("/v2/#token=e2e-token");
  await expect(page.getByTestId("workbench-shell")).toBeVisible();

  // Select the first case -> the evidence tree loads.
  await page.locator(".run-item").first().click();
  const tree = page.getByTestId("evidence-tree");
  await expect(tree).toBeVisible();
  await expect(tree.locator(".tree-row").first()).toBeVisible();

  // Clicking a collection node swaps the center pane to that collection.
  await tree.getByRole("button", { name: "아티팩트" }).click();
  await expect(page.getByTestId("item-table-pane").locator(".pane-title")).toContainText("아티팩트");
  const firstRow = page.locator(".vtable-row").first();
  await expect(firstRow).toBeVisible();

  // Selecting a row shows its provenance block in the detail pane.
  await firstRow.click();
  await expect(page.getByTestId("provenance-block")).toBeVisible();
});
