import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

// Verdict key flow on a filtered list (review #106 P1-2): a verdict that takes its row out of the
// list must move the cursor to the row that was next, never one past it. Own run: the marks below
// must not meet the rows other specs mark.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.use({ viewport: { width: 1440, height: 900 } });

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-verdict-flow-"));
  const response = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
  const list = await request.get("/api/runs", { headers: HEADERS });
  runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  expect(runId).not.toBe("");
});

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId("grid-region")).toBeVisible();
}

const dataRows = (page: Page) =>
  page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');

test("Q-V1: R on a 재검토-filtered list judges the rows in order, none skipped", async ({ page }) => {
  await open(page, `#/case/${runId}/explore/files`);
  const first = dataRows(page).first();
  await expect(first).toBeVisible();
  // Four rows → 재검토 (I on a 4-row selection).
  await first.click();
  await first.focus();
  for (let i = 0; i < 3; i += 1) await page.keyboard.press("Shift+J");
  const keys = await dataRows(page).evaluateAll((rows) =>
    rows.slice(0, 4).map((row) => row.getAttribute("data-row-key") ?? ""),
  );
  expect(keys.every(Boolean)).toBe(true);
  await page.keyboard.press("i");
  for (const key of keys) {
    await expect(page.locator(`[role="row"][data-row-key="${key}"]`)).toHaveAttribute(
      "data-mark",
      "needs-review",
    );
  }

  // The 재검토 list (same page, the route changes): exactly those four, in the same order.
  await page.evaluate((next) => {
    window.location.hash = next;
  }, `#/case/${runId}/explore/files?status=needs-review`);
  await expect(dataRows(page)).toHaveCount(4);
  const listed = await dataRows(page).evaluateAll((rows) =>
    rows.map((row) => row.getAttribute("data-row-key") ?? ""),
  );
  expect(listed).toEqual(keys);
  const row = (key: string) => page.locator(`[role="grid"] [role="row"][data-row-key="${key}"]`);
  await row(keys[0] as string).click();
  await row(keys[0] as string).focus();

  // R: the judged row leaves the list, the cursor sits on the row that was next.
  await page.keyboard.press("r");
  await expect(dataRows(page)).toHaveCount(3);
  await expect(row(keys[1] as string)).toHaveAttribute("tabindex", "0");
  // R again judges that row (not the one after it).
  await page.keyboard.press("r");
  await expect(dataRows(page)).toHaveCount(2);
  await expect(row(keys[2] as string)).toHaveAttribute("tabindex", "0");
  const left = await dataRows(page).evaluateAll((rows) =>
    rows.map((r) => r.getAttribute("data-row-key") ?? ""),
  );
  expect(left).toEqual([keys[2], keys[3]]);
});
