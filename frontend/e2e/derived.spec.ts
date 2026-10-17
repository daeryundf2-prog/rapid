import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

// 통합 보기 (docs/plans/axiom-adoption-2026-10-17.md §3.2, Q-X5 / Q-X12) against the sample case of
// the e2e server: the run's `derived` step builds the tables; a value opens its original rows; a row
// opens the family grid with that record selected.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.use({ viewport: { width: 1440, height: 900 } });

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-derived-"));
  const response = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
  const body = (await response.json()) as { run?: { run_id?: string } };
  runId = body.run?.run_id ?? "";
  if (!runId) {
    const list = await request.get("/api/runs", { headers: HEADERS });
    runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  }
  expect(runId).not.toBe("");
});

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
}

test("Q-X5: 사람 식별자 → 원본 행(2개 이상 계열) → 계열 표에서 같은 행 선택", async ({ page, request }) => {
  const meta = await request.get(`/api/runs/${runId}/derived`, { headers: HEADERS });
  const tables = ((await meta.json()) as { tables: Array<{ table: string; rows: number }> }).tables;
  expect(tables.find((t) => t.table === "people")?.rows ?? 0).toBeGreaterThan(0);

  await open(page, `#/case/${runId}/explore/derived/people`);
  const grid = page.getByRole("grid", { name: "사람 식별자 표" });
  await expect(grid).toBeVisible();
  // The tree lists the 통합 보기 domain.
  await expect(page.getByRole("treeitem", { name: /통합 보기/ }).first()).toBeVisible();
  const first = grid.locator('[role="row"][aria-rowindex="2"]');
  await expect(first).toBeVisible();
  await first.focus();
  await page.keyboard.press("Enter");
  const panel = page.getByTestId("derived-rows");
  const samples = panel.locator("button.derived-sample");
  await expect(samples.first()).toBeFocused();
  const labels = await samples.allTextContents();
  const families = new Set(labels.map((label) => label.split(" · ")[0]));
  expect(families.size).toBeGreaterThanOrEqual(2);
  // Esc returns to the value.
  await page.keyboard.press("Escape");
  await expect(first).toBeFocused();

  // Open a sample of an artifact family; its record index is the "#n" of the label.
  const target = samples.filter({ hasText: /#\d/ }).last();
  const text = (await target.textContent()) ?? "";
  const recordIndex = Number((/#([\d,]+)/.exec(text)?.[1] ?? "0").replace(/,/g, ""));
  await target.click();
  await expect(page).toHaveURL(/explore\/artifacts\/[^?]+\?.*row=/);
  // The deep link restores the grid's focused row (roving tabindex) to that record.
  const selected = page.locator(`[role="grid"] [role="row"][aria-rowindex="${recordIndex + 2}"]`).first();
  await expect(selected).toBeVisible();
  await expect(selected).toHaveAttribute("tabindex", "0", { timeout: 10_000 });
  await expect(selected).toHaveClass(/is-focused/);
  await expect(selected).toHaveAttribute("data-row-key", new RegExp(`/artifacts/${recordIndex}$`));
});

test("Q-X12: 통합 보기 controls are named, chips toggle, search writes q=", async ({ page }) => {
  await open(page, `#/case/${runId}/explore/derived/paths`);
  const grid = page.getByRole("grid", { name: "접근 경로 표" });
  await expect(grid.locator('[role="row"][aria-rowindex="2"]')).toBeVisible();
  const pane = page.getByTestId("derived-pane");
  for (const button of await pane.getByRole("button").all()) {
    const name = (await button.getAttribute("aria-label")) ?? (await button.textContent()) ?? "";
    expect(name.trim()).not.toBe("");
  }
  await page.getByRole("searchbox", { name: "값 검색" }).fill("users");
  await expect(page).toHaveURL(/q=users/);
  await expect(page.getByRole("combobox", { name: "정렬" })).toBeVisible();
  // Tabs between tables.
  await page.getByRole("button", { name: /^URL 분류/ }).click();
  await expect(page.getByRole("grid", { name: "URL 분류 표" })).toBeVisible();
});
