import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";
import { COPY } from "../src/contracts/copy";
import { TEST_IDS } from "../src/contracts/testIds";

// r8 browser verification follow-ups (verify-wb F1 · F2 · F3) on the sample case of the e2e server:
// a capped 더보기 menu scrolls instead of squeezing its items, an undecodable image shows the
// "미리보기 없음" glyph instead of the broken-image icon, and the run picker reaches run delete.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-verify-wb-"));
  const response = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
  const list = await request.get("/api/runs", { headers: HEADERS });
  runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  expect(runId).not.toBe("");
});

async function openFile(page: Page, name: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, `#/case/${runId}/explore/files`);
  await expect(page.getByTestId(TEST_IDS.gridRegion)).toBeVisible();
  const row = page.locator('[role="grid"] [role="row"]', { hasText: name }).first();
  await expect(row).toBeVisible({ timeout: 20_000 });
  await row.click();
  await expect(page.getByRole("region", { name: COPY.viewer.region })).toBeVisible();
}

test("F2: an undecodable image shows the 미리보기 없음 glyph, not the broken-image icon", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  // The sample's screen-capture.png is a PNG signature followed by text: no browser can decode it.
  await openFile(page, "screen-capture.png");
  const viewer = page.getByRole("region", { name: COPY.viewer.region });
  await viewer.getByRole("tab", { name: "이미지" }).click();
  const view = viewer.getByTestId("image-view");
  await expect(view).toBeVisible();
  await expect(view.locator(".image-figure [data-testid='image-glyph']")).toBeVisible({ timeout: 20_000 });
  await expect(view.locator(".image-figure").getByText("미리보기 없음")).toBeVisible();
  await expect(view.locator("img.image-original")).toHaveCount(0);
  // The same-folder strip: no <img> is left in the broken state.
  const strip = view.getByTestId("image-strip");
  await expect(strip).toBeVisible();
  await expect
    .poll(() =>
      strip
        .locator("img")
        .evaluateAll((imgs) =>
          imgs.filter(
            (img) => (img as HTMLImageElement).complete && (img as HTMLImageElement).naturalWidth === 0,
          ),
        ),
    )
    .toHaveLength(0);
});

test("F1: a capped 더보기 menu scrolls; its items never overlap", async ({ page }) => {
  // A short window caps the menu (placePopover max-height).
  await page.setViewportSize({ width: 1280, height: 420 });
  await openFile(page, "invoice-wire-transfer.txt");
  await page.getByTestId(TEST_IDS.viewerActionsMenu).click();
  const menu = page.getByRole("menu", { name: COPY.common.more });
  await expect(menu).toBeVisible();
  const layout = await menu.evaluate((el) => {
    const items = [...el.querySelectorAll<HTMLElement>('[role="menuitem"]')];
    const squeezed = items
      .filter((item) => item.scrollHeight > item.clientHeight + 1)
      .map((item) => `${item.textContent}: ${item.clientHeight} < ${item.scrollHeight}`);
    const overlaps: string[] = [];
    for (let i = 1; i < items.length; i += 1) {
      const above = items[i - 1]?.getBoundingClientRect();
      const below = items[i]?.getBoundingClientRect();
      if (above && below && above.bottom > below.top + 0.5) overlaps.push(`${items[i]?.textContent}`);
    }
    return {
      count: items.length,
      squeezed,
      overlaps,
      overflowY: getComputedStyle(el).overflowY,
      capped: el.scrollHeight > el.clientHeight,
    };
  });
  expect(layout.count).toBeGreaterThan(3);
  expect(layout.squeezed).toEqual([]);
  expect(layout.overlaps).toEqual([]);
  expect(layout.overflowY).toBe("auto");
  expect(layout.capped).toBe(true);
  await page.keyboard.press("Escape");
});

test("F3: the run picker reaches run delete through the confirm dialog (Esc keeps the run)", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openFile(page, "invoice-wire-transfer.txt");
  await page.getByTestId("case-picker").click();
  const picker = page.getByRole("dialog", { name: "런 선택" });
  await expect(picker).toBeVisible();
  const remove = picker.getByRole("button", { name: /처리 결과 삭제…$/ });
  await expect(remove).toBeVisible();
  // The active row carries a pointer shortcut too (aria-hidden; the button above is the a11y path).
  await expect(picker.getByTestId("case-picker-row-delete").first()).toBeAttached();
  await remove.click();
  const dialog = page.getByRole("dialog", { name: "처리 결과 삭제" });
  await expect(dialog).toBeVisible();
  await expect(page.getByTestId("delete-run-cancel")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  const list = await page.request.get("/api/runs", { headers: HEADERS });
  const runs = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs;
  expect(runs.some((run) => run.run_id === runId)).toBe(true);
});
