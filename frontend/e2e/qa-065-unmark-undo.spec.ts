import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type APIRequestContext, expect, type Page, test } from "@playwright/test";
import { COPY } from "../src/contracts/copy";
import { TEST_IDS } from "../src/contracts/testIds";

// QA-065 skeleton (r8 T-036, GAP-024 / IS-042) on the sample case of the e2e server:
// 관련 있음 → 제외 → 해제 goes back to 관련 있음 (not 미검토), the history holds 3 entries, and
// Ctrl+Z (실행 취소) takes the last judgement back. The real-data run of QA-065 (C2) follows the
// same steps against the corpus case (부록 E) and keeps the DB dump as evidence.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-qa065-"));
  const response = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
  const list = await request.get("/api/runs", { headers: HEADERS });
  runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  expect(runId).not.toBe("");
});

async function openFirstFile(page: Page): Promise<string> {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, `#/case/${runId}/explore/files`);
  await expect(page.getByTestId(TEST_IDS.gridRegion)).toBeVisible();
  const row = page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])').first();
  await expect(row).toBeVisible({ timeout: 20_000 });
  const key = (await row.getAttribute("data-row-key")) ?? "";
  await row.click();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("region", { name: COPY.viewer.region })).toBeVisible();
  return key;
}

function batchDone(page: Page) {
  return page.waitForResponse((r) => r.url().endsWith("/api/case-db/review-batch") && r.ok());
}

async function statusOf(request: APIRequestContext, locator: string): Promise<string> {
  const map = await request.get(`/api/runs/${runId}/review-map`, { headers: HEADERS });
  const marks = ((await map.json()) as { marks: Array<{ locator: string; status: string }> }).marks;
  return marks.find((mark) => mark.locator === locator)?.status ?? "unreviewed";
}

test("QA-065: 관련 있음 → 제외 → 해제 = 관련 있음, history 3, Ctrl+Z takes the last one back", async ({
  page,
  request,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const key = await openFirstFile(page);
  const locator = key.slice(key.indexOf(":") + 1);
  expect(locator).toMatch(/^\/candidates\/\d+$/);

  let done = batchDone(page);
  await page.keyboard.press("r");
  await done;
  done = batchDone(page);
  await page.keyboard.press("x");
  await done;
  await expect.poll(() => statusOf(request, locator)).toBe("excluded");
  // The toast offers 실행 취소 with its key.
  await expect(page.getByTestId("toast-action").last()).toHaveAttribute("aria-keyshortcuts", "Control+Z");

  // 해제: the pressed 제외 in the review-status menu un-presses to the previous state.
  await page.getByTestId("viewer-review-status-menu").click();
  done = batchDone(page);
  await page.locator('[data-command="viewer.mark.excluded"]').click();
  await done;
  await expect.poll(() => statusOf(request, locator)).toBe("relevant");

  const history = await request.get(
    `/api/runs/${runId}/review-history?collection=files&locator=${encodeURIComponent(locator)}`,
    { headers: HEADERS },
  );
  const entries = ((await history.json()) as { entries: Array<{ status_after: string }> }).entries;
  expect(entries.map((entry) => entry.status_after)).toEqual(["relevant", "excluded", "relevant"]);

  // Ctrl+Z takes the 해제 back (제외 again); a second Ctrl+Z the 제외 (관련 있음).
  done = batchDone(page);
  await page.keyboard.press("Control+z");
  await done;
  await expect.poll(() => statusOf(request, locator)).toBe("excluded");
  done = batchDone(page);
  await page.keyboard.press("Control+z");
  await done;
  await expect.poll(() => statusOf(request, locator)).toBe("relevant");
});
