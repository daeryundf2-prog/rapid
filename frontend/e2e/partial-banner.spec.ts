// T-020 (WB-3, QA-022): on the SYNTHETIC R8 rich fixture (frontend/e2e/r8_fixture.py, fake values
// only) with a server started under RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS=0.01, a type-filtered
// windows-filesystem node (40,024 rows) stops on the scan budget: the grid shows the amber
// partial band with the server's notice, never the "no rows" empty state, and "다시 시도"
// sends the same request again.
//
// Run: RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS=0.01 RAPIDTRIAGE_E2E_PORT=8807 \
//      npx playwright test -c e2e/playwright.config.ts partial-banner
// Without the budget variable the server scans to the end, so this spec skips itself.
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";
const BUDGET = Number(process.env.RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS || "0");
const KIND = "windows-filesystem";
// A type no row has: the scan must walk all 40,024 rows, so a 0.01 s budget always stops it.
const TYPE = "no-such-type";

let runId = "";

test.describe.configure({ mode: "serial" });
test.skip(
  !(BUDGET > 0 && BUDGET < 1),
  "needs a server started with RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS=0.01",
);

test.beforeAll(async ({ request }) => {
  test.setTimeout(240_000);
  const output = join(mkdtempSync(join(tmpdir(), "rt-v2-e2e-partial-")), "run");
  execFileSync(python, [join("frontend", "e2e", "r8_fixture.py"), output], { cwd: repoRoot });
  const imported = await request.post("/api/runs/import", { headers: HEADERS, data: { output_dir: output } });
  expect(imported.status(), await imported.text()).toBe(201);
  runId = ((await imported.json()) as { run_id: string }).run_id;
  expect(runId).not.toBe("");
});

test("budget-stopped type filter shows the band, never a false empty state", async ({ page }) => {
  const listRequests: string[] = [];
  page.on("request", (req) => {
    const url = new URL(req.url());
    if (url.pathname.endsWith(`/runs/${runId}/artifacts`) && url.searchParams.get("artifact_type") === TYPE) {
      listRequests.push(`${url.pathname}?${url.searchParams.toString()}`);
    }
  });
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, `#/case/${runId}/explore/artifacts/${KIND}?types=${TYPE}`);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();

  const band = page.getByTestId("r8-partial-banner");
  await expect(band).toBeVisible({ timeout: 30_000 });
  await expect(band).toHaveAttribute("data-code", "SCAN_BUDGET_STOPPED");
  await expect(band).toContainText("시간 제한으로 일부만 확인했습니다");
  // The server's Korean notice ("시간 제한(0.01초) 안에 n행까지만 확인했습니다").
  await expect(band).toContainText("행까지만 확인했습니다");

  // No false empty state, no stuck "counting" and none of the retired strings.
  const empty = page.getByTestId("grid-empty");
  await expect(empty).toBeVisible();
  await expect(empty).not.toContainText("표시할 행이 없습니다");
  await expect(empty).not.toContainText("조건에 맞는 행이 없습니다");
  await expect(page.getByTestId("grid-footer-total")).toHaveText(/^총 [\d,]+건 이상$/);
  const body = (await page.locator("body").textContent()) ?? "";
  expect(body).not.toContain(["전체 건수", "미확정"].join(" "));
  expect(body).not.toContain(["전체", "미확인"].join(" "));
  expect(body).not.toContain("이 노드에는 표시할 행이 없습니다");

  // "다시 시도" re-sends the same request.
  await expect.poll(() => listRequests.length).toBeGreaterThan(0);
  const before = listRequests.length;
  const first = listRequests[0];
  await page.getByTestId("r8-partial-retry").click();
  await expect.poll(() => listRequests.length).toBeGreaterThan(before);
  expect(listRequests.slice(before)).toContain(first);
  await expect(band).toBeVisible();
});
