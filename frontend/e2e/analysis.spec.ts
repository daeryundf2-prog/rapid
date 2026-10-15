import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type APIRequestContext, expect, type Page, test } from "@playwright/test";

// Plan analysis-workbench-p1 §5 "A" + console-ia §7 (Q-IA-2, Q-IA-3): an old collection link
// redirects to its stage URL; carving runs from the 처리 stage card → progress → done →
// "결과 보기 →" opens 탐색 › 파일시스템 › 복구/카빙 (count = row_count) → a row opens in the
// viewer, hex at the hit offset. Skips cleanly when the backend has no `/analyses` (§3.1)
// or the served bundle predates the stage rail.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";
let analysesAvailable = false;

async function listAnalyses(request: APIRequestContext) {
  const response = await request.get(`/api/runs/${encodeURIComponent(runId)}/analyses`, {
    headers: HEADERS,
  });
  if (!response.ok()) return null;
  return ((await response.json()) as { analyses?: Array<Record<string, unknown>> }).analyses ?? [];
}

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-analysis-"));
  const created = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  if (created.status() !== 201) return;
  const payload = (await created.json()) as { run?: { run_id?: string } };
  runId = payload.run?.run_id ?? "";
  if (!runId) {
    const list = await request.get("/api/runs", { headers: HEADERS });
    runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  }
  if (!runId) return;
  analysesAvailable = (await listAnalyses(request)) !== null;
});

async function hasRail(page: Page): Promise<boolean> {
  return page
    .getByTestId("stage-rail")
    .waitFor({ timeout: 15_000 })
    .then(
      () => true,
      () => false,
    );
}

const railButton = (page: Page, name: string) =>
  page.getByRole("navigation", { name: "작업 단계" }).getByRole("button", { name });

test("Q-IA-2: an old collection link redirects to its stage URL (same view, same row)", async ({ page }) => {
  test.skip(!runId, "sample case could not be created");
  await page.goto(`/v2/#token=${TOKEN}`);
  test.skip(!(await hasRail(page)), "served bundle predates the stage rail — rebuild static first");
  const row = encodeURIComponent("files||/candidates/0||");
  await page.evaluate(
    ([run, r]) => {
      window.location.hash = `#/case/${run}/files?row=${r}`;
    },
    [runId, row] as const,
  );
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/explore/files\\?row=`));
  await expect(railButton(page, "탐색")).toHaveAttribute("aria-current", "page");
  await expect(
    page.locator('[role="grid"] [role="row"][data-row-key="files:/candidates/0"]'),
  ).toHaveAttribute("tabindex", "0", { timeout: 20_000 });
});

test("Q-IA-3: carve on the 처리 card → progress → done → 결과 보기 → tree node → viewer hex", async ({
  page,
  request,
}) => {
  test.skip(!runId, "sample case could not be created");
  test.skip(!analysesAvailable, "backend without /api/runs/{id}/analyses (plan §3.1)");

  await page.goto(`/v2/#token=${TOKEN}`);
  test.skip(!(await hasRail(page)), "served bundle predates the stage rail — rebuild static first");
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/process/carve`;
  }, runId);
  const card = page.getByTestId("analysis-card-carve");
  await expect(card).toBeVisible({ timeout: 20_000 });
  await expect(railButton(page, "처리")).toHaveAttribute("aria-current", "page");

  const runButton = card.getByRole("button", { name: "카빙 실행…" });
  await expect(runButton).not.toHaveAttribute("aria-disabled", "true", { timeout: 30_000 });
  await runButton.click();
  const dialog = page.getByRole("dialog", { name: "카빙 실행" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("analysis-caution")).toContainText("예상 범위·주의");
  await dialog.getByLabel("최대 후보 수").fill("50");
  await dialog.getByTestId("analysis-submit").click();
  await expect(dialog).toBeHidden();
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/process/carve`));

  // Progress (card / status-bar chip; tiny samples may finish first) — then done.
  let sawProgress = false;
  let analysisId = "";
  await expect
    .poll(
      async () => {
        if (await page.getByTestId("analysis-progress-chip").isVisible()) sawProgress = true;
        const jobs = (await listAnalyses(request)) ?? [];
        const newest = jobs.find((j) => j.kind === "carve");
        analysisId = String(newest?.analysis_id ?? "");
        return newest?.status;
      },
      { timeout: 60_000, intervals: [250] },
    )
    .toBe("completed");
  test.info().annotations.push({ type: "progress-seen", description: String(sawProgress) });
  await expect(page.getByTestId("analysis-progress-chip")).toBeHidden();
  await expect(card.getByTestId("analysis-last")).toContainText("마지막 실행: 완료", { timeout: 10_000 });
  const jobs = (await listAnalyses(request)) ?? [];
  const rowCount = Number(jobs.find((j) => j.analysis_id === analysisId)?.row_count ?? 0);
  test.skip(rowCount === 0, "the sample case has no carving signatures to show");

  // 결과 보기 → : 탐색 › 파일시스템 › 복구/카빙, the count matches the job.
  const results = card.getByTestId("analysis-results-link");
  await expect(results).toContainText(`${rowCount.toLocaleString("ko-KR")}건`);
  await results.click();
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/explore/analysis/carve\\?id=`));
  const node = page.getByRole("treeitem", { name: /^복구\/카빙/ });
  await expect(node).toHaveAttribute("aria-selected", "true", { timeout: 20_000 });
  await expect(node).toHaveAttribute("aria-label", `복구/카빙, ${rowCount.toLocaleString("ko-KR")}건`);

  const grid = page.getByRole("grid", { name: "분석 결과 목록" });
  const firstRow = grid.locator('[role="row"][data-index="0"]');
  await expect(firstRow).toBeVisible({ timeout: 20_000 });
  await expect(grid).toHaveAttribute("aria-rowcount", String(rowCount + 1));

  // The row opens its source file in the viewer, hex mode at the hit offset.
  await firstRow.click();
  await firstRow.press("Enter");
  const hexTab = page.getByRole("tab", { name: /헥스/ });
  await expect(hexTab).toHaveAttribute("aria-selected", "true", { timeout: 20_000 });
  await expect(page.locator("#viewer .is-hl").first()).toBeVisible({ timeout: 20_000 });
});

test("Q-IA-1 / review 16–17: Alt+n switches stage with focus on the panel heading; 침해사고 › 웹셸 exists", async ({
  page,
}) => {
  test.skip(!runId, "sample case could not be created");
  await page.goto(`/v2/#token=${TOKEN}`);
  test.skip(!(await hasRail(page)), "served bundle predates the stage rail — rebuild static first");
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/explore/files`;
  }, runId);
  await expect(page.getByRole("tree", { name: "케이스 탐색 트리" })).toBeVisible({ timeout: 20_000 });
  await page.keyboard.press("Alt+2");
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/process`));
  await expect(page.locator("#stage-heading")).toBeFocused();
  await expect(page.locator("#stage-heading")).toHaveText("처리");
  await page.keyboard.press("Alt+3");
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/explore/files`));

  const incident = page.getByRole("treeitem", { name: /^침해사고/ });
  await incident.click();
  await expect(incident).toHaveAttribute("aria-expanded", "true");
  const webshell = page.getByRole("treeitem", { name: /^웹셸/ });
  await expect(webshell).toBeVisible();
  if ((await webshell.getAttribute("aria-disabled")) === "true") {
    await expect(webshell).toHaveAttribute("title", "이 런에는 해당 데이터가 없습니다");
  } else {
    await webshell.click();
    await expect(page).toHaveURL(/explore\/artifacts\/windows-system\?types=webshell-source-candidate/);
  }
});
