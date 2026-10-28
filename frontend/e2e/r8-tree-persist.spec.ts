import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

// r8 todo 18: the evidence tree folded by a viewer on a narrow window (plan r7 §3.2 L2) stays
// expanded when the analyst moves on to the review board, and no fold leaks into the stage.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-tree-"));
  const created = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  if (created.status() !== 201) return;
  const payload = (await created.json()) as { run?: { run_id?: string } };
  runId = payload.run?.run_id ?? "";
});

test("R8: the tree opened by the viewer stays expanded on the review board", async ({ page }) => {
  // 1280px is below the auto-fold width, so opening the viewer folds the tree to its rail.
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto(`/v2/#token=${TOKEN}`);
  const row = encodeURIComponent("files||/candidates/0||");
  await page.evaluate(
    ([run, r]) => {
      window.location.hash = `#/case/${run}/files?row=${r}`;
    },
    [runId, row] as const,
  );
  await expect(page.getByRole("region", { name: "원본 뷰어" })).toBeVisible();
  await expect(page.getByTestId("tree-rail")).toBeVisible();

  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/review`;
  }, runId);
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/review`));
  await expect(page.getByTestId("tree-region")).toBeVisible();
  await expect(page.getByTestId("tree-rail")).toHaveCount(0);
});
