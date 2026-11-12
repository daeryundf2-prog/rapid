// T5 — the lawyer's report (IS-056·057, QA-075). From the case, open the report stage and see a
// preview of the report body; the candidate count must be the same on the report page and in
// `/review-counts`. Target ≤3 operations once the candidates exist. Marking the 12 "보고서 포함"
// rows is a write and is left to the W5–W8 spec; this skeleton measures with the candidates the run
// already has. Measures only (see harness.ts).
import { test } from "@playwright/test";
import { apiGet, resolveRun, STEP_TIMEOUT_MS, TaskRecorder } from "./harness";

test("T5 report preview (measure)", async ({ page, request }) => {
  const runId = await resolveRun(request, "T5");
  const rec = new TaskRecorder(page, "T5", "변호사 보고서", runId, { maxOps: 3, maxSeconds: 30 });
  await rec.install();
  await rec.open();

  const counts = await apiGet<{ report_candidates: number | null }>(
    request,
    `/api/runs/${encodeURIComponent(runId)}/review-counts`,
  );
  rec.extra.reviewCountsCandidates = counts?.report_candidates ?? null;

  const atReport = await rec.step(
    "stage rail → 보고서",
    async () => {
      const rail = page.getByRole("navigation", { name: "작업 단계" });
      const target = rail.getByRole("button", { name: /보고/ }).or(rail.getByRole("link", { name: /보고/ }));
      await rec.click(target.first());
      await page.waitForURL(/\/report(\/|$|\?)/, { timeout: STEP_TIMEOUT_MS });
    },
    { goal: true },
  );

  if (atReport) {
    await rec.step(
      "report preview shown",
      async () => {
        const preview = page
          .getByRole("region", { name: /미리보기/ })
          .or(page.getByRole("document", { name: /보고서/ }))
          .or(page.getByTestId("report-preview"));
        await preview.first().waitFor({ timeout: STEP_TIMEOUT_MS });
      },
      { goal: true },
    );
    await rec.step("candidate count = /review-counts", async () => {
      const text = await page
        .getByText(/보고 후보 \d+건/)
        .first()
        .textContent({ timeout: STEP_TIMEOUT_MS });
      const shown = Number(/보고 후보 (\d+)건/.exec(text ?? "")?.[1] ?? Number.NaN);
      rec.extra.reportPageCandidates = shown;
      if (shown !== counts?.report_candidates) {
        throw new Error(`report page ${shown} ≠ review-counts ${counts?.report_candidates ?? "n/a"}`);
      }
    });
  } else {
    rec.skip("report preview shown", "report stage not reached", { goal: true });
  }
  rec.finish();
});
