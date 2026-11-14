// T3 — one day's timeline (IS-047, QA-069). From the case briefing, reach the timeline narrowed to a
// single day: target ≤3 operations, ≤15 s, one screen change. Ideal path: a briefing bar → that
// day. Today's fallback path (tree 타임라인 → histogram bar) is tried when the briefing has no bars,
// so the record shows how far the current console gets. Measures only (see harness.ts).
import { type Page, test } from "@playwright/test";
import { ensureTree, resolveRun, STEP_TIMEOUT_MS, TaskRecorder } from "./harness";

const HISTOGRAM = /타임라인 히스토그램/;

/** `from`/`to` of the current timeline address, or null when the view is not a bounded timeline. */
function timelineRange(page: Page): { from: string; to: string; hours: number } | null {
  const hash = page.url().split("#")[1] ?? "";
  if (!hash.includes("/explore/timeline")) return null;
  const params = new URLSearchParams(hash.split("?")[1] ?? "");
  const from = params.get("from");
  const to = params.get("to");
  if (!from || !to) return null;
  const hours = (Date.parse(to) - Date.parse(from)) / 3_600_000;
  return { from, to, hours };
}

test("T3 one-day timeline (measure)", async ({ page, request }) => {
  const runId = await resolveRun(request, "T3");
  const rec = new TaskRecorder(page, "T3", "하루 타임라인", runId, {
    maxOps: 3,
    maxSeconds: 15,
    maxScreens: 2,
  });
  await rec.install();
  await rec.open();

  const fromBrief = await rec.step("briefing bar → that day", async () => {
    const bars = page.getByRole("group", { name: HISTOGRAM }).first().getByRole("button");
    await bars.first().waitFor({ timeout: STEP_TIMEOUT_MS });
    await rec.click(bars.first());
    return "clicked the first briefing bar";
  });

  if (!fromBrief) {
    rec.notes.push("no bar on the case's first screen; tried the tree path");
    await rec.step("fallback: tree 전체 타임라인", async () => {
      await ensureTree(rec);
      const ms = await rec.clickToRows(page.getByRole("treeitem", { name: /^(전체 )?타임라인, / }).first());
      return `first row ${ms} ms`;
    });
    await rec.step("fallback: histogram bar → one day", async () => {
      const bars = page.getByRole("group", { name: HISTOGRAM }).first().getByRole("button");
      await bars.first().waitFor({ timeout: STEP_TIMEOUT_MS });
      await rec.click(bars.first());
    });
  }

  await rec.step(
    "timeline bounded to ≤ 24 h with rows",
    async () => {
      await page.waitForTimeout(300);
      const range = timelineRange(page);
      rec.extra.range = range;
      if (!range) throw new Error(`not a bounded timeline: ${page.url().split("#")[1] ?? ""}`);
      if (!(range.hours > 0 && range.hours <= 24)) throw new Error(`range is ${range.hours} h`);
      await rec.waitFirstRow(Date.now());
      return `${range.from} → ${range.to}`;
    },
    { goal: true },
  );
  rec.finish();
});
