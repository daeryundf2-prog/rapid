// T2 — keyword → tag (IS-031·033, QA-057). From the case, search a keyword in 전체 검색어 and tag
// the first N result rows with the digit-key tag shortcut. Target ≤15 operations, ≤60 s. The UX
// audit measured 3 rows in about 40 s. Measures only (see harness.ts).
//   R8_T2_QUERY  keyword (default "계좌" on a real run, "invoice" on the SYN fixture, whose sample
//                documents are English); no hit records the search step as failed, tagging "not reached".
//   R8_T2_ROWS   rows to tag (default 3; QA-057 uses 10 on C3).
// Fixture mode creates a case tag on shortcut 1 first (set-up, not counted). A real run is
// read-only: the tag write is blocked by the harness guard, so tagging is recorded as blocked.
import { test } from "@playwright/test";
import { apiGet, REAL, resolveRun, STEP_TIMEOUT_MS, TaskRecorder, TOKEN, url } from "./harness";

const QUERY = process.env.R8_T2_QUERY || (REAL ? "계좌" : "invoice");
const ROWS = Number(process.env.R8_T2_ROWS) || 3;
const TAG_NAME = "R8 측정";

interface TagsPayload {
  tags: Array<{ id: number; name: string; shortcut: number | null; count: number }>;
}

test("T2 keyword search to tag (measure)", async ({ page, request }) => {
  const runId = await resolveRun(request, "T2");
  const rec = new TaskRecorder(page, "T2", `키워드("${QUERY}") → ${ROWS}건 태그`, runId, {
    maxOps: 15,
    maxSeconds: 60,
  });
  rec.extra.query = QUERY;
  rec.extra.rows = ROWS;

  // Set-up (not measured): the case id, and in fixture mode a tag bound to digit 1.
  const counts = await apiGet<{ case_id: string }>(
    request,
    `/api/runs/${encodeURIComponent(runId)}/review-counts`,
  );
  const caseId = counts?.case_id ?? "";
  const tagsPath = `/api/cases/${encodeURIComponent(caseId)}/tags?run_id=${encodeURIComponent(runId)}`;
  let tagCountBefore: number | null = null;
  let shortcut = "1";
  if (caseId) {
    const tags = await apiGet<TagsPayload>(request, tagsPath);
    let tag = tags?.tags.find((t) => t.name === TAG_NAME) ?? tags?.tags.find((t) => t.shortcut !== null);
    if (!tag && !REAL) {
      const created = await request.post(url(tagsPath), {
        headers: { "X-RapidTriage-Token": TOKEN },
        data: { name: TAG_NAME, color_token: "tag-6", shortcut: 1, description: "" },
      });
      if (created.ok()) tag = ((await created.json()) as { tag: TagsPayload["tags"][number] }).tag;
    }
    if (tag) {
      tagCountBefore = tag.count;
      shortcut = String(tag.shortcut ?? 1);
      rec.extra.tag = { name: tag.name, shortcut: tag.shortcut };
    }
  }
  if (tagCountBefore === null)
    rec.notes.push("no case tag with a digit shortcut; tag count cannot be verified");

  await rec.install();
  await rec.open("explore/files");

  const searched = await rec.step(
    "search keyword in 전체 검색어",
    async () => {
      const box = page.getByRole("searchbox", { name: "전체 검색어" }).or(page.getByLabel("전체 검색어"));
      await rec.click(box.first());
      await rec.type(QUERY);
      const t0 = Date.now();
      await rec.press("Enter");
      const ms = await rec.waitFirstRow(t0);
      return `first result row ${ms} ms`;
    },
    { goal: true },
  );

  let tagged = 0;
  if (searched) {
    await rec.step(
      `tag ${ROWS} result rows with key ${shortcut}`,
      async () => {
        // One click per row: J did not move the active row on the search grid when measured.
        for (let n = 0; n < ROWS; n += 1) {
          await rec.click(page.locator(`[role="grid"] [role="row"][aria-rowindex="${n + 2}"]`).first());
          await rec.press(shortcut);
          tagged += 1;
        }
        await page.waitForTimeout(500);
        if (rec.blocked.length) throw new Error(`read-only guard blocked ${rec.blocked.length} write(s)`);
      },
      { goal: true },
    );
    await rec.step("tag count rose by the rows tagged (server)", async () => {
      if (tagCountBefore === null) throw new Error("no tag to verify");
      const deadline = Date.now() + STEP_TIMEOUT_MS;
      let after = tagCountBefore;
      while (Date.now() < deadline) {
        const tags = await apiGet<TagsPayload>(request, tagsPath);
        after = tags?.tags.find((t) => t.shortcut === Number(shortcut))?.count ?? after;
        if (after - tagCountBefore >= ROWS) break;
        await page.waitForTimeout(250);
      }
      rec.extra.tagCountDelta = after - tagCountBefore;
      if (after - tagCountBefore < ROWS)
        throw new Error(`tag count +${after - tagCountBefore}, expected +${ROWS}`);
    });
  } else {
    rec.skip(`tag ${ROWS} result rows`, "no search result rows", { goal: true });
  }
  rec.extra.keysPressedForTagging = tagged;
  rec.finish();
});
