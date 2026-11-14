// AXIOM adoption E3 (plan §4 Q-X8, Q-X10, Q-X12): case tags with keys, tree tag counts =
// grid rows, soft delete; classic split / media blur kept across reloads; histogram baseline
// save + compare; 관련 미디어 n = same-hash files. Runs against a synthetic folder with three
// copies of one picture (no evidence data).
import { copyFileSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type APIRequestContext, expect, type Page, test } from "@playwright/test";
import { COPY, copyPattern, escapeRegExp } from "../src/contracts/copy";
import { TEST_IDS } from "../src/contracts/testIds";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";
let caseId = "";

// Test data: the tags this spec creates (names typed by the examiner, not UI copy).
const TAG_A = "증거 A";
const TAG_B = "증거 B";
const TAG_C = "증거 C";

test.beforeAll(async ({ request }) => {
  test.setTimeout(240_000);
  const base = mkdtempSync(join(tmpdir(), "rt-v2-e3-"));
  const root = join(base, "evidence");
  const pictures = join(root, "Users", "kim", "Pictures");
  mkdirSync(pictures, { recursive: true });
  // A real 1x1 PNG, copied three times (same hash) + one different picture and a text file.
  const png = Buffer.from(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489" +
      "0000000b49444154789c6360000200000500017a5eab3f0000000049454e44ae426082",
    "hex",
  );
  writeFileSync(join(pictures, "dup-1.png"), png);
  copyFileSync(join(pictures, "dup-1.png"), join(pictures, "dup-2.png"));
  copyFileSync(join(pictures, "dup-1.png"), join(pictures, "dup-3.png"));
  writeFileSync(join(pictures, "other.png"), Buffer.concat([png, Buffer.from("x")]));
  writeFileSync(join(root, "Users", "kim", "notes.txt"), "plain memo");
  const created = await request.post("/api/runs", {
    headers: HEADERS,
    data: { root, mode: "fraud", output_dir: join(base, "run"), read_only: true, wait: true },
    timeout: 200_000,
  });
  expect(created.status(), await created.text()).toBe(202);
  runId = ((await created.json()) as { run_id: string }).run_id;
  const ensured = await request.post(`/api/runs/${runId}/case-db/ensure`, { headers: HEADERS, data: {} });
  expect(ensured.status()).toBe(200);
  caseId = ((await ensured.json()) as { case_id: string }).case_id;
});

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await page.evaluate((h) => {
    window.location.hash = h;
  }, hash);
  await expect(page.getByTestId(TEST_IDS.workbenchShell)).toBeVisible();
}

/** Subset of the a11y.spec rules for the new screens: names, labels, ids, aria-hidden, live regions. */
async function audit(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const out: string[] = [];
    const visible = (el: Element) => {
      const s = getComputedStyle(el);
      return s.display !== "none" && s.visibility !== "hidden" && !el.closest("[hidden],[inert]");
    };
    const nameOf = (el: Element) =>
      (el.getAttribute("aria-label") ?? "").trim() ||
      (el.getAttribute("aria-labelledby") ?? "")
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.textContent?.trim() ?? "")
        .join(" ")
        .trim() ||
      (el.textContent ?? "").trim() ||
      (el.getAttribute("title") ?? "").trim();
    for (const el of document.querySelectorAll("button,a[href],[role=button],[role=link]")) {
      if (visible(el) && !nameOf(el)) out.push(`accessible-name ${el.outerHTML.slice(0, 80)}`);
    }
    for (const el of document.querySelectorAll("input:not([type=hidden]),select,textarea")) {
      if (visible(el) && !((el as HTMLInputElement).labels?.length || nameOf(el))) {
        out.push(`field-name ${el.outerHTML.slice(0, 80)}`);
      }
    }
    const seen = new Map<string, number>();
    for (const el of document.querySelectorAll("[id]")) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
    for (const [id, n] of seen) if (n > 1) out.push(`duplicate-id #${id} x${n}`);
    for (const el of document.querySelectorAll("[aria-hidden=true]")) {
      if (el.querySelector("a[href],button:not([disabled]),input,select,textarea,[tabindex='0']")) {
        out.push(`aria-hidden-focusable ${el.outerHTML.slice(0, 80)}`);
      }
    }
    const polite = document.querySelectorAll("[aria-live=polite],[role=status]").length;
    if (polite !== 1) out.push(`live-polite ${polite}`);
    return out;
  });
}

/** `files:/candidates/3` → `/candidates/3` (the locator the review batch targets). */
function locatorOf(rowKey: string | null): string {
  return (rowKey ?? "").replace(/^[^/]*/, "");
}

async function tagIds(request: APIRequestContext): Promise<Map<string, number>> {
  const response = await request.get(`/api/cases/${caseId}/tags?run_id=${runId}`, { headers: HEADERS });
  const tags = ((await response.json()) as { tags: Array<{ id: number; name: string }> }).tags;
  return new Map(tags.map((tag) => [tag.name, tag.id]));
}

type BatchBody = {
  targets: Array<{ locator?: string }>;
  tag_ids?: number[];
  remove_tag_ids?: number[];
  propagate_by_hash?: boolean;
};

function batchResponse(page: Page) {
  return page.waitForResponse((r) => r.url().includes("/api/case-db/review-batch") && r.ok());
}

async function createTag(page: Page, name: string, color: string, key: string) {
  const dialog = page.getByRole("dialog", { name: COPY.review.manageTags });
  await dialog.getByTestId(TEST_IDS.tagNew).click();
  const form = dialog.getByRole("form", { name: COPY.review.newTag });
  await form.getByLabel(COPY.common.name).fill(name);
  await form.getByLabel(color).check();
  await form.getByLabel(COPY.common.shortcut).selectOption(key);
  await form.getByTestId(TEST_IDS.tagSave).click();
  await expect(dialog.getByRole("rowheader", { name: new RegExp(escapeRegExp(name)) })).toBeVisible();
}

test("Q-X8: three tags with colours and keys, key tagging in the viewer, tree count = grid rows, soft delete", async ({
  page,
  request,
}) => {
  await open(page, `#/case/${runId}/review/board`);
  const opener = page.getByRole("button", { name: COPY.review.manageTagsOpener });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: COPY.review.manageTags });
  await expect(dialog).toBeVisible();
  await createTag(page, TAG_A, COPY.review.colors.red, "6");
  await createTag(page, TAG_B, COPY.review.colors.green, "7");
  await createTag(page, TAG_C, COPY.review.colors.purple, "8");
  // A taken key is offered disabled with its owner.
  await dialog.getByTestId(TEST_IDS.tagNew).click();
  const taken = dialog.locator("select option[value='6']");
  await expect(taken).toBeDisabled();
  await expect(taken).toContainText(TAG_A);
  expect(await audit(page)).toEqual([]);
  // Esc closes the form first, then the dialog; focus returns to the opener.
  await page.keyboard.press("Escape");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(opener).toBeFocused();

  // Tag two file rows with keys 6 and 7: focus a row, open it in the viewer, press the key there.
  await open(page, `#/case/${runId}/explore/files`);
  const rows = page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');
  await expect(rows.first()).toBeVisible();
  const ids = await tagIds(request);
  const firstKey = await rows.nth(0).getAttribute("data-row-key");
  const secondKey = await rows.nth(1).getAttribute("data-row-key");
  expect(firstKey).not.toBe(secondKey);
  await rows.nth(0).click();
  await page.keyboard.press("Enter");
  const viewer = page.getByRole("region", { name: COPY.viewer.region });
  await expect(viewer).toBeVisible();
  let batch = batchResponse(page);
  await page.keyboard.press("6");
  // Key 6 went to exactly the first row, with 증거 A's id.
  const sixth = (await batch).request().postDataJSON() as BatchBody;
  expect(sixth.targets.map((t) => t.locator)).toEqual([locatorOf(firstKey)]);
  expect(sixth.tag_ids).toEqual([ids.get(TAG_A)]);
  await rows.nth(1).click();
  batch = batchResponse(page);
  await page.keyboard.press("7");
  // Key 7 went to exactly the second row, with 증거 B's id.
  const seventh = (await batch).request().postDataJSON() as BatchBody;
  expect(seventh.targets.map((t) => t.locator)).toEqual([locatorOf(secondKey)]);
  expect(seventh.tag_ids).toEqual([ids.get(TAG_B)]);

  // 검토 tree: tag nodes with counts; the review board filtered to a tag shows that many rows.
  await open(page, `#/case/${runId}/review/board`);
  const nodeA = page.getByRole("link", { name: COPY.review.tagNode(TAG_A, "6", 1), exact: true });
  await expect(nodeA).toBeVisible();
  await expect(
    page.getByRole("link", { name: COPY.review.tagNode(TAG_B, "7", 1), exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("link", { name: COPY.review.tagNode(TAG_C, "8", 0), exact: true }),
  ).toBeVisible();
  await nodeA.click();
  const boardRows = page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');
  await expect(boardRows).toHaveCount(1);
  expect(await audit(page)).toEqual([]);

  // Soft delete: the node goes, the mark loses the tag, the tag row stays with deleted_at.
  await page.getByRole("button", { name: COPY.review.manageTagsOpener }).click();
  await dialog.getByRole("button", { name: COPY.review.deleteTag(TAG_A) }).click();
  await dialog
    .getByRole("group", { name: COPY.review.deleteTagConfirm })
    .getByRole("button", { name: COPY.common.delete })
    .click();
  await expect(dialog.getByRole("rowheader", { name: new RegExp(escapeRegExp(TAG_A)) })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("link", { name: new RegExp(`^${escapeRegExp(TAG_A)},`) })).toHaveCount(0);
  const tags = await request.get(`/api/cases/${caseId}/tags?run_id=${runId}&include_deleted=true`, {
    headers: HEADERS,
  });
  const deleted = (
    (await tags.json()) as { tags: Array<{ name: string; deleted_at: string | null }> }
  ).tags.find((tag) => tag.name === TAG_A);
  expect(deleted?.deleted_at).toBeTruthy();
  const map = await request.get(`/api/runs/${runId}/review-map`, { headers: HEADERS });
  const marks = ((await map.json()) as { marks: Array<{ tags: string[] }> }).marks;
  expect(marks.some((mark) => mark.tags.includes(TAG_A))).toBe(false);
});

test("Q-X10: classic split and media blur survive a reload; baseline compare; 관련 미디어 n", async ({
  page,
  request,
}) => {
  // Classic split: ` toggles, a reload keeps it.
  await open(page, `#/case/${runId}/explore/files`);
  await expect(page.getByRole("grid").first()).toBeVisible();
  await page.locator("body").focus();
  await page.keyboard.press("Backquote");
  await expect(page.getByTestId(TEST_IDS.workbenchShell)).toHaveAttribute("data-split", "classic");
  await expect(page.getByRole("complementary", { name: COPY.viewer.bottomPanel })).toBeVisible();
  expect(await audit(page)).toEqual([]);
  await page.reload();
  await expect(page.getByTestId(TEST_IDS.workbenchShell)).toHaveAttribute("data-split", "classic");
  await page.locator("body").focus();
  await page.keyboard.press("Backquote");
  await expect(page.getByTestId(TEST_IDS.workbenchShell)).not.toHaveAttribute("data-split", "classic");

  // Histogram baseline: save the run's counts, compare: one row per category, deltas 0.
  await open(page, `#/case/${runId}/explore/artifacts?view=histogram`);
  await page.getByRole("button", { name: COPY.histogram.saveBaseline }).click();
  await page.getByLabel(COPY.histogram.baselineName).fill("after processing");
  await page.getByTestId(TEST_IDS.baselineSave).click();
  const compare = page.getByTestId(TEST_IDS.histCompare);
  await expect(compare).toBeVisible();
  const server = await request.get(`/api/runs/${runId}/histogram`, { headers: HEADERS });
  const bars = ((await server.json()) as { bars: unknown[] }).bars;
  await expect(compare.getByTestId(TEST_IDS.histCompareRow)).toHaveCount(bars.length);
  await expect(compare.getByTestId(TEST_IDS.histCompareRow).first()).toHaveAttribute(
    "aria-label",
    new RegExp(`${escapeRegExp(COPY.histogram.compareRow(0))}$`),
  );
  expect(await audit(page)).toEqual([]);

  // Media blur in the gallery: Shift+B, kept after a reload; the duplicate picture's badge.
  await open(page, `#/case/${runId}/explore/files?view=thumbnails`);
  const toggle = page.getByTestId(TEST_IDS.mediaBlurToggle);
  await expect(toggle).toBeVisible();
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await page.reload();
  await expect(page.getByTestId(TEST_IDS.mediaBlurToggle)).toHaveAttribute("aria-pressed", "true");
  await expect(
    page.locator("[data-media-blur]").filter({
      has: page.getByRole("grid", { name: new RegExp(`^${escapeRegExp(COPY.grid.thumbnails)}`) }),
    }),
  ).toHaveAttribute("data-media-blur", "");
  const dupTile = page.getByRole("gridcell", { name: /^dup-1\.png/ });
  await dupTile.click();
  const related = await request.get(
    `/api/runs/${runId}/related-media?path=${encodeURIComponent(
      (
        (await (
          await request.get(`/api/runs/${runId}/files?offset=0&limit=100`, { headers: HEADERS })
        ).json()) as {
          candidates: Array<{ path: string }>;
        }
      ).candidates.find((row) => row.path.endsWith("dup-1.png"))?.path ?? "",
    )}`,
    { headers: HEADERS },
  );
  const n = ((await related.json()) as { count: number }).count;
  expect(n).toBe(2);
  await expect(page.getByRole("button", { name: COPY.viewer.relatedMedia(n) })).toBeVisible();
  expect(await audit(page)).toEqual([]);
  // Turn it off again for the next run of the suite.
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(page.getByTestId(TEST_IDS.mediaBlurToggle)).toHaveAttribute("aria-pressed", "false");
});

test("E3 fixes: propagation from the viewer acts on the viewer row; a tag key toggles after the refetch; the gallery strip blurs", async ({
  page,
  request,
}) => {
  // State from Q-X8: the second file row carries 증거 B (key 7).
  const ids = await tagIds(request);
  await open(page, `#/case/${runId}/explore/files`);
  const rows = page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');
  await expect(rows.nth(2)).toBeVisible();
  // The row tagged 증거 B by key 7 (grid order may differ between tests: find it by locator).
  const map = await request.get(`/api/runs/${runId}/review-map`, { headers: HEADERS });
  const marks = ((await map.json()) as { marks: Array<{ tags: string[]; locator: string }> }).marks;
  const taggedLocator = marks.find((mark) => mark.tags.includes(TAG_B))?.locator ?? "";
  expect(taggedLocator).not.toBe("");
  const viewerKey = `files:${taggedLocator}`;
  const tagged = page.locator(`[role="grid"] [role="row"][data-row-key="${viewerKey}"]`);
  const other = page.locator(
    `[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"]):not([data-row-key="${viewerKey}"])`,
  );
  await tagged.click();
  // The grid selection is another row (checkbox: focus and the viewer stay on the tagged row).
  await other.first().locator('input[type="checkbox"]').check();
  await expect(other.first()).toHaveAttribute("aria-selected", "true");
  const viewer = page.getByRole("region", { name: COPY.viewer.region });
  await expect(viewer).toBeVisible();

  // 더보기 › 같은 해시 행에 태그 전파: the default spreads the row's user tags. With one user tag
  // the per-tag entry would repeat the default, so it is not listed (C-W8).
  await page.getByTestId(TEST_IDS.viewerActionsMenu).click();
  const menu = page.getByRole("menu", { name: COPY.common.more });
  await expect(menu.getByRole("menuitem", { name: COPY.review.propagateOnly(TAG_B) })).toHaveCount(0);
  const batch = batchResponse(page);
  await menu.getByRole("menuitem", { name: COPY.review.propagateByHash(TAG_B) }).click();
  const propagated = (await batch).request().postDataJSON() as BatchBody;
  expect(propagated.propagate_by_hash).toBe(true);
  expect(propagated.tag_ids).toEqual([ids.get(TAG_B)]);
  expect(propagated.targets.map((t) => t.locator)).toEqual([locatorOf(viewerKey)]);
  await expect(
    page.getByText(new RegExp(copyPattern((count) => COPY.review.propagated(count, TAG_B)))).first(),
  ).toBeAttached();

  // Key 7 on the viewer row: off, then (after the refetch lands) on, then off again.
  await viewer.focus();
  for (const expected of ["remove", "add", "remove"] as const) {
    // A press while the previous toggle is still in flight (until its refetch lands) is ignored by
    // the app, so a retry is safe: press until one press posts a batch.
    let body: BatchBody | undefined;
    await expect(async () => {
      const posted = page.waitForRequest((r) => r.url().includes("/api/case-db/review-batch"), {
        timeout: 1500,
      });
      await page.keyboard.press("7");
      const request = await posted;
      expect((await request.response())?.ok()).toBe(true);
      body = request.postDataJSON() as BatchBody;
    }).toPass({ timeout: 30_000 });
    expect(body?.targets.map((t) => t.locator)).toEqual([locatorOf(viewerKey)]);
    if (expected === "remove") expect(body?.remove_tag_ids).toEqual([ids.get(TAG_B)]);
    else expect(body?.tag_ids).toEqual([ids.get(TAG_B)]);
  }

  // Gallery strip under 미디어 흐리게: every tile blurred; keyboard focus reveals one tile.
  await open(page, `#/case/${runId}/explore/files`);
  const dup = rows.filter({ hasText: "dup-1.png" }).first();
  await expect(dup).toBeVisible();
  await dup.click();
  const imageTab = viewer.getByRole("tab", { name: COPY.viewer.tabImage });
  if (await imageTab.count()) await imageTab.first().click();
  const strip = page.getByTestId(TEST_IDS.imageStrip);
  await expect(strip.locator("button img").first()).toBeVisible({ timeout: 15_000 });
  // The strip fills in after its first tile: wait for the others before reading their filters.
  await expect.poll(() => strip.locator("button img").count(), { timeout: 15_000 }).toBeGreaterThan(1);
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(page.getByTestId(TEST_IDS.imageView)).toHaveAttribute("data-media-blur", "on");
  const filters = await strip
    .locator("button img")
    .evaluateAll((imgs) => imgs.map((img) => getComputedStyle(img).filter));
  expect(filters.length).toBeGreaterThan(1);
  for (const filter of filters) expect(filter).toContain("blur");
  const tile = strip.locator("button:not([aria-current])").first();
  await tile.focus();
  await expect.poll(() => tile.locator("img").evaluate((img) => getComputedStyle(img).filter)).toBe("none");
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(page.getByTestId(TEST_IDS.imageView)).not.toHaveAttribute("data-media-blur", "on");
});
