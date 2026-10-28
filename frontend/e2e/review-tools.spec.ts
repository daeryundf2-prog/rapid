// AXIOM adoption E3 (plan §4 Q-X8, Q-X10, Q-X12): case tags with keys, tree tag counts =
// grid rows, soft delete; classic split / media blur kept across reloads; histogram baseline
// save + compare; 관련 미디어 n = same-hash files. Runs against a synthetic folder with three
// copies of one picture (no evidence data).
import { copyFileSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type APIRequestContext, expect, type Page, test } from "@playwright/test";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";
let caseId = "";

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
  writeFileSync(join(root, "Users", "kim", "notes.txt"), "평범한 메모");
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
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
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
  const dialog = page.getByRole("dialog", { name: "태그 관리" });
  await dialog.getByTestId("tag-new").click();
  const form = dialog.getByRole("form", { name: "새 태그" });
  await form.getByLabel("이름").fill(name);
  await form.getByLabel(color).check();
  await form.getByLabel("단축키").selectOption(key);
  await form.getByTestId("tag-save").click();
  await expect(dialog.getByRole("rowheader", { name: new RegExp(name) })).toBeVisible();
}

test("Q-X8: three tags with colours and keys, key tagging in the viewer, tree count = grid rows, soft delete", async ({
  page,
  request,
}) => {
  await open(page, `#/case/${runId}/review/board`);
  const opener = page.getByRole("button", { name: "태그 관리…" });
  await opener.click();
  const dialog = page.getByRole("dialog", { name: "태그 관리" });
  await expect(dialog).toBeVisible();
  await createTag(page, "증거 A", "빨강", "6");
  await createTag(page, "증거 B", "초록", "7");
  await createTag(page, "증거 C", "보라", "8");
  // A taken key is offered disabled with its owner.
  await dialog.getByTestId("tag-new").click();
  const taken = dialog.locator("select option[value='6']");
  await expect(taken).toBeDisabled();
  await expect(taken).toContainText("증거 A");
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
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await expect(viewer).toBeVisible();
  let batch = batchResponse(page);
  await page.keyboard.press("6");
  // Key 6 went to exactly the first row, with 증거 A's id.
  const sixth = (await batch).request().postDataJSON() as BatchBody;
  expect(sixth.targets.map((t) => t.locator)).toEqual([locatorOf(firstKey)]);
  expect(sixth.tag_ids).toEqual([ids.get("증거 A")]);
  await rows.nth(1).click();
  batch = batchResponse(page);
  await page.keyboard.press("7");
  // Key 7 went to exactly the second row, with 증거 B's id.
  const seventh = (await batch).request().postDataJSON() as BatchBody;
  expect(seventh.targets.map((t) => t.locator)).toEqual([locatorOf(secondKey)]);
  expect(seventh.tag_ids).toEqual([ids.get("증거 B")]);

  // 검토 tree: tag nodes with counts; the review board filtered to a tag shows that many rows.
  await open(page, `#/case/${runId}/review/board`);
  const nodeA = page.getByRole("link", { name: /^증거 A, 단축키 6, 1건$/ });
  await expect(nodeA).toBeVisible();
  await expect(page.getByRole("link", { name: /^증거 B, 단축키 7, 1건$/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /^증거 C, 단축키 8, 0건$/ })).toBeVisible();
  await nodeA.click();
  const boardRows = page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');
  await expect(boardRows).toHaveCount(1);
  expect(await audit(page)).toEqual([]);

  // Soft delete: the node goes, the mark loses the tag, the tag row stays with deleted_at.
  await page.getByRole("button", { name: "태그 관리…" }).click();
  await dialog.getByRole("button", { name: "증거 A 태그 삭제" }).click();
  await dialog.getByRole("group", { name: "태그 삭제 확인" }).getByRole("button", { name: "삭제" }).click();
  await expect(dialog.getByRole("rowheader", { name: /증거 A/ })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("link", { name: /^증거 A,/ })).toHaveCount(0);
  const tags = await request.get(`/api/cases/${caseId}/tags?run_id=${runId}&include_deleted=true`, {
    headers: HEADERS,
  });
  const deleted = (
    (await tags.json()) as { tags: Array<{ name: string; deleted_at: string | null }> }
  ).tags.find((tag) => tag.name === "증거 A");
  expect(deleted?.deleted_at).toBeTruthy();
  const map = await request.get(`/api/runs/${runId}/review-map`, { headers: HEADERS });
  const marks = ((await map.json()) as { marks: Array<{ tags: string[] }> }).marks;
  expect(marks.some((mark) => mark.tags.includes("증거 A"))).toBe(false);
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
  await expect(page.getByTestId("workbench-shell")).toHaveAttribute("data-split", "classic");
  await expect(page.getByRole("complementary", { name: "뷰어 패널 (아래)" })).toBeVisible();
  expect(await audit(page)).toEqual([]);
  await page.reload();
  await expect(page.getByTestId("workbench-shell")).toHaveAttribute("data-split", "classic");
  await page.locator("body").focus();
  await page.keyboard.press("Backquote");
  await expect(page.getByTestId("workbench-shell")).not.toHaveAttribute("data-split", "classic");

  // Histogram baseline: save the run's counts, compare: one row per category, deltas 0.
  await open(page, `#/case/${runId}/explore/artifacts?view=histogram`);
  await page.getByRole("button", { name: "현재 건수를 기준선으로 저장…" }).click();
  await page.getByLabel("기준선 이름").fill("처리 직후");
  await page.getByTestId("baseline-save").click();
  const compare = page.getByTestId("hist-compare");
  await expect(compare).toBeVisible();
  const server = await request.get(`/api/runs/${runId}/histogram`, { headers: HEADERS });
  const bars = ((await server.json()) as { bars: unknown[] }).bars;
  await expect(compare.getByTestId("hist-compare-row")).toHaveCount(bars.length);
  await expect(compare.getByTestId("hist-compare-row").first()).toHaveAttribute(
    "aria-label",
    /증감 0, 노드 열기$/,
  );
  expect(await audit(page)).toEqual([]);

  // Media blur in the gallery: Shift+B, kept after a reload; the duplicate picture's badge.
  await open(page, `#/case/${runId}/explore/files?view=thumbnails`);
  const toggle = page.getByTestId("media-blur-toggle");
  await expect(toggle).toBeVisible();
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await page.reload();
  await expect(page.getByTestId("media-blur-toggle")).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".thumb-view")).toHaveAttribute("data-media-blur", "");
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
  await expect(page.getByRole("button", { name: `관련 미디어 ${n}` })).toBeVisible();
  expect(await audit(page)).toEqual([]);
  // Turn it off again for the next run of the suite.
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(page.getByTestId("media-blur-toggle")).toHaveAttribute("aria-pressed", "false");
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
  const taggedLocator = marks.find((mark) => mark.tags.includes("증거 B"))?.locator ?? "";
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
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await expect(viewer).toBeVisible();

  // 더보기 › 같은 해시 행에 태그 전파: the default spreads the row's user tags. With one user tag
  // the per-tag entry would repeat the default, so it is not listed (C-W8).
  await page.getByTestId("viewer-actions-menu").click();
  const menu = page.getByRole("menu", { name: "더보기" });
  await expect(menu.getByRole("menuitem", { name: "'증거 B'만 전파" })).toHaveCount(0);
  let batch = batchResponse(page);
  await menu.getByRole("menuitem", { name: "같은 해시 행에 태그 전파 (증거 B)" }).click();
  const propagated = (await batch).request().postDataJSON() as BatchBody;
  expect(propagated.propagate_by_hash).toBe(true);
  expect(propagated.tag_ids).toEqual([ids.get("증거 B")]);
  expect(propagated.targets.map((t) => t.locator)).toEqual([locatorOf(viewerKey)]);
  await expect(
    page.getByText(/같은 해시 행 \d+건에 태그 '증거 B'을\(를\) 전파했습니다/).first(),
  ).toBeAttached();

  // Key 7 on the viewer row: off, then (after the refetch lands) on, then off again.
  await viewer.focus();
  for (const expected of ["remove", "add", "remove"] as const) {
    batch = batchResponse(page);
    await page.keyboard.press("7");
    const body = (await batch).request().postDataJSON() as BatchBody;
    expect(body.targets.map((t) => t.locator)).toEqual([locatorOf(viewerKey)]);
    if (expected === "remove") expect(body.remove_tag_ids).toEqual([ids.get("증거 B")]);
    else expect(body.tag_ids).toEqual([ids.get("증거 B")]);
    await page.waitForTimeout(800); // the grid refetch lands before the next press
  }

  // Gallery strip under 미디어 흐리게: every tile blurred; keyboard focus reveals one tile.
  await open(page, `#/case/${runId}/explore/files`);
  const dup = rows.filter({ hasText: "dup-1.png" }).first();
  await expect(dup).toBeVisible();
  await dup.click();
  const imageTab = viewer.getByRole("tab", { name: /이미지/ });
  if (await imageTab.count()) await imageTab.first().click();
  const strip = page.locator(".image-strip");
  await expect(strip.locator("img.image-thumb-img").first()).toBeVisible({ timeout: 15_000 });
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(page.locator(".image-view")).toHaveAttribute("data-media-blur", "on");
  const filters = await strip
    .locator("img.image-thumb-img")
    .evaluateAll((imgs) => imgs.map((img) => getComputedStyle(img).filter));
  expect(filters.length).toBeGreaterThan(1);
  for (const filter of filters) expect(filter).toContain("blur");
  const tile = strip.locator("button.image-thumb:not(.is-current)").first();
  await tile.focus();
  await expect
    .poll(() => tile.locator("img.image-thumb-img").evaluate((img) => getComputedStyle(img).filter))
    .toBe("none");
  await page.locator("body").focus();
  await page.keyboard.press("Shift+KeyB");
  await expect(page.locator(".image-view")).not.toHaveAttribute("data-media-blur", "on");
});

test("R8 queue: N walks the unreviewed rows, a tag key reviews each, three distinct rows, keyboard only", async ({
  page,
}) => {
  // A user tag on a free digit (1–5 stay the system 우선순위 tags, which do not count as reviewed).
  await open(page, `#/case/${runId}/review/board`);
  await page.getByRole("button", { name: "태그 관리…" }).click();
  const dialog = page.getByRole("dialog", { name: "태그 관리" });
  await expect(dialog).toBeVisible();
  await createTag(page, "검토 완료", "빨강", "9");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  await open(page, `#/case/${runId}/explore/files`);
  const rows = page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');
  await expect(rows.first()).toBeVisible();
  const selected = page.locator('[role="grid"] [role="row"][aria-selected="true"]');
  await page.locator("body").focus();

  // The viewer's own load announcement can replace the queue sentence in the live region, so each
  // step is asserted on the selected row: N lands on a row that has not been tagged yet.
  const visited: string[] = [];
  for (let step = 0; step < 3; step++) {
    await page.keyboard.press("KeyN");
    await expect(selected).toHaveCount(1);
    await expect
      .poll(async () => visited.includes((await selected.getAttribute("data-row-key")) ?? ""))
      .toBe(false);
    const key = (await selected.getAttribute("data-row-key")) ?? "";
    expect(key).not.toBe("");
    visited.push(key);
    const batch = batchResponse(page);
    await page.keyboard.press("9");
    const body = (await batch).request().postDataJSON() as BatchBody;
    expect(body.targets.map((t) => t.locator)).toEqual([locatorOf(key)]);
  }
  expect(new Set(visited).size).toBe(3);
});
