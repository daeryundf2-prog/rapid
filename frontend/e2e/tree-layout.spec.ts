// T-015 (WB-1, visual audit 9·11·15): the evidence tree on the SYNTHETIC R8 rich fixture
// (frontend/e2e/r8_fixture.py, fake values only). Count badges sit fully inside the tree's client
// width (never under the scrollbar), the tree never scrolls sideways, nothing is italic, empty
// families read "자료 없음", and a filtered tree shows its first match right under the search field.
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Locator, type Page, test } from "@playwright/test";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";

let runId = "";

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  test.setTimeout(240_000);
  const output = join(mkdtempSync(join(tmpdir(), "rt-v2-e2e-tree-")), "run");
  execFileSync(python, [join("frontend", "e2e", "r8_fixture.py"), output], { cwd: repoRoot });
  const imported = await request.post("/api/runs/import", { headers: HEADERS, data: { output_dir: output } });
  expect(imported.status(), await imported.text()).toBe(201);
  runId = ((await imported.json()) as { run_id: string }).run_id;
  expect(runId).not.toBe("");
});

async function openTree(page: Page): Promise<Locator> {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, `#/case/${runId}/explore/artifacts/browser`);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
  // Below 900px the tree is a drawer behind "왼쪽 패널 열기".
  const drawer = page.getByRole("button", { name: "왼쪽 패널 열기" });
  if (await drawer.isVisible()) await drawer.click();
  const tree = page.getByRole("tree", { name: "케이스 탐색 트리" });
  await expect(tree).toBeVisible({ timeout: 20_000 });
  // Counts are shown once the first load settles.
  await expect(tree.locator(".badge").first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("tree-empty-toggle")).toBeVisible({ timeout: 20_000 });
  return tree;
}

/** Opens every collapsed branch (bounded) so the deepest, longest labels are on screen. */
async function expandAll(tree: Locator) {
  for (let round = 0; round < 6; round += 1) {
    const closed = tree.locator('[role="treeitem"][aria-expanded="false"] > .case-tree-twisty');
    const n = await closed.count();
    if (n === 0) return;
    for (let i = n - 1; i >= 0; i -= 1) await closed.nth(i).click();
  }
}

type Overflow = { tree: { scrollWidth: number; clientWidth: number }; cut: string[]; italic: string[] };

async function measure(tree: Locator): Promise<Overflow> {
  return tree.evaluate((el) => {
    const box = el.getBoundingClientRect();
    const inner = box.left + el.clientLeft + el.clientWidth;
    const cut: string[] = [];
    const italic: string[] = [];
    for (const item of el.querySelectorAll<HTMLElement>('[role="treeitem"]')) {
      const badge = item.querySelector<HTMLElement>(":scope > .badge");
      const name = item.getAttribute("aria-label") ?? "";
      if (badge) {
        const rect = badge.getBoundingClientRect();
        if (rect.right > inner + 0.5 || badge.scrollWidth > badge.clientWidth) {
          cut.push(`${name}: right ${rect.right.toFixed(1)} > ${inner.toFixed(1)}`);
        }
      }
      for (const node of [item, ...item.querySelectorAll<HTMLElement>("*")]) {
        if (getComputedStyle(node).fontStyle === "italic") italic.push(name);
      }
    }
    return { tree: { scrollWidth: el.scrollWidth, clientWidth: el.clientWidth }, cut, italic };
  });
}

for (const width of [880, 1280]) {
  test(`tree badges fit inside the tree at ${width}px, no sideways scroll, no italics`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const tree = await openTree(page);
    await page.getByTestId("tree-empty-toggle").click();
    await expect(page.getByTestId("tree-empty-toggle")).toHaveAttribute("aria-pressed", "true");
    await expandAll(tree);
    // The tree is long enough to scroll: the vertical scrollbar is there while we measure.
    const scrolls = await tree.evaluate((el) => el.scrollHeight > el.clientHeight);
    expect(scrolls).toBe(true);
    const result = await measure(tree);
    expect(result.tree.scrollWidth).toBeLessThanOrEqual(result.tree.clientWidth);
    expect(result.cut).toEqual([]);
    expect(result.italic).toEqual([]);
    // Empty families shown by the toggle read "자료 없음" where the count would be.
    const empty = tree.locator('[role="treeitem"][data-hidden-empty]');
    expect(await empty.count()).toBeGreaterThan(0);
    await expect(empty.first().locator(":scope > .badge")).toHaveText("자료 없음");
    // The tree's accessible names keep the counts.
    await expect(tree.getByRole("treeitem", { name: /^브라우저 전체, \d/ }).first()).toBeVisible();
  });
}

test("a filtered tree shows its first match right under the search field", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  const tree = await openTree(page);
  // Scroll the full tree down first: the filtered list must not keep a stale offset.
  await expandAll(tree);
  await tree.evaluate((el) => {
    el.scrollTop = el.scrollHeight;
  });
  await page.getByRole("searchbox", { name: "트리 검색" }).fill("해시");
  const items = tree.getByRole("treeitem");
  await expect(items.first()).toBeVisible();
  const layout = await tree.evaluate((el) => {
    const top = el.getBoundingClientRect().top + el.clientTop;
    const rows = [...el.querySelectorAll<HTMLElement>('[role="treeitem"]')].map((li) =>
      li.getBoundingClientRect(),
    );
    const gaps = rows.slice(1).map((rect, i) => rect.top - (rows[i]?.bottom ?? rect.top));
    return { first: (rows[0]?.top ?? 0) - top, rowHeight: rows[0]?.height ?? 0, gaps, count: rows.length };
  });
  expect(layout.count).toBeGreaterThan(0);
  expect(layout.first).toBeGreaterThanOrEqual(0);
  expect(layout.first).toBeLessThanOrEqual(layout.rowHeight);
  for (const gap of layout.gaps) expect(gap).toBeLessThanOrEqual(layout.rowHeight);
});
