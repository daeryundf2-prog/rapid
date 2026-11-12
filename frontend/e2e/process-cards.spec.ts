import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Locator, type Page, test } from "@playwright/test";

// T-016 (visual audit #10, GAP-078, QA-094): on the 처리 stage a two-line card title never
// overlaps the line under it, and the analysis-card grid leaves empty cells only in its last row.
// Measured on element boxes at 880–1920 with a middle card selected (it spans the whole row).
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const WIDTHS = [880, 1024, 1280, 1440, 1680, 1920];
const SELECTED = "ntfs-meta"; // "NTFS 메타(MFT/USN)": the longest label, third card.

let runId = "";

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-process-cards-"));
  const created = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  if (created.status() !== 201) {
    throw new Error(`POST /api/sample-case/run returned ${created.status()}: ${await created.text()}`);
  }
  runId = ((await created.json()) as { run?: { run_id?: string } }).run?.run_id ?? "";
  if (!runId) throw new Error("sample case was created (201) but no run_id was found");
});

type Box = { x: number; y: number; width: number; height: number };

async function box(locator: Locator): Promise<Box> {
  const found = await locator.boundingBox();
  if (!found) throw new Error("element has no box");
  return found;
}

/** Strict intersection (touching edges is fine; 0.5px tolerance for subpixel rounding). */
function intersects(a: Box, b: Box): boolean {
  const eps = 0.5;
  return (
    a.x + a.width - eps > b.x &&
    b.x + b.width - eps > a.x &&
    a.y + a.height - eps > b.y &&
    b.y + b.height - eps > a.y
  );
}

async function openProcess(page: Page, width: number) {
  await page.setViewportSize({ width, height: 900 });
  await page.goto(`/v2/#token=${TOKEN}`);
  await page.getByTestId("stage-rail").waitFor({ timeout: 15_000 });
  await page.evaluate(
    ([run, kind]) => {
      window.location.hash = `#/case/${run}/process/${kind}`;
    },
    [runId, SELECTED] as const,
  );
  await expect(page.getByTestId(`analysis-card-${SELECTED}`)).toBeVisible({ timeout: 20_000 });
}

for (const width of WIDTHS) {
  test(`T-016 @${width}: process-card titles do not overlap the line below`, async ({ page }) => {
    await openProcess(page, width);
    const panel = page.getByTestId("process-panel");
    // Below 900px the left panel is a closed drawer: open it with the rail's 패널 button.
    if (!(await panel.isVisible())) await page.getByTestId("tree-toggle").click();
    await expect(panel).toBeVisible();
    const cards = panel.locator('li[data-testid^="process-analysis-"]');
    const count = await cards.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i += 1) {
      const card = cards.nth(i);
      const link = card.locator("a").first();
      const title = link.locator("span").first();
      // The meta line is the card's second child (after the link).
      const meta = card.locator(":scope > span").first();
      const [cardBox, titleBox, metaBox, linkBox] = await Promise.all([
        box(card),
        box(title),
        box(meta),
        box(link),
      ]);
      const name = await title.innerText();
      expect(intersects(titleBox, metaBox), `${name}: title × meta at ${width}`).toBe(false);
      expect(intersects(linkBox, metaBox), `${name}: title row × meta at ${width}`).toBe(false);
      // Both lines sit inside the card border.
      expect(metaBox.y + metaBox.height, `${name}: meta inside card`).toBeLessThanOrEqual(
        cardBox.y + cardBox.height + 0.5,
      );
      expect(titleBox.y, `${name}: title inside card`).toBeGreaterThanOrEqual(cardBox.y - 0.5);
    }
  });

  test(`T-016 @${width}: analysis cards — no overlap, holes only in the last row`, async ({ page }) => {
    await openProcess(page, width);
    const cards = page.locator('section[data-testid^="analysis-card-"]');
    const count = await cards.count();
    expect(count).toBeGreaterThan(1);
    const boxes: Box[] = [];
    for (let i = 0; i < count; i += 1) {
      const card = cards.nth(i);
      const [heading, desc] = [card.locator("h3").first(), card.locator("p").first()];
      const [h, d] = await Promise.all([box(heading), box(desc)]);
      expect(intersects(h, d), `card ${i}: heading × description at ${width}`).toBe(false);
      boxes.push(await box(card));
    }
    for (let i = 0; i < boxes.length; i += 1) {
      for (let j = i + 1; j < boxes.length; j += 1) {
        expect(intersects(boxes[i] as Box, boxes[j] as Box), `cards ${i} × ${j} at ${width}`).toBe(false);
      }
    }
    // Rows by top edge; every row but the last reaches the grid's right edge.
    const gridRight = await cards
      .first()
      .evaluate((el) => (el.parentElement as HTMLElement).getBoundingClientRect().right);
    const rows = new Map<number, number>();
    for (const b of boxes) {
      const top = Math.round(b.y);
      rows.set(top, Math.max(rows.get(top) ?? 0, b.x + b.width));
    }
    const tops = [...rows.keys()].sort((a, b) => a - b);
    for (const top of tops.slice(0, -1)) {
      expect(rows.get(top) as number, `row at y=${top} has a hole at ${width}`).toBeGreaterThan(
        gridRight - 2,
      );
    }
  });
}
