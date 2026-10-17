import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

// viewer-families (docs/plans/viewer-families-2026-10-15.md §4): 조건 줄 + panel keyboard (Q-F1/Q-F2),
// the viewer window (Q-F3/Q-F4), catalogue family columns (Q-F5), 특이사항 filter (Q-F9) and the
// hidden empty families (Q-F12), against the sample case of the e2e server.
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

let runId = "";

test.use({ viewport: { width: 1440, height: 900 } });

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-families-"));
  const response = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(response.status()).toBe(201);
  const list = await request.get("/api/runs", { headers: HEADERS });
  runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  expect(runId).not.toBe("");
});

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId("grid-region")).toBeVisible();
}

test("Q-F1: one 조건 line ≤32px; F opens the panel, Esc closes it and focus returns", async ({ page }) => {
  await open(page, `#/case/${runId}/explore/files`);
  const line = page.locator(".filter-row").first();
  await expect(line).toBeVisible();
  const box = await line.boundingBox();
  expect(box?.height ?? 99).toBeLessThanOrEqual(32);
  // No condition: no chips.
  await expect(page.getByRole("list", { name: "적용된 조건" })).toHaveCount(0);
  // F from the grid (not a text field) opens the panel on its heading.
  await page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first().click();
  await page.keyboard.press("f");
  const panel = page.getByRole("dialog", { name: "조건" });
  await expect(panel).toBeVisible();
  await expect(panel.getByRole("heading", { name: "조건" })).toBeFocused();
  // 열 구성 / 밀도 live inside the panel.
  await expect(panel.getByRole("combobox", { name: "열 구성" })).toBeVisible();
  await expect(panel.getByRole("combobox", { name: "밀도" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(panel).toHaveCount(0);
  await expect(page.getByTestId("filter-popover-button")).toBeFocused();
});

test("Q-F2: conditions survive a reload as chips (URL unchanged); chip × refetches at once", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/explore/artifacts?types=browser-history&path=Chrome`);
  const chips = page.getByRole("list", { name: "적용된 조건" });
  await expect(chips.getByRole("listitem")).toHaveCount(2);
  const before = page.url();
  await page.reload();
  await expect(chips.getByRole("listitem")).toHaveCount(2);
  expect(page.url()).toBe(before);
  const refetch = page.waitForRequest(
    (req) => req.url().includes("/artifacts") && !req.url().includes("path_contains"),
  );
  await page.getByRole("button", { name: /^경로 Chrome 조건 제거$/ }).click();
  await refetch;
  await expect(chips.getByRole("listitem")).toHaveCount(1);
  expect(page.url()).not.toContain("path=");
});

test("Q-F3/Q-F4: Ctrl+Shift+V opens the viewer window; it follows J/K; closing it brings the pane back", async ({
  page,
  context,
}) => {
  await open(page, `#/case/${runId}/explore/files`);
  const first = page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first();
  await first.click();
  await expect(page.getByRole("region", { name: "원본 뷰어" })).toBeVisible();
  // A popup gets a copy of the opener's sessionStorage: move the main window's token to
  // localStorage (still signed in) so the viewer window's copy has none — its sessionStorage token
  // can then only come from the main window's postMessage (#14).
  await page.evaluate((token) => {
    window.localStorage.setItem("rapidtriage.authToken", token);
    window.sessionStorage.removeItem("rapidtriage.authToken");
  }, TOKEN);
  const popupPromise = context.waitForEvent("page");
  await page.keyboard.press("Control+Shift+V");
  const popup = await popupPromise;
  await popup.waitForLoadState();
  // Same bundle, popout mode, no token or route in its URL.
  expect(popup.url()).toMatch(/\/v2\/\?popout=viewer&host=[0-9a-f]{16}$/);
  expect(popup.url()).not.toContain("token");
  await expect(popup.getByTestId("popout-shell")).toBeVisible();
  await expect(popup.getByRole("region", { name: "원본 뷰어" })).toBeVisible();
  await expect(popup).toHaveTitle(/^뷰어 — .+/);
  const firstTitle = await popup.title();
  // The main pane is a rail that says where the viewer is.
  await expect(page.getByTestId("viewer-popout-rail")).toBeVisible();
  await expect(page.getByRole("button", { name: /창으로 보는 중 · 되돌리기/ })).toBeVisible();
  // J in the main grid → the window follows quickly.
  await first.focus();
  const started = Date.now();
  await page.keyboard.press("j");
  await expect(popup).not.toHaveTitle(firstTitle, { timeout: 2000 });
  const elapsed = Date.now() - started;
  test.info().annotations.push({ type: "popout-follow-ms", description: String(elapsed) });
  // R inside the window marks the same row in the main window (its grid shows the status).
  await popup.locator("body").press("r");
  await expect(page.locator('[role="grid"] [role="row"][aria-rowindex="3"]').first()).toContainText(
    "관련 있음",
    {
      timeout: 5000,
    },
  );
  // The token reached the window by postMessage (its sessionStorage copy had none), never the URL.
  const stored = await popup.evaluate(() => window.sessionStorage.getItem("rapidtriage.authToken"));
  expect(stored).toBe(TOKEN);
  // A route link inside the window opens in the main window; the window's own URL is untouched (#1).
  const popupUrl = popup.url();
  await popup.evaluate((run) => {
    const link = document.createElement("a");
    link.href = `#/case/${run}/explore/artifacts/browser`;
    link.textContent = "원본 아티팩트 행으로 이동";
    document.getElementById("viewer")?.appendChild(link);
    link.click();
    link.remove();
  }, runId);
  await expect(page).toHaveURL(new RegExp(`#/case/${runId}/explore/artifacts/browser`));
  expect(popup.url()).toBe(popupUrl);
  // Closing the window: the main pane comes back.
  await popup.close();
  await expect(page.getByTestId("viewer-popout-rail")).toHaveCount(0, { timeout: 5000 });
  // The link opened a list with no row selected: the pane is back as its ordinary rail.
  await expect(page.getByTestId("viewer-rail")).toBeVisible();
});

test("Q-F5: a catalogue family lays out its core columns in catalogue order", async ({ page, request }) => {
  const meta = await request.get("/api/meta/families", { headers: HEADERS });
  test.skip(!meta.ok(), "server has no /api/meta/families yet");
  const catalog = (await meta.json()) as {
    families: Array<{ id: string; kinds?: string[]; core_columns: Array<{ label: string }> }>;
  };
  const browser = catalog.families.filter((family) => family.kinds?.includes("browser"));
  test.skip(browser.length !== 1, "catalogue does not claim the browser kind exactly once");
  await open(page, `#/case/${runId}/explore/artifacts/browser`);
  await expect(page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first()).toBeVisible();
  const headers = await page.getByRole("columnheader").allInnerTexts();
  const labels = (browser[0]?.core_columns ?? []).map((column) => column.label);
  const shown = labels.filter((label) => headers.some((header) => header.trim().startsWith(label)));
  // Responsive hiding may drop empty core columns; the shown ones keep catalogue order.
  expect(shown.length).toBeGreaterThan(0);
  const order = shown.map((label) => headers.findIndex((header) => header.trim().startsWith(label)));
  expect([...order].sort((a, b) => a - b)).toEqual(order);
  await expect(page.getByRole("columnheader", { name: /항목/ })).toBeVisible();
});

test("Q-F9: flag_grade=B goes to the server; the grid total equals the tree's B 등급 이상 count", async ({
  page,
  request,
}) => {
  const tree = await request.get(`/api/runs/${runId}/tree`, { headers: HEADERS });
  const flags = ((await tree.json()) as { flags?: { by_grade?: Record<string, number> } }).flags;
  test.skip(!flags, "server has no 특이사항 summary in /tree");
  const expected = (flags?.by_grade?.A ?? 0) + (flags?.by_grade?.B ?? 0);
  const sent = page.waitForRequest((req) => /\/artifacts\?.*flag_grade=B/.test(req.url()));
  await open(page, `#/case/${runId}/explore/artifacts?flag_grade=B`);
  await sent;
  await expect(page.getByTestId("grid-footer-total")).toHaveText(`총 ${expected.toLocaleString("ko-KR")}건`);
  // Every loaded row carries an A or B flag.
  const cells = await page
    .locator('[role="grid"] [role="row"][data-index] [data-col="flags"] button')
    .evaluateAll((els) => els.map((el) => el.getAttribute("aria-label") ?? ""));
  for (const name of cells) expect(name).toMatch(/특이사항 (A|B) /);
  // The tree's B node (shown when not empty) names the same count.
  if (expected > 0) {
    await expect(
      page.getByRole("treeitem", { name: new RegExp(`^B 등급 이상, ${expected.toLocaleString("ko-KR")}건`) }),
    ).toHaveCount(1);
  }
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/explore/artifacts?flag_grade=A`;
  }, runId);
  await expect(page.getByRole("button", { name: "특이사항 A 이상 조건 제거" })).toBeVisible();
  // The panel shows the grade choice pressed.
  await page.getByTestId("filter-popover-button").click();
  const panel = page.getByRole("dialog", { name: "조건" });
  await expect(
    panel.getByRole("group", { name: "특이사항" }).getByRole("button", { name: "A", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
});

test("Q-F12: empty families are hidden; the toggle's n matches; the choice survives a reload", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/explore/files`);
  const tree = page.getByRole("tree", { name: "케이스 탐색 트리" });
  await expect(tree).toBeVisible();
  const toggle = page.getByTestId("tree-empty-toggle");
  await expect(toggle).toHaveText(/^결과 없는 계열 \d+개 표시$/);
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  const n = Number(/(\d+)개/.exec((await toggle.textContent()) ?? "")?.[1]);
  expect(n).toBeGreaterThan(0);
  await expect(tree.locator("[data-hidden-empty]")).toHaveCount(0);
  const before = await tree.getByRole("treeitem").count();
  await page.locator("body").press("t");
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await expect(toggle).toHaveText(`결과 없는 계열 ${n}개 숨김`);
  expect(await tree.getByRole("treeitem").count()).toBeGreaterThan(before);
  await page.reload();
  await expect(page.getByTestId("tree-empty-toggle")).toHaveAttribute("aria-pressed", "true");
  // Hidden again with the button; a tree search still finds a hidden family.
  await page.getByTestId("tree-empty-toggle").click();
  await expect(tree.locator("[data-hidden-empty]")).toHaveCount(0);
  const hiddenName = "위치·여행";
  await page.getByRole("searchbox", { name: "트리 검색" }).fill("위치");
  await expect(tree.getByRole("treeitem", { name: new RegExp(`^${hiddenName}`) })).toBeVisible();
});

test("Q-F13: every artifact = summary columns with label-above-value cells; one family = catalogue columns", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/explore/artifacts`);
  await expect(page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first()).toBeVisible();
  await expect(page.getByRole("columnheader", { name: /주요 세부 정보/ })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: /날짜 및 시각/ })).toBeVisible();
  const cell = page.locator('[role="grid"] [data-col="sum:time"] .sum-cell').first();
  await expect(cell.locator(".sum-label")).not.toHaveText("");
  await expect(cell.locator(".sum-value")).not.toHaveText("");
  // Every header keeps its full name as the tooltip.
  const titles = await page
    .locator('[role="columnheader"] .grid-sort')
    .evaluateAll((els) =>
      els.map(
        (el) =>
          el.getAttribute("title") ??
          el.closest("[data-disabled-reason]")?.getAttribute("data-disabled-reason"),
      ),
    );
  expect(titles.every((t) => Boolean(t))).toBe(true);
  await page.evaluate((h) => {
    window.location.hash = h;
  }, `#/case/${runId}/explore/artifacts/browser`);
  await expect(page.getByRole("columnheader", { name: /주요 세부 정보/ })).toHaveCount(0);
});

test("Q-F14/Q-F15: R/X/B marks give one stripe each; the meta tail lists seven facts", async ({ page }) => {
  await open(page, `#/case/${runId}/explore/files`);
  const row = page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first();
  await row.click();
  await row.focus();
  await page.keyboard.press("r");
  await expect(row).toHaveAttribute("data-mark", "relevant");
  await expect(row.locator(".grid-row-stripe")).toHaveAttribute("data-mark", "relevant");
  await expect(row).toHaveAttribute("aria-description", "검토 표시: 관련 있음");
  const box = await row.locator(".grid-row-stripe").boundingBox();
  expect(Math.round(box?.width ?? 0)).toBe(6);
  await page.keyboard.press("x");
  await expect(row).toHaveAttribute("data-mark", "excluded");
  await expect(row.locator(".grid-row-stripe")).toHaveCount(1);
  // Meta tail.
  await page.keyboard.press("Enter");
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await viewer.getByRole("tab", { name: /메타/ }).click();
  const tail = viewer.getByTestId("evidence-info");
  await expect(tail.getByRole("term")).toHaveText([
    "소스",
    "복구 방법",
    "삭제된 출처",
    "위치",
    "증거 번호",
    "파서 버전",
    "원본 행",
  ]);
  for (const dd of await tail.getByRole("definition").allInnerTexts()) expect(dd.trim()).not.toBe("—");
});
