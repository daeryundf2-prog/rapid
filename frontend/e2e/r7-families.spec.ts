// R7 stage 3 lane A (docs/research/nuix-parity-2026-10-26.md §4 갈래 A): 계열 · 중복 · 예외 항목
// against the synthetic run of tests/r7_a_fixtures.py (3 mails + 5 attachments in one PST
// container, a ZIP with 4 entries, an encrypted EGG, an adb backup, 2 carved rows; no evidence data).
// Q-A1 상위 항목으로 · Q-A2 ZIP 계열 · Q-A3 중복 조건 · Q-A5 예외 항목 카드 · Q-A6 선택 확장 → 일괄 표시.
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Page, test } from "@playwright/test";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";

let runId = "";

test.use({ viewport: { width: 1600, height: 1000 } });

test.beforeAll(async ({ request }) => {
  const output = join(mkdtempSync(join(tmpdir(), "rt-v2-e2e-r7a-")), "run");
  execFileSync(
    python,
    [
      "-c",
      "import sys; from pathlib import Path; from tests import r7_a_fixtures as fx; fx.write_run(Path(sys.argv[1]))",
      output,
    ],
    { cwd: repoRoot },
  );
  const imported = await request.post("/api/runs/import", { headers: HEADERS, data: { output_dir: output } });
  expect(imported.status(), await imported.text()).toBe(201);
  runId = ((await imported.json()) as { run_id: string }).run_id;
  expect(runId).not.toBe("");
});

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
}

const rows = (page: Page) =>
  page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');

/** A grid row by its key (`artifacts:email:/artifacts/6`): the email layout shows no file names. */
function row(page: Page, key: string) {
  return page.locator(`[role="grid"] [role="row"][data-row-key="${key}"]`);
}

async function go(page: Page, hash: string) {
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
}

test("Q-A1: 상위 항목으로 (U) lands on the mail row; the 계열 tab lists every sibling attachment", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/explore/artifacts/email`);
  await row(page, "artifacts:email:/artifacts/6").click();
  await page.keyboard.press("u");
  await expect(page).toHaveURL(/family=artifacts%3Aemail%3A%2Fartifacts%2F4/);
  await expect(page).toHaveURL(/mode=family/);
  // The grid lists the mail and its two attachments; the viewer shows the mail in its 계열 tab.
  await expect(rows(page)).toHaveCount(3);
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await expect(viewer.getByRole("tab", { name: "계열" })).toHaveAttribute("aria-selected", "true");
  const family = viewer.getByTestId("family-view");
  await expect(family.locator("[aria-current='true']")).toContainText("계약서");
  await expect(family).toContainText("견적서 사본.pdf");
  await expect(family).toContainText("계약서.docx");
  // The PST container is the parent of the mail (상위 항목), never part of the mail's family.
  await expect(family.getByRole("navigation", { name: "상위 항목" })).toContainText("box.pst");
  await expect(family).not.toContainText(/email-|attachment|container-inventory/);
});

test("Q-A2: a ZIP row's 계열 shows its 4 entries as virtual children; an entry opens its preview", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/explore/artifacts/generic-documents`);
  await row(page, "artifacts:generic-documents:/artifacts/0").click();
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await viewer.getByRole("tab", { name: "계열" }).click();
  const family = viewer.getByTestId("family-view");
  await expect(family).toContainText("계열 5개 항목 · 하위 4개 · 비중요 1개");
  for (const name of ["보고서/", "보고서/1분기.xlsx", "보고서/2분기.xlsx", "readme.txt"]) {
    await expect(family.getByText(name, { exact: true })).toBeVisible();
  }
  await family.getByText("보고서/1분기.xlsx", { exact: true }).click();
  await expect(viewer.getByRole("heading", { level: 2 })).toHaveText("1분기.xlsx");
});

test("Q-A3: 중복만 lists the duplicate copy only; the chip reads Korean", async ({ page }) => {
  await open(page, `#/case/${runId}/explore/files?dup=duplicate`);
  await expect(rows(page)).toHaveCount(1);
  await expect(page.getByRole("list", { name: "적용된 조건" })).toContainText("중복 중복만");
  await go(page, `#/case/${runId}/explore/artifacts/email?dup=duplicate`);
  // 2 attachment copies + the second copy of 견적서 송부 + its attachment (items − groups).
  await expect(rows(page)).toHaveCount(4);
});

test("Q-A5: the 예외 항목 block totals the categories; 암호화 lists the EGG and the encrypted HWP", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/intake`);
  const block = page.getByTestId("case-irregular");
  await expect(block.getByTestId("irregular-total")).toHaveText("합계 13건 · 항목 13개");
  await block.getByRole("link", { name: "암호화 아티팩트 2건 보기" }).click();
  await expect(page).toHaveURL(/irregular=encrypted/);
  await expect(rows(page)).toHaveCount(2);
  await expect(page.getByRole("list", { name: "적용된 조건" })).toContainText("예외 암호화");
  await expect(rows(page).filter({ hasText: "locked.egg" })).toHaveCount(1);
  await expect(rows(page).filter({ hasText: "secret.hwp" })).toHaveCount(1);
});

test("Q-A6: 선택을 상위+하위 항목으로 확장 selects the whole family; 관련 있음 is one review batch", async ({
  page,
  request,
}) => {
  const ensured = await request.post(`/api/runs/${runId}/case-db/ensure`, { headers: HEADERS, data: {} });
  expect(ensured.status()).toBe(200);
  await open(page, `#/case/${runId}/explore/artifacts/email`);
  const target = row(page, "artifacts:email:/artifacts/5");
  await target.click();
  await target.getByRole("button", { name: "행 메뉴" }).click();
  await page.getByRole("menuitem", { name: /선택을 상위\+하위 항목으로 확장/ }).click();
  await expect(page.getByText(/이 목록 3건 선택/).first()).toBeVisible();
  await expect(rows(page)).toHaveCount(3);
  const batches: string[] = [];
  page.on("request", (req) => {
    if (req.url().includes("/api/case-db/review-batch")) batches.push(req.postData() ?? "");
  });
  const done = page.waitForResponse((r) => r.url().includes("/api/case-db/review-batch") && r.ok());
  await page.getByRole("toolbar", { name: /선택/ }).getByRole("button", { name: "관련 있음" }).click();
  const confirm = page.getByRole("dialog");
  if (await confirm.isVisible().catch(() => false)) {
    await confirm
      .getByRole("button", { name: /확인|적용|표시/ })
      .first()
      .click();
  }
  const body = (await done).request().postDataJSON() as { targets: Array<{ locator?: string }> };
  expect(body.targets.map((t) => t.locator).sort()).toEqual(["/artifacts/4", "/artifacts/5", "/artifacts/6"]);
  expect(batches).toHaveLength(1);
});
