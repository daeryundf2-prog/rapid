// R7 AI 사용 (갈래 D, plan docs/plans/r7-ai-usage-2026-10-27.md §3.5 / Q-AI10) against a SYNTHETIC run:
// tests/fixtures/ai_agents/make_fixtures.py (user u1, invented sessions, fake secrets) through the
// real pipeline (frontend/e2e/ai_fixture.py). Tree "AI 사용" with counts · session → 메타 links →
// 대화 보기 (role bubbles, folded tool calls, file-touch links) · 접수 AI 사용 요약 · no secret value
// and no raw id on these screens.
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
const SHOTS = process.env.AI_E2E_SHOTS ?? "";

let runId = "";
/** Fake secret values of the fixture (assembled by make_fixtures.secret_values()). */
let secrets: string[] = [];

test.use({ viewport: { width: 1600, height: 1000 }, locale: "ko-KR" });
test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  test.setTimeout(240_000);
  const base = mkdtempSync(join(tmpdir(), "rt-v2-e2e-ai-"));
  execFileSync(
    python,
    [join("frontend", "e2e", "ai_fixture.py"), join(base, "evidence"), join(base, "run")],
    {
      cwd: repoRoot,
      stdio: "inherit",
    },
  );
  secrets = JSON.parse(
    execFileSync(
      python,
      [
        "-c",
        "import json,sys; sys.path.insert(0,'tests/fixtures/ai_agents'); import make_fixtures as m; print(json.dumps(m.secret_values()))",
      ],
      { cwd: repoRoot },
    ).toString(),
  ) as string[];
  const imported = await request.post("/api/runs/import", {
    headers: HEADERS,
    data: { output_dir: join(base, "run") },
  });
  expect(imported.status(), await imported.text()).toBe(201);
  runId = ((await imported.json()) as { run_id: string }).run_id;
});

/** Next node in the same page (hash change; the token is already taken). */
async function go(page: Page, hash: string) {
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
}

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId("workbench-shell")).toBeVisible();
}

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

/** Text of the page must never hold one of the fixture's secret values. */
async function expectNoSecrets(page: Page) {
  const text = await page.locator("body").innerText();
  for (const secret of secrets) expect(text, "secret value on screen").not.toContain(secret);
}

const rows = (page: Page) =>
  page.locator('[role="grid"] [role="row"][aria-rowindex]:not([aria-rowindex="1"])');

test("Q-AI10 tree: the AI 사용 domain lists its nodes with the fixture's counts", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await open(page, `#/case/${runId}/explore/artifacts/ai-agent?types=ai-agent-session`);
  const domain = page.getByRole("treeitem", { name: /^AI 사용, / });
  await expect(domain).toBeVisible({ timeout: 30_000 });
  if ((await domain.getAttribute("aria-expanded")) !== "true") await domain.click();
  for (const [label, count] of [
    ["세션", 28],
    ["메시지", 45],
    ["도구 호출", 19],
    ["파일 접촉", 19],
    ["MCP 서버", 17],
    ["지침·메모리 파일", 12],
    ["자격 증명 존재(값 없음)", 23],
    ["계정·전환", 9],
    ["AI 코드 기여", 4],
    ["사용량", 6],
    ["보존 정리", 1],
  ] as const) {
    await expect(
      page.getByRole("treeitem", { name: new RegExp(`^${label.replace(/[()]/g, "\\$&")}, ${count}건`) }),
    ).toBeVisible();
  }
  const tools = page.getByRole("treeitem", { name: /^도구·설치, 83건/ });
  await expect(tools).toBeVisible();
  // A group opens its own view on click; ArrowRight expands it.
  await tools.click();
  await expect(async () => {
    if ((await tools.getAttribute("aria-expanded")) !== "true") await tools.press("ArrowRight");
    await expect(tools).toHaveAttribute("aria-expanded", "true", { timeout: 1000 });
  }).toPass({ timeout: 20_000 });
  // 설치·경로 views counted from the presence rows (14 catalog-path rows, 1 MSIX package).
  await expect(page.getByRole("treeitem", { name: /^경로 흔적\(카탈로그 경로\), 14건/ })).toBeVisible({
    timeout: 30_000,
  });
  await expect(
    page.getByRole("treeitem", { name: /^설치 흔적\(npm·pip·winget·MSIX·확장\), 1건/ }),
  ).toBeVisible();
  await shot(page, "ai-tree");
  expect(errors).toEqual([]);
});

test("Q-AI10 grid: session columns read in Korean; the session's 메타 links open 대화 보기", async ({
  page,
}) => {
  await open(page, `#/case/${runId}/explore/artifacts/ai-agent?types=ai-agent-session`);
  await expect(rows(page).first()).toBeVisible({ timeout: 30_000 });
  const headers = await page.locator('[role="columnheader"]').allInnerTexts();
  for (const header of ["도구", "시작", "종료", "메시지", "도구 호출"]) {
    expect(headers.join("|")).toContain(header);
  }
  // The Claude Code main session (title "fix the bug" — fixture sess-A).
  const session = rows(page).filter({ hasText: "Claude Code" }).first();
  await session.click();
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await viewer.getByRole("tab", { name: "메타" }).click();
  const links = viewer.getByTestId("ai-session-links");
  await expect(links).toBeVisible();
  await expect(links.getByRole("link", { name: "대화 보기" })).toBeVisible();
  await expect(links.getByRole("link", { name: "하위 에이전트 세션" })).toBeVisible();
  await shot(page, "ai-session-meta");
  await links.getByRole("link", { name: "대화 보기" }).click();
  await expect(page).toHaveURL(/view=chat/);
  const thread = page.locator(".chat-thread");
  await expect(thread).toBeVisible({ timeout: 30_000 });
  // Role bubbles (사용자 on the right), a folded tool call, a file-touch link.
  await expect(thread.locator(".chat-sender", { hasText: "사용자" }).first()).toBeVisible();
  await expect(thread.locator(".chat-row.is-out").first()).toBeVisible();
  const call = thread.getByTestId("ai-tool-call").first();
  await expect(call).toBeVisible();
  await expect(call.getByRole("button")).toHaveAttribute("aria-expanded", "false");
  await call.getByRole("button").click();
  await expect(call.getByRole("button")).toHaveAttribute("aria-expanded", "true");
  await expect(call.locator(".chat-tool-command, .chat-tool-target").first()).toBeVisible();
  const touch = thread.getByTestId("ai-file-touch").first();
  await expect(touch.getByRole("link")).toHaveAttribute("href", /explore\/files\?path=/);
  await shot(page, "ai-conversation");
  await expectNoSecrets(page);
});

test("Q-AI10 file touch → file list; tool calls / credentials show no secret value", async ({ page }) => {
  await open(page, `#/case/${runId}/explore/artifacts/ai-agent?types=ai-agent-tool-call`);
  await expect(rows(page).first()).toBeVisible({ timeout: 30_000 });
  await expectNoSecrets(page);
  await go(page, `#/case/${runId}/explore/artifacts/ai-agent?types=ai-credential-presence`);
  await expect(rows(page).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('[role="gridcell"][data-col="d:value_collected"]').first()).toHaveText(
    "수집 안 함",
  );
  await expectNoSecrets(page);
  await go(page, `#/case/${runId}/explore/artifacts/ai-agent?types=ai-agent-file-touch`);
  await rows(page).first().click();
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await viewer.getByRole("tab", { name: "메타" }).click();
  const find = viewer.getByTestId("ai-session-links").getByRole("link", { name: "파일 목록에서 찾기" });
  await find.click();
  await expect(page).toHaveURL(/explore\/files\?path=/);
});

test("Q-AI10 intake: AI 사용 요약 block", async ({ page }) => {
  await open(page, `#/case/${runId}/intake`);
  const block = page.getByTestId("case-ai-usage");
  await expect(block).toBeVisible({ timeout: 60_000 });
  await expect(block.getByTestId("ai-usage-facts")).toBeVisible({ timeout: 60_000 });
  await expect(block.getByRole("link", { name: "AI 세션 28개 보기" })).toBeVisible();
  await expect(block.getByTestId("ai-usage-credentials")).toContainText("값 미수집");
  await expect(block.getByTestId("ai-usage-retention")).toBeVisible();
  await expect(block).not.toContainText(/ai-agent|claude-code|ai-tool-presence/);
  await block.scrollIntoViewIfNeeded();
  await shot(page, "ai-intake");
});

test("Q-AI10 처리: AI 사용 기록 section", async ({ page }) => {
  await open(page, `#/case/${runId}/process`);
  const section = page.getByTestId("process-ai");
  await expect(section).toBeVisible({ timeout: 60_000 });
  await expect(section.getByTestId("process-ai-rows")).toContainText("건");
  await expect(section.getByTestId("process-ai-scope")).toContainText("메시지 본문");
});
