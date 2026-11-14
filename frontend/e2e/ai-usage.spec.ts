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
import { COPY, escapeRegExp } from "../src/contracts/copy";
import { TEST_IDS, testIdSelector } from "../src/contracts/testIds";

const AI = COPY.ai;
const NODES = COPY.ai.nodes;

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
  await expect(page.getByTestId(TEST_IDS.workbenchShell)).toBeVisible();
}

async function open(page: Page, hash: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await page.evaluate((next) => {
    window.location.hash = next;
  }, hash);
  await expect(page.getByTestId(TEST_IDS.workbenchShell)).toBeVisible();
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
  const domain = page.getByRole("treeitem", { name: new RegExp(`^${escapeRegExp(AI.domain)}, `) });
  await expect(domain).toBeVisible({ timeout: 30_000 });
  if ((await domain.getAttribute("aria-expanded")) !== "true") await domain.click();
  for (const [label, count] of [
    [NODES.sessions, 29],
    [NODES.messages, 49],
    [NODES.toolCalls, 24],
    [NODES.fileTouches, 23],
    [NODES.mcpServers, 17],
    [NODES.instructionFiles, 12],
    [NODES.credentialPresence, 23],
    [NODES.accounts, 9],
    [NODES.codeContribution, 4],
    [NODES.usage, 6],
    [NODES.retention, 1],
  ] as const) {
    await expect(
      page.getByRole("treeitem", {
        name: new RegExp(`^${escapeRegExp(COPY.common.countedNode(label, count))}`),
      }),
    ).toBeVisible();
  }
  const tools = page.getByRole("treeitem", {
    name: new RegExp(`^${escapeRegExp(COPY.common.countedNode(NODES.tools, 84))}`),
  });
  await expect(tools).toBeVisible();
  // A group opens its own view on click; ArrowRight expands it.
  await tools.click();
  await expect(async () => {
    if ((await tools.getAttribute("aria-expanded")) !== "true") await tools.press("ArrowRight");
    await expect(tools).toHaveAttribute("aria-expanded", "true", { timeout: 1000 });
  }).toPass({ timeout: 20_000 });
  // 설치·경로 views counted from the presence rows (14 catalog-path rows, 1 MSIX package).
  await expect(
    page.getByRole("treeitem", {
      name: new RegExp(`^${escapeRegExp(COPY.common.countedNode(NODES.pathTraces, 14))}`),
    }),
  ).toBeVisible({
    timeout: 30_000,
  });
  await expect(
    page.getByRole("treeitem", {
      name: new RegExp(`^${escapeRegExp(COPY.common.countedNode(NODES.installTraces, 1))}`),
    }),
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
  for (const header of Object.values(AI.columns)) {
    expect(headers.join("|")).toContain(header);
  }
  // The Claude Code main session: fixture sess-A, custom title "Fix app" with its 2 sub-agent sessions
  // ("하위 2개"; the sub-agent rows only say "상위: Fix app", so this pins the parent row exactly).
  const session = rows(page)
    .filter({ hasText: "Fix app" })
    .filter({ hasText: AI.subAgents(2) });
  await expect(session).toHaveCount(1);
  await session.click();
  const viewer = page.getByRole("region", { name: COPY.viewer.region });
  await viewer.getByRole("tab", { name: COPY.viewer.tabMeta }).click();
  const links = viewer.getByTestId(TEST_IDS.aiSessionLinks);
  await expect(links).toBeVisible();
  await expect(links.getByRole("link", { name: AI.openChat })).toBeVisible();
  await expect(links.getByRole("link", { name: AI.subAgentSessions })).toBeVisible();
  await shot(page, "ai-session-meta");
  await links.getByRole("link", { name: AI.openChat }).click();
  await expect(page).toHaveURL(/view=chat/);
  const thread = page.getByTestId(TEST_IDS.chatThread);
  await expect(thread).toBeVisible({ timeout: 30_000 });
  // Role bubbles (사용자 on the right), a folded tool call, a file-touch link.
  await expect(
    thread.getByTestId(TEST_IDS.chatSender).filter({ hasText: AI.roleUser }).first(),
  ).toBeVisible();
  await expect(
    thread.locator(`${testIdSelector(TEST_IDS.chatMessage)}[data-direction="out"]`).first(),
  ).toBeVisible();
  const call = thread.getByTestId(TEST_IDS.aiToolCall).first();
  await expect(call).toBeVisible();
  await expect(call.getByRole("button")).toHaveAttribute("aria-expanded", "false");
  await call.getByRole("button").click();
  await expect(call.getByRole("button")).toHaveAttribute("aria-expanded", "true");
  await expect(
    call.getByTestId(TEST_IDS.aiToolCommand).or(call.getByTestId(TEST_IDS.aiToolTarget)).first(),
  ).toBeVisible();
  const touch = thread.getByTestId(TEST_IDS.aiFileTouch).first();
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
    COPY.grid.notCollected,
  );
  await expectNoSecrets(page);
  await go(page, `#/case/${runId}/explore/artifacts/ai-agent?types=ai-agent-file-touch`);
  await rows(page).first().click();
  const viewer = page.getByRole("region", { name: COPY.viewer.region });
  await viewer.getByRole("tab", { name: COPY.viewer.tabMeta }).click();
  const find = viewer.getByTestId(TEST_IDS.aiSessionLinks).getByRole("link", { name: AI.findInFiles });
  await find.click();
  await expect(page).toHaveURL(/explore\/files\?path=/);
});

test("Q-AI10 intake: AI 사용 요약 block", async ({ page }) => {
  await open(page, `#/case/${runId}/intake`);
  const block = page.getByTestId(TEST_IDS.caseAiUsage);
  await expect(block).toBeVisible({ timeout: 60_000 });
  await expect(block.getByTestId(TEST_IDS.aiUsageFacts)).toBeVisible({ timeout: 60_000 });
  await expect(block.getByRole("link", { name: AI.sessionsLink(29) })).toBeVisible();
  await expect(block.getByTestId(TEST_IDS.aiUsageCredentials)).toContainText(AI.valueNotCollected);
  await expect(block.getByTestId(TEST_IDS.aiUsageRetention)).toBeVisible();
  await expect(block).not.toContainText(/ai-agent|claude-code|ai-tool-presence/);
  await block.scrollIntoViewIfNeeded();
  await shot(page, "ai-intake");
});

test("Q-AI10 처리: AI 사용 기록 section", async ({ page }) => {
  await open(page, `#/case/${runId}/process`);
  const section = page.getByTestId(TEST_IDS.processAi);
  await expect(section).toBeVisible({ timeout: 60_000 });
  await expect(section.getByTestId(TEST_IDS.processAiRows)).toContainText(COPY.common.countUnit);
  await expect(section.getByTestId(TEST_IDS.processAiScope)).toContainText(AI.messageBody);
});
