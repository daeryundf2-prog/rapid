// T4 — AI trace (IS-052·055, QA-072). From the case: AI 사용 → a session → 대화 보기 → a file the
// session touched (pivot to the file list). Target for reaching the conversation: ≤2 operations,
// ≤20 s. A case without AI artifacts (the SYN fixture) records "AI 사용" as absent — an honest
// fail, never a skip. Measures only (see harness.ts).
import { test } from "@playwright/test";
import { ensureTree, resolveRun, STEP_TIMEOUT_MS, TaskRecorder } from "./harness";

test("T4 AI session trace (measure)", async ({ page, request }) => {
  const runId = await resolveRun(request, "T4");
  // QA-072's ≤2 operations / ≤20 s is to the conversation (`extra.toConversation`); +1 for the pivot.
  const rec = new TaskRecorder(page, "T4", "AI 흔적 추적", runId, { maxOps: 3, maxSeconds: 20 });
  await rec.install();
  await rec.open();
  const viewer = page.getByRole("region", { name: "원본 뷰어" });

  const domain = await rec.step(
    "tree AI 사용 → session rows",
    async () => {
      await ensureTree(rec);
      const domainNode = page.getByRole("treeitem", { name: /^AI 사용, / }).first();
      const before = page.url();
      await rec.click(domainNode);
      // The domain node only expands today: pick a child (a session node first, else any AI child).
      await page.waitForURL((u) => u.toString() !== before, { timeout: 1_500 }).catch(() => undefined);
      if (page.url() === before) {
        const session = page.getByRole("treeitem", { name: /^(?!AI 사용,).*(세션|에이전트)/ });
        const child = (await session.count())
          ? session
          : page.getByRole("treeitem", { name: /^(?!AI 사용,).*AI/ });
        rec.extra.aiChild = await child
          .first()
          .getAttribute("aria-label")
          .catch(() => null);
        rec.notes.push("AI 사용 only expands; a child node was opened");
        await rec.clickToRows(child.first());
      } else {
        await rec.waitFirstRow(Date.now());
      }
      const ms = rec.firstRow ?? 0;
      return `first row ${ms} ms`;
    },
    { goal: true },
  );

  const chat = domain
    ? await rec.step(
        "session → 대화 보기",
        async () => {
          await rec.click(page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first());
          await rec.click(viewer.getByRole("tab", { name: "메타" }));
          await rec.click(viewer.getByTestId("ai-session-links").getByRole("link", { name: "대화 보기" }));
          await page.getByTestId("ai-tool-call").first().waitFor({ timeout: STEP_TIMEOUT_MS });
          rec.extra.toConversation = rec.milestone();
        },
        { goal: true },
      )
    : rec.skip("session → 대화 보기", "no AI 사용 node", { goal: true });

  if (chat) {
    await rec.step(
      "file-touch pivot → file list",
      async () => {
        await rec.click(page.getByTestId("ai-file-touch").first().getByRole("link").first());
        await page.waitForURL(/explore\/files/, { timeout: STEP_TIMEOUT_MS });
      },
      { goal: true },
    );
  } else {
    rec.skip("file-touch pivot → file list", "conversation not reached", { goal: true });
  }
  rec.finish();
});
