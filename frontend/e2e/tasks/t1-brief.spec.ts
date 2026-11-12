// T1 — 1-minute case understanding (IS-001, QA-033). Open the case at 1280×720 with zero
// operations: the case briefing shows the six answers (main account, period of use, top 3
// programs, what was found per category, AI use, next step) without scrolling, facts first and the
// rule section titled "자동 · 검증 전". Also takes the UX-audit baseline numbers (tree nodes, cell
// truncation, Tab presses to the first grid row) on 탐색 › 파일. Measures only (see harness.ts).
import { test } from "@playwright/test";
import {
  cellTruncation,
  countTreeNodes,
  resolveRun,
  STEP_TIMEOUT_MS,
  TaskRecorder,
  tabsToGrid,
  verticalOverflow,
} from "./harness";

/** IS-001's six questions, answered by `r8-brief-q1`…`q6` (T-073). */
const QUESTIONS = [
  "주 사용 계정",
  "사용 기간",
  "주요 프로그램 3",
  "범주별 건수",
  "AI 사용 여부",
  "다음 할 일",
];

test("T1 case briefing in one minute (measure)", async ({ page, request }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  const runId = await resolveRun(request, "T1");
  const rec = new TaskRecorder(page, "T1", "1분 사건 파악", runId, {
    maxOps: 0,
    maxSeconds: 60,
    maxScreens: 1,
  });
  await rec.install();

  const opened = await rec.step("open case (0 operations)", async () => {
    await rec.open();
    return `screen=${page.url().split("#")[1] ?? ""}`;
  });

  if (opened) {
    await rec.step(
      "briefing is the first screen",
      async () => {
        const brief = page.getByRole("heading", { name: /사건 브리핑/ });
        await brief.first().waitFor({ timeout: STEP_TIMEOUT_MS });
      },
      { goal: true },
    );
    await rec.step(
      "six answers in the DOM",
      async () => {
        const found: string[] = [];
        for (let n = 1; n <= QUESTIONS.length; n += 1) {
          if ((await page.getByTestId(`r8-brief-q${n}`).count()) > 0) found.push(`q${n}`);
        }
        rec.extra.briefAnswers = found;
        if (found.length < QUESTIONS.length) {
          const missing = QUESTIONS.filter((_, i) => !found.includes(`q${i + 1}`));
          throw new Error(`${found.length}/6 answers; missing: ${missing.join(", ")}`);
        }
      },
      { goal: true },
    );
    await rec.step("no scroll at 1280×720", async () => {
      const overflow = await verticalOverflow(page);
      rec.extra.overflowPx = overflow;
      if (overflow.document > 0 || overflow.main > 0) {
        throw new Error(`overflow document=${overflow.document}px main=${overflow.main}px`);
      }
    });
    await rec.step("rule section titled 자동 · 검증 전", async () => {
      await page
        .getByText(/자동 · 검증 전/)
        .first()
        .waitFor({ timeout: 2_000 });
    });
  } else {
    for (const name of ["briefing is the first screen", "six answers in the DOM"]) {
      rec.skip(name, "case did not open", { goal: true });
    }
  }
  rec.finish();

  // UX-audit baseline (not part of the T1 operation count): measured on a fresh recorder so the
  // Tab presses do not pollute T1's zero-operation budget.
  const audit = new TaskRecorder(page, "T1", "audit", runId);
  const baseline: Record<string, unknown> = {};
  try {
    await audit.open("explore/files");
    await audit.waitFirstRow(Date.now()).catch(() => undefined);
    baseline.treeNodes = await countTreeNodes(page);
    baseline.truncation = await cellTruncation(page);
    baseline.tabsToGrid = await tabsToGrid(audit);
  } catch (error) {
    baseline.error = error instanceof Error ? error.message.split("\n")[0] : String(error);
  }
  // Re-write T1 with the audit numbers attached (the operation metrics stay frozen at T1's end).
  rec.extra.audit = baseline;
  rec.finish();
});
