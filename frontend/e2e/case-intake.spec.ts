// Case intake E2E (AXIOM adoption E1, plan §4 Q-X1 / Q-X2 / Q-X12): 케이스 만들기 3단계 → 실행 → 접수
// 5 cards → reload keeps them; a run without a case keeps working and links to a case.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

function evidenceFolder(): string {
  const root = mkdtempSync(join(tmpdir(), "rt-e2e-case-evidence-"));
  mkdirSync(join(root, "Users", "alice", "Documents"), { recursive: true });
  writeFileSync(join(root, "Users", "alice", "Documents", "invoice.txt"), "invoice wire transfer", "utf8");
  return root;
}

async function cardOf(page: Page, title: string) {
  return page
    .locator("section.dash-card")
    .filter({ has: page.getByRole("heading", { name: title, exact: true }) });
}

/** In-page subset of e2e/a11y.spec.ts rules for the new screens (names, labels, ids, one polite region). */
async function quickAudit(page: Page): Promise<string[]> {
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
    for (const el of document.querySelectorAll(
      "button,a[href],[role=button]:not(input),[role=switch]:not(input)",
    )) {
      if (visible(el) && !nameOf(el)) out.push(`accessible-name ${el.outerHTML.slice(0, 80)}`);
    }
    for (const el of document.querySelectorAll("input:not([type=hidden]),select,textarea")) {
      const labelled = (el as HTMLInputElement).labels?.length || el.getAttribute("aria-label");
      if (visible(el) && !labelled) out.push(`field-name ${el.outerHTML.slice(0, 80)}`);
    }
    const seen = new Map<string, number>();
    for (const el of document.querySelectorAll("[id]")) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
    for (const [id, n] of seen) if (n > 1) out.push(`duplicate-id #${id} x${n}`);
    const polite = document.querySelectorAll("[aria-live=polite],[role=status]").length;
    if (polite !== 1) out.push(`live-polite ${polite}`);
    return out;
  });
}

test("Q-X1: 케이스 만들기 3단계 → 실행 → 접수 5 cards, kept after reload", async ({ page, request }) => {
  test.setTimeout(180_000);
  const folder = evidenceFolder();
  const caseNumber = `E2E-${Date.now()}`;
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page.getByTestId("landing")).toBeVisible();
  await expect(page.getByTestId("landing-run")).toHaveText("케이스 없이 빠른 런");
  const opener = page.getByTestId("landing-create");
  await opener.click();

  const dialog = page.getByRole("dialog", { name: "케이스 만들기" });
  await expect(dialog).toBeVisible();
  // Step 1: 사건 번호 is required (Korean reason, 다음 inert).
  const next = dialog.getByTestId("wizard-next");
  await expect(next).toHaveAttribute("aria-disabled", "true");
  await expect(dialog.getByText("사건 번호를 입력하세요.").first()).toBeVisible();
  await dialog.getByLabel("사건 번호").fill(caseNumber);
  await dialog.getByLabel("사건명").fill("E2E 법인 자금 유출");
  await dialog.getByLabel("검사관").fill("홍길동");
  await dialog.getByLabel("의뢰처").fill("서울중앙지검");
  expect(await quickAudit(page)).toEqual([]);
  // Enter in a one-line field moves on (review item 12: real browser, not only jsdom).
  await dialog.getByLabel("의뢰처").press("Enter");

  // Step 2: add a second evidence item, delete it, keep one folder item.
  await expect(dialog.getByTestId("wizard-step-evidence")).toBeVisible();
  await dialog.getByTestId("wizard-add-evidence").click();
  await expect(dialog.getByTestId("wizard-evidence")).toHaveCount(2);
  await dialog.getByRole("button", { name: "증거 E-02 삭제" }).click();
  await expect(dialog.getByTestId("wizard-evidence")).toHaveCount(1);
  const item = dialog.getByTestId("wizard-evidence").first();
  await item.getByLabel("증거 종류").selectOption("folder");
  await item.getByLabel("증거 경로").fill(folder);
  await item.getByRole("switch").check();
  expect(await quickAudit(page)).toEqual([]);
  await dialog.getByTestId("wizard-next").click();

  // Step 3: options + summary; the request the UI sends must match the summary 1:1.
  await expect(dialog.getByTestId("wizard-step-options")).toBeVisible();
  await dialog.getByLabel("모드").selectOption("fraud");
  const summaryKeys = await dialog
    .getByTestId("wizard-summary")
    .locator("tr[data-key]")
    .evaluateAll((rows) => rows.map((row) => row.getAttribute("data-key")));
  const runRequest = page.waitForRequest(
    (req) => /\/api\/cases\/[^/]+\/runs$/.test(req.url()) && req.method() === "POST",
  );
  await dialog.getByTestId("wizard-submit").click();
  const sent = (await runRequest).postDataJSON() as Record<string, unknown>;
  expect(
    Object.keys(sent)
      .filter((key) => !["wait", "evidence_citation_id"].includes(key))
      .sort(),
  ).toEqual([...summaryKeys].sort());

  // Lands on the new run's 접수 stage.
  await expect(page).toHaveURL(/#\/case\/[0-9a-f]+\/intake/);
  const runId = /#\/case\/([0-9a-f]+)\/intake/.exec(page.url())?.[1] ?? "";
  expect(runId).not.toBe("");
  await expect(dialog).toBeHidden();
  // Focus returned to the page (not lost on body).
  expect(await page.evaluate(() => document.activeElement !== null)).toBe(true);

  // Wait for the (tiny) run to finish so 처리 문제 fills. It must COMPLETE: a failed run (e.g. the
  // pre-run processing-snapshot.json breaking the run) is a regression, not an acceptable end state.
  await expect
    .poll(
      async () => {
        const res = await request.get(`/api/runs/${runId}`, { headers: HEADERS });
        return ((await res.json()) as { status: string }).status;
      },
      { timeout: 150_000, intervals: [1000] },
    )
    .toMatch(/^(completed|failed|cancelled)$/);
  const finished = (await (await request.get(`/api/runs/${runId}`, { headers: HEADERS })).json()) as {
    status: string;
    error?: string | null;
  };
  expect(finished.status, finished.error ?? "").toBe("completed");

  const checkCards = async () => {
    const info = await cardOf(page, "사건 정보");
    await expect(info.getByText(caseNumber).first()).toBeVisible();
    await expect(info.getByText("서울중앙지검")).toBeVisible();
    const evidence = await cardOf(page, "증거 목록");
    await expect(evidence.getByRole("rowheader", { name: "E-01" })).toBeVisible();
    await expect(evidence.getByText("해당 없음 (폴더)")).toBeVisible();
    const snapshot = await cardOf(page, "처리 설정 스냅샷");
    await expect(snapshot.getByText("런 시작 시 케이스에 고정된 처리 옵션입니다.")).toBeVisible();
    await expect(snapshot.getByText("문서·부정 조사 (fraud)")).toBeVisible();
    const problems = await cardOf(page, "처리 문제");
    await expect(problems.locator(".dash-problems, .dash-empty").first()).toBeVisible({ timeout: 30_000 });
    const memo = await cardOf(page, "케이스 메모");
    await expect(memo.getByLabel("새 메모")).toBeVisible();
    await expect(page.getByTestId("case-crumb")).toContainText(`${caseNumber} › E-01`);
  };
  await checkCards();

  // Q-X4: memo with author and time; soft delete keeps history.
  const memo = await cardOf(page, "케이스 메모");
  await memo.getByLabel("새 메모").fill("압수 목록 확인");
  await memo.getByRole("button", { name: "메모 추가" }).click();
  await expect(memo.getByText("압수 목록 확인").first()).toBeVisible();
  await expect(memo.locator(".dash-memo-meta").first()).toContainText("홍길동");
  expect(await quickAudit(page)).toEqual([]);

  // Reload keeps everything (server state, not browser state).
  await page.reload();
  await checkCards();
  await expect((await cardOf(page, "케이스 메모")).getByText("압수 목록 확인").first()).toBeVisible();

  // The switcher shows 케이스 › 증거 › 런.
  await page.keyboard.press("Escape");
  await page.evaluate(() => {
    window.location.hash = "";
  });
  await page.getByTestId("landing-open").click();
  const picker = page.getByRole("dialog", { name: "케이스 전환" });
  await expect(picker.getByRole("list", { name: "케이스 › 증거 › 런" })).toContainText(caseNumber);
  await expect(
    picker.getByRole("button", { name: new RegExp(`^${caseNumber} › E-01 › .* · 완료$`) }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(picker).toBeHidden();
  await expect(page.getByTestId("landing-open")).toBeFocused();
});

test("Q-X1 review: register-only evidence is pre-checked, saved and skipped", async ({ page }) => {
  test.setTimeout(120_000);
  const folder = evidenceFolder();
  const zip = join(folder, "..", `${Date.now()}-export.zip`);
  writeFileSync(zip, "PK\u0003\u0004 not a real archive", "utf8");
  const caseNumber = `E2E-ZIP-${Date.now()}`;
  await page.goto(`/v2/#token=${TOKEN}`);
  await page.getByTestId("landing-create").click();
  const dialog = page.getByRole("dialog", { name: "케이스 만들기" });
  await dialog.getByLabel("사건 번호").fill(caseNumber);
  await dialog.getByTestId("wizard-next").click();
  await dialog.getByTestId("wizard-add-evidence").click();
  const items = dialog.getByTestId("wizard-evidence");
  await items.nth(0).getByLabel("증거 종류").selectOption("folder");
  await items.nth(0).getByLabel("증거 경로").fill(folder);
  await items.nth(1).getByLabel("증거 종류").selectOption("export");
  await items.nth(1).getByLabel("증거 경로").fill(zip);
  await dialog.getByTestId("wizard-next").click();
  // The server pre-check marked the zip register-only before anything was saved.
  await expect(dialog.getByTestId("wizard-step-options")).toBeVisible();
  await expect(dialog.getByTestId("wizard-skipped")).toContainText("E-02");
  await expect(dialog.getByTestId("wizard-submit")).toHaveText("실행 (런 1개)");
  await dialog.getByTestId("wizard-submit").click();
  await expect(page).toHaveURL(/#\/case\/[0-9a-f]+\/intake/);
  const evidence = await cardOf(page, "증거 목록");
  const zipRow = evidence.getByRole("row").filter({ has: page.getByRole("rowheader", { name: "E-02" }) });
  await expect(zipRow.getByTestId("evidence-register-only")).toBeVisible();
  await expect(zipRow.getByRole("button", { name: "증거 E-02 런 추가" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  await expect(
    evidence
      .getByRole("row")
      .filter({ has: page.getByRole("rowheader", { name: "E-01" }) })
      .getByRole("button", { name: "증거 E-01 런 추가" }),
  ).not.toHaveAttribute("aria-disabled", "true");
  expect(await quickAudit(page)).toEqual([]);
});

test("Q-X2: a run without a case keeps working and offers 케이스에 연결", async ({ page, request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-e2e-caseless-"));
  const created = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(created.status()).toBe(201);
  const runId = ((await created.json()) as { run: { run_id: string } }).run.run_id;
  const caseNumber = `E2E-LINK-${Date.now()}`;
  const made = await request.post("/api/cases", { headers: HEADERS, data: { case_number: caseNumber } });
  expect(made.status()).toBe(201);

  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page.getByTestId("landing")).toBeVisible();
  await expect(
    page
      .getByRole("link")
      .filter({ hasText: runId.slice(0, 8) })
      .first(),
  ).toContainText("케이스 없음");
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/intake`;
  }, runId);
  const info = await cardOf(page, "사건 정보");
  await expect(info.getByTestId("no-case")).toBeVisible();
  // Existing cards still render for the caseless run.
  await expect(page.getByRole("heading", { name: "케이스 요약 노트" })).toBeVisible();
  await expect((await cardOf(page, "처리 설정 스냅샷")).getByText(/케이스 없이 실행된 런/)).toBeVisible();
  expect(await quickAudit(page)).toEqual([]);

  const linkButton = info.getByRole("button", { name: "케이스에 연결" });
  await linkButton.click();
  const dialog = page.getByRole("dialog", { name: "케이스에 연결" });
  await dialog.getByLabel("케이스", { exact: true }).selectOption({ label: `${caseNumber} · ${caseNumber}` });
  await dialog.getByLabel("새 증거 번호").fill("E-01");
  await dialog.getByRole("button", { name: "연결" }).click();
  await expect(dialog).toBeHidden();
  await expect(info.getByText(caseNumber).first()).toBeVisible();
  await expect(page.getByTestId("case-crumb")).toContainText(`${caseNumber} › E-01`);
});
