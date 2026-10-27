import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

/**
 * R7 lane B (QA Q-B1/Q-B3/Q-B5): entity search in the console on a SYNTHETIC run (made-up values
 * with valid check digits, tests/test_r7_b_search_s2.py `build_entity_run`). The run and its search
 * index are written into a temp folder by Python, imported read-only, then:
 *   - 검색 옵션 › 주민등록번호 opens 개체·언어 검색 with Korean chips and masked rows only;
 *   - 값 보기 asks a reason once, then shows the one value (1 audit record server-side);
 *   - the top-bar search runs a field keyword (`rrn:verified`) over the index.
 */
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";

let runId = "";
let values: Record<string, string> = {};

const BUILD = `
import json, sys
from pathlib import Path
from rapidtriage.core.search_index.build import build_search_index
from tests.test_r7_b_search_s2 import build_entity_run
fixture = build_entity_run(Path(sys.argv[1]))
build_search_index(Path(fixture["run_dir"]), fixture["summary"], run_id="e2e")
print(json.dumps({"run_dir": str(fixture["run_dir"]), "values": fixture["values"]}))
`;

test.beforeAll(async ({ request }) => {
  const base = mkdtempSync(join(tmpdir(), "rt-v2-e2e-entities-"));
  const built = spawnSync(python, ["-c", BUILD, base], { cwd: repoRoot, encoding: "utf-8" });
  expect(built.status, built.stderr).toBe(0);
  const lines = built.stdout.trim().split("\n");
  const payload = JSON.parse(lines[lines.length - 1] ?? "{}") as { run_dir: string; values: Record<string, string> };
  values = payload.values;
  const response = await request.post("/api/runs/import", { headers: HEADERS, data: { output_dir: payload.run_dir } });
  expect(response.status()).toBe(201);
  runId = ((await response.json()) as { run_id: string }).run_id;
  expect(runId).not.toBe("");
});

test("entity chips, masked rows, one audited reveal and a field keyword in the top bar", async ({ page }) => {
  await page.goto(`/v2/#token=${TOKEN}`);
  await page.evaluate((run) => {
    window.location.hash = `#/case/${run}/explore/files`;
  }, runId);
  await expect(page.getByTestId("grid-region")).toBeVisible();

  await page.getByRole("button", { name: "검색 옵션" }).click();
  await page.getByRole("button", { name: "주민등록번호" }).click();
  const dialog = page.getByRole("dialog", { name: "개체·언어 검색" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: /주민등록번호 2행/ })).toBeVisible();
  await expect(dialog.getByRole("button", { name: /카드번호/ })).toBeVisible();
  await expect(dialog.getByRole("button", { name: /한국어/ })).toBeVisible();
  await expect(dialog.getByText("개인정보목록.txt")).toBeVisible();
  const before = (await page.content()).toString();
  for (const raw of Object.values(values)) expect(before).not.toContain(raw);
  await expect(dialog.getByText(`${values.rrn?.slice(0, 8)}******`).first()).toBeVisible();

  // Q-B1: the advanced query box
  await dialog.getByLabel("고급 검색 질의").fill("rrn:verified in:docs");
  await dialog.getByRole("button", { name: "검색", exact: true }).click();
  await expect(dialog.getByText("결과 1건")).toBeVisible();

  // Q-B3: reveal (reason once per session) -> the value once
  const row = dialog.locator(".entity-rows > li").filter({ hasText: "개인정보목록.txt" });
  await row.locator("li").filter({ hasText: "주민등록번호" }).getByRole("button", { name: "값 보기" }).click();
  const confirm = dialog.getByRole("form", { name: "값 공개 확인" });
  await expect(confirm).toContainText("감사 기록 1건");
  await confirm.getByLabel(/공개 사유/).fill("e2e 점검");
  await confirm.getByRole("button", { name: "감사 기록 남기고 공개" }).click();
  await expect(dialog.getByText(values.rrn ?? "missing")).toBeVisible();
  // the next reveal of the session needs no reason form
  await row.locator("li").filter({ hasText: "전화번호" }).getByRole("button", { name: "값 보기" }).click();
  await expect(dialog.getByText(values.phone ?? "missing")).toBeVisible();
  await expect(dialog.getByRole("form", { name: "값 공개 확인" })).toHaveCount(0);

  // Q-B5: a language chip
  await dialog.getByRole("button", { name: /일본어/ }).click();
  await expect(dialog.getByText("japanese.txt")).toBeVisible();
  await dialog.getByRole("button", { name: "닫기" }).first().click();
  await expect(dialog).toHaveCount(0);

  // A field keyword in the top-bar search runs over the index.
  const search = page.getByLabel("전체 검색어");
  await search.fill("rrn:verified");
  await search.press("Enter");
  await expect(page.locator('[role="grid"]').getByText("개인정보목록.txt").first()).toBeVisible();
  const after = (await page.content()).toString();
  expect(after).not.toContain(values.card ?? "missing");
});
