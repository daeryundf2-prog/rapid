import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type APIRequestContext, expect, test } from "@playwright/test";

// Plan artifact-columns §5 "A": promote a record field from the column menu, sort its header on
// the server (building → ready), and check the first row follows the server order. Skips when
// the backend has no server sort yet (§4.1 `sort` object / `record_index`) or the served bundle
// predates the field picker (the lead rebuilds rapidtriage/web/static after integration).
const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };

interface KindPage {
  artifacts?: Array<{ record_index?: number; details?: Record<string, unknown> }>;
  total?: number | null;
  sort?: { status?: string };
}

async function artifacts(request: APIRequestContext, runId: string, query: string) {
  const response = await request.get(`/api/runs/${encodeURIComponent(runId)}/artifacts?${query}`, {
    headers: HEADERS,
  });
  if (!response.ok()) return null;
  return ((await response.json()) as { artifacts?: Record<string, KindPage> }).artifacts ?? null;
}

let runId = "";
let kind = "";
/** Scalar details keys whose values differ between sampled rows (the order is observable). */
let candidates: string[] = [];

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-e2e-columns-"));
  const created = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  if (created.status() !== 201) return;
  const list = await request.get("/api/runs", { headers: HEADERS });
  runId = ((await list.json()) as { runs: Array<{ run_id: string }> }).runs[0]?.run_id ?? "";
  if (!runId) return;
  const all = (await artifacts(request, runId, "limit=20")) ?? {};
  const kinds = Object.keys(all).filter((k) => (all[k]?.artifacts?.length ?? 0) >= 2);
  kind = kinds.includes("windows-prefetch") ? "windows-prefetch" : (kinds[0] ?? "");
  const rows = all[kind]?.artifacts ?? [];
  // A scalar details key whose values differ between rows (so the order is observable).
  const keys = Object.keys(rows[0]?.details ?? {}).filter((key) =>
    rows.every((row) => ["string", "number"].includes(typeof row.details?.[key])),
  );
  candidates = keys.filter((key) => new Set(rows.map((row) => String(row.details?.[key]))).size > 1);
});

test("promote a record field, sort it on the server (building → ready), first row follows", async ({
  page,
  request,
}) => {
  test.skip(
    !runId || !kind || candidates.length === 0,
    "sample case has no artifact kind with a sortable field",
  );

  await page.goto(`/v2/#token=${TOKEN}`);
  await page.evaluate(
    ([run, k]) => {
      window.location.hash = `#/case/${run}/artifacts/${k}`;
    },
    [runId, kind],
  );
  const firstRow = page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first();
  await expect(firstRow).toBeVisible();

  await page.getByRole("button", { name: "열 선택" }).click();
  const search = page.getByRole("searchbox", { name: "필드 검색" });
  test.skip((await search.count()) === 0, "served bundle predates the field picker — rebuild static first");
  // A field the default columns do not already show: the picker offers exactly those.
  const offered = await page
    .getByRole("group", { name: "레코드 필드 추가" })
    .getByRole("checkbox")
    .evaluateAll((els) =>
      els
        .filter((el) => el.getAttribute("aria-disabled") !== "true")
        .map((el) => el.getAttribute("aria-label") ?? ""),
    );
  const field = candidates.find((key) => offered.includes(key)) ?? "";
  test.skip(!field, "no sortable record field outside the default columns in the sample case");
  const probe = await artifacts(
    request,
    runId,
    `kind=${encodeURIComponent(kind)}&limit=1&sort=${encodeURIComponent(`details.${field}`)}&order=desc`,
  );
  test.skip(!probe?.[kind]?.sort, "backend without server sort (plan §4.1)");
  await search.fill(field);
  await page
    .getByRole("group", { name: "레코드 필드 추가" })
    .getByRole("checkbox", { name: field, exact: true })
    .check();
  await page.keyboard.press("Escape");
  await expect(page).toHaveURL(new RegExp(`cols=details\\.${field}`));

  const header = page.locator(`[role="columnheader"][data-col="f:${field}"]`);
  await header.getByRole("button").click(); // asc
  await header.getByRole("button").click(); // desc
  const status = page.getByTestId("grid-sort-status");
  await expect(status).toContainText("정렬:", { timeout: 60_000 });
  await expect(header).toHaveAttribute("aria-sort", "descending");
  await expect(page).toHaveURL(new RegExp(`sort=details\\.${field}:desc`));

  // The first grid row is the server's first sorted record (its locator is the JSONL index).
  let first: number | undefined;
  await expect
    .poll(
      async () => {
        const sorted = await artifacts(
          request,
          runId,
          `kind=${encodeURIComponent(kind)}&limit=1&sort=${encodeURIComponent(`details.${field}`)}&order=desc`,
        );
        first = sorted?.[kind]?.artifacts?.[0]?.record_index;
        return sorted?.[kind]?.sort?.status;
      },
      { timeout: 30_000 },
    )
    .toBe("ready");
  await expect(firstRow).toHaveAttribute("data-row-key", `artifacts:${kind}:/artifacts/${first}`);
});
