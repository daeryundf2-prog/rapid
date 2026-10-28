import { expect, type Page, test } from "@playwright/test";

/**
 * R7 stage 1 lane L3 (docs/plans/r7-master-2026-10-26.md §3.3): no raw machine value on screen.
 *
 * Walks representative grid nodes, viewer meta panels and popovers of real runs and fails when a
 * visible text token is an untranslated id — `^[a-z0-9_-]{3,}$` (snake/kebab ids such as
 * `cleartext-url`, `global`, `documents`), a snake_case key (`visit_count`, `EventData_X`) or a
 * text that starts with `{"` (a JSON preview) — outside the allow-list below.
 *
 * Allow-list (explicit, reviewed): evidence text (file names, paths, URLs, hashes, SIDs, GUIDs,
 * numbers, e-mail addresses, product spellings in free-text values) is never an id — see
 * EVIDENCE_COLUMNS / EVIDENCE_KEY (cells), `dd` values (meta lists), the run's evidence folder name
 * and ALLOW_TOKENS; an element marked `data-raw-ok` (a citation line, the folded "기타 필드" raw
 * keys) is a deliberate raw display.
 *
 * Read-only by construction: every non-GET `/api` request (and the GETs that write, such as the
 * validation-package file) is aborted, nothing is exported, sampled or analysed.
 *
 * Runs only against a real-data server (skipped otherwise):
 *   RAW_VALUES_BASE_URL=http://127.0.0.1:5813 RAW_VALUES_TOKEN=… RAW_VALUES_RUNS=b5fabbe09f18,af54ff24ed5f \
 *     npx playwright test raw-values --config e2e/playwright.config.ts
 * RAW_VALUES_REPORT=1 logs every offender and never fails (before/after measurement).
 */

const BASE = process.env.RAW_VALUES_BASE_URL ?? "";
const TOKEN = process.env.RAW_VALUES_TOKEN ?? "";
const RUNS = (process.env.RAW_VALUES_RUNS ?? "").split(",").filter(Boolean);
const REPORT_ONLY = process.env.RAW_VALUES_REPORT === "1";

test.skip(!BASE || !TOKEN || RUNS.length === 0, "real-data raw-value scan: set RAW_VALUES_* (see header)");
test.use({ baseURL: BASE || undefined, viewport: { width: 1600, height: 1000 }, locale: "ko-KR" });
test.describe.configure({ mode: "serial", timeout: 900_000 });

/**
 * Grid columns whose cells hold evidence text (names, paths, URLs, titles, free text, record
 * values): only a JSON preview is a defect there. Catalogue columns (`d:<key>`) are evidence when
 * their key names a free value (…name, …path, title, url, product, publisher …) unless the key is a
 * labelled enum (LABELLED_KEYS). Every other cell is a label cell: each comma-separated item that
 * is a single raw token fails.
 */
// r7 S1 sweep (run-subset10): the 12+ lower-case `title` / `sum:main` cells of 전체 아티팩트 are
// one browser page title as the site wrote it (`omnifit`, URL medicms.omnifit.co.kr) — evidence,
// shown as written.
const EVIDENCE_COLUMNS = [
  "title",
  "name",
  "path",
  "sourcePath",
  "url",
  "value",
  "target",
  "summary",
  "detail",
  "snippet",
  "sha256",
  "md5",
  "sha1",
  "hash",
  "key",
  "keyPath",
  "keywords",
  "data",
  "user",
  "account",
  "host",
  "device",
  "subject",
  "sender",
  "recipient",
  "body",
  "message",
  "command",
  "commandLine",
  "args",
  "sum:main",
  "sum:support",
  "sum:extra",
];
/**
 * Catalogue keys that hold free evidence values (by the key's last word). `product_name` /
 * `publisher` (columns 제품 · 게시자, windows-execution): Amcache stores both lower-cased
 * (`installshield`, `bandizip`, `microsoft`, `estsoft` … on run-subset10, r7 S1) — evidence
 * spellings, kept as written.
 */
const EVIDENCE_KEY =
  /(name|names|path|paths|title|url|uri|description|comment|strings|hash|publisher|product|value|values|data|target|user|account|host|computer|command|arguments|args|keyword|keywords|subject|sender|recipient|body|message|text|domain|email|file|folder|dir|key|sid|guid|id|version|guidance|location|address|serial|label|model|models|server|commit)$/i;
/** Catalogue keys with value labels (src/features/grid/valueLabels.ts KEY_DOMAINS): always checked. */
const LABELLED_KEYS = [
  "browser",
  "browser_name",
  "drive_type_name",
  "drive_type",
  "item_kind",
  "shell_item_kind",
  "binary_type",
  "content_format",
  "image_format",
  "evidence_nature",
  "danger_type",
  "hive_hint",
  "score_semantics",
];
/**
 * Tokens that are legitimately lower-case or constant-cased: encodings, hash algorithms, the
 * external tools the console names (product names, written as their executables are), and the
 * documented USN reason flags a triage rule's rationale cites.
 */
const ALLOW_TOKENS = [
  "utf-8",
  "utf-16",
  "utf-16le",
  "utf-16be",
  "md5",
  "sha1",
  "sha256",
  "sha-256",
  "icat",
  "fls",
  "mmls",
  "ewfmount",
  "tsk_recover",
  "libewf",
  "pffexport",
  "readpst",
  "tesseract",
  "tessdata",
  "BASIC_INFO_CHANGE",
  "RENAME_NEW_NAME",
  // Python packages the 환경 점검 names (product names).
  "rapidtriage",
  "fastapi",
  "uvicorn",
  // AI tool product names written in lower case (R7 AI 사용, catalog names).
  "oh-my-opencode",
  "claude-swap",
];

interface Offender {
  token: string;
  where: string;
}

/**
 * In-page scan of `selector` (all matches): offending tokens with where they were seen. `allow` adds
 * case values that are evidence names (the run's evidence source folder).
 */
async function scan(page: Page, selector: string, allow: readonly string[] = []): Promise<Offender[]> {
  return page.evaluate(
    ({ selector, evidence, labelled, evidenceKey, allow }) => {
      const evidenceCols = new Set(evidence);
      const labelledKeys = new Set(labelled);
      const evidenceKeyRe = new RegExp(evidenceKey, "i");
      const allowed = new Set(allow.map((token) => token.toLowerCase()));
      const out: Array<{ token: string; where: string }> = [];
      const SKIP =
        "[data-raw-ok], a[href], input, textarea, select, code, pre, .mid-path, .hex-view, .text-view, [data-testid='hex-scroll'], .meta-hexdump, .meta-binary-strings, [data-testid='registry-explorer-tree'], .sr-only, script, style, svg";
      const isRawToken = (token: string) => {
        if (token.length < 3 || allowed.has(token.toLowerCase())) return false;
        if (/^\d/.test(token)) return false; // numbers, sizes, dates, 0x…
        if (/^[0-9a-f]{8,}$/.test(token) && /\d/.test(token)) return false; // hashes, short ids
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) return false;
        if (/^s-1-[0-9-]+$/i.test(token)) return false; // SIDs
        if (/^[a-z0-9_-]{3,}$/.test(token) && /[a-z]/.test(token)) return true;
        return /^[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+$/.test(token); // snake_case keys
      };
      const trim = (raw: string) => raw.replace(/^[([{"'“‘«·•…,;:]+|[)\]}"'”’»·•…,;:.!?]+$/g, "");
      const words = (text: string) => {
        const tokens: string[] = [];
        for (const raw of text.split(/\s+/)) {
          const word = trim(raw);
          if (!word) continue;
          // Paths, URLs, file names, e-mail addresses, domains are evidence.
          if (/[\\.:@]/.test(word) || word.startsWith("/")) continue;
          if (word.includes("/")) {
            const parts = word.split("/");
            if (parts.length <= 3) tokens.push(...parts);
            continue;
          }
          tokens.push(word);
        }
        return tokens;
      };
      /** A label cell: each list item that is one raw token (a free-text item is a value). */
      const items = (text: string) =>
        text
          .split(/,\s*|\s·\s/)
          .map((item) => trim(item.trim()))
          .filter((item) => item && !/\s/.test(item) && !/[\\.:@/]/.test(item));
      const describe = (el: Element) => {
        const cell = el.closest("[data-col]");
        if (cell) return `col:${cell.getAttribute("data-col")}`;
        const dt = el.closest("dt, dd");
        if (dt) return dt.tagName.toLowerCase();
        const tagged = el.closest("[data-testid]");
        return tagged ? `#${tagged.getAttribute("data-testid")}` : el.tagName.toLowerCase();
      };
      const visible = (el: Element) => {
        const withCheck = el as Element & { checkVisibility?: (options?: object) => boolean };
        if (withCheck.checkVisibility)
          return withCheck.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true });
        return el.getClientRects().length > 0;
      };
      const evidenceCell = (col: string) => {
        if (evidenceCols.has(col) || col.startsWith("fields.")) return true;
        const key = col.startsWith("d:") ? col.slice(2) : col.startsWith("fam:") ? col.slice(4) : null;
        if (key === null) return false;
        if (labelledKeys.has(key)) return false;
        return evidenceKeyRe.test(key);
      };
      for (const root of Array.from(document.querySelectorAll(selector))) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
          const text = node.textContent ?? "";
          if (!text.trim()) continue;
          const parent = node.parentElement;
          if (!parent || parent.closest(SKIP) || !visible(parent)) continue;
          // Closed <details>: only the summary is on screen.
          const closed = parent.closest("details:not([open])");
          if (closed && !parent.closest("summary")) continue;
          const where = describe(parent);
          if (text.trim().startsWith('{"')) {
            out.push({ token: text.trim().slice(0, 40), where });
            continue;
          }
          const cell = parent.closest("[role='gridcell'][data-col]");
          // An older output's producer prefix ("Artifact event: <type> …", C-D13) is never shown.
          if (/^(Artifact event: |EventLog event: )/.test(text.trim())) {
            out.push({ token: text.trim().slice(0, 40), where });
            continue;
          }
          if (cell) {
            const col = cell.getAttribute("data-col") ?? "";
            if (evidenceCell(col)) continue;
            for (const item of items(text)) if (isRawToken(item)) out.push({ token: item, where });
            continue;
          }
          // Record values (meta `dd`) are evidence; their keys (`dt`) and every label are checked.
          if (parent.closest("dd")) continue;
          for (const token of words(text)) if (isRawToken(token)) out.push({ token, where });
        }
      }
      return out;
    },
    {
      selector,
      evidence: EVIDENCE_COLUMNS,
      labelled: LABELLED_KEYS,
      evidenceKey: EVIDENCE_KEY.source,
      allow: [...ALLOW_TOKENS, ...allow],
    },
  );
}

/** Names that are evidence, not ids: the run's evidence source folder (shown in the tree). */
async function evidenceNames(page: Page, runId: string): Promise<string[]> {
  const response = await page.request.get(`/api/runs/${runId}/summary`, {
    headers: { "X-RapidTriage-Token": TOKEN },
  });
  if (!response.ok()) return [];
  const summary = (await response.json()) as { root?: string; source?: { source_path?: string } };
  return [summary.root, summary.source?.source_path]
    .filter((value): value is string => typeof value === "string" && value !== "")
    .map((value) => value.split(/[\\/]/).filter(Boolean).pop() ?? "")
    .filter(Boolean);
}

async function blockWrites(page: Page) {
  await page.route("**/api/**", (route) => {
    const request = route.request();
    const url = request.url();
    if (request.method() !== "GET" || /validation-package|\/export|sample-case|thumbnail|gallery/.test(url))
      return route.abort();
    return route.continue();
  });
}

async function start(page: Page) {
  await blockWrites(page);
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
}

async function openHash(page: Page, hash: string) {
  await page.goto(`/v2/#/${hash}`);
  await expect(page.getByTestId("topbar")).toBeVisible();
}

/** Wait for a grid node: the grid shows rows or its empty state, then let late labels settle. */
async function settleGrid(page: Page) {
  await expect(page.getByTestId("grid-region")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("grid-loading")).toHaveCount(0, { timeout: 180_000 });
  await page.waitForTimeout(800);
}

const results: Record<string, number> = {};
const failures: string[] = [];

function record(screen: string, offenders: Offender[]) {
  results[screen] = offenders.length;
  if (!offenders.length) return;
  const unique = new Map<string, number>();
  for (const offender of offenders) {
    const key = `${offender.where} ${offender.token}`;
    unique.set(key, (unique.get(key) ?? 0) + 1);
  }
  const lines = [...unique.entries()].map(([key, count]) => `${key}${count > 1 ? ` ×${count}` : ""}`);
  failures.push(`${screen}: ${lines.slice(0, 40).join(" | ")}`);
  console.log(`[raw-values] ${screen}: ${offenders.length} — ${lines.slice(0, 60).join(" | ")}`);
}

/** One screen: a navigation or UI step that fails is a recorded failure, the walk goes on. */
async function screen(name: string, body: () => Promise<void>) {
  try {
    await body();
  } catch (error) {
    results[name] = -1;
    failures.push(`${name}: step failed — ${String(error).split("\n")[0]}`);
    console.log(`[raw-values] ${name}: step failed — ${String(error).split("\n")[0]}`);
  }
}

function assertClean(from: number) {
  const mine = failures.slice(from);
  if (!REPORT_ONLY) expect(mine, mine.join(" || ")).toEqual([]);
}

/** AI 사용 nodes (R7 AI 갈래 D, frontend/src/features/tree/domains.ts AI_USAGE_DOMAIN). */
const AI_NODES = [
  "explore/artifacts/ai-agent",
  "explore/artifacts/ai-agent?types=ai-tool-presence",
  "explore/artifacts/ai-agent?types=ai-agent-session",
  "explore/artifacts/ai-agent?types=ai-agent-message",
  "explore/artifacts/ai-agent?types=ai-agent-tool-call",
  "explore/artifacts/ai-agent?types=ai-agent-file-touch",
  "explore/artifacts/ai-agent?types=ai-mcp-server",
  "explore/artifacts/ai-agent?types=ai-instruction-file",
  "explore/artifacts/ai-agent?types=ai-credential-presence",
  "explore/artifacts/ai-agent?types=ai-account,ai-account-switch",
  "explore/artifacts/ai-agent?types=ai-code-attribution",
  "explore/artifacts/ai-agent?types=ai-usage-stat",
  "explore/artifacts/ai-agent?types=ai-retention-cleanup",
];

/** Grid nodes per run (route below `#/case/{run}/`). */
const GRID_NODES = [
  "explore/files",
  "explore/files?dir=%2F",
  "explore/artifacts",
  "explore/timeline",
  "explore/docs",
  "explore/indicators",
  "explore/search?q=zzqq",
  "explore/artifacts?flag_grade=C",
  "explore/artifacts/browser",
  "explore/artifacts/browser?types=browser-history",
  "explore/artifacts/eventlog?types=eventlog-event",
  "explore/artifacts/windows-prefetch",
  "explore/artifacts/recent-files",
  "explore/artifacts/windows-registry",
  "explore/artifacts/windows-execution",
  "explore/artifacts/windows-system",
  "explore/artifacts/media-image",
  "explore/artifacts/generic-documents",
  "explore/artifacts/kakaotalk-windows",
  "explore/artifacts/windows-shellbags",
  "explore/artifacts/windows-os-account",
  "explore/artifacts/synthetic-media",
  // R7 AI 사용 (갈래 D): every AI 사용 node (empty on runs without AI rows) and a session's 대화 보기.
  ...AI_NODES,
  "explore/artifacts/ai-agent?types=ai-agent-session,ai-agent-message,ai-agent-tool-call,ai-agent-file-touch&view=chat",
];

/** Nodes whose first row's viewer meta panel is scanned. */
const META_NODES = [
  "explore/artifacts/browser?types=browser-history",
  "explore/artifacts/eventlog?types=eventlog-event",
  "explore/artifacts/windows-prefetch",
  "explore/artifacts/recent-files",
  "explore/artifacts/media-image",
  "explore/artifacts/kakaotalk-windows",
  "explore/indicators",
  "explore/files",
  "explore/timeline",
  "explore/artifacts/windows-registry",
  // R7 AI 사용: session (links + 핵심), message, tool call, file touch, MCP, credential, account.
  "explore/artifacts/ai-agent?types=ai-agent-session",
  "explore/artifacts/ai-agent?types=ai-agent-message",
  "explore/artifacts/ai-agent?types=ai-agent-tool-call",
  "explore/artifacts/ai-agent?types=ai-agent-file-touch",
  "explore/artifacts/ai-agent?types=ai-mcp-server",
  "explore/artifacts/ai-agent?types=ai-credential-presence",
  "explore/artifacts/ai-agent?types=ai-account,ai-account-switch",
];

const GRID_SCOPE = "[data-testid='grid-region'], [data-testid='tree-region'], [data-testid='statusbar']";

for (const runId of RUNS) {
  const tag = runId.slice(0, 4);

  test(`grid nodes have no raw values (${tag})`, async ({ page }) => {
    const from = failures.length;
    await start(page);
    const names = await evidenceNames(page, runId);
    for (const node of GRID_NODES) {
      await screen(`${tag} grid ${node}`, async () => {
        await openHash(page, `case/${runId}/${node}`);
        await settleGrid(page);
        // The examiner's own search words are shown back to them (the empty state names them).
        const query = new URLSearchParams(node.split("?")[1] ?? "").get("q");
        record(
          `${tag} grid ${node}`,
          await scan(page, GRID_SCOPE, [...names, ...(query ? query.split(/\s+/) : [])]),
        );
      });
    }
    // C-V1: the artifact histogram's bars carry unique labels (a kind split over groups names it).
    await screen(`${tag} histogram labels`, async () => {
      await openHash(page, `case/${runId}/explore/artifacts?view=histogram`);
      const labels = page.locator(".hist-cat-label");
      await expect(labels.first()).toBeVisible({ timeout: 120_000 });
      const texts = await labels.allInnerTexts();
      const duplicates = texts.filter((text, index) => texts.indexOf(text) !== index);
      console.log(
        `[raw-values] ${tag} histogram labels: ${texts.length} bars, ${new Set(texts).size} unique`,
      );
      record(
        `${tag} histogram labels`,
        duplicates.map((token) => ({ token, where: "duplicate histogram label" })),
      );
      record(`${tag} histogram raw`, await scan(page, ".hist-cats", names));
    });
    await screen(`${tag} registry explorer`, async () => {
      await openHash(page, `case/${runId}/explore/registry`);
      await expect(page.getByTestId("registry-explorer")).toBeVisible({ timeout: 120_000 });
      await page.waitForTimeout(1500);
      record(`${tag} registry explorer`, await scan(page, "[data-testid='registry-explorer']", names));
    });
    assertClean(from);
  });

  test(`viewer meta panels have no raw keys (${tag})`, async ({ page }) => {
    const from = failures.length;
    await start(page);
    const names = await evidenceNames(page, runId);
    for (const node of META_NODES) {
      await screen(`${tag} meta ${node}`, async () => {
        await openHash(page, `case/${runId}/${node}`);
        await settleGrid(page);
        const first = page.locator("[role='grid'] [role='row'][aria-rowindex='2'] [role='gridcell']").nth(1);
        if (!(await first.count())) throw new Error("no rows to open");
        await first.click();
        await expect(page.getByTestId("viewer-region")).toBeVisible({ timeout: 60_000 });
        await page.waitForTimeout(1500);
        record(`${tag} meta ${node}`, await scan(page, "[data-testid='viewer-region']", names));
      });
    }
    assertClean(from);
  });

  test(`popovers have no raw keys (${tag})`, async ({ page }) => {
    const from = failures.length;
    await start(page);
    const names = await evidenceNames(page, runId);
    // 1–2: rule-evidence popovers (특이사항 cells of two nodes).
    for (const node of [
      "explore/artifacts?flag_grade=B",
      "explore/artifacts/browser?types=browser-download",
    ]) {
      await screen(`${tag} popover flags ${node}`, async () => {
        await openHash(page, `case/${runId}/${node}`);
        await settleGrid(page);
        const cell = page.locator("button.flag-cell").first();
        await expect(cell).toBeVisible({ timeout: 30_000 });
        await cell.click();
        await expect(page.locator(".flag-popover")).toBeVisible();
        record(`${tag} popover flags ${node}`, await scan(page, ".flag-popover", names));
        await page.keyboard.press("Escape");
      });
    }
    // 3: search options.
    await screen(`${tag} popover search options`, async () => {
      await openHash(page, `case/${runId}/explore/files`);
      await settleGrid(page);
      await page.getByRole("button", { name: "검색 옵션" }).first().click();
      const dialog = page.getByRole("dialog", { name: "검색 옵션" });
      await expect(dialog).toBeVisible();
      record(`${tag} popover search options`, await scan(page, "[role='dialog']", names));
      await page.keyboard.press("Escape");
    });
    // 4: intake 처리 경고·제한 사항 card, every expander open.
    await screen(`${tag} popover disclosures`, async () => {
      await openHash(page, `case/${runId}/intake`);
      const card = page.getByTestId("warnings-card");
      await expect(card).toBeVisible({ timeout: 180_000 });
      for (const summary of await card.locator("details > summary").all()) await summary.click();
      await page.waitForTimeout(500);
      record(`${tag} popover disclosures`, await scan(page, "[data-testid='warnings-card']", names));
    });
    // 5: 환경 점검 (doctor) dialog — opened from the command palette.
    await screen(`${tag} popover doctor`, async () => {
      await page.getByRole("button", { name: "명령 팔레트" }).click();
      await page.keyboard.type("환경 점검");
      await page.keyboard.press("Enter");
      const doctor = page.getByRole("dialog", { name: "환경 점검" });
      await expect(doctor).toBeVisible();
      await expect(doctor.getByRole("list", { name: "점검 항목" })).toBeVisible({ timeout: 60_000 });
      record(`${tag} popover doctor`, await scan(page, "[role='dialog']", names));
      await page.keyboard.press("Escape");
    });
    assertClean(from);
  });

  // R-7 / R-10: the accept-stage 단계 상세 card and the 출처 section of a record.
  test(`stage details and source section have no raw values (${tag})`, async ({ page }) => {
    const from = failures.length;
    await start(page);
    const names = await evidenceNames(page, runId);
    await screen(`${tag} intake stage details`, async () => {
      await openHash(page, `case/${runId}/intake`);
      const details = page.getByTestId("stage-details");
      await expect(details).toBeVisible({ timeout: 180_000 });
      await details.locator("summary").click();
      await page.waitForTimeout(500);
      record(`${tag} intake stage details`, await scan(page, "[data-testid='stage-details']", names));
    });
    await screen(`${tag} viewer source section`, async () => {
      await openHash(page, `case/${runId}/explore/artifacts/windows-execution`);
      await settleGrid(page);
      const first = page.locator("[role='grid'] [role='row'][aria-rowindex='2'] [role='gridcell']").nth(1);
      if (!(await first.count())) throw new Error("no rows to open");
      await first.click();
      const source = page.locator("[data-testid='viewer-region'] section[aria-label='출처']");
      await expect(source).toBeVisible({ timeout: 60_000 });
      await page.waitForTimeout(500);
      record(
        `${tag} viewer source section`,
        await scan(page, "[data-testid='viewer-region'] section[aria-label='출처']", names),
      );
      // Values under 출처 are not walked by scan() (dd = evidence); an enumerated id is never evidence.
      const values = (await source.locator("dd").allInnerTexts()).map((text) => text.trim());
      const enumerated = values
        .filter((text) => text !== runId && /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/.test(text))
        .map((token) => ({ token, where: "출처 dd" }));
      record(`${tag} viewer source values`, enumerated);
    });
    assertClean(from);
  });
}

test.afterAll(() => {
  console.log(`[raw-values] counts ${JSON.stringify(results)}`);
});
