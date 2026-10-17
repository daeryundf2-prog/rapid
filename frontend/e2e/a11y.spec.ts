// Accessibility E2E (plan §4.4, Q-A1, Q-A3, Q-A6). Authored for the redesigned console;
// not executed by the S5 stream. `@axe-core/playwright` is not installed (npm ls is empty,
// offline), so the rule set below is self-contained and runs in-page.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, type Page, test } from "@playwright/test";

const TOKEN = "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const COLLECTIONS = [
  "intake",
  "search",
  "files",
  "docs",
  "artifacts",
  "timeline",
  "indicators",
  "review",
  "outputs",
  // Stages (console-ia §3, Q-IA-5): 처리 page + a selected card, analysis results, 검토 / 보고.
  "process",
  "process/carve",
  "explore/analysis/carve",
  "review/board/relevant",
  "report/outputs",
  // 통합 보기 (axiom-adoption §3.2, Q-X12).
  "explore/derived/people",
  "explore/derived/paths",
] as const;

let runId = "";

test.beforeAll(async ({ request }) => {
  const outputDir = mkdtempSync(join(tmpdir(), "rt-v2-a11y-sample-"));
  const created = await request.post("/api/sample-case/run", {
    headers: HEADERS,
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  expect(created.status()).toBe(201);
  const list = await request.get("/api/runs", { headers: HEADERS });
  const body = (await list.json()) as { runs: Array<{ run_id: string }> };
  runId = body.runs[0]?.run_id ?? "";
  expect(runId).not.toBe("");
});

async function openRoute(page: Page, collection: string) {
  await page.goto(`/v2/#token=${TOKEN}`);
  await page.evaluate(
    ([run, col]) => {
      window.location.hash = `#/case/${run}/${col}`;
    },
    [runId, collection] as const,
  );
  await expect(page.locator("main, [role=main]").first()).toBeVisible();
  await page.waitForLoadState("networkidle");
}

interface Violation {
  rule: string;
  detail: string;
}

/** Self-contained replacement for axe: runs inside the page, returns violations. */
async function audit(page: Page): Promise<Violation[]> {
  return page.evaluate(() => {
    const out: Array<{ rule: string; detail: string }> = [];
    const visible = (el: Element) => {
      const s = getComputedStyle(el);
      return s.display !== "none" && s.visibility !== "hidden" && !el.closest("[hidden],[inert]");
    };
    const describe = (el: Element) =>
      `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${
        typeof el.className === "string" && el.className ? `.${el.className.split(" ")[0]}` : ""
      }`;
    const nameOf = (el: Element): string => {
      const label = el.getAttribute("aria-label")?.trim();
      if (label) return label;
      const by = el.getAttribute("aria-labelledby");
      if (by) {
        const t = by
          .split(/\s+/)
          .map((id) => document.getElementById(id)?.textContent?.trim() ?? "")
          .join(" ")
          .trim();
        if (t) return t;
      }
      const text = (el.textContent ?? "").trim();
      if (text) return text;
      if (el.querySelector("img[alt]:not([alt=''])")) return "img";
      return (el.getAttribute("title") ?? "").trim();
    };

    // 1. Every button/link/role=button has an accessible name.
    for (const el of document.querySelectorAll("button,a[href],[role=button],[role=link],[role=tab]")) {
      if (visible(el) && !nameOf(el)) out.push({ rule: "accessible-name", detail: describe(el) });
    }
    // 2. Form fields have names.
    for (const el of document.querySelectorAll("input:not([type=hidden]),select,textarea")) {
      const labelled =
        (el as HTMLInputElement).labels?.length || nameOf(el) || el.getAttribute("placeholder");
      if (visible(el) && !labelled) out.push({ rule: "field-name", detail: describe(el) });
    }
    // 3. No duplicate ids.
    const seen = new Map<string, number>();
    for (const el of document.querySelectorAll("[id]")) seen.set(el.id, (seen.get(el.id) ?? 0) + 1);
    for (const [id, n] of seen) if (n > 1) out.push({ rule: "duplicate-id", detail: `#${id} x${n}` });
    // 4. Exactly one main landmark, plus banner/nav/contentinfo present once.
    const mains = document.querySelectorAll("main,[role=main]").length;
    if (mains !== 1) out.push({ rule: "main-landmark", detail: `${mains} main landmarks` });
    for (const [sel, name] of [
      ["header,[role=banner]", "banner"],
      ["footer,[role=contentinfo]", "contentinfo"],
    ] as const) {
      if (document.querySelectorAll(sel).length > 1) out.push({ rule: "landmark-unique", detail: name });
    }
    // 5. tablist / tab / tabpanel wiring.
    for (const list of document.querySelectorAll("[role=tablist]")) {
      const tabs = Array.from(list.querySelectorAll("[role=tab]"));
      if (tabs.length === 0) out.push({ rule: "tablist-empty", detail: describe(list) });
      const selected = tabs.filter((t) => t.getAttribute("aria-selected") === "true");
      if (tabs.length && selected.length !== 1) {
        out.push({ rule: "tab-selected", detail: `${describe(list)} has ${selected.length} selected` });
      }
      const tabStops = tabs.filter((t) => (t as HTMLElement).tabIndex === 0);
      if (tabs.length && tabStops.length !== 1) {
        out.push({ rule: "tab-roving", detail: `${describe(list)} has ${tabStops.length} tab stops` });
      }
      for (const t of tabs) {
        const panelId = t.getAttribute("aria-controls");
        const panel = panelId ? document.getElementById(panelId) : null;
        if (panel === null || panel.getAttribute("role") !== "tabpanel") {
          out.push({ rule: "tab-panel", detail: `${describe(t)} -> #${panelId}` });
        } else if (!(panel.getAttribute("aria-labelledby") ?? "").split(/\s+/).includes(t.id)) {
          out.push({ rule: "tabpanel-labelledby", detail: describe(panel) });
        }
      }
    }
    // 6. Grids: rowcount, row roles, aria-selected on rows, exactly one roving row stop.
    for (const grid of document.querySelectorAll("[role=grid]")) {
      if (!grid.hasAttribute("aria-rowcount")) out.push({ rule: "grid-rowcount", detail: describe(grid) });
      if (!nameOf(grid)) out.push({ rule: "grid-name", detail: describe(grid) });
      const rows = Array.from(grid.querySelectorAll("[role=row]")).filter(
        (r) => r.querySelector("[role=gridcell],[role=rowheader]") !== null,
      );
      const stops = rows.filter((r) => (r as HTMLElement).tabIndex === 0);
      if (rows.length && stops.length !== 1) {
        out.push({ rule: "grid-roving", detail: `${describe(grid)} has ${stops.length} row tab stops` });
      }
      for (const r of rows) {
        if (!r.hasAttribute("aria-selected")) out.push({ rule: "row-selected", detail: describe(r) });
        if (!r.hasAttribute("aria-rowindex")) out.push({ rule: "row-index", detail: describe(r) });
      }
    }
    // 7. Tree semantics.
    for (const item of document.querySelectorAll("[role=treeitem]")) {
      if (!item.hasAttribute("aria-level")) out.push({ rule: "treeitem-level", detail: describe(item) });
      if (!item.closest("[role=tree]")) out.push({ rule: "treeitem-orphan", detail: describe(item) });
    }
    // 8. aria-hidden must not wrap focusable content.
    for (const el of document.querySelectorAll("[aria-hidden=true]")) {
      if (el.querySelector("a[href],button:not([disabled]),input,select,textarea,[tabindex='0']")) {
        out.push({ rule: "aria-hidden-focusable", detail: describe(el) });
      }
    }
    // 9. Live regions: at most one polite and one assertive region mounted.
    const polite = document.querySelectorAll("[aria-live=polite],[role=status]").length;
    const assertive = document.querySelectorAll("[aria-live=assertive],[role=alert]").length;
    if (polite !== 1) out.push({ rule: "live-polite", detail: `${polite} polite regions` });
    if (assertive > 1) out.push({ rule: "live-assertive", detail: `${assertive} assertive regions` });
    // 10. Images have alt; skip link exists and its target resolves.
    for (const img of document.querySelectorAll("img:not([alt])"))
      out.push({ rule: "img-alt", detail: describe(img) });
    const skip = document.querySelector("a.skip-link, a[href^='#main']");
    if (!skip) out.push({ rule: "skip-link", detail: "missing" });
    else if (!document.getElementById((skip.getAttribute("href") ?? "").replace(/^#/, ""))) {
      out.push({ rule: "skip-link-target", detail: skip.getAttribute("href") ?? "" });
    }
    // 11. html lang + title.
    if (!document.documentElement.lang) out.push({ rule: "html-lang", detail: "missing" });
    if (!document.title.trim()) out.push({ rule: "document-title", detail: "missing" });
    return out;
  });
}

for (const collection of COLLECTIONS) {
  test(`self-contained a11y rules pass on /case/${collection}`, async ({ page }) => {
    await openRoute(page, collection);
    expect(await audit(page)).toEqual([]);
  });
}

test("focus is visible after Tab on every route", async ({ page }) => {
  for (const collection of COLLECTIONS) {
    await openRoute(page, collection);
    await page.keyboard.press("Tab");
    const state = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return { ok: false, why: "no focus" };
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      const outlined = s.outlineStyle !== "none" && Number.parseFloat(s.outlineWidth) > 0;
      const shadowed = s.boxShadow !== "none";
      const onScreen = r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0;
      return {
        ok: onScreen && (outlined || shadowed),
        why: `${el.tagName} outline=${s.outline} shadow=${s.boxShadow}`,
      };
    });
    expect(state.ok, `${collection}: ${state.why}`).toBe(true);
  }
});

test("first Tab stop is the skip link and it lands focus on main", async ({ page }) => {
  await openRoute(page, "files");
  await page.keyboard.press("Tab");
  const skip = page.locator("a.skip-link, a[href^='#main']").first();
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
  await expect(page).toHaveURL(/#\/case\//); // hash routing untouched
});

test("prefers-reduced-motion removes animation and transitions", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openRoute(page, "files");
  const offenders = await page.evaluate(() => {
    const bad: string[] = [];
    for (const el of document.querySelectorAll("*")) {
      const s = getComputedStyle(el);
      const dur = (v: string) => v.split(",").some((d) => Number.parseFloat(d) > 0.001);
      const animates = s.animationName !== "none" && dur(s.animationDuration);
      if (animates || dur(s.transitionDuration)) bad.push(`${el.tagName}.${(el as HTMLElement).className}`);
      if (bad.length > 10) break;
    }
    return bad;
  });
  expect(offenders).toEqual([]);
});

test("dark is the default whatever the OS; a chosen light theme is applied and persists (U-V1)", async ({
  page,
}) => {
  const background = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const themeAttr = () => page.evaluate(() => document.documentElement.dataset.theme ?? null);
  await page.emulateMedia({ colorScheme: "light" });
  await openRoute(page, "files");
  await page.evaluate(() => window.localStorage.removeItem("rapidtriage.v2.theme"));
  await page.reload();
  // No stored choice: dark, even on a light OS.
  expect(await themeAttr()).toBeNull();
  const bgDefault = await background();
  await page.emulateMedia({ colorScheme: "dark" });
  await page.reload();
  expect(await background()).toBe(bgDefault);
  // Choosing light applies it at once and survives a reload.
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  const bgLight = await background();
  expect(bgLight).not.toBe(bgDefault);
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await background()).toBe(bgLight);
  await page.evaluate(() => window.localStorage.removeItem("rapidtriage.v2.theme"));
});

test("Q-A1: keyboard-only loop (palette search, J x3, Enter, hex mode, R, review board)", async ({
  page,
}) => {
  await openRoute(page, "files");
  const requests: string[] = [];
  page.on("request", (r) => {
    if (r.method() !== "GET") requests.push(`${r.method()} ${new URL(r.url()).pathname}`);
  });

  await page.keyboard.press("Control+k");
  const palette = page.getByRole("dialog").first();
  await expect(palette).toBeVisible();
  await expect(palette.locator(":focus")).toHaveCount(1); // focus trapped inside
  await page.keyboard.type("powershell");
  await page.keyboard.press("Enter");

  await expect(page.getByRole("grid").first()).toBeVisible();
  for (let i = 0; i < 3; i++) await page.keyboard.press("j");
  // J moves keyboard focus (roving tabindex, .is-focused); it does not change the
  // checkbox selection, so aria-selected is not the signal here.
  const focusedRow = page.locator('[role="row"][tabindex="0"]');
  await expect(focusedRow).toHaveCount(1);
  await expect(focusedRow).toBeFocused();

  await page.keyboard.press("Enter");
  const viewer = page.getByRole("region", { name: "원본 뷰어" });
  await expect(viewer).toBeVisible();
  await expect(viewer.locator(":focus")).toHaveCount(1); // Enter moves focus into the viewer

  // Switch to the hex mode tab with arrow keys (roving tablist).
  const tablist = viewer.getByRole("tablist");
  await tablist.getByRole("tab", { selected: true }).focus();
  for (let i = 0; i < 6; i++) {
    const name = await page.evaluate(() => document.activeElement?.textContent ?? "");
    if (/hex|헥스/i.test(name)) break;
    await page.keyboard.press("ArrowRight");
  }
  await expect(tablist.getByRole("tab", { name: /hex|헥스/i })).toHaveAttribute("aria-selected", "true");

  // Mark relevant: R while focus is on the grid/viewer; must hit the review API.
  const review = page.waitForRequest((r) => /case-db\/review/.test(r.url()) && r.method() !== "GET");
  await page.keyboard.press("r");
  await review;

  await page.evaluate(
    ([run]) => {
      window.location.hash = `#/case/${run}/review`;
    },
    [runId] as const,
  );
  await expect(page.getByRole("grid").first()).toBeVisible();
  expect(requests.some((r) => r.includes("case-db/review"))).toBe(true);
});

test("Q-A3: every visible control does something (request, URL/aria change, or disabled with reason)", async ({
  page,
}) => {
  test.setTimeout(1_800_000); // full route sweep: ~5 min of clicks on a slow run
  const unresponsive: string[] = [];
  for (const collection of COLLECTIONS) {
    await openRoute(page, collection);
    const total = await page.locator("button,[role=button],a[href]").count();
    for (let i = 0; i < total; i++) {
      // Re-open every few controls: an earlier click may have navigated or opened an overlay.
      if (i > 0 && i % 20 === 0) await openRoute(page, collection);
      const target = page.locator("button,[role=button],a[href]").nth(i);
      if (!(await target.isVisible().catch(() => false))) continue;
      const label = (
        await target.evaluate(
          (el) => `${el.tagName}:${el.getAttribute("aria-label") ?? el.textContent?.trim()}`,
        )
      ).slice(0, 80);

      const disabledReason = await target.evaluate((el) => {
        const disabled = el.getAttribute("aria-disabled") === "true" || (el as HTMLButtonElement).disabled;
        if (!disabled) return null;
        const ids = (el.getAttribute("aria-describedby") ?? "").split(/\s+/).filter(Boolean);
        return ids
          .map((id) => document.getElementById(id)?.textContent?.trim() ?? "")
          .join(" ")
          .trim();
      });
      if (disabledReason !== null) {
        if (!disabledReason) unresponsive.push(`${collection} ${label}: disabled without a reason`);
        continue;
      }

      const before = await page.evaluate(() => ({
        url: location.href,
        html: document.body.innerHTML.length,
        expanded: Array.from(
          document.querySelectorAll("[aria-expanded],[aria-pressed],[aria-selected],[aria-checked]"),
        )
          .map(
            (e) =>
              `${e.getAttribute("aria-expanded")}${e.getAttribute("aria-pressed")}${e.getAttribute("aria-selected")}${e.getAttribute("aria-checked")}`,
          )
          .join(","),
        theme: document.documentElement.dataset.theme ?? "",
        focus: document.activeElement?.outerHTML.slice(0, 120) ?? "",
        dialogs: document.querySelectorAll("[role=dialog]").length,
      }));
      let requested = false;
      const onRequest = () => {
        requested = true;
      };
      page.on("request", onRequest);
      // Never leave the app or trigger real downloads: block external navigation, tolerate downloads.
      // Off-screen links (the skip link sits above the viewport until focused) cannot be
      // clicked; activate them with focus + Enter, the same path a keyboard user takes.
      const offscreen = await target.evaluate((el) => {
        const r = el.getBoundingClientRect();
        return r.width === 0 || r.bottom <= 0 || r.right <= 0 || r.top >= innerHeight || r.left >= innerWidth;
      });
      if (offscreen) {
        await target.focus().catch(() => undefined);
        await page.keyboard.press("Enter");
      } else {
        await target.click({ timeout: 3000, noWaitAfter: true }).catch(() => undefined);
      }
      await page.waitForTimeout(250);
      page.off("request", onRequest);
      const after = await page.evaluate(() => ({
        url: location.href,
        html: document.body.innerHTML.length,
        expanded: Array.from(
          document.querySelectorAll("[aria-expanded],[aria-pressed],[aria-selected],[aria-checked]"),
        )
          .map(
            (e) =>
              `${e.getAttribute("aria-expanded")}${e.getAttribute("aria-pressed")}${e.getAttribute("aria-selected")}${e.getAttribute("aria-checked")}`,
          )
          .join(","),
        theme: document.documentElement.dataset.theme ?? "",
        focus: document.activeElement?.outerHTML.slice(0, 120) ?? "",
        dialogs: document.querySelectorAll("[role=dialog]").length,
      }));
      const changed = JSON.stringify(before) !== JSON.stringify(after);
      if (!requested && !changed) unresponsive.push(`${collection} ${label}`);
      await page.keyboard.press("Escape"); // close any overlay the click opened
    }
  }
  expect(unresponsive, `unresponsive controls:\n${unresponsive.join("\n")}`).toEqual([]);
});

test("viewer-families: the viewer window, the 조건 panel and shown empty families pass the rules", async ({
  page,
  context,
}) => {
  await openRoute(page, "explore/files");
  // Empty families shown dimmed with their reason (U-F7).
  await page.locator("body").press("t");
  await expect(page.getByTestId("tree-empty-toggle")).toHaveAttribute("aria-pressed", "true");
  expect(await audit(page)).toEqual([]);
  await page.locator("body").press("t");
  // 조건 panel open (U-F1).
  await page.getByTestId("filter-popover-button").click();
  await expect(page.getByRole("dialog", { name: "조건" })).toBeVisible();
  expect(await audit(page)).toEqual([]);
  await page.keyboard.press("Escape");
  // Viewer window (U-F2): one page, one landmark set; it has no skip link (a single region).
  await page.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first().click();
  const popupPromise = context.waitForEvent("page");
  await page.keyboard.press("Control+Shift+V");
  const popup = await popupPromise;
  await expect(popup.getByRole("region", { name: "원본 뷰어" })).toBeVisible();
  await expect(popup).toHaveTitle(/^뷰어 — /);
  const violations = (await audit(popup)).filter((v) => !v.rule.startsWith("skip-link"));
  expect(violations).toEqual([]);
  expect(await audit(page)).toEqual([]);
  await popup.close();
});
