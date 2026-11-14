// T-203 (GAP-342 / IS-134 / QA-195): interaction measurements for the IS-134 budget table.
// Every item is measured REPS (5) times after two unmeasured warm-up rounds (warm cache) and its p75
// (nearest rank) is written to a JSON file; a cell that could not be measured fails the run.
//
//   item                    trigger -> end                                       budget
//   jk_down                 J keydown -> next row painted as focused             50 ms
//   jk_up                   K keydown -> previous row painted as focused         50 ms
//   viewer_skeleton         row mousedown -> viewer first repaints for the row   100 ms
//   viewer_body             row mousedown -> viewer body ready (not busy)        500 ms
//   review_mark             R keydown -> row painted with the 관련 있음 mark      100 ms
//   category_first_row      tree item mousedown -> first row of the new list     1000 ms
//   search_first_result     Enter keydown in 전체 검색 -> first result row        1500 ms
//   scroll_dropped_frames   2 s of per-frame grid scrolling -> dropped frames    <= 5 %
//
// Times start at the input event's own timeStamp (taken in a capture listener before the app
// sees it) and end at the next paint after the DOM first shows the result: a MutationObserver
// (plus a per-frame check) notices the change, then requestAnimationFrame + a macrotask marks
// the frame that carries it (the Event Timing "next paint" approximation). Dropped frames come
// from requestAnimationFrame intervals while the grid's scroll container moves every frame.
//
// Not part of the default e2e run (playwright.config.ts collects e2e/perf only when asked):
//   npm run e2e -- e2e/perf/interaction.spec.ts        synthetic r8-rich fixture, own server
// Real data (C2) and the env knobs: e2e/perf/README.md.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, type Page, test } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const env = process.env;
const python = env.RAPIDTRIAGE_PYTHON || "python";
const TOKEN = env.RAPIDTRIAGE_PERF_TOKEN || "e2e-token";
const HEADERS = { "X-RapidTriage-Token": TOKEN };
const REAL_RUN_ID = env.RAPIDTRIAGE_PERF_RUN_ID || "";
const REPS = 5;
const WARMUP = 2;
const LABEL = env.RAPIDTRIAGE_PERF_LABEL || (REAL_RUN_ID ? "real" : "synthetic-r8-rich");
const GRID_KIND = env.RAPIDTRIAGE_PERF_GRID_KIND || "windows-filesystem";
const CATEGORIES = (env.RAPIDTRIAGE_PERF_CATEGORIES || "domain:web:web-all,domain:eventlog:evt-all")
  .split(",")
  .map((s) => s.trim());
const QUERIES = (env.RAPIDTRIAGE_PERF_QUERIES || "Chrome,합성,docx,Outlook,History,example,synth")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const OUTPUT = resolve(
  env.RAPIDTRIAGE_PERF_OUTPUT ||
    join(
      here,
      "..",
      "..",
      "test-results",
      "perf",
      `interaction-${new Date().toISOString().replace(/[:.]/g, "-")}.json`,
    ),
);
const COMPARE = env.RAPIDTRIAGE_PERF_COMPARE ? resolve(env.RAPIDTRIAGE_PERF_COMPARE) : "";
const VIEWPORT = { width: 1600, height: 1000 };
const SCROLL_FRAMES = 120;
const SCROLL_STEP_PX = 240;
const MAX_DEVIATION = 0.2;
const VIEWER_ROWS = [3, 5, 2, 4];

type ItemId =
  | "jk_down"
  | "jk_up"
  | "viewer_skeleton"
  | "viewer_body"
  | "review_mark"
  | "category_first_row"
  | "search_first_result"
  | "scroll_dropped_frames";

const ITEMS: Array<{ id: ItemId; label: string; budget: number; unit: "ms" | "%" }> = [
  { id: "jk_down", label: "J 선택 이동", budget: 50, unit: "ms" },
  { id: "jk_up", label: "K 선택 이동", budget: 50, unit: "ms" },
  { id: "viewer_skeleton", label: "행 선택 → 뷰어 골격", budget: 100, unit: "ms" },
  { id: "viewer_body", label: "행 선택 → 뷰어 본문", budget: 500, unit: "ms" },
  { id: "review_mark", label: "판단 키 → 화면 반영", budget: 100, unit: "ms" },
  { id: "category_first_row", label: "범주 클릭 → 첫 행", budget: 1000, unit: "ms" },
  { id: "search_first_result", label: "검색 Enter → 첫 결과", budget: 1500, unit: "ms" },
  { id: "scroll_dropped_frames", label: "스크롤 프레임 누락", budget: 5, unit: "%" },
];

/** What the page waits for after the trigger (evaluated in the page; no eval/Function needed). */
type Pred =
  | { kind: "focused"; index: number }
  | { kind: "mark"; rowKey: string; mark: string }
  | { kind: "firstRow"; notKey: string | null; prefix?: string }
  | { kind: "viewerChanged" }
  | { kind: "viewerReady" };
type Trigger = { type: "keydown"; key: string } | { type: "mousedown" };
type Arm = { trigger: Trigger; preds: Record<string, Pred>; timeoutMs: number };
type Measured = Record<string, { commit: number; paint: number } | null>;

// Installed before the app loads. window.__rtPerf.arm() resolves once every predicate has been
// seen and painted (or null for one that never came within timeoutMs).
const INIT = () => {
  type P = Pred;
  const viewer = () => document.querySelector<HTMLElement>('section.viewer[aria-label="원본 뷰어"]');
  const holds = (pred: P, viewerMutated: boolean): boolean => {
    switch (pred.kind) {
      case "focused":
        return document.querySelector(`[role="grid"] [data-index="${pred.index}"].is-focused`) !== null;
      case "mark": {
        const row = document.querySelector<HTMLElement>(
          `[role="grid"] [data-row-key="${CSS.escape(pred.rowKey)}"]`,
        );
        return row?.dataset.mark === pred.mark;
      }
      case "firstRow": {
        const row = document.querySelector<HTMLElement>('[role="grid"] [data-index="0"][data-row-key]');
        const key = row?.dataset.rowKey ?? null;
        if (!key || key === pred.notKey) return false;
        return !pred.prefix || key.startsWith(pred.prefix);
      }
      case "viewerChanged":
        return viewerMutated;
      case "viewerReady": {
        const v = viewer();
        if (!v || !viewerMutated || v.getAttribute("aria-busy") === "true") return false;
        const notes = v.querySelectorAll(".viewer-panel:not([hidden]) .viewer-note");
        for (const note of notes) if ((note.textContent ?? "").includes("불러오는 중")) return false;
        return true;
      }
    }
  };
  (window as unknown as { __rtPerf: unknown }).__rtPerf = {
    arm(spec: { trigger: Trigger; preds: Record<string, P>; timeoutMs: number }): Promise<Measured> {
      return new Promise((done) => {
        const out: Measured = {};
        const names = Object.keys(spec.preds);
        let t0 = -1;
        let viewerMutated = false;
        let observer: MutationObserver | null = null;
        let finished = false;
        const finish = () => {
          if (finished) return;
          finished = true;
          observer?.disconnect();
          for (const name of names) if (!(name in out)) out[name] = null;
          done(out);
        };
        const pending = new Set(names);
        const painted = new Set<string>();
        const check = () => {
          if (t0 < 0 || finished) return;
          for (const name of [...pending]) {
            const pred = spec.preds[name] as P;
            if (!holds(pred, viewerMutated)) continue;
            pending.delete(name);
            const commit = performance.now() - t0;
            // Next paint: the rAF of the frame that carries the change, then a task after it.
            requestAnimationFrame(() =>
              setTimeout(() => {
                out[name] = { commit, paint: performance.now() - t0 };
                painted.add(name);
                if (painted.size === names.length) finish();
              }, 0),
            );
          }
        };
        const frame = () => {
          if (finished) return;
          check();
          requestAnimationFrame(frame);
        };
        const onEvent = (event: Event) => {
          if (spec.trigger.type === "keydown" && (event as KeyboardEvent).key !== spec.trigger.key) return;
          window.removeEventListener(spec.trigger.type, onEvent, true);
          t0 = event.timeStamp;
          observer = new MutationObserver((records) => {
            const v = viewer();
            if (v && !viewerMutated) viewerMutated = records.some((r) => v.contains(r.target));
            check();
          });
          observer.observe(document.documentElement, {
            subtree: true,
            childList: true,
            attributes: true,
            characterData: true,
          });
          requestAnimationFrame(frame);
          setTimeout(finish, spec.timeoutMs);
        };
        window.addEventListener(spec.trigger.type, onEvent, true);
      });
    },
    /** Per-frame scrolling of the grid's scroll container; returns the dropped-frame share. */
    scroll(
      frames: number,
      step: number,
    ): Promise<{ pct: number; frames: number; dropped: number; interval: number }> {
      const grid = document.querySelector<HTMLElement>('[role="grid"]');
      let box: HTMLElement | null = grid;
      const scrollable = (el: HTMLElement) =>
        el.scrollHeight > el.clientHeight + 50 && /(auto|scroll)/.test(getComputedStyle(el).overflowY);
      const candidates = grid ? [grid, ...grid.querySelectorAll<HTMLElement>("*")] : [];
      box = candidates.find(scrollable) ?? null;
      for (let el = grid?.parentElement ?? null; !box && el; el = el.parentElement)
        if (scrollable(el)) box = el;
      if (!box) return Promise.reject(new Error("no scroll container in the grid"));
      const target = box;
      target.scrollTop = 0;
      return new Promise((done) => {
        const idle: number[] = [];
        const stamps: number[] = [];
        const calibrate = (ts: number) => {
          idle.push(ts);
          if (idle.length < 31) return requestAnimationFrame(calibrate);
          const gaps = idle.slice(1).map((t, i) => t - (idle[i] as number));
          gaps.sort((a, b) => a - b);
          const interval = gaps[Math.floor(gaps.length / 2)] as number;
          const run = (now: number) => {
            stamps.push(now);
            if (stamps.length > frames) {
              let dropped = 0;
              for (let i = 1; i < stamps.length; i += 1) {
                dropped += Math.max(
                  0,
                  Math.round(((stamps[i] as number) - (stamps[i - 1] as number)) / interval) - 1,
                );
              }
              target.scrollTop = 0;
              done({ pct: (dropped / (frames + dropped)) * 100, frames, dropped, interval });
              return;
            }
            target.scrollTop += step;
            requestAnimationFrame(run);
          };
          requestAnimationFrame(run);
        };
        requestAnimationFrame(calibrate);
      });
    },
  };
};

function p75(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil(0.75 * sorted.length) - 1)] as number;
}

const round = (n: number) => Math.round(n * 10) / 10;

async function arm(page: Page, spec: Arm) {
  await page.evaluate((s) => {
    const w = window as unknown as {
      __rtPerf: { arm(s: unknown): Promise<unknown> };
      __rtPerfPending: unknown;
    };
    w.__rtPerfPending = w.__rtPerf.arm(s);
  }, spec);
}

async function collect(page: Page): Promise<Measured> {
  return page.evaluate(() => (window as unknown as { __rtPerfPending: Promise<Measured> }).__rtPerfPending);
}

/** Quiet point between measurements: viewer settled, two frames and a short idle gap. */
async function settle(page: Page) {
  await expect(page.locator('section.viewer[aria-busy="true"]')).toHaveCount(0, { timeout: 30_000 });
  await page.evaluate(
    () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(r, 200)))),
  );
}

let runId = REAL_RUN_ID;

test.describe.configure({ mode: "serial" });

test.beforeAll(async ({ request }) => {
  test.setTimeout(300_000);
  if (runId) return;
  // Synthetic r8-rich fixture (fake values only; CI/engineering data, never release evidence).
  const output = join(mkdtempSync(join(tmpdir(), "rt-v2-e2e-perf-")), "run");
  execFileSync(python, [join("frontend", "e2e", "r8_fixture.py"), output], { cwd: repoRoot });
  const imported = await request.post("/api/runs/import", { headers: HEADERS, data: { output_dir: output } });
  expect(imported.status(), await imported.text()).toBe(201);
  runId = ((await imported.json()) as { run_id: string }).run_id;
  expect(runId).not.toBe("");
});

test("IS-134 interaction budget: 8 items x 5 measurements, p75 to JSON", async ({ page, browser }) => {
  test.setTimeout(600_000);
  const samples = new Map<ItemId, number[]>(ITEMS.map((item) => [item.id, []]));
  const commits = new Map<ItemId, number[]>(ITEMS.map((item) => [item.id, []]));
  const record = (id: ItemId, m: { commit: number; paint: number } | null | undefined, keep: boolean) => {
    expect(m, `${id}: not measured (the expected screen change never came)`).toBeTruthy();
    if (!keep || !m) return;
    samples.get(id)?.push(m.paint);
    commits.get(id)?.push(m.commit);
  };
  const rounds = WARMUP + REPS;
  const markSaves = { saved: 0, rejected: 0 };
  const scrollRuns: Array<{ frames: number; dropped: number; frame_interval_ms: number }> = [];
  const grid = page.locator('[role="grid"]');
  const rowAt = (index: number) => grid.locator(`[data-index="${index}"]`);
  const gridHash = `#/case/${runId}/explore/artifacts/${GRID_KIND}`;
  const openGrid = async () => {
    await page.evaluate((next) => {
      window.location.hash = next;
    }, gridHash);
    await expect(rowAt(0)).toBeVisible({ timeout: 60_000 });
    await expect(rowAt(0)).toHaveAttribute("data-row-key", /^artifacts:/);
  };

  await page.addInitScript(INIT);
  await page.setViewportSize(VIEWPORT);
  await page.goto(`/v2/#token=${TOKEN}`);
  await expect(page).not.toHaveURL(/token=/);
  await openGrid();

  await test.step("J / K row navigation", async () => {
    await rowAt(1).click();
    await expect(rowAt(1)).toHaveClass(/is-focused/);
    await settle(page);
    for (const [id, key, step] of [
      ["jk_down", "j", 1],
      ["jk_up", "k", -1],
    ] as const) {
      for (let i = 0; i < rounds; i += 1) {
        const from = Number(await grid.locator(".is-focused[data-index]").getAttribute("data-index"));
        await arm(page, {
          trigger: { type: "keydown", key },
          preds: { t: { kind: "focused", index: from + step } },
          timeoutMs: 10_000,
        });
        await page.keyboard.press(key);
        record(id, (await collect(page)).t, i >= WARMUP);
        await settle(page);
      }
    }
  });

  await test.step("row select -> viewer skeleton and body", async () => {
    for (let i = 0; i < rounds; i += 1) {
      // Rows of one kind near the top (the J/K step leaves row 1 focused); each click is a new
      // viewer target, so every sample is the same work: target switch + preview load.
      const index = VIEWER_ROWS[i % VIEWER_ROWS.length] as number;
      await arm(page, {
        trigger: { type: "mousedown" },
        preds: { skeleton: { kind: "viewerChanged" }, body: { kind: "viewerReady" } },
        timeoutMs: 20_000,
      });
      await rowAt(index).click();
      const m = await collect(page);
      record("viewer_skeleton", m.skeleton, i >= WARMUP);
      record("viewer_body", m.body, i >= WARMUP);
      await settle(page);
    }
  });

  await test.step("scroll dropped frames", async () => {
    await settle(page);
    for (let i = 0; i < rounds; i += 1) {
      const r = await page.evaluate(
        ([frames, step]) =>
          (
            window as unknown as {
              __rtPerf: {
                scroll(
                  f: number,
                  s: number,
                ): Promise<{ pct: number; frames: number; dropped: number; interval: number }>;
              };
            }
          ).__rtPerf.scroll(frames as number, step as number),
        [SCROLL_FRAMES, SCROLL_STEP_PX],
      );
      if (i >= WARMUP) {
        samples.get("scroll_dropped_frames")?.push(r.pct);
        scrollRuns.push({ frames: r.frames, dropped: r.dropped, frame_interval_ms: round(r.interval) });
      }
      await settle(page);
    }
  });

  await test.step("category click -> first row", async () => {
    const tree = page.getByRole("tree", { name: "케이스 탐색 트리" });
    const drawer = page.getByRole("button", { name: "왼쪽 패널 열기" });
    if (await drawer.isVisible()) await drawer.click();
    await expect(tree).toBeVisible({ timeout: 20_000 });
    expect(
      CATEGORIES.length,
      "RAPIDTRIAGE_PERF_CATEGORIES: the measured node and at least one other",
    ).toBeGreaterThan(1);
    // Leaf nodes open a list; a domain node only expands. Open the parents of every leaf first.
    for (const id of CATEGORIES) {
      const parts = id.split(":");
      for (let depth = 2; depth < parts.length; depth += 1) {
        const parent = tree.locator(`[role="treeitem"][data-node-id="${parts.slice(0, depth).join(":")}"]`);
        if ((await parent.getAttribute("aria-expanded")) === "false") {
          await parent.locator(".case-tree-twisty").click();
        }
      }
      await expect(tree.locator(`[role="treeitem"][data-node-id="${id}"]`)).toBeVisible();
    }
    await settle(page);
    for (let i = 0; i < rounds; i += 1) {
      // Same work every sample: leave for another category (not measured), then measure the click
      // on the first one.
      const node = CATEGORIES[0] as string;
      const away = CATEGORIES[1 + (i % (CATEGORIES.length - 1))] as string;
      await tree.locator(`[role="treeitem"][data-node-id="${away}"]`).click();
      await expect(rowAt(0)).toBeVisible({ timeout: 30_000 });
      await settle(page);
      const before =
        (await rowAt(0)
          .getAttribute("data-row-key")
          .catch(() => null)) ?? null;
      await arm(page, {
        trigger: { type: "mousedown" },
        preds: { t: { kind: "firstRow", notKey: before } },
        timeoutMs: 30_000,
      });
      await tree.locator(`[role="treeitem"][data-node-id="${node}"]`).click();
      record("category_first_row", (await collect(page)).t, i >= WARMUP);
      await settle(page);
    }
  });

  await test.step("search Enter -> first result", async () => {
    expect(
      QUERIES.length,
      "one distinct query per round (a repeated query is served from cache)",
    ).toBeGreaterThanOrEqual(rounds);
    const search = page.getByLabel("전체 검색어");
    for (let i = 0; i < rounds; i += 1) {
      await openGrid();
      await settle(page);
      await search.fill(QUERIES[i] as string);
      await arm(page, {
        trigger: { type: "keydown", key: "Enter" },
        preds: { t: { kind: "firstRow", notKey: null, prefix: "search:" } },
        timeoutMs: 60_000,
      });
      await search.press("Enter");
      const m = (await collect(page)).t;
      expect(m, `search "${QUERIES[i]}" showed no result row (pick queries that hit)`).toBeTruthy();
      record("search_first_result", m, i >= WARMUP);
      await settle(page);
    }
  });

  await test.step("review key -> mark shown (each mark is undone with Ctrl+Z)", async () => {
    // Last: the first mark of a run builds the case DB, which switches 전체 검색 from the scan to
    // FTS. Back on the measured grid, near the top of the list.
    await openGrid();
    await rowAt(0).click();
    await settle(page);
    const batch = () =>
      page.waitForResponse((r) => r.url().endsWith("/api/case-db/review-batch"), { timeout: 120_000 });
    for (let i = 0; i < rounds; i += 1) {
      await page.keyboard.press("j");
      const focused = grid.locator(".is-focused[data-index]");
      await expect(focused).toHaveCount(1);
      const rowKey = (await focused.getAttribute("data-row-key")) ?? "";
      const row = grid.locator(`[data-row-key="${rowKey}"]`);
      expect(await focused.getAttribute("data-mark")).toBeNull();
      await settle(page);
      await arm(page, {
        trigger: { type: "keydown", key: "r" },
        preds: { t: { kind: "mark", rowKey, mark: "relevant" } },
        timeoutMs: 10_000,
      });
      // The first mark of a run may wait for the case DB to be built: the screen shows the mark at
      // once (that is what is measured), the save follows.
      const saved = batch();
      await page.keyboard.press("r");
      record("review_mark", (await collect(page)).t, i >= WARMUP);
      const response = await saved;
      if (response.ok()) {
        markSaves.saved += 1;
        const undone = batch();
        await page.keyboard.press("Control+z");
        expect((await undone).ok(), "Ctrl+Z takes the measured mark back").toBe(true);
      } else {
        // A row the case DB cannot resolve: the app rolls the optimistic mark back on its own.
        markSaves.rejected += 1;
      }
      await expect(row).not.toHaveAttribute("data-mark", /./, { timeout: 20_000 });
      await row.focus();
    }
  });

  // ---- report ---------------------------------------------------------------------------
  let commit = env.RAPIDTRIAGE_PERF_COMMIT || "";
  if (!commit) {
    try {
      commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf-8" }).trim();
    } catch {
      commit = "unknown";
    }
  }
  const items = ITEMS.map((item) => {
    const values = samples.get(item.id) ?? [];
    const value = values.length ? p75(values) : null;
    return {
      id: item.id,
      label: item.label,
      unit: item.unit,
      budget: item.budget,
      samples: values.map(round),
      commit_samples: (commits.get(item.id) ?? []).map(round),
      measured: values.length,
      p75: value === null ? null : round(value),
      within_budget: value === null ? null : value <= item.budget,
    };
  });
  const unmeasured = items.reduce((n, item) => n + (REPS - item.measured), 0);
  let compare: unknown = null;
  if (COMPARE) {
    const previous = JSON.parse(readFileSync(COMPARE, "utf-8")) as {
      items: Array<{ id: string; p75: number }>;
    };
    compare = {
      against: COMPARE,
      max_deviation: MAX_DEVIATION,
      items: items.map((item) => {
        const before = previous.items.find((p) => p.id === item.id)?.p75 ?? null;
        const deviation = before && item.p75 !== null ? Math.abs(item.p75 - before) / before : null;
        return {
          id: item.id,
          previous: before,
          current: item.p75,
          deviation_pct: deviation === null ? null : round(deviation * 100),
          within: deviation === null ? null : deviation <= MAX_DEVIATION,
        };
      }),
    };
  }
  const report = {
    schema: "rapidtriage-interaction-perf/1",
    task: "T-203",
    budget_ref: "IS-134",
    qa_ref: "QA-195",
    label: LABEL,
    synthetic: !REAL_RUN_ID,
    release_evidence: false,
    commit,
    measured_at: new Date().toISOString(),
    target: {
      base_url: page.url().replace(/#.*$/, ""),
      run_id: runId,
      grid_kind: GRID_KIND,
      categories: CATEGORIES,
      queries: QUERIES.slice(0, rounds),
    },
    browser: `${browser.browserType().name()} ${browser.version()}`,
    viewport: VIEWPORT,
    reps: REPS,
    warmup: WARMUP,
    statistic: "p75 (nearest rank) of the paint times; commit_samples = DOM change without the paint",
    unmeasured,
    review_mark_saves: markSaves,
    scroll_runs: { step_px: SCROLL_STEP_PX, runs: scrollRuns },
    items,
    compare,
  };
  mkdirSync(dirname(OUTPUT), { recursive: true });
  writeFileSync(OUTPUT, `${JSON.stringify(report, null, 2)}\n`, "utf-8");
  console.log(`[perf] ${OUTPUT}`);
  for (const item of items) {
    console.log(
      `[perf] ${item.id.padEnd(22)} p75 ${String(item.p75).padStart(7)} ${item.unit} (budget ${item.budget}) ${item.samples.join(" / ")}`,
    );
  }
  expect(unmeasured, "IS-134: every budget cell is measured").toBe(0);
  expect(items.length * REPS).toBe(40);
});
