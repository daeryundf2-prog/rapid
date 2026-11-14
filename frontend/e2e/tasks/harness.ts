// R8 task-measurement harness (T-011, WA-2). Shared helpers for the examiner tasks T1–T5
// (docs/plans/r8-master-2026-11-11.md, r8/r8-qa-scenarios.md QA-033·057·069·072·075).
//
// The specs MEASURE only: a task that today's console cannot finish is recorded as "fail" or
// "partial" with the step that broke, and the Playwright test still passes (target assertions
// are switched on by the W5–W8 tasks). Each task writes `<R8_OUT_DIR>/<task>.json`;
// `scripts/r8-measure.py` runs the specs and aggregates those files into JSON + markdown.
//
// Targets:
//   fixture (default)  the e2e fixture server (start-server.mjs); a SYN sample case is created
//                      once and reused. Never skipped when no real run is configured.
//   real run           R8_BASE_URL + R8_TOKEN + a run id (R8_RUN_<task>, R8_RUN_ID, or the first of
//                      R8_RUN_C1…C6 / R8_RUN_S). READ-ONLY: every non-GET request is aborted except
//                      search/query endpoints, and the harness itself only sends GET.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { APIRequestContext, Locator, Page, Request, Route } from "@playwright/test";

export const FIXTURE_TOKEN = "e2e-token";
export const TASK_IDS = ["T1", "T2", "T3", "T4", "T5"] as const;
export type TaskId = (typeof TASK_IDS)[number];
export type TaskStatus = "pass" | "partial" | "fail";

const env = process.env;
export const REAL = Boolean(env.R8_BASE_URL);
export const BASE_URL = (env.R8_BASE_URL || "").replace(/\/+$/, "");
export const TOKEN = REAL ? env.R8_TOKEN || "" : FIXTURE_TOKEN;
export const OUT_DIR = env.R8_OUT_DIR || join(process.cwd(), "test-results", "r8-tasks");
/** Per-step wait. Short on purpose: a missing control is a measured failure, not a hang. */
export const STEP_TIMEOUT_MS = Number(env.R8_STEP_TIMEOUT_MS) || 8_000;

/** Non-GET requests a real run may still send (read-only searches/queries). */
const READ_ONLY_POST_ALLOW = /\/(search|query)(\/|$|\?)/i;

const authHeaders = () => ({ "X-RapidTriage-Token": TOKEN });

/** Absolute URL for an app path; relative (Playwright baseURL) in fixture mode. */
export const url = (path: string) => (REAL ? `${BASE_URL}${path}` : path);

/** Run id for a task: R8_RUN_<task> → R8_RUN_ID → R8_RUN_C1…C6 → R8_RUN_S (real mode only). */
export function realRunId(task: TaskId): string {
  const keys = [`R8_RUN_${task}`, "R8_RUN_ID", "R8_RUN_C1", "R8_RUN_C2", "R8_RUN_C3"];
  keys.push("R8_RUN_C4", "R8_RUN_C5", "R8_RUN_C6", "R8_RUN_S");
  for (const key of keys) if (env[key]) return env[key] as string;
  return "";
}

export async function apiGet<T>(request: APIRequestContext, path: string): Promise<T | null> {
  const response = await request.get(url(path), { headers: authHeaders() });
  if (!response.ok()) return null;
  return (await response.json()) as T;
}

/**
 * The run to measure. Real mode: from env (throws when none — a misconfigured real run must not
 * silently measure SYN). Fixture mode: reuse a run on the isolated server or create the SYN sample.
 */
export async function resolveRun(request: APIRequestContext, task: TaskId): Promise<string> {
  if (REAL) {
    const id = realRunId(task);
    if (!TOKEN || !id)
      throw new Error("R8_BASE_URL is set: R8_TOKEN and a run id (R8_RUN_ID …) are required");
    return id;
  }
  const listed = await apiGet<{ runs: Array<{ run_id: string; status?: string }> }>(request, "/api/runs");
  const existing = listed?.runs.find((run) => !run.status || run.status === "completed")?.run_id;
  if (existing) return existing;
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const outputDir = mkdtempSync(join(tmpdir(), "rt-r8-tasks-"));
  const created = await request.post("/api/sample-case/run", {
    headers: authHeaders(),
    data: { output_dir: outputDir, overwrite: true, read_only: true },
  });
  if (created.status() !== 201) throw new Error(`sample-case run failed: HTTP ${created.status()}`);
  const after = await apiGet<{ runs: Array<{ run_id: string }> }>(request, "/api/runs");
  const id = after?.runs[0]?.run_id ?? "";
  if (!id) throw new Error("sample-case run created no run");
  return id;
}

export interface StepRecord {
  name: string;
  ok: boolean;
  /** A goal step is part of the task's outcome; the others are sub-checks or set-up. */
  goal: boolean;
  ms: number;
  note?: string;
  /** Where a failed step stopped (diagnosis). */
  at?: { screen: string; treeItems: string[] };
}

export interface TaskTargets {
  /** Upper bound on clicks + keystrokes (QA scenario). */
  maxOps?: number;
  maxSeconds?: number;
  maxScreens?: number;
}

export interface TaskResult {
  task: TaskId;
  title: string;
  status: TaskStatus;
  mode: "fixture" | "real";
  runId: string;
  viewport: { width: number; height: number } | null;
  metrics: {
    clicks: number;
    keystrokes: number;
    ops: number;
    tabPresses: number;
    screens: number;
    screenPath: string[];
    wallSeconds: number;
    firstRowMs: number | null;
  };
  targets: TaskTargets;
  targetsMet: boolean | null;
  steps: StepRecord[];
  /** Extra measurements (audit numbers, DOM facts). */
  extra: Record<string, unknown>;
  blockedRequests: string[];
  notes: string[];
}

/** `#/case/{run}/{stage}/{view}` without query/target: the "screen" a user is on. */
function screenOf(href: string): string {
  const hash = href.includes("#") ? href.slice(href.indexOf("#") + 1) : "";
  const path = hash.split("?")[0] ?? "";
  const parts = path.split("/").filter(Boolean);
  if (parts[0] !== "case") return path || "(landing)";
  return parts.slice(2, 4).join("/") || "(case)";
}

/**
 * Records one task: every user operation goes through `click` / `press` / `type` so the counts are
 * exact; `step` wraps a sub-goal so a missing control becomes a failed step instead of a crash.
 */
export class TaskRecorder {
  readonly steps: StepRecord[] = [];
  readonly notes: string[] = [];
  readonly extra: Record<string, unknown> = {};
  readonly blocked: string[] = [];
  private clicks = 0;
  private keys = 0;
  private tabs = 0;
  private readonly screenPath: string[] = [];
  private started = 0;
  private firstRowMs: number | null = null;
  /** Metrics as of the first `finish()`; later calls (to attach extras) keep them. */
  private frozen: TaskResult["metrics"] | null = null;

  constructor(
    readonly page: Page,
    readonly task: TaskId,
    readonly title: string,
    readonly runId: string,
    readonly targets: TaskTargets = {},
  ) {}

  /** Installs the read-only guard (real runs) and the screen tracker. Call before `open`. */
  async install(): Promise<void> {
    if (REAL) {
      await this.page.route("**/*", (route: Route, request: Request) => {
        const method = request.method();
        if (method === "GET" || method === "HEAD" || method === "OPTIONS") return route.continue();
        const path = new URL(request.url()).pathname;
        if (READ_ONLY_POST_ALLOW.test(path)) return route.continue();
        this.blocked.push(`${method} ${path}`);
        return route.abort("blockedbyclient");
      });
    }
    this.page.on("framenavigated", (frame) => {
      if (frame === this.page.mainFrame()) this.noteScreen(frame.url());
    });
  }

  private noteScreen(href: string): void {
    const screen = screenOf(href);
    if (this.screenPath[this.screenPath.length - 1] !== screen) this.screenPath.push(screen);
  }

  /** Opens the console on `#/case/{run}/{suffix}` (a deep link: 0 operations) and starts the clock. */
  async open(suffix = ""): Promise<void> {
    await this.page.goto(url(`/v2/#token=${TOKEN}`));
    const hash = `#/case/${this.runId}${suffix ? `/${suffix}` : ""}`;
    await this.page.evaluate((h) => {
      window.location.hash = h;
    }, hash);
    await this.page.getByTestId("workbench-shell").waitFor({ timeout: 30_000 });
    this.screenPath.length = 0;
    this.noteScreen(this.page.url());
    this.started = Date.now();
  }

  /** First-row latency recorded so far (ms), or null. */
  get firstRow(): number | null {
    return this.firstRowMs;
  }

  /** Operations (clicks + keystrokes) and seconds since `open`, for intermediate milestones. */
  milestone(): { ops: number; seconds: number } {
    return { ops: this.clicks + this.keys, seconds: Math.round((Date.now() - this.started) / 10) / 100 };
  }

  async click(target: Locator): Promise<void> {
    await target.click({ timeout: STEP_TIMEOUT_MS });
    this.clicks += 1;
    this.noteScreen(this.page.url());
  }

  async press(key: string): Promise<void> {
    await this.page.keyboard.press(key);
    this.keys += 1;
    if (key === "Tab") this.tabs += 1;
    this.noteScreen(this.page.url());
  }

  /** Types `text` into the focused element; each character is one keystroke. */
  async type(text: string): Promise<void> {
    await this.page.keyboard.type(text);
    this.keys += [...text].length;
  }

  /** Runs a sub-goal; failure is recorded (with the error's first line) and returned as false. */
  async step(name: string, fn: () => Promise<unknown>, opts: { goal?: boolean } = {}): Promise<boolean> {
    const t0 = Date.now();
    const goal = opts.goal ?? false;
    try {
      const out = await fn();
      const note = typeof out === "string" ? out : undefined;
      this.steps.push({ name, ok: true, goal, ms: Date.now() - t0, ...(note ? { note } : {}) });
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const note = message.split("\n")[0]?.slice(0, 240) ?? "error";
      this.steps.push({ name, ok: false, goal, ms: Date.now() - t0, note, at: await this.where() });
      return false;
    }
  }

  /** Where a failed step stopped: the screen and the first tree items on it. */
  private async where(): Promise<{ screen: string; treeItems: string[] }> {
    const names = await this.page
      .getByRole("treeitem")
      .evaluateAll((items) =>
        items
          .slice(0, 40)
          .map((el) => (el.getAttribute("aria-label") || el.textContent || "").trim().slice(0, 60)),
      )
      .catch(() => [] as string[]);
    return { screen: screenOf(this.page.url()), treeItems: names };
  }

  /** Clicks `target`, waits for the address to change, then the grid's first row (records latency). */
  async clickToRows(target: Locator): Promise<number> {
    const before = this.page.url();
    const t0 = Date.now();
    await this.click(target);
    await this.page.waitForURL((u) => u.toString() !== before, { timeout: STEP_TIMEOUT_MS });
    this.noteScreen(this.page.url());
    return this.waitFirstRow(t0);
  }

  /** Records a step that was not attempted because an earlier step failed; returns false. */
  skip(name: string, reason: string, opts: { goal?: boolean } = {}): false {
    this.steps.push({ name, ok: false, goal: opts.goal ?? false, ms: 0, note: `not reached: ${reason}` });
    return false;
  }

  /** Waits for the first data row of the main grid; records ms since `since` (first call wins). */
  async waitFirstRow(since: number, scope: Locator | Page = this.page): Promise<number> {
    const row = scope.locator('[role="grid"] [role="row"][aria-rowindex="2"]').first();
    await row.waitFor({ state: "visible", timeout: STEP_TIMEOUT_MS });
    const ms = Date.now() - since;
    if (this.firstRowMs === null) this.firstRowMs = ms;
    return ms;
  }

  /** Writes `<OUT_DIR>/<task>.json` and returns the result. */
  finish(): TaskResult {
    const metrics = this.frozen ?? {
      clicks: this.clicks,
      keystrokes: this.keys,
      ops: this.clicks + this.keys,
      tabPresses: this.tabs,
      screens: this.screenPath.length,
      screenPath: [...this.screenPath],
      wallSeconds: this.started ? Math.round((Date.now() - this.started) / 10) / 100 : 0,
      firstRowMs: this.firstRowMs,
    };
    this.frozen = metrics;
    const { ops, wallSeconds } = metrics;
    const allOk = this.steps.length > 0 && this.steps.every((s) => s.ok);
    const goals = this.steps.filter((s) => s.goal);
    const goalsOk = goals.length > 0 && goals.every((s) => s.ok);
    const someGoalOk = goals.some((s) => s.ok);
    const t = this.targets;
    const checks: boolean[] = [];
    if (t.maxOps !== undefined) checks.push(ops <= t.maxOps);
    if (t.maxSeconds !== undefined) checks.push(wallSeconds <= t.maxSeconds);
    if (t.maxScreens !== undefined) checks.push(metrics.screens <= t.maxScreens);
    const targetsMet = allOk && checks.length ? checks.every(Boolean) : allOk ? true : null;
    // pass: every step done within targets · partial: some of the goal reached (or reached but a
    // sub-check / target missed) · fail: no goal step reached.
    let status: TaskStatus = "fail";
    if (allOk && targetsMet) status = "pass";
    else if (goalsOk || someGoalOk) status = "partial";
    const missNote = "all steps done but a target (ops/time/screens) missed";
    if (allOk && targetsMet === false && !this.notes.includes(missNote)) this.notes.push(missNote);
    const result: TaskResult = {
      task: this.task,
      title: this.title,
      status,
      mode: REAL ? "real" : "fixture",
      runId: this.runId,
      viewport: this.page.viewportSize(),
      metrics,
      targets: t,
      targetsMet,
      steps: this.steps,
      extra: this.extra,
      blockedRequests: this.blocked,
      notes: this.notes,
    };
    mkdirSync(OUT_DIR, { recursive: true });
    writeFileSync(join(OUT_DIR, `${this.task}.json`), `${JSON.stringify(result, null, 2)}\n`, "utf8");
    return result;
  }
}

/**
 * Makes the case tree reachable: when the current screen has no `케이스 탐색 트리` (the case opens on
 * 접수 today), clicks 탐색 in the stage rail — a counted operation, as it is for the user.
 */
export async function ensureTree(rec: TaskRecorder): Promise<void> {
  const tree = rec.page.getByRole("tree", { name: "케이스 탐색 트리" });
  if (await tree.isVisible().catch(() => false)) return;
  const rail = rec.page.getByRole("navigation", { name: "작업 단계" });
  await rec.click(
    rail
      .getByRole("button", { name: /탐색/ })
      .or(rail.getByRole("link", { name: /탐색/ }))
      .first(),
  );
  await tree.waitFor({ timeout: STEP_TIMEOUT_MS });
}

// --- UX-audit measurements (baseline numbers: tree nodes, cell truncation, Tab to grid) --------

/** Tree items currently in the DOM of the case tree (`케이스 탐색 트리`). */
export async function countTreeNodes(page: Page): Promise<number> {
  return page.getByRole("tree", { name: "케이스 탐색 트리" }).getByRole("treeitem").count();
}

/** Share of visible grid cells whose text overflows (`scrollWidth > clientWidth`). */
export async function cellTruncation(
  page: Page,
): Promise<{ cells: number; truncated: number; ratio: number }> {
  return page.evaluate(() => {
    const grid = document.querySelector('[role="grid"]');
    const cells = grid ? Array.from(grid.querySelectorAll<HTMLElement>('[role="gridcell"]')) : [];
    let truncated = 0;
    for (const cell of cells) {
      const inner = Array.from(cell.querySelectorAll<HTMLElement>("*"));
      if ([cell, ...inner].some((el) => el.scrollWidth > el.clientWidth + 1)) truncated += 1;
    }
    const ratio = cells.length ? Math.round((truncated / cells.length) * 1000) / 1000 : 0;
    return { cells: cells.length, truncated, ratio };
  });
}

/**
 * Tab presses from the top of the document until focus lands inside the main grid (cap 80).
 * Counted on the recorder (they are real keystrokes); returns null when the grid is never reached.
 */
export async function tabsToGrid(rec: TaskRecorder, cap = 80): Promise<number | null> {
  await rec.page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
    window.scrollTo(0, 0);
  });
  for (let n = 1; n <= cap; n += 1) {
    await rec.press("Tab");
    const inGrid = await rec.page.evaluate(() => Boolean(document.activeElement?.closest('[role="grid"]')));
    if (inGrid) return n;
  }
  return null;
}

/** Document / main-region vertical overflow at the current viewport (T1 "no scroll"). */
export async function verticalOverflow(page: Page): Promise<{ document: number; main: number }> {
  return page.evaluate(() => {
    const doc = document.scrollingElement ?? document.documentElement;
    const main = document.getElementById("main");
    return {
      document: Math.max(0, doc.scrollHeight - doc.clientHeight),
      main: main ? Math.max(0, main.scrollHeight - main.clientHeight) : 0,
    };
  });
}
