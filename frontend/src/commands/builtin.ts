/**
 * Built-in commands owned by the shell (S1): app, navigate, case lifecycle,
 * viewer focus. Other streams register their own groups (grid, viewer,
 * review, export) — see the S1 report for the ids reserved here.
 */

import type { QueryClient } from "@tanstack/react-query";
import { announce, isTextEntry } from "../a11y";
import { ApiError } from "../api/client";
import { cancelRun, retryRun } from "../api/runControl";
import { controlRunPlan, runPlanQueryKey } from "../api/runPlan";
import { normalizeRunStatus, RETRYABLE_RUN_STATUSES } from "../api/runs";
import { RUNS_QUERY_KEY, type RunPlanCountsCompact, type RunWithProgress } from "../api/runsProgress";
import { COLLECTION_NODES, runDisplayName } from "../app/collections";
import type { Command, CommandContext } from "../contracts/command";
import { conditionsCommand } from "../features/filters/conditionPanel";
import { useViewPrefs } from "../features/review/viewPrefs";
import { treeEmptyCommand } from "../features/tree/treePrefs";
import { focusPopout } from "../features/viewer/popout/host";
import { NO_VIEWER_REASON, stageHasViewer, stageOf } from "../router";
import { viewerPaneCollapsed } from "../state/slices/overlays";
import { DENSITIES, DENSITY_LABEL } from "../state/slices/prefs";
import { anyRunActive, currentRun } from "../state/slices/runs";
import { useAppStore } from "../state/store";
import { CANCEL_ALL_CONFIRM, confirmAction, NO_RUN_REASON } from "./reasons";
import { registerCommands } from "./registry";
import { reviewCommands } from "./review";

export { NO_RUN_REASON };

const needsRun = (ctx: CommandContext) => (ctx.runId ? undefined : NO_RUN_REASON);

/** Ids of DOM landmarks the commands move focus to (Layout renders them). */
export const MAIN_ID = "main";
export const VIEWER_ID = "viewer";
export const GLOBAL_SEARCH_ID = "global-search";
/** The collapsed viewer rail's expand button (뷰어 접기 lands focus here). */
export const VIEWER_EXPAND_ID = "viewer-expand";

function focusById(id: string, preferSelector?: string): void {
  const run = () => {
    const root = document.getElementById(id);
    if (!root) return;
    const preferred = preferSelector ? root.querySelector<HTMLElement>(preferSelector) : null;
    const target = preferred ?? root;
    if (!target.hasAttribute("tabindex") && target === root) target.setAttribute("tabindex", "-1");
    target.focus();
  };
  // Let a just-opened drawer render before moving focus.
  if (typeof window.requestAnimationFrame === "function") window.requestAnimationFrame(run);
  else run();
}

/** Collections "같은 출처" filters in place; any other route falls back to files. */
const ROWS_FOR_SOURCE_KEEP: ReadonlySet<string> = new Set(["files", "docs", "artifacts", "timeline"]);

export const ROWS_FOR_SOURCE_INTAKE_REASON =
  "접수 화면에는 행 목록이 없습니다. 파일·아티팩트 등 목록에서 행을 선택한 뒤 사용하세요";

/** Focus the viewer: an element marked `data-viewer-focus` (S2's title) or the panel itself. */
export function focusViewer(): void {
  // The viewer (S2) also listens for the request and re-focuses once its tabs render.
  useAppStore.getState().requestViewerFocus();
  focusById(VIEWER_ID, "[data-viewer-focus]");
}

/**
 * Show the wide viewer pane when it is the collapsed rail (viewer.open, Enter on a row, the rail's
 * button). With a selected row the pane goes back to "auto"; without one it stays open until
 * the analyst collapses it. No-op in the drawer layout.
 */
export function expandViewerPane(): void {
  const s = useAppStore.getState();
  if (s.viewerIsDrawer || !viewerPaneCollapsed(s)) return;
  s.setViewerPane(s.route.row ? "auto" : "open");
}

export const CLASSIC_COLLAPSE_REASON = "클래식 분할에서는 뷰어를 접을 수 없습니다";

/** Why 뷰어 접기 cannot run: the classic split always shows the viewer (no rail to fold into). */
export function collapseViewerReason(): string | undefined {
  const s = useAppStore.getState();
  if (s.viewerIsDrawer || !stageHasViewer(stageOf(s.route))) return undefined;
  return useViewPrefs.getState().classicSplit ? CLASSIC_COLLAPSE_REASON : undefined;
}

/** 뷰어 접기: collapse the wide viewer to its rail for this session; focus moves to the rail. */
export function collapseViewerPane(): void {
  const s = useAppStore.getState();
  if (s.viewerIsDrawer) return;
  // Never a hidden "collapsed" state the classic split cannot show (it would surface later).
  const reason = collapseViewerReason();
  if (reason) {
    announce(reason);
    return;
  }
  s.setViewerPane("collapsed");
  focusById(VIEWER_EXPAND_ID);
}

const GRID_ROW_SELECTOR = '[data-grid-focus], [role="row"][tabindex="0"]';

/** Focus the grid area now: the roving row (`[data-grid-focus]` / tabindex=0 row) or `#main`. */
export function focusMain(): void {
  focusById(MAIN_ID, GRID_ROW_SELECTOR);
}

let cancelPendingGridFocus: (() => void) | null = null;

const nextFrame = (fn: () => void): number =>
  typeof window.requestAnimationFrame === "function"
    ? window.requestAnimationFrame(fn)
    : window.setTimeout(fn, 16);

/** Keys the grid handles on its roving row; forwarded to it when pressed before focus landed. */
const GRID_KEYS = new Set([
  "j",
  "k",
  "ArrowDown",
  "ArrowUp",
  "Enter",
  " ",
  "Home",
  "End",
  "PageDown",
  "PageUp",
]);

/**
 * After navigating to a collection, move DOM focus to the grid's roving row as
 * soon as the new page has rendered (so J / Enter work immediately, plan Q-A1);
 * falls back to `#main`. Polls each animation frame (up to `timeoutMs`), only
 * accepts a row of the previous collection once the grid has settled, verifies
 * `document.activeElement`, and re-applies focus once if the virtualised row is
 * re-mounted (or a closing overlay restores focus elsewhere) within `guardMs`.
 *
 * Grid keys (J/K/arrows/Enter/Space) pressed while focus is still on the page body
 * keep the request alive and are forwarded to the row once it is ready. Cancelled
 * when the analyst clicks, types into a field, or works a control outside `#main`.
 */
export function focusGridWhenReady(
  options: { settleMs?: number; timeoutMs?: number; guardMs?: number } = {},
): void {
  const settleMs = options.settleMs ?? 800;
  const timeoutMs = options.timeoutMs ?? 2000;
  const guardMs = options.guardMs ?? 300;
  cancelPendingGridFocus?.();
  const main = () => document.getElementById(MAIN_ID);
  const stale = main()?.querySelector<HTMLElement>(GRID_ROW_SELECTOR) ?? null;
  const staleKey = stale?.dataset.rowKey ?? null;
  const started = Date.now();
  let done = false;
  let focusedAt = 0;
  let reapplied = false;

  const focusEl = (el: HTMLElement): boolean => {
    if (el === main() && !el.hasAttribute("tabindex")) el.setAttribute("tabindex", "-1");
    el.focus({ preventScroll: false });
    return document.activeElement === el;
  };
  const currentRow = (): HTMLElement | null => main()?.querySelector<HTMLElement>(GRID_ROW_SELECTOR) ?? null;
  const readyTarget = (final: boolean): HTMLElement | null => {
    const root = main();
    if (!root) return null;
    if (useAppStore.getState().route.collection === "intake") return root;
    const row = currentRow();
    if (!row?.isConnected) return final ? root : null;
    const busy = root.querySelector('[role="grid"][aria-busy="true"]') !== null;
    const fresh = row !== stale && row.dataset.rowKey !== staleKey;
    const settled = !busy && Date.now() - started >= settleMs;
    return fresh || settled || final ? row : null;
  };
  /** Focus outside the grid area (body, or an element a closing overlay restored focus to). */
  const focusLost = (): boolean => {
    const active = document.activeElement;
    if (!active || active === document.body || !active.isConnected) return true;
    return !main()?.contains(active);
  };

  const tick = () => {
    if (done) return;
    const now = Date.now();
    if (focusedAt) {
      // Guard window: the virtualiser may re-mount the row right after we focused it, or a
      // closing dialog may hand focus back to its opener.
      if (focusLost() && !reapplied) {
        reapplied = true;
        const row = currentRow();
        if (row) focusEl(row);
      }
      if (now - focusedAt >= guardMs) finish();
      else nextFrame(tick);
      return;
    }
    const final = now - started >= timeoutMs;
    const target = readyTarget(final);
    if (target && focusEl(target)) {
      focusedAt = now;
      nextFrame(tick);
      return;
    }
    if (final) finish();
    else nextFrame(tick);
  };

  const onPointerDown = () => finish();
  const onKeyDown = (event: KeyboardEvent) => {
    const target = event.target;
    const root = main();
    const onPage =
      target === document.body ||
      target === document.documentElement ||
      target === document ||
      target === null;
    if (isTextEntry(target) || (!onPage && !(target instanceof Node && root?.contains(target)))) {
      finish();
      return;
    }
    // Once focus has landed, any key is the analyst's own action (Enter may move focus to
    // the viewer on purpose): stop guarding so we never pull focus back.
    if (focusedAt) {
      finish();
      return;
    }
    if (!onPage) return;
    const plain = !event.ctrlKey && !event.metaKey && !event.altKey;
    const key = event.key.length === 1 ? event.key.toLowerCase() : event.key;
    if (!plain || !GRID_KEYS.has(key)) return;
    // Focus is still on the page: land on the row now (if it is ready) and hand it the key.
    const row = readyTarget(false);
    if (!row || row === root || !focusEl(row)) return;
    finish();
    event.preventDefault();
    row.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: event.key,
        code: event.code,
        shiftKey: event.shiftKey,
        bubbles: true,
        cancelable: true,
      }),
    );
  };
  function finish() {
    if (done) return;
    done = true;
    document.removeEventListener("pointerdown", onPointerDown, true);
    document.removeEventListener("keydown", onKeyDown, true);
    if (cancelPendingGridFocus === finish) cancelPendingGridFocus = null;
  }
  cancelPendingGridFocus = finish;
  document.addEventListener("pointerdown", onPointerDown, true);
  document.addEventListener("keydown", onKeyDown, true);
  // The palette / search input closes in the same tick; start on the next frame.
  nextFrame(tick);
}

export function appCommands(): Command[] {
  const store = useAppStore.getState;
  return [
    {
      id: "app.palette",
      label: "명령 팔레트",
      group: "app",
      shortcut: "Ctrl+K",
      icon: "command",
      run: () => store().setOverlay("palette", !store().paletteOpen),
    },
    {
      id: "app.help",
      label: "단축키 도움말",
      group: "app",
      shortcut: "?",
      icon: "help",
      run: () => {
        store().setOverlay("palette", false);
        store().setOverlay("help", true);
      },
    },
    {
      id: "app.close",
      label: "닫기",
      group: "app",
      shortcut: "Escape",
      icon: "close",
      disabledReason: () => {
        const s = store();
        return s.paletteOpen || s.helpOpen || s.runDialogOpen || s.viewerDrawerOpen
          ? undefined
          : "닫을 창이 없습니다";
      },
      run: () => {
        const wasDrawer =
          store().viewerDrawerOpen && !store().paletteOpen && !store().helpOpen && !store().runDialogOpen;
        store().closeTopOverlay();
        if (wasDrawer) focusMain();
      },
    },
    {
      id: "app.theme.toggle",
      label: "테마 전환 (다크/라이트)",
      group: "app",
      icon: "sun",
      run: () => store().toggleTheme(),
    },
    {
      id: "app.theme.system",
      label: "테마: 기본(다크)으로 되돌리기",
      group: "app",
      icon: "monitor",
      disabledReason: () => (store().theme === null ? "이미 기본 테마(다크)입니다" : undefined),
      run: () => store().setTheme(null),
    },
    {
      id: "app.density.cycle",
      label: "행 밀도 전환",
      group: "app",
      icon: "density",
      run: () => {
        store().cycleDensity();
        announce(`행 밀도: ${DENSITY_LABEL[store().density]}`);
      },
    },
    ...DENSITIES.map(
      (density): Command => ({
        id: `app.density.${density}`,
        label: `행 밀도: ${DENSITY_LABEL[density]}`,
        group: "app",
        icon: "density",
        disabledReason: () => (store().density === density ? "현재 밀도입니다" : undefined),
        run: () => store().setDensity(density),
      }),
    ),
  ];
}

export function navigateCommands(): Command[] {
  const store = useAppStore.getState;
  return COLLECTION_NODES.map(
    (node): Command => ({
      id: `navigate.${node.id}`,
      label: `이동: ${node.label}`,
      group: "navigate",
      icon: node.icon,
      disabledReason: needsRun,
      run: () => {
        store().openCollection(node.id);
        focusGridWhenReady();
      },
    }),
  );
}

/** Korean disabled reasons of the run-plan controls (R4 V1, plan run-model-p2 §3.7). */
export const NOT_RUNNING_REASON = "실행 중인 런이 아닙니다";
export const NO_QUEUED_REASON = "대기 중인 태스크가 없습니다";
export const FINISHED_TASK_REASON = "이미 끝난 태스크입니다";
export const RETRY_REASON = "실패·취소·중단된 런만 다시 실행할 수 있습니다";
export const RESUME_REASON = "실패·취소·중단된 런만 이어서 실행할 수 있습니다";
export const RETRY_IN_FLIGHT_REASON = "이 런의 다시 실행이 이미 진행 중입니다";
export const RETRY_CONFLICT_MESSAGE = "이 런은 이미 다시 실행되고 있습니다. 새 런으로 이동해 확인하세요";

/** Queued tasks of a run from the runs-list `plan_counts`; null when the server sent none. */
export function queuedTaskCount(counts: RunPlanCountsCompact | null | undefined): number | null {
  if (!counts || typeof counts.tasks !== "number") return null;
  const settled =
    (counts.completed ?? 0) +
    (counts.partial ?? 0) +
    (counts.failed ?? 0) +
    (counts.skipped ?? 0) +
    (counts.cancelled ?? 0) +
    (counts.running ?? 0);
  return Math.max(0, counts.tasks - settled);
}

function retryInFlightReason(ctx: CommandContext): string | undefined {
  return ctx.runRetryInFlight ? RETRY_IN_FLIGHT_REASON : undefined;
}

function retryReason(state: ReturnType<typeof useAppStore.getState>, reason: string): string | undefined {
  return RETRYABLE_RUN_STATUSES.has(normalizeRunStatus(currentRun(state)?.status)) ? undefined : reason;
}

export function caseCommands(queryClient: QueryClient): Command[] {
  const store = useAppStore.getState;
  const refresh = () => queryClient.invalidateQueries({ queryKey: RUNS_QUERY_KEY });
  /**
   * 이어서 실행 / 처음부터 다시: one request at a time; on success the examiner follows the new
   * run (처리 stage) instead of staying on the old one with the button still enabled. A 409
   * (the run is already being retried) becomes a Korean message.
   */
  const submitRetry = async (runId: string, resume: boolean, message: string) => {
    if (store().retryPendingRunId) return;
    store().setRetryPendingRunId(runId);
    try {
      const job = await retryRun(runId, { resume });
      if (job.run_id && store().route.runId === runId) {
        store().navigate({ runId: job.run_id, collection: "process" });
      }
      announce(message);
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) throw new Error(RETRY_CONFLICT_MESSAGE);
      throw error;
    } finally {
      store().setRetryPendingRunId(null);
      await refresh();
    }
  };
  /** Plan controls: stop in-flight plan polls first so an older plan never overwrites the reply. */
  const controlPlan = async (runId: string, action: "cancel_all" | "finish") => {
    await queryClient.cancelQueries({ queryKey: runPlanQueryKey(runId) });
    const result = await controlRunPlan(runId, action);
    await queryClient.cancelQueries({ queryKey: runPlanQueryKey(runId) });
    queryClient.setQueryData(runPlanQueryKey(runId), result.plan);
  };
  return [
    {
      id: "case.run-dialog",
      label: "실행/불러오기",
      group: "case",
      icon: "play",
      disabledReason: () => (anyRunActive(store()) ? "실행 중 런이 있습니다" : undefined),
      run: () => store().setOverlay("runDialog", true),
    },
    {
      id: "case.cancel",
      label: "런 취소",
      group: "case",
      icon: "stop",
      disabledReason: (ctx) => needsRun(ctx) ?? (ctx.runIsActive ? undefined : NOT_RUNNING_REASON),
      run: async (ctx) => {
        if (!ctx.runId) return;
        await cancelRun(ctx.runId);
        announce("런 취소를 요청했습니다");
        await refresh();
      },
    },
    {
      id: "case.retry",
      label: "런 다시 실행",
      group: "case",
      icon: "refresh",
      disabledReason: (ctx) =>
        needsRun(ctx) ?? retryInFlightReason(ctx) ?? retryReason(store(), RETRY_REASON),
      run: async (ctx) => {
        if (!ctx.runId) return;
        await submitRetry(ctx.runId, false, "런을 처음부터 다시 실행합니다");
      },
    },
    {
      id: "run.resume",
      label: "이어서 실행",
      group: "case",
      icon: "play",
      disabledReason: (ctx) =>
        needsRun(ctx) ?? retryInFlightReason(ctx) ?? retryReason(store(), RESUME_REASON),
      run: async (ctx) => {
        if (!ctx.runId) return;
        await submitRetry(ctx.runId, true, "런을 이어서 실행합니다 · 완료된 태스크는 재사용합니다");
      },
    },
    {
      id: "run.plan.cancelAll",
      label: "모두 취소",
      group: "case",
      icon: "stop",
      disabledReason: (ctx) => needsRun(ctx) ?? (ctx.runIsActive ? undefined : NOT_RUNNING_REASON),
      run: async (ctx) => {
        if (!ctx.runId) return;
        if (!confirmAction(CANCEL_ALL_CONFIRM)) return;
        await controlPlan(ctx.runId, "cancel_all");
        announce("남은 처리를 모두 취소합니다 · 보고서는 지금까지의 결과로 만듭니다");
        await refresh();
      },
    },
    {
      id: "run.plan.finish",
      label: "지금까지로 마치기",
      group: "case",
      icon: "check",
      disabledReason: (ctx) => {
        const missing = needsRun(ctx);
        if (missing) return missing;
        if (!ctx.runIsActive) return NOT_RUNNING_REASON;
        const queued = queuedTaskCount(currentRun(store())?.progress?.plan_counts);
        return queued === 0 ? NO_QUEUED_REASON : undefined;
      },
      run: async (ctx) => {
        if (!ctx.runId) return;
        await controlPlan(ctx.runId, "finish");
        announce("대기 중인 태스크를 취소하고 지금까지의 결과로 마칩니다");
        await refresh();
      },
    },
    {
      id: "search.global",
      label: "전체 검색",
      group: "search",
      icon: "search",
      disabledReason: needsRun,
      run: () => focusById(GLOBAL_SEARCH_ID),
    },
    {
      id: "viewer.open",
      label: "뷰어로 이동",
      group: "viewer",
      shortcut: "Enter",
      icon: "panel-right",
      disabledReason: (ctx) =>
        // 접수·처리·보고 mount no viewer (S9): say so instead of silently doing nothing.
        !stageHasViewer(stageOf(store().route))
          ? NO_VIEWER_REASON
          : ctx.viewerHasTarget
            ? undefined
            : "선택된 행이 없습니다",
      run: () => {
        if (!stageHasViewer(stageOf(store().route))) return;
        // The viewer lives in its own window (U-F2): bring that window forward.
        if (focusPopout()) return;
        if (store().viewerIsDrawer) store().setOverlay("viewerDrawer", true);
        else expandViewerPane();
        focusViewer();
      },
    },
    {
      id: "navigate.rows-for-source",
      label: "같은 출처의 다른 행",
      group: "navigate",
      icon: "filter",
      disabledReason: (ctx) => {
        if (!ctx.runId) return NO_RUN_REASON;
        // The intake dashboard has no row list: a viewer target there is a leftover from another
        // route, so "같은 출처" has nothing to act on until a collection with rows is open.
        if (store().route.collection === "intake") return ROWS_FOR_SOURCE_INTAKE_REASON;
        const { viewerTarget: target, route } = store();
        if (!target) return "뷰어에 표시된 행이 없습니다";
        if (!target.sourcePath) return "원본 파일 경로가 없는 행입니다";
        // Re-running it would change nothing (never a silent no-op, plan U3).
        if (route.q === target.sourcePath && ROWS_FOR_SOURCE_KEEP.has(route.collection ?? "")) {
          return "이미 이 원본에서 나온 행만 표시하고 있습니다";
        }
        return undefined;
      },
      run: () => {
        const { viewerTarget, route } = store();
        if (!viewerTarget?.sourcePath) return;
        // Same collection filtered by the source path (server path_contains where the
        // grid supports it, client filter otherwise); collections without paths fall back to files.
        const current = route.collection;
        const keep = ROWS_FOR_SOURCE_KEEP.has(current ?? "");
        store().openCollection(keep && current ? current : "files", {
          kind: current === "artifacts" ? route.kind : undefined,
          q: viewerTarget.sourcePath,
        });
        focusGridWhenReady();
      },
    },
    {
      id: "export.report",
      label: "보고서",
      group: "export",
      icon: "report",
      disabledReason: needsRun,
      run: () => {
        store().openCollection("outputs");
        focusGridWhenReady();
      },
    },
  ];
}

/** Register every built-in command; returns the unregister function. */
export function registerBuiltinCommands(queryClient: QueryClient): () => void {
  return registerCommands([
    ...appCommands(),
    ...navigateCommands(),
    ...caseCommands(queryClient),
    ...reviewCommands(queryClient),
    conditionsCommand(),
    treeEmptyCommand(),
  ]);
}

/** One "case.open.{runId}" command per known run (palette: 케이스 전환). */
export function caseOpenCommands(runs: readonly RunWithProgress[]): Command[] {
  const store = useAppStore.getState;
  return runs.map(
    (run): Command => ({
      id: `case.open.${run.run_id}`,
      label: `케이스 열기: ${runDisplayName(run)}`,
      group: "case",
      icon: "folder",
      disabledReason: (ctx) => (ctx.runId === run.run_id ? "이미 열려 있는 케이스입니다" : undefined),
      run: () => store().navigate({ runId: run.run_id, collection: "intake" }),
    }),
  );
}
