/**
 * Browser tab title (r8 T-169, GAP-336): `{화면} · {사건 표시명} — RapidTriage`, so several tabs of
 * the console (one per case or screen) can be told apart. While the run is processing the title
 * starts with `(n%)`; a failed, interrupted, cancelled or partial run starts with `(!)`.
 */

import { useEffect } from "react";
import { normalizeRunStatus } from "../api/runs";
import type { RunWithProgress } from "../api/runsProgress";
import { useCaseLinks } from "../features/case/caseLink";
import { type Route, stageOf } from "../router";
import { COLLECTION_LABEL, runDisplayName } from "./collections";

export const APP_TITLE = "RapidTriage";
/** Screen name when no case is open. */
export const NO_CASE_SCREEN = "사건 선택";

/** The Korean name of the screen a route shows (one per stage, one per explore view). */
export function screenName(route: Pick<Route, "runId" | "collection" | "inReview">): string {
  if (!route.runId) return NO_CASE_SCREEN;
  switch (stageOf(route)) {
    case "intake":
      return "접수";
    case "process":
      return "처리";
    case "review":
      return route.inReview ? "특이사항" : "검토";
    case "report":
      return "보고";
    default:
      if (route.collection === "analysis") return "분석";
      return (route.collection && COLLECTION_LABEL[route.collection]) || "탐색";
  }
}

/** Processing percentage (0–100) of a queued/running run, from its compact progress. */
export function runPercent(run: RunWithProgress): number {
  const progress = run.progress;
  let done = progress?.completed_count ?? null;
  let total = progress?.total_count ?? null;
  const plan = progress?.plan_counts;
  if (!(total && total > 0) && plan?.tasks) {
    total = plan.tasks;
    done =
      (plan.completed ?? 0) +
      (plan.partial ?? 0) +
      (plan.failed ?? 0) +
      (plan.skipped ?? 0) +
      (plan.cancelled ?? 0);
  }
  if (!total || total <= 0 || done === null || done < 0) return 0;
  return Math.max(0, Math.min(100, Math.floor((done / total) * 100)));
}

const PROBLEM_STATUSES: ReadonlySet<string> = new Set(["failed", "interrupted", "cancelled"]);

/** The title prefix for a run's state: `(n%)` processing, `(!)` failed/partial, else "". */
export function statusPrefix(run: RunWithProgress | undefined): string {
  if (!run) return "";
  const status = normalizeRunStatus(run.status);
  if (status === "queued" || status === "running") return `(${runPercent(run)}%)`;
  if (PROBLEM_STATUSES.has(status)) return "(!)";
  const plan = run.progress?.plan_counts;
  if ((plan?.partial ?? 0) > 0 || (plan?.failed ?? 0) > 0 || (run.progress?.error_count ?? 0) > 0)
    return "(!)";
  return "";
}

/** The case's display name: its 사건 번호 when the run belongs to a case, else the evidence name. */
export function caseDisplayName(
  runId: string,
  run: RunWithProgress | undefined,
  caseNumber?: string,
): string {
  const number = caseNumber?.trim();
  if (number) return number;
  return run ? runDisplayName(run) : runId.slice(0, 8);
}

export function documentTitle({
  route,
  run,
  caseNumber,
}: {
  route: Pick<Route, "runId" | "collection" | "inReview">;
  run?: RunWithProgress;
  caseNumber?: string;
}): string {
  const screen = screenName(route);
  if (!route.runId) return `${screen} — ${APP_TITLE}`;
  const prefix = statusPrefix(run);
  const body = `${screen} · ${caseDisplayName(route.runId, run, caseNumber)} — ${APP_TITLE}`;
  return prefix ? `${prefix} ${body}` : body;
}

/** Keeps `document.title` in step with the route, the open run's state and its case. */
export function useDocumentTitle(route: Route, runs: readonly RunWithProgress[] | undefined): void {
  const caseNumber = useCaseLinks((state) =>
    route.runId ? state.byRun[route.runId]?.caseNumber : undefined,
  );
  const run = route.runId ? runs?.find((item) => item.run_id === route.runId) : undefined;
  const title = documentTitle({ route, run, caseNumber });
  useEffect(() => {
    document.title = title;
  }, [title]);
}
