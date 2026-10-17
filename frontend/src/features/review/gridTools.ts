/**
 * Review-tool commands over rows (AXIOM E3):
 *  - "같은 해시 행에 태그 전파" (shell command, palette + viewer 더보기): the user tags on the
 *    selected rows of the list on screen (grid or thumbnails), else on the viewer row, go on every
 *    file row of the run with the same MD5/SHA-1/SHA-256 (server cap 10,000 rows; a refusal says
 *    why); the notice reports the applied row count. System tags (북마크 · 우선순위 n) are left
 *    out by default; the viewer menu lists the row's tags so one of them (system ones included)
 *    can be propagated on its own. From the viewer it always acts on the viewer row.
 *  - "선택 행 CSV 내보내기" (grid command): the selection as CSV with the seven fixed trailing
 *    columns; rows selected but not loaded are named in the notice, never dropped silently.
 */

import { announce } from "../../a11y";
import { type ExportContext, getExportContext, postTagBatch } from "../../api/reviewTools";
import { NO_RUN_REASON } from "../../commands/reasons";
import type { GridRow } from "../../contracts/collection";
import type { Command } from "../../contracts/command";
import { useAppStore } from "../../state/store";
import type { GridCommandHost } from "../grid/gridCommands";
import { notifyReviewApplied, reviewTargetOf } from "../grid/reviewActions";
import { targetAsGridRow } from "../viewer/citation";
import { currentReviewer } from "./author";
import { buildSelectionCsv, CSV_MAX_ROWS, downloadCsv } from "./csv";
import { currentRowSource } from "./rowSource";
import { loadCaseTags, tagHandle, useCaseTagStore } from "./tagStore";

export const PROPAGATE_COMMAND = "review.tags.propagateByHash";
export const CSV_COMMAND = "grid.exportSelectionCsv";
export const NO_TAGS_TO_PROPAGATE = "행에 붙은 태그가 없습니다. 먼저 태그를 붙이세요";
export const ONLY_SYSTEM_TAGS =
  "행에 사용자 태그가 없습니다. 북마크·우선순위는 뷰어 더보기 메뉴에서 하나씩 골라 전파하세요";
export const NO_PROPAGATE_ROW = "태그를 전파할 행이 없습니다. 목록에서 행을 고르거나 뷰어에 행을 여세요";
export const NO_LOCATOR_PROPAGATE = "출처 위치를 알 수 없는 행은 전파할 수 없습니다.";
export const NO_ROWS_REASON = "행을 먼저 선택하세요.";
export const NO_SELECTION_REASON = "선택된 행이 없습니다.";
const NO_CASE = "열린 케이스가 없습니다.";

/** Where the propagation reads its rows: the list selection (else the viewer row), or the viewer row. */
export type PropagateFrom = "selection" | "viewer";

/** The viewer row as a GridRow (the grid's own row when it published one). */
export function viewerGridRow(): GridRow | null {
  const state = useAppStore.getState();
  const target = state.viewerTarget;
  if (!target) return null;
  return state.viewerRow ?? targetAsGridRow(target);
}

/** Rows the propagation acts on. */
export function propagationRows(from: PropagateFrom): GridRow[] {
  if (from === "selection") {
    const selected = currentRowSource()?.getSelectedRows() ?? [];
    if (selected.length) return selected;
  }
  const row = viewerGridRow();
  return row ? [row] : [];
}

export function tagNamesOf(rows: readonly GridRow[]): string[] {
  const names: string[] = [];
  for (const row of rows) {
    for (const tag of row.tags) {
      if (!names.some((name) => name.toLocaleLowerCase() === tag.toLocaleLowerCase())) names.push(tag);
    }
  }
  return names;
}

const SYSTEM_NAME = /^(북마크|우선순위 [1-5])$/;

/** 북마크 / 우선순위 n (the case's system tags; by name until the tags are loaded). */
export function isSystemTagName(name: string): boolean {
  const key = name.toLocaleLowerCase();
  const known = useCaseTagStore.getState().tags.find((tag) => tag.name.toLocaleLowerCase() === key);
  return known ? known.kind === "system" : SYSTEM_NAME.test(name);
}

/** The tags propagated by default: every user tag on the rows. */
export function defaultPropagationTags(rows: readonly GridRow[]): string[] {
  return tagNamesOf(rows).filter((name) => !isSystemTagName(name));
}

/**
 * Why the propagation cannot run on `rows` (undefined: it can). `names` = the tags chosen in the
 * viewer menu; omitted = the default (user tags only).
 */
export function propagateReason(
  runId: string | null,
  rows: readonly GridRow[],
  names?: readonly string[],
): string | undefined {
  if (!runId) return NO_RUN_REASON;
  if (rows.length === 0) return NO_PROPAGATE_ROW;
  if (rows.some((row) => reviewTargetOf(row) === null)) return NO_LOCATOR_PROPAGATE;
  if (names) return names.length ? undefined : NO_TAGS_TO_PROPAGATE;
  if (tagNamesOf(rows).length === 0) return NO_TAGS_TO_PROPAGATE;
  if (defaultPropagationTags(rows).length === 0) return ONLY_SYSTEM_TAGS;
  return undefined;
}

/** Runs the propagation of `names` (default: the rows' user tags); returns the notice text. */
export async function propagateTagsByHash(
  runId: string | null,
  rows: readonly GridRow[],
  names: readonly string[] = defaultPropagationTags(rows),
): Promise<string> {
  if (!runId) throw new Error(NO_CASE);
  const reason = propagateReason(runId, rows, names);
  if (reason) throw new Error(reason);
  const tags = await loadCaseTags(runId, { force: true });
  const byName = new Map(tags.map((tag) => [tag.name.toLocaleLowerCase(), tag]));
  const chosen = names.map((name) => byName.get(name.toLocaleLowerCase())).filter((tag) => tag !== undefined);
  if (chosen.length === 0) throw new Error(NO_TAGS_TO_PROPAGATE);
  const handle = await tagHandle(runId);
  const targets = rows.map(reviewTargetOf).filter((target) => target !== null);
  const result = await postTagBatch(handle, runId, targets, {
    tag_ids: chosen.map((tag) => tag.id),
    propagate_by_hash: true,
    reviewer: currentReviewer(),
  });
  notifyReviewApplied(runId);
  currentRowSource()?.refetch?.();
  const label = chosen.map((tag) => `'${tag.name}'`).join(", ");
  const hashless = result.propagation?.hashless_targets ?? 0;
  const tail = hashless ? ` (해시가 없는 행 ${hashless.toLocaleString("ko-KR")}건은 그 행에만 적용)` : "";
  return `같은 해시 행 ${result.applied_count.toLocaleString("ko-KR")}건에 태그 ${label}을(를) 전파했습니다${tail}`;
}

/** Run, then say the result once (polite region) and show it in the status notice. */
export async function runPropagation(
  runId: string | null,
  rows: readonly GridRow[],
  names?: readonly string[],
): Promise<void> {
  let text: string;
  let tone: "info" | "error" = "info";
  try {
    text = await propagateTagsByHash(runId, rows, names);
  } catch (error) {
    text = `태그 전파 실패: ${error instanceof Error ? error.message : String(error)}`;
    tone = "error";
  }
  announce(text);
  useAppStore.getState().showNotice(text, tone);
}

function loadingReason(): string | undefined {
  const state = useCaseTagStore.getState();
  return state.status === "loading" && state.tags.length === 0 ? "태그를 불러오는 중입니다" : undefined;
}

/** Shell command (registered with the review tools, so it works in every list view). */
export function propagateCommand(): Command {
  return {
    id: PROPAGATE_COMMAND,
    label: "같은 해시 행에 태그 전파",
    group: "review",
    icon: "tag",
    disabledReason: (ctx) => propagateReason(ctx.runId, propagationRows("selection")) ?? loadingReason(),
    run: (ctx) => runPropagation(ctx.runId, propagationRows("selection")),
  };
}

export function csvReason(host: GridCommandHost): string | undefined {
  if (!host.runId) return NO_CASE;
  const rows = host.getSelectedRows();
  if (rows.length === 0) {
    const selected = host.getSelectedCount?.() ?? 0;
    return selected > 0
      ? `선택한 ${selected.toLocaleString("ko-KR")}행이 아직 불러오지 않은 페이지에 있습니다. 스크롤해 불러온 뒤 내보내세요.`
      : NO_SELECTION_REASON;
  }
  if (rows.length > CSV_MAX_ROWS)
    return `한 번에 ${CSV_MAX_ROWS.toLocaleString("ko-KR")}행까지 CSV로 내보낼 수 있습니다.`;
  return undefined;
}

export function csvFileName(runId: string, collection: string, count: number): string {
  const safe = (value: string) => value.replace(/[^\w.-]+/g, "_");
  return `rapidtriage-${safe(runId)}-${safe(collection)}-${count}rows.csv`;
}

/**
 * The export notice. Rows selected on pages the grid has not loaded (or has dropped) cannot be
 * written — their cells are unknown — so the notice says how many were left out.
 */
export function csvExportNotice(loaded: number, selected: number, name: string): string {
  const n = (value: number) => value.toLocaleString("ko-KR");
  if (selected > loaded) {
    return `선택 ${n(selected)}행 중 불러온 ${n(loaded)}행만 내보냅니다 (${name}). 나머지 ${n(
      selected - loaded,
    )}행은 스크롤해 불러온 뒤 다시 내보내세요.`;
  }
  return `선택한 ${n(loaded)}행을 CSV로 내보냈습니다 (${name})`;
}

export async function exportSelectionCsv(host: GridCommandHost): Promise<string> {
  const runId = host.runId;
  if (!runId) throw new Error(NO_CASE);
  const rows = host.getSelectedRows();
  let context: ExportContext | null = null;
  try {
    context = await getExportContext(runId);
  } catch {
    context = null; // 사건/증거 번호 cells say "없음"
  }
  const csv = buildSelectionCsv(rows, host.getExportColumns?.() ?? [], context);
  const name = csvFileName(
    runId,
    [host.collection.id, host.collection.kind].filter(Boolean).join("-"),
    rows.length,
  );
  downloadCsv(name, csv);
  return csvExportNotice(rows.length, host.getSelectedCount?.() ?? rows.length, name);
}

export function buildReviewToolGridCommands(hostRef: { current: GridCommandHost }): Command[] {
  const host = () => hostRef.current;
  // The grid toast is also its spoken sentence (DataGrid announces the last toast).
  const report = (text: string, tone: "info" | "error" = "info") => host().toast(text, tone);
  return [
    {
      id: CSV_COMMAND,
      label: "선택 행 CSV 내보내기",
      group: "export",
      icon: "download",
      disabledReason: () => csvReason(host()),
      run: async () => {
        report(await exportSelectionCsv(host()));
      },
    },
  ];
}
