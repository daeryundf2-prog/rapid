/**
 * Grid commands of the review tools (AXIOM E3), registered with the other grid.* commands
 * while the grid is mounted (palette + DisabledReason):
 *  - "같은 해시 행에 태그 전파": the tags already on the selected (else focused) rows go on every
 *    file row of the run with the same MD5/SHA-1/SHA-256 (server cap 10,000 rows; a refusal says
 *    why); the toast reports the applied row count.
 *  - "선택 행 CSV 내보내기": the selection as CSV with the seven fixed trailing columns.
 */

import { type ExportContext, getExportContext, postTagBatch } from "../../api/reviewTools";
import type { GridRow } from "../../contracts/collection";
import type { Command } from "../../contracts/command";
import type { GridCommandHost } from "../grid/gridCommands";
import { notifyReviewApplied, reviewTargetOf } from "../grid/reviewActions";
import { currentReviewer } from "./author";
import { buildSelectionCsv, CSV_MAX_ROWS, downloadCsv } from "./csv";
import { loadCaseTags, tagHandle, useCaseTagStore } from "./tagStore";

export const PROPAGATE_COMMAND = "review.tags.propagateByHash";
export const CSV_COMMAND = "grid.exportSelectionCsv";
export const NO_TAGS_TO_PROPAGATE = "선택한 행에 전파할 태그가 없습니다. 먼저 태그를 붙이세요";
export const NO_ROWS_REASON = "행을 먼저 선택하세요.";
export const NO_SELECTION_REASON = "선택된 행이 없습니다.";
const NO_CASE = "열린 케이스가 없습니다.";

/** Rows a command acts on: the selection, else the focused row. */
function actingRows(host: GridCommandHost): GridRow[] {
  const selected = host.getSelectedRows();
  if (selected.length) return selected;
  const row = host.getFocusedRow();
  return row ? [row] : [];
}

function tagNamesOf(rows: readonly GridRow[]): string[] {
  const names: string[] = [];
  for (const row of rows) for (const tag of row.tags) if (!names.includes(tag)) names.push(tag);
  return names;
}

export function propagateReason(host: GridCommandHost): string | undefined {
  if (!host.runId) return NO_CASE;
  const rows = actingRows(host);
  if (rows.length === 0) return NO_ROWS_REASON;
  if (rows.some((row) => reviewTargetOf(row) === null))
    return "출처 위치를 알 수 없는 행은 전파할 수 없습니다.";
  if (tagNamesOf(rows).length === 0) return NO_TAGS_TO_PROPAGATE;
  return undefined;
}

/** Runs the propagation; returns the toast text. */
export async function propagateTagsByHash(host: GridCommandHost): Promise<string> {
  const runId = host.runId;
  if (!runId) throw new Error(NO_CASE);
  const rows = actingRows(host);
  const names = tagNamesOf(rows);
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
  host.refetch();
  const label = chosen.map((tag) => `'${tag.name}'`).join(", ");
  const hashless = result.propagation?.hashless_targets ?? 0;
  const tail = hashless ? ` (해시가 없는 행 ${hashless.toLocaleString("ko-KR")}건은 그 행에만 적용)` : "";
  return `같은 해시 행 ${result.applied_count.toLocaleString("ko-KR")}건에 태그 ${label}을(를) 전파했습니다${tail}`;
}

export function csvReason(host: GridCommandHost): string | undefined {
  if (!host.runId) return NO_CASE;
  const rows = host.getSelectedRows();
  if (rows.length === 0) return NO_SELECTION_REASON;
  if (rows.length > CSV_MAX_ROWS)
    return `한 번에 ${CSV_MAX_ROWS.toLocaleString("ko-KR")}행까지 CSV로 내보낼 수 있습니다.`;
  return undefined;
}

export function csvFileName(runId: string, collection: string, count: number): string {
  const safe = (value: string) => value.replace(/[^\w.-]+/g, "_");
  return `rapidtriage-${safe(runId)}-${safe(collection)}-${count}rows.csv`;
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
  return `선택한 ${rows.length.toLocaleString("ko-KR")}행을 CSV로 내보냈습니다 (${name})`;
}

export function buildReviewToolGridCommands(hostRef: { current: GridCommandHost }): Command[] {
  const host = () => hostRef.current;
  // The grid toast is also its spoken sentence (DataGrid announces the last toast).
  const report = (text: string, tone: "info" | "error" = "info") => host().toast(text, tone);
  return [
    {
      id: PROPAGATE_COMMAND,
      label: "같은 해시 행에 태그 전파",
      group: "review",
      icon: "tag",
      disabledReason: () => {
        const reason = propagateReason(host());
        if (reason) return reason;
        const state = useCaseTagStore.getState();
        return state.status === "loading" && state.tags.length === 0 ? "태그를 불러오는 중입니다" : undefined;
      },
      run: async () => {
        try {
          report(await propagateTagsByHash(host()));
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error);
          report(`태그 전파 실패: ${reason}`, "error");
        }
      },
    },
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
