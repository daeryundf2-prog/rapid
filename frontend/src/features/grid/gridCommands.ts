import { useEffect, useRef } from "react";
import type { RunExtractResult } from "../../api/extract";
import type { CollectionRef, GridRow } from "../../contracts/collection";
import type { Command, CommandContext } from "../../contracts/command";
import type { ViewerMode, ViewerTarget } from "../../contracts/viewer";
import { registerCommand } from "./adapter";
import { baseName } from "./columns/common";
import {
  applyNote,
  applyReviewAction,
  type BatchAction,
  EXTRACT_LIMIT,
  MARK_LABELS,
  optimisticPatch,
  storeNotice,
} from "./reviewActions";

/** Everything the grid commands need from the live grid; read through a ref so commands stay stable. */
export interface GridCommandHost {
  runId: string | null;
  collection: CollectionRef;
  getFocusedRow: () => GridRow | undefined;
  getSelectedRows: () => GridRow[];
  /** Publish the viewer target for a row (optionally with a preferred mode) and move focus to the viewer. */
  openRow: (row: GridRow, mode?: ViewerMode) => void;
  setFilter: (q: string) => void;
  navigate: (collection: CollectionRef, q?: string) => void;
  patchRows: (keys: string[], patch: (row: GridRow) => GridRow) => () => void;
  toast: (message: string, tone?: "error" | "info") => void;
  refetch: () => void;
  /** Show the extract manifest summary + download button. */
  showExtract: (result: RunExtractResult) => void;
  openTagPrompt: () => void;
  runIsActive: boolean;
}

export function buildViewerTarget(runId: string, row: GridRow, mode?: ViewerMode): ViewerTarget {
  const highlight = row.fields.highlight as ViewerTarget["highlight"] | undefined;
  // Artifact rows open on the decoded record first (meta) unless a mode was asked for.
  const isArtifact = row.ref.collection === "artifacts" || row.ref.locator.startsWith("/artifacts/");
  const preferred = mode ?? (isArtifact ? "meta" : undefined);
  return {
    ref: row.ref,
    runId,
    sourcePath: row.sourcePath,
    ...(preferred ? { preferredMode: preferred } : {}),
    ...(highlight ? { highlight } : {}),
  };
}

export function citationText(row: GridRow): string {
  const parts = [row.sourcePath ?? row.title, `[${row.ref.collection}:${row.ref.locator}]`];
  if (row.sha256) parts.push(`sha256=${row.sha256}`);
  if (row.timestamp) parts.push(row.timestamp);
  return parts.join(" ");
}

async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement("textarea");
  area.value = text;
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

const NO_ROW = "행을 먼저 선택하세요.";
const NO_SELECTION = "선택된 행이 없습니다.";
const NO_PATH = "원본 경로가 없는 행입니다.";

export const BATCH_ACTIONS: BatchAction[] = [
  "relevant",
  "needs-review",
  "excluded",
  "include-in-report",
  "bookmark",
  "tag",
  "extract",
];

export function batchCommandId(action: BatchAction): string {
  return `grid.batch.${action}`;
}

export function buildGridCommands(hostRef: { current: GridCommandHost }): Command[] {
  const host = () => hostRef.current;
  const focused = () => host().getFocusedRow();

  const rowDisabled =
    (needsPath: boolean) =>
    (_ctx: CommandContext): string | undefined => {
      const row = focused();
      if (!row) return NO_ROW;
      if (needsPath && !row.sourcePath) return NO_PATH;
      return undefined;
    };

  const open = (mode?: ViewerMode) => () => {
    const row = focused();
    if (row) host().openRow(row, mode);
  };

  const commands: Command[] = [
    {
      id: "grid.openSource",
      label: "원본 보기",
      group: "grid",
      icon: "file",
      disabledReason: rowDisabled(true),
      run: open("source"),
    },
    {
      id: "grid.openHex",
      label: "헥스로 보기",
      group: "grid",
      icon: "hex",
      disabledReason: rowDisabled(true),
      run: open("hex"),
    },
    {
      id: "grid.copyPath",
      label: "경로 복사",
      group: "grid",
      icon: "copy",
      disabledReason: rowDisabled(true),
      run: async () => {
        const row = focused();
        if (!row?.sourcePath) return;
        await copyText(row.sourcePath);
        host().toast("경로를 복사했습니다.", "info");
      },
    },
    {
      id: "grid.copyCitation",
      label: "인용 복사",
      group: "grid",
      icon: "quote",
      disabledReason: rowDisabled(false),
      run: async () => {
        const row = focused();
        if (!row) return;
        await copyText(citationText(row));
        host().toast("인용을 복사했습니다.", "info");
      },
    },
    {
      id: "grid.showInTimeline",
      label: "타임라인에서 보기",
      group: "grid",
      icon: "timeline",
      disabledReason: rowDisabled(true),
      run: () => {
        const row = focused();
        if (row?.sourcePath) host().navigate({ id: "timeline" }, baseName(row.sourcePath));
      },
    },
    {
      id: "grid.sameSource",
      label: "같은 출처 행",
      group: "grid",
      icon: "filter",
      disabledReason: rowDisabled(true),
      run: () => {
        const row = focused();
        if (row?.sourcePath) host().setFilter(row.sourcePath);
      },
    },
  ];

  for (const action of BATCH_ACTIONS) {
    commands.push({
      id: batchCommandId(action),
      label: MARK_LABELS[action],
      group: action === "extract" ? "export" : "review",
      icon: action === "extract" ? "download" : action,
      disabledReason: () => {
        const h = host();
        const rows = h.getSelectedRows();
        if (rows.length === 0) return NO_SELECTION;
        if (!h.runId) return "열린 케이스가 없습니다.";
        if (action === "extract") {
          const paths = new Set(rows.map((r) => r.sourcePath).filter(Boolean));
          if (paths.size === 0) return NO_PATH;
          if (paths.size > EXTRACT_LIMIT) return `한 번에 ${EXTRACT_LIMIT}건까지 추출할 수 있습니다.`;
        }
        return undefined;
      },
      run: async () => {
        const h = host();
        if (action === "tag") {
          h.openTagPrompt();
          return;
        }
        await runBatch(h, action);
      },
    });
  }
  return commands;
}

/** Apply a batch mark with optimistic update + rollback and a Korean error toast. */
export async function runBatch(host: GridCommandHost, action: BatchAction, tag?: string): Promise<boolean> {
  const rows = host.getSelectedRows();
  if (rows.length === 0 || !host.runId) return false;
  const rollback =
    action === "extract"
      ? () => {}
      : host.patchRows(
          rows.map((r) => r.rowKey),
          optimisticPatch(action, tag),
        );
  try {
    const result = await applyReviewAction(host.runId, rows, action, { tag });
    if (result.extract) host.showExtract(result.extract);
    else
      host.toast(`${MARK_LABELS[action]}: ${result.applied}건 처리했습니다.${storeNotice(result)}`, "info");
    return true;
  } catch (error) {
    rollback();
    const reason = error instanceof Error ? error.message : String(error);
    host.toast(`${MARK_LABELS[action]} 처리에 실패했습니다. ${reason}`, "error");
    return false;
  }
}

/** Batch note (X5): one note on every selected row, optimistic on `fields.note`. */
export async function runNote(host: GridCommandHost, note: string): Promise<boolean> {
  const rows = host.getSelectedRows();
  if (rows.length === 0 || !host.runId) return false;
  const text = note.trim();
  const rollback = host.patchRows(
    rows.map((r) => r.rowKey),
    (row) => ({ ...row, fields: { ...row.fields, note: text } }),
  );
  try {
    const result = await applyNote(host.runId, rows, text);
    host.toast(`메모: ${result.applied}건에 저장했습니다.${storeNotice(result)}`, "info");
    return true;
  } catch (error) {
    rollback();
    const reason = error instanceof Error ? error.message : String(error);
    host.toast(`메모 저장에 실패했습니다. ${reason}`, "error");
    return false;
  }
}

/** Register every grid.* command while the grid is mounted. */
export function useGridCommands(host: GridCommandHost): void {
  const hostRef = useRef(host);
  hostRef.current = host;
  useEffect(() => {
    const unregister = buildGridCommands(hostRef).map(registerCommand);
    return () => {
      for (const off of unregister) off();
    };
  }, []);
}
