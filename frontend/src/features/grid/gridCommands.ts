import { useEffect, useRef } from "react";
import type { RunExtractResult } from "../../api/extract";
import type { CollectionRef, GridRow } from "../../contracts/collection";
import type { Command, CommandContext } from "../../contracts/command";
import type { ViewerMode, ViewerTarget } from "../../contracts/viewer";
import { useAppStore } from "../../state/store";
import { runDisabledReason } from "../analysis/commands";
import { caseRoute, otherCaseIds } from "../analysis/crossCase";
import { useAnalysisStore } from "../analysis/store";
import { caseCitationParts, citationDisabledReason, resolveCaseLink } from "../case/caseLink";
import { buildReviewToolGridCommands } from "../review/gridTools";
import { registerRowSource } from "../review/rowSource";
import { recordCitationParts } from "../viewer/citation";
import { PIVOT_LABELS, PIVOT_ORDER, type PivotId, recordPivots } from "../viewer/pivots";
import { registerCommand, registerLocalCommand } from "./adapter";
import { baseName, currentTimezone, isRecord } from "./columns/common";
import { buildFamilyCommands } from "./familyCommands";
import {
  applyNote,
  applyReviewAction,
  type BatchAction,
  EXTRACT_LIMIT,
  MARK_LABELS,
  optimisticPatch,
  partitionReviewRows,
  reviewTargetOf,
  skippedNotice,
  storeNotice,
} from "./reviewActions";
import type { ColumnSpec } from "./types";

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
  /** Visible column specs in display order (CSV export of the selection, AXIOM E3). */
  getExportColumns?: () => ColumnSpec[];
  /** Selected keys, loaded or not (getSelectedRows only returns loaded rows). */
  getSelectedCount?: () => number;
}

export function buildViewerTarget(runId: string, row: GridRow, mode?: ViewerMode): ViewerTarget {
  const highlight = row.fields.highlight as ViewerTarget["highlight"] | undefined;
  // Artifact rows open on the decoded record first (meta) unless a mode was asked for.
  const isArtifact = row.ref.collection === "artifacts" || row.ref.locator.startsWith("/artifacts/");
  // Rows may ask for a mode (analysis carve hits open their source in hex at the offset).
  const rowMode =
    typeof row.fields.viewerMode === "string" ? (row.fields.viewerMode as ViewerMode) : undefined;
  const preferred = mode ?? rowMode ?? (isArtifact ? "meta" : undefined);
  const review = reviewLocatorOf(row);
  return {
    ref: row.ref,
    runId,
    sourcePath: row.sourcePath,
    ...(row.fields.isDirectory === true ? { isDirectory: true, preferredMode: "meta" as const } : {}),
    ...(preferred && row.fields.isDirectory !== true ? { preferredMode: preferred } : {}),
    ...(highlight ? { highlight } : {}),
    ...(review ? { review } : {}),
  };
}

/**
 * The run-output row a search hit carries (`fields.reviewCollection` / `reviewKind` /
 * `reviewPointer`, from the API `locator`; R7 S2 #8); undefined for every other row.
 */
export function reviewLocatorOf(row: GridRow): ViewerTarget["review"] {
  const { reviewCollection, reviewKind, reviewPointer } = row.fields;
  if (typeof reviewCollection !== "string" || !reviewCollection) return undefined;
  if (typeof reviewPointer !== "string" || !reviewPointer.startsWith("/")) return undefined;
  return typeof reviewKind === "string" && reviewKind
    ? { collection: reviewCollection, kind: reviewKind, pointer: reviewPointer }
    : { collection: reviewCollection, pointer: reviewPointer };
}

/** `collection[:kind]:locator` a citation names: a search hit's source row, else the row's own ref. */
export function citationLocator(row: GridRow): string {
  const review = reviewLocatorOf(row);
  if (review) return [review.collection, review.kind, review.pointer].filter(Boolean).join(":");
  return `${row.ref.collection}:${row.ref.locator}`;
}

/**
 * Grid citation: (사건 번호 · 증거 번호 when the run belongs to a case), path, locator, (container)
 * sha256, then the record id and record time.
 */
export function citationText(row: GridRow, runId?: string | null): string {
  const parts = [...caseCitationParts(runId), row.sourcePath ?? row.title, `[${citationLocator(row)}]`];
  const artifactRow = row.ref.collection === "artifacts" || reviewLocatorOf(row)?.collection === "artifacts";
  if (row.sha256) parts.push(`${artifactRow ? "컨테이너 sha256" : "sha256"}=${row.sha256}`);
  const record = recordCitationParts(row, currentTimezone());
  if (record.length) parts.push(...record);
  else if (row.timestamp) parts.push(row.timestamp);
  return parts.join(" ");
}

export async function copyText(text: string): Promise<void> {
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

export const OPEN_OTHER_CASE_COMMAND = "grid.openOtherCase";
export const NO_OTHER_CASE_REASON = "다른 케이스에 나타난 지표 행이 아닙니다.";

/** Other runs a cross-case result row points at (empty for every other row). */
export function otherCasesOf(row: GridRow, runId: string | null): string[] {
  if (row.ref.collection !== "analysis" || row.fields.kind !== "cross-case") return [];
  return otherCaseIds(isRecord(row.fields.details) ? row.fields.details : {}, runId);
}

/** "선택 행 OCR 실행" (plan analysis-workbench-p1 §3.2 ocr-batch `target.locators`). */
export const OCR_SELECTED_COMMAND = "grid.ocrSelected";
export const OCR_NO_IMAGE_REASON = "선택한 행에 이미지가 없습니다.";
export const OCR_COLLECTION_REASON = "파일·아티팩트 목록에서만 선택 행 OCR을 실행할 수 있습니다.";
export const OCR_MAX_IMAGES = 1000;
export const OCR_TOO_MANY_REASON = "한 번에 1,000장까지 OCR할 수 있습니다";
/** The media collector's decoded-picture type (`media-image-unreadable` / video / audio rows are not OCR input). */
const IMAGE_ARTIFACT_TYPES = new Set(["media-image"]);

const IMAGE_EXTENSIONS = new Set(["jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic"]);

/**
 * OCR locator of an image row: files → `/candidates/<n>`, media-image artifacts →
 * `/artifacts/<n>`; null for anything else.
 */
export function ocrLocatorOf(row: GridRow): string | null {
  const extOf = (value: string | null | undefined) =>
    /\.([A-Za-z0-9]+)$/.exec(value ?? "")?.[1]?.toLowerCase() ?? "";
  if (row.ref.collection === "artifacts") {
    if (row.ref.kind !== "media-image" || !/^\/artifacts\/\d+$/.test(row.ref.locator)) return null;
    // Only picture rows: an image artifact type, or an image file extension.
    const type = row.artifactType ?? "";
    const pictured = type ? IMAGE_ARTIFACT_TYPES.has(type) : IMAGE_EXTENSIONS.has(extOf(row.sourcePath));
    return pictured ? row.ref.locator : null;
  }
  if (row.ref.collection !== "files" || !/^\/candidates\/\d+$/.test(row.ref.locator)) return null;
  const field = typeof row.fields.extension === "string" ? row.fields.extension : "";
  const ext = (field || /\.([A-Za-z0-9]+)$/.exec(row.sourcePath ?? row.title)?.[1] || "")
    .replace(/^\./, "")
    .toLowerCase();
  return IMAGE_EXTENSIONS.has(ext) ? row.ref.locator : null;
}

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
      // 사건=…/증거=… prefix: blocked until the run's case link is known (never copied without it).
      disabledReason: (ctx) => rowDisabled(false)(ctx) ?? citationDisabledReason(ctx.runId),
      run: async (ctx) => {
        const row = focused();
        if (!row) return;
        await resolveCaseLink(ctx.runId);
        await copyText(citationText(row, ctx.runId));
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
    {
      // Cross-case result rows: open the (first) other case the indicator occurs in.
      id: OPEN_OTHER_CASE_COMMAND,
      label: "다른 케이스에서 열기",
      group: "grid",
      icon: "external",
      disabledReason: () => {
        const row = focused();
        if (!row) return NO_ROW;
        return otherCasesOf(row, host().runId).length ? undefined : NO_OTHER_CASE_REASON;
      },
      run: () => {
        const row = focused();
        if (!row) return;
        const [first] = otherCasesOf(row, host().runId);
        const details = isRecord(row.fields.details) ? row.fields.details : {};
        if (first) useAppStore.getState().navigate(caseRoute(details, first));
      },
    },
  ];

  const ocrRows = (): GridRow[] => {
    const h = host();
    const selected = h.getSelectedRows();
    if (selected.length) return selected;
    const row = focused();
    return row ? [row] : [];
  };
  commands.push({
    id: OCR_SELECTED_COMMAND,
    label: "선택 행 OCR 실행",
    group: "grid",
    icon: "image",
    disabledReason: (ctx) => {
      const h = host();
      if (!h.runId) return "열린 케이스가 없습니다.";
      if (h.collection.id !== "files" && h.collection.id !== "artifacts") return OCR_COLLECTION_REASON;
      const rows = ocrRows();
      if (rows.length === 0) return NO_SELECTION;
      const images = new Set(rows.map(ocrLocatorOf).filter((l): l is string => l !== null));
      if (images.size === 0) return OCR_NO_IMAGE_REASON;
      if (images.size > OCR_MAX_IMAGES) return OCR_TOO_MANY_REASON;
      return runDisabledReason("ocr-batch", { runId: ctx.runId ?? h.runId });
    },
    run: () => {
      const locators = [
        ...new Set(
          ocrRows()
            .map(ocrLocatorOf)
            .filter((l): l is string => l !== null),
        ),
      ];
      if (locators.length)
        useAnalysisStore.getState().openDialog({ kind: "ocr-batch", preset: { locators } });
    },
  });

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
  // Pivots (viewer redesign §5): same list as the viewer "⋯" menu, on the focused row.
  for (const id of PIVOT_ORDER) {
    const pivotOf = () => {
      const row = focused();
      return row
        ? recordPivots(row, host().runId ?? "", useAppStore.getState().route.tz).find((p) => p.id === id)
        : undefined;
    };
    commands.push({
      id: pivotCommandId(id),
      label: PIVOT_LABELS[id],
      group: "grid",
      icon:
        id === "timeline-window"
          ? "clock"
          : id === "matched-event" || id === "source-artifact"
            ? "external"
            : "filter",
      disabledReason: () => {
        if (!focused()) return NO_ROW;
        return pivotOf()?.reason;
      },
      run: () => {
        const route = pivotOf()?.route;
        if (route) useAppStore.getState().navigate(route);
      },
    });
  }
  return commands;
}

export function pivotCommandId(id: PivotId): string {
  return `grid.pivot.${id}`;
}

/** Review items of the row menu (always listed; disabled with a reason when they cannot run). */
export const ROW_MARK_ACTIONS: BatchAction[] = [
  "relevant",
  "needs-review",
  "excluded",
  "include-in-report",
  "bookmark",
];

export function rowMarkCommandId(action: BatchAction): string {
  return `grid.row.${action}`;
}

const ROW_MARK_LABELS: Partial<Record<BatchAction, string>> = {
  relevant: "관련 있음 표시",
  "needs-review": "재검토 표시",
  excluded: "제외 표시",
  "include-in-report": "보고서 포함 표시",
  bookmark: "북마크",
};

/** Rows a row-menu mark applies to: the selection when it contains the focused row, else that row. */
function menuRows(host: GridCommandHost): GridRow[] {
  const row = host.getFocusedRow();
  if (!row) return [];
  const selected = host.getSelectedRows();
  return selected.some((r) => r.rowKey === row.rowKey) ? selected : [row];
}

/** Row-menu review commands (grid-local: the R/X/I/B shortcuts stay the shell's review.mark.*). */
export function buildRowMarkCommands(hostRef: { current: GridCommandHost }): Command[] {
  const host = () => hostRef.current;
  return ROW_MARK_ACTIONS.map(
    (action): Command => ({
      id: rowMarkCommandId(action),
      label: ROW_MARK_LABELS[action] ?? MARK_LABELS[action],
      group: "review",
      icon: action === "bookmark" ? "bookmark" : "flag",
      disabledReason: () => {
        const h = host();
        if (!h.runId) return "열린 케이스가 없습니다.";
        const rows = menuRows(h);
        if (rows.length === 0) return NO_ROW;
        // Rows without a source record are skipped (with a note); only all-unknown disables.
        if (rows.every((r) => reviewTargetOf(r) === null))
          return "출처 위치를 알 수 없는 행은 표시할 수 없습니다.";
        return undefined;
      },
      run: async () => {
        const h = host();
        await runMark(h, menuRows(h), action);
      },
    }),
  );
}

/** Apply a batch mark with optimistic update + rollback and a Korean error toast. */
export async function runBatch(host: GridCommandHost, action: BatchAction, tag?: string): Promise<boolean> {
  return runMark(host, host.getSelectedRows(), action, tag);
}

async function runMark(
  host: GridCommandHost,
  rows: GridRow[],
  action: BatchAction,
  tag?: string,
): Promise<boolean> {
  if (rows.length === 0 || !host.runId) return false;
  // Only rows with a source record change optimistically; the others are skipped (and named).
  const patched = action === "extract" ? [] : partitionReviewRows(rows).targetable;
  const rollback =
    action === "extract"
      ? () => {}
      : host.patchRows(
          patched.map((r) => r.rowKey),
          optimisticPatch(action, tag),
        );
  try {
    const result = await applyReviewAction(host.runId, rows, action, { tag });
    if (result.extract) host.showExtract(result.extract);
    else
      host.toast(
        `${MARK_LABELS[action]}: ${result.applied}건 처리했습니다.${storeNotice(result)}${skippedNotice(result.skipped ?? [])}`,
        "info",
      );
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
    const unregister = [
      ...buildGridCommands(hostRef).map(registerCommand),
      // 계열 보기 · 상위 항목으로 · 선택 확장 (R7 갈래 A).
      ...buildFamilyCommands(hostRef).map(registerCommand),
      ...buildRowMarkCommands(hostRef).map(registerLocalCommand),
      ...buildReviewToolGridCommands(hostRef).map(registerCommand),
      // Shell review tools (tag propagation, digit keys) read the selection through this.
      registerRowSource({
        getSelectedRows: () => hostRef.current.getSelectedRows(),
        patchRows: (keys, patch) => hostRef.current.patchRows(keys, patch),
        refetch: () => hostRef.current.refetch(),
      }),
    ];
    return () => {
      for (const off of unregister) off();
    };
  }, []);
}
