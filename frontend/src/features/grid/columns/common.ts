import type { CollectionId, GridRow, ReviewStatus } from "../../../contracts/collection";
import type { RowRef } from "../../../contracts/rowRef";
import { runEvidenceTimezone } from "../../../state/hooks";
import { currentRun } from "../../../state/slices/runs";
import { useAppStore } from "../../../state/store";
import { evidenceTimeTooltip, formatGridTime } from "../../../utils/time";
import type { CellValue, ColumnSpec } from "../types";
import { pathCell } from "./PathCell";
import { reviewStatusCell } from "./StatusCells";

/** Effective display timezone (URL tz > preference > evidence > local); useCollectionQuery re-renders the grid on change. */
export function currentTimezone(): string {
  const s = useAppStore.getState();
  return s.route.tz ?? s.timezone ?? runEvidenceTimezone(currentRun(s)) ?? "local";
}

function pick(record: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys)
    if (record[key] !== undefined && record[key] !== null && record[key] !== "") return record[key];
  return undefined;
}

/**
 * Evidence-info fields for MetaView (복구 방법/삭제 여부/위치): flat keys plus the raw record
 * under `recoveryInfo`. (`fields.recovery` stays the short kind string used by the column.)
 */
export function recoveryFields(record: unknown): Record<string, unknown> {
  if (!isRecord(record) || Object.keys(record).length === 0) return {};
  return {
    recoverySourceId: pick(record, [
      "source_id",
      "recovery_source_id",
      "candidate_kind",
      "method",
      "recovery_method",
    ]),
    deletionState: pick(record, [
      "deletion_state",
      "deleted",
      "is_deleted",
      "allocation_state",
      "deleted_state",
    ]),
    sourceOffset: pick(record, ["source_offset", "offset", "page_offset", "start_offset"]),
    recoveryInfo: record,
  };
}

export function str(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function strOrNull(value: unknown): string | null {
  const text = str(value).trim();
  return text ? text : null;
}

export function baseName(path: string | null | undefined): string {
  if (!path) return "";
  const trimmed = path.replace(/[\\/]+$/, "");
  return trimmed.split(/[\\/]/).pop() || trimmed;
}

export function formatBytes(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unit]}`;
}

export function joinList(value: unknown): string {
  return Array.isArray(value) ? value.map(str).filter(Boolean).join(", ") : str(value);
}

export function sha256Of(...candidates: unknown[]): string | null {
  for (const candidate of candidates) {
    const text = strOrNull(candidate);
    if (text && /^[0-9a-f]{64}$/i.test(text)) return text.toLowerCase();
  }
  return null;
}

export function toReviewStatus(status: unknown, includeInReport?: unknown): ReviewStatus | null {
  const value = str(status);
  if (value === "relevant") return "relevant";
  if (value === "needs-review") return "needs-review";
  if (value === "excluded" || value === "not-relevant") return "excluded";
  if (includeInReport === true) return "include-in-report";
  return null;
}

export const REVIEW_LABELS: Record<ReviewStatus, string> = {
  relevant: "관련 있음",
  "needs-review": "재검토",
  excluded: "제외",
  "include-in-report": "보고서 포함",
};

export function makeRef(collection: CollectionId, locator: string, kind?: string): RowRef {
  return kind ? { collection, kind, locator } : { collection, locator };
}

export function makeRow(
  ref: RowRef,
  base: Partial<Omit<GridRow, "rowKey" | "ref" | "fields">> & { title: string },
  fields: Record<string, unknown> = {},
): GridRow {
  return {
    // Artifact locators are kind-local ("/artifacts/0" exists in every kind): the kind is part of
    // the key, or rows of different kinds collide as React keys and leave stale overlapping rows.
    rowKey: ref.kind ? `${ref.collection}:${ref.kind}:${ref.locator}` : `${ref.collection}:${ref.locator}`,
    ref,
    sourcePath: null,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    ...base,
    fields,
  };
}

/** Minimum width of every time column: the whole "YYYY-MM-DD HH:MM:SS" (C-D6, plan r7 §3.2). */
export const TIME_COLUMN_MIN = 180;

/**
 * Share of the grid's spare width a column takes (C-D7): the long-text columns — 항목/이름 (3),
 * 경로 · URL · 대상 (2), 제목 · 메시지 · 내용 · 요약 · 미리보기 (1) — grow; time, number and chip
 * columns keep their width (0).
 */
export function growWeight(spec: Pick<ColumnSpec, "id" | "header" | "filterKind" | "align">): number {
  if (spec.id === "title") return 3;
  if (spec.filterKind === "time" || spec.filterKind === "number" || spec.align === "right") return 0;
  const id = spec.id.toLowerCase();
  if (id === "path" || /(^|[:_])(url|path|uri)$/.test(id) || /경로|URL|대상/.test(spec.header)) return 2;
  if (/제목|메시지|내용|요약|본문|미리보기|세부 정보|상세/.test(spec.header)) return 1;
  return 0;
}

/** Narrowest a long-text column gets before lower-priority columns hide instead: URL / 경로 … · 제목 …. */
const READABLE_MIN_BY_WEIGHT: Readonly<Record<number, number>> = { 2: 200, 1: 120 };

/**
 * The width a column may shrink to when the grid is narrower than the default widths: its own
 * `minWidth` (time columns keep their seconds), raised for the long-text columns so a URL or a
 * title stays readable (C-D7), never above the default width itself.
 */
export function fitMinWidth(
  spec: Pick<ColumnSpec, "id" | "header" | "filterKind" | "align" | "width" | "minWidth">,
): number {
  const own = spec.minWidth ?? 60;
  const readable = READABLE_MIN_BY_WEIGHT[growWeight(spec)] ?? 0;
  return Math.min(spec.width, Math.max(own, readable));
}

/** Shared columns so widths and labels stay uniform across collections. */
export const col = {
  title(header = "항목", width = 280): ColumnSpec {
    return {
      id: "title",
      header,
      width,
      minWidth: 120,
      presets: ["analysis", "compact", "source"],
      value: (r) => r.title,
    };
  },
  path(width = 360, presets: ColumnSpec["presets"] = ["analysis", "source"]): ColumnSpec {
    return {
      id: "path",
      header: "경로",
      width,
      // The middle truncation (folder … file name) needs room: never narrower than 200px.
      minWidth: 200,
      presets,
      value: (r) => r.sourcePath,
      render: (r) => pathCell(r.sourcePath),
    };
  },
  timestamp(width = TIME_COLUMN_MIN, presets: ColumnSpec["presets"] = ["analysis", "compact"]): ColumnSpec {
    return {
      id: "timestamp",
      header: "시각",
      width: Math.max(width, TIME_COLUMN_MIN),
      // "YYYY-MM-DD HH:MM:SS" never loses its seconds (C-D6).
      minWidth: TIME_COLUMN_MIN,
      presets,
      value: (r) => r.timestamp,
      format: (r) => (r.timestamp ? formatGridTime(r.timestamp, currentTimezone()) : ""),
      // Full evidence reading (local · zone · UTC · FILETIME) on hover.
      tooltip: (r) => (r.timestamp ? evidenceTimeTooltip(r.timestamp, currentTimezone()) : ""),
    };
  },
  review(): ColumnSpec {
    return {
      id: "review",
      // One word for the review mark everywhere (용어 지도: 검토, C-D10).
      header: "검토",
      width: 96,
      presets: ["analysis", "source"],
      value: (r) => r.reviewStatus,
      format: (r) => (r.reviewStatus ? REVIEW_LABELS[r.reviewStatus] : ""),
      render: reviewStatusCell,
    };
  },
  sha256(): ColumnSpec {
    return {
      id: "sha256",
      header: "SHA-256",
      width: 200,
      mono: true,
      presets: ["source"],
      value: (r) => r.sha256,
    };
  },
  field(
    id: string,
    header: string,
    width: number,
    presets: ColumnSpec["presets"],
    pick: (r: GridRow) => CellValue,
    extra: Partial<ColumnSpec> = {},
  ): ColumnSpec {
    return { id, header, width, presets, value: pick, ...extra };
  },
};

export function fieldStr(row: GridRow, key: string): string {
  return str(row.fields[key]);
}
