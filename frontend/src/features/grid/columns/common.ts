import type { CollectionId, GridRow, ReviewStatus } from "../../../contracts/collection";
import type { RowRef } from "../../../contracts/rowRef";
import { runEvidenceTimezone } from "../../../state/hooks";
import { currentRun } from "../../../state/slices/runs";
import { useAppStore } from "../../../state/store";
import {
  assumedUtcCandidates,
  compareEvidenceSortKeys,
  type EvidenceSortKey,
  evidenceSortKey,
  evidenceTimeTooltip,
  exactEvidenceTime,
  formatGridTime,
  zoneStatusLabel,
} from "../../../utils/time";
import type { CellValue, ColumnSpec } from "../types";
import { pathCell } from "./PathCell";
import { reviewStatusCell } from "./StatusCells";

/** Effective display timezone (URL tz > preference > evidence > local); useCollectionQuery re-renders the grid on change. */
export function currentTimezone(): string {
  const s = useAppStore.getState();
  return s.route.tz ?? s.timezone ?? runEvidenceTimezone(currentRun(s)) ?? "local";
}

/** Source zone label of a row's time (timeline `timezone`, else `details.timestamp_timezone`). */
export function rowTimeZone(row: GridRow): string | null {
  const zone = str(row.fields.tsZone);
  if (zone) return zone;
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  return strOrNull(details.timestamp_timezone);
}

/** Source FILETIME ticks of a row's time: decimal text when the source kept it, else the raw value. */
export function rowSourceTicks(row: GridRow): string | number | null {
  const details = isRecord(row.fields.details) ? row.fields.details : {};
  for (const value of [row.fields.tsTicks, details.timestamp_utc_ticks, details.timestamp_filetime]) {
    if (typeof value === "string" || typeof value === "number") return value;
  }
  return null;
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
  timestamp(width = 170, presets: ColumnSpec["presets"] = ["analysis", "compact"]): ColumnSpec {
    return {
      id: "timestamp",
      header: "시각",
      width,
      presets,
      value: (r) => r.timestamp,
      format: (r) => (r.timestamp ? formatGridTime(r.timestamp, currentTimezone(), rowTimeZone(r)) : ""),
      // Integer 100 ns ticks, never the text (".000001" would sort before ".0000007").
      ...evidenceTimeColumnParts(
        (r) =>
          r.timestamp
            ? { value: r.timestamp, sourceZone: rowTimeZone(r), sourceTicks: rowSourceTicks(r) }
            : null,
        { utc: "시각 UTC 원문", filetime: "FILETIME", zone: "시간대 상태", assumed: "가정 환산 UTC (근거)" },
      ),
    };
  },
  review(): ColumnSpec {
    return {
      id: "review",
      header: "선별",
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

/** One cell's evidence time: the value as read, its source zone label and its source FILETIME. */
export interface EvidenceTimeCell {
  value: string;
  sourceZone: string | null;
  sourceTicks: string | number | null;
}

/**
 * Order, tooltip and selection CSV of an evidence-time column (the generic 시각 column and every
 * catalogue time column such as the analysis preset's 시각(기록)): integer 100 ns order with
 * undetermined-zone wall clocks apart, every source fraction digit, the exact UTC text, the
 * FILETIME with its basis, the zone status and the assumed-zone conversion of a wall clock.
 */
export function evidenceTimeColumnParts(
  read: (row: GridRow) => EvidenceTimeCell | null,
  headers: { utc: string; filetime: string; zone: string; assumed: string },
): Required<Pick<ColumnSpec, "compare" | "tooltip" | "exportFormat" | "exportExtras">> {
  const exact = (row: GridRow) => {
    const cell = read(row);
    return cell
      ? exactEvidenceTime(cell.value, currentTimezone(), {
          sourceZone: cell.sourceZone,
          rawFiletime: cell.sourceTicks,
        })
      : null;
  };
  const keys = new WeakMap<GridRow, EvidenceSortKey | null>();
  const keyOf = (row: GridRow) => {
    if (!keys.has(row)) {
      const cell = read(row);
      keys.set(row, cell ? evidenceSortKey(cell.value, cell.sourceZone, cell.sourceTicks) : null);
    }
    return keys.get(row) ?? null;
  };
  return {
    compare: (a, b) => {
      const ka = keyOf(a);
      const kb = keyOf(b);
      if (!ka || !kb) return ka === kb ? 0 : ka ? -1 : 1;
      return compareEvidenceSortKeys(ka, kb);
    },
    // Full evidence reading (local · zone · exact UTC · FILETIME) on hover.
    tooltip: (row) => {
      const cell = read(row);
      return cell
        ? evidenceTimeTooltip(cell.value, currentTimezone(), cell.sourceTicks, cell.sourceZone)
        : "";
    },
    // The CSV keeps every fraction digit and never gives an undetermined wall clock a zone.
    exportFormat: (row) => exact(row)?.display ?? read(row)?.value ?? "",
    exportExtras: [
      { header: headers.utc, value: (row) => exact(row)?.exactUtc ?? "" },
      { header: headers.filetime, value: (row) => exact(row)?.filetime ?? "" },
      {
        header: headers.zone,
        value: (row) => {
          const reading = exact(row);
          return reading ? zoneStatusLabel(reading.zoneStatus) : "";
        },
      },
      {
        header: headers.assumed,
        value: (row) => {
          const reading = exact(row);
          const zone = runEvidenceTimezone(currentRun(useAppStore.getState()));
          return reading?.wallClock ? assumedUtcText(reading.wallClock, zone) : "";
        },
      },
    ],
  };
}

/**
 * CSV text of a wall clock converted under the evidence zone: the one UTC instant, both instants
 * of a repeated hour, or why a wall clock inside a daylight-saving gap has none.
 */
export function assumedUtcText(wallClock: string, zone: string | null | undefined): string {
  const candidates = assumedUtcCandidates(wallClock, zone);
  if (!candidates) return "";
  const basis = `가정: 증거 시간대 ${zone}`;
  if (candidates.length === 1) return `${candidates[0]} (${basis})`;
  if (candidates.length === 0) return `환산 불가 — 일광절약시간 전환으로 없는 현지 시각 (${basis})`;
  return `${candidates.join(" 또는 ")} — 일광절약시간 해제로 두 번 있는 현지 시각, 후보 ${candidates.length}개 (${basis})`;
}

export function fieldStr(row: GridRow, key: string): string {
  return str(row.fields[key]);
}
