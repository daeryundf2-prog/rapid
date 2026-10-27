/**
 * 계열 · 중복 columns (R7 갈래 A): the row's `family` / `dedup` annotations of the listing API
 * (present once the run's derivation exists). Both are default columns that hide while no loaded
 * row has a value (the grid's empty-column rule), so runs without the derivation look unchanged.
 */

import type { GridRow } from "../../../contracts/collection";
import type { ColumnSpec } from "../types";
import { col, isRecord } from "./common";

/** Korean names of the relation ids of `families.RELATION_LABELS` (server). */
export const RELATION_LABELS: Readonly<Record<string, string>> = {
  attachment: "첨부",
  message: "메시지",
  member: "압축 항목",
  "backup-member": "백업 항목",
  extracted: "백업에서 추출",
  "chat-attachment": "대화 첨부",
  carved: "카빙",
};

export interface RowFamily {
  parent: string | null;
  parentTitle: string | null;
  relation: string | null;
  children: number;
  top: string;
}

export interface RowDedup {
  status: "original" | "duplicate";
  count: number;
}

/** The API's `family` annotation (`{parent, parent_title, relation, children, top}`), else null. */
export function familyFields(raw: Record<string, unknown>): RowFamily | null {
  const family = raw.family;
  if (!isRecord(family) || typeof family.top !== "string") return null;
  return {
    parent: typeof family.parent === "string" ? family.parent : null,
    parentTitle: typeof family.parent_title === "string" ? family.parent_title : null,
    relation: typeof family.relation === "string" ? family.relation : null,
    children: typeof family.children === "number" ? family.children : 0,
    top: family.top,
  };
}

/** The API's `dedup` annotation (`{status, count}`), else null. */
export function dedupFields(raw: Record<string, unknown>): RowDedup | null {
  const dedup = raw.dedup;
  if (!isRecord(dedup) || (dedup.status !== "original" && dedup.status !== "duplicate")) return null;
  return { status: dedup.status, count: typeof dedup.count === "number" ? dedup.count : 1 };
}

/** `family` / `dedup` grid fields of a raw row (spread into `makeRow` fields). */
export function familyDedupFields(raw: Record<string, unknown>): Record<string, unknown> {
  const family = familyFields(raw);
  const dedup = dedupFields(raw);
  return {
    ...(family ? { family: raw.family, familyInfo: family } : {}),
    ...(dedup ? { dedup: raw.dedup, dedupInfo: dedup } : {}),
  };
}

function rowFamily(row: GridRow): RowFamily | null {
  const info = row.fields.familyInfo;
  return isRecord(info) && typeof info.top === "string" ? (info as unknown as RowFamily) : null;
}

function rowDedup(row: GridRow): RowDedup | null {
  const info = row.fields.dedupInfo;
  return isRecord(info) && (info.status === "original" || info.status === "duplicate")
    ? (info as unknown as RowDedup)
    : null;
}

/** 중복 cell: "원본 · 중복 2건" · "중복(3건 중)" · "—" (a unique item); "" without a dedup key. */
export function dedupText(row: GridRow): string {
  const dedup = rowDedup(row);
  if (!dedup) return "";
  if (dedup.count <= 1) return "—";
  return dedup.status === "original" ? `원본 · 중복 ${dedup.count - 1}건` : `중복(${dedup.count}건 중)`;
}

/** 계열 cell: "상위: <title>" (a child) · "하위 n개" (a parent) · "" (no relation). */
export function familyText(row: GridRow): string {
  const family = rowFamily(row);
  if (!family) return "";
  if (family.parent) {
    const relation = family.relation ? RELATION_LABELS[family.relation] : null;
    const title = family.parentTitle?.trim() || "상위 항목";
    return `${relation ? `${relation} · ` : ""}상위: ${title}${family.children ? ` · 하위 ${family.children}개` : ""}`;
  }
  return family.children ? `하위 ${family.children}개` : "";
}

/** 중복 (원본/중복) and 계열 columns, shown by default when a loaded row has a value. */
export function familyDedupColumns(presets: ColumnSpec["presets"] = ["analysis"]): ColumnSpec[] {
  return [
    col.field("dedup", "중복", 130, presets, (r) => dedupText(r) || null, {
      tooltip: (r) => {
        const text = dedupText(r);
        return text ? `${text} — 같은 SHA-256(메일은 메일 키) 항목 묶음, 항목별 기준` : "";
      },
    }),
    col.field("family", "계열", 180, presets, (r) => familyText(r) || null, {
      tooltip: (r) => familyText(r),
    }),
  ];
}
