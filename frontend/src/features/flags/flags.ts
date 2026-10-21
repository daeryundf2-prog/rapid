/**
 * Row flags (특이사항, viewer-families plan U-F4): rows carry
 * `flags: [{ id, grade, label, evidence, note? }]` from the triage-rules engine (the API joins
 * `analyses/<id>/flags.jsonl` onto artifact / file / analysis rows). Pure helpers: parsing,
 * ordering, accessible names, the filter predicate.
 */

import type { GridRow } from "../../contracts/collection";
import { flatValue } from "../../utils/flatValue";
import {
  type CatalogRule,
  familyValueLabel,
  GRADES,
  type Grade,
  isGrade,
  type RuleValidation,
  type RuleValidationEntry,
  ruleById,
} from "./catalog";

export interface RowFlag {
  id: string;
  grade: Grade;
  label: string;
  /** 근거 필드: `{field: value}` (or one sentence from older engines). */
  evidence: Record<string, unknown> | string | null;
  note?: string;
  /** Rule version that produced the flag (D1 rows carry it; else the catalogue's). */
  version?: string | number;
  /** "provisional" → "검증 필요" (row value, else the catalogue's). */
  status?: "verified" | "provisional";
}

export const GRADE_NAME: Record<Grade, string> = {
  A: "A (단독으로 강함)",
  B: "B (조합 필요)",
  C: "C (약함)",
};

const GRADE_RANK: Record<Grade, number> = { A: 0, B: 1, C: 2 };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Normalise a raw `flags` value; unknown shapes are dropped, A first, then label. */
export function parseFlags(raw: unknown): RowFlag[] {
  if (!Array.isArray(raw)) return [];
  const out: RowFlag[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (!isRecord(entry) || typeof entry.id !== "string" || !entry.id || seen.has(entry.id)) continue;
    const rule = ruleById(entry.id);
    const grade = isGrade(entry.grade) ? entry.grade : rule?.grade;
    if (!grade) continue;
    seen.add(entry.id);
    const evidence = isRecord(entry.evidence)
      ? entry.evidence
      : typeof entry.evidence === "string" && entry.evidence
        ? entry.evidence
        : null;
    out.push({
      id: entry.id,
      grade,
      label: typeof entry.label === "string" && entry.label ? entry.label : (rule?.label_ko ?? entry.id),
      evidence,
      ...(typeof entry.note === "string" && entry.note ? { note: entry.note } : {}),
      ...(typeof entry.version === "number" || (typeof entry.version === "string" && entry.version)
        ? { version: entry.version }
        : {}),
      ...(entry.status === "provisional" || entry.status === "verified" ? { status: entry.status } : {}),
    });
  }
  return out.sort(
    (a, b) => GRADE_RANK[a.grade] - GRADE_RANK[b.grade] || a.label.localeCompare(b.label, "ko"),
  );
}

/** The row's flags (mapRow stores the raw API value under `fields.flags`). */
export function rowFlags(row: Pick<GridRow, "fields"> | null | undefined): RowFlag[] {
  if (!row) return [];
  const cached = row.fields.flagList;
  if (Array.isArray(cached)) return cached as RowFlag[];
  return parseFlags(row.fields.flags);
}

/** Count per grade. */
export function gradeCounts(flags: readonly RowFlag[]): Record<Grade, number> {
  const counts: Record<Grade, number> = { A: 0, B: 0, C: 0 };
  for (const flag of flags) counts[flag.grade] += 1;
  return counts;
}

/** "특이사항 A 2건, B 1건: 로그 삭제, 외부 IP RDP, 신규 서비스" (cell accessible name). */
export function flagsAccessibleName(flags: readonly RowFlag[]): string {
  if (!flags.length) return "특이사항 없음";
  const counts = gradeCounts(flags);
  const parts = GRADES.filter((g) => counts[g] > 0).map((g) => `${g} ${counts[g]}건`);
  return `특이사항 ${parts.join(", ")}: ${flags.map((f) => f.label).join(", ")}`;
}

/** Sort value (client sort): more severe flags first when sorted descending. */
export function flagSortValue(flags: readonly RowFlag[]): number {
  const counts = gradeCounts(flags);
  return counts.A * 10_000 + counts.B * 100 + counts.C;
}

/** Highest grade of the row, or null. */
export function topGrade(flags: readonly RowFlag[]): Grade | null {
  return flags[0]?.grade ?? null;
}

/** `flag_grade=B` keeps A and B ("이상"). */
export function gradeAtLeast(grade: Grade, minimum: Grade): boolean {
  return GRADE_RANK[grade] <= GRADE_RANK[minimum];
}

/** Client predicate of the flag conditions (any listed rule; grade at least). */
export function rowMatchesFlagFilter(
  row: Pick<GridRow, "fields">,
  ids: readonly string[],
  minimum: Grade | undefined,
): boolean {
  if (!ids.length && !minimum) return true;
  const flags = rowFlags(row);
  if (ids.length && !flags.some((flag) => ids.includes(flag.id))) return false;
  if (minimum && !flags.some((flag) => gradeAtLeast(flag.grade, minimum))) return false;
  return true;
}

/** Evidence as `[field, text]` pairs. */
export function evidenceEntries(flag: RowFlag): Array<[string, string]> {
  if (!flag.evidence) return [];
  if (typeof flag.evidence === "string") return [["근거", flag.evidence]];
  return Object.entries(flag.evidence).map(([key, value]) => [key, flatValue(value)]);
}

/** Citation form of one flag: "eventlog.log_cleared@1 (event_id=1102)". */
export function flagCitation(flag: RowFlag, rule: CatalogRule | undefined = ruleById(flag.id)): string {
  // The version that produced the flag wins over the catalogue loaded now (a re-run may differ).
  const raw = flag.version ?? rule?.version;
  const version = raw !== undefined && raw !== "" ? `@${raw}` : "";
  // A raw value with a catalogue reading cites both: `direction=발신(outgoing)`.
  const evidence = evidenceEntries(flag)
    .map(([key, value]) => {
      const reading = familyValueLabel(rule?.family, key, value);
      return reading && reading !== String(value) ? `${key}=${reading}(${value})` : `${key}=${value}`;
    })
    .join(", ");
  return `${flag.id}${version}${evidence ? ` (${evidence})` : ""}`;
}

/** The flag's rule is provisional ("검증 필요"): the row's status, else the catalogue's. */
export function isProvisional(flag: RowFlag): boolean {
  return (flag.status ?? ruleById(flag.id)?.status) === "provisional";
}

/** Sources named in the validation line before "…" (the full list is in the tooltip). */
const VALIDATION_SOURCES_SHOWN = 2;

function validationPart(name: string, entries: readonly RuleValidationEntry[]): string {
  const shown = entries.slice(0, VALIDATION_SOURCES_SHOWN).map((entry) => entry.source);
  const more = entries.length > VALIDATION_SOURCES_SHOWN ? " …" : "";
  return `${name} ${entries.length}건(${shown.join(", ")}${more})`;
}

/**
 * One Korean line on what a rule was checked against (R6 S4, catalogue `validation`):
 * "검증: 합성 픽스처만" · "검증: 실데이터 2건(bsh-mft, bsh-subset) · 합성 픽스처" ·
 * "검증: 공개 데이터셋 1건(cfreds-hacking-case)". Null when the rule carries no block.
 */
export function validationLine(rule: Pick<CatalogRule, "validation"> | undefined): string | null {
  const validation: RuleValidation | undefined = rule?.validation;
  if (!validation) return null;
  const parts: string[] = [];
  if (validation.real.length) parts.push(validationPart("실데이터", validation.real));
  if (validation.public.length) parts.push(validationPart("공개 데이터셋", validation.public));
  if (!parts.length) return validation.synthetic ? "검증: 합성 픽스처만" : "검증: 기록 없음";
  if (validation.synthetic) parts.push("합성 픽스처");
  return `검증: ${parts.join(" · ")}`;
}

/** Label of a rule id for chips / the tree (catalogue label, else the id). */
export function ruleLabel(id: string): string {
  return ruleById(id)?.label_ko ?? id;
}
